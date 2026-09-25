package main

import (
	"errors"
	"fmt"
	hw "local/xkeen-hot-watcher/internal/hotwatcher"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

const xkeenCommand = "/opt/sbin/xkeen"

func xkeen(action string) error {
	info, err := os.Lstat(xkeenCommand)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0111 == 0 {
		return errors.New("не найден исполняемый /opt/sbin/xkeen")
	}
	if _, err = exec.Command(xkeenCommand, action).CombinedOutput(); err != nil {
		return fmt.Errorf("xkeen %s завершился с ошибкой: %w", action, err)
	}
	return nil
}

func watcherRunning() (bool, error) {
	out, err := exec.Command("/opt/etc/init.d/S99hotwatcher", "status").CombinedOutput()
	if err != nil {
		return false, fmt.Errorf("не удалось проверить службу Hot Watcher: %w", err)
	}
	return strings.Contains(string(out), "Hot Watcher PID:"), nil
}

func fetchWithoutVPN(stop, start func() error, fetch func() ([]byte, error)) (body []byte, err error) {
	// Even a failing stop may have changed routing; restore in every case.
	defer func() {
		if startErr := start(); startErr != nil {
			err = errors.Join(err, fmt.Errorf("не удалось вернуть VPN: %w", startErr))
		}
	}()
	if err = stop(); err != nil {
		return nil, err
	}
	return fetch()
}

func waitXrayAPI(engine *hw.Engine, reachable bool, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		_, err := engine.R.List()
		if (err == nil) == reachable {
			return nil
		}
		if time.Now().After(deadline) {
			if reachable {
				return errors.New("API Xray не стал доступен после запуска XKeen")
			}
			return errors.New("Xray не остановился после команды xkeen -stop")
		}
		time.Sleep(time.Second)
	}
}

// The download is made while XKeen is off. The resulting bytes stay in memory
// and are handed to the ordinary transactional Sync after XKeen returns.
func hardSync(c hw.Config, engine *hw.Engine) (err error) {
	status, err := engine.Status()
	if err != nil {
		return err
	}
	if status["adopted"] != true {
		return errors.New("сначала выполните hotwatcher adopt")
	}
	if status["static_fallback_mode"] == true {
		return errors.New("сначала выполните hotwatcher start")
	}
	if status["pending_transaction"] == true {
		return errors.New("есть незавершённая операция: выполните recover или abort")
	}
	if status["hold"] == true {
		return errors.New("обновление приостановлено: выполните hotwatcher hold off")
	}
	if status["disk_matches_state"] != true {
		return errors.New("файл ключей изменён вне Hot Watcher")
	}
	if status["api_reachable"] != true {
		return errors.New("API Xray недоступен; сначала запустите XKeen")
	}
	if _, err = c.URL(); err != nil {
		return err
	}
	if info, e := os.Lstat(xkeenCommand); e != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0111 == 0 {
		return errors.New("не найден исполняемый /opt/sbin/xkeen")
	}

	running, err := watcherRunning()
	if err != nil {
		return err
	}
	if running {
		if err = initService("stop"); err != nil {
			return err
		}
		defer func() {
			if startErr := initService("start"); startErr != nil {
				err = errors.Join(err, startErr)
				return
			}
			time.Sleep(time.Second)
			active, statusErr := watcherRunning()
			if statusErr != nil || !active {
				err = errors.Join(err, errors.New("служба Hot Watcher не запустилась после hard-sync"))
			}
		}()
	}

	interrupt := make(chan os.Signal, 1)
	signal.Notify(interrupt, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(interrupt)
	return hw.WithLock(c, func() (syncErr error) {
		lockedStatus, statusErr := engine.Status()
		if statusErr != nil {
			return statusErr
		}
		if lockedStatus["pending_transaction"] == true || lockedStatus["static_fallback_mode"] == true || lockedStatus["hold"] == true || lockedStatus["disk_matches_state"] != true {
			return errors.New("состояние изменилось перед hard-sync; проверьте hotwatcher status")
		}
		verified := map[string]time.Duration{}
		var prepared hw.Parsed
		_, fetchErr := fetchWithoutVPN(func() error {
			if stopErr := xkeen("-stop"); stopErr != nil {
				return stopErr
			}
			return waitXrayAPI(engine, false, 30*time.Second)
		}, func() error {
			if startErr := xkeen("-start"); startErr != nil {
				return startErr
			}
			return waitXrayAPI(engine, true, 30*time.Second)
		}, func() ([]byte, error) {
			fmt.Println("XKeen остановлен. Загружаю подписку напрямую…")
			b, fetchErr := engine.Fetcher(c)
			if fetchErr != nil {
				return nil, fetchErr
			}
			parsed, parseErr := hw.Parse(b, c)
			if parseErr != nil {
				return nil, parseErr
			}
			fmt.Println("Проверяю ключи без VPN…")
			for _, node := range parsed.Nodes {
				if latency, probeErr := engine.R.ProbeLatency(node); probeErr == nil {
					verified[node.Tag] = latency
					prepared.Nodes = append(prepared.Nodes, node)
				}
			}
			prepared.Skipped = parsed.Skipped
			if len(verified) == 0 {
				return nil, errors.New("ни один ключ не прошёл проверку без VPN; старые ключи сохранены")
			}
			if len(prepared.Nodes) < len(parsed.Nodes) {
				fmt.Printf("Недоступных ключей пропущено: %d. Применяю только проверенные.\n", len(parsed.Nodes)-len(prepared.Nodes))
			}
			return b, nil
		})
		if fetchErr != nil {
			hw.WriteLastCheck(c, false)
			return fetchErr
		}
		select {
		case <-interrupt:
			return errors.New("hard-sync прерван; VPN уже запущен обратно")
		default:
		}
		engine.VerifiedLatencies = verified
		defer func() { engine.VerifiedLatencies = nil }()
		syncErr = engine.SyncPrepared(prepared)
		hw.WriteLastCheck(c, syncErr == nil)
		if syncErr == nil {
			fmt.Println("Подписка применена. XKeen снова запущен.")
		}
		return syncErr
	})
}
