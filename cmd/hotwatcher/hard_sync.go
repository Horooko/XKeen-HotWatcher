package main

import (
	"errors"
	"fmt"
	hw "local/xkeen-hot-watcher/internal/hotwatcher"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"time"
)

const xkeenCommand = "/opt/sbin/xkeen"

func xkeen(action string) error {
	info, err := os.Lstat(xkeenCommand)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0111 == 0 {
		return errors.New("не найден исполняемый /opt/sbin/xkeen")
	}
	cmd := exec.Command(xkeenCommand, action)
	// XKeen detaches start/stop when it has no terminal. Keep the operator's
	// terminal so its real completion and diagnostics remain visible.
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	if err = cmd.Run(); err != nil {
		return fmt.Errorf("xkeen %s завершился с ошибкой: %w", action, err)
	}
	return nil
}

func waitXrayReady(engine *hw.Engine, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	lastStage := "API списка узлов"
	for {
		lastStage = "API списка узлов"
		if _, err := engine.R.List(); err == nil {
			lastStage = "API балансировщика"
			if _, err = engine.R.Balance(); err == nil {
				return nil
			}
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("XKeen запущен, но %s Xray недоступен; подписка сохранена для просмотра через keys, применение отложено", lastStage)
		}
		time.Sleep(time.Second)
	}
}

func fetchWithoutVPN(stop, start func() error, fetch func() ([]byte, error)) (body []byte, err error) {
	// Even a failing stop may have changed routing; restore in every case.
	defer func() {
		if startErr := start(); startErr != nil {
			err = errors.Join(err, fmt.Errorf("после прямой загрузки: %w", startErr))
		}
	}()
	if err = stop(); err != nil {
		return nil, err
	}
	return fetch()
}

func waitXrayStopped(engine *hw.Engine, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		_, err := engine.R.List()
		if err != nil {
			return nil
		}
		if time.Now().After(deadline) {
			return errors.New("Xray не остановился после команды xkeen -stop")
		}
		time.Sleep(time.Second)
	}
}

// Download and probes run while XKeen is off. Parsed nodes stay in memory and
// are handed to the ordinary transaction after XKeen returns.
func hardSync(c hw.Config, engine *hw.Engine) (err error) {
	if progress, progressErr := engine.HardSyncProgress(); progressErr != nil {
		return progressErr
	} else if progress != nil {
		return errors.New("предыдущий hard-sync не завершён; проверьте hotwatcher recovery status")
	}
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

	interrupt := make(chan os.Signal, 1)
	signal.Notify(interrupt, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(interrupt)
	fmt.Println("Подготавливаю ручную синхронизацию; текущая проверка может задержать начало…")
	return hw.WithLockWait(c, 3*time.Minute, func() (syncErr error) {
		previous, progressErr := engine.HardSyncProgress()
		if progressErr != nil {
			return progressErr
		}
		if previous != nil {
			return errors.New("предыдущий hard-sync не завершён; проверьте hotwatcher recovery status")
		}
		lockedStatus, statusErr := engine.Status()
		if statusErr != nil {
			return statusErr
		}
		if lockedStatus["pending_transaction"] == true || lockedStatus["static_fallback_mode"] == true || lockedStatus["hold"] == true || lockedStatus["disk_matches_state"] != true {
			return errors.New("состояние изменилось перед hard-sync; проверьте hotwatcher status")
		}
		stage, mayBeStopped := "preparing", false
		if err := engine.RecordHardSync(stage, mayBeStopped, ""); err != nil {
			return err
		}
		setStage := func(next string, stopped bool) error {
			if err := engine.RecordHardSync(next, stopped, ""); err != nil {
				return err
			}
			stage, mayBeStopped = next, stopped
			return nil
		}
		defer func() {
			if syncErr == nil {
				syncErr = engine.ClearHardSyncProgress()
			} else if recordErr := engine.RecordHardSync("failed", mayBeStopped, "сбой на этапе "+stage); recordErr != nil {
				syncErr = errors.Join(syncErr, recordErr)
			}
		}()
		verified := map[string]time.Duration{}
		var prepared hw.Parsed
		_, fetchErr := fetchWithoutVPN(func() error {
			if err := setStage("stopping_xkeen", true); err != nil {
				return err
			}
			if stopErr := xkeen("-stop"); stopErr != nil {
				return stopErr
			}
			if err := waitXrayStopped(engine, 30*time.Second); err != nil {
				return err
			}
			return setStage("downloading", true)
		}, func() error {
			if err := setStage("starting_xkeen", true); err != nil {
				return err
			}
			startErr := xkeen("-start")
			fmt.Println("Ожидаю API списка узлов и балансировщика после запуска XKeen…")
			readyErr := waitXrayReady(engine, 60*time.Second)
			if readyErr == nil {
				if startErr != nil {
					fmt.Println("XKeen сообщил об ошибке запуска, но оба API Xray доступны.")
				}
				return setStage("applying", false)
			}
			return errors.Join(startErr, readyErr)
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
			if err := setStage("checking_keys", true); err != nil {
				return nil, err
			}
			fmt.Println("Проверяю ключи без VPN…")
			for i, node := range parsed.Nodes {
				fmt.Printf("Ключ %d/%d: ", i+1, len(parsed.Nodes))
				if latency, probeErr := engine.R.ProbeLatency(node); probeErr == nil {
					verified[node.Tag] = latency
					fmt.Printf("работает (%.0f мс)\n", float64(latency.Microseconds())/1000)
				} else {
					fmt.Println("недоступен")
				}
			}
			prepared = parsed
			if cacheErr := engine.SaveFetched(parsed, verified, true); cacheErr != nil {
				return nil, cacheErr
			}
			if len(verified) == 0 {
				return nil, errors.New("ни один ключ не прошёл проверку без VPN; старые ключи сохранены")
			}
			if len(verified) < len(parsed.Nodes) {
				fmt.Printf("Недоступных ключей: %d. Они останутся в списке, но не будут выбраны.\n", len(parsed.Nodes)-len(verified))
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
