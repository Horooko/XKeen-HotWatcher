package updater

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

func Command(args []string) error {
	if len(args) == 0 {
		args = []string{"apply"}
	}
	if err := ensureDir(Root); err != nil {
		return err
	}
	c, err := loadConfig()
	if os.IsNotExist(err) {
		c = Defaults()
	} else if err != nil {
		return err
	}
	s := readState()
	deadline := 3 * time.Minute
	if args[0] == "apply" {
		deadline = 12 * time.Minute
	}
	ctx, cancel := context.WithTimeout(context.Background(), deadline)
	defer cancel()
	switch args[0] {
	case "repair-state":
		if len(args) != 2 {
			return errors.New("repair-state requires the package version")
		}
		return RepairOfflineBootstrap(args[1])
	case "status":
		hash, _ := hashFile(Binary)
		j, _ := readJournal()
		xray, xerr := xrayIdentity()
		var xrayStatus any = xray
		if xerr != nil {
			xrayStatus = xerr.Error()
		}
		installed := s.Installed
		if installed == "" {
			installed = BuildInfo()["version"].(string)
		}
		b, _ := json.MarshalIndent(map[string]any{"configuration": c, "state": s, "state_invalid": s.Invalid, "installed_version": installed, "installed_hash": hash, "architecture": BuildInfo()["arch"], "pending_update_phase": j.Phase, "primary_xray": xrayStatus}, "", "  ")
		fmt.Println(string(b))
		return nil
	case "check", "download", "apply":
		if args[0] == "apply" {
			fmt.Println("Проверяю подписанный релиз и доступность обновления…")
		}
		unlock, lockErr := lock()
		if lockErr != nil {
			return lockErr
		}
		s = readState()
		if s.Invalid {
			unlock()
			return errors.New("updater state invalid; manual intervention required")
		}
		if !c.Enabled {
			unlock()
			return errors.New("updates disabled")
		}
		m, r, a, e := check(ctx, c, &s)
		s.LastCheck = time.Now().UTC()
		s.NextCheck = s.LastCheck.Add(time.Duration(c.CheckIntervalSeconds) * time.Second)
		if e != nil {
			if errors.Is(e, ErrNoUpdate) {
				s.Deferred = ""
				s.Available = ""
				s.Failures = 0
			} else {
				s.Deferred = e.Error()
				s.Failures++
				s.NextCheck = s.LastCheck.Add(backoff(s.Failures, c))
			}
			saveErr := save(statePath(), s)
			unlock()
			if saveErr != nil {
				return saveErr
			}
			if errors.Is(e, ErrNoUpdate) {
				fmt.Println("Подходящих новых версий нет.")
				return nil
			}
			return e
		}
		s.Available = m.Version
		s.Verified = true
		s.Deferred = ""
		s.Failures = 0
		if saveErr := save(statePath(), s); saveErr != nil {
			unlock()
			return saveErr
		}
		unlock()
		if args[0] == "check" {
			fmt.Println("Доступна подписанная версия:", m.Version)
			fmt.Println("Установить: hotwatcher update")
			return nil
		}
		p, e := download(ctx, r, a, c)
		if e != nil {
			return e
		}
		fmt.Println("Пакет скачан и проверен:", m.Version)
		if args[0] == "download" {
			return nil
		}
		if err := apply(ctx, c, m, a, p, &s); err != nil {
			return err
		}
		fmt.Println("Обновление установлено:", m.Version)
		return nil
	case "rollback":
		return errors.New("manual rollback requires a separate verified local-release selection; automatic recovery uses pending journal")
	case "enable":
		unlock, lockErr := lock()
		if lockErr != nil {
			return lockErr
		}
		locked := true
		defer func() {
			if locked {
				unlock()
			}
		}()
		s = readState()
		if s.Invalid {
			return errors.New("updater state invalid; cannot enable automatic updates")
		}
		c.Enabled = true
		c.Mode = "auto"
		for i := 1; i < len(args); i++ {
			switch args[i] {
			case "--notify":
				c.Mode = "notify"
			case "--channel":
				i++
				if i >= len(args) || args[i] != "stable" {
					return errors.New("only stable channel supported")
				}
			case "--policy":
				i++
				if i >= len(args) {
					return errors.New("policy required")
				}
				c.Policy = args[i]
			default:
				return errors.New("unknown update enable option")
			}
		}
		if err := saveConfig(c); err != nil {
			return err
		}
		if _, e := os.Lstat(statePath()); os.IsNotExist(e) {
			if err := save(statePath(), s); err != nil {
				return err
			}
		}
		if err := atomic("/opt/etc/hotwatcher/update-enabled", []byte("enabled\n"), 0600); err != nil {
			return err
		}
		unlock()
		locked = false
		_, err = exec.Command("/opt/etc/init.d/S98hotwatcher-updater", "start").CombinedOutput()
		return err
	case "disable":
		unlock, lockErr := lock()
		if lockErr != nil {
			return lockErr
		}
		defer unlock()
		c.Enabled = false
		if err := saveConfig(c); err != nil {
			return err
		}
		err = os.Remove("/opt/etc/hotwatcher/update-enabled")
		if os.IsNotExist(err) {
			return nil
		}
		return err
	case "pause":
		unlock, lockErr := lock()
		if lockErr != nil {
			return lockErr
		}
		defer unlock()
		if len(args) != 2 {
			return errors.New("use update pause on|off")
		}
		p := filepath.Join(Root, "pause")
		if args[1] == "on" {
			return atomic(p, []byte("paused\n"), 0600)
		}
		if args[1] == "off" {
			e := os.Remove(p)
			if os.IsNotExist(e) {
				return nil
			}
			return e
		}
		return errors.New("use update pause on|off")
	case "pin":
		unlock, lockErr := lock()
		if lockErr != nil {
			return lockErr
		}
		defer unlock()
		if len(args) != 2 {
			return errors.New("pin needs version")
		}
		if _, ok := semver(args[1]); !ok {
			return errors.New("invalid pin version")
		}
		c.PinnedVersion = args[1]
		return saveConfig(c)
	case "unpin":
		unlock, lockErr := lock()
		if lockErr != nil {
			return lockErr
		}
		defer unlock()
		c.PinnedVersion = ""
		return saveConfig(c)
	case "retry":
		unlock, lockErr := lock()
		if lockErr != nil {
			return lockErr
		}
		defer unlock()
		s = readState()
		if s.Invalid {
			return errors.New("updater state invalid")
		}
		if _, e := os.Lstat(journalPath()); e == nil {
			return errors.New("recover pending update first")
		}
		s.BlockedHash = ""
		return save(statePath(), s)
	default:
		return errors.New("unknown update command")
	}
}
func saveConfig(c Config) error {
	if err := c.Validate(); err != nil {
		return err
	}
	if err := ensureDir(filepath.Dir(ConfigPath)); err != nil {
		return err
	}
	return save(ConfigPath, c)
}
func Timer() error {
	if err := Recover(); err != nil {
		return err
	}
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		c, e := loadConfig()
		if e != nil {
			<-ticker.C
			continue
		}
		if _, e := os.Lstat(maintenancePath()); os.IsNotExist(e) {
			if _, e = os.Lstat("/opt/etc/hotwatcher/enabled"); e == nil {
				_, _ = exec.Command("/opt/etc/init.d/S99hotwatcher", "start").CombinedOutput()
			}
		}
		s := readState()
		if s.Invalid {
			<-ticker.C
			continue
		}
		if s.NextCheck.IsZero() {
			if unlock, e := lock(); e == nil {
				s = readState()
				if !s.Invalid && s.NextCheck.IsZero() {
					s.NextCheck = time.Now().Add(time.Minute + jitter(c.JitterSeconds))
					_ = save(statePath(), s)
				}
				unlock()
			}
		}
		if time.Now().Before(s.NextCheck) {
			<-ticker.C
			continue
		}
		if !c.Enabled {
			<-ticker.C
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
		unlock, lockErr := lock()
		if lockErr != nil {
			cancel()
			<-ticker.C
			continue
		}
		s = readState()
		if s.Invalid || time.Now().Before(s.NextCheck) {
			unlock()
			cancel()
			<-ticker.C
			continue
		}
		m, r, a, e := check(ctx, c, &s)
		s.LastCheck = time.Now().UTC()
		s.NextCheck = s.LastCheck.Add(time.Duration(c.CheckIntervalSeconds)*time.Second + jitter(c.JitterSeconds))
		if e != nil {
			if errors.Is(e, ErrNoUpdate) {
				s.Deferred = ""
				s.Available = ""
				s.Failures = 0
			} else {
				s.Deferred = e.Error()
				s.Failures++
				s.NextCheck = s.LastCheck.Add(backoff(s.Failures, c))
			}
			_ = save(statePath(), s)
			unlock()
			cancel()
			continue
		}
		s.Available = m.Version
		s.Verified = true
		s.Failures = 0
		if saveErr := save(statePath(), s); saveErr != nil {
			unlock()
			cancel()
			<-ticker.C
			continue
		}
		unlock()
		if c.Mode == "auto" && c.PinnedVersion == "" {
			if _, e = os.Lstat(filepath.Join(Root, "pause")); os.IsNotExist(e) {
				var p string
				p, e = download(ctx, r, a, c)
				if e == nil {
					applyCtx, cancelApply := context.WithTimeout(context.Background(), 12*time.Minute)
					e = apply(applyCtx, c, m, a, p, &s)
					cancelApply()
				}
				if e != nil {
					s.Deferred = e.Error()
					if unlock, lockErr := lock(); lockErr == nil {
						latest := readState()
						if !latest.Invalid {
							latest.Deferred = e.Error()
							_ = save(statePath(), latest)
						}
						unlock()
					}
				}
			}
		}
		cancel()
		<-ticker.C
	}
}
func jitter(seconds int) time.Duration {
	if seconds <= 0 {
		return 0
	}
	n, e := rand.Int(rand.Reader, big.NewInt(int64(seconds+1)))
	if e != nil {
		return 0
	}
	return time.Duration(n.Int64()) * time.Second
}
func backoff(failures int, c Config) time.Duration {
	if failures > 6 {
		failures = 6
	}
	d := time.Duration(300<<failures) * time.Second
	if d > time.Duration(c.CheckIntervalSeconds)*time.Second {
		d = time.Duration(c.CheckIntervalSeconds) * time.Second
	}
	return d + jitter(c.JitterSeconds)
}
