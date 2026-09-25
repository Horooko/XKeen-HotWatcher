package main

import (
	"errors"
	"fmt"
	hw "local/xkeen-hot-watcher/internal/hotwatcher"
	"time"
)

func recoveryCommand(c hw.Config, engine *hw.Engine, args []string) error {
	if len(args) != 1 {
		return errors.New("использование: hotwatcher recovery status|resume|abort")
	}
	if args[0] == "status" {
		status, err := engine.RecoveryStatus()
		if err == nil {
			printJSON(status)
		}
		return err
	}
	if args[0] != "resume" && args[0] != "abort" {
		return errors.New("использование: hotwatcher recovery status|resume|abort")
	}
	return hw.WithLockWait(c, 30*time.Second, func() error {
		status, err := engine.RecoveryStatus()
		if err != nil {
			return err
		}
		if status.HardSync == nil && !status.PendingTransaction {
			fmt.Println("Незавершённых операций нет.")
			return nil
		}
		if status.HardSync != nil {
			_, listErr := engine.R.List()
			_, balanceErr := engine.R.Balance()
			if listErr != nil || balanceErr != nil {
				fmt.Println("Восстанавливаю XKeen после прерванного hard-sync…")
				if err := xkeen("-start"); err != nil {
					return err
				}
				if err := waitXrayReady(engine, 60*time.Second); err != nil {
					return err
				}
			}
			if err := engine.RecordHardSync("applying", false, ""); err != nil {
				return err
			}
		}
		if status.PendingTransaction {
			if args[0] == "abort" {
				err = engine.Abort()
			} else {
				err = engine.Recover()
			}
			if err != nil {
				return err
			}
		} else if status.HardSync != nil {
			if err := engine.Reconcile(); err != nil {
				return err
			}
		}
		if status.HardSync != nil {
			if err := engine.ClearHardSyncProgress(); err != nil {
				return err
			}
		}
		if args[0] == "abort" {
			fmt.Println("Незавершённое применение отменено; XKeen проверен. Старые ключи сохранены.")
		} else {
			fmt.Println("Восстановление завершено; XKeen проверен. Если подписка не была применена, повторите hard-sync.")
		}
		return nil
	})
}
