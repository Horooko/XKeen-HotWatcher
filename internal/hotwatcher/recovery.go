package hotwatcher

import (
	"errors"
	"os"
	"path/filepath"
	"time"
)

// HardSyncProgress contains only operational state. Subscription URLs and
// outbound credentials must never be written to this recovery marker.
type HardSyncProgress struct {
	Schema            int       `json:"schema"`
	Stage             string    `json:"stage"`
	XKeenMayBeStopped bool      `json:"xkeen_may_be_stopped"`
	StartedAt         time.Time `json:"started_at"`
	UpdatedAt         time.Time `json:"updated_at"`
	Failure           string    `json:"failure,omitempty"`
}

var hardSyncStages = map[string]bool{
	"preparing": true, "stopping_xkeen": true, "downloading": true,
	"checking_keys": true, "starting_xkeen": true, "applying": true,
	"failed": true,
}

func (e *Engine) hardSyncProgressPath() string {
	return filepath.Join(e.C.StateDir, "hard-sync-progress.json")
}

func (e *Engine) HardSyncProgress() (*HardSyncProgress, error) {
	var progress HardSyncProgress
	if err := mustJSON(e.hardSyncProgressPath(), &progress); os.IsNotExist(err) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	if progress.Schema != 1 || !hardSyncStages[progress.Stage] || progress.StartedAt.IsZero() || progress.UpdatedAt.IsZero() {
		return nil, errors.New("повреждён журнал hard-sync; автоматическое восстановление остановлено")
	}
	return &progress, nil
}

func (e *Engine) RecordHardSync(stage string, mayBeStopped bool, failure string) error {
	if !hardSyncStages[stage] {
		return errors.New("неизвестный этап hard-sync")
	}
	if err := privateDir(e.C.StateDir); err != nil {
		return err
	}
	previous, err := e.HardSyncProgress()
	if err != nil {
		return err
	}
	now := e.Now().UTC()
	started := now
	if previous != nil {
		started = previous.StartedAt
	}
	progress := HardSyncProgress{Schema: 1, Stage: stage, XKeenMayBeStopped: mayBeStopped, StartedAt: started, UpdatedAt: now, Failure: failure}
	return atomicWrite(e.hardSyncProgressPath(), encode(progress), 0600)
}

func (e *Engine) ClearHardSyncProgress() error {
	return removeSync(e.hardSyncProgressPath())
}

type RecoverySnapshot struct {
	Lock               LockInfo          `json:"lock"`
	PendingTransaction bool              `json:"pending_transaction"`
	HardSync           *HardSyncProgress `json:"hard_sync,omitempty"`
	SuggestedCommand   string            `json:"suggested_command"`
}

func (e *Engine) RecoveryStatus() (RecoverySnapshot, error) {
	result := RecoverySnapshot{SuggestedCommand: "нет незавершённых операций"}
	var err error
	result.Lock, err = CurrentLock(e.C)
	if err != nil {
		return result, err
	}
	if info, statErr := os.Lstat(e.journalPath()); statErr == nil {
		if !info.Mode().IsRegular() {
			return result, errors.New("незавершённая транзакция не является обычным файлом")
		}
		result.PendingTransaction = true
	} else if !os.IsNotExist(statErr) {
		return result, statErr
	}
	result.HardSync, err = e.HardSyncProgress()
	if err != nil {
		return result, err
	}
	switch {
	case result.Lock.Busy:
		result.SuggestedCommand = "операция ещё выполняется; повторите recovery status после её завершения"
	case result.HardSync != nil && result.HardSync.XKeenMayBeStopped:
		result.SuggestedCommand = "hotwatcher recovery resume (запустить XKeen и продолжить безопасное восстановление)"
	case result.PendingTransaction:
		result.SuggestedCommand = "hotwatcher recovery resume или hotwatcher recovery abort"
	case result.HardSync != nil:
		result.SuggestedCommand = "hotwatcher recovery resume (закрыть журнал после проверки XKeen)"
	}
	return result, nil
}
