package hotwatcher

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Activity is operational metadata only; no subscription URL or key material.
type Activity struct {
	Lock             LockInfo `json:"lock"`
	ElapsedSeconds   int64    `json:"elapsed_seconds"`
	BackgroundPaused bool     `json:"background_paused"`
	StopRequested    bool     `json:"stop_requested"`
	CanStop          bool     `json:"can_stop"`
	Message          string   `json:"message"`
}

func backgroundPausePath(c Config) string {
	return filepath.Join(c.StateDir, "background-paused")
}

func BackgroundPaused(c Config) (bool, error) {
	info, err := os.Lstat(backgroundPausePath(c))
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		return false, errors.New("unsafe background pause marker")
	}
	return true, nil
}

// StopBackground requests cooperative cancellation before another operation or
// before the next transaction begins. It never signals Xray or the daemon.
func StopBackground(c Config) error {
	if err := privateDir(c.StateDir); err != nil {
		return err
	}
	return atomicWrite(backgroundPausePath(c), []byte("paused\n"), 0600)
}

func ResumeBackground(c Config) error {
	paused, err := BackgroundPaused(c)
	if err != nil || !paused {
		return err
	}
	return removeSync(backgroundPausePath(c))
}

func ActivityStatus(c Config) (Activity, error) {
	result := Activity{CanStop: true}
	var err error
	result.Lock, err = CurrentLock(c)
	if err != nil {
		return result, err
	}
	result.BackgroundPaused, err = BackgroundPaused(c)
	if err != nil {
		return result, err
	}
	if result.Lock.Busy {
		if !result.Lock.Since.IsZero() {
			result.ElapsedSeconds = max(0, int64(time.Since(result.Lock.Since).Seconds()))
		}
		result.StopRequested = result.BackgroundPaused && strings.HasPrefix(result.Lock.Operation, "background ")
		if result.StopRequested {
			result.Message = "Остановка запрошена; текущий безопасный этап завершается"
		} else {
			result.Message = "Операция выполняется"
		}
	} else if result.BackgroundPaused {
		result.Message = "Фоновые операции приостановлены"
	} else {
		result.Message = "Нет операции под общей блокировкой; задачи WebUI без блокировки здесь не отображаются"
	}
	return result, nil
}
