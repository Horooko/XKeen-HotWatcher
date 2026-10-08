package hotwatcher

import (
	"strings"
	"testing"
)

func TestActivityShowsNamedLockAndCooperativeStop(t *testing.T) {
	e, _, _ := setupEngine(t)
	if err := WithLockNamed(e.C, "background sync", func() error {
		activity, err := ActivityStatus(e.C)
		if err != nil || !activity.Lock.Busy || activity.Lock.Operation != "background sync" || activity.Lock.PID == 0 {
			t.Fatalf("named activity missing: %+v %v", activity, err)
		}
		if err := StopBackground(e.C); err != nil {
			return err
		}
		activity, err = ActivityStatus(e.C)
		if err != nil || !activity.StopRequested || !activity.BackgroundPaused {
			t.Fatalf("stop request missing: %+v %v", activity, err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	e.ShouldStop = func() bool { paused, _ := BackgroundPaused(e.C); return paused }
	if err := e.Sync(true); err == nil || !strings.Contains(err.Error(), "остановлена") {
		t.Fatalf("background sync ignored stop request: %v", err)
	}
	if e.pending() {
		t.Fatal("stop request left a pending transaction")
	}
	if err := ResumeBackground(e.C); err != nil {
		t.Fatal(err)
	}
	activity, err := ActivityStatus(e.C)
	if err != nil || activity.Lock.Busy || activity.BackgroundPaused {
		t.Fatalf("activity did not resume: %+v %v", activity, err)
	}
	if !strings.Contains(activity.Message, "Нет операции под общей блокировкой") {
		t.Fatalf("idle message claims all work is stopped: %q", activity.Message)
	}
}
