package hotwatcher

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRecoveryStatusDistinguishesHeldFromLeftoverLock(t *testing.T) {
	c := dnsTestConfig(t)
	e := New(c)
	during := LockInfo{}
	if err := WithLock(c, func() error {
		var err error
		during, err = CurrentLock(c)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if !during.Busy || during.PID != os.Getpid() || during.Since.IsZero() {
		t.Fatalf("held lock not identified: %+v", during)
	}
	after, err := CurrentLock(c)
	if err != nil || after.Busy {
		t.Fatalf("leftover lock file treated as busy: %+v, %v", after, err)
	}
	if err := e.RecordHardSync("downloading", true, ""); err != nil {
		t.Fatal(err)
	}
	status, err := e.RecoveryStatus()
	if err != nil || status.HardSync == nil || !strings.Contains(status.SuggestedCommand, "recovery resume") {
		t.Fatalf("incomplete hard-sync not reported: %+v, %v", status, err)
	}
	if err := os.WriteFile(filepath.Join(c.StateDir, "pending.json"), []byte("pending"), 0600); err != nil {
		t.Fatal(err)
	}
	status, err = e.RecoveryStatus()
	if err != nil || !status.PendingTransaction {
		t.Fatalf("pending transaction not reported: %+v, %v", status, err)
	}
	if err := e.ClearHardSyncProgress(); err != nil {
		t.Fatal(err)
	}
	if p, err := e.HardSyncProgress(); err != nil || p != nil {
		t.Fatalf("progress not cleared: %+v, %v", p, err)
	}
}

func TestHardSyncProgressKeepsStartTimeAcrossStages(t *testing.T) {
	c := dnsTestConfig(t)
	e := New(c)
	e.Now = func() time.Time { return time.Date(2026, 9, 25, 10, 0, 0, 0, time.UTC) }
	if err := e.RecordHardSync("stopping_xkeen", true, ""); err != nil {
		t.Fatal(err)
	}
	e.Now = func() time.Time { return time.Date(2026, 9, 25, 10, 1, 0, 0, time.UTC) }
	if err := e.RecordHardSync("failed", true, "сбой на этапе stopping_xkeen"); err != nil {
		t.Fatal(err)
	}
	p, err := e.HardSyncProgress()
	if err != nil || p.StartedAt != time.Date(2026, 9, 25, 10, 0, 0, 0, time.UTC) || p.UpdatedAt.Sub(p.StartedAt) != time.Minute || !p.XKeenMayBeStopped {
		t.Fatalf("invalid persisted progress: %+v, %v", p, err)
	}
}
