package hotwatcher

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestDaemonLockPreventsSecondInstanceAndReleases(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	release, err := LockDaemon(dir)
	if err != nil {
		t.Fatal(err)
	}
	if second, err := LockDaemon(dir); err == nil {
		second()
		release()
		t.Fatal("second daemon acquired the lifetime lock")
	}
	release()
	again, err := LockDaemon(dir)
	if err != nil {
		t.Fatalf("daemon could not restart after release: %v", err)
	}
	again()
}

func TestDaemonLockRejectsUntrackedOlderProcess(t *testing.T) {
	if os.Getenv("HOTWATCHER_DAEMON_LOCK_CHILD") == "1" {
		time.Sleep(10 * time.Second)
		return
	}
	child := exec.Command(os.Args[0], "-test.run=^TestDaemonLockRejectsUntrackedOlderProcess$", "daemon")
	child.Env = append(os.Environ(), "HOTWATCHER_DAEMON_LOCK_CHILD=1")
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = child.Process.Kill(); _ = child.Wait() }()
	if release, err := LockDaemon(filepath.Join(t.TempDir(), "state")); err == nil {
		release()
		t.Fatal("untracked daemon was ignored")
	} else if !strings.Contains(err.Error(), strconv.Itoa(child.Process.Pid)) {
		t.Fatalf("wrong daemon reported: %v", err)
	}
}
