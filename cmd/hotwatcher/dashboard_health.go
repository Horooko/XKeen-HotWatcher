package main

import (
	"context"
	"errors"
	hw "local/xkeen-hot-watcher/internal/hotwatcher"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Health checks are read-only. Slow/missing control APIs must not prevent the
// dashboard from returning saved keys, and opening a tab must not start a probe.
type dashboardHealth struct {
	mu         sync.RWMutex
	once       sync.Once
	status     map[string]any
	statusErr  error
	system     xkeenStatus
	readStatus func() (map[string]any, error)
	readSystem func(context.Context) xkeenStatus
	statusWake chan struct{}
	systemWake chan struct{}
}

func newDashboardHealth(c hw.Config, e *hw.Engine) *dashboardHealth {
	return &dashboardHealth{
		readStatus: e.Status,
		readSystem: func(ctx context.Context) xkeenStatus {
			running := xrayProcessRunning("/proc", c.XrayBinary, c.StateDir)
			system := readXKeenStatusContext(ctx)
			system.XrayRunning = running
			return system
		},
		statusWake: make(chan struct{}, 1),
		systemWake: make(chan struct{}, 1),
	}
}

func (h *dashboardHealth) snapshot() (map[string]any, error, xkeenStatus) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	// Published snapshots are immutable, including their maps and slices.
	return h.status, h.statusErr, h.system
}

func (h *dashboardHealth) refresh() {
	for _, wake := range []chan struct{}{h.statusWake, h.systemWake} {
		select {
		case wake <- struct{}{}:
		default:
		}
	}
}

func (h *dashboardHealth) start(ctx context.Context, interval time.Duration) {
	h.once.Do(func() {
		go healthLoop(ctx, interval, h.statusWake, func() {
			status, err := h.readStatus()
			h.mu.Lock()
			h.status, h.statusErr = status, err
			h.mu.Unlock()
		})
		go healthLoop(ctx, interval, h.systemWake, func() {
			system := h.readSystem(ctx)
			h.mu.Lock()
			h.system = system
			h.mu.Unlock()
		})
	})
}

func healthLoop(ctx context.Context, interval time.Duration, wake <-chan struct{}, read func()) {
	for {
		if ctx.Err() != nil {
			return
		}
		read()
		timer := time.NewTimer(interval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-wake:
			timer.Stop()
		case <-timer.C:
		}
	}
}

// nil means /proc could not be inspected reliably, not that Xray is stopped.
// Ignore our own `xray api`, validation and isolated probe subprocesses.
func xrayProcessRunning(procDir, binary, stateDir string) *bool {
	entries, err := os.ReadDir(procDir)
	if err != nil {
		return nil
	}
	uncertain := false
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		if _, err := strconv.Atoi(entry.Name()); err != nil {
			continue
		}
		b, err := os.ReadFile(filepath.Join(procDir, entry.Name(), "cmdline"))
		if err != nil {
			if !errors.Is(err, os.ErrNotExist) {
				uncertain = true
			}
			continue
		}
		args := strings.Split(strings.TrimRight(string(b), "\x00"), "\x00")
		if isXrayServer(args, binary, stateDir) {
			running := true
			return &running
		}
	}
	if uncertain {
		return nil
	}
	running := false
	return &running
}

func isXrayServer(args []string, binary, stateDir string) bool {
	if len(args) == 0 || filepath.Base(args[0]) != filepath.Base(binary) {
		return false
	}
	if len(args) > 1 && args[1] != "run" && !strings.HasPrefix(args[1], "-") {
		return false
	}
	statePrefix := filepath.Clean(stateDir) + string(os.PathSeparator)
	for _, arg := range args[1:] {
		if arg == "-test" || arg == "--test" || strings.HasPrefix(arg, "-test=") || strings.HasPrefix(arg, "--test=") || arg == "-version" || arg == "--version" || arg == "-h" || arg == "--help" {
			return false
		}
		// Config flags may use either `-config file` or `-config=file`.
		if _, value, found := strings.Cut(arg, "="); found {
			arg = value
		}
		if stateDir != "" && strings.HasPrefix(filepath.Clean(arg), statePrefix) {
			return false
		}
	}
	return true
}

func entwareStatusEnv() []string {
	env := make([]string, 0, len(os.Environ())+1)
	for _, item := range os.Environ() {
		if !strings.HasPrefix(item, "PATH=") {
			env = append(env, item)
		}
	}
	path := "/opt/sbin:/opt/bin:/usr/sbin:/usr/bin:/sbin:/bin"
	if current := os.Getenv("PATH"); current != "" {
		path += ":" + current
	}
	return append(env, "PATH="+path)
}
