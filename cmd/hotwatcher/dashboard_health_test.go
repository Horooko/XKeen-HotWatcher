package main

import (
	"context"
	"encoding/json"
	hw "local/xkeen-hot-watcher/internal/hotwatcher"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestHealthStartsWithoutBrowserAndSystemDoesNotWaitForAPI(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	blocked := make(chan struct{})
	defer close(blocked)
	started := make(chan struct{})
	var systemCalls atomic.Int32
	h := &dashboardHealth{
		statusWake: make(chan struct{}, 1), systemWake: make(chan struct{}, 1),
		readStatus: func() (map[string]any, error) {
			close(started)
			<-blocked
			return map[string]any{"api_reachable": false}, nil
		},
		readSystem: func(context.Context) xkeenStatus {
			systemCalls.Add(1)
			return xkeenStatus{Installed: true, CommandOK: true, CheckedAt: time.Now()}
		},
	}
	h.start(ctx, time.Hour)
	<-started
	deadline := time.After(time.Second)
	for {
		status, _, system := h.snapshot()
		if system.CommandOK {
			if status != nil {
				t.Fatal("blocked API unexpectedly finished")
			}
			break
		}
		select {
		case <-deadline:
			t.Fatal("system status waited for API or browser")
		default:
			time.Sleep(time.Millisecond)
		}
	}
	h.refresh()
	deadline = time.After(time.Second)
	for systemCalls.Load() < 2 {
		select {
		case <-deadline:
			t.Fatal("refresh was not collected")
		default:
			time.Sleep(time.Millisecond)
		}
	}
	cancel()
}

func TestOverviewAndSystemOnlyReadHealthCache(t *testing.T) {
	c := hw.Defaults()
	c.StateDir = filepath.Join(t.TempDir(), "state")
	w, err := newWebUI(c, hw.New(c))
	if err != nil {
		t.Fatal(err)
	}
	w.health.readStatus = func() (map[string]any, error) { t.Fatal("HTTP request triggered Xray command"); return nil, nil }
	w.health.readSystem = func(context.Context) xkeenStatus {
		t.Fatal("HTTP request triggered XKeen command")
		return xkeenStatus{}
	}
	w.health.status = map[string]any{"api_reachable": false, "balancer_api_reachable": false}
	running := true
	w.health.system = xkeenStatus{Installed: true, CommandOK: true, XrayRunning: &running, CheckedAt: time.Now()}
	id := strings.Repeat("a", 64)
	w.sessions[id] = webSession{Token: w.token, Expires: time.Now().Add(time.Hour)}
	for _, path := range []string{"/api/overview", "/api/system"} {
		req := httptest.NewRequest("GET", "http://"+c.WebUIListen+path, nil)
		req.AddCookie(&http.Cookie{Name: "hw_session", Value: id})
		out := httptest.NewRecorder()
		w.handler().ServeHTTP(out, req)
		if out.Code != 200 {
			t.Fatalf("%s: %d", path, out.Code)
		}
		var result map[string]any
		if err := json.Unmarshal(out.Body.Bytes(), &result); err != nil {
			t.Fatal(err)
		}
		if path == "/api/overview" {
			result = result["system"].(map[string]any)
		}
		if result["xray_running"] != true {
			t.Fatal("process status lost when API is unavailable")
		}
	}
}

func TestXrayProcessDetectionExcludesCommandsAndProbes(t *testing.T) {
	for _, tc := range []struct {
		command string
		want    bool
	}{
		{"/opt/sbin/xray\x00run\x00-confdir\x00/opt/etc/xray/configs", true},
		{"/opt/sbin/xray\x00-confdir=/opt/etc/xray/configs", true},
		{"/opt/sbin/xray\x00api\x00lso", false},
		{"/opt/sbin/xray\x00version", false},
		{"/opt/sbin/xray\x00run\x00-test\x00-confdir\x00/opt/etc/xray/configs", false},
		{"/opt/sbin/xray\x00run\x00-test=true", false},
		{"/opt/sbin/xray\x00run\x00-config\x00/opt/var/lib/hotwatcher/probe-123/probe.json", false},
		{"/opt/sbin/xray\x00run\x00-config=/opt/var/lib/hotwatcher/url-test-123/config.json", false},
		{"/bin/sh\x00/opt/sbin/xray", false},
	} {
		t.Run(strings.ReplaceAll(tc.command, "\x00", " "), func(t *testing.T) {
			proc := t.TempDir()
			if err := os.Mkdir(filepath.Join(proc, "123"), 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(proc, "123", "cmdline"), []byte(tc.command+"\x00"), 0600); err != nil {
				t.Fatal(err)
			}
			got := xrayProcessRunning(proc, "/opt/sbin/xray", "/opt/var/lib/hotwatcher")
			if got == nil || *got != tc.want {
				t.Fatalf("running=%v, want %v", got, tc.want)
			}
		})
	}
	if got := xrayProcessRunning(filepath.Join(t.TempDir(), "missing"), "/opt/sbin/xray", ""); got != nil {
		t.Fatal("missing /proc was treated as a stopped service")
	}
}

func TestXKeenStatusAcceptsExecutableSymlinkAndEntwarePATH(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "real-xkeen")
	if err := os.WriteFile(file, []byte("#!/bin/sh\n[ \"$1\" = -status ] || exit 1\ncase \"$PATH\" in /opt/sbin:/opt/bin:*) printf 'Xray is running\\n';; *) exit 2;; esac\n"), 0700); err != nil {
		t.Fatal(err)
	}
	command := filepath.Join(dir, "xkeen")
	if err := os.Symlink(file, command); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", "/minimal")
	status := readXKeenStatusCommand(context.Background(), command)
	if !status.Installed || !status.CommandOK || len(status.Status) != 1 {
		t.Fatalf("%+v", status)
	}
}
