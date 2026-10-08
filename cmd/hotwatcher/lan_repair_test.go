package main

import (
	"context"
	"errors"
	"fmt"
	hw "local/xkeen-hot-watcher/internal/hotwatcher"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type lanRepairFixture struct {
	config   hw.Config
	deps     lanRepairDeps
	root     string
	procDir  string
	ready    string
	hook     string
	xkeen    string
	applied  bool
	runCount int
	runPath  string
	runArgs  []string
	logAtRun bool
	logCalls int
}

func newLANRepairFixture(t *testing.T) *lanRepairFixture {
	t.Helper()
	f := &lanRepairFixture{root: t.TempDir()}
	f.config = hw.Defaults()
	f.config.ConfigDir = filepath.Join(f.root, "configs")
	f.config.StateDir = filepath.Join(f.root, "state")
	f.config.XrayBinary = "/opt/sbin/xray"
	f.procDir = filepath.Join(f.root, "proc")
	f.ready = filepath.Join(f.root, "xkeen-runtime", "ready")
	f.hook = filepath.Join(f.root, "proxy.sh")
	f.xkeen = filepath.Join(f.root, "xkeen")
	for _, path := range []string{f.config.ConfigDir, f.procDir, filepath.Dir(f.ready), filepath.Join(f.procDir, "net"), filepath.Join(f.procDir, "1599")} {
		if err := os.MkdirAll(path, 0700); err != nil {
			t.Fatal(err)
		}
	}
	config := `{"inbounds":[{"tag":"redirect","port":61219,"protocol":"dokodemo-door","settings":{"network":"tcp","followRedirect":true}},{"tag":"tproxy","port":61219,"protocol":"dokodemo-door","settings":{"network":"udp","followRedirect":true},"streamSettings":{"sockopt":{"tproxy":"tproxy"}}}]}`
	if err := os.WriteFile(filepath.Join(f.config.ConfigDir, "03_inbounds.json"), []byte(config), 0600); err != nil {
		t.Fatal(err)
	}
	for name, data := range map[string]string{"comm": "xray\n", "cmdline": "/opt/sbin/xray\x00run\x00"} {
		if err := os.WriteFile(filepath.Join(f.procDir, "1599", name), []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	port := fmt.Sprintf("%04X", 61219)
	line := " 0: 00000000000000000000000000000000:" + port + " 00000000000000000000000000000000:0000 0A\n"
	for _, name := range []string{"tcp6", "udp6"} {
		if err := os.WriteFile(filepath.Join(f.procDir, "net", name), []byte(line), 0600); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"tcp", "udp"} {
		if err := os.WriteFile(filepath.Join(f.procDir, "net", name), []byte(""), 0600); err != nil {
			t.Fatal(err)
		}
	}
	f.setHook(t, true)
	if err := os.WriteFile(f.ready, []byte{}, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(f.xkeen, []byte("#!/bin/sh\n"), 0700); err != nil {
		t.Fatal(err)
	}
	f.deps = lanRepairDeps{
		procDir:   f.procDir,
		netDir:    filepath.Join(f.procDir, "net"),
		hookPath:  f.hook,
		readyPath: f.ready,
		xkeenPath: f.xkeen,
		shellPath: f.xkeen,
		findTool: func(string) string {
			return "/fake/iptables"
		},
		readLAN: func(context.Context, string) lanInterceptionStatus {
			path := lanInterceptionPath{Known: true, Present: f.applied, ExpectedPort: 61219}
			return lanInterceptionStatus{TCP: path, UDP: path, TCPIPv6: path, UDPIPv6: path}
		},
		captureLog: func(context.Context) []string {
			f.logCalls++
			return []string{"XKeen: saved"}
		},
		runCommand: func(_ context.Context, command string, args ...string) ([]string, error) {
			f.runCount++
			f.runPath, f.runArgs = command, args
			f.logAtRun = f.logCalls > 0
			f.applied = true
			return []string{"applied"}, nil
		},
	}
	return f
}

func (f *lanRepairFixture) setHook(t *testing.T, iptables bool) {
	t.Helper()
	value := "false"
	if iptables {
		value = "true"
	}
	content := "#!/bin/sh\n# XKeen: Auto-generated file. DO NOT EDIT!\n" +
		"iptables_supported='" + value + "'\n" +
		"ip6tables_supported='true'\nmode_proxy='Hybrid'\nport_redirect='61219'\nport_tproxy='61219'\n"
	if err := os.WriteFile(f.hook, []byte(content), 0700); err != nil {
		t.Fatal(err)
	}
}

func TestLANRepairRunsHookOnlyForReadyMatchingExistingXray(t *testing.T) {
	f := newLANRepairFixture(t)
	result, err := runLANRepair(context.Background(), f.config, f.deps)
	if err != nil || !result.Recovered || result.Mode != "netfilter_hook" || f.runPath != f.deps.shellPath || len(f.runArgs) != 1 || f.runArgs[0] != f.hook || !f.logAtRun {
		t.Fatalf("hook repair: result=%+v err=%v command=%q args=%q logsSaved=%v", result, err, f.runPath, f.runArgs, f.logAtRun)
	}
	if f.runCount != 1 {
		t.Fatalf("command count=%d", f.runCount)
	}
}

func TestLANRepairRegeneratesStaleHookWithoutStoppingXray(t *testing.T) {
	for _, variant := range []string{"ready_missing", "iptables_baked_off"} {
		t.Run(variant, func(t *testing.T) {
			f := newLANRepairFixture(t)
			if variant == "ready_missing" {
				if err := os.Remove(f.ready); err != nil {
					t.Fatal(err)
				}
			} else {
				f.setHook(t, false)
			}
			result, err := runLANRepair(context.Background(), f.config, f.deps)
			if err != nil || !result.Recovered || result.Mode != "xkeen_start_existing_xray" || f.runPath != f.xkeen || len(f.runArgs) != 1 || f.runArgs[0] != "-start" {
				t.Fatalf("regen repair: result=%+v err=%v command=%q args=%q", result, err, f.runPath, f.runArgs)
			}
		})
	}
}

func TestLANRepairChecksIPv6WhenRouterHasIPv6Address(t *testing.T) {
	f := newLANRepairFixture(t)
	if err := os.WriteFile(filepath.Join(f.procDir, "net", "if_inet6"), []byte("fe800000000000000000000000000001 02 40 20 80 br0\n"), 0600); err != nil {
		t.Fatal(err)
	}
	result, err := runLANRepair(context.Background(), f.config, f.deps)
	if err != nil || !result.Recovered {
		t.Fatalf("IPv6 LAN repair failed: result=%+v err=%v", result, err)
	}
	f = newLANRepairFixture(t)
	if err := os.WriteFile(filepath.Join(f.procDir, "net", "if_inet6"), []byte("fe800000000000000000000000000001 02 40 20 80 br0\n"), 0600); err != nil {
		t.Fatal(err)
	}
	f.deps.readLAN = func(context.Context, string) lanInterceptionStatus {
		return lanInterceptionStatus{
			TCP:     lanInterceptionPath{Known: true, Present: f.applied},
			UDP:     lanInterceptionPath{Known: true, Present: f.applied},
			TCPIPv6: lanInterceptionPath{Known: true, Present: false},
			UDPIPv6: lanInterceptionPath{Known: true, Present: false},
		}
	}
	result, err = runLANRepair(context.Background(), f.config, f.deps)
	if err == nil || result.Recovered || !strings.Contains(err.Error(), "IPv6") {
		t.Fatalf("missing IPv6 rules accepted: result=%+v err=%v", result, err)
	}
}

func TestLANRepairRefusesUnsafePreflightWithoutChangingNetwork(t *testing.T) {
	for _, variant := range []string{"duplicate_main", "missing_tool", "hook_symlink", "busy_xkeen", "socket_missing"} {
		t.Run(variant, func(t *testing.T) {
			f := newLANRepairFixture(t)
			switch variant {
			case "duplicate_main":
				second := filepath.Join(f.procDir, "1600")
				if err := os.MkdirAll(second, 0700); err != nil {
					t.Fatal(err)
				}
				for name, data := range map[string]string{"comm": "xray\n", "cmdline": "/opt/sbin/xray\x00run\x00"} {
					if err := os.WriteFile(filepath.Join(second, name), []byte(data), 0600); err != nil {
						t.Fatal(err)
					}
				}
			case "missing_tool":
				f.deps.findTool = func(name string) string {
					if name == "iptables-restore" {
						return ""
					}
					return "/fake/iptables"
				}
			case "hook_symlink":
				if err := os.Remove(f.hook); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(f.xkeen, f.hook); err != nil {
					t.Fatal(err)
				}
			case "busy_xkeen":
				lock := filepath.Join(filepath.Dir(f.ready), "proxy.mutex.d")
				if err := os.Mkdir(lock, 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(lock, "pid"), []byte("1599"), 0600); err != nil {
					t.Fatal(err)
				}
			case "socket_missing":
				if err := os.WriteFile(filepath.Join(f.procDir, "net", "udp6"), []byte(""), 0600); err != nil {
					t.Fatal(err)
				}
			}
			_, err := runLANRepair(context.Background(), f.config, f.deps)
			if err == nil || f.runCount != 0 {
				t.Fatalf("unsafe preflight accepted: err=%v runs=%d", err, f.runCount)
			}
		})
	}
}

func TestLANRepairDoesNotTrustSuccessfulHookExitWithoutRules(t *testing.T) {
	f := newLANRepairFixture(t)
	f.deps.runCommand = func(context.Context, string, ...string) ([]string, error) {
		f.runCount++
		return nil, nil
	}
	result, err := runLANRepair(context.Background(), f.config, f.deps)
	if err == nil || result.Recovered || f.runCount != 1 || !strings.Contains(err.Error(), "цепочки XKeen") {
		t.Fatalf("silent hook failure accepted: result=%+v err=%v", result, err)
	}
}

func TestLANRepairTrustsRulesAfterXKeenAlreadyRunningExit(t *testing.T) {
	f := newLANRepairFixture(t)
	if err := os.Remove(f.ready); err != nil {
		t.Fatal(err)
	}
	f.deps.runCommand = func(_ context.Context, command string, args ...string) ([]string, error) {
		f.applied = true
		return []string{"Прокси-клиент уже запущен"}, errors.New("xkeen returned already running")
	}
	result, err := runLANRepair(context.Background(), f.config, f.deps)
	if err != nil || !result.Recovered || result.Mode != "xkeen_start_existing_xray" {
		t.Fatalf("verified rules rejected due to existing-Xray exit: result=%+v err=%v", result, err)
	}
}

func TestLANRepairRejectsUnexpectedSecondXrayAfterHook(t *testing.T) {
	f := newLANRepairFixture(t)
	f.deps.runCommand = func(context.Context, string, ...string) ([]string, error) {
		f.applied = true
		second := filepath.Join(f.procDir, "1600")
		if err := os.MkdirAll(second, 0700); err != nil {
			t.Fatal(err)
		}
		for name, data := range map[string]string{"comm": "xray\n", "cmdline": "/opt/sbin/xray\x00run\x00"} {
			if err := os.WriteFile(filepath.Join(second, name), []byte(data), 0600); err != nil {
				t.Fatal(err)
			}
		}
		return nil, nil
	}
	result, err := runLANRepair(context.Background(), f.config, f.deps)
	if err == nil || result.Recovered || !strings.Contains(err.Error(), "дубли") {
		t.Fatalf("duplicate Xray accepted: result=%+v err=%v", result, err)
	}
}

func TestLANRepairActionRequiresExplicitWebAction(t *testing.T) {
	if !webActionAllowed("lan-repair") {
		t.Fatal("manual repair action missing from allowlist")
	}
	if webActionAllowed("lan-repair-now") {
		t.Fatal("unrecognized repair action accepted")
	}
}

func TestLANRepairStartRunsXKeenInForeground(t *testing.T) {
	script := filepath.Join(t.TempDir(), "xkeen")
	if err := os.WriteFile(script, []byte("#!/bin/sh\nprintf '%s\\n' \"$XKEEN_FOREGROUND\"\n"), 0700); err != nil {
		t.Fatal(err)
	}
	lines, err := runLANRepairCommand(context.Background(), script, "-start")
	if err != nil || len(lines) != 1 || lines[0] != "1" {
		t.Fatalf("XKeen start detached or missing foreground marker: lines=%q err=%v", lines, err)
	}
}
