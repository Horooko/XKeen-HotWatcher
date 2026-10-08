package hotwatcher

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestIsXrayServerCommandAcceptsOnlyProductionRun(t *testing.T) {
	const binary = "/opt/sbin/xray"
	const configDir = "/opt/etc/xray/configs"
	const stateDir = "/opt/var/lib/hotwatcher"
	for _, tc := range []struct {
		name string
		args []string
		want bool
	}{
		{"xkeen run", []string{binary, "run"}, true},
		{"production confdir", []string{binary, "run", "-confdir", configDir}, true},
		{"production confdir equals", []string{binary, "-confdir=" + configDir}, true},
		{"api helper", []string{binary, "api", "lso"}, false},
		{"xkeen validation", []string{binary, "run", "-test"}, false},
		{"temporary file outside state", []string{binary, "run", "-config", "/tmp/isolated-xray.json"}, false},
		{"temporary file inside state", []string{binary, "run", "-config=" + stateDir + "/probe-1/config.json"}, false},
		{"temporary confdir", []string{binary, "run", "-confdir", "/tmp/xray-check"}, false},
		{"similar confdir", []string{binary, "run", "-confdir=" + configDir + "-other"}, false},
		{"missing confdir path", []string{binary, "run", "-confdir"}, false},
		{"wrong program", []string{"/bin/sh", "run"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := IsXrayServerCommand(tc.args, binary, configDir, stateDir); got != tc.want {
				t.Fatalf("IsXrayServerCommand(%q) = %v, want %v", tc.args, got, tc.want)
			}
		})
	}
}

func TestStatusWithProductionXraySkipsAPIWhenOnlyHelpersRun(t *testing.T) {
	root := t.TempDir()
	c := Defaults()
	c.StateDir = filepath.Join(root, "state")
	c.ConfigDir = filepath.Join(root, "configs")
	if err := os.Mkdir(c.StateDir, 0700); err != nil {
		t.Fatal(err)
	}
	procDir := filepath.Join(root, "proc")
	if err := os.Mkdir(procDir, 0700); err != nil {
		t.Fatal(err)
	}
	for pid, args := range map[string][]string{
		"101": {c.XrayBinary, "api", "lso", "--server=127.0.0.1:10085"},
		"102": {c.XrayBinary, "run", "-config", "/tmp/isolated-xray.json"},
	} {
		dir := filepath.Join(procDir, pid)
		if err := os.Mkdir(dir, 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "cmdline"), []byte(strings.Join(args, "\x00")+"\x00"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	status, err := StatusWithProductionXray(c, procDir)
	if err != nil {
		t.Fatal(err)
	}
	if status["api_reachable"] != false || status["balancer_api_reachable"] != false || status["adopted"] != false {
		t.Fatalf("offline status unexpectedly queried API: %+v", status)
	}
	status, err = StatusWithProductionXray(c, filepath.Join(root, "missing"))
	if err != nil || status["api_reachable"] != false {
		t.Fatalf("uncertain process state queried API: %+v, %v", status, err)
	}
}
