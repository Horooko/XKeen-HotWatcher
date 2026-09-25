package main

import (
	"encoding/json"
	"io"
	hw "local/xkeen-hot-watcher/internal/hotwatcher"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func invoke(t *testing.T, args ...string) error {
	t.Helper()
	old := os.Args
	os.Args = append([]string{"hotwatcher"}, args...)
	defer func() { os.Args = old }()
	return run()
}
func TestCLIInformationalCommands(t *testing.T) {
	for _, c := range []string{"version", "help", "config-example"} {
		if e := invoke(t, c); e != nil {
			t.Fatal(e)
		}
	}
	if e := invoke(t); e != nil {
		t.Fatal(e)
	}
}

func TestHelpKeepsAdvancedCommandsOutOfBasicView(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	old := os.Stdout
	os.Stdout = w
	usage()
	w.Close()
	os.Stdout = old
	b, err := io.ReadAll(r)
	r.Close()
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	if !strings.Contains(s, "hard-sync") || !strings.Contains(s, "Остановить XKeen") || strings.Contains(s, "recover|abort") {
		t.Fatal("basic help is missing the recovery command or contains advanced commands")
	}
}

func TestKeysOutputStartsWithActiveKey(t *testing.T) {
	activePing, otherPing := 27.5, 61.2
	checkAgo, selectedAgo := 15*time.Minute+4*time.Second, 2*time.Hour
	success := true
	report := hw.KeysReport{Keys: []hw.KeyMeasurement{{Name: "FI", Tag: "active", Active: true, PingMS: &activePing}, {Name: "DE", Tag: "other", PingMS: &otherPing}}, LastCheckAgo: &checkAgo, LastCheckSuccess: &success, SelectedAgo: &selectedAgo}
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	old := os.Stdout
	os.Stdout = w
	printKeys(report)
	w.Close()
	os.Stdout = old
	b, err := io.ReadAll(r)
	r.Close()
	if err != nil {
		t.Fatal(err)
	}
	lines := string(b)
	if !strings.HasPrefix(lines, "Активный ключ: FI [active] — 27.5 мс\n") || !strings.Contains(lines, "С последней проверки подписки: 15 мин 4 сек (успешно)") || !strings.Contains(lines, "С последней смены ключа: 2 ч 0 мин") || !strings.Contains(lines, "- DE [other] — 61.2 мс") {
		t.Fatal(lines)
	}
}
func TestInventoryShowsFetchedButUnappliedKey(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	old := os.Stdout
	os.Stdout = w
	printKeyInventory(hw.KeyInventory{Keys: []hw.KeyInventoryEntry{
		{FetchedKey: hw.FetchedKey{Name: "старый", Tag: "old"}, Selected: true, Applied: true},
		{FetchedKey: hw.FetchedKey{Name: "новый", Tag: "new", Checked: true}, Latest: true},
	}})
	w.Close()
	os.Stdout = old
	b, err := io.ReadAll(r)
	r.Close()
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	if !strings.Contains(s, "новый [new] — не применён, не прошёл проверку без VPN") || !strings.Contains(s, "старый [old]") {
		t.Fatal(s)
	}
}
func testConfig(t *testing.T) string {
	t.Helper()
	d := t.TempDir()
	c := hw.Defaults()
	c.StateDir = filepath.Join(d, "state")
	c.ConfigDir = filepath.Join(d, "configs")
	c.SubscriptionURLFile = filepath.Join(d, "subscription.url")
	c.XrayBinary = "/nonexistent/xray"
	c.AssetDir = d
	os.Mkdir(c.ConfigDir, 0700)
	os.WriteFile(c.SubscriptionURLFile, []byte("https://example.invalid/subscription"), 0600)
	p := filepath.Join(d, "config.json")
	b, _ := json.Marshal(c)
	os.WriteFile(p, b, 0600)
	return p
}
func TestCLIHoldStatusAndErrors(t *testing.T) {
	c := testConfig(t)
	for _, args := range [][]string{{"hold", "on"}, {"status"}, {"nodes"}, {"reconcile"}, {"hold", "off"}} {
		if e := invoke(t, append([]string{"--config", c}, args...)...); e != nil {
			t.Fatal(args, e)
		}
	}
	for _, args := range [][]string{{"hold", "bad"}, {"select"}, {"sync"}, {"doctor"}, {"unknown"}} {
		if e := invoke(t, append([]string{"--config", c}, args...)...); e == nil {
			t.Fatal("expected error", args)
		}
	}
}
func TestKeysDoesNotWaitForSubscriptionLock(t *testing.T) {
	path := testConfig(t)
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var c hw.Config
	if err = json.Unmarshal(b, &c); err != nil {
		t.Fatal(err)
	}
	err = hw.WithLock(c, func() error {
		keyErr := invoke(t, "--config", path, "keys")
		if keyErr == nil || strings.Contains(keyErr.Error(), "another Hot Watcher operation") {
			t.Fatalf("keys should reach its read-only state check: %v", keyErr)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
func TestCLIPlanLoopbackSubscription(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("vless://00000000-0000-4000-8000-000000000001@node.example.invalid:443?security=reality&type=tcp&sni=example.invalid&pbk=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA#Test"))
	}))
	defer srv.Close()
	path := testConfig(t)
	b, _ := os.ReadFile(path)
	var c hw.Config
	json.Unmarshal(b, &c)
	c.AllowLoopbackHTTP = true
	os.WriteFile(c.SubscriptionURLFile, []byte(srv.URL), 0600)
	b, _ = json.Marshal(c)
	os.WriteFile(path, b, 0600)
	if e := invoke(t, "--config", path, "plan"); e != nil {
		t.Fatal(e)
	}
}
