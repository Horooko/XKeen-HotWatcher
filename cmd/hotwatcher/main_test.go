package main

import (
	"encoding/json"
	hw "local/xkeen-hot-watcher/internal/hotwatcher"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
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
