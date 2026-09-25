package hotwatcher

// Optional real-Xray smoke test. It uses loopback-only freedom outbounds to
// isolate API/session behavior from subscription credentials and external servers.
// Set XRAY_INTEGRATION_BINARY=/absolute/path/to/xray to run it.
import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func freePort(t *testing.T) int {
	t.Helper()
	l, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	p := l.Addr().(*net.TCPAddr).Port
	l.Close()
	return p
}
func TestRealXrayHotAPIPreservesEstablishedTCP(t *testing.T) {
	binary := os.Getenv("XRAY_INTEGRATION_BINARY")
	if binary == "" {
		t.Skip("real Xray binary not provided; not a router/UDP test")
	}
	dir := t.TempDir()
	apiPort, proxyPort := freePort(t), freePort(t)
	oldTag, newTag := TagPrefix+"integration-old", TagPrefix+"integration-new"
	config := map[string]any{
		"log":       map[string]any{"loglevel": "none"},
		"api":       map[string]any{"tag": "api", "listen": fmt.Sprintf("127.0.0.1:%d", apiPort), "services": []string{"HandlerService", "RoutingService"}},
		"inbounds":  []any{map[string]any{"tag": "test-http", "listen": "127.0.0.1", "port": proxyPort, "protocol": "http", "settings": map[string]any{}}},
		"outbounds": []any{map[string]any{"tag": oldTag, "protocol": "freedom"}},
		"routing":   map[string]any{"balancers": []any{map[string]any{"tag": "proxy", "selector": []string{TagPrefix}, "strategy": map[string]any{"type": "random"}}}, "rules": []any{map[string]any{"type": "field", "inboundTag": []string{"test-http"}, "balancerTag": "proxy"}}},
	}
	cfg := filepath.Join(dir, "xray.json")
	os.WriteFile(cfg, encode(config), 0600)
	cmd := exec.Command(binary, "run", "-config", cfg)
	cmd.Env = isolatedEnv()
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	if e := cmd.Start(); e != nil {
		t.Fatal(e)
	}
	defer func() { cmd.Process.Kill(); cmd.Wait() }()
	c := Defaults()
	c.XrayBinary = binary
	c.APIAddress = fmt.Sprintf("127.0.0.1:%d", apiPort)
	c.StateDir = dir
	c.AssetDir = dir
	c.APITimeoutSeconds = 2
	x := Xray{c}
	ready := false
	for i := 0; i < 50; i++ {
		if _, e := x.List(); e == nil {
			ready = true
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !ready {
		t.Fatal("real Xray API did not start")
	}
	if e := x.Override(oldTag); e != nil {
		t.Fatal(e)
	}
	echo, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer echo.Close()
	go func() {
		for {
			c, e := echo.Accept()
			if e != nil {
				return
			}
			go func() { defer c.Close(); io.Copy(c, c) }()
		}
	}()
	proxy, e := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", proxyPort))
	if e != nil {
		t.Fatal(e)
	}
	defer proxy.Close()
	proxy.SetDeadline(time.Now().Add(30 * time.Second))
	fmt.Fprintf(proxy, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", echo.Addr(), echo.Addr())
	reader := bufio.NewReader(proxy)
	res, e := http.ReadResponse(reader, &http.Request{Method: "CONNECT"})
	if e != nil || res.StatusCode != 200 {
		t.Fatalf("CONNECT: %v, %v", res, e)
	}
	roundtrip := func(payload string) {
		t.Helper()
		if _, e := io.WriteString(proxy, payload); e != nil {
			t.Fatal(e)
		}
		b := make([]byte, len(payload))
		if _, e := io.ReadFull(reader, b); e != nil || string(b) != payload {
			t.Fatalf("established TCP failed: %v", e)
		}
	}
	roundtrip("before-api-change")
	n := Node{Tag: newTag, Outbound: map[string]any{"tag": newTag, "protocol": "freedom"}}
	if e = x.Add(n); e != nil {
		t.Fatal(e)
	}
	tags, e := x.List()
	if e != nil || !tags[newTag] {
		t.Fatal("new tag not visible", e)
	}
	if e = x.Override(newTag); e != nil {
		t.Fatal(e)
	}
	b, e := x.Balance()
	if e != nil || b.Override != newTag {
		t.Fatal("pin verification failed", e)
	}
	roundtrip("after-api-add-and-switch")
	if e = x.Remove(oldTag); e != nil {
		t.Fatal(e)
	}
	roundtrip("after-api-remove-old")
	t.Logf("Real Xray API add/pin/remove completed; established TCP survived; production test PID=%d", cmd.Process.Pid)
}

// Verify that the existing main--VL selector sees the static copy on a cold
// Xray start. No subscription credentials or production configuration are used.
func TestRealXrayStaticAliasSurvivesRestart(t *testing.T) {
	binary := os.Getenv("XRAY_INTEGRATION_BINARY")
	if binary == "" {
		t.Skip("real Xray binary not provided")
	}
	dir := t.TempDir()
	apiPort := freePort(t)
	cfg := filepath.Join(dir, "xray.json")
	config := map[string]any{
		"log":       map[string]any{"loglevel": "none"},
		"api":       map[string]any{"tag": "api", "listen": fmt.Sprintf("127.0.0.1:%d", apiPort), "services": []string{"HandlerService", "RoutingService"}},
		"outbounds": []any{map[string]any{"tag": staticAlias, "protocol": "freedom"}, map[string]any{"tag": "vless-reality", "protocol": "freedom"}},
		"routing":   map[string]any{"balancers": []any{map[string]any{"tag": "proxy", "selector": []string{"main--VL"}, "strategy": map[string]any{"type": "random"}}}},
	}
	if err := os.WriteFile(cfg, encode(config), 0600); err != nil {
		t.Fatal(err)
	}
	c := Defaults()
	c.XrayBinary, c.APIAddress, c.AssetDir, c.StateDir = binary, fmt.Sprintf("127.0.0.1:%d", apiPort), dir, dir
	x := Xray{c}
	for round := 0; round < 2; round++ {
		cmd := exec.Command(binary, "run", "-config", cfg)
		cmd.Env = isolatedEnv()
		cmd.Stdout, cmd.Stderr = io.Discard, io.Discard
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		ready := false
		for i := 0; i < 50; i++ {
			if tags, err := x.List(); err == nil && tags[staticAlias] {
				ready = true
				break
			}
			time.Sleep(100 * time.Millisecond)
		}
		if !ready {
			cmd.Process.Kill()
			cmd.Wait()
			t.Fatal("Xray did not load static alias")
		}
		balance, err := x.Balance()
		if err != nil || len(balance.Selected) != 1 || balance.Selected[0] != staticAlias {
			cmd.Process.Kill()
			cmd.Wait()
			t.Fatalf("static alias not selected by main--VL after start %d: %+v, %v", round, balance, err)
		}
		cmd.Process.Kill()
		cmd.Wait()
	}
}
