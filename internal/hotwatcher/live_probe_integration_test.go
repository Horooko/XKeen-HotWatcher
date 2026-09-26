package hotwatcher

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRealXrayLiveProbeUsesMainProcessAndCleansUp(t *testing.T) {
	binary := os.Getenv("XRAY_INTEGRATION_BINARY")
	if binary == "" {
		t.Skip("set XRAY_INTEGRATION_BINARY for live Xray API test")
	}
	dir := t.TempDir()
	apiPort := freePort(t)
	selectedTag := TagPrefix + "integration-selected"
	config := map[string]any{
		"log":       map[string]any{"loglevel": "none"},
		"api":       map[string]any{"tag": "api", "listen": fmt.Sprintf("127.0.0.1:%d", apiPort), "services": []string{"HandlerService", "RoutingService"}},
		"outbounds": []any{map[string]any{"tag": "blocked", "protocol": "blackhole"}, map[string]any{"tag": selectedTag, "protocol": "freedom"}},
		"routing":   map[string]any{"rules": []any{map[string]any{"type": "field", "inboundTag": []string{"unrelated"}, "outboundTag": "blocked"}}},
	}
	path := filepath.Join(dir, "main.json")
	if err := os.WriteFile(path, encode(config), 0600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(binary, "run", "-config", path)
	cmd.Env = isolatedEnv()
	cmd.Stdout, cmd.Stderr = io.Discard, io.Discard
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { cmd.Process.Kill(); cmd.Wait() }()
	c := Defaults()
	c.XrayBinary, c.APIAddress, c.StateDir, c.AssetDir = binary, fmt.Sprintf("127.0.0.1:%d", apiPort), dir, dir
	c.APITimeoutSeconds = 3
	x := Xray{c}
	ready := false
	for i := 0; i < 50; i++ {
		if tags, err := x.List(); err == nil && tags[selectedTag] {
			ready = true
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !ready {
		t.Fatal("main Xray API not ready")
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	defer server.Close()
	x.C.ProbeURLs = []string{server.URL}
	x.C.AllowLoopbackHTTP = true
	for _, node := range []Node{
		{Tag: selectedTag, Outbound: map[string]any{"tag": selectedTag, "protocol": "freedom"}},
		{Tag: TagPrefix + "not-yet-installed", Outbound: map[string]any{"tag": TagPrefix + "not-yet-installed", "protocol": "freedom"}},
	} {
		if err := x.withLiveProbe(node, func(proxyURL, controlURL *url.URL) error {
			transport := &http.Transport{Proxy: http.ProxyURL(proxyURL), DisableKeepAlives: true}
			defer transport.CloseIdleConnections()
			client := &http.Client{Transport: transport, Timeout: 3 * time.Second}
			response, err := client.Get(server.URL)
			if err != nil {
				return err
			}
			response.Body.Close()
			if response.StatusCode != 204 {
				return fmt.Errorf("wrong route: HTTP %d", response.StatusCode)
			}
			controlTransport := &http.Transport{Proxy: http.ProxyURL(controlURL), DisableKeepAlives: true}
			defer controlTransport.CloseIdleConnections()
			controlClient := &http.Client{Transport: controlTransport, Timeout: 3 * time.Second}
			controlRequest, _ := http.NewRequest("GET", server.URL, nil)
			if controlRouteOpens(controlClient, controlRequest) {
				return fmt.Errorf("control route bypassed blackhole")
			}
			proxyURL.User = nil
			unauthenticated, err := client.Get(server.URL)
			if err != nil {
				return err
			}
			unauthenticated.Body.Close()
			if unauthenticated.StatusCode != http.StatusProxyAuthRequired {
				return fmt.Errorf("loopback proxy accepted request without auth: HTTP %d", unauthenticated.StatusCode)
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		if latency, err := x.ProbeLatency(node); err != nil || latency <= 0 {
			t.Fatalf("live latency probe failed: %v, %v", latency, err)
		}
		if report, err := x.URLTest(node, []string{server.URL}); err != nil || !report.Passed || !report.Results[0].OK {
			t.Fatalf("live URL Test failed: %+v, %v", report, err)
		}
	}
	// A pre-existing broad production rule can precede appended probe rules.
	// The blocked control path must expose that interception instead of
	// reporting a healthy key based on traffic that bypassed the test route.
	intercept := map[string]any{"routing": map[string]any{"rules": []any{map[string]any{"type": "field", "ruleTag": "integration-intercept", "ip": []string{"127.0.0.1"}, "outboundTag": selectedTag}}}}
	if _, err := x.run(encode(intercept), "api", "adrules", "--server="+c.APIAddress, "--timeout=3", "-append", "stdin:"); err != nil {
		t.Fatal(err)
	}
	selected := Node{Tag: selectedTag, Outbound: map[string]any{"tag": selectedTag, "protocol": "freedom"}}
	if _, err := x.ProbeLatency(selected); err == nil || !strings.Contains(err.Error(), "обходит") {
		t.Fatalf("intercepted latency probe looked healthy: %v", err)
	}
	if report, err := x.URLTest(selected, []string{server.URL}); err != nil || report.Passed || !strings.Contains(report.Results[0].Reason, "обошёл") {
		t.Fatalf("intercepted URL Test looked healthy: %+v, %v", report, err)
	}
	if _, err := x.api("rmrules", "integration-intercept"); err != nil {
		t.Fatal(err)
	}
	inbounds, err := x.api("lsi")
	if err != nil || strings.Contains(string(inbounds), "hw-live-in-") {
		t.Fatalf("temporary inbound leaked: %v", err)
	}
	rules, err := x.api("lsrules")
	if err != nil || strings.Contains(string(rules), "hw-live-rule-") {
		t.Fatalf("temporary rule leaked: %v", err)
	}
	outbounds, err := x.List()
	if err != nil {
		t.Fatal(err)
	}
	for tag := range outbounds {
		if strings.HasPrefix(tag, "hw-live-out-") {
			t.Fatal("temporary outbound leaked")
		}
	}
}
