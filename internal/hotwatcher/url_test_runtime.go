package hotwatcher

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"
)

// URLTest starts one isolated Xray for this key, then checks every configured
// site through its loopback HTTP proxy. No production listener is changed.
func (x Xray) URLTest(n Node, sites []string) (URLTestReport, error) {
	report := URLTestReport{Tag: n.Tag, Time: time.Now().UTC(), Results: make([]URLTestResult, len(sites))}
	if len(sites) == 0 || len(sites) > 12 {
		return report, errors.New("URL Test: неверное количество сайтов")
	}
	for i, site := range sites {
		report.Results[i] = URLTestResult{Site: site, Reason: "проверка не завершена"}
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return report, errors.New("URL Test: нет свободного локального порта")
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()
	dir, err := os.MkdirTemp(x.C.StateDir, "url-test-")
	if err != nil {
		return report, err
	}
	defer os.RemoveAll(dir)
	config := map[string]any{
		"log":       map[string]any{"loglevel": "none"},
		"inbounds":  []any{map[string]any{"tag": "hw-url-test", "listen": "127.0.0.1", "port": port, "protocol": "http", "settings": map[string]any{}}},
		"outbounds": []any{n.Outbound},
	}
	path := filepath.Join(dir, "probe.json")
	if err := os.WriteFile(path, encode(config), 0600); err != nil {
		return report, err
	}
	// Three requests run at once so a single slow site cannot make a routine
	// key switch last six sequential timeouts.
	deadline := time.Duration(x.C.ProbeTimeoutSeconds*((len(sites)+2)/3)+8) * time.Second
	ctx, cancel := context.WithTimeout(context.Background(), deadline)
	defer cancel()
	cmd := exec.CommandContext(ctx, x.C.XrayBinary, "run", "-config", path)
	cmd.Env = append(isolatedEnv(), "XRAY_LOCATION_ASSET="+x.C.AssetDir)
	cmd.Stdout, cmd.Stderr = io.Discard, io.Discard
	if err := cmd.Start(); err != nil {
		return report, errors.New("URL Test: не удалось запустить временный Xray")
	}
	done := make(chan struct{})
	go func() { _ = cmd.Wait(); close(done) }()
	defer func() {
		_ = cmd.Process.Kill()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
		}
	}()
	address := fmt.Sprintf("127.0.0.1:%d", port)
	ready := false
	for i := 0; i < 50; i++ {
		select {
		case <-done:
			return report, errors.New("URL Test: временный Xray завершился при запуске")
		default:
		}
		conn, dialErr := net.DialTimeout("tcp", address, 100*time.Millisecond)
		if dialErr == nil {
			conn.Close()
			ready = true
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !ready {
		return report, errors.New("URL Test: временный Xray не открыл локальный порт")
	}
	tls, err := tlsConfig(x.C)
	if err != nil {
		return report, err
	}
	proxy, _ := url.Parse("http://" + address)
	transport := &http.Transport{Proxy: http.ProxyURL(proxy), TLSClientConfig: tls, DisableKeepAlives: true, MaxConnsPerHost: 3}
	defer transport.CloseIdleConnections()
	client := &http.Client{
		Transport: transport,
		Timeout:   time.Duration(x.C.ProbeTimeoutSeconds) * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 4 || len(via) == 0 || req.URL.Scheme != "https" || req.URL.User != nil || req.URL.Port() != "" {
				return errors.New("unsafe redirect")
			}
			origin := via[0].URL.Hostname()
			if req.URL.Hostname() != origin && req.URL.Hostname() != "www."+origin {
				return errors.New("redirect left test site")
			}
			return nil
		},
	}
	var wg sync.WaitGroup
	sem := make(chan struct{}, 3)
	for i, site := range sites {
		wg.Add(1)
		go func(i int, site string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			item := URLTestResult{Site: site}
			request, requestErr := http.NewRequestWithContext(ctx, http.MethodGet, site, nil)
			if requestErr != nil {
				item.Reason = "неверный адрес"
				report.Results[i] = item
				return
			}
			request.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux aarch64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36")
			request.Header.Set("Accept", "text/html,application/xhtml+xml,*/*;q=0.8")
			started := time.Now()
			response, requestErr := client.Do(request)
			if requestErr != nil {
				item.Reason = "сеть, TLS или таймаут"
			} else {
				item.Status = response.StatusCode
				_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
				_ = response.Body.Close()
				if response.StatusCode >= 200 && response.StatusCode < 300 {
					milliseconds := float64(time.Since(started).Microseconds()) / 1000
					item.OK, item.LatencyMS = true, &milliseconds
				} else {
					item.Reason = "HTTP-ошибка"
				}
			}
			report.Results[i] = item
		}(i, site)
	}
	wg.Wait()
	report.Passed = true
	for _, item := range report.Results {
		if !item.OK {
			report.Passed = false
		}
	}
	select {
	case <-done:
		return report, errors.New("URL Test: временный Xray завершился до окончания проверки")
	default:
	}
	return report, nil
}
