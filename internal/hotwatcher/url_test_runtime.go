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

// URLTest checks every configured site through this key.
func (x Xray) URLTest(n Node, sites []string) (URLTestReport, error) {
	return x.URLTestWithProgress(n, sites, nil)
}

func (x Xray) URLTestWithProgress(n Node, sites []string, progress func(URLTestReport)) (URLTestReport, error) {
	economy, err := x.C.EconomyChecks()
	if err != nil {
		return URLTestReport{}, err
	}
	if economy {
		return x.urlTestLiveWithProgress(n, sites, progress)
	}
	return x.urlTestIsolatedWithProgress(n, sites, progress)
}

func (x Xray) urlTestLiveWithProgress(n Node, sites []string, progress func(URLTestReport)) (URLTestReport, error) {
	report, err := startURLTestReport(n, sites, progress, "main_xray")
	if err != nil {
		return report, err
	}
	deadline := time.Duration(x.C.ProbeTimeoutSeconds*((len(sites)+2)/3)+8) * time.Second
	ctx, cancel := context.WithTimeout(context.Background(), deadline)
	defer cancel()
	err = x.withLiveProbe(n, func(proxy, control *url.URL) error {
		var testErr error
		report, testErr = x.runURLTestRequests(ctx, report, sites, progress, proxy, control)
		return testErr
	})
	return report, err
}

func startURLTestReport(n Node, sites []string, progress func(URLTestReport), mode string) (URLTestReport, error) {
	report := URLTestReport{Tag: n.Tag, Mode: mode, Time: time.Now().UTC(), ProgressKnown: true, Results: make([]URLTestResult, len(sites))}
	if len(sites) == 0 || len(sites) > 12 {
		return report, errors.New("URL Test: неверное количество сайтов")
	}
	for i, site := range sites {
		report.Results[i] = URLTestResult{Site: site, Reason: "проверка не завершена"}
	}
	if progress != nil {
		progress(cloneURLTestReport(report))
	}
	return report, nil
}

func (x Xray) urlTestIsolatedWithProgress(n Node, sites []string, progress func(URLTestReport)) (URLTestReport, error) {
	report, err := startURLTestReport(n, sites, progress, "isolated")
	if err != nil {
		return report, err
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
	probe, err := startAuxiliaryXray(cmd)
	if err != nil {
		return report, fmt.Errorf("URL Test: %w", err)
	}
	defer probe.stop()
	address := fmt.Sprintf("127.0.0.1:%d", port)
	ready := false
	for i := 0; i < 50; i++ {
		select {
		case <-probe.done:
			return report, probe.unexpectedExit("URL Test: временный Xray завершился при запуске")
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
	proxy, _ := url.Parse("http://" + address)
	report, err = x.runURLTestRequests(ctx, report, sites, progress, proxy, nil)
	if err != nil {
		return report, err
	}
	select {
	case <-probe.done:
		return report, probe.unexpectedExit("URL Test: временный Xray завершился до окончания проверки")
	default:
	}
	return report, nil
}

func (x Xray) runURLTestRequests(ctx context.Context, report URLTestReport, sites []string, progress func(URLTestReport), proxy, control *url.URL) (URLTestReport, error) {
	tls, err := tlsConfig(x.C)
	if err != nil {
		return report, err
	}
	transport := &http.Transport{Proxy: http.ProxyURL(proxy), TLSClientConfig: tls, DisableKeepAlives: true, MaxConnsPerHost: 3}
	defer transport.CloseIdleConnections()
	var controlClient *http.Client
	if control != nil {
		controlTransport := &http.Transport{Proxy: http.ProxyURL(control), TLSClientConfig: tls, DisableKeepAlives: true, MaxConnsPerHost: 3}
		defer controlTransport.CloseIdleConnections()
		controlClient = &http.Client{Transport: controlTransport, Timeout: 3 * time.Second}
	}
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
	if controlClient != nil {
		controlClient.CheckRedirect = client.CheckRedirect
	}
	var wg sync.WaitGroup
	var resultsMu sync.Mutex
	publish := func(i int, item URLTestResult) {
		resultsMu.Lock()
		item.Completed = true
		report.Results[i] = item
		if progress != nil {
			progress(cloneURLTestReport(report))
		}
		resultsMu.Unlock()
	}
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
				publish(i, item)
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
					if controlClient != nil && controlRouteOpens(controlClient, request) {
						item.Reason = "маршрут основного Xray обошёл проверяемый ключ"
					} else {
						item.OK, item.LatencyMS = true, &milliseconds
					}
				} else {
					item.Reason = "HTTP-ошибка"
				}
			}
			publish(i, item)
		}(i, site)
	}
	wg.Wait()
	report.Passed = true
	for _, item := range report.Results {
		if !item.OK {
			report.Passed = false
		}
	}
	return report, nil
}

func cloneURLTestReport(report URLTestReport) URLTestReport {
	report.Results = append([]URLTestResult(nil), report.Results...)
	return report
}
