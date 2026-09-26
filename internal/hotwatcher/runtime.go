package hotwatcher

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

type Balance struct {
	Override string   `json:"override"`
	Selected []string `json:"selected"`
}
type Runtime interface {
	List() (map[string]bool, error)
	Balance() (Balance, error)
	Add(Node) error
	Remove(string) error
	Override(string) error
	Validate([]Node, string) error
	Probe(Node) error
	ProbeLatency(Node) (time.Duration, error)
	URLTest(Node, []string) (URLTestReport, error)
}
type Xray struct{ C Config }

// No shell execution. All API commands are fixed here; user data travels in stdin.
// Clear inherited config-directory variables for isolated validation/probe processes.
func isolatedEnv() []string {
	env := []string{}
	for _, e := range os.Environ() {
		k := strings.ToLower(strings.SplitN(e, "=", 2)[0])
		if k == "xray.location.asset" || k == "xray_location_asset" || strings.Contains(k, "confdir") || k == "xray.location.config" || k == "xray_location_config" || k == "v2ray.location.config" || k == "v2ray_location_config" {
			continue
		}
		env = append(env, e)
	}
	return env
}
func (x Xray) run(input []byte, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(x.C.APITimeoutSeconds+5)*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, x.C.XrayBinary, args...)
	cmd.Env = append(isolatedEnv(), "XRAY_LOCATION_ASSET="+x.C.AssetDir)
	if input != nil {
		cmd.Stdin = bytes.NewReader(input)
	}
	// API ListOutbounds can contain credential material; never print or persist it.
	var out cappedBuffer
	cmd.Stdout = &out
	cmd.Stderr = io.Discard
	var commandErr error
	if len(args) > 0 && args[0] == "run" {
		probe, startErr := startAuxiliaryXray(cmd)
		if startErr != nil {
			return nil, startErr
		}
		commandErr = probe.result("Xray command failed; raw output suppressed to protect credentials")
	} else {
		commandErr = cmd.Run()
	}
	if commandErr != nil {
		if ctx.Err() != nil {
			return nil, errors.New("Xray command timeout")
		}
		if errors.Is(commandErr, errAuxiliaryMemory) {
			return nil, commandErr
		}
		return nil, errors.New("Xray command failed; raw output suppressed to protect credentials")
	}
	if out.Exceeded {
		return nil, errors.New("Xray command output limit exceeded")
	}
	return out.Bytes(), nil
}

type cappedBuffer struct {
	bytes.Buffer
	Exceeded bool
}

func (b *cappedBuffer) Write(p []byte) (int, error) {
	n := len(p)
	remain := 8*1024*1024 - b.Len()
	if remain > 0 {
		if len(p) > remain {
			b.Buffer.Write(p[:remain])
			b.Exceeded = true
		} else {
			b.Buffer.Write(p)
		}
	} else {
		b.Exceeded = true
	}
	return n, nil
}
func (x Xray) api(command string, extra ...string) ([]byte, error) {
	a := []string{"api", command, "--server=" + x.C.APIAddress, fmt.Sprintf("--timeout=%d", x.C.APITimeoutSeconds)}
	return x.run(nil, append(a, extra...)...)
}
func (x Xray) List() (map[string]bool, error) {
	b, e := x.api("lso")
	if e != nil {
		return nil, fmt.Errorf("API lso: %w", e)
	}
	var v struct {
		Outbounds []struct {
			Tag string `json:"tag"`
		} `json:"outbounds"`
	}
	if e = json.Unmarshal(b, &v); e != nil {
		return nil, errors.New("API lso returned an unsupported response")
	}
	tags := map[string]bool{}
	for _, o := range v.Outbounds {
		if o.Tag != "" {
			tags[o.Tag] = true
		}
	}
	return tags, nil
}

var balanceRow = regexp.MustCompile(`^\s*\d+\s+(.+?)\s*$`)

func parseBalance(b []byte) (Balance, error) {
	r := Balance{}
	var obj struct {
		Balancer struct {
			Override struct {
				Target string `json:"target"`
			} `json:"override"`
			Principle struct {
				Tag []string `json:"tag"`
			} `json:"principleTarget"`
		} `json:"balancer"`
	}
	if json.Unmarshal(b, &obj) == nil && bytes.Contains(b, []byte(`"balancer"`)) {
		r.Override = obj.Balancer.Override.Target
		r.Selected = obj.Balancer.Principle.Tag
		return r, nil
	}
	section := ""
	recognized := false
	for _, l := range strings.Split(string(b), "\n") {
		if strings.Contains(l, "Selecting Override:") {
			section = "override"
			recognized = true
			continue
		}
		if strings.Contains(l, "Selects:") {
			section = "selects"
			recognized = true
			continue
		}
		if m := balanceRow.FindStringSubmatch(l); len(m) == 2 {
			tag := strings.TrimSpace(m[1])
			if tag == "" {
				continue
			}
			if section == "override" {
				r.Override = tag
			} else if section == "selects" {
				r.Selected = append(r.Selected, tag)
			}
		}
	}
	if !recognized {
		return r, errors.New("unsupported API bi output; no changes applied")
	}
	return r, nil
}
func (x Xray) Balance() (Balance, error) {
	b, e := x.api("bi", x.C.BalancerTag)
	if e != nil {
		return Balance{}, fmt.Errorf("API bi: %w", e)
	}
	return parseBalance(b)
}
func (x Xray) Add(n Node) error {
	a := []string{"api", "ado", "--server=" + x.C.APIAddress, fmt.Sprintf("--timeout=%d", x.C.APITimeoutSeconds), "stdin:"}
	_, e := x.run(configBytes([]Node{n}, n.Tag), a...)
	return e
}
func (x Xray) Remove(tag string) error {
	if !strings.HasPrefix(tag, TagPrefix) {
		return errors.New("refusing to remove an unmanaged outbound")
	}
	_, e := x.api("rmo", tag)
	return e
}
func (x Xray) Override(tag string) error {
	if tag == "" {
		_, e := x.api("bo", "-b", x.C.BalancerTag, "-r")
		return e
	}
	_, e := x.api("bo", "-b", x.C.BalancerTag, tag)
	return e
}
func (x Xray) Validate(nodes []Node, selected string) error {
	dir, e := os.MkdirTemp(x.C.StateDir, "validate-")
	if e != nil {
		return e
	}
	defer os.RemoveAll(dir)
	entries, e := os.ReadDir(x.C.ConfigDir)
	if e != nil {
		return errors.New("cannot read Xray configuration directory")
	}
	count := 0
	for _, f := range entries {
		if f.Name() == x.C.GeneratedFile || !strings.HasSuffix(strings.ToLower(f.Name()), ".json") {
			continue
		}
		b, e := readLimited(filepath.Join(x.C.ConfigDir, f.Name()), 8*1024*1024)
		if e != nil {
			return errors.New("cannot copy local Xray JSON for validation")
		}
		if e = os.WriteFile(filepath.Join(dir, f.Name()), b, 0600); e != nil {
			return e
		}
		count++
	}
	if count == 0 {
		return errors.New("no existing Xray config fragments: refusing to validate against an empty installation")
	}
	if e = os.WriteFile(filepath.Join(dir, x.C.GeneratedFile), configBytes(nodes, selected), 0600); e != nil {
		return e
	}
	_, e = x.run(nil, "run", "-test", "-confdir", dir)
	if e != nil {
		return fmt.Errorf("staged full Xray configuration failed validation: %w", e)
	}
	return nil
}

// Probe a candidate using a short-lived, isolated Xray process. It has no API,
// TProxy, production inbounds or netfilter integration. Only this child is killed.
func (x Xray) Probe(n Node) error {
	_, err := x.ProbeLatency(n)
	return err
}

func (x Xray) ProbeLatency(n Node) (time.Duration, error) {
	economy, err := x.C.EconomyChecks()
	if err != nil {
		return 0, err
	}
	if economy {
		return x.probeLatencyLive(n)
	}
	return x.probeLatencyIsolated(n)
}

func (x Xray) probeLatencyLive(n Node) (time.Duration, error) {
	var latency time.Duration
	err := x.withLiveProbe(n, func(proxy, control *url.URL) error {
		tc, err := tlsConfig(x.C)
		if err != nil {
			return err
		}
		transport := &http.Transport{Proxy: http.ProxyURL(proxy), TLSClientConfig: tc, DisableKeepAlives: true}
		defer transport.CloseIdleConnections()
		controlTransport := &http.Transport{Proxy: http.ProxyURL(control), TLSClientConfig: tc, DisableKeepAlives: true}
		defer controlTransport.CloseIdleConnections()
		client := &http.Client{Transport: transport, Timeout: time.Duration(x.C.ProbeTimeoutSeconds) * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("probe redirect refused") }}
		controlClient := &http.Client{Transport: controlTransport, Timeout: 3 * time.Second, CheckRedirect: client.CheckRedirect}
		for _, target := range x.C.ProbeURLs {
			req, err := http.NewRequest("GET", target, nil)
			if err != nil {
				continue
			}
			req.Header.Set("User-Agent", "HotWatcher-Probe/"+Version)
			started := time.Now()
			res, err := client.Do(req)
			if err != nil {
				continue
			}
			io.Copy(io.Discard, io.LimitReader(res.Body, 4096))
			res.Body.Close()
			if res.StatusCode == 204 {
				measured := time.Since(started)
				if controlRouteOpens(controlClient, req) {
					return errors.New("маршрутизация основного Xray обходит проверяемый ключ")
				}
				latency = measured
				return nil
			}
		}
		return errors.New("ключ не открыл HTTPS-адрес проверки со статусом 204")
	})
	return latency, err
}

func (x Xray) probeLatencyIsolated(n Node) (time.Duration, error) {
	ln, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		return 0, errors.New("cannot reserve loopback probe port")
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	dir, e := os.MkdirTemp(x.C.StateDir, "probe-")
	if e != nil {
		return 0, e
	}
	defer os.RemoveAll(dir)
	cfg := map[string]any{"log": map[string]any{"loglevel": "none"}, "inbounds": []any{map[string]any{"tag": "hw-probe", "listen": "127.0.0.1", "port": port, "protocol": "http", "settings": map[string]any{}}}, "outbounds": []any{n.Outbound}}
	file := filepath.Join(dir, "probe.json")
	if e = os.WriteFile(file, encode(cfg), 0600); e != nil {
		return 0, e
	}
	duration := time.Duration(x.C.ProbeTimeoutSeconds*len(x.C.ProbeURLs)+5) * time.Second
	ctx, cancel := context.WithTimeout(context.Background(), duration)
	defer cancel()
	cmd := exec.CommandContext(ctx, x.C.XrayBinary, "run", "-config", file)
	cmd.Env = append(isolatedEnv(), "XRAY_LOCATION_ASSET="+x.C.AssetDir)
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	probe, e := startAuxiliaryXray(cmd)
	if e != nil {
		return 0, fmt.Errorf("cannot start isolated candidate probe: %w", e)
	}
	defer probe.stop()
	address := fmt.Sprintf("127.0.0.1:%d", port)
	ready := false
	for i := 0; i < 50; i++ {
		select {
		case <-probe.done:
			return 0, probe.unexpectedExit("isolated candidate probe exited at startup")
		default:
		}
		conn, err := net.DialTimeout("tcp", address, 100*time.Millisecond)
		if err == nil {
			conn.Close()
			ready = true
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !ready {
		return 0, errors.New("isolated probe port did not become ready")
	}
	proxy, _ := url.Parse("http://" + address)
	tc, e := tlsConfig(x.C)
	if e != nil {
		return 0, e
	}
	tr := &http.Transport{Proxy: http.ProxyURL(proxy), TLSClientConfig: tc, DisableKeepAlives: true}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, Timeout: time.Duration(x.C.ProbeTimeoutSeconds) * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("probe redirect refused") }}
	for _, target := range x.C.ProbeURLs {
		req, e := http.NewRequestWithContext(ctx, "GET", target, nil)
		if e != nil {
			continue
		}
		req.Header.Set("User-Agent", "HotWatcher-Probe/"+Version)
		started := time.Now()
		res, e := client.Do(req)
		if e != nil {
			continue
		}
		io.Copy(io.Discard, io.LimitReader(res.Body, 4096))
		res.Body.Close()
		if res.StatusCode == 204 {
			select {
			case <-probe.done:
				return 0, probe.unexpectedExit("candidate probe exited unexpectedly")
			default:
				return time.Since(started), nil
			}
		}
	}
	select {
	case <-probe.done:
		return 0, probe.unexpectedExit("isolated candidate probe exited during network checks")
	default:
	}
	return 0, errors.New("candidate could not reach any HTTPS probe endpoint with status 204")
}
