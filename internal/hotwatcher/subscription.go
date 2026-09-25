package hotwatcher

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
)

type Node struct {
	Tag       string         `json:"tag"`
	Identity  string         `json:"identity"`
	Name      string         `json:"name"`
	Emergency bool           `json:"emergency,omitempty"`
	Outbound  map[string]any `json:"outbound"`
}
type Parsed struct {
	Nodes   []Node
	Skipped int
}

func tlsConfig(c Config) (*tls.Config, error) {
	roots, e := x509.SystemCertPool()
	if e != nil || roots == nil {
		roots = x509.NewCertPool()
	}
	// Entware CA bundle is not among Go's default paths on every router.
	paths := []string{"/opt/etc/ssl/certs/ca-certificates.crt", "/opt/etc/ssl/cert.pem"}
	if c.CAFile != "" {
		paths = []string{c.CAFile}
	}
	for _, p := range paths {
		if b, e := os.ReadFile(p); e == nil {
			if !roots.AppendCertsFromPEM(b) && c.CAFile != "" {
				return nil, errors.New("custom CA file contains no certificates")
			}
		} else if c.CAFile != "" {
			return nil, errors.New("cannot read configured CA file")
		}
	}
	return &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}, nil
}
func Fetch(c Config) ([]byte, error) {
	s, e := c.URL()
	if e != nil {
		return nil, e
	}
	tc, e := tlsConfig(c)
	if e != nil {
		return nil, e
	}
	tr := &http.Transport{TLSClientConfig: tc, Proxy: nil}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, Timeout: time.Duration(c.HTTPTimeoutSeconds) * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("redirect refused") }}
	req, e := http.NewRequest("GET", s, nil)
	if e != nil {
		return nil, errors.New("invalid subscription request")
	}
	req.Header.Set("User-Agent", "XKeen-Hot-Watcher/"+Version)
	req.Header.Set("Accept", "text/plain, application/json")
	r, e := client.Do(req)
	if e != nil {
		return nil, errors.New("subscription download failed (network, TLS or redirect); URL redacted")
	}
	defer r.Body.Close()
	if r.StatusCode != 200 {
		return nil, fmt.Errorf("subscription HTTP status %d", r.StatusCode)
	}
	b, e := io.ReadAll(io.LimitReader(r.Body, 2*1024*1024+1))
	if e != nil {
		return nil, errors.New("subscription body read failed")
	}
	if len(b) > 2*1024*1024 {
		return nil, errors.New("subscription exceeds 2 MiB")
	}
	return b, nil
}
func decode64(b []byte) ([]byte, error) {
	compact := strings.Map(func(r rune) rune {
		if unicode.IsSpace(r) {
			return -1
		}
		return r
	}, string(b))
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if v, e := enc.DecodeString(compact); e == nil {
			return v, nil
		}
	}
	return nil, errors.New("invalid base64 subscription")
}
func Parse(b []byte, c Config) (Parsed, error) {
	p := Parsed{}
	b = bytes.TrimSpace(bytes.TrimPrefix(b, []byte{0xef, 0xbb, 0xbf}))
	if len(b) == 0 {
		return p, errors.New("empty subscription: keeping old configuration")
	}
	if bytes.HasPrefix(b, []byte("{")) || bytes.HasPrefix(b, []byte("[")) {
		return p, errors.New("Xray/Clash JSON is not accepted: use plain or base64 VLESS URI subscription")
	}
	if !bytes.Contains(b, []byte("://")) {
		var e error
		b, e = decode64(b)
		if e != nil {
			return p, e
		}
	}
	seen := map[string]bool{}
	for n, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if len(line) > 32768 {
			return p, errors.New("subscription line exceeds 32 KiB")
		}
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if !strings.HasPrefix(line, "vless://") {
			if strings.HasPrefix(line, "trojan://") || strings.HasPrefix(line, "vmess://") || strings.HasPrefix(line, "ss://") || strings.HasPrefix(line, "ssr://") || strings.HasPrefix(line, "hysteria2://") || strings.HasPrefix(line, "hy2://") {
				p.Skipped++
				continue
			}
			return p, fmt.Errorf("unrecognized subscription line %d (content redacted)", n+1)
		}
		node, e := parseVLESS(line, c)
		if e != nil {
			return p, fmt.Errorf("VLESS line %d: %w", n+1, e)
		}
		if !seen[node.Tag] {
			p.Nodes = append(p.Nodes, node)
			seen[node.Tag] = true
		}
	}
	if len(p.Nodes) == 0 {
		return p, errors.New("no supported VLESS nodes: old configuration is kept")
	}
	if len(p.Nodes) > c.MaxNodes {
		return p, errors.New("subscription has too many nodes")
	}
	sort.Slice(p.Nodes, func(i, j int) bool { return p.Nodes[i].Tag < p.Nodes[j].Tag })
	return p, nil
}
func parseVLESS(s string, c Config) (Node, error) {
	n := Node{}
	u, e := url.Parse(s)
	if e != nil || u.Hostname() == "" || u.User == nil {
		return n, errors.New("invalid VLESS URI")
	}
	if _, has := u.User.Password(); has {
		return n, errors.New("password-style userinfo is unsupported")
	}
	id := u.User.Username()
	plain := strings.ReplaceAll(id, "-", "")
	if len(plain) != 32 {
		return n, errors.New("UUID must have 32 hexadecimal digits")
	}
	if _, e := hex.DecodeString(plain); e != nil {
		return n, errors.New("invalid UUID")
	}
	if len(id) != 36 || id[8] != '-' || id[13] != '-' || id[18] != '-' || id[23] != '-' {
		return n, errors.New("UUID must use canonical hyphenated format")
	}
	if u.Path != "" && u.Path != "/" {
		return n, errors.New("unexpected URI path")
	}
	port, e := strconv.Atoi(u.Port())
	if e != nil || port < 1 || port > 65535 {
		return n, errors.New("explicit valid server port required")
	}
	q, e := url.ParseQuery(u.RawQuery)
	if e != nil {
		return n, errors.New("invalid query encoding")
	}
	allowed := map[string]bool{"encryption": true, "flow": true, "type": true, "security": true, "sni": true, "serverName": true, "fp": true, "pbk": true, "sid": true, "spx": true, "alpn": true, "path": true, "host": true, "serviceName": true, "mode": true, "authority": true, "headerType": true}
	for k, v := range q {
		if !allowed[k] || len(v) != 1 {
			return n, errors.New("unsupported or repeated VLESS parameter; see docs/SUBSCRIPTIONS.md")
		}
	}
	enc := q.Get("encryption")
	if enc != "" && enc != "none" {
		return n, errors.New("VLESS encryption other than none is not supported in v0.1")
	}
	network := q.Get("type")
	if network == "" || network == "tcp" {
		network = "raw"
	}
	if network != "raw" && network != "ws" && network != "grpc" && network != "xhttp" {
		return n, errors.New("unsupported transport")
	}
	if h := q.Get("headerType"); h != "" && h != "none" {
		return n, errors.New("transport header obfuscation is unsupported")
	}
	security := q.Get("security")
	if security != "reality" && security != "tls" {
		return n, errors.New("only explicit reality/tls nodes are accepted")
	}
	if security == "tls" && !c.AllowTLS {
		return n, errors.New("TLS node encountered; allow_tls_nodes is false")
	}
	flow := q.Get("flow")
	if flow != "" && flow != "xtls-rprx-vision" {
		return n, errors.New("unsupported VLESS flow")
	}
	if flow != "" && network != "raw" {
		return n, errors.New("Vision flow is supported only with raw/tcp")
	}
	sni := q.Get("sni")
	if sni == "" {
		sni = q.Get("serverName")
	} else if v := q.Get("serverName"); v != "" && v != sni {
		return n, errors.New("conflicting SNI fields")
	}
	if sni == "" {
		if security == "reality" {
			return n, errors.New("Reality SNI required")
		}
		sni = u.Hostname()
	}
	fp := q.Get("fp")
	if fp == "" {
		fp = "chrome"
	}
	ss := map[string]any{"network": network, "security": security}
	if security == "reality" {
		pbk, e := base64.RawURLEncoding.DecodeString(q.Get("pbk"))
		if e != nil || len(pbk) != 32 {
			return n, errors.New("Reality public key must encode 32 bytes")
		}
		sid := q.Get("sid")
		if len(sid) > 16 || len(sid)%2 != 0 {
			return n, errors.New("invalid Reality short ID length")
		}
		if _, e := hex.DecodeString(sid); e != nil {
			return n, errors.New("invalid Reality short ID")
		}
		r := map[string]any{"serverName": sni, "fingerprint": fp, "publicKey": q.Get("pbk"), "shortId": sid}
		if q.Get("spx") != "" {
			r["spiderX"] = q.Get("spx")
		}
		if q.Get("alpn") != "" {
			return n, errors.New("ALPN on Reality URI is not supported by this converter")
		}
		ss["realitySettings"] = r
	} else {
		r := map[string]any{"serverName": sni, "fingerprint": fp, "allowInsecure": false}
		if a := q.Get("alpn"); a != "" {
			r["alpn"] = strings.Split(a, ",")
		}
		ss["tlsSettings"] = r
	}
	switch network {
	case "raw":
		if q.Get("path") != "" || q.Get("host") != "" || q.Get("serviceName") != "" || q.Get("mode") != "" || q.Get("authority") != "" {
			return n, errors.New("raw transport has incompatible parameters")
		}
	case "ws":
		if q.Get("serviceName") != "" || q.Get("mode") != "" || q.Get("authority") != "" {
			return n, errors.New("WebSocket has incompatible parameters")
		}
		ss["wsSettings"] = map[string]any{"path": q.Get("path"), "host": q.Get("host")}
	case "grpc":
		if q.Get("path") != "" {
			return n, errors.New("gRPC uses serviceName, not path")
		}
		mode := q.Get("mode")
		if mode != "" && mode != "gun" && mode != "multi" {
			return n, errors.New("unsupported gRPC mode")
		}
		authority := q.Get("authority")
		if authority == "" {
			authority = q.Get("host")
		}
		ss["grpcSettings"] = map[string]any{"serviceName": q.Get("serviceName"), "authority": authority, "multiMode": mode == "multi"}
	case "xhttp":
		if q.Get("serviceName") != "" || q.Get("authority") != "" {
			return n, errors.New("XHTTP has incompatible parameters")
		}
		mode := q.Get("mode")
		if mode == "" {
			mode = "auto"
		}
		if mode != "auto" && mode != "packet-up" && mode != "stream-up" && mode != "stream-one" {
			return n, errors.New("unsupported XHTTP mode")
		}
		ss["xhttpSettings"] = map[string]any{"path": q.Get("path"), "host": q.Get("host"), "mode": mode}
	}
	n.Outbound = map[string]any{"protocol": "vless", "settings": map[string]any{"vnext": []any{map[string]any{"address": u.Hostname(), "port": port, "users": []any{map[string]any{"id": strings.ToLower(id), "encryption": "none", "flow": flow}}}}}, "streamSettings": ss}
	n.Tag = TagPrefix + digest(encode(n.Outbound))[:24]
	n.Outbound["tag"] = n.Tag
	// Endpoint identity deliberately excludes credentials, Reality key and display name.
	n.Identity = digest(encode([]any{strings.ToLower(u.Hostname()), port, network, security, sni, q.Get("path"), q.Get("serviceName")}))
	n.Name = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, u.Fragment)
	if len(n.Name) > 160 {
		n.Name = n.Name[:160]
	}
	return n, nil
}
func sameNodes(a, b []Node) bool {
	if len(a) != len(b) {
		return false
	}
	m := map[string]bool{}
	for _, n := range a {
		m[n.Tag] = true
	}
	for _, n := range b {
		if !m[n.Tag] {
			return false
		}
	}
	return true
}
func findNode(nodes []Node, tag string) (Node, bool) {
	for _, n := range nodes {
		if n.Tag == tag {
			return n, true
		}
	}
	return Node{}, false
}
func nodeIndex(nodes []Node, tag string) int {
	for i := range nodes {
		if nodes[i].Tag == tag {
			return i
		}
	}
	return -1
}
func configBytes(nodes []Node, selected string) []byte {
	outs := make([]map[string]any, 0, len(nodes))
	if n, ok := findNode(nodes, selected); ok {
		outs = append(outs, n.Outbound)
	}
	for _, n := range nodes {
		if n.Tag != selected {
			outs = append(outs, n.Outbound)
		}
	}
	return encode(map[string]any{"outbounds": outs})
}

// Raw JSON decoding is used only for local, operator-owned configuration, never for subscriptions.
func decodeObject(b []byte) (map[string]any, error) {
	var v map[string]any
	e := json.Unmarshal(b, &v)
	if e != nil || v == nil {
		return nil, errors.New("strict JSON object required")
	}
	return v, nil
}
