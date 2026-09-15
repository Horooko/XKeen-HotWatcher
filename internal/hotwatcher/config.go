package hotwatcher

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

var Version = "0.2.7"

const TagPrefix = "main--VL--hw-"

type Config struct {
	AssetDir            string   `json:"xray_asset_dir"`
	SubscriptionURLFile string   `json:"subscription_url_file"`
	XrayBinary          string   `json:"xray_binary"`
	APIAddress          string   `json:"api_address"`
	BalancerTag         string   `json:"balancer_tag"`
	ConfigDir           string   `json:"xray_config_dir"`
	GeneratedFile       string   `json:"generated_file"`
	StateDir            string   `json:"state_dir"`
	ProbeURLs           []string `json:"probe_urls"`
	ProbeTimeoutSeconds int      `json:"probe_timeout_seconds"`
	HTTPTimeoutSeconds  int      `json:"http_timeout_seconds"`
	APITimeoutSeconds   int      `json:"api_timeout_seconds"`
	IntervalSeconds     int      `json:"interval_seconds"`
	ReconcileSeconds    int      `json:"reconcile_seconds"`
	KeyCheckSeconds     int      `json:"key_check_interval_seconds"`
	GraceSeconds        int      `json:"grace_seconds"`
	AutoGC              bool     `json:"automatic_gc"`
	MaxNodes            int      `json:"max_nodes"`
	MaxRetired          int      `json:"max_retired"`
	PreferredName       string   `json:"preferred_name_contains"`
	SelectionPolicy     string   `json:"selection_policy"`
	StaticFallbackTag   string   `json:"static_fallback_tag"`
	CAFile              string   `json:"ca_file"`
	AllowTLS            bool     `json:"allow_tls_nodes"`
	AllowLoopbackHTTP   bool     `json:"allow_loopback_http_for_tests"`
}

func Defaults() Config {
	return Config{AssetDir: "/opt/etc/xray/dat", SubscriptionURLFile: "/opt/etc/hotwatcher/subscription.url", XrayBinary: "/opt/sbin/xray", APIAddress: "127.0.0.1:10085", BalancerTag: "proxy", ConfigDir: "/opt/etc/xray/configs", GeneratedFile: "04_outbounds.main.json", StateDir: "/opt/var/lib/hotwatcher", ProbeURLs: []string{"https://www.gstatic.com/generate_204"}, ProbeTimeoutSeconds: 12, HTTPTimeoutSeconds: 30, APITimeoutSeconds: 10, IntervalSeconds: 1800, ReconcileSeconds: 60, KeyCheckSeconds: 300, GraceSeconds: 1800, MaxNodes: 64, MaxRetired: 128, SelectionPolicy: "latency", StaticFallbackTag: "vless-reality"}
}
func LoadConfig(path string) (Config, error) {
	c := Defaults()
	b, err := readPrivate(path, 1024*1024)
	if err != nil {
		return c, fmt.Errorf("read configuration: %w", err)
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if err = d.Decode(&c); err != nil {
		return c, errors.New("invalid configuration JSON or unknown field")
	}
	if d.Decode(new(any)) != io.EOF {
		return c, errors.New("configuration contains trailing data")
	}
	return c, c.Validate()
}
func (c Config) Validate() error {
	for _, p := range []string{c.SubscriptionURLFile, c.XrayBinary, c.ConfigDir, c.StateDir, c.AssetDir} {
		if !filepath.IsAbs(p) {
			return errors.New("all filesystem paths must be absolute")
		}
	}
	if filepath.Base(c.GeneratedFile) != c.GeneratedFile || !strings.HasPrefix(c.GeneratedFile, "04_outbounds.") || !strings.HasSuffix(c.GeneratedFile, ".json") || c.GeneratedFile == "04_outbounds.json" {
		return errors.New("generated_file must be a subscription fragment named 04_outbounds.NAME.json (not the static 04_outbounds.json)")
	}
	h, p, e := net.SplitHostPort(c.APIAddress)
	if e != nil || p == "" || net.ParseIP(h) == nil || !net.ParseIP(h).IsLoopback() {
		return errors.New("API must use a loopback IP and port (127.0.0.1:10085)")
	}
	portNumber, portError := strconv.Atoi(p)
	if portError != nil || portNumber < 1 || portNumber > 65535 {
		return errors.New("invalid API port")
	}
	if c.BalancerTag == "" || len(c.BalancerTag) > 128 {
		return errors.New("invalid balancer_tag")
	}
	if c.SelectionPolicy != "latency" && c.SelectionPolicy != "sticky" {
		return errors.New("selection_policy must be latency or sticky")
	}
	if c.StaticFallbackTag == "" || len(c.StaticFallbackTag) > 128 || strings.HasPrefix(c.StaticFallbackTag, "main--VL") || c.StaticFallbackTag == "direct" || c.StaticFallbackTag == "block" {
		return errors.New("static_fallback_tag must name a non-owned proxy outbound")
	}
	if c.IntervalSeconds < 60 || c.ReconcileSeconds < 10 || c.KeyCheckSeconds < 60 || c.KeyCheckSeconds > 3600 || c.GraceSeconds < 60 || c.MaxNodes < 1 || c.MaxNodes > 256 || c.MaxRetired < 1 || c.MaxRetired > 1024 {
		return errors.New("configuration limits out of range")
	}
	for _, n := range []int{c.ProbeTimeoutSeconds, c.HTTPTimeoutSeconds, c.APITimeoutSeconds} {
		if n < 1 || n > 120 {
			return errors.New("timeouts must be 1..120 seconds")
		}
	}
	if len(c.ProbeURLs) == 0 || len(c.ProbeURLs) > 4 {
		return errors.New("1..4 probe URLs required")
	}
	for _, s := range c.ProbeURLs {
		if !allowedURL(s, c.AllowLoopbackHTTP) {
			return errors.New("probe URL must use HTTPS (no credentials or fragment)")
		}
	}
	out := filepath.Join(c.ConfigDir, c.GeneratedFile)
	if strings.HasPrefix(filepath.Clean(c.SubscriptionURLFile), filepath.Clean(c.ConfigDir)+string(os.PathSeparator)) || c.StateDir == c.ConfigDir || strings.HasPrefix(c.StateDir, filepath.Clean(c.ConfigDir)+string(os.PathSeparator)) || out == c.SubscriptionURLFile {
		return errors.New("state and secrets must be outside the Xray config directory")
	}
	return nil
}
func allowedURL(s string, local bool) bool {
	u, e := url.Parse(s)
	if e != nil || u.Hostname() == "" || u.User != nil || u.Fragment != "" {
		return false
	}
	if u.Scheme == "https" {
		return true
	}
	ip := net.ParseIP(u.Hostname())
	return local && u.Scheme == "http" && ip != nil && ip.IsLoopback()
}
func (c Config) URL() (string, error) {
	if s, found, err := c.apiURL(); found || err != nil {
		return s, err
	}
	b, e := readPrivate(c.SubscriptionURLFile, 8192)
	if e != nil {
		return "", errors.New("cannot read private subscription URL file")
	}
	return c.validateURL(strings.TrimSpace(string(b)))
}

func (c Config) APIURLPath() string {
	return filepath.Join(c.ConfigDir, "07_hotwatcher_api.json")
}

func (c Config) validateURL(s string) (string, error) {
	if strings.ContainsAny(s, "\r\n\t ") || !allowedURL(s, c.AllowLoopbackHTTP) {
		return "", errors.New("subscription URL must be one HTTPS URL, without userinfo or fragment")
	}
	return s, nil
}

// Xray ignores the Hot Watcher top-level block, while this program reads it.
// An absent block preserves compatibility with installations predating v0.2.5.
func (c Config) apiURL() (string, bool, error) {
	path := c.APIURLPath()
	b, err := readLimited(path, 1024*1024)
	if os.IsNotExist(err) {
		return "", false, nil
	}
	if err != nil {
		return "", false, errors.New("cannot read Hot Watcher API fragment")
	}
	var fragment struct {
		HotWatcher struct {
			SubscriptionURL string `json:"subscription_url"`
		} `json:"hotwatcher"`
	}
	if err = json.Unmarshal(b, &fragment); err != nil {
		return "", false, errors.New("invalid Hot Watcher API fragment JSON")
	}
	if fragment.HotWatcher.SubscriptionURL == "" {
		return "", false, nil
	}
	if _, err = readPrivate(path, 1024*1024); err != nil {
		return "", true, errors.New("API fragment containing subscription URL must have permissions 0600 or 0400")
	}
	s, err := c.validateURL(fragment.HotWatcher.SubscriptionURL)
	return s, true, err
}

// SetSubscriptionURL preserves the existing Xray API object and writes a
// private legacy copy required by updater binaries installed before v0.2.5.
func (c Config) SetSubscriptionURL(s string) error {
	s, err := c.validateURL(strings.TrimSpace(s))
	if err != nil {
		return err
	}
	path := c.APIURLPath()
	b, err := readLimited(path, 1024*1024)
	if err != nil {
		return errors.New("cannot read Hot Watcher API fragment; run setup-api.sh first")
	}
	var fragment map[string]json.RawMessage
	if err = json.Unmarshal(b, &fragment); err != nil || fragment == nil || len(fragment["api"]) == 0 {
		return errors.New("API fragment must be a JSON object containing the existing Xray api")
	}
	var api map[string]any
	if err = json.Unmarshal(fragment["api"], &api); err != nil || api == nil {
		return errors.New("invalid Xray api object; fragment left unchanged")
	}
	fragment["hotwatcher"], _ = json.Marshal(map[string]string{"subscription_url": s})
	// Keep the old updater's required file before switching the canonical source.
	if err = atomicWrite(c.SubscriptionURLFile, []byte(s+"\n"), 0600); err != nil {
		return errors.New("cannot save private updater-compatible subscription URL")
	}
	if err = atomicWrite(path, encode(fragment), 0600); err != nil {
		return errors.New("cannot save Hot Watcher API fragment")
	}
	return nil
}

func (c Config) MigrateSubscriptionURL() error {
	b, err := readPrivate(c.SubscriptionURLFile, 8192)
	if err != nil {
		return errors.New("cannot read old private subscription URL")
	}
	return c.SetSubscriptionURL(strings.TrimSpace(string(b)))
}
