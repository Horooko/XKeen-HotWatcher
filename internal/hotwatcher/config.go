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

var Version = "0.2.5"

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
	GraceSeconds        int      `json:"grace_seconds"`
	AutoGC              bool     `json:"automatic_gc"`
	MaxNodes            int      `json:"max_nodes"`
	MaxRetired          int      `json:"max_retired"`
	PreferredName       string   `json:"preferred_name_contains"`
	SelectionPolicy     string   `json:"selection_policy"`
	CAFile              string   `json:"ca_file"`
	AllowTLS            bool     `json:"allow_tls_nodes"`
	AllowLoopbackHTTP   bool     `json:"allow_loopback_http_for_tests"`
}

func Defaults() Config {
	return Config{AssetDir: "/opt/etc/xray/dat", SubscriptionURLFile: "/opt/etc/hotwatcher/subscription.url", XrayBinary: "/opt/sbin/xray", APIAddress: "127.0.0.1:10085", BalancerTag: "proxy", ConfigDir: "/opt/etc/xray/configs", GeneratedFile: "04_outbounds.main.json", StateDir: "/opt/var/lib/hotwatcher", ProbeURLs: []string{"https://www.gstatic.com/generate_204"}, ProbeTimeoutSeconds: 12, HTTPTimeoutSeconds: 30, APITimeoutSeconds: 10, IntervalSeconds: 1800, ReconcileSeconds: 60, GraceSeconds: 1800, MaxNodes: 64, MaxRetired: 128, SelectionPolicy: "latency"}
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
	if c.IntervalSeconds < 60 || c.ReconcileSeconds < 10 || c.GraceSeconds < 60 || c.MaxNodes < 1 || c.MaxNodes > 256 || c.MaxRetired < 1 || c.MaxRetired > 1024 {
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
	b, e := readPrivate(c.SubscriptionURLFile, 8192)
	if e != nil {
		return "", errors.New("cannot read private subscription URL file")
	}
	s := strings.TrimSpace(string(b))
	if strings.ContainsAny(s, "\r\n\t ") || !allowedURL(s, c.AllowLoopbackHTTP) {
		return "", errors.New("subscription URL must be one HTTPS URL, without userinfo or fragment")
	}
	return s, nil
}
