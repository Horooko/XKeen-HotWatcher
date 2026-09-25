package hotwatcher

import (
	"encoding/binary"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func dnsTestConfig(t *testing.T) Config {
	t.Helper()
	base := t.TempDir()
	c := Defaults()
	c.ConfigDir = filepath.Join(base, "configs")
	c.StateDir = filepath.Join(base, "state")
	if err := os.MkdirAll(c.ConfigDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(c.StateDir, 0700); err != nil {
		t.Fatal(err)
	}
	return c
}

func TestDNSPreparePreservesSettingsAndRejectsComplexRules(t *testing.T) {
	c := dnsTestConfig(t)
	path := filepath.Join(c.ConfigDir, "03_dns.json")
	original := []byte(`{
  // Existing Xray DNS options must survive.
  "dns": {
    "tag": "dns-via-proxy",
    "hosts": {"service.example": "192.0.2.1", "dns.google": ["8.8.8.8", "8.8.4.4"]},
    "servers": ["https://old.example/dns-query",],
    "queryStrategy": "UseIPv4",
  },
  "log": {"loglevel": "warning"},
}`)
	if err := os.WriteFile(path, original, 0600); err != nil {
		t.Fatal(err)
	}
	src, err := findDNSSource(c)
	if err != nil {
		t.Fatal(err)
	}
	prepared, servers, err := prepareDNS(src, dnsCandidates)
	if err != nil {
		t.Fatal(err)
	}
	if len(servers) != 2 || strings.Contains(string(prepared), "yandex") || strings.Contains(string(prepared), "old.example") {
		t.Fatalf("unexpected DNS servers: %s", prepared)
	}
	var root map[string]json.RawMessage
	var dns map[string]json.RawMessage
	if err := json.Unmarshal(prepared, &root); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(root["dns"], &dns); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"tag", "queryStrategy", "hosts", "servers", "enableParallelQuery"} {
		if len(dns[key]) == 0 {
			t.Fatalf("missing %s", key)
		}
	}
	if !strings.Contains(string(dns["hosts"]), "service.example") || string(dns["tag"]) != `"dns-via-proxy"` || string(dns["enableParallelQuery"]) != "true" {
		t.Fatalf("DNS settings changed unexpectedly: %s", dns)
	}
	if len(root["log"]) == 0 {
		t.Fatal("unrelated top-level setting lost")
	}
	src.dns["servers"] = json.RawMessage(`[{"address":"8.8.8.8","domains":["domain:example.org"]}]`)
	if _, _, err := prepareDNS(src, dnsCandidates); err == nil {
		t.Fatal("per-domain DNS rules were replaced")
	}
	for _, old := range []string{`["localhost"]`, `["fakedns"]`, `["192.168.1.1"]`} {
		src.dns["servers"] = json.RawMessage(old)
		if _, _, err := prepareDNS(src, dnsCandidates); err == nil {
			t.Fatalf("special resolver %s was replaced", old)
		}
	}
}

func TestDNSFindRefusesAmbiguousSources(t *testing.T) {
	c := dnsTestConfig(t)
	for _, name := range []string{"02_dns.json", "03_dns.json"} {
		if err := os.WriteFile(filepath.Join(c.ConfigDir, name), []byte(`{"dns":{"servers":["1.1.1.1"]}}`), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := findDNSSource(c); err == nil {
		t.Fatal("ambiguous DNS sources accepted")
	}
}

func TestDNSSourceChangedDuringProbeIsRejected(t *testing.T) {
	c := dnsTestConfig(t)
	path := filepath.Join(c.ConfigDir, "03_dns.json")
	if err := os.WriteFile(path, []byte(`{"dns":{"servers":["1.1.1.1"]}}`), 0600); err != nil {
		t.Fatal(err)
	}
	src, err := findDNSSource(c)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(`{"dns":{"servers":["9.9.9.9"]}}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := dnsSourceUnchanged(src); err == nil {
		t.Fatal("outside edit during DNS test was ignored")
	}
}

func TestDNSAutoOffRestoresExactBytesAndRejectsOutsideEdit(t *testing.T) {
	c := dnsTestConfig(t)
	e := New(c)
	path := filepath.Join(c.ConfigDir, "03_dns.json")
	original := []byte("{\n  // preserve this comment on rollback\n  \"dns\": {\"servers\": [\"1.1.1.1\"]}\n}\n")
	applied := []byte(`{"dns":{"servers":["https://1.1.1.1/dns-query"]}}`)
	if err := os.WriteFile(path, applied, 0600); err != nil {
		t.Fatal(err)
	}
	journal := dnsJournal{Schema: 1, Path: path, Original: original, OriginalHash: digest(original), AppliedHash: digest(applied)}
	if err := atomicWrite(e.dnsJournalPath(), encode(journal), 0600); err != nil {
		t.Fatal(err)
	}
	outside := []byte(`{"dns":{"servers":["https://custom.example/dns-query"]}}`)
	if err := os.WriteFile(path, outside, 0600); err != nil {
		t.Fatal(err)
	}
	if err := e.DNSAutoOff(); err == nil {
		t.Fatal("outside edit was overwritten")
	}
	if err := os.WriteFile(path, applied, 0600); err != nil {
		t.Fatal(err)
	}
	if err := e.DNSAutoOff(); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil || string(got) != string(original) {
		t.Fatalf("original DNS fragment not restored: %v, %s", err, got)
	}
	if _, err := os.Lstat(e.dnsJournalPath()); !os.IsNotExist(err) {
		t.Fatalf("backup still present: %v", err)
	}
}

func TestDNSAnswerMustContainMatchingSuccessfulReply(t *testing.T) {
	answer := make([]byte, 12)
	binary.BigEndian.PutUint16(answer[0:2], 42)
	binary.BigEndian.PutUint16(answer[2:4], 0x8180)
	binary.BigEndian.PutUint16(answer[4:6], 1)
	binary.BigEndian.PutUint16(answer[6:8], 1)
	if !validDNSAnswer(answer, 42) || validDNSAnswer(answer, 43) {
		t.Fatal("DNS ID mismatch was not detected")
	}
	binary.BigEndian.PutUint16(answer[2:4], 0x8182)
	if validDNSAnswer(answer, 42) {
		t.Fatal("SERVFAIL accepted")
	}
}

func TestDNSProbeConfigUsesBuiltinDNSOnLoopback(t *testing.T) {
	dns := map[string]json.RawMessage{
		"servers": json.RawMessage(`["https://1.1.1.1/dns-query"]`),
		"tag":     json.RawMessage(`"dns-via-proxy"`),
	}
	outbound := map[string]any{"tag": "selected-vless", "protocol": "vless", "settings": map[string]any{}}
	b, err := dnsProbeConfig(dns, outbound, 14053)
	if err != nil {
		t.Fatal(err)
	}
	var config struct {
		Inbounds []struct {
			Listen   string `json:"listen"`
			Protocol string `json:"protocol"`
		} `json:"inbounds"`
		Outbounds []struct {
			Tag      string `json:"tag"`
			Protocol string `json:"protocol"`
		} `json:"outbounds"`
		Routing struct {
			Rules []struct {
				InboundTag  []string `json:"inboundTag"`
				OutboundTag string   `json:"outboundTag"`
			} `json:"rules"`
		} `json:"routing"`
	}
	if err := json.Unmarshal(b, &config); err != nil {
		t.Fatal(err)
	}
	if len(config.Inbounds) != 1 || config.Inbounds[0].Listen != "127.0.0.1" || config.Inbounds[0].Protocol != "dokodemo-door" || len(config.Outbounds) != 2 || config.Outbounds[1].Protocol != "dns" || len(config.Routing.Rules) != 2 || config.Routing.Rules[1].OutboundTag != "selected-vless" {
		t.Fatalf("DNS probe could bypass built-in DNS or bind outside loopback: %s", b)
	}
}
