package hotwatcher

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// Run with HOTWATCHER_TEST_XRAY=/path/to/xray to check the generated DNS
// fragment against an installed Xray and make a real isolated DoH query.
func TestGeneratedDNSWithInstalledXray(t *testing.T) {
	binary := os.Getenv("HOTWATCHER_TEST_XRAY")
	if binary == "" {
		t.Skip("set HOTWATCHER_TEST_XRAY to run the installed-Xray DNS check")
	}
	c := dnsTestConfig(t)
	c.XrayBinary = binary
	c.AssetDir = filepath.Dir(binary)
	src, err := findDNSSource(c)
	if err != nil {
		t.Fatal(err)
	}
	prepared, _, err := prepareDNS(src, dnsCandidates)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateDNSStaged(c, src.path, prepared); err != nil {
		t.Fatal(err)
	}
	root, err := parseDNSFragment(prepared)
	if err != nil {
		t.Fatal(err)
	}
	var dns map[string]json.RawMessage
	if err := json.Unmarshal(root["dns"], &dns); err != nil {
		t.Fatal(err)
	}
	direct := map[string]any{"tag": "hw-dns-direct", "protocol": "freedom", "settings": map[string]any{}}
	if _, err := New(c).probeDNSRoute(dns, direct); err != nil {
		t.Fatalf("prepared DNS did not answer through installed Xray: %v", err)
	}
	if err := os.WriteFile(src.path, prepared, 0600); err != nil {
		t.Fatal(err)
	}
	e := New(c)
	e.R = &fakeRuntime{}
	verification, err := e.DNSVerify()
	if err != nil || !verification.Direct.Success || verification.SelectedVLESS.Checked {
		t.Fatalf("DNS verification claimed an untested VLESS route: %+v, %v", verification, err)
	}
}

func TestDNSAutoOnOffWithInstalledXray(t *testing.T) {
	binary := os.Getenv("HOTWATCHER_TEST_XRAY")
	if binary == "" {
		t.Skip("set HOTWATCHER_TEST_XRAY to run the installed-Xray DNS check")
	}
	c := dnsTestConfig(t)
	c.XrayBinary = binary
	c.AssetDir = filepath.Dir(binary)
	e := New(c)
	change, err := e.DNSAutoOn()
	if err != nil {
		t.Fatalf("DNS auto refused reachable trusted providers: %v, probes: %+v", err, change.Probes)
	}
	if len(change.Servers) != 2 {
		t.Fatalf("DNS auto did not select both trusted providers: %+v", change)
	}
	status, err := e.DNSStatus()
	if err != nil || !status.Managed || !status.ParallelQueries {
		t.Fatalf("DNS auto state not recorded: %+v, %v", status, err)
	}
	if err := e.DNSAutoOff(); err != nil {
		t.Fatalf("DNS auto rollback failed: %v", err)
	}
	if _, err := os.Lstat(change.ConfigFile); !os.IsNotExist(err) {
		t.Fatalf("generated DNS fragment remained after rollback: %v", err)
	}
}
