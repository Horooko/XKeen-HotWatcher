package hotwatcher

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestDNSProviderDefaultsAndPersistence(t *testing.T) {
	e := New(dnsTestConfig(t))
	providers, ids, err := e.DNSProviderCatalog()
	if err != nil {
		t.Fatal(err)
	}
	if len(providers) != len(dnsCandidates) || len(ids) != len(providers)-1 {
		t.Fatalf("unexpected default provider catalog: %+v, %+v", providers, ids)
	}
	for _, p := range providers {
		if p.ID == "yandex" && p.Selected {
			t.Fatal("Yandex must be opt-in")
		}
		if p.ID != "yandex" && !p.Selected {
			t.Fatalf("%s not selected by default", p.ID)
		}
	}
	if err := e.SaveDNSProviderSelection([]string{"google", "cloudflare"}, true); err != nil {
		t.Fatal(err)
	}
	_, got, err := e.DNSProviderCatalog()
	if err != nil || !reflect.DeepEqual(got, []string{"cloudflare", "google"}) {
		t.Fatalf("preferences not restored: %v %+v", err, got)
	}
	if err := e.SaveDNSProviderSelection([]string{"cloudflare", "unknown"}, true); err == nil {
		t.Fatal("unknown provider was accepted")
	}
	if err := e.SaveDNSProviderSelection([]string{"cloudflare", "cloudflare"}, true); err == nil {
		t.Fatal("duplicate provider was accepted")
	}
	if err := e.SaveDNSProviderSelection([]string{"google", "cloudflare"}, false); err != nil {
		t.Fatal(err)
	}
	if auto, err := e.DNSAutoSelectionEnabled(); err != nil || auto {
		t.Fatalf("auto selection preference not restored: %v %v", auto, err)
	}
	if _, err := os.Stat(e.dnsProviderPreferencesPath()); err != nil {
		t.Fatal(err)
	}
}

func TestDNSCommentOnlySourcePointsToGeneratedFragment(t *testing.T) {
	c := dnsTestConfig(t)
	original := []byte("{\n  // XKeen example comment\n}\n")
	if err := os.WriteFile(filepath.Join(c.ConfigDir, "02_dns.json"), original, 0600); err != nil {
		t.Fatal(err)
	}
	status, err := New(c).DNSStatus()
	if err != nil {
		t.Fatal(err)
	}
	if status.ConfigFile != filepath.Join(c.ConfigDir, "02_hotwatcher_dns.json") || status.GeneratedConfigFile != status.ConfigFile {
		t.Fatalf("comment-only source should not be modified: %+v", status)
	}
	if got, err := os.ReadFile(filepath.Join(c.ConfigDir, "02_dns.json")); err != nil || string(got) != string(original) {
		t.Fatalf("original fragment modified: %v %s", err, got)
	}
}

func TestDNSAutoOffRecoversInterruptedReconfiguration(t *testing.T) {
	c := dnsTestConfig(t)
	e := New(c)
	path := filepath.Join(c.ConfigDir, "02_hotwatcher_dns.json")
	original, old, next := []byte(`{"dns":{"servers":["8.8.8.8"]}}`), []byte(`{"dns":{"servers":["https+local://1.1.1.1/dns-query"]}}`), []byte(`{"dns":{"servers":["https+local://8.8.8.8/dns-query"]}}`)
	for _, current := range [][]byte{old, next} {
		if err := os.WriteFile(path, current, 0600); err != nil {
			t.Fatal(err)
		}
		journal := dnsJournal{Schema: 1, Path: path, Original: original, OriginalHash: digest(original), AppliedHash: digest(next), PreviousAppliedHash: digest(old)}
		if err := atomicWrite(e.dnsJournalPath(), encode(journal), 0600); err != nil {
			t.Fatal(err)
		}
		if err := e.DNSAutoOff(); err != nil {
			t.Fatalf("interrupted reconfiguration not recoverable: %v", err)
		}
		got, err := os.ReadFile(path)
		if err != nil || string(got) != string(original) {
			t.Fatalf("original DNS not restored: %v %s", err, got)
		}
	}
}

func TestFastestDNSCandidatesRequireActualDNSAnswers(t *testing.T) {
	a, b, c, d := 30.0, 60.0, 15.0, 5.0
	probes := []DNSProbeResult{
		{ID: "cloudflare", Success: true, MedianMS: &a},
		{ID: "google", Success: true, MedianMS: &b},
		{ID: "adguard", Success: true, MedianMS: &c},
		{ID: "yandex", Success: true, MedianMS: &d},
	}
	ids := defaultDNSProviderIDs()
	candidates, err := dnsCandidatesForIDs(ids)
	if err != nil {
		t.Fatal(err)
	}
	chosen := fastestDNSCandidates(candidates, probes, 3)
	got := []string{}
	for _, candidate := range chosen {
		got = append(got, candidate.ID)
	}
	if !reflect.DeepEqual(got, []string{"adguard", "cloudflare", "google"}) {
		t.Fatalf("selected wrong candidates: %+v", got)
	}
	got = got[:0]
	for _, candidate := range selectedDNSCandidates(candidates, probes, false) {
		got = append(got, candidate.ID)
	}
	if !reflect.DeepEqual(got, []string{"cloudflare", "google", "adguard"}) {
		t.Fatalf("manual selection order changed: %+v", got)
	}
	// A fast TCP/TLS handshake is insufficient; a failed DNS answer cannot win.
	probes[0].Success = false
	got = got[:0]
	for _, candidate := range fastestDNSCandidates(candidates, probes, 3) {
		got = append(got, candidate.ID)
	}
	if !reflect.DeepEqual(got, []string{"adguard", "google"}) {
		t.Fatalf("failed responder selected: %+v", got)
	}
}
