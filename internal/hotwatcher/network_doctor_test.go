package hotwatcher

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNetworkDoctorReportsStagesWithoutSubscriptionSecret(t *testing.T) {
	c := dnsTestConfig(t)
	c.SubscriptionURLFile = filepath.Join(c.StateDir, "subscription.url")
	secret := "https://subscription.example/private-token-123"
	if err := os.WriteFile(c.SubscriptionURLFile, []byte(secret+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	e := New(c)
	e.R = &fakeRuntime{tags: map[string]bool{}, failList: true, failBalance: true}
	e.Fetcher = func(Config) ([]byte, error) { return nil, errors.New("failed: " + secret) }
	var stages []string
	report := e.DoctorNetworkWithProgress(func(check NetworkCheck) { stages = append(stages, check.Name) })
	encoded, _ := json.Marshal(report)
	if report.Healthy || report.SecretsPrinted || strings.Contains(string(encoded), secret) {
		t.Fatalf("unsafe or misleading diagnosis: %s", encoded)
	}
	if len(stages) != len(report.Checks) || len(stages) < 5 {
		t.Fatalf("missing progress stages: %v", stages)
	}
}

func TestNetworkDoctorTreatsSingleHTTPSProbeFailureAsInconclusive(t *testing.T) {
	e, runtime, _ := setupEngine(t)
	if err := e.Sync(true); err != nil {
		t.Fatal(err)
	}
	e.C.SubscriptionURLFile = filepath.Join(e.C.StateDir, "subscription.url")
	if err := os.WriteFile(e.C.SubscriptionURLFile, []byte("https://example.com/subscription\n"), 0600); err != nil {
		t.Fatal(err)
	}
	e.C.XrayBinary = filepath.Join(e.C.StateDir, "xray")
	if err := os.WriteFile(e.C.XrayBinary, []byte("stub"), 0700); err != nil {
		t.Fatal(err)
	}
	runtime.failProbe = true
	report := e.DoctorNetwork()
	var failedProbe bool
	for _, check := range report.Checks {
		if check.Name == "selected_key_https_probe" {
			failedProbe = !check.OK && strings.Contains(check.Detail, "не доказывает неисправность")
		}
	}
	if !failedProbe || !report.Healthy {
		t.Fatalf("single endpoint failure was treated as a broken key: %+v", report)
	}
}
