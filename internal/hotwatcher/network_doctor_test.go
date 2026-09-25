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
