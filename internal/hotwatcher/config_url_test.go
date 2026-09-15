package hotwatcher

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestAPIFragmentSubscriptionURLMigrationAndPrecedence(t *testing.T) {
	dir := t.TempDir()
	c := Defaults()
	c.ConfigDir = filepath.Join(dir, "configs")
	c.SubscriptionURLFile = filepath.Join(dir, "subscription.url")
	if err := os.Mkdir(c.ConfigDir, 0700); err != nil {
		t.Fatal(err)
	}
	legacy := "https://legacy.example.invalid/private"
	if err := os.WriteFile(c.SubscriptionURLFile, []byte(legacy+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	api := `{"api":{"tag":"hotwatcher-api","listen":"127.0.0.1:10085","services":["HandlerService","RoutingService"]}}`
	if err := os.WriteFile(c.APIURLPath(), []byte(api), 0644); err != nil {
		t.Fatal(err)
	}
	if got, err := c.URL(); err != nil || got != legacy {
		t.Fatal(got, err)
	}
	if err := c.MigrateSubscriptionURL(); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(c.APIURLPath())
	if err != nil {
		t.Fatal(err)
	}
	var fragment map[string]json.RawMessage
	if err = json.Unmarshal(b, &fragment); err != nil || len(fragment["api"]) == 0 || len(fragment["hotwatcher"]) == 0 {
		t.Fatal("API or subscription block lost", err)
	}
	if info, err := os.Stat(c.APIURLPath()); err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("API fragment containing URL is not private", err)
	}
	newURL := "https://new.example.invalid/private"
	if err := c.SetSubscriptionURL(newURL); err != nil {
		t.Fatal(err)
	}
	if got, err := c.URL(); err != nil || got != newURL {
		t.Fatal(got, err)
	}
	legacyCopy, err := os.ReadFile(c.SubscriptionURLFile)
	if err != nil || string(legacyCopy) != newURL+"\n" {
		t.Fatal("old updater's required copy missing", err)
	}
	if err = os.WriteFile(c.SubscriptionURLFile, []byte(legacy+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if got, err := c.URL(); err != nil || got != newURL {
		t.Fatal("legacy file took precedence", got, err)
	}
	if err = os.Chmod(c.APIURLPath(), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err = c.URL(); err == nil {
		t.Fatal("public permissions accepted for subscription-bearing Xray fragment")
	}
}

func TestInvalidAPIFragmentDoesNotOverwriteLegacyURL(t *testing.T) {
	dir := t.TempDir()
	c := Defaults()
	c.ConfigDir = dir
	c.SubscriptionURLFile = filepath.Join(dir, "subscription.url")
	if err := os.WriteFile(c.APIURLPath(), []byte(`{"routing":{}}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := c.SetSubscriptionURL("https://new.example.invalid/private"); err == nil {
		t.Fatal("fragment without Xray API accepted")
	}
	if _, err := os.Stat(c.SubscriptionURLFile); !os.IsNotExist(err) {
		t.Fatal("legacy URL was written before API validation", err)
	}
}
