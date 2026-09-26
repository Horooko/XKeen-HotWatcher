package hotwatcher

import (
	"os"
	"path/filepath"
	"testing"
)

func TestEconomyChecksDefaultAndPersistence(t *testing.T) {
	c := Defaults()
	c.StateDir = filepath.Join(t.TempDir(), "state")
	if enabled, err := c.EconomyChecks(); err != nil || !enabled {
		t.Fatalf("new installation must default to economy checks: %v, %v", enabled, err)
	}
	e := New(c)
	if err := e.SetEconomyChecks(false); err != nil {
		t.Fatal(err)
	}
	if enabled, err := c.EconomyChecks(); err != nil || enabled {
		t.Fatalf("disabled setting not persisted: %v, %v", enabled, err)
	}
	if info, err := os.Stat(c.probeModePath()); err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("setting file permissions: %v, %v", info, err)
	}
	if err := e.SetEconomyChecks(true); err != nil {
		t.Fatal(err)
	}
	if enabled, err := c.EconomyChecks(); err != nil || !enabled {
		t.Fatalf("enabled setting not persisted: %v, %v", enabled, err)
	}
}
