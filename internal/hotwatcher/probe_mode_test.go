package hotwatcher

import (
	"os"
	"path/filepath"
	"testing"
)

func TestEconomyChecksDefaultAndPersistence(t *testing.T) {
	c := Defaults()
	c.StateDir = filepath.Join(t.TempDir(), "state")
	if enabled, err := c.EconomyChecks(); err != nil || enabled {
		t.Fatalf("new installation must default to isolated checks: %v, %v", enabled, err)
	}
	e := New(c)
	if err := e.SetEconomyChecks(true); err == nil {
		t.Fatal("live checks enabled without explicit local opt-in")
	}
	if err := e.SetEconomyChecks(false); err != nil {
		t.Fatal(err)
	}
	if enabled, err := c.EconomyChecks(); err != nil || enabled {
		t.Fatalf("disabled setting not persisted: %v, %v", enabled, err)
	}
	if info, err := os.Stat(c.probeModePath()); err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("setting file permissions: %v, %v", info, err)
	}
	c.AllowLiveProbes = true
	e = New(c)
	if err := e.SetEconomyChecks(true); err != nil {
		t.Fatal(err)
	}
	if enabled, err := c.EconomyChecks(); err != nil || !enabled {
		t.Fatalf("enabled setting not persisted: %v, %v", enabled, err)
	}
}

func TestBackgroundChecksStayIsolatedWhenEconomyModeIsEnabled(t *testing.T) {
	c := Defaults()
	c.StateDir = filepath.Join(t.TempDir(), "state")
	c.AllowLiveProbes = true
	if enabled, err := c.EconomyChecks(); err != nil || enabled {
		t.Fatalf("live mode must still require a separate UI opt-in: %v, %v", enabled, err)
	}
	if err := New(c).SetEconomyChecks(true); err != nil {
		t.Fatal(err)
	}
	c.ForceIsolatedChecks = true
	if enabled, err := c.EconomyChecks(); err != nil || enabled {
		t.Fatalf("background probe must be isolated: %v, %v", enabled, err)
	}
}

func TestDiagnosticsStayIsolatedEvenWhenLiveChecksAreEnabled(t *testing.T) {
	c := Defaults()
	c.StateDir = filepath.Join(t.TempDir(), "state")
	c.AllowLiveProbes = true
	if err := New(c).SetEconomyChecks(true); err != nil {
		t.Fatal(err)
	}
	e := New(c)
	if live, err := e.C.EconomyChecks(); err != nil || !live {
		t.Fatalf("explicit opt-in not applied: %v, %v", live, err)
	}
	diagnostic := e.isolatedChecks()
	if live, err := diagnostic.C.EconomyChecks(); err != nil || live {
		t.Fatalf("diagnostic config is not isolated: %v, %v", live, err)
	}
	runtime, ok := diagnostic.R.(Xray)
	if !ok {
		t.Fatal("unexpected diagnostic runtime type")
	}
	if live, err := runtime.C.EconomyChecks(); err != nil || live {
		t.Fatalf("diagnostic runtime still mutates live Xray: %v, %v", live, err)
	}
}
