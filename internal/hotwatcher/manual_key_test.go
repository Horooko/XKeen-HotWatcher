package hotwatcher

import (
	"os"
	"strings"
	"testing"
)

func TestManualPinSurvivesSyncAndDisablesFailover(t *testing.T) {
	e, runtime, raw := setupEngine(t)
	*raw = uri(testUUID, "FI") + "\n" + uri("00000000-0000-4000-8000-000000000002", "DE")
	if err := e.Sync(true); err != nil {
		t.Fatal(err)
	}
	s, err := e.state()
	if err != nil {
		t.Fatal(err)
	}
	pinned, other := "", ""
	for _, node := range s.Active {
		if node.Name == "FI" {
			pinned = node.Tag
		}
		if node.Name == "DE" {
			other = node.Tag
		}
	}
	if pinned == "" || other == "" {
		t.Fatal("fixture keys missing")
	}
	if err := e.Pin(pinned); err != nil {
		t.Fatal(err)
	}
	runtime.failedTags = map[string]bool{pinned: true}
	if _, err := e.CheckKey(); err == nil || runtime.override != pinned {
		t.Fatalf("manual pin switched after a failed check: override=%s err=%v", runtime.override, err)
	}
	*raw = uri("00000000-0000-4000-8000-000000000002", "DE")
	if err := e.Sync(false); err != nil {
		t.Fatal(err)
	}
	s, err = e.state()
	if err != nil || s.SelectionMode != "manual" || s.Selected != pinned || len(s.Active) != 2 {
		t.Fatalf("sync discarded manual key: %+v %v", s, err)
	}
	selected, err := e.Automatic()
	if err != nil || selected != other {
		t.Fatalf("auto mode did not choose healthy key: %s %v", selected, err)
	}
	s, err = e.state()
	if err != nil || s.SelectionMode != "" || s.Selected != other || runtime.override != other {
		t.Fatalf("auto mode was not applied: %+v %v", s, err)
	}
}

func TestEmergencyKeyAppliesWithoutExposingURIAndSurvivesSync(t *testing.T) {
	e, runtime, _ := setupEngine(t)
	if err := e.Sync(true); err != nil {
		t.Fatal(err)
	}
	secret := uri("00000000-0000-4000-8000-000000000003", "RESCUE")
	parsed, err := Parse([]byte(secret), e.C)
	if err != nil {
		t.Fatal(err)
	}
	emergencyTag := parsed.Nodes[0].Tag
	runtime.urlFailures = map[string]bool{emergencyTag: true}
	result, err := e.ImportEmergency(secret)
	if err != nil || result.Tag != emergencyTag || result.URLTestPassed || result.Warning == "" {
		t.Fatalf("emergency import did not apply explicit override: %+v %v", result, err)
	}
	s, err := e.state()
	if err != nil || s.Selected != emergencyTag || s.SelectionMode != "manual" || runtime.override != emergencyTag {
		t.Fatalf("emergency route is not selected and pinned: %+v %v", s, err)
	}
	node, exists := findNode(s.Active, emergencyTag)
	if !exists || !node.Emergency {
		t.Fatal("emergency marker is missing")
	}
	if err := e.Sync(false); err != nil {
		t.Fatal(err)
	}
	s, err = e.state()
	if err != nil || s.Selected != emergencyTag || len(s.Active) != 2 {
		t.Fatalf("subscription sync removed emergency route: %+v %v", s, err)
	}
	for _, path := range []string{e.statePath(), outputFile(e.C)} {
		b, err := os.ReadFile(path)
		if err != nil || strings.Contains(string(b), "vless://") {
			t.Fatalf("raw emergency URI leaked into %s: %v", path, err)
		}
	}
	if err := e.RemoveEmergency(); err != nil {
		t.Fatal(err)
	}
	if tag, err := e.EmergencyTag(); err != nil || tag != "" {
		t.Fatalf("emergency designation not cleared: %s %v", tag, err)
	}
}
