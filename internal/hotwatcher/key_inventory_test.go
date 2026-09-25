package hotwatcher

import (
	"os"
	"strings"
	"testing"
	"time"
)

func TestKeysSnapshotShowsFetchedCandidatesAfterFailedSync(t *testing.T) {
	e, r, raw := setupEngine(t)
	if err := e.Sync(true); err != nil {
		t.Fatal(err)
	}
	*raw = uri(testUUID, "FI") + "\n" + uri("00000000-0000-4000-8000-000000000002", "DE")
	r.failProbe = true
	if err := e.Sync(false); err == nil {
		t.Fatal("expected sync to keep old pool when all probes fail")
	}
	inventory, err := e.KeysSnapshot()
	if err != nil || len(inventory.Keys) != 2 || inventory.FetchedAt == nil {
		t.Fatalf("inventory=%+v err=%v", inventory, err)
	}
	foundUnapplied := false
	for _, key := range inventory.Keys {
		if key.Name == "DE" && key.Latest && !key.Applied {
			foundUnapplied = true
		}
	}
	if !foundUnapplied {
		t.Fatal("new candidate not shown after failed sync")
	}
	b, err := os.ReadFile(e.fetchedPath())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), testUUID) {
		t.Fatal("inventory leaked credentials")
	}
}

func TestKeysContinuesWhenBalancerAPIUnavailable(t *testing.T) {
	e, r, _ := setupEngine(t)
	if err := e.Sync(true); err != nil {
		t.Fatal(err)
	}
	r.failBalance = true
	report, err := e.Keys()
	if err != nil || len(report.Keys) != 1 || report.APIWarning == "" {
		t.Fatalf("report=%+v err=%v", report, err)
	}
}

func TestFetchedInventoryRecordsDirectProbeResults(t *testing.T) {
	e, _, raw := setupEngine(t)
	parsed, err := Parse([]byte(*raw), e.C)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.SaveFetched(parsed, map[string]time.Duration{parsed.Nodes[0].Tag: 35 * time.Millisecond}, true); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(e.fetchedPath())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"verified": true`) {
		t.Fatal("direct probe result missing")
	}
}
