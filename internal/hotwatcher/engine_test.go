package hotwatcher

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type fakeRuntime struct {
	tags                               map[string]bool
	override                           string
	initial                            string
	adds, removes, probes              []string
	failAdd, failProbe, failValidation bool
	addFailAt                          int
	latencies                          map[string]time.Duration
	failedTags                         map[string]bool
	afterOverride                      func(string)
}

func (f *fakeRuntime) List() (map[string]bool, error) {
	m := map[string]bool{}
	for k, v := range f.tags {
		m[k] = v
	}
	return m, nil
}
func (f *fakeRuntime) Balance() (Balance, error) {
	return Balance{Override: f.override, Selected: []string{f.initial}}, nil
}
func (f *fakeRuntime) Add(n Node) error {
	f.adds = append(f.adds, n.Tag)
	if f.failAdd || (f.addFailAt > 0 && len(f.adds) == f.addFailAt) {
		return errors.New("add failure")
	}
	f.tags[n.Tag] = true
	return nil
}
func (f *fakeRuntime) Remove(tag string) error {
	f.removes = append(f.removes, tag)
	delete(f.tags, tag)
	return nil
}
func (f *fakeRuntime) Override(tag string) error {
	if tag != "" && !f.tags[tag] {
		return errors.New("unknown tag")
	}
	f.override = tag
	if f.afterOverride != nil {
		f.afterOverride(tag)
	}
	return nil
}
func (f *fakeRuntime) Validate([]Node, string) error {
	if f.failValidation {
		return errors.New("validation failed")
	}
	return nil
}
func (f *fakeRuntime) Probe(n Node) error {
	_, err := f.ProbeLatency(n)
	return err
}
func (f *fakeRuntime) ProbeLatency(n Node) (time.Duration, error) {
	f.probes = append(f.probes, n.Tag)
	if f.failProbe || f.failedTags[n.Tag] {
		return 0, errors.New("probe failed")
	}
	if f.latencies != nil {
		return f.latencies[n.Tag], nil
	}
	return time.Millisecond, nil
}
func setupEngine(t *testing.T) (*Engine, *fakeRuntime, *string) {
	t.Helper()
	dir := t.TempDir()
	c := Defaults()
	c.StateDir = filepath.Join(dir, "state")
	c.ConfigDir = filepath.Join(dir, "configs")
	os.Mkdir(c.StateDir, 0700)
	os.Mkdir(c.ConfigDir, 0700)
	os.WriteFile(filepath.Join(c.ConfigDir, "05_routing.json"), []byte(`{"routing":{"balancers":[{"tag":"proxy","selector":["main--VL"],"strategy":{"type":"leastPing"}}]}}`), 0600)
	os.WriteFile(outputFile(c), []byte(`{"outbounds":[{"tag":"legacy","protocol":"vless"}]}`), 0600)
	r := &fakeRuntime{tags: map[string]bool{"legacy": true, "direct": true, "block": true, "unmanaged": true}, initial: "legacy"}
	raw := uri(testUUID, "FI")
	e := New(c)
	e.R = r
	e.Fetcher = func(Config) ([]byte, error) { return []byte(raw), nil }
	e.Now = func() time.Time { return time.Date(2026, 9, 15, 1, 0, 0, 0, time.UTC) }
	return e, r, &raw
}
func TestAdoptBacksUpAndDoesNotRemoveLegacy(t *testing.T) {
	e, r, _ := setupEngine(t)
	old, _ := os.ReadFile(outputFile(e.C))
	if er := e.Sync(true); er != nil {
		t.Fatal(er)
	}
	s, er := e.state()
	if er != nil {
		t.Fatal(er)
	}
	if len(s.Active) != 1 || s.Selected != r.override || len(r.removes) != 0 || !r.tags["legacy"] {
		t.Fatal("unsafe migration")
	}
	backup, _ := os.ReadFile(filepath.Join(e.C.StateDir, "pre-migration-outbounds.json"))
	if string(backup) != string(old) {
		t.Fatal("backup missing")
	}
	if e.pending() {
		t.Fatal("unexpected journal")
	}
	if info, _ := os.Stat(outputFile(e.C)); info.Mode().Perm() != 0600 {
		t.Fatal("unsafe file mode")
	}
}
func TestFirstSyncRequiresExplicitAdopt(t *testing.T) {
	e, r, _ := setupEngine(t)
	if er := e.Sync(false); er == nil || len(r.adds) != 0 {
		t.Fatal("silent adoption")
	}
}
func TestRenameOnlyDoesNotMutateRuntimeOrFile(t *testing.T) {
	e, r, raw := setupEngine(t)
	if er := e.Sync(true); er != nil {
		t.Fatal(er)
	}
	before, _ := os.ReadFile(outputFile(e.C))
	adds := len(r.adds)
	*raw = uri(testUUID, "renamed")
	if er := e.Sync(false); er != nil {
		t.Fatal(er)
	}
	after, _ := os.ReadFile(outputFile(e.C))
	if string(before) != string(after) || len(r.adds) != adds {
		t.Fatal("metadata-only update changed runtime")
	}
}

func TestLatencySelectionChangesOnUnchangedSubscription(t *testing.T) {
	e, r, raw := setupEngine(t)
	*raw = uri(testUUID, "FI") + "\n" + uri("00000000-0000-4000-8000-000000000002", "DE")
	if err := e.Sync(true); err != nil {
		t.Fatal(err)
	}
	s, _ := e.state()
	if len(s.Active) != 2 {
		t.Fatal("expected two nodes")
	}
	other := s.Active[0].Tag
	if other == s.Selected {
		other = s.Active[1].Tag
	}
	r.latencies = map[string]time.Duration{s.Selected: 80 * time.Millisecond, other: 20 * time.Millisecond}
	if err := e.Sync(false); err != nil {
		t.Fatal(err)
	}
	s, _ = e.state()
	if s.Selected != other || r.override != other || e.pending() {
		t.Fatal("fastest verified node was not durably selected")
	}
	r.failedTags = map[string]bool{other: true}
	if err := e.Sync(false); err != nil {
		t.Fatal(err)
	}
	s, _ = e.state()
	if s.Selected == other || r.override != s.Selected {
		t.Fatal("unreachable node remained selected")
	}
	r.failProbe = true
	before, _ := os.ReadFile(outputFile(e.C))
	selected := s.Selected
	if err := e.Sync(false); err == nil {
		t.Fatal("all probes failed")
	}
	after, _ := os.ReadFile(outputFile(e.C))
	if string(before) != string(after) || r.override != selected || e.pending() {
		t.Fatal("failed probes changed runtime")
	}
}

func TestStickyPolicySkipsRepeatedLatencyChecks(t *testing.T) {
	e, r, _ := setupEngine(t)
	e.C.SelectionPolicy = "sticky"
	if err := e.Sync(true); err != nil {
		t.Fatal(err)
	}
	probes := len(r.probes)
	if err := e.Sync(false); err != nil {
		t.Fatal(err)
	}
	if len(r.probes) != probes {
		t.Fatal("sticky policy probed unchanged subscription")
	}
}
func TestKeyRotationPinsNewAndRetainsOld(t *testing.T) {
	e, r, raw := setupEngine(t)
	if er := e.Sync(true); er != nil {
		t.Fatal(er)
	}
	first := r.override
	*raw = uri("00000000-0000-4000-8000-000000000002", "FI")
	if er := e.Sync(false); er != nil {
		t.Fatal(er)
	}
	s, _ := e.state()
	if r.override == first || !r.tags[first] || len(s.Retired) != 1 || len(r.removes) != 0 {
		t.Fatal("rotation did not retain old handler")
	}
	if er := e.GC(); er != nil {
		t.Fatal(er)
	}
	if len(r.removes) != 0 {
		t.Fatal("gc ignored grace")
	}
	e.Now = func() time.Time { return time.Date(2026, 9, 15, 3, 0, 0, 0, time.UTC) }
	if er := e.GC(); er != nil {
		t.Fatal(er)
	}
	if len(r.removes) != 1 || r.removes[0] != first || !r.tags[s.Selected] || !r.tags["legacy"] {
		t.Fatal("gc removed incorrect nodes")
	}
}
func TestFailedCandidateLeavesEverythingUntouched(t *testing.T) {
	for _, failure := range []string{"parse", "probe", "validation", "download"} {
		t.Run(failure, func(t *testing.T) {
			e, r, raw := setupEngine(t)
			if er := e.Sync(true); er != nil {
				t.Fatal(er)
			}
			before, _ := os.ReadFile(outputFile(e.C))
			selected := r.override
			adds := len(r.adds)
			*raw = uri("00000000-0000-4000-8000-000000000002", "FI")
			switch failure {
			case "parse":
				*raw = "vless://broken"
			case "probe":
				r.failProbe = true
			case "validation":
				r.failValidation = true
			case "download":
				e.Fetcher = func(Config) ([]byte, error) { return nil, errors.New("offline") }
			}
			if er := e.Sync(false); er == nil {
				t.Fatal("error expected")
			}
			after, _ := os.ReadFile(outputFile(e.C))
			if string(before) != string(after) || r.override != selected || len(r.adds) != adds || e.pending() {
				t.Fatal("preparation failure modified runtime")
			}
		})
	}
}
func TestAPIFailureLeavesJournalRecoverIsIdempotent(t *testing.T) {
	e, r, raw := setupEngine(t)
	if er := e.Sync(true); er != nil {
		t.Fatal(er)
	}
	old := r.override
	*raw = uri("00000000-0000-4000-8000-000000000002", "FI")
	r.failAdd = true
	if er := e.Sync(false); er == nil || !e.pending() {
		t.Fatal("pending journal expected")
	}
	if r.override != old || !r.tags[old] || len(r.removes) != 0 {
		t.Fatal("old flow damaged")
	}
	if er := e.Sync(false); er == nil {
		t.Fatal("second sync should not race transaction")
	}
	r.failAdd = false
	if er := e.Recover(); er != nil {
		t.Fatal(er)
	}
	if e.pending() || r.override == old {
		t.Fatal("not recovered")
	}
}
func TestAbortRestoresBeforeStateAndDoesNotRemoveHandlers(t *testing.T) {
	e, r, raw := setupEngine(t)
	if er := e.Sync(true); er != nil {
		t.Fatal(er)
	}
	old, _ := os.ReadFile(outputFile(e.C))
	tag := r.override
	*raw = uri("00000000-0000-4000-8000-000000000002", "FI")
	r.failAdd = true
	_ = e.Sync(false)
	r.failAdd = false
	if er := e.Abort(); er != nil {
		t.Fatal(er)
	}
	now, _ := os.ReadFile(outputFile(e.C))
	if string(now) != string(old) || r.override != tag || e.pending() || len(r.removes) != 0 {
		t.Fatal("abort did not restore previous configuration")
	}
}
func TestExternalWriterConflict(t *testing.T) {
	e, r, _ := setupEngine(t)
	if er := e.Sync(true); er != nil {
		t.Fatal(er)
	}
	adds := len(r.adds)
	os.WriteFile(outputFile(e.C), []byte(`{"outbounds":[]}`), 0600)
	if er := e.Sync(false); er == nil || len(r.adds) != adds {
		t.Fatal("external edit overwritten")
	}
}
func TestHoldPreventsFetchingAndGC(t *testing.T) {
	e, _, _ := setupEngine(t)
	if er := e.Sync(true); er != nil {
		t.Fatal(er)
	}
	e.Fetcher = func(Config) ([]byte, error) { t.Fatal("hold fetched subscription"); return nil, nil }
	if er := e.Hold(true); er != nil {
		t.Fatal(er)
	}
	if er := e.Sync(false); er != nil {
		t.Fatal(er)
	}
	if er := e.GC(); er == nil {
		t.Fatal("gc should reject hold")
	}
	if er := e.Reconcile(); er != nil {
		t.Fatal(er)
	}
}
func TestReconcileRestoresMissingOwnRuntimeAndPin(t *testing.T) {
	e, r, _ := setupEngine(t)
	if er := e.Sync(true); er != nil {
		t.Fatal(er)
	}
	s, _ := e.state()
	delete(r.tags, s.Selected)
	r.override = ""
	if er := e.Reconcile(); er != nil {
		t.Fatal(er)
	}
	if !r.tags[s.Selected] || r.override != s.Selected {
		t.Fatal("state not reconciled")
	}
}
func TestStateWriteFailureRecoverForward(t *testing.T) {
	e, r, raw := setupEngine(t)
	if er := e.Sync(true); er != nil {
		t.Fatal(er)
	}
	*raw = uri("00000000-0000-4000-8000-000000000002", "FI")
	old := r.override
	r.afterOverride = func(tag string) {
		if tag != old {
			os.Remove(e.statePath())
			os.Mkdir(e.statePath(), 0700)
		}
	}
	if er := e.Sync(false); er == nil || !e.pending() {
		t.Fatal("commit should fail with durable journal")
	}
	r.afterOverride = nil
	os.Remove(e.statePath())
	if er := e.Recover(); er != nil {
		t.Fatal(er)
	}
	if _, er := e.state(); er != nil {
		t.Fatal(er)
	}
}
func TestNoAPIWritesDuringPlan(t *testing.T) {
	e, r, _ := setupEngine(t)
	p, er := e.Plan()
	if er != nil {
		t.Fatal(er)
	}
	if p["runtime_modified"] != false || len(r.adds) != 0 || r.override != "" || e.pending() {
		t.Fatal("plan mutated runtime")
	}
}
func TestBalancerParser(t *testing.T) {
	b, er := parseBalance([]byte("  - Selecting Override:\n    1   main--VL--hw-123\n  - Selects:\n    1   main--VL FI with spaces\n"))
	if er != nil || b.Override != "main--VL--hw-123" || b.Selected[0] != "main--VL FI with spaces" {
		t.Fatal(b, er)
	}
	if _, er = parseBalance([]byte("unexpected")); er == nil {
		t.Fatal("unsafe parser fallback")
	}
}
func TestFileLockAndSymlinkProtection(t *testing.T) {
	d := filepath.Join(t.TempDir(), "state")
	release, er := lock(d)
	if er != nil {
		t.Fatal(er)
	}
	defer release()
	if rel, er := lock(d); er == nil {
		rel()
		t.Fatal("concurrent lock acquired")
	}
	p := filepath.Join(d, "target")
	link := filepath.Join(d, "link")
	os.WriteFile(p, []byte("secret"), 0600)
	os.Symlink(p, link)
	if er = atomicWrite(link, []byte("replaced"), 0600); er == nil {
		t.Fatal("symlink replaced")
	}
}
func TestInvalidSelectorBlocksMigration(t *testing.T) {
	e, r, _ := setupEngine(t)
	p := filepath.Join(e.C.ConfigDir, "05_routing.json")
	b, _ := os.ReadFile(p)
	os.WriteFile(p, []byte(strings.ReplaceAll(string(b), "main--VL", "wrong-prefix")), 0600)
	if er := e.Sync(true); er == nil || len(r.adds) != 0 {
		t.Fatal("incompatible balancer accepted")
	}
}
func TestAdoptWithXrayJSONCInUnrelatedDNSFragment(t *testing.T) {
	e, _, _ := setupEngine(t)
	path := filepath.Join(e.C.ConfigDir, "02_dns.json")
	if err := os.WriteFile(path, []byte("{\n  // Xray allows comments in DNS fragments.\n  \"dns\": {\"servers\": [\"localhost\"]}\n}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := e.Sync(true); err != nil {
		t.Fatal(err)
	}
}
func TestMalformedRoutingFragmentStillBlocksMigration(t *testing.T) {
	e, r, _ := setupEngine(t)
	path := filepath.Join(e.C.ConfigDir, "05_routing.json")
	if err := os.WriteFile(path, []byte("{\"routing\": {\"balancers\": [}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := e.Sync(true); err == nil || len(r.adds) != 0 {
		t.Fatal("malformed routing fragment accepted")
	}
}
func TestBlankBalancerOverrideIsNotAnOutbound(t *testing.T) {
	b, err := parseBalance([]byte("  - Selecting Override:\n    1   \n  - Selects:\n    1   main--VL FI\n"))
	if err != nil || b.Override != "" || len(b.Selected) != 1 || b.Selected[0] != "main--VL FI" {
		t.Fatal("blank API row was treated as an outbound")
	}
}
func TestPreferredAndStickyChoice(t *testing.T) {
	n := []Node{{Tag: "one", Name: "Germany", Identity: "de"}, {Tag: "two", Name: "Finland", Identity: "fi"}}
	if choose(n, "one", "", "Finland") != "one" || choose(n, "old", "fi", "") != "two" || choose(n, "old", "", "finland") != "two" {
		t.Fatal("selection policy")
	}
}
