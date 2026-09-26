package hotwatcher

import (
	"os"
	"testing"
	"time"
)

type progressRuntime struct{ *fakeRuntime }

func (r progressRuntime) URLTestWithProgress(node Node, sites []string, progress func(URLTestReport)) (URLTestReport, error) {
	result := URLTestReport{Tag: node.Tag, Time: time.Now().UTC(), Results: make([]URLTestResult, len(sites))}
	for i, site := range sites {
		result.Results[i] = URLTestResult{Site: site}
	}
	progress(cloneURLTestReport(result))
	for i := range result.Results {
		result.Results[i].OK, result.Results[i].Completed = true, true
		progress(cloneURLTestReport(result))
	}
	result.Passed = true
	return result, nil
}

func TestURLTestPublishesIndependentProgressSnapshots(t *testing.T) {
	e, runtime, _ := setupEngine(t)
	if err := e.Sync(true); err != nil {
		t.Fatal(err)
	}
	e.R = progressRuntime{runtime}
	var snapshots []URLTestReport
	report, err := e.URLTestKeyWithProgress("", func(snapshot URLTestReport) {
		snapshots = append(snapshots, snapshot)
	})
	if err != nil || !report.Passed || len(snapshots) != len(report.Results)+1 {
		t.Fatalf("progress was not published: %v, %+v, %d", err, report, len(snapshots))
	}
	if snapshots[0].Results[0].Completed || !snapshots[1].Results[0].Completed || snapshots[1].Results[1].Completed {
		t.Fatal("progress snapshots were mutated after publication")
	}
	stored, err := e.LastURLTest()
	if err != nil || stored == nil || !stored.Passed {
		t.Fatalf("final report was not saved: %+v, %v", stored, err)
	}
}

func TestURLTestSitesEditableAndSafe(t *testing.T) {
	e, _, _ := setupEngine(t)
	defaults, err := e.URLTestSites()
	if err != nil || len(defaults) != 6 || defaults[1] != "https://chatgpt.com/" {
		t.Fatalf("missing default test sites: %v, %v", defaults, err)
	}
	saved, err := e.SaveURLTestSites([]string{"Example.com", "https://github.com/"})
	if err != nil || len(saved) != 2 || saved[0] != "https://example.com/" {
		t.Fatalf("editor did not normalize sites: %v, %v", saved, err)
	}
	if info, err := os.Stat(e.urlTestSettingsPath()); err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("site settings are not private: %v, %v", info, err)
	}
	loaded, err := e.URLTestSites()
	if err != nil || len(loaded) != 2 || loaded[1] != "https://github.com/" {
		t.Fatalf("editor changes were not applied: %v, %v", loaded, err)
	}
	for _, invalid := range [][]string{{}, {"http://example.com"}, {"https://127.0.0.1"}, {"router.local"}, {"https://example.com/token"}, {"example.com", "https://example.com/"}} {
		if _, err := e.SaveURLTestSites(invalid); err == nil {
			t.Fatalf("unsafe URL Test list accepted: %v", invalid)
		}
	}
}

func TestURLTestRunsOnceForChosenCandidate(t *testing.T) {
	e, runtime, raw := setupEngine(t)
	*raw = uri(testUUID, "FI") + "\n" + uri("00000000-0000-4000-8000-000000000002", "DE")
	parsed, err := Parse([]byte(*raw), e.C)
	if err != nil {
		t.Fatal(err)
	}
	first, second := parsed.Nodes[0].Tag, parsed.Nodes[1].Tag
	runtime.latencies = map[string]time.Duration{first: 10 * time.Millisecond, second: 25 * time.Millisecond}
	runtime.urlFailures = map[string]bool{first: true}
	selected, err := e.fastest(parsed.Nodes, "", time.Time{})
	if err == nil || selected != "" || len(runtime.urlTests) != 1 || runtime.urlTests[0] != first {
		t.Fatalf("URL Test retried another key after the chosen key failed: %s, %v, %v", selected, err, runtime.urlTests)
	}
	delete(runtime.urlFailures, first)
	selected, err = e.fastest(parsed.Nodes, "", time.Time{})
	if err != nil || selected != first || len(runtime.urlTests) != 2 || runtime.urlTests[1] != first {
		t.Fatalf("working chosen key was not accepted: %s, %v, %v", selected, err, runtime.urlTests)
	}
}

func TestSelectKeepsOldKeyWhenMandatorySiteFails(t *testing.T) {
	e, runtime, raw := setupEngine(t)
	*raw = uri(testUUID, "FI") + "\n" + uri("00000000-0000-4000-8000-000000000002", "DE")
	if err := e.Sync(true); err != nil {
		t.Fatal(err)
	}
	state, err := e.state()
	if err != nil {
		t.Fatal(err)
	}
	other := state.Active[0].Tag
	if other == state.Selected {
		other = state.Active[1].Tag
	}
	runtime.urlFailures = map[string]bool{other: true}
	if err := e.Select(other); err == nil {
		t.Fatal("manual selection bypassed URL Test")
	}
	after, err := e.state()
	if err != nil || after.Selected != state.Selected || runtime.override != state.Selected || e.pending() {
		t.Fatalf("failed URL Test changed live selection: %+v, %v", after, err)
	}
}

func TestEconomyURLTestOnlyAllowsSelectedKey(t *testing.T) {
	e, runtime, raw := setupEngine(t)
	*raw = uri(testUUID, "FI") + "\n" + uri("00000000-0000-4000-8000-000000000002", "DE")
	if err := e.Sync(true); err != nil {
		t.Fatal(err)
	}
	s, err := e.state()
	if err != nil {
		t.Fatal(err)
	}
	other := s.Active[0].Tag
	if other == s.Selected {
		other = s.Active[1].Tag
	}
	before := len(runtime.urlTests)
	if _, err := e.URLTestKey(other); err == nil || len(runtime.urlTests) != before {
		t.Fatalf("unselected key was tested in economy mode: %v", err)
	}
	if err := e.SetEconomyChecks(false); err != nil {
		t.Fatal(err)
	}
	if _, err := e.URLTestKey(other); err != nil || len(runtime.urlTests) != before+1 {
		t.Fatalf("explicit legacy mode could not test another key: %v", err)
	}
}
