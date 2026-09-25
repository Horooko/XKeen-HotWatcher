package main

import (
	"errors"
	hw "local/xkeen-hot-watcher/internal/hotwatcher"
	"strings"
	"testing"
	"time"
)

type readyRuntime struct{ listErr, balanceErr bool }

func (r readyRuntime) List() (map[string]bool, error) {
	if r.listErr {
		return nil, errors.New("unavailable")
	}
	return map[string]bool{}, nil
}
func (r readyRuntime) Balance() (hw.Balance, error) {
	if r.balanceErr {
		return hw.Balance{}, errors.New("unavailable")
	}
	return hw.Balance{}, nil
}
func (readyRuntime) Add(hw.Node) error                           { return nil }
func (readyRuntime) Remove(string) error                         { return nil }
func (readyRuntime) Override(string) error                       { return nil }
func (readyRuntime) Validate([]hw.Node, string) error            { return nil }
func (readyRuntime) Probe(hw.Node) error                         { return nil }
func (readyRuntime) ProbeLatency(hw.Node) (time.Duration, error) { return 0, nil }
func (readyRuntime) URLTest(n hw.Node, sites []string) (hw.URLTestReport, error) {
	report := hw.URLTestReport{Tag: n.Tag, Passed: true}
	for _, site := range sites {
		report.Results = append(report.Results, hw.URLTestResult{Site: site, OK: true})
	}
	return report, nil
}

func TestWaitXrayReadyChecksBalancerAsWellAsList(t *testing.T) {
	for _, test := range []struct {
		runtime readyRuntime
		want    string
	}{
		{readyRuntime{}, ""},
		{readyRuntime{balanceErr: true}, "API балансировщика"},
		{readyRuntime{listErr: true}, "API списка узлов"},
	} {
		e := &hw.Engine{R: test.runtime}
		err := waitXrayReady(e, 0)
		if test.want == "" && err != nil || test.want != "" && (err == nil || !strings.Contains(err.Error(), test.want)) {
			t.Fatalf("runtime=%+v err=%v; want %q", test.runtime, err, test.want)
		}
	}
}

func TestFetchWithoutVPNRestoresAfterFailure(t *testing.T) {
	for _, fail := range []string{"stop", "fetch", "start"} {
		t.Run(fail, func(t *testing.T) {
			var calls []string
			stop := func() error {
				calls = append(calls, "stop")
				if fail == "stop" {
					return errors.New("stop failed")
				}
				return nil
			}
			start := func() error {
				calls = append(calls, "start")
				if fail == "start" {
					return errors.New("start failed")
				}
				return nil
			}
			fetch := func() ([]byte, error) {
				calls = append(calls, "fetch")
				if fail == "fetch" {
					return nil, errors.New("fetch failed")
				}
				return []byte("keys"), nil
			}
			_, err := fetchWithoutVPN(stop, start, fetch)
			if err == nil {
				t.Fatal("expected error")
			}
			want := "stop,fetch,start"
			if fail == "stop" {
				want = "stop,start"
			}
			if strings.Join(calls, ",") != want {
				t.Fatalf("calls = %v; want %s", calls, want)
			}
		})
	}
}

func TestFetchWithoutVPNSuccess(t *testing.T) {
	var calls []string
	step := func(name string) func() error { return func() error { calls = append(calls, name); return nil } }
	body, err := fetchWithoutVPN(step("stop"), step("start"), func() ([]byte, error) {
		calls = append(calls, "fetch")
		return []byte("keys"), nil
	})
	if err != nil || string(body) != "keys" || strings.Join(calls, ",") != "stop,fetch,start" {
		t.Fatalf("body=%q err=%v calls=%v", body, err, calls)
	}
}
