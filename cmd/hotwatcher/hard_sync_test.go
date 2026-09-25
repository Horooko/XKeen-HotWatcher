package main

import (
	"errors"
	"strings"
	"testing"
)

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
