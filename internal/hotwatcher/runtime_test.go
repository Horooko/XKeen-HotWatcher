package hotwatcher

// This helper emulates the Xray CLI for process-boundary tests. It is NOT Xray.
import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestMain(m *testing.M) {
	if os.Getenv("HW_FAKE_XRAY") == "1" {
		os.Exit(fakeXrayProcess())
	}
	os.Exit(m.Run())
}

type fakeDB struct {
	Tags     map[string]bool `json:"tags"`
	Override string          `json:"override"`
}

func fakeXrayProcess() int {
	args := os.Args[1:]
	if len(args) < 2 {
		return 2
	}
	if os.Getenv("XRAY_LOCATION_CONFDIR") != "" || os.Getenv("xray.location.confdir") != "" {
		return 23
	}
	if os.Getenv("HW_FORCE_FAILURE") == "1" {
		fmt.Println("private-token-secret-UUID")
		return 5
	}
	if args[0] == "run" {
		if args[1] == "-test" {
			fmt.Println("Configuration OK.")
			return 0
		}
		var file string
		for i, a := range args {
			if a == "-config" && i+1 < len(args) {
				file = args[i+1]
			}
		}
		var c struct {
			Inbounds []struct {
				Port int `json:"port"`
			} `json:"inbounds"`
		}
		b, e := os.ReadFile(file)
		if e != nil || json.Unmarshal(b, &c) != nil || len(c.Inbounds) == 0 {
			return 3
		}
		code := 204
		if n, e := strconv.Atoi(os.Getenv("HW_PROBE_CODE")); e == nil {
			code = n
		}
		http.ListenAndServe(fmt.Sprintf("127.0.0.1:%d", c.Inbounds[0].Port), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(code) }))
		return 0
	}
	if args[0] != "api" {
		return 4
	}
	path := os.Getenv("HW_FAKE_DB")
	var db fakeDB
	raw, _ := os.ReadFile(path)
	if json.Unmarshal(raw, &db) != nil {
		return 5
	}
	switch args[1] {
	case "lso":
		if os.Getenv("HW_STDERR_WARNING") == "1" {
			fmt.Fprintln(os.Stderr, "warning: deprecated transport; private-diagnostic")
		}
		list := []map[string]any{}
		for k := range db.Tags {
			list = append(list, map[string]any{"tag": k})
		}
		j, _ := json.Marshal(map[string]any{"outbounds": list})
		fmt.Println(string(j))
	case "bi":
		if db.Override != "" {
			fmt.Printf("  - Selecting Override:\n    1   %s\n", db.Override)
		}
		fmt.Println("  - Selects:\n    1   base")
	case "bo":
		db.Override = args[len(args)-1]
		if db.Override == "-r" {
			db.Override = ""
		}
	case "ado":
		b, _ := io.ReadAll(os.Stdin)
		var v struct {
			Outbounds []struct {
				Tag string `json:"tag"`
			} `json:"outbounds"`
		}
		if json.Unmarshal(b, &v) != nil {
			return 6
		}
		for _, n := range v.Outbounds {
			db.Tags[n.Tag] = true
		}
		fmt.Println("{}")
	case "rmo":
		delete(db.Tags, args[len(args)-1])
		fmt.Println("{}")
	default:
		return 7
	}
	b, _ := json.Marshal(db)
	if os.WriteFile(path, b, 0600) != nil {
		return 8
	}
	return 0
}
func fakeProcessRuntime(t *testing.T) Xray {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "fake-db.json")
	os.WriteFile(path, encode(fakeDB{Tags: map[string]bool{"base": true}}), 0600)
	t.Setenv("HW_FAKE_XRAY", "1")
	t.Setenv("HW_FAKE_DB", path)
	t.Setenv("XRAY_LOCATION_CONFDIR", "/must-not-be-used")
	t.Setenv("xray.location.confdir", "/also-must-not-be-used")
	binary, e := os.Executable()
	if e != nil {
		t.Fatal(e)
	}
	c := Defaults()
	c.XrayBinary = binary
	c.StateDir = dir
	c.ConfigDir = filepath.Join(dir, "configs")
	c.AssetDir = dir
	c.ProbeTimeoutSeconds = 2
	c.APITimeoutSeconds = 2
	c.ProbeURLs = []string{"http://127.0.0.1:1/probe"}
	c.AllowLoopbackHTTP = true
	os.Mkdir(c.ConfigDir, 0700)
	os.WriteFile(filepath.Join(c.ConfigDir, "01_log.json"), []byte(`{"log":{"loglevel":"none"}}`), 0600)
	return Xray{c}
}
func TestRuntimeCLIAdapterAndEnvironmentIsolation(t *testing.T) {
	x := fakeProcessRuntime(t)
	tags, e := x.List()
	if e != nil || !tags["base"] {
		t.Fatal(tags, e)
	}
	p, e := Parse([]byte(uri(testUUID, "FI")), x.C)
	if e != nil {
		t.Fatal(e)
	}
	n := p.Nodes[0]
	if e = x.Validate(p.Nodes, n.Tag); e != nil {
		t.Fatal(e)
	}
	if e = x.Add(n); e != nil {
		t.Fatal(e)
	}
	tags, e = x.List()
	if e != nil || !tags[n.Tag] {
		t.Fatal(e)
	}
	if e = x.Override(n.Tag); e != nil {
		t.Fatal(e)
	}
	b, e := x.Balance()
	if e != nil || b.Override != n.Tag {
		t.Fatal(b, e)
	}
	if e = x.Remove(n.Tag); e != nil {
		t.Fatal(e)
	}
	if e = x.Remove("unmanaged"); e == nil {
		t.Fatal("unsafe removal")
	}
	if e = x.Override(""); e != nil {
		t.Fatal(e)
	}
}
func TestRuntimeErrorsDoNotExposeRawStderr(t *testing.T) {
	x := fakeProcessRuntime(t)
	t.Setenv("HW_FORCE_FAILURE", "1")
	_, e := x.List()
	if e == nil || strings.Contains(e.Error(), "private-token") {
		t.Fatal(e)
	}
}
func TestIsolatedProbeProcessSuccessAndFailure(t *testing.T) {
	x := fakeProcessRuntime(t)
	p, e := Parse([]byte(uri(testUUID, "FI")), x.C)
	if e != nil {
		t.Fatal(e)
	}
	latency, e := x.ProbeLatency(p.Nodes[0])
	if e != nil || latency <= 0 {
		t.Fatal(e)
	}
	t.Setenv("HW_PROBE_CODE", "403")
	if _, e = x.ProbeLatency(p.Nodes[0]); e == nil {
		t.Fatal("403 accepted as healthy")
	}
}

func TestListOutboundsIgnoresStderrWarnings(t *testing.T) {
	x := fakeProcessRuntime(t)
	t.Setenv("HW_STDERR_WARNING", "1")
	tags, err := x.List()
	if err != nil || !tags["base"] {
		t.Fatalf("valid API JSON was rejected: %v, %v", tags, err)
	}
}
