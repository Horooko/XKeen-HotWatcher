package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

func TestStatusLinesHideConnectionSecrets(t *testing.T) {
	line := "failed vless://user@host:443?pbk=secret token=abc Bearer jwt.value https://example.org/path 00000000-0000-4000-8000-000000000003"
	safe := safeStatusLine(line)
	for _, secret := range []string{"vless://", "pbk=secret", "token=abc", "jwt.value", "example.org", "00000000-0000-4000-8000-000000000003"} {
		if strings.Contains(safe, secret) {
			t.Fatalf("status leaked %q: %s", secret, safe)
		}
	}
}

func TestStartupCheckDoesNotReportSuccessAfterFailedConfigTest(t *testing.T) {
	result := startupCheckResult{
		ConfigTest:  startupCommandResult{OK: false, Lines: []string{"Configuration failed"}},
		PBRStatus:   startupCommandResult{OK: true},
		ProxyStatus: startupCommandResult{OK: false, Lines: []string{"не определён"}},
	}
	if err := startupCheckError(result); err == nil || !strings.Contains(err.Error(), "-xtest") {
		t.Fatalf("failed config test was reported as success: %v", err)
	}
	result.ConfigTest.OK = true
	if err := startupCheckError(result); err != nil {
		t.Fatalf("valid startup checks rejected: %v", err)
	}
}

func TestXKeenEntwareProxyModeIsReadFromInitScript(t *testing.T) {
	path := filepath.Join(t.TempDir(), "S05xkeen")
	if err := os.WriteFile(path, []byte("#!/bin/sh\nproxy_router=\"off\"\nproxy_router='on'\n"), 0600); err != nil {
		t.Fatal(err)
	}
	result := readXKeenEntwareProxyModeAt(path)
	if !result.OK || !strings.Contains(strings.Join(result.Lines, " "), "proxy_router=on") {
		t.Fatalf("unexpected Entware proxy mode: %+v", result)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if readXKeenEntwareProxyModeAt(path).OK {
		t.Fatal("missing init script reported as known proxy state")
	}
}

func TestXrayLogSettingsFollowOrderedFragments(t *testing.T) {
	dir := t.TempDir()
	for name, content := range map[string]string{
		"01_log.json":   `{"log":{"error":"/opt/var/log/xray/old.log","access":"/opt/var/log/xray/old-access.log","loglevel":"none"}}`,
		"02_other.json": `{"routing":{"rules":[]}}`,
		"09_log.json": `// override from a later JSONC fragment
{"log":{"error":"/opt/var/log/xray/current.log","access":"none","loglevel":"warning",}}`,
		"10_invalid.json": `{"log":`,
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
	}
	got := readXrayLogSettings(dir)
	if got.Level != "warning" || got.ErrorPath != "/opt/var/log/xray/current.log" || got.AccessPath != "" {
		t.Fatalf("unexpected merged log settings: %+v", got)
	}
}

func TestXrayLogSettingsRejectUnboundedOrRelativePaths(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "01_log.json"), []byte(`{"log":{"error":"../../private","access":"/opt/var/log/xray/access.log","loglevel":"debug"}}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "02_oversized.json"), []byte(`{"log":{"loglevel":"none"},"padding":"`+strings.Repeat("x", 1024*1024)+`"}`), 0600); err != nil {
		t.Fatal(err)
	}
	got := readXrayLogSettings(dir)
	if got.Level != "debug" || got.ErrorPath != "" || got.AccessPath != "/opt/var/log/xray/access.log" {
		t.Fatalf("unsafe or oversized fragment changed log settings: %+v", got)
	}
}

func TestXrayLogSettingsLaterRelativePathClearsEarlierPath(t *testing.T) {
	dir := t.TempDir()
	for name, content := range map[string]string{
		"01_log.json": `{"log":{"error":"/opt/var/log/xray/old.log","access":"/opt/var/log/xray/old-access.log"}}`,
		"02_log.json": `{"log":{"error":"relative-error.log","access":"../relative-access.log"}}`,
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
	}
	got := readXrayLogSettings(dir)
	if got.ErrorPath != "" || got.AccessPath != "" || got.ErrorPathKnown || got.AccessPathKnown || !got.ConfigKnown {
		t.Fatalf("later relative paths must not expose earlier log files: %+v", got)
	}
}

func TestXrayLogSettingsIgnoreSymlinkFragment(t *testing.T) {
	dir := t.TempDir()
	outside := filepath.Join(t.TempDir(), "outside.json")
	if err := os.WriteFile(filepath.Join(dir, "01_log.json"), []byte(`{"log":{"error":"/opt/var/log/xray/expected.log"}}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(outside, []byte(`{"log":{"error":"/tmp/foreign.log"}}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(dir, "02_log.json")); err != nil {
		t.Skipf("symlinks are unavailable: %v", err)
	}
	if got := readXrayLogSettings(dir); got.ErrorPath != "/opt/var/log/xray/expected.log" {
		t.Fatalf("symlink fragment was followed: %+v", got)
	}
}

func TestXrayLogSettingsBoundDirectoryEnumeration(t *testing.T) {
	dir := t.TempDir()
	for i := 0; i <= maxXrayConfigEntries; i++ {
		name := filepath.Join(dir, "entry-"+strconv.Itoa(i)+".txt")
		if err := os.WriteFile(name, nil, 0600); err != nil {
			t.Fatal(err)
		}
	}
	if got := readXrayLogSettings(dir); got != (xrayLogSettings{}) {
		t.Fatalf("oversized config directory should fail closed: %+v", got)
	}
}

func TestXrayLogSettingsBoundFragmentCount(t *testing.T) {
	dir := t.TempDir()
	for i := 0; i <= maxXrayLogFragments; i++ {
		name := filepath.Join(dir, "fragment-"+strconv.Itoa(i)+".json")
		if err := os.WriteFile(name, []byte(`{"log":{"loglevel":"info"}}`), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if got := readXrayLogSettings(dir); got != (xrayLogSettings{}) {
		t.Fatalf("excessive fragment count should fail closed: %+v", got)
	}
}

func TestXrayLogSettingsMissingDirectoryDoesNotAssumeDefaultPaths(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing")
	if got := readXrayLogSettings(missing); got != (xrayLogSettings{}) {
		t.Fatalf("unreadable config must not imply default log paths: %+v", got)
	}
}

func TestXKeenStatusReadsConfiguredLogFiles(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("XKeen log paths use Linux absolute paths")
	}
	dir := t.TempDir()
	errorPath := filepath.Join(dir, "custom-error.log")
	accessPath := filepath.Join(dir, "custom-access.log")
	if err := os.WriteFile(errorPath, []byte("failed vless://user@host:443?pbk=secret\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(accessPath, []byte("accepted direct request\n"), 0600); err != nil {
		t.Fatal(err)
	}
	fragment, err := json.Marshal(map[string]any{"log": map[string]any{"error": errorPath, "access": accessPath, "loglevel": "warning"}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "01_log.json"), fragment, 0600); err != nil {
		t.Fatal(err)
	}
	status := readXKeenStatusCommandWithConfig(context.Background(), "/nonexistent/xkeen", dir)
	if status.XrayErrorPath != errorPath || status.XrayAccessPath != accessPath || len(status.XrayErrorLog) != 1 || len(status.XrayAccessLog) != 1 {
		t.Fatalf("configured logs were not loaded: %+v", status)
	}
	if strings.Contains(status.XrayErrorLog[0], "pbk=secret") || strings.Contains(status.XrayErrorLog[0], "vless://") {
		t.Fatalf("secret leaked from configured error log: %q", status.XrayErrorLog[0])
	}
}
