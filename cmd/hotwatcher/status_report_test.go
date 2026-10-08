package main

import (
	hw "local/xkeen-hot-watcher/internal/hotwatcher"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestStatusReportRequiresSession(t *testing.T) {
	c := hw.Defaults()
	c.StateDir = filepath.Join(t.TempDir(), "state")
	w, err := newWebUI(c, hw.New(c))
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest("GET", "http://"+c.WebUIListen+"/api/diagnostics/report", nil)
	response := httptest.NewRecorder()
	w.handler().ServeHTTP(response, request)
	if response.Code != 401 {
		t.Fatalf("unauthenticated report accepted: %d", response.Code)
	}
}

func TestBoundedReportLogMarksTruncationAndRedactsSecrets(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.jsonl")
	secret := "vless://123e4567-e89b-12d3-a456-426614174000@secret.example.com:443?token=very-secret"
	content := strings.Repeat("old event\n", reportLogLimit/10) + "latest " + secret + " 203.0.113.9\n"
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	lines := strings.Join(boundedReportLog(path), "\n")
	if !strings.Contains(lines, "усечено") || !strings.Contains(lines, "latest") {
		t.Fatalf("expected marked tail, got %q", lines[:min(len(lines), 300)])
	}
	for _, secretPart := range []string{"very-secret", "secret.example.com", "203.0.113.9", "123e4567"} {
		if strings.Contains(lines, secretPart) {
			t.Fatalf("secret part %q leaked", secretPart)
		}
	}
}

func TestBoundedReportLogRejectsSymlink(t *testing.T) {
	dir := t.TempDir()
	actual := filepath.Join(dir, "actual.log")
	link := filepath.Join(dir, "link.log")
	if err := os.WriteFile(actual, []byte("secret"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(actual, link); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	result := strings.Join(boundedReportLog(link), "\n")
	if strings.Contains(result, "secret") || !strings.Contains(result, "небезопасен") {
		t.Fatalf("unsafe log result: %q", result)
	}
}

func TestSafeReportLineRedactsIPv6(t *testing.T) {
	for _, address := range []string{"2001:db8::1", "::1"} {
		result := safeReportLine("server=" + address)
		if strings.Contains(result, address) || !strings.Contains(result, "[IP скрыт]") {
			t.Fatalf("IPv6 address leaked: %q", result)
		}
	}
}

func TestBoundedReportLogIncludesShortFileWithoutTruncationMarker(t *testing.T) {
	path := filepath.Join(t.TempDir(), "small.log")
	if err := os.WriteFile(path, []byte("first\nsecond\n"), 0600); err != nil {
		t.Fatal(err)
	}
	result := strings.Join(boundedReportLog(path), "\n")
	if !strings.Contains(result, "first") || !strings.Contains(result, "second") || strings.Contains(result, "Начало журнала усечено") {
		t.Fatalf("short journal should be complete: %q", result)
	}
}

func TestReportProcessesClassifiesServerAndAPIWithoutArguments(t *testing.T) {
	proc := t.TempDir()
	for pid, args := range map[string]string{
		"100": "/opt/sbin/xray\x00run\x00",
		"101": "/opt/sbin/xray\x00api\x00lso\x00--server=secret.example.com\x00",
	} {
		dir := filepath.Join(proc, pid)
		if err := os.Mkdir(dir, 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "comm"), []byte("xray\n"), 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "cmdline"), []byte(args), 0600); err != nil {
			t.Fatal(err)
		}
	}
	result := strings.Join(reportProcesses(proc, "/opt/sbin/xray", "/opt/etc/xray/configs", "/opt/var/lib/hotwatcher"), "\n")
	for _, wanted := range []string{"PID 100", "PID 101", "основной Xray", "клиент Xray API", "Основных процессов Xray: 1"} {
		if !strings.Contains(result, wanted) {
			t.Errorf("missing %q in %q", wanted, result)
		}
	}
	if strings.Contains(result, "secret.example.com") {
		t.Fatal("process arguments leaked")
	}
}

func TestModuleCheckSeparatesInstalledFilesFromLoadedModules(t *testing.T) {
	dir := t.TempDir()
	proc := filepath.Join(dir, "modules")
	modules := filepath.Join(dir, "lib")
	if err := os.Mkdir(modules, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(proc, []byte("xt_comment 123 0 - Live 0x0\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(modules, "xt_comment.ko"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	files, unloaded, ok := moduleCheck(proc, []string{modules}, []string{"xt_comment", "xt_multiport"})
	if !ok || len(files) != 1 || files[0] != "xt_multiport" || len(unloaded) != 1 || unloaded[0] != "xt_multiport" {
		t.Fatalf("unexpected module state: files=%v unloaded=%v ok=%v", files, unloaded, ok)
	}
}

func TestBootLoaderCheckDoesNotClaimItRanAfterReboot(t *testing.T) {
	path := filepath.Join(t.TempDir(), "S04xkeen-netfilter-modules")
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if got := bootLoaderCheck(path); got.State != "issue" {
		t.Fatalf("non-executable loader should be an issue: %+v", got)
	}
	if err := os.Chmod(path, 0700); err != nil {
		t.Fatal(err)
	}
	if got := bootLoaderCheck(path); got.State != "ok" || !strings.Contains(got.Detail, "не проверено") {
		t.Fatalf("executable loader should state verification limit: %+v", got)
	}
}

func TestStatusReportTextContainsChecklist(t *testing.T) {
	report := statusReport{Checks: []statusCheck{newStatusCheck("lan-tcp", "Перехват LAN", "IPv4 TCP", "ok", "Правило найдено")}}
	report.finish()
	if !strings.Contains(report.Text, "=== Чек-лист ===") || !strings.Contains(report.Text, "[OK] Перехват LAN / IPv4 TCP") {
		t.Fatalf("checklist missing in text export: %q", report.Text)
	}
}

func TestNetfilterComponentState(t *testing.T) {
	for _, item := range []struct{ output, want string }{
		{"components: base,dhcpd,\n            kmod-netfilter,ppe", "ok"},
		{"components: base,dhcpd,ppe", "issue"},
		{"no component list", "unknown"},
	} {
		if got := netfilterComponentState(item.output); got != item.want {
			t.Errorf("%q: got %s, want %s", item.output, got, item.want)
		}
	}
}

func TestTPROXYPolicyRouteRequiresMarkAndLocalRoute(t *testing.T) {
	rules := "99: from all fwmark 0x111 lookup 111\n"
	routes := "local default dev lo  scope host\n"
	if !hasTPROXYPolicyRoute(rules, routes, "0x111", "111") {
		t.Fatal("valid policy route was not recognized")
	}
	if hasTPROXYPolicyRoute(rules, routes, "0x222", "111") || hasTPROXYPolicyRoute(rules, "", "0x111", "111") {
		t.Fatal("missing policy route was accepted")
	}
}
