package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestXKeenHookSettingsOnlyKnownAssignments(t *testing.T) {
	path := filepath.Join(t.TempDir(), "proxy.sh")
	source := "#!/bin/sh\niptables_supported='false'\nip6tables_supported='true'\nmode_proxy='Hybrid'\nport_redirect='61219'\nport_tproxy=61219\ntable_id='111'\ntable_mark='0x111'\nsecret='never print this'\niptables_supported='$(bad)'\n"
	if err := os.WriteFile(path, []byte(source), 0600); err != nil {
		t.Fatal(err)
	}
	got := xkeenHookSettings(path)
	if got["iptables_supported"] != "false" || got["ip6tables_supported"] != "true" || got["mode_proxy"] != "Hybrid" || got["port_redirect"] != "61219" || got["port_tproxy"] != "61219" || got["table_id"] != "111" || got["table_mark"] != "0x111" {
		t.Fatalf("unexpected hook settings: %+v", got)
	}
	if len(got) != 7 {
		t.Fatalf("unexpected fields from hook: %+v", got)
	}
}

func TestXKeenHookSettingsRejectsSymlink(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "real")
	link := filepath.Join(dir, "proxy.sh")
	if err := os.WriteFile(real, []byte("iptables_supported='true'\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	if len(xkeenHookSettings(link)) != 0 {
		t.Fatal("symlink hook was read")
	}
}

func TestTailBufferKeepsLatestSyslog(t *testing.T) {
	w := &tailBuffer{max: 8}
	_, _ = w.Write([]byte("old log\n"))
	_, _ = w.Write([]byte("new failure"))
	if string(w.buf) != " failure" {
		t.Fatalf("tail = %q", w.buf)
	}
}

func TestSummarizeFirewallRules(t *testing.T) {
	nat := `*nat
:xkeen - [0:0]
:xkeen_force - [0:0]
[4:240] -A PREROUTING -p tcp -m connmark --mark 0x111 -j xkeen
[2:120] -A PREROUTING -p tcp -m dscp --dscp 61 -j xkeen_force
[4:240] -A xkeen -p tcp -j REDIRECT --to-ports 61219
[2:120] -A xkeen_force -p tcp -j REDIRECT --to-ports 1191
COMMIT`
	e := summarizeFirewallRules(nat, "tcp", "REDIRECT", 61219)
	if !e.Chain || !e.ForceChain || !e.Jump || !e.ForceJump || e.Target != 2 || e.PortTarget != 1 {
		t.Fatalf("unexpected firewall evidence: %+v", e)
	}
	mangle := `*mangle
:xkeen - [0:0]
[6:480] -A PREROUTING -p udp -j xkeen
[5:400] -A xkeen -p udp -j TPROXY --on-ip 0.0.0.0 --on-port 61219 --tproxy-mark 0x111/0xffffffff
COMMIT`
	e = summarizeFirewallRules(mangle, "udp", "TPROXY", 61219)
	if !e.Chain || e.ForceChain || !e.Jump || e.ForceJump || e.Target != 1 || e.PortTarget != 1 {
		t.Fatalf("unexpected TPROXY evidence: %+v", e)
	}
}

func TestSummarizeFirewallRulesIgnoresUnrelatedRules(t *testing.T) {
	rules := `*nat
:other - [0:0]
-A PREROUTING -p tcp -j other
-A other -p tcp -j REDIRECT --to-ports 61219
COMMIT`
	e := summarizeFirewallRules(rules, "tcp", "REDIRECT", 61219)
	if e.Chain || e.ForceChain || e.Jump || e.ForceJump || e.Target != 0 || e.PortTarget != 0 {
		t.Fatalf("unrelated rule counted as XKeen: %+v", e)
	}
}
