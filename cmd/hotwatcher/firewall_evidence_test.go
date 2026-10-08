package main

import "testing"

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
