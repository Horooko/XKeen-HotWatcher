package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestTransparentPortsFromXKeenHybridInbound(t *testing.T) {
	dir := t.TempDir()
	config := `{
	  "inbounds": [
	    {"tag":"redirect","port":61219,"protocol":"dokodemo-door","settings":{"network":"tcp","followRedirect":true}},
	    {"tag":"tproxy","port":61219,"protocol":"dokodemo-door","settings":{"network":"udp","followRedirect":true},"streamSettings":{"sockopt":{"tproxy":"tproxy"}}}
	  ]
	}`
	if err := os.WriteFile(filepath.Join(dir, "03_inbounds.json"), []byte(config), 0600); err != nil {
		t.Fatal(err)
	}
	tcp, udp := transparentPorts(dir)
	if tcp != 61219 || udp != 61219 {
		t.Fatalf("ports = %d/%d", tcp, udp)
	}
}

func TestParseXKeenLANInterception(t *testing.T) {
	nat := `*nat
:PREROUTING ACCEPT [0:0]
:xkeen - [0:0]
[17:1020] -A PREROUTING -p tcp -m conntrack ! --ctstate INVALID -j xkeen
[11:660] -A xkeen -p tcp -j REDIRECT --to-ports 61219
COMMIT`
	mangle := `*mangle
:PREROUTING ACCEPT [0:0]
:xkeen - [0:0]
[8:640] -A PREROUTING -p udp -j xkeen
[7:560] -A xkeen -p udp -j TPROXY --on-ip 0.0.0.0 --on-port 61219 --tproxy-mark 0x111/0xffffffff
COMMIT`
	tcp := parseInterceptionRules(nat, "tcp", "REDIRECT", 61219)
	udp := parseInterceptionRules(mangle, "udp", "TPROXY", 61219)
	if !tcp.Present || tcp.IngressPackets != 17 || tcp.RedirectedPackets != 11 {
		t.Fatalf("TCP route = %+v", tcp)
	}
	if !udp.Present || udp.IngressPackets != 8 || udp.RedirectedPackets != 7 {
		t.Fatalf("UDP route = %+v", udp)
	}
}

func TestParseInterceptionDoesNotCountDifferentPortOrChain(t *testing.T) {
	rules := `*nat
:xkeen - [0:0]
[9:540] -A PREROUTING -p tcp -j xkeen_force
[9:540] -A xkeen -p tcp -j REDIRECT --to-ports 11111
COMMIT`
	got := parseInterceptionRules(rules, "tcp", "REDIRECT", 61219)
	if !got.Known || got.Present || got.Missing != "prerouting_jump_missing" || got.IngressPackets != 0 || got.RedirectedPackets != 0 {
		t.Fatalf("wrong chain/port was accepted: %+v", got)
	}
}

func TestParseInterceptionReportsMissingTarget(t *testing.T) {
	rules := `*mangle
:xkeen - [0:0]
[3:180] -A PREROUTING -p udp -j xkeen
[3:180] -A xkeen -p udp -j ACCEPT
COMMIT`
	got := parseInterceptionRules(rules, "udp", "TPROXY", 61219)
	if !got.Known || got.Present || got.Missing != "redirect_target_missing" || got.IngressPackets != 3 {
		t.Fatalf("missing TPROXY was not reported: %+v", got)
	}
}

func TestParseInterceptionAcceptsXKeenFullPolicy(t *testing.T) {
	rules := `*nat
:xkeen_force - [0:0]
[4:240] -A PREROUTING -p tcp -m connmark --mark 0x111 -j xkeen_force
[4:240] -A xkeen_force -p tcp -j REDIRECT --to-ports 61219
COMMIT`
	got := parseInterceptionRules(rules, "tcp", "REDIRECT", 61219)
	if !got.Present || got.IngressPackets != 4 || got.RedirectedPackets != 4 {
		t.Fatalf("full policy route = %+v", got)
	}
}
