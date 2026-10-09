package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDNSFirewallDistinguishesEarlyBypassFromOldException(t *testing.T) {
	mangle := strings.Join([]string{
		"*mangle",
		"[0:0] -A PREROUTING -m set --match-set xkeen_deny_mac src -j RETURN",
		"[10:600] -A PREROUTING -p udp -m udp --dport 53 -j RETURN",
		"[20:1200] -A PREROUTING -p udp -j xkeen",
		"[0:0] -A xkeen -d 192.168.0.0/16 -p udp ! --dport 53 -j RETURN",
		"[0:0] -A xkeen -p udp -j TPROXY --on-port 61219",
	}, "\n")
	nat := "[20:2000] -A PREROUTING -j _NDM_DNS_REDIRECT\n" +
		"[15:1500] -A _NDM_DNS_REDIRECT -j _NDM_HOTSPOT_DNSREDIR\n" +
		"[12:1000] -A _NDM_HOTSPOT_DNSREDIR -p udp --dport 53 -j REDIRECT --to-ports 41100\n"
	got := parseDNSFirewall(mangle, nat)
	if got.BypassPosition != 2 || got.XKeenPosition != 3 || !got.OldDNSException || got.PrivateReturn || !got.KeeneticChainReachable || !got.KeeneticDNSRedirect || got.KeeneticProxyPort != 41100 {
		t.Fatalf("unexpected DNS path: %+v", got)
	}
	withoutBypass := strings.Replace(mangle, "[10:600] -A PREROUTING -p udp -m udp --dport 53 -j RETURN\n", "", 1)
	got = parseDNSFirewall(withoutBypass, nat)
	if got.BypassPosition != 0 || got.XKeenPosition != 2 || !got.OldDNSException {
		t.Fatalf("old UDP/53 exception was hidden: %+v", got)
	}
	scoped := strings.Replace(mangle, "-p udp -m udp --dport 53 -j RETURN", "-i br1 -p udp -m udp --dport 53 -j RETURN", 1)
	if got := parseDNSFirewall(scoped, nat); got.BypassPosition != 0 {
		t.Fatalf("scoped bypass falsely accepted: %+v", got)
	}
	forceFirst := strings.Replace(mangle, "[10:600] -A PREROUTING", "[1:60] -A PREROUTING -p udp -j xkeen_force\n[10:600] -A PREROUTING", 1)
	if got := parseDNSFirewall(forceFirst, nat); got.XKeenPosition != 2 || got.BypassPosition != 3 {
		t.Fatalf("early force jump was missed: %+v", got)
	}
}

func TestSavedProxyDNSReadsOnlyAllowlistedAssignment(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "S05xkeen")
	if err := os.WriteFile(file, []byte("secret=do-not-print\nproxy_dns=\"off\"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if got := savedProxyDNS(file); got != "off" {
		t.Fatalf("unexpected setting %q", got)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(file, link); err == nil && savedProxyDNS(link) != "" {
		t.Fatal("symlink was read")
	}
}

func TestValidRouterDNSReplyRequiresAnswerAndMatchingID(t *testing.T) {
	reply := []byte{0x12, 0x34, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0}
	if !validRouterDNSReply(reply, []byte{0x12, 0x34}) {
		t.Fatal("valid DNS response rejected")
	}
	if validRouterDNSReply(reply, []byte{0x12, 0x35}) {
		t.Fatal("mismatched DNS response accepted")
	}
	reply[6] = 0
	reply[7] = 0
	if validRouterDNSReply(reply, []byte{0x12, 0x34}) {
		t.Fatal("empty DNS answer accepted")
	}
}
