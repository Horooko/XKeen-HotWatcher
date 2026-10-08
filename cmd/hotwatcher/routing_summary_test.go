package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRoutingSummaryDistinguishesBalancerFromStaticOutbound(t *testing.T) {
	dir := t.TempDir()
	data := `{"routing":{"rules":[{"inboundTag":["redirect"],"balancerTag":"proxy"},{"inboundTag":["tproxy"],"outboundTag":"vless-reality"},{"inboundTag":["api"],"outboundTag":"block"}]}}`
	if err := os.WriteFile(filepath.Join(dir, "05_routing.json"), []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	got := strings.Join(routingSummary(dir), " ")
	if !strings.Contains(got, "balancer proxy=1") || !strings.Contains(got, "статический vless-reality=1") || !strings.Contains(got, "direct/block=0") {
		t.Fatal(got)
	}
}
