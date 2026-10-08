package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCountPortSocketsOnlyCountsListeningTCPAtPort(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tcp")
	data := "  sl  local_address rem_address st\n" +
		"   0: 0100007F:EF23 00000000:0000 0A\n" +
		"   1: 0100007F:EF23 00000000:0000 01\n" +
		"   2: 0100007F:0016 00000000:0000 0A\n"
	if err := os.WriteFile(path, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	count, known := countPortSockets(path, 61219, true)
	if !known || count != 1 {
		t.Fatalf("count=%d known=%v", count, known)
	}
}
