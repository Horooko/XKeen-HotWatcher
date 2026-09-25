package main

import (
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
