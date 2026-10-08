package hotwatcher

import (
	"context"
	"crypto/x509"
	"fmt"
	"net"
	"strings"
	"testing"
)

func TestURLTestFailureReasonsDistinguishRouterErrorsWithoutLeakingHosts(t *testing.T) {
	for _, tc := range []struct {
		err  error
		want string
	}{
		{fmt.Errorf("redirect: %w", errURLTestExternalRedirect), "перенаправил на другой домен"},
		{&net.DNSError{Err: "lookup failed", Name: "private.example"}, "ошибка DNS"},
		{x509.UnknownAuthorityError{}, "сертификата TLS"},
		{context.DeadlineExceeded, "время ожидания"},
	} {
		got := urlTestFailureReason(tc.err)
		if !strings.Contains(got, tc.want) || strings.Contains(got, "private.example") {
			t.Fatalf("reason for %T: %q", tc.err, got)
		}
	}
}
