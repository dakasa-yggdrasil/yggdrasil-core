//go:build linux && nativequalification

package httpapi

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestQualificationRegistrationClockRequestGuards(t *testing.T) {
	for _, mode := range []string{"no_verified_peer", "query", "body", "method", "missing_store"} {
		t.Run(mode, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "https://core.invalid/internal/capacity/guest-provisioning/preregistrations/id/qualification-registration-clock", nil)
			req.TLS = &tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{{}}}}
			switch mode {
			case "no_verified_peer":
				req.TLS = &tls.ConnectionState{}
			case "query":
				req.URL.ForceQuery = true
			case "body":
				req = httptest.NewRequest(http.MethodGet, "https://core.invalid/", strings.NewReader("x"))
				req.TLS = &tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{{}}}}
			case "method":
				req.Method = http.MethodPost
			}
			_, err := guestQualificationRegistrationClock(context.Background(), repository.CapacityStore{}, "p", "id", strings.Repeat("a", 64), req)
			if !errors.Is(err, repository.ErrCapacityMutationAuthorization) {
				t.Fatal("unowned clock read accepted")
			}
		})
	}
}
