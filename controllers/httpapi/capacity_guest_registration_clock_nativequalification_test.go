//go:build linux && nativequalification

package httpapi

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	"github.com/lib/pq"
	"io"
	"log"
	"net"
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
	guestRegistrationDiagnosticPrivacyContracts(t)
}

func guestRegistrationDiagnosticPrivacyContracts(t *testing.T) {
	const secret = "private-SQL-token-constraint-detail-DO-NOT-LOG"
	var output bytes.Buffer
	priorWriter, priorFlags, priorPrefix := log.Writer(), log.Flags(), log.Prefix()
	log.SetOutput(&output)
	log.SetFlags(log.Ldate | log.Ltime)
	log.SetPrefix("")
	defer func() { log.SetOutput(priorWriter); log.SetFlags(priorFlags); log.SetPrefix(priorPrefix) }()
	for _, item := range []struct {
		err          error
		class, state string
	}{
		{nil, "none", "none"},
		{fmt.Errorf("%s: %w", secret, repository.ErrCapacityConflict), "held", "none"},
		{fmt.Errorf("%s: %w", secret, context.Canceled), "cancelled", "none"},
		{fmt.Errorf("%s: %w", secret, context.DeadlineExceeded), "deadline", "none"},
		{&net.DNSError{Err: secret, IsTimeout: true}, "timeout", "none"},
		{&tls.CertificateVerificationError{Err: errors.New(secret)}, "tls", "none"},
		{fmt.Errorf("%s: %w", secret, io.ErrUnexpectedEOF), "io", "none"},
		{errors.New(secret + " context deadline exceeded"), "other", "none"},
		{fmt.Errorf("%s: %w", secret, &pq.Error{Code: "23505", Message: secret, Detail: secret, Constraint: secret}), "other", "23505"},
		{&pq.Error{Code: "XX000", Message: secret}, "other", "other"},
		{&pq.Error{Code: pq.ErrorCode(secret), Message: secret}, "other", "other"},
	} {
		output.Reset()
		guestRegistrationDiagnosticLog(item.err)
		text := output.String()
		want := "original_guest_registration_failure_diagnostic_v1 stage=unclassified class=" + item.class + " sqlstate=" + item.state
		if !strings.Contains(text, want) || strings.Count(text, "\n") != 1 || strings.Contains(text, secret) || strings.Contains(text, "XX000") || strings.Contains(text, "context deadline exceeded") {
			t.Fatal("closed error diagnostic leaked or misclassified original facts")
		}
	}
}
