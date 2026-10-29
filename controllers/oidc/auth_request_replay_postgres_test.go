package oidc

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	"github.com/google/uuid"
	"github.com/zitadel/oidc/v3/pkg/oidc"
)

// The real provider, storage and migrated PostgreSQL prove that a closed
// authorization request mints nothing (ADR-0087). A bound request is a
// finished login waiting for its code, and GET <issuer>/authorize/callback
// ?id=<request> mints a fresh code from it with no new authentication. So a
// request is closed once its code was exchanged, when a termination or a
// reactivation sweeps the collaborator (suspend then unsuspend, credential
// reset), and when its lifetime passed. Its unexchanged codes stop
// exchanging too, and a login started after the sweep still works.
func TestCollaboratorAuthRequestReplayPostgres(t *testing.T) {
	if os.Getenv("DB_URL") == "" && os.Getenv("REQUIRE_SESSION_LIFECYCLE_POSTGRES") == "true" {
		t.Fatal("DB_URL is required by the session lifecycle PostgreSQL gate")
	}
	f := newNativeProtocolFixture(t)
	ctx := context.Background()
	s := NewStorage(f.db, f.issuer)

	codeCount := func(t *testing.T, requestID string) int {
		t.Helper()
		var count int
		if err := f.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM oidc_auth_codes WHERE auth_request_id=$1`, requestID).Scan(&count); err != nil {
			t.Fatalf("count codes: %v", err)
		}
		return count
	}
	// requireCallbackRefused replays the provider callback for a request and
	// requires no redirect, no code and no new code row.
	requireCallbackRefused := func(t *testing.T, requestID string) {
		t.Helper()
		before := codeCount(t, requestID)
		response := f.do(t, http.MethodGet, f.issuer+"/authorize/callback?id="+url.QueryEscape(requestID), nil, "")
		if response.StatusCode == http.StatusFound || strings.Contains(response.Header.Get("Location"), "code=") {
			t.Fatalf("a closed request resumed: status=%d location=%q", response.StatusCode, response.Header.Get("Location"))
		}
		if after := codeCount(t, requestID); after != before {
			t.Fatalf("a closed request saved a code: before=%d after=%d", before, after)
		}
		if err := s.SaveAuthCode(ctx, requestID, "closed-"+uuid.NewString()); !errors.Is(err, repository.ErrOIDCAuthRequestNotFound) {
			t.Fatalf("a closed request accepted a code: %v", err)
		}
	}
	setStatus := func(t *testing.T, status string) {
		t.Helper()
		if _, err := repository.UpdateCollaborator(ctx, f.db, model.UpdateCollaboratorRequest{ID: f.subject.String(), Status: &status}); err != nil {
			t.Fatalf("status change to %q failed: %v", status, err)
		}
	}

	t.Run("callback_after_exchange_is_refused", func(t *testing.T) {
		requestID, code, _, verifier := f.authorizeRequest(t, http.MethodGet)
		f.exchange(t, code, verifier, f.redirectURI, http.StatusOK, "")
		requireCallbackRefused(t, requestID)
		// A code row written for the consumed request without the provider
		// (as an old replay would have left behind) does not exchange.
		parsed, err := uuid.Parse(requestID)
		if err != nil {
			t.Fatal("request id fixture failed")
		}
		stale := "stale-" + uuid.NewString()
		if err := repository.SaveOIDCAuthCode(ctx, f.db, stale, parsed, time.Now().Add(5*time.Minute)); err != nil {
			t.Fatalf("stale code fixture failed: %v", err)
		}
		if _, err := s.AuthRequestByCode(ctx, stale); !errors.Is(err, repository.ErrOIDCAuthCodeNotFound) {
			t.Fatalf("a code of a consumed request exchanged: %v", err)
		}
	})

	t.Run("suspend_then_unsuspend_closes_bound_requests", func(t *testing.T) {
		requestID, code, _, verifier := f.authorizeRequest(t, http.MethodGet)
		setStatus(t, "suspended")
		setStatus(t, "active")
		requireCallbackRefused(t, requestID)
		f.exchange(t, code, verifier, f.redirectURI, http.StatusBadRequest, "invalid_grant")
		// A login started after the reactivation is not affected.
		fresh, _, freshVerifier := f.authorize(t, http.MethodGet)
		f.exchange(t, fresh, freshVerifier, f.redirectURI, http.StatusOK, "")
	})

	t.Run("credential_reset_closes_bound_requests", func(t *testing.T) {
		requestID, code, _, verifier := f.authorizeRequest(t, http.MethodGet)
		collab, err := repository.GetCollaborator(ctx, f.db, f.subject.String())
		if err != nil {
			t.Fatalf("read collaborator: %v", err)
		}
		tx, err := f.db.BeginTx(ctx, nil)
		if err != nil {
			t.Fatalf("begin: %v", err)
		}
		if _, err := repository.TerminateCollaboratorSessionsTx(ctx, tx, collab, repository.SessionRevocationReasonPasswordRotated, map[string]any{"source": "auth_request_replay_ci"}); err != nil {
			_ = tx.Rollback()
			t.Fatalf("credential replacement termination failed: %v", err)
		}
		if err := tx.Commit(); err != nil {
			t.Fatalf("commit: %v", err)
		}
		// The status stays active through a credential reset, so only the
		// closed request stops the replay.
		requireCallbackRefused(t, requestID)
		f.exchange(t, code, verifier, f.redirectURI, http.StatusBadRequest, "invalid_grant")
	})

	t.Run("expired_request_is_refused", func(t *testing.T) {
		subject := f.subject
		id, err := repository.CreateOIDCAuthRequest(ctx, f.db, model.OIDCAuthRequest{
			ClientID: f.clientID, CollaboratorID: &subject, RedirectURI: f.redirectURI, Scopes: []string{"openid"},
			CodeChallenge: oidc.NewSHACodeChallenge(strings.Repeat("e", 43)), CodeChallengeMethod: string(oidc.CodeChallengeMethodS256),
			ExpiresAt: time.Now().Add(-time.Minute),
		})
		if err != nil {
			t.Fatalf("expired request fixture failed: %v", err)
		}
		if _, err := s.AuthRequestByID(ctx, id.String()); !errors.Is(err, repository.ErrOIDCAuthRequestNotFound) {
			t.Fatalf("an expired request was honored: %v", err)
		}
		requireCallbackRefused(t, id.String())
	})
}
