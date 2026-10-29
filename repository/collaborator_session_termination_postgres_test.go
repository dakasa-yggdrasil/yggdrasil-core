package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

func sessionPolicyPostgres(t *testing.T) *sql.DB {
	t.Helper()
	dsn := os.Getenv("DB_URL")
	if dsn == "" {
		if os.Getenv("REQUIRE_SESSION_LIFECYCLE_POSTGRES") == "true" {
			t.Fatal("DB_URL is required by the session lifecycle PostgreSQL gate")
		}
		t.Skip("PostgreSQL runs in CI")
	}
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatalf("open PostgreSQL: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := db.Ping(); err != nil {
		t.Fatalf("PostgreSQL unavailable: %v", err)
	}
	return db
}

// sessionPolicyClient registers one OIDC client so refresh tokens can be
// written (oidc_refresh_tokens.client_id is a foreign key).
func sessionPolicyClient(t *testing.T, db *sql.DB) string {
	t.Helper()
	clientID := "session-policy-ci-" + uuid.NewString()
	if err := UpsertOIDCClient(context.Background(), db, model.OIDCClient{
		ClientID:               clientID,
		ClientSecretHash:       "$2a$10$irrelevant",
		RedirectURIs:           []string{"https://session-policy.example.test/cb"},
		PostLogoutRedirectURIs: []string{},
		Scopes:                 []string{"openid"},
		GrantTypes:             []string{"authorization_code", "refresh_token"},
		PKCERequired:           true,
	}); err != nil {
		t.Fatalf("OIDC client fixture failed: %v", err)
	}
	t.Cleanup(func() {
		_, _ = db.Exec(`DELETE FROM public.oidc_refresh_tokens WHERE client_id=$1`, clientID)
		_, _ = db.Exec(`DELETE FROM public.oidc_clients WHERE client_id=$1`, clientID)
	})
	return clientID
}

func sessionPolicyPerson(t *testing.T, db *sql.DB, status string) model.Collaborator {
	t.Helper()
	id := uuid.NewString()
	c, err := CreateCollaborator(context.Background(), db, model.CreateCollaboratorRequest{
		Slug: "session-policy-" + id, DisplayName: "Session Policy CI", PrimaryEmail: id + "@example.test", Status: status,
	})
	if err != nil {
		t.Fatalf("collaborator fixture failed: %v", err)
	}
	t.Cleanup(func() { _, _ = db.Exec(`DELETE FROM public.collaborators WHERE id=$1`, c.ID) })
	return c
}

// sessionPolicyCredentials opens one console session and one refresh token,
// as a login would.
func sessionPolicyCredentials(t *testing.T, db *sql.DB, c model.Collaborator, clientID string) string {
	t.Helper()
	ctx := context.Background()
	_, token, err := CreateAuthSession(ctx, db, c.ID, nil, time.Hour)
	if err != nil {
		t.Fatalf("session fixture failed: %v", err)
	}
	if err := CreateOIDCRefreshToken(ctx, db, model.OIDCRefreshToken{
		Token: "rt-" + uuid.NewString(), CollaboratorID: c.ID, ClientID: clientID,
		Scopes: []string{"openid"}, ExpiresAt: time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatalf("refresh token fixture failed: %v", err)
	}
	return token
}

type sessionPolicyState struct {
	liveSessions, liveRefreshTokens int
	revocations                     []sessionPolicyRevocation
	events                          []sessionPolicyEvent
}

type sessionPolicyRevocation struct {
	id       uuid.UUID
	reason   string
	global   bool
	metadata map[string]any
}

type sessionPolicyEvent struct {
	payload        map[string]any
	idempotencyKey string
}

func sessionPolicyRead(t *testing.T, db *sql.DB, id uuid.UUID) sessionPolicyState {
	t.Helper()
	var st sessionPolicyState
	if err := db.QueryRow(`SELECT COUNT(*) FROM public.auth_sessions WHERE collaborator_id=$1 AND revoked_at IS NULL`, id).Scan(&st.liveSessions); err != nil {
		t.Fatalf("count sessions: %v", err)
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM public.oidc_refresh_tokens WHERE collaborator_id=$1 AND revoked_at IS NULL`, id).Scan(&st.liveRefreshTokens); err != nil {
		t.Fatalf("count refresh tokens: %v", err)
	}
	rows, err := db.Query(`SELECT id, reason, session_jti IS NULL, metadata FROM public.session_revocation WHERE collaborator_id=$1 ORDER BY revoked_at, id`, id)
	if err != nil {
		t.Fatalf("read revocations: %v", err)
	}
	for rows.Next() {
		var rev sessionPolicyRevocation
		var raw []byte
		if err := rows.Scan(&rev.id, &rev.reason, &rev.global, &raw); err != nil {
			t.Fatalf("scan revocation: %v", err)
		}
		if err := json.Unmarshal(raw, &rev.metadata); err != nil {
			t.Fatalf("decode revocation metadata: %v", err)
		}
		st.revocations = append(st.revocations, rev)
	}
	_ = rows.Close()
	rows, err = db.Query(`SELECT payload, COALESCE(idempotency_key, '') FROM public.event_log WHERE type=$1 AND aggregate_type='collaborator' AND aggregate_id=$2 ORDER BY sequence`, EventTypeCollaboratorSessionTerminated, id.String())
	if err != nil {
		t.Fatalf("read events: %v", err)
	}
	for rows.Next() {
		var ev sessionPolicyEvent
		var raw []byte
		if err := rows.Scan(&raw, &ev.idempotencyKey); err != nil {
			t.Fatalf("scan event: %v", err)
		}
		if err := json.Unmarshal(raw, &ev.payload); err != nil {
			t.Fatalf("decode event payload: %v", err)
		}
		st.events = append(st.events, ev)
	}
	_ = rows.Close()
	return st
}

// requireStatusTermination checks one termination of a status change: the
// revocation row (global, reason, metadata) and its event (payload contract
// and idempotency key) match.
func requireStatusTermination(t *testing.T, c model.Collaborator, rev sessionPolicyRevocation, ev sessionPolicyEvent, reason, from, to string) {
	t.Helper()
	if rev.reason != reason || !rev.global {
		t.Fatalf("revocation reason=%q global=%v, want %q global", rev.reason, rev.global, reason)
	}
	if rev.metadata["source"] != "collaborator_status_change" || rev.metadata["from_status"] != from || rev.metadata["to_status"] != to || len(rev.metadata) != 3 {
		t.Fatalf("revocation metadata=%v, want {source, from_status=%s, to_status=%s}", rev.metadata, from, to)
	}
	p := ev.payload
	if p["collaborator_id"] != c.ID.String() || p["reason"] != reason || p["revocation_id"] != rev.id.String() || p["primary_email"] != c.PrimaryEmail {
		t.Fatalf("event payload=%v", p)
	}
	if emitted, _ := p["emitted_at"].(string); emitted == "" {
		t.Fatalf("event payload has no emitted_at: %v", p)
	}
	if ev.idempotencyKey != "session.terminated."+rev.id.String() {
		t.Fatalf("event idempotency key=%q", ev.idempotencyKey)
	}
}

func setStatusRaw(t *testing.T, db *sql.DB, id uuid.UUID, status string) {
	t.Helper()
	if _, err := db.Exec(`UPDATE public.collaborators SET status=$2 WHERE id=$1`, id, status); err != nil {
		t.Fatalf("raw status fixture %q failed: %v", status, err)
	}
}

func updateStatus(t *testing.T, db *sql.DB, id uuid.UUID, status string) model.Collaborator {
	t.Helper()
	updated, err := UpdateCollaborator(context.Background(), db, model.UpdateCollaboratorRequest{ID: id.String(), Status: &status})
	if err != nil {
		t.Fatalf("status change to %q failed: %v", status, err)
	}
	return updated
}

// The status choke point (ADR-0087): every status writer goes through
// UpdateCollaboratorTx, which applies the session policy in the status
// change's own transaction, against the migrated schema.
func TestCollaboratorStatusSessionPolicyPostgres(t *testing.T) {
	db := sessionPolicyPostgres(t)
	ctx := context.Background()
	clientID := sessionPolicyClient(t, db)

	t.Run("leaving_active_terminates_once", func(t *testing.T) {
		for _, tc := range []struct{ status, reason string }{
			{"on_leave", SessionRevocationReasonAdminRevoked},
			{"suspended", SessionRevocationReasonAdminRevoked},
			{"offboarded", SessionRevocationReasonOffboarded},
		} {
			t.Run(tc.status, func(t *testing.T) {
				c := sessionPolicyPerson(t, db, "active")
				token := sessionPolicyCredentials(t, db, c, clientID)
				updateStatus(t, db, c.ID, tc.status)
				st := sessionPolicyRead(t, db, c.ID)
				if st.liveSessions != 0 || st.liveRefreshTokens != 0 {
					t.Fatalf("live sessions=%d refresh tokens=%d after %s", st.liveSessions, st.liveRefreshTokens, tc.status)
				}
				if len(st.revocations) != 1 || len(st.events) != 1 {
					t.Fatalf("revocations=%d events=%d, want exactly one each", len(st.revocations), len(st.events))
				}
				requireStatusTermination(t, c, st.revocations[0], st.events[0], tc.reason, "active", tc.status)
				if _, _, err := ResolveAuthSession(ctx, db, token); err != ErrAuthSessionNotFound {
					t.Fatalf("a terminated session resolved: %v", err)
				}
			})
		}
	})

	t.Run("same_status_write_is_a_noop", func(t *testing.T) {
		c := sessionPolicyPerson(t, db, "active")
		sessionPolicyCredentials(t, db, c, clientID)
		// Raw SQL bypasses the policy, so the session is still live while the
		// row already says suspended: a same-status write must not terminate.
		setStatusRaw(t, db, c.ID, "suspended")
		updateStatus(t, db, c.ID, "suspended")
		st := sessionPolicyRead(t, db, c.ID)
		if st.liveSessions != 1 || st.liveRefreshTokens != 1 || len(st.revocations) != 0 || len(st.events) != 0 {
			t.Fatalf("same-status write changed sessions: %+v", st)
		}
	})

	t.Run("non_status_write_terminates_nothing", func(t *testing.T) {
		c := sessionPolicyPerson(t, db, "active")
		sessionPolicyCredentials(t, db, c, clientID)
		name := "Session Policy Renamed"
		if _, err := UpdateCollaborator(ctx, db, model.UpdateCollaboratorRequest{ID: c.ID.String(), DisplayName: &name}); err != nil {
			t.Fatalf("rename failed: %v", err)
		}
		st := sessionPolicyRead(t, db, c.ID)
		if st.liveSessions != 1 || st.liveRefreshTokens != 1 || len(st.revocations) != 0 || len(st.events) != 0 {
			t.Fatalf("non-status write changed sessions: %+v", st)
		}
	})

	t.Run("moving_between_statuses_that_cannot_sign_in_terminates_again", func(t *testing.T) {
		c := sessionPolicyPerson(t, db, "active")
		sessionPolicyCredentials(t, db, c, clientID)
		updateStatus(t, db, c.ID, "suspended")
		// A login that raced the suspension left a session and a token behind.
		sessionPolicyCredentials(t, db, c, clientID)
		updateStatus(t, db, c.ID, "offboarded")
		st := sessionPolicyRead(t, db, c.ID)
		if st.liveSessions != 0 || st.liveRefreshTokens != 0 {
			t.Fatalf("the second termination left live sessions=%d refresh tokens=%d", st.liveSessions, st.liveRefreshTokens)
		}
		if len(st.revocations) != 2 || len(st.events) != 2 {
			t.Fatalf("revocations=%d events=%d, want two each", len(st.revocations), len(st.events))
		}
		requireStatusTermination(t, c, st.revocations[0], st.events[0], SessionRevocationReasonAdminRevoked, "active", "suspended")
		requireStatusTermination(t, c, st.revocations[1], st.events[1], SessionRevocationReasonOffboarded, "suspended", "offboarded")
	})

	t.Run("reactivation_revokes_leftovers_without_an_event", func(t *testing.T) {
		c := sessionPolicyPerson(t, db, "active")
		sessionPolicyCredentials(t, db, c, clientID)
		updateStatus(t, db, c.ID, "suspended")
		leftover := sessionPolicyCredentials(t, db, c, clientID)
		updateStatus(t, db, c.ID, "active")
		st := sessionPolicyRead(t, db, c.ID)
		if st.liveSessions != 0 || st.liveRefreshTokens != 0 {
			t.Fatalf("reactivation revived live sessions=%d refresh tokens=%d", st.liveSessions, st.liveRefreshTokens)
		}
		if len(st.revocations) != 1 || len(st.events) != 1 {
			t.Fatalf("reactivation recorded revocations=%d events=%d, want only the suspension's", len(st.revocations), len(st.events))
		}
		if _, _, err := ResolveAuthSession(ctx, db, leftover); err != ErrAuthSessionNotFound {
			t.Fatalf("a session opened while suspended survived reactivation: %v", err)
		}
	})

	t.Run("rollback_keeps_sessions_and_emits_nothing", func(t *testing.T) {
		c := sessionPolicyPerson(t, db, "active")
		token := sessionPolicyCredentials(t, db, c, clientID)
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			t.Fatalf("begin: %v", err)
		}
		suspended := "suspended"
		if _, err := UpdateCollaboratorTx(ctx, tx, model.UpdateCollaboratorRequest{ID: c.ID.String(), Status: &suspended}); err != nil {
			_ = tx.Rollback()
			t.Fatalf("suspend in transaction: %v", err)
		}
		if err := tx.Rollback(); err != nil {
			t.Fatalf("rollback: %v", err)
		}
		current, err := GetCollaborator(ctx, db, c.ID.String())
		if err != nil || current.Status != "active" {
			t.Fatalf("status after rollback=%q err=%v", current.Status, err)
		}
		st := sessionPolicyRead(t, db, c.ID)
		if st.liveSessions != 1 || st.liveRefreshTokens != 1 || len(st.revocations) != 0 || len(st.events) != 0 {
			t.Fatalf("a rolled back status change left effects: %+v", st)
		}
		if _, _, err := ResolveAuthSession(ctx, db, token); err != nil {
			t.Fatalf("the session did not survive the rollback: %v", err)
		}
	})

	t.Run("concurrent_suspends_terminate_once", func(t *testing.T) {
		c := sessionPolicyPerson(t, db, "active")
		sessionPolicyCredentials(t, db, c, clientID)
		const writers = 6
		start := make(chan struct{})
		errs := make([]error, writers)
		var wg sync.WaitGroup
		for i := 0; i < writers; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				<-start
				suspended := "suspended"
				_, errs[i] = UpdateCollaborator(ctx, db, model.UpdateCollaboratorRequest{ID: c.ID.String(), Status: &suspended})
			}(i)
		}
		close(start)
		wg.Wait()
		succeeded := 0
		for _, err := range errs {
			switch {
			case err == nil:
				succeeded++
			case errors.Is(err, ErrConcurrentUpdate):
			default:
				t.Fatalf("a concurrent suspend failed with %v", err)
			}
		}
		if succeeded == 0 {
			t.Fatal("no concurrent suspend succeeded")
		}
		st := sessionPolicyRead(t, db, c.ID)
		if st.liveSessions != 0 || st.liveRefreshTokens != 0 || len(st.revocations) != 1 || len(st.events) != 1 {
			t.Fatalf("concurrent suspends: %+v, want one termination", st)
		}
		requireStatusTermination(t, c, st.revocations[0], st.events[0], SessionRevocationReasonAdminRevoked, "active", "suspended")
	})

	t.Run("resolution_reads_current_status", func(t *testing.T) {
		c := sessionPolicyPerson(t, db, "active")
		token := sessionPolicyCredentials(t, db, c, clientID)
		if _, _, err := ResolveAuthSession(ctx, db, token); err != nil {
			t.Fatalf("active session: %v", err)
		}
		setStatusRaw(t, db, c.ID, "suspended")
		if _, _, err := ResolveAuthSession(ctx, db, token); err != ErrAuthSessionNotFound {
			t.Fatalf("a session of a suspended collaborator resolved: %v", err)
		}
		setStatusRaw(t, db, c.ID, "active")
		if _, _, err := ResolveAuthSession(ctx, db, token); err != nil {
			t.Fatalf("resolution did not read the restored status: %v", err)
		}
	})
}
