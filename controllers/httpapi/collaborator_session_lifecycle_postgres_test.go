package httpapi

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/contactphone"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	"github.com/google/uuid"
)

func sessionLifecycleHTTPPostgres(t *testing.T) *sql.DB {
	t.Helper()
	if os.Getenv("DB_URL") == "" && os.Getenv("REQUIRE_SESSION_LIFECYCLE_POSTGRES") == "true" {
		t.Fatal("DB_URL is required by the session lifecycle PostgreSQL gate")
	}
	return directoryHTTPPostgres(t)
}

// sessionLifecycleHTTPSignedIn creates a collaborator with MFA enrolled and an
// open console session.
func sessionLifecycleHTTPSignedIn(t *testing.T, db *sql.DB) (model.Collaborator, model.AuthSession, string) {
	t.Helper()
	person := directoryHTTPPerson(t, db, false)
	if _, err := db.Exec(`UPDATE public.auth_identities SET mfa_enrolled_at=NOW() WHERE collaborator_id=$1`, person.ID); err != nil {
		t.Fatal("MFA fixture failed")
	}
	session, token, err := repository.CreateAuthSession(context.Background(), db, person.ID, nil, time.Hour)
	if err != nil {
		t.Fatal("session fixture failed")
	}
	return person, session, token
}

type sessionLifecycleHTTPState struct {
	liveSessions, terminated, offboarded int
	revocationReasons                    []string
	revocationMetadata                   []map[string]any
}

func sessionLifecycleHTTPRead(t *testing.T, db *sql.DB, id uuid.UUID) sessionLifecycleHTTPState {
	t.Helper()
	var st sessionLifecycleHTTPState
	if err := db.QueryRow(`SELECT COUNT(*) FROM public.auth_sessions WHERE collaborator_id=$1 AND revoked_at IS NULL`, id).Scan(&st.liveSessions); err != nil {
		t.Fatalf("count sessions: %v", err)
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM public.event_log WHERE type=$1 AND aggregate_id=$2`, repository.EventTypeCollaboratorSessionTerminated, id.String()).Scan(&st.terminated); err != nil {
		t.Fatalf("count session.terminated: %v", err)
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM public.event_log WHERE type=$1 AND aggregate_id=$2`, repository.EventTypeCollaboratorOffboarded, id.String()).Scan(&st.offboarded); err != nil {
		t.Fatalf("count collaborator.offboarded: %v", err)
	}
	rows, err := db.Query(`SELECT reason, metadata FROM public.session_revocation WHERE collaborator_id=$1 ORDER BY revoked_at, id`, id)
	if err != nil {
		t.Fatalf("read revocations: %v", err)
	}
	defer rows.Close()
	for rows.Next() {
		var reason string
		var raw []byte
		var metadata map[string]any
		if err := rows.Scan(&reason, &raw); err != nil {
			t.Fatalf("scan revocation: %v", err)
		}
		if err := json.Unmarshal(raw, &metadata); err != nil {
			t.Fatalf("decode revocation metadata: %v", err)
		}
		st.revocationReasons = append(st.revocationReasons, reason)
		st.revocationMetadata = append(st.revocationMetadata, metadata)
	}
	return st
}

func sessionLifecycleHTTPStatus(t *testing.T, db *sql.DB, id uuid.UUID) string {
	t.Helper()
	c, err := repository.GetCollaborator(context.Background(), db, id.String())
	if err != nil {
		t.Fatalf("read collaborator: %v", err)
	}
	return c.Status
}

// The status rule over HTTP against the migrated schema (ADR-0087): every
// HTTP status writer terminates the sessions of a collaborator who can no
// longer sign in, the session endpoint then answers 401 and clears the
// cookie, a reactivation revives nothing, and SSO session reuse falls back
// to the interactive login instead of binding the OIDC request.
func TestCollaboratorSessionLifecycleHTTPPostgres(t *testing.T) {
	db := sessionLifecycleHTTPPostgres(t)
	ctx := context.Background()
	t.Setenv(contactphone.EnrollmentPolicyEnv, "false")

	admin, adminSession, adminToken := sessionLifecycleHTTPSignedIn(t, db)
	traits := map[string]any{"yggdrasil_admin": true}
	if _, err := repository.UpdateCollaborator(ctx, db, model.UpdateCollaboratorRequest{ID: admin.ID.String(), Traits: &traits}); err != nil {
		t.Fatal("admin fixture failed")
	}
	h := directoryHTTPHandler(t, db)
	client := 0
	do := func(method, path string, body any, token string, sessionID uuid.UUID) *httptest.ResponseRecorder {
		client++
		var payload string
		if body != nil {
			raw, _ := json.Marshal(body)
			payload = string(raw)
		}
		r := httptest.NewRequest(method, path, strings.NewReader(payload))
		r.RemoteAddr = fmt.Sprintf("198.51.100.%d:41000", client%250+1)
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("X-Actor", "session-lifecycle-ci")
		if token != "" {
			r.AddCookie(&http.Cookie{Name: authSessionCookieName(), Value: token})
			r.Header.Set(csrfHeaderName, computeCSRFToken(sessionID))
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	asAdmin := func(method, path string, body any) *httptest.ResponseRecorder {
		w := do(method, path, body, adminToken, adminSession.ID)
		if w.Code != http.StatusOK {
			t.Fatalf("%s %s: status=%d body=%s", method, path, w.Code, w.Body.String())
		}
		return w
	}
	sessionStatus := func(token string, sessionID uuid.UUID) (int, bool) {
		w := do(http.MethodGet, "/api/v1/auth/session", nil, token, sessionID)
		cleared := false
		for _, cookie := range w.Result().Cookies() {
			if cookie.Name == authSessionCookieName() && cookie.MaxAge < 0 {
				cleared = true
			}
		}
		return w.Code, cleared
	}

	t.Run("suspend_ends_the_session_and_unsuspend_does_not_revive", func(t *testing.T) {
		person, session, token := sessionLifecycleHTTPSignedIn(t, db)
		if code, _ := sessionStatus(token, session.ID); code != http.StatusOK {
			t.Fatalf("active session status=%d", code)
		}
		asAdmin(http.MethodPost, "/api/v1/collaborators/"+person.ID.String()+"/suspend", map[string]any{"reason": "investigation"})
		if code, cleared := sessionStatus(token, session.ID); code != http.StatusUnauthorized || !cleared {
			t.Fatalf("after suspend: status=%d cookie cleared=%v, want 401 and a cleared cookie", code, cleared)
		}
		st := sessionLifecycleHTTPRead(t, db, person.ID)
		if st.liveSessions != 0 || st.terminated != 1 || len(st.revocationReasons) != 1 || st.revocationReasons[0] != repository.SessionRevocationReasonAdminRevoked {
			t.Fatalf("suspend: %+v", st)
		}
		asAdmin(http.MethodPost, "/api/v1/collaborators/"+person.ID.String()+"/unsuspend", map[string]any{"reason": "cleared"})
		if sessionLifecycleHTTPStatus(t, db, person.ID) != "active" {
			t.Fatal("unsuspend did not reactivate")
		}
		if code, _ := sessionStatus(token, session.ID); code != http.StatusUnauthorized {
			t.Fatalf("unsuspend revived the old session: status=%d", code)
		}
		if st := sessionLifecycleHTTPRead(t, db, person.ID); st.terminated != 1 || len(st.revocationReasons) != 1 {
			t.Fatalf("unsuspend recorded a termination: %+v", st)
		}
	})

	t.Run("patch_status_terminates", func(t *testing.T) {
		person, session, token := sessionLifecycleHTTPSignedIn(t, db)
		asAdmin(http.MethodPatch, "/api/v1/collaborators/"+person.ID.String(), map[string]any{"status": "suspended"})
		st := sessionLifecycleHTTPRead(t, db, person.ID)
		if st.liveSessions != 0 || st.terminated != 1 || len(st.revocationReasons) != 1 || st.revocationReasons[0] != repository.SessionRevocationReasonAdminRevoked {
			t.Fatalf("PATCH status: %+v", st)
		}
		if code, _ := sessionStatus(token, session.ID); code != http.StatusUnauthorized {
			t.Fatalf("PATCH status left the session usable: %d", code)
		}
	})

	t.Run("long_absence_terminates_vacation_does_not", func(t *testing.T) {
		person, session, token := sessionLifecycleHTTPSignedIn(t, db)
		path := "/api/v1/collaborators/" + person.ID.String() + "/absence/start"
		asAdmin(http.MethodPost, path, map[string]any{"type": "vacation", "from": "2026-11-02", "to": "2026-11-13"})
		if sessionLifecycleHTTPStatus(t, db, person.ID) != "active" {
			t.Fatal("vacation changed the status")
		}
		if st := sessionLifecycleHTTPRead(t, db, person.ID); st.liveSessions != 1 || st.terminated != 0 || len(st.revocationReasons) != 0 {
			t.Fatalf("vacation ended sessions: %+v", st)
		}
		if code, _ := sessionStatus(token, session.ID); code != http.StatusOK {
			t.Fatalf("vacation refused the session: %d", code)
		}
		asAdmin(http.MethodPost, path, map[string]any{"type": "leave-medical", "from": "2026-11-16", "to": "2027-02-16", "duration_days": 92})
		if sessionLifecycleHTTPStatus(t, db, person.ID) != "on_leave" {
			t.Fatal("a long leave did not move to on_leave")
		}
		st := sessionLifecycleHTTPRead(t, db, person.ID)
		if st.liveSessions != 0 || st.terminated != 1 || len(st.revocationReasons) != 1 || st.revocationReasons[0] != repository.SessionRevocationReasonAdminRevoked {
			t.Fatalf("long leave: %+v", st)
		}
		if code, _ := sessionStatus(token, session.ID); code != http.StatusUnauthorized {
			t.Fatalf("a long leave left the session usable: %d", code)
		}
	})

	t.Run("offboard_emits_exactly_one_session_terminated", func(t *testing.T) {
		person, _, _ := sessionLifecycleHTTPSignedIn(t, db)
		asAdmin(http.MethodPost, "/api/v1/collaborators/"+person.ID.String()+"/offboard", map[string]any{"reason": "voluntary", "end_date": "2026-11-30"})
		if sessionLifecycleHTTPStatus(t, db, person.ID) != "offboarded" {
			t.Fatal("offboard did not change the status")
		}
		st := sessionLifecycleHTTPRead(t, db, person.ID)
		if st.liveSessions != 0 || st.terminated != 1 || st.offboarded != 1 {
			t.Fatalf("offboard: %+v, want one session.terminated and one collaborator.offboarded", st)
		}
		if len(st.revocationReasons) != 1 || st.revocationReasons[0] != repository.SessionRevocationReasonOffboarded {
			t.Fatalf("offboard revocations: %v", st.revocationReasons)
		}
		m := st.revocationMetadata[0]
		if m["source"] != "collaborator_status_change" || m["from_status"] != "active" || m["to_status"] != "offboarded" {
			t.Fatalf("offboard revocation metadata: %v", m)
		}
		if _, ok := m["offboard_reason"]; ok {
			t.Fatalf("offboard still writes its own revocation: %v", m)
		}
	})

	t.Run("offboard_again_terminates_again", func(t *testing.T) {
		person, _, _ := sessionLifecycleHTTPSignedIn(t, db)
		path := "/api/v1/collaborators/" + person.ID.String() + "/offboard"
		asAdmin(http.MethodPost, path, map[string]any{"reason": "voluntary"})
		// A session left from before the status policy existed (the old PATCH,
		// AMQP and status clock offboards terminated nothing).
		if _, _, err := repository.CreateAuthSession(ctx, db, person.ID, nil, time.Hour); err != nil {
			t.Fatal("leftover session fixture failed")
		}
		asAdmin(http.MethodPost, path, map[string]any{"reason": "voluntary"})
		st := sessionLifecycleHTTPRead(t, db, person.ID)
		if st.liveSessions != 0 || st.terminated != 2 || st.offboarded != 2 {
			t.Fatalf("repeated offboard: %+v, want no live session and two of each event", st)
		}
		if len(st.revocationReasons) != 2 || st.revocationReasons[1] != repository.SessionRevocationReasonOffboarded {
			t.Fatalf("repeated offboard revocations: %v", st.revocationReasons)
		}
		m := st.revocationMetadata[1]
		if m["source"] != "offboard_repeat" || m["from_status"] != "offboarded" || m["to_status"] != "offboarded" || len(m) != 3 {
			t.Fatalf("repeated offboard revocation metadata: %v", m)
		}
	})

	t.Run("introspection_refuses_a_subject_who_cannot_sign_in", func(t *testing.T) {
		clientID := "introspect-ci-" + uuid.NewString()
		if err := repository.UpsertOIDCClient(ctx, db, model.OIDCClient{
			ClientID: clientID, ClientSecretHash: "$2a$10$irrelevant",
			RedirectURIs: []string{"https://introspect.example.test/cb"}, PostLogoutRedirectURIs: []string{},
			Scopes: []string{"openid"}, GrantTypes: []string{"authorization_code", "refresh_token"}, PKCERequired: true,
		}); err != nil {
			t.Fatalf("OIDC client fixture failed: %v", err)
		}
		t.Cleanup(func() {
			_, _ = db.Exec(`DELETE FROM public.oidc_refresh_tokens WHERE client_id=$1`, clientID)
			_, _ = db.Exec(`DELETE FROM public.oidc_clients WHERE client_id=$1`, clientID)
		})
		person, _, _ := sessionLifecycleHTTPSignedIn(t, db)
		refresh := "rt-" + uuid.NewString()
		if err := repository.CreateOIDCRefreshToken(ctx, db, model.OIDCRefreshToken{
			Token: refresh, CollaboratorID: person.ID, ClientID: clientID,
			Scopes: []string{"openid"}, ExpiresAt: time.Now().Add(time.Hour),
		}); err != nil {
			t.Fatalf("refresh token fixture failed: %v", err)
		}
		s := &Server{db: db}
		if resp, ok := s.introspectRefreshToken(ctx, refresh); !ok || !resp.Active {
			t.Fatalf("an active subject's refresh token: ok=%v active=%v", ok, resp.Active)
		}
		// Raw SQL writes no revocation row, as for a collaborator who was
		// already suspended before the status policy existed.
		if _, err := db.Exec(`UPDATE public.collaborators SET status='suspended' WHERE id=$1`, person.ID); err != nil {
			t.Fatal("status fixture failed")
		}
		if resp, ok := s.introspectRefreshToken(ctx, refresh); !ok || resp.Active || resp.Subject != "" {
			t.Fatalf("a suspended subject's refresh token: ok=%v active=%v", ok, resp.Active)
		}
		if _, err := db.Exec(`UPDATE public.collaborators SET status='active' WHERE id=$1`, person.ID); err != nil {
			t.Fatal("status fixture failed")
		}
		if resp, ok := s.introspectRefreshToken(ctx, refresh); !ok || !resp.Active {
			t.Fatalf("introspection did not read the restored status: ok=%v active=%v", ok, resp.Active)
		}
	})

	t.Run("session_reuse_falls_back_to_interactive_login", func(t *testing.T) {
		clientID := "session-reuse-ci-" + uuid.NewString()
		if err := repository.UpsertOIDCClient(ctx, db, model.OIDCClient{
			ClientID: clientID, ClientSecretHash: "$2a$10$irrelevant",
			RedirectURIs: []string{"https://session-reuse.example.test/cb"}, PostLogoutRedirectURIs: []string{},
			Scopes: []string{"openid"}, GrantTypes: []string{"authorization_code"}, PKCERequired: true,
		}); err != nil {
			t.Fatalf("OIDC client fixture failed: %v", err)
		}
		t.Cleanup(func() {
			_, _ = db.Exec(`DELETE FROM public.oidc_auth_requests WHERE client_id=$1`, clientID)
			_, _ = db.Exec(`DELETE FROM public.oidc_clients WHERE client_id=$1`, clientID)
		})
		newRequest := func() uuid.UUID {
			id, err := repository.CreateOIDCAuthRequest(ctx, db, model.OIDCAuthRequest{
				ClientID: clientID, RedirectURI: "https://session-reuse.example.test/cb", Scopes: []string{"openid"},
				ExpiresAt: time.Now().Add(10 * time.Minute),
			})
			if err != nil {
				t.Fatalf("auth request fixture failed: %v", err)
			}
			return id
		}
		boundTo := func(id uuid.UUID) *uuid.UUID {
			ar, err := repository.GetOIDCAuthRequestByID(ctx, db, id)
			if err != nil {
				t.Fatalf("read auth request: %v", err)
			}
			return ar.CollaboratorID
		}

		// Control: an active collaborator's session completes the OIDC login.
		active, activeSession, activeToken := sessionLifecycleHTTPSignedIn(t, db)
		controlID := newRequest()
		w := do(http.MethodGet, "/api/v1/auth/third-party/start/google?auth_request_id="+controlID.String(), nil, activeToken, activeSession.ID)
		if w.Code != http.StatusFound || !strings.Contains(w.Header().Get("Location"), "/authorize/callback?id="+controlID.String()) {
			t.Fatalf("active reuse: status=%d location=%q", w.Code, w.Header().Get("Location"))
		}
		if got := boundTo(controlID); got == nil || *got != active.ID {
			t.Fatalf("active reuse bound %v", got)
		}

		// A session row written after the suspension mimics a login that raced
		// it: the reuse must still not bind the request or mint for the subject.
		suspended := directoryHTTPPerson(t, db, false)
		if _, err := db.Exec(`UPDATE public.auth_identities SET mfa_enrolled_at=NOW() WHERE collaborator_id=$1`, suspended.ID); err != nil {
			t.Fatal("MFA fixture failed")
		}
		status := "suspended"
		if _, err := repository.UpdateCollaborator(ctx, db, model.UpdateCollaboratorRequest{ID: suspended.ID.String(), Status: &status}); err != nil {
			t.Fatalf("suspend fixture failed: %v", err)
		}
		racedSession, racedToken, err := repository.CreateAuthSession(ctx, db, suspended.ID, nil, time.Hour)
		if err != nil {
			t.Fatal("raced session fixture failed")
		}
		refusedID := newRequest()
		w = do(http.MethodGet, "/api/v1/auth/third-party/start/google?auth_request_id="+refusedID.String(), nil, racedToken, racedSession.ID)
		if strings.Contains(w.Header().Get("Location"), "/authorize/callback") {
			t.Fatalf("a suspended collaborator's session completed the OIDC login: status=%d location=%q", w.Code, w.Header().Get("Location"))
		}
		if got := boundTo(refusedID); got != nil {
			t.Fatalf("the OIDC request was bound to %s", got)
		}
	})
}
