package httpapi

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/auth/password"
	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/contactphone"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	"github.com/google/uuid"
	_ "github.com/lib/pq"
	"go.uber.org/zap"
)

func directoryHTTPPostgres(t *testing.T) *sql.DB {
	t.Helper()
	dsn := os.Getenv("DB_URL")
	if dsn == "" {
		if os.Getenv("REQUIRE_DIRECTORY_CONTACT_POSTGRES") == "true" {
			t.Fatal("mandatory PostgreSQL gate has no DB_URL")
		}
		t.Skip("PostgreSQL runs in CI")
	}
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatal("PostgreSQL unavailable")
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func TestPhoneProfileSetupRecoveryHTTPPostgres(t *testing.T) {
	db := directoryHTTPPostgres(t)
	t.Setenv(contactphone.EnrollmentPolicyEnv, "true")
	h := directoryHTTPHandler(t, db)
	for _, scenario := range []struct {
		name     string
		recovery bool
		phone    string
		expected int
	}{
		{"missing_first_profile", false, "", http.StatusUnprocessableEntity},
		{"invalid_first_profile", false, "2025550102", http.StatusUnprocessableEntity},
		{"valid_first_profile", false, "+12025550105", http.StatusPreconditionRequired},
		{"existing_full_recovery", true, "", http.StatusPreconditionRequired},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			person := directoryHTTPPerson(t, db, true)
			raw := uuid.NewString()
			metadata := map[string]any{}
			if scenario.recovery {
				metadata["replaced_credential"] = true
			}
			token, err := repository.IssueCredentialToken(context.Background(), db, repository.IssueCredentialTokenInput{
				CollaboratorID: person.ID, Purpose: model.CredentialTokenPurposeSetup,
				TokenHash: password.HashToken(raw), ExpiresAt: time.Now().Add(time.Hour), Metadata: metadata,
			})
			if err != nil {
				t.Fatal("setup token fixture failed")
			}
			payload := map[string]any{"token": raw, "new_password": "girassol-no-telhado-azul"}
			if scenario.phone != "" {
				payload["profile"] = map[string]any{"phone_e164": scenario.phone}
			}
			body, _ := json.Marshal(payload)
			r := httptest.NewRequest(http.MethodPost, "/api/v1/auth/passwords/setup", strings.NewReader(string(body)))
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != scenario.expected {
				t.Fatalf("setup status=%d expected=%d", w.Code, scenario.expected)
			}
			var consumed bool
			if db.QueryRow(`SELECT consumed_at IS NOT NULL FROM auth_credential_tokens WHERE id=$1`, token.ID).Scan(&consumed) != nil {
				t.Fatal("token observation failed")
			}
			accepted := scenario.expected == http.StatusPreconditionRequired
			if consumed != accepted {
				t.Fatal("refused profile consumed its recovery link")
			}
			var pending bool
			if db.QueryRow(`SELECT phone_profile_required FROM collaborators WHERE id=$1`, person.ID).Scan(&pending) != nil {
				t.Fatal("profile observation failed")
			}
			if pending != (scenario.phone != "+12025550105") {
				t.Fatal("recovery silently cleared the incomplete phone profile")
			}
			if len(w.Result().Cookies()) != 0 {
				t.Fatal("setup/recovery bypassed MFA by creating a session")
			}
		})
	}
}

func directoryHTTPPerson(t *testing.T, db *sql.DB, provisional bool) model.Collaborator {
	t.Helper()
	id := uuid.NewString()
	c, err := repository.CreateCollaborator(context.Background(), db, model.CreateCollaboratorRequest{Slug: "phone-http-" + id, DisplayName: "Phone HTTP CI", PrimaryEmail: id + "@example.test", ProvisionalPhone: provisional})
	if err != nil {
		t.Fatal("HTTP person fixture failed")
	}
	t.Cleanup(func() { _, _ = db.Exec(`DELETE FROM public.collaborators WHERE id=$1`, c.ID) })
	return c
}

func directoryHTTPHandler(t *testing.T, db *sql.DB) http.Handler {
	t.Helper()
	t.Setenv("YGGDRASIL_ENV", "test")
	t.Setenv("YGGDRASIL_AUTH_KEK_BASE64", base64.StdEncoding.EncodeToString([]byte(strings.Repeat("k", 32))))
	h, err := New("contact-directory-ci", db, nil, zap.NewNop())
	if err != nil {
		t.Fatal("Core HTTP fixture failed to start")
	}
	return h
}

func TestHumanPhoneEnrollmentHTTPPostgres(t *testing.T) {
	db := directoryHTTPPostgres(t)
	t.Setenv(contactphone.EnrollmentPolicyEnv, "false")
	actor := directoryHTTPPerson(t, db, false)
	if _, err := db.Exec(`UPDATE public.auth_identities SET mfa_enrolled_at=NOW() WHERE collaborator_id=$1`, actor.ID); err != nil {
		t.Fatal("MFA fixture failed")
	}
	traits := map[string]any{"yggdrasil_admin": true}
	if _, err := repository.UpdateCollaborator(context.Background(), db, model.UpdateCollaboratorRequest{ID: actor.ID.String(), Traits: &traits}); err != nil {
		t.Fatal("actor fixture failed")
	}
	session, token, err := repository.CreateAuthSession(context.Background(), db, actor.ID, nil, time.Hour)
	if err != nil {
		t.Fatal("session fixture failed")
	}
	t.Setenv(contactphone.EnrollmentPolicyEnv, "true")
	h := directoryHTTPHandler(t, db)
	request := func(method, path, body, tok string, sid uuid.UUID) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		r.AddCookie(&http.Cookie{Name: authSessionCookieName(), Value: tok})
		r.Header.Set("X-CSRF-Token", computeCSRFToken(sid))
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	w := request(http.MethodPost, "/api/v1/collaborators", `{"slug":"phone-http-refused","display_name":"Refused HTTP"}`, token, session.ID)
	if w.Code != http.StatusUnprocessableEntity {
		t.Fatal("HTTP accepted a human without required phone")
	}
	var exists bool
	if db.QueryRow(`SELECT EXISTS(SELECT 1 FROM public.collaborators WHERE slug='phone-http-refused')`).Scan(&exists) != nil || exists {
		t.Fatal("refused HTTP creation persisted a person")
	}
	provisional := directoryHTTPPerson(t, db, true)
	pSession, pToken, err := repository.CreateAuthSession(context.Background(), db, provisional.ID, nil, time.Hour)
	if err != nil {
		t.Fatal("provisional session failed")
	}
	w = request(http.MethodGet, "/api/v1/console/teams", "", pToken, pSession.ID)
	if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), phoneProfileRequiredCode) {
		t.Fatal("provisional bootstrap identity gained ordinary access")
	}
	// Its own completion seam is available without borrowing an operator's
	// permissions or making a no-MFA session an ordinary authenticated actor.
	w = request(http.MethodPut, "/api/v1/me/contact/phone", `{"phone_e164":"+12025550102"}`, pToken, pSession.ID)
	if w.Code != http.StatusOK {
		t.Fatal("provisional identity cannot complete its own contact")
	}
	w = request(http.MethodGet, "/api/v1/console/teams", "", pToken, pSession.ID)
	if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "auth.mfa_not_enrolled") {
		t.Fatal("phone completion bypassed the independent MFA gate")
	}
	// Existing actor keeps the original recovery/authorization posture even
	// though new enrollment policy was enabled after its creation.
	w = request(http.MethodGet, "/api/v1/auth/session", "", token, session.ID)
	var envelope model.AuthSessionEnvelope
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &envelope) != nil || envelope.PhoneProfileRequired {
		t.Fatal("existing actor gained an onboarding phone requirement")
	}
	// warn-mode and root wildcard do not become sensitive contact-read grants.
	t.Setenv("YGGDRASIL_CONSOLE_RBAC_ENFORCE", "warn")
	w = request(http.MethodGet, "/api/v1/console/collaborators/"+provisional.ID.String()+"/contact/phone", "", token, session.ID)
	if w.Code != http.StatusForbidden || strings.Contains(w.Body.String(), "+12025550102") {
		t.Fatal("wildcard/admin/warn bypassed exact contact-read authority")
	}
}

func TestDirectorySnapshotHTTPRevisionPostgres(t *testing.T) {
	db := directoryHTTPPostgres(t)
	t.Setenv(contactphone.EnrollmentPolicyEnv, "false")
	person := directoryHTTPPerson(t, db, false)
	_ = directoryHTTPPerson(t, db, false) // Prove pagination without relying on unrelated seed data.
	t.Setenv(snapshotSecretEnv, strings.Repeat("s", 32))
	t.Setenv(directoryMachinePrincipalsEnv, testDirectoryMachinePrincipalsJSON(t, testDirectoryPrincipalConfig(testDirectoryToken, "directory-http-ci", []string{directoryCapabilitySnapshot})))
	h := directoryHTTPHandler(t, db)
	request := func(path, tok string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodGet, path, nil)
		r.Header.Set(directoryMachineTokenHeader, tok)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	if request("/api/v1/directory/snapshot", "wrong-test-token").Code != http.StatusUnauthorized {
		t.Fatal("unknown directory credential gained a snapshot")
	}
	if request("/api/v1/directory/snapshot?include_phone=true", testDirectoryToken).Code != http.StatusForbidden {
		t.Fatal("basic directory capability gained contacts")
	}
	w := request("/api/v1/directory/snapshot?limit=1", testDirectoryToken)
	var page model.DirectorySnapshotPage
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &page) != nil || page.Complete || page.NextCursor == "" || page.Offset != 0 || page.ContactsIncluded {
		t.Fatal("initial bounded directory page invalid")
	}
	if strings.Contains(w.Body.String(), "phone_e164") || strings.Contains(w.Body.String(), "primary_email") || strings.Contains(w.Body.String(), "phone_ciphertext") {
		t.Fatal("basic directory page disclosed contacts")
	}
	seen := len(page.Collaborators) + len(page.Teams) + len(page.Memberships) + len(page.ExternalIdentities)
	firstRevision, firstObserved := page.Revision, page.ObservedAt
	firstCursor := page.NextCursor
	for !page.Complete {
		w = request("/api/v1/directory/snapshot?cursor="+page.NextCursor, testDirectoryToken)
		var next model.DirectorySnapshotPage
		if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &next) != nil || next.Revision != firstRevision || !next.ObservedAt.Equal(firstObserved) || next.Offset != seen {
			t.Fatal("cross-page snapshot changed its revision, time or offset")
		}
		seen += len(next.Collaborators) + len(next.Teams) + len(next.Memberships) + len(next.ExternalIdentities)
		page = next
	}
	if seen != page.TotalRecords {
		t.Fatal("terminal page silently truncated directory records")
	}
	name := "Changed HTTP CI"
	if _, err := repository.UpdateCollaborator(context.Background(), db, model.UpdateCollaboratorRequest{ID: person.ID.String(), DisplayName: &name}); err != nil {
		t.Fatal("revision mutation fixture failed")
	}
	w = request("/api/v1/directory/snapshot?cursor="+firstCursor, testDirectoryToken)
	if w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), snapshotChangedCode) || strings.Contains(w.Body.String(), "collaborators") {
		t.Fatal("mixed-revision export answered as a complete dataset")
	}
}
