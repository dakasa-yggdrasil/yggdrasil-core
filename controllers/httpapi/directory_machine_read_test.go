package httpapi

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

const (
	testForeignWorkflowToken  = "workflow-principal-token"
	testForeignEventToken     = "event-principal-token"
	testForeignDeployToken    = "deploy-only-token"
	testForeignAuthAdminToken = "auth-admin-only-token"
	testLookupEmail           = "ana.souza@dakasa.me"
	testSensitiveCPF          = "123.456.789-09"
)

type directoryAuditCapture struct {
	mu     sync.Mutex
	events []model.AuditEvent
}

func (c *directoryAuditCapture) add(event model.AuditEvent) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.events = append(c.events, event)
}

func (c *directoryAuditCapture) snapshot() []model.AuditEvent {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]model.AuditEvent, len(c.events))
	copy(out, c.events)
	return out
}

// clearMachineCredentialEnv resets every machine credential family so a test
// controls exactly which principals exist.
func clearMachineCredentialEnv(t *testing.T) {
	t.Helper()
	t.Setenv("YGGDRASIL_ENV", "")
	t.Setenv(workflowMachinePrincipalsEnv, "")
	t.Setenv(eventPublisherPrincipalsEnv, "")
	t.Setenv(directoryMachinePrincipalsEnv, "")
	t.Setenv(legacyScopedWorkflowTokensEnv, "")
	t.Setenv("YGGDRASIL_WORKFLOW_RUN_TOKEN", "")
	t.Setenv("YGGDRASIL_WORKFLOW_RUN_LEGACY_ENABLED", "")
	t.Setenv("YGGDRASIL_WORKFLOW_RUN_LEGACY_EXPIRES_AT", "")
	t.Setenv(legacyEventPublishTokenEnv, "")
	t.Setenv(legacyEventPublishEnabledEnv, "")
	t.Setenv(legacyEventPublishExpiryEnv, "")
	t.Setenv("YGGDRASIL_DEPLOY_TOKEN", "")
	t.Setenv("YGGDRASIL_AUTH_ADMIN_TOKEN", "")
	t.Setenv("YGGDRASIL_CONSOLE_JWT_AUDIENCES", "")
}

// newDirectoryGateServer boots the real HTTP server (New: full middleware
// pipeline plus the real mux and handlers) over a sqlmock database.
func newDirectoryGateServer(t *testing.T) (http.Handler, sqlmock.Sqlmock, *directoryAuditCapture) {
	t.Helper()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	capture := &directoryAuditCapture{}
	handler, err := New("yggdrasil-core-test", db, nil, zap.NewNop(), withDirectoryAuditSink(capture.add))
	if err != nil {
		t.Fatalf("boot real server: %v", err)
	}
	return handler, mock, capture
}

func configureDirectoryPrincipal(t *testing.T, capabilities []string, instances ...tartaroInstanceRef) {
	t.Helper()
	clearMachineCredentialEnv(t)
	t.Setenv(directoryMachinePrincipalsEnv, testDirectoryMachinePrincipalsJSON(t,
		testDirectoryPrincipalConfig(testDirectoryToken, testDirectoryPrincipalID, capabilities, instances...)))
}

func collaboratorColumns() []string {
	return []string{
		"id", "slug", "status", "display_name", "primary_email", "manager_id", "primary_team_id",
		"personal_data", "employment_data", "third_party_identities", "traits", "metadata", "version",
		"created_at", "updated_at",
	}
}

func directoryCollaboratorRow(rows *sqlmock.Rows, id uuid.UUID, status, display, email string) *sqlmock.Rows {
	return rows.AddRow(
		id.String(), "ana-souza", status, display, email, "", "",
		[]byte(`{"cpf":"`+testSensitiveCPF+`"}`), []byte(`{"contract":"clt"}`), []byte(`{"slack":{"login":"U123"}}`),
		[]byte(`{"tartaro_actions":["approve_post"]}`), []byte(`{"internal":"x"}`), 3,
		time.Now(), time.Now(),
	)
}

func directoryRequest(method, target, carrier, token string) *http.Request {
	req := httptest.NewRequest(method, target, nil)
	switch carrier {
	case "header":
		req.Header.Set(directoryMachineTokenHeader, token)
	case "bearer":
		req.Header.Set("Authorization", "Bearer "+token)
	}
	return req
}

func decodeDirectoryBody(t *testing.T, recorder *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var body map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode body %q: %v", recorder.Body.String(), err)
	}
	return body
}

func sortedKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func assertMinimalProjection(t *testing.T, item map[string]any, id uuid.UUID, email string) {
	t.Helper()
	wantKeys := []string{"display_name", "id", "primary_email", "status"}
	if got := sortedKeys(item); strings.Join(got, ",") != strings.Join(wantKeys, ",") {
		t.Fatalf("projection keys=%v, want exactly %v", got, wantKeys)
	}
	if item["id"] != id.String() || item["primary_email"] != email || item["status"] != "active" || item["display_name"] != "Ana Souza" {
		t.Fatalf("projection values=%v", item)
	}
}

func assertNoSensitiveContent(t *testing.T, body string) {
	t.Helper()
	for _, forbidden := range []string{testSensitiveCPF, "personal_data", "employment_data", "third_party_identities", "traits", "metadata", "slug", "manager_id", "version"} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("machine response leaks %q: %s", forbidden, body)
		}
	}
}

func assertAuditNeverCarries(t *testing.T, events []model.AuditEvent, secrets ...string) {
	t.Helper()
	for _, event := range events {
		raw, err := json.Marshal(event)
		if err != nil {
			t.Fatal(err)
		}
		for _, secret := range secrets {
			if strings.Contains(string(raw), secret) {
				t.Fatalf("audit event carries %q: %s", secret, string(raw))
			}
		}
	}
}

func requireSingleAudit(t *testing.T, capture *directoryAuditCapture, outcome, capability, targetID, reason string) model.AuditEvent {
	t.Helper()
	events := capture.snapshot()
	if len(events) != 1 {
		t.Fatalf("audit events=%d, want 1: %+v", len(events), events)
	}
	event := events[0]
	if event.Actor != "service:"+testDirectoryPrincipalID || event.Action != directoryMachineAuditAction || event.ResourceKind != "collaborator" {
		t.Fatalf("audit identity=%+v", event)
	}
	if event.Outcome != outcome || event.ResourceID != targetID {
		t.Fatalf("audit outcome=%q target=%q, want %q %q", event.Outcome, event.ResourceID, outcome, targetID)
	}
	if event.Metadata["principal_id"] != testDirectoryPrincipalID || event.Metadata["rotation_id"] != "test-rotation-directory-1" {
		t.Fatalf("audit metadata=%v", event.Metadata)
	}
	gotCapability, _ := event.Metadata["capability"].(string)
	if gotCapability != capability {
		t.Fatalf("audit capability=%q, want %q", gotCapability, capability)
	}
	gotReason, _ := event.Metadata["reason"].(string)
	if gotReason != reason {
		t.Fatalf("audit reason=%q, want %q", gotReason, reason)
	}
	assertAuditNeverCarries(t, events, testDirectoryToken, testLookupEmail, "q=")
	return event
}

func TestDirectoryMachineLookupByExactEmailReturnsMinimalProjection(t *testing.T) {
	for _, carrier := range []string{"header", "bearer"} {
		t.Run(carrier, func(t *testing.T) {
			configureDirectoryPrincipal(t, allDirectoryCapabilities(), testTartaroInstance)
			handler, mock, capture := newDirectoryGateServer(t)
			id := uuid.New()
			mock.ExpectQuery(`LOWER\(primary_email\) = LOWER\(\$1\)\s+AND status = 'active'`).
				WithArgs(testLookupEmail, directoryLookupAmbiguityProbe).
				WillReturnRows(directoryCollaboratorRow(sqlmock.NewRows(collaboratorColumns()), id, "active", "Ana Souza", testLookupEmail))

			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, directoryRequest(http.MethodGet,
				"/api/v1/collaborators?q=ana.souza%40dakasa.me&status=active&limit=100", carrier, testDirectoryToken))

			if recorder.Code != http.StatusOK {
				t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
			}
			body := decodeDirectoryBody(t, recorder)
			if got := sortedKeys(body); strings.Join(got, ",") != "collaborators" {
				t.Fatalf("envelope keys=%v", got)
			}
			items, _ := body["collaborators"].([]any)
			if len(items) != 1 {
				t.Fatalf("collaborators=%v, want one exact match", body["collaborators"])
			}
			assertMinimalProjection(t, items[0].(map[string]any), id, testLookupEmail)
			assertNoSensitiveContent(t, recorder.Body.String())
			requireSingleAudit(t, capture, "success", directoryCapabilityLookupEmail, id.String(), "")
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestDirectoryMachineLookupWithoutLimitAndEmptyResult(t *testing.T) {
	configureDirectoryPrincipal(t, []string{directoryCapabilityLookupEmail})
	handler, mock, capture := newDirectoryGateServer(t)
	mock.ExpectQuery(`LOWER\(primary_email\) = LOWER\(\$1\)`).
		WithArgs("Nobody@Dakasa.me", directoryLookupAmbiguityProbe).
		WillReturnRows(sqlmock.NewRows(collaboratorColumns()))

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, directoryRequest(http.MethodGet,
		"/api/v1/collaborators?status=active&q=Nobody%40Dakasa.me", "header", testDirectoryToken))

	if recorder.Code != http.StatusOK || strings.TrimSpace(recorder.Body.String()) != `{"collaborators":[]}` {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	requireSingleAudit(t, capture, "not_found", directoryCapabilityLookupEmail, "", "")
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestDirectoryMachineLookupAmbiguousIdentityFailsClosed(t *testing.T) {
	configureDirectoryPrincipal(t, []string{directoryCapabilityLookupEmail})
	handler, mock, capture := newDirectoryGateServer(t)
	rows := sqlmock.NewRows(collaboratorColumns())
	rows = directoryCollaboratorRow(rows, uuid.New(), "active", "Ana Souza", testLookupEmail)
	rows = directoryCollaboratorRow(rows, uuid.New(), "active", "Ana Souza", strings.ToUpper(testLookupEmail))
	mock.ExpectQuery(`LOWER\(primary_email\) = LOWER\(\$1\)`).WithArgs(testLookupEmail, directoryLookupAmbiguityProbe).WillReturnRows(rows)

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, directoryRequest(http.MethodGet,
		"/api/v1/collaborators?q="+testLookupEmail+"&status=active", "header", testDirectoryToken))

	if recorder.Code != http.StatusInternalServerError || !strings.Contains(recorder.Body.String(), "ambiguous") {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	assertNoSensitiveContent(t, recorder.Body.String())
	requireSingleAudit(t, capture, "error", directoryCapabilityLookupEmail, "", "ambiguous_identity")
}

func TestDirectoryMachineGetByCanonicalUUIDReturnsMinimalProjection(t *testing.T) {
	configureDirectoryPrincipal(t, []string{directoryCapabilityRead})
	handler, mock, capture := newDirectoryGateServer(t)
	id := uuid.New()
	mock.ExpectQuery(`FROM public\.collaborators\s+WHERE id = \$1`).WithArgs(id).
		WillReturnRows(directoryCollaboratorRow(sqlmock.NewRows(collaboratorColumns()), id, "active", "Ana Souza", testLookupEmail))

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, directoryRequest(http.MethodGet, "/api/v1/collaborators/"+id.String(), "header", testDirectoryToken))

	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	body := decodeDirectoryBody(t, recorder)
	if got := sortedKeys(body); strings.Join(got, ",") != "collaborator" {
		t.Fatalf("envelope keys=%v", got)
	}
	assertMinimalProjection(t, body["collaborator"].(map[string]any), id, testLookupEmail)
	assertNoSensitiveContent(t, recorder.Body.String())
	requireSingleAudit(t, capture, "success", directoryCapabilityRead, id.String(), "")
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestDirectoryMachineGetHidesAbsentAndInactiveCollaborators(t *testing.T) {
	cases := []struct {
		name   string
		rows   func(id uuid.UUID) *sqlmock.Rows
		reason string
	}{
		{name: "absent", rows: func(uuid.UUID) *sqlmock.Rows { return sqlmock.NewRows(collaboratorColumns()) }, reason: "not_found"},
		{name: "suspended", rows: func(id uuid.UUID) *sqlmock.Rows {
			return directoryCollaboratorRow(sqlmock.NewRows(collaboratorColumns()), id, "suspended", "Ana Souza", testLookupEmail)
		}, reason: "inactive"},
		{name: "offboarded", rows: func(id uuid.UUID) *sqlmock.Rows {
			return directoryCollaboratorRow(sqlmock.NewRows(collaboratorColumns()), id, "offboarded", "Ana Souza", testLookupEmail)
		}, reason: "inactive"},
	}
	for _, tc := range cases {
		for _, route := range []string{"", "/effective-tartaro-actions"} {
			t.Run(tc.name+route, func(t *testing.T) {
				configureDirectoryPrincipal(t, allDirectoryCapabilities(), testTartaroInstance)
				handler, mock, capture := newDirectoryGateServer(t)
				id := uuid.New()
				mock.ExpectQuery(`FROM public\.collaborators\s+WHERE id = \$1`).WithArgs(id).WillReturnRows(tc.rows(id))

				recorder := httptest.NewRecorder()
				handler.ServeHTTP(recorder, directoryRequest(http.MethodGet, "/api/v1/collaborators/"+id.String()+route, "header", testDirectoryToken))

				if recorder.Code != http.StatusNotFound {
					t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
				}
				if decodeDirectoryBody(t, recorder)["code"] != "integration.not_found" {
					t.Fatalf("body=%s", recorder.Body.String())
				}
				assertNoSensitiveContent(t, recorder.Body.String())
				capability := directoryCapabilityRead
				if route != "" {
					capability = directoryCapabilityEffectiveActions
				}
				requireSingleAudit(t, capture, "not_found", capability, id.String(), tc.reason)
				if err := mock.ExpectationsWereMet(); err != nil {
					t.Fatal(err)
				}
			})
		}
	}
}

func TestDirectoryMachineEffectiveActionsOnAllowedInstance(t *testing.T) {
	configureDirectoryPrincipal(t, []string{directoryCapabilityEffectiveActions}, testTartaroInstance)
	handler, mock, capture := newDirectoryGateServer(t)
	id := uuid.New()
	teamID := uuid.New()

	// Machine handler loads the collaborator, then the shared computation
	// resolves the collaborator again, lists memberships, resolves the team
	// and lists its grants.
	mock.ExpectQuery(`FROM public\.collaborators\s+WHERE id = \$1`).WithArgs(id).
		WillReturnRows(directoryCollaboratorRow(sqlmock.NewRows(collaboratorColumns()), id, "active", "Ana Souza", testLookupEmail))
	mock.ExpectQuery(`FROM public\.collaborators\s+WHERE id = \$1`).WithArgs(id).
		WillReturnRows(directoryCollaboratorRow(sqlmock.NewRows(collaboratorColumns()), id, "active", "Ana Souza", testLookupEmail))
	mock.ExpectQuery(`FROM public\.team_memberships tm`).WithArgs(id).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "team_id", "team_slug", "collaborator_id", "collaborator_slug",
			"role", "active", "source", "starts_at", "ends_at", "metadata",
			"created_at", "updated_at",
		}).AddRow(uuid.New().String(), teamID.String(), "social", id.String(), "ana-souza",
			"member", true, "manual", nil, nil, []byte("{}"), time.Now(), time.Now()))
	mock.ExpectQuery(`FROM public\.teams\s+WHERE id = \$1`).WithArgs(teamID).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "slug", "name", "type", "status", "email", "parent_team_id", "owners", "traits", "metadata", "created_at", "updated_at",
		}).AddRow(teamID.String(), "social", "Social", "functional", "active", nil, nil, []byte("[]"), []byte("{}"), []byte("{}"), time.Now(), time.Now()))
	mock.ExpectQuery(`FROM public\.team_grants`).WithArgs(teamID.String()).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "team_id", "integration_instance_namespace", "integration_instance_name", "action_name", "scope", "granted_at", "granted_by",
		}).
			AddRow(uuid.New().String(), teamID.String(), "dakasa", "tartaro-dakasa-validation", "publish_social_post", []byte("{}"), time.Now(), nil).
			AddRow(uuid.New().String(), teamID.String(), "dakasa", "tartaro-dakasa-validation", "*", []byte("{}"), time.Now(), nil).
			AddRow(uuid.New().String(), teamID.String(), "dakasa", "other-instance", "delete_everything", []byte("{}"), time.Now(), nil).
			AddRow(uuid.New().String(), teamID.String(), "dakasa", "tartaro-dakasa-validation", "approve_social_post", []byte("{}"), time.Now(), nil))

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, directoryRequest(http.MethodGet, "/api/v1/collaborators/"+id.String()+"/effective-tartaro-actions", "bearer", testDirectoryToken))

	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	body := decodeDirectoryBody(t, recorder)
	if got := sortedKeys(body); strings.Join(got, ",") != "collaborator_id,computed_tartaro_actions" {
		t.Fatalf("envelope keys=%v", got)
	}
	if body["collaborator_id"] != id.String() {
		t.Fatalf("collaborator_id=%v", body["collaborator_id"])
	}
	actions, _ := body["computed_tartaro_actions"].([]any)
	if fmt.Sprint(actions) != "[approve_social_post publish_social_post]" {
		t.Fatalf("computed_tartaro_actions=%v, want the sorted grants of the configured instance only", actions)
	}
	for _, forbidden := range []string{"trait", "drift", "effective_via_teams", "team_id", "delete_everything", "primary_email"} {
		if strings.Contains(recorder.Body.String(), forbidden) {
			t.Fatalf("effective actions response leaks %q: %s", forbidden, recorder.Body.String())
		}
	}
	requireSingleAudit(t, capture, "success", directoryCapabilityEffectiveActions, id.String(), "")
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestDirectoryMachineDeniesOutOfScopeRequestsWithoutTouchingTheDatabase(t *testing.T) {
	id := uuid.New()
	cases := []struct {
		name         string
		capabilities []string
		instances    []tartaroInstanceRef
		lifecycle    func(*directoryMachinePrincipalConfig)
		method       string
		target       string
		carrier      string
		token        string
		wantStatus   int
		wantCode     string
		wantAudit    bool
		wantReason   string
		wantCap      string
	}{
		{name: "no credential", method: http.MethodGet, target: "/api/v1/collaborators?q=" + testLookupEmail + "&status=active", carrier: "", wantStatus: 401, wantCode: "auth.unauthenticated"},
		{name: "unknown token via header", method: http.MethodGet, target: "/api/v1/collaborators?q=" + testLookupEmail + "&status=active", carrier: "header", token: "not-a-configured-token", wantStatus: 401, wantCode: "auth.unauthenticated"},
		{name: "empty header value", method: http.MethodGet, target: "/api/v1/collaborators?q=" + testLookupEmail + "&status=active", carrier: "header", token: "   ", wantStatus: 401, wantCode: "auth.unauthenticated"},
		{name: "expired principal", lifecycle: func(c *directoryMachinePrincipalConfig) {
			c.ExpiresAt = time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
			c.RotatedAt = time.Time{}
		}, method: http.MethodGet, target: "/api/v1/collaborators/" + id.String(), carrier: "header", token: testDirectoryToken, wantStatus: 401, wantCode: "auth.unauthenticated", wantAudit: true, wantReason: "expired"},
		{name: "expired principal via bearer never reaches session path", lifecycle: func(c *directoryMachinePrincipalConfig) {
			c.ExpiresAt = time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
			c.RotatedAt = time.Time{}
		}, method: http.MethodGet, target: "/api/v1/collaborators/" + id.String(), carrier: "bearer", token: testDirectoryToken, wantStatus: 401, wantCode: "auth.unauthenticated", wantAudit: true, wantReason: "expired"},
		{name: "revoked principal", lifecycle: func(c *directoryMachinePrincipalConfig) { c.Status = "revoked" }, method: http.MethodGet, target: "/api/v1/collaborators/" + id.String(), carrier: "header", token: testDirectoryToken, wantStatus: 401, wantCode: "auth.unauthenticated", wantAudit: true, wantReason: "status_revoked"},
		{name: "disabled principal", lifecycle: func(c *directoryMachinePrincipalConfig) { c.Status = "disabled" }, method: http.MethodGet, target: "/api/v1/collaborators/" + id.String(), carrier: "bearer", token: testDirectoryToken, wantStatus: 401, wantCode: "auth.unauthenticated", wantAudit: true, wantReason: "status_disabled"},
		{name: "lookup capability missing", capabilities: []string{directoryCapabilityRead}, method: http.MethodGet, target: "/api/v1/collaborators?q=" + testLookupEmail + "&status=active", carrier: "header", token: testDirectoryToken, wantStatus: 403, wantCode: "permission.denied", wantAudit: true, wantReason: "capability_missing", wantCap: directoryCapabilityLookupEmail},
		{name: "read capability missing", capabilities: []string{directoryCapabilityLookupEmail}, method: http.MethodGet, target: "/api/v1/collaborators/" + id.String(), carrier: "header", token: testDirectoryToken, wantStatus: 403, wantCode: "permission.denied", wantAudit: true, wantReason: "capability_missing", wantCap: directoryCapabilityRead},
		{name: "effective actions capability missing", capabilities: []string{directoryCapabilityRead}, method: http.MethodGet, target: "/api/v1/collaborators/" + id.String() + "/effective-tartaro-actions", carrier: "header", token: testDirectoryToken, wantStatus: 403, wantCode: "permission.denied", wantAudit: true, wantReason: "capability_missing", wantCap: directoryCapabilityEffectiveActions},
		{name: "tartaro instance not allowed", instances: []tartaroInstanceRef{{Namespace: "dakasa", Name: "tartaro-other"}}, method: http.MethodGet, target: "/api/v1/collaborators/" + id.String() + "/effective-tartaro-actions", carrier: "header", token: testDirectoryToken, wantStatus: 403, wantCode: "permission.denied", wantAudit: true, wantReason: "tartaro_instance_not_allowed", wantCap: directoryCapabilityEffectiveActions},
		{name: "query on get route", method: http.MethodGet, target: "/api/v1/collaborators/" + id.String() + "?view=directory", carrier: "header", token: testDirectoryToken, wantStatus: 400, wantCode: "input.invalid", wantAudit: true, wantReason: "invalid_query", wantCap: directoryCapabilityRead},
		{name: "instance selector on effective route", method: http.MethodGet, target: "/api/v1/collaborators/" + id.String() + "/effective-tartaro-actions?instance=other", carrier: "header", token: testDirectoryToken, wantStatus: 400, wantCode: "input.invalid", wantAudit: true, wantReason: "invalid_query", wantCap: directoryCapabilityEffectiveActions},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			capabilities := tc.capabilities
			if capabilities == nil {
				capabilities = allDirectoryCapabilities()
			}
			instances := tc.instances
			if instances == nil {
				instances = []tartaroInstanceRef{testTartaroInstance}
			}
			hasEffective := false
			for _, capability := range capabilities {
				if capability == directoryCapabilityEffectiveActions {
					hasEffective = true
				}
			}
			if !hasEffective {
				instances = nil
			}
			config := testDirectoryPrincipalConfig(testDirectoryToken, testDirectoryPrincipalID, capabilities, instances...)
			if tc.lifecycle != nil {
				tc.lifecycle(&config)
			}
			clearMachineCredentialEnv(t)
			t.Setenv(directoryMachinePrincipalsEnv, testDirectoryMachinePrincipalsJSON(t, config))
			handler, mock, capture := newDirectoryGateServer(t)

			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, directoryRequest(tc.method, tc.target, tc.carrier, tc.token))

			if recorder.Code != tc.wantStatus {
				t.Fatalf("status=%d body=%s, want %d", recorder.Code, recorder.Body.String(), tc.wantStatus)
			}
			if decodeDirectoryBody(t, recorder)["code"] != tc.wantCode {
				t.Fatalf("body=%s, want code %s", recorder.Body.String(), tc.wantCode)
			}
			if tc.wantAudit {
				requireSingleAudit(t, capture, "denied", tc.wantCap, expectedAuditTarget(tc.target, id, tc.wantReason), tc.wantReason)
			} else if events := capture.snapshot(); len(events) != 0 {
				t.Fatalf("unauthenticated attempt produced audit rows: %+v", events)
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func expectedAuditTarget(target string, id uuid.UUID, reason string) string {
	// Lifecycle refusals happen before route classification, so no target
	// collaborator is known yet.
	if reason == "expired" || strings.HasPrefix(reason, "status_") {
		return ""
	}
	if strings.Contains(target, id.String()) {
		return id.String()
	}
	return ""
}

func TestDirectoryMachineRejectsBroadOrMalformedLookupQueries(t *testing.T) {
	queries := map[string]string{
		"missing q":                 "status=active",
		"empty q":                   "q=&status=active",
		"wildcard star":             "q=*&status=active",
		"wildcard percent":          "q=%25dakasa.me&status=active",
		"wildcard question":         "q=ana%3F@dakasa.me&status=active",
		"broad substring":           "q=dakasa&status=active",
		"local part only":           "q=ana.souza&status=active",
		"domain without dot":        "q=ana@dakasa&status=active",
		"display name form":         "q=Ana%20%3Cana.souza%40dakasa.me%3E&status=active",
		"embedded whitespace":       "q=ana%20souza%40dakasa.me&status=active",
		"leading whitespace":        "q=%20ana.souza%40dakasa.me&status=active",
		"two addresses":             "q=ana%40dakasa.me%2Cbob%40dakasa.me&status=active",
		"duplicate q":               "q=ana%40dakasa.me&q=bob%40dakasa.me&status=active",
		"missing status":            "q=ana%40dakasa.me",
		"status suspended":          "q=ana%40dakasa.me&status=suspended",
		"status wildcard":           "q=ana%40dakasa.me&status=*",
		"status empty":              "q=ana%40dakasa.me&status=",
		"limit above bound":         "q=ana%40dakasa.me&status=active&limit=101",
		"limit zero":                "q=ana%40dakasa.me&status=active&limit=0",
		"limit negative":            "q=ana%40dakasa.me&status=active&limit=-1",
		"limit non numeric":         "q=ana%40dakasa.me&status=active&limit=all",
		"limit with sign":           "q=ana%40dakasa.me&status=active&limit=%2B5",
		"limit with leading zeros":  "q=ana%40dakasa.me&status=active&limit=007",
		"directory view mode":       "q=ana%40dakasa.me&status=active&view=directory",
		"enriched mode":             "q=ana%40dakasa.me&status=active&enriched=true",
		"cursor pagination":         "q=ana%40dakasa.me&status=active&cursor=abc",
		"offset pagination":         "q=ana%40dakasa.me&status=active&offset=10",
		"unknown parameter":         "q=ana%40dakasa.me&status=active&team=social",
		"semicolon separated query": "q=ana%40dakasa.me;status=active",
	}
	for name, query := range queries {
		t.Run(name, func(t *testing.T) {
			configureDirectoryPrincipal(t, []string{directoryCapabilityLookupEmail})
			handler, mock, capture := newDirectoryGateServer(t)

			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, directoryRequest(http.MethodGet, "/api/v1/collaborators?"+query, "header", testDirectoryToken))

			if recorder.Code != http.StatusBadRequest {
				t.Fatalf("status=%d body=%s, want 400 for %q", recorder.Code, recorder.Body.String(), query)
			}
			if decodeDirectoryBody(t, recorder)["code"] != "input.invalid" {
				t.Fatalf("body=%s", recorder.Body.String())
			}
			requireSingleAudit(t, capture, "denied", directoryCapabilityLookupEmail, "", "invalid_query")
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestDirectoryMachineRefusesOtherMethodsPathsAndRouteFamilies(t *testing.T) {
	id := uuid.New()
	nilID := uuid.Nil.String()
	targets := []struct {
		method string
		target string
	}{
		{http.MethodPost, "/api/v1/collaborators"},
		{http.MethodHead, "/api/v1/collaborators?q=" + testLookupEmail + "&status=active"},
		{http.MethodOptions, "/api/v1/collaborators?q=" + testLookupEmail + "&status=active"},
		{http.MethodPatch, "/api/v1/collaborators/" + id.String()},
		{http.MethodDelete, "/api/v1/collaborators/" + id.String()},
		{http.MethodPost, "/api/v1/collaborators/" + id.String() + "/offboard"},
		{http.MethodPost, "/api/v1/collaborators/" + id.String() + "/attribute-set"},
		{http.MethodPost, "/api/v1/collaborators/" + id.String() + "/sync-tartaro-actions"},
		{http.MethodGet, "/api/v1/collaborators/"},
		{http.MethodGet, "/api/v1/collaborators/" + id.String() + "/"},
		{http.MethodGet, "/api/v1/collaborators/" + id.String() + "/lifecycle-events"},
		{http.MethodGet, "/api/v1/collaborators/" + id.String() + "/provider-state"},
		{http.MethodGet, "/api/v1/collaborators/" + id.String() + "/effective-tartaro-actions/"},
		{http.MethodGet, "/api/v1/collaborators/" + id.String() + "/effective-tartaro-actions/extra"},
		{http.MethodGet, "/api/v1/collaborators/" + id.String() + "/Effective-Tartaro-Actions"},
		{http.MethodGet, "/api/v1/collaborators/" + strings.ToUpper(id.String())},
		{http.MethodGet, "/api/v1/collaborators/{" + id.String() + "}"},
		{http.MethodGet, "/api/v1/collaborators/urn:uuid:" + id.String()},
		{http.MethodGet, "/api/v1/collaborators/" + strings.ReplaceAll(id.String(), "-", "")},
		{http.MethodGet, "/api/v1/collaborators/" + nilID},
		{http.MethodGet, "/api/v1/collaborators/ana-souza"},
		{http.MethodGet, "/api/v1/collaborators/%2e%2e/secrets"},
		{http.MethodGet, "/api/v1/collaborators/" + id.String() + "%2Fprovider-state"},
		{http.MethodGet, "/api/v1/collaborators/%" + id.String()[1:]},
		{http.MethodGet, "/api/v1/collaborators/./" + id.String()},
		{http.MethodGet, "/api/v1/collaborators/../collaborators/" + id.String()},
		{http.MethodGet, "/api/v1/collaborator-external-identities"},
		{http.MethodGet, "/api/v1/ops/collaborators/missing-mfa"},
		{http.MethodGet, "/api/v1/ops/audit"},
		{http.MethodGet, "/api/v1/console/collaborators"},
		{http.MethodGet, "/api/v1/secrets"},
		{http.MethodGet, "/api/v1/secrets/aws/foo?include_values=true"},
		{http.MethodGet, "/api/v1/manifests?kind=workflow"},
		{http.MethodPost, "/api/v1/manifests?kind=workflow"},
		{http.MethodGet, "/api/v1/teams"},
		{http.MethodGet, "/api/v1/teams/" + id.String() + "/grants"},
		{http.MethodGet, "/api/v1/team-memberships"},
		{http.MethodGet, "/api/v1/permissions/catalog"},
		{http.MethodGet, "/api/v1/integration-instances"},
		{http.MethodGet, "/api/v1/workflow-runs/" + id.String()},
		{http.MethodPost, "/api/v1/workflow-runs"},
		{http.MethodPost, "/api/v1/events"},
		{http.MethodPost, "/api/v1/auth/providers"},
		{http.MethodPost, "/api/v1/auth/scim/clients"},
	}
	for _, carrier := range []string{"header", "bearer"} {
		for _, tc := range targets {
			t.Run(carrier+" "+tc.method+" "+tc.target, func(t *testing.T) {
				configureDirectoryPrincipal(t, allDirectoryCapabilities(), testTartaroInstance)
				handler, mock, capture := newDirectoryGateServer(t)

				recorder := httptest.NewRecorder()
				handler.ServeHTTP(recorder, directoryRequest(tc.method, tc.target, carrier, testDirectoryToken))

				if recorder.Code != http.StatusForbidden {
					t.Fatalf("status=%d body=%s, want 403", recorder.Code, recorder.Body.String())
				}
				if decodeDirectoryBody(t, recorder)["code"] != "permission.denied" {
					t.Fatalf("body=%s", recorder.Body.String())
				}
				requireSingleAudit(t, capture, "denied", "", "", "route_not_allowed")
				if err := mock.ExpectationsWereMet(); err != nil {
					t.Fatal(err)
				}
			})
		}
	}
}

func TestDirectoryMachineRequestNeverReachesConsoleHandlers(t *testing.T) {
	id := uuid.New()
	cases := []struct {
		name       string
		env        func(*testing.T)
		method     string
		target     string
		carrier    string
		token      string
		wantStatus int
	}{
		{name: "valid token on unrelated route", env: func(t *testing.T) {
			configureDirectoryPrincipal(t, allDirectoryCapabilities(), testTartaroInstance)
		}, method: http.MethodGet, target: "/api/v1/ops/audit", carrier: "bearer", token: testDirectoryToken, wantStatus: 403},
		{name: "expired token on directory route", env: func(t *testing.T) {
			clearMachineCredentialEnv(t)
			config := testDirectoryPrincipalConfig(testDirectoryToken, testDirectoryPrincipalID, []string{directoryCapabilityRead})
			config.ExpiresAt = time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
			config.RotatedAt = time.Time{}
			t.Setenv(directoryMachinePrincipalsEnv, testDirectoryMachinePrincipalsJSON(t, config))
		}, method: http.MethodGet, target: "/api/v1/collaborators/" + id.String(), carrier: "bearer", token: testDirectoryToken, wantStatus: 401},
		{name: "garbage in dedicated header", env: func(t *testing.T) {
			configureDirectoryPrincipal(t, allDirectoryCapabilities(), testTartaroInstance)
		}, method: http.MethodGet, target: "/api/v1/collaborators/" + id.String(), carrier: "header", token: "garbage", wantStatus: 401},
		{name: "dedicated header without any inventory", env: clearMachineCredentialEnv,
			method: http.MethodGet, target: "/api/v1/collaborators/" + id.String(), carrier: "header", token: testDirectoryToken, wantStatus: 401},
		{name: "dedicated header with malformed inventory", env: func(t *testing.T) {
			clearMachineCredentialEnv(t)
			t.Setenv(directoryMachinePrincipalsEnv, `[{"principal_id":"broken"}]`)
		}, method: http.MethodGet, target: "/api/v1/collaborators/" + id.String(), carrier: "header", token: testDirectoryToken, wantStatus: 401},
		{name: "valid token on directory route with no database", env: func(t *testing.T) {
			configureDirectoryPrincipal(t, allDirectoryCapabilities(), testTartaroInstance)
		}, method: http.MethodGet, target: "/api/v1/collaborators/" + id.String(), carrier: "header", token: testDirectoryToken, wantStatus: 500},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tc.env(t)
			server := &Server{logger: zap.NewNop()}
			gate := server.requireAuthenticatedConsoleAPIs(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
				claims, _ := claimsFromContext(r.Context())
				t.Fatalf("directory machine request reached the console handler chain (claims=%v)", claims)
			}))

			recorder := httptest.NewRecorder()
			gate.ServeHTTP(recorder, directoryRequest(tc.method, tc.target, tc.carrier, tc.token))
			if recorder.Code != tc.wantStatus {
				t.Fatalf("status=%d body=%s, want %d", recorder.Code, recorder.Body.String(), tc.wantStatus)
			}
		})
	}
}

func TestDirectoryMachineUnknownBearerKeepsConsoleBehavior(t *testing.T) {
	// A bearer that matches no directory digest is not a directory attempt:
	// it continues to the existing session resolution, which refuses it.
	configureDirectoryPrincipal(t, allDirectoryCapabilities(), testTartaroInstance)
	handler, mock, capture := newDirectoryGateServer(t)
	mock.ExpectQuery(`FROM public\.auth_sessions`).WillReturnError(sql.ErrNoRows)

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, directoryRequest(http.MethodGet, "/api/v1/collaborators?q="+testLookupEmail+"&status=active", "bearer", "wrong-"+testDirectoryToken))

	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if events := capture.snapshot(); len(events) != 0 {
		t.Fatalf("unattributed bearer produced directory audit rows: %+v", events)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestOtherMachineCredentialsCannotReadTheDirectory(t *testing.T) {
	id := uuid.New()
	routes := []string{
		"/api/v1/collaborators?q=" + testLookupEmail + "&status=active&limit=100",
		"/api/v1/collaborators/" + id.String(),
		"/api/v1/collaborators/" + id.String() + "/effective-tartaro-actions",
	}
	credentials := []struct {
		name   string
		header string
		token  string
	}{
		{name: "workflow principal", header: "X-Yggdrasil-Workflow-Token", token: testForeignWorkflowToken},
		{name: "event principal", header: "X-Yggdrasil-Event-Token", token: testForeignEventToken},
		{name: "deploy token", header: "X-Deploy-Token", token: testForeignDeployToken},
		{name: "auth admin token", header: "X-Yggdrasil-Auth-Admin-Token", token: testForeignAuthAdminToken},
	}
	for _, credential := range credentials {
		for _, carrier := range []string{"dedicated", "bearer"} {
			for _, route := range routes {
				t.Run(credential.name+" "+carrier+" "+route, func(t *testing.T) {
					configureDirectoryPrincipal(t, allDirectoryCapabilities(), testTartaroInstance)
					t.Setenv(workflowMachinePrincipalsEnv, testWorkflowMachinePrincipalsJSON(t, testForeignWorkflowToken, "ci",
						machineWorkflowRef{Namespace: "dakasa", Name: "deploy"}))
					t.Setenv(eventPublisherPrincipalsEnv, testEventPublisherPrincipalsJSON(t, testForeignEventToken, "adapter"))
					t.Setenv("YGGDRASIL_DEPLOY_TOKEN", testForeignDeployToken)
					t.Setenv("YGGDRASIL_AUTH_ADMIN_TOKEN", testForeignAuthAdminToken)
					handler, mock, capture := newDirectoryGateServer(t)

					req := httptest.NewRequest(http.MethodGet, route, nil)
					if carrier == "bearer" {
						req.Header.Set("Authorization", "Bearer "+credential.token)
						mock.ExpectQuery(`FROM public\.auth_sessions`).WillReturnError(sql.ErrNoRows)
					} else {
						req.Header.Set(credential.header, credential.token)
					}
					recorder := httptest.NewRecorder()
					handler.ServeHTTP(recorder, req)

					if recorder.Code != http.StatusUnauthorized {
						t.Fatalf("status=%d body=%s, want 401", recorder.Code, recorder.Body.String())
					}
					if events := capture.snapshot(); len(events) != 0 {
						t.Fatalf("foreign credential produced directory audit rows: %+v", events)
					}
					if err := mock.ExpectationsWereMet(); err != nil {
						t.Fatal(err)
					}
				})
			}
		}
	}
}

func TestDirectoryCredentialCannotDispatchPublishOrDeploy(t *testing.T) {
	targets := []struct {
		method string
		target string
	}{
		{http.MethodPost, "/api/v1/workflow-runs"},
		{http.MethodGet, "/api/v1/workflow-runs/" + uuid.New().String()},
		{http.MethodPost, "/api/v1/events"},
		{http.MethodPost, "/api/v1/bootstrap"},
		{http.MethodPost, "/api/v1/integrations/install"},
		{http.MethodPost, "/api/v1/auth/providers"},
	}
	for _, carrier := range []string{"header", "bearer"} {
		for _, tc := range targets {
			t.Run(carrier+" "+tc.method+" "+tc.target, func(t *testing.T) {
				configureDirectoryPrincipal(t, allDirectoryCapabilities(), testTartaroInstance)
				t.Setenv(workflowMachinePrincipalsEnv, testWorkflowMachinePrincipalsJSON(t, testForeignWorkflowToken, "ci",
					machineWorkflowRef{Namespace: "dakasa", Name: "deploy"}))
				t.Setenv(eventPublisherPrincipalsEnv, testEventPublisherPrincipalsJSON(t, testForeignEventToken, "adapter"))
				t.Setenv("YGGDRASIL_DEPLOY_TOKEN", testForeignDeployToken)
				t.Setenv("YGGDRASIL_AUTH_ADMIN_TOKEN", testForeignAuthAdminToken)
				handler, mock, _ := newDirectoryGateServer(t)

				recorder := httptest.NewRecorder()
				handler.ServeHTTP(recorder, directoryRequest(tc.method, tc.target, carrier, testDirectoryToken))

				if recorder.Code != http.StatusForbidden && recorder.Code != http.StatusUnauthorized {
					t.Fatalf("status=%d body=%s, want a refusal", recorder.Code, recorder.Body.String())
				}
				if err := mock.ExpectationsWereMet(); err != nil {
					t.Fatal(err)
				}
			})
		}
	}
}

func TestDirectoryMachineRouteClassification(t *testing.T) {
	id := uuid.New()
	cases := []struct {
		method string
		target string
		route  directoryMachineRoute
		id     string
	}{
		{http.MethodGet, "/api/v1/collaborators", directoryRouteLookupEmail, ""},
		{http.MethodGet, "/api/v1/collaborators?q=x", directoryRouteLookupEmail, ""},
		{http.MethodGet, "/api/v1/collaborators/" + id.String(), directoryRouteGet, id.String()},
		{http.MethodGet, "/api/v1/collaborators/" + id.String() + "/effective-tartaro-actions", directoryRouteEffectiveActions, id.String()},
		{http.MethodPost, "/api/v1/collaborators", directoryRouteNone, ""},
		{http.MethodGet, "/api/v1/collaborators/", directoryRouteNone, ""},
		{http.MethodGet, "/api/v1/collaborators/" + strings.ToUpper(id.String()), directoryRouteNone, ""},
		{http.MethodGet, "/api/v1/collaborators/%2e%2e/x", directoryRouteNone, ""},
		{http.MethodGet, "/api/v1/collaborators/" + id.String() + "/effective-tartaro-actions/", directoryRouteNone, ""},
	}
	for _, tc := range cases {
		route, got := directoryMachineRouteFor(httptest.NewRequest(tc.method, tc.target, nil))
		if route != tc.route || got != tc.id {
			t.Fatalf("%s %s: route=%d id=%q, want %d %q", tc.method, tc.target, route, got, tc.route, tc.id)
		}
	}
}

// nonCanonicalDirectoryTargets are spellings the mux would canonicalize and
// redirect (doubled slash, dot segment) that never match the gate prefixes.
// Before the gate learned to recognize them, they bypassed every credential
// branch and reached the mux, whose cleaned-path redirect invited the caller
// to retry the gated path.
func nonCanonicalDirectoryTargets(id uuid.UUID) []string {
	return []string{
		"/api/v1//collaborators",
		"/api/v1//collaborators?q=" + testLookupEmail + "&status=active",
		"//api/v1/collaborators?q=" + testLookupEmail + "&status=active",
		"/api//v1/collaborators/" + id.String(),
		"/api/v1/./collaborators/" + id.String(),
		"/api/v1/../v1/collaborators/" + id.String() + "/effective-tartaro-actions",
		"/api/v1//collaborators/" + id.String() + "/effective-tartaro-actions",
		"/api/v1/../v1/secrets",
		"/api/v1//ops/audit",
		"/api//v1/auth/verify",
	}
}

func TestDirectoryMachineNonCanonicalPathsFailClosedBeforeTheMuxRedirect(t *testing.T) {
	id := uuid.New()
	for _, carrier := range []string{"header", "bearer"} {
		for _, target := range nonCanonicalDirectoryTargets(id) {
			t.Run(carrier+" "+target, func(t *testing.T) {
				configureDirectoryPrincipal(t, allDirectoryCapabilities(), testTartaroInstance)
				handler, mock, capture := newDirectoryGateServer(t)

				recorder := httptest.NewRecorder()
				handler.ServeHTTP(recorder, directoryRequest(http.MethodGet, target, carrier, testDirectoryToken))

				if recorder.Code != http.StatusForbidden {
					t.Fatalf("status=%d body=%s, want 403", recorder.Code, recorder.Body.String())
				}
				if location := recorder.Header().Get("Location"); location != "" {
					t.Fatalf("directory attempt on a non-canonical path was redirected to %q", location)
				}
				if decodeDirectoryBody(t, recorder)["code"] != "permission.denied" {
					t.Fatalf("body=%s", recorder.Body.String())
				}
				assertNoSensitiveContent(t, recorder.Body.String())
				requireSingleAudit(t, capture, "denied", "", "", "route_not_allowed")
				if err := mock.ExpectationsWereMet(); err != nil {
					t.Fatal(err)
				}
			})
		}
	}
}

func TestDirectoryMachineUnknownHeaderOnNonCanonicalPathAnswers401(t *testing.T) {
	// The dedicated header marks the request as a directory attempt even when
	// its value matches nothing, so an unknown credential on a non-canonical
	// spelling is refused as unauthenticated instead of being redirected.
	id := uuid.New()
	for _, target := range nonCanonicalDirectoryTargets(id) {
		t.Run(target, func(t *testing.T) {
			configureDirectoryPrincipal(t, allDirectoryCapabilities(), testTartaroInstance)
			handler, mock, capture := newDirectoryGateServer(t)

			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, directoryRequest(http.MethodGet, target, "header", "wrong-"+testDirectoryToken))

			if recorder.Code != http.StatusUnauthorized {
				t.Fatalf("status=%d body=%s, want 401", recorder.Code, recorder.Body.String())
			}
			if location := recorder.Header().Get("Location"); location != "" {
				t.Fatalf("unknown directory header on a non-canonical path was redirected to %q", location)
			}
			if events := capture.snapshot(); len(events) != 0 {
				t.Fatalf("unknown credential produced directory audit rows: %+v", events)
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestNonCanonicalPathsKeepTheMuxRedirectForEveryOtherCaller(t *testing.T) {
	// The directory branch short-circuits only requests that name themselves
	// as directory attempts. Anonymous callers and bearers that match no
	// directory digest keep the mux's cleaned-path redirect, which carries no
	// data, no credential, and no directory audit row. net/http answers that
	// redirect with 301 through Go 1.25 and 307 from Go 1.26; the contract
	// under test is the redirect to the clean path, not the toolchain's code.
	cases := []struct {
		name         string
		carrier      string
		token        string
		target       string
		wantLocation string
	}{
		{name: "anonymous", carrier: "", target: "/api/v1//collaborators", wantLocation: "/api/v1/collaborators"},
		{name: "anonymous with query", carrier: "", target: "/api/v1//collaborators?status=active", wantLocation: "/api/v1/collaborators?status=active"},
		{name: "unknown bearer", carrier: "bearer", token: "wrong-" + testDirectoryToken, target: "/api/v1//collaborators", wantLocation: "/api/v1/collaborators"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			configureDirectoryPrincipal(t, allDirectoryCapabilities(), testTartaroInstance)
			handler, mock, capture := newDirectoryGateServer(t)

			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, directoryRequest(http.MethodGet, tc.target, tc.carrier, tc.token))

			if recorder.Code != http.StatusMovedPermanently && recorder.Code != http.StatusTemporaryRedirect {
				t.Fatalf("status=%d body=%s, want the mux redirect", recorder.Code, recorder.Body.String())
			}
			if location := recorder.Header().Get("Location"); location != tc.wantLocation {
				t.Fatalf("Location=%q, want %q", location, tc.wantLocation)
			}
			for _, secret := range []string{testDirectoryToken, "Bearer", directoryMachineTokenHeader} {
				if strings.Contains(recorder.Header().Get("Location"), secret) || strings.Contains(recorder.Body.String(), secret) {
					t.Fatalf("redirect carries %q: %s", secret, recorder.Body.String())
				}
			}
			assertNoSensitiveContent(t, recorder.Body.String())
			if events := capture.snapshot(); len(events) != 0 {
				t.Fatalf("redirect produced directory audit rows: %+v", events)
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestDirectoryMachineUnknownRouteSpellingAnswers404WithoutData(t *testing.T) {
	// A canonical path that matches no registered pattern is not redirected
	// and is not gated: the mux answers 404 with no collaborator data and no
	// directory audit row, whichever credential the caller presents.
	for _, carrier := range []string{"header", "bearer"} {
		t.Run(carrier, func(t *testing.T) {
			configureDirectoryPrincipal(t, allDirectoryCapabilities(), testTartaroInstance)
			handler, mock, capture := newDirectoryGateServer(t)

			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, directoryRequest(http.MethodGet, "/API/v1/collaborators", carrier, testDirectoryToken))

			if recorder.Code != http.StatusNotFound {
				t.Fatalf("status=%d body=%s, want 404", recorder.Code, recorder.Body.String())
			}
			if location := recorder.Header().Get("Location"); location != "" {
				t.Fatalf("unknown route was redirected to %q", location)
			}
			assertNoSensitiveContent(t, recorder.Body.String())
			if events := capture.snapshot(); len(events) != 0 {
				t.Fatalf("unknown route produced directory audit rows: %+v", events)
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestNonCanonicalRequestPathMirrorsTheMux(t *testing.T) {
	cases := []struct {
		target string
		want   bool
	}{
		{"/api/v1/collaborators", false},
		{"/api/v1/collaborators/", false},
		{"/", false},
		{"/api/v1/collaborators?q=x", false},
		{"/api/v1/collaborators/%2e%2e/x", false},
		{"/api/v1//collaborators", true},
		{"//api/v1/collaborators", true},
		{"/api/v1/./collaborators", true},
		{"/api/v1/../v1/collaborators", true},
		{"/api/v1/collaborators/.", true},
		{"/api/v1/collaborators//", true},
	}
	for _, tc := range cases {
		req := httptest.NewRequest(http.MethodGet, tc.target, nil)
		if got := nonCanonicalRequestPath(req); got != tc.want {
			t.Fatalf("%s: nonCanonical=%v, want %v", tc.target, got, tc.want)
		}
		// The mux itself must agree: a non-canonical spelling is answered
		// with a redirect, a canonical one is dispatched or answered 404.
		mux := http.NewServeMux()
		mux.HandleFunc("GET /api/v1/collaborators", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
		recorder := httptest.NewRecorder()
		mux.ServeHTTP(recorder, req)
		redirected := recorder.Code == http.StatusMovedPermanently || recorder.Code == http.StatusTemporaryRedirect
		if redirected != tc.want {
			t.Fatalf("%s: mux status=%d, nonCanonical=%v", tc.target, recorder.Code, tc.want)
		}
	}
}
