package httpapi

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

type fakeDispatcher struct {
	gotReq model.ExecuteIntegrationRequest
	resp   any
	err    error
}

func (f *fakeDispatcher) Execute(_ context.Context, req model.ExecuteIntegrationRequest) (any, error) {
	f.gotReq = req
	return f.resp, f.err
}

func TestSurfaceQuery_PassesThrough(t *testing.T) {
	disp := &fakeDispatcher{resp: map[string]any{"items": []any{"a"}}}
	srv := &Server{surfaceQueryDispatcher: disp}
	body, _ := json.Marshal(map[string]any{"query_name": "list-channels", "params": map[string]any{"x": 1}})
	req := httptest.NewRequest("POST", "/api/v1/integrations/i1/surface-query", bytes.NewReader(body))
	req.SetPathValue("instance_id", "i1")
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.handleIntegrationSurfaceQuery()(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body %s", w.Code, w.Body.String())
	}
	if disp.gotReq.Operation != "on_surface_query" {
		t.Errorf("operation = %q", disp.gotReq.Operation)
	}
	if disp.gotReq.Integration.ManifestID != "i1" {
		t.Errorf("integration.manifest_id = %q", disp.gotReq.Integration.ManifestID)
	}
	if in, ok := disp.gotReq.Input["query_name"].(string); !ok || in != "list-channels" {
		t.Errorf("input.query_name = %v", disp.gotReq.Input["query_name"])
	}
}

// SECURITY: the verified caller stamped onto the outbound envelope comes from
// the session claims attached to the request context — never from the client
// body/params. A spoofed collaborator_id nested in params must NOT become the
// verified caller.
func TestSurfaceQuery_StampsVerifiedCallerFromSession(t *testing.T) {
	disp := &fakeDispatcher{resp: map[string]any{"items": []any{}}}
	srv := &Server{surfaceQueryDispatcher: disp}
	// Client tries to spoof a victim id inside params.
	body, _ := json.Marshal(map[string]any{
		"query_name": "my-employment",
		"params":     map[string]any{"collaborator_id": "VICTIM-SPOOFED-ID"},
	})
	req := httptest.NewRequest("POST", "/api/v1/integrations/i1/surface-query", bytes.NewReader(body))
	req.SetPathValue("instance_id", "i1")
	req.Header.Set("Content-Type", "application/json")
	// The auth middleware has validated the session and attached claims.
	ctx := contextWithClaims(req.Context(), map[string]any{
		"collaborator_id": "real-verified-collab",
		"session_id":      "sess-1",
	})
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()
	srv.handleIntegrationSurfaceQuery()(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body %s", w.Code, w.Body.String())
	}
	got, ok := disp.gotReq.Input["verified_caller_id"].(string)
	if !ok {
		t.Fatalf("verified_caller_id not stamped onto Input: %#v", disp.gotReq.Input)
	}
	if got != "real-verified-collab" {
		t.Fatalf("verified_caller_id = %q, want the session collaborator (not the spoofed params id)", got)
	}
	// The client-supplied params must be preserved verbatim (adapter ignores its
	// collaborator_id for scoping, but params still flow through for limits etc.).
	params, _ := disp.gotReq.Input["params"].(map[string]any)
	if params["collaborator_id"] != "VICTIM-SPOOFED-ID" {
		t.Errorf("params should pass through unchanged, got %#v", params)
	}
}

// A machine/token caller authenticates WITHOUT collaborator claims; the handler
// must omit the verified caller rather than stamping an empty string.
func TestSurfaceQuery_NoClaims_OmitsVerifiedCaller(t *testing.T) {
	disp := &fakeDispatcher{resp: map[string]any{"items": []any{}}}
	srv := &Server{surfaceQueryDispatcher: disp}
	body, _ := json.Marshal(map[string]any{"query_name": "list-employees"})
	req := httptest.NewRequest("POST", "/api/v1/integrations/i1/surface-query", bytes.NewReader(body))
	req.SetPathValue("instance_id", "i1")
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.handleIntegrationSurfaceQuery()(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body %s", w.Code, w.Body.String())
	}
	if _, present := disp.gotReq.Input["verified_caller_id"]; present {
		t.Errorf("verified_caller_id must be OMITTED for a no-claims caller, got %#v", disp.gotReq.Input["verified_caller_id"])
	}
}

// A client cannot smuggle verified_caller_id via the top-level body — the body
// decoder disallows unknown fields, so such a request is a 400.
func TestSurfaceQuery_ClientCannotInjectVerifiedCaller(t *testing.T) {
	srv := &Server{surfaceQueryDispatcher: &fakeDispatcher{}}
	body, _ := json.Marshal(map[string]any{
		"query_name":         "my-employment",
		"verified_caller_id": "attacker-injected",
	})
	req := httptest.NewRequest("POST", "/api/v1/integrations/i1/surface-query", bytes.NewReader(body))
	req.SetPathValue("instance_id", "i1")
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.handleIntegrationSurfaceQuery()(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("status %d, want 400 (unknown body field rejected)", w.Code)
	}
}

func TestSurfaceQuery_MissingQueryNameIs400(t *testing.T) {
	srv := &Server{surfaceQueryDispatcher: &fakeDispatcher{}}
	body, _ := json.Marshal(map[string]any{})
	req := httptest.NewRequest("POST", "/api/v1/integrations/i1/surface-query", bytes.NewReader(body))
	req.SetPathValue("instance_id", "i1")
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.handleIntegrationSurfaceQuery()(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("status %d, want 400", w.Code)
	}
}

func TestSurfaceQuery_DispatchErrorIs502(t *testing.T) {
	srv := &Server{surfaceQueryDispatcher: &fakeDispatcher{err: errors.New("amqp down")}}
	body, _ := json.Marshal(map[string]any{"query_name": "x"})
	req := httptest.NewRequest("POST", "/api/v1/integrations/i1/surface-query", bytes.NewReader(body))
	req.SetPathValue("instance_id", "i1")
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.handleIntegrationSurfaceQuery()(w, req)
	if w.Code != http.StatusBadGateway {
		t.Errorf("status %d, want 502", w.Code)
	}
}

// =============================================================================
// View-access gate (opt-in, zero-lockout). A query that DECLARES a required
// permission is gated; a query that declares none is always allowed (the
// no-lockout / self-service case). Admin perms bypass. The declared perm comes
// from the surface manifest via the injectable surfaceQueryPermSource seam; the
// caller's effective perms come from the injectable callerPermResolver seam —
// both fakes, so the handler (the unit under test) runs its REAL gating logic.
// =============================================================================

// fakeSurfaceQueryPermSource maps (instanceID, queryName) → the declared
// requirement. A missing entry means "no permission declared" (ungated).
type fakeSurfaceQueryPermSource struct {
	// keyed by "<instanceID>\x00<queryName>"
	perms map[string]surfaceQueryRequirement
	err   error
}

func (f *fakeSurfaceQueryPermSource) RequiredPermission(_ context.Context, instanceID, queryName string) (surfaceQueryRequirement, error) {
	if f.err != nil {
		return surfaceQueryRequirement{}, f.err
	}
	req, ok := f.perms[instanceID+"\x00"+queryName]
	if !ok {
		return surfaceQueryRequirement{}, nil // no declaration ⇒ ungated
	}
	return req, nil
}

// callerPerms returns a callerPermResolver fake yielding a fixed perm list for
// any collaborator id (the verified caller in the test).
func callerPerms(perms ...string) func(context.Context, string) ([]string, error) {
	return func(context.Context, string) ([]string, error) {
		return perms, nil
	}
}

func surfaceQueryReq(instanceID, queryName, collabID string, body map[string]any) *http.Request {
	raw, _ := json.Marshal(body)
	req := httptest.NewRequest("POST", "/api/v1/integrations/"+instanceID+"/surface-query", bytes.NewReader(raw))
	req.SetPathValue("instance_id", instanceID)
	req.Header.Set("Content-Type", "application/json")
	if collabID != "" {
		req = req.WithContext(contextWithClaims(req.Context(), map[string]any{
			"collaborator_id": collabID,
			"session_id":      "sess-test",
		}))
	}
	return req
}

// A query that declares a required permission + a caller WITHOUT it ⇒ 403
// permission_denied, and the adapter is NEVER reached.
func TestSurfaceQuery_DeclaredPerm_CallerWithout_Denied(t *testing.T) {
	disp := &fakeDispatcher{resp: map[string]any{"items": []any{}}}
	srv := &Server{
		surfaceQueryDispatcher: disp,
		surfaceQueryPermSource: &fakeSurfaceQueryPermSource{
			perms: map[string]surfaceQueryRequirement{
				"clt-instance\x00list-employees": {Permission: "clt:contract:view-all", Namespace: "clt"},
			},
		},
		// Caller holds a perm in a DIFFERENT namespace ("slack."), so neither the
		// exact-perm rule nor the namespace-match rule (which mirrors
		// canViewSurface) grants access to the clt-namespaced query.
		callerPermResolver: callerPerms("slack.users.read"),
	}
	req := surfaceQueryReq("clt-instance", "list-employees", "real-collab", map[string]any{"query_name": "list-employees"})
	w := httptest.NewRecorder()
	srv.handleIntegrationSurfaceQuery()(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body %s", w.Code, w.Body.String())
	}
	if disp.gotReq.Operation != "" {
		t.Fatalf("adapter MUST NOT be reached on deny, got dispatched op %q", disp.gotReq.Operation)
	}
	if body := w.Body.String(); !bytesContains(body, "permission_denied") || !bytesContains(body, "clt:contract:view-all") {
		t.Errorf("deny body should name the error + missing perm, got %s", body)
	}
}

// A caller holding ANY perm in the declared (colon-style) namespace is allowed,
// mirroring canViewSurface's "holds ≥1 perm in the integration's namespace".
// Here the gate requires clt:contract:view-all but the caller only has
// clt:paystub:view-own — same "clt" family ⇒ allowed (surface-level view grant).
func TestSurfaceQuery_DeclaredPerm_CallerInNamespace_Allowed(t *testing.T) {
	disp := &fakeDispatcher{resp: map[string]any{"items": []any{"row"}}}
	srv := &Server{
		surfaceQueryDispatcher: disp,
		surfaceQueryPermSource: &fakeSurfaceQueryPermSource{
			perms: map[string]surfaceQueryRequirement{
				"clt-instance\x00list-employees": {Permission: "clt:contract:view-all", Namespace: "clt"},
			},
		},
		callerPermResolver: callerPerms("clt:paystub:view-own"),
	}
	req := surfaceQueryReq("clt-instance", "list-employees", "base-employee", map[string]any{"query_name": "list-employees"})
	w := httptest.NewRecorder()
	srv.handleIntegrationSurfaceQuery()(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (in-namespace view grant); body %s", w.Code, w.Body.String())
	}
	if disp.gotReq.Operation != "on_surface_query" {
		t.Fatalf("in-namespace caller should reach the adapter, got op %q", disp.gotReq.Operation)
	}
}

// A query that declares a required permission + a caller WITH that exact perm
// ⇒ allowed (reaches the adapter).
func TestSurfaceQuery_DeclaredPerm_CallerWith_Allowed(t *testing.T) {
	disp := &fakeDispatcher{resp: map[string]any{"items": []any{"row"}}}
	srv := &Server{
		surfaceQueryDispatcher: disp,
		surfaceQueryPermSource: &fakeSurfaceQueryPermSource{
			perms: map[string]surfaceQueryRequirement{
				"clt-instance\x00list-employees": {Permission: "clt:contract:view-all", Namespace: "clt"},
			},
		},
		callerPermResolver: callerPerms("clt:contract:view-all"),
	}
	req := surfaceQueryReq("clt-instance", "list-employees", "real-collab", map[string]any{"query_name": "list-employees"})
	w := httptest.NewRecorder()
	srv.handleIntegrationSurfaceQuery()(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %s", w.Code, w.Body.String())
	}
	if disp.gotReq.Operation != "on_surface_query" {
		t.Fatalf("adapter should be reached when caller holds the perm, got op %q", disp.gotReq.Operation)
	}
}

// A query that declares a required permission + an ADMIN caller (holds an admin
// bypass perm, none of the surface's own perms) ⇒ allowed.
func TestSurfaceQuery_DeclaredPerm_AdminCaller_Allowed(t *testing.T) {
	disp := &fakeDispatcher{resp: map[string]any{"items": []any{"row"}}}
	srv := &Server{
		surfaceQueryDispatcher: disp,
		surfaceQueryPermSource: &fakeSurfaceQueryPermSource{
			perms: map[string]surfaceQueryRequirement{
				"clt-instance\x00list-employees": {Permission: "clt:contract:view-all", Namespace: "clt"},
			},
		},
		callerPermResolver: callerPerms("yggdrasil:manage_integrations"),
	}
	req := surfaceQueryReq("clt-instance", "list-employees", "admin-collab", map[string]any{"query_name": "list-employees"})
	w := httptest.NewRecorder()
	srv.handleIntegrationSurfaceQuery()(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (admin bypass); body %s", w.Code, w.Body.String())
	}
	if disp.gotReq.Operation != "on_surface_query" {
		t.Fatalf("admin should reach the adapter, got op %q", disp.gotReq.Operation)
	}
}

// THE CRITICAL NO-LOCKOUT CASE: a query that declares NO permission ⇒ allowed
// for ANY authenticated caller, regardless of their (lack of) perms. This is
// what keeps every current surface working and what protects the CLT my-*
// self-service reads.
func TestSurfaceQuery_NoPermDeclared_AnyCaller_Allowed(t *testing.T) {
	disp := &fakeDispatcher{resp: map[string]any{"employment": nil}}
	srv := &Server{
		surfaceQueryDispatcher: disp,
		// Source has NO entry for this query ⇒ ungated.
		surfaceQueryPermSource: &fakeSurfaceQueryPermSource{perms: map[string]surfaceQueryRequirement{}},
		// Caller holds zero perms — must STILL be allowed because the query
		// declares none (self-service exemption).
		callerPermResolver: callerPerms(),
	}
	req := surfaceQueryReq("clt-instance", "my-employment", "base-employee", map[string]any{"query_name": "my-employment"})
	w := httptest.NewRecorder()
	srv.handleIntegrationSurfaceQuery()(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (no perm declared ⇒ allow); body %s", w.Code, w.Body.String())
	}
	if disp.gotReq.Operation != "on_surface_query" {
		t.Fatalf("ungated query must reach the adapter, got op %q", disp.gotReq.Operation)
	}
}

func bytesContains(haystack, needle string) bool {
	return bytes.Contains([]byte(haystack), []byte(needle))
}

// =============================================================================
// Production SurfaceQueryPermSource (dbSurfaceQueryPermSource) — verifies the
// instance→type→surface resolution + the queries[] requirement extraction
// against sqlmock, so the SQL contract is checked offline.
// =============================================================================

func TestDBSurfaceQueryPermSource_DeclaredQuery_ReturnsRequirement(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	spec := `{"category":"integration","runtime":{"kind":"spa","base_path":"/s/employment-clt"},"display":{"title":"Pessoas"},"queries":[{"name":"list-employees","requires_permission":"clt:contract:view-all"},{"name":"my-employment"}]}`
	mock.ExpectQuery("FROM public.manifests ii").
		WithArgs("clt-instance").
		WillReturnRows(sqlmock.NewRows([]string{"spec"}).AddRow([]byte(spec)))

	src := NewDBSurfaceQueryPermSource(db)
	got, err := src.RequiredPermission(context.Background(), "clt-instance", "list-employees")
	if err != nil {
		t.Fatalf("RequiredPermission: %v", err)
	}
	if got.Permission != "clt:contract:view-all" {
		t.Errorf("permission = %q, want clt:contract:view-all", got.Permission)
	}
	if got.Namespace != "clt" {
		t.Errorf("namespace = %q, want clt", got.Namespace)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet sqlmock expectations: %v", err)
	}
}

func TestDBSurfaceQueryPermSource_UndeclaredQuery_Ungated(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	// list-employees IS gated, but my-employment is listed with NO
	// requires_permission ⇒ ungated (the self-service exemption).
	spec := `{"category":"integration","runtime":{"kind":"spa","base_path":"/x"},"display":{"title":"P"},"queries":[{"name":"list-employees","requires_permission":"clt:contract:view-all"},{"name":"my-employment"}]}`
	mock.ExpectQuery("FROM public.manifests ii").
		WithArgs("clt-instance").
		WillReturnRows(sqlmock.NewRows([]string{"spec"}).AddRow([]byte(spec)))

	src := NewDBSurfaceQueryPermSource(db)
	got, err := src.RequiredPermission(context.Background(), "clt-instance", "my-employment")
	if err != nil {
		t.Fatalf("RequiredPermission: %v", err)
	}
	if got.Permission != "" {
		t.Errorf("permission = %q, want empty (ungated)", got.Permission)
	}
}

func TestDBSurfaceQueryPermSource_NoSurfaceRow_Ungated(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	// Instance has no registered surface manifest ⇒ ErrNoRows ⇒ ungated (must
	// never lock out an instance that simply has no surface).
	mock.ExpectQuery("FROM public.manifests ii").
		WithArgs("orphan-instance").
		WillReturnError(sql.ErrNoRows)

	src := NewDBSurfaceQueryPermSource(db)
	got, err := src.RequiredPermission(context.Background(), "orphan-instance", "list-employees")
	if err != nil {
		t.Fatalf("RequiredPermission should swallow ErrNoRows, got %v", err)
	}
	if got.Permission != "" {
		t.Errorf("permission = %q, want empty (ungated)", got.Permission)
	}
}
