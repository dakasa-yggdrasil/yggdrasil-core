package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/manifestsync"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

// --- fake manifestsync.Deps for unit tests ---

// fakeSyncDeps implements manifestsync.Deps without any DB or network.
// The zero value returns a happy-path synced outcome.
type fakeSyncDeps struct {
	// Controls what GetIntegrationType returns.
	typeNotFound bool
	// Controls what ListInstances returns.
	noInstances bool

	// Recorded calls.
	emittedEventType string
	emittedPayload   map[string]any
}

var (
	fakeTypeID     = uuid.MustParse("11111111-1111-1111-1111-111111111111")
	fakeInstanceID = uuid.MustParse("22222222-2222-2222-2222-222222222222")
)

func (f *fakeSyncDeps) Now() time.Time { return time.Date(2026, 5, 16, 0, 0, 0, 0, time.UTC) }

func (f *fakeSyncDeps) GetIntegrationType(ctx context.Context, typeID uuid.UUID) (model.Manifest, model.IntegrationTypeManifestSpec, error) {
	if f.typeNotFound {
		return model.Manifest{}, model.IntegrationTypeManifestSpec{}, errors.New("manifest not found")
	}
	m := model.Manifest{
		ID:      typeID,
		Kind:    "integration_type",
		Version: 3,
		Metadata: model.ManifestMetadata{
			Namespace: "dakasa",
			Name:      "github",
		},
	}
	spec := model.IntegrationTypeManifestSpec{
		Adapter:          model.IntegrationAdapterSpec{Version: "1.0.0"},
		CredentialSchema: model.IntegrationSchemaSpec{Mode: "static"},
		ActionCatalog:    []model.IntegrationActionDefinition{{Name: "list-repos"}},
	}
	return m, spec, nil
}

func (f *fakeSyncDeps) ListInstances(ctx context.Context, typeID uuid.UUID) ([]model.Manifest, []model.IntegrationInstanceManifestSpec, error) {
	if f.noInstances {
		return nil, nil, nil
	}
	inst := model.Manifest{
		ID:   fakeInstanceID,
		Kind: "integration_instance",
		Metadata: model.ManifestMetadata{
			Namespace: "dakasa",
			Name:      "github-prod",
		},
	}
	spec := model.IntegrationInstanceManifestSpec{
		TypeRef: model.ManifestSelector{Namespace: "dakasa", Name: "github"},
	}
	return []model.Manifest{inst}, []model.IntegrationInstanceManifestSpec{spec}, nil
}

func (f *fakeSyncDeps) InvokeDescribe(
	ctx context.Context,
	instanceManifest model.Manifest,
	typeManifest model.Manifest,
	instanceSpec model.IntegrationInstanceManifestSpec,
	typeSpec model.IntegrationTypeManifestSpec,
) (model.IntegrationTypeManifestSpec, error) {
	// Return a live spec that differs from typeSpec (adds an action) so
	// SyncIntegrationType proceeds to ApplyManifestVersion.
	live := typeSpec
	live.Adapter.Version = "2.0.0"
	live.ActionCatalog = append(live.ActionCatalog, model.IntegrationActionDefinition{Name: "create-repo"})
	return live, nil
}

func (f *fakeSyncDeps) ApplyManifestVersion(ctx context.Context, doc model.ManifestDocument) (model.Manifest, error) {
	return model.Manifest{
		ID:      fakeTypeID,
		Version: 4,
	}, nil
}

func (f *fakeSyncDeps) EmitEvent(ctx context.Context, eventType string, aggregateID uuid.UUID, payload map[string]any) error {
	f.emittedEventType = eventType
	f.emittedPayload = payload
	return nil
}

// --- test helper: build a minimal mux with only the sync route ---

func newIntegrationTypeSyncHandler(deps manifestsync.Deps) http.Handler {
	server := &Server{
		serviceName: "test",
		db:          nil, // not needed: deps is injected
	}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v1/integration-types/{id}/sync", server.handleIntegrationTypeSync(deps))
	return mux
}

func doSync(t *testing.T, h http.Handler, typeID string, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/integration-types/"+typeID+"/sync", nil)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w
}

// --- tests ---

func TestIntegrationTypeSync_HappyPath_Returns200(t *testing.T) {
	t.Setenv("YGGDRASIL_AUTH_ADMIN_TOKEN", "admin-token")
	t.Setenv("YGGDRASIL_WORKFLOW_RUN_TOKEN", "")

	fake := &fakeSyncDeps{}
	h := newIntegrationTypeSyncHandler(fake)

	w := doSync(t, h, fakeTypeID.String(), map[string]string{
		"X-Yggdrasil-Auth-Admin-Token": "admin-token",
	})

	if w.Code != http.StatusOK {
		t.Fatalf("status: got %d, want 200 (body=%s)", w.Code, w.Body.String())
	}

	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if got, want := resp["status"], "synced"; got != want {
		t.Errorf("status: got %q, want %q", got, want)
	}
	if resp["from_version"] == nil {
		t.Errorf("from_version missing in response: %s", w.Body.String())
	}
	if resp["to_version"] == nil {
		t.Errorf("to_version missing in response: %s", w.Body.String())
	}
}

func TestIntegrationTypeSync_Unauthorized_Returns401(t *testing.T) {
	t.Setenv("YGGDRASIL_AUTH_ADMIN_TOKEN", "admin-token")
	t.Setenv("YGGDRASIL_WORKFLOW_RUN_TOKEN", "")

	fake := &fakeSyncDeps{}
	h := newIntegrationTypeSyncHandler(fake)

	// No auth header.
	w := doSync(t, h, fakeTypeID.String(), nil)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status: got %d, want 401 (body=%s)", w.Code, w.Body.String())
	}
}

func TestIntegrationTypeSync_TypeNotFound_Returns404(t *testing.T) {
	t.Setenv("YGGDRASIL_AUTH_ADMIN_TOKEN", "admin-token")
	t.Setenv("YGGDRASIL_WORKFLOW_RUN_TOKEN", "")

	// typeNotFound=true causes GetIntegrationType to error → syncer emits
	// integration_type.sync_skipped with reason=type_not_found.
	fake := &fakeSyncDeps{typeNotFound: true}
	h := newIntegrationTypeSyncHandler(fake)

	w := doSync(t, h, fakeTypeID.String(), map[string]string{
		"X-Yggdrasil-Auth-Admin-Token": "admin-token",
	})

	if w.Code != http.StatusNotFound {
		t.Fatalf("status: got %d, want 404 (body=%s)", w.Code, w.Body.String())
	}

	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if got := resp["error"]; got != "type not found" {
		t.Errorf("error: got %q, want %q", got, "type not found")
	}
}

func TestIntegrationTypeSync_InvalidUUID_Returns400(t *testing.T) {
	t.Setenv("YGGDRASIL_AUTH_ADMIN_TOKEN", "admin-token")
	t.Setenv("YGGDRASIL_WORKFLOW_RUN_TOKEN", "")

	fake := &fakeSyncDeps{}
	h := newIntegrationTypeSyncHandler(fake)

	w := doSync(t, h, "not-a-uuid", map[string]string{
		"X-Yggdrasil-Auth-Admin-Token": "admin-token",
	})

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status: got %d, want 400 (body=%s)", w.Code, w.Body.String())
	}

	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if got := resp["error"]; got != "invalid uuid" {
		t.Errorf("error: got %q, want %q", got, "invalid uuid")
	}
}
