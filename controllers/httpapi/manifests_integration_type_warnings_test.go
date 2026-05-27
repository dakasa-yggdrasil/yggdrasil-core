package httpapi

import (
	"bytes"
	"database/sql/driver"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"

	manifestengine "github.com/dakasa-yggdrasil/yggdrasil-core/manifest"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

// loadTestAllowlist returns the seeded allowlist from the repo's
// config/ directory. Tests assert against the canonical exempt list
// shipped in the YAML rather than maintaining a duplicate.
func loadTestAllowlist(t *testing.T) *manifestengine.CapabilityNamingAllowlist {
	t.Helper()
	al, err := manifestengine.LoadCapabilityNamingAllowlist("../../config/capability_naming_allowlist.yaml")
	if err != nil {
		t.Fatalf("load allowlist: %v", err)
	}
	return al
}

// capturingArg implements sqlmock's driver.Value matcher contract,
// always matching but also copying the raw argument bytes into the
// caller-owned dst so the test can verify the persisted shape after
// the UPDATE has fired.
type capturingArg struct {
	dst *[]byte
}

// Match copies the inbound argument into dst when it is a byte slice
// or a string, then always reports a match — the test layer asserts
// on the captured bytes after handler return.
func (c capturingArg) Match(v driver.Value) bool {
	switch b := v.(type) {
	case []byte:
		buf := make([]byte, len(b))
		copy(buf, b)
		*c.dst = buf
	case string:
		*c.dst = []byte(b)
	}
	return true
}

// newWarningsTestServer wires the minimal mux + Server with sqlmock for
// the capability-naming warning HTTP integration test. Mirrors
// newManifestDeleteServer in scope but uses sqlmock so we can verify
// the persistence UPDATE without a live Postgres.
func newWarningsTestServer(t *testing.T) (*Server, sqlmock.Sqlmock) {
	t.Helper()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	srv := &Server{
		serviceName:         "yggdrasil-core-test",
		db:                  db,
		capabilityAllowlist: loadTestAllowlist(t),
	}
	return srv, mock
}

// grafanaWarningsSpec is the manifest body the integration test POSTs.
// Returns the JSON-encoded payload and the non-conformant action
// names expected to trip the validator.
//
// Note: list_identities was added to the allowlist in cycle 2026-05-27
// as a compat alias of observe_identities (kept under the v0.5.x shim
// window so the core re-sync cron does not break during cutover). The
// fixture now uses delete_user as the second non-conformant entry —
// canonical observe alias is destroy_user, a TRUE rename candidate
// across multiple adapters in the residual table.
func grafanaWarningsSpec(name string) (raw []byte, nonConformant []string) {
	body := map[string]any{
		"name":      name,
		"namespace": "default",
		"spec": map[string]any{
			"provider":          "grafana",
			"adapter":           map[string]any{"transport": "http_json", "version": "1.3.0", "timeout_seconds": 30, "endpoints": map[string]any{"describe": "/describe", "execute": "/execute"}},
			"capabilities":      []string{"describe", "execute"},
			"credential_schema": map[string]any{"mode": "inline"},
			"instance_schema":   map[string]any{"mode": "inline"},
			"resource_types": []map[string]any{
				{"name": "user", "canonical_prefix": "thirdparty.grafana.user", "identity_template": "user.{id}", "default_actions": []string{"create_user"}},
			},
			"action_catalog": []map[string]any{
				{"name": "ensure_folder", "category": "capability", "resource_types": []string{"user"}, "idempotent": true},
				{"name": "create_user", "category": "capability", "resource_types": []string{"user"}, "idempotent": true},
				{"name": "delete_user", "category": "capability", "resource_types": []string{"user"}, "idempotent": true},
				{"name": "on_user_provisioned", "category": "reactor", "resource_types": []string{"user"}, "idempotent": true},
			},
			"discovery":     map[string]any{"mode": "push", "cursor": "none"},
			"normalization": map[string]any{"external_id_path": "id", "fallback_resource_prefix": "thirdparty.grafana.custom"},
			"execution":     map[string]any{"idempotent_actions": []string{"ensure_folder", "create_user", "delete_user"}},
		},
	}
	raw, _ = json.Marshal(body)
	return raw, []string{"create_user", "delete_user"}
}

// TestHandleManifestCreate_IntegrationType_WarningsSurfaced is an
// HTTP-level integration test: POST a non-conformant integration_type
// manifest and assert the 201 response carries a warnings array with
// the expected entries, AND that the warnings land in the
// public.manifests.metadata column.
func TestHandleManifestCreate_IntegrationType_WarningsSurfaced(t *testing.T) {
	srv, mock := newWarningsTestServer(t)

	rawBody, wantValues := grafanaWarningsSpec("grafana-warns")

	// 1. Version lookup — returns 1 (first version).
	mock.ExpectBegin()
	mock.ExpectQuery(`SELECT COALESCE\(MAX\(version\), 0\) \+ 1 FROM public\.manifests`).
		WithArgs("integration_type", "default", "grafana-warns").
		WillReturnRows(sqlmock.NewRows([]string{"v"}).AddRow(1))

	// 2. Deactivate any previously-active row (no-op for first version).
	mock.ExpectExec(`UPDATE public\.manifests SET active = FALSE WHERE kind`).
		WithArgs("integration_type", "default", "grafana-warns").
		WillReturnResult(sqlmock.NewResult(0, 0))

	// 3. Insert the new manifest row. RETURNING populates the scan.
	manifestID := uuid.New()
	now := time.Date(2026, 5, 27, 0, 0, 0, 0, time.UTC)
	mock.ExpectQuery(`INSERT INTO public\.manifests`).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "api_version", "kind", "namespace", "name", "version",
			"active", "description", "labels", "spec", "checksum",
			"created_at", "updated_at",
		}).AddRow(
			manifestID, "yggdrasil.io/v1alpha1", "integration_type", "default", "grafana-warns", 1,
			true, "", []byte("{}"), []byte("{}"), "sha256:abc",
			now, now,
		))
	mock.ExpectCommit()

	// 4. Warnings persist UPDATE — argument capture lets us verify the
	// shape of the metadata JSONB blob that lands in the manifests row.
	var persistedMetadata []byte
	mock.ExpectExec(`UPDATE public\.manifests SET metadata = \$1::jsonb WHERE id = \$2`).
		WithArgs(capturingArg{dst: &persistedMetadata}, manifestID).
		WillReturnResult(sqlmock.NewResult(0, 1))

	req := httptest.NewRequest(http.MethodPost, "/api/v1/manifests?kind=integration_type", bytes.NewReader(rawBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	srv.handleManifestCreateGeneric(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201 Created, got %d (body=%s)", w.Code, w.Body.String())
	}

	var resp struct {
		Warnings []manifestengine.Warning `json:"warnings"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parse response: %v", err)
	}
	if len(resp.Warnings) != len(wantValues) {
		t.Fatalf("expected %d warnings, got %d (%v)", len(wantValues), len(resp.Warnings), resp.Warnings)
	}

	gotCodes := map[string]string{}
	for _, w := range resp.Warnings {
		gotCodes[w.Value] = w.Code
	}
	for _, want := range wantValues {
		if gotCodes[want] != "CAPABILITY_NAME_NONCONFORMANT" {
			t.Errorf("expected %s warning with code CAPABILITY_NAME_NONCONFORMANT, got %v", want, gotCodes)
		}
	}

	for _, warn := range resp.Warnings {
		if warn.Value == "create_user" && !strings.Contains(warn.Message, "ensure_user") {
			t.Errorf("expected suggestion to mention ensure_user, got %q", warn.Message)
		}
		if warn.Value == "delete_user" && !strings.Contains(warn.Message, "destroy_user") {
			t.Errorf("expected suggestion to mention destroy_user, got %q", warn.Message)
		}
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet sqlmock expectations: %v", err)
	}

	// Persistence assertion (Task 17): the warnings must reach the
	// manifests.metadata column so the console can render a conformance
	// badge without re-running the validator on every page load.
	if len(persistedMetadata) == 0 {
		t.Fatalf("expected metadata JSON to be persisted, got empty bytes")
	}
	var stored struct {
		Warnings []manifestengine.Warning `json:"warnings"`
	}
	if err := json.Unmarshal(persistedMetadata, &stored); err != nil {
		t.Fatalf("parse persisted metadata: %v (raw=%s)", err, string(persistedMetadata))
	}
	if len(stored.Warnings) != len(wantValues) {
		t.Fatalf("expected %d warnings persisted, got %d (raw=%s)", len(wantValues), len(stored.Warnings), string(persistedMetadata))
	}
}

// TestValidatorSmokeAgainstGrafana130 runs the validator against the
// historical Grafana v1.3.0 action_catalog (per spec §1.1 + §7 Tier B)
// and asserts the validator flags exactly the expected
// non-conformances. This is the rollout's first real-world
// regression test.
//
// Note (cycle 2026-05-27): list_identities is now allowlisted as a
// compat alias of observe_identities (kept under the v0.5.x shim
// window), so it no longer triggers a warning. The other three
// non-conformant names remain residual rename candidates documented
// in the post-sweep table.
func TestValidatorSmokeAgainstGrafana130(t *testing.T) {
	al := loadTestAllowlist(t)

	// The exact list from spec §1.1 + §7 Tier B Grafana table.
	grafanaCatalog := []model.IntegrationActionDefinition{
		{Name: "ensure_folder", Category: "capability"},
		{Name: "create_user", Category: "capability"},
		{Name: "update_user_role", Category: "capability"},
		{Name: "create_team", Category: "capability"},
		{Name: "list_identities", Category: "capability"},
		{Name: "observe_datasource_health", Category: "capability"},
	}

	warnings := manifestengine.ValidateActionCatalogNaming(grafanaCatalog, al)
	wantValues := []string{"create_user", "update_user_role", "create_team"}
	if len(warnings) != len(wantValues) {
		t.Fatalf("expected %d warnings (one per non-conformant), got %d (%v)", len(wantValues), len(warnings), warnings)
	}
	gotValues := map[string]bool{}
	for _, w := range warnings {
		gotValues[w.Value] = true
	}
	for _, want := range wantValues {
		if !gotValues[want] {
			t.Errorf("expected warning for %q in Grafana smoke, got %v", want, gotValues)
		}
	}
}
