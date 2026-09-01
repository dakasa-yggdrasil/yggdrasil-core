package httpapi

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"
)

func newGenericInstancePolicyTestServer(t *testing.T) (*Server, sqlmock.Sqlmock) {
	t.Helper()
	t.Setenv("YGGDRASIL_WORKFLOW_RUN_TOKEN", "")

	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	return &Server{serviceName: "yggdrasil-core-test", db: db}, mock
}

func expectResolvedIntegrationType(
	t *testing.T,
	mock sqlmock.Sqlmock,
	name string,
	spec map[string]any,
) {
	t.Helper()

	rawSpec, err := json.Marshal(spec)
	if err != nil {
		t.Fatalf("marshal integration_type fixture: %v", err)
	}

	now := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	mock.ExpectQuery(`(?s)SELECT.*FROM public\.manifests.*WHERE kind = \$1 AND namespace = \$2 AND name = \$3.*active = TRUE.*ORDER BY version DESC LIMIT 1`).
		WithArgs("integration_type", "global", name).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "api_version", "kind", "namespace", "name", "version",
			"active", "description", "labels", "spec", "checksum",
			"created_at", "updated_at",
		}).AddRow(
			uuid.New(), "yggdrasil.io/v1alpha1", "integration_type", "global", name, 1,
			true, "", []byte(`{}`), rawSpec, "sha256:type-contract",
			now, now,
		))
}

func genericIntegrationInstanceBody(t *testing.T, name, typeName string, specExtras map[string]any) []byte {
	t.Helper()

	spec := map[string]any{
		"type_ref": map[string]any{
			"namespace": "global",
			"name":      typeName,
		},
		"status": "active",
	}
	for key, value := range specExtras {
		spec[key] = value
	}

	raw, err := json.Marshal(map[string]any{
		"name":      name,
		"namespace": "global",
		"spec":      spec,
	})
	if err != nil {
		t.Fatalf("marshal integration_instance request: %v", err)
	}
	return raw
}

func TestHandleManifestCreateGeneric_IntegrationInstanceRejectsInlineCredentialsForSecretRefPolicy(t *testing.T) {
	srv, mock := newGenericInstancePolicyTestServer(t)
	typeName := "secret-ref-provider"
	expectResolvedIntegrationType(t, mock, typeName, map[string]any{
		"credential_policy": map[string]any{"source": "secret_ref"},
		"credential_schema": map[string]any{"mode": "secret_ref"},
		"instance_schema":   map[string]any{"mode": "none"},
	})

	body := genericIntegrationInstanceBody(t, "policy-bypass-attempt", typeName, map[string]any{
		"credentials": map[string]any{"credential_present": true},
	})
	req := httptest.NewRequest(
		http.MethodPost,
		"/api/v1/manifests?kind=Integration_Instance",
		bytes.NewReader(body),
	)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	srv.handleManifestCreateGeneric(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d (body=%s)", w.Code, http.StatusBadRequest, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "must store credentials through credentials_ref") {
		t.Fatalf("expected credential policy refusal, body=%s", w.Body.String())
	}
	if strings.Contains(w.Body.String(), "credential_present") {
		t.Fatalf("response exposed an input credential field: %s", w.Body.String())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet sqlmock expectations: %v", err)
	}
}

func TestHandleManifestCreateGeneric_IntegrationInstanceAllowsNoCredentialsForNonePolicy(t *testing.T) {
	srv, mock := newGenericInstancePolicyTestServer(t)
	typeName := "credentialless-provider"
	expectResolvedIntegrationType(t, mock, typeName, map[string]any{
		"credential_policy": map[string]any{"source": "none"},
		"credential_schema": map[string]any{"mode": "none"},
		"instance_schema": map[string]any{
			"mode":     "inline",
			"required": []string{"region"},
			"properties": map[string]any{
				"region": map[string]any{"type": "string"},
			},
		},
	})

	instanceName := "credentialless-instance"
	mock.ExpectBegin()
	mock.ExpectQuery(`SELECT COALESCE\(MAX\(version\), 0\) \+ 1 FROM public\.manifests`).
		WithArgs("integration_instance", "global", instanceName).
		WillReturnRows(sqlmock.NewRows([]string{"version"}).AddRow(1))
	mock.ExpectExec(`UPDATE public\.manifests SET active = FALSE WHERE kind`).
		WithArgs("integration_instance", "global", instanceName).
		WillReturnResult(sqlmock.NewResult(0, 0))

	manifestID := uuid.New()
	now := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	mock.ExpectQuery(`INSERT INTO public\.manifests`).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "api_version", "kind", "namespace", "name", "version",
			"active", "description", "labels", "spec", "checksum",
			"created_at", "updated_at",
		}).AddRow(
			manifestID, "yggdrasil.io/v1alpha1", "integration_instance", "global", instanceName, 1,
			true, "", []byte(`{}`), []byte(`{}`), "sha256:instance",
			now, now,
		))
	mock.ExpectCommit()

	body := genericIntegrationInstanceBody(t, instanceName, typeName, map[string]any{
		"config": map[string]any{"region": "sa-east-1"},
	})
	req := httptest.NewRequest(
		http.MethodPost,
		"/api/v1/manifests?kind=integration_instance",
		bytes.NewReader(body),
	)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	srv.handleManifestCreateGeneric(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, want %d (body=%s)", w.Code, http.StatusCreated, w.Body.String())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet sqlmock expectations: %v", err)
	}
}

func TestHandleManifestCreateGeneric_IntegrationInstanceRejectsConfigOutsideTypeSchema(t *testing.T) {
	srv, mock := newGenericInstancePolicyTestServer(t)
	typeName := "schema-bound-provider"
	expectResolvedIntegrationType(t, mock, typeName, map[string]any{
		"credential_policy": map[string]any{"source": "none"},
		"credential_schema": map[string]any{"mode": "none"},
		"instance_schema": map[string]any{
			"mode":     "inline",
			"required": []string{"region"},
			"properties": map[string]any{
				"region": map[string]any{"type": "string"},
			},
		},
	})

	body := genericIntegrationInstanceBody(t, "invalid-config-instance", typeName, map[string]any{
		"config": map[string]any{"region": true},
	})
	req := httptest.NewRequest(
		http.MethodPost,
		"/api/v1/manifests?kind=integration_instance",
		bytes.NewReader(body),
	)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	srv.handleManifestCreateGeneric(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d (body=%s)", w.Code, http.StatusBadRequest, w.Body.String())
	}
	var problem struct {
		Detail string `json:"detail"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &problem); err != nil {
		t.Fatalf("decode problem response: %v", err)
	}
	if problem.Detail != `integration config "region" must be a string` {
		t.Fatalf("unexpected referenced type schema refusal: %q", problem.Detail)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet sqlmock expectations: %v", err)
	}
}
