package httpapi

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/metrics"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

// Phase 5B permission split tests — audit 2026-05-27 §3.1 follow-up.
//
// Secret read/rotate/disable/revoke/materialize used to be gated by
// yggdrasil:manage_integrations alongside integration provisioning.
// Phase 5B splits the secret surface onto a dedicated
// yggdrasil:manage_secrets permission because the blast radius differs:
// an integration admin can register a stripe instance with a
// credentials_ref URI WITHOUT inheriting the right to read or rotate
// the underlying cluster secret. The two tests below lock that split.

// TestSecretsUsePermManageSecrets is the negative case for the split.
// A caller with manage_integrations ALONE (without manage_secrets)
// MUST be denied at the secret gate in enforce mode. If this test
// passes the call through, the split has regressed and integration
// admins have inherited secret custody.
func TestSecretsUsePermManageSecrets(t *testing.T) {
	t.Setenv("YGGDRASIL_CONSOLE_RBAC_ENFORCE", "enforce")

	metrics.ResetForTest()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer func() { _ = db.Close() }()
	srv := &Server{db: db, logger: zap.NewNop()}

	collabID := uuid.New()
	// Integration admin: has manage_integrations but NOT manage_secrets.
	programCollaboratorWithPermissions(mock, collabID, []string{"yggdrasil:manage_integrations"})

	called := false
	wrapped := srv.requireOpsPermissionFunc(permManageSecrets, func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	r := rbacTestRequestWithClaims(http.MethodGet, "/api/v1/console/secrets", collabID)
	w := httptest.NewRecorder()
	wrapped(w, r)

	if called {
		t.Fatalf("integration admin without manage_secrets must NOT reach secret handler — split regressed")
	}
	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d (body=%s)", w.Code, w.Body.String())
	}
}

// TestManageSecretsHolderPassesSecretGate is the positive case for the
// split: a user with the dedicated manage_secrets perm reaches the
// secret handler.
func TestManageSecretsHolderPassesSecretGate(t *testing.T) {
	t.Setenv("YGGDRASIL_CONSOLE_RBAC_ENFORCE", "enforce")

	metrics.ResetForTest()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer func() { _ = db.Close() }()
	srv := &Server{db: db, logger: zap.NewNop()}

	collabID := uuid.New()
	programCollaboratorWithPermissions(mock, collabID, []string{"yggdrasil:manage_secrets"})

	called := false
	wrapped := srv.requireOpsPermissionFunc(permManageSecrets, func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	r := rbacTestRequestWithClaims(http.MethodGet, "/api/v1/console/secrets", collabID)
	w := httptest.NewRecorder()
	wrapped(w, r)

	if !called {
		t.Fatalf("manage_secrets holder must pass the secret gate; status=%d", w.Code)
	}
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}
