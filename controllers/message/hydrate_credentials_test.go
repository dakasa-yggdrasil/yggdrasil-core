package message

import (
	"context"
	"regexp"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

// secretMockRows returns a sqlmock row set that matches the managed_secrets
// SELECT query used by repository.ResolveSecretObjectRef / ResolveSecretRef.
func secretMockRows(namespace, name, dataJSON string) *sqlmock.Rows {
	now := time.Now().UTC()
	return sqlmock.NewRows([]string{
		"id", "namespace", "name", "status", "version",
		"data", "metadata", "rotation",
		"last_rotated_at", "expires_at", "created_at", "updated_at",
	}).AddRow(
		uuid.New(), namespace, name, "active", 1,
		[]byte(dataJSON), []byte(`{}`), []byte(`{"mode":"manual"}`),
		now, nil, now, now,
	)
}

var managedSecretSelectQuery = regexp.QuoteMeta(`
			SELECT
				id,
				namespace,
				name,
				status,
				version,
				data,
				metadata,
				rotation,
				last_rotated_at,
				expires_at,
				created_at,
				updated_at
			FROM public.managed_secrets
			WHERE namespace = $1
				AND name = $2
		`)

// TestHydrateIntegrationInstanceSecrets_CredentialsRef proves that
// hydrateIntegrationInstanceSecrets resolves a credentials_ref URI
// (secret://<ns>/<name>) into the spec's Credentials map so that the adapter
// receives real token values rather than an empty map or a bare URI string.
func TestHydrateIntegrationInstanceSecrets_CredentialsRef(t *testing.T) {
	t.Parallel()

	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New error: %v", err)
	}
	defer db.Close()

	// The managed secret holds {"token": "ghp_testtoken"}.
	mock.ExpectQuery(managedSecretSelectQuery).
		WithArgs("github", "platform").
		WillReturnRows(secretMockRows("github", "platform", `{"token":"ghp_testtoken"}`))

	spec := model.IntegrationInstanceManifestSpec{
		CredentialsRef: "secret://github/platform",
	}

	if err := hydrateIntegrationInstanceSecrets(context.Background(), db, &spec); err != nil {
		t.Fatalf("hydrateIntegrationInstanceSecrets error: %v", err)
	}

	if spec.Credentials["token"] != "ghp_testtoken" {
		t.Fatalf("expected Credentials[token]=ghp_testtoken after hydration, got %#v", spec.Credentials)
	}
	// CredentialsRef must NOT be cleared — it is the source-of-truth URI.
	if spec.CredentialsRef != "secret://github/platform" {
		t.Fatalf("expected CredentialsRef to be preserved, got %q", spec.CredentialsRef)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet sql expectations: %v", err)
	}
}

// TestHydrateIntegrationInstanceSecrets_NoCredentialsRef proves that the
// hydration is a no-op when neither credentials_ref nor inline secret://
// refs exist — no DB queries are issued and Credentials is untouched.
func TestHydrateIntegrationInstanceSecrets_NoCredentialsRef(t *testing.T) {
	t.Parallel()

	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New error: %v", err)
	}
	defer db.Close()

	spec := model.IntegrationInstanceManifestSpec{
		Credentials: map[string]any{"static_key": "value"},
	}

	if err := hydrateIntegrationInstanceSecrets(context.Background(), db, &spec); err != nil {
		t.Fatalf("hydrateIntegrationInstanceSecrets (no-op) error: %v", err)
	}

	if spec.Credentials["static_key"] != "value" {
		t.Fatalf("expected static Credentials to be preserved, got %#v", spec.Credentials)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet sql expectations: %v", err)
	}
}

// TestHydrateIntegrationInstanceSecrets_NestedSecretRefs proves that
// secret:// refs nested inside the Credentials map are also resolved.
func TestHydrateIntegrationInstanceSecrets_NestedSecretRefs(t *testing.T) {
	t.Parallel()

	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New error: %v", err)
	}
	defer db.Close()

	mock.ExpectQuery(managedSecretSelectQuery).
		WithArgs("global", "github-token").
		WillReturnRows(secretMockRows("global", "github-token", `{"value":"ghp_nested"}`))

	spec := model.IntegrationInstanceManifestSpec{
		Credentials: map[string]any{
			"token": "secret://global/github-token",
		},
	}

	if err := hydrateIntegrationInstanceSecrets(context.Background(), db, &spec); err != nil {
		t.Fatalf("hydrateIntegrationInstanceSecrets (nested) error: %v", err)
	}

	if spec.Credentials["token"] != "ghp_nested" {
		t.Fatalf("expected nested secret resolved to ghp_nested, got %#v", spec.Credentials["token"])
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet sql expectations: %v", err)
	}
}

// TestHydrateIntegrationInstanceSecrets_Config proves that secret:// refs
// inside the Config map are resolved the same way as Credentials.
func TestHydrateIntegrationInstanceSecrets_Config(t *testing.T) {
	t.Parallel()

	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New error: %v", err)
	}
	defer db.Close()

	mock.ExpectQuery(managedSecretSelectQuery).
		WithArgs("ops", "registry-token").
		WillReturnRows(secretMockRows("ops", "registry-token", `{"value":"reg_token_xyz"}`))

	spec := model.IntegrationInstanceManifestSpec{
		Config: map[string]any{
			"registry_token": "secret://ops/registry-token",
		},
	}

	if err := hydrateIntegrationInstanceSecrets(context.Background(), db, &spec); err != nil {
		t.Fatalf("hydrateIntegrationInstanceSecrets (config) error: %v", err)
	}

	if spec.Config["registry_token"] != "reg_token_xyz" {
		t.Fatalf("expected Config[registry_token]=reg_token_xyz, got %#v", spec.Config["registry_token"])
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet sql expectations: %v", err)
	}
}
