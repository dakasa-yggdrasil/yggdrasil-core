package repository

import (
	"context"
	"regexp"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

func TestResolveSecretRefReturnsSingleValue(t *testing.T) {
	t.Parallel()

	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New error: %v", err)
	}
	defer db.Close()

	now := time.Now().UTC()
	rows := sqlmock.NewRows([]string{
		"id",
		"namespace",
		"name",
		"status",
		"version",
		"data",
		"metadata",
		"rotation",
		"last_rotated_at",
		"expires_at",
		"created_at",
		"updated_at",
	}).AddRow(
		uuid.New(),
		"github",
		"private-key",
		"active",
		1,
		[]byte(`{"value":"pem-data"}`),
		[]byte(`{}`),
		[]byte(`{"mode":"manual"}`),
		now,
		nil,
		now,
		now,
	)

	mock.ExpectQuery(regexp.QuoteMeta(`
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
		`)).
		WithArgs("github", "private-key").
		WillReturnRows(rows)

	value, err := ResolveSecretRef(context.Background(), db, "secret://github/private-key")
	if err != nil {
		t.Fatalf("ResolveSecretRef error: %v", err)
	}

	if value != "pem-data" {
		t.Fatalf("expected single secret value, got %#v", value)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet sql expectations: %v", err)
	}
}

func TestResolveSecretObjectRefReturnsObjectForSingleKeySecret(t *testing.T) {
	t.Parallel()

	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New error: %v", err)
	}
	defer db.Close()

	now := time.Now().UTC()
	rows := sqlmock.NewRows([]string{
		"id",
		"namespace",
		"name",
		"status",
		"version",
		"data",
		"metadata",
		"rotation",
		"last_rotated_at",
		"expires_at",
		"created_at",
		"updated_at",
	}).AddRow(
		uuid.New(),
		"github",
		"caller",
		"active",
		1,
		[]byte(`{"token":"ghp_123"}`),
		[]byte(`{}`),
		[]byte(`{"mode":"manual"}`),
		now,
		nil,
		now,
		now,
	)

	mock.ExpectQuery(regexp.QuoteMeta(`
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
		`)).
		WithArgs("github", "caller").
		WillReturnRows(rows)

	value, err := ResolveSecretObjectRef(context.Background(), db, "secret://github/caller")
	if err != nil {
		t.Fatalf("ResolveSecretObjectRef error: %v", err)
	}

	if value["token"] != "ghp_123" {
		t.Fatalf("expected token object, got %#v", value)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet sql expectations: %v", err)
	}
}

func TestResolveSecretRefsResolvesNestedReferences(t *testing.T) {
	t.Parallel()

	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New error: %v", err)
	}
	defer db.Close()

	now := time.Now().UTC()
	query := regexp.QuoteMeta(`
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

	mock.ExpectQuery(query).
		WithArgs("github", "platform").
		WillReturnRows(sqlmock.NewRows([]string{
			"id",
			"namespace",
			"name",
			"status",
			"version",
			"data",
			"metadata",
			"rotation",
			"last_rotated_at",
			"expires_at",
			"created_at",
			"updated_at",
		}).AddRow(
			uuid.New(),
			"github",
			"platform",
			"active",
			2,
			[]byte(`{"token":"ghp_123","app_id":"42"}`),
			[]byte(`{}`),
			[]byte(`{"mode":"scheduled","rotate_after_days":30}`),
			now,
			nil,
			now,
			now,
		))

	mock.ExpectQuery(query).
		WithArgs("github", "private-key").
		WillReturnRows(sqlmock.NewRows([]string{
			"id",
			"namespace",
			"name",
			"status",
			"version",
			"data",
			"metadata",
			"rotation",
			"last_rotated_at",
			"expires_at",
			"created_at",
			"updated_at",
		}).AddRow(
			uuid.New(),
			"github",
			"private-key",
			"active",
			1,
			[]byte(`{"value":"pem-data"}`),
			[]byte(`{}`),
			[]byte(`{"mode":"manual"}`),
			now,
			nil,
			now,
			now,
		))

	resolved, err := ResolveSecretRefs(context.Background(), db, map[string]any{
		"credentials": "secret://github/platform",
		"nested": map[string]any{
			"private_key": "secret://github/private-key",
		},
	})
	if err != nil {
		t.Fatalf("ResolveSecretRefs error: %v", err)
	}

	payload, ok := resolved.(map[string]any)
	if !ok {
		t.Fatalf("expected map result, got %#v", resolved)
	}

	credentials, ok := payload["credentials"].(map[string]any)
	if !ok {
		t.Fatalf("expected credentials object, got %#v", payload["credentials"])
	}
	if credentials["token"] != "ghp_123" || credentials["app_id"] != "42" {
		t.Fatalf("unexpected resolved credentials %#v", credentials)
	}

	nested, ok := payload["nested"].(map[string]any)
	if !ok {
		t.Fatalf("expected nested map, got %#v", payload["nested"])
	}
	if nested["private_key"] != "pem-data" {
		t.Fatalf("unexpected nested private key %#v", nested["private_key"])
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet sql expectations: %v", err)
	}
}

func TestRotateManagedSecret(t *testing.T) {
	t.Parallel()

	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New error: %v", err)
	}
	defer db.Close()

	now := time.Now().UTC()
	expiresAt := now.Add(7 * 24 * time.Hour)
	selectQuery := regexp.QuoteMeta(`
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
	currentID := uuid.New()
	mock.ExpectQuery(selectQuery).
		WithArgs("global", "github-app").
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "namespace", "name", "status", "version", "data", "metadata", "rotation", "last_rotated_at", "expires_at", "created_at", "updated_at",
		}).AddRow(
			currentID,
			"global",
			"github-app",
			"active",
			1,
			[]byte(`{"token":"old-token"}`),
			[]byte(`{"owner":"platform"}`),
			[]byte(`{"mode":"manual"}`),
			now.Add(-24*time.Hour),
			expiresAt,
			now.Add(-24*time.Hour),
			now.Add(-24*time.Hour),
		))

	mock.ExpectQuery(regexp.QuoteMeta(`
			INSERT INTO public.managed_secrets (
				namespace,
				name,
				status,
				data,
				metadata,
				rotation,
				expires_at
			) VALUES (
				$1,
				$2,
				$3,
				$4::jsonb,
				$5::jsonb,
				$6::jsonb,
				$7
			)
			ON CONFLICT (namespace, name)
			DO UPDATE SET
				status = EXCLUDED.status,
				data = EXCLUDED.data,
				metadata = EXCLUDED.metadata,
				rotation = EXCLUDED.rotation,
				expires_at = EXCLUDED.expires_at,
				version = CASE
					WHEN public.managed_secrets.data IS DISTINCT FROM EXCLUDED.data
						THEN public.managed_secrets.version + 1
					ELSE public.managed_secrets.version
				END,
				last_rotated_at = CASE
					WHEN public.managed_secrets.data IS DISTINCT FROM EXCLUDED.data
						THEN NOW()
					ELSE public.managed_secrets.last_rotated_at
				END,
				updated_at = NOW()
			RETURNING
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
		`)).
		WithArgs("global", "github-app", "active", []byte(`{"token":"new-token"}`), []byte(`{"owner":"platform"}`), []byte(`{"mode":"manual"}`), expiresAt).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "namespace", "name", "status", "version", "data", "metadata", "rotation", "last_rotated_at", "expires_at", "created_at", "updated_at",
		}).AddRow(
			currentID,
			"global",
			"github-app",
			"active",
			2,
			[]byte(`{"token":"new-token"}`),
			[]byte(`{"owner":"platform"}`),
			[]byte(`{"mode":"manual"}`),
			now,
			expiresAt,
			now.Add(-24*time.Hour),
			now,
		))

	secret, err := RotateManagedSecret(context.Background(), db, model.RotateManagedSecretRequest{
		Namespace: "global",
		Name:      "github-app",
		Data:      map[string]string{"token": "new-token"},
	})
	if err != nil {
		t.Fatalf("RotateManagedSecret error: %v", err)
	}
	if secret.Version != 2 {
		t.Fatalf("expected rotated secret version 2, got %d", secret.Version)
	}
	if secret.ExpiresAt == nil || !secret.ExpiresAt.Equal(expiresAt) {
		t.Fatalf("expected rotated secret to preserve expires_at, got %#v", secret.ExpiresAt)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet sql expectations: %v", err)
	}
}

func TestRevokeManagedSecret(t *testing.T) {
	t.Parallel()

	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New error: %v", err)
	}
	defer db.Close()

	now := time.Now().UTC()
	selectQuery := regexp.QuoteMeta(`
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
	currentID := uuid.New()
	mock.ExpectQuery(selectQuery).
		WithArgs("global", "github-app").
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "namespace", "name", "status", "version", "data", "metadata", "rotation", "last_rotated_at", "expires_at", "created_at", "updated_at",
		}).AddRow(
			currentID,
			"global",
			"github-app",
			"active",
			2,
			[]byte(`{"token":"current-token"}`),
			[]byte(`{"owner":"platform"}`),
			[]byte(`{"mode":"manual"}`),
			now.Add(-24*time.Hour),
			nil,
			now.Add(-24*time.Hour),
			now.Add(-24*time.Hour),
		))

	mock.ExpectQuery(regexp.QuoteMeta(`
			UPDATE public.managed_secrets
			SET
				status = $3,
				data = $4::jsonb,
				metadata = $5::jsonb,
				version = CASE
					WHEN public.managed_secrets.data IS DISTINCT FROM $4::jsonb
						THEN public.managed_secrets.version + 1
					ELSE public.managed_secrets.version
				END,
				last_rotated_at = CASE
					WHEN public.managed_secrets.data IS DISTINCT FROM $4::jsonb
						THEN NOW()
					ELSE public.managed_secrets.last_rotated_at
				END,
				updated_at = NOW()
			WHERE namespace = $1
				AND name = $2
			RETURNING
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
		`)).
		WithArgs("global", "github-app", "revoked", []byte(`{}`), []byte(`{"owner":"platform"}`)).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "namespace", "name", "status", "version", "data", "metadata", "rotation", "last_rotated_at", "expires_at", "created_at", "updated_at",
		}).AddRow(
			currentID,
			"global",
			"github-app",
			"revoked",
			3,
			[]byte(`{}`),
			[]byte(`{"owner":"platform"}`),
			[]byte(`{"mode":"manual"}`),
			now,
			nil,
			now.Add(-24*time.Hour),
			now,
		))

	secret, err := RevokeManagedSecret(context.Background(), db, model.RevokeManagedSecretRequest{
		Namespace: "global",
		Name:      "github-app",
	})
	if err != nil {
		t.Fatalf("RevokeManagedSecret error: %v", err)
	}
	if secret.Status != "revoked" {
		t.Fatalf("expected revoked status, got %q", secret.Status)
	}
	if len(secret.Data) != 0 {
		t.Fatalf("expected revoked secret data to be cleared, got %#v", secret.Data)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet sql expectations: %v", err)
	}
}
