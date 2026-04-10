package httpapi

import (
	"context"
	"net/http/httptest"
	"regexp"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

func TestMaterializeThirdPartyAuthProviderClientSecretUsesDefaultManagedSecret(t *testing.T) {
	t.Parallel()

	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New error: %v", err)
	}
	defer db.Close()

	now := time.Now().UTC()
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
		WithArgs(
			"global",
			"auth-provider/github-platform/client-secret",
			"active",
			[]byte(`{"value":"top-secret"}`),
			[]byte(`{"auth_provider":{"name":"github-platform"},"source_kind":"auth_provider"}`),
			[]byte(`{"mode":"manual"}`),
			nil,
		).
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
			"global",
			"auth-provider/github-platform/client-secret",
			"active",
			1,
			[]byte(`{"value":"top-secret"}`),
			[]byte(`{"auth_provider":{"name":"github-platform"},"source_kind":"auth_provider"}`),
			[]byte(`{"mode":"manual"}`),
			now,
			nil,
			now,
			now,
		))

	server := &Server{db: db}
	req := &model.UpsertThirdPartyAuthProviderRequest{
		Name:         "github-platform",
		ClientSecret: "top-secret",
	}

	if err := server.materializeThirdPartyAuthProviderClientSecret(context.Background(), req); err != nil {
		t.Fatalf("materializeThirdPartyAuthProviderClientSecret error: %v", err)
	}

	if req.ClientSecret != "" {
		t.Fatalf("expected raw client secret to be cleared, got %q", req.ClientSecret)
	}

	expectedRef := "secret://global/auth-provider/github-platform/client-secret#value"
	if req.ClientSecretRef != expectedRef {
		t.Fatalf("expected client secret ref %q, got %q", expectedRef, req.ClientSecretRef)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet sql expectations: %v", err)
	}
}

func TestMaterializeThirdPartyAuthProviderClientSecretHonorsExplicitSecretRef(t *testing.T) {
	t.Parallel()

	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New error: %v", err)
	}
	defer db.Close()

	now := time.Now().UTC()
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
		WithArgs(
			"identity",
			"providers/workforce/client-secret",
			"active",
			[]byte(`{"oauth":"top-secret"}`),
			[]byte(`{"auth_provider":{"name":"workforce-oidc"},"source_kind":"auth_provider"}`),
			[]byte(`{"mode":"manual"}`),
			nil,
		).
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
			"identity",
			"providers/workforce/client-secret",
			"active",
			3,
			[]byte(`{"oauth":"top-secret"}`),
			[]byte(`{"auth_provider":{"name":"workforce-oidc"},"source_kind":"auth_provider"}`),
			[]byte(`{"mode":"manual"}`),
			now,
			nil,
			now,
			now,
		))

	server := &Server{db: db}
	req := &model.UpsertThirdPartyAuthProviderRequest{
		Name:            "workforce-oidc",
		ClientSecret:    "top-secret",
		ClientSecretRef: "secret://identity/providers/workforce/client-secret#oauth",
	}

	if err := server.materializeThirdPartyAuthProviderClientSecret(context.Background(), req); err != nil {
		t.Fatalf("materializeThirdPartyAuthProviderClientSecret error: %v", err)
	}

	expectedRef := "secret://identity/providers/workforce/client-secret#oauth"
	if req.ClientSecretRef != expectedRef {
		t.Fatalf("expected client secret ref %q, got %q", expectedRef, req.ClientSecretRef)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet sql expectations: %v", err)
	}
}

func TestMaterializeIntegrationInstanceSecretConfigUsesHashValueRef(t *testing.T) {
	t.Parallel()

	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New error: %v", err)
	}
	defer db.Close()

	now := time.Now().UTC()
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
		WithArgs(
			"global",
			"heimdall-guardian-config-llm-gpt-api-key",
			"active",
			[]byte(`{"value":"top-secret"}`),
			[]byte(`{"field":"llm_gpt_api_key","integration_instance":{"name":"heimdall-guardian","namespace":"global"},"source_kind":"integration_instance_config"}`),
			[]byte(`{"mode":"manual"}`),
			nil,
		).
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
			"global",
			"heimdall-guardian-config-llm-gpt-api-key",
			"active",
			1,
			[]byte(`{"value":"top-secret"}`),
			[]byte(`{"field":"llm_gpt_api_key","integration_instance":{"name":"heimdall-guardian","namespace":"global"},"source_kind":"integration_instance_config"}`),
			[]byte(`{"mode":"manual"}`),
			now,
			nil,
			now,
			now,
		))

	server := &Server{db: db}
	payload := &consoleCreateIntegrationInstanceRequest{
		Name:      "heimdall-guardian",
		Namespace: "global",
		Config: map[string]any{
			"llm_gpt_api_key": "top-secret",
		},
	}
	typeSpec := model.IntegrationTypeManifestSpec{
		InstanceSchema: model.IntegrationSchemaSpec{
			Properties: map[string]model.IntegrationSchemaProperty{
				"llm_gpt_api_key": {
					Type:   "string",
					Secret: true,
				},
			},
		},
	}

	if err := server.materializeIntegrationInstanceSecretConfig(context.Background(), payload, typeSpec); err != nil {
		t.Fatalf("materializeIntegrationInstanceSecretConfig error: %v", err)
	}

	expectedRef := "secret://global/heimdall-guardian-config-llm-gpt-api-key#value"
	if got := payload.Config["llm_gpt_api_key"]; got != expectedRef {
		t.Fatalf("config ref = %#v, want %q", got, expectedRef)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet sql expectations: %v", err)
	}
}

func TestAuthSurfaceBaseURLPrefersExplicitSurfaceHeader(t *testing.T) {
	t.Parallel()

	request := httptest.NewRequest("GET", "http://yggdrasil-core:9080/api/v1/auth/third-party/start/github", nil)
	request.Host = "yggdrasil-core:9080"
	request.Header.Set("X-Yggdrasil-Surface-Base-URL", "http://127.0.0.1:19090/")
	request.Header.Set("X-Forwarded-Host", "127.0.0.1:19090")

	got := authSurfaceBaseURL(request)
	want := "http://127.0.0.1:19090"
	if got != want {
		t.Fatalf("expected auth surface base URL %q, got %q", want, got)
	}
}

func TestAuthSurfaceBaseURLUsesForwardedHostWhenSurfaceHeaderIsMissing(t *testing.T) {
	t.Parallel()

	request := httptest.NewRequest("GET", "http://yggdrasil-core:9080/api/v1/auth/third-party/start/github", nil)
	request.Host = "yggdrasil-core:9080"
	request.Header.Set("X-Forwarded-Proto", "http")
	request.Header.Set("X-Forwarded-Host", "127.0.0.1:19090")

	got := authSurfaceBaseURL(request)
	want := "http://127.0.0.1:19090"
	if got != want {
		t.Fatalf("expected auth surface base URL %q, got %q", want, got)
	}
}
