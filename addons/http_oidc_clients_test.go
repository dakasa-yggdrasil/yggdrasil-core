package addons

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"go.uber.org/zap"
)

func TestEnsureConfiguredOIDCClientsFailsStartupWhenMountedFileIsMissing(t *testing.T) {
	t.Setenv("YGGDRASIL_OIDC_CLIENTS_FILE", filepath.Join(t.TempDir(), "missing.json"))
	t.Setenv("YGGDRASIL_OIDC_PUBLIC_CLIENTS_JSON", "")
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	err = ensureConfiguredOIDCClients(context.Background(), db, zap.NewNop())
	if err == nil || !strings.Contains(err.Error(), "oidc confidential client bootstrap") {
		t.Fatalf("expected startup failure for missing client file, got %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestEnsureConfiguredOIDCClientsFailsStartupBeforeDBForUnsafeOrUnknownFile(t *testing.T) {
	t.Setenv("YGGDRASIL_OIDC_PUBLIC_CLIENTS_JSON", "")
	tests := []struct {
		name    string
		payload string
		mode    os.FileMode
		want    string
	}{
		{
			name:    "writable file",
			payload: `{"version":1,"clients":[]}`,
			mode:    0o600,
			want:    "read-only",
		},
		{
			name:    "unknown plaintext field",
			payload: `{"version":1,"clients":[{"client_id":"tartaro","client_secret":"do-not-leak-this-value"}]}`,
			mode:    0o400,
			want:    "unknown field",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "clients.json")
			if err := os.WriteFile(path, []byte(tc.payload), tc.mode); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(path, tc.mode); err != nil {
				t.Fatal(err)
			}
			t.Setenv("YGGDRASIL_OIDC_CLIENTS_FILE", path)
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()

			err = ensureConfiguredOIDCClients(context.Background(), db, zap.NewNop())
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("expected startup error containing %q, got %v", tc.want, err)
			}
			if strings.Contains(err.Error(), "do-not-leak-this-value") {
				t.Fatal("startup error exposed confidential file contents")
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestEnsureConfiguredOIDCClientsKeepsUnconfiguredDeploymentsUnchanged(t *testing.T) {
	t.Setenv("YGGDRASIL_OIDC_CLIENTS_FILE", "")
	t.Setenv("YGGDRASIL_OIDC_PUBLIC_CLIENTS_JSON", "")
	if err := ensureConfiguredOIDCClients(context.Background(), nil, zap.NewNop()); err != nil {
		t.Fatalf("unconfigured deployment behavior changed: %v", err)
	}
}

func TestBootstrapHTTPRejectsConfidentialClientFileWithoutIssuerBeforeDatabase(t *testing.T) {
	t.Setenv("YGGDRASIL_OIDC_ISSUER", "")
	t.Setenv("YGGDRASIL_OIDC_CLIENTS_FILE", filepath.Join(t.TempDir(), "clients.json"))
	err := bootstrapHTTP(context.Background(), nil)
	if err == nil || !strings.Contains(err.Error(), "requires YGGDRASIL_OIDC_ISSUER") {
		t.Fatalf("expected configured client file without issuer to fail startup, got %v", err)
	}
}
