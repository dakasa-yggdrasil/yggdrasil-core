package bootstrap

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"testing"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	_ "github.com/lib/pq"
)

// dbForBootstrapTest mirrors the DB_URL-gated pattern used by other
// integration tests in the repo: skip the test gracefully when the
// envvar is not set so `go test ./...` stays green in environments
// without Postgres, but exercise the real repository code when the
// envvar points at a migrated database.
func dbForBootstrapTest(t *testing.T) *sql.DB {
	t.Helper()
	dsn := os.Getenv("DB_URL")
	if dsn == "" {
		t.Skip("DB_URL not set; skipping bootstrap integration test")
	}
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	if err := db.Ping(); err != nil {
		t.Fatalf("ping db: %v", err)
	}
	return db
}

// cleanDatabase truncates the tables that bootstrap touches so each
// test starts from a known-empty state.
func cleanDatabase(t *testing.T, db *sql.DB) {
	t.Helper()
	_, err := db.Exec(`TRUNCATE TABLE public.password_credential, public.auth_session, public.collaborator RESTART IDENTITY CASCADE`)
	if err != nil {
		t.Fatalf("truncate identity tables: %v", err)
	}
	_, err = db.Exec(`TRUNCATE TABLE public.manifest_version, public.manifest RESTART IDENTITY CASCADE`)
	if err != nil {
		t.Fatalf("truncate manifest tables: %v", err)
	}
}

func TestRun_ProvisionAdminOnFreshDatabase(t *testing.T) {
	db := dbForBootstrapTest(t)
	defer db.Close()
	cleanDatabase(t, db)

	res, err := Run(context.Background(), db, Config{
		AdminUsername: "admin",
		AdminPassword: "admin-password-12345",
		AdminEmail:    "admin@example.com",
	})
	if err != nil {
		t.Fatalf("Run error: %v", err)
	}
	if !res.AdminCreated {
		t.Fatal("AdminCreated = false, want true on a fresh database")
	}
	if res.AdminCollaborator == nil {
		t.Fatal("AdminCollaborator is nil on a created admin")
	}
	if res.AdminCollaborator.Slug != "admin" {
		t.Errorf("admin slug = %q", res.AdminCollaborator.Slug)
	}

	// Password credential must exist and be usable via the normal
	// authentication path — this is the contract the init CLI counts on.
	_, _, _, err = repository.AuthenticateWithPassword(
		context.Background(),
		db,
		model.LoginWithPasswordRequest{
			Identifier: "admin",
			Password:   "admin-password-12345",
		},
		3600,
	)
	if err != nil {
		t.Fatalf("cannot log in with created admin: %v", err)
	}
}

func TestRun_IsIdempotentWhenAdminAlreadyExists(t *testing.T) {
	db := dbForBootstrapTest(t)
	defer db.Close()
	cleanDatabase(t, db)

	// First run creates.
	if _, err := Run(context.Background(), db, Config{
		AdminUsername: "admin",
		AdminPassword: "first-password",
	}); err != nil {
		t.Fatalf("first Run: %v", err)
	}

	// Second run must be a no-op, even with a different password.
	res, err := Run(context.Background(), db, Config{
		AdminUsername: "admin",
		AdminPassword: "different-password",
	})
	if err != nil {
		t.Fatalf("second Run: %v", err)
	}
	if res.AdminCreated {
		t.Fatal("AdminCreated = true on second Run (must be idempotent)")
	}

	// The original password must still work; the second Run MUST NOT
	// have reset it. This is the security contract — a restart does not
	// rotate credentials out from under the operator.
	_, _, _, err = repository.AuthenticateWithPassword(
		context.Background(),
		db,
		model.LoginWithPasswordRequest{Identifier: "admin", Password: "first-password"},
		3600,
	)
	if err != nil {
		t.Fatalf("original password no longer works after second Run: %v", err)
	}
}

func TestRun_ReturnsErrNoAdminPasswordWhenUsernameButNoPassword(t *testing.T) {
	db := dbForBootstrapTest(t)
	defer db.Close()
	cleanDatabase(t, db)

	_, err := Run(context.Background(), db, Config{
		AdminUsername: "admin",
		AdminPassword: "",
	})
	if err == nil {
		t.Fatal("expected ErrNoAdminPassword, got nil")
	}
}

func TestRun_SeedsManifestsIdempotently(t *testing.T) {
	db := dbForBootstrapTest(t)
	defer db.Close()
	cleanDatabase(t, db)

	dir := t.TempDir()
	seedPath := filepath.Join(dir, "integration-family.json")
	seed := `{
		"apiVersion": "yggdrasil.io/v1alpha1",
		"kind": "integration_family",
		"metadata": {"name": "bootstrap-smoke", "namespace": "global"},
		"spec": {
			"display_name": "Bootstrap smoke",
			"description": "Fixture for bootstrap_test.go",
			"capabilities": ["describe", "execute"],
			"operations": [{"name": "noop"}]
		}
	}`
	if err := os.WriteFile(seedPath, []byte(seed), 0o644); err != nil {
		t.Fatalf("write seed: %v", err)
	}

	// First run imports the manifest.
	res, err := Run(context.Background(), db, Config{ManifestsPath: dir})
	if err != nil {
		t.Fatalf("first Run: %v", err)
	}
	if res.ManifestsCreated != 1 {
		t.Fatalf("first ManifestsCreated = %d, want 1", res.ManifestsCreated)
	}
	if res.ManifestsSkipped != 0 {
		t.Fatalf("first ManifestsSkipped = %d, want 0", res.ManifestsSkipped)
	}

	// Second run skips by checksum.
	res, err = Run(context.Background(), db, Config{ManifestsPath: dir})
	if err != nil {
		t.Fatalf("second Run: %v", err)
	}
	if res.ManifestsCreated != 0 {
		t.Fatalf("second ManifestsCreated = %d, want 0", res.ManifestsCreated)
	}
	if res.ManifestsSkipped != 1 {
		t.Fatalf("second ManifestsSkipped = %d, want 1", res.ManifestsSkipped)
	}
}

func TestIsEmpty_DistinguishesFreshFromSeeded(t *testing.T) {
	db := dbForBootstrapTest(t)
	defer db.Close()
	cleanDatabase(t, db)

	empty, err := IsEmpty(context.Background(), db)
	if err != nil {
		t.Fatalf("IsEmpty: %v", err)
	}
	if !empty {
		t.Fatal("IsEmpty = false on a freshly truncated database")
	}

	if _, err := repository.CreateCollaborator(context.Background(), db, model.CreateCollaboratorRequest{
		Slug:        "pre-existing",
		DisplayName: "Pre-existing",
	}); err != nil {
		t.Fatalf("seed collaborator: %v", err)
	}

	empty, err = IsEmpty(context.Background(), db)
	if err != nil {
		t.Fatalf("IsEmpty after seed: %v", err)
	}
	if empty {
		t.Fatal("IsEmpty = true after seeding a collaborator")
	}
}

// TestImportManifestsFromDir_EmptyDirIsNotAnError guards the contract
// that a deployment running without seeds is valid. Self-hosted
// deployments may opt out of the default catalog and populate their
// own via the HTTP API.
func TestImportManifestsFromDir_EmptyDirIsNotAnError(t *testing.T) {
	db := dbForBootstrapTest(t)
	defer db.Close()
	cleanDatabase(t, db)

	dir := t.TempDir()
	summary, err := importManifestsFromDir(context.Background(), db, dir)
	if err != nil {
		t.Fatalf("importManifestsFromDir(empty) error: %v", err)
	}
	if summary.Validated != 0 || summary.Created != 0 || summary.Skipped != 0 {
		t.Errorf("empty dir summary = %+v, want zeroes", summary)
	}
}

// TestImportManifestsFromDir_MissingDirIsError guards against silent
// misconfiguration — a typo in YGGDRASIL_BOOTSTRAP_MANIFESTS_PATH should
// be loud, not swallowed.
func TestImportManifestsFromDir_MissingDirIsError(t *testing.T) {
	db := dbForBootstrapTest(t)
	defer db.Close()

	_, err := importManifestsFromDir(context.Background(), db, filepath.Join(t.TempDir(), "does-not-exist"))
	if err == nil {
		t.Fatal("expected error for missing directory, got nil")
	}
}
