package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	_ "github.com/lib/pq"
)

// CI runs this against migrated PostgreSQL. An uncommitted revocation holds
// the manifest row lock while the snapshot attempts SELECT FOR SHARE. Once
// revocation commits, the read must return no rows and no collaborator data.
func TestProvisioningSnapshotRevocationAgainstPostgres(t *testing.T) {
	dsn := os.Getenv("DB_URL")
	if dsn == "" {
		if os.Getenv("REQUIRE_PROVISIONING_SNAPSHOT_DB_TEST") == "true" {
			t.Fatal("DB_URL is required for the provisioning snapshot PostgreSQL gate")
		}
		t.Skip("DB_URL not set; PostgreSQL gate runs in CI")
	}
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.SetMaxOpenConns(3)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	active := true
	manifest, err := CreateManifestVersion(ctx, db, model.ManifestDocument{
		APIVersion: "yggdrasil.io/v1alpha1",
		Kind:       "workflow",
		Metadata: model.ManifestMetadataInput{
			Namespace: "dakasa", Name: "reconcile-identity-providers", Active: &active,
		},
		Spec: json.RawMessage(`{"steps":[]}`),
	}, "sha256:provisioning-revocation-ci")
	if err != nil {
		t.Fatal(err)
	}
	defer db.ExecContext(context.Background(), `DELETE FROM public.manifests WHERE id = $1`, manifest.ID)

	revoker, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer revoker.Rollback()
	if _, err := revoker.ExecContext(ctx, `UPDATE public.manifests SET active = FALSE WHERE id = $1`, manifest.ID); err != nil {
		t.Fatal(err)
	}
	finished := make(chan error, 1)
	go func() {
		_, readErr := ListCollaboratorProvisioningIdentities(ctx, db, manifest.ID, 1000)
		finished <- readErr
	}()
	// Observe the server-side lock wait before releasing the revoker. A sleep
	// alone would allow this test to pass without the reader ever reaching SQL.
	poll := time.NewTicker(25 * time.Millisecond)
	defer poll.Stop()
	waiting := false
	for !waiting {
		select {
		case readErr := <-finished:
			t.Fatalf("snapshot returned before revocation committed: %v", readErr)
		case <-poll.C:
			var waiters int
			if err := db.QueryRowContext(ctx, `
				SELECT COUNT(*) FROM pg_stat_activity
				WHERE state = 'active' AND wait_event_type = 'Lock'
					AND query LIKE '%SELECT id FROM public.manifests%'
			`).Scan(&waiters); err != nil {
				t.Fatal(err)
			}
			waiting = waiters > 0
		case <-ctx.Done():
			t.Fatalf("snapshot never waited on revoked manifest row: %v", ctx.Err())
		}
	}
	if err := revoker.Commit(); err != nil {
		t.Fatal(err)
	}
	select {
	case readErr := <-finished:
		if !errors.Is(readErr, sql.ErrNoRows) {
			t.Fatalf("revoked manifest read returned %v, want sql.ErrNoRows", readErr)
		}
	case <-ctx.Done():
		t.Fatalf("snapshot stayed blocked after revocation: %v", ctx.Err())
	}
}
