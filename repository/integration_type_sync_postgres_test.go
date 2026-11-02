package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	manifestengine "github.com/dakasa-yggdrasil/yggdrasil-core/manifest"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

func TestIntegrationTypeSyncHistoricalIdentityAndConcurrentCAS(t *testing.T) {
	dsn := os.Getenv("ORIGINAL_INTEGRATION_SYNC_PG_DSN")
	if dsn == "" {
		t.Skip("explicit isolated Unix-socket sync test DB required")
	}
	if !strings.Contains(dsn, "host=/") || !strings.Contains(dsn, "dbname=original_disposition_test_") {
		t.Fatal("refuse non-isolated DB")
	}
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	var local bool
	if err = db.QueryRowContext(ctx, `SELECT inet_server_addr() IS NULL`).Scan(&local); err != nil || !local {
		t.Fatal("refuse network DB", err)
	}
	active := true
	doc := model.ManifestDocument{APIVersion: "yggdrasil.io/v1", Kind: "integration_type", Metadata: model.ManifestMetadataInput{Namespace: "sync-" + uuid.NewString(), Name: "declared", Description: "original operator fields", Active: &active}, Spec: json.RawMessage(`{"provider":"declared","adapter":{"version":"0.3.4"}}`)}
	sum := func(v model.ManifestDocument) string {
		t.Helper()
		s, e := manifestengine.Checksum(v)
		if e != nil {
			t.Fatal(e)
		}
		return s
	}
	old, err := CreateManifestVersion(ctx, db, doc, sum(doc))
	if err != nil {
		t.Fatal(err)
	}
	upgraded := doc
	upgraded.Spec = json.RawMessage(`{"provider":"declared","adapter":{"version":"0.3.5"}}`)
	current, err := ApplyIntegrationTypeSyncVersion(ctx, db, old, upgraded, sum(upgraded))
	if err != nil || current.Version != 2 {
		t.Fatal("first catalog upgrade", err)
	}
	for i := 0; i < 3; i++ {
		resolved, e := CurrentIntegrationTypeForSync(ctx, db, old.ID)
		if e != nil || resolved.ID != current.ID {
			t.Fatal("historical nudge did not resolve active type", e)
		}
		reused, e := ApplyIntegrationTypeSyncVersion(ctx, db, old, upgraded, sum(upgraded))
		if e != nil || reused.ID != current.ID {
			t.Fatal("same current catalog cloned", e)
		}
	}
	next := upgraded
	next.Spec = json.RawMessage(`{"provider":"declared","adapter":{"version":"0.3.6"}}`)
	nextSHA := sum(next)
	var wg sync.WaitGroup
	errs := make(chan error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, e := ApplyIntegrationTypeSyncVersion(ctx, db, current, next, nextSHA)
			errs <- e
		}()
	}
	wg.Wait()
	close(errs)
	successes := 0
	for e := range errs {
		if e == nil {
			successes++
		}
	}
	latest, err := CurrentIntegrationTypeForSync(ctx, db, old.ID)
	if err != nil || successes < 1 || latest.Version != 3 {
		t.Fatal("concurrent catalog version multiplied", successes, latest.Version, err)
	}
	operator := next
	operator.Metadata.Description = "newer operator-owned declaration"
	operatorVersion, err := CreateManifestVersion(ctx, db, operator, sum(operator))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = ApplyIntegrationTypeSyncVersion(ctx, db, current, next, nextSHA); err == nil {
		t.Fatal("stale describe overwrote newer operator declaration")
	}
	latest, err = CurrentIntegrationTypeForSync(ctx, db, old.ID)
	if err != nil || latest.ID != operatorVersion.ID || latest.Metadata.Description != operator.Metadata.Description {
		t.Fatal("operator declaration changed", err)
	}
	if _, err = ApplyIntegrationTypeSyncVersion(ctx, db, latest, operator, strings.Repeat("0", 64)); err == nil {
		t.Fatal("unchecked checksum admitted")
	}
	inactive := false
	tombstone := operator
	tombstone.Metadata.Active = &inactive
	if _, err = CreateManifestVersion(ctx, db, tombstone, sum(tombstone)); err != nil {
		t.Fatal(err)
	}
	if _, err = CurrentIntegrationTypeForSync(ctx, db, old.ID); err == nil {
		t.Fatal("inactive logical catalog resurrected by historical nudge")
	}
}
