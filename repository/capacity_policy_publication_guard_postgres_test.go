package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

func capacityPolicyPublicationDocument(e CapacityDispatchEnvelope, name, environment string) model.ManifestDocument {
	raw, _ := json.Marshal(map[string]string{"environment": environment, "domain": e.Domain, "dimension": e.Dimension})
	return model.ManifestDocument{APIVersion: "v1", Kind: "capacity_policy", Metadata: model.ManifestMetadataInput{Namespace: e.Realm, Name: name}, Spec: raw}
}

func capacityPolicyPublicationFixture(t *testing.T) (*sql.DB, CapacityDispatchEnvelope, model.ManifestDocument) {
	t.Helper()
	db, e := capacityDispatchPostgresFixture(t)
	doc := capacityPolicyPublicationDocument(e, e.Policy.Name, e.Environment)
	m, err := CreateManifestVersion(t.Context(), db, doc, capacityDispatchSHA(doc.Spec))
	if err != nil {
		t.Fatal(err)
	}
	e.Policy = CapacityDispatchManifestPin{ID: m.ID, Namespace: e.Realm, Name: m.Metadata.Name, Version: m.Version, Checksum: m.Checksum}
	return db, e, doc
}

func capacityPolicyPublicationCatalog(t *testing.T, db *sql.DB, realm string) string {
	t.Helper()
	var raw string
	if err := db.QueryRowContext(t.Context(), `SELECT COALESCE(jsonb_agg(to_jsonb(m) ORDER BY id),'[]'::jsonb)::text FROM public.manifests m WHERE namespace=$1`, realm).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	return raw
}

// Runs inside the existing original-pin case: no new root, child ID or clock.
func testCapacityPolicyPublicationGuardPostgres(t *testing.T) {
	t.Helper()
	testCapacityPolicyPublicationFirstRow(t)
	testCapacityPolicyPublicationCatalogDrift(t)
	for _, state := range []string{"queued", "started", "unknown", "returned_without_ack"} {
		db, e, doc := capacityPolicyPublicationFixture(t)
		alias := doc
		alias.Metadata.Name = "same-scope-alias"
		aliasRow, err := CreateManifestVersion(t.Context(), db, alias, e.Policy.Checksum)
		if err != nil {
			t.Fatal(err)
		}
		capacityDispatchEnqueueFixture(t, db, e)
		var started CapacityDispatchJob
		if state != "queued" {
			started, err = StartCapacityDispatch(t.Context(), db, capacityDispatchClaimFixture(t, db, e, time.Minute))
			if err != nil {
				t.Fatal(err)
			}
		}
		var release chan struct{}
		var done chan error
		joined := false
		if state == "unknown" {
			if err := FinishCapacityDispatch(t.Context(), db, started, capacityDispatchResponse(e, "unknown"), time.Now().UTC(), nil); !errors.Is(err, ErrCapacityDispatchUnknown) {
				t.Fatal("actual uncertain return must remain UNKNOWN", err)
			}
		}
		if state == "returned_without_ack" {
			release, done = make(chan struct{}), make(chan error, 1)
			visible := make(chan struct{})
			go func() {
				done <- FinishCapacityDispatch(t.Context(), db, started, capacityDispatchResponse(e, "succeeded"), time.Now().UTC(), nil, func(context.Context) error { close(visible); <-release; return nil })
			}()
			defer func() {
				if !joined {
					close(release)
					<-done
				}
			}()
			select {
			case <-visible:
			case err := <-done:
				joined = true
				t.Fatal("actual first return did not reach pre-ACK boundary", err)
			case <-time.After(5 * time.Second):
				t.Fatal("actual first return did not reach pre-ACK boundary")
			}
		}
		job, err := readCapacityDispatchJob(t.Context(), db, e.JobID, false)
		wantState := state
		if state == "returned_without_ack" {
			wantState = "returned"
		}
		if err != nil || job.State != wantState || job.FinalizationAckAt != nil {
			t.Fatalf("real busy state missing: %s %+v %v", state, job, err)
		}
		before := capacityPolicyPublicationCatalog(t, db, e.Realm)
		moved := doc
		moved.Spec = capacityPolicyPublicationDocument(e, doc.Metadata.Name, "other-environment").Spec
		malformed := doc
		malformed.Spec = json.RawMessage(`{"environment":true}`)
		tombstone := doc
		inactive := false
		tombstone.Metadata.Active = &inactive
		tombstone.Spec = json.RawMessage(`{}`)
		// Same checksum, same-scope alias, moved scope, malformed incoming and
		// a default-off tombstone all retain the old active pin while busy.
		for _, candidate := range []model.ManifestDocument{doc, alias, moved, malformed, tombstone} {
			tx, err := db.BeginTx(t.Context(), nil)
			if err != nil {
				t.Fatal(err)
			}
			_, createErr := CreateManifestVersionTx(t.Context(), tx, candidate, e.Policy.Checksum)
			if !errors.Is(createErr, ErrCapacityPolicyPublicationConflict) {
				_ = tx.Rollback()
				t.Fatalf("busy %s publication did not refuse before writes: %v", state, createErr)
			}
			// A refusal is not a partially-written or SQL-aborted transaction.
			// Committing it must leave the entire original catalog unchanged.
			if err := tx.Commit(); err != nil {
				t.Fatal(err)
			}
		}
		for _, id := range []uuid.UUID{e.Policy.ID, aliasRow.ID} {
			if _, err := MarkManifestInactiveByID(t.Context(), db, id); !errors.Is(err, ErrCapacityPolicyPublicationConflict) {
				t.Fatalf("busy %s soft delete: %v", state, err)
			}
			if _, err := HardDeleteManifestByID(t.Context(), db, id); !errors.Is(err, ErrCapacityPolicyPublicationConflict) {
				t.Fatalf("busy %s hard delete: %v", state, err)
			}
		}
		if after := capacityPolicyPublicationCatalog(t, db, e.Realm); after != before {
			t.Fatal("refused publication/deletion changed original catalog bytes")
		}
		independent := capacityPolicyPublicationDocument(e, "independent-dimension", "other-environment")
		if _, err := CreateManifestVersion(t.Context(), db, independent, capacityDispatchSHA(independent.Spec)); err != nil {
			t.Fatal("busy scope paused an independent dimension", err)
		}
		// Namespace is the dispatch realm, not a global lock by policy name.
		otherDB, other, otherDoc := capacityPolicyPublicationFixture(t)
		if _, err := CreateManifestVersion(t.Context(), otherDB, otherDoc, other.Policy.Checksum); err != nil {
			t.Fatal("busy scope paused an independent realm", err)
		}
		if state == "returned_without_ack" {
			close(release)
			err := <-done
			joined = true
			if err != nil {
				t.Fatal("genuine ACK refused", err)
			}
			closed, err := readCapacityDispatchJob(t.Context(), db, e.JobID, false)
			if err != nil || closed.FinalizationAckAt == nil || closed.State != "returned" {
				t.Fatal("genuine ACK missing", err)
			}
			revision, err := CreateManifestVersion(t.Context(), db, doc, e.Policy.Checksum)
			if err != nil || revision.ID == e.Policy.ID || revision.Version != e.Policy.Version+1 {
				t.Fatal("closed original did not permit a genuine new revision", err)
			}
			if _, err := MarkManifestInactiveByID(t.Context(), db, revision.ID); err != nil {
				t.Fatal("closed original blocked soft delete", err)
			}
			if _, err := HardDeleteManifestByID(t.Context(), db, revision.ID); err != nil {
				t.Fatal("closed original blocked hard delete", err)
			}
		}
		t.Logf("capacity policy publication busy-state proof: %s", state)
	}
	// Moving an idle policy INTO a different busy scope must also refuse;
	// checking only the old scope would miss this alias admission.
	db, e, target := capacityPolicyPublicationFixture(t)
	incoming := target
	incoming.Spec = capacityPolicyPublicationDocument(e, target.Metadata.Name, "busy-incoming").Spec
	alias := capacityPolicyPublicationDocument(e, "incoming-owner", "busy-incoming")
	m, err := CreateManifestVersion(t.Context(), db, alias, capacityDispatchSHA(alias.Spec))
	if err != nil {
		t.Fatal(err)
	}
	e.Environment = "busy-incoming"
	e.Policy = CapacityDispatchManifestPin{ID: m.ID, Namespace: e.Realm, Name: m.Metadata.Name, Version: m.Version, Checksum: m.Checksum}
	e.Inputs = map[string]any{"policy": map[string]any{"namespace": e.Realm, "name": m.Metadata.Name}}
	e.InputsSHA256, e.MetadataSHA256, err = CapacityDispatchEnvelopeHashes(e)
	if err != nil {
		t.Fatal(err)
	}
	capacityDispatchEnqueueFixture(t, db, e)
	if _, err := CreateManifestVersion(t.Context(), db, incoming, capacityDispatchSHA(incoming.Spec)); !errors.Is(err, ErrCapacityPolicyPublicationConflict) {
		t.Fatal("moving policy ignored incoming busy scope", err)
	}
	if _, err := CreateManifestVersion(t.Context(), db, target, capacityDispatchSHA(target.Spec)); err != nil {
		t.Fatal("independent old scope was globally paused", err)
	}
}

func testCapacityPolicyPublicationCatalogDrift(t *testing.T) {
	t.Helper()
	db, e, doc := capacityPolicyPublicationFixture(t)
	doc.Spec = capacityPolicyPublicationDocument(e, doc.Metadata.Name, "zz-incoming").Spec
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	hold, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer hold.Rollback()
	key, _ := json.Marshal([]string{e.Realm, "zz-incoming", e.Domain, e.Dimension})
	if _, err := hold.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, string(key)); err != nil {
		t.Fatal(err)
	}
	pidReady, done := make(chan int, 1), make(chan error, 1)
	go func() {
		conn, err := db.Conn(ctx)
		if err != nil {
			done <- err
			return
		}
		defer conn.Close()
		var pid int
		if err := conn.QueryRowContext(ctx, `SELECT pg_backend_pid()`).Scan(&pid); err != nil {
			done <- err
			return
		}
		tx, err := conn.BeginTx(ctx, nil)
		if err != nil {
			done <- err
			return
		}
		defer tx.Rollback()
		pidReady <- pid
		_, err = CreateManifestVersionTx(ctx, tx, doc, e.Policy.Checksum)
		done <- errors.Join(err, tx.Rollback())
	}()
	var pid int
	select {
	case pid = <-pidReady:
	case err := <-done:
		t.Fatal(err)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	waiting := false
	until := time.Now().Add(2 * time.Second)
	for time.Now().Before(until) {
		if err := db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE pid=$1 AND wait_event_type='Lock' AND wait_event='advisory')`, pid).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !waiting {
		t.Fatal("publication did not reach its real incoming-scope lock")
	}
	// Explicit hostile catalog-writer control, only in this synthetic fixture:
	// change a discovered row without the application scope protocol. The
	// guard must detect this drift rather than lock another scope out of order.
	if _, err := db.ExecContext(ctx, `UPDATE public.manifests SET checksum=$2 WHERE id=$1`, e.Policy.ID, capacityDispatchSHA([]byte("external-catalog-drift"))); err != nil {
		t.Fatal(err)
	}
	before := capacityPolicyPublicationCatalog(t, db, e.Realm)
	if err := hold.Commit(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if !errors.Is(err, ErrCapacityPolicyPublicationConflict) {
			t.Fatal("changed discovery was not a typed conflict", err)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	if after := capacityPolicyPublicationCatalog(t, db, e.Realm); after != before {
		t.Fatal("discovery conflict partially wrote a new catalog revision")
	}
}

func testCapacityPolicyPublicationFirstRow(t *testing.T) {
	t.Helper()
	db, e := capacityDispatchPostgresFixture(t)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	first := capacityPolicyPublicationDocument(e, "first-logical-publication", e.Environment)
	second := capacityPolicyPublicationDocument(e, first.Metadata.Name, "different-scope")
	var count int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM public.manifests WHERE kind='capacity_policy' AND namespace=$1 AND name=$2`, e.Realm, first.Metadata.Name).Scan(&count); err != nil || count != 0 {
		t.Fatal("first-publication witness must start with no catalog row", count, err)
	}
	publisher, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer publisher.Rollback()
	created, err := CreateManifestVersionTx(ctx, publisher, first, capacityDispatchSHA(first.Spec))
	if err != nil || created.Version != 1 {
		t.Fatal("real first publication", created.Version, err)
	}
	pidReady, done := make(chan int, 1), make(chan error, 1)
	go func() {
		conn, err := db.Conn(ctx)
		if err != nil {
			done <- err
			return
		}
		defer conn.Close()
		var pid int
		if err := conn.QueryRowContext(ctx, `SELECT pg_backend_pid()`).Scan(&pid); err != nil {
			done <- err
			return
		}
		tx, err := conn.BeginTx(ctx, nil)
		if err != nil {
			done <- err
			return
		}
		defer tx.Rollback()
		pidReady <- pid
		_, err = CreateManifestVersionTx(ctx, tx, second, capacityDispatchSHA(second.Spec))
		done <- errors.Join(err, tx.Rollback())
	}()
	var pid int
	select {
	case pid = <-pidReady:
	case err := <-done:
		t.Fatal("second first-publication backend unavailable", err)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	waiting := false
	until := time.Now().Add(2 * time.Second)
	for time.Now().Before(until) {
		if err := db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE pid=$1 AND wait_event_type='Lock' AND wait_event='advisory')`, pid).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !waiting {
		t.Fatal("same logical empty-name writer did not serialize before catalog discovery")
	}
	// The waiting writer has a different scope. It must not lock that scope
	// before discovering the now-visible predecessor, or pause another name.
	independent := second
	independent.Metadata.Name = "independent-logical-publication"
	if _, err := CreateManifestVersion(ctx, db, independent, capacityDispatchSHA(independent.Spec)); err != nil {
		t.Fatal("logical-name serialization became a global/different-scope pause", err)
	}
	// Commit the authentic first catalog pin and its caller-managed enqueue
	// together while the other backend is waiting. The second writer must
	// rediscover this scope and refuse its busy owner, never deactivate it.
	e.Policy = CapacityDispatchManifestPin{ID: created.ID, Namespace: e.Realm, Name: first.Metadata.Name, Version: created.Version, Checksum: created.Checksum}
	e.Inputs = map[string]any{"policy": map[string]any{"namespace": e.Realm, "name": first.Metadata.Name}}
	e.InputsSHA256, e.MetadataSHA256, err = CapacityDispatchEnvelopeHashes(e)
	if err != nil {
		t.Fatal(err)
	}
	if _, dedup, err := EnqueueCapacityDispatch(ctx, publisher, e); err != nil || dedup {
		t.Fatal("actual first-pin enqueue", dedup, err)
	}
	if err := publisher.Commit(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if !errors.Is(err, ErrCapacityPolicyPublicationConflict) {
			t.Fatal("different-scope writer did not rediscover and retain busy first pin", err)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	var activeID uuid.UUID
	if err := db.QueryRowContext(ctx, `SELECT count(*),(array_agg(id ORDER BY version))[1] FROM public.manifests WHERE kind='capacity_policy' AND namespace=$1 AND name=$2`, e.Realm, first.Metadata.Name).Scan(&count, &activeID); err != nil || count != 1 || activeID != created.ID {
		t.Fatal("first pin replaced or extra catalog version written", count, activeID, err)
	}
	current, err := GetManifestByID(ctx, db, created.ID)
	if err != nil || !current.Metadata.Active || string(current.Spec) != string(created.Spec) {
		t.Fatal("first active scope lost", err)
	}
	claimed := capacityDispatchClaimFixture(t, db, e, time.Minute)
	if claimed.Policy != e.Policy || claimed.JobID != e.JobID || ValidateCapacityDispatchClaim(ctx, db, claimed, false) != nil {
		t.Fatal("serialized publication invalidated the genuine queued original pin")
	}
	t.Log("first publication and enqueue retain their pin against a concurrent same-name/different-scope writer")
}
