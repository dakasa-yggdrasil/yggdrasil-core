package repository

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

// TestCreateManifestVersionTx_EmitsEventInSameTransaction verifies that wiring
// EmitEvent alongside CreateManifestVersionTx inside the same transaction
// produces a manifest.created event that is visible via PullEvents after commit.
//
// This is the end-to-end test for Task 19 (manifest.created wiring).
func TestCreateManifestVersionTx_EmitsEventInSameTransaction(t *testing.T) {
	db := dbForEventTest(t)
	defer db.Close()
	cleanEventLog(t, db)
	// Clean manifests for repeatable test
	if _, err := db.Exec(`DELETE FROM public.manifests WHERE name = 'wire-test-manifest'`); err != nil {
		t.Fatalf("clean manifests: %v", err)
	}

	ctx := context.Background()

	// Arrange: a valid product manifest document
	doc := model.ManifestDocument{
		APIVersion: "yggdrasil.io/v1alpha1",
		Kind:       "product",
		Metadata: model.ManifestMetadataInput{
			Namespace: "wire-test",
			Name:      "wire-test-manifest",
		},
		Spec: json.RawMessage(`{
			"category": "application",
			"class": "platform",
			"lifecycle": {},
			"components": []
		}`),
	}

	// Act: begin tx, create manifest, emit event, commit
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("begin tx: %v", err)
	}

	manifestRecord, err := CreateManifestVersionTx(ctx, tx, doc, "sha256:aaaabbbbccccddddeeeeffff0000111122223333444455556666777788889999")
	if err != nil {
		tx.Rollback()
		t.Fatalf("CreateManifestVersionTx: %v", err)
	}

	eventPayload := map[string]interface{}{
		"manifest_id": manifestRecord.ID.String(),
		"kind":        manifestRecord.Kind,
		"namespace":   manifestRecord.Metadata.Namespace,
		"name":        manifestRecord.Metadata.Name,
		"version":     manifestRecord.Version,
		"checksum":    manifestRecord.Checksum,
	}

	eventID, err := EmitEvent(ctx, tx, model.EmitEventRequest{
		Type:          "manifest.created",
		SchemaVersion: "v1",
		AggregateType: "manifest",
		AggregateID:   manifestRecord.ID.String(),
		Payload:       eventPayload,
	})
	if err != nil {
		tx.Rollback()
		t.Fatalf("EmitEvent: %v", err)
	}

	if err := tx.Commit(); err != nil {
		t.Fatalf("commit: %v", err)
	}

	// Assert 1: manifest exists in DB
	var manifestCount int
	err = db.QueryRow(`SELECT COUNT(*) FROM public.manifests WHERE id = $1`, manifestRecord.ID).Scan(&manifestCount)
	if err != nil {
		t.Fatalf("count manifests: %v", err)
	}
	if manifestCount != 1 {
		t.Errorf("expected 1 manifest, got %d", manifestCount)
	}

	// Assert 2: event is retrievable via PullEvents with the right filter
	resp, err := PullEvents(ctx, db, model.PullEventsRequest{
		Limit: 100,
		Filters: model.PullEventsFilters{
			Types:         []string{"manifest.created"},
			AggregateType: "manifest",
			AggregateID:   manifestRecord.ID.String(),
		},
	})
	if err != nil {
		t.Fatalf("PullEvents: %v", err)
	}
	if len(resp.Events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(resp.Events))
	}

	event := resp.Events[0]
	if event.EventID != eventID {
		t.Errorf("event_id mismatch: got %s, expected %s", event.EventID, eventID)
	}
	if event.Type != "manifest.created" {
		t.Errorf("type mismatch: got %s", event.Type)
	}
	if event.AggregateID != manifestRecord.ID.String() {
		t.Errorf("aggregate_id mismatch: got %s", event.AggregateID)
	}

	// Assert 3: event payload matches the manifest fields
	var payloadMap map[string]interface{}
	if err := json.Unmarshal(event.Payload, &payloadMap); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	if payloadMap["kind"] != "product" {
		t.Errorf("payload kind mismatch: got %v", payloadMap["kind"])
	}
	if payloadMap["namespace"] != "wire-test" {
		t.Errorf("payload namespace mismatch: got %v", payloadMap["namespace"])
	}
	if payloadMap["name"] != "wire-test-manifest" {
		t.Errorf("payload name mismatch: got %v", payloadMap["name"])
	}
}

// TestCreateManifestVersionTx_RollbackDoesNotPersistEvent verifies atomicity:
// if the tx rolls back, neither the manifest nor the event should exist.
func TestCreateManifestVersionTx_RollbackDoesNotPersistEvent(t *testing.T) {
	db := dbForEventTest(t)
	defer db.Close()
	cleanEventLog(t, db)
	if _, err := db.Exec(`DELETE FROM public.manifests WHERE name = 'rollback-test-manifest'`); err != nil {
		t.Fatalf("clean manifests: %v", err)
	}

	ctx := context.Background()

	doc := model.ManifestDocument{
		APIVersion: "yggdrasil.io/v1alpha1",
		Kind:       "product",
		Metadata: model.ManifestMetadataInput{
			Namespace: "rollback-test",
			Name:      "rollback-test-manifest",
		},
		Spec: json.RawMessage(`{
			"category": "application",
			"class": "platform",
			"lifecycle": {},
			"components": []
		}`),
	}

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("begin tx: %v", err)
	}

	manifestRecord, err := CreateManifestVersionTx(ctx, tx, doc, "sha256:aaaabbbbccccddddeeeeffff0000111122223333444455556666777788889999")
	if err != nil {
		tx.Rollback()
		t.Fatalf("CreateManifestVersionTx: %v", err)
	}

	_, err = EmitEvent(ctx, tx, model.EmitEventRequest{
		Type:          "manifest.created",
		SchemaVersion: "v1",
		AggregateType: "manifest",
		AggregateID:   manifestRecord.ID.String(),
		Payload: map[string]interface{}{
			"manifest_id": manifestRecord.ID.String(),
			"kind":        "product",
			"namespace":   "rollback-test",
			"name":        "rollback-test-manifest",
			"version":     manifestRecord.Version,
			"checksum":    manifestRecord.Checksum,
		},
	})
	if err != nil {
		tx.Rollback()
		t.Fatalf("EmitEvent: %v", err)
	}

	// Rollback instead of commit
	if err := tx.Rollback(); err != nil {
		t.Fatalf("rollback: %v", err)
	}

	// Assert: manifest does NOT exist
	var manifestCount int
	err = db.QueryRow(`SELECT COUNT(*) FROM public.manifests WHERE id = $1`, manifestRecord.ID).Scan(&manifestCount)
	if err != nil {
		t.Fatalf("count manifests: %v", err)
	}
	if manifestCount != 0 {
		t.Errorf("expected 0 manifests after rollback, got %d", manifestCount)
	}

	// Assert: event does NOT exist
	var eventCount int
	err = db.QueryRow(`SELECT COUNT(*) FROM public.event_log WHERE aggregate_id = $1`, manifestRecord.ID.String()).Scan(&eventCount)
	if err != nil {
		t.Fatalf("count events: %v", err)
	}
	if eventCount != 0 {
		t.Errorf("expected 0 events after rollback, got %d", eventCount)
	}
}
