package repository

import (
	"context"
	"database/sql"
	"os"
	"testing"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	_ "github.com/lib/pq"
)

func dbForEventTest(t *testing.T) *sql.DB {
	t.Helper()
	dsn := os.Getenv("DB_URL")
	if dsn == "" {
		t.Skip("DB_URL not set; skipping event repository integration test")
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

func cleanEventLog(t *testing.T, db *sql.DB) {
	t.Helper()
	_, err := db.Exec(`TRUNCATE TABLE public.event_log RESTART IDENTITY`)
	if err != nil {
		t.Fatalf("truncate event_log: %v", err)
	}
}

func validManifestCreatedPayload(name string, version int) map[string]interface{} {
	return map[string]interface{}{
		"manifest_id": "018f2b4a-1234-7abc-def0-123456789012",
		"kind":        "product",
		"namespace":   "dakasa",
		"name":        name,
		"version":     version,
		"checksum":    "sha256:abc123def456abc123def456abc123def456abc123def456abc123def456abc1",
	}
}

func TestEmitEvent_ValidPayload_InsertsEvent(t *testing.T) {
	db := dbForEventTest(t)
	defer db.Close()
	cleanEventLog(t, db)

	ctx := context.Background()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("begin tx: %v", err)
	}
	defer func() { _ = tx.Rollback() }()

	req := model.EmitEventRequest{
		Type:          "manifest.created",
		SchemaVersion: "v1",
		AggregateType: "manifest",
		AggregateID:   "018f2b4a-1234-7abc-def0-123456789012",
		Actor: &model.EventActor{
			Type: "collaborator",
			ID:   "alice",
		},
		Payload: validManifestCreatedPayload("dakasa-app", 1),
	}

	eventID, err := EmitEvent(ctx, tx, req)
	if err != nil {
		t.Fatalf("EmitEvent: %v", err)
	}
	if eventID.String() == "" {
		t.Fatal("expected non-zero event ID")
	}

	if err := tx.Commit(); err != nil {
		t.Fatalf("commit: %v", err)
	}

	var count int
	err = db.QueryRow(`SELECT COUNT(*) FROM public.event_log WHERE event_id = $1`, eventID).Scan(&count)
	if err != nil {
		t.Fatalf("query count: %v", err)
	}
	if count != 1 {
		t.Errorf("expected 1 row, got %d", count)
	}
}

func TestEmitEvent_InvalidPayload_ReturnsValidationError(t *testing.T) {
	db := dbForEventTest(t)
	defer db.Close()
	cleanEventLog(t, db)

	ctx := context.Background()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("begin tx: %v", err)
	}
	defer func() { _ = tx.Rollback() }()

	req := model.EmitEventRequest{
		Type:          "manifest.created",
		AggregateType: "manifest",
		AggregateID:   "some-id",
		Payload: map[string]interface{}{
			"manifest_id": "not-a-uuid",
			// missing required fields
		},
	}

	_, err = EmitEvent(ctx, tx, req)
	if err == nil {
		t.Fatal("expected validation error")
	}
}

func TestEmitEvent_NilTransaction_ReturnsError(t *testing.T) {
	ctx := context.Background()
	_, err := EmitEvent(ctx, nil, model.EmitEventRequest{
		Type:          "manifest.created",
		AggregateType: "manifest",
		AggregateID:   "id",
		Payload:       validManifestCreatedPayload("x", 1),
	})
	if err == nil {
		t.Fatal("expected error for nil transaction")
	}
}

func TestEmitEvent_TransactionRollback_EventNotPersisted(t *testing.T) {
	db := dbForEventTest(t)
	defer db.Close()
	cleanEventLog(t, db)

	ctx := context.Background()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("begin tx: %v", err)
	}

	req := model.EmitEventRequest{
		Type:          "manifest.created",
		AggregateType: "manifest",
		AggregateID:   "id-1",
		Payload:       validManifestCreatedPayload("x", 1),
	}

	_, err = EmitEvent(ctx, tx, req)
	if err != nil {
		t.Fatalf("EmitEvent: %v", err)
	}

	_ = tx.Rollback()

	var count int
	err = db.QueryRow(`SELECT COUNT(*) FROM public.event_log`).Scan(&count)
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if count != 0 {
		t.Errorf("expected 0 rows after rollback, got %d", count)
	}
}

func TestPullEvents_NoCursor_ReturnsAllInOrder(t *testing.T) {
	db := dbForEventTest(t)
	defer db.Close()
	cleanEventLog(t, db)

	ctx := context.Background()

	for i := 0; i < 5; i++ {
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			t.Fatalf("begin tx: %v", err)
		}
		req := model.EmitEventRequest{
			Type:          "manifest.created",
			AggregateType: "manifest",
			AggregateID:   "id-x",
			Payload:       validManifestCreatedPayload("x", i+1),
		}
		if _, err := EmitEvent(ctx, tx, req); err != nil {
			t.Fatalf("EmitEvent[%d]: %v", i, err)
		}
		if err := tx.Commit(); err != nil {
			t.Fatalf("commit[%d]: %v", i, err)
		}
	}

	resp, err := PullEvents(ctx, db, model.PullEventsRequest{Limit: 100})
	if err != nil {
		t.Fatalf("PullEvents: %v", err)
	}
	if len(resp.Events) != 5 {
		t.Errorf("expected 5 events, got %d", len(resp.Events))
	}
	for i := 1; i < len(resp.Events); i++ {
		if resp.Events[i].Sequence <= resp.Events[i-1].Sequence {
			t.Errorf("sequence not monotonic: %d <= %d", resp.Events[i].Sequence, resp.Events[i-1].Sequence)
		}
	}
	if resp.HasMore {
		t.Error("expected has_more=false")
	}
}

func TestPullEvents_WithCursor_ReturnsEventsAfterCursor(t *testing.T) {
	db := dbForEventTest(t)
	defer db.Close()
	cleanEventLog(t, db)

	ctx := context.Background()
	for i := 0; i < 3; i++ {
		tx, _ := db.BeginTx(ctx, nil)
		if _, err := EmitEvent(ctx, tx, model.EmitEventRequest{
			Type:          "manifest.created",
			AggregateType: "manifest",
			AggregateID:   "id-y",
			Payload:       validManifestCreatedPayload("y", i+1),
		}); err != nil {
			t.Fatalf("EmitEvent[%d]: %v", i, err)
		}
		_ = tx.Commit()
	}

	firstResp, err := PullEvents(ctx, db, model.PullEventsRequest{Limit: 2})
	if err != nil {
		t.Fatalf("first pull: %v", err)
	}
	if len(firstResp.Events) != 2 {
		t.Fatalf("expected 2 events in first pull, got %d", len(firstResp.Events))
	}
	if !firstResp.HasMore {
		t.Error("expected has_more=true in first pull")
	}

	secondResp, err := PullEvents(ctx, db, model.PullEventsRequest{
		Cursor: firstResp.NextCursor,
		Limit:  2,
	})
	if err != nil {
		t.Fatalf("second pull: %v", err)
	}
	if len(secondResp.Events) != 1 {
		t.Errorf("expected 1 event in second pull, got %d", len(secondResp.Events))
	}
	if secondResp.HasMore {
		t.Error("expected has_more=false in second pull")
	}
}

func TestPullEvents_FilterByType(t *testing.T) {
	db := dbForEventTest(t)
	defer db.Close()
	cleanEventLog(t, db)

	ctx := context.Background()
	for _, eventType := range []string{"manifest.created", "manifest.created", "authorization.evaluated"} {
		tx, _ := db.BeginTx(ctx, nil)
		var payload map[string]interface{}
		if eventType == "manifest.created" {
			payload = validManifestCreatedPayload("z", 1)
		} else {
			payload = map[string]interface{}{
				"resource": "products/x",
				"action":   "apply",
				"decision": "allow",
			}
		}
		if _, err := EmitEvent(ctx, tx, model.EmitEventRequest{
			Type:          eventType,
			AggregateType: "test",
			AggregateID:   "id-z",
			Payload:       payload,
		}); err != nil {
			t.Fatalf("EmitEvent %s: %v", eventType, err)
		}
		tx.Commit()
	}

	resp, err := PullEvents(ctx, db, model.PullEventsRequest{
		Limit: 100,
		Filters: model.PullEventsFilters{
			Types: []string{"manifest.*"},
		},
	})
	if err != nil {
		t.Fatalf("PullEvents: %v", err)
	}
	if len(resp.Events) != 2 {
		t.Errorf("expected 2 manifest events, got %d", len(resp.Events))
	}
	for _, ev := range resp.Events {
		if ev.Type != "manifest.created" {
			t.Errorf("unexpected event type: %s", ev.Type)
		}
	}
}

func TestPullEvents_InvalidCursor_ReturnsError(t *testing.T) {
	db := dbForEventTest(t)
	defer db.Close()

	ctx := context.Background()
	_, err := PullEvents(ctx, db, model.PullEventsRequest{
		Cursor: "not-a-valid-cursor",
		Limit:  10,
	})
	if err == nil {
		t.Fatal("expected error for invalid cursor")
	}
}

func TestPullEvents_LimitCapped(t *testing.T) {
	db := dbForEventTest(t)
	defer db.Close()
	cleanEventLog(t, db)

	ctx := context.Background()
	// Request limit above the max
	_, err := PullEvents(ctx, db, model.PullEventsRequest{
		Limit: 999999,
	})
	if err != nil {
		t.Fatalf("PullEvents: %v", err)
	}
	// No assertions on result count since table is empty;
	// we just verify the call succeeds (limit is capped internally)
}

func TestListRetentionPolicies_ReturnsSeededDefaults(t *testing.T) {
	db := dbForEventTest(t)
	defer db.Close()

	ctx := context.Background()
	policies, err := ListRetentionPolicies(ctx, db)
	if err != nil {
		t.Fatalf("ListRetentionPolicies: %v", err)
	}
	if len(policies) < 1 {
		t.Errorf("expected at least 1 policy, got %d", len(policies))
	}
	// Check that '*' default exists
	foundDefault := false
	for _, p := range policies {
		if p.TypePattern == "*" {
			foundDefault = true
			break
		}
	}
	if !foundDefault {
		t.Error("expected '*' default policy to be seeded")
	}
}
