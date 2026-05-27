package repository

import (
	"context"
	"testing"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	_ "github.com/lib/pq"
)

// TestEmitEventWithOutcome_ReturnsMaterializedCount uses a non-canon event
// type so the materialiser is a no-op — the assertion locks in that the
// outcome struct is populated even on the zero-fan-out path. Adapters
// emitting their first mutation event will hit this branch.
func TestEmitEventWithOutcome_ReturnsMaterializedCount(t *testing.T) {
	db := dbForEventTest(t)
	defer func() { _ = db.Close() }()
	cleanEventLog(t, db)

	ctx := context.Background()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("begin tx: %v", err)
	}
	defer func() { _ = tx.Rollback() }()

	outcome, err := EmitEventWithOutcome(ctx, tx, model.EmitEventRequest{
		Type:          "manifest.created",
		AggregateType: "manifest",
		AggregateID:   "018f2b4a-1234-7abc-def0-123456789020",
		Payload:       validManifestCreatedPayload("outcome-1", 1),
	})
	if err != nil {
		t.Fatalf("EmitEventWithOutcome: %v", err)
	}
	if outcome.EventID.String() == "" {
		t.Fatal("outcome.EventID empty")
	}
	if outcome.Deduped {
		t.Fatal("outcome.Deduped: expected false for fresh emit")
	}
	if outcome.MaterializedReactions != 0 {
		t.Fatalf("outcome.MaterializedReactions: got %d, want 0 (no reactors registered)", outcome.MaterializedReactions)
	}

	if err := tx.Commit(); err != nil {
		t.Fatalf("commit: %v", err)
	}
}

// TestEmitEventWithOutcome_IdempotencyDedupsSecondEmit posts the same event
// twice with the same idempotency_key and asserts the second call returns
// the original event_id with Deduped=true and no second row in event_log.
// This is the §6.5 contract: adapters can safely retry mutation emissions.
func TestEmitEventWithOutcome_IdempotencyDedupsSecondEmit(t *testing.T) {
	db := dbForEventTest(t)
	defer func() { _ = db.Close() }()
	cleanEventLog(t, db)

	ctx := context.Background()

	tx1, _ := db.BeginTx(ctx, nil)
	first, err := EmitEventWithOutcome(ctx, tx1, model.EmitEventRequest{
		Type:           "stripe.customer.ensured",
		AggregateType:  "stripe_customer",
		AggregateID:    "cus_dedup_1",
		Payload:        mutationPayloadForTest("stripe", "customer", "ensured", "cus_dedup_1", "stripe-acme"),
		IdempotencyKey: "ensure_customer_acme_1",
	})
	if err != nil {
		t.Fatalf("first EmitEventWithOutcome: %v", err)
	}
	if first.Deduped {
		t.Fatal("first emit must not be flagged deduped")
	}
	if err := tx1.Commit(); err != nil {
		t.Fatalf("commit1: %v", err)
	}

	tx2, _ := db.BeginTx(ctx, nil)
	second, err := EmitEventWithOutcome(ctx, tx2, model.EmitEventRequest{
		Type:           "stripe.customer.ensured",
		AggregateType:  "stripe_customer",
		AggregateID:    "cus_dedup_1",
		Payload:        mutationPayloadForTest("stripe", "customer", "ensured", "cus_dedup_1", "stripe-acme"),
		IdempotencyKey: "ensure_customer_acme_1",
	})
	if err != nil {
		t.Fatalf("second EmitEventWithOutcome: %v", err)
	}
	if err := tx2.Commit(); err != nil {
		t.Fatalf("commit2: %v", err)
	}

	if !second.Deduped {
		t.Fatalf("second emit must be flagged deduped; got %#v", second)
	}
	if second.EventID != first.EventID {
		t.Fatalf("deduped emit must return original event_id; got %s want %s",
			second.EventID, first.EventID)
	}

	var count int
	if err := db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM public.event_log WHERE idempotency_key = $1 AND type = $2`,
		"ensure_customer_acme_1", "stripe.customer.ensured").Scan(&count); err != nil {
		t.Fatalf("count: %v", err)
	}
	if count != 1 {
		t.Fatalf("expected exactly 1 row in event_log for the idempotency key, got %d", count)
	}
}

// TestEmitEventWithOutcome_DifferentTypesShareKey confirms the dedup scope
// is (type, idempotency_key) — two different event types with the same
// idempotency string MUST land as two distinct rows.
func TestEmitEventWithOutcome_DifferentTypesShareKey(t *testing.T) {
	db := dbForEventTest(t)
	defer func() { _ = db.Close() }()
	cleanEventLog(t, db)

	ctx := context.Background()

	tx1, _ := db.BeginTx(ctx, nil)
	first, err := EmitEventWithOutcome(ctx, tx1, model.EmitEventRequest{
		Type:           "stripe.customer.ensured",
		AggregateType:  "stripe_customer",
		AggregateID:    "cus_x",
		Payload:        mutationPayloadForTest("stripe", "customer", "ensured", "cus_x", "stripe-acme"),
		IdempotencyKey: "shared-key",
	})
	if err != nil {
		t.Fatalf("first emit: %v", err)
	}
	_ = tx1.Commit()

	tx2, _ := db.BeginTx(ctx, nil)
	second, err := EmitEventWithOutcome(ctx, tx2, model.EmitEventRequest{
		Type:           "stripe.subscription.ensured",
		AggregateType:  "stripe_subscription",
		AggregateID:    "sub_x",
		Payload:        mutationPayloadForTest("stripe", "subscription", "ensured", "sub_x", "stripe-acme"),
		IdempotencyKey: "shared-key",
	})
	if err != nil {
		t.Fatalf("second emit: %v", err)
	}
	_ = tx2.Commit()

	if second.Deduped {
		t.Fatal("different event types with same idempotency_key must not dedup")
	}
	if second.EventID == first.EventID {
		t.Fatal("different rows expected")
	}
}

// mutationPayloadForTest returns the §6.5 payload shape suitable for the
// shared integration_mutation/<verb>.json schema.
func mutationPayloadForTest(provider, resource, verb, resourceID, instanceID string) map[string]interface{} {
	return map[string]interface{}{
		"provider":    provider,
		"resource":    resource,
		"verb":        verb,
		"resource_id": resourceID,
		"instance_id": instanceID,
		"emitted_at":  "2026-05-27T10:30:00Z",
	}
}
