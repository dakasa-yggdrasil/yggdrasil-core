package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

// validMutationBody returns the §6.5 wire body suitable for the new
// adapter-side emit path. Tests vary individual fields off this baseline.
func validMutationBody(idempotency string) map[string]any {
	return map[string]any{
		"event_type":  "stripe.customer.ensured",
		"provider":    "stripe",
		"resource":    "customer",
		"verb":        "ensured",
		"resource_id": "cus_1234abc",
		"instance_id": "stripe-acme",
		"idempotency": idempotency,
		"observed":    map[string]any{"id": "cus_1234abc", "email": "acme@example.com"},
		"emitted_at":  "2026-05-27T10:30:00Z",
	}
}

// TestHandleEventPublish_Mutation_HappyPath posts a canonical §6.5 mutation
// event and asserts the response carries event_id + materialized_reactions
// and a 201 status. materialized_reactions is 0 here because no reactor
// manifests target this event_type in the integration DB.
func TestHandleEventPublish_Mutation_HappyPath(t *testing.T) {
	t.Setenv("YGGDRASIL_WORKFLOW_RUN_TOKEN", "")
	db := dbForEventPublishTest(t)
	defer db.Close()
	cleanEventLogForPublishTest(t, db)

	h := newEventPublishServer(db)
	body := validMutationBody("ensure_customer_acme_happy")
	w := doPublish(t, h, body, nil)

	if w.Code != http.StatusCreated {
		t.Fatalf("status: got %d, want %d (body=%s)", w.Code, http.StatusCreated, w.Body.String())
	}

	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if id, _ := resp["event_id"].(string); id == "" {
		t.Fatalf("response missing event_id: %s", w.Body.String())
	}
	matRaw, ok := resp["materialized_reactions"]
	if !ok {
		t.Fatalf("response missing materialized_reactions: %s", w.Body.String())
	}
	// JSON decodes numbers as float64 by default.
	if mat, ok := matRaw.(float64); !ok || mat < 0 {
		t.Fatalf("materialized_reactions: got %v (%T), want non-negative number", matRaw, matRaw)
	}

	var count int
	if err := db.QueryRowContext(context.Background(),
		`SELECT COUNT(*) FROM public.event_log WHERE type = $1`,
		"stripe.customer.ensured").Scan(&count); err != nil {
		t.Fatalf("count: %v", err)
	}
	if count != 1 {
		t.Errorf("expected 1 row for stripe.customer.ensured, got %d", count)
	}
}

// TestHandleEventPublish_Mutation_IdempotencyReturns200WithSameID posts the
// same event_type+idempotency twice. The second call MUST return 200 (not
// 201) and the same event_id, and event_log MUST hold exactly one row.
// This is the §6.5 contract: adapters can retry safely on transient
// failures.
func TestHandleEventPublish_Mutation_IdempotencyReturns200WithSameID(t *testing.T) {
	t.Setenv("YGGDRASIL_WORKFLOW_RUN_TOKEN", "")
	db := dbForEventPublishTest(t)
	defer db.Close()
	cleanEventLogForPublishTest(t, db)

	h := newEventPublishServer(db)
	body := validMutationBody("ensure_customer_acme_dedup")

	w1 := doPublish(t, h, body, nil)
	if w1.Code != http.StatusCreated {
		t.Fatalf("first post status: got %d, want 201 (body=%s)", w1.Code, w1.Body.String())
	}
	var first map[string]any
	_ = json.Unmarshal(w1.Body.Bytes(), &first)
	firstID, _ := first["event_id"].(string)
	if firstID == "" {
		t.Fatalf("first post missing event_id: %s", w1.Body.String())
	}

	w2 := doPublish(t, h, body, nil)
	if w2.Code != http.StatusOK {
		t.Fatalf("second post status: got %d, want 200 (body=%s)", w2.Code, w2.Body.String())
	}
	var second map[string]any
	_ = json.Unmarshal(w2.Body.Bytes(), &second)
	secondID, _ := second["event_id"].(string)
	if secondID != firstID {
		t.Fatalf("second post event_id: got %s, want %s (dedup hit)", secondID, firstID)
	}
	if deduped, _ := second["deduped"].(bool); !deduped {
		t.Errorf("second post must carry deduped:true; got %v", second["deduped"])
	}

	var count int
	if err := db.QueryRowContext(context.Background(),
		`SELECT COUNT(*) FROM public.event_log WHERE idempotency_key = $1 AND type = $2`,
		"ensure_customer_acme_dedup", "stripe.customer.ensured").Scan(&count); err != nil {
		t.Fatalf("count: %v", err)
	}
	if count != 1 {
		t.Errorf("expected 1 deduped row, got %d", count)
	}
}

// TestHandleEventPublish_Mutation_RejectsNonConformantEventType locks in
// the regex validation. The handler MUST reject types that don't match
// <provider>.<resource>.<verb_past> with a 400 — Phase 2 hard-fail per
// the contract.
func TestHandleEventPublish_Mutation_RejectsNonConformantEventType(t *testing.T) {
	t.Setenv("YGGDRASIL_WORKFLOW_RUN_TOKEN", "")
	db := dbForEventPublishTest(t)
	defer db.Close()
	cleanEventLogForPublishTest(t, db)

	h := newEventPublishServer(db)
	bad := []string{
		"stripe.customer.updated",         // unknown verb
		"Stripe.customer.ensured",         // uppercase
		"stripe.customer",                 // missing verb
		"stripe.customer.profile.ensured", // four segments
		"stripe.customer-id.ensured",      // hyphen
	}
	for _, et := range bad {
		t.Run(et, func(t *testing.T) {
			body := validMutationBody("ignored")
			body["event_type"] = et
			// Keep `verb` aligned to avoid a verb-mismatch contradiction
			// from a different validator — we want the regex to be the
			// failing step here.
			body["verb"] = "ensured"
			w := doPublish(t, h, body, nil)
			if w.Code != http.StatusBadRequest {
				t.Fatalf("status: got %d, want 400 (body=%s)", w.Code, w.Body.String())
			}
			if !strings.Contains(strings.ToLower(w.Body.String()), "event_type") {
				t.Errorf("error body should mention event_type: %s", w.Body.String())
			}
		})
	}
}

// TestHandleEventPublish_Mutation_RequiresIdempotency asserts the mutation
// endpoint refuses requests missing the idempotency key. §6.5 calls it
// the dedup key and SDK v0.6.0 always supplies it; refusing here keeps
// the audit trail safe from non-conforming adapters.
func TestHandleEventPublish_Mutation_RequiresIdempotency(t *testing.T) {
	t.Setenv("YGGDRASIL_WORKFLOW_RUN_TOKEN", "")
	db := dbForEventPublishTest(t)
	defer db.Close()
	cleanEventLogForPublishTest(t, db)

	h := newEventPublishServer(db)
	body := validMutationBody("")
	delete(body, "idempotency")
	w := doPublish(t, h, body, nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status: got %d, want 400 (body=%s)", w.Code, w.Body.String())
	}
	if !strings.Contains(strings.ToLower(w.Body.String()), "idempotency") {
		t.Errorf("error body should mention idempotency: %s", w.Body.String())
	}
}

// TestHandleEventPublish_Mutation_ValidationErrors covers the per-field
// 400s for missing required §6.5 fields. The handler must surface a clear
// fragment for each so adapter authors can diagnose without grepping
// schema errors.
func TestHandleEventPublish_Mutation_ValidationErrors(t *testing.T) {
	t.Setenv("YGGDRASIL_WORKFLOW_RUN_TOKEN", "")
	db := dbForEventPublishTest(t)
	defer db.Close()
	cleanEventLogForPublishTest(t, db)

	h := newEventPublishServer(db)
	cases := []struct {
		name        string
		mutate      func(map[string]any)
		errFragment string
	}{
		{"missing provider", func(m map[string]any) { delete(m, "provider") }, "provider"},
		{"missing resource", func(m map[string]any) { delete(m, "resource") }, "resource"},
		{"missing verb", func(m map[string]any) { delete(m, "verb") }, "verb"},
		{"missing resource_id", func(m map[string]any) { delete(m, "resource_id") }, "resource_id"},
		{"missing instance_id", func(m map[string]any) { delete(m, "instance_id") }, "instance_id"},
		{"empty event_type", func(m map[string]any) { m["event_type"] = "" }, "event_type"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			body := validMutationBody("ignored-for-validation")
			tc.mutate(body)
			w := doPublish(t, h, body, nil)
			if w.Code != http.StatusBadRequest {
				t.Fatalf("status: got %d, want 400 (body=%s)", w.Code, w.Body.String())
			}
			if !strings.Contains(strings.ToLower(w.Body.String()), tc.errFragment) {
				t.Errorf("error body missing %q: %s", tc.errFragment, w.Body.String())
			}
		})
	}
}

// TestHandleEventPublish_Mutation_GenericShapeStillAccepted is a regression
// test — the existing generic event shape (manifest.created etc.) must
// keep working unchanged after the mutation shape is added.
func TestHandleEventPublish_Mutation_GenericShapeStillAccepted(t *testing.T) {
	t.Setenv("YGGDRASIL_WORKFLOW_RUN_TOKEN", "")
	db := dbForEventPublishTest(t)
	defer db.Close()
	cleanEventLogForPublishTest(t, db)

	h := newEventPublishServer(db)
	body := map[string]any{
		"type":           "manifest.created",
		"schema_version": "v1",
		"aggregate_type": "manifest",
		"aggregate_id":   "018f2b4a-1234-7abc-def0-1234567890aa",
		"payload":        validManifestCreatedPayloadForPublish(),
	}
	w := doPublish(t, h, body, nil)
	if w.Code != http.StatusCreated {
		t.Fatalf("generic shape regression: got %d, want 201 (body=%s)", w.Code, w.Body.String())
	}
}
