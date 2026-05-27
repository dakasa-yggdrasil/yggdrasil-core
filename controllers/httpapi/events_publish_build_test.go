package httpapi

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestBuildEmitEventRequestFromMutation_HappyPath exercises the §6.5 → generic
// translation. It runs without DB so the validation logic is covered in
// every `go test` invocation, not only under integration runs.
func TestBuildEmitEventRequestFromMutation_HappyPath(t *testing.T) {
	req := eventPublishRequest{
		EventType:   "stripe.customer.ensured",
		Provider:    "stripe",
		Resource:    "customer",
		Verb:        "ensured",
		ResourceID:  "cus_1234abc",
		InstanceID:  "stripe-acme",
		Idempotency: "ensure_customer_acme_abc",
		Observed:    map[string]any{"id": "cus_1234abc", "email": "acme@example.com"},
		EmittedAt:   "2026-05-27T10:30:00Z",
	}
	got, err := buildEmitEventRequestFromPublish(req)
	if err != nil {
		t.Fatalf("buildEmitEventRequestFromPublish: %v", err)
	}
	if got.Type != "stripe.customer.ensured" {
		t.Errorf("Type: got %q, want stripe.customer.ensured", got.Type)
	}
	if got.SchemaVersion != "v1" {
		t.Errorf("SchemaVersion: got %q, want v1", got.SchemaVersion)
	}
	if got.AggregateType != "stripe_customer" {
		t.Errorf("AggregateType: got %q, want stripe_customer", got.AggregateType)
	}
	if got.AggregateID != "cus_1234abc" {
		t.Errorf("AggregateID: got %q, want cus_1234abc", got.AggregateID)
	}
	if got.IdempotencyKey != "ensure_customer_acme_abc" {
		t.Errorf("IdempotencyKey: got %q", got.IdempotencyKey)
	}
	for _, k := range []string{"provider", "resource", "verb", "resource_id", "instance_id"} {
		if _, ok := got.Payload[k]; !ok {
			t.Errorf("Payload missing %q", k)
		}
	}
	if got.Payload["observed"] == nil {
		t.Error("Payload.observed should be set")
	}
	if got.Payload["emitted_at"] != "2026-05-27T10:30:00Z" {
		t.Errorf("Payload.emitted_at: got %v", got.Payload["emitted_at"])
	}
	if got.Metadata["source"] != "integration_mutation" {
		t.Errorf("Metadata.source: got %v", got.Metadata["source"])
	}
}

// TestBuildEmitEventRequestFromMutation_RegexValidation locks the regex
// gate. Non-conformant event_types are rejected with a 400-ready error.
func TestBuildEmitEventRequestFromMutation_RegexValidation(t *testing.T) {
	cases := []string{
		"stripe.customer.updated",
		"Stripe.customer.ensured",
		"stripe.customer",
		"stripe.customer.profile.ensured",
		"stripe.customer-id.ensured",
		"1stripe.customer.ensured",
	}
	for _, et := range cases {
		t.Run(et, func(t *testing.T) {
			_, err := buildEmitEventRequestFromPublish(eventPublishRequest{
				EventType:   et,
				Provider:    "stripe",
				Resource:    "customer",
				Verb:        "ensured",
				ResourceID:  "cus_1",
				InstanceID:  "stripe-acme",
				Idempotency: "x",
			})
			if err == nil {
				t.Fatalf("expected validation error for event_type=%q", et)
			}
			if !strings.Contains(strings.ToLower(err.Error()), "event_type") {
				t.Errorf("error should mention event_type: %v", err)
			}
		})
	}
}

// TestBuildEmitEventRequestFromMutation_RequiredFields covers each missing
// field branch. The error message must mention the missing field name so
// adapter authors can fix without reading source.
func TestBuildEmitEventRequestFromMutation_RequiredFields(t *testing.T) {
	good := func() eventPublishRequest {
		return eventPublishRequest{
			EventType:   "stripe.customer.ensured",
			Provider:    "stripe",
			Resource:    "customer",
			Verb:        "ensured",
			ResourceID:  "cus_1",
			InstanceID:  "stripe-acme",
			Idempotency: "x",
		}
	}
	cases := []struct {
		name        string
		mutate      func(*eventPublishRequest)
		errFragment string
	}{
		{"empty event_type", func(r *eventPublishRequest) { r.EventType = "" }, "event_type"},
		{"empty provider", func(r *eventPublishRequest) { r.Provider = "" }, "provider"},
		{"empty resource", func(r *eventPublishRequest) { r.Resource = "" }, "resource"},
		{"empty verb", func(r *eventPublishRequest) { r.Verb = "" }, "verb"},
		{"empty resource_id", func(r *eventPublishRequest) { r.ResourceID = "" }, "resource_id"},
		{"empty instance_id", func(r *eventPublishRequest) { r.InstanceID = "" }, "instance_id"},
		{"empty idempotency", func(r *eventPublishRequest) { r.Idempotency = "" }, "idempotency"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := good()
			tc.mutate(&r)
			// Empty event_type forces the dispatcher to fall through to the
			// generic-shape path, which expects `type`. So for that case
			// the failure surfaces as "type is required" which doesn't
			// mention event_type. Skip the fragment check there but still
			// require an error.
			_, err := buildEmitEventRequestFromPublish(r)
			if err == nil {
				t.Fatalf("expected error for %s", tc.name)
			}
			if tc.name == "empty event_type" {
				return
			}
			if !strings.Contains(strings.ToLower(err.Error()), tc.errFragment) {
				t.Errorf("error missing %q: %v", tc.errFragment, err)
			}
		})
	}
}

// TestBuildEmitEventRequestFromMutation_CrossCheck ensures the
// provider/resource/verb fields agree with the event_type triple.
// Otherwise an adapter author mis-fills one field and audit consumers
// see contradictory data.
func TestBuildEmitEventRequestFromMutation_CrossCheck(t *testing.T) {
	base := eventPublishRequest{
		EventType:   "stripe.customer.ensured",
		Provider:    "stripe",
		Resource:    "customer",
		Verb:        "ensured",
		ResourceID:  "cus_1",
		InstanceID:  "stripe-acme",
		Idempotency: "x",
	}

	t.Run("provider mismatch", func(t *testing.T) {
		r := base
		r.Provider = "efi"
		_, err := buildEmitEventRequestFromPublish(r)
		if err == nil || !strings.Contains(strings.ToLower(err.Error()), "provider") {
			t.Fatalf("expected provider-mismatch error, got: %v", err)
		}
	})
	t.Run("resource mismatch", func(t *testing.T) {
		r := base
		r.Resource = "subscription"
		_, err := buildEmitEventRequestFromPublish(r)
		if err == nil || !strings.Contains(strings.ToLower(err.Error()), "resource") {
			t.Fatalf("expected resource-mismatch error, got: %v", err)
		}
	})
	t.Run("verb mismatch", func(t *testing.T) {
		r := base
		r.Verb = "destroyed"
		_, err := buildEmitEventRequestFromPublish(r)
		if err == nil || !strings.Contains(strings.ToLower(err.Error()), "verb") {
			t.Fatalf("expected verb-mismatch error, got: %v", err)
		}
	})
}

// TestBuildEmitEventRequestFromPublish_GenericFallback confirms that the
// existing generic-shape path is unaffected when `event_type` is absent.
// Regression guard for control-plane callers (workflow_event_triggers,
// manifest sync, …).
func TestBuildEmitEventRequestFromPublish_GenericFallback(t *testing.T) {
	rawPayload, _ := json.Marshal(map[string]any{
		"manifest_id": "018f2b4a-1234-7abc-def0-123456789012",
		"kind":        "product",
		"namespace":   "dakasa",
		"name":        "service-a",
		"version":     1,
		"checksum":    "sha256:abc123def456abc123def456abc123def456abc123def456abc123def456abc1",
	})
	r := eventPublishRequest{
		Type:          "manifest.created",
		AggregateType: "manifest",
		AggregateID:   "018f2b4a-1234-7abc-def0-123456789012",
		Payload:       rawPayload,
	}
	got, err := buildEmitEventRequestFromPublish(r)
	if err != nil {
		t.Fatalf("generic fallback errored: %v", err)
	}
	if got.Type != "manifest.created" {
		t.Errorf("Type: got %q", got.Type)
	}
	if got.IdempotencyKey != "" {
		t.Errorf("IdempotencyKey should be empty for generic shape; got %q", got.IdempotencyKey)
	}
}
