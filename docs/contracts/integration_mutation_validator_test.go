package contracts

import (
	"strings"
	"testing"
)

// TestValidateEventPayload_IntegrationMutationEnsured_Valid confirms that
// payloads emitted by adapters under the §6.5 grammar route through the
// shared `events/v1/integration_mutation/ensured.json` schema regardless
// of which provider/resource fired the event.
func TestValidateEventPayload_IntegrationMutationEnsured_Valid(t *testing.T) {
	payload := map[string]interface{}{
		"provider":    "stripe",
		"resource":    "customer",
		"verb":        "ensured",
		"resource_id": "cus_1234abc",
		"instance_id": "stripe-acme",
		"observed":    map[string]interface{}{"id": "cus_1234abc", "email": "acme@example.com"},
		"emitted_at":  "2026-05-27T10:30:00Z",
	}
	if err := ValidateEventPayload("stripe.customer.ensured", "v1", payload); err != nil {
		t.Fatalf("expected valid payload, got error: %v", err)
	}
}

// TestValidateEventPayload_IntegrationMutationDestroyed_Valid mirrors the
// ensured case but exercises the `destroyed` branch — observed is optional
// because the resource may no longer be readable post-destroy.
func TestValidateEventPayload_IntegrationMutationDestroyed_Valid(t *testing.T) {
	payload := map[string]interface{}{
		"provider":    "efi",
		"resource":    "charge",
		"verb":        "destroyed",
		"resource_id": "chg_42",
		"instance_id": "efi-prod",
		"emitted_at":  "2026-05-27T10:31:00Z",
	}
	if err := ValidateEventPayload("efi.charge.destroyed", "v1", payload); err != nil {
		t.Fatalf("expected valid payload, got error: %v", err)
	}
}

// TestValidateEventPayload_IntegrationMutationCreated_Valid confirms the
// money-movement branch (allowlist actions like create_payout) routes to
// the `created` schema.
func TestValidateEventPayload_IntegrationMutationCreated_Valid(t *testing.T) {
	payload := map[string]interface{}{
		"provider":    "stripe",
		"resource":    "refund",
		"verb":        "created",
		"resource_id": "re_xyz",
		"instance_id": "stripe-acme",
		"observed":    map[string]interface{}{"id": "re_xyz", "amount": 1000},
		"emitted_at":  "2026-05-27T10:32:00Z",
	}
	if err := ValidateEventPayload("stripe.refund.created", "v1", payload); err != nil {
		t.Fatalf("expected valid payload, got error: %v", err)
	}
}

// TestValidateEventPayload_IntegrationMutation_MissingRequired triggers
// the required-field branch on the shared schema. We expect the per-event
// diagnostic to include the event type so adapter authors can find the
// offending emission quickly.
func TestValidateEventPayload_IntegrationMutation_MissingRequired(t *testing.T) {
	payload := map[string]interface{}{
		"provider": "stripe",
		// missing resource, verb, resource_id, instance_id
	}
	err := ValidateEventPayload("stripe.customer.ensured", "v1", payload)
	if err == nil {
		t.Fatal("expected validation error for missing required fields")
	}
	if !strings.Contains(err.Error(), "stripe.customer.ensured") {
		t.Errorf("error should mention event type: %v", err)
	}
}

// TestValidateEventPayload_IntegrationMutation_VerbMismatch ensures the
// verb field embedded in the payload must match the event type's verb
// (otherwise audit consumers see contradictory data).
func TestValidateEventPayload_IntegrationMutation_VerbMismatch(t *testing.T) {
	payload := map[string]interface{}{
		"provider":    "stripe",
		"resource":    "customer",
		"verb":        "destroyed", // wrong — event type says ensured
		"resource_id": "cus_1234abc",
		"instance_id": "stripe-acme",
	}
	err := ValidateEventPayload("stripe.customer.ensured", "v1", payload)
	if err == nil {
		t.Fatal("expected validation error for verb mismatch (schema const)")
	}
}

// TestValidateEventPayload_IntegrationMutation_BadProviderShape rejects
// payloads where the provider/resource don't match the snake_case shape
// the regex requires.
func TestValidateEventPayload_IntegrationMutation_BadProviderShape(t *testing.T) {
	payload := map[string]interface{}{
		"provider":    "Stripe", // uppercase
		"resource":    "customer",
		"verb":        "ensured",
		"resource_id": "cus_1234abc",
		"instance_id": "stripe-acme",
	}
	err := ValidateEventPayload("stripe.customer.ensured", "v1", payload)
	if err == nil {
		t.Fatal("expected validation error for non-snake-case provider")
	}
}
