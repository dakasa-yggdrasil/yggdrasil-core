package contracts

import (
	"strings"
	"testing"
)

func TestValidateEventPayload_ManifestCreated_Valid(t *testing.T) {
	payload := map[string]interface{}{
		"manifest_id": "018f2b4a-1234-7abc-def0-123456789012",
		"kind":        "product",
		"namespace":   "dakasa",
		"name":        "dakasa-app",
		"version":     1,
		"checksum":    "sha256:abc123def456abc123def456abc123def456abc123def456abc123def456abc1",
	}
	if err := ValidateEventPayload("manifest.created", "v1", payload); err != nil {
		t.Fatalf("expected valid payload, got error: %v", err)
	}
}

func TestValidateEventPayload_ManifestCreated_MissingRequired(t *testing.T) {
	payload := map[string]interface{}{
		"manifest_id": "018f2b4a-1234-7abc-def0-123456789012",
		// missing kind, namespace, name, version, checksum
	}
	err := ValidateEventPayload("manifest.created", "v1", payload)
	if err == nil {
		t.Fatal("expected validation error for missing required fields")
	}
	if !strings.Contains(err.Error(), "manifest.created") {
		t.Errorf("error should mention event type: %v", err)
	}
}

func TestValidateEventPayload_ManifestCreated_InvalidKind(t *testing.T) {
	payload := map[string]interface{}{
		"manifest_id": "018f2b4a-1234-7abc-def0-123456789012",
		"kind":        "not_a_valid_kind",
		"namespace":   "dakasa",
		"name":        "dakasa-app",
		"version":     1,
		"checksum":    "sha256:abc123def456abc123def456abc123def456abc123def456abc123def456abc1",
	}
	err := ValidateEventPayload("manifest.created", "v1", payload)
	if err == nil {
		t.Fatal("expected error for invalid kind enum")
	}
}

func TestValidateEventPayload_AuthorizationEvaluated_Valid(t *testing.T) {
	payload := map[string]interface{}{
		"collaborator_id": "alice",
		"resource":        "products/dakasa-app",
		"action":          "apply",
		"decision":        "allow",
		"matched_roles":   []interface{}{"dakasa-deployer"},
		"matched_rules":   []interface{}{"allow-deploy"},
	}
	if err := ValidateEventPayload("authorization.evaluated", "v1", payload); err != nil {
		t.Fatalf("expected valid payload, got error: %v", err)
	}
}

func TestValidateEventPayload_UnknownType(t *testing.T) {
	payload := map[string]interface{}{"foo": "bar"}
	err := ValidateEventPayload("unknown.event.type", "v1", payload)
	if err == nil {
		t.Fatal("expected error for unknown event type")
	}
	if !strings.Contains(err.Error(), "no schema registered") {
		t.Errorf("error should mention missing schema: %v", err)
	}
}

func TestValidateEventPayload_EmptyType(t *testing.T) {
	payload := map[string]interface{}{"foo": "bar"}
	err := ValidateEventPayload("", "v1", payload)
	if err == nil {
		t.Fatal("expected error for empty event type")
	}
}

func TestValidateEventPayload_ProductInstallationApplied_Valid(t *testing.T) {
	payload := map[string]interface{}{
		"product_ref": map[string]interface{}{
			"name":      "dakasa-app",
			"namespace": "dakasa",
		},
		"components_applied": []interface{}{
			map[string]interface{}{
				"name": "identities",
				"target": map[string]interface{}{
					"kind": "kubernetes",
				},
			},
		},
	}
	if err := ValidateEventPayload("product.installation.applied", "v1", payload); err != nil {
		t.Fatalf("expected valid payload, got error: %v", err)
	}
}

func TestValidateEventPayload_WorkflowRunCompleted_Valid(t *testing.T) {
	payload := map[string]interface{}{
		"workflow_ref": map[string]interface{}{
			"name":      "deploy-dakasa",
			"namespace": "dakasa",
		},
		"run_id":      "018f2b4a-1234-7abc-def0-123456789012",
		"status":      "succeeded",
		"started_at":  "2026-04-10T12:00:00Z",
		"finished_at": "2026-04-10T12:05:00Z",
	}
	if err := ValidateEventPayload("workflow.run.completed", "v1", payload); err != nil {
		t.Fatalf("expected valid payload, got error: %v", err)
	}
}

// TestValidateEventPayload_CollaboratorSessionTerminated_Valid covers the
// §13 INTEGRATION_CONTRACT canon event. Required fields are
// collaborator_id + reason; everything else is optional context.
func TestValidateEventPayload_CollaboratorSessionTerminated_Valid(t *testing.T) {
	payload := map[string]interface{}{
		"collaborator_id": "018f2b4a-1234-7abc-def0-123456789012",
		"primary_email":   "user@example.com",
		"session_id":      "00000000-0000-0000-0000-000000000001",
		"reason":          "logout",
		"revocation_id":   "00000000-0000-0000-0000-000000000002",
		"emitted_at":      "2026-05-27T12:00:00Z",
	}
	if err := ValidateEventPayload("collaborator.session.terminated", "v1", payload); err != nil {
		t.Fatalf("expected valid payload, got error: %v", err)
	}
}

func TestValidateEventPayload_CollaboratorSessionTerminated_InvalidReason(t *testing.T) {
	payload := map[string]interface{}{
		"collaborator_id": "018f2b4a-1234-7abc-def0-123456789012",
		"reason":          "not_a_reason",
	}
	err := ValidateEventPayload("collaborator.session.terminated", "v1", payload)
	if err == nil {
		t.Fatal("expected validation error for unknown reason value")
	}
}
