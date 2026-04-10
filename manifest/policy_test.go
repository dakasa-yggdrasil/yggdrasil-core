package manifest

import (
	"encoding/json"
	"testing"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

func TestValidatePolicySpec(t *testing.T) {
	spec := model.PolicyManifestSpec{
		Rules: []model.PolicyRule{
			{
				Name:      "finance-limit",
				Effect:    "allow",
				Resources: []string{"thirdparty.gcp.project.yggdrasil.secret.*"},
				Actions:   []string{"read"},
				Conditions: []model.PolicyCondition{
					{Key: "subject.department", Operator: "eq", Value: "finance"},
				},
			},
		},
	}

	if err := ValidatePolicySpec(spec); err != nil {
		t.Fatalf("ValidatePolicySpec error: %v", err)
	}
}

func TestEvaluatePolicyAllow(t *testing.T) {
	spec := model.PolicyManifestSpec{
		Rules: []model.PolicyRule{
			{
				Name:      "deploy-budget",
				Effect:    "allow",
				Resources: []string{"core.project.yggdrasil.deployment.*"},
				Actions:   []string{"approve"},
				Conditions: []model.PolicyCondition{
					{Key: "context.amount", Operator: "lte", Value: 10000},
					{Key: "subject.department", Operator: "eq", Value: "finance"},
				},
			},
		},
	}

	allowed, decision, matches, err := EvaluatePolicy(spec, "core.project.yggdrasil.deployment.api", "approve", map[string]any{
		"context": map[string]any{"amount": 9500},
		"subject": map[string]any{"department": "finance"},
	})
	if err != nil {
		t.Fatalf("EvaluatePolicy error: %v", err)
	}
	if !allowed || decision != "allow" {
		t.Fatalf("unexpected decision: allowed=%v decision=%s", allowed, decision)
	}
	if len(matches) != 1 || matches[0].Name != "deploy-budget" {
		t.Fatalf("unexpected matches: %#v", matches)
	}
}

func TestEvaluatePolicyDenyPrecedence(t *testing.T) {
	spec := model.PolicyManifestSpec{
		Rules: []model.PolicyRule{
			{
				Name:      "allow-finance",
				Effect:    "allow",
				Resources: []string{"payment.*"},
				Actions:   []string{"approve"},
				Conditions: []model.PolicyCondition{
					{Key: "subject.department", Operator: "eq", Value: "finance"},
				},
			},
			{
				Name:      "deny-over-limit",
				Effect:    "deny",
				Resources: []string{"payment.*"},
				Actions:   []string{"approve"},
				Conditions: []model.PolicyCondition{
					{Key: "context.amount", Operator: "gt", Value: 10000},
				},
			},
		},
	}

	allowed, decision, matches, err := EvaluatePolicy(spec, "payment.invoice", "approve", map[string]any{
		"context": map[string]any{"amount": 15000},
		"subject": map[string]any{"department": "finance"},
	})
	if err != nil {
		t.Fatalf("EvaluatePolicy error: %v", err)
	}
	if allowed || decision != "deny" {
		t.Fatalf("unexpected decision: allowed=%v decision=%s", allowed, decision)
	}
	if len(matches) != 2 {
		t.Fatalf("expected both matching rules, got %#v", matches)
	}
}

func TestPolicyDocumentValidation(t *testing.T) {
	raw, err := json.Marshal(model.PolicyManifestSpec{
		Rules: []model.PolicyRule{
			{
				Name:      "owner-only",
				Effect:    "allow",
				Resources: []string{"core.collaborator.profile"},
				Actions:   []string{"update"},
				Conditions: []model.PolicyCondition{
					{Key: "subject.id", Operator: "eq", Value: map[string]any{"$ref": "resource.owner_id"}},
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("json.Marshal error: %v", err)
	}

	doc := model.ManifestDocument{
		APIVersion: "yggdrasil.io/v1alpha1",
		Kind:       "policy",
		Metadata: model.ManifestMetadataInput{
			Name:      "profile-ownership",
			Namespace: "global",
		},
		Spec: raw,
	}

	if err := ValidateDocument(doc); err != nil {
		t.Fatalf("ValidateDocument(policy) error: %v", err)
	}
}
