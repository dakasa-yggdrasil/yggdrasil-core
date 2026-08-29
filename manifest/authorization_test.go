package manifest

import (
	"testing"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

func TestEvaluateAuthorizationRBACDenyStopsPipeline(t *testing.T) {
	rbacSpec := model.RBACManifestSpec{
		Roles: []model.RBACRole{
			{
				Name: "manifest-reader",
				Rules: []model.RBACRule{
					{
						Effect:    "allow",
						Resources: []string{"manifest.*"},
						Actions:   []string{"read"},
					},
				},
			},
		},
		Bindings: []model.RBACBinding{
			{
				Name: "platform",
				Subjects: []model.RBACSubject{
					{Type: "team", ID: "platform"},
				},
				Roles: []string{"manifest-reader"},
			},
		},
	}

	policySpec := &model.PolicyManifestSpec{
		Rules: []model.PolicyRule{
			{
				Name:      "allow-deletes-for-finance",
				Effect:    "allow",
				Resources: []string{"manifest.*"},
				Actions:   []string{"delete"},
				Conditions: []model.PolicyCondition{
					{Key: "subject.department", Operator: "eq", Value: "finance"},
				},
			},
		},
	}

	response, err := EvaluateAuthorization(
		rbacSpec,
		policySpec,
		model.RBACSubject{Type: "team", ID: "platform"},
		"manifest.rbac",
		"delete",
		map[string]any{
			"subject": map[string]any{"department": "finance"},
		},
	)
	if err != nil {
		t.Fatalf("EvaluateAuthorization error: %v", err)
	}
	if response.Allowed || response.Decision != "deny" {
		t.Fatalf("unexpected decision: %#v", response)
	}
	if response.Policy != nil {
		t.Fatalf("policy should not run when rbac denies: %#v", response.Policy)
	}
}

func TestEvaluateAuthorizationPolicyDenyOverridesRBACAllow(t *testing.T) {
	rbacSpec := model.RBACManifestSpec{
		Roles: []model.RBACRole{
			{
				Name: "payment-approver",
				Rules: []model.RBACRule{
					{
						Effect:    "allow",
						Resources: []string{"payment.*"},
						Actions:   []string{"approve"},
					},
				},
			},
		},
		Bindings: []model.RBACBinding{
			{
				Name: "finance-collaborators",
				Subjects: []model.RBACSubject{
					{Type: "collaborator", ID: "ana"},
				},
				Roles: []string{"payment-approver"},
			},
		},
	}

	policySpec := &model.PolicyManifestSpec{
		Rules: []model.PolicyRule{
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

	response, err := EvaluateAuthorization(
		rbacSpec,
		policySpec,
		model.RBACSubject{Type: "collaborator", ID: "ana"},
		"payment.invoice",
		"approve",
		map[string]any{
			"context": map[string]any{"amount": 15000},
			"subject": map[string]any{"department": "finance"},
		},
	)
	if err != nil {
		t.Fatalf("EvaluateAuthorization error: %v", err)
	}
	if response.Allowed || response.Decision != "deny" {
		t.Fatalf("unexpected decision: %#v", response)
	}
	if response.Policy == nil || response.Policy.Decision != "deny" {
		t.Fatalf("expected policy deny, got %#v", response.Policy)
	}
}

func TestEvaluateAuthorizationPolicyNotApplicablePreservesRBACAllow(t *testing.T) {
	rbacSpec := model.RBACManifestSpec{
		Roles: []model.RBACRole{
			{
				Name: "profile-editor",
				Rules: []model.RBACRule{
					{
						Effect:    "allow",
						Resources: []string{"core.collaborator.profile"},
						Actions:   []string{"update"},
					},
				},
			},
		},
		Bindings: []model.RBACBinding{
			{
				Name: "self-service",
				Subjects: []model.RBACSubject{
					{Type: "collaborator", ID: "ana"},
				},
				Roles: []string{"profile-editor"},
			},
		},
	}

	policySpec := &model.PolicyManifestSpec{
		Rules: []model.PolicyRule{
			{
				Name:      "owner-only",
				Effect:    "allow",
				Resources: []string{"core.collaborator.profile"},
				Actions:   []string{"update"},
				Conditions: []model.PolicyCondition{
					{Key: "resource.owner_id", Operator: "eq", Value: "col:ana"},
				},
			},
		},
	}

	response, err := EvaluateAuthorization(
		rbacSpec,
		policySpec,
		model.RBACSubject{Type: "collaborator", ID: "ana"},
		"core.collaborator.profile",
		"update",
		nil,
	)
	if err != nil {
		t.Fatalf("EvaluateAuthorization error: %v", err)
	}
	if !response.Allowed || response.Decision != "allow" {
		t.Fatalf("unexpected decision: %#v", response)
	}
	if response.Policy == nil || response.Policy.Decision != "not_applicable" {
		t.Fatalf("expected policy not_applicable, got %#v", response.Policy)
	}
}

func TestEvaluateAuthorizationInjectsSubjectIdentityIntoPolicyInput(t *testing.T) {
	rbacSpec := model.RBACManifestSpec{
		Roles: []model.RBACRole{
			{
				Name: "profile-editor",
				Rules: []model.RBACRule{
					{
						Effect:    "allow",
						Resources: []string{"core.collaborator.profile"},
						Actions:   []string{"update"},
					},
				},
			},
		},
		Bindings: []model.RBACBinding{
			{
				Name: "self-service",
				Subjects: []model.RBACSubject{
					{Type: "collaborator", ID: "col:ana"},
				},
				Roles: []string{"profile-editor"},
			},
		},
	}

	policySpec := &model.PolicyManifestSpec{
		Rules: []model.PolicyRule{
			{
				Name:      "subject-must-match",
				Effect:    "allow",
				Resources: []string{"core.collaborator.profile"},
				Actions:   []string{"update"},
				Conditions: []model.PolicyCondition{
					{Key: "subject.id", Operator: "eq", Value: "col:ana"},
				},
			},
		},
	}

	response, err := EvaluateAuthorization(
		rbacSpec,
		policySpec,
		model.RBACSubject{Type: "collaborator", ID: "col:ana"},
		"core.collaborator.profile",
		"update",
		map[string]any{},
	)
	if err != nil {
		t.Fatalf("EvaluateAuthorization error: %v", err)
	}
	if !response.Allowed || response.Policy == nil || response.Policy.Decision != "allow" {
		t.Fatalf("unexpected decision: %#v", response)
	}
}

func TestEvaluateAuthorizationSubjectsResolveTeamAccess(t *testing.T) {
	rbacSpec := model.RBACManifestSpec{
		Roles: []model.RBACRole{
			{
				Name: "deployer",
				Rules: []model.RBACRule{
					{
						Effect:    "allow",
						Resources: []string{"deployment.*"},
						Actions:   []string{"trigger"},
					},
				},
			},
		},
		Bindings: []model.RBACBinding{
			{
				Name: "platform-team",
				Subjects: []model.RBACSubject{
					{Type: "team", ID: "team:platform"},
				},
				Roles: []string{"deployer"},
			},
		},
	}

	response, err := EvaluateAuthorizationSubjects(
		rbacSpec,
		nil,
		[]model.RBACSubject{
			{Type: "collaborator", ID: "col:ana"},
			{Type: "team", ID: "team:platform"},
		},
		"deployment.api",
		"trigger",
		nil,
	)
	if err != nil {
		t.Fatalf("EvaluateAuthorizationSubjects error: %v", err)
	}
	if !response.Allowed || response.Decision != "allow" {
		t.Fatalf("unexpected decision: %#v", response)
	}
	if len(response.ResolvedSubjects) != 2 {
		t.Fatalf("expected resolved subjects, got %#v", response.ResolvedSubjects)
	}
}

func TestAuthorizationPolicyInputExposesCanonicalInputNamespace(t *testing.T) {
	got := authorizationPolicyInput(
		[]model.RBACSubject{{Type: "service", ID: "cd-bot"}},
		map[string]any{"environment": "validation"},
	)
	nested, ok := got["input"].(map[string]any)
	if !ok {
		t.Fatalf("input namespace missing: %#v", got)
	}
	if nested["environment"] != "validation" {
		t.Fatalf("input.environment mismatch: %#v", nested)
	}
	if got["environment"] != "validation" {
		t.Fatalf("historical flat key must remain available: %#v", got)
	}
}

func TestEvaluateAuthorizationDeniesScopedServiceOutsideValidation(t *testing.T) {
	rbac := model.RBACManifestSpec{
		Roles: []model.RBACRole{{
			Name:  "cd-dispatcher",
			Rules: []model.RBACRule{{Effect: "allow", Resources: []string{"workflow:dakasa:dakasa-deploy-component"}, Actions: []string{"run"}}},
		}},
		Bindings: []model.RBACBinding{{
			Name: "cd-bot", Subjects: []model.RBACSubject{{Type: "service", ID: "github-actions-cd-bot"}}, Roles: []string{"cd-dispatcher"},
		}},
	}
	policy := &model.PolicyManifestSpec{Rules: []model.PolicyRule{
		{
			Name: "allow-validation", Effect: "allow", Resources: []string{"workflow:dakasa:dakasa-deploy-component"}, Actions: []string{"run"},
			Conditions: []model.PolicyCondition{{Key: "input.environment", Operator: "eq", Value: "validation"}},
		},
		{
			Name: "deny-outside-validation", Effect: "deny", Resources: []string{"workflow:dakasa:dakasa-deploy-component"}, Actions: []string{"run"},
			Conditions: []model.PolicyCondition{
				{Key: "subject.id", Operator: "eq", Value: "github-actions-cd-bot"},
				{Key: "input.environment", Operator: "neq", Value: "validation"},
			},
		},
	}}
	subject := model.RBACSubject{Type: "service", ID: "github-actions-cd-bot"}

	allowed, err := EvaluateAuthorization(rbac, policy, subject, "workflow:dakasa:dakasa-deploy-component", "run", map[string]any{"environment": "validation"})
	if err != nil || !allowed.Allowed {
		t.Fatalf("validation dispatch should be allowed: response=%#v err=%v", allowed, err)
	}
	denied, err := EvaluateAuthorization(rbac, policy, subject, "workflow:dakasa:dakasa-deploy-component", "run", map[string]any{"environment": "production"})
	if err != nil {
		t.Fatal(err)
	}
	if denied.Allowed || denied.Decision != "deny" {
		t.Fatalf("production dispatch must be denied: %#v", denied)
	}
}
