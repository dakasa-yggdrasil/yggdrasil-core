package manifest

import (
	"testing"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

func TestEvaluateRBACAllow(t *testing.T) {
	spec := model.RBACManifestSpec{
		Roles: []model.RBACRole{
			{
				Name: "core-admin",
				Rules: []model.RBACRule{
					{
						Resources: []string{"manifest.*"},
						Actions:   []string{"write", "read"},
					},
				},
			},
		},
		Bindings: []model.RBACBinding{
			{
				Name: "platform-admins",
				Subjects: []model.RBACSubject{
					{Type: "collaborator", ID: "giovanni"},
				},
				Roles: []string{"core-admin"},
			},
		},
	}

	allowed, roles, matches, err := EvaluateRBAC(spec, model.RBACSubject{Type: "collaborator", ID: "giovanni"}, "manifest.rbac", "write")
	if err != nil {
		t.Fatalf("EvaluateRBAC error: %v", err)
	}
	if !allowed {
		t.Fatal("expected access to be allowed")
	}
	if len(roles) != 1 || roles[0] != "core-admin" {
		t.Fatalf("unexpected roles: %#v", roles)
	}
	if len(matches) != 1 || matches[0].Effect != "allow" {
		t.Fatalf("unexpected rule matches: %#v", matches)
	}
}

func TestEvaluateRBACDenyTakesPrecedence(t *testing.T) {
	spec := model.RBACManifestSpec{
		Roles: []model.RBACRole{
			{
				Name: "manifest-operator",
				Rules: []model.RBACRule{
					{
						Effect:    "allow",
						Resources: []string{"manifest.*"},
						Actions:   []string{"*"},
					},
					{
						Effect:    "deny",
						Resources: []string{"manifest.rbac"},
						Actions:   []string{"delete"},
					},
				},
			},
		},
		Bindings: []model.RBACBinding{
			{
				Name: "operators",
				Subjects: []model.RBACSubject{
					{Type: "team", ID: "platform"},
				},
				Roles: []string{"manifest-operator"},
			},
		},
	}

	allowed, _, matches, err := EvaluateRBAC(spec, model.RBACSubject{Type: "team", ID: "platform"}, "manifest.rbac", "delete")
	if err != nil {
		t.Fatalf("EvaluateRBAC error: %v", err)
	}
	if allowed {
		t.Fatal("expected access to be denied")
	}
	if len(matches) != 2 {
		t.Fatalf("expected both matching rules to be returned, got %#v", matches)
	}
}

func TestEvaluateRBACSubjectsAllowViaTeam(t *testing.T) {
	spec := model.RBACManifestSpec{
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

	allowed, roles, matches, err := EvaluateRBACSubjects(
		spec,
		[]model.RBACSubject{
			{Type: "collaborator", ID: "col:ana"},
			{Type: "team", ID: "team:platform"},
		},
		"deployment.api",
		"trigger",
	)
	if err != nil {
		t.Fatalf("EvaluateRBACSubjects error: %v", err)
	}
	if !allowed {
		t.Fatal("expected access to be allowed via team subject")
	}
	if len(roles) != 1 || roles[0] != "deployer" {
		t.Fatalf("unexpected roles: %#v", roles)
	}
	if len(matches) != 1 || matches[0].Role != "deployer" {
		t.Fatalf("unexpected rule matches: %#v", matches)
	}
}
