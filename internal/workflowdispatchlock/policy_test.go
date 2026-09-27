package workflowdispatchlock

import (
	"errors"
	"strings"
	"testing"
)

func TestParseDispatchLockPolicy(t *testing.T) {
	tests := []struct {
		name      string
		raw       string
		present   bool
		wantError string
		wantLock  bool
	}{
		{name: "unset is off", present: false},
		{name: "explicit off", present: true, raw: `{"mode":"off","allowed_workflows":[]}`},
		{name: "exact enforce", present: true, raw: `{"mode":"enforce","allowed_workflows":[{"namespace":"dakasa","name":"fixed-unlock"}]}`, wantLock: true},
		{name: "blank", present: true, raw: "  ", wantError: "set but blank"},
		{name: "malformed", present: true, raw: `{`, wantError: "parse"},
		{name: "unknown field", present: true, raw: `{"mode":"off","extra":true}`, wantError: "unknown field"},
		{name: "trailing value", present: true, raw: `{"mode":"off"}{}`, wantError: "trailing"},
		{name: "unknown mode", present: true, raw: `{"mode":"open"}`, wantError: "off or enforce"},
		{name: "off with allowlist", present: true, raw: `{"mode":"off","allowed_workflows":[{"namespace":"dakasa","name":"fixed-unlock"}]}`, wantError: "empty"},
		{name: "enforce empty", present: true, raw: `{"mode":"enforce","allowed_workflows":[]}`, wantError: "at least one"},
		{name: "blank namespace", present: true, raw: `{"mode":"enforce","allowed_workflows":[{"namespace":"","name":"fixed-unlock"}]}`, wantError: "requires namespace and name"},
		{name: "surrounding whitespace", present: true, raw: `{"mode":"enforce","allowed_workflows":[{"namespace":"dakasa ","name":"fixed-unlock"}]}`, wantError: "surrounding whitespace"},
		{name: "wildcard", present: true, raw: `{"mode":"enforce","allowed_workflows":[{"namespace":"dakasa","name":"fixed-*"}]}`, wantError: "wildcards"},
		{name: "duplicate", present: true, raw: `{"mode":"enforce","allowed_workflows":[{"namespace":"dakasa","name":"fixed-unlock"},{"namespace":"dakasa","name":"fixed-unlock"}]}`, wantError: "duplicates"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			policy, err := Parse(test.raw, test.present)
			if test.wantError != "" {
				if err == nil || !strings.Contains(err.Error(), test.wantError) {
					t.Fatalf("error = %v, want diagnostic containing %q", err, test.wantError)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got := policy.Enforced(); got != test.wantLock {
				t.Fatalf("Enforced() = %v, want %v", got, test.wantLock)
			}
		})
	}
}

func TestPolicyCheckUsesExactNamespaceAndName(t *testing.T) {
	policy, err := Parse(`{"mode":"enforce","allowed_workflows":[{"namespace":"dakasa","name":"fixed-unlock"}]}`, true)
	if err != nil {
		t.Fatal(err)
	}
	if err := policy.Check("dakasa", "fixed-unlock"); err != nil {
		t.Fatalf("exact workflow refused: %v", err)
	}
	for _, ref := range []WorkflowRef{
		{Namespace: "global", Name: "fixed-unlock"},
		{Namespace: "dakasa", Name: "fixed-unlock-v2"},
		{Namespace: "DaKasa", Name: "fixed-unlock"},
		{Namespace: "dakasa ", Name: "fixed-unlock"},
	} {
		if err := policy.Check(ref.Namespace, ref.Name); !errors.Is(err, ErrLocked) {
			t.Fatalf("%s/%s error = %v, want ErrLocked", ref.Namespace, ref.Name, err)
		}
	}
}

func TestCheckEnvironmentDeniesInvalidConfiguredJSON(t *testing.T) {
	t.Setenv(EnvName, "{")
	if err := CheckEnvironment("dakasa", "fixed-unlock"); !errors.Is(err, ErrLocked) {
		t.Fatalf("error = %v, want ErrLocked", err)
	}
}

func TestCheckUnboundEnvironmentRefusesEveryRequestWhileEnforced(t *testing.T) {
	t.Setenv(EnvName, `{"mode":"enforce","allowed_workflows":[{"namespace":"dakasa","name":"fixed-unlock"}]}`)
	if err := CheckUnboundEnvironment(); !errors.Is(err, ErrLocked) {
		t.Fatalf("error = %v, want ErrLocked", err)
	}
}

func TestCheckRepositoryBindingDispatchEnvironmentRefusesAllowlistedWorkflowIngress(t *testing.T) {
	t.Setenv(EnvName, `{"mode":"enforce","allowed_workflows":[{"namespace":"dakasa","name":"fixed-unlock"}]}`)
	if err := CheckEnvironment("dakasa", "fixed-unlock"); err != nil {
		t.Fatalf("allowlisted workflow check = %v, want nil", err)
	}
	if err := CheckRepositoryBindingDispatchEnvironment(); !errors.Is(err, ErrLocked) {
		t.Fatalf("repository-binding check = %v, want ErrLocked", err)
	}
}

func TestCheckRepositoryBindingDispatchEnvironmentAllowsExplicitOffAndRefusesInvalidPolicy(t *testing.T) {
	t.Setenv(EnvName, `{"mode":"off","allowed_workflows":[]}`)
	if err := CheckRepositoryBindingDispatchEnvironment(); err != nil {
		t.Fatalf("explicit off check = %v, want nil", err)
	}

	t.Setenv(EnvName, `{`)
	if err := CheckRepositoryBindingDispatchEnvironment(); !errors.Is(err, ErrLocked) {
		t.Fatalf("invalid policy check = %v, want ErrLocked", err)
	}
}

func TestCheckManifestMutationEnvironmentRefusesEnforcedAndInvalidPolicy(t *testing.T) {
	for _, config := range []string{
		`{"mode":"enforce","allowed_workflows":[{"namespace":"dakasa","name":"fixed-unlock"}]}`,
		`{`,
	} {
		t.Setenv(EnvName, config)
		if err := CheckManifestMutationEnvironment(); !errors.Is(err, ErrLocked) {
			t.Fatalf("config %q error = %v, want ErrLocked", config, err)
		}
	}
}

func TestCheckControlPlaneMutationEnvironmentRefusesEnforcedAndInvalidPolicy(t *testing.T) {
	for _, config := range []string{
		`{"mode":"enforce","allowed_workflows":[{"namespace":"dakasa","name":"fixed-unlock"}]}`,
		`{`,
	} {
		t.Setenv(EnvName, config)
		if err := CheckControlPlaneMutationEnvironment(); !errors.Is(err, ErrLocked) {
			t.Fatalf("config %q error = %v, want ErrLocked", config, err)
		}
	}
}
