package manifest

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

// Literal source graph used by the native command. Parsing/validation is source
// admission only: this fixture supplies no original creator or native fact.
const guestOriginalWorkflowGraph = `{
 "dispatch_mode":"async",
 "authorization":{"rbac":{"namespace":"dakasa","name":"original-native-rbac"}},
 "input_schema":{"required":["mode","slot","assessment"],"additionalProperties":false,"properties":{"mode":{"type":"string","enum":["baseline","burst","observe_reduction_demand","retire"]},"slot":{"type":"integer"},"assessment":{"type":"object"},"preregistration_id":{"type":"string"}}},
 "steps":[
  {"id":"original_assess","use":{"kind":"yggdrasil","operation":"capacity.assess"},"with":{"policy":{"namespace":"dakasa","name":"original-native-qemu"},"assessment":"{{ inputs.assessment }}"},"timeout_seconds":600,"retry":{"max_attempts":1}},
  {"id":"original_claim","use":{"kind":"yggdrasil","operation":"capacity.claim"},"with":{"policy":{"namespace":"dakasa","name":"original-native-qemu"},"assessment":"{{ inputs.assessment }}","generation":"{{ steps.original_assess.metadata.generation }}"},"condition":"{{ inputs.mode }} != observe_reduction_demand","depends_on":["original_assess"],"timeout_seconds":600,"retry":{"max_attempts":1}},
  {"id":"original-native-qemu-create","use":{"kind":"yggdrasil","operation":"capacity.provision_original_guest"},"with":{"policy":{"namespace":"dakasa","name":"original-native-qemu"},"binding_name":"native-qemu","slot":"{{ inputs.slot }}","generation":"{{ steps.original_claim.metadata.generation }}","fencing_token":"{{ steps.original_claim.metadata.fencing_token }}","lease_owner":"{{ steps.original_claim.metadata.lease_owner }}"},"condition":"{{ inputs.mode }} == baseline || {{ inputs.mode }} == burst","depends_on":["original_claim"],"timeout_seconds":600,"retry":{"max_attempts":1}},
  {"id":"original_echo_qualified","use":{"kind":"yggdrasil","operation":"capacity.qualify_original_guest_echo"},"with":{"policy":{"namespace":"dakasa","name":"original-native-qemu"},"binding_name":"native-qemu","slot":"{{ inputs.slot }}","generation":"{{ steps.original_claim.metadata.generation }}","fencing_token":"{{ steps.original_claim.metadata.fencing_token }}","lease_owner":"{{ steps.original_claim.metadata.lease_owner }}"},"condition":"{{ inputs.mode }} == baseline || {{ inputs.mode }} == burst","depends_on":["original-native-qemu-create"],"timeout_seconds":600,"retry":{"max_attempts":1}},
  {"id":"original_burst_retire","use":{"kind":"yggdrasil","operation":"capacity.retire_original_guest"},"with":{"policy":{"namespace":"dakasa","name":"original-native-qemu"},"binding_name":"native-qemu","slot":"{{ inputs.slot }}","generation":"{{ steps.original_claim.metadata.generation }}","fencing_token":"{{ steps.original_claim.metadata.fencing_token }}","lease_owner":"{{ steps.original_claim.metadata.lease_owner }}","preregistration_id":"{{ inputs.preregistration_id }}"},"condition":"{{ inputs.mode }} == retire","depends_on":["original_claim"],"timeout_seconds":600,"retry":{"max_attempts":1}},
  {"id":"original_burst_native_off","use":{"kind":"yggdrasil","operation":"capacity.finish_original_guest_retirement"},"with":{"policy":{"namespace":"dakasa","name":"original-native-qemu"},"binding_name":"native-qemu","slot":"{{ inputs.slot }}","generation":"{{ steps.original_claim.metadata.generation }}","fencing_token":"{{ steps.original_claim.metadata.fencing_token }}","lease_owner":"{{ steps.original_claim.metadata.lease_owner }}","preregistration_id":"{{ inputs.preregistration_id }}","request_id":"{{ steps.original_burst_retire.metadata.request_id }}"},"condition":"{{ inputs.mode }} == retire","depends_on":["original_burst_retire"],"timeout_seconds":600,"retry":{"max_attempts":1}}
 ]
}`

func guestOriginalGraphSpec(t *testing.T) model.WorkflowManifestSpec {
	t.Helper()
	spec, err := ParseWorkflowSpec(json.RawMessage(guestOriginalWorkflowGraph))
	if err != nil {
		t.Fatal(err)
	}
	return spec
}

func TestWorkflowGuestOriginalGraph(t *testing.T) {
	t.Run("complete_declared_source_graph", func(t *testing.T) {
		spec := guestOriginalGraphSpec(t)
		if err := ValidateWorkflowSpec(spec); err != nil {
			t.Fatal("real public dispatcher cannot admit source graph", err)
		}
		if len(spec.Steps) != 6 || spec.DispatchMode != "async" || spec.Authorization == nil {
			t.Fatal("original graph was reduced")
		}
		order, err := WorkflowExecutionOrder(spec)
		if err != nil || len(order) != 6 {
			t.Fatal("complete graph cannot be ordered", err)
		}
		want := []string{"capacity.provision_original_guest", "capacity.qualify_original_guest_echo", "capacity.retire_original_guest", "capacity.finish_original_guest_retirement"}
		var got []string
		for _, step := range spec.Steps[2:] {
			got = append(got, step.Use.Operation)
			if step.TimeoutSeconds != 600 || step.Retry.MaxAttempts != 1 || step.ForEach != nil {
				t.Fatal("literal original source step changed")
			}
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatal("approved operation graph changed", got)
		}
	})
	for _, test := range []struct {
		name, contains string
		mutate         func(*model.WorkflowManifestSpec)
	}{
		{"unknown_operation", "unsupported", func(s *model.WorkflowManifestSpec) {
			s.Steps[2].Use.Operation = "capacity.provision_original_guest_unapproved"
		}},
		{"empty_operation", "use.operation", func(s *model.WorkflowManifestSpec) { s.Steps[2].Use.Operation = "" }},
		{"invalid_rbac_selector", "rbac", func(s *model.WorkflowManifestSpec) { s.Authorization.RBAC = model.ManifestSelector{} }},
		{"unknown_dependency", "unknown step", func(s *model.WorkflowManifestSpec) { s.Steps[3].DependsOn = []string{"caller_invented_create"} }},
		{"self_dependency", "itself", func(s *model.WorkflowManifestSpec) { s.Steps[2].DependsOn = []string{s.Steps[2].ID} }},
		{"cycle", "cycl", func(s *model.WorkflowManifestSpec) { s.Steps[2].DependsOn = []string{s.Steps[3].ID} }},
		{"duplicate_step", "duplicated", func(s *model.WorkflowManifestSpec) { s.Steps[3].ID = s.Steps[2].ID }},
		{"integration_instance_on_guest", "instance_ref", func(s *model.WorkflowManifestSpec) {
			s.Steps[2].Use.InstanceRef = &model.ManifestSelector{Name: "caller-selected"}
		}},
		{"integration_family_on_guest", "family", func(s *model.WorkflowManifestSpec) { s.Steps[2].Use.Family = "caller-selected" }},
		{"integration_provider_on_guest", "provider_ref", func(s *model.WorkflowManifestSpec) {
			s.Steps[2].Use.ProviderRef = &model.ManifestSelector{Name: "caller-selected"}
		}},
		{"negative_timeout", "timeout", func(s *model.WorkflowManifestSpec) { s.Steps[2].TimeoutSeconds = -1 }},
	} {
		t.Run(test.name, func(t *testing.T) {
			spec := guestOriginalGraphSpec(t)
			test.mutate(&spec)
			if err := ValidateWorkflowSpec(spec); err == nil || !strings.Contains(err.Error(), test.contains) {
				t.Fatalf("wrong graph refusal: %v; want %s", err, test.contains)
			}
		})
	}
	for _, operation := range []string{"provision_original_guest", "qualify_original_guest_echo", "retire_original_guest", "finish_original_guest_retirement"} {
		t.Run("authorization_required_"+operation, func(t *testing.T) {
			spec := guestOriginalGraphSpec(t)
			spec.Authorization = nil
			spec.Steps = []model.WorkflowStepSpec{{ID: "original", Use: model.WorkflowStepUseSpec{Kind: "yggdrasil", Operation: "capacity." + operation}}}
			if err := ValidateWorkflowSpec(spec); err == nil || !strings.Contains(err.Error(), "require workflow authorization") {
				t.Fatal("actorless Guest operation admitted", err)
			}
		})
	}
	t.Run("malformed_literal_json", func(t *testing.T) {
		if _, err := ParseWorkflowSpec(json.RawMessage(guestOriginalWorkflowGraph + ` {}`)); err == nil {
			t.Fatal("trailing graph accepted")
		}
	})
}
