//go:build linux && nativequalification

package main

import (
	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	q "github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacitynativeqemu"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

func (f *fixture) workflowSpec(rbac model.Manifest) model.WorkflowManifestSpec {
	closed := false
	policy := map[string]any{"namespace": f.namespace, "name": "original-native-qemu"}
	step := func(id, operation string, input map[string]any) model.WorkflowStepSpec {
		return model.WorkflowStepSpec{ID: id, Use: model.WorkflowStepUseSpec{Kind: "yggdrasil", Operation: operation}, With: input, TimeoutSeconds: 600, Retry: model.WorkflowRetrySpec{MaxAttempts: 1}}
	}
	owned := func() map[string]any {
		return map[string]any{"policy": policy, "binding_name": "native-qemu", "slot": "{{ inputs.slot }}", "generation": "{{ steps.original_claim.metadata.generation }}", "fencing_token": "{{ steps.original_claim.metadata.fencing_token }}", "lease_owner": "{{ steps.original_claim.metadata.lease_owner }}"}
	}
	assess := step("original_assess", "capacity.assess", map[string]any{"policy": policy, "assessment": "{{ inputs.assessment }}"})
	claim := step("original_claim", "capacity.claim", map[string]any{"policy": policy, "assessment": "{{ inputs.assessment }}", "generation": "{{ steps.original_assess.metadata.generation }}"})
	claim.Condition = "{{ inputs.mode }} != observe_reduction_demand"
	claim.DependsOn = []string{assess.ID}
	create := step(f.profile.OriginalProvisioningStepID, capacity.ProvisionOriginalGuestOperation, owned())
	create.Condition = "{{ inputs.mode }} == baseline || {{ inputs.mode }} == burst"
	create.DependsOn = []string{claim.ID}
	if q.SourceLivePartialCase(f.request.NativeCase) {
		create.Condition += " || {{ inputs.mode }} == live_partial"
	}
	if q.SourceHistoricalConfirmCase(f.request.NativeCase) {
		create.Condition += " || {{ inputs.mode }} == historical_confirm"
	}
	if q.SourceTerminalCase(f.request.NativeCase) {
		create.Condition += " || {{ inputs.mode }} == terminal_contract"
	}
	if q.SourceFailedFloorCase(f.request.NativeCase) {
		create.Condition += " || {{ inputs.mode }} == floor_repair"
	}
	qualify := step("original_echo_qualified", "capacity.qualify_original_guest_echo", owned())
	qualify.Condition = "{{ inputs.mode }} == baseline || {{ inputs.mode }} == burst"
	qualify.DependsOn = []string{create.ID}
	retireInput := owned()
	retireInput["preregistration_id"] = "{{ inputs.preregistration_id }}"
	retire := step("original_burst_retire", capacity.RetireOriginalGuestOperation, retireInput)
	retire.Condition = "{{ inputs.mode }} == retire"
	retire.DependsOn = []string{claim.ID}
	finish := step("original_burst_native_off", "capacity.finish_original_guest_retirement", owned())
	finish.Condition = "{{ inputs.mode }} == retire"
	finish.DependsOn = []string{retire.ID}
	finish.With["preregistration_id"] = "{{ inputs.preregistration_id }}"
	finish.With["request_id"] = "{{ steps.original_burst_retire.metadata.request_id }}"
	if q.SourceContractCase(f.request.NativeCase) {
		create.Condition = "{{ inputs.mode }} == source_contract"
		return model.WorkflowManifestSpec{DispatchMode: "async", Authorization: &model.WorkflowAuthorizationSpec{RBAC: model.ManifestSelector{ManifestID: rbac.ID.String()}}, InputSchema: model.WorkflowInputSchemaSpec{Required: []string{"mode", "slot", "assessment"}, AdditionalProperties: &closed, Properties: map[string]model.IntegrationSchemaProperty{"mode": {Type: "string", Enum: []any{"source_contract"}}, "slot": {Type: "integer"}, "assessment": {Type: "object"}, "preregistration_id": {Type: "string"}}}, Steps: []model.WorkflowStepSpec{assess, claim, create}}
	}
	spec := model.WorkflowManifestSpec{DispatchMode: "async", Authorization: &model.WorkflowAuthorizationSpec{RBAC: model.ManifestSelector{ManifestID: rbac.ID.String()}}, InputSchema: model.WorkflowInputSchemaSpec{Required: []string{"mode", "slot", "assessment"}, AdditionalProperties: &closed, Properties: map[string]model.IntegrationSchemaProperty{"mode": {Type: "string", Enum: []any{"baseline", "burst", "observe_reduction_demand", "retire"}}, "slot": {Type: "integer"}, "assessment": {Type: "object"}, "preregistration_id": {Type: "string"}}}, Steps: []model.WorkflowStepSpec{assess, claim, create, qualify, retire, finish}}
	if q.SourceLivePartialCase(f.request.NativeCase) {
		mode := spec.InputSchema.Properties["mode"]
		mode.Enum = append(mode.Enum, "live_partial")
		spec.InputSchema.Properties["mode"] = mode
	}
	if q.SourceHistoricalConfirmCase(f.request.NativeCase) {
		mode := spec.InputSchema.Properties["mode"]
		mode.Enum = append(mode.Enum, "historical_confirm")
		spec.InputSchema.Properties["mode"] = mode
	}
	if q.SourceTerminalCase(f.request.NativeCase) {
		mode := spec.InputSchema.Properties["mode"]
		mode.Enum = append(mode.Enum, "terminal_contract")
		spec.InputSchema.Properties["mode"] = mode
	}
	if q.SourceFailedFloorCase(f.request.NativeCase) {
		mode := spec.InputSchema.Properties["mode"]
		mode.Enum = append(mode.Enum, "floor_repair")
		spec.InputSchema.Properties["mode"] = mode
	}

	if q.CanonicalSourceCompensationCase(f.request.NativeCase) {
		mode := spec.InputSchema.Properties["mode"]
		mode.Enum = append(mode.Enum, "recovery_cleanup")
		spec.InputSchema.Properties["mode"] = mode
		spec.InputSchema.Properties["generation"] = model.IntegrationSchemaProperty{Type: "integer"}
		spec.Steps[0].Condition = "{{ inputs.mode }} != recovery_cleanup"
		spec.Steps[1].Condition += " && {{ inputs.mode }} != recovery_cleanup"
		recover := step("original_recovery_cleanup_recover", "capacity.recover", map[string]any{"policy": policy, "generation": "{{ inputs.generation }}", "assessment": "{{ inputs.assessment }}"})
		recover.Condition = "{{ inputs.mode }} == recovery_cleanup"
		fresh := step("original_recovery_cleanup_read", "capacity.qualify_original_guest_echo", map[string]any{"policy": policy, "binding_name": "native-qemu", "slot": q.SourceFailureSlot(f.request.NativeCase), "generation": "{{ steps.original_recovery_cleanup_recover.metadata.generation }}", "fencing_token": "{{ steps.original_recovery_cleanup_recover.metadata.fencing_token }}", "lease_owner": "{{ steps.original_recovery_cleanup_recover.metadata.lease_owner }}", "preregistration_id": "{{ inputs.preregistration_id }}", "request_id": "source_recovery_cleanup_v1"})
		fresh.Condition = "{{ inputs.mode }} == recovery_cleanup"
		fresh.DependsOn = []string{recover.ID}
		spec.Steps = append(spec.Steps, recover, fresh)
	}
	return spec
}
