package httpapi

import (
	"encoding/json"
	"testing"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

func TestOriginalGuestDispatchDoesNotTranslateHPAIntoVMAuthority(t *testing.T) {
	enabled := true
	policy := model.Manifest{Kind: "capacity_policy", Metadata: model.ManifestMetadata{Namespace: "unit-only", Name: "pods"}, Spec: json.RawMessage(`{}`)}
	hpa := model.WorkflowManifestSpec{Trigger: model.WorkflowTriggerSpec{Mode: "schedule", Enabled: &enabled, Schedule: &model.WorkflowScheduleTriggerSpec{CronExpression: "* * * * *"}}, Authorization: &model.WorkflowAuthorizationSpec{RBAC: model.ManifestSelector{Namespace: "unit-only", Name: "rbac"}}, Steps: []model.WorkflowStepSpec{{ID: "hpa", Use: model.WorkflowStepUseSpec{Kind: "yggdrasil", Operation: "capacity.execute_bound"}, With: map[string]any{"policy": map[string]any{"namespace": "unit-only", "name": "pods"}}}}}
	if err := dispatchWorkflowGraph(hpa, policy); err != nil {
		t.Fatal("historical exact HPA graph changed", err)
	}
	for _, op := range []string{capacity.PlanOriginalGuestOperation, capacity.CompleteOriginalGuestOperation, capacity.ProvisionOriginalGuestOperation, capacity.RetireOriginalGuestOperation} {
		t.Run(op, func(t *testing.T) {
			candidate := hpa
			candidate.Steps = append([]model.WorkflowStepSpec(nil), hpa.Steps...)
			candidate.Steps[0].Use.Operation = op
			if !CapacityScheduleGraphRequiresOwner(candidate) {
				t.Fatal("Guest operation escaped protected owner classifier")
			}
			if dispatchWorkflowGraph(candidate, policy) == nil {
				t.Fatal("HPA delegation granted original VM authority")
			}
		})
	}
	// An optional field or an invented profile is never a production registry.
	p := model.CapacityPolicySpec{GuestNotifyReconcileBinding: &model.CapacityGuestNotifyReconcileBinding{Mode: capacity.GuestNotifyReconcileMode}, GuestRetirementBinding: &model.CapacityGuestRetirementBinding{}, Profiles: []model.CapacityProfile{{Provider: "aws"}}, ControllerBinding: &model.CapacityControllerBinding{Mode: "capacity_dispatch_prestart_v1"}}
	policy.Spec, _ = json.Marshal(p)
	if dispatchWorkflowGraph(hpa, policy) == nil {
		t.Fatal("missing compiled Guest approval admitted")
	}
}
