//go:build !nativequalification

package message

import (
	"context"
	"reflect"
	"slices"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/manifest"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

func originalAWSGuestSupplierCatalog(ts model.IntegrationTypeManifestSpec) bool {
	if ts.Provider != "aws" || (ts.Adapter.Version != "1.61.0" && ts.Adapter.Version != "1.62.0" && ts.Adapter.Version != "1.63.0" && ts.Adapter.Version != "1.64.0") || ts.Adapter.Transport != "http_json" || ts.Adapter.Endpoints.Execute != "/rpc/execute" || ts.Adapter.Endpoints.Describe != "/rpc/describe" || manifest.ValidateIntegrationTypeSpec(ts) != nil {
		return false
	}
	operations := []string{"ensure_ec2_instance", "observe_ec2_instance", "terminate_ec2_instance"}
	if ts.Adapter.Version == "1.64.0" {
		operations = append(operations, capacity.VMObserveInventory)
	}
	for _, required := range operations {
		count := 0
		for _, action := range ts.ActionCatalog {
			if action.Name != required {
				continue
			}
			if (required != "observe_ec2_instance" && !action.Idempotent) || !slices.Contains(action.ResourceTypes, "ec2_instance") {
				return false
			}
			for _, resource := range ts.ResourceTypes {
				if resource.Name == "ec2_instance" && slices.Contains(resource.DefaultActions, required) {
					count++
				}
			}
		}
		if count != 1 {
			return false
		}
	}
	return true
}

func (s *originalProductionGuestSupplier) prepareAWS(ctx context.Context, slot int) error {
	var expected *model.CapacityMutationSlotBinding
	for n := range s.binding.Slots {
		if s.binding.Slots[n].Slot == slot {
			expected = &s.binding.Slots[n]
		}
	}
	if expected == nil || expected.DesiredSpec == nil {
		return errOriginalGuestStep
	}
	var plan model.CapacityVMFleetPlan
	status, err := s.call(ctx, "ensure_ec2_instance", map[string]any{"profile": s.binding.ProfileName, "slot": slot}, &plan)
	if err != nil || status != "dry_run" || plan.Server != nil || plan.Quote != nil || plan.RequestSHA256 != expected.DesiredSpecSHA256 || !reflect.DeepEqual(plan.DesiredSpec, *expected.DesiredSpec) || plan.Protected != (slot <= s.binding.ProtectedSlots) || plan.ProviderFencingEvidence || plan.WarmReadinessEvidence || plan.BusinessReadyEvidence {
		return errOriginalGuestStep
	}
	// Real image/subnet/security-group/account reads establish the configured
	// native realm. This result asserts no provider stock, quote or readiness.
	return nil
}

func (s *originalProductionGuestSupplier) readAWS(ctx context.Context, g model.CapacityMutationGrant) (model.CapacityMutationProof, error) {
	var empty model.CapacityMutationProof
	receipt, err := s.store.NativeMutationReceipt(ctx, s.policy, s.binding, g.GrantID)
	if err != nil || !receipt.TransportCompleted || receipt.Outcome != "accepted" || (receipt.Grant.State != "settled" && receipt.Grant.State != "confirmed") || receipt.ActionID == "" || len(receipt.NextActionIDs) != 0 {
		return empty, errOriginalGuestStep
	}
	original := receipt.Grant
	original.State = g.State
	if !reflect.DeepEqual(original, g) {
		return empty, errOriginalGuestStep
	}
	var observed struct {
		Plan      model.CapacityVMFleetPlan          `json:"plan"`
		Lifecycle model.CapacityAWSInstanceLifecycle `json:"lifecycle"`
	}
	status, err := s.call(ctx, "observe_ec2_instance", map[string]any{"profile": s.binding.ProfileName, "slot": g.Slot, "grant_id": g.GrantID, "expected_resource_id": receipt.ResourceID, "expected_resource_created_at": receipt.ResourceCreatedAt}, &observed)
	if err != nil || status != "observed" || observed.Lifecycle.Schema != "aws_original_request_and_instance_status_v1" || observed.Lifecycle.RequestID != receipt.ActionID {
		return empty, errOriginalGuestStep
	}
	proof, err := capacity.VMServerPlanProof(s.p, s.binding, observed.Plan, receipt, status, time.Now().UTC(), "original-aws-instance-status:"+g.GrantID)
	if err != nil || proof.ResourceAbsent || observed.Plan.Server == nil || observed.Plan.Server.Status != observed.Lifecycle.EC2State || !observed.Lifecycle.ObservedAt.Equal(proof.ObservedAt) {
		return empty, errOriginalGuestStep
	}
	if observed.Lifecycle.EC2State == "pending" || observed.Lifecycle.EC2State == "running" && (observed.Lifecycle.SystemStatus == "initializing" || observed.Lifecycle.InstanceStatus == "initializing" || observed.Lifecycle.SystemStatus == "insufficient-data" || observed.Lifecycle.InstanceStatus == "insufficient-data") {
		return empty, errOriginalGuestProviderPending
	}
	if observed.Lifecycle.EC2State != "running" || observed.Lifecycle.SystemStatus != "ok" || observed.Lifecycle.InstanceStatus != "ok" {
		return empty, errOriginalGuestStep
	}
	proof.AWSInstanceLifecycle = &observed.Lifecycle
	proof.ProviderNativeIdentity, err = capacity.OriginalGuestProviderIdentity(s.p, s.binding, observed.Plan, proof, time.Now().UTC())
	if err != nil {
		return empty, errOriginalGuestStep
	}
	// ActionIDs and every generic Actions* flag deliberately stay empty/false.
	// EC2's native health checks establish only this creation lifecycle.
	return proof, nil
}
