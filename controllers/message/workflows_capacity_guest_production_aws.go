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
	if ts.Provider != "aws" || (ts.Adapter.Version != "1.61.0" && ts.Adapter.Version != "1.62.0" && ts.Adapter.Version != "1.63.0" && ts.Adapter.Version != "1.64.0" && ts.Adapter.Version != "1.65.1" && ts.Adapter.Version != "1.65.2" && ts.Adapter.Version != "1.65.3" && ts.Adapter.Version != "1.65.4" && ts.Adapter.Version != "1.65.5") || ts.Adapter.Transport != "http_json" || ts.Adapter.Endpoints.Execute != "/rpc/execute" || ts.Adapter.Endpoints.Describe != "/rpc/describe" || manifest.ValidateIntegrationTypeSpec(ts) != nil {
		return false
	}
	operations := []string{"ensure_ec2_instance", "observe_ec2_instance", "terminate_ec2_instance"}
	if ts.Adapter.Version == "1.64.0" || ts.Adapter.Version == "1.65.1" || ts.Adapter.Version == "1.65.2" || ts.Adapter.Version == "1.65.3" || ts.Adapter.Version == "1.65.4" || ts.Adapter.Version == "1.65.5" {
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
	var observed originalAWSStatusObservation
	status, err := s.call(ctx, "observe_ec2_instance", map[string]any{"profile": s.binding.ProfileName, "slot": g.Slot, "grant_id": g.GrantID, "expected_resource_id": receipt.ResourceID, "expected_resource_created_at": receipt.ResourceCreatedAt}, &observed)
	if err != nil {
		return empty, errOriginalGuestStep
	}
	return classifyOriginalAWSStatus(ctx, s.p, s.binding, receipt, status, observed, time.Now().UTC())
}

type originalAWSStatusObservation struct {
	Plan      model.CapacityVMFleetPlan          `json:"plan"`
	Lifecycle model.CapacityAWSInstanceLifecycle `json:"lifecycle"`
}

// An unpublished status is retryable only after the same closed physical and
// receipt proof as an ordinary observation. It conveys no AWS health value.
func classifyOriginalAWSStatus(ctx context.Context, p model.CapacityPolicySpec, b model.CapacityMutationBinding, receipt model.CapacityMutationReceipt, status string, observed originalAWSStatusObservation, now time.Time) (model.CapacityMutationProof, error) {
	var empty model.CapacityMutationProof
	if ctx == nil || ctx.Err() != nil || status != "observed" || !receipt.TransportCompleted || receipt.Outcome != "accepted" || (receipt.Grant.State != "settled" && receipt.Grant.State != "confirmed") || receipt.ActionID == "" || len(receipt.NextActionIDs) != 0 || observed.Lifecycle.RequestID != receipt.ActionID || observed.Plan.RequestSHA256 != receipt.Grant.RequestSHA256 || observed.Plan.DesiredSpec.ExpectedResourceID != receipt.ResourceID || observed.Plan.DesiredSpec.ExpectedResourceCreatedAt != receipt.ResourceCreatedAt {
		return empty, errOriginalGuestStep
	}
	deadline, ok := ctx.Deadline()
	if !ok || !now.Before(deadline) {
		return empty, errOriginalGuestStep
	}
	if observed.Lifecycle.Schema == "aws_original_topology_pending_v1" {
		return classifyOriginalAWSTopologyPending(ctx, p, b, receipt, observed, now, deadline)
	}
	if len(observed.Lifecycle.PendingReasons) != 0 {
		return empty, errOriginalGuestStep
	}
	proof, err := capacity.VMServerPlanProof(p, b, observed.Plan, receipt, status, now, "original-aws-instance-status:"+receipt.Grant.GrantID)
	if err != nil || ctx.Err() != nil || !time.Now().Before(deadline) || proof.ResourceAbsent || observed.Plan.Server == nil || observed.Plan.Server.Status != observed.Lifecycle.EC2State || !observed.Lifecycle.ObservedAt.Equal(proof.ObservedAt) {
		return empty, errOriginalGuestStep
	}
	if observed.Lifecycle.Schema == "aws_original_instance_status_unpublished_v1" {
		if (observed.Lifecycle.EC2State != "pending" && observed.Lifecycle.EC2State != "running") || observed.Lifecycle.SystemStatus != "" || observed.Lifecycle.InstanceStatus != "" {
			return empty, errOriginalGuestStep
		}
		return empty, errOriginalGuestProviderPending
	}
	if observed.Lifecycle.Schema != "aws_original_request_and_instance_status_v1" {
		return empty, errOriginalGuestStep
	}
	if observed.Lifecycle.EC2State == "pending" || observed.Lifecycle.EC2State == "running" && (observed.Lifecycle.SystemStatus == "initializing" || observed.Lifecycle.InstanceStatus == "initializing" || observed.Lifecycle.SystemStatus == "insufficient-data" || observed.Lifecycle.InstanceStatus == "insufficient-data") {
		return empty, errOriginalGuestProviderPending
	}
	if observed.Lifecycle.EC2State != "running" || observed.Lifecycle.SystemStatus != "ok" || observed.Lifecycle.InstanceStatus != "ok" {
		return empty, errOriginalGuestStep
	}
	proof.AWSInstanceLifecycle = &observed.Lifecycle
	proof.ProviderNativeIdentity, err = capacity.OriginalGuestProviderIdentity(p, b, observed.Plan, proof, now)
	if err != nil || ctx.Err() != nil || !time.Now().Before(deadline) {
		return empty, errOriginalGuestStep
	}
	return proof, nil
}

// Topology pending asserts no physical proof. The authenticated supplier must
// have returned a validated native transient from the exact owning lifetime.
func classifyOriginalAWSTopologyPending(ctx context.Context, p model.CapacityPolicySpec, b model.CapacityMutationBinding, r model.CapacityMutationReceipt, o originalAWSStatusObservation, now, deadline time.Time) (model.CapacityMutationProof, error) {
	var empty model.CapacityMutationProof
	g, plan, l := r.Grant, o.Plan, o.Lifecycle
	if ctx.Err() != nil || !time.Now().Before(deadline) || g.GrantID == "" || g.CompensationOf != "" || g.BindingName != b.Name || g.IntegrationInstanceID != b.IntegrationInstanceID || g.ScopeChecksum != b.ScopeChecksum || g.ProfileName != b.ProfileName || g.Capability != b.EnsureCapability || r.ResourceID == "" || r.ResourceCreatedAt == "" || plan.DesiredSpec.Capability != "observe_ec2_instance" || plan.Server != nil || plan.Quote != nil || len(plan.AuxiliaryResources) != 0 || plan.CompensationOf != "" || plan.CompensationIdentityVerified || plan.ProviderFencingEvidence || plan.WarmReadinessEvidence || plan.BusinessReadyEvidence || plan.Protected != (g.Slot <= b.ProtectedSlots) || (l.EC2State != "pending" && l.EC2State != "running") || l.SystemStatus != "" || l.InstanceStatus != "" || len(l.PendingReasons) == 0 || len(l.PendingReasons) > 4 {
		return empty, errOriginalGuestStep
	}
	var approved *model.CapacityMutationSlotBinding
	for i := range b.Slots {
		if b.Slots[i].Slot == g.Slot {
			if approved != nil {
				return empty, errOriginalGuestStep
			}
			approved = &b.Slots[i]
		}
	}
	if approved == nil || approved.DesiredSpec == nil || approved.DesiredSpecSHA256 != g.RequestSHA256 {
		return empty, errOriginalGuestStep
	}
	spec := plan.DesiredSpec
	spec.Capability = b.EnsureCapability
	spec.ExpectedResourceID, spec.ExpectedResourceCreatedAt = "", ""
	if spec != *approved.DesiredSpec {
		return empty, errOriginalGuestStep
	}
	at, err := time.Parse(time.RFC3339Nano, plan.ObservedAt)
	if err != nil || at.UTC().Format(time.RFC3339Nano) != plan.ObservedAt || !capacity.Fresh(at, now, p.MaxEvidenceAgeSeconds) || !l.ObservedAt.Equal(at) {
		return empty, errOriginalGuestStep
	}
	created, err := time.Parse(time.RFC3339Nano, r.ResourceCreatedAt)
	if err != nil || created.UTC().Format(time.RFC3339Nano) != r.ResourceCreatedAt || created.After(now.Add(5*time.Second)) {
		return empty, errOriginalGuestStep
	}
	seen := map[string]bool{}
	for _, reason := range l.PendingReasons {
		switch reason {
		case "metadata_pending", "private_dns_pending", "root_mapping_pending", "network_attachment_pending":
		default:
			return empty, errOriginalGuestStep
		}
		if seen[reason] || (l.EC2State != "pending" && (reason == "root_mapping_pending" || reason == "network_attachment_pending")) {
			return empty, errOriginalGuestStep
		}
		seen[reason] = true
	}
	if ctx.Err() != nil || !time.Now().Before(deadline) {
		return empty, errOriginalGuestStep
	}
	return empty, errOriginalGuestProviderPending
}
