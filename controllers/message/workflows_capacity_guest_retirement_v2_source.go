//go:build !nativequalification

package message

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/json"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
)

func productionRetirementSupplierV2(ctx context.Context, store repository.CapacityStore, policy model.Manifest, p model.CapacityPolicySpec, b model.CapacityMutationBinding, input guestOriginalStepInput) (*originalProductionGuestSupplier, error) {
	transport, ok := ctx.Value(originalGuestTransportKey{}).(originalGuestTransport)
	provider := ""
	for _, profile := range p.Profiles {
		if profile.Name == b.ProfileName {
			provider = profile.Provider
		}
	}
	if !ok || p.GuestRetirementBinding == nil || !capacity.GuestOriginalProfileEnabled(p, *p.GuestRetirementBinding, provider) || (provider != "aws" && provider != "hetzner") {
		return nil, errOriginalGuestStep
	}
	scope := model.CapacityObservationAdapterBinding{IntegrationInstanceID: b.IntegrationInstanceID, InstanceChecksum: b.IntegrationChecksum, IntegrationTypeID: b.IntegrationTypeID, TypeChecksum: b.IntegrationTypeChecksum}
	resolved, err := resolveOriginalGuestSupplier(ctx, transport.conn, store, scope, b.OriginalProviderSourceCommit, provider)
	if err != nil {
		return nil, err
	}
	return &originalProductionGuestSupplier{provider: provider, store: store, policy: policy, p: p, binding: b, resolved: resolved, conn: transport.conn, parent: ctx, input: input}, nil
}

// The complete five-second source budget starts before the durable challenge,
// catalog resolution and the actual provider RPC. Native stamps are diagnostics;
// freshness is joined independently to this original read and Core PG custody.
func sourceProductionGuestNativeOffV2(ctx context.Context, store repository.CapacityStore, policy model.Manifest, p model.CapacityPolicySpec, input guestOriginalStepInput, stored repository.GuestRetirementOriginalV2) (repository.GuestNativePoweroffReturnV2, error) {
	var out repository.GuestNativePoweroffReturnV2
	original, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	challenge, err := store.PrepareGuestNativePoweroffReadV2(original, input.RequestID)
	if err != nil {
		return out, err
	}
	out.Schema = "original_core_guest_native_poweroff_read_return_v2"
	out.Challenge = challenge
	b, err := capacity.VMObservationBinding(p, input.BindingName)
	if err != nil {
		return out, err
	}
	supplier, err := productionRetirementSupplierV2(original, store, policy, p, b, input)
	if err == nil {
		fixed := map[string]any{"profile": b.ProfileName, "slot": input.Slot, "grant_id": stored.Preregistration.OriginalCreateGrantID, "expected_resource_id": stored.Request.Intent.Tuple.ResourceID, "expected_resource_created_at": stored.Request.Intent.Tuple.CreatedAt}
		out.StartedAtCore = time.Now().UTC()
		if supplier.provider == "aws" {
			var returned struct {
				Plan      model.CapacityVMFleetPlan          `json:"plan"`
				Lifecycle model.CapacityAWSInstanceLifecycle `json:"lifecycle"`
			}
			out.Status, err = supplier.call(original, "observe_ec2_instance", fixed, &returned)
			if err == nil {
				receipt, receiptErr := store.NativeMutationReceipt(original, policy, b, stored.Preregistration.OriginalCreateGrantID)
				nativeAt := ""
				if returned.Plan.Server != nil {
					nativeAt = returned.Plan.Server.ObservedAt
				}
				if receiptErr != nil || receipt.ActionID == "" || returned.Lifecycle.RequestID != receipt.ActionID || returned.Lifecycle.Schema != "aws_original_request_and_instance_status_v1" || returned.Lifecycle.EC2State != "stopped" || returned.Plan.Server == nil || returned.Plan.Server.Status != "stopped" || returned.Lifecycle.ObservedAt.UTC().Format(time.RFC3339Nano) != nativeAt {
					err = errOriginalGuestStep
				}
			}
			if err == nil {
				out.Plan = &returned.Plan
			}
		} else {
			var plan model.CapacityVMFleetPlan
			out.Status, err = supplier.call(original, capacity.VMObserveServer, fixed, &plan)
			if err == nil {
				out.Plan = &plan
			}
		}
	}
	out.OriginalReturnedAtCore = time.Now().UTC()
	out.CallFailed = err != nil
	out.OriginalContextFailed = original.Err() != nil || !out.OriginalReturnedAtCore.Before(challenge.OriginalDeadlineCore)
	retain, stop := context.WithTimeout(context.WithoutCancel(original), 5*time.Second)
	recordErr := store.RecordGuestNativePoweroffV2(retain, out)
	stop()
	if err != nil || recordErr != nil || out.OriginalContextFailed {
		return out, errOriginalGuestStep
	}
	return out, nil
}

func executeProductionGuestRetirementFinishedV2(ctx context.Context, db *sql.DB, store repository.CapacityStore, policy model.Manifest, p model.CapacityPolicySpec, step model.WorkflowStepSpec, input guestOriginalStepInput, key ed25519.PrivateKey) (any, error) {
	if input.RequestID == "" || input.PreregistrationID == "" || p.GuestRetirementBinding == nil || p.GuestRetirementBinding.EvidenceClass != "owned_provisioner_original" {
		return nil, errOriginalGuestStep
	}
	store = store.WithOriginalGuestNotifyCanary(step, capacity.CurrentGuestCoreSource())
	stored, err := store.GuestRetirementWorkflowOriginalV2(ctx, policy, input.Generation, input.FencingToken, input.LeaseOwner, input.RequestID, input.PreregistrationID, input.Slot)
	if err != nil {
		return nil, err
	}
	existing, found, err := store.GuestRetirementDestroyReceiptV2(ctx, input.RequestID)
	if err != nil {
		return nil, err
	}
	var off repository.GuestNativePoweroffReturnV2
	if !found {
		off, err = sourceProductionGuestNativeOffV2(ctx, store, policy, p, input, stored)
		if err != nil {
			return nil, err
		}
	}
	if err = originalGuestNotifyFloor(ctx, db, store, policy, p, input, key, "after_retirement_floor"); err != nil {
		return nil, err
	}
	return finishProductionGuestNativeDestroyV2(ctx, store, policy, p, input, stored, off, existing, found)
}

// This source owns one actual destroy RPC. A prior issued/redeemed/uncertain
// grant is never resent, even when its adapter response was lost.
func finishProductionGuestNativeDestroyV2(ctx context.Context, store repository.CapacityStore, policy model.Manifest, p model.CapacityPolicySpec, input guestOriginalStepInput, stored repository.GuestRetirementOriginalV2, off repository.GuestNativePoweroffReturnV2, existing model.CapacityMutationReceipt, found bool) (any, error) {
	b, err := capacity.VMObservationBinding(p, input.BindingName)
	if err != nil {
		return nil, err
	}
	// Each provider must have its own exact ordinary destroy/read contract.
	// Version checks below happen before issuance or the actual adapter send.
	if !capacity.AWSOriginalMutationPair(b) && (b.EnsureCapability != "ensure_server" || b.DestroyCapability != "destroy_server") {
		return nil, errOriginalGuestStep
	}
	if found && existing.Grant.State == "confirmed" {
		return struct {
			RequestID                string                      `json:"request_id"`
			Grant                    model.CapacityMutationGrant `json:"grant"`
			OriginalConfirmedDestroy bool                        `json:"original_confirmed_destroy"`
		}{input.RequestID, existing.Grant, true}, nil
	}
	original, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	supplier, err := productionRetirementSupplierV2(original, store, policy, p, b, input)
	if err != nil || !productionRetirementCatalogV2(supplier.provider, supplier.resolved.typeSpec) {
		return nil, errOriginalGuestStep
	}
	receipt := existing
	if !found {
		var projection *model.CapacityMutationSpecV1
		for _, slot := range b.Slots {
			if slot.Slot == input.Slot && slot.DesiredSpec != nil {
				copy := *slot.DesiredSpec
				projection = &copy
			}
		}
		if projection == nil {
			return nil, errOriginalGuestStep
		}
		projection.Capability = b.DestroyCapability
		projection.ExpectedResourceID = stored.Request.Intent.Tuple.ResourceID
		projection.ExpectedResourceCreatedAt = stored.Request.Intent.Tuple.CreatedAt
		raw, err := json.Marshal(projection)
		if err != nil {
			return nil, err
		}
		// Assessment/drain transitions remain owned by their actual source workflow;
		// this method does not invent metrics or advance a phase to obtain a grant.
		grant, err := store.IssueMutation(original, policy, input.Generation, input.FencingToken, input.LeaseOwner, model.CapacityMutationIssue{BindingName: b.Name, DesiredSpec: raw})
		if err != nil {
			return nil, err
		}
		var returned struct {
			Plan          model.CapacityVMFleetPlan `json:"plan"`
			ActionID      string                    `json:"action_id"`
			NextActionIDs []string                  `json:"next_action_ids"`
		}
		status, callErr := supplier.call(original, b.DestroyCapability, map[string]any{"profile": b.ProfileName, "slot": input.Slot, "grant_id": grant.GrantID, "dry_run": false, "expected_resource_id": grant.ExpectedResourceID, "expected_resource_created_at": grant.ExpectedResourceCreatedAt}, &returned)
		if callErr != nil || status != "accepted" || original.Err() != nil {
			return nil, errOriginalGuestStep
		}
		receipt, err = store.NativeMutationReceipt(original, policy, b, grant.GrantID)
		if err != nil || receipt.Grant.State != "settled" || !originalGuestReceiptActionJoin(receipt, returned.ActionID, returned.NextActionIDs) || receipt.ResourceID != grant.ExpectedResourceID || receipt.ResourceCreatedAt != grant.ExpectedResourceCreatedAt {
			return nil, errOriginalGuestStep
		}
	}
	if receipt.Grant.State != "settled" || receipt.Outcome != "accepted" || !receipt.TransportCompleted {
		return nil, errOriginalGuestStep
	}
	// Read-only eventual-consistency polling remains inside this ONE original
	// sixty-second finish invocation. Each actual RPC has a shorter new five-
	// second read challenge. Neither budget can substitute for the original
	// thirty-second Guest caller success or authorize another DELETE.
	for {
		returned, proof, pending, readErr := sourceProductionNativeAbsenceV2(original, store, policy, p, b, input, receipt)
		if readErr == nil {
			confirmed, err := store.ConfirmMutation(original, policy, input.Generation, input.FencingToken, input.LeaseOwner, proof)
			if err != nil {
				return nil, err
			}
			return struct {
				RequestID                string                      `json:"request_id"`
				DestroyGrant             model.CapacityMutationGrant `json:"destroy_grant"`
				NativeOffSHA256          string                      `json:"native_off_sha256,omitempty"`
				NativeAbsenceSHA256      string                      `json:"native_absence_sha256"`
				PhysicalCapacityReleased bool                        `json:"physical_capacity_released"`
			}{input.RequestID, confirmed, capacity.GuestRetirementSHA(off), capacity.GuestRetirementSHA(returned), true}, nil
		}
		if !pending {
			return nil, readErr
		}
		timer := time.NewTimer(time.Second)
		select {
		case <-original.Done():
			timer.Stop()
			return nil, errOriginalGuestStep
		case <-timer.C:
		}
	}
}

func sourceProductionNativeAbsenceV2(ctx context.Context, store repository.CapacityStore, policy model.Manifest, p model.CapacityPolicySpec, b model.CapacityMutationBinding, input guestOriginalStepInput, receipt model.CapacityMutationReceipt) (repository.GuestNativeAbsenceReturnV2, model.CapacityMutationProof, bool, error) {
	var returned repository.GuestNativeAbsenceReturnV2
	var proof model.CapacityMutationProof
	read, stop := context.WithTimeout(ctx, 5*time.Second)
	defer stop()
	challenge, err := store.PrepareGuestNativePoweroffReadV2(read, input.RequestID)
	if err != nil {
		return returned, proof, false, err
	}
	reader, err := productionRetirementSupplierV2(read, store, policy, p, b, input)
	if err != nil {
		return returned, proof, false, err
	}
	returned = repository.GuestNativeAbsenceReturnV2{Schema: "original_core_guest_native_absence_return_v2", Challenge: challenge, DestroyGrantID: receipt.Grant.GrantID, OriginalDestroyReceiptSHA256: capacity.GuestRetirementSHA(receipt), StartedAtCore: time.Now().UTC()}
	var observed model.CapacityVMRetirementObservation
	if !productionRetirementCatalogV2(reader.provider, reader.resolved.typeSpec) {
		return returned, proof, false, errOriginalGuestStep
	}
	operation := capacity.VMObserveRetirement
	fixed := map[string]any{"profile": b.ProfileName, "slot": input.Slot, "grant_id": receipt.Grant.GrantID, "expected_resource_id": receipt.ResourceID, "expected_resource_created_at": receipt.ResourceCreatedAt}
	if reader.provider == "aws" {
		operation = "observe_ec2_instance"
		fixed["retirement"] = true
	}
	returned.Status, err = reader.call(read, operation, fixed, &observed)
	returned.OriginalReturnedAtCore = time.Now().UTC()
	returned.CallFailed = err != nil
	returned.OriginalContextFailed = read.Err() != nil || !returned.OriginalReturnedAtCore.Before(challenge.OriginalDeadlineCore)
	if err == nil {
		returned.Observation = &observed
	}
	retain, stopRetain := context.WithTimeout(context.WithoutCancel(read), 5*time.Second)
	proof, recordErr := store.RecordGuestNativeAbsenceV2(retain, returned)
	stopRetain()
	if err != nil || returned.OriginalContextFailed {
		return returned, proof, false, errOriginalGuestStep
	}
	if recordErr != nil {
		pending := originalAWSRetirementPendingV2(observed, receipt)
		if reader.provider == "hetzner" {
			pending = originalHetznerRetirementPendingV2(observed, receipt)
		}
		return returned, proof, returned.Status == "observed" && pending, errOriginalGuestStep
	}
	return returned, proof, false, nil
}

func originalAWSRetirementPendingV2(o model.CapacityVMRetirementObservation, r model.CapacityMutationReceipt) bool {
	l := o.AWSRetirementLifecycle
	if r.Grant.State != "settled" || r.Outcome != "accepted" || !r.TransportCompleted || !r.AuxiliaryInventoryComplete || len(r.AuxiliaryResources) != 2 || o.DestroyGrantID != r.Grant.GrantID || o.DestroyGrantState != r.Grant.State || o.ID != r.ResourceID || o.CreatedAt != r.ResourceCreatedAt || o.OriginalOutcome != "accepted" || !o.OriginalTransportCompleted || !o.AuxiliaryInventoryComplete || len(o.AuxiliaryResources) != 2 || o.RetirementComplete || len(o.HoldReasons) < 1 || len(o.HoldReasons) > 3 || o.WriterQuiescenceEvidence || o.ProviderFencingEvidence || o.InvoiceReconciled || o.BillingExposure != nil || o.DeleteAction != (model.CapacityVMRetirementAction{}) || o.NextActions == nil || len(o.NextActions) != 0 || l == nil || l.Schema != "aws_original_terminate_and_native_absence_v1" || l.RequestID != r.ActionID {
		return false
	}
	switch l.EC2State {
	case "pending", "running", "stopping", "stopped", "shutting-down", "terminated", "not_found":
	default:
		return false
	}
	absent := l.EC2State == "terminated" || l.EC2State == "not_found"
	if o.ServerAbsent != absent || o.ServerAbsenceComplete != absent || o.BillableResourcesAbsent || (absent && o.ServerStatus != "") || (!absent && o.ServerStatus != l.EC2State) {
		return false
	}
	seen := map[string]bool{}
	for _, hold := range o.HoldReasons {
		if seen[hold] || (hold != "instance_not_terminated" && hold != "aws_ebs_volume_still_present" && hold != "aws_network_interface_still_present") {
			return false
		}
		seen[hold] = true
	}
	if seen["instance_not_terminated"] == absent {
		return false
	}
	for n, a := range o.AuxiliaryResources {
		if a.Kind != r.AuxiliaryResources[n].Kind || a.ID != r.AuxiliaryResources[n].ID || seen[a.Kind+"_still_present"] == a.Absent {
			return false
		}
	}
	return true
}

func productionRetirementCatalogV2(provider string, ts model.IntegrationTypeManifestSpec) bool {
	if provider == "aws" {
		return (ts.Adapter.Version == "1.62.0" || ts.Adapter.Version == "1.63.0" || ts.Adapter.Version == "1.64.0" || ts.Adapter.Version == "1.65.1" || ts.Adapter.Version == "1.65.2" || ts.Adapter.Version == "1.65.3" || ts.Adapter.Version == "1.65.4" || ts.Adapter.Version == "1.65.5") && originalGuestSupplierCatalogFor(provider, ts)
	}
	return provider == "hetzner" && (ts.Adapter.Version == "0.3.0" || ts.Adapter.Version == "0.3.2" || ts.Adapter.Version == "0.3.3" || ts.Adapter.Version == "0.3.4" || ts.Adapter.Version == "0.3.5") && originalGuestSupplierCatalogFor(provider, ts)
}

func originalHetznerRetirementPendingV2(o model.CapacityVMRetirementObservation, r model.CapacityMutationReceipt) bool {
	if r.Grant.State != "settled" || r.Grant.CompensationOf != "" || r.Outcome != "accepted" || !r.TransportCompleted || !r.AuxiliaryInventoryComplete || len(r.AuxiliaryResources) < 1 || len(r.AuxiliaryResources) > 2 || o.AWSRetirementLifecycle != nil || o.DestroyGrantID != r.Grant.GrantID || o.DestroyGrantState != r.Grant.State || o.CompensationOf != "" || o.ID != r.ResourceID || o.CreatedAt != r.ResourceCreatedAt || o.OriginalOutcome != "accepted" || !o.OriginalTransportCompleted || !o.ServerAbsenceComplete || !o.AuxiliaryInventoryComplete || len(o.AuxiliaryResources) != len(r.AuxiliaryResources) || o.RetirementComplete || len(o.HoldReasons) < 1 || len(o.HoldReasons) > 3 || o.WriterQuiescenceEvidence || o.ProviderFencingEvidence || o.InvoiceReconciled || o.BillingExposure != nil || o.DeleteAction.ID != r.ActionID || !o.DeleteAction.Known || !o.DeleteAction.Observed || o.DeleteAction.Command != "delete_server" || o.DeleteAction.ErrorCode != "" || (o.DeleteAction.Status != "running" && o.DeleteAction.Status != "success") || o.NextActions == nil || len(o.NextActions) != len(r.NextActionIDs) {
		return false
	}
	seen := map[string]bool{}
	for _, hold := range o.HoldReasons {
		if seen[hold] || (hold != "native_server_present" && hold != "original_delete_actions_not_successful" && hold != "native_billable_resources_present") {
			return false
		}
		seen[hold] = true
	}
	allAbsent := o.ServerAbsent
	if o.ServerAbsent && o.ServerStatus != "" || !o.ServerAbsent && o.ServerStatus == "" {
		return false
	}
	for n, a := range o.AuxiliaryResources {
		if a.Kind != r.AuxiliaryResources[n].Kind || a.ID != r.AuxiliaryResources[n].ID {
			return false
		}
		allAbsent = allAbsent && a.Absent
	}
	allActions := o.DeleteAction.Status == "success"
	for n, a := range o.NextActions {
		if a.ID != r.NextActionIDs[n] || a.ResourceID != r.ResourceID || a.ErrorCode != "" || (a.Status != "running" && a.Status != "success") {
			return false
		}
		allActions = allActions && a.Status == "success"
	}
	return seen["native_server_present"] != o.ServerAbsent && seen["original_delete_actions_not_successful"] != allActions && seen["native_billable_resources_present"] != allAbsent && o.BillableResourcesAbsent == allAbsent
}
