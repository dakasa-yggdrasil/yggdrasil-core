package message

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/manifest"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	amqp "github.com/rabbitmq/amqp091-go"
)

var errCapacityNativeObservation = fmt.Errorf("protected native VM observation refused")

func capacityNativeOperation(operation string) bool {
	switch operation {
	case "capacity.observe_vm_inventory", "capacity.observe_failed_vm_creation", "capacity.record_vm_inventory", "capacity.confirm_native_mutation":
		return true
	}
	return false
}

// The fixed operation chooses every capability, scope and proof-producing
// read. Workflow input supplies no provider URL, selector, assessment or bool.
func executeCapacityNativeWorkflowStep(ctx context.Context, conn *amqp.Connection, db *sql.DB, workflowRef model.ManifestReference, result model.WorkflowRunStepResult, input map[string]any) model.WorkflowRunStepResult {
	result.Attempts = 1
	fail := func() model.WorkflowRunStepResult {
		result.Error = errCapacityNativeObservation.Error()
		result.FinishedAt = time.Now().UTC()
		return result
	}
	ctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	var parsed model.CapacityVMObservationInput
	if !capacityNativeOperation(result.Operation) || capacity.DecodeVMObservation(input, &parsed) != nil || db == nil || parsed.Policy.ManifestID != "" || strings.TrimSpace(parsed.Policy.Namespace) == "" || strings.TrimSpace(parsed.Policy.Name) == "" || parsed.BindingName == "" {
		return fail()
	}
	writes := result.Operation == "capacity.record_vm_inventory" || result.Operation == "capacity.confirm_native_mutation"
	if parsed.Policy.Version != nil && (!writes || *parsed.Policy.Version < 1) {
		return fail()
	}
	if !writes && (parsed.Generation != 0 || parsed.FencingToken != 0 || parsed.LeaseOwner != "") {
		return fail()
	}
	if writes && (parsed.Generation < 1 || parsed.FencingToken < 1 || parsed.LeaseOwner == "") {
		return fail()
	}
	if result.Operation == "capacity.confirm_native_mutation" {
		if parsed.GrantID == "" || parsed.ParentGrantID != "" || parsed.Slot != 0 {
			return fail()
		}
	} else if parsed.GrantID != "" || (parsed.ParentGrantID == "") != (parsed.Slot == 0) || parsed.Slot < 0 || (result.Operation == "capacity.observe_failed_vm_creation" && parsed.ParentGrantID == "") {
		return fail()
	}
	policy, err := repository.ResolveManifest(ctx, db, "capacity_policy", parsed.Policy.Namespace, parsed.Policy.Name, parsed.Policy.Version, parsed.Policy.Version == nil)
	if err != nil {
		return fail()
	}
	p, err := manifest.ParseCapacityPolicySpec(policy.Spec)
	if err != nil || manifest.ValidateCapacityPolicySpec(p) != nil || workflowRef.Kind != "workflow" || workflowRef.Namespace != p.Workflow.Namespace || workflowRef.Name != p.Workflow.Name {
		return fail()
	}
	wf, err := repository.ResolveManifest(ctx, db, "workflow", p.Workflow.Namespace, p.Workflow.Name, nil, true)
	if err != nil || wf.ID != workflowRef.ID || wf.Version != workflowRef.Version {
		return fail()
	}
	workflow, err := manifest.ParseWorkflowSpec(wf.Spec)
	if err != nil || workflow.Authorization == nil {
		return fail()
	}
	b, err := capacity.VMObservationBinding(p, parsed.BindingName)
	if err != nil {
		return fail()
	}
	executorID, _ := ctx.Value(capacityInvocationKey{}).(string)
	store := repository.CapacityStore{DB: db, ExecutionEnabled: os.Getenv("YGGDRASIL_CAPACITY_EXECUTION_ENABLED") == "true", WorkflowID: wf.ID, ExecutorID: executorID}
	if writes && store.ValidateNativeObservationLease(ctx, policy, parsed.Generation, parsed.FencingToken, parsed.LeaseOwner) != nil {
		return fail()
	}
	required := []string{capacity.VMObserveInventory}
	switch result.Operation {
	case "capacity.observe_failed_vm_creation":
		required = []string{capacity.VMObserveFailedCreation}
	case "capacity.confirm_native_mutation":
		required = []string{capacity.VMObserveServer, capacity.VMObserveAction}
	}
	revision := model.CapacityObservationAdapterBinding{IntegrationInstanceID: b.IntegrationInstanceID, InstanceChecksum: b.IntegrationChecksum, IntegrationTypeID: b.IntegrationTypeID, TypeChecksum: b.IntegrationTypeChecksum}
	resolved, err := resolveCapacityObservationAdapterWithResolver(ctx, conn, db, revision, required, resolveIntegrationInstance)
	if err != nil {
		return fail()
	}
	im, is, tm, ts := resolved.instance, resolved.instanceSpec, resolved.typ, resolved.typeSpec
	read := func(operation string, fixed map[string]any, out any) (string, error) {
		if !capacityNativeCatalogOperation(ts, operation) {
			return "", errCapacityNativeObservation
		}
		r, err := executeIntegrationThroughResolvedWithPolicy(ctx, conn, model.ExecuteIntegrationRequest{Operation: operation, Capability: operation, Input: fixed}, im, is, tm, ts, 65*time.Second, integrationExecutionPolicy{detailFreeErrors: true, safeError: errCapacityNativeObservation, requireExplicitResponse: true})
		if err != nil || (r.Status != "observed" && r.Status != "absent") || capacity.DecodeVMObservation(r.Output, out) != nil {
			return "", errCapacityNativeObservation
		}
		return r.Status, nil
	}
	receiptRef := "core-native:" + wf.ID.String() + ":" + b.IntegrationInstanceID + ":" + result.Operation
	var output any
	switch result.Operation {
	case "capacity.observe_vm_inventory", "capacity.record_vm_inventory":
		var parent *model.CapacityMutationReceipt
		fixed := map[string]any{"profile": b.ProfileName}
		if parsed.ParentGrantID != "" {
			r, err := store.NativeMutationReceipt(ctx, policy, b, parsed.ParentGrantID)
			if err != nil || !capacityNativeFailedParent(r, b, parsed.Slot) {
				return fail()
			}
			parent = &r
			fixed["failed_creation_parent"], fixed["slot"] = parsed.ParentGrantID, parsed.Slot
		}
		var inv model.CapacityVMFleetInventory
		status, err := read(capacity.VMObserveInventory, fixed, &inv)
		if err != nil || status != "observed" {
			return fail()
		}
		proofs, err := capacity.VMInventoryProofs(p, b, inv, parsed.ParentGrantID, parsed.Slot, time.Now().UTC(), receiptRef)
		if err != nil || (parent != nil && !capacityNativeFailedReadbackMatches(*parent, inv.FailedCreation)) {
			return fail()
		}
		registered := 0
		if writes {
			for _, proof := range proofs {
				var projection *model.CapacityMutationSpecV1
				for _, slot := range b.Slots {
					if slot.Slot == proof.Slot {
						projection = slot.DesiredSpec
					}
				}
				raw, err := json.Marshal(projection)
				if err != nil || projection == nil || store.RecordMutationSlot(ctx, policy, parsed.Generation, parsed.FencingToken, parsed.LeaseOwner, model.CapacityMutationIssue{BindingName: b.Name, DesiredSpec: raw}, proof) != nil {
					return fail()
				}
				registered++
			}
			if store.CheckNativeMembershipCoverage(ctx, policy, b, proofs) != nil {
				return fail()
			}
		}
		output = model.CapacityVMInventoryReceipt{Inventory: inv, MutationProofs: proofs, NativeMembers: len(inv.Members), Registered: registered}
	case "capacity.observe_failed_vm_creation":
		parent, err := store.NativeMutationReceipt(ctx, policy, b, parsed.ParentGrantID)
		if err != nil || !capacityNativeFailedParent(parent, b, parsed.Slot) {
			return fail()
		}
		var candidate model.CapacityVMFailedCreationCandidate
		status, err := read(capacity.VMObserveFailedCreation, map[string]any{"profile": b.ProfileName, "slot": parsed.Slot, "grant_id": parsed.ParentGrantID}, &candidate)
		if err != nil || status != "observed" || !capacityNativeFailedReadbackMatches(parent, &candidate) {
			return fail()
		}
		proof, err := capacity.VMFailedCreationProof(p, b, candidate, parsed.ParentGrantID, parsed.Slot, time.Now().UTC(), receiptRef)
		if err != nil {
			return fail()
		}
		output = map[string]any{"candidate": candidate, "mutation_proof": proof, "useful_capacity_known": false}
	case "capacity.confirm_native_mutation":
		r, err := store.NativeMutationReceipt(ctx, policy, b, parsed.GrantID)
		if err != nil || r.Grant.CompensationOf != "" || (r.Grant.State != "settled" && r.Grant.State != "confirmed") {
			return fail()
		}
		fixed := map[string]any{"profile": b.ProfileName, "slot": r.Grant.Slot, "grant_id": r.Grant.GrantID}
		if r.Grant.Capability == b.DestroyCapability {
			fixed["expected_resource_id"], fixed["expected_resource_created_at"] = r.Grant.ExpectedResourceID, r.Grant.ExpectedResourceCreatedAt
		} else if r.ResourceID != "" {
			fixed["expected_resource_id"], fixed["expected_resource_created_at"] = r.ResourceID, r.ResourceCreatedAt
		}
		var plan model.CapacityVMFleetPlan
		status, err := read(capacity.VMObserveServer, fixed, &plan)
		if err != nil {
			return fail()
		}
		proof, err := capacity.VMServerPlanProof(p, b, plan, r, status, time.Now().UTC(), receiptRef)
		if err != nil {
			return fail()
		}
		fixed["expected_resource_id"], fixed["expected_resource_created_at"] = proof.ResourceID, proof.ResourceCreatedAt
		ids := append([]string{}, r.NextActionIDs...)
		if r.ActionID != "" {
			ids = append([]string{r.ActionID}, ids...)
		}
		collection := model.CapacityVMActionCollection{ResourceID: proof.ResourceID, ResourceCreatedAt: proof.ResourceCreatedAt, Complete: true}
		if len(ids) == 0 {
			if proof.ResourceAbsent {
				return fail() // Unknown deletion actions cannot be recovered from absence.
			}
			status, err = read(capacity.VMObserveAction, fixed, &collection)
			if err != nil || status != "observed" || collection.CreationGrantID != r.Grant.GrantID || collection.ResourceCreatedAt != proof.ResourceCreatedAt {
				return fail()
			}
			proof.ActionHistoryComplete = true
		} else {
			if len(ids) > 64 {
				return fail()
			}
			for _, id := range ids {
				var action model.CapacityVMActionObservation
				fixed["action_id"] = id
				status, err = read(capacity.VMObserveAction, fixed, &action)
				if err != nil || status != "observed" || action.ID != id {
					return fail()
				}
				collection.Actions = append(collection.Actions, action)
			}
			collection.ObservedAt = time.Now().UTC().Format(time.RFC3339Nano)
		}
		proof.ActionIDs, err = capacity.VMActionProof(p, collection, proof.ResourceID, time.Now().UTC(), true)
		if err != nil {
			return fail()
		}
		proof.ActionsTerminal, proof.ActionsSuccessful = true, true
		// Repeat observation never re-emits an event or alters the original
		// confirmed receipt. Fresh readback can differ in timestamp.
		grant := r.Grant
		if grant.State != "confirmed" {
			grant, err = store.ConfirmMutation(ctx, policy, parsed.Generation, parsed.FencingToken, parsed.LeaseOwner, proof)
			if err != nil {
				return fail()
			}
		}
		output = map[string]any{"grant": grant, "mutation_proof": proof, "useful_capacity_known": false}
	}
	raw, err := json.Marshal(output)
	if err != nil || json.Unmarshal(raw, &result.Metadata) != nil {
		return fail()
	}
	result.Status, result.Error, result.FinishedAt = "succeeded", "", time.Now().UTC()
	return result
}

func capacityNativeCatalogOperation(ts model.IntegrationTypeManifestSpec, operation string) bool {
	if !strings.HasPrefix(operation, "observe_") || !slices.Contains(ts.Capabilities, "execute") {
		return false
	}
	for _, action := range ts.ActionCatalog {
		if action.Name != operation || (action.Category != "" && action.Category != "capability") {
			continue
		}
		for _, resource := range ts.ResourceTypes {
			if slices.Contains(action.ResourceTypes, resource.Name) && slices.Contains(resource.DefaultActions, operation) {
				return true
			}
		}
	}
	return false
}

func capacityNativeFailedParent(r model.CapacityMutationReceipt, b model.CapacityMutationBinding, slot int) bool {
	g := r.Grant
	return g.CompensationOf == "" && g.Capability == b.EnsureCapability && g.Slot == slot && g.BindingName == b.Name && g.IntegrationInstanceID == b.IntegrationInstanceID && g.ScopeChecksum == b.ScopeChecksum && g.ProfileName == b.ProfileName && (g.State == "settled" || g.State == "compensating") && r.TransportCompleted && (r.Outcome == "accepted" || r.Outcome == "uncertain")
}

func capacityNativeFailedReadbackMatches(r model.CapacityMutationReceipt, c *model.CapacityVMFailedCreationCandidate) bool {
	if c == nil || c.Plan.Server == nil || c.ParentGrantID != r.Grant.GrantID || c.Plan.RequestSHA256 != r.Grant.RequestSHA256 {
		return false
	}
	s := c.Plan.Server
	if r.ResourceID != "" && (s.ID != r.ResourceID || s.CreatedAt != r.ResourceCreatedAt) {
		return false
	}
	if previous := r.NativeReadback; previous != nil && (s.ID != previous.ResourceID || s.CreatedAt != previous.ResourceCreatedAt || previous.ObservedCreationGrantID != r.Grant.GrantID) {
		return false
	}
	seen := map[string]bool{}
	for _, action := range c.Actions.Actions {
		seen[action.ID] = true
	}
	for _, id := range append([]string{r.ActionID}, r.NextActionIDs...) {
		if id != "" && !seen[id] {
			return false
		}
	}
	if r.NativeReadback != nil {
		for _, id := range r.NativeReadback.ActionIDs {
			if !seen[id] {
				return false
			}
		}
	}
	return true
}
