package message

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/manifest"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	"github.com/google/uuid"
	amqp "github.com/rabbitmq/amqp091-go"
)

var errCapacityNativeObservation = fmt.Errorf("protected native VM observation refused")

func capacityNativeOperation(operation string) bool {
	switch operation {
	case "capacity.observe_vm_inventory", "capacity.observe_failed_vm_creation", "capacity.record_vm_inventory", "capacity.confirm_native_mutation", "capacity.observe_vm_node_membership", "capacity.observe_original_creation_canary":
		return true
	}
	return false
}

// The fixed operation chooses every capability, scope and proof-producing
// read. Workflow input supplies no provider URL, selector, assessment or bool.
func executeCapacityNativeWorkflowStep(ctx context.Context, conn *amqp.Connection, db *sql.DB, workflowRef model.ManifestReference, result model.WorkflowRunStepResult, input map[string]any) model.WorkflowRunStepResult {
	if result.Operation == "capacity.observe_original_creation_canary" {
		return executeCapacityBusinessWorkflowStep(ctx, conn, db, workflowRef, result, input)
	}
	if result.Operation == "capacity.observe_vm_node_membership" {
		return executeCapacityVMNodeWorkflowStep(ctx, conn, db, workflowRef, result, input)
	}
	result.Attempts = 1
	fail := func() model.WorkflowRunStepResult {
		result.Error = errCapacityNativeObservation.Error()
		result.FinishedAt = time.Now().UTC()
		return result
	}
	parent := ctx
	ctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	ctx = withNativeAdapterPolicy(ctx, parent)
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
		r, err := executeIntegrationThroughResolvedWithPolicy(ctx, conn, model.ExecuteIntegrationRequest{Operation: operation, Capability: operation, Input: fixed}, im, is, tm, ts, 65*time.Second, integrationExecutionPolicy{detailFreeErrors: true, safeError: errCapacityNativeObservation, requireExplicitResponse: true, nativeHTTP: &nativeAdapterHTTPPolicy{limit: 2 << 20, parent: parent}})
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

func capacityVMNodeContextFailure(ctx context.Context) error {
	if ctx == nil {
		return errors.New("original membership context missing")
	}
	err := errors.Join(ctx.Err(), context.Cause(ctx), nativeAdapterContext(ctx))
	if d, ok := ctx.Deadline(); ok && !time.Now().Before(d) {
		err = errors.Join(err, context.DeadlineExceeded)
	}
	return err
}

// Check both immutable catalogs before any private resolver can hydrate a
// credential or make a health/Describe request. This operation is GET-only.
func preflightVMNodeCatalog(ctx context.Context, db *sql.DB, b model.CapacityObservationAdapterBinding, operations []string) error {
	im, err := resolveManifestForKind(ctx, db, "integration_instance", b.IntegrationInstanceID, "", "", nil)
	if err != nil || !im.Metadata.Active || im.Kind != "integration_instance" || im.ID.String() != b.IntegrationInstanceID || im.Checksum != b.InstanceChecksum {
		return errCapacityNativeObservation
	}
	is, err := manifest.ParseIntegrationInstanceSpec(im.Spec)
	if err != nil {
		return errCapacityNativeObservation
	}
	tm, err := resolveManifestForKind(ctx, db, "integration_type", is.TypeRef.ManifestID, is.TypeRef.Namespace, is.TypeRef.Name, is.TypeRef.Version)
	if err != nil || !tm.Metadata.Active || tm.Kind != "integration_type" || tm.ID.String() != b.IntegrationTypeID || tm.Checksum != b.TypeChecksum {
		return errCapacityNativeObservation
	}
	ts, err := manifest.ParseIntegrationTypeSpec(tm.Spec)
	if err != nil || manifest.ValidateIntegrationTypeSpec(ts) != nil {
		return errCapacityNativeObservation
	}
	for _, op := range operations {
		if !capacityNativeCatalogOperation(ts, op) {
			return errCapacityNativeObservation
		}
	}
	return capacityVMNodeContextFailure(ctx)
}

func executeCapacityVMNodeWorkflowStep(parent context.Context, conn *amqp.Connection, db *sql.DB, workflowRef model.ManifestReference, result model.WorkflowRunStepResult, input map[string]any) (out model.WorkflowRunStepResult) {
	out = result
	out.Attempts, out.Status, out.Error = 1, "failed", errCapacityNativeObservation.Error()
	if capacityVMNodeContextFailure(parent) != nil {
		out.FinishedAt = time.Now().UTC()
		return out
	}
	ctx, cancel := context.WithTimeout(parent, 90*time.Second)
	defer cancel()
	ctx = withNativeAdapterPolicy(ctx, parent)
	defer func() {
		out.FinishedAt = time.Now().UTC()
		if errors.Join(capacityVMNodeContextFailure(ctx), capacityVMNodeContextFailure(parent)) != nil {
			out.Status, out.Error, out.Metadata = "failed", errCapacityNativeObservation.Error(), nil
		}
	}()
	var parsed model.CapacityVMObservationInput
	if db == nil || result.Operation != "capacity.observe_vm_node_membership" || capacity.DecodeVMObservation(input, &parsed) != nil || parsed.Policy.ManifestID != "" || parsed.Policy.Version != nil || parsed.Policy.Namespace == "" || parsed.Policy.Name == "" || parsed.BindingName == "" || parsed.Generation != 0 || parsed.FencingToken != 0 || parsed.LeaseOwner != "" || parsed.GrantID != "" || parsed.ParentGrantID != "" || parsed.Slot != 0 {
		return out
	}
	executor, _ := ctx.Value(capacityInvocationKey{}).(string)
	if id, e := uuid.Parse(executor); e != nil || id == uuid.Nil || id.String() != executor {
		return out
	}
	policy, err := repository.ResolveManifest(ctx, db, "capacity_policy", parsed.Policy.Namespace, parsed.Policy.Name, nil, true)
	if err != nil {
		return out
	}
	p, err := manifest.ParseCapacityPolicySpec(policy.Spec)
	if err != nil || manifest.ValidateCapacityPolicySpec(p) != nil || p.VMNodeMembershipBinding == nil || p.VMNodeMembershipBinding.MutationBindingName != parsed.BindingName || workflowRef.Kind != "workflow" || workflowRef.Namespace != p.Workflow.Namespace || workflowRef.Name != p.Workflow.Name {
		return out
	}
	wf, err := repository.ResolveManifest(ctx, db, "workflow", p.Workflow.Namespace, p.Workflow.Name, nil, true)
	if err != nil || wf.ID != workflowRef.ID || wf.Version != workflowRef.Version {
		return out
	}
	ws, err := manifest.ParseWorkflowSpec(wf.Spec)
	if err != nil || ws.Authorization == nil {
		return out
	}
	b, err := capacity.VMObservationBinding(p, parsed.BindingName)
	if err != nil {
		return out
	}
	vmRevision := model.CapacityObservationAdapterBinding{IntegrationInstanceID: b.IntegrationInstanceID, InstanceChecksum: b.IntegrationChecksum, IntegrationTypeID: b.IntegrationTypeID, TypeChecksum: b.IntegrationTypeChecksum}
	nb := p.VMNodeMembershipBinding
	if preflightVMNodeCatalog(ctx, db, vmRevision, []string{capacity.VMObserveInventory, capacity.VMObserveAction}) != nil || preflightVMNodeCatalog(ctx, db, nb.Adapter, []string{capacity.ObserveNodeMembership}) != nil {
		return out
	}
	vm, err := resolveCapacityObservationAdapterWithResolver(ctx, conn, db, vmRevision, []string{capacity.VMObserveInventory, capacity.VMObserveAction}, resolveIntegrationInstance)
	if err != nil {
		return out
	}
	native, err := resolveCapacityObservationAdapterWithResolver(ctx, conn, db, nb.Adapter, []string{capacity.ObserveNodeMembership}, resolveIntegrationInstance)
	if err != nil {
		return out
	}
	read := func(a capacityResolvedObservationAdapter, op string, fixed map[string]any, reply any) error {
		if errors.Join(capacityVMNodeContextFailure(ctx), capacityVMNodeContextFailure(parent)) != nil {
			return errCapacityNativeObservation
		}
		r, e := executeIntegrationThroughResolvedWithPolicy(ctx, conn, model.ExecuteIntegrationRequest{Operation: op, Capability: op, Input: fixed}, a.instance, a.instanceSpec, a.typ, a.typeSpec, 65*time.Second, integrationExecutionPolicy{detailFreeErrors: true, safeError: errCapacityNativeObservation, requireExplicitResponse: true, nativeHTTP: &nativeAdapterHTTPPolicy{limit: 2 << 20, parent: parent}})
		if e != nil || errors.Join(capacityVMNodeContextFailure(ctx), capacityVMNodeContextFailure(parent)) != nil || r.Status != "observed" || capacity.DecodeVMObservation(r.Output, reply) != nil {
			return errCapacityNativeObservation
		}
		return capacityVMNodeContextFailure(ctx)
	}
	store := repository.CapacityStore{DB: db, WorkflowID: wf.ID, ExecutorID: executor}
	readVM := func() (model.CapacityVMFleetInventory, error) {
		var inv model.CapacityVMFleetInventory
		if e := read(vm, capacity.VMObserveInventory, map[string]any{"profile": b.ProfileName}, &inv); e != nil {
			return inv, e
		}
		proofs, e := capacity.VMInventoryProofs(p, b, inv, "", 0, time.Now().UTC(), "core-native-node-membership")
		if e != nil || inv.FailedCreation != nil {
			return inv, errCapacityNativeObservation
		}
		if e = store.CheckNativeMembershipCoverage(ctx, policy, b, proofs); e != nil || capacityVMNodeContextFailure(ctx) != nil {
			return inv, errCapacityNativeObservation
		}
		return inv, nil
	}
	before, err := readVM()
	if err != nil {
		return out
	}
	// A baseline without an owning create grant can be linked physically, but
	// it never acquires provider-mutation quiescence authority from that link.
	creationKnown := true
	for _, member := range before.Members {
		id := member.Server.Labels["yggdrasil.io/intent"]
		if id == "" {
			creationKnown = false
			continue
		}
		r, e := store.NativeMutationReceipt(ctx, policy, b, id)
		if e != nil || (r.Grant.State != "settled" && r.Grant.State != "confirmed") || r.Grant.CompensationOf != "" || r.Grant.Capability != b.EnsureCapability || !r.TransportCompleted || (r.Outcome != "accepted" && r.Outcome != "uncertain") || r.ResourceID != member.Server.ID || r.ResourceCreatedAt != member.Server.CreatedAt || r.Grant.Slot != member.Slot || r.Grant.RequestSHA256 != member.RequestSHA256 {
			return out
		}
		fixed := map[string]any{"profile": b.ProfileName, "slot": member.Slot, "grant_id": id, "expected_resource_id": member.Server.ID, "expected_resource_created_at": member.Server.CreatedAt}
		collection := model.CapacityVMActionCollection{ResourceID: member.Server.ID, ResourceCreatedAt: member.Server.CreatedAt, Complete: true}
		ids := append([]string{}, r.NextActionIDs...)
		if r.ActionID != "" {
			ids = append([]string{r.ActionID}, ids...)
		}
		if len(ids) == 0 {
			if read(vm, capacity.VMObserveAction, fixed, &collection) != nil || collection.CreationGrantID != id || collection.ResourceCreatedAt != member.Server.CreatedAt {
				return out
			}
		} else {
			if len(ids) > 64 {
				return out
			}
			for _, actionID := range ids {
				var action model.CapacityVMActionObservation
				fixed["action_id"] = actionID
				if read(vm, capacity.VMObserveAction, fixed, &action) != nil || action.ID != actionID {
					return out
				}
				collection.Actions = append(collection.Actions, action)
			}
			collection.ObservedAt = time.Now().UTC().Format(time.RFC3339Nano)
		}
		if _, e = capacity.VMActionProof(p, collection, member.Server.ID, time.Now().UTC(), true); e != nil {
			return out
		}
	}
	var nodes, nodesAfter model.CapacityNodeMembershipResponse
	if read(native, capacity.ObserveNodeMembership, map[string]any{"binding_name": nb.Target.BindingName}, &nodes) != nil {
		return out
	}
	joins, err := capacity.JoinVMNodeMembership(p, before, nodes, time.Now().UTC())
	if err != nil {
		return out
	}
	after, err := readVM()
	if err != nil || read(native, capacity.ObserveNodeMembership, map[string]any{"binding_name": nb.Target.BindingName}, &nodesAfter) != nil {
		return out
	}
	final, err := capacity.JoinVMNodeMembership(p, after, nodesAfter, time.Now().UTC())
	if err != nil || len(joins) != len(final) {
		return out
	}
	for i := range joins {
		a, z := joins[i], final[i]
		if a.Slot != z.Slot || a.ResourceID != z.ResourceID || a.ResourceCreatedAt != z.ResourceCreatedAt || a.DesiredSpecSHA256 != z.DesiredSpecSHA256 || a.Node.Name != z.Node.Name || a.Node.UID != z.Node.UID || !a.Node.CreatedAt.Equal(z.Node.CreatedAt) || a.Node.ProviderID != z.Node.ProviderID || a.Node.BootID != z.Node.BootID || a.Node.Ready != z.Node.Ready || !a.Node.ReadyChangedAt.Equal(z.Node.ReadyChangedAt) || a.Node.Unschedulable != z.Node.Unschedulable || a.Node.LeaseUID != z.Node.LeaseUID || a.Node.LeaseHolder != z.Node.LeaseHolder {
			return out
		}
	}
	metadata := map[string]any{"native_join_observed": len(final) > 0, "joins": final, "before_node_read": nodes, "after_node_read": nodesAfter, "creation_action_history_known": creationKnown, "provider_mutation_quiescence_known": false, "atomic_snapshot": false, "bootstrap_completed_known": false, "warm_resources_known": false, "useful_capacity_known": false, "routing_withdrawn_known": false, "business_drain_known": false, "physical_capacity_released": false, "missing": []string{"bootstrap_completion", "warmup", "useful_canary", "route_lifecycle", "business_drain", "writer_retirement", "provider_quiescence"}}
	raw, err := json.Marshal(metadata)
	if err != nil || len(raw) > 4<<20 || capacityVMNodeContextFailure(ctx) != nil {
		return out
	}
	if json.Unmarshal(raw, &out.Metadata) != nil {
		out.Metadata = nil
		return out
	}
	out.Status, out.Error = "succeeded", ""
	return out
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
