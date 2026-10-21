//go:build !nativequalification

package message

import (
	"context"
	"errors"
	"reflect"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacityguestprovider"
	"github.com/dakasa-yggdrasil/yggdrasil-core/manifest"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	amqp "github.com/rabbitmq/amqp091-go"
)

type originalGuestTransportKey struct{}
type productionGuestInvocationKey struct{}
type originalGuestTransport struct{ conn *amqp.Connection }

// Only the original workflow executor installs its transport dependency. This
// is not a manifest/JSON registration API and carries no provider or proof.
func withOriginalGuestWorkflowTransport(ctx context.Context, conn *amqp.Connection) context.Context {
	return context.WithValue(ctx, originalGuestTransportKey{}, originalGuestTransport{conn})
}
func guestOriginalProviderAvailable(ctx context.Context) bool {
	_, ok := ctx.Value(originalGuestTransportKey{}).(originalGuestTransport)
	return ok
}

type productionGuestInvocation struct {
	owner     *capacityguestprovider.Invocation
	supplier  *originalHetznerGuestSupplier
	grant     model.CapacityMutationGrant
	pre       model.CapacityGuestOriginalProvisioningPreregistration
	witness   model.CapacityGuestOriginalCreateWitness
	receipt   model.CapacityGuestOriginalProvisioningReceipt
	installed bool
}

func productionGuestSource(ctx context.Context) (*productionGuestInvocation, error) {
	source, ok := ctx.Value(productionGuestInvocationKey{}).(*productionGuestInvocation)
	if !ok || source == nil || source.owner == nil || ctx.Err() != nil {
		return nil, errOriginalGuestStep
	}
	return source, nil
}

// This constructor selects the existing reviewed Hetzner durable grant
// protocol. AWS's legacy name-adopting EC2 ensure is deliberately unsupported:
// it has no compatible original redemption/settlement supplier.
func guestOriginalProviderInvocation(ctx context.Context, store repository.CapacityStore, policy, workflow model.Manifest, step model.WorkflowStepSpec, p model.CapacityPolicySpec, b model.CapacityMutationBinding, input guestOriginalStepInput) (context.Context, guestOriginalProvider, error) {
	transport, ok := ctx.Value(originalGuestTransportKey{}).(originalGuestTransport)
	if !ok || step.Use.Operation != capacity.ProvisionOriginalGuestOperation || p.GuestRetirementBinding == nil || !capacity.GuestOriginalProfileEnabled(p, *p.GuestRetirementBinding, "hetzner") || b.EnsureCapability != "ensure_server" || b.DestroyCapability != "destroy_server" {
		return ctx, nil, errOriginalGuestStep
	}
	// Fail before catalog hydration, reservation or native send until the
	// repository implements this actual provider's original-return source.
	if !repository.OriginalGuestCreateWitnessProviderEnabled("hetzner") {
		return ctx, nil, errOriginalGuestStep
	}
	scope := model.CapacityObservationAdapterBinding{IntegrationInstanceID: b.IntegrationInstanceID, InstanceChecksum: b.IntegrationChecksum, IntegrationTypeID: b.IntegrationTypeID, TypeChecksum: b.IntegrationTypeChecksum}
	resolved, err := resolveOriginalGuestSupplier(ctx, transport.conn, store, scope, b.OriginalProviderSourceCommit)
	if err != nil {
		return ctx, nil, err
	}
	invocation, _ := ctx.Value(capacityInvocationKey{}).(string)
	memberName := ""
	for _, member := range p.GuestRetirementBinding.Members {
		if member.Slot == input.Slot {
			if memberName != "" {
				return ctx, nil, errOriginalGuestStep
			}
			memberName = member.Name
		}
	}
	supplier := &originalHetznerGuestSupplier{store: store, policy: policy, p: p, binding: b, resolved: resolved, conn: transport.conn, parent: ctx, input: input}
	owner, err := capacityguestprovider.New(ctx, capacityguestprovider.Scope{InvocationID: invocation, PolicyID: policy.ID.String(), PolicyChecksum: policy.Checksum, WorkflowID: workflow.ID.String(), WorkflowChecksum: workflow.Checksum, StepID: step.ID, StepTimeoutSeconds: step.TimeoutSeconds, ProvisioningBudgetSeconds: p.GuestRetirementBinding.ProfileManifest.OriginalProvisioningBudgetSeconds, MemberBindingName: memberName, Slot: input.Slot, Generation: input.Generation, Fence: input.FencingToken, LeaseOwner: input.LeaseOwner, ExecutorID: store.ExecutorID, CoreSourceCommit: capacity.CurrentGuestCoreSource(), ProfileSHA256: p.GuestRetirementBinding.ProfileManifestSHA256, Binding: b}, supplier)
	if err != nil {
		return ctx, nil, errOriginalGuestStep
	}
	source := &productionGuestInvocation{owner: owner, supplier: supplier}
	return context.WithValue(owner.Context(), productionGuestInvocationKey{}, source), source, nil
}

func (s *productionGuestInvocation) Prepare(ctx context.Context, slot int) error {
	if s == nil || s.owner == nil {
		return errOriginalGuestStep
	}
	return s.owner.Prepare(ctx, slot)
}

func (s *productionGuestInvocation) Create(ctx context.Context, store repository.CapacityStore, policy model.Manifest, g model.CapacityMutationGrant, pre model.CapacityGuestOriginalProvisioningPreregistration) (model.CapacityMutationProof, error) {
	if s == nil || s.owner == nil || s.supplier == nil || store.DB != s.supplier.store.DB || store.WorkflowID != s.supplier.store.WorkflowID || store.ExecutorID != s.supplier.store.ExecutorID || !reflect.DeepEqual(policy, s.supplier.policy) {
		return model.CapacityMutationProof{}, errOriginalGuestStep
	}
	return s.owner.Create(ctx, g, pre)
}

func originalGuestSupplierCatalog(ts model.IntegrationTypeManifestSpec) bool {
	// The reviewed supplier uses the original broker request protocol. HTTP
	// adapters need their own reviewed no-replay transport contract.
	if ts.Provider != "hetzner" || ts.Adapter.Version != "0.1.0" || ts.Adapter.Transport != "rabbitmq" || manifest.ValidateIntegrationTypeSpec(ts) != nil {
		return false
	}
	for _, required := range []string{"ensure_server", capacity.VMObserveServer, capacity.VMObserveAction} {
		found := 0
		for _, action := range ts.ActionCatalog {
			if action.Name != required {
				continue
			}
			if !action.Idempotent || (action.Category != "" && action.Category != "capability") {
				return false
			}
			for _, resource := range ts.ResourceTypes {
				for _, kind := range action.ResourceTypes {
					if kind == resource.Name {
						for _, allowed := range resource.DefaultActions {
							if allowed == required {
								found++
							}
						}
					}
				}
			}
		}
		if found != 1 {
			return false
		}
	}
	return true
}

func originalGuestSupplierSourceConfig(spec model.IntegrationInstanceManifestSpec, source string) bool {
	if len(source) != 40 {
		return false
	}
	for _, c := range source {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	config, ok := spec.Config["fleet"].(map[string]any)
	if !ok {
		return false
	}
	pinned, ok := config["original_create_source_commit"].(string)
	return ok && pinned == source
}

func resolveOriginalGuestSupplier(ctx context.Context, conn *amqp.Connection, store repository.CapacityStore, b model.CapacityObservationAdapterBinding, source string) (capacityResolvedObservationAdapter, error) {
	var empty capacityResolvedObservationAdapter
	im, err := resolveManifestForKind(ctx, store.DB, "integration_instance", b.IntegrationInstanceID, "", "", nil)
	if err != nil || !im.Metadata.Active || im.Checksum != b.InstanceChecksum {
		return empty, errOriginalGuestStep
	}
	is, err := manifest.ParseIntegrationInstanceSpec(im.Spec)
	if err != nil || !originalGuestSupplierSourceConfig(is, source) {
		return empty, errOriginalGuestStep
	}
	tm, err := resolveManifestForKind(ctx, store.DB, "integration_type", is.TypeRef.ManifestID, is.TypeRef.Namespace, is.TypeRef.Name, is.TypeRef.Version)
	if err != nil || !tm.Metadata.Active || tm.ID.String() != b.IntegrationTypeID || tm.Checksum != b.TypeChecksum {
		return empty, errOriginalGuestStep
	}
	ts, err := manifest.ParseIntegrationTypeSpec(tm.Spec)
	if err != nil || !originalGuestSupplierCatalog(ts) || !originalGuestSupplierSourceConfig(is, source) {
		return empty, errOriginalGuestStep
	}
	// Secret hydration and live Describe occur only after public registry and
	// exact raw catalog checks. Recheck the same immutable revisions afterward.
	im, is, tm, ts, err = resolveIntegrationInstance(ctx, conn, store.DB, model.ManifestSelector{ManifestID: b.IntegrationInstanceID})
	if err != nil || !im.Metadata.Active || im.ID.String() != b.IntegrationInstanceID || im.Checksum != b.InstanceChecksum || !tm.Metadata.Active || tm.ID.String() != b.IntegrationTypeID || tm.Checksum != b.TypeChecksum || !originalGuestSupplierCatalog(ts) || !originalGuestSupplierSourceConfig(is, source) {
		return empty, errOriginalGuestStep
	}
	return capacityResolvedObservationAdapter{im, is, tm, ts}, nil
}

type originalHetznerGuestSupplier struct {
	store        repository.CapacityStore
	policy       model.Manifest
	p            model.CapacityPolicySpec
	binding      model.CapacityMutationBinding
	resolved     capacityResolvedObservationAdapter
	conn         *amqp.Connection
	parent       context.Context
	input        guestOriginalStepInput
	createdGrant model.CapacityMutationGrant
	createdPre   model.CapacityGuestOriginalProvisioningPreregistration
	createdProof model.CapacityMutationProof
}

func (s *originalHetznerGuestSupplier) guard(ctx context.Context) error {
	if ctx == nil || ctx.Err() != nil || s.parent.Err() != nil {
		return errOriginalGuestStep
	}
	if s.store.ValidateNativeObservationLease(ctx, s.policy, s.input.Generation, s.input.FencingToken, s.input.LeaseOwner) != nil {
		return errOriginalGuestStep
	}
	for _, m := range []model.Manifest{s.resolved.instance, s.resolved.typ} {
		current, err := resolveManifestForKind(ctx, s.store.DB, m.Kind, m.ID.String(), "", "", nil)
		if err != nil || !current.Metadata.Active || current.Checksum != m.Checksum {
			return errOriginalGuestStep
		}
	}
	return nil
}
func (s *originalHetznerGuestSupplier) call(ctx context.Context, op string, fixed map[string]any, out any) (string, error) {
	if s.guard(ctx) != nil {
		return "", errOriginalGuestStep
	}
	a := s.resolved
	r, err := executeIntegrationThroughResolvedWithPolicy(ctx, s.conn, model.ExecuteIntegrationRequest{Operation: op, Capability: op, Input: fixed}, a.instance, a.instanceSpec, a.typ, a.typeSpec, 65*time.Second, integrationExecutionPolicy{detailFreeErrors: true, safeError: errOriginalGuestStep, requireExplicitResponse: true, nativeHTTP: &nativeAdapterHTTPPolicy{limit: 2 << 20, parent: s.parent}})
	if err != nil || s.guard(ctx) != nil || capacity.DecodeVMObservation(r.Output, out) != nil {
		return "", errOriginalGuestStep
	}
	return r.Status, nil
}
func (s *originalHetznerGuestSupplier) Prepare(ctx context.Context, slot int) error {
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
	status, err := s.call(ctx, s.binding.EnsureCapability, map[string]any{"profile": s.binding.ProfileName, "slot": slot}, &plan)
	if err != nil || status != "dry_run" || plan.Server != nil || plan.RequestSHA256 != expected.DesiredSpecSHA256 || !reflect.DeepEqual(plan.DesiredSpec, *expected.DesiredSpec) || plan.Protected != (slot <= s.binding.ProtectedSlots) || plan.ProviderFencingEvidence || plan.WarmReadinessEvidence || plan.BusinessReadyEvidence || plan.Quote == nil || !plan.Quote.Available || plan.Quote.StockReserved || plan.Quote.Currency != s.p.Currency {
		return errOriginalGuestStep
	}
	until, err := time.Parse(time.RFC3339Nano, plan.Quote.ValidUntil)
	if err != nil || !time.Now().Before(until) {
		return errOriginalGuestStep
	}
	return nil
}
func (s *originalHetznerGuestSupplier) Create(ctx context.Context, g model.CapacityMutationGrant, pre model.CapacityGuestOriginalProvisioningPreregistration) (model.CapacityMutationProof, error) {
	var returned struct {
		Plan          model.CapacityVMFleetPlan `json:"plan"`
		ActionID      string                    `json:"action_id"`
		NextActionIDs []string                  `json:"next_action_ids"`
	}
	status, err := s.call(ctx, s.binding.EnsureCapability, map[string]any{"profile": s.binding.ProfileName, "slot": g.Slot, "dry_run": false, "grant_id": g.GrantID}, &returned)
	if err != nil || status != "accepted" || returned.Plan.Server == nil || returned.Plan.RequestSHA256 != g.RequestSHA256 {
		return model.CapacityMutationProof{}, errOriginalGuestStep
	}
	receipt, err := s.store.NativeMutationReceipt(ctx, s.policy, s.binding, g.GrantID)
	if err != nil || !receipt.TransportCompleted || receipt.Outcome != "accepted" || receipt.ActionID != returned.ActionID || !reflect.DeepEqual(receipt.NextActionIDs, returned.NextActionIDs) || receipt.ResourceID != returned.Plan.Server.ID || receipt.ResourceCreatedAt != returned.Plan.Server.CreatedAt {
		return model.CapacityMutationProof{}, errOriginalGuestStep
	}
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		proof, err := s.Read(ctx, g)
		if !errors.Is(err, errOriginalGuestProviderPending) {
			if err == nil {
				s.createdGrant = g
				s.createdPre = pre
				s.createdProof = proof
			}
			return proof, err
		}
		select {
		case <-ctx.Done():
			return model.CapacityMutationProof{}, errOriginalGuestStep
		case <-ticker.C:
		}
	}
}

var errOriginalGuestProviderPending = errors.New("original native provider action pending")

func (s *originalHetznerGuestSupplier) Read(ctx context.Context, g model.CapacityMutationGrant) (model.CapacityMutationProof, error) {
	var empty model.CapacityMutationProof
	receipt, err := s.store.NativeMutationReceipt(ctx, s.policy, s.binding, g.GrantID)
	if err != nil || !receipt.TransportCompleted || receipt.Outcome != "accepted" || (receipt.Grant.State != "settled" && receipt.Grant.State != "confirmed") {
		return empty, errOriginalGuestStep
	}
	original := receipt.Grant
	original.State = g.State
	if !reflect.DeepEqual(original, g) {
		return empty, errOriginalGuestStep
	}
	fixed := map[string]any{"profile": s.binding.ProfileName, "slot": g.Slot, "grant_id": g.GrantID, "expected_resource_id": receipt.ResourceID, "expected_resource_created_at": receipt.ResourceCreatedAt}
	var plan model.CapacityVMFleetPlan
	status, err := s.call(ctx, capacity.VMObserveServer, fixed, &plan)
	if err != nil {
		return empty, err
	}
	proof, err := capacity.VMServerPlanProof(s.p, s.binding, plan, receipt, status, time.Now().UTC(), "original-provider:"+g.GrantID)
	if err != nil || proof.ResourceAbsent {
		return empty, errOriginalGuestStep
	}
	ids := append([]string{receipt.ActionID}, receipt.NextActionIDs...)
	if receipt.ActionID == "" || len(ids) > 64 {
		return empty, errOriginalGuestStep
	}
	collection := model.CapacityVMActionCollection{ResourceID: proof.ResourceID, ResourceCreatedAt: proof.ResourceCreatedAt, Complete: true}
	for _, id := range ids {
		fixed["action_id"] = id
		var action model.CapacityVMActionObservation
		status, err = s.call(ctx, capacity.VMObserveAction, fixed, &action)
		if err != nil || status != "observed" || action.ID != id || action.ResourceID != proof.ResourceID {
			return empty, errOriginalGuestStep
		}
		if action.Status == "running" {
			return empty, errOriginalGuestProviderPending
		}
		collection.Actions = append(collection.Actions, action)
	}
	collection.ObservedAt = time.Now().UTC().Format(time.RFC3339Nano)
	proof.ActionIDs, err = capacity.VMActionProof(s.p, collection, proof.ResourceID, time.Now().UTC(), true)
	if err != nil {
		return empty, errOriginalGuestStep
	}
	proof.ActionsTerminal, proof.ActionsSuccessful = true, true
	return proof, nil
}
