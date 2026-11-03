package message

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"reflect"
	"sync"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacityhostfactory"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
)

type originalHostInvocation struct {
	store            repository.CapacityStore
	preparation      model.HostFactoryRootPreparation
	policy, workflow model.Manifest
	intent           model.CapacityIntent
	returned         bool
}

func executeOriginalHostOrdinaryProvision(ctx context.Context, realm *capacityhostfactory.OriginalFactoryRealm, store repository.CapacityStore, policy, workflow model.Manifest, step model.WorkflowStepSpec, p model.CapacityPolicySpec, b model.CapacityMutationBinding, input guestOriginalStepInput, issue model.CapacityMutationIssue, requestSHA string) (any, error) {
	if err := store.ReserveOriginalHostAwaitingOwner(ctx, policy, workflow, step, p, b, input.Slot, "ordinary_original_create"); err != nil {
		return nil, err
	}
	binding, bindingRaw, stages, err := realm.PrepareOriginalOrdinary(ctx, store.ExecutorID, policy, workflow, step, b, requestSHA, input.Slot)
	if err != nil {
		return nil, repository.ErrHostFactoryHold
	}
	registrationCalled := time.Now().UTC()
	store, err = store.RegisterOriginalOrdinaryPreparation(ctx, policy, workflow, p, b, binding, bindingRaw, stages)
	registrationReturned := time.Now().UTC()
	if err = store.CaptureOriginalHostPreparationReturn(ctx, registrationCalled, registrationReturned, err); err != nil {
		return nil, err
	}
	// Guest intent authority retains its existing independent key/source
	// contract; the Host issuer key never signs a Guest witness.
	key, err := sourceGuestSigningKey(ctx, store.DB, p.GuestRetirementBinding.IntentSigningKeyRef)
	if err != nil {
		return nil, err
	}
	defer clear(key)
	nonce, err := sourceGuestNonce()
	if err != nil {
		return nil, err
	}
	store = store.WithOriginalGuestProvisioning(step, capacity.CurrentGuestCoreSource(), capacity.BusinessCreationSHA256([]byte(nonce)))
	issueCalled := time.Now().UTC()
	grant, err := store.IssueMutation(ctx, policy, input.Generation, input.FencingToken, input.LeaseOwner, issue)
	issueReturned := time.Now().UTC()
	if err = store.CaptureOriginalOrdinaryIssueReturn(ctx, grant, issueCalled, issueReturned, err); err != nil {
		return nil, err
	}
	pre, err := store.OriginalGuestProvisioning(ctx, grant.GrantID)
	if err != nil {
		return nil, err
	}
	original, cancel := context.WithDeadline(ctx, pre.OriginalDeadline)
	defer cancel()
	proof, err := store.ContinueOriginalOrdinaryCreate(original)
	if err != nil {
		return nil, err
	}
	witness, err := store.RecordGuestCreateWitness(original, pre.PreregistrationID, proof, key)
	if err != nil {
		return nil, err
	}
	if err = realm.OriginalOrdinaryWitnessed(original, grant, pre, witness); err != nil {
		return nil, err
	}
	var member model.CapacityGuestRetirementMemberBinding
	for _, candidate := range p.GuestRetirementBinding.Members {
		if candidate.Slot == input.Slot {
			member = candidate
		}
	}
	if member.Name == "" {
		return nil, repository.ErrHostFactoryHold
	}
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	var receipt model.CapacityGuestOriginalProvisioningReceipt
	for {
		receipt, err = store.GuestProvisioningReceipt(original, member.ProvisionerClientPrincipal, pre.PreregistrationID, pre.NonceSHA256)
		if err == nil {
			break
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return nil, err
		}
		select {
		case <-original.Done():
			return nil, repository.ErrHostFactoryHold
		case <-ticker.C:
		}
	}
	if _, err = store.ConfirmMutation(original, policy, input.Generation, input.FencingToken, input.LeaseOwner, proof); err != nil {
		return nil, err
	}
	if err = realm.OriginalOrdinaryEnrolled(original, grant, pre, receipt); err != nil {
		return nil, err
	}
	return struct {
		Preregistration     model.CapacityGuestOriginalProvisioningPreregistration `json:"preregistration"`
		WitnessSHA256       string                                                 `json:"witness_sha256"`
		Receipt             model.CapacityGuestOriginalProvisioningReceipt         `json:"receipt"`
		UsefulCapacityKnown bool                                                   `json:"useful_capacity_known"`
	}{pre, capacity.GuestRetirementSHA(witness), receipt, false}, nil
}

var originalHostInvocations struct {
	sync.Mutex
	byID map[string]*originalHostInvocation
}

// Called once by the source-owned same-process fixture before httpapi.New.
// No workflow input, boolean, environment or supplied key installs a realm.
func InstallOriginalHostFactoryQualification(realm *capacityhostfactory.OriginalFactoryRealm) error {
	if realm == nil {
		return repository.ErrHostFactoryHold
	}
	ctx, err := realm.Context(context.Background())
	if err != nil {
		return repository.ErrHostFactoryHold
	}
	return repository.InstallOriginalHostFactoryRealm(ctx, realm)
}

func originalHostCapacityContext(parent context.Context, ref model.ManifestReference) (context.Context, context.CancelFunc, error) {
	realm, approval, installed := repository.OriginalHostFactoryRealm()
	if !installed || ref.ID.String() != approval.AllowedWorkflowID {
		return parent, func() {}, nil
	}
	first, err := realm.Context(parent)
	if err != nil {
		return nil, nil, repository.ErrHostFactoryHold
	}
	deadline, exists := first.Deadline()
	if !exists {
		return nil, nil, repository.ErrHostFactoryHold
	}
	if earlier, exists := parent.Deadline(); exists && earlier.Before(deadline) {
		deadline = earlier
	}
	ctx, cancel := context.WithDeadline(parent, deadline)
	return ctx, cancel, nil
}

func originalHostStepContext(parent context.Context, ref model.ManifestReference, step model.WorkflowStepSpec, operation string) (context.Context, context.CancelFunc, *capacityhostfactory.OriginalFactoryRealm, error) {
	realm, approval, installed := repository.OriginalHostFactoryRealm()
	if !installed || ref.ID.String() != approval.AllowedWorkflowID {
		return parent, func() {}, nil, nil
	}
	if operation != capacity.ProvisionOriginalGuestOperation || step.ID != approval.AllowedOriginalStepID || step.Use.Kind != "yggdrasil" || step.Use.Operation != operation || step.TimeoutSeconds < 1 || step.Retry.MaxAttempts > 1 || step.ForEach != nil {
		return nil, nil, nil, repository.ErrHostFactoryHold
	}
	first, err := realm.Context(parent)
	if err != nil {
		return nil, nil, nil, repository.ErrHostFactoryHold
	}
	deadline, exists := first.Deadline()
	if !exists {
		return nil, nil, nil, repository.ErrHostFactoryHold
	}
	// Retain the actual workflow context/invocation lineage. Returning the
	// realm's first context would discard the private dispatcher invocation.
	stepDeadline := time.Now().Add(time.Duration(step.TimeoutSeconds) * time.Second)
	if stepDeadline.Before(deadline) {
		deadline = stepDeadline
	}
	if parentDeadline, exists := parent.Deadline(); exists && parentDeadline.Before(deadline) {
		deadline = parentDeadline
	}
	ctx, cancel := context.WithDeadline(parent, deadline)
	return ctx, cancel, realm, nil
}

func originalHostCapacityCarrier(ctx context.Context, store repository.CapacityStore, policy, workflow model.Manifest, spec model.WorkflowManifestSpec, result model.WorkflowRunStepResult, assessment model.CapacityAssessment) (repository.CapacityStore, error) {
	realm, approval, installed := repository.OriginalHostFactoryRealm()
	if !installed || workflow.ID.String() != approval.AllowedWorkflowID {
		return store, nil
	}
	if policy.ID.String() != approval.AllowedPolicyID || policy.Metadata.Namespace != approval.AllowedNamespace || (result.Operation != "capacity.assess" && result.Operation != "capacity.claim") {
		return store, repository.ErrHostFactoryHold
	}
	var assessStep, claimStep, provisionStep model.WorkflowStepSpec
	for _, step := range spec.Steps {
		if step.ID == approval.AllowedAssessStepID && step.Use.Kind == "yggdrasil" && step.Use.Operation == "capacity.assess" {
			assessStep = step
		}
		if step.ID == approval.AllowedClaimStepID && step.Use.Kind == "yggdrasil" && step.Use.Operation == "capacity.claim" {
			claimStep = step
		}
		if step.ID == approval.AllowedOriginalStepID && step.Use.Kind == "yggdrasil" && step.Use.Operation == capacity.ProvisionOriginalGuestOperation {
			provisionStep = step
		}
	}
	actual := assessStep
	if result.Operation == "capacity.claim" {
		actual = claimStep
	}
	if actual.ID == "" || actual.ID != result.ID || assessStep.ID == "" || claimStep.ID == "" || provisionStep.ID == "" || provisionStep.Retry.MaxAttempts > 1 || provisionStep.ForEach != nil {
		return store, repository.ErrHostFactoryHold
	}
	// Compare the SAME actual DB resolver returns with the original private
	// Source-read policy/workflow/three-step cache before BOTH Assess and Claim.
	// Logical metadata supplies no native snapshot, lease or effect permission.
	if realm.VerifyOriginalPolicyInput(ctx, policy, workflow, assessStep, claimStep, provisionStep) != nil {
		return store, repository.ErrHostFactoryHold
	}
	// Constructor/export raw custody precedes DB ownership. Actual SAME-SQL
	// FIRST/native graph verification must finish before Assess or Claim.
	if err := store.PrimeOriginalHostRoot(ctx, realm, policy, workflow, assessStep, claimStep, provisionStep); err != nil {
		return store, err
	}
	// Only the actual committed initializer's owning Go return can precede
	// current native/source admission. This read adds no native observations.
	if err := store.GuardOriginalHostPrimedRoot(ctx, realm, policy, workflow, assessStep, claimStep, provisionStep); err != nil {
		return store, err
	}
	initial, err := realm.InitialAssessment(ctx)
	if err != nil {
		return store, repository.ErrHostFactoryHold
	}
	a, e1 := json.Marshal(assessment)
	b, e2 := json.Marshal(initial)
	if e1 != nil || e2 != nil || !bytes.Equal(a, b) {
		return store, repository.ErrHostFactoryHold
	}
	if result.Operation == "capacity.assess" {
		return store, nil
	}
	if err = realm.BindOriginalInvocation(ctx, store.ExecutorID, policy, workflow, assessStep, claimStep, provisionStep, assessment); err != nil {
		return store, repository.ErrHostFactoryHold
	}
	_, preparationRaw, _, _, err := realm.OriginalClaimTransactionBinding(ctx, store.ExecutorID)
	var preparation model.HostFactoryRootPreparation
	if err != nil || capacity.DecodeHostFactory(preparationRaw, &preparation) != nil {
		return store, repository.ErrHostFactoryHold
	}
	store, err = store.WithOriginalHostClaim(ctx, realm, store.ExecutorID)
	if err != nil {
		return store, err
	}
	originalHostInvocations.Lock()
	defer originalHostInvocations.Unlock()
	if originalHostInvocations.byID == nil {
		originalHostInvocations.byID = map[string]*originalHostInvocation{}
	}
	if originalHostInvocations.byID[store.ExecutorID] != nil {
		return store, repository.ErrHostFactoryHold
	}
	originalHostInvocations.byID[store.ExecutorID] = &originalHostInvocation{store: store, preparation: preparation, policy: policy, workflow: workflow}
	return store, nil
}

func originalHostClaimReturned(ctx context.Context, store repository.CapacityStore, intent model.CapacityIntent, calledAt, returnedAt time.Time, callErr error) error {
	originalHostInvocations.Lock()
	entry := originalHostInvocations.byID[store.ExecutorID]
	originalHostInvocations.Unlock()
	if entry == nil {
		return callErr
	}
	// On failure the same TX raw association/lease is already committed.
	// Keep this invocation outstanding/HOLD; no rollback/renew/re-Claim.
	if err := store.CaptureOriginalHostClaimReturn(ctx, intent, calledAt, returnedAt, callErr); err != nil {
		return err
	}
	originalHostInvocations.Lock()
	defer originalHostInvocations.Unlock()
	if entry.returned {
		return repository.ErrHostFactoryHold
	}
	entry.intent, entry.returned = intent, true
	return nil
}

func executeOriginalHostFactoryStep(ctx context.Context, realm *capacityhostfactory.OriginalFactoryRealm, store repository.CapacityStore, policy, workflow model.Manifest, step model.WorkflowStepSpec, p model.CapacityPolicySpec, b model.CapacityMutationBinding, input guestOriginalStepInput) (any, error) {
	originalHostInvocations.Lock()
	entry := originalHostInvocations.byID[store.ExecutorID]
	originalHostInvocations.Unlock()
	if entry == nil || !entry.returned || entry.policy.ID != policy.ID || entry.policy.Checksum != policy.Checksum || entry.workflow.ID != workflow.ID || !reflect.DeepEqual(entry.intent.Assessment.Snapshot, entry.intent.BaselineSnapshot) {
		return nil, repository.ErrHostFactoryHold
	}
	store = entry.store
	if entry.intent.LeaseExpiresAt == nil {
		return nil, repository.ErrHostFactoryHold
	}
	if deadline, bounded := ctx.Deadline(); !bounded || entry.intent.LeaseExpiresAt.Before(deadline) {
		boundedCtx, cancel := context.WithDeadline(ctx, *entry.intent.LeaseExpiresAt)
		defer cancel()
		ctx = boundedCtx
	}
	// This is a separate actual owning private lease read, not public Observe
	// and not an alias of the original Claim's Go return.
	readCalled := time.Now().UTC()
	current, err := store.ReadOriginalHostCurrentLease(ctx, policy, input.Generation, input.FencingToken, input.LeaseOwner)
	readReturned := time.Now().UTC()
	if err != nil || realm.CaptureOriginalCurrentLeaseRead(ctx, store.ExecutorID, current, readCalled, readReturned) != nil {
		return nil, repository.ErrHostFactoryHold
	}
	_, provenanceRaw, err := realm.OriginalLeaseProvenance(ctx, store.ExecutorID)
	if err != nil {
		return nil, repository.ErrHostFactoryHold
	}
	provenanceEnvelope, err := realm.SignOriginalAuthority(ctx, "original-lease-provenance", provenanceRaw)
	if err != nil {
		return nil, repository.ErrHostFactoryHold
	}
	if err = store.RecordOriginalHostPrivateStage(ctx, "original-lease-provenance", provenanceEnvelope); err != nil {
		return nil, err
	}
	var desired *model.CapacityMutationSpecV1
	for _, s := range b.Slots {
		if s.Slot == input.Slot {
			desired = s.DesiredSpec
		}
	}
	if desired == nil {
		return nil, repository.ErrHostFactoryHold
	}
	desiredRaw, err := json.Marshal(desired)
	if err != nil {
		return nil, err
	}
	issue := model.CapacityMutationIssue{BindingName: b.Name, DesiredSpec: desiredRaw}
	plan, err := capacity.PrepareMutationPlan(p, issue)
	if err != nil {
		return nil, err
	}
	class := entry.preparation.FactoryEntryClass
	if class == "ordinary_original_create" {
		return executeOriginalHostOrdinaryProvision(ctx, realm, store, policy, workflow, step, p, b, input, issue, plan.RequestSHA256)
	}
	if class != "sealed_a0" && class != "sealed_a1" {
		return nil, repository.ErrHostFactoryHold
	}
	if err = store.ReserveOriginalHostAwaitingOwner(ctx, policy, workflow, step, p, b, input.Slot, class); err != nil {
		return nil, err
	}
	scope, scopeRaw, stages, err := realm.PrepareOriginalSealed(ctx, store.ExecutorID, policy, workflow, step, b, plan.RequestSHA256, input.Slot, class)
	if err != nil {
		return nil, repository.ErrHostFactoryHold
	}
	registrationCalled := time.Now().UTC()
	store, err = store.RegisterOriginalHostPreparation(ctx, policy, p, scope, scopeRaw, stages)
	registrationReturned := time.Now().UTC()
	if err = store.CaptureOriginalHostPreparationReturn(ctx, registrationCalled, registrationReturned, err); err != nil {
		return nil, err
	}
	if class == "sealed_a1" {
		nonce, err := sourceGuestNonce()
		if err != nil {
			return nil, err
		}
		store = store.WithOriginalGuestProvisioning(step, capacity.CurrentGuestCoreSource(), capacity.BusinessCreationSHA256([]byte(nonce)))
		issueCalled := time.Now().UTC()
		grant, err := store.IssueMutation(ctx, policy, input.Generation, input.FencingToken, input.LeaseOwner, issue)
		issueReturned := time.Now().UTC()
		if err = store.CaptureOriginalHostIssueReturn(grant, issueCalled, issueReturned, err); err != nil {
			return nil, err
		}
	}
	reservationStage := "unissued-choice-reservation"
	if class == "sealed_a1" {
		reservationStage = "issued-choice-reservation"
	}
	reservationRaw, err := realm.OriginalAuthorityBody(ctx, reservationStage)
	if err != nil {
		return nil, repository.ErrHostFactoryHold
	}
	reservationEnvelope, err := realm.SignOriginalAuthority(ctx, reservationStage, reservationRaw)
	if err != nil {
		return nil, repository.ErrHostFactoryHold
	}
	if err = store.ReserveOriginalHostSealed(ctx, reservationStage, reservationEnvelope); err != nil {
		return nil, err
	}
	terminalStages, err := realm.SealOriginal(ctx, reservationRaw)
	if err != nil {
		return nil, repository.ErrHostFactoryHold
	}
	if err = store.RecordOriginalHostTerminalStages(ctx, terminalStages); err != nil {
		return nil, err
	}
	// A Source disposition is recorded separately. It never makes the Guest
	// operation successful or supplies provisioning/enrollment/native proof.
	return nil, repository.ErrHostFactoryHold
}
