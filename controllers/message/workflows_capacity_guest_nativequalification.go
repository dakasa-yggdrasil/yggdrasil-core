//go:build linux && nativequalification

package message

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"path/filepath"
	"sync"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacitynativeqemu"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
)

var originalGuestNativeRealm *capacitynativeqemu.Realm
var originalGuestNativeInstall sync.Once

// Called once BEFORE the real Core API starts. This constructor is absent
// from production binaries and cannot be selected by a workflow input.
func InstallOriginalGuestNativeFixture(realm *capacitynativeqemu.Realm) error {
	installed := false
	originalGuestNativeInstall.Do(func() {
		if realm != nil {
			originalGuestNativeRealm = realm
			originalGuestSourceProvider = realm
			installed = true
		}
	})
	if !installed {
		return errOriginalGuestStep
	}
	return nil
}
func guestOriginalSourceLimit(ctx context.Context) (context.Context, context.CancelFunc, error) {
	if originalGuestNativeRealm == nil || ctx.Err() != nil {
		return ctx, func() {}, errOriginalGuestStep
	}
	deadline, ok := ctx.Deadline()
	if !ok {
		return ctx, func() {}, errOriginalGuestStep
	}
	if originalGuestNativeRealm.Request.OriginalContextDeadline.Before(deadline) {
		deadline = originalGuestNativeRealm.Request.OriginalContextDeadline
	}
	if !time.Now().UTC().Before(deadline) {
		return ctx, func() {}, errOriginalGuestStep
	}
	original, cancel := context.WithDeadline(ctx, deadline)
	return original, cancel, nil
}
func guestOriginalSourceEnrolled(ctx context.Context, g model.CapacityMutationGrant, p model.CapacityGuestOriginalProvisioningPreregistration, r model.CapacityGuestOriginalProvisioningReceipt) error {
	if originalGuestNativeRealm == nil {
		return errOriginalGuestStep
	}
	return originalGuestNativeRealm.Enrolled(ctx, g, p, r)
}
func guestOriginalSourceWitnessed(ctx context.Context, g model.CapacityMutationGrant, p model.CapacityGuestOriginalProvisioningPreregistration, w model.CapacityGuestOriginalCreateWitness) error {
	if originalGuestNativeRealm == nil {
		return errOriginalGuestStep
	}
	return originalGuestNativeRealm.Witnessed(ctx, g, p, w)
}

func sourceGuestQualificationStep(ctx context.Context, store repository.CapacityStore, policy model.Manifest, p model.CapacityPolicySpec, input guestOriginalStepInput, key ed25519.PrivateKey, operation string) (any, error) {
	if input.RequestID == "source_recovery_cleanup_v1" {
		return sourceGuestRecoveryCleanupStep(ctx, store, policy, p, input, operation)
	}
	if originalGuestNativeRealm == nil || p.GuestRetirementBinding == nil || !capacity.GuestOriginalProfileEnabled(p, *p.GuestRetirementBinding, "native-qemu") {
		return nil, capacity.GuestQualificationRefusal("realm_profile", errOriginalGuestStep)
	}
	if operation == "capacity.finish_original_guest_retirement" {
		return sourceGuestNativeRetirementFinished(ctx, store, policy, p, input, key)
	}
	current, err := store.Observe(ctx, policy)
	if err != nil {
		return nil, capacity.GuestQualificationRefusal("observe", errOriginalGuestStep)
	}
	if current.LeaseExpiresAt == nil {
		return nil, capacity.GuestQualificationRefusal("lease_missing", errOriginalGuestStep)
	}
	if current.Generation != input.Generation {
		return nil, capacity.GuestQualificationRefusal("generation", errOriginalGuestStep)
	}
	if current.FencingToken != input.FencingToken {
		return nil, capacity.GuestQualificationRefusal("fence", errOriginalGuestStep)
	}
	if current.Phase != "preparing" {
		return nil, capacity.GuestQualificationRefusal("phase", errOriginalGuestStep)
	}
	b, err := capacity.VMObservationBinding(p, input.BindingName)
	if err != nil {
		return nil, capacity.GuestQualificationRefusal("binding", errOriginalGuestStep)
	}
	slots := originalGuestNativeRealm.OwnedSlots()
	if len(slots) != current.Decision.Units {
		return nil, capacity.GuestQualificationRefusal("owned_slots", errOriginalGuestStep)
	}
	var probes []capacitynativeqemu.QualificationProbeReceipt
	for _, slot := range slots {
		member := model.CapacityGuestRetirementMemberBinding{}
		for _, m := range p.GuestRetirementBinding.Members {
			if m.Slot == slot {
				member = m
			}
		}
		if member.Name == "" {
			return nil, capacity.GuestQualificationRefusal("member", errOriginalGuestStep)
		}
		client, err := sourceGuestClient(ctx, store.DB, member)
		if err != nil {
			return nil, capacity.GuestQualificationRefusal("client", err)
		}
		probe, err := originalGuestNativeRealm.Probe(ctx, store, policy, input.Generation, input.FencingToken, input.LeaseOwner, slot, key, client, *current.LeaseExpiresAt)
		client.Close()
		if err != nil {
			return nil, err
		}
		probes = append(probes, probe)
		physical, err := originalGuestNativeRealm.FreshNativeMember(ctx, slot, b)
		if err != nil {
			return nil, capacity.GuestQualificationRefusal("fresh_native", err)
		}
		var projection *model.CapacityMutationSpecV1
		for _, approved := range b.Slots {
			if approved.Slot == slot {
				projection = approved.DesiredSpec
			}
		}
		if projection == nil {
			return nil, capacity.GuestQualificationRefusal("projection", errOriginalGuestStep)
		}
		wire, err := json.Marshal(projection)
		if err != nil {
			return nil, capacity.GuestQualificationRefusal("projection_encode", err)
		}
		if err = store.RecordMutationSlot(ctx, policy, input.Generation, input.FencingToken, input.LeaseOwner, model.CapacityMutationIssue{BindingName: b.Name, DesiredSpec: wire}, physical); err != nil {
			return nil, capacity.GuestQualificationRefusal("record_slot", err)
		}
	}
	// Healthy is restricted to the ACTUAL admitted source echo profile. Each
	// same original writer just served its bounded challenge; native/count or
	// a signed census alone cannot produce this phase receipt.
	at := time.Now().UTC()
	assessment := capacitynativeqemu.QualificationAssessment(p, len(probes), 0.9, at)
	zero := 0
	proof := model.CapacityTransitionProof{Assessment: assessment, ObservedAt: at, ReceiptRef: "original-native-useful-echo:" + capacity.GuestRetirementSHA(probes), Healthy: len(probes) == len(slots) && len(probes) > 0, Inflight: &zero}
	for _, phase := range []string{"prepared", "canary", "promoted"} {
		if _, err = store.Advance(ctx, policy, input.Generation, input.FencingToken, input.LeaseOwner, phase, proof); err != nil {
			return nil, capacity.GuestQualificationRefusal("advance_"+phase, err)
		}
	}
	return struct {
		Scope                             string                                         `json:"scope"`
		UsefulEchoProbes                  []capacitynativeqemu.QualificationProbeReceipt `json:"useful_echo_probes"`
		ProductionUsefulCapacityQualified bool                                           `json:"production_useful_capacity_qualified"`
	}{"same_original_qualification_echo_profile_only", probes, false}, nil
}

// Twenty logical contenders use the SAME original source-owned store, step,
// nonce, slot and parent context. Only the one returned durable grant proceeds
// to the unchanged single Create call; this never requests twenty native VMs.
func guestOriginalSourceIssueContenders(ctx context.Context, store repository.CapacityStore, policy model.Manifest, input guestOriginalStepInput, issue model.CapacityMutationIssue, expectedHistory int, contractName string) (model.CapacityMutationGrant, error) {
	var zero model.CapacityMutationGrant
	if originalGuestNativeRealm == nil || ctx.Err() != nil || input.Slot < 1 || input.Slot > 2 || (expectedHistory != 1 && expectedHistory != 2) {
		return zero, errOriginalGuestStep
	}
	type returned struct {
		grant model.CapacityMutationGrant
		err   error
	}
	const contenders = 20
	results := make(chan returned, contenders)
	start := make(chan struct{})
	var joined sync.WaitGroup
	for n := 0; n < contenders; n++ {
		joined.Add(1)
		go func() {
			defer joined.Done()
			<-start
			grant, err := store.IssueMutation(ctx, policy, input.Generation, input.FencingToken, input.LeaseOwner, issue)
			results <- returned{grant: grant, err: err}
		}()
	}
	close(start)
	// Context cancellation never substitutes for return of a SQL owner.
	joined.Wait()
	close(results)
	var grant model.CapacityMutationGrant
	var first []byte
	var failures error
	returnedCount := 0
	for result := range results {
		returnedCount++
		failures = errors.Join(failures, result.err)
		wire, err := json.Marshal(result.grant)
		failures = errors.Join(failures, err)
		if first == nil {
			first, grant = wire, result.grant
		} else if !bytes.Equal(first, wire) {
			failures = errors.Join(failures, errOriginalGuestStep)
		}
	}
	if failures != nil || returnedCount != contenders || ctx.Err() != nil || grant.GrantID == "" || grant.Slot != input.Slot {
		return zero, errors.Join(errOriginalGuestStep, failures)
	}
	var grants, history, preregistrations int
	if err := store.DB.QueryRowContext(ctx, `SELECT count(*) FILTER(WHERE state IN ('issued','redeemed','settled','compensating')),count(*) FROM public.capacity_mutation_grants WHERE namespace=$1 AND integration_instance_id=$2 AND scope_checksum=$3 AND profile_name=$4 AND slot=$5`, policy.Metadata.Namespace, grant.IntegrationInstanceID, grant.ScopeChecksum, grant.ProfileName, grant.Slot).Scan(&grants, &history); err != nil {
		return zero, err
	}
	if err := store.DB.QueryRowContext(ctx, `SELECT count(*) FROM public.capacity_vm_provisioning_preregistrations WHERE create_grant_id=$1`, grant.GrantID).Scan(&preregistrations); err != nil {
		return zero, err
	}
	if grants != 1 || history != expectedHistory || preregistrations != 1 {
		return zero, errOriginalGuestStep
	}
	proof := struct {
		Schema           string `json:"schema"`
		CoreSource       string `json:"core_source"`
		Slot             int    `json:"slot"`
		Contenders       int    `json:"contenders"`
		Returned         int    `json:"returned"`
		GrantID          string `json:"grant_id"`
		GrantSHA256      string `json:"grant_sha256"`
		GrantRows        int    `json:"active_grant_rows"`
		HistoryRows      int    `json:"historical_grant_rows"`
		Preregistrations int    `json:"preregistrations"`
	}{"original_guest_logical_reservation_concurrency_v1", capacity.CurrentGuestCoreSource(), input.Slot, contenders, returnedCount, grant.GrantID, capacity.BusinessCreationSHA256(first), grants, history, preregistrations}
	_, err := capacitynativeqemu.Publish(ctx, filepath.Join(capacitynativeqemu.SlotDirectory(originalGuestNativeRealm.PrivateDirectory, input.Slot), contractName), proof)
	if err != nil {
		return zero, err
	}
	return grant, nil
}

func guestOriginalSourceIssue(ctx context.Context, store repository.CapacityStore, policy model.Manifest, step model.WorkflowStepSpec, input guestOriginalStepInput, issue model.CapacityMutationIssue) (model.CapacityMutationGrant, error) {
	var zero model.CapacityMutationGrant
	if originalGuestNativeRealm == nil {
		return zero, errOriginalGuestStep
	}
	// Negative cases retain exactly one original preregistration per slot.
	// Only the closed source-owned positive selector exercises unsent reissue.
	if !capacitynativeqemu.PositiveCase(originalGuestNativeRealm.Request.NativeCase) {
		return guestOriginalSourceIssueContenders(ctx, store, policy, input, issue, 1, "logical-reservation-contract.json")
	}
	grant, err := guestOriginalSourceIssueContenders(ctx, store, policy, input, issue, 1, "unsent-logical-reservation-contract.json")
	if err != nil {
		return zero, err
	}
	firstPre, err := store.OriginalGuestProvisioning(ctx, grant.GrantID)
	if err != nil {
		return zero, err
	}
	// The unsent contract does not renew the first original420s budget.
	original, cancel := context.WithDeadline(ctx, firstPre.OriginalDeadline)
	defer cancel()
	if err = originalGuestNativeRealm.RejectOriginalUnsent(original, grant); err != nil {
		return zero, err
	}
	nonce, err := sourceGuestNonce()
	if err != nil {
		return zero, err
	}
	// Only this actual resolved source-owned step mints the replacement nonce.
	// No test request supplies a private original context or an admission field.
	freshStore := store.WithOriginalGuestProvisioning(step, capacity.CurrentGuestCoreSource(), capacity.BusinessCreationSHA256([]byte(nonce)))
	reissued, err := guestOriginalSourceIssueContenders(original, freshStore, policy, input, issue, 2, "logical-reservation-contract.json")
	if err != nil || reissued.GrantID == grant.GrantID || reissued.GrantID == "" || reissued.Slot != grant.Slot {
		return zero, errors.Join(errOriginalGuestStep, err)
	}
	nextPre, err := freshStore.OriginalGuestProvisioning(original, reissued.GrantID)
	if err != nil || nextPre.OriginalDeadline.After(firstPre.OriginalDeadline) || nextPre.OriginalCreateGrantID != reissued.GrantID {
		return zero, errors.Join(errOriginalGuestStep, err)
	}
	contract := struct {
		Schema           string    `json:"schema"`
		CoreSource       string    `json:"core_source"`
		Slot             int       `json:"slot"`
		FirstGrantID     string    `json:"first_grant_id"`
		ReissuedGrantID  string    `json:"reissued_grant_id"`
		OriginalDeadline time.Time `json:"original_deadline"`
		ReissuedDeadline time.Time `json:"reissued_deadline"`
	}{"original_guest_unsent_reissue_contract_v1", capacity.CurrentGuestCoreSource(), input.Slot, grant.GrantID, reissued.GrantID, firstPre.OriginalDeadline, nextPre.OriginalDeadline}
	_, err = capacitynativeqemu.Publish(original, filepath.Join(capacitynativeqemu.SlotDirectory(originalGuestNativeRealm.PrivateDirectory, input.Slot), "unsent-reissue-contract.json"), contract)
	if err != nil {
		return zero, err
	}
	return reissued, nil
}

// Repeating confirmation of the SAME actual independent native proof must not
// apply a second canonical event or manufacture another registered member.
func guestOriginalSourceAssertApply(ctx context.Context, store repository.CapacityStore, policy model.Manifest, input guestOriginalStepInput, proof model.CapacityMutationProof, grant model.CapacityMutationGrant) error {
	if originalGuestNativeRealm == nil || input.Slot < 1 || input.Slot > 2 {
		return errOriginalGuestStep
	}
	if err := guestOriginalConsumeRedemption(ctx, store, policy, input, grant); err != nil {
		return err
	}
	if _, err := store.ConfirmMutation(ctx, policy, input.Generation, input.FencingToken, input.LeaseOwner, proof); err != nil {
		return err
	}
	var events, members int
	if err := store.DB.QueryRowContext(ctx, `SELECT count(*) FROM public.event_log WHERE idempotency_key=$1 AND metadata->>'namespace'=$2`, "capacity-mutation/"+grant.GrantID, policy.Metadata.Namespace).Scan(&events); err != nil {
		return err
	}
	if err := store.DB.QueryRowContext(ctx, `SELECT count(*) FROM public.capacity_resource_slots WHERE namespace=$1 AND integration_instance_id=$2 AND scope_checksum=$3 AND profile_name=$4 AND slot=$5 AND resource_id=$6`, policy.Metadata.Namespace, grant.IntegrationInstanceID, grant.ScopeChecksum, grant.ProfileName, grant.Slot, proof.ResourceID).Scan(&members); err != nil {
		return err
	}
	if events != 1 || members != 1 || ctx.Err() != nil {
		return errOriginalGuestStep
	}
	contract := struct {
		Schema      string `json:"schema"`
		CoreSource  string `json:"core_source"`
		Slot        int    `json:"slot"`
		GrantID     string `json:"grant_id"`
		ResourceID  string `json:"resource_id"`
		ProofSHA256 string `json:"proof_sha256"`
		Events      int    `json:"canonical_events"`
		Members     int    `json:"registered_members"`
	}{"original_guest_canonical_apply_once_v1", capacity.CurrentGuestCoreSource(), input.Slot, grant.GrantID, proof.ResourceID, capacity.GuestRetirementSHA(proof), events, members}
	_, err := capacitynativeqemu.Publish(ctx, filepath.Join(capacitynativeqemu.SlotDirectory(originalGuestNativeRealm.PrivateDirectory, input.Slot), "canonical-apply-contract.json"), contract)
	return err
}

// Refusal inputs derive from the SAME actual native read, settled grant and
// enrollment. No fabricated successful proof or private source context enters
// the repository. Every rejected transaction must leave canonical state empty.
func guestOriginalSourceAssertNativeRefusals(ctx context.Context, store repository.CapacityStore, policy model.Manifest, input guestOriginalStepInput, proof model.CapacityMutationProof, grant model.CapacityMutationGrant) error {
	if originalGuestNativeRealm == nil || ctx.Err() != nil {
		return errOriginalGuestStep
	}
	canonicalEmpty := func() error {
		var events, members int
		if err := store.DB.QueryRowContext(ctx, `SELECT count(*) FROM public.event_log WHERE idempotency_key=$1 AND metadata->>'namespace'=$2`, "capacity-mutation/"+grant.GrantID, policy.Metadata.Namespace).Scan(&events); err != nil {
			return err
		}
		if err := store.DB.QueryRowContext(ctx, `SELECT count(*) FROM public.capacity_resource_slots WHERE namespace=$1 AND integration_instance_id=$2 AND scope_checksum=$3 AND profile_name=$4 AND slot=$5 AND resource_id=$6`, policy.Metadata.Namespace, grant.IntegrationInstanceID, grant.ScopeChecksum, grant.ProfileName, grant.Slot, proof.ResourceID).Scan(&members); err != nil {
			return err
		}
		if events != 0 || members != 0 || ctx.Err() != nil {
			return errOriginalGuestStep
		}
		return nil
	}
	if err := canonicalEmpty(); err != nil {
		return err
	}
	names := []string{"creation_grant_missing", "creation_grant_foreign", "resource_foreign", "creation_epoch_foreign", "actions_empty", "required_action_missing", "actions_nonterminal", "actions_unsuccessful", "owner_unverified", "spec_unverified", "request_foreign"}
	refused := make([]string, 0, len(names))
	for _, name := range names {
		bad := proof
		switch name {
		case "creation_grant_missing":
			bad.ObservedCreationGrantID = ""
		case "creation_grant_foreign":
			bad.ObservedCreationGrantID = "00000000-0000-4000-8000-000000000001"
			if bad.ObservedCreationGrantID == grant.GrantID {
				return errOriginalGuestStep
			}
		case "resource_foreign":
			bad.ResourceID = "00000000-0000-4000-8000-000000000001"
			if bad.ResourceID == proof.ResourceID {
				return errOriginalGuestStep
			}
		case "creation_epoch_foreign":
			created, err := time.Parse(time.RFC3339Nano, proof.ResourceCreatedAt)
			if err != nil {
				return err
			}
			bad.ResourceCreatedAt = created.Add(-time.Nanosecond).UTC().Format(time.RFC3339Nano)
		case "actions_empty":
			bad.ActionIDs = nil
		case "required_action_missing":
			bad.ActionIDs = []string{"different-action:" + capacity.GuestRetirementSHA(proof)}
		case "actions_nonterminal":
			bad.ActionsTerminal = false
		case "actions_unsuccessful":
			bad.ActionsSuccessful = false
		case "owner_unverified":
			bad.OwnerVerified = false
		case "spec_unverified":
			bad.SpecVerified = false
		case "request_foreign":
			bad.RequestSHA256 = "0000000000000000000000000000000000000000000000000000000000000000"
			if bad.RequestSHA256 == proof.RequestSHA256 {
				return errOriginalGuestStep
			}
		}
		if _, err := store.ConfirmMutation(ctx, policy, input.Generation, input.FencingToken, input.LeaseOwner, bad); !errors.Is(err, repository.ErrCapacityConflict) {
			return errors.Join(errOriginalGuestStep, err)
		}
		if err := canonicalEmpty(); err != nil {
			return err
		}
		refused = append(refused, name)
	}
	contract := struct {
		Schema              string   `json:"schema"`
		CoreSource          string   `json:"core_source"`
		Slot                int      `json:"slot"`
		GrantID             string   `json:"grant_id"`
		ResourceID          string   `json:"resource_id"`
		OriginalProofSHA256 string   `json:"original_proof_sha256"`
		Refused             []string `json:"refused"`
		CanonicalEvents     int      `json:"canonical_events"`
		CanonicalMembers    int      `json:"canonical_members"`
	}{"original_guest_native_refusal_contract_v1", capacity.CurrentGuestCoreSource(), input.Slot, grant.GrantID, proof.ResourceID, capacity.GuestRetirementSHA(proof), refused, 0, 0}
	_, err := capacitynativeqemu.Publish(ctx, filepath.Join(capacitynativeqemu.SlotDirectory(originalGuestNativeRealm.PrivateDirectory, input.Slot), "native-refusal-contract.json"), contract)
	return err
}

// Selector is the immutable owning source request, never a workflow input.
func guestOriginalSourceContractFence(ctx context.Context, store repository.CapacityStore, policy model.Manifest, p model.CapacityPolicySpec, binding model.CapacityMutationBinding, input guestOriginalStepInput, grant model.CapacityMutationGrant, pre model.CapacityGuestOriginalProvisioningPreregistration) (any, bool, error) {
	if originalGuestNativeRealm == nil || !capacitynativeqemu.SourceContractCase(originalGuestNativeRealm.Request.NativeCase) {
		return nil, false, nil
	}
	if input.Slot != 1 || grant.Slot != 1 || input.Generation != pre.Generation || input.FencingToken != pre.Fence || input.LeaseOwner != pre.LeaseOwner || store.ExecutorID != pre.ExecutorID {
		return nil, true, errOriginalGuestStep
	}
	if capacitynativeqemu.SourceRecoveryCase(originalGuestNativeRealm.Request.NativeCase) {
		contract, err := originalGuestNativeRealm.OriginalRecoveryContract(ctx, store, policy, p, binding, grant, pre)
		return contract, true, err
	}
	contract, err := originalGuestNativeRealm.OriginalSourceFence(ctx, store, policy, p, binding, grant, pre)
	return contract, true, err
}

func guestOriginalSourceCreateWitness(ctx context.Context, store repository.CapacityStore, id string, proof model.CapacityMutationProof, key ed25519.PrivateKey) (model.CapacityGuestOriginalCreateWitness, error) {
	if originalGuestNativeRealm != nil && capacitynativeqemu.PostlossSourceCase(originalGuestNativeRealm.Request.NativeCase) && proof.Slot == 2 {
		return store.RecordGuestPostlossObservedWitness(ctx, id, proof, key, originalGuestNativeRealm.Request.NativeCase, filepath.Join(capacitynativeqemu.SlotDirectory(originalGuestNativeRealm.PrivateDirectory, 2), "core-original-create-transport-uncertain.json"))
	}
	return store.RecordGuestCreateWitness(ctx, id, proof, key)
}

// The standard capacity.recover step and this resolved step share the actual
// original RunOne invocation executor. Caller JSON supplies no private context.
func sourceGuestRecoveryCleanupStep(ctx context.Context, store repository.CapacityStore, policy model.Manifest, p model.CapacityPolicySpec, input guestOriginalStepInput, operation string) (any, error) {
	if originalGuestNativeRealm == nil || !capacitynativeqemu.CanonicalSourceCompensationCase(originalGuestNativeRealm.Request.NativeCase) || operation != "capacity.qualify_original_guest_echo" || input.Slot != 2 || input.RequestID != "source_recovery_cleanup_v1" || p.GuestRetirementBinding == nil || p.GuestRetirementBinding.EvidenceClass != "native_qemu_qualification" || p.GuestRetirementBinding.ProfileManifest.Profile != "qualification-original-echo-writer-v1" {
		return nil, errOriginalGuestStep
	}
	pre, err := originalGuestNativeRealm.OriginalPreregistration(2)
	if err != nil || pre.PreregistrationID != input.PreregistrationID || pre.PolicyID != policy.ID.String() || pre.PolicyChecksum != policy.Checksum || pre.WorkflowID != store.WorkflowID.String() {
		return nil, errOriginalGuestStep
	}
	current, err := store.Observe(ctx, policy)
	if err != nil || !current.RecoveryOnly || current.Generation != input.Generation || current.FencingToken != input.FencingToken || current.LeaseOwner != input.LeaseOwner || current.LeaseExecutorID != store.ExecutorID {
		return nil, errOriginalGuestStep
	}
	var member model.CapacityGuestRetirementMemberBinding
	for _, m := range p.GuestRetirementBinding.Members {
		if m.Slot == 2 {
			member = m
		}
	}
	client, err := sourceGuestClient(ctx, store.DB, member)
	if err != nil {
		return nil, err
	}
	defer client.Close()
	if err = originalGuestNativeRealm.PrepareOriginalRecoveryCleanupRead(ctx, store, policy, pre, client); err != nil {
		return nil, err
	}
	// No executor/lease/token escapes through the public workflow result.
	return map[string]any{"schema": "original_source_recovery_cleanup_admitted_v1", "scope": "CURRENT_READ_ONLY_ADMISSION_NOT_PHYSICAL_EFFECT", "native_qualified": false}, nil
}
