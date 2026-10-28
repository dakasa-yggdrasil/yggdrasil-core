//go:build linux && nativequalification

package message

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"path/filepath"
	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	q "github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacitynativeqemu"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	"time"
	"github.com/google/uuid"
)

func sourceNativeBaseline(ctx context.Context, store repository.CapacityStore, policy model.Manifest, p model.CapacityPolicySpec, input guestOriginalStepInput, key ed25519.PrivateKey) (q.QualificationProbeReceipt, error) {
	var probe q.QualificationProbeReceipt
	if err := store.ValidateNativeObservationLease(ctx, policy, input.Generation, input.FencingToken, input.LeaseOwner); err != nil {
		return probe, err
	}
	current, err := store.Observe(ctx, policy)
	if err != nil || current.LeaseExpiresAt == nil || current.Generation != input.Generation || current.FencingToken != input.FencingToken {
		return probe, errOriginalGuestStep
	}
	var member model.CapacityGuestRetirementMemberBinding
	for _, m := range p.GuestRetirementBinding.Members {
		if m.Slot == 1 {
			member = m
		}
	}
	client, err := sourceGuestClient(ctx, store.DB, member)
	if err != nil {
		return probe, err
	}
	defer client.Close()
	if current.RecoveryOnly {
		probe, err = originalGuestNativeRealm.RecoveryProbe(ctx, store, policy, input.Generation, input.FencingToken, input.LeaseOwner, 1, key, client, *current.LeaseExpiresAt)
	} else {
	probe, err = originalGuestNativeRealm.Probe(ctx, store, policy, input.Generation, input.FencingToken, input.LeaseOwner, 1, key, client, *current.LeaseExpiresAt)
	}
	if err != nil {
		return probe, err
	}
	b, err := capacity.VMObservationBinding(p, input.BindingName)
	if err != nil {
		return probe, err
	}
	physical, err := originalGuestNativeRealm.FreshNativeMember(ctx, 1, b)
	if err != nil {
		return probe, err
	}
	var spec *model.CapacityMutationSpecV1
	for _, slot := range b.Slots {
		if slot.Slot == 1 {
			spec = slot.DesiredSpec
		}
	}
	if spec == nil {
		return probe, errOriginalGuestStep
	}
	wire, _ := json.Marshal(spec)
	err = store.RecordMutationSlot(ctx, policy, input.Generation, input.FencingToken, input.LeaseOwner, model.CapacityMutationIssue{BindingName: b.Name, DesiredSpec: wire}, physical)
	return probe, err
}

func guestOriginalSourceBeforeRetirement(ctx context.Context, store repository.CapacityStore, policy model.Manifest, p model.CapacityPolicySpec, input guestOriginalStepInput, key ed25519.PrivateKey) (func(context.Context) error, error) {
	if originalGuestNativeRealm == nil || input.Slot != 2 || !q.RetirementCase(originalGuestNativeRealm.Request.NativeCase) {
		return nil, errOriginalGuestStep
	}
	if _, err := sourceNativeBaseline(ctx, store, policy, p, input, key); err != nil {
		return nil, err
	}
	if err := originalGuestNativeRealm.PinOriginalRetirement(ctx, 2); err != nil {
		return nil, err
	}
	if q.PositiveCase(originalGuestNativeRealm.Request.NativeCase) {
	// Retain the genuine live physical tuple BEFORE quiescence. This record
	// is never refreshed or rewritten after deletion to manufacture presence.
	readoptionBinding,err:=capacity.VMObservationBinding(p,input.BindingName)
	if err!=nil{return nil,err}
	presence,err:=originalGuestNativeRealm.OriginalReadoptionPresence(ctx,2,readoptionBinding)
	if err!=nil{return nil,err}
	if _,err=q.Publish(ctx,filepath.Join(q.SlotDirectory(originalGuestNativeRealm.PrivateDirectory,2),"delete-readoption-original-presence.json"),presence);err!=nil{return nil,err}
	}
	ticker := time.NewTicker(2 * time.Second)
	join := startOriginalFloorKeeper(ctx, ticker.C, ticker.Stop, func(probeCtx context.Context) error {
		_, err := sourceNativeBaseline(probeCtx, store, policy, p, input, key)
		return err
	})
	return join, nil
}

func sourceGuestNativeRetirementFinished(ctx context.Context, store repository.CapacityStore, policy model.Manifest, p model.CapacityPolicySpec, input guestOriginalStepInput, key ed25519.PrivateKey) (any, error) {
	if input.Slot != 2 || input.RequestID == "" || input.PreregistrationID == "" || originalGuestNativeRealm == nil {
		return nil, errOriginalGuestStep
	}
	var member model.CapacityGuestRetirementMemberBinding
	for _, m := range p.GuestRetirementBinding.Members {
		if m.Slot == 2 {
			member = m
		}
	}
	// Source records name the exact original request. No latest/replacement ID
	// or missing response can be turned into a second retirement POST.
	var intentSHA string
	if err := store.DB.QueryRowContext(ctx, `SELECT intent_sha256 FROM public.capacity_vm_retirement_intents WHERE id=$1 AND preregistration_id=$2`, input.RequestID, input.PreregistrationID).Scan(&intentSHA); err != nil {
		return nil, err
	}
	stored, err := store.GuestRetirementOriginal(ctx, member.ActorClientPrincipal, input.RequestID, intentSHA)
	if err != nil {
		return nil, err
	}
	original, cancel := context.WithDeadline(ctx, stored.Request.Intent.OriginalDeadline)
	defer cancel()
	offWire, pidfdWire, err := originalGuestNativeRealm.OriginalNativeOff(original)
	if err != nil {
		return nil, err
	}
	baseline, err := sourceNativeBaseline(original, store, policy, p, input, key)
	if err != nil {
		return nil, err
	}
	if err = store.RecordGuestNativeQEMUPoweroff(original, input.RequestID, offWire, pidfdWire); err != nil {
		return nil, err
	}
	// Actual enrolled, quiescent and powered-off original success remains
	// ineligible for failed-create compensation; never relabel it as failed.
	if err = store.AssertOriginalSuccessfulParentNotCompensable(original, policy, stored.Preregistration.OriginalCreateGrantID); err != nil {
		return nil, err
	}
	current, err := store.Observe(original, policy)
	if err != nil || current.Phase != "draining" || current.Decision.Units != 1 {
		return nil, errOriginalGuestStep
	}
	assessment := q.QualificationAssessment(p, 1, 0.1, baseline.OriginalNativeAfterReturnedAt)
	zero := 0
	proof := model.CapacityTransitionProof{Assessment: assessment, ObservedAt: baseline.OriginalNativeAfterReturnedAt, ReceiptRef: "original-baseline-useful-and-burst-quiescent:" + capacity.BusinessCreationSHA256(offWire), Healthy: true, Inflight: &zero}
	b, err := capacity.VMObservationBinding(p, input.BindingName)
	if err != nil {
		return nil, err
	}
	var spec *model.CapacityMutationSpecV1
	for _, slot := range b.Slots {
		if slot.Slot == 2 && slot.DesiredSpec != nil {
			copy := *slot.DesiredSpec
			spec = &copy
		}
	}
	if spec == nil {
		return nil, errOriginalGuestStep
	}
	spec.Capability = b.DestroyCapability
	spec.ExpectedResourceID = stored.Request.Intent.Tuple.ResourceID
	spec.ExpectedResourceCreatedAt = stored.Request.Intent.Tuple.CreatedAt
	wire, _ := json.Marshal(spec)
	burstIssue := model.CapacityMutationIssue{BindingName: b.Name, DesiredSpec: wire}
	// The unchanged real intent is still draining. No caller writes phase or
	// grants: the original method must reject a physical delete before drain.
	if _, err = store.IssueMutation(original, policy, input.Generation, input.FencingToken, input.LeaseOwner, burstIssue); !errors.Is(err, repository.ErrCapacityConflict) {
		return nil, errOriginalGuestStep
	}
	if _, err = store.Advance(original, policy, input.Generation, input.FencingToken, input.LeaseOwner, "drained", proof); err != nil {
		return nil, err
	}
	baselineIssue, err := sourceNativeProtectedDestroyIssue(original, p, b)
	if err != nil {
		return nil, capacity.GuestQualificationRefusal("native_finish_protected_spec", err)
	}
	if _, err = store.IssueMutation(original, policy, input.Generation, input.FencingToken, input.LeaseOwner, baselineIssue); !errors.Is(err, repository.ErrCapacityConflict) {
		return nil, capacity.GuestQualificationRefusal("native_finish_protected_refusal", errOriginalGuestStep)
	}
	grant, err := store.IssueMutation(original, policy, input.Generation, input.FencingToken, input.LeaseOwner, burstIssue)
	if err != nil {
		return nil, capacity.GuestQualificationRefusal("native_finish_burst_issue", err)
	}
	if err = sourceNativePendingDeleteContract(original, store, policy, p, b, input, burstIssue, baselineIssue, grant); err != nil {
		return nil, err
	}
	observed, err := originalGuestNativeRealm.DestroyOriginal(original, grant)
	if err != nil {
		return nil, err
	}
	if err = store.RecordGuestNativeQEMUDeleteReadback(original, policy, input.Generation, input.FencingToken, input.LeaseOwner, observed); err != nil {
		return nil, err
	}
	receipt, err := originalGuestNativeRealm.OriginalMutationReceipt(original, grant.GrantID)
	if err != nil {
		return nil, err
	}
	nativeProof, err := repository.GuestNativeQEMUDeleteProof(p, b, receipt, observed, time.Now().UTC(), "original-native-qemu-disk-delete:"+capacity.GuestRetirementSHA(observed))
	if err != nil {
		return nil, err
	}
	confirmed, err := store.ConfirmMutation(original, policy, input.Generation, input.FencingToken, input.LeaseOwner, nativeProof)
	if err != nil {
		return nil, err
	}
	if err = sourceNativeConfirmedDeleteContract(original, store, policy, p, b, input, nativeProof, confirmed); err != nil {
		return nil, err
	}
	baseline, err = sourceNativeBaseline(original, store, policy, p, input, key)
	if err != nil {
		return nil, err
	}
	proof.Assessment = q.QualificationAssessment(p, 1, 0.1, baseline.OriginalNativeAfterReturnedAt)
	proof.ObservedAt = baseline.OriginalNativeAfterReturnedAt
	proof.ReceiptRef = "original-post-delete-baseline-useful:" + capacity.GuestRetirementSHA(baseline)
	if _, err = store.Advance(original, policy, input.Generation, input.FencingToken, input.LeaseOwner, "promoted", proof); err != nil {
		return nil, err
	}
	return struct {
		RequestID                  string                      `json:"request_id"`
		DestroyGrant               model.CapacityMutationGrant `json:"destroy_grant"`
		NativeOffSHA256            string                      `json:"native_off_sha256"`
		NativeDeleteReadbackSHA256 string                      `json:"native_delete_readback_sha256"`
		BaselineUsefulSHA256       string                      `json:"baseline_useful_sha256"`
		Scope                      string                      `json:"scope"`
	}{input.RequestID, confirmed, capacity.BusinessCreationSHA256(offWire), capacity.GuestRetirementSHA(observed), capacity.GuestRetirementSHA(baseline), "original_native_qemu_only_not_physical_provider_or_production20"}, nil
}

// The protected baseline identity comes from the real independent native read,
// never from a caller resource name or an invented desired expected tuple.
func sourceNativeProtectedDestroyIssue(ctx context.Context, p model.CapacityPolicySpec, b model.CapacityMutationBinding) (model.CapacityMutationIssue, error) {
	var issue model.CapacityMutationIssue
	physical, err := originalGuestNativeRealm.FreshNativeMember(ctx, 1, b)
	if err != nil || physical.Slot != 1 || physical.ResourceAbsent || physical.ResourceID == "" || physical.ResourceCreatedAt == "" {
		return issue, errOriginalGuestStep
	}
	for _, slot := range b.Slots {
		if slot.Slot == 1 && slot.DesiredSpec != nil {
			spec := *slot.DesiredSpec
			spec.Capability = b.DestroyCapability
			spec.ExpectedResourceID, spec.ExpectedResourceCreatedAt = physical.ResourceID, physical.ResourceCreatedAt
			wire, err := json.Marshal(spec)
			if err != nil {
				return issue, err
			}
			return model.CapacityMutationIssue{BindingName: b.Name, DesiredSpec: wire}, nil
		}
	}
	return issue, errOriginalGuestStep
}

func sourceNativePendingDeleteContract(ctx context.Context, store repository.CapacityStore, policy model.Manifest, p model.CapacityPolicySpec, b model.CapacityMutationBinding, input guestOriginalStepInput, burstIssue, baselineIssue model.CapacityMutationIssue, grant model.CapacityMutationGrant) error {
	current, err := store.Observe(ctx, policy)
	if err != nil || current.Phase != "drained" || current.Decision.Units != 1 || p.Floor != 1 || b.ProtectedSlots != 1 || b.MaxSlots != 2 || grant.Slot != 2 || grant.Capability != b.DestroyCapability {
		return errOriginalGuestStep
	}
	repeated, err := store.IssueMutation(ctx, policy, input.Generation, input.FencingToken, input.LeaseOwner, burstIssue)
	if err != nil || capacity.GuestRetirementSHA(repeated) != capacity.GuestRetirementSHA(grant) {
		return errOriginalGuestStep
	}
	if _, err = store.IssueMutation(ctx, policy, input.Generation, input.FencingToken, input.LeaseOwner, baselineIssue); !errors.Is(err, repository.ErrCapacityConflict) {
		return errOriginalGuestStep
	}
	var live, pending, creates int
	if err = store.DB.QueryRowContext(ctx, `SELECT count(*) FROM public.capacity_resource_slots WHERE namespace=$1 AND environment=$2 AND domain=$3 AND dimension=$4 AND resource_id<>''`, policy.Metadata.Namespace, p.Environment, p.Domain, p.Dimension).Scan(&live); err != nil {
		return err
	}
	if err = store.DB.QueryRowContext(ctx, `SELECT count(*) FILTER(WHERE state IN ('issued','redeemed','settled') AND grant_record->'grant'->>'capability'=$5),count(*) FILTER(WHERE state IN ('issued','redeemed','settled','compensating') AND grant_record->'grant'->>'capability'=$6) FROM public.capacity_mutation_grants WHERE namespace=$1 AND environment=$2 AND domain=$3 AND dimension=$4`, policy.Metadata.Namespace, p.Environment, p.Domain, p.Dimension, b.DestroyCapability, b.EnsureCapability).Scan(&pending, &creates); err != nil {
		return err
	}
	if live != 2 || pending != 1 || creates != 0 || live-pending != current.Decision.Units || live-pending != p.Floor || ctx.Err() != nil {
		return errOriginalGuestStep
	}
	contract := struct {
		Schema string `json:"schema"`
		CoreSource string `json:"core_source"`
		GrantID string `json:"grant_id"`
		Live int `json:"live_members"`
		Pending int `json:"pending_deletes"`
		PendingCreates int `json:"pending_creates"`
		Floor int `json:"protected_floor"`
		Target int `json:"target_units"`
		UndrainedRefused bool `json:"undrained_delete_refused"`
		FloorRefused bool `json:"protected_delete_refused"`
		ReplaySame bool `json:"pending_replay_same_grant"`
	}{"original_guest_two_slot_delete_budget_v1", capacity.CurrentGuestCoreSource(), grant.GrantID, live, pending, creates, p.Floor, current.Decision.Units, true, true, true}
	_, err = q.Publish(ctx, filepath.Join(q.SlotDirectory(originalGuestNativeRealm.PrivateDirectory, 2), "delete-budget-contract.json"), contract)
	return err
}

func sourceNativeConfirmedDeleteContract(ctx context.Context, store repository.CapacityStore, policy model.Manifest, p model.CapacityPolicySpec, b model.CapacityMutationBinding, input guestOriginalStepInput, proof model.CapacityMutationProof, confirmed model.CapacityMutationGrant) error {
	// Re-use exactly the authentic independent absence proof; no re-observation,
	// copied resource-presence assertion or timestamp refresh is manufactured.
	repeated, err := store.ConfirmMutation(ctx, policy, input.Generation, input.FencingToken, input.LeaseOwner, proof)
	if err != nil || capacity.GuestRetirementSHA(repeated) != capacity.GuestRetirementSHA(confirmed) || confirmed.State != "confirmed" {
		return errOriginalGuestStep
	}
	var tombstone bool
	var resource, created string
	if err = store.DB.QueryRowContext(ctx, `SELECT COALESCE((slot_record->>'tombstone')::boolean,false),resource_id,slot_record->>'resource_created_at' FROM public.capacity_resource_slots WHERE namespace=$1 AND environment=$2 AND domain=$3 AND dimension=$4 AND integration_instance_id=$5 AND scope_checksum=$6 AND profile_name=$7 AND slot=2`, policy.Metadata.Namespace, p.Environment, p.Domain, p.Dimension, b.IntegrationInstanceID, b.ScopeChecksum, b.ProfileName).Scan(&tombstone, &resource, &created); err != nil {
		return err
	}
	var events int
	if err = store.DB.QueryRowContext(ctx, `SELECT count(*) FROM public.event_log WHERE metadata->>'namespace'=$1 AND idempotency_key=$2`, policy.Metadata.Namespace, "capacity-mutation/"+confirmed.GrantID).Scan(&events); err != nil {
		return err
	}
	if !tombstone || resource != "" || created != proof.ResourceCreatedAt || events != 1 || ctx.Err() != nil {
		return errOriginalGuestStep
	}
	if err=sourceNativePostDeleteReadoptionContract(ctx,store,policy,p,b,input,proof,confirmed);err!=nil{return err}
	contract := struct {
		Schema string `json:"schema"`
		CoreSource string `json:"core_source"`
		GrantID string `json:"grant_id"`
		ResourceID string `json:"original_resource_id"`
		ResourceCreatedAt string `json:"original_resource_created_at"`
		ProofSHA256 string `json:"absence_proof_sha256"`
		CanonicalEvents int `json:"canonical_events"`
		Tombstone bool `json:"tombstone"`
		ResourceCleared bool `json:"resource_cleared"`
		SameProofReplay bool `json:"same_absence_proof_replay"`
	}{"original_guest_native_delete_tombstone_v1", capacity.CurrentGuestCoreSource(), confirmed.GrantID, proof.ResourceID, proof.ResourceCreatedAt, capacity.GuestRetirementSHA(proof), events, tombstone, resource == "", true}
	_, err = q.Publish(ctx, filepath.Join(q.SlotDirectory(originalGuestNativeRealm.PrivateDirectory, 2), "delete-tombstone-contract.json"), contract)
	return err
}

// Same actual settled/native create, paused administratively BEFORE canonical
// Confirm. The original proof is retained unchanged, not timestamp-restamped.
func guestOriginalSourceHistoricalConfirm(ctx context.Context,store repository.CapacityStore,policy model.Manifest,p model.CapacityPolicySpec,binding model.CapacityMutationBinding,input guestOriginalStepInput,key ed25519.PrivateKey,grant model.CapacityMutationGrant,pre model.CapacityGuestOriginalProvisioningPreregistration,enrollment model.CapacityGuestOriginalProvisioningReceipt,originalProof model.CapacityMutationProof)(any,bool,error){
	if originalGuestNativeRealm==nil || !q.SourceHistoricalConfirmCase(originalGuestNativeRealm.Request.NativeCase){return nil,false,nil}
	if input.Slot!=1 || grant.Slot!=1 || pre.Generation!=input.Generation || pre.Fence!=input.FencingToken || pre.LeaseOwner!=input.LeaseOwner || pre.ExecutorID!=store.ExecutorID || pre.OriginalCreateGrantID!=grant.GrantID || originalProof.GrantID!=grant.GrantID{return nil,true,errOriginalGuestStep}
	limit:=originalGuestNativeRealm.Request.OriginalStepStartedAt.Add(420*time.Second);if pre.OriginalDeadline.Before(limit){limit=pre.OriginalDeadline}
	original,cancel:=context.WithDeadline(ctx,limit);defer cancel();ctx=original
	actual,err:=store.NativeMutationReceipt(ctx,policy,binding,grant.GrantID)
	if err!=nil || actual.Grant.State!="settled" || !actual.TransportCompleted || actual.ResourceID!=originalProof.ResourceID || actual.ResourceCreatedAt!=originalProof.ResourceCreatedAt{return nil,true,errOriginalGuestStep}
	// Admission/enrollment is an authentic existing callback, not canonical
	// capacity membership. Remember it once so the original actor can be read.
	if err=originalGuestNativeRealm.Enrolled(ctx,grant,pre,enrollment);err!=nil{return nil,true,err}
	var encoded []byte;var before model.CapacityIntent
	if err=store.DB.QueryRowContext(ctx,`SELECT intent FROM public.capacity_intents WHERE namespace=$1 AND environment=$2 AND domain=$3 AND dimension=$4`,policy.Metadata.Namespace,p.Environment,p.Domain,p.Dimension).Scan(&encoded);err!=nil{return nil,true,err}
	if json.Unmarshal(encoded,&before)!=nil || before.PolicyID!=policy.ID || before.Generation!=input.Generation || before.FencingToken!=input.FencingToken || before.LeaseOwner!=input.LeaseOwner || before.LeaseExecutorID!=store.ExecutorID || before.RecoveryOnly || before.LeaseExpiresAt==nil || !before.LeaseExpiresAt.Before(limit){return nil,true,errOriginalGuestStep}
	prior,err:=repository.GetManifestByID(ctx,store.DB,policy.ID)
	if err!=nil || prior.ID!=policy.ID || prior.Checksum!=policy.Checksum || prior.Kind!="capacity_policy" || prior.Metadata.Namespace!=policy.Metadata.Namespace || !prior.Metadata.Active{return nil,true,errOriginalGuestStep}
	rows,err:=repository.MarkManifestInactiveByID(ctx,store.DB,policy.ID);if err!=nil || rows!=1{return nil,true,errOriginalGuestStep}
	paused,err:=repository.GetManifestByID(ctx,store.DB,policy.ID)
	if err!=nil || paused.ID!=prior.ID || paused.Checksum!=prior.Checksum || paused.Kind!=prior.Kind || paused.Metadata.Namespace!=prior.Metadata.Namespace || paused.Metadata.Active{return nil,true,errOriginalGuestStep}
	var expiredAt time.Time
	for{if err=store.DB.QueryRowContext(ctx,`SELECT clock_timestamp()`).Scan(&expiredAt);err!=nil{return nil,true,err};if !expiredAt.Before(*before.LeaseExpiresAt){break};timer:=time.NewTimer(20*time.Millisecond);select{case <-ctx.Done():timer.Stop();return nil,true,ctx.Err();case <-timer.C:}}
	var member model.CapacityGuestRetirementMemberBinding;for _,m:=range p.GuestRetirementBinding.Members{if m.Slot==1{member=m}}
	client,err:=sourceGuestClient(ctx,store.DB,member);if err!=nil{return nil,true,err}
	diagnostic,readErr:=originalGuestNativeRealm.DiagnosticProbe(ctx,store,1,key,client);client.Close();if readErr!=nil{return nil,true,readErr}
	recovery:=store;recovery.ExecutionEnabled=false;recovery.ExecutorID=uuid.NewString()
	lease,err:=recovery.Recover(ctx,policy,input.Generation,q.QualificationAssessment(p,1,0.9,diagnostic.OriginalNativeAfterReturnedAt))
	if err!=nil || !lease.RecoveryOnly || lease.Decision.ExecutionPermitted || lease.LeaseExecutorID!=recovery.ExecutorID || lease.FencingToken!=before.FencingToken+1 || lease.LeaseOwner==before.LeaseOwner{return nil,true,errOriginalGuestStep}
	if err=recovery.ValidateNativeObservationLease(ctx,policy,input.Generation,lease.FencingToken,lease.LeaseOwner);err!=nil{return nil,true,err}
	// The old observation must actually age out. This negative cannot be
	// mistaken for a retained old timestamp being accepted after300s.
	if capacity.Fresh(originalProof.ObservedAt,time.Now().UTC(),p.MaxEvidenceAgeSeconds){return nil,true,errOriginalGuestStep}
	if _,err=recovery.ConfirmMutation(ctx,policy,input.Generation,lease.FencingToken,lease.LeaseOwner,originalProof);err==nil{return nil,true,errOriginalGuestStep}
	var events int
	if err=store.DB.QueryRowContext(ctx,`SELECT count(*) FROM public.event_log WHERE idempotency_key=$1`,"capacity-mutation/"+grant.GrantID).Scan(&events);err!=nil || events!=0{return nil,true,errOriginalGuestStep}
	physical,err:=originalGuestNativeRealm.FreshNativeMember(ctx,1,binding)
	if err!=nil || physical.ResourceID!=originalProof.ResourceID || physical.ResourceCreatedAt!=originalProof.ResourceCreatedAt || physical.RequestSHA256!=originalProof.RequestSHA256 || physical.ObservedCreationGrantID!=grant.GrantID{return nil,true,errOriginalGuestStep}
	// Preserve the genuine original completed action IDs/transport lineage.
	// Only observation facts come from the fresh actual native read above.
	fresh:=originalProof;fresh.ObservedAt=physical.ObservedAt;fresh.ReceiptRef=physical.ReceiptRef;fresh.OwnerVerified=physical.OwnerVerified;fresh.SpecVerified=physical.SpecVerified
	confirmed,err:=recovery.ConfirmMutation(ctx,policy,input.Generation,lease.FencingToken,lease.LeaseOwner,fresh)
	if err!=nil || confirmed.State!="confirmed" || confirmed.GrantID!=grant.GrantID{return nil,true,errOriginalGuestStep}
	if _,err=recovery.ConfirmMutation(ctx,policy,input.Generation,lease.FencingToken,lease.LeaseOwner,fresh);err!=nil{return nil,true,err}
	if err=recovery.CheckNativeMembershipCoverage(ctx,policy,binding,[]model.CapacityMutationProof{fresh});err!=nil{return nil,true,err}
	if err=store.DB.QueryRowContext(ctx,`SELECT count(*) FROM public.event_log WHERE idempotency_key=$1`,"capacity-mutation/"+grant.GrantID).Scan(&events);err!=nil || events!=1{return nil,true,errOriginalGuestStep}
	retained,err:=recovery.NativeMutationReceipt(ctx,policy,binding,grant.GrantID);if err!=nil || retained.Grant.State!="confirmed" || retained.ResourceID!=fresh.ResourceID || !retained.TransportCompleted{return nil,true,errOriginalGuestStep}
	result:=q.SourceHistoricalConfirmContract{Schema:"core_original_source_historical_confirm_v1",Scope:"SOURCE_HISTORICAL_CONFIRMED_AFTER_REAL_PAUSE_ONLY",Case:originalGuestNativeRealm.Request.NativeCase,CoreSource:capacity.CurrentGuestCoreSource(),GuestSource:originalGuestNativeRealm.Request.SourceCommit,PolicyID:policy.ID.String(),GrantID:grant.GrantID,PreregistrationID:pre.PreregistrationID,Generation:input.Generation,RecoveryFence:lease.FencingToken,PauseRows:rows,PolicyActiveAfter:paused.Metadata.Active,RecoveryExecutionEnabled:recovery.ExecutionEnabled,OriginalProofSHA256:capacity.GuestRetirementSHA(originalProof),FreshPhysicalSHA256:capacity.GuestRetirementSHA(physical),FreshConfirmSHA256:capacity.GuestRetirementSHA(fresh),OriginalReceiptSHA256:capacity.GuestRetirementSHA(actual),ConfirmedReceiptSHA256:capacity.GuestRetirementSHA(retained),DiagnosticSHA256:capacity.GuestRetirementSHA(diagnostic),StateAfter:confirmed.State,CanonicalEvents:events,OldObservationRefused:true,LeaseExpiredObservedAt:expiredAt,CheckedAt:time.Now().UTC(),OriginalDeadline:limit}
	if _,err=q.Publish(ctx,filepath.Join(originalGuestNativeRealm.PrivateDirectory,"source-historical-confirm-contract.json"),result);err!=nil{return nil,true,err}
	if ctx.Err()!=nil || !time.Now().UTC().Before(limit){return nil,true,errOriginalGuestStep}
	return result,true,nil
}
