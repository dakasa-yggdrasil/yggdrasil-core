//go:build linux && nativequalification

package repository

import (
 "bytes"
 "context"
 "database/sql"
 "encoding/json"
 "reflect"
 "time"

 "github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
 "github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

const sourceRecoveryCleanupSchema="original_source_recovery_failure_cleanup_authority_v1"
const sourceRecoveryCleanupScope="same_original_host_qemu_recovery_owned_cleanup_not_guest_positive_retirement"

// This predicate cannot turn an original tuple into a current lease. The caller
// must additionally load the locked database intent and checkRecoveryLease.
func recoveryCleanupEpochMatches(e *model.CapacitySourceRecoveryCleanupEpoch, current model.CapacityIntent, parent capacityMutationRecord, now time.Time) bool {
 return e!=nil && e.Schema=="original_source_recovery_cleanup_epoch_v1" && e.OriginalGeneration==parent.Generation && e.OriginalFencingToken==parent.FencingToken && e.OriginalLeaseOwner==parent.LeaseOwner && e.OriginalExecutorID==parent.ExecutorID && e.CurrentPolicyID==current.PolicyID.String() && e.CurrentPolicyChecksum==current.PolicyChecksum && e.Generation==current.Generation && e.Generation==parent.Generation && e.FencingToken==current.FencingToken && e.FencingToken>e.OriginalFencingToken && e.LeaseOwner==current.LeaseOwner && e.LeaseOwner!=e.OriginalLeaseOwner && e.ExecutorID==current.LeaseExecutorID && validCapacityExecutor(e.ExecutorID) && current.RecoveryOnly && current.LeaseExpiresAt!=nil && e.LeaseExpiresAt.Equal(*current.LeaseExpiresAt) && e.RecoveryDBObservedAt.Equal(current.UpdatedAt) && capacity.ValidDigest(e.IntentSHA256) && e.IntentSHA256==capacity.GuestRetirementSHA(current) && capacity.ValidDigest(e.NonceSHA256) && !e.ChallengePreparedAt.IsZero() && !e.ChallengePreparedAt.After(now) && now.Before(e.LeaseExpiresAt)
}

func(s CapacityStore) sourceRecoveryCleanupLeaseTx(ctx context.Context,tx *sql.Tx,b SourceFailureCleanupBody,parent capacityMutationRecord,now time.Time)(model.CapacityIntent,error){
 var none model.CapacityIntent
 if b.Schema!=sourceRecoveryCleanupSchema || b.Mode!="recovery_failure_cleanup_only" || b.Scope!=sourceRecoveryCleanupScope || b.Recovery==nil || !canonicalKnownFailedCase(b.NativeCase) || b.ProductionQualified || b.PositiveQuiescence || b.Slot!=2 || b.BaselineMembers!=1 || b.FailedSlotMembers!=0 || b.FailedSlotEnsuredEvents!=0 || b.ParentGrantID!=parent.Grant.GrantID || parent.Grant.CompensationOf!="" || (parent.Grant.State!="settled" && parent.Grant.State!="compensating" && parent.Grant.State!="compensated") || parent.WorkflowID!=s.WorkflowID || b.PolicyID!=parent.PolicyID.String() || b.PolicyChecksum!=parent.PolicyChecksum || b.CoreSource!=capacity.CurrentGuestCoreSource() || !now.Before(b.CleanupDeadline) || b.OriginalProvisioningDeadline.IsZero() || !now.Before(b.OriginalProvisioningDeadline) || b.CleanupDeadline.After(b.OriginalProvisioningDeadline) || b.CleanupDeadline.After(b.OriginalContextDeadline) || b.CleanupDeadline.After(b.IssuedAt.Add(150*time.Second)){return none,ErrCapacityConflict}
 originalPolicy,err:=GetManifestByID(ctx,s.DB,parent.PolicyID);if err!=nil{return none,err};p,err:=parseCapacityPolicy(originalPolicy);if err!=nil{return none,err}
 current,err:=loadCapacityIntent(ctx,tx,originalPolicy.Metadata.Namespace,p,true);if err!=nil{return none,err}
 if !recoveryCleanupEpochMatches(b.Recovery,current,parent,now) || b.CleanupDeadline.After(b.Recovery.LeaseExpiresAt){return none,ErrCapacityLease}
 owner:=s;owner.ExecutorID=current.LeaseExecutorID // read-only validation of locked database identity, not an actor/context grant
 if err=owner.checkRecoveryLease(originalPolicy,&current,current.Generation,current.FencingToken,current.LeaseOwner,now);err!=nil{return none,err}
 var epochWire []byte
 if err=tx.QueryRowContext(ctx,`SELECT epoch_wire FROM public.capacity_source_recovery_cleanup_reads WHERE nonce_sha256=$1`,b.Recovery.NonceSHA256).Scan(&epochWire);err!=nil{return none,err}
 var retained model.CapacitySourceRecoveryCleanupEpoch
 if capacity.DecodeGuestLifecycle(epochWire,&retained)!=nil || !reflect.DeepEqual(retained,*b.Recovery){return none,ErrCapacityConflict}
 return current,nil
}

func(s CapacityStore) CheckSourceRecoveryCleanupLease(ctx context.Context,policy model.Manifest,parentID string,b SourceFailureCleanupBody)error{
 tx,err:=s.DB.BeginTx(ctx,nil);if err!=nil{return err};defer tx.Rollback();p,err:=parseCapacityPolicy(policy);if err!=nil{return err}
 if err=lockMutationScope(ctx,tx,policy.Metadata.Namespace,p);err!=nil{return err};parent,err:=loadCompensationRecord(ctx,tx,policy,p,parentID);if err!=nil{return err};var now time.Time;if err=tx.QueryRowContext(ctx,`SELECT clock_timestamp()`).Scan(&now);err!=nil{return err}
 if _,err=s.sourceRecoveryCleanupLeaseTx(ctx,tx,b,parent,now);err!=nil{return err};return tx.Commit()
}

// Called only with the actual store captured by the resolved Source step. The
// executor and lease are never populated from caller-provided JSON.
func(s CapacityStore) PrepareSourceRecoveryCleanupChallenge(ctx context.Context,policy model.Manifest,parentID,nonce string)(model.CapacitySourceRecoveryCleanupEpoch,error){
 var e model.CapacitySourceRecoveryCleanupEpoch
 if !capacity.ValidDigest(nonce) || s.DB==nil || !validCapacityExecutor(s.ExecutorID){return e,ErrCapacityDisabled}
 tx,err:=s.DB.BeginTx(ctx,nil);if err!=nil{return e,err};defer tx.Rollback();p,err:=parseCapacityPolicy(policy);if err!=nil{return e,err};if err=lockMutationScope(ctx,tx,policy.Metadata.Namespace,p);err!=nil{return e,err}
 parent,err:=loadCompensationRecord(ctx,tx,policy,p,parentID);if err!=nil{return e,err};if parent.Grant.State!="settled" || parent.Grant.CompensationOf!="" || parent.WorkflowID!=s.WorkflowID || parent.Settlement==nil || !parent.Settlement.TransportCompleted{return e,ErrCapacityConflict}
 var preID string;if err=tx.QueryRowContext(ctx,`SELECT id::text FROM public.capacity_vm_provisioning_preregistrations WHERE create_grant_id=$1`,parentID).Scan(&preID);err!=nil{return e,err};stored,err:=loadGuestOriginalTx(ctx,tx,preID);if err!=nil{return e,err}
 if stored.binding.EvidenceClass!="native_qemu_qualification" || stored.binding.ProfileManifest.Profile!="qualification-original-echo-writer-v1" || stored.pre.OriginalWorkflowStepTimeoutSeconds!=600 || stored.pre.CoreSourceCommit!=capacity.CurrentGuestCoreSource() || stored.pre.WorkflowID!=s.WorkflowID.String() || stored.pre.PolicyID!=parent.PolicyID.String() || stored.pre.PolicyChecksum!=parent.PolicyChecksum{return e,ErrCapacityDisabled}
 var now time.Time;if err=tx.QueryRowContext(ctx,`SELECT clock_timestamp()`).Scan(&now);err!=nil{return e,err};current,err:=loadCapacityIntent(ctx,tx,policy.Metadata.Namespace,p,true);if err!=nil{return e,err}
 if current.Generation!=parent.Generation || current.FencingToken<=parent.FencingToken || current.LeaseOwner==parent.LeaseOwner || current.LeaseExpiresAt==nil || !now.Before(stored.pre.OriginalDeadline) || !now.Before(stored.pre.OriginalWorkflowContextDeadline){return e,ErrCapacityConflict}
 if err=s.checkRecoveryLease(policy,&current,current.Generation,current.FencingToken,current.LeaseOwner,now);err!=nil{return e,err}
 e=model.CapacitySourceRecoveryCleanupEpoch{Schema:"original_source_recovery_cleanup_epoch_v1",OriginalGeneration:parent.Generation,OriginalFencingToken:parent.FencingToken,OriginalLeaseOwner:parent.LeaseOwner,OriginalExecutorID:parent.ExecutorID,CurrentPolicyID:current.PolicyID.String(),CurrentPolicyChecksum:current.PolicyChecksum,Generation:current.Generation,FencingToken:current.FencingToken,LeaseOwner:current.LeaseOwner,ExecutorID:current.LeaseExecutorID,RecoveryDBObservedAt:current.UpdatedAt,LeaseExpiresAt:*current.LeaseExpiresAt,IntentSHA256:capacity.GuestRetirementSHA(current),NonceSHA256:nonce,ChallengePreparedAt:now}
 wire,err:=json.Marshal(e);if err!=nil{return e,err};if _,err=tx.ExecContext(ctx,`INSERT INTO public.capacity_source_recovery_cleanup_challenges VALUES($1,$2,$3,$4,$5,$6,$7,$8)`,nonce,parentID,preID,policy.Metadata.Namespace,current.Generation,current.FencingToken,wire,now);err!=nil{return e,err}
 return e,tx.Commit()
}

// Fresh reads append independent observations; immutable failed.RecordedAt,
// action IDs, original Wait/EOF and enrollment never change.
func(s CapacityStore) CompleteSourceRecoveryCleanupRead(ctx context.Context,policy model.Manifest,parentID string,epoch model.CapacitySourceRecoveryCleanupEpoch,nativeWire,failureWire []byte)(model.CapacitySourceRecoveryCleanupEpoch,error){
 out:=epoch
 tx,err:=s.DB.BeginTx(ctx,nil);if err!=nil{return out,err};defer tx.Rollback();p,err:=parseCapacityPolicy(policy);if err!=nil{return out,err};if err=lockMutationScope(ctx,tx,policy.Metadata.Namespace,p);err!=nil{return out,err}
 parent,err:=loadCompensationRecord(ctx,tx,policy,p,parentID);if err!=nil{return out,err};var now time.Time;if err=tx.QueryRowContext(ctx,`SELECT clock_timestamp()`).Scan(&now);err!=nil{return out,err};current,err:=loadCapacityIntent(ctx,tx,policy.Metadata.Namespace,p,true);if err!=nil{return out,err}
 if !recoveryCleanupEpochMatches(&epoch,current,parent,now) || s.ExecutorID!=current.LeaseExecutorID{return out,ErrCapacityLease};if err=s.checkRecoveryLease(policy,&current,current.Generation,current.FencingToken,current.LeaseOwner,now);err!=nil{return out,err}
 var preID string;var challenge []byte;if err=tx.QueryRowContext(ctx,`SELECT preregistration_id::text,epoch_wire FROM public.capacity_source_recovery_cleanup_challenges WHERE parent_grant_id=$1 AND nonce_sha256=$2`,parentID,epoch.NonceSHA256).Scan(&preID,&challenge);err!=nil{return out,err};var retained model.CapacitySourceRecoveryCleanupEpoch;if capacity.DecodeGuestLifecycle(challenge,&retained)!=nil || !reflect.DeepEqual(epoch,retained){return out,ErrCapacityConflict}
 stored,err:=loadGuestOriginalTx(ctx,tx,preID);if err!=nil{return out,err};creator,err:=guestNativeQEMUIdentityTx(ctx,tx,preID);if err!=nil{return out,err}
 var f CanonicalPostlossFreshFailureRead;if capacity.DecodeGuestLifecycle(failureWire,&f)!=nil{return out,ErrCapacityConflict}
 var immutableFailure []byte;if err=tx.QueryRowContext(ctx,`SELECT original_wire FROM public.capacity_guest_qualification_native_source_returns WHERE preregistration_id=$1 AND native_stage='source_refusal' AND return_sha256=$2 AND original_record=convert_from(original_wire,'UTF8')::jsonb`,preID,f.FailureSHA256).Scan(&immutableFailure);err!=nil{return out,err}
 var failed QualificationFailureRecord;if capacity.DecodeGuestLifecycle(immutableFailure,&failed)!=nil || !canonicalKnownFailedCase(failed.NativeCase) || failed.OriginalExitCode==nil || *failed.OriginalExitCode!=1 || failed.Phase!="original_probe_failed_owner_exit" || failed.PreregistrationID!=preID || failed.SourceCommit!=stored.binding.GuestSourceCommit{return out,ErrCapacityConflict}
 b:=SourceFailureCleanupBody{CreatorSHA256:creator.OriginalCreatorSHA256,FailureSHA256:f.FailureSHA256,OriginalProvisioningDeadline:stored.pre.OriginalDeadline}
 identity:=CanonicalSourceEligibility{NativeCase:failed.NativeCase,GuestSource:stored.binding.GuestSourceCommit,PreregistrationID:preID,FailureSHA256:f.FailureSHA256}
	var native struct {
		Schema                               string          `json:"schema"`
		OriginalCreatorSHA256                string          `json:"original_creator_sha256"`
		Original                             json.RawMessage `json:"original"`
		Before                               json.RawMessage `json:"before"`
		After                                json.RawMessage `json:"after"`
		QMPPeerPID                           int32           `json:"qmp_peer_pid"`
		ExecutableSHA256                     string          `json:"executable_sha256"`
		CommandLineSHA256                    string          `json:"command_line_sha256"`
		OriginalDisk                         json.RawMessage `json:"original_disk"`
		OriginalDiskFD                       int             `json:"original_disk_fd"`
		OriginalDiskReadReturnedAt           time.Time       `json:"original_disk_read_returned_at"`
		OriginalDiskDirectoryCloseReturnedAt time.Time       `json:"original_disk_directory_close_returned_at"`
		UUID                                 json.RawMessage `json:"uuid"`
		Status                               json.RawMessage `json:"status"`
		StartedAt                            time.Time       `json:"started_at"`
		ReadReturnedAt                       time.Time       `json:"read_returned_at"`
		CloseReturnedAt                      time.Time       `json:"close_returned_at"`
		IO                                   json.RawMessage `json:"io"`
	}
	// Decode the same original native schema without importing provider package
	// (which already imports repository). Exact original stable identity is
	// checked against the immutable original native row, all refreshed IO is real.
	if capacity.DecodeGuestLifecycle(nativeWire, &native) != nil || native.Schema != "core_independent_original_qemu_read_v1" || native.OriginalCreatorSHA256 != b.CreatorSHA256 || native.StartedAt.IsZero() || native.ReadReturnedAt.Before(native.StartedAt) || native.CloseReturnedAt.Before(native.ReadReturnedAt) || !capacity.Fresh(native.CloseReturnedAt, now, p.MaxEvidenceAgeSeconds) {
		return out, ErrCapacityConflict
	}
	var originalNativeWire []byte
	if err = tx.QueryRowContext(ctx, `SELECT original_wire FROM public.capacity_guest_qualification_native_source_returns WHERE preregistration_id=$1 AND native_stage='native_read'`, preID).Scan(&originalNativeWire); err != nil {
		return out, err
	}
	var prior map[string]json.RawMessage
	if json.Unmarshal(originalNativeWire, &prior) != nil {
		return out, ErrCapacityConflict
	}
	for key, raw := range map[string]json.RawMessage{"original": native.Original, "original_disk": native.OriginalDisk} {
		var a, c any
		if json.Unmarshal(raw, &a) != nil || json.Unmarshal(prior[key], &c) != nil || !reflect.DeepEqual(a, c) {
			return out, ErrCapacityConflict
		}
	}

	for _, raw := range []json.RawMessage{native.Before, native.After} {
		var actual, original struct {
			PID        int    `json:"pid"`
			PPID       int    `json:"ppid"`
			StartTicks uint64 `json:"start_ticks"`
			StatSHA256 string `json:"stat_sha256"`
		}
		if json.Unmarshal(raw, &actual) != nil || json.Unmarshal(prior["after"], &original) != nil || actual.PID != original.PID || actual.PPID != original.PPID || actual.StartTicks != original.StartTicks || !capacity.ValidDigest(actual.StatSHA256) {
			return out, ErrCapacityConflict
		}
	}
	var fresh CanonicalPostlossFreshFailureRead
	if capacity.DecodeGuestLifecycle(failureWire, &fresh) != nil || !recoveryFreshFailureMatches(fresh, identity, b, epoch.NonceSHA256, now, p.MaxEvidenceAgeSeconds) {
		return out, ErrCapacityConflict
	}
 sig:=fresh.Signature;fresh.Signature=""
 if fresh.ProducerPublicKey!=stored.binding.ProvisionerPublicKey || !capacity.GuestQualificationSignature(stored.binding.ProvisionerPublicKey,sig,fresh){return out,ErrCapacityConflict}
 observed:=native.CloseReturnedAt;if fresh.ReturnedAt.Before(observed){observed=fresh.ReturnedAt}
 if !observed.Before(stored.pre.OriginalDeadline) || !observed.Before(stored.pre.OriginalWorkflowContextDeadline) || !capacity.Fresh(observed,now,p.MaxEvidenceAgeSeconds){return out,ErrCapacityConflict}
 out.FreshFailureSHA256=capacity.BusinessCreationSHA256(failureWire);out.FreshNativeSHA256=capacity.BusinessCreationSHA256(nativeWire);out.FreshObservedAt=observed
 wire,err:=json.Marshal(out);if err!=nil{return out,err};if _,err=tx.ExecContext(ctx,`INSERT INTO public.capacity_source_recovery_cleanup_reads VALUES($1,$2,$3,$4,$5)`,out.NonceSHA256,nativeWire,failureWire,wire,capacity.BusinessCreationSHA256(wire));err!=nil{return out,err}
 return out,tx.Commit()
}

func recoveryFreshFailureMatches(f CanonicalPostlossFreshFailureRead,e CanonicalSourceEligibility,b SourceFailureCleanupBody,nonce string,now time.Time,maxAge int)bool{
 if f.Schema!="canonical_recovery_fresh_failure_read_v1"{return false}
 // Only this local predicate adapts the fixed schema discriminator. The
 // signature check ALWAYS uses the untouched new-schema actual object.
 original:=f;original.Schema="canonical_postloss_fresh_failure_read_v1"
 return canonicalKnownFailedCase(f.NativeCase) && postlossFreshFailureMatches(original,e,b,nonce,now,maxAge)
}

func(s CapacityStore) ValidateSourceRecoveryPreparation(ctx context.Context,policy model.Manifest,parentID string,e model.CapacitySourceRecoveryCleanupEpoch)(model.CapacityIntent,error){
 var none model.CapacityIntent
 tx,err:=s.DB.BeginTx(ctx,nil);if err!=nil{return none,err};defer tx.Rollback();p,err:=parseCapacityPolicy(policy);if err!=nil{return none,err};if err=lockMutationScope(ctx,tx,policy.Metadata.Namespace,p);err!=nil{return none,err};parent,err:=loadCompensationRecord(ctx,tx,policy,p,parentID);if err!=nil{return none,err};var now time.Time;if err=tx.QueryRowContext(ctx,`SELECT clock_timestamp()`).Scan(&now);err!=nil{return none,err};current,err:=loadCapacityIntent(ctx,tx,policy.Metadata.Namespace,p,true);if err!=nil{return none,err}
 if !recoveryCleanupEpochMatches(&e,current,parent,now) || s.ExecutorID!=current.LeaseExecutorID || !capacity.ValidDigest(e.FreshFailureSHA256) || !capacity.ValidDigest(e.FreshNativeSHA256) || !capacity.Fresh(e.FreshObservedAt,now,p.MaxEvidenceAgeSeconds){return none,ErrCapacityConflict};if err=s.checkRecoveryLease(policy,&current,current.Generation,current.FencingToken,current.LeaseOwner,now);err!=nil{return none,err}
 var wire []byte;if err=tx.QueryRowContext(ctx,`SELECT epoch_wire FROM public.capacity_source_recovery_cleanup_reads WHERE nonce_sha256=$1`,e.NonceSHA256).Scan(&wire);err!=nil{return none,err};var actual model.CapacitySourceRecoveryCleanupEpoch;if capacity.DecodeGuestLifecycle(wire,&actual)!=nil || !reflect.DeepEqual(e,actual){return none,ErrCapacityConflict}
 return current,tx.Commit()
}

func canonicalCleanupMode(b SourceFailureCleanupBody)bool{
 if b.Recovery==nil{return b.Schema=="original_source_failure_cleanup_authority_v1" && b.Mode=="failure_cleanup_only" && b.Scope=="same_original_host_qemu_cleanup_not_guest_positive_retirement"}
 return b.Schema==sourceRecoveryCleanupSchema && b.Mode=="recovery_failure_cleanup_only" && b.Scope==sourceRecoveryCleanupScope
}
func canonicalRecoveryObservedAt(b SourceFailureCleanupBody,old time.Time)time.Time{if b.Recovery!=nil{return b.Recovery.FreshObservedAt};return old}

func recoveryNativeIdentity(b SourceFailureCleanupBody)(string,error){
 var process,disk any
 decode:=func(raw []byte,out *any)error{d:=json.NewDecoder(bytes.NewReader(raw));d.UseNumber();return d.Decode(out)}
 if err:=decode(b.QEMU,&process);err!=nil{return "",err};if err:=decode(b.OriginalDisk,&disk);err!=nil{return "",err}
 return capacity.GuestRetirementSHA(map[string]any{"qemu":process,"original_disk":disk}),nil
}

// One transaction per effect. It COMMITs before the original Realm publishes
// the permit; no SQL lock is held while either process awaits the stage file.
func(s CapacityStore) AuthorizeSourceRecoveryEffect(ctx context.Context,policy model.Manifest,childID string,requestWire []byte)(SourceFailureCleanupAuthority,error){
 var signed SourceFailureCleanupAuthority
 var request model.CapacitySourceRecoveryEffectRequest
 if capacity.DecodeGuestLifecycle(requestWire,&request)!=nil || request.Schema!="original_source_recovery_effect_request_v1" || (request.Phase!="signal" && request.Phase!="unlink") || !capacity.ValidDigest(request.NonceSHA256){return signed,ErrCapacityConflict}
 err:=s.compensationTransaction(ctx,policy,false,func(tx *sql.Tx,p model.CapacityPolicySpec,now time.Time)error{
  locator,err:=readCompensationRecord(ctx,tx,policy,p,childID,false);if err!=nil{return err}
  if err=lockNativeMutationSlot(ctx,tx,locator.Binding,locator.Grant.Slot);err!=nil{return err}
  child,err:=loadCompensationRecord(ctx,tx,policy,p,childID);if err!=nil{return err}
  if !reflect.DeepEqual(child,locator) || child.Grant.State!="redeemed" || child.AttemptID=="" || child.ExecutorID!=s.ExecutorID || child.WorkflowID!=s.WorkflowID || !now.Before(child.Grant.ExpiresAt){return ErrCapacityConflict}
  e,handled,err:=s.canonicalEligibilityTx(ctx,tx,child.Grant.CompensationOf,now);if !handled || err!=nil{return ErrCapacityConflict}
  stored,b,t,err:=canonicalCleanupHistory(ctx,s,tx,e.PreregistrationID);if err!=nil || b.Recovery==nil || t.TerminalSHA256!=""{return ErrCapacityConflict}
  parent,err:=loadCompensationRecord(ctx,tx,policy,p,e.ParentGrantID);if err!=nil{return err};if parent.Grant.State!="compensating"{return ErrCapacityConflict}
  current,err:=s.sourceRecoveryCleanupLeaseTx(ctx,tx,b,parent,now);if err!=nil{return err};if s.ExecutorID!=current.LeaseExecutorID{return ErrCapacityLease}
  var childWire []byte;var childSHA string
  if err=tx.QueryRowContext(ctx,`SELECT authority_wire,authority_sha256 FROM public.capacity_canonical_source_effect_authorities WHERE child_grant_id=$1`,childID).Scan(&childWire,&childSHA);err!=nil{return err}
  raw,err:=canonicalSignedBody(ctx,s,stored,childWire);if err!=nil{return err};var a CanonicalSourceChildAuthority
  if capacity.DecodeGuestLifecycle(raw,&a)!=nil || capacity.BusinessCreationSHA256(childWire)!=childSHA || a.ChildGrantID!=childID || a.AttemptID!=child.AttemptID || a.ParentGrantID!=e.ParentGrantID || a.SourceAuthoritySHA256!=e.CleanupAuthoritySHA256 || !now.Before(a.OriginalDeadline){return ErrCapacityConflict}
  nativeSHA,err:=recoveryNativeIdentity(b);if err!=nil{return err}
  if request.AuthoritySHA256!=e.CleanupAuthoritySHA256 || request.ChildAuthoritySHA256!=childSHA || request.NativeIdentitySHA256!=nativeSHA{return ErrCapacityConflict}
  if request.Phase=="unlink"{var n int;if err=tx.QueryRowContext(ctx,`SELECT count(*) FROM public.capacity_source_recovery_cleanup_effect_permits WHERE child_grant_id=$1 AND phase='signal'`,childID).Scan(&n);err!=nil || n!=1{return ErrCapacityConflict}}
  deadline:=a.OriginalDeadline;if b.CleanupDeadline.Before(deadline){deadline=b.CleanupDeadline};if current.LeaseExpiresAt.Before(deadline){deadline=*current.LeaseExpiresAt};if b.OriginalProvisioningDeadline.Before(deadline){deadline=b.OriginalProvisioningDeadline};if d,ok:=ctx.Deadline();!ok{return ErrCapacityConflict}else if d.Before(deadline){deadline=d};if !now.Before(deadline){return ErrCapacityConflict}
  permit:=model.CapacitySourceRecoveryEffectPermit{Schema:"original_source_recovery_effect_permit_v1",Scope:"ONE_ORIGINAL_CHILD_EFFECT_CURRENT_RECOVERY_LEASE_NOT_POSITIVE_QUIESCENCE",Phase:request.Phase,RequestSHA256:capacity.BusinessCreationSHA256(requestWire),AuthoritySHA256:request.AuthoritySHA256,ChildAuthoritySHA256:childSHA,ChildGrantID:childID,ChildAttemptID:child.AttemptID,NativeIdentitySHA256:nativeSHA,NonceSHA256:request.NonceSHA256,Generation:current.Generation,FencingToken:current.FencingToken,LeaseOwner:current.LeaseOwner,ExecutorID:current.LeaseExecutorID,CheckedAt:now,Deadline:deadline,CoreSource:b.CoreSource,GuestSource:b.GuestSource,ProductionQualified:false}
  wire,err:=canonicalSign(ctx,s,stored,permit);if err!=nil{return err};if capacity.DecodeGuestLifecycle(wire,&signed)!=nil{return ErrCapacityConflict}
  _,err=tx.ExecContext(ctx,`INSERT INTO public.capacity_source_recovery_cleanup_effect_permits VALUES($1,$2,$3,$4,$5,$6,$7,$8)`,childID,request.Phase,requestWire,permit.RequestSHA256,request.NonceSHA256,wire,capacity.BusinessCreationSHA256(wire),now)
  return err
 })
 return signed,err
}

func(s CapacityStore) validateRecoveryPhysicalPermitsTx(ctx context.Context,tx *sql.Tx,stored guestOriginalStored,b SourceFailureCleanupBody,child capacityMutationRecord,a CanonicalSourceChildAuthority,f SourceFailureCleanupPhysical,now time.Time)error{
 originalPolicy,err:=GetManifestByID(ctx,s.DB,child.PolicyID);if err!=nil{return err};p,err:=parseCapacityPolicy(originalPolicy);if err!=nil{return err}
 parent,err:=loadCompensationRecord(ctx,tx,originalPolicy,p,child.Grant.CompensationOf);if err!=nil{return err}
 if _,err=s.sourceRecoveryCleanupLeaseTx(ctx,tx,b,parent,now);err!=nil{return err}
 nativeSHA,err:=recoveryNativeIdentity(b);if err!=nil{return err}
 var childWire []byte;if err=tx.QueryRowContext(ctx,`SELECT authority_wire FROM public.capacity_canonical_source_effect_authorities WHERE child_grant_id=$1`,child.Grant.GrantID).Scan(&childWire);err!=nil{return err}
 for _,phase:=range []string{"signal","unlink"}{
  var requestWire,permitWire []byte;var requestSHA,permitSHA,nonce string
  if err=tx.QueryRowContext(ctx,`SELECT request_wire,request_sha256,nonce_sha256,permit_wire,permit_sha256 FROM public.capacity_source_recovery_cleanup_effect_permits WHERE child_grant_id=$1 AND phase=$2`,child.Grant.GrantID,phase).Scan(&requestWire,&requestSHA,&nonce,&permitWire,&permitSHA);err!=nil{return err}
  raw,err:=canonicalSignedBody(ctx,s,stored,permitWire);if err!=nil{return err};var permit model.CapacitySourceRecoveryEffectPermit;var request model.CapacitySourceRecoveryEffectRequest
  if capacity.DecodeGuestLifecycle(raw,&permit)!=nil || capacity.DecodeGuestLifecycle(requestWire,&request)!=nil || capacity.BusinessCreationSHA256(requestWire)!=requestSHA || capacity.BusinessCreationSHA256(permitWire)!=permitSHA || permit.Schema!="original_source_recovery_effect_permit_v1" || permit.Scope!="ONE_ORIGINAL_CHILD_EFFECT_CURRENT_RECOVERY_LEASE_NOT_POSITIVE_QUIESCENCE" || permit.Phase!=phase || request.Phase!=phase || permit.RequestSHA256!=requestSHA || permit.NonceSHA256!=nonce || request.NonceSHA256!=nonce || permit.AuthoritySHA256!=a.SourceAuthoritySHA256 || permit.ChildAuthoritySHA256!=capacity.BusinessCreationSHA256(childWire) || permit.ChildGrantID!=child.Grant.GrantID || permit.ChildAttemptID!=child.AttemptID || permit.NativeIdentitySHA256!=nativeSHA || permit.ProductionQualified || permit.Generation!=b.Recovery.Generation || permit.FencingToken!=b.Recovery.FencingToken || permit.LeaseOwner!=b.Recovery.LeaseOwner || permit.ExecutorID!=b.Recovery.ExecutorID || !permit.CheckedAt.Before(permit.Deadline) || permit.Deadline.After(a.OriginalDeadline) || permit.Deadline.After(b.CleanupDeadline) || permit.Deadline.After(b.OriginalProvisioningDeadline){return ErrCapacityConflict}
  at:=f.OriginalSignalCalledAt;if phase=="unlink"{at=f.OriginalUnlinkCalledAt};if !at.Before(permit.Deadline){return ErrCapacityConflict}
 }
 return nil
}
