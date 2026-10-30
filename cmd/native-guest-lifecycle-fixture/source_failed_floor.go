//go:build linux && nativequalification

package main

import (
 "context"
 "encoding/json"
 "errors"
 "path/filepath"
 "time"
 "github.com/google/uuid"

 "github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
 q "github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacitynativeqemu"
 "github.com/dakasa-yggdrasil/yggdrasil-core/model"
 "github.com/dakasa-yggdrasil/yggdrasil-core/repository"
)

// The initial failed owner must reach its real echo probe. The later repair
// stops after issuing its next grant and must not run that probe.
const failedFloorInitialMode = "burst"
const failedFloorNextMode = "floor_repair"

// Raise only the floor and the unique profile minimum required by the policy
// contract. The baseline policy must remain unchanged for its real owner.
func strongerSourceFloorPolicy(before model.CapacityPolicySpec)(model.CapacityPolicySpec,error){
 if before.Floor!=1 || before.Ceiling!=2 || len(before.Profiles)!=1 || before.Profiles[0].MinUnits!=1 || before.Profiles[0].MaxUnits!=2{return model.CapacityPolicySpec{},q.ErrOriginalUnknown}
 after:=before;after.Profiles=append([]model.CapacityProfile(nil),before.Profiles...);after.Floor=2;after.Profiles[0].MinUnits=2
 if capacity.ValidatePolicy(before)!=nil || capacity.ValidatePolicy(after)!=nil{return model.CapacityPolicySpec{},q.ErrOriginalUnknown}
 return after,nil
}

// The source bridge is an immutable observation of two REAL administrative
// versions. It is not authority supplied by a workflow parameter or a caller.
func(f *fixture) prepareOriginalFloorBridge(ctx context.Context, baselineProbeSHA string)(q.SourceFloorPolicyBridge,error){
 if !q.SourceFailedFloorCase(f.request.NativeCase) || len(f.realm.OwnedSlots())!=1{return q.SourceFloorPolicyBridge{},q.ErrOriginalUnknown}
 old,err:=repository.GetManifestByID(ctx,f.db,f.policy.ID);if err!=nil{return q.SourceFloorPolicyBridge{},err}
 var before model.CapacityPolicySpec
 if json.Unmarshal(old.Spec,&before)!=nil || old.ID!=f.policy.ID || old.Checksum!=f.policy.Checksum || !old.Metadata.Active || old.Metadata.Namespace!=f.namespace || before.Floor!=1 || before.Ceiling!=2 || before.GuestRetirementBinding==nil || capacity.GuestRetirementSHA(*before.GuestRetirementBinding)!=capacity.GuestRetirementSHA(f.binding){return q.SourceFloorPolicyBridge{},q.ErrOriginalUnknown}
 originalBinding,bindingErr:=capacity.VMObservationBinding(before,before.GuestRetirementBinding.MutationBindingName)
 if bindingErr!=nil || !originalBinding.CompensationEnabled{return q.SourceFloorPolicyBridge{},q.ErrOriginalUnknown}
 // ValidatePolicy forbids profile.MinUnits below the raised policy floor.
 after,err:=strongerSourceFloorPolicy(before);if err!=nil{return q.SourceFloorPolicyBridge{},err}
 current,err:=f.createManifest(ctx,"capacity_policy",old.Metadata.Name,after);if err!=nil{return q.SourceFloorPolicyBridge{},err}
 oldRead,err:=repository.GetManifestByID(ctx,f.db,old.ID);if err!=nil{return q.SourceFloorPolicyBridge{},err}
 newRead,err:=repository.GetManifestByID(ctx,f.db,current.ID);if err!=nil{return q.SourceFloorPolicyBridge{},err}
 var actual model.CapacityPolicySpec
 if oldRead.Metadata.Active || !newRead.Metadata.Active || newRead.ID==oldRead.ID || newRead.Kind!=oldRead.Kind || newRead.Metadata.Namespace!=oldRead.Metadata.Namespace || newRead.Metadata.Name!=oldRead.Metadata.Name || newRead.Version!=oldRead.Version+1 || oldRead.Checksum!=old.Checksum || string(oldRead.Spec)!=string(old.Spec) || json.Unmarshal(newRead.Spec,&actual)!=nil || actual.Floor!=2 || len(actual.Profiles)!=1 || actual.Profiles[0].MinUnits!=2{return q.SourceFloorPolicyBridge{},q.ErrOriginalUnknown}
 actual.Floor=1;actual.Profiles[0].MinUnits=1
 if capacity.GuestRetirementSHA(actual)!=capacity.GuestRetirementSHA(before){return q.SourceFloorPolicyBridge{},q.ErrOriginalUnknown}
 bridge:=q.SourceFloorPolicyBridge{Schema:"core_original_floor_policy_bridge_v1",Scope:"SOURCE_ONLY_EXACT_FLOOR_1_TO_2",CoreSource:capacity.CurrentGuestCoreSource(),GuestSource:f.request.SourceCommit,Namespace:f.namespace,PolicyName:old.Metadata.Name,OriginalPolicyID:old.ID.String(),OriginalPolicyChecksum:old.Checksum,CurrentPolicyID:current.ID.String(),CurrentPolicyChecksum:current.Checksum,OriginalVersion:old.Version,CurrentVersion:current.Version,WorkflowID:f.workflow.ID.String(),BindingSHA256:capacity.GuestRetirementSHA(f.binding),OriginalFloor:1,CurrentFloor:2,BaselineUnits:1,OriginalBaselineProbeSHA256:baselineProbeSHA,CreatedAt:time.Now().UTC(),NativeQualified:false}
 wire,err:=json.Marshal(bridge);if err!=nil{return q.SourceFloorPolicyBridge{},err}
 if _,err=f.db.ExecContext(ctx,`CREATE TABLE public.capacity_guest_floor_source_bridges(
 current_policy_id uuid PRIMARY KEY REFERENCES public.manifests(id), original_policy_id uuid UNIQUE NOT NULL REFERENCES public.manifests(id),
 original_checksum text NOT NULL,current_checksum text NOT NULL,namespace text NOT NULL,policy_name text NOT NULL,core_source text NOT NULL,guest_source text NOT NULL,
 bridge_wire bytea NOT NULL,bridge_sha256 text NOT NULL UNIQUE CHECK(bridge_sha256 ~ '^[0-9a-f]{64}$'))`);err!=nil{return q.SourceFloorPolicyBridge{},err}
 if _,err=f.db.ExecContext(ctx,`CREATE TRIGGER capacity_floor_source_bridge_immutable BEFORE UPDATE OR DELETE ON public.capacity_guest_floor_source_bridges FOR EACH ROW EXECUTE FUNCTION public.capacity_vm_original_retirement_immutable()`);err!=nil{return q.SourceFloorPolicyBridge{},err}
 if _,err=f.db.ExecContext(ctx,`INSERT INTO public.capacity_guest_floor_source_bridges(current_policy_id,original_policy_id,original_checksum,current_checksum,namespace,policy_name,core_source,guest_source,bridge_wire,bridge_sha256) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,current.ID,old.ID,old.Checksum,current.Checksum,f.namespace,old.Metadata.Name,bridge.CoreSource,bridge.GuestSource,wire,capacity.BusinessCreationSHA256(wire));err!=nil{return q.SourceFloorPolicyBridge{},err}
 if _,err=q.PublishBytes(ctx,filepath.Join(f.private,"source-floor-policy-bridge.json"),wire);err!=nil{return q.SourceFloorPolicyBridge{},err}
 for _,statement:=range []string{
 `CREATE TABLE public.capacity_guest_qualification_floor_source_challenges(challenge_id uuid PRIMARY KEY,preregistration_id uuid NOT NULL REFERENCES public.capacity_vm_provisioning_preregistrations(id),challenge_sha256 text NOT NULL UNIQUE CHECK(challenge_sha256 ~ '^[0-9a-f]{64}$'),original_wire bytea NOT NULL CHECK(octet_length(original_wire) BETWEEN 1 AND 16384),original_record jsonb NOT NULL CHECK(jsonb_typeof(original_record)='object'),original_deadline timestamptz NOT NULL,recorded_at timestamptz NOT NULL,usage_class text NOT NULL CHECK(usage_class='capacity_floor_source'))`,
 `CREATE TABLE public.capacity_guest_qualification_floor_source_returns(id uuid PRIMARY KEY,preregistration_id uuid NOT NULL REFERENCES public.capacity_vm_provisioning_preregistrations(id),native_stage text NOT NULL CHECK(native_stage='floor_serving_probe'),return_sha256 text NOT NULL CHECK(return_sha256 ~ '^[0-9a-f]{64}$'),original_wire bytea NOT NULL CHECK(octet_length(original_wire) BETWEEN 1 AND 1048576),original_record jsonb NOT NULL CHECK(jsonb_typeof(original_record)='object'),recorded_at timestamptz NOT NULL,UNIQUE(preregistration_id,native_stage,return_sha256))`,
 `CREATE TRIGGER capacity_floor_source_challenges_immutable BEFORE UPDATE OR DELETE ON public.capacity_guest_qualification_floor_source_challenges FOR EACH ROW EXECUTE FUNCTION public.capacity_vm_original_retirement_immutable()`,
 `CREATE TRIGGER capacity_floor_source_returns_immutable BEFORE UPDATE OR DELETE ON public.capacity_guest_qualification_floor_source_returns FOR EACH ROW EXECUTE FUNCTION public.capacity_vm_original_retirement_immutable()`}{if _,err=f.db.ExecContext(ctx,statement);err!=nil{return q.SourceFloorPolicyBridge{},err}}
 f.policy=current
 return bridge,nil
}

// Concrete called prefix: baseline1 -> stronger persisted Floor2 -> actual
// failed Create2 -> independently signed physical cleanup. A settled original
// cannot become terminal just because the physical child was cleaned up.
func(f *fixture) runOriginalFailedFloorCaller(ctx context.Context)(runErr error){
 // Same failure-only retention as the public caller: an early refusal keeps
 // its actual public workflow returns observable. Still a failure.
 defer func(){
  if runErr!=nil{
   diagnostic,cancel:=context.WithTimeout(context.WithoutCancel(ctx),5*time.Second);defer cancel()
   _,writeErr:=q.Publish(diagnostic,filepath.Join(f.private,"core-original-public-caller-failure-returns.json"),f.publicReturns)
   runErr=errors.Join(runErr,writeErr)
  }
 }()
 if !q.SourceFailedFloorCase(f.request.NativeCase) || len(f.realm.OwnedSlots())!=0{return q.ErrOriginalUnknown}
 var p model.CapacityPolicySpec
 if json.Unmarshal(f.policy.Spec,&p)!=nil || p.Floor!=1 || p.Ceiling!=2{return q.ErrOriginalUnknown}
 baseline,returns,err:=f.originalWorkflow(ctx,"baseline",1,q.QualificationAssessment(p,0,0.9,time.Now().UTC()),"")
 if err!=nil || baseline.Status!="succeeded"{return q.ErrOriginalUnknown}
 client,err:=f.sourceClient(1);if err!=nil{return err};defer client.Close()
 store:=repository.CapacityStore{DB:f.db,WorkflowID:f.workflow.ID}
 probe,err:=f.realm.DiagnosticProbe(ctx,store,1,f.corePrivate,client);if err!=nil{return err}
 bridge,err:=f.prepareOriginalFloorBridge(ctx,capacity.GuestRetirementSHA(probe));if err!=nil{return err}
 if json.Unmarshal(f.policy.Spec,&p)!=nil || p.Floor!=2 || p.Ceiling!=2{return q.ErrOriginalUnknown}
 at,err:=f.actualLastUsefulProbeTime(ctx,1);if err!=nil{return err}
 burst,burstReturns,err:=f.originalWorkflow(ctx,failedFloorInitialMode,2,q.QualificationAssessment(p,1,0.9,at),"")
 returns=append(returns,burstReturns...)
 if err!=nil || burst.Status!="failed"{return q.ErrOriginalUnknown}
 if q.CanonicalSourceCompensationCase(f.request.NativeCase){
  if err=f.finishOriginalCanonicalSourceCompensation(ctx,p,baseline,burst,[]string{baseline.ID.String(),burst.ID.String()},returns);err!=nil{return err}
  pre,err:=f.realm.OriginalPreregistration(2);if err!=nil{return err}
  return f.finishOriginalCanonicalFloorRecovery(ctx,p,store,bridge,pre)
 }
 if err=f.finishOriginalSourceCompensation(ctx,p,baseline,burst,[]string{baseline.ID.String(),burst.ID.String()},returns);err!=nil{return err}
 // The compensation dependency may publish Source cleanup completion, but
 // this case must never publish its ordinary/native completion as floor PASS.
 f.completed=q.SourceCaseStage{}
 pre,err:=f.realm.OriginalPreregistration(2);if err!=nil{return err}
 // Source-only counterpart validates the signed physical terminal inside
 // the SAME advisory/intent transaction; ordinary parent stays SETTLED.
 return f.finishOriginalSourceFloorRecovery(ctx,p,store,bridge,pre)
}

func(f *fixture) finishOriginalSourceFloorRecovery(ctx context.Context,p model.CapacityPolicySpec,store repository.CapacityStore,bridge q.SourceFloorPolicyBridge,pre model.CapacityGuestOriginalProvisioningPreregistration)error{
 limit:=f.request.OriginalStepStartedAt.Add(420*time.Second)
 if pre.OriginalDeadline.Before(limit){limit=pre.OriginalDeadline}
 original,cancel:=context.WithDeadline(ctx,limit);defer cancel();ctx=original
 var raw []byte;var before model.CapacityIntent
 if err:=f.db.QueryRowContext(ctx,`SELECT intent FROM public.capacity_intents WHERE namespace=$1 AND environment=$2 AND domain=$3 AND dimension=$4`,f.namespace,p.Environment,p.Domain,p.Dimension).Scan(&raw);err!=nil{return err}
 if json.Unmarshal(raw,&before)!=nil || before.PolicyID!=f.policy.ID || before.PolicyChecksum!=f.policy.Checksum || before.RecoveryOnly || before.Decision.Reason!="protected_floor_recovery" || before.BaselineSnapshot.Units!=1 || before.Decision.Units!=2 || before.LeaseExpiresAt==nil || !before.LeaseExpiresAt.Before(limit){return q.ErrOriginalUnknown}
 for {
  var now time.Time;if err:=f.db.QueryRowContext(ctx,`SELECT clock_timestamp()`).Scan(&now);err!=nil{return err}
  if !now.Before(*before.LeaseExpiresAt){break}
  timer:=time.NewTimer(20*time.Millisecond);select{case<-ctx.Done():timer.Stop();return ctx.Err();case<-timer.C:}
 }
 client,err:=f.sourceClient(1);if err!=nil{return err};defer client.Close()
 observed,err:=f.realm.DiagnosticProbe(ctx,store,1,f.corePrivate,client);if err!=nil{return err}
 recoveredStore:=store;recoveredStore.ExecutorID=uuid.NewString()
 recovered,err:=recoveredStore.Recover(ctx,f.policy,before.Generation,q.QualificationAssessment(p,1,0.9,observed.OriginalNativeAfterReturnedAt))
 if err!=nil || !recovered.RecoveryOnly || recovered.FencingToken!=before.FencingToken+1 || recovered.LeaseOwner==before.LeaseOwner || recovered.LeaseExecutorID!=recoveredStore.ExecutorID || recovered.LeaseExpiresAt==nil{return q.ErrOriginalUnknown}
 probe,err:=f.realm.FloorSourceProbe(ctx,recoveredStore,f.policy,recovered.Generation,recovered.FencingToken,recovered.LeaseOwner,1,f.corePrivate,client,*recovered.LeaseExpiresAt);if err!=nil{return err}
 binding,err:=capacity.VMObservationBinding(p,f.binding.MutationBindingName);if err!=nil{return err}
 physical,err:=f.realm.FreshNativeMember(ctx,1,binding);if err!=nil{return err}
 var desired []byte;for _,slot:=range binding.Slots{if slot.Slot==1{desired,err=json.Marshal(slot.DesiredSpec)}}
 if err!=nil || len(desired)==0{return q.ErrOriginalUnknown}
 if err=recoveredStore.RecordMutationSlot(ctx,f.policy,recovered.Generation,recovered.FencingToken,recovered.LeaseOwner,model.CapacityMutationIssue{BindingName:binding.Name,DesiredSpec:desired},physical);err!=nil{return err}
 if err=recoveredStore.CheckNativeMembershipCoverage(ctx,f.policy,binding,[]model.CapacityMutationProof{physical});err!=nil{return err}
 var live,foreign int
 if err=f.db.QueryRowContext(ctx,`SELECT count(*),count(*) FILTER(WHERE slot<>1 OR resource_id<>$2) FROM public.capacity_resource_slots WHERE namespace=$1 AND resource_id<>''`,f.namespace,physical.ResourceID).Scan(&live,&foreign);err!=nil || live!=1 || foreign!=0{return q.ErrOriginalUnknown}
 if _,err=q.Publish(ctx,filepath.Join(f.private,"source-floor-baseline-probe.json"),probe);err!=nil{return err}
 if _,err=q.Publish(ctx,filepath.Join(f.private,"source-floor-baseline-physical.json"),physical);err!=nil{return err}
 zero:=0
 // This health statement is exclusively the real signed SAME echo writer
 // plus fresh physical baseline1 above, never a production readiness metric.
 proof:=model.CapacityTransitionProof{Assessment:q.QualificationAssessment(p,1,0.1,probe.OriginalNativeAfterReturnedAt),ObservedAt:probe.OriginalNativeAfterReturnedAt,ReceiptRef:"source-failed-floor-signed-baseline:"+capacity.GuestRetirementSHA(probe),Healthy:true,Inflight:&zero,MutationInflight:&zero,MutationAuthorityKind:"core_mutation_grants",MembershipComplete:true}
 refused:=[]string{}
 unchanged:=func()error{var current []byte;if err:=f.db.QueryRowContext(ctx,`SELECT intent FROM public.capacity_intents WHERE namespace=$1 AND environment=$2 AND domain=$3 AND dimension=$4`,f.namespace,p.Environment,p.Domain,p.Dimension).Scan(&current);err!=nil{return err};var actual model.CapacityIntent;if json.Unmarshal(current,&actual)!=nil || capacity.GuestRetirementSHA(actual)!=capacity.GuestRetirementSHA(recovered){return q.ErrOriginalUnknown};return nil}
 for _,variant:=range []string{"baseline_lost","membership_incomplete","wrong_profile","no_mutation"}{
  bad:=proof
  switch variant{case "baseline_lost":bad.Assessment.Snapshot.Units=0;case "membership_incomplete":bad.MembershipComplete=false;case "wrong_profile":bad.Assessment.Snapshot.Profile="foreign-profile";case "no_mutation":bad.NoMutationVerified=true}
  if _,_,err=recoveredStore.ReconcileSourceFailedFloorRecovery(ctx,f.policy,recovered.Generation,recovered.FencingToken,recovered.LeaseOwner,pre.OriginalCreateGrantID,bad);err==nil{return q.ErrOriginalUnknown}
  if err=unchanged();err!=nil{return err};refused=append(refused,variant)
 }
 // Ordinary reconciliation must still reject the unresolved SETTLED parent.
 if _,err=recoveredStore.Reconcile(ctx,f.policy,recovered.Generation,recovered.FencingToken,recovered.LeaseOwner,"reconciled_failed_floor",proof);err==nil{return q.ErrOriginalUnknown}
 if err=unchanged();err!=nil{return err};refused=append(refused,"ordinary_settled_parent")
 terminal,cleanupRead,err:=recoveredStore.ReconcileSourceFailedFloorRecovery(ctx,f.policy,recovered.Generation,recovered.FencingToken,recovered.LeaseOwner,pre.OriginalCreateGrantID,proof)
 if err!=nil || terminal.Phase!="reconciled_failed_floor" || !terminal.FloorDegraded || terminal.Decision.ExecutionPermitted || terminal.LeaseOwner!="" || terminal.LeaseExecutorID!="" || terminal.LeaseExpiresAt!=nil || terminal.Assessment.Snapshot.Units!=1{return q.ErrOriginalUnknown}
 if len(cleanupRead.FreshReadWire)==0 || cleanupRead.FreshReadSHA256!=capacity.BusinessCreationSHA256(cleanupRead.FreshReadWire){return q.ErrOriginalUnknown}
 if _,err=q.PublishBytes(ctx,filepath.Join(f.private,"source-floor-failed-slot-current-read.json"),cleanupRead.FreshReadWire);err!=nil{return err}
 if _,err=q.Publish(ctx,filepath.Join(f.private,"source-floor-accounting-intent.json"),terminal);err!=nil{return err}
 // Assess/Claim do not bypass an outstanding mutation guard: their
 // original code has no terminal mutation transition. Exercise those real
 // APIs unchanged with a fresh original snapshot, and do NOT Issue/Create.
 fresh,err:=f.realm.DiagnosticProbe(ctx,recoveredStore,1,f.corePrivate,client);if err!=nil{return err}
 assessment:=q.QualificationAssessment(p,1,0.9,fresh.OriginalNativeAfterReturnedAt)
 nextStore:=recoveredStore;nextStore.ExecutionEnabled=true;nextStore.ExecutorID=uuid.NewString()
 proposed,err:=nextStore.Assess(ctx,f.policy,assessment)
 if err!=nil || proposed.Generation!=terminal.Generation+1 || proposed.Phase!="proposed" || proposed.Decision.Reason!="protected_floor_recovery" || proposed.Decision.Units!=2{return q.ErrOriginalUnknown}
 next,err:=nextStore.Claim(ctx,f.policy,proposed.Generation,assessment)
 if err!=nil || next.Generation!=proposed.Generation || next.RecoveryOnly || next.Phase!="preparing" || next.BaselineSnapshot.Units!=1 || next.LeaseExecutorID!=nextStore.ExecutorID || next.LeaseOwner=="" || next.LeaseExpiresAt==nil{return q.ErrOriginalUnknown}
 var nextRaw []byte;var nextRead model.CapacityIntent
 if err=f.db.QueryRowContext(ctx,`SELECT intent FROM public.capacity_intents WHERE namespace=$1 AND environment=$2 AND domain=$3 AND dimension=$4`,f.namespace,p.Environment,p.Domain,p.Dimension).Scan(&nextRaw);err!=nil || json.Unmarshal(nextRaw,&nextRead)!=nil || capacity.GuestRetirementSHA(nextRead)!=capacity.GuestRetirementSHA(next){return q.ErrOriginalUnknown}
 if _,err=q.Publish(ctx,filepath.Join(f.private,"source-floor-next-intent.json"),next);err!=nil{return err}
 // No next mutation grant/third native creation is claimed. The ordinary
 // settled parent and original provisioning deadline remain unchanged.
 var parentState string
 if err=f.db.QueryRowContext(ctx,`SELECT state FROM public.capacity_mutation_grants WHERE id=$1 AND namespace=$2`,pre.OriginalCreateGrantID,f.namespace).Scan(&parentState);err!=nil || parentState!="settled"{return q.ErrOriginalUnknown}
 var cleanup map[string]json.RawMessage
 cleanupWire,err:=q.ReadPrivate(ctx,filepath.Join(f.private,"source-original-compensation-result.json"),&cleanup);if err!=nil{return err}
 var signedTerminal map[string]json.RawMessage
 signedTerminalWire,err:=q.ReadPrivate(ctx,filepath.Join(f.private,"source-failure-cleanup-terminal.json"),&signedTerminal);if err!=nil{return err}
 bridgeWire,err:=json.Marshal(bridge);if err!=nil{return err}
 result:=q.SourceFailedFloorContract{Schema:"core_original_source_failed_floor_v1",Scope:"SOURCE_ONLY_FAILED_FLOOR_SIGNED_PHYSICAL_ACCOUNTING_NOT_CANONICAL_COMPENSATION",Case:f.request.NativeCase,CoreSource:capacity.CurrentGuestCoreSource(),GuestSource:f.request.SourceCommit,OriginalPolicyID:bridge.OriginalPolicyID,CurrentPolicyID:f.policy.ID.String(),PolicyBridgeSHA256:capacity.BusinessCreationSHA256(bridgeWire),CompensationResultSHA256:capacity.BusinessCreationSHA256(cleanupWire),ParentGrantID:pre.OriginalCreateGrantID,ParentState:parentState,FailedFloorPhase:terminal.Phase,BaselineUnits:1,FloorUnits:2,NativeProbeSHA256:capacity.GuestRetirementSHA(probe),PhysicalSHA256:capacity.GuestRetirementSHA(physical),FailedSlotCurrentReadSHA256:cleanupRead.FreshReadSHA256,TerminalSHA256:capacity.BusinessCreationSHA256(signedTerminalWire),SourceIntentTerminalSHA256:capacity.GuestRetirementSHA(terminal),NextIntentSHA256:capacity.GuestRetirementSHA(next),NextGeneration:next.Generation,Refused:refused,Generation:terminal.Generation,CheckedAt:time.Now().UTC(),OriginalDeadline:limit,NativeQualified:false}
 wire,err:=q.Publish(ctx,filepath.Join(f.private,"source-failed-floor-contract.json"),result);if err!=nil{return err}
 f.completedSourceFloor=map[string]any{"schema":q.FixtureSchema,"stage":"original-failed-floor-completed.json","case":f.request.NativeCase,"scope":result.Scope,"contract_sha256":capacity.BusinessCreationSHA256(wire),"core_source":result.CoreSource,"guest_source":result.GuestSource,"native_qualified":false}
 return nil
}
