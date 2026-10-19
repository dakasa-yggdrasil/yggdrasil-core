//go:build linux && nativequalification

package message

import (
 "bytes"
 "context"
 "crypto/ed25519"
 "encoding/json"
 "errors"
 "path/filepath"
 "time"
 "github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
 q "github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacitynativeqemu"
 "github.com/dakasa-yggdrasil/yggdrasil-core/model"
 "github.com/dakasa-yggdrasil/yggdrasil-core/repository"
 "github.com/google/uuid"
)

// The source slot2 gate runs after actual Issue/pre lookup and before Create.
// Slot1 is always the unchanged original native baseline. It does not receive
// a caller context/proof, lease override or a provider absence assertion.
func guestOriginalSourceTerminal(ctx context.Context,store repository.CapacityStore,policy model.Manifest,p model.CapacityPolicySpec,binding model.CapacityMutationBinding,input guestOriginalStepInput,grant model.CapacityMutationGrant,pre model.CapacityGuestOriginalProvisioningPreregistration,key ed25519.PrivateKey)(any,bool,error){
 if originalGuestNativeRealm==nil || !q.SourceTerminalCase(originalGuestNativeRealm.Request.NativeCase) || input.Slot==1{return nil,false,nil}
 if input.Slot!=2 || grant.Slot!=2 || pre.OriginalCreateGrantID!=grant.GrantID || pre.Generation!=input.Generation || pre.Fence!=input.FencingToken || pre.ExecutorID!=store.ExecutorID || pre.LeaseOwner!=input.LeaseOwner || len(originalGuestNativeRealm.OwnedSlots())!=1 || originalGuestNativeRealm.OwnedSlots()[0]!=1{return nil,true,errOriginalGuestStep}
 limit:=originalGuestNativeRealm.Request.OriginalStepStartedAt.Add(420*time.Second);if pre.OriginalDeadline.Before(limit){limit=pre.OriginalDeadline}
 original,cancel:=context.WithDeadline(ctx,limit);defer cancel();ctx=original
 var raw []byte;var before model.CapacityIntent
 if err:=store.DB.QueryRowContext(ctx,`SELECT intent FROM public.capacity_intents WHERE namespace=$1 AND environment=$2 AND domain=$3 AND dimension=$4`,policy.Metadata.Namespace,p.Environment,p.Domain,p.Dimension).Scan(&raw);err!=nil{return nil,true,err}
 if json.Unmarshal(raw,&before)!=nil || before.PolicyID!=policy.ID || before.PolicyChecksum!=policy.Checksum || before.Generation!=input.Generation || before.FencingToken!=input.FencingToken || before.LeaseOwner!=input.LeaseOwner || before.LeaseExecutorID!=store.ExecutorID || before.RecoveryOnly || before.LeaseExpiresAt==nil || !before.LeaseExpiresAt.Before(limit) || before.BaselineSnapshot.Units!=1 || before.Decision.Units!=2{return nil,true,errOriginalGuestStep}
 readGrant:=func()([]byte,error){var wire []byte;err:=store.DB.QueryRowContext(ctx,`SELECT grant_record FROM public.capacity_mutation_grants WHERE id=$1 AND namespace=$2 AND generation=$3`,grant.GrantID,policy.Metadata.Namespace,input.Generation).Scan(&wire);return wire,err}
 wire,err:=readGrant();if err!=nil{return nil,true,err}
 var record struct{Grant model.CapacityMutationGrant `json:"grant"`;AttemptID string `json:"attempt_id"`;Settlement *model.CapacityMutationSettleRequest `json:"settlement"`}
 if json.Unmarshal(wire,&record)!=nil || record.Grant.GrantID!=grant.GrantID || record.Grant.State!="issued" || record.AttemptID!="" || record.Settlement!=nil{return nil,true,errOriginalGuestStep}
 unresolved:=originalGuestNativeRealm.Request.NativeCase=="source_live_unresolved_terminal"
 nonce,err:=sourceGuestNonce();if err!=nil{return nil,true,err}
 request:=model.CapacityMutationRedeemRequest{GrantID:grant.GrantID,AttemptID:uuid.NewString(),SettlementTokenSHA256:capacity.BusinessCreationSHA256([]byte(nonce)),Capability:grant.Capability,IntegrationInstanceID:grant.IntegrationInstanceID,ScopeChecksum:grant.ScopeChecksum,ProfileName:grant.ProfileName,Slot:2,RequestSHA256:grant.RequestSHA256}
 var replaySHA,firstSHA,refusalSHA string
 if unresolved{
  first,err:=originalGuestNativeRealm.TerminalRedeem(ctx,request);if err!=nil || first.Mode!="write_once"{return nil,true,errOriginalGuestStep}
  firstWire,publishErr:=q.Publish(ctx,filepath.Join(originalGuestNativeRealm.PrivateDirectory,"source-terminal-first-typed-return.json"),first);if publishErr!=nil{return nil,true,publishErr};firstSHA=capacity.BusinessCreationSHA256(firstWire)
  // Existing same-source Issue must retain the SAME unresolved grant, not
  // allocate another permission or preregistration before expiry.
  var desired *model.CapacityMutationSpecV1;for _,s:=range binding.Slots{if s.Slot==2{desired=s.DesiredSpec}}
  if desired==nil{return nil,true,errOriginalGuestStep};body,err:=json.Marshal(desired);if err!=nil{return nil,true,err}
  same,err:=store.IssueMutation(ctx,policy,input.Generation,input.FencingToken,input.LeaseOwner,model.CapacityMutationIssue{BindingName:binding.Name,DesiredSpec:body})
  if err!=nil || same.GrantID!=grant.GrantID{return nil,true,errOriginalGuestStep}
 }else{
  prior,err:=repository.GetManifestByID(ctx,store.DB,policy.ID);if err!=nil || !prior.Metadata.Active || prior.Checksum!=policy.Checksum || prior.Metadata.Namespace!=policy.Metadata.Namespace{return nil,true,errOriginalGuestStep}
  rows,err:=repository.MarkManifestInactiveByID(ctx,store.DB,policy.ID);if err!=nil || rows!=1{return nil,true,errOriginalGuestStep}
  paused,err:=repository.GetManifestByID(ctx,store.DB,policy.ID);if err!=nil || paused.Metadata.Active || paused.Checksum!=prior.Checksum{return nil,true,errOriginalGuestStep}
 }
 var expiry time.Time
 for{if err=store.DB.QueryRowContext(ctx,`SELECT clock_timestamp()`).Scan(&expiry);err!=nil{return nil,true,err};if !expiry.Before(*before.LeaseExpiresAt){break};timer:=time.NewTimer(20*time.Millisecond);select{case <-ctx.Done():timer.Stop();return nil,true,ctx.Err();case <-timer.C:}}
 if expiry.Before(grant.ExpiresAt){return nil,true,errOriginalGuestStep}
 recovery:=store;recovery.ExecutionEnabled=false;recovery.ExecutorID=uuid.NewString()
 var member model.CapacityGuestRetirementMemberBinding;for _,m:=range p.GuestRetirementBinding.Members{if m.Slot==1{member=m}}
 client,err:=sourceGuestClient(ctx,store.DB,member);if err!=nil{return nil,true,err}
 diagnostic,err:=originalGuestNativeRealm.DiagnosticProbe(ctx,store,1,key,client);client.Close()
 if err!=nil{return nil,true,err}
 lease,err:=recovery.Recover(ctx,policy,input.Generation,q.QualificationAssessment(p,1,0.9,diagnostic.OriginalNativeAfterReturnedAt))
 if err!=nil || !lease.RecoveryOnly || lease.FencingToken!=before.FencingToken+1 || lease.LeaseExecutorID!=recovery.ExecutorID || lease.LeaseOwner==before.LeaseOwner || lease.Decision.ExecutionPermitted{return nil,true,errOriginalGuestStep}
 current:=input;current.FencingToken,current.LeaseOwner=lease.FencingToken,lease.LeaseOwner
 probe,err:=sourceNativeBaseline(ctx,recovery,policy,p,current,key);if err!=nil{return nil,true,err}
 physical,err:=originalGuestNativeRealm.FreshNativeMember(ctx,1,binding);if err!=nil{return nil,true,err}
 if err=recovery.CheckNativeMembershipCoverage(ctx,policy,binding,[]model.CapacityMutationProof{physical});err!=nil{return nil,true,err}
 var count,grants2 int
 if err=store.DB.QueryRowContext(ctx,`SELECT count(*) FROM public.capacity_resource_slots WHERE namespace=$1 AND resource_id<>''`,policy.Metadata.Namespace).Scan(&count);err!=nil || count!=1{return nil,true,errOriginalGuestStep}
 if err=store.DB.QueryRowContext(ctx,`SELECT count(*) FROM public.capacity_mutation_grants WHERE namespace=$1 AND slot=2`,policy.Metadata.Namespace).Scan(&grants2);err!=nil || grants2!=1{return nil,true,errOriginalGuestStep}
 zero:=0
 proof:=model.CapacityTransitionProof{Assessment:q.QualificationAssessment(p,1,0.1,probe.OriginalNativeAfterReturnedAt),ObservedAt:probe.OriginalNativeAfterReturnedAt,ReceiptRef:"original-source-terminal:"+capacity.GuestRetirementSHA(probe),Healthy:true,Inflight:&zero,MutationInflight:&zero,MutationAuthorityKind:"core_mutation_grants",MembershipComplete:true,NoMutationVerified:!unresolved}
 outcome:="aborted";if unresolved{outcome="reconciled_partial"}
 beforeGrant,err:=readGrant();if err!=nil{return nil,true,err}
 if json.Unmarshal(beforeGrant,&record)!=nil || record.Settlement!=nil || (unresolved && (record.Grant.State!="redeemed" || record.AttemptID!=request.AttemptID)) || (!unresolved && (record.Grant.State!="issued" || record.AttemptID!="")){return nil,true,errOriginalGuestStep}
 var intentBefore []byte;if err=store.DB.QueryRowContext(ctx,`SELECT intent FROM public.capacity_intents WHERE namespace=$1 AND environment=$2 AND domain=$3 AND dimension=$4`,policy.Metadata.Namespace,p.Environment,p.Domain,p.Dimension).Scan(&intentBefore);err!=nil{return nil,true,err}
 terminal,terminalErr:=recovery.Reconcile(ctx,policy,input.Generation,lease.FencingToken,lease.LeaseOwner,outcome,proof)
 if unresolved{
  expectedRefusal:=repository.ErrCapacityConflict.Error()+": unresolved provider mutation authority"
  if !errors.Is(terminalErr,repository.ErrCapacityConflict) || terminalErr.Error()!=expectedRefusal{return nil,true,errOriginalGuestStep}
  refusal:=q.SourceTerminalRefusal{Schema:"core_original_terminal_refusal_return_v1",Representation:"ACTUAL_ERROR_CLASS_COUNT_HASH_NO_RAW_MESSAGE",ErrorClass:"repository.ErrCapacityConflict",Predicate:"unresolved_provider_mutation_authority",ReturnCount:1,ErrorBytes:len(terminalErr.Error()),ErrorSHA256:capacity.BusinessCreationSHA256([]byte(terminalErr.Error()))}
  refusalWire,publishErr:=q.Publish(ctx,filepath.Join(originalGuestNativeRealm.PrivateDirectory,"source-terminal-refusal-return.json"),refusal);if publishErr!=nil{return nil,true,publishErr};refusalSHA=capacity.BusinessCreationSHA256(refusalWire)
  again,err:=originalGuestNativeRealm.TerminalRedeem(ctx,request);if err!=nil || again.Mode!="read_only"{return nil,true,errOriginalGuestStep}
  replayWire,publishErr:=q.Publish(ctx,filepath.Join(originalGuestNativeRealm.PrivateDirectory,"source-terminal-replay-typed-return.json"),again);if publishErr!=nil{return nil,true,publishErr};replaySHA=capacity.BusinessCreationSHA256(replayWire)
  after,err:=readGrant();if err!=nil || !bytes.Equal(beforeGrant,after){return nil,true,errOriginalGuestStep}
  var intentAfter []byte;if err=store.DB.QueryRowContext(ctx,`SELECT intent FROM public.capacity_intents WHERE namespace=$1 AND environment=$2 AND domain=$3 AND dimension=$4`,policy.Metadata.Namespace,p.Environment,p.Domain,p.Dimension).Scan(&intentAfter);err!=nil || !bytes.Equal(intentBefore,intentAfter){return nil,true,errOriginalGuestStep}
  if json.Unmarshal(after,&record)!=nil || record.Grant.State!="redeemed" || record.Settlement!=nil{return nil,true,errOriginalGuestStep}
 }else{
  if terminalErr!=nil || terminal.Phase!="aborted"{return nil,true,errOriginalGuestStep}
  after,err:=readGrant();if err!=nil || json.Unmarshal(after,&record)!=nil || record.Grant.State!="expired" || record.AttemptID!="" || record.Settlement!=nil{return nil,true,errOriginalGuestStep}
 }
 // Retain actual typed proof bodies in the existing private namespace. These
 // are Source-controlled qualified echo facts, not public/native permission.
 if _,err=q.Publish(ctx,filepath.Join(originalGuestNativeRealm.PrivateDirectory,"source-terminal-transition-proof.json"),proof);err!=nil{return nil,true,err}
 if _,err=q.Publish(ctx,filepath.Join(originalGuestNativeRealm.PrivateDirectory,"source-terminal-physical-proof.json"),physical);err!=nil{return nil,true,err}
 var canonicalEvents int
 if err=store.DB.QueryRowContext(ctx,`SELECT count(*) FROM public.event_log WHERE idempotency_key=$1 AND metadata->>'namespace'=$2`,"capacity-mutation/"+grant.GrantID,policy.Metadata.Namespace).Scan(&canonicalEvents);err!=nil || canonicalEvents!=0{return nil,true,errOriginalGuestStep}
 result:=q.SourceTerminalContract{Schema:"core_original_source_terminal_contract_v1",Case:originalGuestNativeRealm.Request.NativeCase,Scope:"SOURCE_TERMINAL_CONTRACT_ONLY_NO_NATIVE_CREDIT",CoreSource:capacity.CurrentGuestCoreSource(),GuestSource:originalGuestNativeRealm.Request.SourceCommit,PolicyID:policy.ID.String(),GrantID:grant.GrantID,Generation:input.Generation,RecoveryFence:lease.FencingToken,GrantState:record.Grant.State,Terminal:outcome,TerminalRefused:unresolved,ProbeSHA256:capacity.GuestRetirementSHA(probe),PhysicalSHA256:capacity.GuestRetirementSHA(physical),ProofSHA256:capacity.GuestRetirementSHA(proof),ReplaySHA256:replaySHA,FirstSHA256:firstSHA,RefusalSHA256:refusalSHA,CallbackRepresentation:"TYPED_RESERIALIZATION_NOT_RAW_HTTP",CallbackAttemptID:"",CallbackRequestSHA256:"",LeaseExpiredObservedAt:expiry,CheckedAt:time.Now().UTC(),OriginalDeadline:limit}
 if unresolved{result.CallbackAttemptID=request.AttemptID;result.CallbackRequestSHA256=request.RequestSHA256}
 if _,err=q.Publish(ctx,filepath.Join(originalGuestNativeRealm.PrivateDirectory,"source-terminal-contract.json"),result);err!=nil{return nil,true,err}
 if ctx.Err()!=nil || !time.Now().UTC().Before(limit){return nil,true,errOriginalGuestStep}
 return result,true,nil
}
