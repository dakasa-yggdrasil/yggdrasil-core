//go:build linux && nativequalification
package main
import("context";"crypto/sha256";"encoding/json";"errors";"fmt";"sync";"github.com/google/uuid";"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity";q "github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacitynativeqemu";"github.com/dakasa-yggdrasil/yggdrasil-core/model";"github.com/dakasa-yggdrasil/yggdrasil-core/repository")
func(f *fixture) prepareCanonicalSourceChild(ctx context.Context,p model.CapacityPolicySpec,pre model.CapacityGuestOriginalProvisioningPreregistration)(repository.CapacityStore,model.Manifest,model.CapacityMutationGrant,q.CanonicalCleanupSession,error){
 var none repository.CapacityStore;var noPolicy model.Manifest;var noChild model.CapacityMutationGrant;var noSession q.CanonicalCleanupSession
 issuer:=repository.CapacityStore{DB:f.db,WorkflowID:f.workflow.ID,ExecutionEnabled:true,ExecutorID:uuid.NewString()}
 eligible,err:=issuer.PrepareCanonicalSourceCompensation(ctx,f.policy,pre.OriginalCreateGrantID);if err!=nil{return none,noPolicy,noChild,noSession,err}
 var currentWire []byte;var intent model.CapacityIntent
 if err=f.db.QueryRowContext(ctx,`SELECT intent FROM public.capacity_intents WHERE namespace=$1 AND environment=$2 AND domain=$3 AND dimension=$4`,f.namespace,p.Environment,p.Domain,p.Dimension).Scan(&currentWire);err!=nil || capacity.DecodeGuestLifecycle(currentWire,&intent)!=nil{return none,noPolicy,noChild,noSession,q.ErrOriginalUnknown}
 client,err:=f.sourceClient(1);if err!=nil{return none,noPolicy,noChild,noSession,err};defer client.Close()
 parentStore:=issuer;parentStore.ExecutorID=intent.LeaseExecutorID
 useful,err:=f.realm.DiagnosticProbe(ctx,parentStore,1,f.corePrivate,client);if err!=nil{return none,noPolicy,noChild,noSession,err}
 binding,err:=capacity.VMObservationBinding(p,f.binding.MutationBindingName);if err!=nil{return none,noPolicy,noChild,noSession,err}
 native,err:=f.realm.FreshNativeMember(ctx,1,binding);if err!=nil{return none,noPolicy,noChild,noSession,err}
 var baselineDesired []byte;for _,slot:=range binding.Slots{if slot.Slot==1{baselineDesired,err=json.Marshal(slot.DesiredSpec)}};if err!=nil || len(baselineDesired)==0{return none,noPolicy,noChild,noSession,q.ErrOriginalUnknown}
 if err=parentStore.RecordMutationSlot(ctx,f.policy,intent.Generation,intent.FencingToken,intent.LeaseOwner,model.CapacityMutationIssue{BindingName:binding.Name,DesiredSpec:baselineDesired},native);err!=nil{return none,noPolicy,noChild,noSession,err}
 if err=parentStore.CheckNativeMembershipCoverage(ctx,f.policy,binding,[]model.CapacityMutationProof{native});err!=nil{return none,noPolicy,noChild,noSession,err}
 var live,failed int;if err=f.db.QueryRowContext(ctx,`SELECT count(*) FILTER(WHERE resource_id<>''),count(*) FILTER(WHERE slot=2 AND resource_id<>'') FROM public.capacity_resource_slots WHERE namespace=$1`,f.namespace).Scan(&live,&failed);err!=nil || live!=1 || failed!=0{return none,noPolicy,noChild,noSession,q.ErrOriginalUnknown}
 var destroy model.CapacityMutationSpecV1;for _,slot:=range binding.Slots{if slot.Slot==2{if json.Unmarshal(slot.DesiredSpec,&destroy)!=nil{return none,noPolicy,noChild,noSession,q.ErrOriginalUnknown}}};destroy.Capability=binding.DestroyCapability;destroy.ExpectedResourceID=eligible.Aggregate.ResourceID;destroy.ExpectedResourceCreatedAt=eligible.Aggregate.ResourceCreatedAt;desired,err:=json.Marshal(destroy);if err!=nil{return none,noPolicy,noChild,noSession,err}
 zero:=0
 // Healthy/member completeness derives from SAME signed useful probe plus
 // fresh original native/member coverage above. Failed payload is reaped; its QEMU is still owned and running until
 // the redeemed child authorizes the original frontend kill/unlink. It has
 // never been a serving SQL member.
 drain:=model.CapacityTransitionProof{Assessment:q.QualificationAssessment(p,live,0.9,useful.OriginalNativeAfterReturnedAt),ObservedAt:useful.OriginalNativeAfterReturnedAt,ReceiptRef:"canonical-source-original-baseline:"+capacity.GuestRetirementSHA(useful),Healthy:true,MembershipComplete:true,AdmissionClosed:true,RoutingWithdrawn:true,Inflight:&zero,NativeActionsInflight:&zero}
 issue:=model.CapacityCompensationIssue{ParentGrantID:pre.OriginalCreateGrantID,Mutation:model.CapacityMutationIssue{BindingName:binding.Name,DesiredSpec:desired},FailedProof:eligible.Aggregate,DrainProof:drain}
 current:=f.policy
 if !binding.CompensationEnabled {
  if _,err=issuer.IssueCompensation(ctx,f.policy,issue);!errors.Is(err,repository.ErrCapacityDisabled){return none,noPolicy,noChild,noSession,q.ErrOriginalUnknown}
  enabled:=p;enabled.MutationBindings=append([]model.CapacityMutationBinding(nil),p.MutationBindings...);for i:=range enabled.MutationBindings{if enabled.MutationBindings[i].Name==binding.Name{enabled.MutationBindings[i].CompensationEnabled=true}}
  spec,err:=json.Marshal(enabled);if err!=nil{return none,noPolicy,noChild,noSession,err};sum:=sha256.Sum256(spec)
  current,err=repository.CreateManifestVersion(ctx,f.db,model.ManifestDocument{APIVersion:f.policy.APIVersion,Kind:f.policy.Kind,Metadata:model.ManifestMetadataInput{Namespace:f.policy.Metadata.Namespace,Name:f.policy.Metadata.Name},Spec:spec},fmt.Sprintf("%x",sum));if err!=nil{return none,noPolicy,noChild,noSession,err}
 }
 paused:=issuer;paused.ExecutionEnabled=false;if _,err=paused.IssueCompensation(ctx,current,issue);!errors.Is(err,repository.ErrCapacityDisabled){return none,noPolicy,noChild,noSession,q.ErrOriginalUnknown}
 var group sync.WaitGroup;children:=make(chan model.CapacityMutationGrant,2);failures:=make(chan error,2)
 for i:=0;i<2;i++{group.Add(1);go func(){defer group.Done();child,err:=issuer.IssueCompensation(ctx,current,issue);children<-child;failures<-err}()};group.Wait()
 child,repeat:=<-children,<-children;first,second:=<-failures,<-failures
 if first!=nil || second!=nil || child.GrantID!=repeat.GrantID || child.CompensationOf!=pre.OriginalCreateGrantID{return none,noPolicy,noChild,noSession,q.ErrOriginalUnknown}
 stranger:=issuer;stranger.ExecutorID=uuid.NewString();if _,err=stranger.IssueCompensation(ctx,current,issue);!errors.Is(err,repository.ErrCapacityConflict){return none,noPolicy,noChild,noSession,q.ErrOriginalUnknown}
 // Actual negative calls cannot mint effects before the original API
 // redemption, and no physical absence exists before the frontend action.
 if _,err=issuer.AuthorizeCanonicalSourceChild(ctx,current,child.GrantID,uuid.NewString(),capacity.BusinessCreationSHA256([]byte("unredeemed-probe")));err==nil{return none,noPolicy,noChild,noSession,q.ErrOriginalUnknown}
 session,err:=f.realm.RedeemCanonicalSourceChild(ctx,issuer,current,child);if err!=nil{return none,noPolicy,noChild,noSession,err}
 if _,err=issuer.ObserveCanonicalSourceCompensation(ctx,current,child.GrantID);err==nil{return none,noPolicy,noChild,noSession,q.ErrOriginalUnknown}
 foreign:=issuer;foreign.ExecutorID=uuid.NewString()
 if _,err=foreign.AuthorizeCanonicalSourceChild(ctx,current,child.GrantID,session.AttemptID,capacity.BusinessCreationSHA256([]byte("foreign-executor-probe")));err==nil{return none,noPolicy,noChild,noSession,q.ErrOriginalUnknown}
 return issuer,current,child,session,nil
}
