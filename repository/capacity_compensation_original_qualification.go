//go:build linux && nativequalification

package repository

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

// OriginalCompensationCase consumes actual original source returns. It does not
// create a provisioning context, a proof, an executor identity or a VM. A caller
// must first obtain enrolled/quiescent/native-off evidence for the failed slot.
// Slot 1 is protected, slot 2 is burst; the OTHER original VM remains serving.
type OriginalCompensationCase struct {
	Name string
	DisabledPolicy model.Manifest
	EnabledPolicy model.Manifest
	Parent model.CapacityMutationGrant
	OriginalTransport model.CapacityMutationReceipt
	Issue model.CapacityCompensationIssue
	AdapterPrincipalID string
}

type OriginalCompensationPreparation struct {
	Case string `json:"case"`
	ParentGrantID string `json:"parent_grant_id"`
	ChildGrantID string `json:"child_grant_id"`
	Refusals []string `json:"refusals"`
	ConcurrentReturns int `json:"concurrent_returns"`
	ServingMembers int `json:"serving_members"`
}

// PrepareOriginalCompensation exercises all issuance refusals against the real
// current store and returns a real durable child. The caller must redeem it via
// its original authenticated transport and run the original physical deletion.
// This function never labels absence, timeout or a successful create as failed.
func (s CapacityStore) PrepareOriginalCompensation(ctx context.Context, c OriginalCompensationCase) (model.CapacityMutationGrant, OriginalCompensationPreparation, error) {
	var zero model.CapacityMutationGrant
	report := OriginalCompensationPreparation{Case:c.Name, ParentGrantID:c.Parent.GrantID}
	refuse := func(detail string) (model.CapacityMutationGrant, OriginalCompensationPreparation, error) { return zero, report, fmt.Errorf("original compensation: %s: %w", detail, ErrCapacityConflict) }
	lost, protected := false, false
	switch c.Name {
	case "unprotected_failed_create":
	case "protected_failed_create_without_serving_membership": protected=true
	case "lost_create_reply_uses_separate_native_readback": lost=true
	case "protected_lost_create_reply": lost,protected=true,true
	default: return refuse("unknown original case")
	}
	failedSlot := 2
	if protected { failedSlot=1 }
	if ctx.Err()!=nil || s.DB==nil || c.Parent.GrantID=="" || c.Parent.Slot!=failedSlot || c.Issue.ParentGrantID!=c.Parent.GrantID || c.Issue.FailedProof.GrantID!=c.Parent.GrantID || c.Issue.FailedProof.SpecVerified || !c.Issue.FailedProof.ActionsFailed || !c.Issue.FailedProof.ActionsTerminal || !c.Issue.FailedProof.CompensationIdentityVerified || c.Issue.FailedProof.ResourceID=="" || c.Issue.FailedProof.ResourceCreatedAt=="" || c.Issue.FailedProof.ObservedCreationGrantID!=c.Parent.GrantID { return refuse("missing genuine failed original") }
	if c.OriginalTransport.Grant.GrantID!=c.Parent.GrantID || !c.OriginalTransport.TransportCompleted { return refuse("missing owning transport") }
	if lost && (c.OriginalTransport.Outcome!="uncertain" || c.OriginalTransport.ResourceID!="" || c.OriginalTransport.ResourceCreatedAt!="" || !c.Issue.FailedProof.ActionHistoryComplete) { return refuse("lost reply lacks separate complete native history") }
	if !lost && (c.OriginalTransport.ResourceID!=c.Issue.FailedProof.ResourceID || c.OriginalTransport.ResourceCreatedAt!=c.Issue.FailedProof.ResourceCreatedAt) { return refuse("transport/native identity mismatch") }
	var disabled,enabled model.CapacityPolicySpec
	if json.Unmarshal(c.DisabledPolicy.Spec,&disabled)!=nil || json.Unmarshal(c.EnabledPolicy.Spec,&enabled)!=nil || c.DisabledPolicy.Metadata.Namespace!=c.EnabledPolicy.Metadata.Namespace || enabled.Floor!=1 || enabled.Ceiling!=2 { return refuse("not the registered two-slot policy") }
	// Only the already-registered compensation switch may differ. No policy,
	// assessment, lease, source provenance or deadline is minted by this runner.
	found:=false
	for i:=range enabled.MutationBindings { if enabled.MutationBindings[i].Name==c.Parent.BindingName { if !enabled.MutationBindings[i].CompensationEnabled { return refuse("enabled policy missing switch") }; enabled.MutationBindings[i].CompensationEnabled=false; found=true } }
	a,_:=json.Marshal(disabled); b,_:=json.Marshal(enabled)
	if !found || !bytes.Equal(a,b) { return refuse("policy difference beyond compensation enable") }
	var serving,failedServing int
	if err:=s.DB.QueryRowContext(ctx,`SELECT count(*) FILTER (WHERE resource_id<>''),count(*) FILTER (WHERE slot=$2 AND resource_id<>'') FROM public.capacity_resource_slots WHERE namespace=$1`,c.EnabledPolicy.Metadata.Namespace,failedSlot).Scan(&serving,&failedServing); err!=nil { return zero,report,err }
	if serving!=1 || failedServing!=0 { return refuse("failed slot is serving or original floor absent") }
	report.ServingMembers=serving
	if _,err:=s.IssueCompensation(ctx,c.DisabledPolicy,c.Issue); err==nil { return refuse("default disabled admitted cleanup") }
	report.Refusals=append(report.Refusals,"default_disabled")
	paused:=s; paused.ExecutionEnabled=false
	if _,err:=paused.IssueCompensation(ctx,c.EnabledPolicy,c.Issue); !errors.Is(err,ErrCapacityDisabled) { return refuse("paused issuer admitted cleanup") }
	report.Refusals=append(report.Refusals,"paused")
	for _,name:=range []string{"unknown_action","successful_action","wrong_parent","wrong_creation_label","missing_identity","running_business","running_native","open_admission","routed","incomplete_inventory","below_floor","wrong_tuple","incomplete_action_history"} {
		bad:=c.Issue
		switch name {
		case "unknown_action": bad.FailedProof.ActionsTerminal=false
		case "successful_action": bad.FailedProof.ActionsSuccessful=true
		case "wrong_parent": bad.ParentGrantID="00000000-0000-0000-0000-000000000000"
		case "wrong_creation_label": bad.FailedProof.ObservedCreationGrantID="00000000-0000-0000-0000-000000000000"
		case "missing_identity": bad.FailedProof.CompensationIdentityVerified=false
		case "running_business": one:=1; bad.DrainProof.Inflight=&one
		case "running_native": one:=1; bad.DrainProof.NativeActionsInflight=&one
		case "open_admission": bad.DrainProof.AdmissionClosed=false
		case "routed": bad.DrainProof.RoutingWithdrawn=false
		case "incomplete_inventory": bad.DrainProof.MembershipComplete=false
		case "below_floor": bad.DrainProof.Assessment.Snapshot.Units=0
		case "wrong_tuple": bad.FailedProof.ResourceID="not-the-original-resource"
		case "incomplete_action_history": if !lost { continue }; bad.FailedProof.ActionHistoryComplete=false
		}
		if _,err:=s.IssueCompensation(ctx,c.EnabledPolicy,bad); err==nil { return refuse("unsafe compensation admitted: "+name) }
		report.Refusals=append(report.Refusals,name)
	}
	type result struct { grant model.CapacityMutationGrant; err error }
	returns:=make(chan result,2); var owners sync.WaitGroup
	for n:=0;n<2;n++ { owners.Add(1); go func(){ defer owners.Done(); g,err:=s.IssueCompensation(ctx,c.EnabledPolicy,c.Issue); returns<-result{g,err} }() }
	owners.Wait(); close(returns)
	var child model.CapacityMutationGrant
	for original:=range returns { if original.err!=nil { return zero,report,original.err }; if child.GrantID!="" && child.GrantID!=original.grant.GrantID { return refuse("two cleanup children") }; child=original.grant; report.ConcurrentReturns++ }
	if ctx.Err()!=nil || child.GrantID=="" || child.CompensationOf!=c.Parent.GrantID || child.ExpectedResourceID!=c.Issue.FailedProof.ResourceID || child.ExpectedResourceCreatedAt!=c.Issue.FailedProof.ResourceCreatedAt { return refuse("child lifetime escaped original") }
	report.ChildGrantID=child.GrantID
	return child,report,nil
}

// FinishOriginalCompensation only consumes a separately produced physical
// deletion proof AFTER its owning settlement. It never synthesizes deletion.
// The ordinary ConfirmCompensation still validates enrolled retirement/native
// off, paid auxiliary absence, lineage and all original authority fences.
func (s CapacityStore) FinishOriginalCompensation(ctx context.Context,c OriginalCompensationCase,child model.CapacityMutationGrant,deleted model.CapacityMutationProof) error {
	if child.CompensationOf!=c.Parent.GrantID || deleted.GrantID!=child.GrantID || deleted.ResourceID!=c.Issue.FailedProof.ResourceID || deleted.ResourceCreatedAt!=c.Issue.FailedProof.ResourceCreatedAt || !deleted.ResourceAbsent || !deleted.ActionsSuccessful || deleted.ActionsFailed { return ErrCapacityConflict }
	before,err:=s.MutationReceipt(ctx,c.AdapterPrincipalID,c.Parent.GrantID); if err!=nil { return err }
	// Compare only original transport fields: grant state and separately admitted
	// NativeReadback legitimately change, owning transport evidence must not.
	transport:=func(r model.CapacityMutationReceipt) []byte { r.Grant=model.CapacityMutationGrant{}; r.NativeReadback=nil; raw,_:=json.Marshal(r); return raw }
	if !bytes.Equal(transport(before),transport(c.OriginalTransport)) { return ErrCapacityConflict }
	if _,err=s.ConfirmCompensation(ctx,c.EnabledPolicy,deleted); err!=nil { return err }
	if _,err=s.ConfirmCompensation(ctx,c.EnabledPolicy,deleted); err!=nil { return err }
	after,err:=s.MutationReceipt(ctx,c.AdapterPrincipalID,c.Parent.GrantID); if err!=nil { return err }
	if after.Grant.State!="compensated" || after.NativeReadback==nil || after.NativeReadback.ResourceID!=deleted.ResourceID || after.NativeReadback.ResourceCreatedAt!=deleted.ResourceCreatedAt || !bytes.Equal(transport(after),transport(c.OriginalTransport)) { return ErrCapacityConflict }
	var serving,ensured,destroyed int
	if err=s.DB.QueryRowContext(ctx,`SELECT count(*) FROM public.capacity_resource_slots WHERE namespace=$1 AND resource_id<>''`,c.EnabledPolicy.Metadata.Namespace).Scan(&serving); err!=nil { return err }
	if err=s.DB.QueryRowContext(ctx,`SELECT count(*) FILTER(WHERE type='fixture.server.ensured'),count(*) FILTER(WHERE type='fixture.server.destroyed') FROM public.event_log WHERE metadata->>'namespace'=$1`,c.EnabledPolicy.Metadata.Namespace).Scan(&ensured,&destroyed); err!=nil { return err }
	// One REAL baseline remains; failed creation contributes no ensured event.
	// The harness requires a fresh case namespace with baseline event retained.
	if serving!=1 || ensured!=1 || destroyed!=1 { return ErrCapacityConflict }
	var parent string
	if err=s.DB.QueryRowContext(ctx,`SELECT payload->'observed'->>'compensation_of' FROM public.event_log WHERE metadata->>'namespace'=$1 AND type='fixture.server.destroyed'`,c.EnabledPolicy.Metadata.Namespace).Scan(&parent); err!=nil || parent!=c.Parent.GrantID { return ErrCapacityConflict }
	return ctx.Err()
}

// AssertOriginalSuccessfulParentNotCompensable runs at the existing post-off
// retirement hook. It tests the actual successful parent, never a proof whose
// status bits were changed to manufacture a failed creation. The repository
// success predicate is checked separately, so a refusal cannot be credited
// merely to missing drain evidence, inactive policy or a disabled executor.
func (s CapacityStore) AssertOriginalSuccessfulParentNotCompensable(ctx context.Context,policy model.Manifest,parentID string) error {
 p,err:=parseCapacityPolicy(policy); if err!=nil { return err }
 tx,err:=s.DB.BeginTx(ctx,nil); if err!=nil { return err }; defer tx.Rollback()
 record,err:=readCompensationRecord(ctx,tx,policy,p,parentID,false); if err!=nil { return err }
 if record.Proof==nil || record.Grant.Capability!=record.Binding.EnsureCapability || record.Proof.GrantID!=parentID || !record.Proof.SpecVerified || !record.Proof.ActionsSuccessful || record.Proof.ActionsFailed || record.Proof.ResourceAbsent || record.Settlement==nil || !record.Settlement.TransportCompleted { return ErrCapacityConflict }
 var now time.Time
 if err=tx.QueryRowContext(ctx,`SELECT clock_timestamp()`).Scan(&now); err!=nil { return err }
 if validFailedCreationProof(p,record,*record.Proof,now.UTC()) { return ErrCapacityConflict }
 var before int
 if err=tx.QueryRowContext(ctx,`SELECT count(*) FROM public.capacity_mutation_grants WHERE grant_record->'grant'->>'compensation_of'=$1`,parentID).Scan(&before); err!=nil || before!=0 { return ErrCapacityConflict }
 if err=tx.Rollback(); err!=nil { return err }
 var desired *model.CapacityMutationSpecV1
 for _,slot:=range record.Binding.Slots { if slot.Slot==record.Grant.Slot && slot.DesiredSpec!=nil { copy:=*slot.DesiredSpec; desired=&copy } }
 if desired==nil { return ErrCapacityConflict }
 desired.Capability=record.Binding.DestroyCapability
 desired.ExpectedResourceID=record.Proof.ResourceID; desired.ExpectedResourceCreatedAt=record.Proof.ResourceCreatedAt
 raw,err:=json.Marshal(desired); if err!=nil { return err }
 issue:=model.CapacityCompensationIssue{ParentGrantID:parentID,Mutation:model.CapacityMutationIssue{BindingName:record.Binding.Name,DesiredSpec:raw},FailedProof:*record.Proof}
 // The original profile may intentionally leave compensation disabled.
 // That public refusal is required but is NOT credited as a failed-proof test;
 // the exact production failed-proof predicate above establishes that claim.
 if _,err=s.IssueCompensation(ctx,policy,issue); err==nil { return ErrCapacityConflict }
 var after int
 if err=s.DB.QueryRowContext(ctx,`SELECT count(*) FROM public.capacity_mutation_grants WHERE grant_record->'grant'->>'compensation_of'=$1`,parentID).Scan(&after); err!=nil || after!=before { return ErrCapacityConflict }
 return ctx.Err()
}
