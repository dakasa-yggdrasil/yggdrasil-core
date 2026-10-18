//go:build linux && nativequalification
package repository
import("testing";"time";"strings";"github.com/dakasa-yggdrasil/yggdrasil-core/model")
// Unit regression data is not a signed original, physical read, Native result
// or qualification. Runtime always ALSO verifies signatures/DB/source/census.
func TestCanonicalFailedOwnerPayloadContinuity(t *testing.T){
 yes:=true;exit:=1;nonce:=strings.Repeat("a",64)
 w:=model.CapacityGuestRetirementLifetime{PID:42,StartTicks:7,ProcessNonceSHA256:nonce}
 f:=QualificationFailureRecord{Phase:"original_probe_failed_owner_exit",OriginalExitCode:&exit,OriginalWait:QualificationFailedOwnerReturn{ErrorClass:"original_owner_error"},OriginalOutputEOF:&yes,OriginalOutputCloseSucceeded:&yes,OriginalDiagnosticEOF:&yes,OriginalDiagnosticCloseSucceeded:&yes,OriginalPayloadActionID:"guest-protected-payload:"+nonce,OriginalPayloadSessionNonceSHA256:nonce}
 f.OriginalChild.PID=42;f.OriginalChild.StartTicks=7
 if !canonicalPayloadLinked(f,w){t.Fatal("same authenticated failed payload was refused")}
 for _,name:=range []string{"success_is_not_failure","missing_wait","missing_eof","foreign_pid","foreign_nonce","synthetic_action"}{
  bad:=f
  switch name{case "success_is_not_failure":zero:=0;bad.OriginalExitCode=&zero;case "missing_wait":bad.OriginalWait.ErrorClass="";case "missing_eof":bad.OriginalDiagnosticEOF=nil;case "foreign_pid":bad.OriginalChild.PID++;case "foreign_nonce":bad.OriginalPayloadSessionNonceSHA256=strings.Repeat("b",64);case "synthetic_action":bad.OriginalPayloadActionID="bootstrap-action"}
  if canonicalPayloadLinked(bad,w){t.Fatal("aggregate actionhistory accepted unrelated or incomplete original",name)}
 }
 if canonicalKnownFailedCase("canonical_compensation_unprotected_lost_reply") || canonicalKnownFailedCase("positive_original_lifecycle"){t.Fatal("lost/positive original became failed payload authority")}
}
func TestCanonicalChildDeadlineCannotRenewOriginalAuthority(t *testing.T){
 now:=time.Date(2026,10,18,0,0,0,0,time.UTC);grant:=now.Add(60*time.Second);cleanup:=now.Add(150*time.Second);lease:=now.Add(30*time.Second)
 end,ok:=canonicalChildDeadline(now,grant,cleanup,lease,now.Add(420*time.Second));if !ok || !end.Equal(lease){t.Fatal("child escaped current original lease")}
 end,ok=canonicalChildDeadline(now,grant,cleanup,now.Add(300*time.Second),now.Add(420*time.Second));if !ok || !end.Equal(grant){t.Fatal("cleanup150 renewed actual child60")}
 if _,ok=canonicalChildDeadline(lease,grant,cleanup,lease,now.Add(420*time.Second));ok{t.Fatal("strict endpoint admitted late effect")}
 if _,ok=canonicalChildDeadline(now,time.Time{},cleanup,lease,now.Add(420*time.Second));ok{t.Fatal("unknown grant lifetime minted authority")}
}

func TestCanonicalChildMustOwnFuturePhysicalEffects(t *testing.T){
 now:=time.Date(2026,10,18,0,0,0,0,time.UTC)
 id:="aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";parent:="bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";attempt:="cccccccc-cccc-4ccc-8ccc-cccccccccccc";executor:="dddddddd-dddd-4ddd-8ddd-dddddddddddd"
 child:=capacityMutationRecord{Grant:model.CapacityMutationGrant{GrantID:id,CompensationOf:parent,Slot:2,State:"redeemed",RequestSHA256:strings.Repeat("e",64),ExpectedResourceID:parent,ExpectedResourceCreatedAt:now.Format(time.RFC3339Nano),ExpiresAt:now.Add(time.Minute)},AttemptID:attempt,ExecutorID:executor}
 if !canonicalRedeemedChild(child,id,attempt,executor,now){t.Fatal("actual redeemed child identity rejected")}
 for _,name:=range []string{"not_redeemed","expired","foreign_executor","foreign_attempt","no_parent","wrong_slot"}{bad:=child;switch name{case "not_redeemed":bad.Grant.State="issued";case "expired":bad.Grant.ExpiresAt=now;case "foreign_executor":bad.ExecutorID=parent;case "foreign_attempt":bad.AttemptID=parent;case "no_parent":bad.Grant.CompensationOf="";case "wrong_slot":bad.Grant.Slot=1};if canonicalRedeemedChild(bad,id,attempt,executor,now){t.Fatal("physical effects received foreign/unredeemed/late authority",name)}}
}

func TestCanonicalChildProvisioningDeadlineIsOriginalAbsolute(t *testing.T){
 now:=time.Date(2026,10,18,0,10,0,0,time.UTC)
 originalStart:=now.Add(-400*time.Second)
 originalProvisioningDeadline:=originalStart.Add(420*time.Second)
 grant:=now.Add(60*time.Second);cleanup:=now.Add(150*time.Second);lease:=now.Add(300*time.Second)
 end,ok:=canonicalChildDeadline(now,grant,cleanup,lease,originalProvisioningDeadline)
 if !ok || !end.Equal(originalProvisioningDeadline) || end.Sub(now)!=20*time.Second{t.Fatal("late failed owner renewed its original420 provisioning window")}
 for _,invalid:=range []time.Time{time.Time{},now.Add(-time.Nanosecond),now}{
  if _,ok=canonicalChildDeadline(now,grant,cleanup,lease,invalid);ok{t.Fatal("missing, expired or exact provisioning endpoint authorized physical effects",invalid)}
 }
 // An earlier real grant still dominates: adding420 cannot extend child60.
 end,ok=canonicalChildDeadline(now,grant,cleanup,lease,now.Add(420*time.Second))
 if !ok || !end.Equal(grant){t.Fatal("provisioning cap extended an earlier actual child expiry")}
}
