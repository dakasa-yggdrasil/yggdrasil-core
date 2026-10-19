//go:build linux && nativequalification

package repository

import (
 "testing"
 "time"
 "strings"
 "github.com/google/uuid"
 "github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
 "github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

func TestSourceRecoveryCleanupRejectsOriginalOrForeignLease(t *testing.T) {
 now:=time.Date(2026,1,1,0,0,0,0,time.UTC);expiry:=now.Add(time.Minute)
 parent:=capacityMutationRecord{Generation:2,FencingToken:3,LeaseOwner:uuid.NewString(),ExecutorID:uuid.NewString()}
 current:=model.CapacityIntent{PolicyID:uuid.New(),PolicyChecksum:strings.Repeat("a",64),Generation:2,FencingToken:4,LeaseOwner:uuid.NewString(),LeaseExecutorID:uuid.NewString(),LeaseExpiresAt:&expiry,RecoveryOnly:true,UpdatedAt:now}
 e:=model.CapacitySourceRecoveryCleanupEpoch{Schema:"original_source_recovery_cleanup_epoch_v1",OriginalGeneration:parent.Generation,OriginalFencingToken:parent.FencingToken,OriginalLeaseOwner:parent.LeaseOwner,OriginalExecutorID:parent.ExecutorID,CurrentPolicyID:current.PolicyID.String(),CurrentPolicyChecksum:current.PolicyChecksum,Generation:current.Generation,FencingToken:current.FencingToken,LeaseOwner:current.LeaseOwner,ExecutorID:current.LeaseExecutorID,RecoveryDBObservedAt:now,LeaseExpiresAt:expiry,IntentSHA256:capacity.GuestRetirementSHA(current),NonceSHA256:strings.Repeat("b",64),ChallengePreparedAt:now}
 if !recoveryCleanupEpochMatches(&e,current,parent,now){t.Fatal("valid independently recovered tuple refused")}
 for _,tc:=range []struct{name string; mutate func(*model.CapacitySourceRecoveryCleanupEpoch)}{
  {"original_fence",func(x *model.CapacitySourceRecoveryCleanupEpoch){x.FencingToken=parent.FencingToken}},
  {"foreign_owner",func(x *model.CapacitySourceRecoveryCleanupEpoch){x.LeaseOwner=uuid.NewString()}},
  {"foreign_executor",func(x *model.CapacitySourceRecoveryCleanupEpoch){x.ExecutorID=uuid.NewString()}},
  {"historical_tuple_rewritten",func(x *model.CapacitySourceRecoveryCleanupEpoch){x.OriginalExecutorID=current.LeaseExecutorID}},
  {"foreign_policy",func(x *model.CapacitySourceRecoveryCleanupEpoch){x.CurrentPolicyID=uuid.NewString()}},
  {"missing_nonce",func(x *model.CapacitySourceRecoveryCleanupEpoch){x.NonceSHA256=""}},
  {"future_challenge",func(x *model.CapacitySourceRecoveryCleanupEpoch){x.ChallengePreparedAt=now.Add(time.Second)}},
  {"lease_renewed_in_wire",func(x *model.CapacitySourceRecoveryCleanupEpoch){x.LeaseExpiresAt=expiry.Add(time.Second)}},
 }{t.Run(tc.name,func(t *testing.T){bad:=e;tc.mutate(&bad);if recoveryCleanupEpochMatches(&bad,current,parent,now){t.Fatal("foreign/historical tuple accepted")}})}
 if recoveryCleanupEpochMatches(&e,current,parent,expiry){t.Fatal("expired current lease accepted")}
 current.RecoveryOnly=false;if recoveryCleanupEpochMatches(&e,current,parent,now){t.Fatal("ordinary owner accepted as recovered authority")}
}

func TestSourceRecoveryCleanupDoesNotAliasV1OrPositiveAuthority(t *testing.T){
 original:=SourceFailureCleanupBody{Schema:"original_source_failure_cleanup_authority_v1",Mode:"failure_cleanup_only",Scope:"same_original_host_qemu_cleanup_not_guest_positive_retirement"}
 if !canonicalCleanupMode(original){t.Fatal("legacy discriminator changed")}
 recovery:=original;recovery.Recovery=&model.CapacitySourceRecoveryCleanupEpoch{}
 if canonicalCleanupMode(recovery){t.Fatal("recovery epoch accepted under legacy schema")}
 recovery.Schema=sourceRecoveryCleanupSchema;recovery.Mode="recovery_failure_cleanup_only";recovery.Scope=sourceRecoveryCleanupScope
 if !canonicalCleanupMode(recovery){t.Fatal("distinct recovery discriminator rejected")}
 recovery.Recovery=nil;if canonicalCleanupMode(recovery){t.Fatal("missing recovery tuple accepted")}
 recovery.Recovery=&model.CapacitySourceRecoveryCleanupEpoch{};recovery.Mode="positive_quiescence";if canonicalCleanupMode(recovery){t.Fatal("positive authority alias accepted")}
}

func TestSourceRecoveryNativeIdentityPreservesLargeIntegerAndCanonicalKeys(t *testing.T){
 a:=SourceFailureCleanupBody{QEMU:[]byte(`{"pid":9007199254740993,"boot":"x"}`),OriginalDisk:[]byte(`{"inode":9007199254740995,"dev":4}`)}
 b:=a;b.QEMU=[]byte(`{"boot":"x","pid":9007199254740993}`);b.OriginalDisk=[]byte(`{"dev":4,"inode":9007199254740995}`)
 ah,err:=recoveryNativeIdentity(a);if err!=nil{t.Fatal(err)};bh,err:=recoveryNativeIdentity(b);if err!=nil || ah!=bh{t.Fatal("canonical identity depends on JSON key order")}
 b.QEMU=[]byte(`{"pid":9007199254740992,"boot":"x"}`);bh,err=recoveryNativeIdentity(b);if err!=nil || ah==bh{t.Fatal("process identity precision lost")}
}

func TestSourceRecoveryObservationNeverRestampsHistoricalFailure(t *testing.T){
 old:=time.Date(2026,1,1,0,0,0,0,time.UTC);fresh:=old.Add(301*time.Second)
 b:=SourceFailureCleanupBody{}
 if !canonicalRecoveryObservedAt(b,old).Equal(old){t.Fatal("legacy failure timestamp changed")}
 b.Recovery=&model.CapacitySourceRecoveryCleanupEpoch{FreshObservedAt:fresh}
 if !canonicalRecoveryObservedAt(b,old).Equal(fresh) || !old.Equal(time.Date(2026,1,1,0,0,0,0,time.UTC)){t.Fatal("fresh observation relabeled historical failure")}
}

func TestSourceRecoveryEffectRequestRejectsUnknownAndWrongTypes(t *testing.T){
 for _,wire:=range []string{
  `{"schema":"original_source_recovery_effect_request_v1","phase":"signal","nonce_sha256":true}`,
  `{"schema":"original_source_recovery_effect_request_v1","phase":"signal","generation":2}`,
  `{"schema":"original_source_recovery_effect_request_v1","phase":1}`,
 }{var request model.CapacitySourceRecoveryEffectRequest;if capacity.DecodeGuestLifecycle([]byte(wire),&request)==nil{t.Fatal("nonclosed request decoded",wire)}}
}
