package repository

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

// PostgreSQL and signed, source-derived semantic operands only. All rows are
// rolled back; no real Guest, provider mutation, admission or readiness exists.
func TestHistoricalUnknownReadPostgresSignedLineage(t *testing.T) {
	db := guestOriginalPostgres(t)
	tx, ctx := guestOriginalStorageTx(t, db)
	p, read, enrollment, pub, pubReturn, at := recoveryPublicationFixture(t)
	p.GuestRetirementBinding.GuestSourceCommit = originalReadGuestSource
	p.GuestRetirementBinding.CoreAuthoritySourceCommit = originalReadCoreSource
	if p.GuestNotifyCanaryBinding.QuerySHA256 != originalReadQuerySHA256 {
		t.Fatal("query source mismatch")
	}
	wire := func(v any) []byte {
		b, e := json.Marshal(v)
		if e != nil {
			t.Fatal(e)
		}
		return b
	}
	must := func(query string, args ...any) {
		t.Helper()
		if _, err := tx.ExecContext(ctx, query, args...); err != nil {
			t.Fatalf("fixture insert: %v", err)
		}
	}
	ns := "unit-recovery-" + uuid.NewString()
	must(`INSERT INTO public.manifests(id,api_version,kind,namespace,name,version,checksum,spec,active) VALUES($1,'v1','capacity_policy',$2,'unit',1,$3,'{}'::jsonb,false)`, read.PolicyID, ns, read.PolicyChecksum)
	must(`INSERT INTO public.manifests(id,api_version,kind,namespace,name,version,checksum,spec,active) VALUES($1,'v1','workflow',$2,'unit',1,$3,'{}'::jsonb,false)`, read.WorkflowID, ns, read.WorkflowChecksum)
	f := guestOriginalStorageRecords(t)
	f.pre.PreregistrationID = read.PreregistrationID
	guestOriginalStoragePre(t, tx, ctx, f, f.wire, f.wire, f.pre.OriginalDeadline)
	must(`INSERT INTO public.capacity_vm_original_enrollments(preregistration_id,resource_tuple_sha256,enrollment_sha256,original_provisioning_sha256,enrollment_record,recorded_at) VALUES($1,$2,$3,$4,'{}'::jsonb,$5)`, read.PreregistrationID, capacity.BusinessCreationSHA256([]byte("unit tuple")), capacity.GuestRetirementSHA(enrollment), capacity.BusinessCreationSHA256([]byte("unit registration")), f.pre.ReservedAt)
	const executor = "unit-executor"
	for _, challenge := range []model.CapacityGuestNotifyCanaryChallenge{pub, read} {
		phase := "read"
		if challenge.ChallengeID == pub.ChallengeID {
			phase = "publish"
		}
		pre := challenge
		pre.GuestNonce = model.CapacityGuestNotifyCanaryNonce{}
		pre.Signature = ""
		preWire := wire(pre)
		preSHA := capacity.GuestRetirementSHA(pre)
		must(`INSERT INTO public.capacity_guest_notify_canary_challenges(id,preregistration_id,record_challenge_id,phase,policy_id,workflow_id,generation,fence,executor_id,lease_owner,challenge_sha256,nonce_sha256,original_wire,original_record,original_deadline,recorded_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14::jsonb,$15,$16)`, challenge.ChallengeID, challenge.PreregistrationID, challenge.RecordChallengeID, phase, challenge.PolicyID, challenge.WorkflowID, challenge.Generation, challenge.Fence, executor, challenge.LeaseOwner, preSHA, challenge.NonceSHA256, preWire, string(preWire), challenge.OriginalDeadline, challenge.IssuedAt)
		must(`INSERT INTO public.capacity_guest_notify_canary_nonces(challenge_id,guest_nonce_sha256,nonce_wire,final_challenge_wire,final_challenge_sha256,original_transport,recorded_at) VALUES($1,$2,$3,$4,$5,'{}'::jsonb,$6)`, challenge.ChallengeID, challenge.GuestNonce.NonceSHA256, wire(challenge.GuestNonce), wire(challenge), capacity.GuestRetirementSHA(challenge), challenge.IssuedAt)
		issue := map[string]any{"schema": "guest_authority_issue_v1", "issue_kind": "canary_challenge", "issue_id": challenge.ChallengeID, "issuer_actual_source_commit": originalReadCoreSource, "protocol_authority_source_commit": originalReadCoreSource, "compatibility_map_sha256": strings.Repeat("f", 64), "profile": "notify-hetzner-elastic", "policy_id": challenge.PolicyID, "workflow_id": challenge.WorkflowID, "executor_id": executor, "issued_wire_sha256": preSHA}
		issueWire := wire(issue)
		must(`INSERT INTO public.capacity_guest_authority_issues(issue_kind,issue_id,issuer_actual_source_commit,protocol_authority_source_commit,compatibility_map_sha256,profile,policy_id,workflow_id,executor_id,issued_wire_sha256,original_wire,original_record) VALUES('canary_challenge',$1,$2,$2,$3,'notify-hetzner-elastic',$4,$5,$6,$7,$8,$9::jsonb)`, challenge.ChallengeID, originalReadCoreSource, strings.Repeat("f", 64), challenge.PolicyID, challenge.WorkflowID, executor, preSHA, issueWire, string(issueWire))
	}
	req := wire(model.CapacityGuestNotifyCanaryRequest{Challenge: read})
	must(`INSERT INTO public.capacity_guest_notify_canary_sends(challenge_id,request_sha256,possible_send_at,original_deadline,recorded_at) VALUES($1,$2,$3,$4,$3)`, read.ChallengeID, capacity.BusinessCreationSHA256(req), read.IssuedAt.Add(time.Millisecond), read.OriginalDeadline)
	pubWire := wire(pubReturn)
	digest := capacity.BusinessCreationSHA256(pubWire)
	transport := capacity.GuestOriginalHTTPReturn{StartedAt: at.Add(-10 * time.Millisecond), DoStartedAt: at.Add(-9 * time.Millisecond), DoReturnedAt: at.Add(-2 * time.Millisecond), ReadReturnedAt: at.Add(-time.Millisecond), CloseReturnedAt: at, DriverReturnedAt: at.Add(500 * time.Microsecond), Status: 200, ReceivedBodyBytes: len(pubWire), ResponseSHA256: digest, ResponseBodyScope: capacity.GuestOriginalBodyCompleteRead, RetainedPrefixBytes: len(pubWire), RetainedPrefixSHA256: digest}
	must(`INSERT INTO public.capacity_guest_notify_canary_returns(challenge_id,outcome,return_sha256,original_wire,original_transport,recorded_at) VALUES($1,'accepted',$2,$3,$4::jsonb,$5)`, pub.ChallengeID, digest, pubWire, string(wire(transport)), at)
	original := capacity.GuestOriginalHTTPReturn{StartedAt: read.IssuedAt.Add(2 * time.Millisecond), DoStartedAt: read.IssuedAt.Add(3 * time.Millisecond), DoReturnedAt: read.OriginalDeadline.Add(time.Millisecond), DriverReturnedAt: read.OriginalDeadline.Add(2 * time.Millisecond), DoFailed: true, OriginalContextFailed: true, ResponseBodyScope: capacity.GuestOriginalBodyNoRead, RetainedPrefixSHA256: capacity.BusinessCreationSHA256(nil)}
	diagnostic, err := json.Marshal(original)
	if err != nil {
		t.Fatal(err)
	}
	must(`INSERT INTO public.capacity_guest_notify_canary_returns(challenge_id,outcome,return_sha256,original_transport,recorded_at) VALUES($1,'held',$2,$3::jsonb,$4)`, read.ChallengeID, capacity.BusinessCreationSHA256(diagnostic), string(diagnostic), at.Add(10*time.Second))
	policy := model.Manifest{ID: uuid.MustParse(read.PolicyID), Checksum: read.PolicyChecksum}
	store := CapacityStore{WorkflowID: uuid.MustParse(read.WorkflowID), guestReconcile: &guestReconcileSource{workflow: model.Manifest{Checksum: read.WorkflowChecksum}}}
	old := model.CapacityIntent{Generation: int64(read.Generation), FencingToken: int64(read.Fence), LeaseOwner: read.LeaseOwner, LeaseExecutorID: executor, InstalledGuestReconcile: &model.CapacityInstalledGuestReconcile{Attempt: 1, NewFence: int64(read.Fence), OriginalFailurePreserved: true}}
	stored := guestOriginalStored{binding: *p.GuestRetirementBinding, pre: model.CapacityGuestOriginalProvisioningPreregistration{PreregistrationID: read.PreregistrationID}}
	got, err := store.previousInstalledCanariesVerifiedTx(ctx, tx, policy, p, old, stored, enrollment, at.Add(10*time.Second))
	if err != nil {
		t.Fatal("real postgres signed chain", err)
	}
	if len(got) != 2 || got[1].ChallengeID != read.ChallengeID || got[1].Outcome != "held" || got[1].OriginalTransportState != "unknown_read_timeout" || !capacity.ValidDigest(got[1].OriginalTransportSHA256) {
		t.Fatalf("original unknown not retained: %+v", got)
	}
	// Exercise the actual CAS/event writer with the verified original records in
	// the same PG transaction. This is not the entire TryResume entrypoint.
	policy.Metadata.Namespace = ns
	p.Environment, p.Domain, p.Dimension = "ci-recovery", "vm", "physical_membership"
	old.Namespace, old.Environment, old.Domain, old.Dimension = ns, p.Environment, p.Domain, p.Dimension
	old.PolicyID, old.PolicyChecksum, old.Phase, old.UpdatedAt = policy.ID, policy.Checksum, "preparing", at
	must(`INSERT INTO public.capacity_intents(namespace,environment,domain,dimension,intent,updated_at) VALUES($1,$2,$3,$4,$5::jsonb,$6)`, ns, p.Environment, p.Domain, p.Dimension, string(wire(old)), at)
	next := old
	next.FencingToken++
	next.UpdatedAt = at.Add(time.Second)
	next.InstalledGuestReconcile = &model.CapacityInstalledGuestReconcile{Schema: "installed_original_guest_readiness_reconcile_v1", Attempt: 2, OriginalGeneration: old.Generation, OriginalFence: old.FencingToken - 1, PreviousFence: old.FencingToken, NewFence: next.FencingToken, OriginalRunID: uuid.NewString(), NewRunID: uuid.NewString(), PreviousCanaries: got, OriginalFailurePreserved: true}
	if err = persistInstalledGuestResumeTx(ctx, tx, policy, p, old, next); err != nil {
		t.Fatal("persist verified marker", err)
	}
	var storedIntent []byte
	if err = tx.QueryRowContext(ctx, `SELECT intent FROM public.capacity_intents WHERE namespace=$1 AND environment=$2 AND domain=$3 AND dimension=$4`, ns, p.Environment, p.Domain, p.Dimension).Scan(&storedIntent); err != nil {
		t.Fatal(err)
	}
	var reread model.CapacityIntent
	if json.Unmarshal(storedIntent, &reread) != nil || reread.FencingToken != next.FencingToken || reread.InstalledGuestReconcile == nil || len(reread.InstalledGuestReconcile.PreviousCanaries) != 2 || reread.InstalledGuestReconcile.PreviousCanaries[1].OriginalTransportSHA256 != capacity.BusinessCreationSHA256(diagnostic) || reread.InstalledGuestReconcile.PreviousCanaries[1].Outcome != "held" {
		t.Fatal("fence or original digest was not durably preserved")
	}
	if err = persistInstalledGuestResumeTx(ctx, tx, policy, p, old, next); err == nil {
		t.Fatal("stale epoch repeated")
	}
	guestOriginalExpectedSQLRefusal(t, tx, ctx, `UPDATE public.capacity_guest_notify_canary_returns SET outcome='accepted' WHERE challenge_id=$1`, read.ChallengeID)
	guestOriginalExpectedSQLRefusal(t, tx, ctx, `UPDATE public.capacity_guest_notify_canary_nonces SET nonce_wire='{}'::bytea WHERE challenge_id=$1`, read.ChallengeID)
	old.LeaseExecutorID = "foreign-executor"
	if _, err = store.previousInstalledCanariesVerifiedTx(ctx, tx, policy, p, old, stored, enrollment, at.Add(10*time.Second)); err == nil {
		t.Fatal("foreign original executor accepted")
	}
}

func TestHistoricalUnknownReadPostgresB509Compatibility(t *testing.T) {
	db := guestOriginalPostgres(t)
	tx, ctx := guestOriginalStorageTx(t, db)
	raw, err := os.ReadFile("../internal/capacity/testdata/b509-notify-hetzner-production-contract.json")
	if err != nil {
		t.Fatal(err)
	}
	var p model.CapacityPolicySpec
	if capacity.DecodeNativeCapacity(json.RawMessage(raw), &p) != nil || p.GuestRetirementBinding == nil {
		t.Fatal("owning B509 policy fixture")
	}
	binding := *p.GuestRetirementBinding
	if binding.GuestSourceCommit != originalReadGuestSource || binding.CoreAuthoritySourceCommit != capacity.GuestD11ProtocolAuthority {
		t.Fatal("historical authority mismatch")
	}
	encoded, _ := json.Marshal(p)
	policyID, workflowID, issueID := uuid.NewString(), uuid.NewString(), uuid.NewString()
	checksum := capacity.BusinessCreationSHA256(encoded)
	ns := "b509-compat-" + uuid.NewString()
	must := func(query string, args ...any) {
		t.Helper()
		if _, e := tx.ExecContext(ctx, query, args...); e != nil {
			t.Fatal(e)
		}
	}
	must(`INSERT INTO public.manifests(id,api_version,kind,namespace,name,version,checksum,spec,active) VALUES($1,'v1','capacity_policy',$2,'unit',1,$3,$4::jsonb,false)`, policyID, ns, checksum, string(encoded))
	must(`INSERT INTO public.manifests(id,api_version,kind,namespace,name,version,checksum,spec,active) VALUES($1,'v1','workflow',$2,'unit',1,$3,'{}'::jsonb,false)`, workflowID, ns, strings.Repeat("a", 64))
	sha := strings.Repeat("b", 64)
	compat := capacity.GuestProtocolCompatibilityMapSHA256()
	issue := map[string]any{"schema": "guest_authority_issue_v1", "issue_kind": "canary_challenge", "issue_id": issueID, "issuer_actual_source_commit": originalReadCoreSource, "protocol_authority_source_commit": capacity.GuestD11ProtocolAuthority, "compatibility_map_sha256": compat, "profile": binding.ProfileManifest.Profile, "policy_id": policyID, "workflow_id": workflowID, "executor_id": "unit-executor", "issued_wire_sha256": sha}
	issueWire, _ := json.Marshal(issue)
	must(`INSERT INTO public.capacity_guest_authority_issues(issue_kind,issue_id,issuer_actual_source_commit,protocol_authority_source_commit,compatibility_map_sha256,profile,policy_id,workflow_id,executor_id,issued_wire_sha256,original_wire,original_record) VALUES('canary_challenge',$1,$2,$3,$4,$5,$6,$7,'unit-executor',$8,$9,$10::jsonb)`, issueID, originalReadCoreSource, capacity.GuestD11ProtocolAuthority, compat, binding.ProfileManifest.Profile, policyID, workflowID, sha, issueWire, string(issueWire))
	pre := model.CapacityGuestOriginalProvisioningPreregistration{PolicyID: policyID, PolicyChecksum: checksum, WorkflowID: workflowID}
	if err = verifyGuestAuthorityIssuerTx(ctx, tx, "canary_challenge", issueID, originalReadCoreSource, binding, pre); err != nil {
		t.Fatal("actual historical B509 compatibility rejected", err)
	}
	changed := binding
	changed.IntentSigningKeyRef += "-foreign"
	if err = verifyGuestAuthorityIssuerTx(ctx, tx, "canary_challenge", issueID, originalReadCoreSource, changed, pre); err == nil {
		t.Fatal("changed original binding accepted")
	}
	pre.PolicyChecksum = strings.Repeat("f", 64)
	if err = verifyGuestAuthorityIssuerTx(ctx, tx, "canary_challenge", issueID, originalReadCoreSource, binding, pre); err == nil {
		t.Fatal("foreign policy checksum accepted")
	}
}
