package repository

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

type protectRecoveryPG struct {
	db              *sql.DB
	ordinary, human CapacityStore
	policy          model.Manifest
	p               model.CapacityPolicySpec
	intent          model.CapacityIntent
	cp              model.CapacityNativePodCheckpoint
	boot            model.AdapterCapacityPodAdmissionResponse
	b               model.CapacityUnredeemedProtectRecoveryBinding
	originals       [][]byte
}

func protectRecoveryWorkflow(b model.CapacityUnredeemedProtectRecoveryBinding) map[string]any {
	return map[string]any{"trigger": map[string]any{"mode": "manual"}, "dispatch_mode": "sync", "authorization": map[string]any{"rbac": map[string]any{"namespace": "fixed", "name": "named-human"}}, "steps": []any{map[string]any{"id": "recover-once", "timeout_seconds": 90, "retry": map[string]any{"max_attempts": 1}, "use": map[string]any{"kind": "yggdrasil", "operation": capacity.RecoverUnredeemedNativeProtect}, "with": map[string]any{"binding": b, "confirmation": "{{ inputs.confirmation }}"}}}}
}

func protectRecoveryPGSetup(t *testing.T) protectRecoveryPG {
	t.Helper()
	db, ordinary, policy, p, intent := nativeLifetimePostgresFixture(t)
	boot := nativeLifetimeBoot(p)
	cp, err := ordinary.RegisterNativeLifetime(context.Background(), policy, intent, boot)
	if err != nil {
		t.Fatal(err)
	}
	var ch model.NativePodTerminationChallenge
	if json.Unmarshal(cp.Challenge, &ch) != nil {
		t.Fatal("challenge")
	}
	no := false
	req := model.AdapterEnsureCapacityPodDrainRequest{BindingName: p.HPAExecutionBinding.PodTerminationBinding, PodName: cp.PodName, ExpectedPodUID: cp.PodUID, ExpectedPodGeneration: cp.PodGeneration, ExpectedPodResourceVersion: cp.PodResourceVersion, ExpectedContainerID: cp.ContainerID, ExpectedContainerStartedAt: cp.ContainerStartedAt, ExpectedRestartCount: cp.RestartCount, Challenge: ch, Phase: "protect", DryRun: &no}
	raw, _ := json.Marshal(req)
	f := protectRecoveryPG{db: db, ordinary: ordinary, policy: policy, p: p, intent: intent, cp: cp, boot: boot}
	f.b = model.CapacityUnredeemedProtectRecoveryBinding{Schema: capacity.UnredeemedProtectRecoverySchema, PolicyID: policy.ID.String(), PolicyChecksum: policy.Checksum, OperatorID: uuid.NewString(), PodUID: cp.PodUID, ExpectedIntentGeneration: intent.Generation, ExpectedIntentFencingToken: intent.FencingToken, Confirmation: "RECOVER ONE PROVEN UNREDEEMED PROTECT"}
	for n := 0; n < 4; n++ {
		c, token, e := ordinary.IssueNativeCommand(context.Background(), policy, intent, capacity.EnsureNativePodDrain, cp.PodUID, raw)
		if e != nil || c.Sequence != n+1 {
			t.Fatal("ordinary sequence", n, e)
		}
		refused, e := ordinary.RevokeUnredeemedNativeCommand(context.Background(), policy, intent, c.CommandID)
		if e != nil || !refused {
			t.Fatal("atomic original revocation", e)
		}
		if _, e = ordinary.RedeemNativeCommand(context.Background(), p.HPAExecutionBinding.AdapterPrincipalID, model.CapacityNativeAuthorityRedeemRequest{AuthorityToken: token, IntegrationInstanceID: c.Adapter.IntegrationInstanceID, IntegrationTypeID: c.Adapter.IntegrationTypeID, Capability: c.Operation, RequestSHA256: c.RequestSHA256}); e == nil {
			t.Fatal("late revoked original redeemed")
		}
		var record []byte
		if e = db.QueryRow(`SELECT command_record FROM public.capacity_native_commands WHERE id=$1`, c.CommandID).Scan(&record); e != nil {
			t.Fatal(e)
		}
		f.originals = append(f.originals, record)
		f.b.Commands = append(f.b.Commands, model.CapacityUnredeemedProtectReference{CommandID: c.CommandID.String(), RecordSHA256: nativeCanonicalArchiveSHA(record)})
	}
	if _, _, err = ordinary.IssueNativeCommand(context.Background(), policy, intent, capacity.EnsureNativePodDrain, cp.PodUID, raw); err == nil {
		t.Fatal("ordinary four phase cap relaxed")
	}
	if err = db.QueryRow(`SELECT checkpoint_record FROM public.capacity_native_lifetimes WHERE pod_uid=$1`, cp.PodUID).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	f.b.CheckpointSHA256 = nativeCanonicalArchiveSHA(raw)
	// Expire only a fixture's mutable lease, not command deadlines/history.
	if _, err = db.Exec(`UPDATE public.capacity_intents SET intent=jsonb_set(intent,'{lease_expires_at}',to_jsonb($2::text)) WHERE namespace=$1`, policy.Metadata.Namespace, time.Now().UTC().Add(-time.Second).Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
	wf := abortPGCreate(t, db, policy.Metadata.Namespace, "workflow", "recover-protect", protectRecoveryWorkflow(f.b))
	f.human = CapacityStore{DB: db, ExecutionEnabled: true, AdmissionOnly: true, WorkflowID: wf.ID, ExecutorID: uuid.NewString(), ExecutorPowerOperator: f.b.OperatorID}
	return f
}

func (f protectRecoveryPG) issue(t *testing.T) (model.CapacityIntent, model.CapacityNativeCommand, string, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 80*time.Second)
	defer cancel()
	return f.human.IssueUnredeemedProtectRecovery(ctx, f.policy, f.b, f.boot)
}

func (f protectRecoveryPG) unchanged(t *testing.T) {
	t.Helper()
	for i, ref := range f.b.Commands {
		var raw []byte
		if err := f.db.QueryRow(`SELECT command_record FROM public.capacity_native_commands WHERE id=$1`, ref.CommandID).Scan(&raw); err != nil || !bytes.Equal(raw, f.originals[i]) {
			t.Fatal("original permission changed", i, err)
		}
	}
}

func TestCapacityNativeProtectRecoveryPostgres(t *testing.T) {
	t.Run("one_child_then_normal_admission", func(t *testing.T) {
		f := protectRecoveryPGSetup(t)
		before, _ := json.Marshal(f.cp)
		next, c, token, err := f.issue(t)
		if err != nil || next.Generation != f.intent.Generation+1 || next.FencingToken != f.intent.FencingToken+1 || c.Sequence != 1 || c.WorkflowID != f.human.WorkflowID || c.WorkflowID == f.ordinary.WorkflowID || c.ProtectRecovery == nil || token == "" {
			t.Fatal("separate one-use child", err)
		}
		var raw []byte
		if err = f.db.QueryRow(`SELECT checkpoint_record FROM public.capacity_native_lifetimes WHERE pod_uid=$1`, f.cp.PodUID).Scan(&raw); err != nil || nativeCanonicalArchiveSHA(raw) != nativeCanonicalArchiveSHA(before) {
			t.Fatal("child rewrote checkpoint", err)
		}
		nativeLifetimeRedeem(t, f.ordinary, f.p, c, token)
		after := model.AdapterCapacityPodTerminationResponse{Operation: capacity.ObserveNativePodTermination, Status: "observed", Observation: f.boot.Observation}
		after.Observation.PodResourceVersion = "11"
		after.Observation.ObservedAt = time.Now().UTC()
		refused, err := f.human.SettleUnredeemedProtectRecovery(context.Background(), f.policy, next, c, &after)
		if err != nil || refused {
			t.Fatal("readback settlement", err)
		}
		if _, _, _, err = f.issue(t); err == nil {
			t.Fatal("same recovery repeated")
		}
		ordinary := f.ordinary
		// A distinct ordinary invocation reacquires the expired mutable lease
		// through its normal admission producer; it does not impersonate the
		// human workflow or reuse that executor.
		if _, err = f.db.Exec(`UPDATE public.capacity_intents SET intent=jsonb_set(intent,'{lease_expires_at}',to_jsonb($2::text)) WHERE namespace=$1`, f.policy.Metadata.Namespace, time.Now().UTC().Add(-time.Second).Format(time.RFC3339Nano)); err != nil {
			t.Fatal(err)
		}
		ordinary.ExecutorID = uuid.NewString()
		snapshot := f.p.AssessmentBinding.Snapshot
		hpa := model.CapacityHPAEnvelopeResponse{Operation: capacity.ObserveHPAEnvelope, Status: "observed", Observation: model.CapacityHPAEnvelopeObservation{Namespace: snapshot.Namespace, HPAName: snapshot.HPAName, HPAUID: snapshot.HPAUID, ResourceVersion: "2", WorkloadName: snapshot.WorkloadName, WorkloadUID: snapshot.WorkloadUID, WorkloadResourceVersion: "10", Owner: f.p.Owner, EnvelopeGeneration: 7, IdempotencyKey: "previous", MinReplicas: 4, MaxReplicas: f.p.Ceiling, ProtectedFloor: f.p.Floor, TrackedProtectedFloor: f.p.Floor, MaximumReplicas: f.p.Ceiling, MatchedOwner: true, BoundsWithinScope: true, TrackingMatchesScope: true, BoundsMatchTracking: true, DiagnosticOnly: true, ObservedAt: time.Now().UTC().Format(time.RFC3339Nano)}}
		next, err = ordinary.AcquireNativeAdmissionExecution(context.Background(), f.policy, hpa)
		if err != nil || next.LeaseExecutorID != ordinary.ExecutorID {
			t.Fatal("normal new admission invocation", err)
		}
		if _, _, err = ordinary.IssueNativeCommand(context.Background(), f.policy, next, capacity.EnsureNativePodDrain, f.cp.PodUID, c.Request); err == nil {
			t.Fatal("generic protect retried fifth permission")
		}
		actual := f.boot
		actual.Observation.PodResourceVersion, actual.Observation.AdmissionReady = "11", true
		actual.Observation.ObservedAt, actual.Admission.ObservedAt = time.Now().UTC(), time.Now().UTC()
		var challenge model.NativePodTerminationChallenge
		if json.Unmarshal(f.cp.Challenge, &challenge) != nil {
			t.Fatal("origin")
		}
		actual.Admission.State, actual.Admission.Challenge, actual.Admission.ChallengeSHA256 = "roots_open", &challenge, f.cp.OriginChallengeSHA256
		if err = ordinary.AcknowledgeNativeProjection(context.Background(), f.policy, next, f.cp.PodUID, actual); err != nil {
			t.Fatal("normal projection after recovery", err)
		}
		no := false
		admit := model.AdapterEnsureCapacityPodDrainRequest{BindingName: f.p.HPAExecutionBinding.PodTerminationBinding, PodName: f.cp.PodName, ExpectedPodUID: f.cp.PodUID, ExpectedPodGeneration: f.cp.PodGeneration, ExpectedPodResourceVersion: "11", ExpectedContainerID: f.cp.ContainerID, ExpectedContainerStartedAt: f.cp.ContainerStartedAt, ExpectedRestartCount: f.cp.RestartCount, Challenge: challenge, Phase: "admit", DryRun: &no}
		admitRaw, _ := json.Marshal(admit)
		admitted, admitToken, err := ordinary.IssueNativeCommand(context.Background(), f.policy, next, capacity.EnsureNativePodDrain, f.cp.PodUID, admitRaw)
		if err != nil || admitted.Sequence != 1 || admitted.ProtectRecovery != nil {
			t.Fatal("normal admission phase", err)
		}
		nativeLifetimeRedeem(t, ordinary, f.p, admitted, admitToken)
		if err = ordinary.ConfirmNativeCommand(context.Background(), f.policy, next, admitted.CommandID, actual); err != nil {
			t.Fatal("normal actual roots/readiness", err)
		}
		f.unchanged(t)
	})
	t.Run("unredeemed_child_is_terminal", func(t *testing.T) {
		f := protectRecoveryPGSetup(t)
		next, c, _, err := f.issue(t)
		if err != nil {
			t.Fatal(err)
		}
		refused, err := f.human.SettleUnredeemedProtectRecovery(context.Background(), f.policy, next, c, nil)
		if err != nil || !refused {
			t.Fatal("child not atomically revoked", err)
		}
		if _, _, _, err = f.issue(t); err == nil {
			t.Fatal("terminal child retried")
		}
		f.unchanged(t)
	})
	t.Run("redeemed_without_readback_holds", func(t *testing.T) {
		f := protectRecoveryPGSetup(t)
		next, c, token, err := f.issue(t)
		if err != nil {
			t.Fatal(err)
		}
		nativeLifetimeRedeem(t, f.ordinary, f.p, c, token)
		if _, err = f.human.SettleUnredeemedProtectRecovery(context.Background(), f.policy, next, c, nil); err == nil {
			t.Fatal("unknown child certified")
		}
		var state string
		if err = f.db.QueryRow(`SELECT state FROM public.capacity_native_commands WHERE id=$1`, c.CommandID).Scan(&state); err != nil || state != "uncertain" {
			t.Fatal("uncertainty lost", err)
		}
		if _, _, _, err = f.issue(t); err == nil {
			t.Fatal("unknown child resent")
		}
		f.unchanged(t)
	})
}

func TestCapacityNativeProtectRecoveryConcurrencyPostgres(t *testing.T) {
	f := protectRecoveryPGSetup(t)
	var wg sync.WaitGroup
	var issued atomic.Int32
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, _, _, err := f.issue(t); err == nil {
				issued.Add(1)
			}
		}()
	}
	wg.Wait()
	var count int
	if err := f.db.QueryRow(`SELECT count(*) FROM public.capacity_native_command_identities WHERE subject_uid=$1`, f.cp.PodUID).Scan(&count); err != nil || count != 5 || issued.Load() != 1 {
		t.Fatal("atomic child race", count, issued.Load(), err)
	}
	f.unchanged(t)
}

func TestCapacityNativeProtectRecoveryRefusalsPostgres(t *testing.T) {
	for _, name := range []string{"machine", "different_human", "policy", "generation", "fence", "checkpoint_hash", "command_hash", "duplicate_id", "order", "missing_original", "redeemed_original", "unknown_original", "native_readback", "changed_cid", "changed_start", "changed_nonce", "empty_rv", "stale_sdk", "roots_open", "restarted", "live_lease", "fifth_identity_without_body", "workflow_async", "workflow_retry", "workflow_binding_template", "orphan_archive_reference", "checkpoint_receipt", "checkpoint_root_ack"} {
		t.Run(name, func(t *testing.T) {
			f := protectRecoveryPGSetup(t)
			switch name {
			case "machine":
				f.human.ExecutorPowerOperator = ""
			case "different_human":
				f.human.ExecutorPowerOperator = uuid.NewString()
			case "policy":
				f.b.PolicyChecksum = "other"
			case "generation":
				f.b.ExpectedIntentGeneration++
			case "fence":
				f.b.ExpectedIntentFencingToken++
			case "checkpoint_hash":
				f.b.CheckpointSHA256 = nativeArchiveSHA([]byte("other"))
			case "command_hash":
				f.b.Commands[0].RecordSHA256 = nativeArchiveSHA([]byte("other"))
			case "duplicate_id":
				f.b.Commands[3] = f.b.Commands[0]
			case "order":
				f.b.Commands[0], f.b.Commands[1] = f.b.Commands[1], f.b.Commands[0]
			case "changed_cid":
				f.boot.Observation.ContainerID = "containerd://other"
			case "changed_start":
				at := f.cp.ContainerStartedAt.Add(time.Second)
				f.boot.Observation.StartedAt = &at
			case "changed_nonce":
				f.boot.Admission.ProcessNonce = uuid.NewString()
			case "empty_rv":
				f.boot.Observation.PodResourceVersion = ""
			case "stale_sdk":
				f.boot.Admission.ObservedAt = time.Now().Add(-time.Hour)
			case "roots_open":
				f.boot.Admission.State = "roots_open"
			case "restarted":
				f.boot.Observation.RestartCount++
			case "live_lease":
				if _, err := f.db.Exec(`UPDATE public.capacity_intents SET intent=jsonb_set(intent,'{lease_expires_at}',to_jsonb($2::text)) WHERE namespace=$1`, f.policy.Metadata.Namespace, time.Now().UTC().Add(time.Hour).Format(time.RFC3339Nano)); err != nil {
					t.Fatal(err)
				}
			case "missing_original":
				if _, err := f.db.Exec(`DELETE FROM public.capacity_native_commands WHERE id=$1`, f.b.Commands[0].CommandID); err != nil {
					t.Fatal(err)
				}
			case "fifth_identity_without_body":
				if _, err := f.db.Exec(`INSERT INTO public.capacity_native_command_identities(id,namespace,environment,domain,dimension,generation,operation,subject_uid,phase,sequence,authority_token_sha256,request_sha256) SELECT $2,namespace,environment,domain,dimension,generation+1,operation,subject_uid,phase,1,$3,request_sha256 FROM public.capacity_native_command_identities WHERE id=$1`, f.b.Commands[0].CommandID, uuid.New(), nativeArchiveSHA([]byte(uuid.NewString()))); err != nil {
					t.Fatal(err)
				}
			case "redeemed_original", "unknown_original", "native_readback":
				var c model.CapacityNativeCommand
				if json.Unmarshal(f.originals[0], &c) != nil {
					t.Fatal("original")
				}
				if name == "redeemed_original" {
					c.State, c.RedeemedBy, c.AttemptID = "redeemed", c.AdapterPrincipalID, uuid.New()
				}
				if name == "unknown_original" {
					c.State = "uncertain"
				}
				if name == "native_readback" {
					c.NativeReadback = json.RawMessage(`{}`)
				}
				raw, _ := json.Marshal(c)
				if _, err := f.db.Exec(`UPDATE public.capacity_native_commands SET state=$2,command_record=$3 WHERE id=$1`, c.CommandID, c.State, raw); err != nil {
					t.Fatal(err)
				}
				f.b.Commands[0].RecordSHA256 = nativeCanonicalArchiveSHA(raw)
			case "orphan_archive_reference":
				id := uuid.New()
				if _, err := f.db.Exec(`INSERT INTO public.capacity_native_command_identities(id,namespace,environment,domain,dimension,generation,operation,subject_uid,phase,sequence,authority_token_sha256,request_sha256) SELECT $2,namespace,environment,domain,dimension,generation,operation,$3,phase,1,$4,request_sha256 FROM public.capacity_native_command_identities WHERE id=$1`, f.b.Commands[0].CommandID, id, uuid.NewString(), nativeArchiveSHA([]byte(uuid.NewString()))); err != nil {
					t.Fatal(err)
				}
				if _, err := f.db.Exec(`INSERT INTO public.capacity_native_command_archive(id,record_sha256,command_record)VALUES($1,$2,$3)`, id, nativeCanonicalArchiveSHA(f.originals[0]), f.originals[0]); err != nil {
					t.Fatal(err)
				}
			case "checkpoint_receipt", "checkpoint_root_ack":
				cp := f.cp
				if name == "checkpoint_receipt" {
					cp.NativeTerminationReceipt = json.RawMessage(`{}`)
				} else {
					cp.RootAcknowledgement = json.RawMessage(`{}`)
				}
				raw, _ := json.Marshal(cp)
				if _, err := f.db.Exec(`UPDATE public.capacity_native_lifetimes SET checkpoint_record=$2 WHERE pod_uid=$1`, cp.PodUID, raw); err != nil {
					t.Fatal(err)
				}
				f.b.CheckpointSHA256 = nativeCanonicalArchiveSHA(raw)
			case "workflow_async", "workflow_retry", "workflow_binding_template":
				wf := protectRecoveryWorkflow(f.b)
				if name == "workflow_async" {
					wf["dispatch_mode"] = "async"
				}
				step := wf["steps"].([]any)[0].(map[string]any)
				if name == "workflow_retry" {
					step["retry"] = map[string]any{"max_attempts": 2}
				}
				if name == "workflow_binding_template" {
					step["with"].(map[string]any)["binding"] = "{{ inputs.binding }}"
				}
				x := abortPGCreate(t, f.db, f.policy.Metadata.Namespace, "workflow", "wrong-recovery", wf)
				f.human.WorkflowID = x.ID
			}
			if name != "workflow_async" && name != "workflow_retry" && name != "workflow_binding_template" {
				x := abortPGCreate(t, f.db, f.policy.Metadata.Namespace, "workflow", "bound-negative", protectRecoveryWorkflow(f.b))
				f.human.WorkflowID = x.ID
			}
			if _, _, _, err := f.issue(t); err == nil {
				t.Fatal("unsafe child issued")
			}
			var children int
			if err := f.db.QueryRow(`SELECT count(*) FROM public.capacity_native_commands WHERE subject_uid=$1 AND generation>$2`, f.cp.PodUID, f.intent.Generation).Scan(&children); err != nil || children != 0 {
				t.Fatal("refusal left a child", err)
			}
		})
	}
}
