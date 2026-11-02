package repository

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestCapacityMutationBoundExecutionPostgres(t *testing.T) {
	db, old, a := capacityPostgresFixture(t)
	ctx := context.Background()
	create := func(kind, name string, spec any) model.Manifest {
		raw, _ := json.Marshal(spec)
		m, err := CreateManifestVersion(ctx, db, model.ManifestDocument{APIVersion: "v1", Kind: kind, Metadata: model.ManifestMetadataInput{Namespace: old.Metadata.Namespace, Name: name}, Spec: raw}, fmt.Sprintf("%x", sha256.Sum256(raw)))
		if err != nil {
			t.Fatal(err)
		}
		return m
	}
	wf := create("workflow", "scale-api", map[string]any{"authorization": map[string]any{"rbac": map[string]string{"namespace": old.Metadata.Namespace, "name": "native"}}})
	typ := create("integration_type", "native-type", map[string]any{"provider": "kubernetes"})
	instance := create("integration_instance", "native-instance", map[string]any{"type_ref": model.ManifestSelector{ManifestID: typ.ID.String()}})
	var p model.CapacityPolicySpec
	if json.Unmarshal(old.Spec, &p) != nil {
		t.Fatal("policy")
	}
	p.Dimension = capacity.ReservedPodEnvelopeUnit
	p.LeaseSeconds = 120
	adapter := model.CapacityObservationAdapterBinding{IntegrationInstanceID: instance.ID.String(), InstanceChecksum: instance.Checksum, IntegrationTypeID: typ.ID.String(), TypeChecksum: typ.Checksum}
	p.AssessmentBinding = &model.CapacityBoundAssessmentBinding{Snapshot: model.CapacityHPAMinimumBinding{Mode: capacity.HPAMinimumSnapshotMode, Unit: capacity.ReservedPodEnvelopeUnit, Adapter: adapter, Namespace: "platform", HPAName: "api-hpa", HPAUID: uuid.NewString(), WorkloadName: "api", WorkloadUID: uuid.NewString(), Owner: p.Owner, Profile: "base", ProtectedFloor: p.Floor, MaximumReplicas: p.Ceiling}, Signals: []model.CapacityMetricSignalBinding{{Name: "pressure", Adapter: adapter, BindingName: "pressure", BindingSHA256: strings.Repeat("a", 64)}}}
	p.HPAExecutionBinding = &model.CapacityHPAExecutionBinding{AdapterPrincipalID: "native-adapter", Mode: capacity.HPAExecutionMode, PodTerminationBinding: "api-native", ContainerName: "api", ImageDigest: "sha256:" + strings.Repeat("a", 64), Lanes: []string{"listener", "workers"}, ProjectionDirectory: "/native"}
	policy := create("capacity_policy", "api", p)
	a.Snapshot.ResourceUID = p.AssessmentBinding.Snapshot.HPAUID
	a.Snapshot.WorkloadUID = p.AssessmentBinding.Snapshot.WorkloadUID
	store := CapacityStore{DB: db, ExecutionEnabled: true, WorkflowID: wf.ID, ExecutorID: uuid.NewString()}
	intent, err := store.Assess(ctx, policy, a)
	if err != nil {
		t.Fatal(err)
	}
	intent, err = store.Claim(ctx, policy, intent.Generation, a)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		for _, table := range []string{"capacity_native_commands", "capacity_native_pod_checkpoints", "capacity_native_scope_owners"} {
			if _, err := db.ExecContext(context.Background(), `DELETE FROM public.`+table+` WHERE namespace=$1`, old.Metadata.Namespace); err != nil {
				t.Error(err)
			}
		}
	})
	hpa := model.CapacityHPAEnvelopeResponse{Operation: capacity.ObserveHPAEnvelope, Status: "observed", Observation: model.CapacityHPAEnvelopeObservation{Namespace: "platform", HPAName: "api-hpa", HPAUID: a.Snapshot.ResourceUID, ResourceVersion: a.Snapshot.ResourceVersion, APIGeneration: 1, WorkloadName: "api", WorkloadUID: a.Snapshot.WorkloadUID, WorkloadResourceVersion: a.Snapshot.WorkloadResourceVersion, Owner: p.Owner, EnvelopeGeneration: 7, IdempotencyKey: "previous", MinReplicas: a.Snapshot.Units, MaxReplicas: p.Ceiling, ProtectedFloor: p.Floor, TrackedProtectedFloor: p.Floor, MaximumReplicas: p.Ceiling, MatchedOwner: true, BoundsWithinScope: true, TrackingMatchesScope: true, BoundsMatchTracking: true, DiagnosticOnly: true, ObservedAt: time.Now().UTC().Format(time.RFC3339Nano)}}
	inventory := model.AdapterCapacityPodInventoryResponse{Operation: capacity.ObserveNativePodInventory, Status: "observed", BindingName: "api-native", Namespace: "platform", WorkloadUID: a.Snapshot.WorkloadUID, WorkloadResourceVersion: "10", ListResourceVersion: "1", Complete: true, Pods: []model.NativeTerminationObservation{}, ObservedAt: time.Now().UTC()}
	if err := store.SaveNativePodPlan(ctx, policy, intent, inventory, hpa, nil); err != nil {
		t.Fatal(err)
	}
	intent.NativeHPAGeneration = 8
	intent.NativePodBaseline = []string{}
	no := false
	req := model.CapacityNativeHPARequest{Namespace: "platform", HPAName: "api-hpa", ExpectedUID: a.Snapshot.ResourceUID, ExpectedResourceVersion: a.Snapshot.ResourceVersion, ExpectedWorkloadUID: a.Snapshot.WorkloadUID, ExpectedWorkloadResourceVersion: a.Snapshot.WorkloadResourceVersion, Owner: p.Owner, Generation: 8, IdempotencyKey: "native-private", MinReplicas: intent.Decision.Units, MaxReplicas: p.Ceiling, DryRun: &no, Mode: "upshift"}
	raw, _ := json.Marshal(req)
	var command model.CapacityNativeCommand
	var token string
	newRevocationScope := func(t *testing.T) (model.Manifest, model.CapacityIntent, model.CapacityNativeHPARequest, model.AdapterCapacityPodInventoryResponse) {
		t.Helper()
		encoded, _ := json.Marshal(p)
		var isolated model.CapacityPolicySpec
		if json.Unmarshal(encoded, &isolated) != nil {
			t.Fatal("isolated policy")
		}
		isolated.Domain = "revoke-" + uuid.NewString()
		isolated.TargetIdentity += "/" + isolated.Domain
		isolated.AssessmentBinding.Snapshot.HPAUID, isolated.AssessmentBinding.Snapshot.WorkloadUID = uuid.NewString(), uuid.NewString()
		m := create("capacity_policy", isolated.Domain, isolated)
		fresh := a
		fresh.Snapshot.TargetIdentity = isolated.TargetIdentity
		fresh.Snapshot.ResourceUID, fresh.Snapshot.WorkloadUID = isolated.AssessmentBinding.Snapshot.HPAUID, isolated.AssessmentBinding.Snapshot.WorkloadUID
		i, err := store.Assess(ctx, m, fresh)
		if err != nil {
			t.Fatal(err)
		}
		i, err = store.Claim(ctx, m, i.Generation, fresh)
		if err != nil {
			t.Fatal(err)
		}
		nativeHPA, nativeInventory := hpa, inventory
		nativeHPA.Observation.HPAUID, nativeHPA.Observation.WorkloadUID = fresh.Snapshot.ResourceUID, fresh.Snapshot.WorkloadUID
		nativeInventory.WorkloadUID = fresh.Snapshot.WorkloadUID
		if err := store.SaveNativePodPlan(ctx, m, i, nativeInventory, nativeHPA, nil); err != nil {
			t.Fatal(err)
		}
		i.NativeHPAGeneration, i.NativePodBaseline = 8, []string{}
		r := req
		r.ExpectedUID, r.ExpectedWorkloadUID, r.MinReplicas = fresh.Snapshot.ResourceUID, fresh.Snapshot.WorkloadUID, i.Decision.Units
		return m, i, r, nativeInventory
	}
	t.Run("finite_unredeemed_permission_budget", func(t *testing.T) {
		m, i, r, nativeInventory := newRevocationScope(t)
		for sequence := 1; sequence <= 4; sequence++ {
			r.ExpectedResourceVersion = fmt.Sprint(sequence + 20)
			body, _ := json.Marshal(r)
			c, permission, err := store.IssueNativeCommand(ctx, m, i, capacity.EnsureBoundHPAEnvelope, r.ExpectedUID, body)
			if err != nil || c.Sequence != sequence {
				t.Fatal("bounded sequence missing", sequence, err)
			}
			refused, err := store.RevokeUnredeemedNativeCommand(ctx, m, i, c.CommandID)
			if err != nil || !refused {
				t.Fatal("unredeemed sequence retained authority", err)
			}
			if _, err := store.RedeemNativeCommand(ctx, "native-adapter", model.CapacityNativeAuthorityRedeemRequest{AuthorityToken: permission, IntegrationInstanceID: instance.ID.String(), IntegrationTypeID: typ.ID.String(), Capability: capacity.EnsureBoundHPAEnvelope, RequestSHA256: c.RequestSHA256}); err == nil {
				t.Fatal("history token remained redeemable")
			}
		}
		body, _ := json.Marshal(r)
		if _, _, err := store.IssueNativeCommand(ctx, m, i, capacity.EnsureBoundHPAEnvelope, r.ExpectedUID, body); err == nil {
			t.Fatal("fifth phase permission escaped the fixed budget")
		}
		commands, _, err := store.NativeLedger(ctx, m, i)
		if err != nil || len(commands) != 4 || store.CompleteNativeExecution(ctx, m, i, nativeInventory) == nil {
			t.Fatal("refusal history disappeared or became native completion", err)
		}
	})
	t.Run("redemption_and_revocation_share_one_fence", func(t *testing.T) {
		m, i, r, _ := newRevocationScope(t)
		body, _ := json.Marshal(r)
		c, permission, err := store.IssueNativeCommand(ctx, m, i, capacity.EnsureBoundHPAEnvelope, r.ExpectedUID, body)
		if err != nil {
			t.Fatal(err)
		}
		start := make(chan struct{})
		var wg sync.WaitGroup
		var redeemed, refused atomic.Int32
		wg.Add(2)
		go func() {
			defer wg.Done()
			<-start
			if _, err := store.RedeemNativeCommand(ctx, "native-adapter", model.CapacityNativeAuthorityRedeemRequest{AuthorityToken: permission, IntegrationInstanceID: instance.ID.String(), IntegrationTypeID: typ.ID.String(), Capability: capacity.EnsureBoundHPAEnvelope, RequestSHA256: c.RequestSHA256}); err == nil {
				redeemed.Add(1)
			}
		}()
		go func() {
			defer wg.Done()
			<-start
			if revoked, err := store.RevokeUnredeemedNativeCommand(ctx, m, i, c.CommandID); err != nil {
				t.Error(err)
			} else if revoked {
				refused.Add(1)
			}
		}()
		close(start)
		wg.Wait()
		if redeemed.Load()+refused.Load() != 1 {
			t.Fatal("redemption and retry authority both won", redeemed.Load(), refused.Load())
		}
		commands, _, err := store.NativeLedger(ctx, m, i)
		if err != nil || len(commands) != 1 || (redeemed.Load() == 1 && (commands[0].State != "redeemed" || commands[0].AttemptID == uuid.Nil || commands[0].RedeemedBy != "native-adapter")) || (refused.Load() == 1 && (commands[0].State != "refused_no_redemption" || commands[0].AttemptID != uuid.Nil || commands[0].RedeemedBy != "")) {
			t.Fatal("durable fence differs from the winning authority", err)
		}
	})
	t.Run("unredeemed_token_revocation_and_history", func(t *testing.T) {
		first, permission, err := store.IssueNativeCommand(ctx, policy, intent, capacity.EnsureBoundHPAEnvelope, req.ExpectedUID, raw)
		if err != nil {
			t.Fatal(err)
		}
		refused, err := store.RevokeUnredeemedNativeCommand(ctx, policy, intent, first.CommandID)
		if err != nil || !refused {
			t.Fatal("unredeemed permission was not atomically revoked", err)
		}
		if _, err := store.RedeemNativeCommand(ctx, "native-adapter", model.CapacityNativeAuthorityRedeemRequest{AuthorityToken: permission, IntegrationInstanceID: instance.ID.String(), IntegrationTypeID: typ.ID.String(), Capability: capacity.EnsureBoundHPAEnvelope, RequestSHA256: first.RequestSHA256}); err == nil {
			t.Fatal("late revoked token acquired native permission")
		}
		commands, _, err := store.NativeLedger(ctx, policy, intent)
		if err != nil || len(commands) != 1 || commands[0].State != "refused_no_redemption" || commands[0].CommandID != first.CommandID || commands[0].RequestSHA256 != first.RequestSHA256 || commands[0].AuthorityTokenSHA256 != first.AuthorityTokenSHA256 || commands[0].AttemptID != uuid.Nil || commands[0].RedeemedBy != "" {
			t.Fatal("revocation replaced history or fabricated an attempt", err)
		}
		if store.CompleteNativeExecution(ctx, policy, intent, inventory) == nil {
			t.Fatal("no native write became completion")
		}
	})
	t.Run("single_send_and_canonical_request", func(t *testing.T) {
		command, token, err = store.IssueNativeCommand(ctx, policy, intent, capacity.EnsureBoundHPAEnvelope, req.ExpectedUID, raw)
		if err != nil {
			t.Fatal(err)
		}
		if command.Sequence != 2 {
			t.Fatal("revoked history did not bound the new sequence")
		}
		if _, _, err := store.IssueNativeCommand(ctx, policy, intent, capacity.EnsureBoundHPAEnvelope, req.ExpectedUID, raw); err == nil {
			t.Fatal("command sent twice")
		}
	})
	redeem := model.CapacityNativeAuthorityRedeemRequest{AuthorityToken: token, IntegrationInstanceID: instance.ID.String(), IntegrationTypeID: typ.ID.String(), Capability: capacity.EnsureBoundHPAEnvelope, RequestSHA256: command.RequestSHA256}
	t.Run("principal_scope_and_single_redemption", func(t *testing.T) {
		bad := redeem
		bad.RequestSHA256 = strings.Repeat("b", 64)
		if _, err := store.RedeemNativeCommand(ctx, "native-adapter", bad); err == nil {
			t.Fatal("foreign request")
		}
		if _, err := store.RedeemNativeCommand(ctx, "foreign", redeem); err == nil {
			t.Fatal("foreign principal")
		}
		var successes atomic.Int32
		var wg sync.WaitGroup
		for i := 0; i < 8; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if _, err := store.RedeemNativeCommand(ctx, "native-adapter", redeem); err == nil {
					successes.Add(1)
				}
			}()
		}
		wg.Wait()
		if successes.Load() != 1 {
			t.Fatal("one-use redemption", successes.Load())
		}
		if refused, err := store.RevokeUnredeemedNativeCommand(ctx, policy, intent, command.CommandID); err != nil || refused {
			t.Fatal("redeemed lifetime acquired retry authority", err)
		}
	})
	t.Run("lost_reply_blocks_new_write_and_terminal", func(t *testing.T) {
		if err := store.MarkNativeCommandUncertain(ctx, command.CommandID); err != nil {
			t.Fatal(err)
		}
		if store.CompleteNativeExecution(ctx, policy, intent, inventory) == nil {
			t.Fatal("uncertain command became terminal")
		}
		if _, _, err := store.IssueNativeCommand(ctx, policy, intent, capacity.EnsureBoundHPAEnvelope, req.ExpectedUID, raw); err == nil {
			t.Fatal("uncertain send reissued")
		}
	})
	t.Run("native_readback_and_restart_recovery", func(t *testing.T) {
		wrong := hpa
		wrong.Observation.MinReplicas = intent.Decision.Units
		if store.ConfirmNativeCommand(ctx, policy, intent, command.CommandID, wrong) == nil {
			t.Fatal("wrong native generation confirmed")
		}
		hpa.Observation.MinReplicas = intent.Decision.Units
		hpa.Observation.EnvelopeGeneration = req.Generation
		hpa.Observation.IdempotencyKey = req.IdempotencyKey
		hpa.Observation.ObservedAt = time.Now().UTC().Format(time.RFC3339Nano)
		if err := store.ConfirmNativeCommand(ctx, policy, intent, command.CommandID, hpa); err != nil {
			t.Fatal(err)
		}
		if err := store.CompleteNativeExecution(ctx, policy, intent, inventory); err != nil {
			t.Fatal(err)
		}
		done, err := store.Observe(ctx, policy)
		if err != nil || done.Phase != "native_completed" || done.Dimension != capacity.ReservedPodEnvelopeUnit {
			t.Fatal("bounded reserved proof missing", done, err)
		}
	})
}
