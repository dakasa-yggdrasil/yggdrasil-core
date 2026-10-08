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
	t.Run("single_send_and_canonical_request", func(t *testing.T) {
		command, token, err = store.IssueNativeCommand(ctx, policy, intent, capacity.EnsureBoundHPAEnvelope, req.ExpectedUID, raw)
		if err != nil {
			t.Fatal(err)
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
