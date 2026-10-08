package repository

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

// These PostgreSQL cases qualify the durable ledger and permissions only.
// Actual SDK/native controller execution is a separate mandatory KinD gate.
func nativeLifetimePostgresFixture(t *testing.T) (*sql.DB, CapacityStore, model.Manifest, model.CapacityPolicySpec, model.CapacityIntent) {
	t.Helper()
	db, base, _ := capacityPostgresFixture(t)
	ctx := context.Background()
	create := func(kind, name string, spec any) model.Manifest {
		raw, err := json.Marshal(spec)
		if err != nil {
			t.Fatal(err)
		}
		m, err := CreateManifestVersion(ctx, db, model.ManifestDocument{APIVersion: "v1", Kind: kind, Metadata: model.ManifestMetadataInput{Namespace: base.Metadata.Namespace, Name: name}, Spec: raw}, fmt.Sprintf("%x", sha256.Sum256(raw)))
		if err != nil {
			t.Fatal(err)
		}
		return m
	}
	wf := create("workflow", "admit-api", map[string]any{"authorization": map[string]any{"rbac": map[string]string{"namespace": base.Metadata.Namespace, "name": "native"}}})
	create("workflow", "scale-api", map[string]any{"authorization": map[string]any{"rbac": map[string]string{"namespace": base.Metadata.Namespace, "name": "native"}}})
	typ := create("integration_type", "native-type", map[string]any{"provider": "kubernetes"})
	instance := create("integration_instance", "native-instance", map[string]any{"type_ref": model.ManifestSelector{ManifestID: typ.ID.String()}})
	var p model.CapacityPolicySpec
	if json.Unmarshal(base.Spec, &p) != nil {
		t.Fatal("policy")
	}
	p.Dimension, p.LeaseSeconds = capacity.ReservedPodEnvelopeUnit, 120
	binding := model.CapacityObservationAdapterBinding{IntegrationInstanceID: instance.ID.String(), InstanceChecksum: instance.Checksum, IntegrationTypeID: typ.ID.String(), TypeChecksum: typ.Checksum}
	p.AssessmentBinding = &model.CapacityBoundAssessmentBinding{Snapshot: model.CapacityHPAMinimumBinding{Mode: capacity.HPAMinimumSnapshotMode, Unit: capacity.ReservedPodEnvelopeUnit, Adapter: binding, Namespace: "platform", HPAName: "api-hpa", HPAUID: uuid.NewString(), WorkloadName: "api", WorkloadUID: uuid.NewString(), Owner: p.Owner, Profile: "base", ProtectedFloor: p.Floor, MaximumReplicas: p.Ceiling}, Signals: []model.CapacityMetricSignalBinding{{Name: "pressure", Adapter: binding, BindingName: "pressure", BindingSHA256: strings.Repeat("a", 64)}}}
	p.HPAExecutionBinding = &model.CapacityHPAExecutionBinding{AdapterPrincipalID: "native-adapter", Mode: capacity.HPALifetimeExecutionMode, PodTerminationBinding: "api-native", ContainerName: "api", ImageDigest: "sha256:" + strings.Repeat("a", 64), Lanes: []string{"listener", "workers"}, ProjectionDirectory: "/native", AdmissionMode: "process_v2", AdmissionPort: 8080, AdmissionWorkflow: model.ManifestSelector{Namespace: base.Metadata.Namespace, Name: "admit-api"}}
	policy := create("capacity_policy", "api", p)
	store := CapacityStore{DB: db, ExecutionEnabled: true, AdmissionOnly: true, WorkflowID: wf.ID, ExecutorID: uuid.NewString()}
	hpa := model.CapacityHPAEnvelopeResponse{Operation: capacity.ObserveHPAEnvelope, Status: "observed", Observation: model.CapacityHPAEnvelopeObservation{Namespace: "platform", HPAName: "api-hpa", HPAUID: p.AssessmentBinding.Snapshot.HPAUID, ResourceVersion: "1", APIGeneration: 0, WorkloadName: "api", WorkloadUID: p.AssessmentBinding.Snapshot.WorkloadUID, WorkloadResourceVersion: "10", Owner: p.Owner, EnvelopeGeneration: 7, IdempotencyKey: "previous", MinReplicas: 4, MaxReplicas: p.Ceiling, ProtectedFloor: p.Floor, TrackedProtectedFloor: p.Floor, MaximumReplicas: p.Ceiling, MatchedOwner: true, BoundsWithinScope: true, TrackingMatchesScope: true, BoundsMatchTracking: true, DiagnosticOnly: true, ObservedAt: time.Now().UTC().Format(time.RFC3339Nano)}}
	intent, err := store.AcquireNativeAdmissionExecution(ctx, policy, hpa)
	if err != nil {
		t.Fatal(err)
	}
	return db, store, policy, p, intent
}

func nativeLifetimeBoot(p model.CapacityPolicySpec) model.AdapterCapacityPodAdmissionResponse {
	start := time.Now().UTC().Add(-time.Minute)
	pod := model.NativeTerminationObservation{BindingName: p.HPAExecutionBinding.PodTerminationBinding, Namespace: p.AssessmentBinding.Snapshot.Namespace, PodName: "api-" + uuid.NewString(), PodUID: uuid.NewString(), PodResourceVersion: "10", PodGeneration: 0, WorkloadUID: p.AssessmentBinding.Snapshot.WorkloadUID, WorkloadResourceVersion: "10", ContainerName: "api", ContainerID: "containerd://" + uuid.NewString(), ImageID: "fixture@" + p.HPAExecutionBinding.ImageDigest, ImageDigest: p.HPAExecutionBinding.ImageDigest, StartedAt: &start, Protected: true, ContainerState: "running", State: "running", Reason: "exact_native_admission_lifetime", ObservedAt: time.Now().UTC()}
	frame := model.NativeProcessAdmissionObservation{SchemaVersion: 2, Namespace: pod.Namespace, PodName: pod.PodName, PodUID: pod.PodUID, ImageDigest: pod.ImageDigest, LaneRosterSHA256: capacity.NativeRosterDigest(p.HPAExecutionBinding.Lanes), ProcessNonce: uuid.NewString(), ObservedAt: time.Now().UTC(), State: "waiting_projection"}
	return model.AdapterCapacityPodAdmissionResponse{Operation: capacity.ObserveNativePodAdmission, Status: "observed", Observation: pod, Admission: frame}
}

func nativeLifetimeRedeem(t *testing.T, store CapacityStore, p model.CapacityPolicySpec, command model.CapacityNativeCommand, token string) {
	t.Helper()
	binding := p.AssessmentBinding.Snapshot.Adapter
	if _, err := store.RedeemNativeCommand(context.Background(), p.HPAExecutionBinding.AdapterPrincipalID, model.CapacityNativeAuthorityRedeemRequest{AuthorityToken: token, IntegrationInstanceID: binding.IntegrationInstanceID, IntegrationTypeID: binding.IntegrationTypeID, Capability: command.Operation, RequestSHA256: command.RequestSHA256}); err != nil {
		t.Fatal(err)
	}
}

func nativeLifetimeProtect(t *testing.T, store CapacityStore, policy model.Manifest, p model.CapacityPolicySpec, intent model.CapacityIntent, boot model.AdapterCapacityPodAdmissionResponse) (model.CapacityNativePodCheckpoint, model.NativePodTerminationChallenge) {
	t.Helper()
	ctx := context.Background()
	cp, err := store.RegisterNativeLifetime(ctx, policy, intent, boot)
	if err != nil {
		t.Fatal(err)
	}
	var challenge model.NativePodTerminationChallenge
	if json.Unmarshal(cp.Challenge, &challenge) != nil {
		t.Fatal("challenge")
	}
	no := false
	req := model.AdapterEnsureCapacityPodDrainRequest{BindingName: p.HPAExecutionBinding.PodTerminationBinding, PodName: cp.PodName, ExpectedPodUID: cp.PodUID, ExpectedPodResourceVersion: cp.PodResourceVersion, ExpectedPodGeneration: cp.PodGeneration, ExpectedContainerID: cp.ContainerID, ExpectedContainerStartedAt: cp.ContainerStartedAt, ExpectedRestartCount: cp.RestartCount, Challenge: challenge, Phase: "protect", DryRun: &no}
	raw, _ := json.Marshal(req)
	command, token, err := store.IssueNativeCommand(ctx, policy, intent, capacity.EnsureNativePodDrain, cp.PodUID, raw)
	if err != nil {
		t.Fatal(err)
	}
	nativeLifetimeRedeem(t, store, p, command, token)
	pod := boot.Observation
	pod.PodResourceVersion = "11"
	pod.ObservedAt = time.Now().UTC()
	readback := model.AdapterCapacityPodTerminationResponse{Operation: capacity.ObserveNativePodTermination, Status: "observed", Observation: pod}
	if err := store.ConfirmNativeCommand(ctx, policy, intent, command.CommandID, readback); err != nil {
		t.Fatal(err)
	}
	cp.State, cp.PodResourceVersion = "protected", "11"
	return cp, challenge
}

func nativeLifetimeClose(t *testing.T, store CapacityStore, policy model.Manifest, p model.CapacityPolicySpec, intent model.CapacityIntent, cp model.CapacityNativePodCheckpoint, challenge model.NativePodTerminationChallenge) {
	t.Helper()
	ctx := context.Background()
	zero := int32(0)
	start := cp.ContainerStartedAt
	joined := time.Now().UTC()
	finished := joined.Add(time.Millisecond)
	deleted := joined.Add(-time.Millisecond)
	pod := model.NativeTerminationObservation{BindingName: p.HPAExecutionBinding.PodTerminationBinding, Namespace: cp.Namespace, PodName: cp.PodName, PodUID: cp.PodUID, PodResourceVersion: "13", PodGeneration: cp.PodGeneration, WorkloadUID: cp.WorkloadUID, ContainerName: cp.ContainerName, ContainerID: cp.ContainerID, ImageID: "fixture@" + cp.ImageDigest, ImageDigest: cp.ImageDigest, RestartCount: cp.RestartCount, ContainerState: "terminated", ExitCode: &zero, Signal: &zero, StartedAt: &start, FinishedAt: &finished, DeletionRequestedAt: &deleted, Protected: true, State: "terminated", Receipt: &model.NativePodTerminationReceipt{NativePodTerminationChallenge: challenge, JoinedAt: joined, Lanes: map[string]string{"listener": "done", "workers": "inactive"}, RootAdmission: "never_opened"}, ReceiptSHA256: strings.Repeat("a", 64), ObservedAt: time.Now().UTC()}
	if err := store.ConfirmNativePodWitness(ctx, policy, intent, cp.PodUID, model.AdapterCapacityPodTerminationResponse{Operation: capacity.ObserveNativePodTermination, Status: "observed", Observation: pod}); err != nil {
		t.Fatal(err)
	}
	no := false
	req := model.AdapterDestroyCapacityPodDrainProtectionRequest{AdapterObserveCapacityPodTerminationRequest: model.AdapterObserveCapacityPodTerminationRequest{BindingName: p.HPAExecutionBinding.PodTerminationBinding, PodName: cp.PodName, ExpectedPodUID: cp.PodUID, ExpectedPodGeneration: cp.PodGeneration, ExpectedContainerID: cp.ContainerID, ExpectedContainerStartedAt: cp.ContainerStartedAt, ExpectedRestartCount: cp.RestartCount, Challenge: challenge}, ExpectedPodResourceVersion: "13", DryRun: &no}
	raw, _ := json.Marshal(req)
	command, token, err := store.IssueNativeCommand(ctx, policy, intent, capacity.DestroyNativePodProtection, cp.PodUID, raw)
	if err != nil {
		t.Fatal(err)
	}
	nativeLifetimeRedeem(t, store, p, command, token)
	pod.Protected, pod.State, pod.Reason, pod.ObservedAt = false, "unprotected", "native_capacity_finalizer_absent", time.Now().UTC()
	if err := store.ConfirmNativeCommand(ctx, policy, intent, command.CommandID, model.AdapterCapacityPodTerminationResponse{Operation: capacity.ObserveNativePodTermination, Status: "observed", Observation: pod}); err != nil {
		t.Fatal(err)
	}
}

func TestCapacityNativeLifetimePostgres(t *testing.T) {
	t.Run("jsonb_origin_and_actual_ack", func(t *testing.T) {
		db, store, policy, p, intent := nativeLifetimePostgresFixture(t)
		boot := nativeLifetimeBoot(p)
		cp, challenge := nativeLifetimeProtect(t, store, policy, p, intent, boot)
		actual := boot
		actual.Observation.PodResourceVersion = "11"
		actual.Admission.State = "roots_open"
		actual.Admission.Challenge = &challenge
		actual.Admission.ChallengeSHA256 = cp.OriginChallengeSHA256
		actual.Admission.ObservedAt = time.Now().UTC()
		actual.Observation.ObservedAt = time.Now().UTC()
		if err := store.AcknowledgeNativeProjection(context.Background(), policy, intent, cp.PodUID, actual); err != nil {
			t.Fatal("JSONB reformat lost original native projection digest", err)
		}
		var raw []byte
		if err := db.QueryRow(`SELECT checkpoint_record FROM public.capacity_native_lifetimes WHERE pod_uid=$1`, cp.PodUID).Scan(&raw); err != nil {
			t.Fatal(err)
		}
		var stored model.CapacityNativePodCheckpoint
		if json.Unmarshal(raw, &stored) != nil || string(stored.OriginChallengeBytes) != string(cp.OriginChallengeBytes) || len(stored.RootAcknowledgement) == 0 {
			t.Fatal("immutable origin bytes/startup acknowledgement not retained")
		}
		no := false
		request := model.AdapterEnsureCapacityPodDrainRequest{BindingName: p.HPAExecutionBinding.PodTerminationBinding, PodName: cp.PodName, ExpectedPodUID: cp.PodUID, ExpectedPodResourceVersion: "11", ExpectedPodGeneration: cp.PodGeneration, ExpectedContainerID: cp.ContainerID, ExpectedContainerStartedAt: cp.ContainerStartedAt, ExpectedRestartCount: cp.RestartCount, Challenge: challenge, Phase: "admit", DryRun: &no}
		encoded, _ := json.Marshal(request)
		command, token, err := store.IssueNativeCommand(context.Background(), policy, intent, capacity.EnsureNativePodDrain, cp.PodUID, encoded)
		if err != nil {
			t.Fatal(err)
		}
		nativeLifetimeRedeem(t, store, p, command, token)
		if err := store.ConfirmNativeCommand(context.Background(), policy, intent, command.CommandID, actual); err == nil {
			t.Fatal("SDK roots alone confirmed native readiness condition")
		}
		actual.Observation.AdmissionReady = true
		actual.Observation.PodResourceVersion = "12"
		actual.Observation.ObservedAt = time.Now().UTC()
		actual.Admission.ObservedAt = time.Now().UTC()
		if err := store.ConfirmNativeCommand(context.Background(), policy, intent, command.CommandID, actual); err != nil {
			t.Fatal(err)
		}
		for _, operation := range []string{capacity.EnsureBoundHPAEnvelope, capacity.EnsureNativePodDrain} {
			request.Phase = "terminate"
			encoded, _ := json.Marshal(request)
			if _, _, err := store.IssueNativeCommand(context.Background(), policy, intent, operation, cp.PodUID, encoded); err == nil {
				t.Fatal("admission workflow acquired pressure or own Pod DELETE permission")
			}
		}
	})
	t.Run("terminal_archive_repeated_rollouts", func(t *testing.T) {
		db, store, policy, p, intent := nativeLifetimePostgresFixture(t)
		var first model.AdapterCapacityPodAdmissionResponse
		for i := 0; i < maxNativeRetainedLifetimes+1; i++ {
			if i > 0 && i%32 == 0 {
				var err error
				intent, err = store.Renew(context.Background(), policy, intent.Generation, intent.FencingToken, intent.LeaseOwner)
				if err != nil {
					t.Fatal(err)
				}
			}
			boot := nativeLifetimeBoot(p)
			if i == 0 {
				first = boot
			}
			cp, challenge := nativeLifetimeProtect(t, store, policy, p, intent, boot)
			nativeLifetimeClose(t, store, policy, p, intent, cp, challenge)
			if err := store.ArchiveNativeTerminalHistory(context.Background(), policy, intent); err != nil {
				t.Fatal(i, err)
			}
		}
		var hot, archived, identities int
		if err := db.QueryRow(`SELECT count(*) FROM public.capacity_native_lifetimes WHERE namespace=$1`, policy.Metadata.Namespace).Scan(&hot); err != nil {
			t.Fatal(err)
		}
		if err := db.QueryRow(`SELECT count(*) FROM public.capacity_native_lifetime_archive WHERE namespace=$1`, policy.Metadata.Namespace).Scan(&archived); err != nil {
			t.Fatal(err)
		}
		if err := db.QueryRow(`SELECT count(*) FROM public.capacity_native_command_identities WHERE namespace=$1`, policy.Metadata.Namespace).Scan(&identities); err != nil {
			t.Fatal(err)
		}
		if hot != 0 || archived != maxNativeRetainedLifetimes+1 || identities != 2*archived {
			t.Fatalf("hot quota permanently exhausted or identity lost: %d %d %d", hot, archived, identities)
		}
		terminal, found, err := store.ArchivedNativeLifetime(context.Background(), policy, first.Observation.PodUID)
		if err != nil || !found || terminal.State != "released" || terminal.PodUID != first.Observation.PodUID || terminal.Namespace != p.AssessmentBinding.Snapshot.Namespace || terminal.ConfirmedAt == nil || len(terminal.NativeTerminationReceipt) == 0 {
			t.Fatal("readonly immutable terminal archive unavailable", found, err)
		}
		if _, found, err := store.ArchivedNativeLifetime(context.Background(), policy, uuid.NewString()); err != nil || found {
			t.Fatal("missing native UID invented archived origin", found, err)
		}
		foreignPolicy := policy
		foreignPolicy.Checksum = strings.Repeat("f", 64)
		if _, _, err := store.ArchivedNativeLifetime(context.Background(), foreignPolicy, first.Observation.PodUID); err == nil {
			t.Fatal("archive readonly lookup accepted a different policy checksum")
		}
		if _, err := store.RegisterNativeLifetime(context.Background(), policy, intent, first); err == nil {
			t.Fatal("archived native UID origin revived")
		}
		if _, err := db.Exec(`UPDATE public.capacity_native_lifetime_archive SET bundle_sha256='changed' WHERE namespace=$1`, policy.Metadata.Namespace); err == nil {
			t.Fatal("immutable native archive updated")
		}
		if _, err := db.Exec(`DELETE FROM public.capacity_native_command_identities WHERE namespace=$1`, policy.Metadata.Namespace); err == nil {
			t.Fatal("permanent identity fence deleted")
		}
	})
	t.Run("alive_and_uncertain_never_archived", func(t *testing.T) {
		db, store, policy, p, intent := nativeLifetimePostgresFixture(t)
		boot := nativeLifetimeBoot(p)
		cp, _ := nativeLifetimeProtect(t, store, policy, p, intent, boot)
		if err := store.ArchiveNativeTerminalHistory(context.Background(), policy, intent); err != nil {
			t.Fatal(err)
		}
		var retained int
		if err := db.QueryRow(`SELECT count(*) FROM public.capacity_native_lifetimes WHERE pod_uid=$1`, cp.PodUID).Scan(&retained); err != nil || retained != 1 {
			t.Fatal("alive protection treated as completion")
		}
		if _, err := store.RegisterNativeLifetime(context.Background(), policy, intent, boot); err == nil {
			t.Fatal("same exact lifetime origin replaced")
		}
		other := nativeLifetimeBoot(p)
		pending, err := store.RegisterNativeLifetime(context.Background(), policy, intent, other)
		if err != nil {
			t.Fatal(err)
		}
		var challenge model.NativePodTerminationChallenge
		if json.Unmarshal(pending.Challenge, &challenge) != nil {
			t.Fatal("pending origin")
		}
		no := false
		request := model.AdapterEnsureCapacityPodDrainRequest{BindingName: p.HPAExecutionBinding.PodTerminationBinding, PodName: pending.PodName, ExpectedPodUID: pending.PodUID, ExpectedPodResourceVersion: pending.PodResourceVersion, ExpectedPodGeneration: pending.PodGeneration, ExpectedContainerID: pending.ContainerID, ExpectedContainerStartedAt: pending.ContainerStartedAt, ExpectedRestartCount: pending.RestartCount, Challenge: challenge, Phase: "protect", DryRun: &no}
		raw, _ := json.Marshal(request)
		command, token, err := store.IssueNativeCommand(context.Background(), policy, intent, capacity.EnsureNativePodDrain, pending.PodUID, raw)
		if err != nil {
			t.Fatal(err)
		}
		nativeLifetimeRedeem(t, store, p, command, token)
		if err := store.MarkNativeCommandUncertain(context.Background(), command.CommandID); err != nil {
			t.Fatal(err)
		}
		if err := store.ArchiveNativeTerminalHistory(context.Background(), policy, intent); err != nil {
			t.Fatal(err)
		}
		if _, err := store.RegisterNativeLifetime(context.Background(), policy, intent, nativeLifetimeBoot(p)); err == nil {
			t.Fatal("uncertain native send allowed a new write")
		}
		var state string
		if err := db.QueryRow(`SELECT state FROM public.capacity_native_commands WHERE id=$1`, command.CommandID).Scan(&state); err != nil || state != "uncertain" {
			t.Fatal("uncertain native send was pruned or normalized")
		}
	})
	t.Run("partial_terminal_never_archived", func(t *testing.T) {
		db, store, policy, p, intent := nativeLifetimePostgresFixture(t)
		cp, _ := nativeLifetimeProtect(t, store, policy, p, intent, nativeLifetimeBoot(p))
		if _, err := db.Exec(`UPDATE public.capacity_native_lifetimes SET checkpoint_record=jsonb_set(checkpoint_record,'{state}','"released"') WHERE pod_uid=$1`, cp.PodUID); err != nil {
			t.Fatal(err)
		}
		if err := store.ArchiveNativeTerminalHistory(context.Background(), policy, intent); err == nil {
			t.Fatal("partial caller-style terminal record archived without actual durable witness/release")
		}
		var retained int
		if err := db.QueryRow(`SELECT count(*) FROM public.capacity_native_lifetimes WHERE pod_uid=$1`, cp.PodUID).Scan(&retained); err != nil || retained != 1 {
			t.Fatal("partial terminal origin lost")
		}
	})
}
