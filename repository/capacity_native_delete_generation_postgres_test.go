package repository

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

// The real PostgreSQL ledger must preserve birth generation 1 while issuing
// release against the independently witnessed Kubernetes DELETE generation 2.
// This is a CI test; it does not substitute for native API/KinD qualification.
func TestCapacityNativeFirstDeleteGenerationPostgres(t *testing.T) {
	ctx := context.Background()
	recovery := &model.CapacityNativeReleaseRecoveryBinding{Protocol: capacity.NativeReleaseResultProtocol, AdapterSourceCommit: strings.Repeat("a", 40)}
	db, store, policy, p, intent := nativeLifetimePostgresFixture(t, recovery)
	boot := nativeLifetimeBoot(p)
	boot.Observation.PodGeneration = 1
	cp, challenge := nativeLifetimeProtect(t, store, policy, p, intent, boot)
	admitted := boot
	admitted.Observation.PodResourceVersion = "11"
	admitted.Observation.ObservedAt = time.Now().UTC()
	admitted.Admission.State, admitted.Admission.Challenge = "roots_open", &challenge
	admitted.Admission.ChallengeSHA256 = cp.OriginChallengeSHA256
	admitted.Admission.ObservedAt = time.Now().UTC()
	if err := store.AcknowledgeNativeProjection(ctx, policy, intent, cp.PodUID, admitted); err != nil {
		t.Fatal(err)
	}
	no := false
	admit := model.AdapterEnsureCapacityPodDrainRequest{BindingName: p.HPAExecutionBinding.PodTerminationBinding, PodName: cp.PodName, ExpectedPodUID: cp.PodUID, ExpectedPodGeneration: 1, ExpectedPodResourceVersion: "11", ExpectedContainerID: cp.ContainerID, ExpectedContainerStartedAt: cp.ContainerStartedAt, ExpectedRestartCount: cp.RestartCount, Challenge: challenge, Phase: "admit", DryRun: &no}
	raw, _ := json.Marshal(admit)
	command, token, err := store.IssueNativeCommand(ctx, policy, intent, capacity.EnsureNativePodDrain, cp.PodUID, raw)
	if err != nil {
		t.Fatal(err)
	}
	nativeLifetimeRedeem(t, store, p, command, token)
	admitted.Observation.PodResourceVersion, admitted.Observation.AdmissionReady = "12", true
	admitted.Observation.ObservedAt, admitted.Admission.ObservedAt = time.Now().UTC(), time.Now().UTC()
	if err = store.ConfirmNativeCommand(ctx, policy, intent, command.CommandID, admitted); err != nil {
		t.Fatal(err)
	}
	zero := int32(0)
	now := time.Now().UTC()
	started, finished, deleted := cp.ContainerStartedAt, now, now.Add(-time.Millisecond)
	pod := model.NativeTerminationObservation{BindingName: p.HPAExecutionBinding.PodTerminationBinding, Namespace: cp.Namespace, PodName: cp.PodName, PodUID: cp.PodUID, PodResourceVersion: "13", PodGeneration: 2, WorkloadUID: cp.WorkloadUID, ContainerName: cp.ContainerName, ContainerID: cp.ContainerID, ImageID: "fixture@" + cp.ImageDigest, ImageDigest: cp.ImageDigest, RestartCount: cp.RestartCount, ContainerState: "terminated", ExitCode: &zero, Signal: &zero, StartedAt: &started, FinishedAt: &finished, DeletionRequestedAt: &deleted, Protected: true, State: "terminated", Receipt: &model.NativePodTerminationReceipt{NativePodTerminationChallenge: challenge, JoinedAt: finished, Lanes: map[string]string{"listener": "done", "workers": "inactive"}, RootAdmission: "previously_opened"}, ReceiptSHA256: strings.Repeat("a", 64), ObservedAt: now}
	witness := model.AdapterCapacityPodTerminationResponse{Operation: capacity.ObserveNativePodTermination, Status: "observed", Observation: pod}
	if err = store.ConfirmNativePodWitness(ctx, policy, intent, cp.PodUID, witness); err != nil {
		t.Fatal("first Kubernetes DELETE generation refused despite complete current witness", err)
	}
	_, checkpoints, err := store.NativeLedger(ctx, policy, intent)
	if err != nil || len(checkpoints) != 1 {
		t.Fatal("durable witness reload failed", err)
	}
	stored := checkpoints[0]
	retained, err := capacity.NativePodConfirmedTermination(p, stored)
	if err != nil || stored.PodGeneration != 1 || stored.State != "confirmed" || stored.ConfirmedAt == nil || retained.Observation.PodGeneration != 2 {
		t.Fatal("birth generation or actual persisted termination was rewritten", err)
	}
	release := model.AdapterDestroyCapacityPodDrainProtectionRequest{AdapterObserveCapacityPodTerminationRequest: model.AdapterObserveCapacityPodTerminationRequest{BindingName: p.HPAExecutionBinding.PodTerminationBinding, PodName: cp.PodName, ExpectedPodUID: cp.PodUID, ExpectedPodGeneration: 2, ExpectedContainerID: cp.ContainerID, ExpectedContainerStartedAt: cp.ContainerStartedAt, ExpectedRestartCount: cp.RestartCount, Challenge: challenge}, ExpectedPodResourceVersion: "13", DryRun: &no}
	for _, generation := range []int64{1, 3} {
		wrong := release
		wrong.ExpectedPodGeneration = generation
		raw, _ = json.Marshal(wrong)
		if _, _, err = store.IssueNativeCommand(ctx, policy, intent, capacity.DestroyNativePodProtection, cp.PodUID, raw); err == nil {
			t.Fatal("release authority used a generation absent from the durable witness", generation)
		}
	}
	raw, _ = json.Marshal(release)
	command, token, err = store.IssueNativeCommand(ctx, policy, intent, capacity.DestroyNativePodProtection, cp.PodUID, raw)
	if err != nil {
		t.Fatal("exact witnessed release generation refused", err)
	}
	redeem := func(c model.CapacityNativeCommand, token string) model.CapacityNativeAuthorityPermit {
		t.Helper()
		permit, err := store.RedeemNativeCommand(ctx, p.HPAExecutionBinding.AdapterPrincipalID, model.CapacityNativeAuthorityRedeemRequest{AuthorityToken: token, IntegrationInstanceID: c.Adapter.IntegrationInstanceID, IntegrationTypeID: c.Adapter.IntegrationTypeID, Capability: c.Operation, RequestSHA256: c.RequestSHA256, ReleaseProtocol: c.ReleaseProtocol, AdapterSourceCommit: c.AdapterSourceCommit})
		if err != nil {
			t.Fatal(err)
		}
		return permit
	}
	permit := redeem(command, token)
	result := model.CapacityNativeReleaseResult{Protocol: capacity.NativeReleaseResultProtocol, CommandID: command.CommandID, AttemptID: permit.AttemptID, IntegrationInstanceID: command.Adapter.IntegrationInstanceID, IntegrationTypeID: command.Adapter.IntegrationTypeID, Capability: command.Operation, RequestSHA256: command.RequestSHA256, AdapterSourceCommit: recovery.AdapterSourceCommit, ReturnNonce: permit.ReturnNonce, OriginalStatus: 409, OriginalResponseSHA256: strings.Repeat("c", 64), Outcome: "rejected_no_effect", OneSend: true, DoReturned: true, ReadReturned: true, CloseReturned: true}
	if err = store.RecordNativeReleaseResult(ctx, p.HPAExecutionBinding.AdapterPrincipalID, result); err != nil {
		t.Fatal("original adapter return ACK failed for actual DELETE generation", err)
	}
	parent, err := store.AcknowledgeNativeReleaseCaller(ctx, policy, intent, command.CommandID)
	if err != nil {
		t.Fatal("original caller ACK failed for actual DELETE generation", err)
	}
	var dualACK bool
	if err = db.QueryRow(`SELECT adapter_ack_at IS NOT NULL AND caller_ack_at IS NOT NULL FROM public.capacity_native_release_results WHERE command_id=$1`, parent.CommandID).Scan(&dualACK); err != nil || !dualACK {
		t.Fatal("both original returns were not durably joined", err)
	}
	hpa := model.CapacityHPAEnvelopeResponse{Operation: capacity.ObserveHPAEnvelope, Status: "observed", Observation: model.CapacityHPAEnvelopeObservation{Namespace: "platform", HPAName: "api-hpa", HPAUID: p.AssessmentBinding.Snapshot.HPAUID, ResourceVersion: "1", WorkloadName: "api", WorkloadUID: p.AssessmentBinding.Snapshot.WorkloadUID, WorkloadResourceVersion: "10", Owner: p.Owner, EnvelopeGeneration: 7, IdempotencyKey: "previous", MinReplicas: 4, MaxReplicas: p.Ceiling, ProtectedFloor: p.Floor, TrackedProtectedFloor: p.Floor, MaximumReplicas: p.Ceiling, MatchedOwner: true, BoundsWithinScope: true, TrackingMatchesScope: true, BoundsMatchTracking: true, DiagnosticOnly: true, ObservedAt: time.Now().UTC().Format(time.RFC3339Nano)}}
	inventoryPod := pod
	inventoryPod.State, inventoryPod.ContainerState, inventoryPod.StartedAt, inventoryPod.Receipt = "unknown", "", nil, nil
	inventory := model.AdapterCapacityPodInventoryResponse{Operation: capacity.ObserveNativePodInventory, Status: "observed", BindingName: p.HPAExecutionBinding.PodTerminationBinding, Namespace: cp.Namespace, WorkloadUID: cp.WorkloadUID, WorkloadResourceVersion: "10", ListResourceVersion: "14", Complete: true, Pods: []model.NativeTerminationObservation{inventoryPod}, ObservedAt: time.Now().UTC()}
	command, token, err = store.IssueNativeReleaseRecovery(ctx, policy, intent, parent, raw, hpa, inventory, model.AdapterCapacityPodTerminationResponse{Operation: capacity.ObserveNativePodTermination, Status: "observed", Observation: pod})
	if err != nil || command.ParentCommandID != parent.CommandID.String() {
		t.Fatal("fresh release authority did not preserve both ACKs and exact native witness", err)
	}
	_ = redeem(command, token)
	unprotected := pod
	unprotected.Protected, unprotected.State, unprotected.Reason = false, "unprotected", "native_capacity_finalizer_absent"
	unprotected.Receipt, unprotected.FinishedAt = nil, nil
	unprotected.ObservedAt = time.Now().UTC()
	for _, generation := range []int64{1, 3} {
		wrong := unprotected
		wrong.PodGeneration = generation
		if err = store.ConfirmNativeCommand(ctx, policy, intent, command.CommandID, model.AdapterCapacityPodTerminationResponse{Operation: capacity.ObserveNativePodTermination, Status: "observed", Observation: wrong}); err == nil {
			t.Fatal("foreign generation confirmed finalizer removal", generation)
		}
	}
	if err = store.ConfirmNativeCommand(ctx, policy, intent, command.CommandID, model.AdapterCapacityPodTerminationResponse{Operation: capacity.ObserveNativePodTermination, Status: "observed", Observation: unprotected}); err != nil {
		t.Fatal("actual first-DELETE generation readback refused", err)
	}
	// Even a privately stored released row cannot archive a +2 witness. Restore
	// its genuine original before proving terminal compaction and readback.
	var original []byte
	if err = db.QueryRow(`SELECT checkpoint_record FROM public.capacity_native_lifetimes WHERE namespace=$1 AND pod_uid=$2`, policy.Metadata.Namespace, cp.PodUID).Scan(&original); err != nil {
		t.Fatal(err)
	}
	var corrupt model.CapacityNativePodCheckpoint
	if err = json.Unmarshal(original, &corrupt); err != nil {
		t.Fatal(err)
	}
	witness.Observation.PodGeneration = 3
	corrupt.NativeTerminationReceipt, _ = json.Marshal(witness)
	raw, _ = json.Marshal(corrupt)
	if _, err = db.Exec(`UPDATE public.capacity_native_lifetimes SET checkpoint_record=$3 WHERE namespace=$1 AND pod_uid=$2`, policy.Metadata.Namespace, cp.PodUID, raw); err != nil {
		t.Fatal(err)
	}
	if err = store.ArchiveNativeTerminalHistory(ctx, policy, intent); err == nil {
		t.Fatal("archive accepted a terminal witness beyond the single DELETE generation")
	}
	if _, err = db.Exec(`UPDATE public.capacity_native_lifetimes SET checkpoint_record=$3 WHERE namespace=$1 AND pod_uid=$2`, policy.Metadata.Namespace, cp.PodUID, original); err != nil {
		t.Fatal(err)
	}
	if err = store.ArchiveNativeTerminalHistory(ctx, policy, intent); err != nil {
		t.Fatal("exact original and native DELETE generations did not archive", err)
	}
	archived, found, err := store.ArchivedNativeLifetime(ctx, policy, cp.PodUID)
	if err != nil || !found || archived.PodGeneration != 1 || archived.State != "released" {
		t.Fatal("immutable archived birth origin unavailable", err)
	}
	retained, err = capacity.NativePodConfirmedTermination(p, archived)
	if err != nil || retained.Observation.PodGeneration != 2 {
		t.Fatal("archive lost actual native termination generation", err)
	}
	unprotected.ObservedAt = time.Now().UTC()
	if err = capacity.NativePodReleaseTarget(p, archived, unprotected, time.Now().UTC()); err != nil {
		t.Fatal("retained native object could not prove exact removal after archive", err)
	}
}
