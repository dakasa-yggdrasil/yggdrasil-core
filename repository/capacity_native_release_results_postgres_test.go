package repository

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

// PostgreSQL protocol evidence only. The mandatory Core/Kubernetes KinD gate
// independently qualifies the original producer/caller and actual API409.
func TestCapacityNativeReleaseRecoveryPostgres(t *testing.T) {
	for _, name := range []string{"both_original_acks_new_identity_and_archive", "no_adapter_ack_hold", "no_caller_ack_hold", "wrong_nonce_hold", "source_mismatch_hold", "catalog_changed_hold", "late_owner_hold", "expired_owner_hold", "duplicate_result_exact_only", "four_history_no_reset", "old_protocol_hold"} {
		t.Run(name, func(t *testing.T) {
			binding := &model.CapacityNativeReleaseRecoveryBinding{Protocol: capacity.NativeReleaseResultProtocol, AdapterSourceCommit: strings.Repeat("a", 40)}
			if name == "old_protocol_hold" {
				binding = nil
			}
			db, store, policy, p, intent := nativeLifetimePostgresFixture(t, binding)
			ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
			defer cancel()
			boot := nativeLifetimeBoot(p)
			cp, challenge := nativeLifetimeProtect(t, store, policy, p, intent, boot)
			zero := int32(0)
			start := cp.ContainerStartedAt
			joined := time.Now().UTC()
			finished := joined.Add(time.Millisecond)
			deleted := joined.Add(-time.Millisecond)
			pod := model.NativeTerminationObservation{BindingName: p.HPAExecutionBinding.PodTerminationBinding, Namespace: cp.Namespace, PodName: cp.PodName, PodUID: cp.PodUID, PodResourceVersion: "13", PodGeneration: cp.PodGeneration, WorkloadUID: cp.WorkloadUID, WorkloadResourceVersion: "10", ContainerName: cp.ContainerName, ContainerID: cp.ContainerID, ImageID: "fixture@" + cp.ImageDigest, ImageDigest: cp.ImageDigest, RestartCount: cp.RestartCount, ContainerState: "terminated", ExitCode: &zero, Signal: &zero, StartedAt: &start, FinishedAt: &finished, DeletionRequestedAt: &deleted, Protected: true, State: "terminated", Receipt: &model.NativePodTerminationReceipt{NativePodTerminationChallenge: challenge, JoinedAt: joined, Lanes: map[string]string{"listener": "done", "workers": "inactive"}, RootAdmission: "never_opened"}, ReceiptSHA256: strings.Repeat("b", 64), ObservedAt: time.Now().UTC()}
			witness := model.AdapterCapacityPodTerminationResponse{Operation: capacity.ObserveNativePodTermination, Status: "observed", Observation: pod}
			if err := store.ConfirmNativePodWitness(ctx, policy, intent, cp.PodUID, witness); err != nil {
				t.Fatal("original PG witness", err)
			}
			no := false
			req := model.AdapterDestroyCapacityPodDrainProtectionRequest{AdapterObserveCapacityPodTerminationRequest: model.AdapterObserveCapacityPodTerminationRequest{BindingName: p.HPAExecutionBinding.PodTerminationBinding, PodName: cp.PodName, ExpectedPodUID: cp.PodUID, ExpectedPodGeneration: cp.PodGeneration, ExpectedContainerID: cp.ContainerID, ExpectedContainerStartedAt: cp.ContainerStartedAt, ExpectedRestartCount: cp.RestartCount, Challenge: challenge}, ExpectedPodResourceVersion: "13", DryRun: &no}
			raw, _ := json.Marshal(req)
			command, token, err := store.IssueNativeCommand(ctx, policy, intent, capacity.DestroyNativePodProtection, cp.PodUID, raw)
			if err != nil {
				t.Fatal(err)
			}
			redeem := func(c model.CapacityNativeCommand, token string) model.CapacityNativeAuthorityPermit {
				permit, err := store.RedeemNativeCommand(ctx, p.HPAExecutionBinding.AdapterPrincipalID, model.CapacityNativeAuthorityRedeemRequest{AuthorityToken: token, IntegrationInstanceID: c.Adapter.IntegrationInstanceID, IntegrationTypeID: c.Adapter.IntegrationTypeID, Capability: c.Operation, RequestSHA256: c.RequestSHA256, ReleaseProtocol: c.ReleaseProtocol, AdapterSourceCommit: c.AdapterSourceCommit})
				if err != nil {
					t.Fatal("original redemption", err)
				}
				return permit
			}
			permit := redeem(command, token)
			result := func(c model.CapacityNativeCommand, permit model.CapacityNativeAuthorityPermit) model.CapacityNativeReleaseResult {
				return model.CapacityNativeReleaseResult{Protocol: capacity.NativeReleaseResultProtocol, CommandID: c.CommandID, AttemptID: permit.AttemptID, IntegrationInstanceID: c.Adapter.IntegrationInstanceID, IntegrationTypeID: c.Adapter.IntegrationTypeID, Capability: c.Operation, RequestSHA256: c.RequestSHA256, AdapterSourceCommit: strings.Repeat("a", 40), ReturnNonce: permit.ReturnNonce, OriginalStatus: 409, OriginalResponseSHA256: strings.Repeat("c", 64), Outcome: "rejected_no_effect", OneSend: true, DoReturned: true, ReadReturned: true, CloseReturned: true}
			}
			r := result(command, permit)
			if name == "wrong_nonce_hold" {
				r.ReturnNonce = strings.Repeat("d", 64)
			}
			if name == "source_mismatch_hold" {
				r.AdapterSourceCommit = strings.Repeat("e", 40)
			}
			if name == "old_protocol_hold" || name == "wrong_nonce_hold" || name == "source_mismatch_hold" {
				if store.RecordNativeReleaseResult(ctx, p.HPAExecutionBinding.AdapterPrincipalID, r) == nil {
					t.Fatal("unbound result became an ACK")
				}
				if _, err := store.AcknowledgeNativeReleaseCaller(ctx, policy, intent, command.CommandID); err == nil {
					t.Fatal("unbound result became rejected_no_effect")
				}
				return
			}
			if name != "no_adapter_ack_hold" {
				if err := store.RecordNativeReleaseResult(ctx, p.HPAExecutionBinding.AdapterPrincipalID, r); err != nil {
					t.Fatal("original adapter ACK", err)
				}
			}
			if name == "duplicate_result_exact_only" {
				if err := store.RecordNativeReleaseResult(ctx, p.HPAExecutionBinding.AdapterPrincipalID, r); err != nil {
					t.Fatal("exact duplicate was not read-only", err)
				}
				r.OriginalResponseSHA256 = strings.Repeat("f", 64)
				if store.RecordNativeReleaseResult(ctx, p.HPAExecutionBinding.AdapterPrincipalID, r) == nil {
					t.Fatal("different original result replaced immutable ACK")
				}
				return
			}
			if name == "no_adapter_ack_hold" {
				if _, err := store.AcknowledgeNativeReleaseCaller(ctx, policy, intent, command.CommandID); err == nil {
					t.Fatal("missing adapter ACK became known no-effect")
				}
				return
			}
			hpa := model.CapacityHPAEnvelopeResponse{Operation: capacity.ObserveHPAEnvelope, Status: "observed", Observation: model.CapacityHPAEnvelopeObservation{Namespace: "platform", HPAName: "api-hpa", HPAUID: p.AssessmentBinding.Snapshot.HPAUID, ResourceVersion: "1", APIGeneration: 0, WorkloadName: "api", WorkloadUID: p.AssessmentBinding.Snapshot.WorkloadUID, WorkloadResourceVersion: "10", Owner: p.Owner, EnvelopeGeneration: 7, IdempotencyKey: "previous", MinReplicas: 4, MaxReplicas: p.Ceiling, ProtectedFloor: p.Floor, TrackedProtectedFloor: p.Floor, MaximumReplicas: p.Ceiling, MatchedOwner: true, BoundsWithinScope: true, TrackingMatchesScope: true, BoundsMatchTracking: true, DiagnosticOnly: true, ObservedAt: time.Now().UTC().Format(time.RFC3339Nano)}}
			inventory := model.AdapterCapacityPodInventoryResponse{Operation: capacity.ObserveNativePodInventory, Status: "observed", BindingName: p.HPAExecutionBinding.PodTerminationBinding, Namespace: cp.Namespace, WorkloadUID: cp.WorkloadUID, WorkloadResourceVersion: "10", ListResourceVersion: "14", Complete: true, Pods: []model.NativeTerminationObservation{pod}, ObservedAt: time.Now().UTC()}
			if name == "no_caller_ack_hold" {
				if _, _, err := store.IssueNativeReleaseRecovery(ctx, policy, intent, command, raw, hpa, inventory, witness); err == nil {
					t.Fatal("row visibility replaced caller return")
				}
				return
			}
			parent, err := store.AcknowledgeNativeReleaseCaller(ctx, policy, intent, command.CommandID)
			if err != nil {
				t.Fatal("original caller ACK", err)
			}
			original, _ := json.Marshal(parent)
			if name == "catalog_changed_hold" {
				if _, err := db.ExecContext(ctx, `UPDATE public.manifests SET active=false WHERE id=$1`, parent.Adapter.IntegrationTypeID); err != nil {
					t.Fatal(err)
				}
			}
			if name == "late_owner_hold" {
				store.ExecutorID = uuid.NewString()
			}
			if name == "expired_owner_hold" {
				expired, cancel := context.WithDeadline(ctx, time.Now().Add(-time.Second))
				defer cancel()
				ctx = expired
			}
			child, childToken, err := store.IssueNativeReleaseRecovery(ctx, policy, intent, parent, raw, hpa, inventory, witness)
			if name == "catalog_changed_hold" || name == "late_owner_hold" || name == "expired_owner_hold" {
				if err == nil {
					t.Fatal("stale source/owner/deadline minted new authority")
				}
				return
			}
			if err != nil || child.CommandID == parent.CommandID || child.RecoveryDecisionID == "" || child.RecoveryFence == "" || child.ParentCommandID != parent.CommandID.String() || child.ParentAttemptID != parent.AttemptID.String() || child.AuthorityTokenSHA256 == parent.AuthorityTokenSHA256 || !child.ExpiresAt.Equal(parent.ExpiresAt) || child.Sequence != 2 {
				t.Fatal("fresh recovery authority/absolute deadline missing", err)
			}
			if _, _, err := store.IssueNativeReleaseRecovery(ctx, policy, intent, parent, raw, hpa, inventory, witness); err == nil {
				t.Fatal("same original parent admitted twice")
			}
			if _, err := store.RedeemNativeCommand(ctx, p.HPAExecutionBinding.AdapterPrincipalID, model.CapacityNativeAuthorityRedeemRequest{AuthorityToken: token, IntegrationInstanceID: parent.Adapter.IntegrationInstanceID, IntegrationTypeID: parent.Adapter.IntegrationTypeID, Capability: parent.Operation, RequestSHA256: parent.RequestSHA256, ReleaseProtocol: parent.ReleaseProtocol, AdapterSourceCommit: parent.AdapterSourceCommit}); err == nil {
				t.Fatal("old permission was respent")
			}
			if name == "four_history_no_reset" {
				for sequence := 2; sequence <= 4; sequence++ {
					permit = redeem(child, childToken)
					if err := store.RecordNativeReleaseResult(ctx, p.HPAExecutionBinding.AdapterPrincipalID, result(child, permit)); err != nil {
						t.Fatal(err)
					}
					parent, err = store.AcknowledgeNativeReleaseCaller(ctx, policy, intent, child.CommandID)
					if err != nil {
						t.Fatal(err)
					}
					child, childToken, err = store.IssueNativeReleaseRecovery(ctx, policy, intent, parent, raw, hpa, inventory, witness)
					if sequence < 4 && err != nil {
						t.Fatal(err)
					}
					if sequence == 4 && err == nil {
						t.Fatal("four-command history reset")
					}
				}
				return
			}
			permit = redeem(child, childToken)
			if permit.AttemptID == parent.AttemptID {
				t.Fatal("original attempt reused")
			}
			pod.Protected, pod.State, pod.Reason, pod.ObservedAt = false, "unprotected", "native_capacity_finalizer_absent", time.Now().UTC()
			if err := store.ConfirmNativeCommand(ctx, policy, intent, child.CommandID, model.AdapterCapacityPodTerminationResponse{Operation: capacity.ObserveNativePodTermination, Status: "observed", Observation: pod}); err != nil {
				t.Fatal("new release independent readback", err)
			}
			if err := store.ArchiveNativeTerminalHistory(ctx, policy, intent); err != nil {
				t.Fatal("complete original archive", err)
			}
			var archived []byte
			if err := db.QueryRowContext(ctx, `SELECT command_record FROM public.capacity_native_command_archive WHERE id=$1`, parent.CommandID).Scan(&archived); err != nil || nativeCanonicalArchiveSHA(archived) != nativeCanonicalArchiveSHA(original) {
				t.Fatal("rejected original was erased or relabelled", err)
			}
			if _, err := store.RedeemNativeCommand(ctx, p.HPAExecutionBinding.AdapterPrincipalID, model.CapacityNativeAuthorityRedeemRequest{AuthorityToken: token, IntegrationInstanceID: parent.Adapter.IntegrationInstanceID, IntegrationTypeID: parent.Adapter.IntegrationTypeID, Capability: parent.Operation, RequestSHA256: parent.RequestSHA256, ReleaseProtocol: parent.ReleaseProtocol, AdapterSourceCommit: parent.AdapterSourceCommit}); err == nil {
				t.Fatal("archived permission was restored")
			}
		})
	}
}
