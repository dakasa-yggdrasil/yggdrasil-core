package message

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

// Read-only framing evidence. The KinD witness/inventory race separately proves
// the new authority, native CAS and immutable original parent with real stores.
func TestCapacityReleaseRecoveryFrame(t *testing.T) {
	for _, name := range []string{"matched_frame", "version_race_fresh_frame", "repeated_version_race_bounded_hold", "incomplete_inventory_hold", "identity_drift_hold", "missing_target_hold", "read_failure_hold", "fence_revoked_hold", "expired_owner_zero_reads"} {
		t.Run(name, func(t *testing.T) {
			now := time.Now().UTC()
			started, finished, deleted := now.Add(-time.Minute), now.Add(-time.Second), now.Add(-2*time.Second)
			zero := int32(0)
			p := model.CapacityPolicySpec{MaxEvidenceAgeSeconds: 60, AssessmentBinding: &model.CapacityBoundAssessmentBinding{Snapshot: model.CapacityHPAMinimumBinding{Namespace: "frame", WorkloadUID: uuid.NewString()}}, HPAExecutionBinding: &model.CapacityHPAExecutionBinding{PodTerminationBinding: "api-native", ContainerName: "api", ImageDigest: "sha256:" + strings.Repeat("a", 64), Lanes: []string{"workers"}}}
			challenge := model.NativePodTerminationChallenge{SchemaVersion: 1, Namespace: "frame", PodName: "api", PodUID: uuid.NewString(), WorkloadUID: p.AssessmentBinding.Snapshot.WorkloadUID, ContainerName: "api", ImageDigest: p.HPAExecutionBinding.ImageDigest, IntentGeneration: 1, DrainNonce: uuid.NewString(), IssuedAt: now.Add(-time.Minute), LaneRosterSHA256: capacity.NativeRosterDigest(p.HPAExecutionBinding.Lanes)}
			raw, err := json.Marshal(challenge)
			if err != nil {
				t.Fatal(err)
			}
			cp := model.CapacityNativePodCheckpoint{Namespace: challenge.Namespace, PodName: challenge.PodName, PodUID: challenge.PodUID, WorkloadUID: challenge.WorkloadUID, ContainerName: challenge.ContainerName, ContainerID: "containerd://original", ImageDigest: challenge.ImageDigest, ContainerStartedAt: started, IntentGeneration: 1, DrainNonce: challenge.DrainNonce, Challenge: raw}
			pod := model.NativeTerminationObservation{BindingName: "api-native", Namespace: cp.Namespace, PodName: cp.PodName, PodUID: cp.PodUID, PodResourceVersion: "13", WorkloadUID: cp.WorkloadUID, WorkloadResourceVersion: "10", ContainerName: cp.ContainerName, ContainerID: cp.ContainerID, ImageID: "fixture@" + cp.ImageDigest, ImageDigest: cp.ImageDigest, ContainerState: "terminated", ExitCode: &zero, Signal: &zero, StartedAt: &started, FinishedAt: &finished, DeletionRequestedAt: &deleted, Protected: true, State: "terminated", Receipt: &model.NativePodTerminationReceipt{NativePodTerminationChallenge: challenge, JoinedAt: finished, Lanes: map[string]string{"workers": "done"}}, ReceiptSHA256: strings.Repeat("b", 64), ObservedAt: now}
			reads, inventories, hpas, fences := 0, 0, 0, 0
			cause := errors.New("original read refused")
			fence := func() error {
				fences++
				if name == "expired_owner_zero_reads" {
					return context.DeadlineExceeded
				}
				if name == "fence_revoked_hold" && hpas == 1 {
					return cause
				}
				return nil
			}
			observe := func(model.CapacityNativePodCheckpoint) (model.AdapterCapacityPodTerminationResponse, error) {
				reads++
				if name == "read_failure_hold" {
					return model.AdapterCapacityPodTerminationResponse{}, cause
				}
				view := pod
				if reads > 1 {
					view.PodResourceVersion = "14"
				}
				return model.AdapterCapacityPodTerminationResponse{Operation: capacity.ObserveNativePodTermination, Status: "observed", Observation: view}, nil
			}
			hpa := func() (model.CapacityHPAEnvelopeResponse, error) {
				hpas++
				return model.CapacityHPAEnvelopeResponse{Operation: capacity.ObserveHPAEnvelope}, nil
			}
			inventory := func() (model.AdapterCapacityPodInventoryResponse, error) {
				inventories++
				view := pod
				if name == "version_race_fresh_frame" || name == "repeated_version_race_bounded_hold" {
					view.PodResourceVersion = "14"
				}
				if name == "repeated_version_race_bounded_hold" && inventories > 1 {
					view.PodResourceVersion = "15"
				}
				if name == "identity_drift_hold" {
					view.ContainerID = "containerd://replacement"
				}
				pods := []model.NativeTerminationObservation{view}
				if name == "missing_target_hold" {
					pods = nil
				}
				return model.AdapterCapacityPodInventoryResponse{Operation: capacity.ObserveNativePodInventory, Status: "observed", BindingName: "api-native", Namespace: cp.Namespace, WorkloadUID: cp.WorkloadUID, WorkloadResourceVersion: "10", ListResourceVersion: "15", Complete: name != "incomplete_inventory_hold", Pods: pods, ObservedAt: now}, nil
			}
			witness, _, membership, err := capacityReleaseRecoveryFrame(p, cp, fence, observe, hpa, inventory)
			if name == "matched_frame" || name == "version_race_fresh_frame" {
				expected := 1
				if name == "version_race_fresh_frame" {
					expected = 2
				}
				if err != nil || reads != expected || hpas != expected || inventories != expected || fences != 4*expected || witness.Observation.PodResourceVersion != membership.Pods[0].PodResourceVersion {
					t.Fatal("fresh same-lifetime frame was not retained", err, reads, inventories)
				}
				return
			}
			if err == nil || witness.Observation.PodUID != "" || len(membership.Pods) != 0 {
				t.Fatal("failed frame escaped as admission evidence")
			}
			if name == "repeated_version_race_bounded_hold" && (reads != 4 || hpas != 4 || inventories != 4) {
				t.Fatal("read-only retry budget was renewed")
			}
			if name != "repeated_version_race_bounded_hold" && reads > 1 {
				t.Fatal("non-RV refusal was retried")
			}
			if name == "expired_owner_zero_reads" && (reads != 0 || hpas != 0 || inventories != 0 || !errors.Is(err, context.DeadlineExceeded)) {
				t.Fatal("expired owner performed reads")
			}
			if name == "fence_revoked_hold" && (inventories != 0 || !errors.Is(err, cause)) {
				t.Fatal("revoked fence reached inventory")
			}
		})
	}
}
