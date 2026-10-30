package capacity

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

func NativeProcessNonce(value string) bool {
	id, err := uuid.Parse(value)
	return err == nil && id != uuid.Nil && id.String() == value
}

func NativeLifetimeBindingSHA256(p model.CapacityPolicySpec) string {
	if p.AssessmentBinding == nil || p.HPAExecutionBinding == nil {
		return ""
	}
	raw, err := json.Marshal(struct {
		Snapshot  model.CapacityHPAMinimumBinding   `json:"snapshot"`
		Execution model.CapacityHPAExecutionBinding `json:"execution"`
	}{p.AssessmentBinding.Snapshot, *p.HPAExecutionBinding})
	if err != nil {
		return ""
	}
	digest := sha256.Sum256(raw)
	return hex.EncodeToString(digest[:])
}

func NativeProcessAdmission(p model.CapacityPolicySpec, response model.AdapterCapacityPodAdmissionResponse, now time.Time) error {
	b := p.HPAExecutionBinding
	pod, frame := response.Observation, response.Admission
	if b == nil || b.Mode != HPALifetimeExecutionMode || b.AdmissionMode != "process_v2" || response.Operation != ObserveNativePodAdmission || response.Status != "observed" || NativePodIdentity(p, pod, now) != nil || pod.ContainerState != "running" || pod.State != "running" || pod.StartedAt == nil || pod.StartedAt.IsZero() || pod.DeletionRequestedAt != nil || !pod.Protected || frame.SchemaVersion != 2 || frame.Namespace != pod.Namespace || frame.PodName != pod.PodName || frame.PodUID != pod.PodUID || frame.ImageDigest != pod.ImageDigest || frame.LaneRosterSHA256 != NativeRosterDigest(b.Lanes) || !NativeProcessNonce(frame.ProcessNonce) || !Fresh(frame.ObservedAt, now, p.MaxEvidenceAgeSeconds) || frame.ObservedAt.Before(*pod.StartedAt) {
		return fmt.Errorf("current bound native SDK process observation unavailable")
	}
	switch frame.State {
	case "waiting_projection", "invalid_projection", "foreign_process_projection", "origin_changed":
		if frame.Challenge != nil || frame.ChallengeSHA256 != "" || pod.AdmissionReady {
			return fmt.Errorf("waiting SDK frame asserted admission")
		}
	case "projection_observed", "roots_open":
		if frame.Challenge == nil || frame.Challenge.SchemaVersion != 2 || frame.Challenge.ProcessNonce != frame.ProcessNonce || frame.Challenge.PodUID != pod.PodUID || frame.Challenge.Namespace != pod.Namespace || frame.Challenge.PodName != pod.PodName || frame.Challenge.WorkloadUID != pod.WorkloadUID || frame.Challenge.ContainerName != pod.ContainerName || frame.Challenge.ImageDigest != pod.ImageDigest || frame.Challenge.LaneRosterSHA256 != frame.LaneRosterSHA256 || frame.Challenge.IntentGeneration < 1 || !NativeProcessNonce(frame.Challenge.DrainNonce) || frame.Challenge.IssuedAt.Before(*pod.StartedAt) || frame.Challenge.IssuedAt.After(frame.ObservedAt) || len(frame.ChallengeSHA256) != 64 || (pod.AdmissionReady && frame.State != "roots_open") {
			return fmt.Errorf("current SDK projected origin incomplete")
		}
	default:
		return fmt.Errorf("current SDK process remains unavailable for admission")
	}
	return nil
}

func NativeProcessChallenge(p model.CapacityPolicySpec, intent model.CapacityIntent, pod model.NativeTerminationObservation, frame model.NativeProcessAdmissionObservation, now time.Time) (model.NativePodTerminationChallenge, error) {
	response := model.AdapterCapacityPodAdmissionResponse{Operation: ObserveNativePodAdmission, Status: "observed", Observation: pod, Admission: frame}
	if intent.Generation < 1 || NativeProcessAdmission(p, response, now) != nil || frame.State != "waiting_projection" {
		return model.NativePodTerminationChallenge{}, fmt.Errorf("fresh SDK boot observation required before immutable origin")
	}
	return model.NativePodTerminationChallenge{SchemaVersion: 2, Namespace: pod.Namespace, PodName: pod.PodName, PodUID: pod.PodUID, WorkloadUID: pod.WorkloadUID, ContainerName: pod.ContainerName, ImageDigest: pod.ImageDigest, IntentGeneration: intent.Generation, DrainNonce: uuid.NewString(), IssuedAt: now.UTC(), LaneRosterSHA256: frame.LaneRosterSHA256, ProcessNonce: frame.ProcessNonce}, nil
}

func NativeProcessAdmissionCheckpoint(p model.CapacityPolicySpec, checkpoint model.CapacityNativePodCheckpoint, response model.AdapterCapacityPodAdmissionResponse, now time.Time) error {
	if NativeProcessAdmission(p, response, now) != nil || NativePodMatchesCheckpoint(p, checkpoint, response.Observation, now) != nil || response.Observation.StartedAt == nil || !response.Observation.StartedAt.Equal(checkpoint.ContainerStartedAt) || response.Admission.ProcessNonce != checkpoint.ProcessNonce || response.Admission.Challenge == nil {
		return fmt.Errorf("native SDK origin differs from retained lifetime")
	}
	var retained model.NativePodTerminationChallenge
	if json.Unmarshal(checkpoint.Challenge, &retained) != nil {
		return fmt.Errorf("retained native origin unavailable")
	}
	rawExpected, _ := json.Marshal(retained)
	rawActual, _ := json.Marshal(*response.Admission.Challenge)
	digest := sha256.Sum256(checkpoint.OriginChallengeBytes)
	var original model.NativePodTerminationChallenge
	if json.Unmarshal(checkpoint.OriginChallengeBytes, &original) != nil {
		return fmt.Errorf("immutable original projected challenge bytes unavailable")
	}
	originalCanonical, _ := json.Marshal(original)
	if string(rawExpected) != string(rawActual) || string(originalCanonical) != string(rawExpected) || checkpoint.OriginChallengeSHA256 != hex.EncodeToString(digest[:]) || response.Admission.ChallengeSHA256 != checkpoint.OriginChallengeSHA256 {
		return fmt.Errorf("native current projection does not acknowledge immutable origin")
	}
	return nil
}

func NativeAdmissionCandidates(p model.CapacityPolicySpec, response model.AdapterCapacityPodAdmissionCandidatesResponse, now time.Time) error {
	if p.HPAExecutionBinding == nil || p.AssessmentBinding == nil || response.Operation != ObserveNativePodAdmissionCandidates || response.Status != "observed" || !response.Complete || response.BindingName != p.HPAExecutionBinding.PodTerminationBinding || response.Namespace != p.AssessmentBinding.Snapshot.Namespace || response.WorkloadUID != p.AssessmentBinding.Snapshot.WorkloadUID || response.WorkloadResourceVersion == "" || response.ListResourceVersion == "" || !Fresh(response.ObservedAt, now, p.MaxEvidenceAgeSeconds) || len(response.Candidates)+len(response.Unqualified) > 64 {
		return fmt.Errorf("native candidate LIST coverage unavailable")
	}
	seen := map[string]bool{}
	for _, pod := range response.Candidates {
		if NativePodIdentity(p, pod, now) != nil || seen[pod.PodUID] || pod.StartedAt == nil || pod.DeletionRequestedAt != nil || !pod.Protected {
			return fmt.Errorf("native candidate identity incomplete")
		}
		seen[pod.PodUID] = true
	}
	for _, pod := range response.Unqualified {
		if !NativeProcessNonce(pod.PodUID) || seen[pod.PodUID] || pod.PodName == "" || pod.PodResourceVersion == "" || pod.Namespace != response.Namespace || pod.WorkloadUID != response.WorkloadUID || !Fresh(pod.ObservedAt, now, p.MaxEvidenceAgeSeconds) || pod.Receipt != nil || pod.AdmissionReady {
			return fmt.Errorf("unknown old baseline identity cannot be admitted")
		}
		seen[pod.PodUID] = true
	}
	return nil
}
