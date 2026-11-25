package capacity

import (
	"fmt"
	"strings"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

const RetireMigratedNativeOrigin = "capacity.retire_migrated_native_origin"
const MigratedNativeOriginSchema = "native_migrated_origin_administrative_retirement_v1"
const MigratedSourceFenceClass = "root_measured_source_fence_and_complete_absence"

func ValidateMigratedNativeOriginBinding(policy model.Manifest, p model.CapacityPolicySpec, b model.CapacityMigratedNativeOriginBinding) error {
	if !p.ExecutionEnabled || ValidateBoundAssessmentBinding(p) != nil || p.HPAExecutionBinding.Mode != HPALifetimeExecutionMode || b.Schema != MigratedNativeOriginSchema || b.PolicyID != policy.ID.String() || b.PolicyChecksum != policy.Checksum || b.OriginPolicyID == b.PolicyID || b.WorkloadUID == p.AssessmentBinding.Snapshot.WorkloadUID || b.Source.WorkloadUID != b.WorkloadUID || b.Source.NamespaceUID == b.TargetNamespaceUID || b.Source.MeasuredBy != b.OperatorID || b.OriginGeneration < 1 || b.OriginGeneration >= 9007199254740991 || b.ExpectedIntentGeneration < 1 || b.ExpectedIntentFencingToken < 1 || b.ExpectedIntentGeneration >= 9007199254740991 || b.ExpectedIntentFencingToken >= 9007199254740991 || b.ProtectCommandID == b.AdmitCommandID {
		return fmt.Errorf("exact migrated origin and different current Target required")
	}
	for _, v := range []string{b.OriginPolicyID, b.PodUID, b.WorkloadUID, b.ProtectCommandID, b.AdmitCommandID, b.TargetNamespaceUID, b.Source.NamespaceUID} {
		if !NativeProcessNonce(v) {
			return fmt.Errorf("closed migration identity required")
		}
	}
	for _, v := range []string{b.PolicyChecksum, b.OriginPolicyChecksum, b.CheckpointSHA256, b.ProtectCommandSHA256, b.AdmitCommandSHA256, b.Source.EvidenceSHA256, b.Source.FenceEvidenceSHA256} {
		if !ValidDigest(v) {
			return fmt.Errorf("exact retained migration evidence digest required")
		}
	}
	for _, v := range []string{b.PodName, b.ContainerName, b.OperatorID, b.Confirmation} {
		if v == "" || strings.TrimSpace(v) != v || len(v) > 253 || strings.ContainsAny(v, "\r\n\t") {
			return fmt.Errorf("literal named human migration declaration required")
		}
	}
	if !capacityNativeImage(b.ImageDigest) {
		return fmt.Errorf("exact original image required")
	}
	return nil
}

func ValidateMigratedSourceFence(b model.CapacityMigratedNativeOriginBinding, p model.CapacityPolicySpec, now time.Time) error {
	s := b.Source
	if s.Class != MigratedSourceFenceClass || !Fresh(s.ObservedAt, now, p.MaxEvidenceAgeSeconds) || s.ResourceVersion == "" || len(s.ResourceVersion) > 253 || strings.ContainsAny(s.ResourceVersion, "\r\n\t") || s.Generation < 1 || s.ObservedGeneration < s.Generation || !s.CompletePodCensus || !s.OldUIDAbsent || !s.OldNameHTTP404 || !s.ReopeningFenced {
		return fmt.Errorf("fresh explicit Root-measured Source fence and absence required")
	}
	for _, n := range []*int32{s.DesiredReplicas, s.CurrentReplicas, s.ReadyReplicas, s.AvailableReplicas, s.UnavailableReplicas, s.OwnedPods, s.UnattributedMatchingPods} {
		if n == nil || *n != 0 {
			return fmt.Errorf("explicit Source replica zero measurements required")
		}
	}
	return nil
}

func ValidateMigratedNativeTarget(p model.CapacityPolicySpec, b model.CapacityMigratedNativeOriginBinding, e model.CapacityMigratedNativeTargetEvidence, now time.Time) error {
	if CurrentNativeBirthGuard(p, e.BirthGuard, now) != nil || NativeAdmissionCandidates(p, e.Candidates, now) != nil {
		return fmt.Errorf("current Target native graph and complete candidates required")
	}
	if _, err := BoundHPASnapshot(p, e.HPA, now); err != nil {
		return err
	}
	matched, workloadMatched := false, false
	for _, r := range e.BirthGuard.Resources {
		if r.Kind == "Namespace" && r.Name == p.AssessmentBinding.Snapshot.Namespace && r.UID == b.TargetNamespaceUID {
			matched = true
		}
		if r.Kind == "Deployment" && r.UID == p.AssessmentBinding.Snapshot.WorkloadUID && r.Name == p.AssessmentBinding.Snapshot.WorkloadName && r.ResourceVersion == e.HPA.Observation.WorkloadResourceVersion {
			workloadMatched = true
		}
		if r.UID == b.PodUID || r.UID == b.WorkloadUID {
			return fmt.Errorf("retired Source identity is present on Target")
		}
	}
	if !matched || !workloadMatched || e.Candidates.WorkloadResourceVersion != e.HPA.Observation.WorkloadResourceVersion {
		return fmt.Errorf("current Target namespace/workload observations differ")
	}
	for _, pod := range e.Candidates.Candidates {
		if pod.PodUID == b.PodUID {
			return fmt.Errorf("old Source UID remains a candidate")
		}
	}
	for _, pod := range e.Candidates.Unqualified {
		if pod.PodUID == b.PodUID {
			return fmt.Errorf("old Source UID remains unqualified on Target")
		}
	}
	return nil
}
