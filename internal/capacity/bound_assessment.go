package capacity

import (
	"fmt"
	"strings"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

const HPAMinimumSnapshotMode = "native_hpa_minimum_v1"
const ReservedPodEnvelopeUnit = "reserved_pod_envelope"
const ObserveHPAEnvelope = "observe_capacity_envelope"
const ObserveMetricRange = "observe_metric_range_evidence"

func validObservationAdapter(b model.CapacityObservationAdapterBinding) bool {
	instance, e1 := uuid.Parse(b.IntegrationInstanceID)
	typ, e2 := uuid.Parse(b.IntegrationTypeID)
	return e1 == nil && e2 == nil && instance != uuid.Nil && typ != uuid.Nil && instance.String() == b.IntegrationInstanceID && typ.String() == b.IntegrationTypeID && ValidDigest(b.InstanceChecksum) && ValidDigest(b.TypeChecksum)
}

// This initial bound mode is assessment-only. VM membership cannot be compared
// with its pod envelope; old caller-provided actuation cannot use it either.
func ValidateBoundAssessmentBinding(p model.CapacityPolicySpec) error {
	if p.AssessmentBinding == nil {
		return nil
	}
	b := p.AssessmentBinding
	s := b.Snapshot
	if s.Mode != HPAMinimumSnapshotMode || s.Unit != ReservedPodEnvelopeUnit || p.Dimension != ReservedPodEnvelopeUnit || p.ExecutionEnabled || len(p.MutationBindings) != 0 || len(p.Profiles) != 1 || s.Profile != p.Profiles[0].Name || s.Owner != p.Owner || s.ProtectedFloor != p.Floor || s.MaximumReplicas != p.Ceiling || !validObservationAdapter(s.Adapter) {
		return fmt.Errorf("bound HPA assessment requires shadow-only reserved pod units, one profile and no VM mutations")
	}
	for _, name := range []string{s.Namespace, s.HPAName, s.HPAUID, s.WorkloadName, s.WorkloadUID, s.Owner, s.Profile} {
		if strings.TrimSpace(name) != name || name == "" || len(name) > 253 || strings.ContainsAny(name, "/\r\n\t") {
			return fmt.Errorf("bound HPA snapshot requires exact names and immutable identities")
		}
	}
	if len(b.Signals) != len(p.Signals) || len(b.Signals) == 0 || len(b.Signals) > 64 {
		return fmt.Errorf("bound assessment requires every declared signal")
	}
	seen, targets := map[string]bool{}, map[string]bool{}
	for _, signal := range b.Signals {
		found := false
		for _, rule := range p.Signals {
			if rule.Name == signal.Name {
				found = true
			}
		}
		key := signal.Adapter.IntegrationInstanceID + "/" + signal.BindingName
		if !found || seen[signal.Name] || targets[key] || !validObservationAdapter(signal.Adapter) || !ValidDigest(signal.BindingSHA256) || signal.BindingName == "" || len(signal.BindingName) > 128 || strings.TrimSpace(signal.BindingName) != signal.BindingName {
			return fmt.Errorf("bound metric signal requires unique exact approved provider binding")
		}
		seen[signal.Name], targets[key] = true, true
	}
	return nil
}

func BoundHPASnapshot(p model.CapacityPolicySpec, r model.CapacityHPAEnvelopeResponse, now time.Time) (model.CapacitySnapshot, error) {
	var snapshot model.CapacitySnapshot
	if ValidateBoundAssessmentBinding(p) != nil || p.AssessmentBinding == nil {
		return snapshot, fmt.Errorf("HPA assessment binding unavailable")
	}
	b := p.AssessmentBinding.Snapshot
	s := r.Observation
	at, err := vmTime(s.ObservedAt, p, now)
	if err != nil || r.Operation != ObserveHPAEnvelope || r.Status != "observed" || s.Namespace != b.Namespace || s.HPAName != b.HPAName || s.HPAUID != b.HPAUID || s.WorkloadName != b.WorkloadName || s.WorkloadUID != b.WorkloadUID || s.Owner != b.Owner || s.ResourceVersion == "" || s.WorkloadResourceVersion == "" || s.APIGeneration < 1 || s.EnvelopeGeneration < 1 || s.IdempotencyKey == "" || s.ProtectedFloor != b.ProtectedFloor || s.TrackedProtectedFloor != b.ProtectedFloor || s.MaximumReplicas != b.MaximumReplicas || s.MinReplicas < p.Floor || s.MaxReplicas < s.MinReplicas || s.MaxReplicas > p.Ceiling || !s.MatchedOwner || !s.BoundsWithinScope || !s.TrackingMatchesScope || !s.BoundsMatchTracking || s.ControllerOwned || !s.DiagnosticOnly || s.AtomicSnapshot || s.WarmCapacityVerified || s.WorkloadDrainVerified {
		return snapshot, fmt.Errorf("native HPA reserved envelope lacks exact fresh owner, UID, version or bounds evidence")
	}
	snapshot = model.CapacitySnapshot{TargetIdentity: p.TargetIdentity, ResourceUID: s.HPAUID, ResourceVersion: s.ResourceVersion, WorkloadUID: s.WorkloadUID, WorkloadResourceVersion: s.WorkloadResourceVersion, Owner: p.Owner, Profile: b.Profile, Units: s.MinReplicas, ObservedAt: at}
	return snapshot, nil
}

// Quality failures retain their explicit data state and null/diagnostic values.
// Assess then holds; configuration/identity/schema mismatches are refused.
func BoundMetricEvidence(p model.CapacityPolicySpec, b model.CapacityMetricSignalBinding, r model.CapacityMetricRangeObservation, now time.Time) (model.CapacityEvidence, error) {
	var rule *model.CapacitySignalRule
	for i := range p.Signals {
		if p.Signals[i].Name == b.Name {
			rule = &p.Signals[i]
		}
	}
	if rule == nil || r.Operation != ObserveMetricRange || r.Binding != b.BindingName || r.BindingSHA256 != b.BindingSHA256 || r.Name != rule.Name || r.SourceIdentity != rule.SourceIdentity || r.Unit != rule.Unit || !r.RequireData || !Fresh(r.EvaluatedAt, now, p.MaxEvidenceAgeSeconds) || r.Reason == "" || r.OK != r.CoverageComplete {
		return model.CapacityEvidence{}, fmt.Errorf("metric range response differs from exact bound source")
	}
	switch r.DataState {
	case "missing", "invalid", "non_finite", "present":
	default:
		return model.CapacityEvidence{}, fmt.Errorf("unknown metric source quality")
	}
	if r.OK && (r.DataState != "present" || !r.Matched || r.Reason != "complete") {
		return model.CapacityEvidence{}, fmt.Errorf("metric response claims complete invalid data")
	}
	return r.CapacityEvidence, nil
}
