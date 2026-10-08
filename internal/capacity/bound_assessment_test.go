package capacity

import (
	"strings"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

func boundAssessmentFixture() (model.CapacityPolicySpec, model.CapacityHPAEnvelopeResponse, model.CapacityMetricRangeObservation, time.Time) {
	now := time.Now().UTC()
	p, _ := fixture(now)
	p.ExecutionEnabled = false
	p.Dimension = ReservedPodEnvelopeUnit
	p.Profiles = p.Profiles[:1]
	adapter := model.CapacityObservationAdapterBinding{IntegrationInstanceID: "11111111-1111-4111-8111-111111111111", InstanceChecksum: strings.Repeat("a", 64), IntegrationTypeID: "22222222-2222-4222-8222-222222222222", TypeChecksum: strings.Repeat("b", 64)}
	p.AssessmentBinding = &model.CapacityBoundAssessmentBinding{Snapshot: model.CapacityHPAMinimumBinding{Mode: HPAMinimumSnapshotMode, Unit: ReservedPodEnvelopeUnit, Adapter: adapter, Namespace: "platform", HPAName: "api-hpa", HPAUID: "hpa-1", WorkloadName: "api", WorkloadUID: "deployment-1", Owner: p.Owner, Profile: "base", ProtectedFloor: p.Floor, MaximumReplicas: p.Ceiling}, Signals: []model.CapacityMetricSignalBinding{{Name: p.Signals[0].Name, Adapter: adapter, BindingName: "fixed-pressure", BindingSHA256: strings.Repeat("c", 64)}}}
	hpa := model.CapacityHPAEnvelopeResponse{Operation: ObserveHPAEnvelope, Status: "observed", Observation: model.CapacityHPAEnvelopeObservation{Namespace: "platform", HPAName: "api-hpa", HPAUID: "hpa-1", ResourceVersion: "10", APIGeneration: 3, WorkloadName: "api", WorkloadUID: "deployment-1", WorkloadResourceVersion: "30", Owner: p.Owner, EnvelopeGeneration: 1, IdempotencyKey: "intent-1", MinReplicas: 2, MaxReplicas: 8, ProtectedFloor: p.Floor, TrackedProtectedFloor: p.Floor, MaximumReplicas: p.Ceiling, CurrentReplicas: 7, DesiredReplicas: 9, MatchedOwner: true, BoundsWithinScope: true, TrackingMatchesScope: true, BoundsMatchTracking: true, DiagnosticOnly: true, ObservedAt: now.Format(time.RFC3339Nano)}}
	v := .9
	metric := model.CapacityMetricRangeObservation{CapacityEvidence: model.CapacityEvidence{Name: p.Signals[0].Name, SourceIdentity: p.Signals[0].SourceIdentity, Unit: p.Signals[0].Unit, RequireData: true, Matched: true, DataState: "present", Value: &v, RangeMin: &v, RangeMax: &v, SourceSampledAt: now, WindowStart: now.Add(-time.Minute), WindowEnd: now, Samples: 5, CoverageComplete: true, MaxGapSeconds: 15}, Operation: ObserveMetricRange, Binding: "fixed-pressure", BindingSHA256: strings.Repeat("c", 64), EvaluatedAt: now, OK: true, Reason: "complete"}
	return p, hpa, metric, now
}

func TestBoundAssessmentPreservesReservedPodUnitAndStrictSourceQuality(t *testing.T) {
	p, hpa, metric, now := boundAssessmentFixture()
	if err := ValidatePolicy(p); err != nil {
		t.Fatal(err)
	}
	s, err := BoundHPASnapshot(p, hpa, now)
	if err != nil || s.Units != 2 || s.Units == hpa.Observation.CurrentReplicas || s.Units == hpa.Observation.DesiredReplicas {
		t.Fatal("pod reservation became actual/ready/VM count", s, err)
	}
	e, err := BoundMetricEvidence(p, p.AssessmentBinding.Signals[0], metric, now)
	if err != nil || e.Value == nil || *e.Value != .9 {
		t.Fatal(e, err)
	}
	metric.OK, metric.CoverageComplete, metric.DataState, metric.Reason = false, false, "missing", "missing"
	metric.Value, metric.RangeMin, metric.RangeMax = nil, nil, nil
	e, err = BoundMetricEvidence(p, p.AssessmentBinding.Signals[0], metric, now)
	if err != nil || e.Value != nil || e.DataState != "missing" {
		t.Fatal("missing source became zero", e, err)
	}
	d, err := Assess(p, model.CapacityAssessment{Snapshot: s, Evidence: []model.CapacityEvidence{e}}, model.CapacityClockState{}, now)
	if err != nil || d.Action != "hold" || d.ExecutionPermitted {
		t.Fatal("missing bound data approved action", d, err)
	}
}

func TestBoundAssessmentRefusesUnitMixingAndCallerExecution(t *testing.T) {
	for _, mode := range []string{"execution", "vm_mutations", "profile_migration", "unit", "signal_missing", "signal_duplicate", "adapter_revision", "binding_hash"} {
		t.Run(mode, func(t *testing.T) {
			p, _, _, _ := boundAssessmentFixture()
			switch mode {
			case "execution":
				p.ExecutionEnabled = true
			case "vm_mutations":
				p.MutationBindings = []model.CapacityMutationBinding{{Name: "vm"}}
			case "profile_migration":
				p.Profiles = append(p.Profiles, p.Profiles[0])
			case "unit":
				p.AssessmentBinding.Snapshot.Unit = "vm_members"
			case "signal_missing":
				p.AssessmentBinding.Signals = nil
			case "signal_duplicate":
				p.AssessmentBinding.Signals = append(p.AssessmentBinding.Signals, p.AssessmentBinding.Signals[0])
			case "adapter_revision":
				p.AssessmentBinding.Snapshot.Adapter.TypeChecksum = ""
			case "binding_hash":
				p.AssessmentBinding.Signals[0].BindingSHA256 = ""
			}
			if ValidatePolicy(p) == nil {
				t.Fatal("unsafe bound mode accepted", mode)
			}
		})
	}
}

func TestBoundAssessmentRefusesForeignOrIncompleteHPAAndMetric(t *testing.T) {
	for _, mode := range []string{"hpa_uid", "workload_uid", "resource_version", "workload_version", "owner", "tracking", "controller", "warmth", "stale", "fingerprint", "metric_identity", "require_data", "evaluation_time"} {
		t.Run(mode, func(t *testing.T) {
			p, hpa, metric, now := boundAssessmentFixture()
			switch mode {
			case "hpa_uid":
				hpa.Observation.HPAUID = "other"
			case "workload_uid":
				hpa.Observation.WorkloadUID = "other"
			case "resource_version":
				hpa.Observation.ResourceVersion = ""
			case "workload_version":
				hpa.Observation.WorkloadResourceVersion = ""
			case "owner":
				hpa.Observation.Owner = "other"
			case "tracking":
				hpa.Observation.BoundsMatchTracking = false
			case "controller":
				hpa.Observation.ControllerOwned = true
			case "warmth":
				hpa.Observation.WarmCapacityVerified = true
			case "stale":
				hpa.Observation.ObservedAt = now.Add(-time.Hour).Format(time.RFC3339Nano)
			case "fingerprint":
				metric.BindingSHA256 = strings.Repeat("d", 64)
			case "metric_identity":
				metric.SourceIdentity = "other"
			case "require_data":
				metric.RequireData = false
			case "evaluation_time":
				metric.EvaluatedAt = now.Add(-time.Hour)
			}
			if strings.HasPrefix(mode, "metric") || mode == "fingerprint" || mode == "require_data" || mode == "evaluation_time" {
				if _, err := BoundMetricEvidence(p, p.AssessmentBinding.Signals[0], metric, now); err == nil {
					t.Fatal("foreign metric accepted")
				}
			} else if _, err := BoundHPASnapshot(p, hpa, now); err == nil {
				t.Fatal("unbound HPA accepted")
			}
		})
	}
}
