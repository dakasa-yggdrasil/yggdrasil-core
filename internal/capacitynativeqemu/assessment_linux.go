//go:build linux && nativequalification

package capacitynativeqemu

import (
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"time"
)

// The signal is explicitly source-controlled qualification demand, never a
// production metric. Units are supplied only by the actual same-writer probes
// or the original empty (no issued/native attempts) realm before first create.
func QualificationAssessment(p model.CapacityPolicySpec, units int, demand float64, at time.Time) model.CapacityAssessment {
	return model.CapacityAssessment{Snapshot: model.CapacitySnapshot{TargetIdentity: p.TargetIdentity, ResourceUID: p.TargetIdentity, WorkloadUID: p.TargetIdentity, WorkloadResourceVersion: "original-qualified-source-v1", ResourceVersion: "original-qualified-source-v1", Owner: p.Owner, Profile: p.Profiles[0].Name, Units: units, ObservedAt: at}, Evidence: []model.CapacityEvidence{{Name: "qualification-demand", SourceIdentity: "source-controlled-native-fixture-demand", Unit: "ratio", RequireData: true, Matched: true, DataState: "present", Value: &demand, RangeMin: &demand, RangeMax: &demand, SourceSampledAt: at, WindowStart: at, WindowEnd: at, Samples: 1, CoverageComplete: true, MaxGapSeconds: 0}}}
}

// Source-controlled demand is sampled over the actual caller-owned interval;
// the native useful snapshot keeps the original probe's separate timestamp.
func QualificationDemandWindow(p model.CapacityPolicySpec, units int, demand float64, probeAt, start, end time.Time) model.CapacityAssessment {
	assessment := QualificationAssessment(p, units, demand, probeAt)
	evidence := &assessment.Evidence[0]
	evidence.SourceSampledAt = end
	evidence.WindowStart = start
	evidence.WindowEnd = end
	return assessment
}
