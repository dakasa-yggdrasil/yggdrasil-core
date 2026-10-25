package capacity

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

// Declared content fixtures only. These never create a compiled approval,
// original SQL authority, native inventory or a useful Notify receipt.
func guestFloorBootstrapUnit(t *testing.T) (model.CapacityPolicySpec, model.CapacityIntent, model.CapacityAssessment, model.CapacityMetricRangeObservation, time.Time) {
	t.Helper()
	policy, p, inventory, now := guestReconcileUnit(t)
	p.Currency, p.MinSamples, p.MaxSampleGapSeconds, p.MaxEvidenceAgeSeconds = "USD", 61, 10, 120
	p.DownHoldSeconds, p.UpHoldSeconds, p.LeaseSeconds, p.ExecutionEnabled = 300, 60, 300, true
	p.Profiles[0].ValidationRef = "declared-unit-only"
	p.Profiles[0].QuoteValidUntil, p.Profiles[0].ValidationValidUntil = now.Add(time.Hour), now.Add(time.Hour)
	baseline, err := GuestReconcileSnapshot(policy, p, inventory, now)
	if err != nil {
		t.Fatal(err)
	}
	a := model.CapacityAssessment{Snapshot: baseline}
	a.Snapshot.Units, a.Snapshot.ResourceVersion = 1, strings.Repeat("6", 64)
	b := p.GuestNotifyReconcileBinding.MemberCoverage
	value, low, high := 1.0, 1.0, 1.0
	reporting := model.CapacityMetricRangeObservation{CapacityEvidence: model.CapacityEvidence{Name: OriginalGuestMemberCoverageName, SourceIdentity: "production/notify/aws/reporting-members", Unit: "members", RequireData: true, Matched: true, DataState: "present", Value: &value, RangeMin: &low, RangeMax: &high, SourceSampledAt: now, WindowStart: now.Add(-30 * time.Second), WindowEnd: now, Samples: 7, CoverageComplete: true, MaxGapSeconds: 5}, Operation: ObserveMetricRange, Binding: b.BindingName, BindingSHA256: b.BindingSHA256, EvaluatedAt: now, OK: true, Reason: "complete"}
	expires := now.Add(time.Minute)
	intent := model.CapacityIntent{Namespace: policy.Metadata.Namespace, PolicyID: policy.ID, PolicyChecksum: policy.Checksum, Environment: p.Environment, Domain: p.Domain, Dimension: p.Dimension, Generation: 1, FencingToken: 1, Phase: "preparing", BaselineSnapshot: baseline, Assessment: model.CapacityAssessment{Snapshot: baseline}, Decision: model.CapacityDecision{Action: "expand", Reason: "protected_floor_recovery", Profile: a.Snapshot.Profile, Units: 1, Floor: 1, ExecutionPermitted: true}, LeaseOwner: "declared-unit-owner", LeaseExecutorID: "declared-unit-executor", LeaseExpiresAt: &expires}
	return p, intent, a, reporting, now
}

func TestOriginalGuestReconcileFloorBootstrapKeepsDemandMissing(t *testing.T) {
	p, intent, a, reporting, now := guestFloorBootstrapUnit(t)
	before, _ := json.Marshal(a)
	if ValidateAssessment(p, a, now) == nil {
		t.Fatal("ordinary readiness accepted absent Demand300")
	}
	for _, phase := range []string{"preparing", "prepared", "canary"} {
		intent.Phase = phase
		if err := ValidateOriginalGuestFloorBootstrap(p, intent, a, reporting, now); err != nil {
			t.Fatal("complete Coverage30 cannot certify first-floor content", phase, err)
		}
	}
	after, _ := json.Marshal(a)
	if string(before) != string(after) || len(a.Evidence) != 0 {
		t.Fatal("floor exception manufactured or changed demand")
	}
	decision, err := Assess(p, a, model.CapacityClockState{}, now)
	if err != nil || decision.Action != "hold" || decision.ExecutionPermitted {
		t.Fatal("floor exception authorized a later demand mutation", err)
	}
	// Ordinary readiness still requires the real complete demand contract.
	v := 2.0
	a.Evidence = []model.CapacityEvidence{{Name: p.Signals[0].Name, SourceIdentity: p.Signals[0].SourceIdentity, Unit: p.Signals[0].Unit, RequireData: true, Matched: true, DataState: "present", Value: &v, RangeMin: &v, RangeMax: &v, SourceSampledAt: now, WindowStart: now.Add(-300 * time.Second), WindowEnd: now, Samples: 61, CoverageComplete: true, MaxGapSeconds: 5}}
	if err := ValidateAssessment(p, a, now); err != nil {
		t.Fatal("complete declared Demand300 content refused", err)
	}
	a.Evidence[0].CoverageComplete = false
	if ValidateAssessment(p, a, now) == nil {
		t.Fatal("incomplete demand became ordinary readiness")
	}
}

func TestOriginalGuestReconcileFloorBootstrapRefusesOtherAuthority(t *testing.T) {
	for _, name := range []string{"nonzero_baseline", "absent_baseline", "baseline_identity", "baseline_profile", "current_identity", "stale_snapshot", "ordinary_expand", "retirement", "above_floor", "not_permitted", "recovery", "degraded", "unclaimed", "unfenced", "absent_owner", "absent_executor", "absent_lease", "expired_lease", "promoted", "draining", "legacy", "missing_reporting", "partial_reporting", "foreign_reporting", "short_reporting", "stale_reporting", "reporting_waited_16s"} {
		t.Run(name, func(t *testing.T) {
			p, intent, a, reporting, now := guestFloorBootstrapUnit(t)
			switch name {
			case "nonzero_baseline":
				intent.BaselineSnapshot.Units = 1
			case "absent_baseline":
				intent.BaselineSnapshot = model.CapacitySnapshot{}
			case "baseline_identity":
				intent.BaselineSnapshot.ResourceUID = "foreign"
			case "baseline_profile":
				intent.BaselineSnapshot.Profile = "foreign"
			case "current_identity":
				a.Snapshot.ResourceUID = "foreign"
			case "stale_snapshot":
				a.Snapshot.ObservedAt = now.Add(-121 * time.Second)
			case "ordinary_expand":
				intent.Decision.Reason = "sustained_pressure"
			case "retirement":
				intent.Decision.Action = "drain"
			case "above_floor":
				intent.Decision.Units, a.Snapshot.Units = 2, 2
			case "not_permitted":
				intent.Decision.ExecutionPermitted = false
			case "recovery":
				intent.RecoveryOnly = true
			case "degraded":
				intent.FloorDegraded = true
			case "unclaimed":
				intent.Generation = 0
			case "unfenced":
				intent.FencingToken = 0
			case "absent_owner":
				intent.LeaseOwner = ""
			case "absent_executor":
				intent.LeaseExecutorID = ""
			case "absent_lease":
				intent.LeaseExpiresAt = nil
			case "expired_lease":
				intent.LeaseExpiresAt = &now
			case "promoted", "draining":
				intent.Phase = name
			case "legacy":
				p.GuestNotifyReconcileBinding = nil
			case "missing_reporting":
				reporting = model.CapacityMetricRangeObservation{}
			case "partial_reporting":
				v := 0.0
				reporting.RangeMin = &v
			case "foreign_reporting":
				reporting.BindingSHA256 = strings.Repeat("0", 64)
			case "short_reporting":
				reporting.WindowStart = now.Add(-29 * time.Second)
			case "stale_reporting":
				reporting.SourceSampledAt = now.Add(-121 * time.Second)
			case "reporting_waited_16s":
				reporting.SourceSampledAt, reporting.WindowEnd, reporting.EvaluatedAt = now.Add(-16*time.Second), now.Add(-16*time.Second), now.Add(-16*time.Second)
				reporting.WindowStart = reporting.WindowEnd.Add(-30 * time.Second)
				if GuestReconcileMemberCoverage(p, reporting, 1, now) != nil {
					t.Fatal("fixture must isolate post-read age from ordinary quality")
				}
			}
			if ValidateOriginalGuestFloorBootstrap(p, intent, a, reporting, now) == nil {
				t.Fatal("foreign, incomplete or ordinary transition accepted as first floor")
			}
		})
	}
}
