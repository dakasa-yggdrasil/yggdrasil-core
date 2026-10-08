package capacity

import (
	"math"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

func fixture(now time.Time) (model.CapacityPolicySpec, model.CapacityAssessment) {
	p := model.CapacityPolicySpec{Environment: "production", Domain: "api", Dimension: "replicas", TargetIdentity: "cluster/ns/api", Owner: "capacity-api", Workflow: model.ManifestSelector{Namespace: "ops", Name: "scale-api"}, Currency: "USD", Floor: 2, Ceiling: 50, Step: 2, MaxEvidenceAgeSeconds: 60, MaxSampleGapSeconds: 30, MinSamples: 3, UpHoldSeconds: 30, DownHoldSeconds: 120, CooldownSeconds: 60, LeaseSeconds: 30, ExecutionEnabled: true,
		Signals:  []model.CapacitySignalRule{{Name: "load", SourceIdentity: "prometheus/api", Unit: "ratio", UpAbove: 0.8, DownBelow: 0.3}},
		Profiles: []model.CapacityProfile{{Name: "base", Provider: "provider", Region: "region", MinUnits: 2, MaxUnits: 50, UnitMonthlyCostMinor: 100, QuoteValidUntil: now.Add(time.Hour), ValidationValidUntil: now.Add(time.Hour), ValidationRef: "receipt:validated", ReadinessSeconds: 10}}}
	value := 0.9
	a := model.CapacityAssessment{Snapshot: model.CapacitySnapshot{TargetIdentity: p.TargetIdentity, ResourceUID: "hpa-1", WorkloadUID: "deployment-1", WorkloadResourceVersion: "10", ResourceVersion: "10", Owner: p.Owner, Profile: "base", Units: 4, ObservedAt: now}, Evidence: []model.CapacityEvidence{{Name: "load", SourceIdentity: "prometheus/api", Unit: "ratio", RequireData: true, Matched: true, DataState: "present", Value: &value, RangeMin: &value, RangeMax: &value, SourceSampledAt: now, WindowStart: now.Add(-time.Minute), WindowEnd: now, Samples: 10, CoverageComplete: true, MaxGapSeconds: 15}}}
	return p, a
}

func refresh(a model.CapacityAssessment, now time.Time, value float64) model.CapacityAssessment {
	a.Snapshot.ObservedAt = now
	e := a.Evidence[0]
	e.Value, e.RangeMin, e.RangeMax = &value, &value, &value
	e.SourceSampledAt, e.WindowEnd = now, now
	a.Evidence = []model.CapacityEvidence{e}
	return a
}

func TestCapacityPlannerStrictEvidence(t *testing.T) {
	now := time.Now().UTC()
	for _, test := range []struct {
		name   string
		mutate func(*model.CapacityAssessment)
	}{
		{"missing", func(a *model.CapacityAssessment) { a.Evidence = nil }},
		{"legacy", func(a *model.CapacityAssessment) { a.Evidence[0].RequireData = false }},
		{"nan", func(a *model.CapacityAssessment) { v := math.NaN(); a.Evidence[0].Value = &v }},
		{"stale_source", func(a *model.CapacityAssessment) { a.Evidence[0].SourceSampledAt = now.Add(-2 * time.Minute) }},
		{"future_source", func(a *model.CapacityAssessment) { a.Evidence[0].SourceSampledAt = now.Add(time.Minute) }},
		{"coverage", func(a *model.CapacityAssessment) { a.Evidence[0].CoverageComplete = false }},
		{"gap", func(a *model.CapacityAssessment) { a.Evidence[0].MaxGapSeconds = 31 }},
		{"unit", func(a *model.CapacityAssessment) { a.Evidence[0].Unit = "seconds" }},
		{"duplicate", func(a *model.CapacityAssessment) { a.Evidence = append(a.Evidence, a.Evidence[0]) }},
		{"range", func(a *model.CapacityAssessment) { v := 0.1; a.Evidence[0].RangeMax = &v }},
	} {
		t.Run(test.name, func(t *testing.T) {
			p, a := fixture(now)
			test.mutate(&a)
			d, err := Assess(p, a, model.CapacityClockState{}, now)
			if err != nil || d.Action != "hold" || d.ExecutionPermitted || !d.Clock.DownSince.IsZero() {
				t.Fatalf("unsafe decision: %+v err=%v", d, err)
			}
		})
	}
}

func TestCapacityPlannerHysteresisAndResourceReset(t *testing.T) {
	now := time.Now().UTC()
	p, a := fixture(now)
	d, err := Assess(p, a, model.CapacityClockState{}, now)
	if err != nil || d.Reason != "up_window_pending" {
		t.Fatalf("%+v %v", d, err)
	}
	later := now.Add(30 * time.Second)
	a = refresh(a, later, 0.9)
	d, err = Assess(p, a, d.Clock, later)
	if err != nil || d.Action != "expand" || d.Units != 6 {
		t.Fatalf("%+v %v", d, err)
	}
	a.Snapshot.WorkloadUID = "deployment-2"
	d, err = Assess(p, a, d.Clock, later)
	if err != nil || d.Action != "hold" || !d.Clock.UpSince.Equal(later) {
		t.Fatalf("resource replacement inherited hold: %+v %v", d, err)
	}
}

func TestCapacityPlannerSustainedSurplus(t *testing.T) {
	now := time.Now().UTC()
	p, a := fixture(now)
	a = refresh(a, now, 0.1)
	a.Evidence[0].WindowStart = now.Add(-5 * time.Minute)
	d, _ := Assess(p, a, model.CapacityClockState{}, now)
	for i := 1; i <= 4; i++ {
		at := now.Add(time.Duration(i) * 30 * time.Second)
		a = refresh(a, at, 0.1)
		d, _ = Assess(p, a, d.Clock, at)
	}
	if d.Action != "drain" || d.Units != 2 {
		t.Fatalf("%+v", d)
	}
	// A recent low sample with an earlier high value cannot prove surplus.
	v := 0.7
	a.Evidence[0].RangeMax = &v
	d, _ = Assess(p, a, d.Clock, now.Add(120*time.Second))
	if d.Action != "hold" {
		t.Fatalf("range was ignored: %+v", d)
	}
}

func TestCapacityPlannerFloorProfilesAndShadow(t *testing.T) {
	now := time.Now().UTC()
	p, a := fixture(now)
	a.Snapshot.Units = 0
	d, _ := Assess(p, a, model.CapacityClockState{}, now)
	if d.Action != "expand" || d.Units != p.Floor {
		t.Fatalf("floor was not restored: %+v", d)
	}
	p.ExecutionEnabled = false
	d, _ = Assess(p, a, model.CapacityClockState{}, now)
	if d.ExecutionPermitted {
		t.Fatal("shadow enabled execution")
	}
	p.Profiles[0].QuoteValidUntil = now.Add(5 * time.Second)
	d, _ = Assess(p, a, model.CapacityClockState{}, now)
	if d.Action != "hold" {
		t.Fatal("quote expires before readiness")
	}
	p, a = fixture(now)
	p.Profiles = append(p.Profiles, model.CapacityProfile{Name: "cheap-large", Provider: "other", Region: "region", MinUnits: 20, MaxUnits: 50, UnitMonthlyCostMinor: 1, QuoteValidUntil: now.Add(time.Hour), ValidationValidUntil: now.Add(time.Hour), ValidationRef: "receipt", ReadinessSeconds: 10})
	profile, ok := cheapestEligible(p, 2, now)
	if !ok || profile.Name != "base" {
		t.Fatal("downshift selected oversized profile")
	}
}

func TestCapacityPlannerPolicyAndGapReset(t *testing.T) {
	now := time.Now().UTC()
	p, a := fixture(now)
	d, _ := Assess(p, a, model.CapacityClockState{}, now)
	later := now.Add(45 * time.Second)
	a = refresh(a, later, 0.9)
	d, _ = Assess(p, a, d.Clock, later)
	if d.Action != "hold" || !d.Clock.UpSince.Equal(later) {
		t.Fatal("observation gap inherited hysteresis")
	}
	p.Step = 3
	later = later.Add(30 * time.Second)
	a = refresh(a, later, 0.9)
	d, _ = Assess(p, a, d.Clock, later)
	if d.Action != "hold" || !d.Clock.UpSince.Equal(later) {
		t.Fatal("policy change inherited hysteresis")
	}
}
