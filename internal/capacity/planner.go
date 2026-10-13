// Package capacity plans bounded changes from explicit, independently fresh evidence.
// It never calls a provider or treats absent metrics as idle demand.
package capacity

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

// ValidatePolicy rejects ambiguous scope, invalid budgets and unsafe numeric inputs.
func ValidatePolicy(p model.CapacityPolicySpec) error {
	for label, value := range map[string]string{"environment": p.Environment, "domain": p.Domain, "dimension": p.Dimension, "target_identity": p.TargetIdentity, "owner": p.Owner} {
		if strings.TrimSpace(value) == "" || len(value) > 256 {
			return fmt.Errorf("capacity %s is required and bounded", label)
		}
	}
	if p.Workflow.ManifestID != "" || p.Workflow.Version != nil || strings.TrimSpace(p.Workflow.Namespace) == "" || strings.TrimSpace(p.Workflow.Name) == "" {
		return fmt.Errorf("capacity workflow requires exact logical namespace/name without version or manifest ID")
	}
	if len(p.Currency) != 3 || strings.IndexFunc(p.Currency, func(r rune) bool { return r < 'A' || r > 'Z' }) >= 0 {
		return fmt.Errorf("capacity currency requires an uppercase three-letter code")
	}
	if p.Floor < 1 || p.Ceiling < p.Floor || p.Ceiling > 100000 || p.Step < 1 || p.Step > p.Ceiling {
		return fmt.Errorf("capacity floor/ceiling/step are invalid")
	}
	if p.MaxEvidenceAgeSeconds < 1 || p.MaxEvidenceAgeSeconds > 3600 || p.MinSamples < 1 || p.MinSamples > 100000 || p.MaxSampleGapSeconds < 1 || p.MaxSampleGapSeconds > p.MaxEvidenceAgeSeconds {
		return fmt.Errorf("capacity evidence age and samples are invalid")
	}
	if p.UpHoldSeconds < 0 || p.DownHoldSeconds < 1 || p.DownHoldSeconds < p.UpHoldSeconds || p.DownHoldSeconds > 86400 || p.CooldownSeconds < 0 || p.CooldownSeconds > 86400 {
		return fmt.Errorf("capacity hysteresis/cooldown is invalid")
	}
	if p.LeaseSeconds < 5 || p.LeaseSeconds > 300 {
		return fmt.Errorf("capacity lease must be between 5 and 300 seconds")
	}
	if len(p.Signals) == 0 || len(p.Signals) > 64 || len(p.Profiles) == 0 || len(p.Profiles) > 64 {
		return fmt.Errorf("capacity requires bounded signals and profiles")
	}
	names := map[string]bool{}
	for _, s := range p.Signals {
		if s.Name == "" || s.SourceIdentity == "" || s.Unit == "" || names[s.Name] || !finite(s.UpAbove) || !finite(s.DownBelow) || s.DownBelow >= s.UpAbove {
			return fmt.Errorf("capacity signal identity/unit/threshold is invalid")
		}
		names[s.Name] = true
	}
	names = map[string]bool{}
	for _, profile := range p.Profiles {
		if profile.Name == "" || names[profile.Name] || profile.Provider == "" || profile.Region == "" || profile.ValidationRef == "" || profile.QuoteValidUntil.IsZero() || profile.ValidationValidUntil.IsZero() {
			return fmt.Errorf("capacity profile requires unique name, provider, region and dated validation/quote")
		}
		if profile.MinUnits < p.Floor || profile.MaxUnits < profile.MinUnits || profile.MaxUnits > p.Ceiling || profile.UnitMonthlyCostMinor < 0 || profile.UnitMonthlyCostMinor > 1000000000000 || profile.ReadinessSeconds < 0 || profile.ReadinessSeconds > 86400 {
			return fmt.Errorf("capacity profile budget is invalid")
		}
		names[profile.Name] = true
	}
	if err := ValidateMutationBindings(p); err != nil {
		return err
	}
	return ValidateBoundAssessmentBinding(p)
}

// Assess requires every declared signal and a matching current resource snapshot.
// Profiles change only after sustained pressure; a new profile requires preparation.
func Assess(p model.CapacityPolicySpec, a model.CapacityAssessment, previous model.CapacityClockState, now time.Time) (model.CapacityDecision, error) {
	if err := ValidatePolicy(p); err != nil {
		return model.CapacityDecision{}, err
	}
	s := a.Snapshot
	d := model.CapacityDecision{Action: "hold", Reason: "within_envelope", Profile: s.Profile, Units: s.Units, Floor: p.Floor, Clock: previous}
	if s.TargetIdentity != p.TargetIdentity || s.Owner != p.Owner || s.ResourceUID == "" || s.WorkloadUID == "" || s.WorkloadResourceVersion == "" || s.ResourceVersion == "" || s.Units < 0 || s.Units > p.Ceiling || !fresh(s.ObservedAt, now, p.MaxEvidenceAgeSeconds) {
		return holdUnknown(d, "snapshot_unavailable"), nil
	}
	if !knownProfile(p, s.Profile) {
		return holdUnknown(d, "current_profile_unknown"), nil
	}
	if s.Units < p.Floor {
		profile, exists := selectEligibleProfile(p, p.Floor, now, true)
		if !exists {
			d.Reason = "validated_profile_unavailable"
			return d, nil
		}
		d.Units, d.Profile, d.Reason = max(p.Floor, profile.MinUnits), profile.Name, "protected_floor_recovery"
		d.Action = "expand"
		if profile.Name != s.Profile {
			d.Action = "prepare"
		}
		d.ExecutionPermitted = p.ExecutionEnabled
		d.Clock.UpSince, d.Clock.DownSince = time.Time{}, time.Time{}
		return d, nil
	}
	observations := map[string]model.CapacityEvidence{}
	for _, evidence := range a.Evidence {
		if _, exists := observations[evidence.Name]; exists {
			return holdUnknown(d, "duplicate_signal"), nil
		}
		observations[evidence.Name] = evidence
	}
	if len(observations) != len(p.Signals) {
		return holdUnknown(d, "signal_coverage_missing"), nil
	}
	up, down := false, true
	windowStart := time.Time{}
	for _, rule := range p.Signals {
		e, exists := observations[rule.Name]
		if !exists || !e.RequireData || !e.Matched || e.DataState != "present" || e.Value == nil || !finite(*e.Value) || e.SourceIdentity != rule.SourceIdentity || e.Unit != rule.Unit || e.Samples < p.MinSamples || !e.CoverageComplete || e.MaxGapSeconds < 0 || e.MaxGapSeconds > p.MaxSampleGapSeconds || !fresh(e.SourceSampledAt, now, p.MaxEvidenceAgeSeconds) || !fresh(e.WindowEnd, now, p.MaxEvidenceAgeSeconds) || e.WindowStart.IsZero() || e.WindowStart.After(e.WindowEnd) || e.SourceSampledAt.Before(e.WindowStart) || e.SourceSampledAt.After(e.WindowEnd.Add(5*time.Second)) {
			return holdUnknown(d, "signal_evidence_unavailable"), nil
		}
		if e.RangeMin == nil || e.RangeMax == nil || !finite(*e.RangeMin) || !finite(*e.RangeMax) || *e.RangeMin > *e.Value || *e.RangeMax < *e.Value || *e.RangeMin > *e.RangeMax {
			return holdUnknown(d, "signal_evidence_unavailable"), nil
		}
		if windowStart.IsZero() || e.WindowStart.After(windowStart) {
			windowStart = e.WindowStart
		}
		up = up || (*e.Value >= rule.UpAbove && (p.UpHoldSeconds == 0 || *e.RangeMin >= rule.UpAbove))
		down = down && *e.RangeMax <= rule.DownBelow
	}
	policyJSON, _ := json.Marshal(p) // ValidatePolicy already excludes non-finite numbers.
	fingerprint := fmt.Sprintf("%x", sha256.Sum256(policyJSON))
	if previous.PolicyFingerprint != fingerprint || previous.ResourceUID != s.ResourceUID || previous.WorkloadUID != s.WorkloadUID || previous.WorkloadResourceVersion != s.WorkloadResourceVersion || previous.Profile != s.Profile || previous.LastObservedAt.IsZero() || !fresh(previous.LastObservedAt, now, p.MaxSampleGapSeconds) {
		d.Clock.UpSince, d.Clock.DownSince = time.Time{}, time.Time{}
	}
	d.Clock.PolicyFingerprint, d.Clock.ResourceUID, d.Clock.WorkloadUID, d.Clock.Profile = fingerprint, s.ResourceUID, s.WorkloadUID, s.Profile
	d.Clock.WorkloadResourceVersion = s.WorkloadResourceVersion
	d.Clock.LastObservedAt = now

	if up {
		d.Clock.DownSince = time.Time{}
		if d.Clock.UpSince.IsZero() {
			d.Clock.UpSince = now
		}
		if now.Sub(d.Clock.UpSince) < time.Duration(p.UpHoldSeconds)*time.Second || windowStart.After(now.Add(-time.Duration(p.UpHoldSeconds)*time.Second)) {
			d.Reason = "up_window_pending"
			return d, nil
		}
	} else if down {
		d.Clock.UpSince = time.Time{}
		if d.Clock.DownSince.IsZero() {
			d.Clock.DownSince = now
		}
		if now.Sub(d.Clock.DownSince) < time.Duration(p.DownHoldSeconds)*time.Second || windowStart.After(now.Add(-time.Duration(p.DownHoldSeconds)*time.Second)) {
			d.Reason = "down_window_pending"
			return d, nil
		}
	} else {
		d.Clock.UpSince, d.Clock.DownSince = time.Time{}, time.Time{}
		return d, nil
	}
	if !previous.LastActionAt.IsZero() && now.Sub(previous.LastActionAt) < time.Duration(p.CooldownSeconds)*time.Second {
		d.Reason = "cooldown"
		return d, nil
	}
	var wanted int
	if up {
		wanted = min(p.Ceiling, s.Units+p.Step)
	} else {
		wanted = max(p.Floor, s.Units-p.Step)
	}
	profile, exists := cheapestEligible(p, wanted, now)
	if !exists {
		d.Reason = "validated_profile_unavailable"
		return d, nil
	}
	wanted = max(wanted, profile.MinUnits)
	if wanted == s.Units && profile.Name == s.Profile {
		d.Reason = "capacity_boundary"
		return d, nil
	}
	d.Profile, d.Units = profile.Name, wanted
	if profile.Name != s.Profile {
		d.Action, d.Reason = "prepare", "profile_transition_required"
	} else if wanted > s.Units {
		d.Action, d.Reason = "expand", "sustained_pressure"
	} else {
		d.Action, d.Reason = "drain", "sustained_surplus"
	}
	d.ExecutionPermitted = p.ExecutionEnabled
	return d, nil
}

func holdUnknown(d model.CapacityDecision, reason string) model.CapacityDecision {
	d.Reason = reason
	d.ExecutionPermitted = false
	d.Clock.UpSince, d.Clock.DownSince = time.Time{}, time.Time{}
	return d
}

func knownProfile(p model.CapacityPolicySpec, name string) bool {
	for _, profile := range p.Profiles {
		if profile.Name == name {
			return true
		}
	}
	return false
}

func cheapestEligible(p model.CapacityPolicySpec, units int, now time.Time) (model.CapacityProfile, bool) {
	return selectEligibleProfile(p, units, now, false)
}

func selectEligibleProfile(p model.CapacityPolicySpec, units int, now time.Time, floorRepair bool) (model.CapacityProfile, bool) {
	var selected model.CapacityProfile
	found := false
	for _, candidate := range p.Profiles {
		horizon := now.Add(time.Duration(candidate.ReadinessSeconds) * time.Second)
		if (!floorRepair && candidate.MinUnits > units) || candidate.MaxUnits < units || !candidate.QuoteValidUntil.After(horizon) || !candidate.ValidationValidUntil.After(horizon) {
			continue
		}
		cost := candidate.UnitMonthlyCostMinor * int64(max(units, candidate.MinUnits))
		selectedCost := selected.UnitMonthlyCostMinor * int64(max(units, selected.MinUnits))
		if !found || cost < selectedCost || (cost == selectedCost && candidate.Name < selected.Name) {
			selected, found = candidate, true
		}
	}
	return selected, found
}

func finite(value float64) bool { return !math.IsNaN(value) && !math.IsInf(value, 0) }

// Fresh bounds source/receipt times. Query evaluation timestamps alone cannot
// satisfy this contract.
func Fresh(at, now time.Time, maxAge int) bool { return fresh(at, now, maxAge) }

func ValidateSnapshot(p model.CapacityPolicySpec, a model.CapacityAssessment, now time.Time) error {
	s := a.Snapshot
	if s.TargetIdentity != p.TargetIdentity || s.Owner != p.Owner || s.ResourceUID == "" || s.WorkloadUID == "" || s.WorkloadResourceVersion == "" || s.ResourceVersion == "" || s.Units < 0 || s.Units > p.Ceiling || !fresh(s.ObservedAt, now, p.MaxEvidenceAgeSeconds) || !knownProfile(p, s.Profile) {
		return fmt.Errorf("capacity snapshot rejected")
	}
	return nil
}

// ValidateAssessment applies the same strict evidence checks without requiring
// a scale decision. Canary and drain receipts may legitimately show normal load.
func ValidateAssessment(p model.CapacityPolicySpec, a model.CapacityAssessment, now time.Time) error {
	if err := ValidateSnapshot(p, a, now); err != nil {
		return err
	}
	// Floor repair itself may proceed without demand telemetry, but declaring
	// readiness/canary/drain still requires the full strict metric contract.
	checked := a
	checked.Snapshot.Units = max(p.Floor, checked.Snapshot.Units)
	d, err := Assess(p, checked, model.CapacityClockState{}, now)
	if err != nil {
		return err
	}
	switch d.Reason {
	case "snapshot_unavailable", "current_profile_unknown", "duplicate_signal", "signal_coverage_missing", "signal_evidence_unavailable":
		return fmt.Errorf("capacity evidence rejected: %s", d.Reason)
	}
	return nil
}
func fresh(at, now time.Time, maxAge int) bool {
	return !at.IsZero() && !at.After(now.Add(5*time.Second)) && !at.Before(now.Add(-time.Duration(maxAge)*time.Second))
}
