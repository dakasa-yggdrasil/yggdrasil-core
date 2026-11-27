package capacity

import (
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

// IsNativeWorkerRetirementOnly classifies the freshly recomputed decision. It
// grants no provider mutation, admission or drain authority on its own. Existing
// workload/PDB/ownership and native absence proofs still precede retirement.
// "No new allocation" does not assert that traffic or elapsed VM time is free.
func IsNativeWorkerRetirementOnly(p model.CapacityPolicySpec, a model.CapacityAssessment, d model.CapacityDecision) bool {
	minimum, known := nativeWorkerRetirementMinimum(p, a.Snapshot.Profile)
	return p.NativeWorkerPoolBinding != nil && p.MarketBinding != nil &&
		d.Action == "drain" && d.Reason == "sustained_surplus_retirement_only" &&
		d.Profile == a.Snapshot.Profile && known && d.Units >= minimum && d.Units < a.Snapshot.Units
}

func nativeWorkerRetirementMinimum(p model.CapacityPolicySpec, name string) (int, bool) {
	for _, profile := range p.Profiles {
		if profile.Name == name {
			return max(p.Floor, profile.MinUnits), true
		}
	}
	return 0, false
}

func nativeMarketLedgerCurrent(p model.CapacityPolicySpec, s model.CapacitySnapshot, l *MarketLedgerObservation, now time.Time) bool {
	return l != nil && l.Complete && l.TargetIdentity == p.TargetIdentity &&
		l.Owner == p.Owner && l.CurrentProfile == s.Profile && l.CurrentUnits == s.Units &&
		l.CurrentPoolEpoch == p.NativeWorkerPoolBinding.ExpectedPoolEpoch &&
		l.BudgetScope == p.MarketBinding.BudgetScope && !l.ObservedAt.IsZero() &&
		!l.ObservedAt.After(now) && now.Sub(l.ObservedAt) <= time.Duration(p.MarketBinding.MaxQuotaAgeSeconds)*time.Second
}
