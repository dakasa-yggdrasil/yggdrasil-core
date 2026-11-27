package capacity

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

func UsesObservedMarketConstraints(p model.CapacityPolicySpec) bool {
	return p.MarketBinding != nil && p.NativeWorkerPoolBinding != nil && p.MarketBinding.GrowthMode == "observed_constraints"
}

func selectMarketProfile(p model.CapacityPolicySpec, profiles []MarketProfile, units int, now time.Time, repair bool) (model.CapacityProfile, bool) {
	var selected model.CapacityProfile
	var selectedCost int64
	found := false
	for _, candidate := range profiles {
		v := candidate.Profile
		if (!repair && v.MinUnits > units) || v.MaxUnits < units || !ProfilePlanningCurrent(p, v, now.Add(time.Duration(v.ReadinessSeconds)*time.Second)) {
			continue
		}
		cost, err := MarketCost(candidate, max(units, v.MinUnits))
		if err != nil || (p.MarketBinding.BudgetMode == "bounded_total" && cost > p.MarketBinding.BudgetMicros) {
			continue
		}
		if !found || cost < selectedCost || (cost == selectedCost && v.Name < selected.Name) {
			selected, selectedCost, found = v, cost, true
		}
	}
	return selected, found
}

// Price-only replacement has an independent dwell. Its identity includes only
// stable operator declarations: a fresh quote timestamp cannot reset it.
func economicMarketDecision(p model.CapacityPolicySpec, profiles []MarketProfile, snapshot model.CapacitySnapshot, d model.CapacityDecision, now time.Time) model.CapacityDecision {
	b := p.MarketBinding
	reset := func(reason string) model.CapacityDecision {
		d.Reason = reason
		d.Clock.EconomicCandidate, d.Clock.EconomicSince = "", nil
		return d
	}
	if snapshot.Units == 0 {
		return reset("within_envelope")
	}
	selected, ok := selectMarketProfile(p, profiles, snapshot.Units, now, false)
	if !ok {
		return reset("validated_market_profile_unavailable")
	}
	if selected.Name == snapshot.Profile {
		return reset("within_envelope")
	}
	var current, replacement *MarketProfile
	for i := range profiles {
		if profiles[i].Profile.Name == snapshot.Profile {
			current = &profiles[i]
		}
		if profiles[i].Profile.Name == selected.Name {
			replacement = &profiles[i]
		}
	}
	if current == nil || replacement == nil {
		return reset("current_market_cost_unavailable")
	}
	oldCost, oldErr := MarketLowerCost(*current, snapshot.Units)
	newCost, newErr := MarketCost(*replacement, snapshot.Units)
	if oldErr != nil || newErr != nil || oldCost <= newCost {
		return reset("economic_savings_unproven")
	}
	savings := oldCost - newCost // Both totals include the same horizon and all declared switch/overlap costs.
	percentage := new(big.Int).Mul(big.NewInt(savings), big.NewInt(10000))
	threshold := new(big.Int).Mul(big.NewInt(oldCost), big.NewInt(int64(b.MinSavingsBasisPoints)))
	if savings < b.MinSavingsMicros || percentage.Cmp(threshold) < 0 {
		return reset("economic_savings_below_margin")
	}
	var identity model.CapacityMarketProfileBinding
	for _, candidate := range b.Profiles {
		if candidate.Profile == selected.Name {
			identity = candidate
		}
	}
	raw, _ := json.Marshal(identity)
	key := sha256.Sum256(raw)
	candidateKey := selected.Name + ":" + hex.EncodeToString(key[:])
	if d.Clock.EconomicCandidate != candidateKey || d.Clock.EconomicSince == nil || d.Clock.EconomicSince.After(now) {
		at := now
		d.Clock.EconomicCandidate, d.Clock.EconomicSince = candidateKey, &at
	}
	if now.Sub(*d.Clock.EconomicSince) < time.Duration(b.EconomicHoldSeconds)*time.Second {
		d.Reason = "economic_window_pending"
		return d
	}
	residentSince := d.Clock.LastActionAt
	if residentSince.IsZero() {
		residentSince = *d.Clock.EconomicSince
	}
	if now.Sub(residentSince) < time.Duration(b.MinResidenceSeconds)*time.Second {
		d.Reason = "economic_minimum_residence"
		return d
	}
	if !d.Clock.LastActionAt.IsZero() && now.Sub(d.Clock.LastActionAt) < time.Duration(p.CooldownSeconds)*time.Second {
		d.Reason = "cooldown"
		return d
	}
	d.Action, d.Reason, d.Profile = "prepare", "sustained_all_in_savings", selected.Name
	d.ExecutionPermitted = p.ExecutionEnabled
	return d
}
