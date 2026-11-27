package capacity

import (
	"fmt"
	"math"
	"math/big"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

const CapacityMarketMode = "capacity_market_v1"

var marketID = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$`)
var marketSHA = regexp.MustCompile(`^[a-f0-9]{64}$`)
var marketCommit = regexp.MustCompile(`^[a-f0-9]{40}$`)
var marketDNSLabel = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
var marketChecksum = regexp.MustCompile(`^(sha256:)?[a-f0-9]{64}$`)
var marketUUID = regexp.MustCompile(`^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$`)
var marketProviderPrefix = regexp.MustCompile(`^[a-z][a-z0-9+.-]{0,31}:///?$`)
var marketProviderSuffix = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9/_:.-]{0,479}$`)

// Mandatory explicit charge coverage; not_applicable is an affirmative zero,
// never a substitute for an unknown price or an unobserved billing dimension.
var marketCostNames = []string{"compute", "storage", "public_ip", "load_balancer", "nat", "egress", "backup", "control_plane", "overlap", "migration", "warmup", "teardown", "committed_remaining", "tax"}

type MarketQuotaReservation = model.CapacityMarketQuotaReservation

type MarketQuotaUnknownScope struct{ Provider, Region, Scope, Dimension string }

// This input is constructed from Core's locked shared ledger, never decoded
// from an assessment. Reservations include pending and uncertain originals.
type MarketLedgerObservation struct {
	Complete            bool
	ObservedAt          time.Time
	TargetIdentity      string
	Owner               string
	CurrentProfile      string
	CurrentUnits        int
	CurrentPoolEpoch    int64
	ReservedCostMicros  int64
	BudgetScope         string
	QuotaReservations   []MarketQuotaReservation
	UnknownReservations bool
	UnknownQuotaScopes  []MarketQuotaUnknownScope
}

type MarketProfile struct {
	Profile            model.CapacityProfile
	Quote              model.CapacityMarketProfileQuote
	Currency           string
	HorizonSeconds     int64
	ReservedCostMicros int64
	ReusableUnits      int
	BudgetScope        string
}

func marketAdapterValid(a model.CapacityMarketAdapterBinding) bool {
	return marketUUID.MatchString(a.ManifestID) && a.Version > 0 && marketChecksum.MatchString(a.Checksum) && marketUUID.MatchString(a.IntegrationTypeID) && marketChecksum.MatchString(a.TypeChecksum)
}

func marketCurrent(observed, until, now time.Time, age int, readiness int) bool {
	return !observed.IsZero() && !observed.After(now) && age > 0 && now.Sub(observed) <= time.Duration(age)*time.Second && until.After(now.Add(time.Duration(readiness)*time.Second)) && until.After(observed)
}

func ValidateMarketBinding(p model.CapacityPolicySpec) error {
	b := p.MarketBinding
	if b == nil {
		return nil
	}
	budgetValid := b.BudgetMode == "bounded_total" && b.BudgetMicros > 0 || b.BudgetMode == "demand_only_no_total_cap" && b.BudgetMicros == 0
	dynamic := b.GrowthMode == "observed_constraints"
	if !dynamic && b.GrowthMode != "policy_bounds" || dynamic && p.Ceiling != 0 {
		return fmt.Errorf("explicit market growth mode and ceiling sentinel required")
	}
	if b.Mode != CapacityMarketMode || !marketSHA.MatchString(b.WorkloadShapeSHA256) || b.HorizonSeconds < 1 || b.HorizonSeconds > 31*86400 || !budgetValid || !marketID.MatchString(b.BudgetScope) || b.MaxQuoteAgeSeconds < 1 || b.MaxQuoteAgeSeconds > 86400 || b.MaxQuotaAgeSeconds < 1 || b.MaxQuotaAgeSeconds > 3600 || b.MaxEligibilityAgeSeconds < 1 || b.MaxEligibilityAgeSeconds > 3600 || b.MinSavingsMicros < 1 || b.MinSavingsBasisPoints < 1 || b.MinSavingsBasisPoints > 10000 || b.EconomicHoldSeconds < 1 || b.EconomicHoldSeconds > 86400 || b.MinResidenceSeconds < b.EconomicHoldSeconds || b.MinResidenceSeconds > 604800 || len(b.Profiles) != len(p.Profiles) || len(b.Profiles) == 0 || len(b.Profiles) > 64 || len(b.LegacyAllocators) > 256 {
		return fmt.Errorf("invalid finite market policy and economic hysteresis")
	}
	profiles := map[string]model.CapacityProfile{}
	for _, v := range p.Profiles {
		if v.MinUnits < 0 || v.ReadinessSeconds < 0 || v.ReadinessSeconds > 86400 {
			return fmt.Errorf("invalid market workload unit or readiness bound")
		}
		if _, exists := profiles[v.Name]; exists {
			return fmt.Errorf("duplicate market policy profile")
		}
		profiles[v.Name] = v
	}
	seen := map[string]bool{}
	allDimensions := map[string]bool{}
	for _, v := range b.Profiles {
		base, ok := profiles[v.Profile]
		if !ok || seen[v.Profile] || !marketID.MatchString(v.Profile) || v.Provider != base.Provider || v.Region != base.Region || !marketID.MatchString(v.Provider) || !marketID.MatchString(v.Region) || !marketAdapterValid(v.Adapter) || !marketSHA.MatchString(v.PhysicalSpecSHA256) || v.WorkloadShapeSHA256 != b.WorkloadShapeSHA256 || !containsMarket([]string{"amd64", "arm64"}, v.Architecture) || !containsMarket([]string{"stop", "delete"}, v.BillingStopCondition) || v.MaxUnreservedAttempts < 1 || !dynamic && v.MaxUnreservedAttempts > base.MaxUnits || dynamic && base.MaxUnits != 0 || !marketID.MatchString(v.QuoteSourceIdentity) || !marketID.MatchString(v.QuotaSourceIdentity) || !marketSHA.MatchString(v.RegistrationBindingSHA) || !marketSHA.MatchString(v.NetworkBindingSHA) || len(v.QuotaDimensions) < 1 || len(v.QuotaDimensions) > 64 {
			return fmt.Errorf("market profile identity or protected producer binding invalid")
		}
		seen[v.Profile] = true
		dims := map[string]bool{}
		for _, d := range v.QuotaDimensions {
			key := quotaKey(v.Provider, v.Region, d.Scope, d.Dimension)
			if !marketID.MatchString(d.Scope) || !marketID.MatchString(d.Dimension) || d.PerUnit < 1 || dims[key] {
				return fmt.Errorf("invalid bound market quota dimensions")
			}
			dims[key] = true
			allDimensions[quotaKey(v.Provider, v.Region, "", d.Dimension)] = true
		}
		if len(v.ReviewedCostSourceIdentities) > 32 {
			return fmt.Errorf("too many reviewed cost sources")
		}
		sources := map[string]bool{}
		for _, source := range v.ReviewedCostSourceIdentities {
			if !marketID.MatchString(source) || sources[source] {
				return fmt.Errorf("invalid reviewed cost source")
			}
			sources[source] = true
		}
	}
	legacySeen := map[string]bool{}
	for _, a := range b.LegacyAllocators {
		key := a.IntegrationInstanceID + "\x00" + a.ScopeChecksum + "\x00" + a.ProfileName
		if !marketUUID.MatchString(a.IntegrationInstanceID) || !marketChecksum.MatchString(a.ScopeChecksum) || !marketID.MatchString(a.ProfileName) || !marketID.MatchString(a.Namespace) || !marketID.MatchString(a.Environment) || !marketID.MatchString(a.Domain) || !marketID.MatchString(a.Dimension) || legacySeen[key] || len(a.Quotas) < 1 || len(a.Quotas) > 64 {
			return fmt.Errorf("invalid immutable legacy allocator scope")
		}
		legacySeen[key] = true
		quotaSeen := map[string]bool{}
		for _, q := range a.Quotas {
			k := quotaKey(q.Provider, q.Region, q.Scope, q.Dimension)
			if !allDimensions[quotaKey(q.Provider, q.Region, "", q.Dimension)] || !marketID.MatchString(q.Scope) || quotaSeen[k] || q.PerUnit < 1 {
				return fmt.Errorf("legacy allocator quota outside bound shared dimensions")
			}
			quotaSeen[k] = true
		}
	}
	return nil
}

func costComponent(c model.CapacityMarketCostComponent, horizon int64) (int64, bool, error) {
	if c.Scope != "per_unit" && c.Scope != "fixed" {
		return 0, false, fmt.Errorf("explicit market charge scope required")
	}
	if c.Quantity < 0 || c.MinimumQuantity < 0 || c.QuantumQuantity < 0 || c.PriceMicros < 0 || c.PriceQuantity < 0 || c.ChargeCapMicros < 0 || c.LowerBoundMicros < 0 {
		return 0, false, fmt.Errorf("negative market billing quantity")
	}
	if c.State == "unknown" {
		return 0, false, nil
	}
	if c.State == "not_applicable" {
		if c.Quantity != 0 || c.MinimumQuantity != 0 || c.QuantumQuantity != 0 || c.PriceMicros != 0 || c.PriceQuantity != 0 || c.ChargeCapMicros != 0 || c.LowerBoundMicros != 0 || c.BillingUnit != "none" {
			return 0, false, fmt.Errorf("nonapplicable market charge must be an explicit zero")
		}
		return 0, true, nil
	}
	if c.State != "known" || c.QuantumQuantity < 1 || c.PriceQuantity < 1 || !containsMarket([]string{"provider_rate", "reviewed_upper_bound"}, c.Basis) || !marketID.MatchString(c.SourceIdentity) || !marketSHA.MatchString(c.EvidenceSHA256) || c.ValidUntil.IsZero() || !containsMarket([]string{"second", "byte_second", "byte", "request", "one_time"}, c.BillingUnit) || c.BillingUnit == "second" && c.Quantity != horizon {
		return 0, false, fmt.Errorf("known market billing basis and horizon required")
	}
	q := big.NewInt(max(c.Quantity, c.MinimumQuantity))
	quantum := big.NewInt(c.QuantumQuantity)
	q.Add(q, new(big.Int).Sub(quantum, big.NewInt(1))).Quo(q, quantum).Mul(q, quantum)
	cost := new(big.Int).Mul(q, big.NewInt(c.PriceMicros))
	denom := big.NewInt(c.PriceQuantity)
	cost.Add(cost, new(big.Int).Sub(denom, big.NewInt(1))).Quo(cost, denom)
	if c.ChargeCapMicros > 0 && cost.Cmp(big.NewInt(c.ChargeCapMicros)) > 0 {
		cost.SetInt64(c.ChargeCapMicros)
	}
	if !cost.IsInt64() {
		return 0, false, fmt.Errorf("market cost overflow")
	}
	if c.LowerBoundMicros > cost.Int64() {
		return 0, false, fmt.Errorf("market lower bound exceeds conservative upper charge")
	}
	return cost.Int64(), true, nil
}

func containsMarket(values []string, value string) bool {
	for _, v := range values {
		if v == value {
			return true
		}
	}
	return false
}

func quoteCosts(q model.CapacityMarketProfileQuote, horizon int64) (int64, int64, bool, error) {
	if len(q.Costs) != len(marketCostNames) {
		return 0, 0, false, fmt.Errorf("complete explicit all-in market charge coverage required")
	}
	seen := map[string]bool{}
	per, fixed := int64(0), int64(0)
	complete := q.AllInComplete
	for _, c := range q.Costs {
		if seen[c.Name] || !containsMarket(marketCostNames, c.Name) {
			return 0, 0, false, fmt.Errorf("duplicate or unsupported market charge")
		}
		seen[c.Name] = true
		amount, known, err := costComponent(c, horizon)
		if err != nil {
			return 0, 0, false, err
		}
		complete = complete && known
		if c.Scope == "per_unit" {
			if amount > math.MaxInt64-per {
				return 0, 0, false, fmt.Errorf("market cost overflow")
			}
			per += amount
		} else {
			if amount > math.MaxInt64-fixed {
				return 0, 0, false, fmt.Errorf("market cost overflow")
			}
			fixed += amount
		}
	}
	if complete && per <= 0 {
		return 0, 0, false, fmt.Errorf("positive all-in per-unit cost required")
	}
	return per, fixed, complete, nil
}

func MarketCost(p MarketProfile, units int) (int64, error) {
	if units < 0 || units > p.Profile.MaxUnits || p.ReservedCostMicros < 0 {
		return 0, fmt.Errorf("market units outside effective envelope")
	}
	per, fixed, complete, err := quoteCosts(p.Quote, p.HorizonSeconds)
	if err != nil {
		return 0, err
	}
	if !complete {
		return 0, fmt.Errorf("all-in cost unknown")
	}
	// With no eligible worker units, no conditional provisioning/migration fee
	// is incurred. Existing outstanding charges remain in the locked ledger.
	if units == 0 {
		return p.ReservedCostMicros, nil
	}
	cost := new(big.Int).Mul(big.NewInt(per), big.NewInt(int64(units)))
	cost.Add(cost, big.NewInt(fixed)).Add(cost, big.NewInt(p.ReservedCostMicros))
	if !cost.IsInt64() {
		return 0, fmt.Errorf("market total cost overflow")
	}
	return cost.Int64(), nil
}

// MarketLowerCost is a conservative lower bound over the same unit/horizon.
// Savings may compare candidate upper against incumbent lower, never assume a
// forecast or a reviewed tax/egress upper bound is an invoice or a guaranteed cost.
func MarketLowerCost(p MarketProfile, units int) (int64, error) {
	if _, err := MarketCost(p, units); err != nil {
		return 0, err
	}
	if units == 0 {
		return p.ReservedCostMicros, nil
	}
	total := big.NewInt(p.ReservedCostMicros)
	for _, c := range p.Quote.Costs {
		amount := big.NewInt(c.LowerBoundMicros)
		if c.Scope == "per_unit" {
			amount.Mul(amount, big.NewInt(int64(units)))
		}
		total.Add(total, amount)
	}
	if !total.IsInt64() {
		return 0, fmt.Errorf("market lower total overflow")
	}
	return total.Int64(), nil
}

func quotaKey(provider, region, scope, dimension string) string {
	return provider + "\x00" + region + "\x00" + scope + "\x00" + dimension
}

// EffectiveProfiles changes copies only. It preserves policy, demand clocks and
// existing profile planning declarations; callers retain those independent gates.
func EffectiveProfiles(p model.CapacityPolicySpec, market *model.CapacityMarketAssessment, ledger MarketLedgerObservation, now time.Time) ([]MarketProfile, error) {
	if p.MarketBinding == nil {
		return nil, fmt.Errorf("market policy disabled; use legacy planner")
	}
	if err := ValidateMarketBinding(p); err != nil {
		return nil, err
	}
	b := p.MarketBinding
	if market == nil || market.Schema != CapacityMarketMode || market.Currency != p.Currency || market.HorizonSeconds != b.HorizonSeconds || !marketCurrent(market.ObservedAt, market.ValidUntil, now, b.MaxQuoteAgeSeconds, 0) || len(market.Profiles)+len(market.Unavailable) != len(b.Profiles) || !ledger.Complete || ledger.UnknownReservations || ledger.TargetIdentity != p.TargetIdentity || ledger.Owner != p.Owner || ledger.BudgetScope != b.BudgetScope || ledger.CurrentPoolEpoch < 1 || p.NativeWorkerPoolBinding != nil && ledger.CurrentPoolEpoch != p.NativeWorkerPoolBinding.ExpectedPoolEpoch || ledger.CurrentUnits < 0 || b.GrowthMode == "policy_bounds" && ledger.CurrentUnits > p.Ceiling || ledger.ReservedCostMicros < 0 || ledger.ObservedAt.IsZero() || ledger.ObservedAt.After(now) || now.Sub(ledger.ObservedAt) > time.Duration(b.MaxQuotaAgeSeconds)*time.Second || len(ledger.UnknownQuotaScopes) > 10000 {
		return nil, fmt.Errorf("fresh protected market observation and complete server ledger required")
	}
	reserved := map[string]int64{}
	for _, r := range ledger.QuotaReservations {
		if !marketID.MatchString(r.Provider) || !marketID.MatchString(r.Region) || !marketID.MatchString(r.Scope) || !marketID.MatchString(r.Dimension) || r.Amount < 0 {
			return nil, fmt.Errorf("invalid server quota reservation")
		}
		key := quotaKey(r.Provider, r.Region, r.Scope, r.Dimension)
		if r.Amount > math.MaxInt64-reserved[key] {
			return nil, fmt.Errorf("quota reservation overflow")
		}
		reserved[key] += r.Amount
	}
	bindings := map[string]model.CapacityMarketProfileBinding{}
	base := map[string]model.CapacityProfile{}
	for _, v := range b.Profiles {
		bindings[v.Profile] = v
	}
	for _, v := range p.Profiles {
		base[v.Name] = v
	}
	for _, u := range ledger.UnknownQuotaScopes {
		if !marketID.MatchString(u.Provider) || (u.Region != "" && !marketID.MatchString(u.Region)) || (u.Scope != "" && !marketID.MatchString(u.Scope)) || (u.Dimension != "" && !marketID.MatchString(u.Dimension)) {
			return nil, fmt.Errorf("invalid scoped unknown quota reservation")
		}
	}
	if ledger.CurrentUnits > 0 {
		if _, ok := base[ledger.CurrentProfile]; !ok {
			return nil, fmt.Errorf("current server capacity profile is not policy bound")
		}
	}
	seen := map[string]bool{}
	for _, u := range market.Unavailable {
		binding, ok := bindings[u.Profile]
		if !ok || seen[u.Profile] || u.Provider != binding.Provider || u.Region != binding.Region || u.Adapter != binding.Adapter || !containsMarket([]string{"collector_unavailable", "collector_contract_refused"}, u.Reason) || u.ObservedAt.IsZero() || u.ObservedAt.After(now) || now.Sub(u.ObservedAt) > time.Duration(b.MaxQuoteAgeSeconds)*time.Second {
			return nil, fmt.Errorf("invalid protected collector unavailable outcome")
		}
		seen[u.Profile] = true
	}
	out := []MarketProfile{}
	for _, q := range market.Profiles {
		binding, ok := bindings[q.Profile]
		if !ok || seen[q.Profile] || q.Provider != binding.Provider || q.Region != binding.Region || q.Adapter != binding.Adapter || q.PhysicalSpecSHA256 != binding.PhysicalSpecSHA256 || q.WorkloadShapeSHA256 != binding.WorkloadShapeSHA256 || q.Architecture != binding.Architecture || q.BillingStopCondition != binding.BillingStopCondition || q.SourceIdentity != binding.QuoteSourceIdentity || !marketSHA.MatchString(q.EvidenceSHA256) {
			return nil, fmt.Errorf("market quote outside immutable producer or physical binding")
		}
		seen[q.Profile] = true
		profile := base[q.Profile]
		if !q.WorkloadQualified || q.ValidationRef != profile.ValidationRef || !q.ValidationValidUntil.Equal(profile.ValidationValidUntil) || !q.ValidationValidUntil.After(now.Add(time.Duration(profile.ReadinessSeconds)*time.Second)) || !marketSHA.MatchString(q.QualificationEvidenceSHA256) {
			continue
		}
		if !marketCurrent(q.ObservedAt, q.ValidUntil, now, b.MaxQuoteAgeSeconds, profile.ReadinessSeconds) {
			continue
		}
		_, _, complete, err := quoteCosts(q, b.HorizonSeconds)
		if err != nil {
			return nil, err
		}
		if !complete {
			continue
		}
		costSourcesCurrent := true
		for _, c := range q.Costs {
			if c.State != "known" {
				continue
			}
			if c.Basis == "provider_rate" && c.SourceIdentity != binding.QuoteSourceIdentity || c.Basis == "reviewed_upper_bound" && !containsMarket(binding.ReviewedCostSourceIdentities, c.SourceIdentity) {
				return nil, fmt.Errorf("market cost source outside approved rate/projection binding")
			}
			if !c.ValidUntil.After(now.Add(time.Duration(profile.ReadinessSeconds) * time.Second)) {
				costSourcesCurrent = false
			}
		}
		if !costSourcesCurrent {
			continue
		}
		reuse := 0
		if ledger.CurrentProfile == q.Profile {
			reuse = ledger.CurrentUnits
		}
		cap := min(profile.MaxUnits, p.Ceiling)
		if b.GrowthMode == "observed_constraints" {
			cap = q.Registration.MaxUnits
		}
		eligible := true
		for _, u := range ledger.UnknownQuotaScopes {
			if u.Provider != q.Provider || u.Region != "" && u.Region != q.Region {
				continue
			}
			if u.Scope == "" || u.Dimension == "" {
				eligible = false
				continue
			}
			for _, d := range binding.QuotaDimensions {
				if u.Scope == d.Scope && u.Dimension == d.Dimension {
					eligible = false
				}
			}
		}
		for i, e := range []model.CapacityMarketEligibility{q.Stock, q.Registration, q.Network} {
			expected := binding.PhysicalSpecSHA256
			if i == 1 {
				expected = binding.RegistrationBindingSHA
			}
			if i == 2 {
				expected = binding.NetworkBindingSHA
			}
			states := []string{"eligible", "ineligible", "unknown"}
			if i == 0 {
				states = []string{"offered_unreserved", "reserved", "unavailable", "unknown"}
			}
			if e.BindingSHA256 != expected || !marketSHA.MatchString(e.EvidenceSHA256) || e.MaxUnits < 0 || !containsMarket(states, e.State) {
				return nil, fmt.Errorf("invalid market stock/registration/network binding")
			}
			if i == 0 && ((e.State == "offered_unreserved" && (e.MaxUnits > binding.MaxUnreservedAttempts || e.ReservationRef != "")) || (e.State == "reserved" && !marketID.MatchString(e.ReservationRef))) {
				return nil, fmt.Errorf("unreserved attempt ceiling or real stock reservation binding invalid")
			}
			if i > 0 && e.ReservationRef != "" {
				return nil, fmt.Errorf("unexpected registration/network reservation")
			}
			stateEligible := e.State == "eligible" || i == 0 && (e.State == "offered_unreserved" || e.State == "reserved")
			if i == 0 && !stateEligible && reuse > 0 {
				// No offered stock does not make existing registered Nodes vanish.
				// Retain/drain only: no additional unit can pass this envelope.
				cap = min(cap, reuse)
				continue
			}
			if !stateEligible || !marketCurrent(e.ObservedAt, e.ValidUntil, now, b.MaxEligibilityAgeSeconds, profile.ReadinessSeconds) {
				eligible = false
				continue
			}
			limit := e.MaxUnits
			if i == 0 {
				if limit > math.MaxInt-reuse {
					return nil, fmt.Errorf("stock capacity overflow")
				}
				limit += reuse
			}
			cap = min(cap, limit)
		}
		if len(q.Quotas) != len(binding.QuotaDimensions) {
			return nil, fmt.Errorf("complete bound provider quota dimensions required")
		}
		boundDimensions := map[string]int64{}
		for _, dimension := range binding.QuotaDimensions {
			boundDimensions[quotaKey(q.Provider, q.Region, dimension.Scope, dimension.Dimension)] = dimension.PerUnit
		}
		quotaSeen := map[string]bool{}
		for _, quota := range q.Quotas {
			key := quotaKey(q.Provider, q.Region, quota.Scope, quota.Dimension)
			if !marketID.MatchString(quota.Scope) || !marketID.MatchString(quota.Dimension) || quotaSeen[key] || boundDimensions[key] != quota.PerUnit || quota.SourceIdentity != binding.QuotaSourceIdentity || !marketSHA.MatchString(quota.EvidenceSHA256) || quota.Limit < 0 || quota.Used < 0 || quota.PerUnit < 1 || !containsMarket([]string{"known", "unknown"}, quota.State) {
				return nil, fmt.Errorf("invalid market provider quota dimension")
			}
			quotaSeen[key] = true
			if quota.State != "known" || !marketCurrent(quota.ObservedAt, quota.ValidUntil, now, b.MaxQuotaAgeSeconds, profile.ReadinessSeconds) {
				eligible = false
				continue
			}
			usedByCurrent := new(big.Int).Mul(big.NewInt(int64(reuse)), big.NewInt(quota.PerUnit))
			if usedByCurrent.Cmp(big.NewInt(quota.Used)) > 0 {
				return nil, fmt.Errorf("quota usage does not include current registered capacity")
			}
			headroom := new(big.Int).Sub(big.NewInt(quota.Limit), big.NewInt(quota.Used))
			headroom.Sub(headroom, big.NewInt(reserved[key]))
			if headroom.Sign() < 0 {
				eligible = false
				continue
			}
			headroom.Quo(headroom, big.NewInt(quota.PerUnit)).Add(headroom, big.NewInt(int64(reuse)))
			if headroom.Cmp(big.NewInt(int64(cap))) < 0 {
				cap = int(headroom.Int64())
			}
		}
		if !eligible || cap < profile.MinUnits {
			continue
		}
		profile.MaxUnits = cap
		candidate := MarketProfile{Profile: profile, Quote: q, Currency: p.Currency, HorizonSeconds: b.HorizonSeconds, ReservedCostMicros: ledger.ReservedCostMicros, ReusableUnits: reuse, BudgetScope: b.BudgetScope}
		low, high := 0, cap
		for low < high {
			span := high - low
			mid := low + span/2 + span%2
			cost, err := MarketCost(candidate, mid)
			if err != nil || b.BudgetMode == "bounded_total" && cost > b.BudgetMicros {
				high = mid - 1
			} else {
				low = mid
			}
		}
		if low < profile.MinUnits {
			continue
		}
		candidate.Profile.MaxUnits = low
		out = append(out, candidate)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Profile.Name < out[j].Profile.Name })
	return out, nil
}

func MarketReservationFor(p MarketProfile, desiredUnits int, now time.Time) (model.CapacityMarketReservation, error) {
	if desiredUnits < p.Profile.MinUnits || desiredUnits > p.Profile.MaxUnits || p.ReusableUnits < 0 || !p.Quote.ValidUntil.After(now) {
		return model.CapacityMarketReservation{}, fmt.Errorf("reservation outside current effective market envelope")
	}
	for _, c := range p.Quote.Costs {
		if c.State == "known" && !c.ValidUntil.After(now) {
			return model.CapacityMarketReservation{}, fmt.Errorf("reservation cost source expired")
		}
	}
	units := max(desiredUnits-p.ReusableUnits, 0)
	copy := p
	copy.ReservedCostMicros = 0
	cost, err := MarketCost(copy, units)
	if err != nil {
		return model.CapacityMarketReservation{}, err
	}
	if units == 0 {
		cost = 0
	}
	r := model.CapacityMarketReservation{Schema: CapacityMarketMode, Profile: p.Profile.Name, Provider: p.Profile.Provider, Region: p.Profile.Region, Currency: p.Currency, BudgetScope: p.BudgetScope, Units: units, CostMicros: cost, HorizonSeconds: p.HorizonSeconds, QuoteEvidenceSHA256: p.Quote.EvidenceSHA256, ObservedAt: now, Quotas: []model.CapacityMarketQuotaReservation{}}
	for _, q := range p.Quote.Quotas {
		amount := new(big.Int).Mul(big.NewInt(int64(units)), big.NewInt(q.PerUnit))
		if !amount.IsInt64() {
			return model.CapacityMarketReservation{}, fmt.Errorf("reserved quota overflow")
		}
		r.Quotas = append(r.Quotas, model.CapacityMarketQuotaReservation{Provider: p.Profile.Provider, Region: p.Profile.Region, Scope: q.Scope, Dimension: q.Dimension, Amount: amount.Int64()})
	}
	return r, nil
}

type NativeWorkerPoolSummary struct {
	RegisteredUnits        int
	ReadyUnits             int
	AllocatableMilliCPU    int64
	AllocatableMemoryBytes int64
	NodeUIDs               []string
}

func ValidateNativeWorkerPoolBinding(p model.CapacityPolicySpec) error {
	b := p.NativeWorkerPoolBinding
	if b == nil {
		return nil
	}
	if p.MarketBinding == nil || b.Owner != p.Owner {
		return fmt.Errorf("native worker pool requires same-owner market policy")
	}
	if len(b.Profiles) != len(p.Profiles) {
		return fmt.Errorf("complete native worker profile bindings required")
	}
	for _, bp := range b.Profiles {
		matched := false
		for _, mp := range p.MarketBinding.Profiles {
			if mp.Profile == bp.Profile && mp.Provider == bp.Provider && mp.PhysicalSpecSHA256 == bp.PhysicalSpecSHA256 && mp.RegistrationBindingSHA == bp.RegistrationBindingSHA {
				matched = true
			}
		}
		if !matched {
			return fmt.Errorf("native worker profile outside market physical binding")
		}
	}
	return validateNativeWorkerBinding(*b)
}

func validateNativeWorkerBinding(b model.CapacityNativeWorkerPoolBinding) error {
	if b.Mode != "native_worker_pool_v1" || !marketID.MatchString(b.Name) || !marketCommit.MatchString(b.SourceCommit) || !marketAdapterValid(b.Adapter) || !marketUUID.MatchString(b.RealmUID) || !marketUUID.MatchString(b.PoolUID) || !marketID.MatchString(b.Owner) || b.MaxAgeSeconds < 1 || b.MaxAgeSeconds > 600 || b.ExpectedPoolEpoch < 1 || !validNativeRegistry(b.RegistryRef) || len(b.Profiles) < 1 || len(b.Profiles) > 64 || len(b.ProtectedNodes) < 1 || len(b.ProtectedNodes) > 64 {
		return fmt.Errorf("invalid protected native worker pool binding")
	}
	profiles := map[string]bool{}
	for _, p := range b.Profiles {
		if profiles[p.Profile] || !marketID.MatchString(p.Profile) || !marketID.MatchString(p.Provider) || !marketProviderPrefix.MatchString(p.ProviderIDPrefix) || !marketSHA.MatchString(p.PhysicalSpecSHA256) || !marketSHA.MatchString(p.RegistrationBindingSHA) || p.MinAllocatableMilliCPU < 1 || p.MinAllocatableMemory < 1 {
			return fmt.Errorf("invalid native worker profile binding")
		}
		profiles[p.Profile] = true
	}
	uids, providers := map[string]bool{}, map[string]bool{}
	for _, n := range b.ProtectedNodes {
		if !marketUUID.MatchString(n.NodeUID) || n.ProviderID == "" || uids[n.NodeUID] || providers[n.ProviderID] {
			return fmt.Errorf("invalid protected floor/Notify identity")
		}
		uids[n.NodeUID], providers[n.ProviderID] = true, true
	}
	return nil
}

func validNativeProviderID(prefix, id string) bool {
	// Scheme is an immutable operator binding, independent of integration name.
	// The collector and persisted creation grant authenticate the physical suffix.
	return strings.HasPrefix(id, prefix) && marketProviderSuffix.MatchString(strings.TrimPrefix(id, prefix))
}

func validNativeRegistry(r model.CapacityNativePoolRegistryRef) bool {
	if r.Kind != "Lease" || !marketDNSLabel.MatchString(r.Namespace) || len(r.Name) > 253 || !marketUUID.MatchString(r.UID) {
		return false
	}
	for _, label := range strings.Split(r.Name, ".") {
		if !marketDNSLabel.MatchString(label) {
			return false
		}
	}
	return true
}

func SummarizeNativeWorkerPool(b model.CapacityNativeWorkerPoolBinding, o *model.CapacityNativeWorkerPoolObservation, expectedEpoch int64, now time.Time) (NativeWorkerPoolSummary, error) {
	var s NativeWorkerPoolSummary
	if err := validateNativeWorkerBinding(b); err != nil {
		return s, err
	}
	if o == nil || o.Schema != "native_worker_pool_v1" || o.SourceCommit != b.SourceCommit || o.Adapter != b.Adapter || o.RealmUID != b.RealmUID || o.PoolUID != b.PoolUID || o.Owner != b.Owner || expectedEpoch != b.ExpectedPoolEpoch || o.OwnerEpoch != b.ExpectedPoolEpoch || o.RegistryRef != b.RegistryRef || !o.Complete || o.OwnerResourceUID != b.RegistryRef.UID || o.OwnerResourceVersion == "" || o.CollectionResourceVersion == "" || !marketSHA.MatchString(o.EvidenceSHA256) || o.ObservedAt.IsZero() || o.ObservedAt.After(now) || now.Sub(o.ObservedAt) > time.Duration(b.MaxAgeSeconds)*time.Second || len(o.Nodes) > 100000 {
		return s, fmt.Errorf("fresh complete server-bound native worker pool observation required")
	}
	profiles := map[string]model.CapacityNativeWorkerProfileBinding{}
	for _, p := range b.Profiles {
		profiles[p.Profile] = p
	}
	if _, ok := profiles[o.CurrentProfile]; !ok {
		return s, fmt.Errorf("native registry current profile is not declared")
	}
	protectedUID, protectedProvider := map[string]bool{}, map[string]bool{}
	for _, p := range b.ProtectedNodes {
		protectedUID[p.NodeUID], protectedProvider[p.ProviderID] = true, true
	}
	seenUID, seenProvider := map[string]bool{}, map[string]bool{}
	for _, n := range o.Nodes {
		p, ok := profiles[n.Profile]
		if !ok || n.Profile != o.CurrentProfile || !marketUUID.MatchString(n.NodeUID) || n.NodeResourceVersion == "" || n.Provider != p.Provider || !validNativeProviderID(p.ProviderIDPrefix, n.ProviderID) || protectedUID[n.NodeUID] || protectedProvider[n.ProviderID] || seenUID[n.NodeUID] || seenProvider[n.ProviderID] || n.PoolUID != b.PoolUID || !n.CurrentRegistration || n.RegistrationEpoch != expectedEpoch || n.RegistrationBindingSHA256 != p.RegistrationBindingSHA || n.PhysicalSpecSHA256 != p.PhysicalSpecSHA256 || !marketUUID.MatchString(n.CapacityPolicyID) || n.IntentGeneration < 1 || n.FencingToken < 1 || !marketSHA.MatchString(n.RegistrationReceiptSHA256) || n.AllocatableMilliCPU < p.MinAllocatableMilliCPU || n.AllocatableMemoryBytes < p.MinAllocatableMemory {
			return NativeWorkerPoolSummary{}, fmt.Errorf("native worker identity/registration/allocation outside exact pool")
		}
		seenUID[n.NodeUID], seenProvider[n.ProviderID] = true, true
		s.RegisteredUnits++
		s.NodeUIDs = append(s.NodeUIDs, n.NodeUID)
		if n.Ready && n.SchedulingAdmitted && !n.Deleting && !n.Unschedulable {
			if !marketSHA.MatchString(n.AdmissionReceiptSHA256) || n.AdmissionRegistryUID != b.RegistryRef.UID || n.AdmissionRegistryResourceVersion != o.OwnerResourceVersion {
				return NativeWorkerPoolSummary{}, fmt.Errorf("useful worker lacks persisted current-registry admission proof")
			}
			if n.ReadyObservedAt.IsZero() || n.ReadyObservedAt.After(now) || now.Sub(n.ReadyObservedAt) > time.Duration(b.MaxAgeSeconds)*time.Second || n.AllocatableMilliCPU > math.MaxInt64-s.AllocatableMilliCPU || n.AllocatableMemoryBytes > math.MaxInt64-s.AllocatableMemoryBytes {
				return NativeWorkerPoolSummary{}, fmt.Errorf("fresh ready worker allocation required")
			}
			s.ReadyUnits++
			s.AllocatableMilliCPU += n.AllocatableMilliCPU
			s.AllocatableMemoryBytes += n.AllocatableMemoryBytes
		}
	}
	sort.Strings(s.NodeUIDs)
	return s, nil
}
