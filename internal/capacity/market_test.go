package capacity

import (
	"encoding/json"
	"fmt"
	"math"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

func marketTestUUID(n int) string   { return fmt.Sprintf("%08x-0000-4000-8000-000000000000", n) }
func marketTestSHA(s string) string { return strings.Repeat(s, 64) }
func marketTestAdapter() model.CapacityMarketAdapterBinding {
	return model.CapacityMarketAdapterBinding{ManifestID: marketTestUUID(1), Version: 1, Checksum: marketTestSHA("a"), IntegrationTypeID: marketTestUUID(2), TypeChecksum: marketTestSHA("b")}
}

func marketKnownCost(c model.CapacityMarketCostComponent, source string, now time.Time) model.CapacityMarketCostComponent {
	c.Basis = "provider_rate"
	c.SourceIdentity = source
	c.EvidenceSHA256 = marketTestSHA("a")
	c.ValidUntil = now.Add(time.Hour)
	return c
}

func marketFixture(now time.Time) (model.CapacityPolicySpec, *model.CapacityMarketAssessment, MarketLedgerObservation) {
	p := model.CapacityPolicySpec{TargetIdentity: "native/pool", Owner: "capacity-pool", Currency: "USD", Floor: 0, Ceiling: 100, Profiles: []model.CapacityProfile{}}
	b := &model.CapacityMarketBinding{Mode: CapacityMarketMode, GrowthMode: "policy_bounds", WorkloadShapeSHA256: marketTestSHA("c"), HorizonSeconds: 60, BudgetMode: "bounded_total", BudgetScope: "production/native-surplus", BudgetMicros: 1_000_000, MaxQuoteAgeSeconds: 60, MaxQuotaAgeSeconds: 60, MaxEligibilityAgeSeconds: 60, MinSavingsMicros: 1, MinSavingsBasisPoints: 100, EconomicHoldSeconds: 120, MinResidenceSeconds: 600, Profiles: []model.CapacityMarketProfileBinding{}}
	m := &model.CapacityMarketAssessment{Schema: CapacityMarketMode, Currency: "USD", HorizonSeconds: 60, ObservedAt: now, ValidUntil: now.Add(10 * time.Minute), Profiles: []model.CapacityMarketProfileQuote{}}
	for i, name := range []string{"hcloud", "aws"} {
		region := "hel1"
		stop := "delete"
		used := int64(4)
		if name == "aws" {
			region = "us-east-1"
			stop = "stop"
			used = 0
		}
		p.Profiles = append(p.Profiles, model.CapacityProfile{Name: name, Provider: name, Region: region, MinUnits: 0, MaxUnits: 100, UnitMonthlyCostMinor: int64(100 + i), ReadinessSeconds: 10, ValidationRef: "qualified/same-workload", ValidationValidUntil: now.Add(time.Hour)})
		binding := model.CapacityMarketProfileBinding{Profile: name, Provider: name, Region: region, Adapter: marketTestAdapter(), PhysicalSpecSHA256: marketTestSHA("d"), WorkloadShapeSHA256: b.WorkloadShapeSHA256, Architecture: "amd64", BillingStopCondition: stop, MaxUnreservedAttempts: 100, QuoteSourceIdentity: "official/" + name, QuotaSourceIdentity: "quota/" + name, RegistrationBindingSHA: marketTestSHA("e"), NetworkBindingSHA: marketTestSHA("f"), QuotaDimensions: []model.CapacityMarketQuotaDimensionBinding{{Scope: "regional", Dimension: "instances", PerUnit: 1}, {Scope: "regional", Dimension: "ipv4", PerUnit: 1}}}
		b.Profiles = append(b.Profiles, binding)
		q := model.CapacityMarketProfileQuote{Currency: "USD", Profile: name, Provider: name, Region: region, Adapter: binding.Adapter, PhysicalSpecSHA256: binding.PhysicalSpecSHA256, WorkloadShapeSHA256: binding.WorkloadShapeSHA256, Architecture: binding.Architecture, BillingStopCondition: stop, WorkloadQualified: true, ValidationRef: p.Profiles[i].ValidationRef, ValidationValidUntil: p.Profiles[i].ValidationValidUntil, QualificationEvidenceSHA256: marketTestSHA("a"), SourceIdentity: binding.QuoteSourceIdentity, EvidenceSHA256: marketTestSHA("b"), ObservedAt: now, ValidUntil: m.ValidUntil, AllInComplete: true, Costs: []model.CapacityMarketCostComponent{}, Quotas: []model.CapacityMarketQuota{}}
		for _, n := range marketCostNames {
			q.Costs = append(q.Costs, model.CapacityMarketCostComponent{Name: n, Scope: "per_unit", State: "not_applicable", BillingUnit: "none"})
		}
		q.Costs[0] = marketKnownCost(model.CapacityMarketCostComponent{Name: "compute", State: "known", Scope: "per_unit", BillingUnit: "second", Quantity: 60, MinimumQuantity: 60, QuantumQuantity: 1, PriceMicros: 1, PriceQuantity: 1, LowerBoundMicros: 60}, binding.QuoteSourceIdentity, now)
		for _, d := range binding.QuotaDimensions {
			q.Quotas = append(q.Quotas, model.CapacityMarketQuota{Dimension: d.Dimension, Scope: d.Scope, State: "known", SourceIdentity: binding.QuotaSourceIdentity, EvidenceSHA256: marketTestSHA("c"), Limit: 100, Used: used, PerUnit: d.PerUnit, ObservedAt: now, ValidUntil: m.ValidUntil})
		}
		q.Stock = model.CapacityMarketEligibility{State: "offered_unreserved", MaxUnits: 100, BindingSHA256: binding.PhysicalSpecSHA256, EvidenceSHA256: marketTestSHA("d"), ObservedAt: now, ValidUntil: m.ValidUntil}
		q.Registration = model.CapacityMarketEligibility{State: "eligible", MaxUnits: 100, BindingSHA256: binding.RegistrationBindingSHA, EvidenceSHA256: marketTestSHA("e"), ObservedAt: now, ValidUntil: m.ValidUntil}
		q.Network = model.CapacityMarketEligibility{State: "eligible", MaxUnits: 100, BindingSHA256: binding.NetworkBindingSHA, EvidenceSHA256: marketTestSHA("f"), ObservedAt: now, ValidUntil: m.ValidUntil}
		m.Profiles = append(m.Profiles, q)
	}
	p.MarketBinding = b
	l := MarketLedgerObservation{Complete: true, ObservedAt: now, TargetIdentity: p.TargetIdentity, Owner: p.Owner, BudgetScope: b.BudgetScope, CurrentProfile: "hcloud", CurrentUnits: 4, CurrentPoolEpoch: 1, QuotaReservations: []MarketQuotaReservation{}}
	return p, m, l
}

func marketFind(t *testing.T, profiles []MarketProfile, name string) MarketProfile {
	t.Helper()
	for _, p := range profiles {
		if p.Profile.Name == name {
			return p
		}
	}
	t.Fatalf("missing market profile %s: %+v", name, profiles)
	return MarketProfile{}
}

func TestMarketRealBillingQuantumAndFiniteCycleCap(t *testing.T) {
	for _, tc := range []struct {
		name                                           string
		horizon, min, quantum, price, denom, cap, want int64
	}{
		{"aws_minute", 1, 60, 1, 1_000_000, 3600, 0, 16_667},
		{"hcloud_hour", 1, 0, 3600, 500_000, 3600, 0, 500_000},
		{"aws_61_seconds", 61, 60, 1, 1_000_000, 3600, 0, 16_945},
		{"hcloud_two_hours", 3601, 0, 3600, 500_000, 3600, 0, 1_000_000},
		{"verified_remaining_cycle_cap", 7200, 0, 3600, 500_000, 3600, 750_000, 750_000},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cost, known, err := costComponent(marketKnownCost(model.CapacityMarketCostComponent{Scope: "per_unit", State: "known", BillingUnit: "second", Quantity: tc.horizon, MinimumQuantity: tc.min, QuantumQuantity: tc.quantum, PriceMicros: tc.price, PriceQuantity: tc.denom, ChargeCapMicros: tc.cap}, "official/rate", time.Date(2026, 11, 27, 12, 0, 0, 0, time.UTC)), tc.horizon)
			if err != nil || !known || cost != tc.want {
				t.Fatalf("charge=%d known=%v err=%v want=%d", cost, known, err, tc.want)
			}
		})
	}
	if _, _, err := costComponent(marketKnownCost(model.CapacityMarketCostComponent{Scope: "per_unit", State: "known", BillingUnit: "second", Quantity: math.MaxInt64, QuantumQuantity: math.MaxInt64, PriceMicros: math.MaxInt64, PriceQuantity: 1}, "official/rate", time.Date(2026, 11, 27, 12, 0, 0, 0, time.UTC)), math.MaxInt64); err == nil {
		t.Fatal("overflow became a cheap quote")
	}
}

func TestMarketAdaptiveEnvelopeBeyondNinePreservesPolicy(t *testing.T) {
	now := time.Date(2026, 11, 27, 12, 0, 0, 0, time.UTC)
	p, m, l := marketFixture(now)
	before, _ := json.Marshal(p)
	profiles, err := EffectiveProfiles(p, m, l, now)
	if err != nil || len(profiles) != 2 {
		t.Fatalf("%+v %v", profiles, err)
	}
	if marketFind(t, profiles, "hcloud").Profile.MaxUnits != 100 {
		t.Fatal("obsolete nine-node cap retained")
	}
	after, _ := json.Marshal(p)
	if string(before) != string(after) {
		t.Fatal("volatile quotes rewrote policy fingerprint")
	}
	l.CurrentUnits = 0
	profiles, err = EffectiveProfiles(p, m, l, now)
	if err != nil {
		t.Fatal(err)
	}
	if cost, err := MarketCost(marketFind(t, profiles, "aws"), 0); err != nil || cost != 0 {
		t.Fatalf("empty worker pool incurred conditional charge: %d %v", cost, err)
	}
}

func TestMarketCannotRelabelAProviderCurrency(t *testing.T) {
	now := time.Date(2026, 11, 27, 12, 0, 0, 0, time.UTC)
	for _, currency := range []string{"", "EUR"} {
		p, m, l := marketFixture(now)
		m.Profiles[1].Currency = currency
		if _, err := EffectiveProfiles(p, m, l, now); err == nil {
			t.Fatalf("provider currency %q was silently relabeled USD", currency)
		}
	}
	p, m, l := marketFixture(now)
	p.Currency, m.Currency = "EUR", "EUR"
	if _, err := EffectiveProfiles(p, m, l, now); err == nil {
		t.Fatal("outer policy currency relabeled factual USD provider rates")
	}
}

func TestMarketProviderQuotaGlobalReservationsAndBudget(t *testing.T) {
	now := time.Date(2026, 11, 27, 12, 0, 0, 0, time.UTC)
	p, m, l := marketFixture(now)
	l.QuotaReservations = []MarketQuotaReservation{{Provider: "hcloud", Region: "hel1", Scope: "regional", Dimension: "ipv4", Amount: 90}}
	profiles, err := EffectiveProfiles(p, m, l, now)
	if err != nil {
		t.Fatal(err)
	}
	if got := marketFind(t, profiles, "hcloud").Profile.MaxUnits; got != 10 {
		t.Fatalf("shared pending IP reservations ignored: %d", got)
	}
	if got := marketFind(t, profiles, "aws").Profile.MaxUnits; got != 100 {
		t.Fatalf("wrong region/provider reservation leaked: %d", got)
	}
	p.MarketBinding.BudgetMicros = 1_200
	l.ReservedCostMicros = 60
	profiles, err = EffectiveProfiles(p, m, l, now)
	if err != nil {
		t.Fatal(err)
	}
	if got := marketFind(t, profiles, "aws").Profile.MaxUnits; got != 19 {
		t.Fatalf("budget/committed reservation ignored: %d", got)
	}
	reservation, err := MarketReservationFor(marketFind(t, profiles, "hcloud"), 8, now)
	if err != nil || reservation.Units != 4 || reservation.CostMicros != 240 || len(reservation.Quotas) != 2 || reservation.Quotas[0].Amount != 4 {
		t.Fatalf("incorrect delta reservation: %+v %v", reservation, err)
	}
}

func TestMarketDemandOnlyModeHasNoInventedFinancialCeiling(t *testing.T) {
	now := time.Date(2026, 11, 27, 12, 0, 0, 0, time.UTC)
	p, m, l := marketFixture(now)
	p.MarketBinding.BudgetMode = "demand_only_no_total_cap"
	p.MarketBinding.BudgetMicros = 0
	l.ReservedCostMicros = 2_000_000
	ps, err := EffectiveProfiles(p, m, l, now)
	if err != nil || marketFind(t, ps, "aws").Profile.MaxUnits != 100 {
		t.Fatalf("invented zero/global financial ceiling: %+v %v", ps, err)
	}
	m.Profiles[1].Network.MaxUnits = 37
	ps, err = EffectiveProfiles(p, m, l, now)
	if err != nil || marketFind(t, ps, "aws").Profile.MaxUnits != 37 {
		t.Fatalf("no-budget mode ignored real network capacity: %+v %v", ps, err)
	}
	l.UnknownReservations = true
	if _, err := EffectiveProfiles(p, m, l, now); err == nil {
		t.Fatal("no-budget mode ignored unknown reservation")
	}
}

func TestMarketBindingRejectsUnknownBudgetAndIncompatibleUnitShape(t *testing.T) {
	now := time.Date(2026, 11, 27, 12, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name   string
		mutate func(*model.CapacityPolicySpec)
	}{
		{"implicit_budget", func(p *model.CapacityPolicySpec) { p.MarketBinding.BudgetMode = "" }},
		{"bounded_zero", func(p *model.CapacityPolicySpec) { p.MarketBinding.BudgetMicros = 0 }},
		{"unbounded_hidden_budget", func(p *model.CapacityPolicySpec) { p.MarketBinding.BudgetMode = "demand_only_no_total_cap" }},
		{"different_unit", func(p *model.CapacityPolicySpec) {
			p.MarketBinding.Profiles[0].WorkloadShapeSHA256 = marketTestSHA("a")
		}},
		{"unknown_arch", func(p *model.CapacityPolicySpec) { p.MarketBinding.Profiles[0].Architecture = "unknown" }},
		{"type_unbound", func(p *model.CapacityPolicySpec) { p.MarketBinding.Profiles[0].Adapter.IntegrationTypeID = "" }},
		{"no_quota_contract", func(p *model.CapacityPolicySpec) { p.MarketBinding.Profiles[0].QuotaDimensions = nil }},
		{"duplicate_quota_contract", func(p *model.CapacityPolicySpec) {
			p.MarketBinding.Profiles[0].QuotaDimensions[1] = p.MarketBinding.Profiles[0].QuotaDimensions[0]
		}},
		{"no_economic_hysteresis", func(p *model.CapacityPolicySpec) { p.MarketBinding.EconomicHoldSeconds = 0 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, _, _ := marketFixture(now)
			tc.mutate(&p)
			if ValidateMarketBinding(p) == nil {
				t.Fatal("unsafe stable market binding accepted")
			}
		})
	}
}

func TestMarketRejectsUnboundStaleUnknownOrUnaccountedInputs(t *testing.T) {
	now := time.Date(2026, 11, 27, 12, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name   string
		mutate func(*model.CapacityPolicySpec, *model.CapacityMarketAssessment, *MarketLedgerObservation)
	}{
		{"currency", func(p *model.CapacityPolicySpec, m *model.CapacityMarketAssessment, l *MarketLedgerObservation) {
			m.Currency = "EUR"
		}},
		{"horizon", func(p *model.CapacityPolicySpec, m *model.CapacityMarketAssessment, l *MarketLedgerObservation) {
			m.HorizonSeconds++
		}},
		{"wire_adapter_forgery", func(p *model.CapacityPolicySpec, m *model.CapacityMarketAssessment, l *MarketLedgerObservation) {
			m.Profiles[0].Adapter.TypeChecksum = marketTestSHA("c")
		}},
		{"profile_omitted", func(p *model.CapacityPolicySpec, m *model.CapacityMarketAssessment, l *MarketLedgerObservation) {
			m.Profiles = m.Profiles[:1]
		}},
		{"quota_omitted", func(p *model.CapacityPolicySpec, m *model.CapacityMarketAssessment, l *MarketLedgerObservation) {
			m.Profiles[0].Quotas = m.Profiles[0].Quotas[:1]
		}},
		{"quota_consumption_tampered", func(p *model.CapacityPolicySpec, m *model.CapacityMarketAssessment, l *MarketLedgerObservation) {
			m.Profiles[0].Quotas[0].PerUnit = 2
		}},
		{"cost_omitted", func(p *model.CapacityPolicySpec, m *model.CapacityMarketAssessment, l *MarketLedgerObservation) {
			m.Profiles[0].Costs = m.Profiles[0].Costs[:1]
		}},
		{"cost_duplicate", func(p *model.CapacityPolicySpec, m *model.CapacityMarketAssessment, l *MarketLedgerObservation) {
			m.Profiles[0].Costs[1] = m.Profiles[0].Costs[0]
		}},
		{"workload_shape", func(p *model.CapacityPolicySpec, m *model.CapacityMarketAssessment, l *MarketLedgerObservation) {
			m.Profiles[0].WorkloadShapeSHA256 = marketTestSHA("a")
		}},
		{"stop_is_not_delete", func(p *model.CapacityPolicySpec, m *model.CapacityMarketAssessment, l *MarketLedgerObservation) {
			m.Profiles[0].BillingStopCondition = "stop"
		}},
		{"global_unknown", func(p *model.CapacityPolicySpec, m *model.CapacityMarketAssessment, l *MarketLedgerObservation) {
			l.UnknownReservations = true
		}},
		{"ledger_missing", func(p *model.CapacityPolicySpec, m *model.CapacityMarketAssessment, l *MarketLedgerObservation) {
			l.Complete = false
		}},
		{"ledger_future", func(p *model.CapacityPolicySpec, m *model.CapacityMarketAssessment, l *MarketLedgerObservation) {
			l.ObservedAt = now.Add(time.Second)
		}},
		{"ledger_stale", func(p *model.CapacityPolicySpec, m *model.CapacityMarketAssessment, l *MarketLedgerObservation) {
			l.ObservedAt = now.Add(-61 * time.Second)
		}},
		{"usage_omits_current", func(p *model.CapacityPolicySpec, m *model.CapacityMarketAssessment, l *MarketLedgerObservation) {
			m.Profiles[0].Quotas[0].Used = 0
		}},
		{"unreserved_stock_is_not_guaranteed", func(p *model.CapacityPolicySpec, m *model.CapacityMarketAssessment, l *MarketLedgerObservation) {
			m.Profiles[0].Stock.State = "eligible"
		}},
		{"unreserved_attempt_exceeds_bound", func(p *model.CapacityPolicySpec, m *model.CapacityMarketAssessment, l *MarketLedgerObservation) {
			m.Profiles[0].Stock.MaxUnits = 101
		}},
		{"fake_reserved_stock", func(p *model.CapacityPolicySpec, m *model.CapacityMarketAssessment, l *MarketLedgerObservation) {
			m.Profiles[0].Stock.State = "reserved"
		}},
		{"reservation_overflow", func(p *model.CapacityPolicySpec, m *model.CapacityMarketAssessment, l *MarketLedgerObservation) {
			r := MarketQuotaReservation{Provider: "hcloud", Region: "hel1", Scope: "regional", Dimension: "ipv4", Amount: math.MaxInt64}
			l.QuotaReservations = []MarketQuotaReservation{r, r}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, m, l := marketFixture(now)
			tc.mutate(&p, m, &l)
			if _, err := EffectiveProfiles(p, m, l, now); err == nil {
				t.Fatal("unsafe market envelope accepted")
			}
		})
	}
}

func TestMarketUnavailableDimensionExcludesCandidateWithoutInventingCapacity(t *testing.T) {
	now := time.Date(2026, 11, 27, 12, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name   string
		mutate func(*model.CapacityMarketProfileQuote)
	}{
		{"unknown_cost", func(q *model.CapacityMarketProfileQuote) { q.Costs[1].State = "unknown" }},
		{"incomplete_all_in", func(q *model.CapacityMarketProfileQuote) { q.AllInComplete = false }},
		{"unknown_quota", func(q *model.CapacityMarketProfileQuote) { q.Quotas[0].State = "unknown" }},
		{"unknown_network", func(q *model.CapacityMarketProfileQuote) { q.Network.State = "unknown" }},
		{"unknown_registration", func(q *model.CapacityMarketProfileQuote) { q.Registration.State = "unknown" }},
		{"unqualified_workload", func(q *model.CapacityMarketProfileQuote) { q.WorkloadQualified = false }},
		{"different_qualification", func(q *model.CapacityMarketProfileQuote) { q.ValidationRef = "nominal-vcpu-is-not-qualification" }},
		{"stale_price", func(q *model.CapacityMarketProfileQuote) { q.ObservedAt = now.Add(-61 * time.Second) }},
		{"expiry_before_readiness", func(q *model.CapacityMarketProfileQuote) { q.Network.ValidUntil = now.Add(5 * time.Second) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, m, l := marketFixture(now)
			tc.mutate(&m.Profiles[0])
			ps, err := EffectiveProfiles(p, m, l, now)
			if err != nil || len(ps) != 1 || ps[0].Profile.Name != "aws" {
				t.Fatalf("unknown became capacity: %+v %v", ps, err)
			}
		})
	}
}

func TestMarketObservedConstraintsGrowAcrossBatchesWithoutStaticCeiling(t *testing.T) {
	now := time.Date(2026, 11, 27, 12, 0, 0, 0, time.UTC)
	p, m, l := marketFixture(now)
	p.MarketBinding.GrowthMode = "observed_constraints"
	p.Ceiling = 0
	for i := range p.Profiles {
		p.Profiles[i].MaxUnits = 0
		m.Profiles[i].Registration.MaxUnits = 1000
		m.Profiles[i].Network.MaxUnits = 1000
		for j := range m.Profiles[i].Quotas {
			m.Profiles[i].Quotas[j].Limit = 1000
		}
	}
	ps, err := EffectiveProfiles(p, m, l, now)
	if err != nil || marketFind(t, ps, "hcloud").Profile.MaxUnits != 104 {
		t.Fatalf("dynamic first batch retained static bound: %+v %v", ps, err)
	}
	l.CurrentUnits = 120
	for j := range m.Profiles[0].Quotas {
		m.Profiles[0].Quotas[j].Used = 120
	}
	ps, err = EffectiveProfiles(p, m, l, now)
	if err != nil || marketFind(t, ps, "hcloud").Profile.MaxUnits != 220 {
		t.Fatalf("per-batch attempts became permanent fleet ceiling: %+v %v", ps, err)
	}
	if p.Ceiling != 0 || p.Profiles[0].MaxUnits != 0 {
		t.Fatal("dynamic market rewrote stable policy")
	}
}

func TestMarketPartialOutageAndScopedUnknownPermitHealthyProvider(t *testing.T) {
	now := time.Date(2026, 11, 27, 12, 0, 0, 0, time.UTC)
	p, m, l := marketFixture(now)
	failed := m.Profiles[1]
	m.Unavailable = []model.CapacityMarketUnavailableProfile{{Profile: failed.Profile, Provider: failed.Provider, Region: failed.Region, Adapter: failed.Adapter, Reason: "collector_unavailable", ObservedAt: now}}
	m.Profiles = m.Profiles[:1]
	ps, err := EffectiveProfiles(p, m, l, now)
	if err != nil || len(ps) != 1 || ps[0].Profile.Name != "hcloud" {
		t.Fatalf("AWS outage globally blocked HCloud: %+v %v", ps, err)
	}
	m.Unavailable[0].Adapter.Version++
	if _, err := EffectiveProfiles(p, m, l, now); err == nil {
		t.Fatal("failure outcome accepted wrong adapter")
	}
	p, m, l = marketFixture(now)
	l.UnknownQuotaScopes = []MarketQuotaUnknownScope{{Provider: "aws", Region: ""}}
	ps, err = EffectiveProfiles(p, m, l, now)
	if err != nil || len(ps) != 1 || ps[0].Profile.Name != "hcloud" {
		t.Fatalf("unresolved AWS allocation poisoned unrelated HCloud: %+v %v", ps, err)
	}
	l.UnknownQuotaScopes = []MarketQuotaUnknownScope{{Provider: "aws", Region: "us-east-1", Scope: "different-account", Dimension: "ipv4"}}
	if ps, err = EffectiveProfiles(p, m, l, now); err != nil || len(ps) != 2 {
		t.Fatalf("nonintersecting scope blocked offer: %+v %v", ps, err)
	}
}

func TestMarketLegacyMappingCanProveDistinctAccountWithoutRestoringAuthority(t *testing.T) {
	now := time.Date(2026, 11, 27, 12, 0, 0, 0, time.UTC)
	p, _, _ := marketFixture(now)
	p.MarketBinding.LegacyAllocators = []model.CapacityMarketLegacyAllocatorBinding{{IntegrationInstanceID: marketTestUUID(80), ScopeChecksum: marketTestSHA("a"), ProfileName: "old-worker", Namespace: "legacy", Environment: "production", Domain: "notify", Dimension: "compute", Quotas: []model.CapacityMarketLegacyQuotaBinding{{Provider: "aws", Region: "us-east-1", Scope: "verified-other-account", Dimension: "instances", PerUnit: 1}}}}
	if err := ValidateMarketBinding(p); err != nil {
		t.Fatalf("verified nonintersecting account scope could not be declared: %v", err)
	}
	p.MarketBinding.LegacyAllocators[0].Quotas[0].Dimension = "undeclared-resource"
	if err := ValidateMarketBinding(p); err == nil {
		t.Fatal("unbound quota kind accepted")
	}
}

func TestMarketUnavailableStockOnlyRetainsActualCurrentCapacity(t *testing.T) {
	now := time.Date(2026, 11, 27, 12, 0, 0, 0, time.UTC)
	p, m, l := marketFixture(now)
	for i := range m.Profiles {
		m.Profiles[i].Stock.State = "unavailable"
	}
	ps, err := EffectiveProfiles(p, m, l, now)
	if err != nil || len(ps) != 1 || ps[0].Profile.Name != "hcloud" || ps[0].Profile.MaxUnits != l.CurrentUnits {
		t.Fatalf("stock absence removed actual workers or authorized growth: %+v %v", ps, err)
	}
}

func TestMarketConservativeUpperAndLowerAreNotInvoiceOrGuaranteedSavings(t *testing.T) {
	now := time.Date(2026, 11, 27, 12, 0, 0, 0, time.UTC)
	p, m, l := marketFixture(now)
	tax := marketKnownCost(model.CapacityMarketCostComponent{Name: "tax", State: "known", Scope: "per_unit", BillingUnit: "one_time", Quantity: 1, QuantumQuantity: 1, PriceQuantity: 1, PriceMicros: 10, LowerBoundMicros: 0}, "review/tax-upper", now)
	tax.Basis = "reviewed_upper_bound"
	for i := range m.Profiles[0].Costs {
		if m.Profiles[0].Costs[i].Name == "tax" {
			m.Profiles[0].Costs[i] = tax
		}
	}
	if _, err := EffectiveProfiles(p, m, l, now); err == nil {
		t.Fatal("unapproved projection source accepted")
	}
	p.MarketBinding.Profiles[0].ReviewedCostSourceIdentities = []string{tax.SourceIdentity}
	ps, err := EffectiveProfiles(p, m, l, now)
	if err != nil {
		t.Fatal(err)
	}
	profile := marketFind(t, ps, "hcloud")
	upper, _ := MarketCost(profile, 4)
	lower, _ := MarketLowerCost(profile, 4)
	if upper != 280 || lower != 240 {
		t.Fatalf("projection bounds collapsed into fake exact bill: upper%d lower%d", upper, lower)
	}
	profile.Quote.Costs[0].LowerBoundMicros = 61
	if _, err := MarketCost(profile, 4); err == nil {
		t.Fatal("lower bound exceeded real upper charge")
	}
}

func TestMarketCostFixedFeesSameHorizonAndOverflow(t *testing.T) {
	now := time.Date(2026, 11, 27, 12, 0, 0, 0, time.UTC)
	p, m, l := marketFixture(now)
	// Lower nominal rate loses over this short horizon to a real whole-hour quantum.
	m.Profiles[0].Costs[0].QuantumQuantity = 3600
	m.Profiles[1].Costs[0].PriceMicros = 2
	ps, err := EffectiveProfiles(p, m, l, now)
	if err != nil {
		t.Fatal(err)
	}
	h, _ := MarketCost(marketFind(t, ps, "hcloud"), 4)
	a, _ := MarketCost(marketFind(t, ps, "aws"), 4)
	if a >= h {
		t.Fatalf("compared monthly labels rather than actual horizon: aws%d hcloud%d", a, h)
	}
	profile := marketFind(t, ps, "aws")
	for i := range profile.Quote.Costs {
		if profile.Quote.Costs[i].Name == "migration" {
			profile.Quote.Costs[i] = marketKnownCost(model.CapacityMarketCostComponent{Name: "migration", State: "known", Scope: "fixed", BillingUnit: "one_time", Quantity: 1, QuantumQuantity: 1, PriceMicros: 1_000, PriceQuantity: 1}, profile.Quote.SourceIdentity, now)
		}
	}
	if cost, err := MarketCost(profile, 4); err != nil || cost != 1_480 {
		t.Fatalf("migration fee not charged once: %d %v", cost, err)
	}
	profile.ReservedCostMicros = math.MaxInt64
	if _, err := MarketCost(profile, 4); err == nil {
		t.Fatal("total charge overflow accepted")
	}
	if !reflect.DeepEqual(l.QuotaReservations, []MarketQuotaReservation{}) {
		t.Fatal("pure planning mutated ledger")
	}
}
