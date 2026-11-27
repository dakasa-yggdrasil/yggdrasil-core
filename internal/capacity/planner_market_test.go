package capacity

import (
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

func plannerMarketFixture(now time.Time, units int) (model.CapacityPolicySpec, model.CapacityAssessment, MarketLedgerObservation) {
	p, m, l := marketFixture(now)
	p.Environment, p.Domain, p.Dimension = "production", "workers", "native_worker"
	p.Workflow = model.ManifestSelector{Namespace: "ops", Name: "workers"}
	p.Step, p.MaxEvidenceAgeSeconds, p.MaxSampleGapSeconds, p.MinSamples = 1, 60, 30, 3
	p.UpHoldSeconds, p.DownHoldSeconds, p.CooldownSeconds, p.LeaseSeconds = 0, 1, 1, 30
	p.ExecutionEnabled = true
	p.Signals = []model.CapacitySignalRule{{Name: "pending", SourceIdentity: "native/pending", Unit: "units", UpAbove: 0.8, DownBelow: 0.3}}
	adapter := marketTestAdapter()
	b := &model.CapacityNativeWorkerPoolBinding{Mode: "native_worker_pool_v1", Name: "workers", SourceCommit: marketTestSHA("a")[:40], Adapter: adapter, RealmUID: marketTestUUID(3), PoolUID: marketTestUUID(4), Owner: p.Owner, MaxAgeSeconds: 60, ExpectedPoolEpoch: 1, RegistryRef: model.CapacityNativePoolRegistryRef{Kind: "Lease", Namespace: "infra", Name: "workers", UID: marketTestUUID(5)}, Signals: []model.CapacityMetricSignalBinding{{Name: "pending", BindingName: "pending", BindingSHA256: marketTestSHA("b"), Adapter: model.CapacityObservationAdapterBinding{IntegrationInstanceID: adapter.ManifestID, InstanceChecksum: adapter.Checksum, IntegrationTypeID: adapter.IntegrationTypeID, TypeChecksum: adapter.TypeChecksum}}}, ProtectedNodes: []model.CapacityNativeProtectedNode{{NodeUID: marketTestUUID(6), ProviderID: "hcloud://floor"}}}
	for _, profile := range p.MarketBinding.Profiles {
		b.Profiles = append(b.Profiles, model.CapacityNativeWorkerProfileBinding{Profile: profile.Profile, Provider: profile.Provider, ProviderIDPrefix: profile.Provider + "://", PhysicalSpecSHA256: profile.PhysicalSpecSHA256, RegistrationBindingSHA: profile.RegistrationBindingSHA, MinAllocatableMilliCPU: 1000, MinAllocatableMemory: 1 << 30})
	}
	p.NativeWorkerPoolBinding = b
	o := &model.CapacityNativeWorkerPoolObservation{Schema: b.Mode, SourceCommit: b.SourceCommit, Adapter: b.Adapter, RealmUID: b.RealmUID, PoolUID: b.PoolUID, Owner: p.Owner, CurrentProfile: "hcloud", OwnerEpoch: 1, RegistryRef: b.RegistryRef, OwnerResourceUID: b.RegistryRef.UID, OwnerResourceVersion: "10", CollectionResourceVersion: "12", EvidenceSHA256: marketTestSHA("c"), ObservedAt: now, Complete: true, Nodes: []model.CapacityNativeWorkerNode{}}
	for i := 0; i < units; i++ {
		o.Nodes = append(o.Nodes, model.CapacityNativeWorkerNode{NodeUID: marketTestUUID(100 + i), NodeResourceVersion: "9", ProviderID: "hcloud://" + marketTestUUID(100+i), Provider: "hcloud", Profile: "hcloud", PoolUID: b.PoolUID, RegistrationEpoch: 1, RegistrationBindingSHA256: b.Profiles[0].RegistrationBindingSHA, PhysicalSpecSHA256: b.Profiles[0].PhysicalSpecSHA256, CurrentRegistration: true, CapacityPolicyID: marketTestUUID(7), IntentGeneration: 1, FencingToken: 1, RegistrationReceiptSHA256: marketTestSHA("d"), Ready: true, SchedulingAdmitted: true, AdmissionReceiptSHA256: marketTestSHA("e"), AdmissionRegistryUID: b.RegistryRef.UID, AdmissionRegistryResourceVersion: o.OwnerResourceVersion, ReadyObservedAt: now, AllocatableMilliCPU: 2000, AllocatableMemoryBytes: 2 << 30})
	}
	v := 0.5
	a := model.CapacityAssessment{Market: m, NativeWorkerPool: o, Evidence: []model.CapacityEvidence{{Name: "pending", SourceIdentity: "native/pending", Unit: "units", RequireData: true, Matched: true, DataState: "present", Value: &v, RangeMin: &v, RangeMax: &v, SourceSampledAt: now, WindowStart: now.Add(-time.Minute), WindowEnd: now, Samples: 10, CoverageComplete: true, MaxGapSeconds: 15}}}
	a.Snapshot, _ = NativeWorkerPoolSnapshot(p, o, now)
	l.CurrentUnits = units
	return p, a, l
}

func advancePlannerMarket(p model.CapacityPolicySpec, a model.CapacityAssessment, l MarketLedgerObservation, now time.Time, value float64) (model.CapacityAssessment, MarketLedgerObservation) {
	a = refresh(a, now, value)
	a.NativeWorkerPool.ObservedAt = now
	for i := range a.NativeWorkerPool.Nodes {
		a.NativeWorkerPool.Nodes[i].ReadyObservedAt = now
	}
	a.Snapshot, _ = NativeWorkerPoolSnapshot(p, a.NativeWorkerPool, now)
	a.Market.ObservedAt = now
	for i := range a.Market.Profiles {
		q := &a.Market.Profiles[i]
		q.ObservedAt = now
		q.Stock.ObservedAt, q.Registration.ObservedAt, q.Network.ObservedAt = now, now, now
		for j := range q.Quotas {
			q.Quotas[j].ObservedAt = now
		}
	}
	l.ObservedAt = now
	return a, l
}

func TestMarketPlannerZeroManagedWorkersNeedsRealPressure(t *testing.T) {
	now := time.Date(2026, 11, 27, 12, 0, 0, 0, time.UTC)
	p, a, l := plannerMarketFixture(now, 0)
	if err := ValidatePolicy(p); err != nil {
		t.Fatal(err)
	}
	d, err := AssessWithMarketLedger(p, a, model.CapacityClockState{}, l, now)
	if err != nil || d.Action != "hold" || d.Units != 0 {
		t.Fatalf("invented paid worker floor: %+v %v", d, err)
	}
	a, l = advancePlannerMarket(p, a, l, now.Add(time.Second), 1)
	d, err = AssessWithMarketLedger(p, a, d.Clock, l, now.Add(time.Second))
	if err != nil || d.Units != 1 || d.Action == "hold" {
		t.Fatalf("complete pending demand did not grow empty real pool: %+v %v", d, err)
	}
	a.Evidence = nil
	d, err = AssessWithMarketLedger(p, a, d.Clock, l, now.Add(time.Second))
	if err != nil || d.Action != "hold" || d.ExecutionPermitted {
		t.Fatalf("empty pool was treated as idle without demand evidence: %+v %v", d, err)
	}
	p.NativeWorkerPoolBinding = nil
	p.MarketBinding = nil
	if ValidatePolicy(p) == nil {
		t.Fatal("zero floor escaped into legacy policy")
	}
}

func TestMarketPlannerEconomicDwellSurvivesFreshPricesAndPaysSwitchCost(t *testing.T) {
	now := time.Date(2026, 11, 27, 12, 0, 0, 0, time.UTC)
	p, a, l := plannerMarketFixture(now, 4)
	p.MarketBinding.EconomicHoldSeconds, p.MarketBinding.MinResidenceSeconds = 2, 3
	a.Market.Profiles[0].Costs[0].PriceMicros = 10
	a.Market.Profiles[0].Costs[0].LowerBoundMicros = 600
	policyBefore, _ := json.Marshal(p)
	d, err := AssessWithMarketLedger(p, a, model.CapacityClockState{}, l, now)
	if err != nil || d.Reason != "economic_window_pending" {
		t.Fatalf("%+v %v", d, err)
	}
	key := d.Clock.EconomicCandidate
	start := *d.Clock.EconomicSince
	fingerprint := d.Clock.PolicyFingerprint
	for i := 1; i <= 3; i++ {
		at := now.Add(time.Duration(i) * time.Second)
		a, l = advancePlannerMarket(p, a, l, at, 0.5)
		d, err = AssessWithMarketLedger(p, a, d.Clock, l, at)
		if err != nil || d.Clock.EconomicCandidate != key || d.Clock.EconomicSince == nil || !d.Clock.EconomicSince.Equal(start) || d.Clock.PolicyFingerprint != fingerprint {
			t.Fatalf("fresh quote reset policy or dwell: %+v %v", d, err)
		}
	}
	if d.Action != "prepare" || d.Profile != "aws" || d.Reason != "sustained_all_in_savings" {
		t.Fatalf("no economically qualified replacement: %+v", d)
	}
	after, _ := json.Marshal(p)
	if string(policyBefore) != string(after) {
		t.Fatal("runtime prices rewrote policy")
	}
	for i := range a.Market.Profiles[1].Costs {
		if a.Market.Profiles[1].Costs[i].Name == "migration" {
			a.Market.Profiles[1].Costs[i] = model.CapacityMarketCostComponent{Name: "migration", State: "known", Scope: "fixed", BillingUnit: "one_time", Quantity: 1, QuantumQuantity: 1, PriceMicros: 10000, PriceQuantity: 1, Basis: "provider_rate", SourceIdentity: a.Market.Profiles[1].SourceIdentity, EvidenceSHA256: marketTestSHA("a"), ValidUntil: now.Add(time.Minute)}
		}
	}
	d, err = AssessWithMarketLedger(p, a, d.Clock, l, now.Add(3*time.Second))
	if err != nil || d.Action != "hold" || d.Clock.EconomicSince != nil {
		t.Fatalf("migration cost ignored: %+v %v", d, err)
	}
}

func TestMarketPlannerRequiresServerLedgerAndExactUsefulMembership(t *testing.T) {
	now := time.Date(2026, 11, 27, 12, 0, 0, 0, time.UTC)
	p, a, l := plannerMarketFixture(now, 1)
	if d, err := Assess(p, a, model.CapacityClockState{}, now); err != nil || d.Reason != "market_ledger_unavailable" {
		t.Fatalf("wire price authority accepted: %+v %v", d, err)
	}
	a.NativeWorkerPool.Nodes[0].Ready = false
	if d, err := AssessWithMarketLedger(p, a, model.CapacityClockState{}, l, now); err != nil || d.Reason != "native_worker_pool_unavailable" {
		t.Fatalf("non-ready worker became useful capacity: %+v %v", d, err)
	}
	a.NativeWorkerPool.Nodes[0].Ready = true
	a.NativeWorkerPool.OwnerEpoch++
	if _, err := NativeWorkerPoolSnapshot(p, a.NativeWorkerPool, now); err == nil {
		t.Fatal("observation selected its own expected epoch")
	}
}

func TestMarketEconomicWindowRestartsAfterPressureObservations(t *testing.T) {
	now := time.Date(2026, 11, 27, 12, 0, 0, 0, time.UTC)
	p, a, l := plannerMarketFixture(now, 4)
	p.MarketBinding.EconomicHoldSeconds, p.MarketBinding.MinResidenceSeconds = 2, 2
	p.UpHoldSeconds, p.DownHoldSeconds = 10, 10
	a.Market.Profiles[0].Costs[0].PriceMicros = 10
	a.Market.Profiles[0].Costs[0].LowerBoundMicros = 600
	d, err := AssessWithMarketLedger(p, a, model.CapacityClockState{}, l, now)
	if err != nil || d.Clock.EconomicSince == nil {
		t.Fatalf("economic dwell not started: %+v %v", d, err)
	}
	a, l = advancePlannerMarket(p, a, l, now.Add(time.Second), 1)
	d, err = AssessWithMarketLedger(p, a, d.Clock, l, now.Add(time.Second))
	if err != nil || d.Reason != "up_window_pending" || d.Clock.EconomicSince != nil || d.Clock.EconomicCandidate != "" {
		t.Fatalf("pressure preserved unobserved economic window: %+v %v", d, err)
	}
	a, l = advancePlannerMarket(p, a, l, now.Add(4*time.Second), 0.5)
	d, err = AssessWithMarketLedger(p, a, d.Clock, l, now.Add(4*time.Second))
	if err != nil || d.Action != "hold" || d.Clock.EconomicSince == nil || !d.Clock.EconomicSince.Equal(now.Add(4*time.Second)) {
		t.Fatalf("old window granted an immediate price switch: %+v %v", d, err)
	}
}

func TestMarketNativeWorkersCanReturnToZeroWithoutProfileMigration(t *testing.T) {
	now := time.Date(2026, 11, 27, 12, 0, 0, 0, time.UTC)
	p, a, l := plannerMarketFixture(now, 1)
	a, l = advancePlannerMarket(p, a, l, now, 0)
	d, err := AssessWithMarketLedger(p, a, model.CapacityClockState{}, l, now)
	if err != nil || d.Reason != "down_window_pending" {
		t.Fatalf("%+v %v", d, err)
	}
	a, l = advancePlannerMarket(p, a, l, now.Add(time.Second), 0)
	d, err = AssessWithMarketLedger(p, a, d.Clock, l, now.Add(time.Second))
	if err != nil || d.Action != "drain" || d.Units != 0 || d.Profile != "hcloud" {
		t.Fatalf("worker pool could not release final paid node: %+v %v", d, err)
	}
}

func TestNativeSnapshotFreshCollectionDoesNotResetMembershipClock(t *testing.T) {
	now := time.Date(2026, 11, 27, 12, 0, 0, 0, time.UTC)
	p, a, _ := plannerMarketFixture(now, 1)
	before := a.Snapshot
	beforeFingerprint, _ := NativeWorkerPoolSemanticFingerprint(a.NativeWorkerPool)
	a.NativeWorkerPool.CollectionResourceVersion = "999"
	a.NativeWorkerPool.OwnerResourceVersion = "200"
	for i := range a.NativeWorkerPool.Nodes {
		a.NativeWorkerPool.Nodes[i].AdmissionRegistryResourceVersion = "200"
	}
	a.NativeWorkerPool.ObservedAt = now.Add(time.Second)
	after, err := NativeWorkerPoolSnapshot(p, a.NativeWorkerPool, now.Add(time.Second))
	afterFingerprint, _ := NativeWorkerPoolSemanticFingerprint(a.NativeWorkerPool)
	if err != nil || before.WorkloadResourceVersion == after.WorkloadResourceVersion || before.ResourceVersion == after.ResourceVersion || beforeFingerprint != afterFingerprint {
		t.Fatalf("volatile API RV changed stable hold identity: %+v %v", after, err)
	}
	if reflect.DeepEqual(before, after) {
		t.Fatal("fresh source observation was not retained")
	}
}

func TestMarketObservedConstraintsGrowBeyondOldNineWithoutPolicyRewrite(t *testing.T) {
	now := time.Date(2026, 11, 27, 12, 0, 0, 0, time.UTC)
	p, a, l := plannerMarketFixture(now, 10)
	p.MarketBinding.GrowthMode = "observed_constraints"
	p.Ceiling = 0
	for i := range p.Profiles {
		p.Profiles[i].MaxUnits = 0
	}
	for i := range a.Market.Profiles[0].Quotas {
		a.Market.Profiles[0].Quotas[i].Used = 10
	}
	a, l = advancePlannerMarket(p, a, l, now, 1)
	raw, _ := json.Marshal(p)
	d, err := AssessWithMarketLedger(p, a, model.CapacityClockState{}, l, now)
	if err != nil || d.Action == "hold" || d.Units != 11 {
		t.Fatalf("fresh observed constraints retained fixed nine/static-zero cap: %+v %v", d, err)
	}
	after, _ := json.Marshal(p)
	if string(raw) != string(after) || p.Ceiling != 0 || p.Profiles[0].MaxUnits != 0 {
		t.Fatal("quote refresh rewrote stable growth-mode policy")
	}
	p.MarketBinding.GrowthMode = "policy_bounds"
	if ValidatePolicy(p) == nil {
		t.Fatal("zero ceiling sentinel escaped into policy-bounded mode")
	}
}

func unavailablePlannerMarket(a *model.CapacityAssessment, now time.Time) {
	for _, q := range a.Market.Profiles {
		a.Market.Unavailable = append(a.Market.Unavailable, model.CapacityMarketUnavailableProfile{Profile: q.Profile, Provider: q.Provider, Region: q.Region, Adapter: q.Adapter, Reason: "collector_unavailable", ObservedAt: now})
	}
	a.Market.Profiles = []model.CapacityMarketProfileQuote{}
}

func TestNativeRetirementDoesNotDependOnNewProviderPrices(t *testing.T) {
	now := time.Date(2026, 11, 27, 12, 0, 0, 0, time.UTC)
	for _, outage := range []string{"all_collectors_unavailable", "expired_price", "unknown_shared_cost"} {
		t.Run(outage, func(t *testing.T) {
			p, a, l := plannerMarketFixture(now, 3)
			switch outage {
			case "all_collectors_unavailable":
				unavailablePlannerMarket(&a, now)
			case "expired_price":
				a.Market.ValidUntil = now.Add(-time.Second)
			case "unknown_shared_cost":
				l.UnknownReservations = true
			}
			a, l = advancePlannerMarket(p, a, l, now, 0)
			d, err := AssessWithMarketLedger(p, a, model.CapacityClockState{}, l, now)
			if err != nil || d.Reason != "down_window_pending" {
				t.Fatalf("retirement did not retain its demand hold: %+v %v", d, err)
			}
			at := now.Add(2 * time.Second)
			a, l = advancePlannerMarket(p, a, l, at, 0)
			d, err = AssessWithMarketLedger(p, a, d.Clock, l, at)
			if err != nil || !IsNativeWorkerRetirementOnly(p, a, d) || !d.ExecutionPermitted || d.Units != 2 || d.Profile != a.Snapshot.Profile {
				t.Fatalf("price outage required a new allocation or blocked owned surplus: %+v %v", d, err)
			}
		})
	}
}

func TestNativeRetirementStillRequiresFreshDemandPoolLedgerAndCooldown(t *testing.T) {
	now := time.Date(2026, 11, 27, 12, 0, 0, 0, time.UTC)
	for _, fault := range []string{"pressure", "missing_signal", "stale_pool", "incomplete_ledger", "wrong_ledger_units", "cooldown", "disabled"} {
		t.Run(fault, func(t *testing.T) {
			p, a, l := plannerMarketFixture(now, 3)
			unavailablePlannerMarket(&a, now)
			a, l = advancePlannerMarket(p, a, l, now, 0)
			d, err := AssessWithMarketLedger(p, a, model.CapacityClockState{}, l, now)
			if err != nil {
				t.Fatal(err)
			}
			at := now.Add(2 * time.Second)
			a, l = advancePlannerMarket(p, a, l, at, 0)
			switch fault {
			case "pressure":
				a, l = advancePlannerMarket(p, a, l, at, 1)
			case "missing_signal":
				a.Evidence = nil
			case "stale_pool":
				a.NativeWorkerPool.ObservedAt = now.Add(-time.Hour)
			case "incomplete_ledger":
				l.Complete = false
			case "wrong_ledger_units":
				l.CurrentUnits++
			case "cooldown":
				d.Clock.LastActionAt = at
			case "disabled":
				p.ExecutionEnabled = false
			}
			d, err = AssessWithMarketLedger(p, a, d.Clock, l, at)
			if err != nil || d.ExecutionPermitted || fault != "disabled" && d.Action != "hold" {
				t.Fatalf("retirement bypassed its independent safety evidence: %+v %v", d, err)
			}
		})
	}
}

func TestNativeRetirementPreservesCurrentProfileMinimumWithoutPrices(t *testing.T) {
	now := time.Date(2026, 11, 27, 12, 0, 0, 0, time.UTC)
	p, a, l := plannerMarketFixture(now, 1)
	p.Profiles[0].MinUnits = 1 // Pool floor0 does not erase this profile's floor1.
	unavailablePlannerMarket(&a, now)
	a, l = advancePlannerMarket(p, a, l, now, 0)
	d, err := AssessWithMarketLedger(p, a, model.CapacityClockState{}, l, now)
	if err != nil {
		t.Fatal(err)
	}
	at := now.Add(2 * time.Second)
	a, l = advancePlannerMarket(p, a, l, at, 0)
	d, err = AssessWithMarketLedger(p, a, d.Clock, l, at)
	if err != nil || d.Action != "hold" || d.Units != 1 || d.Reason != "capacity_boundary" {
		t.Fatalf("retirement erased the declared current profile floor: %+v %v", d, err)
	}
	forged := model.CapacityDecision{Action: "drain", Reason: "sustained_surplus_retirement_only", Profile: a.Snapshot.Profile, Units: 0}
	if IsNativeWorkerRetirementOnly(p, a, forged) {
		t.Fatal("retirement classifier accepted units below the current profile minimum")
	}
}
