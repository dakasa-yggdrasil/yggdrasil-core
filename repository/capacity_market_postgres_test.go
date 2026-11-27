package repository

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

type marketRepositoryFixture struct {
	db     *sql.DB
	policy model.Manifest
	p      model.CapacityPolicySpec
	a      model.CapacityAssessment
	market *model.CapacityMarketAssessment
	pool   *model.CapacityNativeWorkerPoolObservation
	store  CapacityStore
}

func marketRepoFixture(t *testing.T) marketRepositoryFixture {
	t.Helper()
	db, original, a := capacityPostgresFixture(t)
	ctx := context.Background()
	create := func(kind, name string, spec any) model.Manifest {
		raw, err := json.Marshal(spec)
		if err != nil {
			t.Fatal(err)
		}
		m, err := CreateManifestVersion(ctx, db, model.ManifestDocument{APIVersion: "yggdrasil.io/v1alpha1", Kind: kind, Metadata: model.ManifestMetadataInput{Namespace: original.Metadata.Namespace, Name: name}, Spec: raw}, fmt.Sprintf("%x", sha256.Sum256(raw)))
		if err != nil {
			t.Fatal(err)
		}
		return m
	}
	ty := create("integration_type", "market-observer", map[string]any{"fixture": true})
	im := create("integration_instance", "market-observer", map[string]any{"type_ref": model.ManifestSelector{ManifestID: ty.ID.String()}})
	adapter := model.CapacityMarketAdapterBinding{ManifestID: im.ID.String(), Version: im.Version, Checksum: im.Checksum, IntegrationTypeID: ty.ID.String(), TypeChecksum: ty.Checksum}
	var p model.CapacityPolicySpec
	if err := json.Unmarshal(original.Spec, &p); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	sha := func(s string) string { return strings.Repeat(s, 64) }
	p.Floor, p.Ceiling, p.Step = 0, 10, 1
	p.Dimension = "native_worker"
	p.Domain = "market"
	p.TargetIdentity = "native/market-pool"
	p.Owner = "market-owner"
	p.Profiles = []model.CapacityProfile{{Name: "hcloud", Provider: "hcloud", Region: "hel1", MinUnits: 0, MaxUnits: 10, ReadinessSeconds: 1, ValidationRef: "qualified/same-workload", ValidationValidUntil: now.Add(time.Hour)}}
	profile := model.CapacityMarketProfileBinding{Profile: "hcloud", Provider: "hcloud", Region: "hel1", Adapter: adapter, PhysicalSpecSHA256: sha("a"), WorkloadShapeSHA256: sha("b"), Architecture: "amd64", BillingStopCondition: "delete", MaxUnreservedAttempts: 10, QuoteSourceIdentity: "official/hcloud", QuotaSourceIdentity: "quota/project", RegistrationBindingSHA: sha("c"), NetworkBindingSHA: sha("d"), QuotaDimensions: []model.CapacityMarketQuotaDimensionBinding{{Scope: "same-account", Dimension: "instances", PerUnit: 1}}}
	p.MarketBinding = &model.CapacityMarketBinding{Mode: capacity.CapacityMarketMode, GrowthMode: "policy_bounds", BudgetScope: "fixture/account", WorkloadShapeSHA256: sha("b"), HorizonSeconds: 60, BudgetMode: "demand_only_no_total_cap", MaxQuoteAgeSeconds: 60, MaxQuotaAgeSeconds: 60, MaxEligibilityAgeSeconds: 60, MinSavingsMicros: 1, MinSavingsBasisPoints: 100, EconomicHoldSeconds: 1, MinResidenceSeconds: 1, Profiles: []model.CapacityMarketProfileBinding{profile}}
	p.NativeWorkerPoolBinding = &model.CapacityNativeWorkerPoolBinding{Mode: "native_worker_pool_v1", Name: "market-pool", SourceCommit: sha("a")[:40], Adapter: adapter, RealmUID: uuid.NewString(), PoolUID: uuid.NewString(), Owner: p.Owner, MaxAgeSeconds: 60, ExpectedPoolEpoch: 1, RegistryRef: model.CapacityNativePoolRegistryRef{Kind: "Lease", Namespace: "infra", Name: "market-pool", UID: uuid.NewString()}, Signals: []model.CapacityMetricSignalBinding{{Name: p.Signals[0].Name, BindingName: "market-pending", BindingSHA256: sha("b"), Adapter: model.CapacityObservationAdapterBinding{IntegrationInstanceID: im.ID.String(), InstanceChecksum: im.Checksum, IntegrationTypeID: ty.ID.String(), TypeChecksum: ty.Checksum}}}, Profiles: []model.CapacityNativeWorkerProfileBinding{{Profile: "hcloud", Provider: "hcloud", ProviderIDPrefix: "hcloud://", PhysicalSpecSHA256: sha("a"), RegistrationBindingSHA: sha("c"), MinAllocatableMilliCPU: 1000, MinAllocatableMemory: 1 << 30}}, ProtectedNodes: []model.CapacityNativeProtectedNode{{NodeUID: uuid.NewString(), ProviderID: "hcloud://1"}}}
	b := p.NativeWorkerPoolBinding
	pool := &model.CapacityNativeWorkerPoolObservation{Schema: b.Mode, SourceCommit: b.SourceCommit, Adapter: adapter, RealmUID: b.RealmUID, PoolUID: b.PoolUID, Owner: b.Owner, CurrentProfile: "hcloud", OwnerEpoch: 1, RegistryRef: b.RegistryRef, OwnerResourceUID: b.RegistryRef.UID, OwnerResourceVersion: "1", CollectionResourceVersion: "2", EvidenceSHA256: sha("c"), ObservedAt: now, Complete: true, Nodes: []model.CapacityNativeWorkerNode{}}
	quote := model.CapacityMarketProfileQuote{Currency: "USD", Profile: profile.Profile, Provider: profile.Provider, Region: profile.Region, Adapter: adapter, PhysicalSpecSHA256: profile.PhysicalSpecSHA256, WorkloadShapeSHA256: profile.WorkloadShapeSHA256, Architecture: profile.Architecture, BillingStopCondition: profile.BillingStopCondition, WorkloadQualified: true, ValidationRef: p.Profiles[0].ValidationRef, ValidationValidUntil: p.Profiles[0].ValidationValidUntil, QualificationEvidenceSHA256: sha("d"), SourceIdentity: profile.QuoteSourceIdentity, EvidenceSHA256: sha("e"), ObservedAt: now, ValidUntil: now.Add(time.Minute), AllInComplete: true, Quotas: []model.CapacityMarketQuota{{Dimension: "instances", Scope: "same-account", State: "known", SourceIdentity: profile.QuotaSourceIdentity, EvidenceSHA256: sha("f"), Limit: 1, PerUnit: 1, ObservedAt: now, ValidUntil: now.Add(time.Minute)}}}
	for _, name := range []string{"compute", "storage", "public_ip", "load_balancer", "nat", "egress", "backup", "control_plane", "overlap", "migration", "warmup", "teardown", "committed_remaining", "tax"} {
		quote.Costs = append(quote.Costs, model.CapacityMarketCostComponent{Name: name, Scope: "per_unit", State: "not_applicable", BillingUnit: "none"})
	}
	quote.Costs[0] = model.CapacityMarketCostComponent{Name: "compute", Scope: "per_unit", State: "known", BillingUnit: "second", Quantity: 60, QuantumQuantity: 1, MinimumQuantity: 60, PriceMicros: 1, PriceQuantity: 1, LowerBoundMicros: 60, Basis: "provider_rate", SourceIdentity: quote.SourceIdentity, EvidenceSHA256: sha("e"), ValidUntil: now.Add(time.Minute)}
	quote.Stock = model.CapacityMarketEligibility{State: "offered_unreserved", MaxUnits: 10, BindingSHA256: profile.PhysicalSpecSHA256, EvidenceSHA256: sha("a"), ObservedAt: now, ValidUntil: quote.ValidUntil}
	quote.Registration = model.CapacityMarketEligibility{State: "eligible", MaxUnits: 10, BindingSHA256: profile.RegistrationBindingSHA, EvidenceSHA256: sha("b"), ObservedAt: now, ValidUntil: quote.ValidUntil}
	quote.Network = model.CapacityMarketEligibility{State: "eligible", MaxUnits: 10, BindingSHA256: profile.NetworkBindingSHA, EvidenceSHA256: sha("c"), ObservedAt: now, ValidUntil: quote.ValidUntil}
	market := &model.CapacityMarketAssessment{Schema: capacity.CapacityMarketMode, Currency: p.Currency, HorizonSeconds: 60, ObservedAt: now, ValidUntil: quote.ValidUntil, Profiles: []model.CapacityMarketProfileQuote{quote}}
	policy := create("capacity_policy", "market", p)
	store := CapacityStore{DB: db, ExecutionEnabled: true, ExecutorID: uuid.NewString(), MarketObserver: func(context.Context, model.Manifest) (*model.CapacityMarketAssessment, *model.CapacityNativeWorkerPoolObservation, error) {
		return market, pool, nil
	}}
	return marketRepositoryFixture{db, policy, p, a, market, pool, store}
}

func TestMarketRepositoryReobservesClaimAndRejectsCallerAuthority(t *testing.T) {
	f := marketRepoFixture(t)
	ctx := context.Background()
	missing := f.store
	missing.DB = nil
	missing.MarketObserver = nil
	f.a.Market = f.market
	f.a.NativeWorkerPool = f.pool
	if _, err := missing.Assess(ctx, f.policy, f.a); err == nil {
		t.Fatal("caller-supplied market bypassed missing protected observer")
	}
	f.a.Snapshot.Units = 999
	i, err := f.store.Assess(ctx, f.policy, f.a)
	if err != nil || i.Assessment.Snapshot.Units != 0 || i.Decision.Units != 1 {
		t.Fatalf("server pool did not replace forged snapshot: %+v %v", i, err)
	}
	f.market.Profiles[0].Quotas[0].Limit = 0
	if _, err = f.store.Claim(ctx, f.policy, i.Generation, f.a); err == nil {
		t.Fatal("Claim used proposal's stale quota instead of fresh server offer")
	}
	var raw []byte
	if err = f.db.QueryRow(`SELECT intent FROM public.capacity_intents WHERE namespace=$1 AND domain=$2`, f.policy.Metadata.Namespace, f.p.Domain).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	var persisted model.CapacityIntent
	if err = json.Unmarshal(raw, &persisted); err != nil {
		t.Fatal(err)
	}
	if persisted.MarketReservation != nil || persisted.Phase != "proposed" {
		t.Fatalf("failed fresh Claim still reserved or advanced: %+v", persisted)
	}
}

func TestMarketRepositorySharedQuotaSerializesDifferentLogicalPolicies(t *testing.T) {
	f := marketRepoFixture(t)
	ctx := context.Background()
	p := f.p
	p.Domain = "market-other"
	p.TargetIdentity = "native/another-pool"
	p.Owner = "another-owner"
	b := *p.NativeWorkerPoolBinding
	b.Owner = p.Owner
	b.PoolUID = uuid.NewString()
	b.RegistryRef.UID = uuid.NewString()
	p.NativeWorkerPoolBinding = &b
	raw, _ := json.Marshal(p)
	other, err := CreateManifestVersion(ctx, f.db, model.ManifestDocument{APIVersion: f.policy.APIVersion, Kind: "capacity_policy", Metadata: model.ManifestMetadataInput{Namespace: f.policy.Metadata.Namespace, Name: "market-other"}, Spec: raw}, fmt.Sprintf("%x", sha256.Sum256(raw)))
	if err != nil {
		t.Fatal(err)
	}
	pool := *f.pool
	pool.PoolUID = b.PoolUID
	pool.Owner = b.Owner
	pool.RegistryRef = b.RegistryRef
	pool.OwnerResourceUID = b.RegistryRef.UID
	store := f.store
	store.ExecutorID = uuid.NewString()
	store.MarketObserver = func(context.Context, model.Manifest) (*model.CapacityMarketAssessment, *model.CapacityNativeWorkerPoolObservation, error) {
		return f.market, &pool, nil
	}
	first, err := f.store.Assess(ctx, f.policy, f.a)
	if err != nil {
		t.Fatal(err)
	}
	second, err := store.Assess(ctx, other, f.a)
	if err != nil {
		t.Fatal(err)
	}
	var won atomic.Int32
	var wg sync.WaitGroup
	for _, call := range []func() error{func() error { _, e := f.store.Claim(ctx, f.policy, first.Generation, f.a); return e }, func() error { _, e := store.Claim(ctx, other, second.Generation, f.a); return e }} {
		wg.Add(1)
		go func(claim func() error) {
			defer wg.Done()
			if claim() == nil {
				won.Add(1)
			}
		}(call)
	}
	wg.Wait()
	if won.Load() != 1 {
		t.Fatalf("same-account quota overbooked across logical scope locks: winners=%d", won.Load())
	}
	var reservations int
	if err = f.db.QueryRow(`SELECT count(*) FROM public.capacity_intents WHERE namespace=$1 AND intent ? 'market_reservation'`, f.policy.Metadata.Namespace).Scan(&reservations); err != nil || reservations != 1 {
		t.Fatalf("reservations=%d err=%v", reservations, err)
	}
}

// A nil-market legacy writer shares account quota with market reservations.
// Hold the real Claim after its global lock, then prove the legacy Issue cannot
// take its different logical lock first. No Guest authorization is manufactured:
// after serialization, the original legacy create guard still refuses it.
func TestMarketClaimSerializesLegacyIssueBeforeItsLogicalScope(t *testing.T) {
	f := marketRepoFixture(t)
	legacy := mutationPostgresFixture(t, false)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	var legacyPolicy model.CapacityPolicySpec
	if err := json.Unmarshal(legacy.policy.Spec, &legacyPolicy); err != nil || legacyPolicy.MarketBinding != nil {
		t.Fatal("fixture must exercise the actual legacy nil-market path", err)
	}
	proposal, err := f.store.Assess(ctx, f.policy, f.a)
	if err != nil {
		t.Fatal(err)
	}
	processDB := func(name string) (*sql.DB, int) {
		t.Helper()
		db, err := sql.Open("postgres", os.Getenv("DB_URL"))
		if err != nil {
			t.Fatal(err)
		}
		db.SetMaxOpenConns(1)
		t.Cleanup(func() { _ = db.Close() })
		if _, err = db.ExecContext(ctx, `SELECT set_config('application_name',$1,false)`, name); err != nil {
			t.Fatal(err)
		}
		var pid int
		if err = db.QueryRowContext(ctx, `SELECT pg_backend_pid()`).Scan(&pid); err != nil {
			t.Fatal(err)
		}
		return db, pid
	}
	marketDB, marketPID := processDB("capacity-market-claim-" + uuid.NewString())
	legacyDB, legacyPID := processDB("capacity-legacy-issue-" + uuid.NewString())
	marketStore, legacyStore := f.store, legacy.store
	marketStore.DB, legacyStore.DB = marketDB, legacyDB
	gate, err := f.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	var workers sync.WaitGroup
	defer func() {
		_ = gate.Rollback()
		cancel()
		workers.Wait()
	}()
	var policyID string
	if err = gate.QueryRowContext(ctx, `SELECT id::text FROM public.manifests WHERE id=$1 FOR UPDATE`, f.policy.ID).Scan(&policyID); err != nil || policyID != f.policy.ID.String() {
		t.Fatal("could not hold the exact Claim policy row", err)
	}
	waitLock := func(pid int, queryPart, event string, finished <-chan struct{}) {
		t.Helper()
		for {
			var blocked bool
			if err := f.db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE pid=$1 AND wait_event_type='Lock' AND query LIKE $2 AND ($3='' OR wait_event=$3))`, pid, "%"+queryPart+"%", event).Scan(&blocked); err != nil {
				t.Fatal(err)
			}
			if blocked {
				return
			}
			select {
			case <-finished:
				t.Fatal("actual repository call returned before its required native lock")
			case <-ctx.Done():
				t.Fatal("actual repository call did not reach its bounded native lock", ctx.Err())
			case <-time.After(10 * time.Millisecond):
			}
		}
	}
	type claimResult struct {
		intent model.CapacityIntent
		err    error
	}
	marketDone := make(chan claimResult, 1)
	marketFinished := make(chan struct{})
	workers.Add(1)
	go func() {
		defer workers.Done()
		defer close(marketFinished)
		i, err := marketStore.Claim(ctx, f.policy, proposal.Generation, f.a)
		marketDone <- claimResult{i, err}
	}()
	// This row wait occurs after the real Claim acquired its global quota lock.
	waitLock(marketPID, "kind='capacity_policy'", "", marketFinished)
	legacyDone := make(chan error, 1)
	legacyFinished := make(chan struct{})
	workers.Add(1)
	go func() {
		defer workers.Done()
		defer close(legacyFinished)
		_, err := legacyStore.IssueMutation(ctx, legacy.policy, legacy.intent.Generation, legacy.intent.FencingToken, legacy.intent.LeaseOwner, legacy.plans[5])
		legacyDone <- err
	}()
	waitLock(legacyPID, "capacity-market-shared-reservations-v1", "advisory", legacyFinished)
	// A waiting legacy writer must not hold its logical scope before global.
	logical, _ := json.Marshal([]string{legacy.policy.Metadata.Namespace, legacyPolicy.Environment, legacyPolicy.Domain, legacyPolicy.Dimension})
	probe, err := f.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	var available bool
	err = probe.QueryRowContext(ctx, `SELECT pg_try_advisory_xact_lock(hashtextextended($1,0))`, string(logical)).Scan(&available)
	_ = probe.Rollback()
	if err != nil || !available {
		t.Fatal("legacy writer held its logical lock before the shared quota lock", err)
	}
	if err = gate.Rollback(); err != nil {
		t.Fatal(err)
	}
	claimed := <-marketDone
	if claimed.err != nil || claimed.intent.Phase != "preparing" || claimed.intent.MarketReservation == nil || claimed.intent.MarketReservation.Units != 1 {
		t.Fatalf("actual market Claim did not retain its one reservation: %+v %v", claimed.intent, claimed.err)
	}
	if err = <-legacyDone; !errors.Is(err, ErrCapacityConflict) || !strings.Contains(err.Error(), "original Guest provisioning step and profile required before create") {
		t.Fatal("serialization changed the original legacy authorization refusal", err)
	}
	var grants int
	if err = legacy.db.QueryRowContext(ctx, `SELECT count(*) FROM public.capacity_mutation_grants WHERE namespace=$1`, legacy.policy.Metadata.Namespace).Scan(&grants); err != nil || grants != 0 {
		t.Fatal("legacy refusal still issued a create grant", grants, err)
	}
}

func TestMarketClaimAllowsFreshCollectionAndRegistryHeartbeatVersions(t *testing.T) {
	f := marketRepoFixture(t)
	ctx := context.Background()
	i, err := f.store.Assess(ctx, f.policy, f.a)
	if err != nil {
		t.Fatal(err)
	}
	f.pool.CollectionResourceVersion = "9999"
	f.pool.OwnerResourceVersion = "8888"
	f.pool.ObservedAt = time.Now().UTC()
	claimed, err := f.store.Claim(ctx, f.policy, i.Generation, f.a)
	if err != nil || claimed.Phase != "preparing" || claimed.MarketReservation == nil {
		t.Fatalf("native heartbeat prevented unchanged semantic Claim: %+v %v", claimed, err)
	}
	if claimed.Assessment.Snapshot.ResourceVersion != "9999" || claimed.Assessment.Snapshot.WorkloadResourceVersion != "8888" {
		t.Fatal("raw native resource versions were replaced with a synthetic SHA")
	}
}

// This isolated CI fixture declares a historical confirmed creation row and a
// current observer result. It qualifies only their database join and retirement
// Claim, never a real provider create, network admission or useful worker.
func declaredMarketWorker(t *testing.T, f marketRepositoryFixture) {
	t.Helper()
	now := time.Now().UTC()
	profile := f.p.MarketBinding.Profiles[0]
	grantID := uuid.NewString()
	proof := model.CapacityMutationProof{GrantID: grantID, BindingName: "declared-native", Slot: 1, ResourceID: "222222222", ResourceCreatedAt: now.Format(time.RFC3339Nano), RequestSHA256: strings.Repeat("a", 64), ObservedAt: now, ReceiptRef: "declared-ci/native-birth", OwnerVerified: true, SpecVerified: true}
	record := capacityMutationRecord{PolicyID: f.policy.ID, Generation: 1, FencingToken: 1, EventProvider: "hcloud", EventResource: "server", Grant: model.CapacityMutationGrant{GrantID: grantID, Capability: "ensure_server", State: "confirmed"}, Binding: model.CapacityMutationBinding{IntegrationInstanceID: profile.Adapter.ManifestID, ProfileName: profile.Profile, EnsureCapability: "ensure_server"}, Proof: &proof}
	raw, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.db.Exec(`INSERT INTO public.capacity_mutation_grants(id,namespace,environment,domain,dimension,generation,integration_instance_id,scope_checksum,profile_name,slot,state,grant_record,expires_at) VALUES($1,$2,$3,$4,$5,1,$6,$7,$8,1,'confirmed',$9,$10)`, grantID, f.policy.Metadata.Namespace, f.p.Environment, f.p.Domain, f.p.Dimension, profile.Adapter.ManifestID, strings.Repeat("c", 64), profile.Profile, raw, now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := f.db.Exec(`DELETE FROM public.capacity_mutation_grants WHERE id=$1`, grantID); err != nil {
			t.Error(err)
		}
	})
	proofRaw, _ := json.Marshal(proof)
	f.pool.Nodes = []model.CapacityNativeWorkerNode{{NodeUID: uuid.NewString(), NodeResourceVersion: "7", ProviderID: "hcloud://222222222", Provider: "hcloud", Profile: profile.Profile, PoolUID: f.pool.PoolUID, RegistrationEpoch: f.pool.OwnerEpoch, RegistrationBindingSHA256: profile.RegistrationBindingSHA, PhysicalSpecSHA256: profile.PhysicalSpecSHA256, CurrentRegistration: true, CapacityPolicyID: f.policy.ID.String(), IntentGeneration: 1, FencingToken: 1, RegistrationReceiptSHA256: fmt.Sprintf("%x", sha256.Sum256(proofRaw)), Ready: true, SchedulingAdmitted: true, AdmissionReceiptSHA256: strings.Repeat("f", 64), AdmissionRegistryUID: f.pool.RegistryRef.UID, AdmissionRegistryResourceVersion: f.pool.OwnerResourceVersion, ReadyObservedAt: now, AllocatableMilliCPU: 1000, AllocatableMemoryBytes: 1 << 30}}
}

func TestNativeRetirementClaimReobservesWithoutReservingMissingPrices(t *testing.T) {
	for _, changedPressure := range []bool{false, true} {
		t.Run(fmt.Sprintf("changed_pressure_%t", changedPressure), func(t *testing.T) {
			f := marketRepoFixture(t)
			declaredMarketWorker(t, f)
			for _, q := range f.market.Profiles {
				f.market.Unavailable = append(f.market.Unavailable, model.CapacityMarketUnavailableProfile{Profile: q.Profile, Provider: q.Provider, Region: q.Region, Adapter: q.Adapter, Reason: "collector_unavailable", ObservedAt: time.Now().UTC()})
			}
			f.market.Profiles = []model.CapacityMarketProfileQuote{}
			value := 0.0
			f.a.Evidence[0].Value, f.a.Evidence[0].RangeMin, f.a.Evidence[0].RangeMax = &value, &value, &value
			ctx := context.Background()
			first, err := f.store.Assess(ctx, f.policy, f.a)
			if err != nil || first.Decision.Reason != "down_window_pending" {
				t.Fatalf("missing prices bypassed down hold: %+v %v", first, err)
			}
			time.Sleep(1100 * time.Millisecond) // Actual CI database time owns the hold.
			proposal, err := f.store.Assess(ctx, f.policy, f.a)
			if err != nil || !capacity.IsNativeWorkerRetirementOnly(f.p, proposal.Assessment, proposal.Decision) || proposal.Decision.Units != 0 {
				t.Fatalf("could not propose independently observed retirement: %+v %v", proposal, err)
			}
			if changedPressure {
				value = 1
			}
			claimed, err := f.store.Claim(ctx, f.policy, proposal.Generation, f.a)
			if changedPressure {
				if err == nil {
					t.Fatal("Claim ignored newly observed demand before retirement")
				}
				return
			}
			if err != nil || claimed.Phase != "draining" || claimed.MarketReservation != nil || !claimed.Decision.ExecutionPermitted {
				t.Fatalf("retirement required a missing quote or reserved a new allocation: %+v %v", claimed, err)
			}
			var reserved bool
			if err = f.db.QueryRow(`SELECT intent ? 'market_reservation' FROM public.capacity_intents WHERE namespace=$1 AND domain=$2`, f.policy.Metadata.Namespace, f.p.Domain).Scan(&reserved); err != nil || reserved {
				t.Fatal("retirement persisted a fictional zero-cost provider offer", reserved, err)
			}
		})
	}
}

func TestNativeClaimComparisonIncludesStableBirthAdmissionAndAllocation(t *testing.T) {
	p := model.CapacityPolicySpec{NativeWorkerPoolBinding: &model.CapacityNativeWorkerPoolBinding{}}
	o := &model.CapacityNativeWorkerPoolObservation{Schema: "native_worker_pool_v1", RegistryRef: model.CapacityNativePoolRegistryRef{UID: "registry"}, OwnerEpoch: 1, Nodes: []model.CapacityNativeWorkerNode{{NodeUID: "node", ProviderID: "aws:///az/i-1", CapacityPolicyID: "policy", IntentGeneration: 1, FencingToken: 2, RegistrationReceiptSHA256: "birth", AdmissionReceiptSHA256: "admission", AdmissionRegistryUID: "registry", Ready: true, SchedulingAdmitted: true, AllocatableMilliCPU: 2000, AllocatableMemoryBytes: 4 << 30}}}
	a := model.CapacityAssessment{Snapshot: model.CapacitySnapshot{TargetIdentity: "pool", Owner: "owner", ResourceUID: "registry", WorkloadUID: "pool"}, NativeWorkerPool: o}
	for _, tc := range []struct {
		name   string
		mutate func(*model.CapacityNativeWorkerPoolObservation)
	}{
		{"node_replaced", func(v *model.CapacityNativeWorkerPoolObservation) { v.Nodes[0].NodeUID = "replacement" }},
		{"birth_fence", func(v *model.CapacityNativeWorkerPoolObservation) { v.Nodes[0].FencingToken++ }},
		{"creation_proof", func(v *model.CapacityNativeWorkerPoolObservation) { v.Nodes[0].RegistrationReceiptSHA256 = "other" }},
		{"admission", func(v *model.CapacityNativeWorkerPoolObservation) { v.Nodes[0].AdmissionReceiptSHA256 = "other" }},
		{"allocation", func(v *model.CapacityNativeWorkerPoolObservation) { v.Nodes[0].AllocatableMilliCPU++ }},
		{"epoch", func(v *model.CapacityNativeWorkerPoolObservation) { v.OwnerEpoch++ }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw, _ := json.Marshal(o)
			var changed model.CapacityNativeWorkerPoolObservation
			if err := json.Unmarshal(raw, &changed); err != nil {
				t.Fatal(err)
			}
			tc.mutate(&changed)
			b := a
			b.NativeWorkerPool = &changed
			if sameCapacityAssessmentResources(p, a, b) {
				t.Fatal("different native lifetime/authority/allocation passed Claim comparison")
			}
		})
	}
	if !sameCapacityAssessmentResources(p, a, a) {
		t.Fatal("identical immutable native state refused")
	}
}

func TestMarketReservationUnknownAndOverflowRemainReserved(t *testing.T) {
	p := model.CapacityPolicySpec{Currency: "USD", MarketBinding: &model.CapacityMarketBinding{HorizonSeconds: 60, BudgetMode: "bounded_total", BudgetScope: "same-budget", Profiles: []model.CapacityMarketProfileBinding{{Provider: "aws", Region: "us-east-1", QuotaDimensions: []model.CapacityMarketQuotaDimensionBinding{{Scope: "account", Dimension: "vcpu", PerUnit: 4}}}}}}
	ledger := capacity.MarketLedgerObservation{}
	r := &model.CapacityMarketReservation{Schema: capacity.CapacityMarketMode, BudgetScope: "same-budget", Profile: "aws", Provider: "aws", Region: "us-east-1", Currency: "EUR", Units: 1, CostMicros: 50, HorizonSeconds: 60, QuoteEvidenceSHA256: strings.Repeat("a", 64), ObservedAt: time.Now(), Quotas: []model.CapacityMarketQuotaReservation{{Provider: "aws", Region: "us-east-1", Scope: "account", Dimension: "vcpu", Amount: 4}}}
	if err := appendMarketReservation(&ledger, p, r); err != nil || !ledger.UnknownReservations || len(ledger.QuotaReservations) != 1 {
		t.Fatalf("incompatible or uncertain reservation became zero: %+v %v", ledger, err)
	}
	r.Quotas[0].Amount = -1
	if err := appendMarketReservation(&ledger, p, r); err == nil {
		t.Fatal("negative durable quota accepted")
	}
}

func TestMarketReservationOtherFinancialAndQuotaScopesDoNotBlock(t *testing.T) {
	p := model.CapacityPolicySpec{Currency: "USD", MarketBinding: &model.CapacityMarketBinding{BudgetMode: "bounded_total", BudgetScope: "current-budget", HorizonSeconds: 60, Profiles: []model.CapacityMarketProfileBinding{{Provider: "aws", Region: "us-east-1", QuotaDimensions: []model.CapacityMarketQuotaDimensionBinding{{Scope: "account-a", Dimension: "vcpu", PerUnit: 4}}}}}}
	r := &model.CapacityMarketReservation{Schema: capacity.CapacityMarketMode, BudgetScope: "other-budget", Profile: "old", Provider: "aws", Region: "us-east-1", Currency: "EUR", HorizonSeconds: 3600, Units: 1, CostMicros: 100, QuoteEvidenceSHA256: strings.Repeat("a", 64), ObservedAt: time.Now(), Quotas: []model.CapacityMarketQuotaReservation{{Provider: "aws", Region: "us-east-1", Scope: "account-b", Dimension: "vcpu", Amount: 4}}}
	l := capacity.MarketLedgerObservation{}
	if err := appendMarketReservation(&l, p, r); err != nil || l.UnknownReservations || l.ReservedCostMicros != 0 || len(l.QuotaReservations) != 0 {
		t.Fatalf("unrelated financial/account scope blocked current pool: %+v %v", l, err)
	}
	r.Quotas[0].Scope = "account-a"
	if err := appendMarketReservation(&l, p, r); err != nil || l.UnknownReservations || len(l.QuotaReservations) != 1 {
		t.Fatalf("shared quota was not counted independently from financial currency: %+v %v", l, err)
	}
}

func TestMarketLegacyScopeRequiresImmutableParentAndVerifiedAccountMapping(t *testing.T) {
	p := model.CapacityPolicySpec{MarketBinding: &model.CapacityMarketBinding{Profiles: []model.CapacityMarketProfileBinding{{Provider: "aws", Region: "us-east-1", QuotaDimensions: []model.CapacityMarketQuotaDimensionBinding{{Scope: "account-a", Dimension: "vcpu", PerUnit: 4}, {Scope: "account-a", Dimension: "ipv4", PerUnit: 1}}}}}}
	realm := marketGrantRealm{"historical", "production", "old-workers", "native_worker"}
	parent := model.CapacityPolicySpec{Environment: realm.Environment, Domain: realm.Domain, Dimension: realm.Dimension, Profiles: []model.CapacityProfile{{Name: "old-aws", Provider: "aws", Region: "us-east-1"}}}
	grant := capacityMutationRecord{EventProvider: "aws", Binding: model.CapacityMutationBinding{IntegrationInstanceID: uuid.NewString(), ScopeChecksum: strings.Repeat("a", 64), ProfileName: "old-aws", EnsureCapability: "ensure_server", DestroyCapability: "destroy_server"}, Grant: model.CapacityMutationGrant{Capability: "ensure_server"}}
	raw, _ := json.Marshal(parent)
	l := capacity.MarketLedgerObservation{}
	if err := appendLegacyMarketGrant(&l, p, grant, realm, raw); err != nil || l.UnknownReservations || len(l.UnknownQuotaScopes) != 1 || len(l.QuotaReservations) != 0 {
		t.Fatalf("unmapped actual account was guessed or blocked unrelated providers: %+v %v", l, err)
	}
	parent.Profiles[0].Region = "eu-west-1"
	raw, _ = json.Marshal(parent)
	l = capacity.MarketLedgerObservation{}
	if err := appendLegacyMarketGrant(&l, p, grant, realm, raw); err != nil || l.UnknownReservations || len(l.UnknownQuotaScopes) != 0 {
		t.Fatalf("immutable unrelated region blocked current policy: %+v %v", l, err)
	}
	parent.Profiles[0].Region = "us-east-1"
	raw, _ = json.Marshal(parent)
	mapping := model.CapacityMarketLegacyAllocatorBinding{IntegrationInstanceID: grant.Binding.IntegrationInstanceID, ScopeChecksum: grant.Binding.ScopeChecksum, ProfileName: grant.Binding.ProfileName, Namespace: realm.Namespace, Environment: realm.Environment, Domain: realm.Domain, Dimension: realm.Dimension, Quotas: []model.CapacityMarketLegacyQuotaBinding{{Provider: "aws", Region: "us-east-1", Scope: "account-b", Dimension: "vcpu", PerUnit: 4}, {Provider: "aws", Region: "us-east-1", Scope: "account-b", Dimension: "ipv4", PerUnit: 1}}}
	p.MarketBinding.LegacyAllocators = []model.CapacityMarketLegacyAllocatorBinding{mapping}
	l = capacity.MarketLedgerObservation{}
	if err := appendLegacyMarketGrant(&l, p, grant, realm, raw); err != nil || len(l.UnknownQuotaScopes) != 0 || len(l.QuotaReservations) != 0 {
		t.Fatalf("verified unrelated account wasn't excluded: %+v %v", l, err)
	}
	for i := range p.MarketBinding.LegacyAllocators[0].Quotas {
		p.MarketBinding.LegacyAllocators[0].Quotas[i].Scope = "account-a"
	}
	l = capacity.MarketLedgerObservation{}
	if err := appendLegacyMarketGrant(&l, p, grant, realm, raw); err != nil || len(l.UnknownQuotaScopes) != 0 || len(l.QuotaReservations) != 2 {
		t.Fatalf("overlapping possible-start grant lost exact dimensions: %+v %v", l, err)
	}
}
