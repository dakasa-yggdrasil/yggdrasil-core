package repository

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
	"github.com/lib/pq"
	"github.com/pressly/goose/v3"
)

// CI-only isolated database: immutable attempt/ACK history is NOT deleted or
// weakened to accommodate the old fixture cleanup. The whole owned DB goes away.
func nativeAttemptDatabase(t *testing.T) *sql.DB {
	t.Helper()
	dsn := os.Getenv("DB_URL")
	if dsn == "" {
		if os.Getenv("REQUIRE_CAPACITY_POSTGRES") == "true" {
			t.Fatal("DB_URL required")
		}
		t.Skip("PostgreSQL CI fixture")
	}
	u, err := url.Parse(dsn)
	if err != nil || os.Getenv("GITHUB_ACTIONS") != "true" || (u.Hostname() != "127.0.0.1" && u.Hostname() != "localhost" && u.Hostname() != "::1") {
		t.Fatal("new disposable test database requires the loopback GitHub CI service")
	}
	admin, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatal(err)
	}
	name := "native_attempt_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if _, err = admin.Exec("CREATE DATABASE " + pq.QuoteIdentifier(name)); err != nil {
		admin.Close()
		t.Fatal(err)
	}
	u.Path = "/" + name
	db, err := sql.Open("postgres", u.String())
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(20)
	t.Cleanup(func() {
		db.Close()
		if _, err := admin.Exec("DROP DATABASE " + pq.QuoteIdentifier(name) + " WITH (FORCE)"); err != nil {
			t.Error(err)
		}
		admin.Close()
	})
	if err = goose.SetDialect("postgres"); err != nil {
		t.Fatal(err)
	}
	if err = goose.Up(db, "../db/migrations"); err != nil {
		t.Fatal(err)
	}
	return db
}

func nativeAttemptFixture(t *testing.T, configure ...func(*model.CapacityPolicySpec)) (marketRepositoryFixture, CapacityNativeWorkerStore, *nativeAttemptRuntime, model.CapacityNativeWorkerAuthority) {
	t.Helper()
	db := nativeAttemptDatabase(t)
	now := time.Now().UTC()
	ns := "native-" + uuid.NewString()
	p := model.CapacityPolicySpec{Environment: "production", Domain: "api", Dimension: "replicas", TargetIdentity: "ci/native", Owner: "ci-owner", Workflow: model.ManifestSelector{Namespace: ns, Name: "scale-api"}, Currency: "USD", Floor: 0, Ceiling: 10, Step: 1, MaxEvidenceAgeSeconds: 60, MaxSampleGapSeconds: 30, MinSamples: 3, UpHoldSeconds: 0, DownHoldSeconds: 1, CooldownSeconds: 1, LeaseSeconds: 120, ExecutionEnabled: true, Signals: []model.CapacitySignalRule{{Name: "pressure", SourceIdentity: "prom/api", Unit: "ratio", UpAbove: 0.8, DownBelow: 0.3}}, Profiles: []model.CapacityProfile{{Name: "base", Provider: "fixture", Region: "fixture", MinUnits: 0, MaxUnits: 10, ValidationRef: "ci/qualified", ValidationValidUntil: now.Add(time.Hour)}}}
	create := func(kind, name string, spec any) model.Manifest {
		raw, _ := json.Marshal(spec)
		m, err := CreateManifestVersion(t.Context(), db, model.ManifestDocument{APIVersion: "yggdrasil.io/v1alpha1", Kind: kind, Metadata: model.ManifestMetadataInput{Namespace: ns, Name: name}, Spec: raw}, fmt.Sprintf("%x", sha256.Sum256(raw)))
		if err != nil {
			t.Fatal(err)
		}
		return m
	}
	original := create("capacity_policy", "base", p)
	value := 0.9
	a := model.CapacityAssessment{Evidence: []model.CapacityEvidence{{Name: "pressure", SourceIdentity: "prom/api", Unit: "ratio", RequireData: true, Matched: true, DataState: "present", Value: &value, RangeMin: &value, RangeMax: &value, SourceSampledAt: now, WindowStart: now.Add(-time.Minute), WindowEnd: now, Samples: 10, CoverageComplete: true, MaxGapSeconds: 15}}}
	f := marketRepoFixtureOnDB(t, db, original, a)
	typ := create("integration_type", "native-writer", map[string]any{"fixture": "separate-writer"})
	inst := create("integration_instance", "native-writer", map[string]any{"type_ref": model.ManifestSelector{ManifestID: typ.ID.String()}})
	adapter := model.CapacityMarketAdapterBinding{ManifestID: inst.ID.String(), Version: inst.Version, Checksum: inst.Checksum, IntegrationTypeID: typ.ID.String(), TypeChecksum: typ.Checksum}
	f.p.Ceiling = 0
	f.p.Step = 135
	f.p.Profiles[0].MaxUnits = 0
	f.p.MarketBinding.GrowthMode = "observed_constraints"
	f.p.MarketBinding.Profiles[0].MaxUnreservedAttempts = 1000
	f.market.Profiles[0].Quotas[0].Limit = 1000
	f.market.Profiles[0].Stock.MaxUnits = 1000
	f.market.Profiles[0].Registration.MaxUnits = 1000
	f.market.Profiles[0].Network.MaxUnits = 1000
	f.p.NativeWorkerLifecycleBinding = &model.CapacityNativeWorkerLifecycleBinding{Mode: capacity.NativeWorkerLifecycleMode, SourceCommit: strings.Repeat("a", 40), MaxReadAgeSeconds: 60, Profiles: []model.CapacityNativeWorkerExecutionProfile{{Profile: "hcloud", Adapter: adapter, BindingName: "ci-writer", SDKSourceCommit: strings.Repeat("e", 40), ScopeSHA256: strings.Repeat("f", 64), EnsureCapability: "ensure_server", ObserveCapability: "observe_server", DestroyCapability: "destroy_server", LaunchTemplateSHA256: strings.Repeat("b", 64), BootstrapSourceCommit: strings.Repeat("c", 40), IPAMScope: "ci/" + uuid.NewString(), OverlayCIDR: "10.81.0.0/24", ExcludedIPv4: []string{"10.81.0.2"}}}}
	for _, apply := range configure {
		apply(&f.p)
	}
	f.policy = create("capacity_policy", "market", f.p)
	workflow := create("workflow", f.p.Workflow.Name, map[string]any{"authorization": map[string]any{}})
	f.store.WorkflowID = workflow.ID
	proposed, err := f.store.Assess(t.Context(), f.policy, f.a)
	if err != nil {
		t.Fatal(err)
	}
	claimed, err := f.store.Claim(t.Context(), f.policy, proposed.Generation, f.a)
	if err != nil || claimed.MarketReservation == nil || claimed.MarketReservation.Units != f.p.Step {
		t.Fatal("actual market Claim did not reserve desired children", claimed, err)
	}
	r := &nativeAttemptRuntime{db: db, pool: f.pool}
	s := CapacityNativeWorkerStore{Capacity: f.store, Runtime: r, Enabled: true}
	return f, s, r, model.CapacityNativeWorkerAuthority{Generation: claimed.Generation, FencingToken: claimed.FencingToken}
}

type nativeAttemptRuntime struct {
	db      *sql.DB
	pool    *model.CapacityNativeWorkerPoolObservation
	failSDK atomic.Bool
	pending atomic.Bool
}

func (r *nativeAttemptRuntime) ObserveAuthority(context.Context, model.Manifest) (*model.CapacityNativeWorkerPoolObservation, error) {
	copy := *r.pool
	copy.ObservedAt = time.Now().UTC()
	return &copy, nil
}

func (*nativeAttemptRuntime) SourceCommit() string { return strings.Repeat("a", 40) }
func (*nativeAttemptRuntime) Prepare(a model.CapacityNativeWorkerAttempt) (model.CapacityNativeWorkerLaunch, error) {
	// Synthetic scoped context only, not a qualified System boot or key.
	raw, _ := json.Marshal(map[string]any{"schema": 1, "mode": "native_k3s_worker_v1", "source_commit": a.Execution.BootstrapSourceCommit, "pool_id": "ci-workers", "pool_uid": a.PoolUID, "registry": a.Registry, "policy_id": a.PolicyID.String(), "policy_sha256": a.PolicyChecksum, "expected_pool_epoch": a.PoolEpoch, "intent_generation": a.Generation, "fencing_token": a.FencingToken, "reservation_id": a.ID.String(), "intent_sha256": a.IntentSHA256, "provider": map[string]any{}, "floor": map[string]any{}, "network": map[string]any{"worker_ipv4": a.OverlayIPv4}, "operator": map[string]any{}, "reserve": map[string]any{}})
	return model.CapacityNativeWorkerLaunch{AttemptID: a.ID, PoolUID: a.PoolUID, PoolEpoch: a.PoolEpoch, Generation: a.Generation, FencingToken: a.FencingToken, OverlayIPv4: a.OverlayIPv4, TemplateSHA256: a.Execution.LaunchTemplateSHA256, PublicJSON: raw}, nil
}
func (r *nativeAttemptRuntime) CaptureOriginalReturn(context.Context, model.CapacityNativeWorkerAttempt) (model.CapacityNativeWorkerOriginalReturn, error) {
	if r.pending.Load() {
		return model.CapacityNativeWorkerOriginalReturn{}, ErrCapacityNativeReturnPending
	}
	return model.CapacityNativeWorkerOriginalReturn{Wire: []byte(`{"fixture":"original-provider-return","root_password":"ci-private-never-public"}`), CaptureComplete: true}, nil
}
func (r *nativeAttemptRuntime) Qualify(ctx context.Context, a model.CapacityNativeWorkerAttempt, raw model.CapacityNativeWorkerOriginalReturn) (model.CapacityNativeWorkerObservation, error) {
	var count int
	if err := r.db.QueryRowContext(ctx, `SELECT count(*) FROM public.capacity_native_worker_original_returns WHERE attempt_id=$1 AND wire=$2`, a.ID, raw.Wire).Scan(&count); err != nil || count != 1 {
		return model.CapacityNativeWorkerObservation{}, errors.New("SDK read preceded committed raw custody")
	}
	if r.failSDK.Load() {
		return model.CapacityNativeWorkerObservation{}, errors.New("fixture SDK unavailable")
	}
	physical := model.CapacityNativeWorkerPhysical{ResourceID: a.ID.String(), ProviderID: a.ProviderIDPrefix + a.ID.String(), InstanceType: "ci-type", NetworkID: "ci-network", CreatedAt: a.CreatedAt, ImageID: "ci-image", Region: a.Region, Zone: a.Region, NativeIPv4: "10.90.0.2", MACAddress: "86:00:00:2a:7d:e0", PhysicalSpecSHA256: a.PhysicalSpecSHA256, PhysicalBindingSHA256: strings.Repeat("d", 64), LaunchSHA256: a.LaunchSHA256}
	o := model.CapacityNativeWorkerObservation{State: "acknowledged", ExecutionScopeSHA256: a.Execution.ScopeSHA256, ObservedAt: time.Now().UTC(), OriginalReturnSHA256: fmt.Sprintf("%x", sha256.Sum256(raw.Wire)), OriginalAcceptance: physical, IndependentCurrent: physical, OriginalRequestID: "ci-create", IndependentRequestID: "ci-get"}
	if a.State == "acknowledged" {
		o.State = "registered"
		o.NodeUID = uuid.NewString()
		o.NodeProviderID = physical.ProviderID
		o.RegistryUID = a.Registry.UID
		o.RegistryBeforeResourceVersion = "1"
		o.RegistryAfterResourceVersion = "2"
	}
	return o, nil
}

func TestNativeWorkerAttemptLedgerPostgres(t *testing.T) {
	f, s, r, authority := nativeAttemptFixture(t)
	ctx := context.Background()
	attempts := make([]model.CapacityNativeWorkerAttempt, 0, 135)
	ids, ips := map[uuid.UUID]bool{}, map[string]bool{}
	for i := 0; i < 135; i++ {
		a, err := s.Reserve(ctx, f.policy, authority)
		if err != nil {
			t.Fatal(i, err)
		}
		if ids[a.ID] || ips[a.OverlayIPv4] || a.OverlayIPv4 == "10.81.0.2" {
			t.Fatal("UUID/IPAM collided or used excluded address")
		}
		ids[a.ID], ips[a.OverlayIPv4] = true, true
		attempts = append(attempts, a)
	}
	if _, err := s.Reserve(ctx, f.policy, authority); err == nil {
		t.Fatal("exceeded actual parent reservation")
	}
	var legacy int
	if err := f.db.QueryRow(`SELECT count(*) FROM public.capacity_mutation_grants`).Scan(&legacy); err != nil || legacy != 0 {
		t.Fatal("new UUID child forged legacy slots/grants", legacy, err)
	}
	a := attempts[0]
	r.pool.OwnerEpoch++
	if _, err := s.Redeem(ctx, f.policy, authority, a.ID); err == nil {
		t.Fatal("cached parent epoch authorized a new send after registry changed")
	}
	r.pool.OwnerEpoch--
	var won atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := s.Redeem(ctx, f.policy, authority, a.ID); err == nil {
				won.Add(1)
			}
		}()
	}
	wg.Wait()
	if won.Load() != 1 {
		t.Fatal("not exactly one durable send permit", won.Load())
	}
	r.pending.Store(true)
	if _, err := s.Record(ctx, f.policy, authority, a.ID); !errors.Is(err, ErrCapacityNativeReturnPending) {
		t.Fatal("pending original was sealed as empty", err)
	}
	var captures int
	if err := f.db.QueryRow(`SELECT count(*) FROM public.capacity_native_worker_original_returns`).Scan(&captures); err != nil || captures != 0 {
		t.Fatal("pending created false original custody")
	}
	r.pending.Store(false)
	r.failSDK.Store(true)
	unknown, err := s.Record(ctx, f.policy, authority, a.ID)
	if err != nil || unknown.State != "unknown" {
		t.Fatal("SDK failure erased original/uncertain child", unknown, err)
	}
	// Expiry is not permission to resend. A completed original remains truth.
	var original model.CapacityIntent
	err = f.db.QueryRow(`SELECT intent FROM public.capacity_intents WHERE namespace=$1`, f.policy.Metadata.Namespace).Scan((*nativeIntentScan)(&original))
	if err != nil {
		t.Fatal(err)
	}
	expired := time.Now().Add(-time.Second)
	original.LeaseExpiresAt = &expired
	wire, _ := json.Marshal(original)
	if _, err = f.db.Exec(`UPDATE public.capacity_intents SET intent=$2 WHERE namespace=$1`, f.policy.Metadata.Namespace, wire); err != nil {
		t.Fatal(err)
	}
	if _, err = s.Redeem(ctx, f.policy, authority, a.ID); err == nil {
		t.Fatal("expired uncertainty minted another send")
	}
	r.failSDK.Store(false)
	ack, err := s.Record(ctx, f.policy, authority, a.ID)
	if err != nil || ack.State != "acknowledged" || ack.BirthSHA256 == "" {
		t.Fatal("late exact original/SDK truth was lost", ack, err)
	}
	public, _ := json.Marshal(ack)
	raw := []byte(`{"fixture":"original-provider-return","root_password":"ci-private-never-public"}`)
	if strings.Contains(string(public), "ci-private-never-public") || strings.Contains(string(public), fmt.Sprintf("%x", sha256.Sum256(raw))) {
		t.Fatal("private return or raw hash entered public attempt")
	}
	if _, err = s.Record(ctx, f.policy, authority, a.ID); err == nil {
		t.Fatal("late ACK bypassed expired lease to register")
	}
	if _, err = f.db.Exec(`UPDATE public.capacity_native_worker_original_returns SET wire='{}' WHERE attempt_id=$1`, a.ID); err == nil {
		t.Fatal("original raw custody mutable")
	}
	if _, err = f.db.Exec(`DELETE FROM public.capacity_native_worker_attempts WHERE id=$1`, a.ID); err == nil {
		t.Fatal("possible start/history deleted")
	}
	if _, err = f.db.Exec(`UPDATE public.capacity_native_worker_attempts SET state='absent' WHERE id=$1`, attempts[1].ID); err == nil {
		t.Fatal("expiry/absence-free state released IPAM")
	}
	// Parent completion/fallback does not poison the whole account as unknown,
	// but retains every finite owned child quantity after the group closes.
	original.Phase = "promoted"
	original.MarketReservation = nil
	wire, _ = json.Marshal(original)
	if _, err = f.db.Exec(`UPDATE public.capacity_intents SET intent=$2 WHERE namespace=$1`, f.policy.Metadata.Namespace, wire); err != nil {
		t.Fatal(err)
	}
	var ledger capacity.MarketLedgerObservation
	err = s.tx(ctx, f.policy, func(tx *sql.Tx, p model.CapacityPolicySpec, _ time.Time) error {
		return appendNativeAttemptReservationsTx(ctx, tx, &ledger, p, map[string]bool{})
	})
	if err != nil || ledger.UnknownReservations || len(ledger.QuotaReservations) != 135 || ledger.ReservedCostMicros <= 0 {
		t.Fatal("closed parent erased finite child charges or blocked whole pool", len(ledger.QuotaReservations), err)
	}
}

type nativeIntentScan model.CapacityIntent

func TestNativeWorkerAttemptCreationBudget(t *testing.T) {
	now := time.Now().UTC()
	valid := func(baseline, target int, different bool) model.CapacityIntent {
		profile := "same"
		budget := target - baseline
		if different {
			profile, budget = "other", target
		}
		return model.CapacityIntent{Phase: "preparing", BaselineSnapshot: model.CapacitySnapshot{TargetIdentity: "pool", Owner: "owner", ResourceUID: "registry", WorkloadUID: "pool", ResourceVersion: "1", WorkloadResourceVersion: "2", Profile: "same", Units: baseline, ObservedAt: now}, Decision: model.CapacityDecision{Action: "expand", Profile: profile, Units: target}, MarketReservation: &model.CapacityMarketReservation{Schema: capacity.CapacityMarketMode, Profile: profile, Provider: "fixture", Region: "region", Currency: "USD", Units: budget, QuoteEvidenceSHA256: strings.Repeat("a", 64)}, Assessment: model.CapacityAssessment{Market: &model.CapacityMarketAssessment{ValidUntil: now.Add(time.Minute), Profiles: []model.CapacityMarketProfileQuote{{Profile: profile, Provider: "fixture", Region: "region", Currency: "USD", EvidenceSHA256: strings.Repeat("a", 64), ValidUntil: now.Add(time.Minute), ValidationValidUntil: now.Add(time.Hour)}}}}}
	}
	for _, tc := range []struct {
		name             string
		baseline, target int
		different        bool
		want             int
	}{{"first", 0, 135, false, 135}, {"increment", 10, 20, false, 10}, {"provider_overlap", 10, 20, true, 20}} {
		t.Run(tc.name, func(t *testing.T) {
			if got, err := nativeAttemptCreationBudget(valid(tc.baseline, tc.target, tc.different), now); err != nil || got != tc.want {
				t.Fatal("Claim baseline was not applied exactly once", got, err)
			}
		})
	}
	for _, tc := range []struct {
		name  string
		alter func(*model.CapacityIntent)
	}{
		{"negative_baseline", func(i *model.CapacityIntent) { i.BaselineSnapshot.Units = -1 }},
		{"unknown_baseline", func(i *model.CapacityIntent) { i.BaselineSnapshot.ObservedAt = time.Time{} }},
		{"missing_baseline_identity", func(i *model.CapacityIntent) { i.BaselineSnapshot.ResourceUID = "" }},
		{"total_instead_of_delta", func(i *model.CapacityIntent) { i.MarketReservation.Units = 20 }},
		{"underreserved", func(i *model.CapacityIntent) { i.MarketReservation.Units = 9 }},
		{"reservation_profile", func(i *model.CapacityIntent) { i.MarketReservation.Profile = "other" }},
		{"nonexpansion", func(i *model.CapacityIntent) { i.Decision.Units = 10 }},
		{"draining", func(i *model.CapacityIntent) { i.Phase = "draining" }},
		{"drain_action", func(i *model.CapacityIntent) { i.Decision.Action = "drain" }},
		{"expired_market", func(i *model.CapacityIntent) { i.Assessment.Market.ValidUntil = now }},
		{"expired_quote", func(i *model.CapacityIntent) { i.Assessment.Market.Profiles[0].ValidUntil = now }},
		{"expired_qualification", func(i *model.CapacityIntent) { i.Assessment.Market.Profiles[0].ValidationValidUntil = now }},
		{"different_source_quote", func(i *model.CapacityIntent) { i.MarketReservation.QuoteEvidenceSHA256 = strings.Repeat("b", 64) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			i := valid(10, 20, false)
			tc.alter(&i)
			if _, err := nativeAttemptCreationBudget(i, now); err == nil {
				t.Fatal("inconsistent or non-create Claim authorized children")
			}
		})
	}
}

// Synthetic protected CI observations exercise real store transitions and birth
// joins. These are not evidence of provider, network or Kubernetes qualification.
type nativeBudgetRuntime struct{ *nativeAttemptRuntime }

func (r nativeBudgetRuntime) Qualify(ctx context.Context, a model.CapacityNativeWorkerAttempt, raw model.CapacityNativeWorkerOriginalReturn) (model.CapacityNativeWorkerObservation, error) {
	o, err := r.nativeAttemptRuntime.Qualify(ctx, a, raw)
	if err != nil {
		return o, err
	}
	if a.State == "registered" || a.State == "admitted" || a.State == "draining" {
		o.NodeUID, o.NodeProviderID = a.NodeUID, a.Physical.ProviderID
		o.RegistryUID, o.RegistryBeforeResourceVersion, o.RegistryAfterResourceVersion = a.Registry.UID, "1", "2"
		o.NetworkBindingSHA256, o.QualificationEvidenceSHA256 = a.NetworkBindingSHA256, a.QualificationEvidenceSHA256
		o.NetworkEvidenceSHA256, o.WarmupEvidenceSHA256, o.AdmissionReceiptSHA256 = strings.Repeat("a", 64), strings.Repeat("b", 64), strings.Repeat("c", 64)
		o.DrainEvidenceSHA256 = strings.Repeat("d", 64)
		switch a.State {
		case "registered":
			o.State = "admitted"
		case "admitted":
			o.State = "draining"
		case "draining":
			o.State = "absent"
			o.AbsentProviderID, o.AbsentResourceCreatedAt, o.AbsentOverlayIPv4 = a.Physical.ProviderID, a.Physical.CreatedAt, a.OverlayIPv4
			o.ProviderAbsenceEvidenceSHA256, o.NetworkAbsenceEvidenceSHA256 = strings.Repeat("e", 64), strings.Repeat("f", 64)
		}
	}
	return o, nil
}

func TestNativeWorkerAttemptNonzeroClaimBaselinePostgres(t *testing.T) {
	f, s, r, authority := nativeAttemptFixture(t)
	s.Runtime = nativeBudgetRuntime{r}
	ctx := t.Context()
	load := func() model.CapacityIntent {
		t.Helper()
		var i model.CapacityIntent
		if err := f.db.QueryRowContext(ctx, `SELECT intent FROM public.capacity_intents WHERE namespace=$1`, f.policy.Metadata.Namespace).Scan((*nativeIntentScan)(&i)); err != nil {
			t.Fatal(err)
		}
		return i
	}
	store := func(i model.CapacityIntent) {
		t.Helper()
		b, err := json.Marshal(i)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = f.db.ExecContext(ctx, `UPDATE public.capacity_intents SET intent=$2 WHERE namespace=$1`, f.policy.Metadata.Namespace, b); err != nil {
			t.Fatal(err)
		}
	}
	// Establish ten birth-matched useful fixture workers using the actual
	// Reserve/Redeem/Record methods, not caller snapshot.Units or legacy grants.
	for range 10 {
		a, err := s.Reserve(ctx, f.policy, authority)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = s.Redeem(ctx, f.policy, authority, a.ID); err != nil {
			t.Fatal(err)
		}
		for range 3 {
			a, err = s.Record(ctx, f.policy, authority, a.ID)
			if err != nil {
				t.Fatal(err)
			}
		}
		if a.State != "admitted" {
			t.Fatal("fixture failed real child admission transitions", a.State)
		}
		f.pool.Nodes = append(f.pool.Nodes, model.CapacityNativeWorkerNode{NodeUID: a.NodeUID, NodeResourceVersion: "1", ProviderID: a.Physical.ProviderID, Provider: a.Provider, Profile: a.Profile, PoolUID: a.PoolUID, RegistrationEpoch: a.PoolEpoch, RegistrationBindingSHA256: f.p.NativeWorkerPoolBinding.Profiles[0].RegistrationBindingSHA, PhysicalSpecSHA256: a.PhysicalSpecSHA256, CurrentRegistration: true, CapacityPolicyID: a.PolicyID.String(), IntentGeneration: a.Generation, FencingToken: a.FencingToken, RegistrationReceiptSHA256: a.BirthSHA256, Ready: true, SchedulingAdmitted: true, AdmissionReceiptSHA256: strings.Repeat("c", 64), AdmissionRegistryUID: a.Registry.UID, AdmissionRegistryResourceVersion: f.pool.OwnerResourceVersion, ReadyObservedAt: time.Now().UTC(), AllocatableMilliCPU: 1000, AllocatableMemoryBytes: 1 << 30})
	}
	// Complete only this CI fixture parent so a real subsequent Assess/Claim
	// observes the established ten-worker pool. Immutable child/events remain.
	prior := load()
	prior.Phase, prior.MarketReservation = "promoted", nil
	prior.LeaseOwner, prior.LeaseExecutorID, prior.LeaseExpiresAt = "", "", nil
	store(prior)
	f.market.Profiles[0].Quotas[0].Used = 10
	// Current workers also retain their conservative child reservations; the
	// quote allows those ten plus ten existing and ten new provider slots.
	f.market.Profiles[0].Quotas[0].Limit = 30
	f.market.Profiles[0].Registration.MaxUnits = 20
	f.market.Profiles[0].Network.MaxUnits = 20
	// A provider path/zone cannot be substituted while retaining the same
	// resource suffix, Node UID and creation receipt. The outer pool contract
	// accepts the bound scheme/path syntax; the durable birth must join it fully.
	originalProviderID := f.pool.Nodes[0].ProviderID
	f.pool.Nodes[0].ProviderID = "hcloud://wrong-zone/" + originalProviderID[strings.LastIndex(originalProviderID, "/")+1:]
	if _, err := f.store.Assess(ctx, f.policy, f.a); err == nil {
		t.Fatal("same resource suffix/Node UID bypassed full physical provider identity")
	}
	f.pool.Nodes[0].ProviderID = originalProviderID
	proposal, err := f.store.Assess(ctx, f.policy, f.a)
	if err != nil || proposal.Decision.Units != 20 || proposal.Assessment.Snapshot.Units != 10 {
		t.Fatal("nonzero actual pool did not propose target20", proposal, err)
	}
	claim, err := f.store.Claim(ctx, f.policy, proposal.Generation, f.a)
	if err != nil || claim.BaselineSnapshot.Units != 10 || claim.MarketReservation == nil || claim.MarketReservation.Units != 10 {
		t.Fatal("real Claim must reserve target minus ten reusable workers", claim, err)
	}
	authority = model.CapacityNativeWorkerAuthority{Generation: claim.Generation, FencingToken: claim.FencingToken}
	children := make([]model.CapacityNativeWorkerAttempt, 10)
	for n := range children {
		children[n], err = s.Reserve(ctx, f.policy, authority)
		if err != nil {
			t.Fatal(n, err)
		}
	}
	draining := load()
	draining.Phase, draining.Decision.Action = "draining", "drain"
	store(draining)
	if _, err = s.Redeem(ctx, f.policy, authority, children[0].ID); err == nil {
		t.Fatal("reserved child started after its same parent moved to draining")
	}
	store(claim)
	if _, err = s.Redeem(ctx, f.policy, authority, children[0].ID); err != nil {
		t.Fatal(err)
	}
	r.failSDK.Store(true)
	if a, e := s.Record(ctx, f.policy, authority, children[0].ID); e != nil || a.State != "unknown" {
		t.Fatal("unknown fixture transition failed", a.State, e)
	}
	r.failSDK.Store(false)
	if _, err = s.Redeem(ctx, f.policy, authority, children[1].ID); err != nil {
		t.Fatal(err)
	}
	for range 3 {
		if _, err = s.Record(ctx, f.policy, authority, children[1].ID); err != nil {
			t.Fatal(err)
		}
	}
	store(draining)
	for range 2 {
		if _, err = s.Record(ctx, f.policy, authority, children[1].ID); err != nil {
			t.Fatal(err)
		}
	}
	store(claim)
	if _, err = s.Reserve(ctx, f.policy, authority); err == nil {
		t.Fatal("unknown/absent children replenished the consumed create budget")
	}
	rotated := load()
	rotated.FencingToken++
	store(rotated)
	authority.FencingToken = rotated.FencingToken
	if _, err = s.Reserve(ctx, f.policy, authority); err == nil {
		t.Fatal("fence rotation replenished the same generation's consumed budget")
	}
	var total, unknown, absent int
	if err = f.db.QueryRowContext(ctx, `SELECT count(*),count(*) FILTER(WHERE state='unknown'),count(*) FILTER(WHERE state='absent') FROM public.capacity_native_worker_attempts WHERE policy_id=$1 AND generation=$2`, f.policy.ID, claim.Generation).Scan(&total, &unknown, &absent); err != nil || total != 10 || unknown != 1 || absent != 1 {
		t.Fatal("generation history/state census changed", total, unknown, absent, err)
	}
}

func (i *nativeIntentScan) Scan(v any) error {
	raw, ok := v.([]byte)
	if !ok {
		return fmt.Errorf("intent bytes required")
	}
	return json.Unmarshal(raw, (*model.CapacityIntent)(i))
}
