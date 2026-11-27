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
	f.p.NativeWorkerLifecycleBinding = &model.CapacityNativeWorkerLifecycleBinding{Mode: capacity.NativeWorkerLifecycleMode, SourceCommit: strings.Repeat("a", 40), MaxReadAgeSeconds: 60, Profiles: []model.CapacityNativeWorkerExecutionProfile{{Profile: "hcloud", Adapter: adapter, BindingName: "ci-writer", ScopeSHA256: strings.Repeat("f", 64), EnsureCapability: "ensure_server", ObserveCapability: "observe_server", DestroyCapability: "destroy_server", LaunchTemplateSHA256: strings.Repeat("b", 64), BootstrapSourceCommit: strings.Repeat("c", 40), IPAMScope: "ci/" + uuid.NewString(), OverlayCIDR: "10.81.0.0/24", ExcludedIPv4: []string{"10.81.0.2"}}}}
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
	if err != nil || claimed.MarketReservation == nil || claimed.MarketReservation.Units != 135 {
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

func (i *nativeIntentScan) Scan(v any) error {
	raw, ok := v.([]byte)
	if !ok {
		return fmt.Errorf("intent bytes required")
	}
	return json.Unmarshal(raw, (*model.CapacityIntent)(i))
}
