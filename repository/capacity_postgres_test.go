package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
	_ "github.com/lib/pq"
)

func capacityPostgresFixture(t *testing.T) (*sql.DB, model.Manifest, model.CapacityAssessment) {
	t.Helper()
	dsn := os.Getenv("DB_URL")
	if dsn == "" {
		if os.Getenv("REQUIRE_CAPACITY_POSTGRES") == "true" {
			t.Fatal("DB_URL required by capacity gate")
		}
		t.Skip("PostgreSQL integration runs in CI")
	}
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(20)
	ns := "capacity-" + uuid.NewString()
	now := time.Now().UTC()
	p := model.CapacityPolicySpec{Environment: "production", Domain: "api", Dimension: "replicas", TargetIdentity: "cluster/ns/api", Owner: "capacity-api", Workflow: model.ManifestSelector{Namespace: ns, Name: "scale-api"}, Currency: "USD", Floor: 2, Ceiling: 20, Step: 2, MaxEvidenceAgeSeconds: 60, MaxSampleGapSeconds: 30, MinSamples: 3, UpHoldSeconds: 0, DownHoldSeconds: 1, CooldownSeconds: 30, LeaseSeconds: 10, ExecutionEnabled: true, Signals: []model.CapacitySignalRule{{Name: "pressure", SourceIdentity: "prom/api", Unit: "ratio", UpAbove: 0.8, DownBelow: 0.3}}, Profiles: []model.CapacityProfile{{Name: "base", Provider: "provider", Region: "region", MinUnits: 2, MaxUnits: 20, UnitMonthlyCostMinor: 100, QuoteValidUntil: now.Add(time.Hour), ValidationValidUntil: now.Add(time.Hour), ValidationRef: "receipt:validated", ReadinessSeconds: 5}}}
	spec, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	policy, err := CreateManifestVersion(context.Background(), db, model.ManifestDocument{APIVersion: "v1", Kind: "capacity_policy", Metadata: model.ManifestMetadataInput{Namespace: ns, Name: "api"}, Spec: spec}, uuid.NewString())
	if err != nil {
		t.Fatal(err)
	}
	v := 0.9
	a := model.CapacityAssessment{Snapshot: model.CapacitySnapshot{TargetIdentity: p.TargetIdentity, ResourceUID: "hpa-1", WorkloadUID: "deployment-1", WorkloadResourceVersion: "10", ResourceVersion: "1", Owner: p.Owner, Profile: "base", Units: 4, ObservedAt: now}, Evidence: []model.CapacityEvidence{{Name: "pressure", SourceIdentity: "prom/api", Unit: "ratio", RequireData: true, Matched: true, DataState: "present", Value: &v, RangeMin: &v, RangeMax: &v, SourceSampledAt: now, WindowStart: now.Add(-time.Minute), WindowEnd: now, Samples: 10, CoverageComplete: true, MaxGapSeconds: 15}}}
	t.Cleanup(func() {
		ctx := context.Background()
		for _, q := range []string{`DELETE FROM public.capacity_intent_events WHERE namespace=$1`, `DELETE FROM public.capacity_intents WHERE namespace=$1`, `DELETE FROM public.manifests WHERE namespace=$1`} {
			if _, err := db.ExecContext(ctx, q, ns); err != nil {
				t.Error(err)
			}
		}
		db.Close()
	})
	return db, policy, a
}

func TestCapacityIntentPostgres(t *testing.T) {
	t.Run("concurrent_assess_and_claim", func(t *testing.T) {
		db, policy, a := capacityPostgresFixture(t)
		store := CapacityStore{DB: db, ExecutionEnabled: true, ExecutorID: uuid.NewString()}
		ctx := context.Background()
		var wg sync.WaitGroup
		for i := 0; i < 12; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				intent, err := store.Assess(ctx, policy, a)
				if err != nil || intent.Generation != 1 || intent.Phase != "proposed" {
					t.Errorf("generation not coalesced: %+v %v", intent, err)
				}
			}()
		}
		wg.Wait()
		var won atomic.Int32
		var winner model.CapacityIntent
		var mu sync.Mutex
		for i := 0; i < 12; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				intent, err := store.Claim(ctx, policy, 1, a)
				if err == nil {
					won.Add(1)
					mu.Lock()
					winner = intent
					mu.Unlock()
				} else if !errors.Is(err, ErrCapacityLease) {
					t.Errorf("unexpected claim: %v", err)
				}
			}()
		}
		wg.Wait()
		if won.Load() != 1 {
			t.Fatalf("owners=%d", won.Load())
		}
		restarted := CapacityStore{DB: db, ExecutionEnabled: true, ExecutorID: uuid.NewString()}
		observed, err := restarted.Observe(ctx, policy)
		if err != nil || observed.LeaseOwner != "" || observed.LeaseExecutorID != "" || observed.FencingToken != 1 {
			t.Fatalf("restart lost intent: %+v %v", observed, err)
		}
		if _, err := db.ExecContext(ctx, `UPDATE public.capacity_intents SET intent=jsonb_set(intent,'{lease_expires_at}',to_jsonb($2::text)) WHERE namespace=$1`, policy.Metadata.Namespace, time.Now().UTC().Add(-time.Second).Format(time.RFC3339Nano)); err != nil {
			t.Fatal(err)
		}
		if _, err := restarted.Claim(ctx, policy, 1, a); !errors.Is(err, ErrCapacityConflict) {
			t.Fatal("elapsed lease granted normal execution over an uncertain mutation", err)
		}
		next, err := restarted.Recover(ctx, policy, 1, a)
		if err != nil || next.FencingToken != 2 || next.LeaseOwner == winner.LeaseOwner {
			t.Fatalf("fenced recovery: %+v %v", next, err)
		}
		if _, err := store.Renew(ctx, policy, 1, winner.FencingToken, winner.LeaseOwner); !errors.Is(err, ErrCapacityConflict) {
			t.Fatalf("stale owner renewed: %v", err)
		}
		if _, err := restarted.RenewRecovery(ctx, policy, 1, next.FencingToken, next.LeaseOwner); err != nil {
			t.Fatal(err)
		}
		if _, err := store.Assess(ctx, policy, a); err != nil {
			t.Fatal(err)
		}
		var count int
		if err := db.QueryRowContext(ctx, `SELECT count(*) FROM public.capacity_intent_events WHERE namespace=$1`, policy.Metadata.Namespace).Scan(&count); err != nil || count != 3 {
			t.Fatalf("audit replay count=%d err=%v", count, err)
		}
	})
	t.Run("phase_receipts_and_promotion", func(t *testing.T) {
		db, policy, a := capacityPostgresFixture(t)
		store := CapacityStore{DB: db, ExecutionEnabled: true, ExecutorID: uuid.NewString()}
		ctx := context.Background()
		intent, err := store.Assess(ctx, policy, a)
		if err != nil {
			t.Fatal(err)
		}
		intent, err = store.Claim(ctx, policy, intent.Generation, a)
		if err != nil {
			t.Fatal(err)
		}
		proof := model.CapacityTransitionProof{Assessment: a, ObservedAt: time.Now().UTC(), ReceiptRef: "receipt:ready", Healthy: true, Inflight: capacityTestCount(0)}
		if _, err = store.Advance(ctx, policy, 1, intent.FencingToken, intent.LeaseOwner, "promoted", proof); !errors.Is(err, ErrCapacityConflict) {
			t.Fatalf("skipped canary: %v", err)
		}
		bad := proof
		bad.Assessment.Snapshot.WorkloadUID = "replacement"
		if _, err = store.Advance(ctx, policy, 1, intent.FencingToken, intent.LeaseOwner, "prepared", bad); !errors.Is(err, ErrCapacityConflict) {
			t.Fatalf("replacement accepted: %v", err)
		}
		for _, phase := range []string{"prepared", "canary"} {
			if _, err = store.Advance(ctx, policy, 1, intent.FencingToken, intent.LeaseOwner, phase, proof); err != nil {
				t.Fatal(err)
			}
		}
		if _, err = store.Advance(ctx, policy, 1, intent.FencingToken, intent.LeaseOwner, "promoted", proof); err == nil {
			t.Fatal("unobserved capacity promoted")
		}
		proof.Assessment.Snapshot.Units = intent.Decision.Units
		finished, err := store.Advance(ctx, policy, 1, intent.FencingToken, intent.LeaseOwner, "promoted", proof)
		if err != nil || finished.LeaseExpiresAt != nil || finished.Decision.Clock.LastActionAt.IsZero() {
			t.Fatalf("promotion: %+v %v", finished, err)
		}
		if _, err = store.Renew(ctx, policy, 1, intent.FencingToken, intent.LeaseOwner); !errors.Is(err, ErrCapacityConflict) {
			t.Fatalf("completed lease remained active: %v", err)
		}
		// Same-UID status/spec RV changes must reset pressure windows while
		// preserving cooldown from the last completed action.
		proof.Assessment.Snapshot.WorkloadResourceVersion = "11"
		after, err := store.Assess(ctx, policy, proof.Assessment)
		if err != nil || after.Decision.Action != "hold" || after.Decision.Reason != "cooldown" {
			t.Fatalf("RV change erased cooldown: %+v %v", after, err)
		}
	})
	t.Run("shadow_and_inactive_policy", func(t *testing.T) {
		db, policy, a := capacityPostgresFixture(t)
		store := CapacityStore{DB: db, ExecutorID: uuid.NewString()}
		ctx := context.Background()
		intent, err := store.Assess(ctx, policy, a)
		if err != nil || intent.Decision.ExecutionPermitted {
			t.Fatalf("shadow proposal %+v %v", intent, err)
		}
		if _, err = store.Claim(ctx, policy, 1, a); !errors.Is(err, ErrCapacityDisabled) {
			t.Fatal(err)
		}
		if _, err = db.ExecContext(ctx, `UPDATE public.manifests SET active=false WHERE id=$1`, policy.ID); err != nil {
			t.Fatal(err)
		}
		if _, err = store.Assess(ctx, policy, a); !errors.Is(err, ErrCapacityConflict) {
			t.Fatalf("inactive policy assessed: %v", err)
		}
	})
	t.Run("dimension_ownership_and_stale_evidence", func(t *testing.T) {
		db, policy, a := capacityPostgresFixture(t)
		store := CapacityStore{DB: db, ExecutionEnabled: true, ExecutorID: uuid.NewString()}
		ctx := context.Background()
		if _, err := store.Assess(ctx, policy, a); err != nil {
			t.Fatal(err)
		}
		other, err := CreateManifestVersion(ctx, db, model.ManifestDocument{APIVersion: "v1", Kind: "capacity_policy", Metadata: model.ManifestMetadataInput{Namespace: policy.Metadata.Namespace, Name: "other"}, Spec: policy.Spec}, uuid.NewString())
		if err != nil {
			t.Fatal(err)
		}
		if _, err = store.Assess(ctx, other, a); !errors.Is(err, ErrCapacityConflict) {
			t.Fatalf("two owners: %v", err)
		}
		a.Evidence[0].SourceSampledAt = time.Now().Add(-time.Hour)
		if _, err = store.Claim(ctx, policy, 1, a); err == nil {
			t.Fatal("stale metric claimed intent")
		}
	})
}

func capacityTestCount(value int) *int { return &value }

func freshCapacityTestAssessment(a model.CapacityAssessment, units int) model.CapacityAssessment {
	now := time.Now().UTC()
	a.Snapshot.Units, a.Snapshot.ObservedAt = units, now
	a.Evidence = append([]model.CapacityEvidence(nil), a.Evidence...)
	for i := range a.Evidence {
		a.Evidence[i].SourceSampledAt, a.Evidence[i].WindowEnd = now, now
		a.Evidence[i].WindowStart = now.Add(-time.Minute)
	}
	return a
}

func expireCapacityTestLease(t *testing.T, db *sql.DB, namespace string) {
	t.Helper()
	if _, err := db.ExecContext(context.Background(), `UPDATE public.capacity_intents SET intent=jsonb_set(intent,'{lease_expires_at}',to_jsonb($2::text)) WHERE namespace=$1`, namespace, time.Now().UTC().Add(-time.Second).Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
}

func TestCapacityIntentExecutorAndReadbackPrivacyPostgres(t *testing.T) {
	db, policy, a := capacityPostgresFixture(t)
	ctx := context.Background()
	owner := CapacityStore{DB: db, ExecutionEnabled: true, ExecutorID: uuid.NewString()}
	other := CapacityStore{DB: db, ExecutionEnabled: true, ExecutorID: uuid.NewString()}
	intent, err := owner.Assess(ctx, policy, a)
	if err != nil {
		t.Fatal(err)
	}
	intent, err = owner.Claim(ctx, policy, intent.Generation, a)
	if err != nil {
		t.Fatal(err)
	}
	for _, store := range []CapacityStore{owner, other} {
		read, err := store.Observe(ctx, policy)
		if err != nil || read.LeaseOwner != "" || read.LeaseExecutorID != "" {
			t.Fatal("readback disclosed a private executor lease")
		}
		read, err = store.Assess(ctx, policy, a)
		if err != nil || read.LeaseOwner != "" || read.LeaseExecutorID != "" {
			t.Fatal("pending assessment disclosed a private executor lease")
		}
	}
	if _, err := other.Renew(ctx, policy, intent.Generation, intent.FencingToken, intent.LeaseOwner); !errors.Is(err, ErrCapacityLease) {
		t.Fatalf("another invocation renewed a disclosed nonce: %v", err)
	}
	proof := model.CapacityTransitionProof{Assessment: a, ObservedAt: time.Now().UTC(), ReceiptRef: "receipt:ready", Healthy: true, Inflight: capacityTestCount(0)}
	if _, err := other.Advance(ctx, policy, intent.Generation, intent.FencingToken, intent.LeaseOwner, "prepared", proof); !errors.Is(err, ErrCapacityLease) {
		t.Fatalf("another invocation advanced a disclosed nonce: %v", err)
	}
	if _, err := owner.Renew(ctx, policy, intent.Generation, intent.FencingToken, intent.LeaseOwner); err != nil {
		t.Fatal("read-only redaction erased the persisted lease", err)
	}
}

func TestCapacityIntentExpiredQuoteAndHistoricalRecoveryPostgres(t *testing.T) {
	db, initial, a := capacityPostgresFixture(t)
	ctx := context.Background()
	var p model.CapacityPolicySpec
	if err := json.Unmarshal(initial.Spec, &p); err != nil {
		t.Fatal(err)
	}
	expires := time.Now().UTC().Add(3 * time.Second)
	p.Profiles[0].QuoteValidUntil, p.Profiles[0].ValidationValidUntil, p.Profiles[0].ReadinessSeconds = expires, expires, 0
	spec, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	policy, err := CreateManifestVersion(ctx, db, model.ManifestDocument{APIVersion: "v1", Kind: "capacity_policy", Metadata: model.ManifestMetadataInput{Namespace: initial.Metadata.Namespace, Name: initial.Metadata.Name}, Spec: spec}, uuid.NewString())
	if err != nil {
		t.Fatal(err)
	}
	owner := CapacityStore{DB: db, ExecutionEnabled: true, ExecutorID: uuid.NewString()}
	intent, err := owner.Assess(ctx, policy, freshCapacityTestAssessment(a, 4))
	if err != nil {
		t.Fatal(err)
	}
	intent, err = owner.Claim(ctx, policy, intent.Generation, freshCapacityTestAssessment(a, 4))
	if err != nil {
		t.Fatal(err)
	}
	// Executed only by the remote PostgreSQL CI gate, never on the laptop.
	time.Sleep(time.Until(expires.Add(25 * time.Millisecond)))
	renewed, err := owner.Renew(ctx, policy, intent.Generation, intent.FencingToken, intent.LeaseOwner)
	if err != nil || renewed.Decision.ExecutionPermitted {
		t.Fatalf("expired quote prevented renewal or enabled acquisition: %+v %v", renewed, err)
	}
	proof := model.CapacityTransitionProof{Assessment: freshCapacityTestAssessment(a, 4), ObservedAt: time.Now().UTC(), ReceiptRef: "receipt:readback", Healthy: true, Inflight: capacityTestCount(0)}
	if _, err := owner.Advance(ctx, policy, intent.Generation, intent.FencingToken, intent.LeaseOwner, "prepared", proof); err == nil {
		t.Fatal("expired profile advanced new preparation")
	}
	p.ExecutionEnabled = false
	p.Profiles[0].QuoteValidUntil, p.Profiles[0].ValidationValidUntil = time.Now().UTC().Add(time.Hour), time.Now().UTC().Add(time.Hour)
	spec, err = json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	revised, err := CreateManifestVersion(ctx, db, model.ManifestDocument{APIVersion: "v1", Kind: "capacity_policy", Metadata: model.ManifestMetadataInput{Namespace: policy.Metadata.Namespace, Name: policy.Metadata.Name}, Spec: spec}, uuid.NewString())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := owner.Assess(ctx, revised, freshCapacityTestAssessment(a, 4)); !errors.Is(err, ErrCapacityConflict) {
		t.Fatal("new revision replaced unfinished historical generation", err)
	}
	expireCapacityTestLease(t, db, policy.Metadata.Namespace)
	recovery := CapacityStore{DB: db, ExecutorID: uuid.NewString()} // Global execution is disabled.
	if _, err := recovery.Recover(ctx, revised, intent.Generation, freshCapacityTestAssessment(a, 6)); !errors.Is(err, ErrCapacityConflict) {
		t.Fatal("recovery changed original policy revision", err)
	}
	recovered, err := recovery.Recover(ctx, policy, intent.Generation, freshCapacityTestAssessment(a, 6))
	if err != nil || !recovered.RecoveryOnly || recovered.Decision.ExecutionPermitted || recovered.PolicyID != policy.ID || recovered.BaselineSnapshot.Units != 4 || recovered.FencingToken != intent.FencingToken+1 {
		t.Fatalf("historical recovery lost baseline/fencing or enabled execution: %+v %v", recovered, err)
	}
	other := CapacityStore{DB: db, ExecutorID: uuid.NewString()}
	if _, err := other.RenewRecovery(ctx, policy, recovered.Generation, recovered.FencingToken, recovered.LeaseOwner); !errors.Is(err, ErrCapacityLease) {
		t.Fatal("recovery executor nonce was adopted by another invocation", err)
	}
	if _, err := recovery.RenewRecovery(ctx, policy, recovered.Generation, recovered.FencingToken, recovered.LeaseOwner); err != nil {
		t.Fatal(err)
	}
	if _, err := owner.Renew(ctx, policy, recovered.Generation, intent.FencingToken, intent.LeaseOwner); err == nil {
		t.Fatal("old executor continued after fenced historical recovery")
	}
	zero := 0
	proof.Assessment, proof.ObservedAt = freshCapacityTestAssessment(a, recovered.Decision.Units), time.Now().UTC()
	proof.ProviderFencingToken, proof.MutationInflight = recovered.FencingToken, &zero
	finished, err := recovery.Reconcile(ctx, policy, recovered.Generation, recovered.FencingToken, recovered.LeaseOwner, "reconciled", proof)
	if err != nil || finished.Phase != "reconciled" || finished.Decision.ExecutionPermitted || finished.LeaseOwner != "" || finished.LeaseExecutorID != "" || finished.BaselineSnapshot.Units != 4 {
		t.Fatalf("observed target could not close historical intent: %+v %v", finished, err)
	}
	if _, err := recovery.RenewRecovery(ctx, policy, recovered.Generation, recovered.FencingToken, recovered.LeaseOwner); !errors.Is(err, ErrCapacityConflict) {
		t.Fatal("terminal recovery retained a lease", err)
	}
}

func TestCapacityIntentAbortRequiresMutationFenceProofPostgres(t *testing.T) {
	db, policy, a := capacityPostgresFixture(t)
	ctx := context.Background()
	owner := CapacityStore{DB: db, ExecutionEnabled: true, ExecutorID: uuid.NewString()}
	intent, err := owner.Assess(ctx, policy, a)
	if err != nil {
		t.Fatal(err)
	}
	intent, err = owner.Claim(ctx, policy, intent.Generation, a)
	if err != nil {
		t.Fatal(err)
	}
	expireCapacityTestLease(t, db, policy.Metadata.Namespace)
	recovery := CapacityStore{DB: db, ExecutionEnabled: true, ExecutorID: uuid.NewString()}
	recovered, err := recovery.Recover(ctx, policy, intent.Generation, freshCapacityTestAssessment(a, 4))
	if err != nil {
		t.Fatal(err)
	}
	proof := model.CapacityTransitionProof{Assessment: freshCapacityTestAssessment(a, 4), ObservedAt: time.Now().UTC(), ReceiptRef: "receipt:original-state", Healthy: true, Inflight: capacityTestCount(0)}
	if _, err := recovery.Advance(ctx, policy, recovered.Generation, recovered.FencingToken, recovered.LeaseOwner, "prepared", proof); !errors.Is(err, ErrCapacityConflict) {
		t.Fatal("recovery lease advanced normal acquisition phases", err)
	}
	zero, one := 0, 1
	proof.NoMutationVerified, proof.ProviderFencingToken = true, recovered.FencingToken
	for _, scenario := range []string{"absent-business-count", "absent-mutation-count", "outstanding-mutation", "stale-provider-fence", "no-absence-proof", "replacement-uid", "unhealthy", "stale-proof"} {
		bad := proof
		bad.MutationInflight = &zero
		switch scenario {
		case "absent-business-count":
			bad.Inflight = nil
		case "absent-mutation-count":
			bad.MutationInflight = nil
		case "outstanding-mutation":
			bad.MutationInflight = &one
		case "stale-provider-fence":
			bad.ProviderFencingToken--
		case "no-absence-proof":
			bad.NoMutationVerified = false
		case "replacement-uid":
			bad.Assessment.Snapshot.WorkloadUID = "replacement"
		case "unhealthy":
			bad.Healthy = false
		case "stale-proof":
			bad.ObservedAt = time.Now().Add(-time.Hour)
		}
		if _, err := recovery.Reconcile(ctx, policy, recovered.Generation, recovered.FencingToken, recovered.LeaseOwner, "aborted", bad); err == nil {
			t.Fatalf("unsafe recovery accepted %s", scenario)
		}
	}
	proof.MutationInflight = &zero
	finished, err := recovery.Reconcile(ctx, policy, recovered.Generation, recovered.FencingToken, recovered.LeaseOwner, "aborted", proof)
	if err != nil || finished.Phase != "aborted" || finished.Decision.ExecutionPermitted || finished.LeaseExpiresAt != nil || finished.Assessment.Snapshot.Units != finished.BaselineSnapshot.Units {
		t.Fatalf("verified original state did not close as aborted: %+v %v", finished, err)
	}
}

func TestCapacityIntentDrainRequiresExplicitZeroInflightPostgres(t *testing.T) {
	db, policy, a := capacityPostgresFixture(t)
	ctx := context.Background()
	store := CapacityStore{DB: db, ExecutionEnabled: true, ExecutorID: uuid.NewString()}
	low := 0.1
	a.Evidence[0].Value, a.Evidence[0].RangeMin, a.Evidence[0].RangeMax = &low, &low, &low
	first, err := store.Assess(ctx, policy, freshCapacityTestAssessment(a, 4))
	if err != nil || first.Decision.Action != "hold" {
		t.Fatalf("surplus did not begin a hold: %+v %v", first, err)
	}
	// Remote CI only: preserve source coverage while the one-second hold elapses.
	time.Sleep(1100 * time.Millisecond)
	intent, err := store.Assess(ctx, policy, freshCapacityTestAssessment(a, 4))
	if err != nil || intent.Decision.Action != "drain" || intent.Decision.Units != 2 {
		t.Fatalf("sustained surplus did not propose bounded drain: %+v %v", intent, err)
	}
	intent, err = store.Claim(ctx, policy, intent.Generation, freshCapacityTestAssessment(a, 4))
	if err != nil || intent.Phase != "draining" {
		t.Fatalf("claim did not enter draining: %+v %v", intent, err)
	}
	proof := model.CapacityTransitionProof{Assessment: freshCapacityTestAssessment(a, 4), ObservedAt: time.Now().UTC(), ReceiptRef: "receipt:business-drain", Healthy: true}
	for _, count := range []*int{nil, capacityTestCount(1)} {
		proof.Inflight = count
		if _, err := store.Advance(ctx, policy, intent.Generation, intent.FencingToken, intent.LeaseOwner, "drained", proof); err == nil {
			t.Fatal("absent/nonzero inflight was treated as drained")
		}
	}
	proof.Inflight = capacityTestCount(0)
	if _, err := store.Advance(ctx, policy, intent.Generation, intent.FencingToken, intent.LeaseOwner, "drained", proof); err != nil {
		t.Fatal(err)
	}
	proof.Assessment = freshCapacityTestAssessment(a, intent.Decision.Units)
	proof.Assessment.Snapshot.WorkloadResourceVersion = "11"
	for _, count := range []*int{nil, capacityTestCount(1)} {
		proof.Inflight = count
		if _, err := store.Advance(ctx, policy, intent.Generation, intent.FencingToken, intent.LeaseOwner, "promoted", proof); err == nil {
			t.Fatal("absent/nonzero inflight reduction was promoted")
		}
	}
	proof.Inflight = capacityTestCount(0)
	finished, err := store.Advance(ctx, policy, intent.Generation, intent.FencingToken, intent.LeaseOwner, "promoted", proof)
	if err != nil || finished.Phase != "promoted" || finished.LeaseExpiresAt != nil {
		t.Fatalf("observed drained reduction did not finish: %+v %v", finished, err)
	}
}

func TestCapacityIntentFloorReadbackWithoutDemandMetricsPostgres(t *testing.T) {
	db, policy, a := capacityPostgresFixture(t)
	ctx := context.Background()
	store := CapacityStore{DB: db, ExecutionEnabled: true, ExecutorID: uuid.NewString()}
	a.Snapshot.Units, a.Evidence = 1, nil
	intent, err := store.Assess(ctx, policy, a)
	if err != nil || intent.Decision.Reason != "protected_floor_recovery" || intent.Decision.Units != 2 {
		t.Fatalf("missing demand metrics blocked floor recovery: %+v %v", intent, err)
	}
	intent, err = store.Claim(ctx, policy, intent.Generation, freshCapacityTestAssessment(a, 1))
	if err != nil {
		t.Fatal(err)
	}
	strict := model.CapacityTransitionProof{Assessment: freshCapacityTestAssessment(a, 2), ObservedAt: time.Now().UTC(), ReceiptRef: "receipt:floor-observed", Healthy: true, Inflight: capacityTestCount(4)}
	if _, err := store.Advance(ctx, policy, intent.Generation, intent.FencingToken, intent.LeaseOwner, "prepared", strict); err == nil {
		t.Fatal("readback exception falsely asserted normal preparation/business readiness")
	}
	expireCapacityTestLease(t, db, policy.Metadata.Namespace)
	recovery := CapacityStore{DB: db, ExecutorID: uuid.NewString()}
	recovered, err := recovery.Recover(ctx, policy, intent.Generation, freshCapacityTestAssessment(a, 2))
	if err != nil {
		t.Fatal(err)
	}
	proof := strict
	proof.Assessment, proof.ObservedAt = freshCapacityTestAssessment(a, 2), time.Now().UTC()
	if _, err := recovery.Reconcile(ctx, policy, recovered.Generation, recovered.FencingToken, recovered.LeaseOwner, "reconciled", proof); err == nil {
		t.Fatal("floor readback bypassed required provider fencing/quiescence proof")
	}
	proof.MutationInflight, proof.ProviderFencingToken = capacityTestCount(0), recovered.FencingToken
	finished, err := recovery.Reconcile(ctx, policy, recovered.Generation, recovered.FencingToken, recovered.LeaseOwner, "reconciled", proof)
	if err != nil || finished.Phase != "reconciled" || finished.Decision.ExecutionPermitted || !finished.RecoveryOnly {
		t.Fatalf("healthy fenced floor result could not be recorded without demand metrics: %+v %v", finished, err)
	}
}
