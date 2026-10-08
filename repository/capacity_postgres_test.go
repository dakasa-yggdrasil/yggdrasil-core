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
		store := CapacityStore{DB: db, ExecutionEnabled: true}
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
		restarted := CapacityStore{DB: db, ExecutionEnabled: true}
		observed, err := restarted.Observe(ctx, policy)
		if err != nil || observed.LeaseOwner != winner.LeaseOwner || observed.FencingToken != 1 {
			t.Fatalf("restart lost intent: %+v %v", observed, err)
		}
		if _, err := db.ExecContext(ctx, `UPDATE public.capacity_intents SET intent=jsonb_set(intent,'{lease_expires_at}',to_jsonb($2::text)) WHERE namespace=$1`, policy.Metadata.Namespace, time.Now().UTC().Add(-time.Second).Format(time.RFC3339Nano)); err != nil {
			t.Fatal(err)
		}
		next, err := restarted.Claim(ctx, policy, 1, a)
		if err != nil || next.FencingToken != 2 || next.LeaseOwner == winner.LeaseOwner {
			t.Fatalf("fenced recovery: %+v %v", next, err)
		}
		if _, err := store.Renew(ctx, policy, 1, winner.FencingToken, winner.LeaseOwner); !errors.Is(err, ErrCapacityConflict) {
			t.Fatalf("stale owner renewed: %v", err)
		}
		if _, err := restarted.Renew(ctx, policy, 1, next.FencingToken, next.LeaseOwner); err != nil {
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
		store := CapacityStore{DB: db, ExecutionEnabled: true}
		ctx := context.Background()
		intent, err := store.Assess(ctx, policy, a)
		if err != nil {
			t.Fatal(err)
		}
		intent, err = store.Claim(ctx, policy, intent.Generation, a)
		if err != nil {
			t.Fatal(err)
		}
		proof := model.CapacityTransitionProof{Assessment: a, ObservedAt: time.Now().UTC(), ReceiptRef: "receipt:ready", Healthy: true}
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
	})
	t.Run("shadow_and_inactive_policy", func(t *testing.T) {
		db, policy, a := capacityPostgresFixture(t)
		store := CapacityStore{DB: db}
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
		store := CapacityStore{DB: db, ExecutionEnabled: true}
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
