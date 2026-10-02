package repository

import (
	"context"
	"database/sql"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
	_ "github.com/lib/pq"
)

func openReactorPauseDB(t *testing.T) *sql.DB {
	t.Helper()
	dsn := os.Getenv("DB_URL")
	if dsn == "" {
		if os.Getenv("REQUIRE_REACTOR_PAUSE_DB_TEST") == "true" {
			t.Fatal("REQUIRE_REACTOR_PAUSE_DB_TEST=true but DB_URL is not set")
		}
		t.Skip("DB_URL not set")
	}
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatalf("open database: %v", err)
	}
	if err := db.Ping(); err != nil {
		t.Fatalf("ping database: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func seedReactorPauseManifests(t *testing.T, db *sql.DB) (model.Manifest, model.Manifest) {
	t.Helper()
	namespace := "pause-" + uuid.New().String()[:8]
	typeManifest := seedIdentityManifest(t, db, "integration_type", namespace, "adapter", true,
		map[string]any{"reactors": []map[string]string{{"event_type": "team.created", "capability": "on_team_created"}}})
	instance := seedIdentityManifest(t, db, "integration_instance", namespace, "instance", true,
		map[string]any{"type_ref": map[string]string{"namespace": namespace, "name": "adapter"}})
	t.Cleanup(func() {
		_, _ = db.Exec(`DELETE FROM public.integration_reactor_dispatch_policies WHERE namespace = $1 AND name = $2`, namespace, "instance")
	})
	return typeManifest, instance
}

func emitReactorPauseTeamEvent(t *testing.T, db *sql.DB, synthetic bool) uuid.UUID {
	t.Helper()
	ctx := context.Background()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("begin event: %v", err)
	}
	defer tx.Rollback()
	req := model.EmitEventRequest{
		Type:          EventTypeTeamCreated,
		AggregateType: "team",
		AggregateID:   uuid.NewString(),
		Payload: map[string]any{
			"id": uuid.NewString(), "slug": "pause-ci", "name": "Pause CI",
		},
	}
	var eventID uuid.UUID
	if synthetic {
		eventID, err = EmitTeamReconcileEvent(ctx, tx, req)
	} else {
		eventID, err = EmitEvent(ctx, tx, req)
	}
	if err != nil {
		t.Fatalf("emit event: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit event: %v", err)
	}
	t.Cleanup(func() { _, _ = db.Exec(`DELETE FROM public.event_log WHERE event_id = $1`, eventID) })
	return eventID
}

func reactionForEvent(t *testing.T, db *sql.DB, eventID uuid.UUID) (uuid.UUID, int) {
	t.Helper()
	var id uuid.UUID
	var attempt int
	if err := db.QueryRow(`SELECT id, attempt FROM public.integration_event_reactions WHERE event_id = $1`, eventID).
		Scan(&id, &attempt); err != nil {
		t.Fatalf("lookup reaction: %v", err)
	}
	return id, attempt
}

func TestReactorPausePostgresClaimAndReplay(t *testing.T) {
	db := openReactorPauseDB(t)
	ctx := context.Background()
	_, instanceV1 := seedReactorPauseManifests(t, db)
	actorID := uuid.New()
	unwritten, err := GetIntegrationReactorDispatchPolicy(ctx, db, instanceV1.Metadata.Namespace, instanceV1.Metadata.Name)
	if err != nil || unwritten.Revision != 0 || len(unwritten.PausedEventTypes) != 0 || unwritten.UpdatedAt != nil {
		t.Fatalf("unwritten policy=%+v err=%v", unwritten, err)
	}
	paused, err := ReplaceIntegrationReactorDispatchPolicy(ctx, db, instanceV1.Metadata.Namespace, instanceV1.Metadata.Name, []string{EventTypeTeamCreated}, 0, actorID)
	if err != nil || len(paused.PausedEventTypes) != 1 || paused.Revision != 1 {
		t.Fatalf("pause: policy=%+v err=%v", paused, err)
	}
	stored, err := GetIntegrationReactorDispatchPolicy(ctx, db, instanceV1.Metadata.Namespace, instanceV1.Metadata.Name)
	if err != nil || stored.Revision != paused.Revision || len(stored.PausedEventTypes) != 1 || stored.UpdatedAt == nil {
		t.Fatalf("stored policy=%+v err=%v", stored, err)
	}
	if _, err := ReplaceIntegrationReactorDispatchPolicy(ctx, db, instanceV1.Metadata.Namespace, instanceV1.Metadata.Name, []string{}, 0, actorID); err != ErrIntegrationReactorPolicyRevisionConflict {
		t.Fatalf("stale revision unexpectedly replaced pause: %v", err)
	}
	var auditActor string
	if err := db.QueryRow(`
		SELECT actor FROM public.audit_events
		WHERE action = 'integration_instance.reactor_dispatch.replace' AND resource_id = $1
		ORDER BY created_at DESC LIMIT 1
	`, instanceV1.Metadata.Namespace+"/"+instanceV1.Metadata.Name).Scan(&auditActor); err != nil || auditActor != "user:"+actorID.String() {
		t.Fatalf("policy audit actor=%q err=%v", auditActor, err)
	}

	// Normal events stay durable during a pause; synthetic reconcile events do
	// not pile up for the same unprovisioned team.
	eventID := emitReactorPauseTeamEvent(t, db, false)
	reactionID, attempt := reactionForEvent(t, db, eventID)
	if attempt != 0 {
		t.Fatalf("initial attempt=%d, want 0", attempt)
	}
	if _, err := db.Exec(`
		UPDATE public.integration_event_reactions
		SET status='failed', last_error='prior transient error', next_attempt_at=NOW()
		WHERE id=$1
	`, reactionID); err != nil {
		t.Fatalf("seed failed retry: %v", err)
	}
	syntheticID := emitReactorPauseTeamEvent(t, db, true)
	var syntheticCount int
	if err := db.QueryRow(`SELECT COUNT(*) FROM public.integration_event_reactions WHERE event_id = $1`, syntheticID).Scan(&syntheticCount); err != nil || syntheticCount != 0 {
		t.Fatalf("synthetic paused fan-out=%d, err=%v", syntheticCount, err)
	}

	// A newer active manifest cannot bypass the logical instance policy for a
	// reaction whose FK still points to the older manifest version.
	instanceV2 := seedIdentityManifest(t, db, "integration_instance", instanceV1.Metadata.Namespace, instanceV1.Metadata.Name, true,
		map[string]any{"type_ref": map[string]string{"namespace": instanceV1.Metadata.Namespace, "name": "adapter"}})
	if instanceV1.ID == instanceV2.ID {
		t.Fatal("expected a new manifest version")
	}
	claims, err := ClaimPendingBatch(ctx, db, 10)
	if err != nil || len(claims) != 0 {
		t.Fatalf("paused claims=%d, err=%v", len(claims), err)
	}
	_, attempt = reactionForEvent(t, db, eventID)
	if attempt != 0 {
		t.Fatalf("paused reaction consumed attempt=%d", attempt)
	}

	// Resuming requires an explicit empty policy and claims the old version's
	// backlog once. A newly written pause between claim and RPC releases it.
	if _, err := ReplaceIntegrationReactorDispatchPolicy(ctx, db, instanceV1.Metadata.Namespace, instanceV1.Metadata.Name, []string{}, 1, actorID); err != nil {
		t.Fatalf("resume: %v", err)
	}
	claims, err = ClaimPendingBatch(ctx, db, 10)
	if err != nil || len(claims) != 1 || claims[0].ID != reactionID || claims[0].Attempt != 1 {
		t.Fatalf("resumed claims=%+v, err=%v", claims, err)
	}
	if claims[0].DispatchInstanceID != instanceV2.ID {
		t.Fatalf("claim dispatches stale instance %s, want active %s", claims[0].DispatchInstanceID, instanceV2.ID)
	}
	if _, err := ReplaceIntegrationReactorDispatchPolicy(ctx, db, instanceV1.Metadata.Namespace, instanceV1.Metadata.Name, []string{EventTypeTeamCreated}, 2, actorID); err != nil {
		t.Fatalf("re-pause: %v", err)
	}
	_, allowed, err := ReactionDispatchAllowed(ctx, db, reactionID, 1)
	if err != nil || allowed {
		t.Fatalf("in-flight policy allowed=%v, err=%v", allowed, err)
	}
	if err := ReleaseClaim(ctx, db, reactionID, 1, claims[0].PriorStatus, claims[0].PriorLastError); err != nil {
		t.Fatalf("release claim: %v", err)
	}
	var status string
	var lastError sql.NullString
	if err := db.QueryRow(`SELECT status, attempt, last_error FROM public.integration_event_reactions WHERE id = $1`, reactionID).Scan(&status, &attempt, &lastError); err != nil || status != "failed" || attempt != 0 || lastError.String != "prior transient error" {
		t.Fatalf("released reaction status=%q attempt=%d last_error=%q err=%v", status, attempt, lastError.String, err)
	}
	if _, err := ReplaceIntegrationReactorDispatchPolicy(ctx, db, instanceV1.Metadata.Namespace, instanceV1.Metadata.Name, []string{}, 3, actorID); err != nil {
		t.Fatalf("final resume: %v", err)
	}
	type claimResult struct {
		rows []model.IntegrationEventReaction
		err  error
	}
	results := make(chan claimResult, 2)
	start := make(chan struct{})
	var workers sync.WaitGroup
	for range 2 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			<-start
			rows, claimErr := ClaimPendingBatch(ctx, db, 1)
			results <- claimResult{rows: rows, err: claimErr}
		}()
	}
	close(start)
	workers.Wait()
	close(results)
	claimed := 0
	for result := range results {
		if result.err != nil {
			t.Fatalf("concurrent claim: %v", result.err)
		}
		for _, row := range result.rows {
			if row.ID != reactionID || row.Attempt != 1 {
				t.Fatalf("unexpected concurrent claim: %+v", row)
			}
			claimed++
		}
	}
	if claimed != 1 {
		t.Fatalf("concurrent claim count=%d, want 1", claimed)
	}
	// Simulate healing a worker that stopped responding, then reclaiming the
	// same row. The stale worker must not pass the pre-RPC gate or overwrite
	// the second attempt's outcome.
	if _, err := db.Exec(`UPDATE public.integration_event_reactions SET status='failed', next_attempt_at=NOW() WHERE id=$1`, reactionID); err != nil {
		t.Fatalf("simulate healed claim: %v", err)
	}
	reclaimed, err := ClaimPendingBatch(ctx, db, 1)
	if err != nil || len(reclaimed) != 1 || reclaimed[0].Attempt != 2 {
		t.Fatalf("reclaimed attempt=%+v err=%v", reclaimed, err)
	}
	if _, allowed, err := ReactionDispatchAllowed(ctx, db, reactionID, 1); err != nil || allowed {
		t.Fatalf("stale attempt allowed=%v err=%v", allowed, err)
	}
	if err := MarkSucceeded(ctx, db, reactionID, 1); err == nil {
		t.Fatal("stale worker overwrote the active attempt")
	}
	if err := MarkSucceeded(ctx, db, reactionID, 2); err != nil {
		t.Fatalf("finish reaction: %v", err)
	}
	if err := ReleaseClaim(ctx, db, reactionID, 1, model.ReactionStatusPending, ""); err == nil {
		t.Fatal("stale release unexpectedly matched terminal outcome")
	}
	if err := db.QueryRow(`SELECT status FROM public.integration_event_reactions WHERE id = $1`, reactionID).Scan(&status); err != nil || status != "succeeded" {
		t.Fatalf("stale release changed terminal outcome to %q, err=%v", status, err)
	}
}

func TestReactorPausePostgresRetentionGuards(t *testing.T) {
	db := openReactorPauseDB(t)
	ctx := context.Background()
	_, instanceV1 := seedReactorPauseManifests(t, db)
	eventID := emitReactorPauseTeamEvent(t, db, false)
	reactionID, _ := reactionForEvent(t, db, eventID)
	seedIdentityManifest(t, db, "integration_instance", instanceV1.Metadata.Namespace, instanceV1.Metadata.Name, true,
		map[string]any{"type_ref": map[string]string{"namespace": instanceV1.Metadata.Namespace, "name": "adapter"}})
	if _, err := db.Exec(`UPDATE public.event_log SET emitted_at = NOW() - INTERVAL '100 days' WHERE event_id = $1`, eventID); err != nil {
		t.Fatalf("age event: %v", err)
	}
	if _, err := CleanupExpiredEvents(ctx, db); err != nil {
		t.Fatalf("clean expired events: %v", err)
	}
	if _, err := PurgeInactiveManifestsOlderThan(ctx, db, time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("purge inactive manifests: %v", err)
	}
	var eventExists, manifestExists bool
	if err := db.QueryRow(`SELECT EXISTS(SELECT 1 FROM public.event_log WHERE event_id = $1)`, eventID).Scan(&eventExists); err != nil || !eventExists {
		t.Fatalf("pending event retained=%v, err=%v", eventExists, err)
	}
	if err := db.QueryRow(`SELECT EXISTS(SELECT 1 FROM public.manifests WHERE id = $1)`, instanceV1.ID).Scan(&manifestExists); err != nil || !manifestExists {
		t.Fatalf("pending instance version retained=%v, err=%v", manifestExists, err)
	}
	claims, err := ClaimPendingBatch(ctx, db, 1)
	if err != nil || len(claims) != 1 || claims[0].ID != reactionID {
		t.Fatalf("claim retained reaction=%+v err=%v", claims, err)
	}
	if err := MarkSucceeded(ctx, db, reactionID, claims[0].Attempt); err != nil {
		t.Fatalf("finish reaction: %v", err)
	}
	if _, err := CleanupExpiredEvents(ctx, db); err != nil {
		t.Fatalf("clean terminal event: %v", err)
	}
	if err := db.QueryRow(`SELECT EXISTS(SELECT 1 FROM public.event_log WHERE event_id = $1)`, eventID).Scan(&eventExists); err != nil || eventExists {
		t.Fatalf("terminal event retained=%v, err=%v", eventExists, err)
	}
}

func TestReactorPausePostgresBlocksTypeRefDrift(t *testing.T) {
	db := openReactorPauseDB(t)
	ctx := context.Background()
	typeV1, instanceV1 := seedReactorPauseManifests(t, db)
	eventID := emitReactorPauseTeamEvent(t, db, false)
	reactionID, _ := reactionForEvent(t, db, eventID)
	namespace := instanceV1.Metadata.Namespace

	// The same instance name can be re-applied with a different type. Its
	// historical A reaction must not invoke B's adapter or credentials.
	seedIdentityManifest(t, db, "integration_type", namespace, "other_adapter", true,
		map[string]any{"reactors": []map[string]string{{"event_type": "team.created", "capability": "on_team_created"}}})
	seedIdentityManifest(t, db, "integration_instance", namespace, instanceV1.Metadata.Name, true,
		map[string]any{"type_ref": map[string]string{"namespace": namespace, "name": "other_adapter"}})
	claims, err := ClaimPendingBatch(ctx, db, 1)
	if err != nil || len(claims) != 0 {
		t.Fatalf("cross-type claim=%+v err=%v", claims, err)
	}
	_, attempt := reactionForEvent(t, db, eventID)
	if attempt != 0 {
		t.Fatalf("cross-type mismatch consumed attempt=%d", attempt)
	}

	// Upgrading A's manifest version is safe: the reaction's type identity
	// matches even though its historical type UUID is no longer active.
	typeV2 := seedIdentityManifest(t, db, "integration_type", namespace, typeV1.Metadata.Name, true,
		map[string]any{"reactors": []map[string]string{{"event_type": "team.created", "capability": "on_team_created"}}})
	if typeV1.ID == typeV2.ID {
		t.Fatal("expected a new same-type manifest version")
	}
	instanceV3 := seedIdentityManifest(t, db, "integration_instance", namespace, instanceV1.Metadata.Name, true,
		map[string]any{"type_ref": map[string]string{"namespace": namespace, "name": typeV1.Metadata.Name}})
	claims, err = ClaimPendingBatch(ctx, db, 1)
	if err != nil || len(claims) != 1 || claims[0].ID != reactionID || claims[0].DispatchInstanceID != instanceV3.ID {
		t.Fatalf("same-type upgrade claim=%+v err=%v", claims, err)
	}

	// A type switch after claim is also blocked by the pre-RPC recheck.
	seedIdentityManifest(t, db, "integration_instance", namespace, instanceV1.Metadata.Name, true,
		map[string]any{"type_ref": map[string]string{"namespace": namespace, "name": "other_adapter"}})
	if _, allowed, err := ReactionDispatchAllowed(ctx, db, reactionID, claims[0].Attempt); err != nil || allowed {
		t.Fatalf("cross-type recheck allowed=%v err=%v", allowed, err)
	}
	if err := ReleaseClaim(ctx, db, reactionID, claims[0].Attempt, claims[0].PriorStatus, claims[0].PriorLastError); err != nil {
		t.Fatalf("release cross-type claim: %v", err)
	}
	var status string
	if err := db.QueryRow(`SELECT status, attempt FROM public.integration_event_reactions WHERE id=$1`, reactionID).Scan(&status, &attempt); err != nil || status != "pending" || attempt != 0 {
		t.Fatalf("cross-type backlog status=%q attempt=%d err=%v", status, attempt, err)
	}
}
