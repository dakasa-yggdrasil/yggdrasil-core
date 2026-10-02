package reactors

import (
	"context"
	"database/sql"
	"os"
	"testing"

	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	"github.com/google/uuid"
	_ "github.com/lib/pq"
)

type pauseCaptureCaller struct {
	instanceIDs []string
}

func (c *pauseCaptureCaller) Call(_ context.Context, instanceID, _ string, _ []byte) error {
	c.instanceIDs = append(c.instanceIDs, instanceID)
	return nil
}

func openDispatcherPauseDB(t *testing.T) *sql.DB {
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

func TestReactorPauseDispatcherUsesActiveInstanceAndReleasesRepausedClaim(t *testing.T) {
	db := openDispatcherPauseDB(t)
	ctx := context.Background()
	namespace := "pause-dispatch-" + uuid.NewString()[:8]
	typeID, oldID, activeID := uuid.New(), uuid.New(), uuid.New()
	t.Cleanup(func() {
		_, _ = db.Exec(`DELETE FROM public.event_log WHERE aggregate_type = 'reactor_pause_ci' AND aggregate_id = $1`, namespace)
		_, _ = db.Exec(`DELETE FROM public.integration_reactor_dispatch_policies WHERE namespace = $1`, namespace)
		_, _ = db.Exec(`DELETE FROM public.manifests WHERE namespace = $1`, namespace)
	})
	for _, row := range []struct {
		id      uuid.UUID
		kind    string
		name    string
		version int
		active  bool
		spec    string
	}{
		{typeID, "integration_type", "adapter", 1, true, `{"reactors":[{"event_type":"team.created","capability":"on_team_created"}]}`},
		{oldID, "integration_instance", "instance", 1, false, `{"type_ref":{"namespace":"` + namespace + `","name":"adapter"}}`},
		{activeID, "integration_instance", "instance", 2, true, `{"type_ref":{"namespace":"` + namespace + `","name":"adapter"}}`},
	} {
		if _, err := db.Exec(`
			INSERT INTO public.manifests (id, api_version, kind, namespace, name, version, active, spec, checksum)
			VALUES ($1, 'yggdrasil.io/v1', $2, $3, $4, $5, $6, $7::jsonb, 'sha256:reactor-pause-ci')
		`, row.id, row.kind, namespace, row.name, row.version, row.active, row.spec); err != nil {
			t.Fatalf("seed manifest: %v", err)
		}
	}
	seedReaction := func() uuid.UUID {
		t.Helper()
		eventID := uuid.New()
		if _, err := db.Exec(`
			INSERT INTO public.event_log (event_id, type, aggregate_type, aggregate_id, payload)
			VALUES ($1, 'team.created', 'reactor_pause_ci', $2, '{"id":"team-ci"}'::jsonb)
		`, eventID, namespace); err != nil {
			t.Fatalf("seed event: %v", err)
		}
		var reactionID uuid.UUID
		if err := db.QueryRow(`
			INSERT INTO public.integration_event_reactions
			  (event_id, event_type, integration_instance_id, integration_type_manifest_id, capability,
			   status, next_attempt_at)
			VALUES ($1, 'team.created', $2, $3, 'on_team_created', 'pending', NOW())
			RETURNING id
		`, eventID, oldID, typeID).Scan(&reactionID); err != nil {
			t.Fatalf("seed reaction: %v", err)
		}
		return reactionID
	}
	caller := &pauseCaptureCaller{}
	runner := &Runner{DB: db, Caller: caller}
	firstID := seedReaction()
	first, err := runner.realClaim(ctx, 1)
	if err != nil || len(first) != 1 || first[0].ID != firstID {
		t.Fatalf("claim historical reaction=%+v err=%v", first, err)
	}
	runner.dispatchOne(ctx, first[0])
	if len(caller.instanceIDs) != 1 || caller.instanceIDs[0] != activeID.String() {
		t.Fatalf("adapter called with instances=%v, want active %s", caller.instanceIDs, activeID)
	}
	var status string
	if err := db.QueryRow(`SELECT status FROM public.integration_event_reactions WHERE id = $1`, firstID).Scan(&status); err != nil || status != "succeeded" {
		t.Fatalf("historical reaction status=%q err=%v", status, err)
	}

	secondID := seedReaction()
	second, err := runner.realClaim(ctx, 1)
	if err != nil || len(second) != 1 || second[0].ID != secondID {
		t.Fatalf("claim before pause=%+v err=%v", second, err)
	}
	if _, err := repository.ReplaceIntegrationReactorDispatchPolicy(ctx, db, namespace, "instance", []string{"team.created"}, 0, uuid.New()); err != nil {
		t.Fatalf("pause before dispatch: %v", err)
	}
	runner.dispatchOne(ctx, second[0])
	if len(caller.instanceIDs) != 1 {
		t.Fatalf("paused reaction called adapter: %v", caller.instanceIDs)
	}
	var attempt int
	if err := db.QueryRow(`SELECT status, attempt FROM public.integration_event_reactions WHERE id = $1`, secondID).Scan(&status, &attempt); err != nil || status != "pending" || attempt != 0 {
		t.Fatalf("repaused reaction status=%q attempt=%d err=%v", status, attempt, err)
	}
}
