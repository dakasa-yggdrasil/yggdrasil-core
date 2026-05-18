package teamreconcile

import (
	"context"
	"testing"
	"time"
)

func TestRunnerTickEmitsForGaps(t *testing.T) {
	db := openTestDB(t)
	t.Cleanup(func() { _ = db.Close() })

	teamID := seedTeam(t, db)
	_ = seedIntegrationInstanceWithTeamReactor(t, db)

	r := &Runner{DB: db}
	if err := r.tick(context.Background()); err != nil {
		t.Fatalf("tick: %v", err)
	}

	var count int
	if err := db.QueryRow(`
		SELECT COUNT(*) FROM event_log
		WHERE type = 'team.created' AND aggregate_id = $1
	`, teamID.String()).Scan(&count); err != nil {
		t.Fatalf("query event_log: %v", err)
	}
	if count != 1 {
		t.Fatalf("expected 1 team.created event after tick, got %d", count)
	}
	// cleanup event_log row
	t.Cleanup(func() {
		_, _ = db.Exec(`DELETE FROM event_log WHERE aggregate_type = 'team' AND aggregate_id = $1`, teamID.String())
	})
}

func TestRunnerTickIsNoOpWhenAllProvisioned(t *testing.T) {
	db := openTestDB(t)
	t.Cleanup(func() { _ = db.Close() })

	teamID := seedTeam(t, db)
	instance := seedIntegrationInstanceWithTeamReactor(t, db)
	if _, err := db.Exec(`
		INSERT INTO team_provisioning_log (team_id, integration_instance_id, external_id, last_event_type)
		VALUES ($1, $2, 'X', 'team.created')
	`, teamID, instance); err != nil {
		t.Fatalf("seed: %v", err)
	}
	t.Cleanup(func() {
		_, _ = db.Exec(`DELETE FROM team_provisioning_log WHERE team_id = $1`, teamID)
	})

	r := &Runner{DB: db}
	if err := r.tick(context.Background()); err != nil {
		t.Fatalf("tick: %v", err)
	}

	var count int
	_ = db.QueryRow(`SELECT COUNT(*) FROM event_log WHERE type = 'team.created' AND aggregate_id = $1`, teamID.String()).Scan(&count)
	if count != 0 {
		t.Fatalf("expected 0 events after tick (all provisioned), got %d", count)
	}
}

func TestRunnerRespectsKillSwitch(t *testing.T) {
	t.Setenv("TEAM_RECONCILE_ENABLED", "false")
	r := &Runner{DB: nil, Interval: time.Millisecond}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if err := r.Run(ctx); err != nil && err != context.DeadlineExceeded {
		t.Fatalf("Run returned unexpected error: %v", err)
	}
}
