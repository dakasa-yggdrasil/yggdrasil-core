package teamreconcile

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	"go.uber.org/zap"
)

// Runner sweeps team_provisioning_log gaps and re-emits team.created
// for each (team, integration_instance) pair that hasn't been mirrored.
// Adapter idempotency makes the re-emit safe — adapters that already
// have a row in team_provisioning_log will receive the reaction and
// respond with their no-op idempotent path.
//
// Kill switch: TEAM_RECONCILE_ENABLED=false skips the loop entirely.
type Runner struct {
	DB       *sql.DB
	Interval time.Duration
	Logger   *zap.Logger
}

const defaultInterval = 5 * time.Minute

// Run blocks until ctx is canceled.
func (r *Runner) Run(ctx context.Context) error {
	if os.Getenv("TEAM_RECONCILE_ENABLED") == "false" {
		<-ctx.Done()
		return ctx.Err()
	}
	interval := r.Interval
	if interval == 0 {
		interval = defaultInterval
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		if err := r.tick(ctx); err != nil && r.Logger != nil {
			r.Logger.Warn("team reconcile tick failed", zap.Error(err))
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
		}
	}
}

// tick is a single sweep — visible so tests can drive it directly.
func (r *Runner) tick(ctx context.Context) error {
	pairs, err := ListUnprovisionedPairs(ctx, r.DB)
	if err != nil {
		return fmt.Errorf("list unprovisioned: %w", err)
	}
	if len(pairs) == 0 {
		return nil
	}

	// Group by team so we emit one event per team (MaterializeReactions
	// fans out to every matching integration_instance automatically; we
	// don't need to emit per-instance).
	seen := map[string]struct{}{}
	for _, p := range pairs {
		if _, ok := seen[p.TeamID.String()]; ok {
			continue
		}
		seen[p.TeamID.String()] = struct{}{}
		if err := r.reEmit(ctx, p.TeamID.String()); err != nil && r.Logger != nil {
			r.Logger.Warn("reEmit team.created failed", zap.String("team_id", p.TeamID.String()), zap.Error(err))
		}
	}
	return nil
}

// reEmit looks up the team and emits a team.created canon event.
// Uses repository.GetTeam which filters by status='active' internally.
func (r *Runner) reEmit(ctx context.Context, teamID string) error {
	team, err := repository.GetTeam(ctx, r.DB, teamID)
	if err != nil {
		return fmt.Errorf("get team: %w", err)
	}

	tx, err := r.DB.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	payload := map[string]any{
		"id":   team.ID.String(),
		"slug": team.Slug,
		"name": team.Name,
		"type": team.Type,
	}
	if team.ParentTeamID != nil {
		payload["parent_team_id"] = team.ParentTeamID.String()
	}

	if _, err := repository.EmitEvent(ctx, tx, model.EmitEventRequest{
		Type:          repository.EventTypeTeamCreated,
		SchemaVersion: "v1",
		AggregateType: "team",
		AggregateID:   team.ID.String(),
		Payload:       payload,
		Actor: &model.EventActor{
			Type: model.ActorTypeSystem,
			ID:   "team_reconcile_addon",
		},
	}); err != nil {
		return fmt.Errorf("emit: %w", err)
	}
	return tx.Commit()
}
