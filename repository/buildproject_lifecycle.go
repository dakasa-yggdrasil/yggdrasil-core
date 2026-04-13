package repository

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

// BuildProject lifecycle states. Transitions: active -> expiring -> deleted.
const (
	BuildProjectLifecycleActive   = "active"
	BuildProjectLifecycleExpiring = "expiring"
	BuildProjectLifecycleDeleted  = "deleted"
)

// FindExpiredBuildProjectCandidates returns ephemeral BuildProjects that are
// currently active and whose expires_at is in the past. The lifecycle
// enforcement loop uses this to find candidates for expiration.
//
// The query leverages the partial index topology_build_projects_expiring_idx
// (ephemeral = TRUE AND lifecycle_status = 'active') added in migration
// 00014 so this is efficient even with many BuildProjects.
func FindExpiredBuildProjectCandidates(ctx context.Context, db *sql.DB, limit int) ([]model.BuildProject, error) {
	if limit <= 0 {
		limit = 100
	}
	query := `
		SELECT
			id,
			infra_map_document_id,
			project_env_resource_id,
			build_name,
			env_type,
			cloud,
			ephemeral,
			expires_at,
			cluster_name,
			cluster_zone,
			immutable
		FROM public.topology_build_projects
		WHERE ephemeral = TRUE
		  AND lifecycle_status = 'active'
		  AND expires_at <> ''
		  AND expires_at::timestamptz < NOW()
		ORDER BY expires_at ASC
		LIMIT $1
	`
	rows, err := db.QueryContext(ctx, query, limit)
	if err != nil {
		return nil, fmt.Errorf("query expired candidates: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var builds []model.BuildProject
	for rows.Next() {
		build, err := scanBuildProject(rows)
		if err != nil {
			return nil, fmt.Errorf("scan candidate: %w", err)
		}
		build.LifecycleStatus = BuildProjectLifecycleActive
		builds = append(builds, build)
	}
	return builds, rows.Err()
}

// TransitionBuildProjectToExpiring atomically moves an active BuildProject to
// the expiring state. Uses WHERE conditions to ensure idempotency across
// multiple concurrent lifecycle enforcer workers: only one call per BP wins.
// Returns true if the transition happened, false if another worker already
// picked it up (affected = 0), and any error.
//
// The caller must pass the transaction so events can be emitted alongside
// the state transition.
func TransitionBuildProjectToExpiring(ctx context.Context, tx *sql.Tx, buildProjectID string) (bool, error) {
	result, err := tx.ExecContext(ctx, `
		UPDATE public.topology_build_projects
		SET lifecycle_status = 'expiring',
			expiring_started_at = NOW()
		WHERE id = $1
		  AND lifecycle_status = 'active'
		  AND ephemeral = TRUE
		  AND expires_at <> ''
		  AND expires_at::timestamptz < NOW()
	`, buildProjectID)
	if err != nil {
		return false, fmt.Errorf("update lifecycle_status to expiring: %w", err)
	}
	affected, _ := result.RowsAffected()
	return affected > 0, nil
}

// TransitionBuildProjectToDeleted marks an expiring BuildProject as soft-
// deleted. Called after the teardown workflow (if any) completed successfully,
// or directly if no teardown workflow was configured.
func TransitionBuildProjectToDeleted(ctx context.Context, tx *sql.Tx, buildProjectID string) (bool, error) {
	result, err := tx.ExecContext(ctx, `
		UPDATE public.topology_build_projects
		SET lifecycle_status = 'deleted',
			deleted_at = NOW()
		WHERE id = $1
		  AND lifecycle_status = 'expiring'
	`, buildProjectID)
	if err != nil {
		return false, fmt.Errorf("update lifecycle_status to deleted: %w", err)
	}
	affected, _ := result.RowsAffected()
	return affected > 0, nil
}

// ExtendBuildProjectExpiry updates the ExpiresAt of an active BuildProject.
// Used by activity-aware auto-extend flows (e.g., a PR env getting extended
// on each commit push). Only operates on active projects.
func ExtendBuildProjectExpiry(ctx context.Context, db *sql.DB, buildProjectID string, newExpiresAt time.Time) error {
	result, err := db.ExecContext(ctx, `
		UPDATE public.topology_build_projects
		SET expires_at = $2,
			extended_at = NOW()
		WHERE id = $1
		  AND lifecycle_status = 'active'
	`, buildProjectID, newExpiresAt.UTC().Format(time.RFC3339))
	if err != nil {
		return fmt.Errorf("extend expiry: %w", err)
	}
	affected, _ := result.RowsAffected()
	if affected == 0 {
		return fmt.Errorf("build_project not found or not active: %s", buildProjectID)
	}
	return nil
}

// ExpireBuildProjectNow forces an active BuildProject into the expiring state
// immediately, regardless of its expires_at. Useful for "delete this env now"
// UX without waiting for the natural expiration.
func ExpireBuildProjectNow(ctx context.Context, tx *sql.Tx, buildProjectID string) (bool, error) {
	result, err := tx.ExecContext(ctx, `
		UPDATE public.topology_build_projects
		SET lifecycle_status = 'expiring',
			expiring_started_at = NOW()
		WHERE id = $1
		  AND lifecycle_status = 'active'
	`, buildProjectID)
	if err != nil {
		return false, fmt.Errorf("expire_now: %w", err)
	}
	affected, _ := result.RowsAffected()
	return affected > 0, nil
}

// HardDeleteBuildProjectsOlderThan removes BuildProjects that have been in the
// deleted state longer than the given cutoff. Frees database storage after
// the configured retention period has passed.
func HardDeleteBuildProjectsOlderThan(ctx context.Context, db *sql.DB, cutoff time.Time) (int64, error) {
	result, err := db.ExecContext(ctx, `
		DELETE FROM public.topology_build_projects
		WHERE lifecycle_status = 'deleted'
		  AND deleted_at IS NOT NULL
		  AND deleted_at < $1
	`, cutoff)
	if err != nil {
		return 0, fmt.Errorf("hard delete expired build_projects: %w", err)
	}
	affected, _ := result.RowsAffected()
	return affected, nil
}
