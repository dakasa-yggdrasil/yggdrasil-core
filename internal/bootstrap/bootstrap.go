// Package bootstrap encapsulates the "fresh install" work that makes a new
// yggdrasil-core reachable for a human operator without tribal knowledge.
//
// Two capabilities live here:
//
//  1. Admin provisioning — create the first collaborator + password
//     credential so a human can actually log in. Gated by "no existing
//     collaborators" so running startup N times does not duplicate.
//
//  2. Manifest seeding — import the baseline integration_family,
//     integration_type, product, etc. manifests from a directory of JSON
//     files, skipping anything whose checksum already matches.
//
// The package is consumed from two places:
//
//   - The scripts/bootstrap command (operator runs it manually against
//     any environment).
//   - The addons/first_run startup hook (yggdrasil-core auto-runs it
//     on boot when env vars are present).
//
// Keeping the logic in one package is what guarantees a developer who
// iterates on the JSON seeds by hand sees the exact same persistence
// path that production runs, including the dedup-by-checksum rule.
package bootstrap

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
)

// Config is what the caller provides to Run.
type Config struct {
	// AdminUsername is the slug of the first collaborator (used as login
	// identifier). If empty, admin provisioning is skipped entirely —
	// manifest seeding still runs.
	AdminUsername string
	// AdminDisplayName is shown in the UI. Defaults to "Admin" when empty.
	AdminDisplayName string
	// AdminEmail is the primary email of the first collaborator. Can be
	// empty but typically improves notifications.
	AdminEmail string
	// AdminPassword is the password for the first collaborator. Must be
	// non-empty when AdminUsername is set.
	AdminPassword string
	// ManifestsPath is the directory scanned for *.json bootstrap
	// manifests (walked recursively). Empty disables manifest seeding.
	ManifestsPath string
}

// Result summarizes what Run did, letting callers log or assert a useful
// message without parsing stdout.
type Result struct {
	AdminCreated       bool
	AdminCollaborator  *model.Collaborator
	ManifestsValidated int
	ManifestsCreated   int
	ManifestsSkipped   int
}

// Run executes the configured bootstrap steps in a safe order: admin
// first (so the next steps have a subject to attribute to, if we ever
// start tracking actor), then manifest seeding. Each step is idempotent
// and the function is safe to call on every process start.
//
// Returns an error on the first failure; callers should treat bootstrap
// failures as fatal because the service will otherwise serve traffic in
// a partially-initialized state.
func Run(ctx context.Context, db *sql.DB, cfg Config) (Result, error) {
	var result Result

	// Always provision the canonical yggdrasil-self integration_type +
	// integration_instance. Without an instance at (global, yggdrasil-self)
	// every non-god team_grant resolves EMPTY, so a fresh install must have
	// it before any grant is issued. Idempotent (checksum-dedup), so it is
	// safe on every process start and independent of the admin/manifest
	// branches below.
	if err := ensureYggdrasilSelf(ctx, db); err != nil {
		return result, fmt.Errorf("ensure yggdrasil-self: %w", err)
	}

	if cfg.AdminUsername != "" {
		created, collab, err := ensureFirstAdmin(ctx, db, cfg)
		if err != nil {
			return result, fmt.Errorf("provision first admin: %w", err)
		}
		result.AdminCreated = created
		if created {
			c := collab
			result.AdminCollaborator = &c
		}
	}

	if cfg.ManifestsPath != "" {
		summary, err := importManifestsFromDir(ctx, db, cfg.ManifestsPath)
		if err != nil {
			return result, fmt.Errorf("seed manifests from %s: %w", cfg.ManifestsPath, err)
		}
		result.ManifestsValidated = summary.Validated
		result.ManifestsCreated = summary.Created
		result.ManifestsSkipped = summary.Skipped
	}

	return result, nil
}

// IsEmpty reports whether the database has no collaborators yet. Used by
// callers (notably the startup addon) to decide whether to run the
// first-admin branch. Extracted so tests can exercise the rule cheaply.
func IsEmpty(ctx context.Context, db *sql.DB) (bool, error) {
	existing, err := repository.ListCollaborators(ctx, db, model.ListCollaboratorsRequest{})
	if err != nil {
		return false, fmt.Errorf("list collaborators: %w", err)
	}
	return len(existing) == 0, nil
}

// ErrNoAdminPassword is returned when AdminUsername is set but
// AdminPassword is empty. Sentinel so callers can surface a clear
// configuration error without string matching.
var ErrNoAdminPassword = errors.New("bootstrap: admin password is required when admin username is set")
