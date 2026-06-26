package surface

import (
	"context"
	"database/sql"
	"fmt"

	"go.uber.org/zap"
)

// PermissionsReconciler implements PermissionReconciler by writing into
// public.permissions_catalog. The strategy is "delete-then-insert by
// registered_by" so permissions removed from the manifest disappear
// from the catalog automatically.
type PermissionsReconciler struct {
	db     *sql.DB
	logger *zap.Logger
}

func NewPermissionsReconciler(db *sql.DB, logger *zap.Logger) *PermissionsReconciler {
	if logger == nil {
		logger = zap.NewNop()
	}
	return &PermissionsReconciler{db: db, logger: logger}
}

func (r *PermissionsReconciler) Reconcile(ctx context.Context, surfaceID string, perms []SurfacePerm) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin perm tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(ctx,
		`DELETE FROM public.permissions_catalog WHERE registered_by = $1`,
		surfaceID,
	); err != nil {
		return fmt.Errorf("delete prev perms %s: %w", surfaceID, err)
	}
	for _, p := range perms {
		// Idempotent on (name) — mirrors repository.RegisterPermission. A
		// permission name is globally unique (permissions_catalog_name_unique),
		// so when the same name is already registered (e.g. by another surface
		// or a bootstrap path) a plain INSERT collides with 23505 and the whole
		// reconcile rolls back, failing every tick (~30s) forever. Last-writer-
		// wins: this surface takes ownership and refreshes the description.
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO public.permissions_catalog (name, description, registered_by) VALUES ($1, $2, $3)
			 ON CONFLICT (name) DO UPDATE SET
			     description   = EXCLUDED.description,
			     registered_by = EXCLUDED.registered_by,
			     updated_at    = NOW()`,
			p.ID, p.Label, surfaceID,
		); err != nil {
			return fmt.Errorf("insert perm %s: %w", p.ID, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit perm tx: %w", err)
	}
	return nil
}
