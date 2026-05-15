package addons

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/auth/password"
	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/runtime"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

func init() {
	Register("password_rotation", bootstrapPasswordRotation, 65)
}

// bootstrapPasswordRotation starts the periodic worker that scans for
// collaborators whose passwords have expired and marks them must_change=true,
// emitting a credential.password_rotation_required event per collaborator.
//
// Controlled by:
//
//	AUTH_PASSWORD_ROTATION_CRON_INTERVAL — duration string (e.g. "1h", "30m").
//	  Defaults to 1 hour.
//
// Mirrors the pattern used by collaborator_status_clock and buildproject_lifecycle.
func bootstrapPasswordRotation(ctx context.Context, app *runtime.ServiceApp) error {
	db, ok := Postgres(app)
	if !ok {
		return nil
	}
	logger, _ := Logger(app)

	runner := &password.Runner{
		DB:       db,
		Interval: passwordRotationInterval(),
		Batch:    1000,
		Logger:   passwordRunnerLoggerAdapter{log: logger},
		EmitMark: func(ctx context.Context, id uuid.UUID) error {
			return emitPasswordRotationEvent(ctx, db, id)
		},
	}

	go func() {
		if err := runner.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
			if logger != nil {
				logger.Error("password rotation runner exited unexpectedly", zap.Error(err))
			}
		}
	}()

	return nil
}

// passwordRunnerLoggerAdapter adapts *zap.Logger to the password.Logger interface.
type passwordRunnerLoggerAdapter struct {
	log *zap.Logger
}

func (a passwordRunnerLoggerAdapter) Info(msg string, args ...any) {
	if a.log == nil {
		return
	}
	a.log.Sugar().Infow(msg, args...)
}

func (a passwordRunnerLoggerAdapter) Error(msg string, args ...any) {
	if a.log == nil {
		return
	}
	a.log.Sugar().Errorw(msg, args...)
}

// emitPasswordRotationEvent opens a transaction, fetches the collaborator's
// actual password_expires_at, and emits a credential.password_rotation_required
// event. If the emit fails the transaction rolls back so no partial event is
// recorded; the next runner pass will retry.
func emitPasswordRotationEvent(ctx context.Context, db *sql.DB, id uuid.UUID) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck

	ai, err := repository.GetPasswordCredentialState(ctx, tx, id)
	if err != nil {
		return fmt.Errorf("fetch credential state for %s: %w", id, err)
	}

	markedAt := time.Now().UTC()

	// expires_at: use the stored value when available; fall back to markedAt
	// so the payload schema requirement is always satisfied.
	expiresAt := markedAt
	if ai.PasswordExpiresAt != nil {
		expiresAt = ai.PasswordExpiresAt.UTC()
	}

	if _, err := repository.EmitEvent(ctx, tx, model.EmitEventRequest{
		Type:          repository.EventTypeCredentialPasswordRotationRequired,
		SchemaVersion: "v1",
		AggregateType: "collaborator",
		AggregateID:   id.String(),
		Actor: &model.EventActor{
			Type: "system",
			ID:   "password_rotation_runner",
		},
		Payload: map[string]any{
			"collaborator_id": id.String(),
			"marked_at":       markedAt.Format(time.RFC3339),
			"expires_at":      expiresAt.Format(time.RFC3339),
		},
	}); err != nil {
		return fmt.Errorf("emit event for %s: %w", id, err)
	}

	return tx.Commit()
}

// passwordRotationInterval returns the runner cadence.
// AUTH_PASSWORD_ROTATION_CRON_INTERVAL accepts any Go duration string (e.g. "30m", "2h").
// Falls back to 1 hour when the env var is absent or invalid.
func passwordRotationInterval() time.Duration {
	raw := os.Getenv("AUTH_PASSWORD_ROTATION_CRON_INTERVAL")
	if raw == "" {
		return time.Hour
	}
	d, err := time.ParseDuration(raw)
	if err != nil || d <= 0 {
		return time.Hour
	}
	return d
}
