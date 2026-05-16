package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

var ErrReactionNotFound = errors.New("integration event reaction not found")

// MaterializeReactions runs inside the same transaction as EmitEvent and
// inserts one integration_event_reactions row per matching (integration_instance,
// reactor declaration). Caller guarantees tx is already inside a tx where the
// event_log row was just inserted with the same event_id.
//
// Non-canon events (e.g., reactor.dead_lettered, manifest.created) are a no-op.
func MaterializeReactions(ctx context.Context, tx *sql.Tx, eventID uuid.UUID, eventType string) error {
	if !IsCanonLifecycleEvent(eventType) {
		return nil
	}
	_, err := tx.ExecContext(ctx, `
		INSERT INTO integration_event_reactions
			(event_id, event_type, integration_instance_id, integration_type_manifest_id, capability, status, next_attempt_at)
		SELECT $1, $2, ii.id, it.id, r->>'capability', 'pending', NOW()
		FROM manifests ii
		JOIN manifests it ON it.kind = 'integration_type'
		                  AND it.namespace = (ii.spec->'type_ref'->>'namespace')
		                  AND it.name = (ii.spec->'type_ref'->>'name')
		                  AND it.active = true
		JOIN LATERAL jsonb_array_elements(COALESCE(it.spec->'reactors', '[]'::jsonb)) r ON r->>'event_type' = $2
		WHERE ii.kind = 'integration_instance'
		  AND ii.active = true
	`, eventID, eventType)
	if err != nil {
		return fmt.Errorf("materialize reactions: %w", err)
	}
	return nil
}

// ClaimPendingBatch atomically claims up to `limit` pending/failed rows
// whose next_attempt_at <= NOW(), marks them in_progress with attempt+1 and
// started_at=NOW(). Uses FOR UPDATE SKIP LOCKED for multi-pod safety.
func ClaimPendingBatch(ctx context.Context, db *sql.DB, limit int) ([]model.IntegrationEventReaction, error) {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin: %w", err)
	}
	defer tx.Rollback()

	rows, err := tx.QueryContext(ctx, `
		SELECT id, event_id, event_type, integration_instance_id, integration_type_manifest_id, capability, attempt
		FROM integration_event_reactions
		WHERE status IN ('pending','failed') AND next_attempt_at <= NOW()
		ORDER BY next_attempt_at ASC
		LIMIT $1
		FOR UPDATE SKIP LOCKED
	`, limit)
	if err != nil {
		return nil, fmt.Errorf("select: %w", err)
	}

	type claim struct {
		ID                        uuid.UUID
		EventID                   uuid.UUID
		EventType                 string
		IntegrationInstanceID     uuid.UUID
		IntegrationTypeManifestID uuid.UUID
		Capability                string
		Attempt                   int
	}
	var claims []claim
	for rows.Next() {
		var c claim
		if err := rows.Scan(&c.ID, &c.EventID, &c.EventType, &c.IntegrationInstanceID, &c.IntegrationTypeManifestID, &c.Capability, &c.Attempt); err != nil {
			rows.Close()
			return nil, fmt.Errorf("scan: %w", err)
		}
		claims = append(claims, c)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate: %w", err)
	}

	now := time.Now()
	out := make([]model.IntegrationEventReaction, 0, len(claims))
	for _, c := range claims {
		newAttempt := c.Attempt + 1
		if _, err := tx.ExecContext(ctx, `
			UPDATE integration_event_reactions
			SET status='in_progress', attempt=$2, started_at=$3, last_error=NULL
			WHERE id=$1
		`, c.ID, newAttempt, now); err != nil {
			return nil, fmt.Errorf("update claim %s: %w", c.ID, err)
		}
		started := now
		out = append(out, model.IntegrationEventReaction{
			ID:                        c.ID,
			EventID:                   c.EventID,
			EventType:                 c.EventType,
			IntegrationInstanceID:     c.IntegrationInstanceID,
			IntegrationTypeManifestID: c.IntegrationTypeManifestID,
			Capability:                c.Capability,
			Status:                    model.ReactionStatusInProgress,
			Attempt:                   newAttempt,
			StartedAt:                 &started,
		})
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit: %w", err)
	}
	return out, nil
}

// MarkSucceeded transitions a row in_progress → succeeded.
func MarkSucceeded(ctx context.Context, db *sql.DB, reactionID uuid.UUID) error {
	_, err := db.ExecContext(ctx, `
		UPDATE integration_event_reactions
		SET status='succeeded', finished_at=NOW(), last_error=NULL
		WHERE id=$1
	`, reactionID)
	if err != nil {
		return fmt.Errorf("mark succeeded %s: %w", reactionID, err)
	}
	return nil
}

// MarkFailed transitions in_progress → failed and schedules next_attempt_at.
func MarkFailed(ctx context.Context, db *sql.DB, reactionID uuid.UUID, errMsg string, backoff time.Duration) error {
	if len(errMsg) > 4096 {
		errMsg = errMsg[:4096]
	}
	_, err := db.ExecContext(ctx, `
		UPDATE integration_event_reactions
		SET status='failed', next_attempt_at=NOW()+$3::interval, last_error=$2
		WHERE id=$1
	`, reactionID, errMsg, backoff.String())
	if err != nil {
		return fmt.Errorf("mark failed %s: %w", reactionID, err)
	}
	return nil
}

// MarkDeadLettered transitions in_progress → dead_lettered (terminal).
func MarkDeadLettered(ctx context.Context, db *sql.DB, reactionID uuid.UUID, errMsg string) error {
	if len(errMsg) > 4096 {
		errMsg = errMsg[:4096]
	}
	_, err := db.ExecContext(ctx, `
		UPDATE integration_event_reactions
		SET status='dead_lettered', finished_at=NOW(), last_error=$2
		WHERE id=$1
	`, reactionID, errMsg)
	if err != nil {
		return fmt.Errorf("mark dead_lettered %s: %w", reactionID, err)
	}
	return nil
}

// HealStuckInProgress marks rows stuck in 'in_progress' for longer than
// threshold as 'failed' with next_attempt_at=NOW() so the Runner re-claims them.
// Fixes pods that crashed mid-dispatch.
func HealStuckInProgress(ctx context.Context, db *sql.DB, threshold time.Duration) (int64, error) {
	res, err := db.ExecContext(ctx, `
		UPDATE integration_event_reactions
		SET status='failed', next_attempt_at=NOW(), last_error='healed from stuck in_progress'
		WHERE status='in_progress' AND started_at < NOW() - $1::interval
	`, threshold.String())
	if err != nil {
		return 0, fmt.Errorf("heal stuck: %w", err)
	}
	n, _ := res.RowsAffected()
	return n, nil
}

// FetchEventForReactor reads the event_log payload + emitted_at + actor used
// to build the reactor input payload.
func FetchEventForReactor(ctx context.Context, db *sql.DB, eventID uuid.UUID) (json.RawMessage, time.Time, *model.EventActor, error) {
	var raw []byte
	var emittedAt time.Time
	var actorType, actorID sql.NullString
	row := db.QueryRowContext(ctx, `
		SELECT payload, emitted_at, actor_type, actor_id
		FROM event_log
		WHERE event_id=$1
	`, eventID)
	if err := row.Scan(&raw, &emittedAt, &actorType, &actorID); err != nil {
		return nil, time.Time{}, nil, fmt.Errorf("fetch event %s: %w", eventID, err)
	}
	var actor *model.EventActor
	if actorType.Valid && actorID.Valid {
		actor = &model.EventActor{Type: actorType.String, ID: actorID.String}
	}
	return raw, emittedAt, actor, nil
}
