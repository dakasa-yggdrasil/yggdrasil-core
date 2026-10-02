package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/metrics"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

var ErrReactionNotFound = errors.New("integration event reaction not found")

// MaterializeReactions runs inside the same transaction as EmitEvent and
// inserts one integration_event_reactions row per matching (integration_instance,
// reactor declaration). Caller guarantees tx is already inside a tx where the
// event_log row was just inserted with the same event_id.
//
// Materialisation triggers for:
//   - the closed canon lifecycle set (IsCanonLifecycleEvent), and
//   - the open-ended integration mutation set (IsIntegrationMutationEvent)
//     defined by INTEGRATION_CONTRACT §6.5 (<provider>.<resource>.<verb_past>).
//
// All other events (e.g. reactor.dead_lettered, manifest.created,
// integration_type.synced) are a no-op so we don't infinite-loop or
// fan-out to consumers that didn't ask for them.
//
// Returns the number of integration_event_reactions rows inserted (0 when
// the event type is skipped or no instances have a matching reactor).
//
// Metrics: bumps yggdrasil_reactor_evaluations_total{outcome=...} per call:
//   - "skipped" for events outside the materialisation set,
//   - "matched" by the rows-affected count (so a single canon event that
//     materialises N reactions across N integration_instances counts as N
//     matches — operators see the same fan-out the dispatcher will work),
//   - "error" when the INSERT itself fails.
func MaterializeReactions(ctx context.Context, tx *sql.Tx, eventID uuid.UUID, eventType string) (int64, error) {
	return materializeReactions(ctx, tx, eventID, eventType, false)
}

// materializeReactions keeps normal events durable during a pause for later
// replay. Only the team reconciler's synthetic re-emissions suppress paused
// targets; it will find their unresolved gaps after dispatch is resumed.
func materializeReactions(ctx context.Context, tx *sql.Tx, eventID uuid.UUID, eventType string, suppressPaused bool) (int64, error) {
	if !IsCanonLifecycleEvent(eventType) && !IsIntegrationMutationEvent(eventType) {
		metrics.IncReactorEvaluation(metrics.ReactorEvalSkipped)
		return 0, nil
	}
	res, err := tx.ExecContext(ctx, `
		INSERT INTO integration_event_reactions
			(event_id, event_type, integration_instance_id, integration_type_manifest_id, capability, status, next_attempt_at)
		SELECT $1, $2, ii.id, it.id, r->>'capability', 'pending', NOW()
		FROM manifests ii
		JOIN manifests it ON it.kind = 'integration_type'
		                  AND it.namespace = (ii.spec->'type_ref'->>'namespace')
		                  AND it.name = (ii.spec->'type_ref'->>'name')
		                  AND it.active = true
		JOIN LATERAL jsonb_array_elements(COALESCE(it.spec->'reactors', '[]'::jsonb)) r ON r->>'event_type' = $2
		LEFT JOIN public.integration_reactor_dispatch_policies p
		  ON p.namespace = ii.namespace AND p.name = ii.name
		WHERE ii.kind = 'integration_instance'
		  AND ii.active = true
		  AND (NOT $3 OR NOT ($2 = ANY(COALESCE(p.paused_event_types, ARRAY[]::text[]))))
	`, eventID, eventType, suppressPaused)
	if err != nil {
		metrics.IncReactorEvaluation(metrics.ReactorEvalError)
		return 0, fmt.Errorf("materialize reactions: %w", err)
	}
	// rows-affected is best-effort: not all drivers populate it.  We treat
	// a negative or zero count as "no fan-out" so the metric stays at 0
	// instead of spuriously incrementing.
	n, raErr := res.RowsAffected()
	if raErr != nil || n < 0 {
		n = 0
	}
	if n > 0 {
		metrics.AddReactorEvaluations(metrics.ReactorEvalMatched, uint64(n))
	}
	return n, nil
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
		SELECT r.id, r.event_id, r.event_type, r.integration_instance_id,
		       active_ii.id, r.integration_type_manifest_id, r.capability,
		       r.attempt, r.status, r.last_error
		FROM public.integration_event_reactions r
		JOIN public.manifests old_ii
		  ON old_ii.id = r.integration_instance_id
		 AND old_ii.kind = 'integration_instance'
		JOIN public.manifests active_ii
		  ON active_ii.kind = old_ii.kind
		 AND active_ii.namespace = old_ii.namespace
		 AND active_ii.name = old_ii.name
		 AND active_ii.active = TRUE
		LEFT JOIN public.integration_reactor_dispatch_policies p
		  ON p.namespace = active_ii.namespace AND p.name = active_ii.name
		WHERE r.status IN ('pending','failed') AND r.next_attempt_at <= NOW()
		  AND NOT (r.event_type = ANY(COALESCE(p.paused_event_types, ARRAY[]::text[])))
		ORDER BY r.next_attempt_at ASC
		LIMIT $1
		FOR UPDATE OF r SKIP LOCKED
	`, limit)
	if err != nil {
		return nil, fmt.Errorf("select: %w", err)
	}

	type claim struct {
		ID                        uuid.UUID
		EventID                   uuid.UUID
		EventType                 string
		IntegrationInstanceID     uuid.UUID
		DispatchInstanceID        uuid.UUID
		IntegrationTypeManifestID uuid.UUID
		Capability                string
		Attempt                   int
		PriorStatus               model.ReactionStatus
		PriorLastError            sql.NullString
	}
	var claims []claim
	for rows.Next() {
		var c claim
		if err := rows.Scan(&c.ID, &c.EventID, &c.EventType, &c.IntegrationInstanceID, &c.DispatchInstanceID, &c.IntegrationTypeManifestID, &c.Capability, &c.Attempt, &c.PriorStatus, &c.PriorLastError); err != nil {
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
			DispatchInstanceID:        c.DispatchInstanceID,
			PriorStatus:               c.PriorStatus,
			PriorLastError:            c.PriorLastError.String,
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

// ReleaseClaim returns a reaction blocked between claim and RPC to its prior
// attempt number. The compare-and-swap prevents a stale worker from changing
// a row that another worker has already healed or completed.
func ReleaseClaim(ctx context.Context, db *sql.DB, reactionID uuid.UUID, attempt int, priorStatus model.ReactionStatus, priorLastError string) error {
	if attempt < 1 || (priorStatus != model.ReactionStatusPending && priorStatus != model.ReactionStatusFailed) {
		return fmt.Errorf("release reaction claim %s: invalid prior state", reactionID)
	}
	lastError := sql.NullString{String: priorLastError, Valid: priorLastError != ""}
	result, err := db.ExecContext(ctx, `
		UPDATE public.integration_event_reactions
		SET status = $3, attempt = attempt - 1,
		    started_at = NULL, next_attempt_at = NOW(), last_error = $4
		WHERE id = $1 AND status = 'in_progress' AND attempt = $2
	`, reactionID, attempt, priorStatus, lastError)
	if err != nil {
		return fmt.Errorf("release reaction claim %s: %w", reactionID, err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("release reaction claim %s rows affected: %w", reactionID, err)
	}
	if rows != 1 {
		return fmt.Errorf("release reaction claim %s: claim no longer current", reactionID)
	}
	return nil
}

// PausedReactionBacklog reports the durable work currently held by an operator
// pause. The aggregate deliberately has no instance or payload labels, so the
// metric cannot expose personally identifying event data.
func PausedReactionBacklog(ctx context.Context, db *sql.DB) (int64, float64, error) {
	var count int64
	var oldestAgeSeconds float64
	err := db.QueryRowContext(ctx, `
		SELECT COUNT(*),
		       COALESCE(EXTRACT(EPOCH FROM (NOW() - MIN(r.created_at))), 0)::float8
		FROM public.integration_event_reactions r
		JOIN public.manifests old_ii
		  ON old_ii.id = r.integration_instance_id
		 AND old_ii.kind = 'integration_instance'
		JOIN public.manifests active_ii
		  ON active_ii.kind = old_ii.kind
		 AND active_ii.namespace = old_ii.namespace
		 AND active_ii.name = old_ii.name
		 AND active_ii.active = TRUE
		JOIN public.integration_reactor_dispatch_policies p
		  ON p.namespace = active_ii.namespace AND p.name = active_ii.name
		WHERE r.status IN ('pending', 'failed', 'in_progress')
		  AND r.event_type = ANY(p.paused_event_types)
	`).Scan(&count, &oldestAgeSeconds)
	if err != nil {
		return 0, 0, fmt.Errorf("paused reaction backlog: %w", err)
	}
	return count, oldestAgeSeconds, nil
}

// MarkSucceeded transitions a row in_progress → succeeded.
func MarkSucceeded(ctx context.Context, db *sql.DB, reactionID uuid.UUID, attempt int) error {
	result, err := db.ExecContext(ctx, `
		UPDATE integration_event_reactions
		SET status='succeeded', finished_at=NOW(), last_error=NULL
		WHERE id=$1 AND status='in_progress' AND attempt=$2
	`, reactionID, attempt)
	if err != nil {
		return fmt.Errorf("mark succeeded %s: %w", reactionID, err)
	}
	return requireReactionTransition(result, reactionID, "succeeded")
}

// MarkFailed transitions in_progress → failed and schedules next_attempt_at.
func MarkFailed(ctx context.Context, db *sql.DB, reactionID uuid.UUID, attempt int, errMsg string, backoff time.Duration) error {
	if len(errMsg) > 4096 {
		errMsg = errMsg[:4096]
	}
	result, err := db.ExecContext(ctx, `
		UPDATE integration_event_reactions
		SET status='failed', next_attempt_at=NOW()+$4::interval, last_error=$3
		WHERE id=$1 AND status='in_progress' AND attempt=$2
	`, reactionID, attempt, errMsg, backoff.String())
	if err != nil {
		return fmt.Errorf("mark failed %s: %w", reactionID, err)
	}
	return requireReactionTransition(result, reactionID, "failed")
}

// MarkDeadLettered transitions in_progress → dead_lettered (terminal).
func MarkDeadLettered(ctx context.Context, db *sql.DB, reactionID uuid.UUID, attempt int, errMsg string) error {
	if len(errMsg) > 4096 {
		errMsg = errMsg[:4096]
	}
	result, err := db.ExecContext(ctx, `
		UPDATE integration_event_reactions
		SET status='dead_lettered', finished_at=NOW(), last_error=$3
		WHERE id=$1 AND status='in_progress' AND attempt=$2
	`, reactionID, attempt, errMsg)
	if err != nil {
		return fmt.Errorf("mark dead_lettered %s: %w", reactionID, err)
	}
	return requireReactionTransition(result, reactionID, "dead_lettered")
}

func requireReactionTransition(result sql.Result, reactionID uuid.UUID, status string) error {
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("mark %s %s rows affected: %w", status, reactionID, err)
	}
	if rows != 1 {
		return fmt.Errorf("mark %s %s: claim no longer current", status, reactionID)
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
