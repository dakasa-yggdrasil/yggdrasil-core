package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/dakasa-yggdrasil/yggdrasil-core/docs/contracts"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

// EmitEvent inserts an event into event_log within a caller-provided transaction.
// MUST be called from inside an active *sql.Tx to guarantee atomicity with the
// state mutation that generated the event. If the transaction rolls back, the
// event is not persisted.
//
// Validates the payload against the JSON Schema for the event type before insert.
// Returns the generated UUID v7 event_id on success.
func EmitEvent(ctx context.Context, tx *sql.Tx, req model.EmitEventRequest) (uuid.UUID, error) {
	if tx == nil {
		return uuid.Nil, fmt.Errorf("EmitEvent requires a non-nil transaction")
	}

	req.Type = strings.TrimSpace(req.Type)
	if req.Type == "" {
		return uuid.Nil, fmt.Errorf("event type is required")
	}
	if req.SchemaVersion == "" {
		req.SchemaVersion = "v1"
	}
	req.AggregateType = strings.TrimSpace(req.AggregateType)
	if req.AggregateType == "" {
		return uuid.Nil, fmt.Errorf("aggregate_type is required")
	}
	req.AggregateID = strings.TrimSpace(req.AggregateID)
	if req.AggregateID == "" {
		return uuid.Nil, fmt.Errorf("aggregate_id is required")
	}
	if req.Payload == nil {
		return uuid.Nil, fmt.Errorf("payload is required")
	}

	if err := contracts.ValidateEventPayload(req.Type, req.SchemaVersion, req.Payload); err != nil {
		return uuid.Nil, err
	}

	eventID, err := uuid.NewV7()
	if err != nil {
		return uuid.Nil, fmt.Errorf("generate event_id: %w", err)
	}

	payloadJSON, err := json.Marshal(req.Payload)
	if err != nil {
		return uuid.Nil, fmt.Errorf("marshal payload: %w", err)
	}

	var metadataJSON []byte
	if req.Metadata != nil {
		metadataJSON, err = json.Marshal(req.Metadata)
		if err != nil {
			return uuid.Nil, fmt.Errorf("marshal metadata: %w", err)
		}
	}

	var actorType, actorID sql.NullString
	var actorContextJSON []byte
	if req.Actor != nil {
		actorType = sql.NullString{String: req.Actor.Type, Valid: req.Actor.Type != ""}
		actorID = sql.NullString{String: req.Actor.ID, Valid: req.Actor.ID != ""}
		if req.Actor.Context != nil {
			actorContextJSON, err = json.Marshal(req.Actor.Context)
			if err != nil {
				return uuid.Nil, fmt.Errorf("marshal actor context: %w", err)
			}
		}
	}

	_, err = tx.ExecContext(ctx, `
		INSERT INTO public.event_log (
			event_id, type, schema_version, aggregate_type, aggregate_id,
			actor_type, actor_id, actor_context, payload, metadata
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10
		)
	`, eventID, req.Type, req.SchemaVersion, req.AggregateType, req.AggregateID,
		actorType, actorID, nullableJSON(actorContextJSON), payloadJSON, nullableJSON(metadataJSON))
	if err != nil {
		return uuid.Nil, fmt.Errorf("insert event_log: %w", err)
	}

	return eventID, nil
}

// PullEvents returns a batch of events starting from the given cursor, respecting
// the provided filters and limit. The cursor is an opaque string that the caller
// obtained from a previous PullEvents call (or empty to start from the beginning).
//
// Limit is normalized to DefaultPullLimit (100) if <=0 and capped at MaxPullLimit (1000).
//
// Filters are AND-combined. `types` supports wildcards (e.g., "manifest.*").
// Per-aggregate ordering is guaranteed; cross-aggregate ordering is monotonic by sequence.
func PullEvents(ctx context.Context, db *sql.DB, req model.PullEventsRequest) (model.PullEventsResponse, error) {
	cursorSeq, err := decodePullCursor(req.Cursor)
	if err != nil {
		return model.PullEventsResponse{}, fmt.Errorf("invalid cursor: %w", err)
	}

	limit := req.Limit
	if limit <= 0 {
		limit = model.DefaultPullLimit
	}
	if limit > model.MaxPullLimit {
		limit = model.MaxPullLimit
	}

	query, args := buildPullQuery(cursorSeq, req.Filters, limit+1)

	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return model.PullEventsResponse{}, fmt.Errorf("query event_log: %w", err)
	}
	defer rows.Close()

	events := make([]model.Event, 0, limit)
	for rows.Next() {
		var (
			ev                 model.Event
			actorType, actorID sql.NullString
			actorContext       sql.NullString
			payloadRaw         []byte
			metadataRaw        []byte
		)
		if err := rows.Scan(
			&ev.EventID,
			&ev.Sequence,
			&ev.Type,
			&ev.SchemaVersion,
			&ev.AggregateType,
			&ev.AggregateID,
			&actorType,
			&actorID,
			&actorContext,
			&ev.EmittedAt,
			&payloadRaw,
			&metadataRaw,
		); err != nil {
			return model.PullEventsResponse{}, fmt.Errorf("scan event row: %w", err)
		}

		ev.Payload = json.RawMessage(payloadRaw)
		if len(metadataRaw) > 0 {
			ev.Metadata = json.RawMessage(metadataRaw)
		}
		if actorType.Valid || actorID.Valid || actorContext.Valid {
			actor := &model.EventActor{
				Type: actorType.String,
				ID:   actorID.String,
			}
			if actorContext.Valid && actorContext.String != "" {
				var ctxMap map[string]interface{}
				if err := json.Unmarshal([]byte(actorContext.String), &ctxMap); err == nil {
					actor.Context = ctxMap
				}
			}
			ev.Actor = actor
		}
		events = append(events, ev)
	}
	if err := rows.Err(); err != nil {
		return model.PullEventsResponse{}, fmt.Errorf("iterate event rows: %w", err)
	}

	hasMore := len(events) > limit
	if hasMore {
		events = events[:limit]
	}

	lastSeq := cursorSeq
	if len(events) > 0 {
		lastSeq = events[len(events)-1].Sequence
	}
	nextCursor := encodePullCursor(lastSeq)

	return model.PullEventsResponse{
		Events:     events,
		NextCursor: nextCursor,
		HasMore:    hasMore,
	}, nil
}

// buildPullQuery composes the SQL query for PullEvents based on filters.
// Returns the query and ordered arguments.
func buildPullQuery(cursorSeq int64, filters model.PullEventsFilters, limit int) (string, []interface{}) {
	var (
		conditions = []string{"sequence > $1"}
		args       = []interface{}{cursorSeq}
		idx        = 2
	)

	if len(filters.Types) > 0 {
		parts := make([]string, 0, len(filters.Types))
		for _, pattern := range filters.Types {
			pattern = strings.TrimSpace(pattern)
			if pattern == "" {
				continue
			}
			parts = append(parts, fmt.Sprintf("type LIKE $%d", idx))
			args = append(args, wildcardToLike(pattern))
			idx++
		}
		if len(parts) > 0 {
			conditions = append(conditions, "("+strings.Join(parts, " OR ")+")")
		}
	}

	if filters.AggregateType != "" {
		conditions = append(conditions, fmt.Sprintf("aggregate_type = $%d", idx))
		args = append(args, filters.AggregateType)
		idx++
	}

	if filters.AggregateID != "" {
		conditions = append(conditions, fmt.Sprintf("aggregate_id = $%d", idx))
		args = append(args, filters.AggregateID)
		idx++
	}

	if len(filters.SupportedSchemaVersions) > 0 {
		versionArgs := make([]string, 0, len(filters.SupportedSchemaVersions))
		for _, v := range filters.SupportedSchemaVersions {
			versionArgs = append(versionArgs, fmt.Sprintf("$%d", idx))
			args = append(args, v)
			idx++
		}
		conditions = append(conditions, "schema_version IN ("+strings.Join(versionArgs, ", ")+")")
	}

	if filters.EmittedAfter != nil {
		conditions = append(conditions, fmt.Sprintf("emitted_at > $%d", idx))
		args = append(args, *filters.EmittedAfter)
		idx++
	}

	args = append(args, limit)
	query := `
		SELECT
			event_id, sequence, type, schema_version,
			aggregate_type, aggregate_id,
			actor_type, actor_id, actor_context::text,
			emitted_at, payload::text, metadata::text
		FROM public.event_log
		WHERE ` + strings.Join(conditions, " AND ") + `
		ORDER BY sequence ASC
		LIMIT $` + fmt.Sprintf("%d", idx)

	return query, args
}

// CleanupExpiredEvents deletes events older than their type-specific retention TTL.
// Iterates over event_retention_policy and runs a DELETE per active pattern.
// Patterns with ttl_days = 0 are skipped (infinite retention).
// Safe to call periodically; idempotent.
func CleanupExpiredEvents(ctx context.Context, db *sql.DB) (int64, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT type_pattern, ttl_days
		FROM public.event_retention_policy
		WHERE ttl_days > 0
	`)
	if err != nil {
		return 0, fmt.Errorf("load retention policies: %w", err)
	}

	type policy struct {
		pattern string
		days    int
	}
	var policies []policy
	for rows.Next() {
		var p policy
		if err := rows.Scan(&p.pattern, &p.days); err != nil {
			rows.Close()
			return 0, fmt.Errorf("scan retention policy: %w", err)
		}
		policies = append(policies, p)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return 0, fmt.Errorf("iterate retention policies: %w", err)
	}
	rows.Close()

	var totalDeleted int64
	for _, p := range policies {
		sqlPattern := wildcardToLike(p.pattern)
		result, err := db.ExecContext(ctx, `
			DELETE FROM public.event_log
			WHERE type LIKE $1
			  AND emitted_at < NOW() - ($2::text || ' days')::interval
		`, sqlPattern, fmt.Sprintf("%d", p.days))
		if err != nil {
			return totalDeleted, fmt.Errorf("delete events for pattern %q: %w", p.pattern, err)
		}
		deleted, _ := result.RowsAffected()
		totalDeleted += deleted
	}

	return totalDeleted, nil
}

// ListRetentionPolicies returns all configured retention policies ordered by pattern.
func ListRetentionPolicies(ctx context.Context, db *sql.DB) ([]model.EventRetentionPolicy, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT type_pattern, ttl_days, created_at, updated_at
		FROM public.event_retention_policy
		ORDER BY type_pattern
	`)
	if err != nil {
		return nil, fmt.Errorf("query retention policies: %w", err)
	}
	defer rows.Close()

	var policies []model.EventRetentionPolicy
	for rows.Next() {
		var p model.EventRetentionPolicy
		if err := rows.Scan(&p.TypePattern, &p.TTLDays, &p.CreatedAt, &p.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan policy: %w", err)
		}
		policies = append(policies, p)
	}
	return policies, rows.Err()
}

// wildcardToLike converts a pattern like "manifest.*" or "workflow.run.*" into
// a SQL LIKE pattern.
func wildcardToLike(pattern string) string {
	return strings.ReplaceAll(pattern, "*", "%")
}

// encodePullCursor turns a sequence number into an opaque cursor string.
func encodePullCursor(seq int64) string {
	return fmt.Sprintf("seq:%d", seq)
}

// decodePullCursor extracts the sequence number from an opaque cursor string.
// Empty cursor returns 0 (start from beginning).
func decodePullCursor(cursor string) (int64, error) {
	cursor = strings.TrimSpace(cursor)
	if cursor == "" {
		return 0, nil
	}
	const prefix = "seq:"
	if !strings.HasPrefix(cursor, prefix) {
		return 0, fmt.Errorf("cursor must start with %q", prefix)
	}
	var seq int64
	_, err := fmt.Sscanf(cursor[len(prefix):], "%d", &seq)
	if err != nil {
		return 0, fmt.Errorf("parse cursor sequence: %w", err)
	}
	if seq < 0 {
		return 0, fmt.Errorf("cursor sequence must be non-negative")
	}
	return seq, nil
}

// nullableJSON returns nil for empty JSON bytes so SQL NULL is inserted instead
// of empty string (which would fail JSONB parsing).
func nullableJSON(raw []byte) interface{} {
	if len(raw) == 0 {
		return nil
	}
	return raw
}
