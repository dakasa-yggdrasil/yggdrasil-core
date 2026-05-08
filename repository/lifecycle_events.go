package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

// ErrLifecycleEventInvalidActorType is returned when the actor_type is
// not in the canonical set. Callers translate this to HTTP 400.
var ErrLifecycleEventInvalidActorType = errors.New("invalid lifecycle_event actor_type")

var validActorTypes = map[string]struct{}{
	model.ActorTypeHuman:    {},
	model.ActorTypeWorkflow: {},
	model.ActorTypeCLI:      {},
	model.ActorTypeAPI:      {},
	model.ActorTypeSystem:   {},
}

// AppendLifecycleEvent inserts a new row in lifecycle_events. Append-
// only — there is no UpdateLifecycleEvent or DeleteLifecycleEvent in
// this package; corrections are new events.
func AppendLifecycleEvent(ctx context.Context, db *sql.DB, req model.AppendLifecycleEventRequest) (model.LifecycleEvent, error) {
	if req.CollaboratorID == uuid.Nil {
		return model.LifecycleEvent{}, fmt.Errorf("collaborator_id is required")
	}
	if strings.TrimSpace(req.EventType) == "" {
		return model.LifecycleEvent{}, fmt.Errorf("event_type is required")
	}
	if _, ok := validActorTypes[req.ActorType]; !ok {
		return model.LifecycleEvent{}, fmt.Errorf("%w: %q", ErrLifecycleEventInvalidActorType, req.ActorType)
	}

	payload, err := json.Marshal(req.Payload)
	if err != nil {
		return model.LifecycleEvent{}, fmt.Errorf("marshal payload: %w", err)
	}
	if len(req.Payload) == 0 {
		payload = []byte(`{}`)
	}

	row := db.QueryRowContext(ctx, `
		INSERT INTO public.lifecycle_events (
			collaborator_id, event_type, payload, actor_type, actor_id, effective_at
		) VALUES ($1, $2, $3, $4, $5, COALESCE($6, NOW()))
		RETURNING id, collaborator_id, event_type, payload, actor_type, actor_id, occurred_at, effective_at
	`, req.CollaboratorID, req.EventType, payload, req.ActorType, req.ActorID, req.EffectiveAt)

	return scanLifecycleEvent(row)
}

// ListLifecycleEventsByCollaborator returns events for a collaborator
// ordered by occurred_at DESC (most recent first). Limit defaults to 100.
func ListLifecycleEventsByCollaborator(ctx context.Context, db *sql.DB, req model.ListLifecycleEventsRequest) ([]model.LifecycleEvent, error) {
	if req.CollaboratorID == uuid.Nil {
		return nil, fmt.Errorf("collaborator_id is required")
	}
	limit := req.Limit
	if limit <= 0 {
		limit = 100
	}

	args := []any{req.CollaboratorID}
	q := `SELECT id, collaborator_id, event_type, payload, actor_type, actor_id, occurred_at, effective_at
		FROM public.lifecycle_events
		WHERE collaborator_id = $1`
	if et := strings.TrimSpace(req.EventType); et != "" {
		args = append(args, et)
		q += fmt.Sprintf(" AND event_type = $%d", len(args))
	}
	args = append(args, limit)
	q += fmt.Sprintf(" ORDER BY occurred_at DESC LIMIT $%d", len(args))

	rows, err := db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("query lifecycle_events: %w", err)
	}
	defer func() { _ = rows.Close() }()

	out := make([]model.LifecycleEvent, 0)
	for rows.Next() {
		event, err := scanLifecycleEvent(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, event)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate lifecycle_events: %w", err)
	}
	return out, nil
}

type lifecycleEventScanner interface {
	Scan(dest ...any) error
}

func scanLifecycleEvent(s lifecycleEventScanner) (model.LifecycleEvent, error) {
	var event model.LifecycleEvent
	var payload []byte
	if err := s.Scan(
		&event.ID,
		&event.CollaboratorID,
		&event.EventType,
		&payload,
		&event.ActorType,
		&event.ActorID,
		&event.OccurredAt,
		&event.EffectiveAt,
	); err != nil {
		return model.LifecycleEvent{}, fmt.Errorf("scan lifecycle_event: %w", err)
	}
	if len(payload) > 0 {
		if err := json.Unmarshal(payload, &event.Payload); err != nil {
			return model.LifecycleEvent{}, fmt.Errorf("unmarshal payload: %w", err)
		}
	} else {
		event.Payload = map[string]any{}
	}
	return event, nil
}
