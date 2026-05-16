package reactors

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

// BuildReactorPayload merges the event payload with a `_context` block and
// returns the full JSON sent over RabbitMQ to the integration adapter.
//
// If the event payload already has a `_context` key it is overwritten — the
// `_` prefix is reserved for the core.
func BuildReactorPayload(
	eventID uuid.UUID,
	eventType string,
	schemaVersion string,
	eventPayload json.RawMessage,
	emittedAt time.Time,
	actor *model.EventActor,
	attempt int,
) ([]byte, error) {
	var merged map[string]any
	if len(eventPayload) > 0 {
		if err := json.Unmarshal(eventPayload, &merged); err != nil {
			return nil, fmt.Errorf("unmarshal event payload: %w", err)
		}
	}
	if merged == nil {
		merged = map[string]any{}
	}
	ctx := map[string]any{
		"event_id":       eventID.String(),
		"event_type":     eventType,
		"schema_version": schemaVersion,
		"emitted_at":     emittedAt.UTC().Format(time.RFC3339),
		"attempt":        attempt,
	}
	if actor != nil {
		ctx["actor"] = map[string]any{"type": actor.Type, "id": actor.ID}
	}
	merged["_context"] = ctx

	out, err := json.Marshal(merged)
	if err != nil {
		return nil, fmt.Errorf("marshal reactor payload: %w", err)
	}
	return out, nil
}
