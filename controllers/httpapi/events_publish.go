package httpapi

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
)

// eventPublishRequest is the wire shape accepted by POST /api/v1/events.
// Mirrors model.EmitEventRequest with json-tagged fields and a json.RawMessage
// payload so we can validate "is the payload an object" before unmarshaling
// into the typed map[string]interface{} that EmitEvent expects.
type eventPublishRequest struct {
	Type          string             `json:"type"`
	SchemaVersion string             `json:"schema_version,omitempty"`
	AggregateType string             `json:"aggregate_type"`
	AggregateID   string             `json:"aggregate_id"`
	Payload       json.RawMessage    `json:"payload"`
	Actor         *model.EventActor  `json:"actor,omitempty"`
	Metadata      map[string]any     `json:"metadata,omitempty"`
}

// handleEventPublish is the public publish endpoint reactive sources call to
// drop a typed event into the event_log. The trigger loop in
// addons/workflow_event_triggers picks them up and dispatches workflows
// configured with trigger.mode=event.
//
// Auth: deferred to authorizeWorkflowRunRequest, the same env-token guard
// that protects POST /api/v1/workflow-runs. POST /api/v1/manifests today
// has no in-handler auth — but reusing the manifest pattern verbatim would
// leave the endpoint open, and the spec asks for a 401 path. Borrowing the
// existing workflow-runs helper means no new auth scheme is invented; the
// same YGGDRASIL_WORKFLOW_RUN_TOKEN env var gates both. When the env var is
// unset (dev / tests without configured auth) the endpoint is open, exactly
// like /api/v1/workflow-runs.
//
// Validation: type, aggregate_type, aggregate_id all non-empty; payload
// MUST be a JSON object (so workflows can reference {{ inputs.event.foo }});
// schema_version defaults to "v1". Each constraint returns 400 with a
// field-named error message.
//
// Persistence mirrors handleManifestCreateGeneric: open a *sql.Tx on s.db,
// run repository.EmitEvent inside it, commit. On any error map via
// writeMappedError so the same status-code logic applies.
func (s *Server) handleEventPublish(w http.ResponseWriter, r *http.Request) {
	if err := authorizeWorkflowRunRequest(r); err != nil {
		writeMappedError(w, err)
		return
	}

	var payload eventPublishRequest
	if err := decodeJSON(r, &payload); err != nil {
		writeMappedError(w, err)
		return
	}

	emitReq, err := buildEmitEventRequestFromPublish(payload)
	if err != nil {
		writeMappedError(w, err)
		return
	}

	tx, err := s.db.BeginTx(r.Context(), nil)
	if err != nil {
		writeMappedError(w, fmt.Errorf("begin tx: %w", err))
		return
	}
	defer func() { _ = tx.Rollback() }()

	eventID, err := repository.EmitEvent(r.Context(), tx, emitReq)
	if err != nil {
		writeMappedError(w, err)
		return
	}

	if err := tx.Commit(); err != nil {
		writeMappedError(w, fmt.Errorf("commit tx: %w", err))
		return
	}

	writeJSON(w, http.StatusCreated, map[string]any{
		"event_id": eventID.String(),
	})
}

// buildEmitEventRequestFromPublish translates the wire shape into the
// repository.EmitEvent request, applying field-level validation up front so
// callers get clear 400s instead of the looser sql/contracts errors.
func buildEmitEventRequestFromPublish(req eventPublishRequest) (model.EmitEventRequest, error) {
	if strings.TrimSpace(req.Type) == "" {
		return model.EmitEventRequest{}, fmt.Errorf("type is required")
	}
	if strings.TrimSpace(req.AggregateType) == "" {
		return model.EmitEventRequest{}, fmt.Errorf("aggregate_type is required")
	}
	if strings.TrimSpace(req.AggregateID) == "" {
		return model.EmitEventRequest{}, fmt.Errorf("aggregate_id is required")
	}
	if len(req.Payload) == 0 {
		return model.EmitEventRequest{}, fmt.Errorf("payload is required")
	}

	// Reject non-object payloads up front. Leaving this to EmitEvent would
	// surface as a contracts validation error — fine, but the field name
	// gets buried. The reactive workflow story also depends on payload
	// being addressable as {{ inputs.event.foo }}, which only works for
	// objects.
	var payloadMap map[string]interface{}
	if err := json.Unmarshal(req.Payload, &payloadMap); err != nil {
		return model.EmitEventRequest{}, fmt.Errorf("payload must be a JSON object: %w", err)
	}
	if payloadMap == nil {
		return model.EmitEventRequest{}, fmt.Errorf("payload must be a JSON object, got null")
	}

	schemaVersion := strings.TrimSpace(req.SchemaVersion)
	if schemaVersion == "" {
		schemaVersion = "v1"
	}

	return model.EmitEventRequest{
		Type:          strings.TrimSpace(req.Type),
		SchemaVersion: schemaVersion,
		AggregateType: strings.TrimSpace(req.AggregateType),
		AggregateID:   strings.TrimSpace(req.AggregateID),
		Actor:         req.Actor,
		Payload:       payloadMap,
		Metadata:      req.Metadata,
	}, nil
}
