package httpapi

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
)

// eventPublishRequest is the unified wire shape accepted by POST /api/v1/events.
//
// The endpoint supports two payload shapes on the same route, distinguished
// by the presence of `event_type`:
//
//  1. Generic events (existing): `type`, `schema_version`, `aggregate_type`,
//     `aggregate_id`, `payload` — used by `manifest.created` and similar
//     control-plane lifecycle events.
//
//  2. Integration mutation events (INTEGRATION_CONTRACT §6.5): `event_type`,
//     `provider`, `resource`, `verb`, `resource_id`, `instance_id`,
//     `idempotency`, `observed`, `emitted_at` — used by adapter pods after
//     every `ensure_*` / `destroy_*` (and money-movement `create_*`).
//
// The struct accepts the union of both — fields not present in JSON stay
// zero-valued so the dispatch logic can pick the right branch off the
// `event_type` field.
type eventPublishRequest struct {
	// Generic shape.
	Type          string            `json:"type"`
	SchemaVersion string            `json:"schema_version,omitempty"`
	AggregateType string            `json:"aggregate_type"`
	AggregateID   string            `json:"aggregate_id"`
	Payload       json.RawMessage   `json:"payload"`
	Actor         *model.EventActor `json:"actor,omitempty"`
	Metadata      map[string]any    `json:"metadata,omitempty"`

	// §6.5 mutation shape.
	EventType   string         `json:"event_type,omitempty"`
	Provider    string         `json:"provider,omitempty"`
	Resource    string         `json:"resource,omitempty"`
	Verb        string         `json:"verb,omitempty"`
	ResourceID  string         `json:"resource_id,omitempty"`
	InstanceID  string         `json:"instance_id,omitempty"`
	Idempotency string         `json:"idempotency,omitempty"`
	Observed    map[string]any `json:"observed,omitempty"`
	EmittedAt   string         `json:"emitted_at,omitempty"`
}

var errEventPublishAuthorizationDenied = errors.New("event publish authorization denied")

const (
	eventPublisherMachinePrincipalMetadataKey = "yggdrasil.io/publisher_machine_principal_id"
	legacyEventPublisherPrincipalID           = "legacy-event-publish-bridge"
)

type eventPublishActor struct {
	MachinePrincipal *eventPublisherPrincipal
	LegacyMigration  bool
}

// handleEventPublish is the adapter mutation-event endpoint. Adapter pods
// (every `dakasa-yggdrasil/integration-*`) emit one mutation event per
// successful `ensure_*` / `destroy_*` / allowlist-`create_*` call per
// INTEGRATION_CONTRACT §6.5. The wire shape carries the §6.5 fields and is
// translated into the generic model.EmitEventRequest below. The historical
// generic wire shape remains available only in the entirely unconfigured
// non-production posture; trusted control-plane paths emit generic events
// in-process rather than through a machine HTTP credential.
//
// Auth: hashed event-publisher principals are the durable path and are accepted
// only on this write-only surface. YGGDRASIL_EVENT_PUBLISH_TOKEN remains a
// mutation-only plaintext migration bridge for existing adapters. Human
// sessions and workflow credentials are never accepted. With no event
// credential outside production, an anonymous request remains available for
// local development.
//
// Status codes:
//   - 201 Created: fresh insert (both shapes).
//   - 200 OK: §6.5 idempotency dedup hit — body carries the original
//     event_id and `deduped: true`.
//   - 400 Bad Request: validation failure (missing field, non-conformant
//     event_type, payload not a JSON object, schema validation, …).
//   - 401 Unauthorized: token gate.
//
// Persistence mirrors handleManifestCreateGeneric: open a *sql.Tx on s.db,
// run repository.EmitEventWithOutcome inside it, commit. On any error map
// via writeMappedError so the same status-code logic applies.
func (s *Server) handleEventPublish(w http.ResponseWriter, r *http.Request) {
	actor, err := authenticateEventPublishRequest(r)
	if err != nil {
		writeMappedError(w, err)
		return
	}

	var payload eventPublishRequest
	if err := decodeJSON(r, &payload); err != nil {
		writeMappedError(w, err)
		return
	}
	if err := authorizeEventPublishPayload(payload, actor); err != nil {
		writeProblemJSON(w, http.StatusForbidden, "event.authorization_denied", err.Error())
		return
	}
	payload = bindEventPublishActor(payload, actor)

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

	outcome, err := repository.EmitEventWithOutcome(r.Context(), tx, emitReq)
	if err != nil {
		writeMappedError(w, err)
		return
	}

	if err := tx.Commit(); err != nil {
		writeMappedError(w, fmt.Errorf("commit tx: %w", err))
		return
	}

	status := http.StatusCreated
	if outcome.Deduped {
		// §6.5 contract: re-emission of the same logical mutation returns
		// 200 with the original event_id so the adapter can confirm the
		// audit row is in place without inflating the log.
		status = http.StatusOK
	}
	writeJSON(w, status, map[string]any{
		"event_id":               outcome.EventID.String(),
		"materialized_reactions": outcome.MaterializedReactions,
		"deduped":                outcome.Deduped,
	})
}

func authorizeEventPublishRequest(r *http.Request) error {
	_, err := authenticateEventPublishRequest(r)
	return err
}

func authenticateEventPublishRequest(r *http.Request) (eventPublishActor, error) {
	if r.Method != http.MethodPost || r.URL.Path != "/api/v1/events" {
		return eventPublishActor{}, errWorkflowRunUnauthorized
	}
	// This machine-only route is not wrapped in an event-publish RBAC
	// permission. A verified console session must therefore not become an
	// implicit generic event publisher merely because bearerOrSession attached
	// claims to the request context.
	if _, ok := claimsFromContext(r.Context()); ok {
		return eventPublishActor{}, errWorkflowRunUnauthorized
	}

	candidates := []string{
		strings.TrimSpace(r.Header.Get("X-Yggdrasil-Event-Token")),
		bearerToken(r.Header.Get("Authorization")),
	}
	principals, err := eventPublisherPrincipalsFromEnv()
	if err != nil {
		return eventPublishActor{}, err
	}
	for _, candidate := range candidates {
		if principal := activeEventPublisherPrincipal(candidate, principals, time.Now().UTC()); principal != nil {
			return eventPublishActor{MachinePrincipal: principal}, nil
		}
	}

	// Plaintext compatibility bridge. It is accepted only when operators opt in
	// explicitly with a future expiry, remains route-limited here, and is not
	// consulted by workflow, manifest, auth-admin, deploy, or generic ops gates.
	legacy, err := legacyEventPublishCredentialFromEnv(time.Now().UTC())
	if err != nil {
		return eventPublishActor{}, err
	}
	if legacy.Active {
		for _, candidate := range candidates {
			if constantTimeTokenEqual(candidate, legacy.Token) {
				return eventPublishActor{LegacyMigration: true}, nil
			}
		}
	}

	// Preserve anonymous local development only when the event auth surface is
	// entirely unconfigured and the caller did not present a credential that
	// belongs to some other scope.
	if !legacy.Configured && len(principals) == 0 && !requestPresentsStaticCredential(r) && devEnvAllowsFallback() {
		return eventPublishActor{}, nil
	}
	return eventPublishActor{}, errWorkflowRunUnauthorized
}

func authorizeEventPublishPayload(req eventPublishRequest, actor eventPublishActor) error {
	if actor.LegacyMigration && strings.TrimSpace(req.EventType) == "" {
		return fmt.Errorf("%w: legacy event bridge cannot publish generic events", errEventPublishAuthorizationDenied)
	}
	if actor.MachinePrincipal == nil {
		return nil
	}
	if strings.TrimSpace(req.EventType) == "" {
		return fmt.Errorf("%w: machine event principals cannot publish generic events", errEventPublishAuthorizationDenied)
	}
	if !eventPublisherPrincipalAllows(actor.MachinePrincipal, req.Provider, req.InstanceID, req.EventType) {
		return fmt.Errorf("%w: machine event principal is not allowed for this provider, instance, and event type", errEventPublishAuthorizationDenied)
	}
	return nil
}

func bindEventPublishActor(req eventPublishRequest, actor eventPublishActor) eventPublishRequest {
	metadata := make(map[string]any, len(req.Metadata)+1)
	for key, value := range req.Metadata {
		metadata[key] = value
	}
	delete(metadata, eventPublisherMachinePrincipalMetadataKey)
	if actor.MachinePrincipal != nil {
		req.Actor = &model.EventActor{Type: "service", ID: actor.MachinePrincipal.PrincipalID}
		metadata[eventPublisherMachinePrincipalMetadataKey] = actor.MachinePrincipal.PrincipalID
	} else if actor.LegacyMigration {
		// The migration bridge is broad by design, but it must still leave a
		// non-spoofable server-authored identity in the event audit record.
		req.Actor = &model.EventActor{Type: "service", ID: legacyEventPublisherPrincipalID}
		metadata[eventPublisherMachinePrincipalMetadataKey] = legacyEventPublisherPrincipalID
	}
	if len(metadata) == 0 {
		req.Metadata = nil
	} else {
		req.Metadata = metadata
	}
	return req
}

// buildEmitEventRequestFromPublish translates the wire shape into the
// repository.EmitEvent request, applying field-level validation up front so
// callers get clear 400s instead of the looser sql/contracts errors.
//
// Dispatches on the presence of `event_type`: when set the request is
// treated as a §6.5 mutation event (regex-validated and translated);
// otherwise it falls through the existing generic-shape path.
func buildEmitEventRequestFromPublish(req eventPublishRequest) (model.EmitEventRequest, error) {
	if strings.TrimSpace(req.EventType) != "" {
		return buildEmitEventRequestFromMutation(req)
	}
	return buildEmitEventRequestFromGeneric(req)
}

// buildEmitEventRequestFromGeneric handles the legacy shape.
func buildEmitEventRequestFromGeneric(req eventPublishRequest) (model.EmitEventRequest, error) {
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

// buildEmitEventRequestFromMutation validates the §6.5 wire body and
// translates it to the generic EmitEventRequest the repository layer
// expects. The translation is mechanical:
//
//   - Type            ← event_type (regex-validated against the
//     <provider>.<resource>.<verb_past> grammar)
//   - SchemaVersion   ← "v1"
//   - AggregateType   ← <provider>_<resource> (snake-case denormalisation
//     so PullEvents filters by aggregate_type work
//     cleanly for adapter audit consumers)
//   - AggregateID     ← resource_id
//   - Payload         ← {provider, resource, verb, resource_id,
//     instance_id, observed?, emitted_at?} (matches the
//     shared events/v1/integration_mutation/<verb>.json
//     schema; observed/emitted_at omitted when blank so
//     additionalProperties:false stays happy)
//   - IdempotencyKey  ← idempotency (REQUIRED — adapters supplying empty
//     are rejected with a 400)
//   - Metadata        ← {idempotency, instance_id, source} for
//     observability beyond the payload itself
func buildEmitEventRequestFromMutation(req eventPublishRequest) (model.EmitEventRequest, error) {
	eventType := strings.TrimSpace(req.EventType)
	if eventType == "" {
		return model.EmitEventRequest{}, fmt.Errorf("event_type is required")
	}
	if !repository.IsIntegrationMutationEvent(eventType) {
		return model.EmitEventRequest{}, fmt.Errorf(
			"event_type %q invalid: must match <provider>.<resource>.<verb_past> (verbs: ensured|destroyed|created)",
			eventType,
		)
	}
	provider := strings.TrimSpace(req.Provider)
	resource := strings.TrimSpace(req.Resource)
	verb := strings.TrimSpace(req.Verb)
	resourceID := strings.TrimSpace(req.ResourceID)
	instanceID := strings.TrimSpace(req.InstanceID)
	idempotency := strings.TrimSpace(req.Idempotency)

	if provider == "" {
		return model.EmitEventRequest{}, fmt.Errorf("provider is required for mutation events")
	}
	if resource == "" {
		return model.EmitEventRequest{}, fmt.Errorf("resource is required for mutation events")
	}
	if verb == "" {
		return model.EmitEventRequest{}, fmt.Errorf("verb is required for mutation events")
	}
	if resourceID == "" {
		return model.EmitEventRequest{}, fmt.Errorf("resource_id is required for mutation events")
	}
	if instanceID == "" {
		return model.EmitEventRequest{}, fmt.Errorf("instance_id is required for mutation events")
	}
	if idempotency == "" {
		return model.EmitEventRequest{}, fmt.Errorf("idempotency is required for mutation events (dedup key for safe retries per INTEGRATION_CONTRACT 6.5)")
	}

	// Cross-check the denormalised fields against the event_type so a
	// typo in `provider` or `verb` doesn't slip past the schema constancy
	// check (which catches verb mismatches but not provider/resource).
	parsedProvider, parsedResource, parsedVerb, _ := repository.ParseIntegrationMutationEventType(eventType)
	if parsedProvider != provider {
		return model.EmitEventRequest{}, fmt.Errorf(
			"provider %q does not match event_type provider %q", provider, parsedProvider,
		)
	}
	if parsedResource != resource {
		return model.EmitEventRequest{}, fmt.Errorf(
			"resource %q does not match event_type resource %q", resource, parsedResource,
		)
	}
	if parsedVerb != verb {
		return model.EmitEventRequest{}, fmt.Errorf(
			"verb %q does not match event_type verb %q", verb, parsedVerb,
		)
	}

	payload := map[string]any{
		"provider":    provider,
		"resource":    resource,
		"verb":        verb,
		"resource_id": resourceID,
		"instance_id": instanceID,
	}
	if req.Observed != nil {
		payload["observed"] = req.Observed
	}
	if strings.TrimSpace(req.EmittedAt) != "" {
		payload["emitted_at"] = strings.TrimSpace(req.EmittedAt)
	}

	// Metadata captures the audit trail context that doesn't go into the
	// payload (so the schema stays additionalProperties:false). Adapter
	// `source` is a marker so downstream consumers can tell §6.5 events
	// apart from generic emissions without re-parsing the event_type.
	metadata := map[string]any{
		"idempotency": idempotency,
		"instance_id": instanceID,
		"source":      "integration_mutation",
	}
	if req.Metadata != nil {
		for k, v := range req.Metadata {
			if _, exists := metadata[k]; !exists {
				metadata[k] = v
			}
		}
	}

	return model.EmitEventRequest{
		Type:           eventType,
		SchemaVersion:  "v1",
		AggregateType:  provider + "_" + resource,
		AggregateID:    resourceID,
		Actor:          req.Actor,
		Payload:        payload,
		Metadata:       metadata,
		IdempotencyKey: idempotency,
	}, nil
}
