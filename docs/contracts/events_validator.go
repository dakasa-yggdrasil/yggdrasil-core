package contracts

import (
	"embed"
	"encoding/json"
	"fmt"
	"strings"
	"sync"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

// FamilyEventsV1 identifies the events/v1 contract family.
const FamilyEventsV1 = "events/v1"

//go:embed events/v1/schema.json events/v1/manifest/*.json events/v1/product/*.json events/v1/workflow/*.json events/v1/authorization/*.json events/v1/buildproject/*.json events/v1/infra/*.json events/v1/collaborator/*.json events/v1/credential/*.json events/v1/team/*.json events/v1/team_membership/*.json events/v1/reactor/*.json events/v1/runtime_state/*.json events/v1/integration_type/*.json events/v1/collaborator_external_identity/*.json events/v1/integration_surface/*.json
var eventSchemaFS embed.FS

var (
	eventSchemasMu sync.RWMutex
	eventSchemas   = map[string]*jsonschema.Schema{}
)

// ValidateEventPayload validates a payload against the JSON Schema of a specific
// event type + schema version. Returns an error describing the validation failure
// if the payload does not match the schema, or if the schema is unknown.
//
// Example:
//
//	err := contracts.ValidateEventPayload("manifest.created", "v1", payloadMap)
func ValidateEventPayload(eventType string, schemaVersion string, payload interface{}) error {
	eventType = strings.TrimSpace(eventType)
	schemaVersion = strings.TrimSpace(schemaVersion)
	if eventType == "" {
		return fmt.Errorf("event type is required")
	}
	if schemaVersion == "" {
		schemaVersion = "v1"
	}

	schemaPath := eventTypeToSchemaPath(eventType, schemaVersion)
	if schemaPath == "" {
		return fmt.Errorf("no schema registered for event type %q version %q", eventType, schemaVersion)
	}

	schema, err := loadEventSchema(schemaPath)
	if err != nil {
		return fmt.Errorf("load event schema %q: %w", schemaPath, err)
	}

	if err := schema.Validate(payload); err != nil {
		return fmt.Errorf("event payload validation for %q: %w", eventType, err)
	}
	return nil
}

// eventTypeToSchemaPath maps "manifest.created" → "events/v1/manifest/created.json".
// Only MVP event types are registered here; extend this map as new types are added.
func eventTypeToSchemaPath(eventType string, schemaVersion string) string {
	_ = schemaVersion // placeholder for v2+ routing when multiple versions coexist
	mapping := map[string]string{
		"manifest.created":             "events/v1/manifest/created.json",
		"product.installation.applied": "events/v1/product/installation_applied.json",
		"workflow.run.completed":       "events/v1/workflow/run_completed.json",
		"workflow.event.matched":       "events/v1/workflow/event_matched.json",
		"workflow.schedule.fired":      "events/v1/workflow/schedule_fired.json",
		"authorization.evaluated":      "events/v1/authorization/evaluated.json",
		"buildproject.expired":         "events/v1/buildproject/expired.json",
		"infra.alert.firing":           "events/v1/infra/alert_firing.json",
		"collaborator.created":                "events/v1/collaborator/created.json",
		"collaborator.offboarded":             "events/v1/collaborator/offboarded.json",
		"collaborator.status.drift_detected":  "events/v1/collaborator/status_drift_detected.json",
		// credential lifecycle events
		"credential.setup_token_issued":         "events/v1/credential/setup_token_issued.json",
		"credential.password_setup_completed":   "events/v1/credential/password_setup_completed.json",
		"credential.password_changed":           "events/v1/credential/password_changed.json",
		"credential.reset_token_issued":         "events/v1/credential/reset_token_issued.json",
		"credential.password_rotation_required": "events/v1/credential/password_rotation_required.json",
		// collaborator lifecycle events
		"collaborator.absence_started": "events/v1/collaborator/absence_started.json",
		"collaborator.absence_ended":   "events/v1/collaborator/absence_ended.json",
		"collaborator.role_changed":    "events/v1/collaborator/role_changed.json",
		"collaborator.re_onboarded":    "events/v1/collaborator/re_onboarded.json",
		// team events
		"team.created": "events/v1/team/created.json",
		"team.updated": "events/v1/team/updated.json",
		"team.deleted": "events/v1/team/deleted.json",
		// team membership events
		"team_membership.added":   "events/v1/team_membership/added.json",
		"team_membership.removed": "events/v1/team_membership/removed.json",
		// reactor observability events
		"reactor.dead_lettered": "events/v1/reactor/dead_lettered.json",
		// manifest sync framework events
		"runtime_state.contract_mismatch_detected": "events/v1/runtime_state/contract_mismatch_detected.json",
		"integration_type.synced":                   "events/v1/integration_type/synced.json",
		"integration_type.sync_no_op":               "events/v1/integration_type/sync_no_op.json",
		"integration_type.sync_skipped":             "events/v1/integration_type/sync_skipped.json",
		// external identity framework events
		"collaborator_external_identity.linked":            "events/v1/collaborator_external_identity/linked.json",
		"collaborator_external_identity.unlinked":          "events/v1/collaborator_external_identity/unlinked.json",
		"collaborator_external_identity.drift_detected":    "events/v1/collaborator_external_identity/drift_detected.json",
		"collaborator_external_identity.unknown_external": "events/v1/collaborator_external_identity/unknown_external.json",
		"collaborator_external_identity.purged":            "events/v1/collaborator_external_identity/purged.json",
		"collaborator_external_identity.conflict_detected": "events/v1/collaborator_external_identity/conflict_detected.json",
		// integration_surface framework events (federated surfaces)
		"integration_surface.registered":     "events/v1/integration_surface/registered.json",
		"integration_surface.updated":        "events/v1/integration_surface/updated.json",
		"integration_surface.deactivated":    "events/v1/integration_surface/deactivated.json",
		"integration_surface.drift_detected": "events/v1/integration_surface/drift_detected.json",
	}
	return mapping[eventType]
}

func loadEventSchema(schemaPath string) (*jsonschema.Schema, error) {
	eventSchemasMu.RLock()
	if cached, ok := eventSchemas[schemaPath]; ok {
		eventSchemasMu.RUnlock()
		return cached, nil
	}
	eventSchemasMu.RUnlock()

	data, err := eventSchemaFS.ReadFile(schemaPath)
	if err != nil {
		return nil, err
	}

	var raw interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parse schema: %w", err)
	}

	compiler := jsonschema.NewCompiler()
	if err := compiler.AddResource(schemaPath, raw); err != nil {
		return nil, fmt.Errorf("add resource: %w", err)
	}

	schema, err := compiler.Compile(schemaPath)
	if err != nil {
		return nil, fmt.Errorf("compile schema: %w", err)
	}

	eventSchemasMu.Lock()
	eventSchemas[schemaPath] = schema
	eventSchemasMu.Unlock()

	return schema, nil
}
