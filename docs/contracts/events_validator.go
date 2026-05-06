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

//go:embed events/v1/schema.json events/v1/manifest/*.json events/v1/product/*.json events/v1/workflow/*.json events/v1/authorization/*.json events/v1/buildproject/*.json
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
		"authorization.evaluated":      "events/v1/authorization/evaluated.json",
		"buildproject.expired":         "events/v1/buildproject/expired.json",
		"infra.alert.firing":           "events/v1/infra/alert_firing.json",
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
