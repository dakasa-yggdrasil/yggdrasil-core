package contracts

import (
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

const (
	FamilyIntegrationAdapterV1         = "integration-adapter/v1"
	FamilyProductInstallationAdapterV1 = "product-installation-adapter/v1"
)

//go:embed integration-adapter/v1/schema.json product-installation-adapter/v1/schema.json
var schemaFS embed.FS

var (
	compiledSchemasMu sync.RWMutex
	compiledSchemas   = map[string]*jsonschema.Schema{}
)

// Validate checks one payload against one specific public contract definition.
func Validate(family string, definition string, payload any) error {
	family = strings.TrimSpace(family)
	definition = strings.TrimSpace(definition)
	if family == "" {
		return fmt.Errorf("contract family is required")
	}
	if definition == "" {
		return fmt.Errorf("contract definition is required")
	}

	schema, err := compiledDefinition(family, definition)
	if err != nil {
		return err
	}

	instance, err := normalizePayload(payload)
	if err != nil {
		return fmt.Errorf("normalize payload for contract validation: %w", err)
	}

	if err := schema.Validate(instance); err != nil {
		// Serialize DetailedOutput as JSON so every failing schema
		// path + instance path + reason lands in the error message.
		// The library's default Error() only shows the outer schema
		// URL, which hides the actual failing field.
		var detail string
		var ve *jsonschema.ValidationError
		if errors.As(err, &ve) {
			if raw, mErr := json.Marshal(ve.DetailedOutput()); mErr == nil {
				detail = " detail=" + string(raw)
			}
		}
		return fmt.Errorf("%s#/$defs/%s: %w%s", family, definition, err, detail)
	}
	return nil
}

func compiledDefinition(family string, definition string) (*jsonschema.Schema, error) {
	cacheKey := family + "#/$defs/" + definition

	compiledSchemasMu.RLock()
	if schema, ok := compiledSchemas[cacheKey]; ok {
		compiledSchemasMu.RUnlock()
		return schema, nil
	}
	compiledSchemasMu.RUnlock()

	compiledSchemasMu.Lock()
	defer compiledSchemasMu.Unlock()

	if schema, ok := compiledSchemas[cacheKey]; ok {
		return schema, nil
	}

	rootDocument, err := loadRootSchema(family)
	if err != nil {
		return nil, err
	}

	rootMap, ok := rootDocument.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("contract %s root schema is not an object", family)
	}

	defs, ok := rootMap["$defs"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("contract %s does not expose $defs", family)
	}
	if _, exists := defs[definition]; !exists {
		return nil, fmt.Errorf("contract %s does not define %q", family, definition)
	}

	wrapper := map[string]any{
		"$schema": rootMap["$schema"],
		"$id":     "mem://yggdrasil/" + strings.ReplaceAll(family, "/", "-") + "/" + definition + ".json",
		"$ref":    "#/$defs/" + definition,
		"$defs":   defs,
	}

	compiler := jsonschema.NewCompiler()
	compiler.DefaultDraft(jsonschema.Draft2020)
	compiler.AssertFormat()
	resourceURL := wrapper["$id"].(string)
	if err := compiler.AddResource(resourceURL, wrapper); err != nil {
		return nil, fmt.Errorf("add contract resource %s: %w", resourceURL, err)
	}

	schema, err := compiler.Compile(resourceURL)
	if err != nil {
		return nil, fmt.Errorf("compile contract %s#/$defs/%s: %w", family, definition, err)
	}

	compiledSchemas[cacheKey] = schema
	return schema, nil
}

func loadRootSchema(family string) (any, error) {
	path := strings.Trim(strings.TrimSpace(family), "/") + "/schema.json"
	data, err := schemaFS.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read contract schema %s: %w", path, err)
	}

	var document any
	if err := json.Unmarshal(data, &document); err != nil {
		return nil, fmt.Errorf("decode contract schema %s: %w", path, err)
	}
	return document, nil
}

func normalizePayload(payload any) (any, error) {
	data, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	var instance any
	if err := json.Unmarshal(data, &instance); err != nil {
		return nil, err
	}
	return instance, nil
}
