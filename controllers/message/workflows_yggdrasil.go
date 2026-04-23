package message

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

// executeYggdrasilWorkflowStep runs a workflow step with use.kind = "yggdrasil".
// These steps persist a manifest document, carried in with.manifest, against
// the core's own manifest store — they do NOT dispatch to an integration
// adapter. The only supported operation today is apply_manifest; the
// validator in manifest/workflow.go enforces that.
//
// The handler reuses persistManifestVersion so that workflow-driven
// manifest creation goes through the same normalize/validate/persist/emit
// pipeline as the HTTP and AMQP entrypoints. That keeps the manifest.created
// event stream consistent regardless of which surface created the record.
//
// Step output (step.Metadata) on success:
//
//	manifest_id: UUID string of the persisted manifest record
//	kind:        lowercase kind the manifest was created as
//	namespace:   normalized namespace
//	name:        normalized name
//	version:     integer version number assigned by the repository
//	checksum:    deterministic sha256 checksum
//
// Downstream steps can reference these via {{ steps.<id>.metadata.manifest_id }} etc.
func executeYggdrasilWorkflowStep(
	ctx context.Context,
	db *sql.DB,
	step model.WorkflowStepSpec,
	result model.WorkflowRunStepResult,
	renderedInput map[string]any,
) model.WorkflowRunStepResult {
	result.Attempts = 1

	operation := strings.ToLower(strings.TrimSpace(step.Use.Operation))
	if operation != "apply_manifest" {
		result.Error = fmt.Sprintf("unsupported yggdrasil step operation %q", operation)
		result.FinishedAt = time.Now().UTC()
		return result
	}

	doc, err := manifestDocumentFromStepInput(renderedInput)
	if err != nil {
		result.Error = err.Error()
		result.FinishedAt = time.Now().UTC()
		return result
	}

	manifestRecord, err := persistManifestVersion(ctx, db, doc)
	if err != nil {
		result.Error = err.Error()
		result.FinishedAt = time.Now().UTC()
		return result
	}

	result.Status = "succeeded"
	result.Metadata = map[string]any{
		"manifest_id": manifestRecord.ID.String(),
		"kind":        manifestRecord.Kind,
		"namespace":   manifestRecord.Metadata.Namespace,
		"name":        manifestRecord.Metadata.Name,
		"version":     manifestRecord.Version,
		"checksum":    manifestRecord.Checksum,
	}
	result.FinishedAt = time.Now().UTC()
	return result
}

// manifestDocumentFromStepInput extracts the with.manifest value produced by
// template rendering and shapes it into a model.ManifestDocument ready for
// persistManifestVersion. The input map is the result of RenderWorkflowInput,
// so templates have already been resolved and values are plain Go types
// (map[string]any, string, float64, bool, []any, nil).
//
// Round-tripping through JSON is deliberate: it is the same normalization
// the HTTP handler applies (manifestDocumentFromPayload in httpapi/server.go)
// and it means any shape the workflow author wrote in YAML becomes a
// canonical, checksummable envelope without custom per-field plumbing.
func manifestDocumentFromStepInput(input map[string]any) (model.ManifestDocument, error) {
	raw, ok := input["manifest"]
	if !ok {
		return model.ManifestDocument{}, fmt.Errorf("yggdrasil apply_manifest requires with.manifest")
	}
	manifestMap, ok := raw.(map[string]any)
	if !ok {
		return model.ManifestDocument{}, fmt.Errorf("yggdrasil apply_manifest: with.manifest must be an object")
	}
	if len(manifestMap) == 0 {
		return model.ManifestDocument{}, fmt.Errorf("yggdrasil apply_manifest: with.manifest is empty")
	}

	encoded, err := json.Marshal(manifestMap)
	if err != nil {
		return model.ManifestDocument{}, fmt.Errorf("marshal with.manifest: %w", err)
	}

	var doc model.ManifestDocument
	decoder := json.NewDecoder(strings.NewReader(string(encoded)))
	if err := decoder.Decode(&doc); err != nil {
		return model.ManifestDocument{}, fmt.Errorf("decode with.manifest: %w", err)
	}
	return doc, nil
}
