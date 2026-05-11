package message

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/controlplane"
	"github.com/dakasa-yggdrasil/yggdrasil-core/manifest"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
)

// executeYggdrasilWorkflowStep runs a workflow step with use.kind = "yggdrasil".
// These steps execute in-process against the core rather than
// dispatching to an adapter. The dispatch table lives here; the
// manifest-level validator in manifest/workflow.go gates which
// operations are legal.
//
// Supported operations:
//
//   - apply_manifest                       — persists with.manifest through the standard
//     normalize/validate/persist/emit pipeline. See handleApplyManifest.
//   - control_plane.render                 — loads a `control_plane` manifest by ref
//     and returns its rendered Kubernetes objects as step metadata.
//   - collaborator.reconcile_provider_state — matches a batch of provider identities
//     to collaborators by primary_email and upserts collaborator_provider_state rows.
//
// On success, step.Metadata carries operation-specific fields (see the
// per-handler doc comments).
func executeYggdrasilWorkflowStep(
	ctx context.Context,
	db *sql.DB,
	step model.WorkflowStepSpec,
	result model.WorkflowRunStepResult,
	renderedInput map[string]any,
) model.WorkflowRunStepResult {
	result.Attempts = 1

	operation := strings.ToLower(strings.TrimSpace(step.Use.Operation))
	switch operation {
	case "apply_manifest":
		return handleApplyManifest(ctx, db, result, renderedInput)
	case "control_plane.render":
		return handleControlPlaneRender(ctx, db, result, renderedInput)
	case "collaborator.reconcile_provider_state":
		return handleCollaboratorReconcileProviderState(ctx, db, result, renderedInput)
	default:
		result.Error = fmt.Sprintf("unsupported yggdrasil step operation %q", operation)
		result.FinishedAt = time.Now().UTC()
		return result
	}
}

// handleApplyManifest persists with.manifest through the same pipeline
// the HTTP and RPC endpoints use. See persistManifestVersion for the
// normalize/validate/persist/emit contract.
//
// Metadata on success:
//
//	manifest_id, kind, namespace, name, version, checksum
func handleApplyManifest(
	ctx context.Context,
	db *sql.DB,
	result model.WorkflowRunStepResult,
	renderedInput map[string]any,
) model.WorkflowRunStepResult {
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

// handleControlPlaneRender loads a control_plane manifest identified by
// with.control_plane_ref, renders it via internal/controlplane, and
// surfaces the rendered bundle as step metadata for downstream steps.
//
// Input:
//
//	with:
//	  control_plane_ref:
//	    namespace: global
//	    name:      primary
//	    version:   3      # optional; latest active when absent
//
// Metadata on success:
//
//	control_plane:  { manifest_id, namespace, name, version }
//	infra_objects:  [ ... K8s objects ... ]
//	core_objects:   [ ... K8s objects ... ]
//	wait_targets:   [ { phase, namespace, kind, name } ]
//
// Downstream steps reference these via
// {{ steps.<id>.metadata.infra_objects }} as the objects input to
// integration-kubernetes declarative_apply.
func handleControlPlaneRender(
	ctx context.Context,
	db *sql.DB,
	result model.WorkflowRunStepResult,
	renderedInput map[string]any,
) model.WorkflowRunStepResult {
	selector, err := controlPlaneSelectorFromInput(renderedInput)
	if err != nil {
		result.Error = err.Error()
		result.FinishedAt = time.Now().UTC()
		return result
	}

	record, err := resolveControlPlaneManifest(ctx, db, selector)
	if err != nil {
		result.Error = fmt.Errorf("load control_plane manifest: %w", err).Error()
		result.FinishedAt = time.Now().UTC()
		return result
	}

	spec, err := manifest.ParseControlPlaneSpec(record.Spec)
	if err != nil {
		result.Error = err.Error()
		result.FinishedAt = time.Now().UTC()
		return result
	}

	bundle, err := controlplane.Render(spec)
	if err != nil {
		result.Error = fmt.Errorf("render control_plane: %w", err).Error()
		result.FinishedAt = time.Now().UTC()
		return result
	}

	result.Status = "succeeded"
	result.Metadata = map[string]any{
		"control_plane": map[string]any{
			"manifest_id": record.ID.String(),
			"namespace":   record.Metadata.Namespace,
			"name":        record.Metadata.Name,
			"version":     record.Version,
		},
		"infra_objects": bundle.InfraObjects,
		"core_objects":  bundle.CoreObjects,
		"wait_targets":  waitTargetsForMetadata(bundle.WaitTargets),
	}
	result.FinishedAt = time.Now().UTC()
	return result
}

// controlPlaneSelectorFromInput reads the `control_plane_ref` field
// from the rendered with-block and normalizes it into a
// ManifestSelector. The ref accepts the same shape as ManifestSelector
// itself (name + optional namespace + optional version) to stay
// consistent with how integrations reference their type_ref.
func controlPlaneSelectorFromInput(input map[string]any) (model.ManifestSelector, error) {
	raw, ok := input["control_plane_ref"]
	if !ok {
		return model.ManifestSelector{}, fmt.Errorf("control_plane.render requires with.control_plane_ref")
	}
	refMap, ok := raw.(map[string]any)
	if !ok {
		return model.ManifestSelector{}, fmt.Errorf("control_plane.render: with.control_plane_ref must be an object")
	}

	selector := model.ManifestSelector{
		ManifestID: stringField(refMap, "manifest_id"),
		Namespace:  strings.ToLower(strings.TrimSpace(stringField(refMap, "namespace"))),
		Name:       strings.ToLower(strings.TrimSpace(stringField(refMap, "name"))),
	}
	if selector.Namespace == "" {
		selector.Namespace = "global"
	}
	if selector.ManifestID == "" && selector.Name == "" {
		return model.ManifestSelector{}, fmt.Errorf("control_plane.render: control_plane_ref requires manifest_id or name")
	}
	if version, ok := refMap["version"]; ok {
		if parsed, err := toPositiveInt(version); err != nil {
			return model.ManifestSelector{}, fmt.Errorf("control_plane.render: control_plane_ref.version is invalid: %w", err)
		} else if parsed > 0 {
			selector.Version = &parsed
		}
	}
	return selector, nil
}

func stringField(m map[string]any, key string) string {
	if v, ok := m[key].(string); ok {
		return v
	}
	return ""
}

// toPositiveInt accepts the JSON number representations workflow
// rendering produces (float64, json.Number, int) and rejects anything
// else. Zero and negatives are valid inputs but the caller filters
// them — we only signal whether the encoding itself is parseable.
func toPositiveInt(v any) (int, error) {
	switch value := v.(type) {
	case float64:
		return int(value), nil
	case int:
		return value, nil
	case json.Number:
		n, err := value.Int64()
		if err != nil {
			return 0, err
		}
		return int(n), nil
	case nil:
		return 0, nil
	default:
		return 0, fmt.Errorf("unsupported type %T", v)
	}
}

// resolveControlPlaneManifest lifts a ManifestSelector into the
// corresponding stored record. The selector may carry a manifest_id
// (UUID), in which case GetManifestByID is exact; otherwise we fall
// back to namespace/name/version resolution, honoring the activeOnly
// default that everything else in the core uses.
func resolveControlPlaneManifest(ctx context.Context, db *sql.DB, selector model.ManifestSelector) (model.Manifest, error) {
	if id := strings.TrimSpace(selector.ManifestID); id != "" {
		parsed, err := uuid.Parse(id)
		if err != nil {
			return model.Manifest{}, fmt.Errorf("manifest_id %q is not a valid UUID: %w", id, err)
		}
		record, err := repository.GetManifestByID(ctx, db, parsed)
		if err != nil {
			return model.Manifest{}, err
		}
		if !strings.EqualFold(record.Kind, "control_plane") {
			return model.Manifest{}, fmt.Errorf("manifest %s is kind %q, not control_plane", id, record.Kind)
		}
		return record, nil
	}

	record, err := repository.ResolveManifest(ctx, db, "control_plane", selector.Namespace, selector.Name, selector.Version, true)
	if err != nil {
		if errors.Is(err, repository.ErrManifestNotFound) {
			return model.Manifest{}, fmt.Errorf("control_plane %s/%s not found", selector.Namespace, selector.Name)
		}
		return model.Manifest{}, err
	}
	return record, nil
}

func waitTargetsForMetadata(targets []controlplane.WaitTarget) []map[string]any {
	out := make([]map[string]any, 0, len(targets))
	for _, target := range targets {
		out = append(out, map[string]any{
			"phase":     target.Phase,
			"namespace": target.Namespace,
			"kind":      target.Kind,
			"name":      target.Name,
		})
	}
	return out
}

// handleCollaboratorReconcileProviderState is the in-process executor for
// the yggdrasil step operation "collaborator.reconcile_provider_state".
// It reads with.provider and with.users from the rendered step input,
// matches each user entry to a collaborator by primary_email, and upserts
// collaborator_provider_state rows. Orphaned emails (no matching collaborator)
// are collected and surfaced in step metadata rather than failing the step.
//
// Input (with block):
//
//	provider: github
//	users:    # list — each item must carry email; external_id and
//	          # observed_state are optional
//	  - email:       alice@example.com
//	    external_id: u-abc123
//	    observed_state: { ... }
//
// Metadata on success:
//
//	matched:          int     — number of provider_state rows upserted
//	unmatched_emails: []string — emails with no matching collaborator
func handleCollaboratorReconcileProviderState(
	ctx context.Context,
	db *sql.DB,
	result model.WorkflowRunStepResult,
	renderedInput map[string]any,
) model.WorkflowRunStepResult {
	provider, _ := renderedInput["provider"].(string)
	provider = strings.TrimSpace(provider)
	if provider == "" {
		result.Error = "collaborator.reconcile_provider_state: with.provider is required"
		result.FinishedAt = time.Now().UTC()
		return result
	}

	rawUsers, _ := renderedInput["users"]
	var users []model.ReconcileProviderStateUser
	switch v := rawUsers.(type) {
	case []any:
		// Template rendering produces []any; re-encode + decode into typed slice.
		encoded, err := json.Marshal(v)
		if err != nil {
			result.Error = fmt.Sprintf("collaborator.reconcile_provider_state: marshal users: %v", err)
			result.FinishedAt = time.Now().UTC()
			return result
		}
		if err := json.Unmarshal(encoded, &users); err != nil {
			result.Error = fmt.Sprintf("collaborator.reconcile_provider_state: decode users: %v", err)
			result.FinishedAt = time.Now().UTC()
			return result
		}
	case nil:
		// No users supplied — succeed with matched=0.
	default:
		result.Error = fmt.Sprintf("collaborator.reconcile_provider_state: with.users must be a list, got %T", rawUsers)
		result.FinishedAt = time.Now().UTC()
		return result
	}

	var unmatched []string
	matched := 0
	for _, u := range users {
		email := strings.TrimSpace(strings.ToLower(u.Email))
		if email == "" {
			// Accept SCIM userName as a fallback so payloads forwarded
			// directly from scim_list_users don't need transformation.
			email = strings.TrimSpace(strings.ToLower(u.UserName))
		}
		if email == "" {
			continue
		}
		collab, err := repository.GetCollaboratorByPrimaryEmail(ctx, db, email)
		if errors.Is(err, repository.ErrCollaboratorNotFound) {
			unmatched = append(unmatched, email)
			continue
		}
		if err != nil {
			result.Error = fmt.Sprintf("collaborator.reconcile_provider_state: lookup %s: %v", email, err)
			result.FinishedAt = time.Now().UTC()
			return result
		}

		observedState := u.ObservedState
		if _, err := repository.UpsertCollaboratorProviderState(ctx, db, model.UpsertProviderStateRequest{
			CollaboratorID: collab.ID,
			Provider:       provider,
			ExternalID:     u.ExternalID,
			ObservedState:  &observedState,
		}); err != nil {
			result.Error = fmt.Sprintf("collaborator.reconcile_provider_state: upsert %s: %v", email, err)
			result.FinishedAt = time.Now().UTC()
			return result
		}
		matched++
	}

	meta := map[string]any{
		"provider": provider,
		"matched":  matched,
	}
	if len(unmatched) > 0 {
		meta["unmatched_emails"] = unmatched
	}

	result.Status = "succeeded"
	result.Metadata = meta
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
