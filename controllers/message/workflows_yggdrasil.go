package message

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"

	oidccontroller "github.com/dakasa-yggdrasil/yggdrasil-core/controllers/oidc"
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
//   - oidc_client.verify_bootstrap_file — proves that the persisted clients match
//     the server-local, read-only confidential-client Secret file. It accepts no
//     input, performs no mutation, and returns only public client identifiers.
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
	case "oidc_client.verify_bootstrap_file":
		return handleOIDCClientVerifyBootstrapFile(ctx, db, result, renderedInput)
	default:
		result.Error = fmt.Sprintf("unsupported yggdrasil step operation %q", operation)
		result.FinishedAt = time.Now().UTC()
		return result
	}
}

func handleOIDCClientVerifyBootstrapFile(
	ctx context.Context,
	db *sql.DB,
	result model.WorkflowRunStepResult,
	renderedInput map[string]any,
) model.WorkflowRunStepResult {
	if len(renderedInput) != 0 {
		result.Error = "oidc_client.verify_bootstrap_file accepts no input; client material must come only from the server-local mounted Secret file"
		result.FinishedAt = time.Now().UTC()
		return result
	}
	path := strings.TrimSpace(os.Getenv("YGGDRASIL_OIDC_CLIENTS_FILE"))
	if path == "" {
		result.Error = "oidc_client.verify_bootstrap_file: YGGDRASIL_OIDC_CLIENTS_FILE is not configured"
		result.FinishedAt = time.Now().UTC()
		return result
	}
	verified, err := oidccontroller.VerifyConfiguredConfidentialClientsFromFile(ctx, db, path)
	if err != nil {
		result.Error = fmt.Sprintf("oidc_client.verify_bootstrap_file: %v", err)
		result.FinishedAt = time.Now().UTC()
		return result
	}
	result.Status = "succeeded"
	result.Metadata = map[string]any{
		"managed_client_count": len(verified.ClientIDs),
		"managed_client_ids":   verified.ClientIDs,
		"source":               "server_local_mounted_file",
	}
	result.FinishedAt = time.Now().UTC()
	return result
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

	rawUsers := renderedInput["users"]
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

		// Mark the row as reconciled (last_reconciled_at, clear error_count,
		// pending_action). When observed_state contradicts the Yggdrasil
		// collaborator status (provider says suspended/deleted but the
		// canonical record is still active), set last_drift_detected_at AND
		// emit a collaborator.status.drift_detected event so an event-triggered
		// workflow can alert. Drift detection is best-effort — neither the
		// mark nor the emit failure aborts the reconcile.
		drifted, providerSignal := observedShowsStatusDrift(provider, observedState, collab)
		// row was just upserted — ErrProviderStateNotFound here would
		// indicate a race with deletion that's worth noting but not
		// fatal. Best-effort: errors are intentionally swallowed.
		_ = repository.MarkProviderStateReconciled(ctx, db, collab.ID, provider, drifted)
		if drifted {
			emitStatusDriftEvent(ctx, db, collab, provider, providerSignal, observedState)
		}

		// Side-effect: when an observed_state proves the user is enrolled
		// in MFA at the provider, mirror that signal onto collaborator.traits
		// so the surface-console security panel can flip from "Sem registro"
		// to "Informada como ativa" without re-fetching provider_state per
		// row. The mirror is best-effort — failure to patch traits does NOT
		// fail the reconcile, since the canonical state is still in
		// collaborator_provider_state.
		if mfaEnrolledFromObservedState(provider, observedState) && !traitsMFAEnrolledAlreadySet(collab.Traits) {
			merged := cloneTraitsWithMFA(collab.Traits, time.Now().UTC())
			id := collab.ID.String()
			if _, err := repository.UpdateCollaborator(ctx, db, model.UpdateCollaboratorRequest{
				ID:     id,
				Traits: &merged,
			}); err != nil {
				// Surface as metadata note instead of hard-failing the step.
				if meta := result.Metadata; meta != nil {
					if existing, ok := meta["mfa_trait_patch_errors"].([]string); ok {
						meta["mfa_trait_patch_errors"] = append(existing, fmt.Sprintf("%s: %v", email, err))
					}
				}
			}
		}
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

// observedShowsStatusDrift returns true when the provider observed_state
// contradicts collaborator.status. The signal is per-provider because each
// adapter normalizes the upstream API field differently:
//
//	google-workspace.suspended  — Admin SDK Directory directoryUser.suspended
//	slack.deleted               — users.list member.deleted (filtered at
//	                              adapter today; here for forward-compat if
//	                              the filter is loosened)
//
// Drift is only flagged when the canonical Yggdrasil status is "active" —
// suspending or offboarding through Yggdrasil and then observing the same
// state at the provider is the desired flow, not drift.
//
// The second return is the canonical signal name so the alert payload can
// say WHY this is drift instead of relying on the consumer to introspect
// observed_state.
func observedShowsStatusDrift(provider string, observed map[string]any, collab model.Collaborator) (bool, string) {
	if observed == nil {
		return false, ""
	}
	if strings.ToLower(strings.TrimSpace(collab.Status)) != "active" {
		return false, ""
	}
	switch provider {
	case "google-workspace":
		if v, ok := observed["suspended"].(bool); ok && v {
			return true, "suspended"
		}
	case "slack":
		if v, ok := observed["deleted"].(bool); ok && v {
			return true, "deleted"
		}
	}
	return false, ""
}

// emitStatusDriftEvent writes one collaborator.status.drift_detected event
// into the event stream so the alert-on-status-drift event-triggered workflow
// can react. Best-effort: failures are swallowed (the reconcile itself is the
// canonical store; the event is just a notification path).
// concurrentDriftingProvidersForCollaborator counts how many distinct
// providers currently report drift for the given collaborator (rows in
// collaborator_provider_state with last_drift_detected_at NOT NULL).
// Best-effort: a query failure returns 0 so the caller keeps emitting the
// event without the count rather than swallowing the whole drift signal.
func concurrentDriftingProvidersForCollaborator(ctx context.Context, db *sql.DB, collaboratorID string) int {
	const q = `
		SELECT COUNT(DISTINCT provider)
		FROM public.collaborator_provider_state
		WHERE collaborator_id = $1
		  AND last_drift_detected_at IS NOT NULL`
	var n int
	if err := db.QueryRowContext(ctx, q, collaboratorID).Scan(&n); err != nil {
		return 0
	}
	return n
}

func emitStatusDriftEvent(ctx context.Context, db *sql.DB, collab model.Collaborator, provider, signal string, observed map[string]any) {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return
	}
	defer tx.Rollback()
	concurrentCount := concurrentDriftingProvidersForCollaborator(ctx, db, collab.ID.String())
	multiProviderDrift := "false"
	if concurrentCount >= 2 {
		multiProviderDrift = "true"
	}
	payload := map[string]any{
		"collaborator_id":               collab.ID.String(),
		"collaborator_slug":             collab.Slug,
		"collaborator_email":            collab.PrimaryEmail,
		"yggdrasil_status":              collab.Status,
		"provider":                      provider,
		"provider_signal":               signal,
		"concurrent_drifting_providers": concurrentCount,
		"multi_provider_drift":          multiProviderDrift,
	}
	if _, err := repository.EmitEvent(ctx, tx, model.EmitEventRequest{
		Type:          "collaborator.status.drift_detected",
		SchemaVersion: "v1",
		AggregateType: "collaborator",
		AggregateID:   collab.ID.String(),
		Payload:       payload,
	}); err != nil {
		return
	}
	_ = tx.Commit()
}

// mfaEnrolledFromObservedState reports whether the observed_state payload
// from a given provider proves the user has MFA enrolled. The mapping is
// per-provider because each adapter normalizes the upstream API field
// differently — keeping this co-located with the reconcile lets one
// place own the mfa_enrolled_at trait contract instead of scattering it
// across adapter manifests.
//
//	google-workspace.isEnrolledIn2Sv  — Admin SDK Directory directoryUser
//	slack.has_2fa                     — users.list (admin scope) profile
//
// Returning false on unknown providers is intentional: we only mirror
// signals we trust, never guess.
func mfaEnrolledFromObservedState(provider string, observed map[string]any) bool {
	if observed == nil {
		return false
	}
	switch provider {
	case "google-workspace":
		v, ok := observed["isEnrolledIn2Sv"].(bool)
		return ok && v
	case "slack":
		v, ok := observed["has_2fa"].(bool)
		return ok && v
	default:
		return false
	}
}

// traitsMFAEnrolledAlreadySet returns true when mfa_enrolled_at is already
// stored on the collaborator (regardless of source). Re-emitting the trait
// every reconcile tick would overwrite a precise enrolment timestamp
// captured by another flow (SAML SSO bootstrap, explicit MFA workflow) with
// a NOW() stamp that drifts later than the truth.
func traitsMFAEnrolledAlreadySet(traits map[string]any) bool {
	if traits == nil {
		return false
	}
	v, ok := traits["mfa_enrolled_at"]
	if !ok {
		return false
	}
	switch s := v.(type) {
	case string:
		return strings.TrimSpace(s) != ""
	case time.Time:
		return !s.IsZero()
	default:
		return false
	}
}

// cloneTraitsWithMFA returns a NEW traits map with mfa_enrolled_at set to
// when. UpdateCollaborator replaces the whole jsonb blob (does not merge),
// so we have to send the full merged map.
func cloneTraitsWithMFA(existing map[string]any, when time.Time) map[string]any {
	out := make(map[string]any, len(existing)+1)
	for k, v := range existing {
		out[k] = v
	}
	out["mfa_enrolled_at"] = when.Format(time.RFC3339)
	return out
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
