package message

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/collaboratorstate"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
)

const (
	identityProvisioningManifestIDEnv = "YGGDRASIL_IDENTITY_PROVISIONING_WORKFLOW_MANIFEST_ID"
	identityProvisioningSource        = "private://list-collaborators/collaborators"
	identityProvisioningMaxPeople     = 1000
)

var errIdentityProvisioningUnavailable = errors.New("identity provisioning snapshot is unavailable")

// This state belongs to one invocation of runWorkflow. It is not reachable
// through WorkflowExecutionContext, a result, an event, or workflow_runs.
type identityProvisioningPrivateState struct {
	collaborators []any
	ready         bool
}

func (state *identityProvisioningPrivateState) clear() {
	if state == nil {
		return
	}
	for i := range state.collaborators {
		state.collaborators[i] = nil
	}
	state.collaborators = nil
	state.ready = false
}

func usesIdentityProvisioningSnapshot(spec model.WorkflowManifestSpec) bool {
	for _, step := range spec.Steps {
		if strings.EqualFold(strings.TrimSpace(step.Use.Kind), "yggdrasil") &&
			strings.EqualFold(strings.TrimSpace(step.Use.Operation), "collaborator.provisioning_snapshot") {
			return true
		}
	}
	return false
}

// The deployment pins one immutable manifest row, not a logical name or a
// version selector. Replacing the active version cannot inherit this grant.
// No adapter credential participates in this read.
func authorizeIdentityProvisioningSnapshot(
	workflow model.Manifest,
	spec model.WorkflowManifestSpec,
	req model.RunWorkflowRequest,
) error {
	if !usesIdentityProvisioningSnapshot(spec) {
		return nil
	}
	pinnedID, err := uuid.Parse(strings.TrimSpace(os.Getenv(identityProvisioningManifestIDEnv)))
	if err != nil || pinnedID == uuid.Nil || workflow.ID != pinnedID ||
		!strings.EqualFold(strings.TrimSpace(workflow.Kind), "workflow") ||
		!workflow.Metadata.Active || workflow.Metadata.Namespace != "dakasa" ||
		workflow.Metadata.Name != "reconcile-identity-providers" ||
		strings.TrimSpace(req.Auth.Token) != "" {
		return errIdentityProvisioningUnavailable
	}
	// Async runs persist both fields before execution. This contract permits
	// only boolean controls and the scheduler's fixed, non-personal evidence.
	for _, value := range req.Inputs {
		if _, ok := value.(bool); !ok {
			return errIdentityProvisioningUnavailable
		}
	}
	for key, value := range req.Metadata {
		text, ok := value.(string)
		if !ok {
			return errIdentityProvisioningUnavailable
		}
		switch key {
		case "triggered_by":
			if text != "workflow_scheduler" {
				return errIdentityProvisioningUnavailable
			}
		case "manifest_id":
			if text != workflow.ID.String() {
				return errIdentityProvisioningUnavailable
			}
		case "scheduled_for":
			if _, err := time.Parse(time.RFC3339, text); err != nil {
				return errIdentityProvisioningUnavailable
			}
		default:
			return errIdentityProvisioningUnavailable
		}
	}
	return nil
}

func executeIdentityProvisioningSnapshot(
	ctx context.Context,
	db *sql.DB,
	workflow model.Manifest,
	result model.WorkflowRunStepResult,
	state *identityProvisioningPrivateState,
) model.WorkflowRunStepResult {
	result.Attempts = 1
	pinnedID, err := uuid.Parse(strings.TrimSpace(os.Getenv(identityProvisioningManifestIDEnv)))
	if state == nil || db == nil || err != nil || pinnedID == uuid.Nil ||
		workflow.ID != pinnedID || !strings.EqualFold(strings.TrimSpace(workflow.Kind), "workflow") ||
		!workflow.Metadata.Active ||
		workflow.Metadata.Namespace != "dakasa" || workflow.Metadata.Name != "reconcile-identity-providers" ||
		result.ID != "list-collaborators" {
		result.Error = errIdentityProvisioningUnavailable.Error()
		result.FinishedAt = time.Now().UTC()
		return result
	}
	identities, err := repository.ListCollaboratorProvisioningIdentities(ctx, db, identityProvisioningMaxPeople)
	if err != nil || len(identities) > identityProvisioningMaxPeople {
		result.Error = errIdentityProvisioningUnavailable.Error()
		result.FinishedAt = time.Now().UTC()
		return result
	}
	items := make([]any, 0, len(identities))
	for _, person := range identities {
		status := collaboratorstate.Status(person.Status)
		if !collaboratorstate.IsKnown(status) {
			result.Error = errIdentityProvisioningUnavailable.Error()
			result.FinishedAt = time.Now().UTC()
			return result
		}
		items = append(items, map[string]any{
			"id":     person.ID.String(),
			"status": person.Status,
			"provider_desired": map[string]any{
				"primary_email": person.PrimaryEmail,
				"display_name":  person.DisplayName,
				"given_name":    person.GivenName,
				"family_name":   person.FamilyName,
				"external_id":   person.ID.String(),
			},
		})
	}
	state.collaborators = items
	state.ready = true
	result.Status = "succeeded"
	result.Metadata = map[string]any{"total_count": len(items)}
	result.FinishedAt = time.Now().UTC()
	return result
}

// An integration can echo its input in output, metadata, status or an error.
// Keep only engine-owned identifiers, attempts, times and the terminal state.
func redactIdentityProvisioningIteration(raw model.WorkflowRunStepResult) model.WorkflowRunStepResult {
	status := raw.Status
	if status != "succeeded" && status != "skipped" {
		status = "failed"
	}
	safe := model.WorkflowRunStepResult{
		ID:         raw.ID,
		Kind:       raw.Kind,
		Operation:  raw.Operation,
		Capability: raw.Capability,
		Status:     status,
		Attempts:   raw.Attempts,
		StartedAt:  raw.StartedAt,
		FinishedAt: raw.FinishedAt,
	}
	if status == "failed" {
		safe.Error = "identity provisioning iteration failed"
	}
	return safe
}
