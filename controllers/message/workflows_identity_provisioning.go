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
	manifestengine "github.com/dakasa-yggdrasil/yggdrasil-core/manifest"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
)

const (
	identityProvisioningManifestIDEnv = "YGGDRASIL_IDENTITY_PROVISIONING_WORKFLOW_MANIFEST_ID"
	identityProvisioningMaxPeople     = 1000
)

var errIdentityProvisioningUnavailable = errors.New("identity provisioning snapshot is unavailable")

// Pin an immutable active manifest and require an authenticated actor channel.
// ADR-0027 rejects spec.authorization on actorless AMQP and webhook paths.
// Manual dispatch carries no caller-supplied data into durable run evidence.
func authorizeIdentityProvisioningSnapshot(
	workflow model.Manifest,
	spec model.WorkflowManifestSpec,
	req model.RunWorkflowRequest,
) error {
	if !manifestengine.WorkflowUsesIdentityProvisioningSnapshot(spec) {
		return nil
	}
	if len(spec.Steps) != 1 {
		return errIdentityProvisioningUnavailable
	}
	step := spec.Steps[0]
	if step.ID != "list-collaborators" || !strings.EqualFold(strings.TrimSpace(step.Use.Kind), "yggdrasil") ||
		strings.ToLower(strings.TrimSpace(step.Use.Operation)) != "collaborator.provisioning_snapshot" ||
		len(step.With) != 0 || step.ForEach != nil || len(step.DependsOn) != 0 ||
		(strings.TrimSpace(step.Condition) != "" && strings.TrimSpace(step.Condition) != "false") {
		return errIdentityProvisioningUnavailable
	}
	pinnedID, err := uuid.Parse(strings.TrimSpace(os.Getenv(identityProvisioningManifestIDEnv)))
	if err != nil || pinnedID == uuid.Nil || workflow.ID != pinnedID ||
		!strings.EqualFold(strings.TrimSpace(workflow.Kind), "workflow") ||
		!workflow.Metadata.Active || workflow.Metadata.Namespace != "dakasa" ||
		workflow.Metadata.Name != "reconcile-identity-providers" ||
		spec.Authorization == nil ||
		!strings.EqualFold(strings.TrimSpace(spec.Trigger.Mode), "manual") ||
		spec.Trigger.Enabled == nil || *spec.Trigger.Enabled ||
		len(req.Inputs) != 0 || len(req.Metadata) != 0 || strings.TrimSpace(req.Auth.Token) != "" {
		return errIdentityProvisioningUnavailable
	}
	return nil
}

func executeIdentityProvisioningSnapshot(
	ctx context.Context,
	db *sql.DB,
	workflow model.Manifest,
	result model.WorkflowRunStepResult,
) model.WorkflowRunStepResult {
	result.Attempts = 1
	pinnedID, err := uuid.Parse(strings.TrimSpace(os.Getenv(identityProvisioningManifestIDEnv)))
	if db == nil || err != nil || pinnedID == uuid.Nil ||
		workflow.ID != pinnedID || !strings.EqualFold(strings.TrimSpace(workflow.Kind), "workflow") ||
		!workflow.Metadata.Active ||
		workflow.Metadata.Namespace != "dakasa" || workflow.Metadata.Name != "reconcile-identity-providers" ||
		result.ID != "list-collaborators" {
		result.Error = errIdentityProvisioningUnavailable.Error()
		result.FinishedAt = time.Now().UTC()
		return result
	}
	// The repository locks and rechecks this exact manifest row in the same
	// transaction as the projection. A replacement between dispatch and read
	// cannot inherit the old pin or leak a stale snapshot.
	identities, err := repository.ListCollaboratorProvisioningIdentities(ctx, db, workflow.ID, identityProvisioningMaxPeople)
	if err != nil || len(identities) > identityProvisioningMaxPeople {
		result.Error = errIdentityProvisioningUnavailable.Error()
		result.FinishedAt = time.Now().UTC()
		return result
	}
	seenEmails := make(map[string]struct{}, len(identities))
	for _, person := range identities {
		status := collaboratorstate.Status(person.Status)
		email := strings.TrimSpace(person.PrimaryEmail)
		emailKey := strings.ToLower(email)
		if !collaboratorstate.IsKnown(status) || email == "" {
			result.Error = errIdentityProvisioningUnavailable.Error()
			result.FinishedAt = time.Now().UTC()
			return result
		}
		if _, duplicate := seenEmails[emailKey]; duplicate {
			result.Error = errIdentityProvisioningUnavailable.Error()
			result.FinishedAt = time.Now().UTC()
			return result
		}
		seenEmails[emailKey] = struct{}{}
	}
	result.Status = "succeeded"
	result.Metadata = map[string]any{"total_count": len(identities)}
	result.FinishedAt = time.Now().UTC()
	return result
}
