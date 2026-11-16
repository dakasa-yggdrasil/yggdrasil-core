package message

import (
	"errors"
	"strings"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/coreprocess"
	manifestengine "github.com/dakasa-yggdrasil/yggdrasil-core/manifest"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

// Enforced at the actual resolved execution boundary, including nested runs.
// An HTTP preflight of a prior version is not this check. Caller metadata and
// workflow inputs cannot change the process's startup role.
func requireWorkflowProcessRole(spec model.WorkflowManifestSpec) error {
	role, err := coreprocess.FromEnvironment()
	if err != nil {
		return err
	}
	if role != coreprocess.APIWorker {
		return nil
	}
	for _, step := range spec.Steps {
		kind := strings.ToLower(strings.TrimSpace(step.Use.Kind))
		operation := manifestengine.NormalizeWorkflowStepOperation(step)
		capability := manifestengine.NormalizeWorkflowStepCapability(step)
		if (kind != "" && kind != "integration") || strings.EqualFold(operation, model.WorkflowDispatchOperation) || strings.EqualFold(capability, model.WorkflowDispatchOperation) || strings.HasPrefix(strings.ToLower(operation), "capacity.") || strings.HasPrefix(strings.ToLower(capability), "capacity.") {
			return errors.New("workflow requires configured control authority origin")
		}
	}
	return nil
}
