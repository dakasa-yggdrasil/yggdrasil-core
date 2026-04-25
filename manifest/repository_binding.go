package manifest

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

var (
	supportedRepositoryBindingComponentKinds = []string{"product", "surface", "integration", "repository"}
	repositorySlugPattern                    = regexp.MustCompile(`^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$`)
)

const (
	workflowKindYggdrasil     = "yggdrasil"
	workflowKindGithubActions = "github_actions"
)

// ParseRepositoryBindingSpec parses the raw spec payload into the typed manifest.
func ParseRepositoryBindingSpec(raw json.RawMessage) (model.RepositoryBindingManifestSpec, error) {
	var spec model.RepositoryBindingManifestSpec
	if err := json.Unmarshal(raw, &spec); err != nil {
		return model.RepositoryBindingManifestSpec{}, fmt.Errorf("parse repository_binding spec: %w", err)
	}
	return spec, nil
}

// ValidateRepositoryBindingSpec validates one repository binding manifest.
func ValidateRepositoryBindingSpec(spec model.RepositoryBindingManifestSpec) error {
	componentKind := strings.ToLower(strings.TrimSpace(spec.ComponentKind))
	if !slices.Contains(supportedRepositoryBindingComponentKinds, componentKind) {
		return fmt.Errorf("repository_binding component_kind %q is unsupported", spec.ComponentKind)
	}

	componentName := normalizeIntegrationName(spec.ComponentName)
	if componentName == "" {
		return fmt.Errorf("repository_binding component_name is required")
	}

	repository := strings.TrimSpace(spec.Repository)
	if !repositorySlugPattern.MatchString(repository) {
		return fmt.Errorf("repository_binding repository must use owner/name format")
	}

	if branch := strings.TrimSpace(spec.DefaultBranch); strings.Contains(branch, " ") {
		return fmt.Errorf("repository_binding default_branch cannot contain spaces")
	}
	if workflow := strings.TrimSpace(spec.DeployWorkflow); workflow != "" && !strings.HasSuffix(workflow, ".yml") && !strings.HasSuffix(workflow, ".yaml") {
		return fmt.Errorf("repository_binding deploy_workflow must be a workflow filename")
	}

	if err := validateRepositoryBindingDeploy(spec.Deploy); err != nil {
		return err
	}

	if err := validateLooseObject("repository_binding metadata", spec.Metadata); err != nil {
		return err
	}
	return nil
}

// validateRepositoryBindingDeploy validates the optional deploy block. Returns
// nil when spec is nil. Enforces workflow_kind enum, workflow_ref presence for
// yggdrasil dispatch, and well-formed path_filter glob patterns.
func validateRepositoryBindingDeploy(spec *model.RepositoryBindingDeploySpec) error {
	if spec == nil {
		return nil
	}
	kind := strings.ToLower(strings.TrimSpace(spec.WorkflowKind))
	switch kind {
	case workflowKindYggdrasil:
		if spec.WorkflowRef == nil {
			return fmt.Errorf("repository_binding deploy.workflow_ref is required when workflow_kind is %q", workflowKindYggdrasil)
		}
		if strings.TrimSpace(spec.WorkflowRef.Name) == "" {
			return fmt.Errorf("repository_binding deploy.workflow_ref.name is required")
		}
	case workflowKindGithubActions:
		// No required fields beyond workflow_kind in v2.0.0.
	case "":
		return fmt.Errorf("repository_binding deploy.workflow_kind is required")
	default:
		return fmt.Errorf("repository_binding deploy.workflow_kind %q is unsupported (expected %q or %q)",
			spec.WorkflowKind, workflowKindYggdrasil, workflowKindGithubActions)
	}

	for _, glob := range spec.PathFilter {
		if _, err := filepath.Match(glob, ""); err != nil {
			return fmt.Errorf("repository_binding deploy.path_filter %q is malformed: %w", glob, err)
		}
	}
	return nil
}

// NormalizeRepositoryBindingSpec applies compatibility defaults to repository bindings.
func NormalizeRepositoryBindingSpec(spec model.RepositoryBindingManifestSpec) model.RepositoryBindingManifestSpec {
	spec.ComponentKind = strings.ToLower(strings.TrimSpace(spec.ComponentKind))
	spec.ComponentName = normalizeIntegrationName(spec.ComponentName)
	spec.ComponentNamespace = strings.ToLower(strings.TrimSpace(spec.ComponentNamespace))
	if spec.ComponentNamespace == "" {
		spec.ComponentNamespace = "global"
	}
	spec.Repository = strings.TrimSpace(spec.Repository)
	spec.DefaultBranch = strings.TrimSpace(spec.DefaultBranch)
	if spec.DefaultBranch == "" {
		spec.DefaultBranch = "main"
	}
	spec.DeployWorkflow = strings.TrimSpace(spec.DeployWorkflow)
	if spec.DeployWorkflow == "" {
		spec.DeployWorkflow = "deploy.yml"
	}
	if spec.Metadata == nil {
		spec.Metadata = map[string]any{}
	}
	spec.Automation = NormalizeRepositoryBindingAutomation(spec.Automation)
	if spec.Deploy != nil {
		spec.Deploy.WorkflowKind = strings.ToLower(strings.TrimSpace(spec.Deploy.WorkflowKind))
		if spec.Deploy.WorkflowRef != nil {
			spec.Deploy.WorkflowRef.Namespace = strings.ToLower(strings.TrimSpace(spec.Deploy.WorkflowRef.Namespace))
			if spec.Deploy.WorkflowRef.Namespace == "" {
				spec.Deploy.WorkflowRef.Namespace = "global"
			}
			spec.Deploy.WorkflowRef.Name = strings.TrimSpace(spec.Deploy.WorkflowRef.Name)
		}
		if len(spec.Deploy.BranchFilter) == 0 {
			spec.Deploy.BranchFilter = []string{"main"}
		}
	}
	return spec
}

// NormalizeRepositoryBindingAutomation applies compatibility defaults to repository automation settings.
func NormalizeRepositoryBindingAutomation(spec model.RepositoryBindingAutomationSpec) model.RepositoryBindingAutomationSpec {
	if !spec.Observe && !spec.AllowDispatchWorkflow && !spec.AllowPullRequestAutomation && !spec.AllowDirectPush {
		spec.Observe = true
	}
	return spec
}
