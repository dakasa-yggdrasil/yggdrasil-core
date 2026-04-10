package manifest

import (
	"encoding/json"
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

var (
	supportedRepositoryBindingComponentKinds = []string{"product", "surface", "integration", "repository"}
	repositorySlugPattern                    = regexp.MustCompile(`^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$`)
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

	if err := validateLooseObject("repository_binding metadata", spec.Metadata); err != nil {
		return err
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
	return spec
}

// NormalizeRepositoryBindingAutomation applies compatibility defaults to repository automation settings.
func NormalizeRepositoryBindingAutomation(spec model.RepositoryBindingAutomationSpec) model.RepositoryBindingAutomationSpec {
	if !spec.Observe && !spec.AllowDispatchWorkflow && !spec.AllowPullRequestAutomation && !spec.AllowDirectPush {
		spec.Observe = true
	}
	return spec
}
