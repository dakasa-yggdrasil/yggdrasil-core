package manifest

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

// tenantSlugPattern requires 2-63 chars, lowercase alphanumeric or hyphens,
// starting and ending with alphanumeric. Single-char slugs are rejected to
// avoid collisions with kubernetes-style "a"/"b" labels and to keep audit
// log entries readable.
var tenantSlugPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,61}[a-z0-9]$`)

// ParseTenantSpec parses the raw spec payload.
func ParseTenantSpec(raw json.RawMessage) (model.TenantManifestSpec, error) {
	var spec model.TenantManifestSpec
	if err := json.Unmarshal(raw, &spec); err != nil {
		return model.TenantManifestSpec{}, fmt.Errorf("parse tenant spec: %w", err)
	}
	return spec, nil
}

// ValidateTenantSpec validates one tenant manifest.
func ValidateTenantSpec(spec model.TenantManifestSpec) error {
	slug := strings.TrimSpace(spec.Slug)
	if !tenantSlugPattern.MatchString(slug) {
		return fmt.Errorf("tenant slug must match ^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
	}
	for i, o := range spec.Owners {
		o = strings.TrimSpace(o)
		if o == "" {
			return fmt.Errorf("tenant owners[%d] must not be empty", i)
		}
		// owner format: "<kind>:<id>" with kind in {user, team, service}
		parts := strings.SplitN(o, ":", 2)
		if len(parts) != 2 || (parts[0] != "user" && parts[0] != "team" && parts[0] != "service") {
			return fmt.Errorf("tenant owners[%d] must be 'user:<id>', 'team:<name>' or 'service:<name>'; got %q", i, o)
		}
	}
	if q := spec.Quotas; q != nil {
		for name, v := range map[string]int{
			"max_projects":                q.MaxProjects,
			"max_manifests":               q.MaxManifests,
			"max_workflow_runs_per_day":   q.MaxWorkflowRunsPerDay,
			"max_secrets":                 q.MaxSecrets,
			"max_ephemeral_environments":  q.MaxEphemeralEnvironments,
			"max_integration_instances":   q.MaxIntegrationInstances,
		} {
			if v < 0 {
				return fmt.Errorf("tenant quotas.%s must be >= 0 (use 0 for no cap)", name)
			}
		}
	}
	return validateLooseObject("tenant metadata", spec.Metadata)
}

// NormalizeTenantSpec applies compatibility defaults.
func NormalizeTenantSpec(spec model.TenantManifestSpec) model.TenantManifestSpec {
	spec.Slug = strings.ToLower(strings.TrimSpace(spec.Slug))
	spec.DisplayName = strings.TrimSpace(spec.DisplayName)
	spec.Description = strings.TrimSpace(spec.Description)
	for i, o := range spec.Owners {
		spec.Owners[i] = strings.TrimSpace(o)
	}
	if spec.Metadata == nil {
		spec.Metadata = map[string]any{}
	}
	return spec
}
