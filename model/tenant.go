package model

import (
	"time"

	"github.com/google/uuid"
)

// TenantManifestSpec declares a top-level tenancy unit. Tenants are
// the outer boundary of multi-tenant isolation in Yggdrasil v2.3+:
// each tenant has its own slug, billing identity, and default RBAC
// root. Other manifests carry an optional `metadata.tenant` annotation
// referencing the tenant slug; in v2.3 this is informational, in v3
// it becomes a server-side enforced authorization scope.
type TenantManifestSpec struct {
	// Slug is the unique short identifier (lower-case, alphanumeric + hyphens).
	// All cross-manifest references use this string.
	Slug string `json:"slug"`

	// DisplayName is the human-readable label shown in surfaces and audit logs.
	DisplayName string `json:"display_name,omitempty"`

	// Description explains the tenant's purpose for human reviewers.
	Description string `json:"description,omitempty"`

	// Owners are the principals who can administer tenant-scoped manifests.
	// Format follows the rbac convention: "user:<id>", "team:<name>", "service:<name>".
	Owners []string `json:"owners,omitempty"`

	// BillingRef is an opaque adopter-defined reference (e.g. Stripe customer ID,
	// internal cost-centre code). Yggdrasil does not interpret it but surfaces
	// emit it on audit/metrics.
	BillingRef string `json:"billing_ref,omitempty"`

	// Quotas declare per-tenant ceilings. Optional in v2.3 (informational);
	// enforced in v3.
	Quotas *TenantQuotas `json:"quotas,omitempty"`

	// Metadata is a free-form bag for adopter-side annotations.
	Metadata map[string]any `json:"metadata,omitempty"`
}

// TenantQuotas caps tenant-scoped resource counts. Each value 0 means "no cap".
type TenantQuotas struct {
	MaxProjects              int `json:"max_projects,omitempty"`
	MaxManifests             int `json:"max_manifests,omitempty"`
	MaxWorkflowRunsPerDay    int `json:"max_workflow_runs_per_day,omitempty"`
	MaxSecrets               int `json:"max_secrets,omitempty"`
	MaxEphemeralEnvironments int `json:"max_ephemeral_environments,omitempty"`
	MaxIntegrationInstances  int `json:"max_integration_instances,omitempty"`
}

// TenantBrand is the organization profile shown by generic Yggdrasil surfaces.
type TenantBrand struct {
	Name           string     `json:"name"`
	ShortName      string     `json:"short_name"`
	ProductLabel   string     `json:"product_label"`
	Locale         string     `json:"locale"`
	AccentOverride string     `json:"accent_override,omitempty"`
	LogoURL        string     `json:"logo_url,omitempty"`
	SupportEmail   string     `json:"support_email,omitempty"`
	UpdatedBy      *uuid.UUID `json:"updated_by,omitempty"`
	CreatedAt      time.Time  `json:"created_at,omitempty"`
	UpdatedAt      time.Time  `json:"updated_at,omitempty"`
}

type UpdateTenantBrandRequest struct {
	Name           string `json:"name"`
	ShortName      string `json:"short_name"`
	ProductLabel   string `json:"product_label"`
	Locale         string `json:"locale"`
	AccentOverride string `json:"accent_override,omitempty"`
	LogoURL        string `json:"logo_url,omitempty"`
	SupportEmail   string `json:"support_email,omitempty"`
}

func DefaultTenantBrand() TenantBrand {
	return TenantBrand{
		Name:         "Sua organização",
		ShortName:    "ORG",
		ProductLabel: "Yggdrasil Console",
		Locale:       "pt-BR",
	}
}
