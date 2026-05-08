package model

import (
	"time"

	"github.com/google/uuid"
)

// Permission is one entry in the global registry. Integrations declare
// their permissions at install via RegisterPermission; the catalog
// is single-tenant and authoritative.
type Permission struct {
	ID           uuid.UUID      `json:"id"`
	Name         string         `json:"name"`
	Description  string         `json:"description,omitempty"`
	RegisteredBy string         `json:"registered_by"`
	Metadata     map[string]any `json:"metadata"`
	CreatedAt    time.Time      `json:"created_at"`
	UpdatedAt    time.Time      `json:"updated_at"`
}

// RegisterPermissionRequest is the input to
// repository.RegisterPermission. Idempotent on (name): a second call
// with the same name updates description/metadata in place.
type RegisterPermissionRequest struct {
	Name         string         `json:"name"`
	Description  string         `json:"description,omitempty"`
	RegisteredBy string         `json:"registered_by"`
	Metadata     map[string]any `json:"metadata,omitempty"`
}

// RoleBinding maps one role to one permission. Multiple bindings per
// role accumulate (the role gets all bound permissions).
type RoleBinding struct {
	ID             uuid.UUID      `json:"id"`
	Role           string         `json:"role"`
	PermissionName string         `json:"permission_name"`
	BoundBy        string         `json:"bound_by,omitempty"`
	Metadata       map[string]any `json:"metadata"`
	CreatedAt      time.Time      `json:"created_at"`
}

// BindRoleToPermissionRequest is the input to
// repository.BindRoleToPermission. Idempotent on (role, permission_name).
type BindRoleToPermissionRequest struct {
	Role           string         `json:"role"`
	PermissionName string         `json:"permission_name"`
	BoundBy        string         `json:"bound_by,omitempty"`
	Metadata       map[string]any `json:"metadata,omitempty"`
}

// EvaluatePermissionRequest carries a subject (resolved to role + teams)
// and an action; the response says whether the subject's bound
// permissions include the action.
type EvaluatePermissionRequest struct {
	SubjectRole  string   `json:"subject_role"`
	SubjectTeams []string `json:"subject_teams,omitempty"`
	Permission   string   `json:"permission"`
}

type EvaluatePermissionResponse struct {
	Allowed         bool     `json:"allowed"`
	MatchedRole     string   `json:"matched_role,omitempty"`
	MatchedBindings []string `json:"matched_bindings,omitempty"`
}

// ListPermissionsRequest filters the catalog query.
type ListPermissionsRequest struct {
	RegisteredBy string `json:"registered_by,omitempty"`
	NamePrefix   string `json:"name_prefix,omitempty"`
}

// ListBindingsRequest filters the bindings query.
type ListBindingsRequest struct {
	Role           string `json:"role,omitempty"`
	PermissionName string `json:"permission_name,omitempty"`
}
