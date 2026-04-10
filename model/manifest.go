package model

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

// ManifestDocument is the payload accepted by the API before persistence metadata is added.
type ManifestDocument struct {
	APIVersion string                `json:"apiVersion"`
	Kind       string                `json:"kind"`
	Metadata   ManifestMetadataInput `json:"metadata"`
	Spec       json.RawMessage       `json:"spec"`
}

// ManifestMetadataInput is the incoming manifest metadata payload.
type ManifestMetadataInput struct {
	Name        string            `json:"name"`
	Namespace   string            `json:"namespace"`
	Description string            `json:"description,omitempty"`
	Labels      map[string]string `json:"labels,omitempty"`
	Active      *bool             `json:"active,omitempty"`
}

// ManifestMetadata is the persisted manifest metadata.
type ManifestMetadata struct {
	Name        string            `json:"name"`
	Namespace   string            `json:"namespace"`
	Description string            `json:"description,omitempty"`
	Labels      map[string]string `json:"labels,omitempty"`
	Active      bool              `json:"active"`
}

// Manifest is the stored manifest record.
type Manifest struct {
	ID         uuid.UUID        `json:"id"`
	APIVersion string           `json:"apiVersion"`
	Kind       string           `json:"kind"`
	Metadata   ManifestMetadata `json:"metadata"`
	Version    int              `json:"version"`
	Checksum   string           `json:"checksum"`
	Spec       json.RawMessage  `json:"spec"`
	CreatedAt  time.Time        `json:"created_at"`
	UpdatedAt  time.Time        `json:"updated_at"`
}

// ListManifestFilters constrains list queries.
type ListManifestFilters struct {
	Kind       string
	Namespace  string
	Name       string
	Labels     map[string]string
	ActiveOnly bool
}

// ListManifestRequest is the RabbitMQ payload for listing manifests.
type ListManifestRequest struct {
	Kind       string            `json:"kind,omitempty"`
	Namespace  string            `json:"namespace,omitempty"`
	Name       string            `json:"name,omitempty"`
	Labels     map[string]string `json:"labels,omitempty"`
	ActiveOnly bool              `json:"active_only,omitempty"`
}

// GetManifestRequest is the RabbitMQ payload for fetching a manifest by id.
type GetManifestRequest struct {
	ID string `json:"id"`
}

// RBACManifestSpec is the first manifest kind supported by yggdrasil-core.
type RBACManifestSpec struct {
	Roles    []RBACRole    `json:"roles"`
	Bindings []RBACBinding `json:"bindings"`
}

// RBACRole defines a named collection of rules.
type RBACRole struct {
	Name        string     `json:"name"`
	Description string     `json:"description,omitempty"`
	Rules       []RBACRule `json:"rules"`
}

// RBACRule defines which resources and actions are allowed or denied.
type RBACRule struct {
	Description string   `json:"description,omitempty"`
	Effect      string   `json:"effect,omitempty"`
	Resources   []string `json:"resources"`
	Actions     []string `json:"actions"`
}

// RBACBinding connects subjects to roles.
type RBACBinding struct {
	Name     string        `json:"name"`
	Subjects []RBACSubject `json:"subjects"`
	Roles    []string      `json:"roles"`
}

// RBACSubject identifies a caller handled by Yggdrasil.
type RBACSubject struct {
	Type string `json:"type"`
	ID   string `json:"id"`
}

// EvaluateRBACRequest resolves a stored RBAC manifest and evaluates a decision.
type EvaluateRBACRequest struct {
	ManifestID string      `json:"manifest_id,omitempty"`
	Namespace  string      `json:"namespace,omitempty"`
	Name       string      `json:"name,omitempty"`
	Version    *int        `json:"version,omitempty"`
	Subject    RBACSubject `json:"subject"`
	Resource   string      `json:"resource"`
	Action     string      `json:"action"`
}

// PolicyManifestSpec is the second manifest kind supported by yggdrasil-core.
type PolicyManifestSpec struct {
	Rules []PolicyRule `json:"rules"`
}

// PolicyRule defines conditional authorization logic.
type PolicyRule struct {
	Name        string            `json:"name"`
	Description string            `json:"description,omitempty"`
	Effect      string            `json:"effect,omitempty"`
	Resources   []string          `json:"resources"`
	Actions     []string          `json:"actions"`
	Conditions  []PolicyCondition `json:"conditions,omitempty"`
}

// PolicyCondition checks a dynamic input attribute using a supported operator.
type PolicyCondition struct {
	Key      string `json:"key"`
	Operator string `json:"operator"`
	Value    any    `json:"value,omitempty"`
}

// EvaluatePolicyRequest resolves a stored policy manifest and evaluates it against runtime input.
type EvaluatePolicyRequest struct {
	ManifestID string         `json:"manifest_id,omitempty"`
	Namespace  string         `json:"namespace,omitempty"`
	Name       string         `json:"name,omitempty"`
	Version    *int           `json:"version,omitempty"`
	Resource   string         `json:"resource"`
	Action     string         `json:"action"`
	Input      map[string]any `json:"input,omitempty"`
}

// ManifestSelector resolves a stored manifest by id or by namespace/name/version.
type ManifestSelector struct {
	ManifestID string `json:"manifest_id,omitempty"`
	Namespace  string `json:"namespace,omitempty"`
	Name       string `json:"name,omitempty"`
	Version    *int   `json:"version,omitempty"`
}

// EvaluateAuthorizationRequest resolves RBAC and optional policy manifests into one final decision.
type EvaluateAuthorizationRequest struct {
	RBAC           ManifestSelector  `json:"rbac"`
	Policy         *ManifestSelector `json:"policy,omitempty"`
	CollaboratorID string            `json:"collaborator_id,omitempty"`
	Subject        RBACSubject       `json:"subject,omitempty"`
	Resource       string            `json:"resource"`
	Action         string            `json:"action"`
	Input          map[string]any    `json:"input,omitempty"`
}

// ManifestReference is a lightweight manifest identity.
type ManifestReference struct {
	ID        uuid.UUID `json:"id"`
	Kind      string    `json:"kind"`
	Namespace string    `json:"namespace"`
	Name      string    `json:"name"`
	Version   int       `json:"version"`
}

// RBACRuleMatch describes a rule used during decision calculation.
type RBACRuleMatch struct {
	Role        string   `json:"role"`
	Effect      string   `json:"effect"`
	Description string   `json:"description,omitempty"`
	Resources   []string `json:"resources"`
	Actions     []string `json:"actions"`
}

// EvaluateRBACResponse contains the resolved RBAC decision.
type EvaluateRBACResponse struct {
	Allowed      bool              `json:"allowed"`
	Decision     string            `json:"decision"`
	Manifest     ManifestReference `json:"manifest"`
	MatchedRoles []string          `json:"matched_roles"`
	MatchedRules []RBACRuleMatch   `json:"matched_rules"`
}

// PolicyConditionMatch records one satisfied policy condition.
type PolicyConditionMatch struct {
	Key      string `json:"key"`
	Operator string `json:"operator"`
	Expected any    `json:"expected,omitempty"`
	Actual   any    `json:"actual,omitempty"`
}

// PolicyRuleMatch describes a rule used during policy evaluation.
type PolicyRuleMatch struct {
	Name        string                 `json:"name"`
	Effect      string                 `json:"effect"`
	Description string                 `json:"description,omitempty"`
	Resources   []string               `json:"resources"`
	Actions     []string               `json:"actions"`
	Conditions  []PolicyConditionMatch `json:"conditions,omitempty"`
}

// EvaluatePolicyResponse contains the resolved policy decision.
type EvaluatePolicyResponse struct {
	Allowed      bool              `json:"allowed"`
	Decision     string            `json:"decision"`
	Manifest     ManifestReference `json:"manifest"`
	MatchedRules []PolicyRuleMatch `json:"matched_rules"`
}

// EvaluateAuthorizationResponse contains the final authorization decision together with the RBAC and policy traces.
type EvaluateAuthorizationResponse struct {
	Allowed          bool                    `json:"allowed"`
	Decision         string                  `json:"decision"`
	ResolvedSubjects []RBACSubject           `json:"resolved_subjects,omitempty"`
	Collaborator     *CollaboratorReference  `json:"collaborator,omitempty"`
	Teams            []TeamReference         `json:"teams,omitempty"`
	RBAC             EvaluateRBACResponse    `json:"rbac"`
	Policy           *EvaluatePolicyResponse `json:"policy,omitempty"`
}
