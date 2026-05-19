package model

import (
	"time"

	"github.com/google/uuid"
)

// Collaborator is the canonical internal subject managed by yggdrasil-core.
//
// Version is the row's optimistic-locking sequence; it is bumped by every
// successful UpdateCollaborator. Callers receive the post-update value and may
// stash it for subsequent updates if they wish to detect concurrent writes
// explicitly. UpdateCollaborator transparently uses the loaded value for its
// own conflict check via repository.ErrConcurrentUpdate.
type Collaborator struct {
	ID                   uuid.UUID      `json:"id"`
	Slug                 string         `json:"slug"`
	Status               string         `json:"status"`
	DisplayName          string         `json:"display_name"`
	PrimaryEmail         string         `json:"primary_email"`
	ManagerID            *uuid.UUID     `json:"manager_id,omitempty"`
	PrimaryTeamID        *uuid.UUID     `json:"primary_team_id,omitempty"`
	PersonalData         map[string]any `json:"personal_data"`
	EmploymentData       map[string]any `json:"employment_data"`
	ThirdPartyIdentities map[string]any `json:"third_party_identities"`
	Traits               map[string]any `json:"traits"`
	Metadata             map[string]any `json:"metadata"`
	Version              int            `json:"version"`
	CreatedAt            time.Time      `json:"created_at"`
	UpdatedAt            time.Time      `json:"updated_at"`
}

// Team is the canonical internal group used to aggregate collaborators.
type Team struct {
	ID           uuid.UUID      `json:"id"`
	Slug         string         `json:"slug"`
	Name         string         `json:"name"`
	Type         string         `json:"type"`
	Status       string         `json:"status"`
	// Email is the team's canonical contact address. Integrations may use
	// it to provision external resources (Google Workspace group, Slack
	// channel email, notification targets). Empty string = unset.
	Email        string         `json:"email,omitempty"`
	ParentTeamID *uuid.UUID     `json:"parent_team_id,omitempty"`
	Owners       []string       `json:"owners"`
	Traits       map[string]any `json:"traits"`
	Metadata     map[string]any `json:"metadata"`
	CreatedAt    time.Time      `json:"created_at"`
	UpdatedAt    time.Time      `json:"updated_at"`
}

// TeamMembership links a collaborator to one team.
type TeamMembership struct {
	ID               uuid.UUID      `json:"id"`
	TeamID           uuid.UUID      `json:"team_id"`
	TeamSlug         string         `json:"team_slug"`
	CollaboratorID   uuid.UUID      `json:"collaborator_id"`
	CollaboratorSlug string         `json:"collaborator_slug"`
	Role             string         `json:"role"`
	Active           bool           `json:"active"`
	Source           string         `json:"source"`
	StartsAt         *time.Time     `json:"starts_at,omitempty"`
	EndsAt           *time.Time     `json:"ends_at,omitempty"`
	Metadata         map[string]any `json:"metadata"`
	CreatedAt        time.Time      `json:"created_at"`
	UpdatedAt        time.Time      `json:"updated_at"`
}

// CollaboratorReference is the lightweight collaborator identity used in authorization responses.
type CollaboratorReference struct {
	ID     uuid.UUID `json:"id"`
	Slug   string    `json:"slug"`
	Status string    `json:"status"`
}

// TeamReference is the lightweight team identity used in authorization responses.
type TeamReference struct {
	ID   uuid.UUID `json:"id"`
	Slug string    `json:"slug"`
	Name string    `json:"name"`
	Type string    `json:"type"`
}

// CreateCollaboratorRequest creates one collaborator record.
type CreateCollaboratorRequest struct {
	Slug                 string         `json:"slug"`
	Status               string         `json:"status,omitempty"`
	DisplayName          string         `json:"display_name"`
	PrimaryEmail         string         `json:"primary_email,omitempty"`
	ManagerID            string         `json:"manager_id,omitempty"`
	PrimaryTeamID        string         `json:"primary_team_id,omitempty"`
	PersonalData         map[string]any `json:"personal_data,omitempty"`
	EmploymentData       map[string]any `json:"employment_data,omitempty"`
	ThirdPartyIdentities map[string]any `json:"third_party_identities,omitempty"`
	Traits               map[string]any `json:"traits,omitempty"`
	Metadata             map[string]any `json:"metadata,omitempty"`
}

// UpdateCollaboratorRequest updates one collaborator record with patch semantics.
type UpdateCollaboratorRequest struct {
	ID                   string          `json:"id"`
	Slug                 *string         `json:"slug,omitempty"`
	Status               *string         `json:"status,omitempty"`
	DisplayName          *string         `json:"display_name,omitempty"`
	PrimaryEmail         *string         `json:"primary_email,omitempty"`
	ManagerID            *string         `json:"manager_id,omitempty"`
	PrimaryTeamID        *string         `json:"primary_team_id,omitempty"`
	PersonalData         *map[string]any `json:"personal_data,omitempty"`
	EmploymentData       *map[string]any `json:"employment_data,omitempty"`
	ThirdPartyIdentities *map[string]any `json:"third_party_identities,omitempty"`
	Traits               *map[string]any `json:"traits,omitempty"`
	Metadata             *map[string]any `json:"metadata,omitempty"`

	// ExpectedVersion, when non-nil, switches UpdateCollaborator into strict
	// optimistic-locking mode: the UPDATE only commits if the row's current
	// version equals this value, otherwise repository.ErrConcurrentUpdate is
	// returned. Callers that loaded the row in a previous transaction (or
	// across HTTP requests) should pass the version they saw, so a concurrent
	// writer bumping it in the meantime flips them to retry-or-409. When nil,
	// UpdateCollaborator transparently re-loads the row inside the same call
	// — the race window collapses to the time between SELECT and UPDATE in
	// the function, which is acceptable for short patches.
	ExpectedVersion *int `json:"expected_version,omitempty"`
}

// GetCollaboratorRequest fetches one collaborator by UUID or slug.
type GetCollaboratorRequest struct {
	ID string `json:"id"`
}

// DeleteCollaboratorRequest removes one collaborator by UUID or slug.
type DeleteCollaboratorRequest struct {
	ID string `json:"id"`
}

// ListCollaboratorsRequest filters collaborator listing.
// Search is a case-insensitive substring matched against display_name,
// slug, and primary_email — used by the console "add person to team"
// modal so 1k+ collaborators stay usable without paging through everything.
type ListCollaboratorsRequest struct {
	Status string `json:"status,omitempty"`
	Search string `json:"search,omitempty"`
}

// CreateTeamRequest creates one team record.
type CreateTeamRequest struct {
	Slug         string         `json:"slug"`
	Name         string         `json:"name"`
	Type         string         `json:"type,omitempty"`
	Status       string         `json:"status,omitempty"`
	Email        string         `json:"email,omitempty"`
	ParentTeamID string         `json:"parent_team_id,omitempty"`
	Owners       []string       `json:"owners,omitempty"`
	Traits       map[string]any `json:"traits,omitempty"`
	Metadata     map[string]any `json:"metadata,omitempty"`
}

// UpdateTeamRequest updates one team record with patch semantics.
type UpdateTeamRequest struct {
	ID           string          `json:"id"`
	Slug         *string         `json:"slug,omitempty"`
	Name         *string         `json:"name,omitempty"`
	Type         *string         `json:"type,omitempty"`
	Status       *string         `json:"status,omitempty"`
	Email        *string         `json:"email,omitempty"`
	ParentTeamID *string         `json:"parent_team_id,omitempty"`
	Owners       *[]string       `json:"owners,omitempty"`
	Traits       *map[string]any `json:"traits,omitempty"`
	Metadata     *map[string]any `json:"metadata,omitempty"`
}

// GetTeamRequest fetches one team by UUID or slug.
type GetTeamRequest struct {
	ID string `json:"id"`
}

// DeleteTeamRequest removes one team by UUID or slug.
type DeleteTeamRequest struct {
	ID string `json:"id"`
}

// ListTeamsRequest filters team listing.
type ListTeamsRequest struct {
	Status string `json:"status,omitempty"`
	Type   string `json:"type,omitempty"`
}

// UpsertTeamMembershipRequest creates or updates one collaborator-team link.
type UpsertTeamMembershipRequest struct {
	TeamID         string         `json:"team_id"`
	CollaboratorID string         `json:"collaborator_id"`
	Role           string         `json:"role,omitempty"`
	Active         *bool          `json:"active,omitempty"`
	Source         string         `json:"source,omitempty"`
	StartsAt       *time.Time     `json:"starts_at,omitempty"`
	EndsAt         *time.Time     `json:"ends_at,omitempty"`
	Metadata       map[string]any `json:"metadata,omitempty"`
}

// ListTeamMembershipsRequest filters memberships by team/collaborator.
type ListTeamMembershipsRequest struct {
	TeamID         string `json:"team_id,omitempty"`
	CollaboratorID string `json:"collaborator_id,omitempty"`
	ActiveOnly     bool   `json:"active_only,omitempty"`
}

// TeamGrant binds one team to an action of one integration_instance.
// action_name = "*" means wildcard (all actions of that integration_instance).
type TeamGrant struct {
	ID                            string         `json:"id"`
	TeamID                        string         `json:"team_id"`
	IntegrationInstanceNamespace  string         `json:"integration_instance_namespace"`
	IntegrationInstanceName       string         `json:"integration_instance_name"`
	ActionName                    string         `json:"action_name"`
	Scope                         map[string]any `json:"scope"`
	GrantedAt                     time.Time      `json:"granted_at"`
	GrantedBy                     *string        `json:"granted_by,omitempty"`
}

// GrantTeamActionRequest grants one team an action of one integration_instance.
type GrantTeamActionRequest struct {
	TeamID                        string         `json:"team_id"`
	IntegrationInstanceNamespace  string         `json:"integration_instance_namespace"`
	IntegrationInstanceName       string         `json:"integration_instance_name"`
	ActionName                    string         `json:"action_name,omitempty"`
	Scope                         map[string]any `json:"scope,omitempty"`
	GrantedBy                     string         `json:"granted_by,omitempty"`
}

// ListTeamGrantsRequest filters grants by team.
type ListTeamGrantsRequest struct {
	TeamID string `json:"team_id,omitempty"`
}

// RevokeTeamGrantRequest removes one grant by id.
type RevokeTeamGrantRequest struct {
	GrantID string `json:"grant_id"`
}

// TeamGrantSource is one (namespace, name) pair representing an
// integration_instance that some team in a hierarchy holds a grant for.
// Returned by ListAvailableSourcesForTeam.
type TeamGrantSource struct {
	Namespace string `json:"integration_instance_namespace"`
	Name      string `json:"integration_instance_name"`
}
