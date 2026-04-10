package model

import (
	"time"

	"github.com/google/uuid"
)

// Collaborator is the canonical internal subject managed by yggdrasil-core.
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
type ListCollaboratorsRequest struct {
	Status string `json:"status,omitempty"`
}

// CreateTeamRequest creates one team record.
type CreateTeamRequest struct {
	Slug         string         `json:"slug"`
	Name         string         `json:"name"`
	Type         string         `json:"type,omitempty"`
	Status       string         `json:"status,omitempty"`
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
