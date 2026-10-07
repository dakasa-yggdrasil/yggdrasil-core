package model

import "time"

// DirectorySnapshotPage is a bounded page of one principal/projection revision.
// Complete means this is the terminal page, not that a consumer received all
// earlier pages. Consumers must collect offsets 0..TotalRecords of one revision
// before replacing a directory projection or deactivating absent identities.
type DirectorySnapshotPage struct {
	SchemaVersion      int                         `json:"schema_version"`
	Revision           string                      `json:"revision"`
	ObservedAt         time.Time                   `json:"observed_at"`
	Offset             int                         `json:"offset"`
	Limit              int                         `json:"limit"`
	TotalRecords       int                         `json:"total_records"`
	Complete           bool                        `json:"complete"`
	NextCursor         string                      `json:"next_cursor,omitempty"`
	ContactsIncluded   bool                        `json:"contacts_included"`
	Collaborators      []DirectoryCollaborator     `json:"collaborators"`
	Teams              []DirectoryTeam             `json:"teams"`
	Memberships        []DirectoryMembership       `json:"memberships"`
	ExternalIdentities []DirectoryExternalIdentity `json:"external_identities"`
	PhoneContacts      []DirectoryPhoneContact     `json:"phone_contacts,omitempty"`
}

type DirectoryCollaborator struct {
	PhoneProfileRequired bool      `json:"phone_profile_required"`
	ID                   string    `json:"id"`
	Slug                 string    `json:"slug"`
	DisplayName          string    `json:"display_name"`
	Status               string    `json:"status"`
	ManagerID            *string   `json:"manager_id,omitempty"`
	PrimaryTeamID        *string   `json:"primary_team_id,omitempty"`
	Version              int       `json:"version"`
	UpdatedAt            time.Time `json:"updated_at"`
}

type DirectoryTeam struct {
	ID           string    `json:"id"`
	Slug         string    `json:"slug"`
	Name         string    `json:"name"`
	Type         string    `json:"type"`
	Status       string    `json:"status"`
	ParentTeamID *string   `json:"parent_team_id,omitempty"`
	OwnerIDs     []string  `json:"owner_ids"`
	UpdatedAt    time.Time `json:"updated_at"`
}

// Membership preserves the canonical Core authority window. Active membership
// in an active team confers authority at ObservedAt when StartsAt<=ObservedAt
// and EndsAt>=ObservedAt (nil bounds are open). Collaborator lifecycle remains
// separate; membership never changes a collaborator lifecycle status.
type DirectoryMembership struct {
	ID             string     `json:"id"`
	TeamID         string     `json:"team_id"`
	CollaboratorID string     `json:"collaborator_id"`
	Active         bool       `json:"active"`
	IsLead         bool       `json:"is_lead"`
	StartsAt       *time.Time `json:"starts_at,omitempty"`
	EndsAt         *time.Time `json:"ends_at,omitempty"`
	UpdatedAt      time.Time  `json:"updated_at"`
}

type DirectoryExternalIdentity struct {
	ID                    string    `json:"id"`
	CollaboratorID        string    `json:"collaborator_id"`
	IntegrationInstanceID string    `json:"integration_instance_id"`
	ExternalID            string    `json:"external_id"`
	UpdatedAt             time.Time `json:"updated_at"`
}

// State is missing, declared or ambiguous. Ambiguous associations deliberately
// omit the number, so a consumer cannot select one person for that destination.
// Assurance never claims OTP verification, consent or channel engagement.
type DirectoryPhoneContact struct {
	CollaboratorID    string     `json:"collaborator_id"`
	State             string     `json:"state"`
	PhoneE164         string     `json:"phone_e164,omitempty"`
	Assurance         string     `json:"assurance,omitempty"`
	DeclaredAt        *time.Time `json:"declared_at,omitempty"`
	DeclarationSource string     `json:"declaration_source,omitempty"`
	Version           int64      `json:"version,omitempty"`
}
