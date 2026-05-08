package model

import (
	"time"

	"github.com/google/uuid"
)

// SCIMClient is one external service authorized to read User/Group resources
// over SCIM 2.0. BearerTokenHash is the only credential field stored.
type SCIMClient struct {
	ID              uuid.UUID              `json:"id"`
	Slug            string                 `json:"slug"`
	BearerTokenHash string                 `json:"-"`
	Permissions     map[string]string      `json:"permissions"`
	LastUsedAt      *time.Time             `json:"last_used_at,omitempty"`
	ExpiresAt       *time.Time             `json:"expires_at,omitempty"`
	RevokedAt       *time.Time             `json:"revoked_at,omitempty"`
	Metadata        map[string]interface{} `json:"metadata"`
	CreatedAt       time.Time              `json:"created_at"`
	UpdatedAt       time.Time              `json:"updated_at"`
}

// SCIMUser is the SCIM 2.0 User resource projected from a Collaborator +
// AuthIdentity. Read-only — Yggdrasil is the source of truth, downstream
// providers may only consume.
type SCIMUser struct {
	Schemas    []string         `json:"schemas"`
	ID         string           `json:"id"`
	ExternalID string           `json:"externalId,omitempty"`
	UserName   string           `json:"userName"`
	Name       SCIMName         `json:"name"`
	Active     bool             `json:"active"`
	Emails     []SCIMEmail      `json:"emails"`
	Enterprise *SCIMEnterprise  `json:"urn:ietf:params:scim:schemas:extension:enterprise:2.0:User,omitempty"`
	Meta       SCIMResourceMeta `json:"meta"`
}

type SCIMName struct {
	Formatted  string `json:"formatted"`
	GivenName  string `json:"givenName,omitempty"`
	FamilyName string `json:"familyName,omitempty"`
}

type SCIMEmail struct {
	Value   string `json:"value"`
	Type    string `json:"type,omitempty"`
	Primary bool   `json:"primary,omitempty"`
}

type SCIMEnterprise struct {
	EmployeeNumber string      `json:"employeeNumber,omitempty"`
	Department     string      `json:"department,omitempty"`
	CostCenter     string      `json:"costCenter,omitempty"`
	Manager        *SCIMRef    `json:"manager,omitempty"`
}

type SCIMRef struct {
	Value       string `json:"value"`
	DisplayName string `json:"displayName,omitempty"`
	Ref         string `json:"$ref,omitempty"`
}

type SCIMResourceMeta struct {
	ResourceType string    `json:"resourceType"`
	Created      time.Time `json:"created"`
	LastModified time.Time `json:"lastModified"`
	Location     string    `json:"location,omitempty"`
	Version      string    `json:"version,omitempty"`
}

// SCIMGroup is the SCIM 2.0 Group resource projected from a Team or
// role-derived synthetic group ("role:engineer", "team:platform").
type SCIMGroup struct {
	Schemas     []string         `json:"schemas"`
	ID          string           `json:"id"`
	ExternalID  string           `json:"externalId,omitempty"`
	DisplayName string           `json:"displayName"`
	Members     []SCIMGroupMember `json:"members"`
	Meta        SCIMResourceMeta `json:"meta"`
}

type SCIMGroupMember struct {
	Value   string `json:"value"`
	Display string `json:"display,omitempty"`
	Type    string `json:"type,omitempty"`
	Ref     string `json:"$ref,omitempty"`
}

// SCIMListResponse is the standard SCIM list envelope.
type SCIMListResponse struct {
	Schemas      []string      `json:"schemas"`
	TotalResults int           `json:"totalResults"`
	StartIndex   int           `json:"startIndex"`
	ItemsPerPage int           `json:"itemsPerPage"`
	Resources    []interface{} `json:"Resources"`
}
