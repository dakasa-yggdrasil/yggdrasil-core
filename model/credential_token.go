package model

import "time"

type CredentialTokenPurpose string

const (
	CredentialTokenPurposeSetup CredentialTokenPurpose = "setup"
	CredentialTokenPurposeReset CredentialTokenPurpose = "reset"
)

type CredentialToken struct {
	ID             string                 `json:"id"`
	CollaboratorID string                 `json:"collaborator_id"`
	Purpose        CredentialTokenPurpose `json:"purpose"`
	ExpiresAt      time.Time              `json:"expires_at"`
	ConsumedAt     *time.Time             `json:"consumed_at,omitempty"`
	CreatedBy      *string                `json:"created_by,omitempty"`
	CreatedAt      time.Time              `json:"created_at"`
}
