package model

import (
	"time"

	"github.com/google/uuid"
)

type MFAContactFactor struct {
	CollaboratorID uuid.UUID `json:"-"`
	Channel        string    `json:"channel"`
	ContactBinding string    `json:"-"`
	EnrolledAt     time.Time `json:"enrolled_at"`
}

// MFAContactChallenge contains only hashes of the bearer token and code.
// Contact and authentication-context bindings are private server state.
type MFAContactChallenge struct {
	TokenHash      string     `json:"-"`
	CodeHash       string     `json:"-"`
	CollaboratorID uuid.UUID  `json:"-"`
	Channel        string     `json:"channel"`
	Purpose        string     `json:"purpose"`
	ContextBinding string     `json:"-"`
	ContactBinding string     `json:"-"`
	ExpiresAt      time.Time  `json:"expires_at"`
	Attempts       int        `json:"-"`
	ConsumedAt     *time.Time `json:"-"`
	DeliveredAt    *time.Time `json:"-"`
	CreatedAt      time.Time  `json:"-"`
}
