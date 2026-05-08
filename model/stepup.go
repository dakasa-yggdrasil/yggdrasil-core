package model

import "time"

// StepUpRequest asks the auth core to verify the caller has a recent MFA
// factor (within MaxAge of now) before authorizing a sensitive capability.
type StepUpRequest struct {
	Capability string `json:"capability"`
	Factor     string `json:"factor"` // "webauthn" | "totp" | "recovery_code"
	Code       string `json:"code,omitempty"`
}

// StepUpChallenge is the response when a step-up is required but no recent
// factor exists; client must complete it before retrying the original op.
type StepUpChallenge struct {
	Required   bool      `json:"required"`
	Capability string    `json:"capability"`
	IssuedAt   time.Time `json:"issued_at"`
	ExpiresAt  time.Time `json:"expires_at"`
}
