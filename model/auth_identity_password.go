package model

type IssueSetupTokenRequest struct {
	CollaboratorID   string `json:"collaborator_id"`
	ExpiresInSeconds int    `json:"expires_in_seconds,omitempty"`
}

type IssueSetupTokenResponse struct {
	TokenID   string `json:"token_id"`
	SetupURL  string `json:"setup_url"`
	ExpiresAt string `json:"expires_at"`
}

type SetupProfile struct {
	DisplayName  *string        `json:"display_name,omitempty"`
	Timezone     *string        `json:"timezone,omitempty"`
	PersonalData map[string]any `json:"personal_data,omitempty"`
}

type PasswordSetupRequest struct {
	Token       string        `json:"token"`
	NewPassword string        `json:"new_password"`
	Profile     *SetupProfile `json:"profile,omitempty"`
}

type PasswordChangeRequest struct {
	CurrentPassword   string         `json:"current_password"`
	NewPassword       string         `json:"new_password"`
	TOTPCode          string         `json:"totp_code,omitempty"`
	RecoveryCode      string         `json:"recovery_code,omitempty"`
	WebAuthnAssertion map[string]any `json:"webauthn_assertion,omitempty"`
}

type PasswordForgotRequest struct {
	Identifier string `json:"identifier"`
}

type PasswordResetRequest struct {
	Token             string         `json:"token"`
	NewPassword       string         `json:"new_password"`
	TOTPCode          string         `json:"totp_code,omitempty"`
	RecoveryCode      string         `json:"recovery_code,omitempty"`
	WebAuthnAssertion map[string]any `json:"webauthn_assertion,omitempty"`
}
