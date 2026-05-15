package repository

// Credential lifecycle event type constants. Each value is the canonical
// event type string stored in event_log.type and validated against the
// corresponding JSON Schema in docs/contracts/events/v1/credential/.
const (
	EventTypeCredentialSetupTokenIssued         = "credential.setup_token_issued"
	EventTypeCredentialPasswordSetupCompleted   = "credential.password_setup_completed"
	EventTypeCredentialPasswordChanged          = "credential.password_changed"
	EventTypeCredentialResetTokenIssued         = "credential.reset_token_issued"
	EventTypeCredentialPasswordRotationRequired = "credential.password_rotation_required"
)
