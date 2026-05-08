package mfa

import (
	"errors"
	"fmt"

	"github.com/go-webauthn/webauthn/protocol"
	wa "github.com/go-webauthn/webauthn/webauthn"
)

// ErrInvalidWebAuthnAssertion is returned when a passkey/security-key challenge
// fails verification (counter regression, signature mismatch, origin mismatch).
var ErrInvalidWebAuthnAssertion = errors.New("invalid WebAuthn assertion")

// Config bundles the relying-party metadata needed by go-webauthn. The host
// app fills RPDisplayName/RPID/Origins from environment.
type Config struct {
	RPDisplayName string
	RPID          string
	Origins       []string
}

// NewWebAuthn returns a configured *wa.WebAuthn ready to handle Begin/Finish
// registration and assertion. Wraps go-webauthn's New constructor with the
// project's defaults.
func NewWebAuthn(cfg Config) (*wa.WebAuthn, error) {
	if cfg.RPID == "" {
		return nil, fmt.Errorf("RPID required")
	}
	if cfg.RPDisplayName == "" {
		cfg.RPDisplayName = "Yggdrasil"
	}
	if len(cfg.Origins) == 0 {
		return nil, fmt.Errorf("at least one origin required")
	}
	w, err := wa.New(&wa.Config{
		RPDisplayName: cfg.RPDisplayName,
		RPID:          cfg.RPID,
		RPOrigins:     cfg.Origins,
		AttestationPreference: protocol.PreferDirectAttestation,
		AuthenticatorSelection: protocol.AuthenticatorSelection{
			UserVerification: protocol.VerificationPreferred,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("webauthn new: %w", err)
	}
	return w, nil
}

// User adapts an internal collaborator+credentials view to webauthn.User.
type User struct {
	IDBytes     []byte
	Username    string
	DisplayName string
	Credentials []wa.Credential
}

func (u *User) WebAuthnID() []byte                         { return u.IDBytes }
func (u *User) WebAuthnName() string                       { return u.Username }
func (u *User) WebAuthnDisplayName() string                { return u.DisplayName }
func (u *User) WebAuthnIcon() string                       { return "" }
func (u *User) WebAuthnCredentials() []wa.Credential       { return u.Credentials }

var _ wa.User = (*User)(nil)
