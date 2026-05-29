package mfa

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	wa "github.com/go-webauthn/webauthn/webauthn"
)

// ErrInvalidWebAuthnAssertion is returned when a passkey/security-key challenge
// fails verification (counter regression, signature mismatch, origin mismatch).
var ErrInvalidWebAuthnAssertion = errors.New("invalid WebAuthn assertion")

// ErrWebAuthnSessionExpired is returned when the registration or login
// ceremony's transient session blob is missing — typically because the
// browser took longer than the 5min ceremony TTL between begin and
// finish, or because the server restarted between the two calls.
var ErrWebAuthnSessionExpired = errors.New("webauthn ceremony session expired")

// ErrWebAuthnSignCountReplay is the canonical "this credential's
// counter is older than the one we already have on file" signal —
// indicates either a cloned authenticator or an out-of-order replay of
// an old assertion. We reject the login and emit a metric + audit row
// so an operator can pull the user's full session list and decide
// whether to revoke the credential.
var ErrWebAuthnSignCountReplay = errors.New("webauthn sign count replay detected")

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
//
// AttestationPreference: "none" — we don't need the attestation chain to
// pin a manufacturer; passkeys synced through iCloud Keychain or 1Password
// often deliver no attestation. Surfacing "no attestation accepted" would
// cripple the most common consumer flow without buying us security.
// UserVerification: "preferred" — security keys without biometrics work
// (cross-platform yubikey + PIN), while platform authenticators with
// biometrics gain full UV. Strict "required" would lock out hardware
// keys without PINs.
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
		RPDisplayName:         cfg.RPDisplayName,
		RPID:                  cfg.RPID,
		RPOrigins:             cfg.Origins,
		AttestationPreference: protocol.PreferNoAttestation,
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

func (u *User) WebAuthnID() []byte                   { return u.IDBytes }
func (u *User) WebAuthnName() string                 { return u.Username }
func (u *User) WebAuthnDisplayName() string          { return u.DisplayName }
func (u *User) WebAuthnIcon() string                 { return "" }
func (u *User) WebAuthnCredentials() []wa.Credential { return u.Credentials }

var _ wa.User = (*User)(nil)

// SessionStore is the in-memory cache of in-flight WebAuthn ceremony
// session blobs (challenge + RP metadata) keyed by an opaque string.
//
// We chose in-memory over Redis for Phase 2 because:
//   - The ceremony round-trip lasts seconds — long enough to survive a
//     normal pod, short enough that a single-pod restart is acceptable
//     UX. If the FE retries after a restart, the user just clicks the
//     enroll button again.
//   - Multi-replica concerns: WebAuthn ceremonies need sticky session
//     affinity (same pod for begin + finish) OR a shared store. Today's
//     yggdrasil-core deploys as a single replica per cluster (HPA off),
//     so affinity holds. When HPA gets enabled, swap the store for a
//     Redis-backed implementation; the SessionStore interface is the
//     pivot point.
//
// Entries TTL at 5min by default — generous enough for a slow biometric
// prompt, tight enough that an abandoned ceremony's challenge can't be
// replayed an hour later. A background goroutine reaps expired entries
// every minute.
type SessionStore struct {
	mu      sync.Mutex
	entries map[string]webauthnSessionEntry
	ttl     time.Duration
}

type webauthnSessionEntry struct {
	data      wa.SessionData
	expiresAt time.Time
}

// NewSessionStore returns a SessionStore with the given ceremony TTL.
// Pass 0 for the project default (5 minutes). The store auto-reaps
// expired entries on every Get/Put call; explicit GC loop optional.
func NewSessionStore(ttl time.Duration) *SessionStore {
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	return &SessionStore{
		entries: map[string]webauthnSessionEntry{},
		ttl:     ttl,
	}
}

// Put writes a ceremony session blob into the store keyed by `key`.
// Caller chooses the key — typically `"reg:" + collabID` for
// registration or `"login:" + identifier` for login. Overwrites silently
// on duplicate key (e.g. user clicks "register passkey" twice — only the
// most recent ceremony wins).
func (s *SessionStore) Put(key string, data wa.SessionData) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.reapLocked()
	s.entries[key] = webauthnSessionEntry{
		data:      data,
		expiresAt: time.Now().Add(s.ttl),
	}
}

// Take retrieves and deletes (one-shot) the ceremony session blob for
// `key`. Returns ErrWebAuthnSessionExpired when the entry is missing or
// past its TTL — both surfaced as "ceremony timed out, retry" in the FE.
// Idempotency: subsequent Take with the same key returns
// ErrWebAuthnSessionExpired (which is the desired behavior — preventing
// replay).
func (s *SessionStore) Take(key string) (wa.SessionData, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.reapLocked()
	entry, ok := s.entries[key]
	if !ok {
		return wa.SessionData{}, ErrWebAuthnSessionExpired
	}
	delete(s.entries, key)
	if time.Now().After(entry.expiresAt) {
		return wa.SessionData{}, ErrWebAuthnSessionExpired
	}
	return entry.data, nil
}

// reapLocked removes expired entries. Caller must hold s.mu.
func (s *SessionStore) reapLocked() {
	now := time.Now()
	for k, e := range s.entries {
		if now.After(e.expiresAt) {
			delete(s.entries, k)
		}
	}
}

// RegistrationKey is the canonical key shape for a registration
// ceremony. Pass the collaborator UUID. Keeping the helper here so
// callers don't duplicate the prefix and break uniqueness invariants.
func RegistrationKey(collabID string) string {
	return "reg:" + collabID
}

// LoginKey is the canonical key shape for a login ceremony. We key by
// collaborator UUID (the same as registration) because the login flow
// resolves the identifier to a UUID before /begin returns. Keeping the
// helper here so callers don't duplicate the prefix and break
// uniqueness invariants.
func LoginKey(collabID string) string {
	return "login:" + collabID
}

// DeviceKindFromAttachment maps go-webauthn's AuthenticatorAttachment to
// the surface-facing "platform" / "cross-platform" enumeration. The
// canonical strings ride out to the FE via WebAuthnCredential.DeviceKind
// — the surface uses them to pick the right device-type icon.
func DeviceKindFromAttachment(att protocol.AuthenticatorAttachment) string {
	switch strings.ToLower(string(att)) {
	case "platform":
		return "platform"
	case "cross-platform", "cross_platform":
		return "cross-platform"
	default:
		return ""
	}
}

// TransportsToStrings flattens go-webauthn's typed transport enum into
// the surface-facing []string. Empty input returns nil so the
// WebAuthnCredential.Transports field stays omitempty.
func TransportsToStrings(transports []protocol.AuthenticatorTransport) []string {
	if len(transports) == 0 {
		return nil
	}
	out := make([]string, 0, len(transports))
	for _, t := range transports {
		s := strings.TrimSpace(string(t))
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}
