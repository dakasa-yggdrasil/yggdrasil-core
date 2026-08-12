package httpapi

import (
	"testing"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	wa "github.com/go-webauthn/webauthn/webauthn"
)

// TestWebAuthnCredentialsToLibCredentialsRestoresBackupFlags guards the
// passkey-login regression where a synced/backup-eligible credential
// (iCloud Keychain, Google Password Manager, 1Password) failed EVERY
// login with "Backup Eligible flag inconsistency detected during login
// validation". go-webauthn's login validation compares the assertion's
// Backup Eligibility flag against the STORED credential's flag; if we
// hydrate the lib Credential without its Flags, the stored BE reads as
// false while the authenticator reports true, and the ceremony is
// rejected. The conversion MUST carry BackupEligible + BackupState back.
func TestWebAuthnCredentialsToLibCredentialsRestoresBackupFlags(t *testing.T) {
	stored := []model.WebAuthnCredential{{
		ID:             "abc",
		RawID:          []byte{0x01, 0x02, 0x03},
		PublicKey:      []byte{0x0a, 0x0b},
		SignCount:      7,
		BackupEligible: true,
		BackupState:    true,
	}}

	got := webauthnCredentialsToLibCredentials(stored)
	if len(got) != 1 {
		t.Fatalf("expected 1 lib credential, got %d", len(got))
	}
	if !got[0].Flags.BackupEligible {
		t.Errorf("Flags.BackupEligible not restored: a backup-eligible passkey would fail login with a BE-inconsistency error")
	}
	if !got[0].Flags.BackupState {
		t.Errorf("Flags.BackupState not restored")
	}
}

// TestWebAuthnCredentialFlagsRoundTrip proves the persist->read cycle
// preserves the backup flags through libCredentialToModel (register) and
// webauthnCredentialsToLibCredentials (login), for both the eligible and
// the device-bound case.
func TestWebAuthnCredentialFlagsRoundTrip(t *testing.T) {
	cases := []struct {
		name           string
		backupEligible bool
		backupState    bool
	}{
		{"synced passkey", true, true},
		{"eligible not yet backed up", true, false},
		{"device-bound key", false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			lc := &wa.Credential{
				ID:        []byte{0x09, 0x08, 0x07},
				PublicKey: []byte{0x11, 0x22},
				Flags: wa.CredentialFlags{
					BackupEligible: tc.backupEligible,
					BackupState:    tc.backupState,
				},
			}
			persisted := libCredentialToModel(lc)
			if persisted.BackupEligible != tc.backupEligible {
				t.Fatalf("persist dropped BackupEligible: got %v want %v", persisted.BackupEligible, tc.backupEligible)
			}
			if persisted.BackupState != tc.backupState {
				t.Fatalf("persist dropped BackupState: got %v want %v", persisted.BackupState, tc.backupState)
			}

			back := webauthnCredentialsToLibCredentials([]model.WebAuthnCredential{persisted})
			if len(back) != 1 {
				t.Fatalf("expected 1 credential back, got %d", len(back))
			}
			if back[0].Flags.BackupEligible != tc.backupEligible {
				t.Errorf("read dropped BackupEligible: got %v want %v", back[0].Flags.BackupEligible, tc.backupEligible)
			}
			if back[0].Flags.BackupState != tc.backupState {
				t.Errorf("read dropped BackupState: got %v want %v", back[0].Flags.BackupState, tc.backupState)
			}
		})
	}
}
