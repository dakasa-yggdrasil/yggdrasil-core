package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

// ErrWebAuthnCredentialNotFound is returned by repository helpers that
// need to mutate one credential within the JSONB array — rename, delete,
// counter-update — when the supplied credential ID doesn't match any
// row entry.
var ErrWebAuthnCredentialNotFound = errors.New("webauthn credential not found")

// ListWebAuthnCredentials returns the WebAuthn credentials registered
// for collaboratorID. Empty slice (not nil) when none exist so handlers
// can JSON-encode an [] without a special case.
//
// Returns ErrAuthIdentityNotFound when the auth_identities row itself
// is missing (callers should treat as "no credentials" same as empty).
func ListWebAuthnCredentials(ctx context.Context, db *sql.DB, collaboratorID uuid.UUID) ([]model.WebAuthnCredential, error) {
	var blob []byte
	err := db.QueryRowContext(ctx, `
		SELECT webauthn_credentials
		FROM public.auth_identities
		WHERE collaborator_id = $1
	`, collaboratorID).Scan(&blob)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrAuthIdentityNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("read webauthn_credentials: %w", err)
	}
	creds := decodeWebAuthnCredentials(blob)
	if creds == nil {
		return []model.WebAuthnCredential{}, nil
	}
	return creds, nil
}

// AppendWebAuthnCredential persists a freshly-registered credential as
// the LAST element of the JSONB array. We do the read-modify-write inside
// a single transaction with row-level locking (FOR UPDATE) so two
// concurrent /finish requests for the same user (e.g. user double-clicks
// the enroll button) can't race and lose one of the appends.
//
// Idempotency: if a credential with the same ID already exists, the
// append is a no-op (returns nil). This prevents the duplicate-credential
// edge case where the browser fires /finish twice on a flaky network.
func AppendWebAuthnCredential(ctx context.Context, db *sql.DB, collaboratorID uuid.UUID, credential model.WebAuthnCredential) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin webauthn append: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	var blob []byte
	err = tx.QueryRowContext(ctx, `
		SELECT webauthn_credentials
		FROM public.auth_identities
		WHERE collaborator_id = $1
		FOR UPDATE
	`, collaboratorID).Scan(&blob)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrAuthIdentityNotFound
	}
	if err != nil {
		return fmt.Errorf("lock auth_identity: %w", err)
	}

	creds := decodeWebAuthnCredentials(blob)
	for _, existing := range creds {
		if existing.ID == credential.ID {
			// Already present — idempotent succeed without an extra
			// write. Safe even on a stale row because the credential ID
			// is the WebAuthn-generated unique identifier.
			return tx.Commit()
		}
	}

	creds = append(creds, credential)
	newBlob, err := json.Marshal(creds)
	if err != nil {
		return fmt.Errorf("marshal webauthn_credentials: %w", err)
	}

	if _, err := tx.ExecContext(ctx, `
		UPDATE public.auth_identities
		SET webauthn_credentials = $1::jsonb
		WHERE collaborator_id = $2
	`, newBlob, collaboratorID); err != nil {
		return fmt.Errorf("update webauthn_credentials: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit webauthn append: %w", err)
	}
	return nil
}

// UpdateWebAuthnCredentialName renames one credential in the JSONB
// array. Returns ErrWebAuthnCredentialNotFound when the credID doesn't
// match any element. Trims/truncates the name so an absurd 10MB payload
// never lands in the DB.
func UpdateWebAuthnCredentialName(ctx context.Context, db *sql.DB, collaboratorID uuid.UUID, credID string, name string) error {
	if len(name) > 128 {
		name = name[:128]
	}
	return mutateOneCredential(ctx, db, collaboratorID, credID, func(c *model.WebAuthnCredential) error {
		c.Name = name
		return nil
	})
}

// UpdateWebAuthnSignCount bumps the credential's sign_count + records
// the last-used timestamp. Called after every successful login finish
// so the next login can detect counter-regression replay attempts.
//
// Returns ErrWebAuthnCredentialNotFound when credID doesn't match
// (shouldn't happen post-login — the login path resolved the cred from
// the same array — but kept for defensive correctness).
func UpdateWebAuthnSignCount(ctx context.Context, db *sql.DB, collaboratorID uuid.UUID, credID string, signCount uint32, lastUsedAt time.Time) error {
	return mutateOneCredential(ctx, db, collaboratorID, credID, func(c *model.WebAuthnCredential) error {
		c.SignCount = signCount
		t := lastUsedAt
		c.LastUsedAt = &t
		return nil
	})
}

// RemoveWebAuthnCredential deletes one credential from the JSONB array.
// Returns ErrWebAuthnCredentialNotFound when credID doesn't match.
//
// Caller is responsible for the "don't strand the user without any
// factor" invariant — this helper unconditionally removes whichever
// credential matches.
func RemoveWebAuthnCredential(ctx context.Context, db *sql.DB, collaboratorID uuid.UUID, credID string) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin webauthn remove: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	var blob []byte
	err = tx.QueryRowContext(ctx, `
		SELECT webauthn_credentials
		FROM public.auth_identities
		WHERE collaborator_id = $1
		FOR UPDATE
	`, collaboratorID).Scan(&blob)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrAuthIdentityNotFound
	}
	if err != nil {
		return fmt.Errorf("lock auth_identity: %w", err)
	}

	creds := decodeWebAuthnCredentials(blob)
	found := false
	out := make([]model.WebAuthnCredential, 0, len(creds))
	for _, c := range creds {
		if c.ID == credID {
			found = true
			continue
		}
		out = append(out, c)
	}
	if !found {
		return ErrWebAuthnCredentialNotFound
	}

	newBlob, err := json.Marshal(out)
	if err != nil {
		return fmt.Errorf("marshal webauthn_credentials: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE public.auth_identities
		SET webauthn_credentials = $1::jsonb
		WHERE collaborator_id = $2
	`, newBlob, collaboratorID); err != nil {
		return fmt.Errorf("update webauthn_credentials: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit webauthn remove: %w", err)
	}
	return nil
}

// mutateOneCredential is the read-modify-write helper that the rename +
// sign-count helpers share. Caller supplies a closure that mutates one
// credential in place; the helper picks it out, applies the change, and
// writes the array back atomically.
func mutateOneCredential(ctx context.Context, db *sql.DB, collaboratorID uuid.UUID, credID string, fn func(*model.WebAuthnCredential) error) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin webauthn mutate: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	var blob []byte
	err = tx.QueryRowContext(ctx, `
		SELECT webauthn_credentials
		FROM public.auth_identities
		WHERE collaborator_id = $1
		FOR UPDATE
	`, collaboratorID).Scan(&blob)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrAuthIdentityNotFound
	}
	if err != nil {
		return fmt.Errorf("lock auth_identity: %w", err)
	}

	creds := decodeWebAuthnCredentials(blob)
	if len(creds) == 0 {
		return ErrWebAuthnCredentialNotFound
	}
	found := false
	for i := range creds {
		if creds[i].ID == credID {
			if err := fn(&creds[i]); err != nil {
				return err
			}
			found = true
			break
		}
	}
	if !found {
		return ErrWebAuthnCredentialNotFound
	}

	newBlob, err := json.Marshal(creds)
	if err != nil {
		return fmt.Errorf("marshal webauthn_credentials: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE public.auth_identities
		SET webauthn_credentials = $1::jsonb
		WHERE collaborator_id = $2
	`, newBlob, collaboratorID); err != nil {
		return fmt.Errorf("update webauthn_credentials: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit webauthn mutate: %w", err)
	}
	return nil
}
