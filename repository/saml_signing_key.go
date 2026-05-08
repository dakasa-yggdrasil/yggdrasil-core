package repository

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

var ErrSAMLSigningKeyNotFound = errors.New("saml signing key not found")

// InsertSAMLSigningKey persists one private/public keypair envelope-encrypted
// at rest. The key starts in 'pending' status; promote with ActivateSAMLSigningKey.
func InsertSAMLSigningKey(ctx context.Context, db *sql.DB, keyID string, ciphertext, dek []byte, x509CertPEM, algorithm, status string) (uuid.UUID, error) {
	if keyID == "" {
		return uuid.Nil, fmt.Errorf("key_id required")
	}
	if status == "" {
		status = "pending"
	}
	if algorithm == "" {
		algorithm = "RSA-SHA256"
	}
	var id uuid.UUID
	err := db.QueryRowContext(ctx, `
		INSERT INTO public.saml_signing_keys (
			key_id, private_key_ciphertext, private_key_dek, x509_cert_pem,
			algorithm, status
		) VALUES ($1, $2, $3, $4, $5, $6)
		RETURNING id
	`, keyID, ciphertext, dek, x509CertPEM, algorithm, status).Scan(&id)
	if err != nil {
		return uuid.Nil, fmt.Errorf("insert saml signing key: %w", err)
	}
	return id, nil
}

// ActivateSAMLSigningKey transactionally retires any current active key and
// promotes the named key to active status.
func ActivateSAMLSigningKey(ctx context.Context, db *sql.DB, keyID string) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	if _, err := tx.ExecContext(ctx, `
		UPDATE public.saml_signing_keys
		SET status = 'retired', retired_at = NOW()
		WHERE status = 'active'
	`); err != nil {
		return fmt.Errorf("retire active keys: %w", err)
	}
	res, err := tx.ExecContext(ctx, `
		UPDATE public.saml_signing_keys
		SET status = 'active', activated_at = NOW(), retired_at = NULL
		WHERE key_id = $1
	`, keyID)
	if err != nil {
		return fmt.Errorf("activate key: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrSAMLSigningKeyNotFound
	}
	return tx.Commit()
}

func GetActiveSAMLSigningKey(ctx context.Context, db *sql.DB) (model.SAMLSigningKey, error) {
	row := db.QueryRowContext(ctx, `
		SELECT id, key_id, private_key_ciphertext, private_key_dek,
			x509_cert_pem, algorithm, status, activated_at, retired_at,
			created_at
		FROM public.saml_signing_keys
		WHERE status = 'active'
		ORDER BY activated_at DESC NULLS LAST
		LIMIT 1
	`)
	k, err := scanSAMLSigningKey(row)
	if errors.Is(err, sql.ErrNoRows) {
		return model.SAMLSigningKey{}, ErrSAMLSigningKeyNotFound
	}
	return k, err
}

func GetSAMLSigningKeyByKID(ctx context.Context, db *sql.DB, keyID string) (model.SAMLSigningKey, error) {
	row := db.QueryRowContext(ctx, `
		SELECT id, key_id, private_key_ciphertext, private_key_dek,
			x509_cert_pem, algorithm, status, activated_at, retired_at,
			created_at
		FROM public.saml_signing_keys
		WHERE key_id = $1
	`, keyID)
	k, err := scanSAMLSigningKey(row)
	if errors.Is(err, sql.ErrNoRows) {
		return model.SAMLSigningKey{}, ErrSAMLSigningKeyNotFound
	}
	return k, err
}

func ListSAMLSigningKeys(ctx context.Context, db *sql.DB, includeRetired bool) ([]model.SAMLSigningKey, error) {
	q := `
		SELECT id, key_id, private_key_ciphertext, private_key_dek,
			x509_cert_pem, algorithm, status, activated_at, retired_at,
			created_at
		FROM public.saml_signing_keys
	`
	if !includeRetired {
		q += ` WHERE status <> 'retired' `
	}
	q += ` ORDER BY created_at DESC `
	rows, err := db.QueryContext(ctx, q)
	if err != nil {
		return nil, fmt.Errorf("list saml signing keys: %w", err)
	}
	defer rows.Close()
	var out []model.SAMLSigningKey
	for rows.Next() {
		k, err := scanSAMLSigningKey(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	return out, rows.Err()
}

func RetireSAMLSigningKey(ctx context.Context, db *sql.DB, keyID string, retireAt time.Time) error {
	res, err := db.ExecContext(ctx, `
		UPDATE public.saml_signing_keys
		SET status = 'retired', retired_at = $2
		WHERE key_id = $1 AND status <> 'retired'
	`, keyID, retireAt)
	if err != nil {
		return fmt.Errorf("retire saml signing key: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrSAMLSigningKeyNotFound
	}
	return nil
}

func scanSAMLSigningKey(r rowScanner) (model.SAMLSigningKey, error) {
	var k model.SAMLSigningKey
	if err := r.Scan(
		&k.ID, &k.KeyID, &k.PrivateKeyCiphertext, &k.PrivateKeyDEK,
		&k.X509CertPEM, &k.Algorithm, &k.Status, &k.ActivatedAt,
		&k.RetiredAt, &k.CreatedAt,
	); err != nil {
		return model.SAMLSigningKey{}, err
	}
	return k, nil
}
