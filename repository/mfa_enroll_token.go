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

var (
	ErrMFAEnrollTokenNotFound        = errors.New("mfa enroll token not found")
	ErrMFAEnrollTokenAlreadyConsumed = errors.New("mfa enroll token already consumed")
	ErrMFAEnrollTokenExpired         = errors.New("mfa enroll token expired")
)

// IssueMFAEnrollToken stores a single-use enroll token (only the hash is
// kept; the raw token leaves the service exactly once via the welcome email).
func IssueMFAEnrollToken(ctx context.Context, db *sql.DB, collaboratorID uuid.UUID, tokenHash string, expiresAt time.Time) (uuid.UUID, error) {
	var id uuid.UUID
	err := db.QueryRowContext(ctx, `
		INSERT INTO public.mfa_enroll_tokens (collaborator_id, token_hash, expires_at)
		VALUES ($1, $2, $3) RETURNING id
	`, collaboratorID, tokenHash, expiresAt).Scan(&id)
	if err != nil {
		return uuid.Nil, fmt.Errorf("issue mfa enroll token: %w", err)
	}
	return id, nil
}

func GetMFAEnrollTokenByHash(ctx context.Context, db *sql.DB, tokenHash string) (model.MFAEnrollToken, error) {
	var t model.MFAEnrollToken
	err := db.QueryRowContext(ctx, `
		SELECT id, collaborator_id, token_hash, expires_at, consumed_at, created_at
		FROM public.mfa_enroll_tokens WHERE token_hash = $1
	`, tokenHash).Scan(&t.ID, &t.CollaboratorID, &t.TokenHash, &t.ExpiresAt, &t.ConsumedAt, &t.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return model.MFAEnrollToken{}, ErrMFAEnrollTokenNotFound
	}
	if err != nil {
		return model.MFAEnrollToken{}, fmt.Errorf("get mfa enroll token: %w", err)
	}
	return t, nil
}

// ConsumeMFAEnrollToken marks the token consumed in a single conditional
// UPDATE. Returns ErrMFAEnrollTokenAlreadyConsumed or ErrMFAEnrollTokenExpired
// when the row exists but is no longer usable.
func ConsumeMFAEnrollToken(ctx context.Context, db *sql.DB, tokenHash string) error {
	res, err := db.ExecContext(ctx, `
		UPDATE public.mfa_enroll_tokens
		SET consumed_at = NOW()
		WHERE token_hash = $1 AND consumed_at IS NULL AND expires_at > NOW()
	`, tokenHash)
	if err != nil {
		return fmt.Errorf("consume mfa enroll token: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		t, getErr := GetMFAEnrollTokenByHash(ctx, db, tokenHash)
		if errors.Is(getErr, ErrMFAEnrollTokenNotFound) {
			return ErrMFAEnrollTokenNotFound
		}
		if getErr != nil {
			return getErr
		}
		if t.ConsumedAt != nil {
			return ErrMFAEnrollTokenAlreadyConsumed
		}
		return ErrMFAEnrollTokenExpired
	}
	return nil
}
