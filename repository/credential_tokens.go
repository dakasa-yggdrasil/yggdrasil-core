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

var ErrCredentialTokenInvalid = errors.New("credential token invalid")

type IssueCredentialTokenInput struct {
	CollaboratorID  uuid.UUID
	Purpose         model.CredentialTokenPurpose
	TokenHash       string
	ExpiresAt       time.Time
	CreatedBy       *uuid.UUID
	Metadata        map[string]any
	InvalidatePrior bool
}

type ConsumeCredentialTokenInput struct {
	TokenHash string
	Purpose   model.CredentialTokenPurpose
}

// IssueCredentialToken inserts a new auth_credential_tokens row.
// If InvalidatePrior is true, all active tokens for the same (collaborator_id, purpose) are
// marked consumed atomically in the same transaction.
func IssueCredentialToken(ctx context.Context, db *sql.DB, in IssueCredentialTokenInput) (model.CredentialToken, error) {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return model.CredentialToken{}, fmt.Errorf("begin: %w", err)
	}
	defer tx.Rollback()

	if in.InvalidatePrior {
		if _, err := tx.ExecContext(ctx, `
            UPDATE auth_credential_tokens
            SET consumed_at = NOW()
            WHERE collaborator_id = $1 AND purpose = $2 AND consumed_at IS NULL
        `, in.CollaboratorID, in.Purpose); err != nil {
			return model.CredentialToken{}, fmt.Errorf("invalidate prior: %w", err)
		}
	}

	var t model.CredentialToken
	var createdBy sql.NullString
	if in.CreatedBy != nil {
		createdBy = sql.NullString{String: in.CreatedBy.String(), Valid: true}
	}
	metaJSON := []byte("{}")
	if in.Metadata != nil {
		b, err := json.Marshal(in.Metadata)
		if err != nil {
			return t, fmt.Errorf("marshal metadata: %w", err)
		}
		metaJSON = b
	}
	row := tx.QueryRowContext(ctx, `
        INSERT INTO auth_credential_tokens (collaborator_id, purpose, token_hash, expires_at, created_by, metadata)
        VALUES ($1, $2, $3, $4, $5, $6)
        RETURNING id, created_at
    `, in.CollaboratorID, in.Purpose, in.TokenHash, in.ExpiresAt, createdBy, metaJSON)
	if err := row.Scan(&t.ID, &t.CreatedAt); err != nil {
		return t, fmt.Errorf("insert token: %w", err)
	}
	t.CollaboratorID = in.CollaboratorID.String()
	t.Purpose = in.Purpose
	t.ExpiresAt = in.ExpiresAt
	if in.CreatedBy != nil {
		cb := in.CreatedBy.String()
		t.CreatedBy = &cb
	}
	if err := tx.Commit(); err != nil {
		return t, fmt.Errorf("commit: %w", err)
	}
	return t, nil
}

// ConsumeCredentialToken atomically consumes the active matching token.
// Returns ErrCredentialTokenInvalid if no row matches OR row is already consumed/expired/wrong-purpose.
func ConsumeCredentialToken(ctx context.Context, db *sql.DB, in ConsumeCredentialTokenInput) (model.CredentialToken, error) {
	var t model.CredentialToken
	var createdBy sql.NullString
	var consumedAt sql.NullTime
	row := db.QueryRowContext(ctx, `
        UPDATE auth_credential_tokens
        SET consumed_at = NOW()
        WHERE token_hash = $1
          AND purpose = $2
          AND consumed_at IS NULL
          AND expires_at > NOW()
        RETURNING id, collaborator_id, purpose, expires_at, consumed_at, created_by, created_at
    `, in.TokenHash, in.Purpose)
	if err := row.Scan(&t.ID, &t.CollaboratorID, &t.Purpose, &t.ExpiresAt, &consumedAt, &createdBy, &t.CreatedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return t, ErrCredentialTokenInvalid
		}
		return t, fmt.Errorf("consume token: %w", err)
	}
	if consumedAt.Valid {
		ct := consumedAt.Time
		t.ConsumedAt = &ct
	}
	if createdBy.Valid {
		s := createdBy.String
		t.CreatedBy = &s
	}
	return t, nil
}
