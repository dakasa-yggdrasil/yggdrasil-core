package repository

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
	"github.com/lib/pq"
)

var (
	ErrOIDCAuthRequestNotFound  = errors.New("oidc auth request not found")
	ErrOIDCAuthCodeNotFound     = errors.New("oidc auth code not found")
	ErrOIDCAuthCodeAlreadyUsed  = errors.New("oidc auth code already used (replay attempt)")
	ErrOIDCRefreshTokenNotFound = errors.New("oidc refresh token not found")
)

func CreateOIDCAuthRequest(ctx context.Context, db *sql.DB, ar model.OIDCAuthRequest) (uuid.UUID, error) {
	var id uuid.UUID
	err := db.QueryRowContext(ctx, `
		INSERT INTO oidc_auth_requests (
			client_id, collaborator_id, redirect_uri, scopes,
			code_challenge, code_challenge_method, state, nonce, expires_at
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		RETURNING id
	`,
		ar.ClientID, ar.CollaboratorID, ar.RedirectURI, pq.Array(ar.Scopes),
		nullableString(ar.CodeChallenge), nullableString(ar.CodeChallengeMethod),
		nullableString(ar.State), nullableString(ar.Nonce), ar.ExpiresAt,
	).Scan(&id)
	if err != nil {
		return uuid.Nil, fmt.Errorf("create auth request: %w", err)
	}
	return id, nil
}

func GetOIDCAuthRequestByID(ctx context.Context, db *sql.DB, id uuid.UUID) (model.OIDCAuthRequest, error) {
	var ar model.OIDCAuthRequest
	var codeCh, codeChMethod, state, nonce sql.NullString
	err := db.QueryRowContext(ctx, `
		SELECT id, client_id, collaborator_id, redirect_uri, scopes,
		       code_challenge, code_challenge_method, state, nonce,
		       expires_at, consumed_at, created_at
		FROM oidc_auth_requests
		WHERE id = $1
	`, id).Scan(
		&ar.ID, &ar.ClientID, &ar.CollaboratorID, &ar.RedirectURI, pq.Array(&ar.Scopes),
		&codeCh, &codeChMethod, &state, &nonce,
		&ar.ExpiresAt, &ar.ConsumedAt, &ar.CreatedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return model.OIDCAuthRequest{}, ErrOIDCAuthRequestNotFound
	}
	if err != nil {
		return model.OIDCAuthRequest{}, fmt.Errorf("get auth request: %w", err)
	}
	ar.CodeChallenge = codeCh.String
	ar.CodeChallengeMethod = codeChMethod.String
	ar.State = state.String
	ar.Nonce = nonce.String
	return ar, nil
}

func MarkOIDCAuthRequestConsumed(ctx context.Context, db *sql.DB, id uuid.UUID) error {
	_, err := db.ExecContext(ctx, `UPDATE oidc_auth_requests SET consumed_at=NOW() WHERE id=$1 AND consumed_at IS NULL`, id)
	if err != nil {
		return fmt.Errorf("mark auth request consumed: %w", err)
	}
	return nil
}

func SaveOIDCAuthCode(ctx context.Context, db *sql.DB, code string, authRequestID uuid.UUID, expiresAt time.Time) error {
	_, err := db.ExecContext(ctx, `
		INSERT INTO oidc_auth_codes (code, auth_request_id, expires_at) VALUES ($1, $2, $3)
	`, code, authRequestID, expiresAt)
	if err != nil {
		return fmt.Errorf("save auth code: %w", err)
	}
	return nil
}

// ConsumeOIDCAuthCode marks the code as used in a single transaction; returns
// the underlying record and ErrOIDCAuthCodeAlreadyUsed if the code was
// already consumed (replay attempt).
func ConsumeOIDCAuthCode(ctx context.Context, db *sql.DB, code string) (model.OIDCAuthCode, error) {
	tx, err := db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return model.OIDCAuthCode{}, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()
	var got model.OIDCAuthCode
	err = tx.QueryRowContext(ctx, `
		SELECT code, auth_request_id, expires_at, consumed_at, created_at
		FROM oidc_auth_codes
		WHERE code = $1
		FOR UPDATE
	`, code).Scan(&got.Code, &got.AuthRequestID, &got.ExpiresAt, &got.ConsumedAt, &got.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return model.OIDCAuthCode{}, ErrOIDCAuthCodeNotFound
	}
	if err != nil {
		return model.OIDCAuthCode{}, fmt.Errorf("select code: %w", err)
	}
	if got.ConsumedAt != nil {
		return model.OIDCAuthCode{}, ErrOIDCAuthCodeAlreadyUsed
	}
	if _, err := tx.ExecContext(ctx, `UPDATE oidc_auth_codes SET consumed_at=NOW() WHERE code=$1`, code); err != nil {
		return model.OIDCAuthCode{}, fmt.Errorf("mark consumed: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return model.OIDCAuthCode{}, fmt.Errorf("commit: %w", err)
	}
	return got, nil
}

func CreateOIDCRefreshToken(ctx context.Context, db *sql.DB, r model.OIDCRefreshToken) error {
	_, err := db.ExecContext(ctx, `
		INSERT INTO oidc_refresh_tokens (token, collaborator_id, client_id, scopes, expires_at, rotated_from)
		VALUES ($1, $2, $3, $4, $5, $6)
	`, r.Token, r.CollaboratorID, r.ClientID, pq.Array(r.Scopes), r.ExpiresAt, r.RotatedFrom)
	if err != nil {
		return fmt.Errorf("create refresh token: %w", err)
	}
	return nil
}

func GetOIDCRefreshToken(ctx context.Context, db *sql.DB, token string) (model.OIDCRefreshToken, error) {
	var r model.OIDCRefreshToken
	err := db.QueryRowContext(ctx, `
		SELECT token, collaborator_id, client_id, scopes, expires_at, rotated_from, revoked_at, created_at
		FROM oidc_refresh_tokens WHERE token = $1
	`, token).Scan(&r.Token, &r.CollaboratorID, &r.ClientID, pq.Array(&r.Scopes),
		&r.ExpiresAt, &r.RotatedFrom, &r.RevokedAt, &r.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return model.OIDCRefreshToken{}, ErrOIDCRefreshTokenNotFound
	}
	if err != nil {
		return model.OIDCRefreshToken{}, fmt.Errorf("get refresh token: %w", err)
	}
	return r, nil
}

// RotateOIDCRefreshToken revokes the old token and inserts the new one in
// a single serializable transaction. If the old token is already revoked
// or absent, returns an error — caller should treat that as a replay
// signal and call RevokeOIDCRefreshChainByRoot.
func RotateOIDCRefreshToken(ctx context.Context, db *sql.DB, oldToken string, newToken model.OIDCRefreshToken) error {
	tx, err := db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	res, err := tx.ExecContext(ctx, `
		UPDATE oidc_refresh_tokens SET revoked_at=NOW()
		WHERE token = $1 AND revoked_at IS NULL
	`, oldToken)
	if err != nil {
		return fmt.Errorf("revoke old: %w", err)
	}
	if rows, _ := res.RowsAffected(); rows == 0 {
		return errors.New("old refresh token already revoked or missing")
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO oidc_refresh_tokens (token, collaborator_id, client_id, scopes, expires_at, rotated_from)
		VALUES ($1, $2, $3, $4, $5, $6)
	`, newToken.Token, newToken.CollaboratorID, newToken.ClientID,
		pq.Array(newToken.Scopes), newToken.ExpiresAt, newToken.RotatedFrom); err != nil {
		return fmt.Errorf("create new: %w", err)
	}
	return tx.Commit()
}

// RevokeOIDCRefreshChainByRoot revokes the given root token and all
// descendants linked via rotated_from. Returns count of NEWLY revoked
// rows (already-revoked rows don't count). Used on replay detection.
func RevokeOIDCRefreshChainByRoot(ctx context.Context, db *sql.DB, root string) (int, error) {
	res, err := db.ExecContext(ctx, `
		WITH RECURSIVE chain AS (
		  SELECT token FROM oidc_refresh_tokens WHERE token = $1
		  UNION ALL
		  SELECT t.token FROM oidc_refresh_tokens t INNER JOIN chain c ON t.rotated_from = c.token
		)
		UPDATE oidc_refresh_tokens SET revoked_at = NOW()
		WHERE token IN (SELECT token FROM chain) AND revoked_at IS NULL
	`, root)
	if err != nil {
		return 0, fmt.Errorf("revoke chain: %w", err)
	}
	rows, _ := res.RowsAffected()
	return int(rows), nil
}

func nullableString(s string) any {
	if s == "" {
		return nil
	}
	return s
}
