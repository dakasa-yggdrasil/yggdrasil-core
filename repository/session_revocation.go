package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

// Canonical reasons accepted by session_revocation.reason (mirrored in the
// migration CHECK constraint). Surfaces and audit consumers should treat
// these strings as stable identifiers.
const (
	SessionRevocationReasonLogout           = "logout"
	SessionRevocationReasonAdminRevoked     = "admin_revoked"
	SessionRevocationReasonPasswordRotated  = "password_rotated"
	SessionRevocationReasonOffboarded       = "offboarded"
	SessionRevocationReasonSessionExpired   = "session_expired"
	SessionRevocationReasonMFAReset         = "mfa_reset"
)

var validSessionRevocationReasons = map[string]struct{}{
	SessionRevocationReasonLogout:          {},
	SessionRevocationReasonAdminRevoked:    {},
	SessionRevocationReasonPasswordRotated: {},
	SessionRevocationReasonOffboarded:      {},
	SessionRevocationReasonSessionExpired:  {},
	SessionRevocationReasonMFAReset:        {},
}

// ErrSessionRevocationInvalidReason is returned when an unknown reason
// string is passed to InsertSessionRevocation. The caller should pick from
// the SessionRevocationReason* constants exported in this package.
var ErrSessionRevocationInvalidReason = errors.New("invalid session revocation reason")

// InsertSessionRevocationRequest scopes one revocation. sessionJTI is
// optional; when nil the revocation applies to every active session for
// the collaborator since revoked_at.
type InsertSessionRevocationRequest struct {
	CollaboratorID uuid.UUID
	SessionJTI     *uuid.UUID
	Reason         string
	Metadata       map[string]any
}

// InsertSessionRevocation writes one revocation row. When tx is non-nil
// the insert participates in the caller's transaction (typical: logout
// handler revokes the session row AND inserts the revocation atomically).
// When tx is nil it runs on the caller-supplied *sql.DB directly.
//
// Returns the inserted row so callers can use its ID/timestamps to
// correlate downstream events (RFC 8417 dispatch outcome, audit log).
func InsertSessionRevocation(
	ctx context.Context,
	db *sql.DB,
	tx *sql.Tx,
	req InsertSessionRevocationRequest,
) (model.SessionRevocation, error) {
	reason := strings.TrimSpace(req.Reason)
	if _, ok := validSessionRevocationReasons[reason]; !ok {
		return model.SessionRevocation{}, fmt.Errorf("%w: %q", ErrSessionRevocationInvalidReason, reason)
	}
	if req.CollaboratorID == uuid.Nil {
		return model.SessionRevocation{}, fmt.Errorf("collaborator_id is required")
	}

	metaJSON := []byte("{}")
	if len(req.Metadata) > 0 {
		raw, err := json.Marshal(req.Metadata)
		if err != nil {
			return model.SessionRevocation{}, fmt.Errorf("marshal metadata: %w", err)
		}
		metaJSON = raw
	}

	const q = `
		INSERT INTO session_revocation (collaborator_id, session_jti, reason, metadata)
		VALUES ($1, $2, $3, $4)
		RETURNING id, collaborator_id, session_jti, revoked_at, reason, broadcast_completed_at, metadata
	`
	var row *sql.Row
	if tx != nil {
		row = tx.QueryRowContext(ctx, q, req.CollaboratorID, req.SessionJTI, reason, metaJSON)
	} else {
		row = db.QueryRowContext(ctx, q, req.CollaboratorID, req.SessionJTI, reason, metaJSON)
	}
	return scanSessionRevocation(row)
}

// IsSessionRevoked answers the §13 introspection query "is this
// (collaborator, jti) pair valid as of issuedAt?". Returns true when ANY
// revocation row exists matching the lookup:
//
//   - a row with session_jti = jti revokes that specific session (logout
//     from one device)
//   - a row with session_jti = NULL revokes every session for the
//     collaborator with iat < revoked_at (admin revoke / password rotation
//     / offboarding)
//
// issuedAt should be the token's iat claim or session creation time. A
// revocation row inserted BEFORE the token was issued does NOT invalidate
// the new token — same shape as OIDC's "revoke before iat" semantics.
func IsSessionRevoked(
	ctx context.Context,
	db *sql.DB,
	collaboratorID uuid.UUID,
	jti *uuid.UUID,
	issuedAt time.Time,
) (bool, error) {
	if collaboratorID == uuid.Nil {
		return false, fmt.Errorf("collaborator_id is required")
	}

	// Two-condition lookup: per-session revocation OR global revocation
	// since iat. The partial index session_revocation_jti_idx covers the
	// first, session_revocation_collaborator_idx covers the second.
	const q = `
		SELECT EXISTS (
			SELECT 1 FROM session_revocation
			WHERE collaborator_id = $1
			  AND (
			    (session_jti IS NOT NULL AND $2::uuid IS NOT NULL AND session_jti = $2)
			    OR (session_jti IS NULL AND revoked_at >= $3)
			  )
		)
	`
	var revoked bool
	err := db.QueryRowContext(ctx, q, collaboratorID, jti, issuedAt).Scan(&revoked)
	if err != nil {
		return false, fmt.Errorf("is session revoked: %w", err)
	}
	return revoked, nil
}

// ListPendingBackchannelRevocations returns revocations whose RFC 8417
// dispatch hasn't completed yet. The back-channel dispatcher consumes
// this list, attempts each client, and either marks the row complete
// (broadcast_completed_at) or records the failure in metadata.
func ListPendingBackchannelRevocations(
	ctx context.Context,
	db *sql.DB,
	limit int,
) ([]model.SessionRevocation, error) {
	if limit <= 0 {
		limit = 50
	}
	const q = `
		SELECT id, collaborator_id, session_jti, revoked_at, reason, broadcast_completed_at, metadata
		FROM session_revocation
		WHERE broadcast_completed_at IS NULL
		ORDER BY revoked_at ASC
		LIMIT $1
	`
	rows, err := db.QueryContext(ctx, q, limit)
	if err != nil {
		return nil, fmt.Errorf("list pending backchannel revocations: %w", err)
	}
	defer rows.Close()

	var out []model.SessionRevocation
	for rows.Next() {
		r, err := scanSessionRevocation(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// MarkSessionRevocationBroadcastComplete stamps broadcast_completed_at on
// the revocation row, optionally appending dispatch outcome details into
// metadata. Called by the RFC 8417 dispatcher once every client has been
// notified (or has hit retry exhaustion).
func MarkSessionRevocationBroadcastComplete(
	ctx context.Context,
	db *sql.DB,
	id uuid.UUID,
	dispatchSummary map[string]any,
) error {
	if id == uuid.Nil {
		return fmt.Errorf("revocation id is required")
	}
	var summaryJSON []byte
	if len(dispatchSummary) > 0 {
		raw, err := json.Marshal(dispatchSummary)
		if err != nil {
			return fmt.Errorf("marshal dispatch summary: %w", err)
		}
		summaryJSON = raw
	}
	const q = `
		UPDATE session_revocation
		SET broadcast_completed_at = NOW(),
		    metadata = CASE
		      WHEN $2::jsonb IS NULL THEN metadata
		      ELSE metadata || $2::jsonb
		    END
		WHERE id = $1
	`
	if _, err := db.ExecContext(ctx, q, id, summaryJSON); err != nil {
		return fmt.Errorf("mark broadcast complete: %w", err)
	}
	return nil
}

// CleanupExpiredSessionRevocations deletes rows older than retention. The
// addon scheduler calls this periodically; retention should be at least
// as long as the max access-token lifetime so introspection still sees
// recent revocations.
func CleanupExpiredSessionRevocations(
	ctx context.Context,
	db *sql.DB,
	retention time.Duration,
) (int64, error) {
	if retention <= 0 {
		retention = 30 * 24 * time.Hour
	}
	res, err := db.ExecContext(ctx, `
		DELETE FROM session_revocation
		WHERE revoked_at < NOW() - $1::interval
	`, retention.String())
	if err != nil {
		return 0, fmt.Errorf("cleanup expired session revocations: %w", err)
	}
	rows, _ := res.RowsAffected()
	return rows, nil
}

// scanSessionRevocation uses the package-level rowScanner declared in
// saml_service_provider.go so the same scan body works whether we're
// paging through ListPendingBackchannelRevocations or returning the
// single InsertSessionRevocation result.
func scanSessionRevocation(row rowScanner) (model.SessionRevocation, error) {
	var (
		r        model.SessionRevocation
		metaRaw  []byte
	)
	err := row.Scan(
		&r.ID,
		&r.CollaboratorID,
		&r.SessionJTI,
		&r.RevokedAt,
		&r.Reason,
		&r.BroadcastCompletedAt,
		&metaRaw,
	)
	if err != nil {
		return model.SessionRevocation{}, fmt.Errorf("scan session revocation: %w", err)
	}
	if len(metaRaw) > 0 {
		var m map[string]any
		if err := json.Unmarshal(metaRaw, &m); err != nil {
			return model.SessionRevocation{}, fmt.Errorf("unmarshal metadata: %w", err)
		}
		r.Metadata = m
	}
	return r, nil
}
