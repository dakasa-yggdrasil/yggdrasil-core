package repository

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

// ErrOIDCSessionLinkNotFound is returned by GetOIDCSessionLinkByID when no
// row matches the supplied id.
var ErrOIDCSessionLinkNotFound = errors.New("oidc session link not found")

// UpsertOIDCSessionLink records that the OIDC OP has issued (or refreshed)
// a token pair for the given (collaborator, client) tuple backed by
// auth_session sessionID. The first call materializes the row and mints a
// SID; subsequent calls bump last_seen_at and return the existing SID so
// the same back-channel logout_token correlates across refresh cycles.
//
// Pass a nil sessionID for SSO-only flows where no yggdrasil auth_session
// backs the OIDC issuance — those rows still receive global revocations.
func UpsertOIDCSessionLink(
	ctx context.Context,
	db *sql.DB,
	collaboratorID uuid.UUID,
	clientID string,
	sessionID *uuid.UUID,
) (model.OIDCSessionLink, error) {
	if collaboratorID == uuid.Nil {
		return model.OIDCSessionLink{}, fmt.Errorf("collaborator_id is required")
	}
	if clientID == "" {
		return model.OIDCSessionLink{}, fmt.Errorf("client_id is required")
	}

	// Look up existing active link first — composite "collaborator_id +
	// client_id + (session_id IS NULL OR session_id = X)" matches a live
	// row before we mint a new SID.
	const fetch = `
		SELECT id, collaborator_id, client_id, session_id, sid, created_at, last_seen_at, terminated_at
		FROM oidc_session_links
		WHERE collaborator_id = $1 AND client_id = $2
		  AND terminated_at IS NULL
		  AND (
		    ($3::uuid IS NULL AND session_id IS NULL) OR
		    ($3::uuid IS NOT NULL AND session_id = $3)
		  )
		ORDER BY created_at DESC
		LIMIT 1
	`
	row := db.QueryRowContext(ctx, fetch, collaboratorID, clientID, sessionID)
	link, err := scanOIDCSessionLink(row)
	if err == nil {
		// Already exists — touch last_seen_at and return.
		_, _ = db.ExecContext(ctx, `UPDATE oidc_session_links SET last_seen_at = NOW() WHERE id = $1`, link.ID)
		return link, nil
	}
	if !errors.Is(err, sql.ErrNoRows) && !errors.Is(err, ErrOIDCSessionLinkNotFound) {
		return model.OIDCSessionLink{}, err
	}

	const insert = `
		INSERT INTO oidc_session_links (collaborator_id, client_id, session_id)
		VALUES ($1, $2, $3)
		RETURNING id, collaborator_id, client_id, session_id, sid, created_at, last_seen_at, terminated_at
	`
	row = db.QueryRowContext(ctx, insert, collaboratorID, clientID, sessionID)
	return scanOIDCSessionLink(row)
}

// ListActiveOIDCSessionLinksForCollaborator returns every non-terminated
// link for the collaborator. Called by the RFC 8417 dispatcher to fan out
// logout_token POSTs.
func ListActiveOIDCSessionLinksForCollaborator(
	ctx context.Context,
	db *sql.DB,
	collaboratorID uuid.UUID,
) ([]model.OIDCSessionLink, error) {
	if collaboratorID == uuid.Nil {
		return nil, fmt.Errorf("collaborator_id is required")
	}
	const q = `
		SELECT id, collaborator_id, client_id, session_id, sid, created_at, last_seen_at, terminated_at
		FROM oidc_session_links
		WHERE collaborator_id = $1 AND terminated_at IS NULL
	`
	rows, err := db.QueryContext(ctx, q, collaboratorID)
	if err != nil {
		return nil, fmt.Errorf("list active oidc session links: %w", err)
	}
	defer rows.Close()
	var out []model.OIDCSessionLink
	for rows.Next() {
		link, err := scanOIDCSessionLink(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, link)
	}
	return out, rows.Err()
}

// ListActiveOIDCSessionLinksForSession narrows the lookup to one specific
// auth_session (when a single browser logout terminates one device but
// leaves the other devices intact). Returns rows where session_id matches.
func ListActiveOIDCSessionLinksForSession(
	ctx context.Context,
	db *sql.DB,
	sessionID uuid.UUID,
) ([]model.OIDCSessionLink, error) {
	if sessionID == uuid.Nil {
		return nil, fmt.Errorf("session_id is required")
	}
	const q = `
		SELECT id, collaborator_id, client_id, session_id, sid, created_at, last_seen_at, terminated_at
		FROM oidc_session_links
		WHERE session_id = $1 AND terminated_at IS NULL
	`
	rows, err := db.QueryContext(ctx, q, sessionID)
	if err != nil {
		return nil, fmt.Errorf("list active oidc session links: %w", err)
	}
	defer rows.Close()
	var out []model.OIDCSessionLink
	for rows.Next() {
		link, err := scanOIDCSessionLink(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, link)
	}
	return out, rows.Err()
}

// MarkOIDCSessionLinkTerminated stamps terminated_at on the link row.
// Idempotent: re-stamping has no effect (broadcast retries don't disturb
// the original terminated_at timestamp).
func MarkOIDCSessionLinkTerminated(ctx context.Context, db *sql.DB, id uuid.UUID) error {
	if id == uuid.Nil {
		return fmt.Errorf("id is required")
	}
	if _, err := db.ExecContext(ctx, `
		UPDATE oidc_session_links
		SET terminated_at = NOW()
		WHERE id = $1 AND terminated_at IS NULL
	`, id); err != nil {
		return fmt.Errorf("mark oidc session link terminated: %w", err)
	}
	return nil
}

func scanOIDCSessionLink(row rowScanner) (model.OIDCSessionLink, error) {
	var link model.OIDCSessionLink
	err := row.Scan(
		&link.ID,
		&link.CollaboratorID,
		&link.ClientID,
		&link.SessionID,
		&link.SID,
		&link.CreatedAt,
		&link.LastSeenAt,
		&link.TerminatedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return model.OIDCSessionLink{}, ErrOIDCSessionLinkNotFound
	}
	if err != nil {
		return model.OIDCSessionLink{}, fmt.Errorf("scan oidc session link: %w", err)
	}
	return link, nil
}
