package repository

import (
	"context"
	"regexp"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"
)

// TestListActiveSessionsForCollaborator_ReturnsRowsOrdered verifies the
// listing returns rows with the device columns populated and ordered
// by activity (last_seen_at DESC).
//
// Audit ref: C8 (no self-service session list endpoint).
func TestListActiveSessionsForCollaborator_ReturnsRowsOrdered(t *testing.T) {
	t.Parallel()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	collab := uuid.New()
	id1 := uuid.New()
	id2 := uuid.New()
	now := time.Now().UTC()

	mock.ExpectQuery(regexp.QuoteMeta(`
		SELECT
			id,
			collaborator_id,
			status,
			last_seen_at,
			expires_at,
			created_at,
			COALESCE(user_agent, '') AS user_agent,
			COALESCE(host(ip_address), '') AS ip_address,
			COALESCE(device_fingerprint, '') AS device_fingerprint
		FROM public.auth_sessions
		WHERE collaborator_id = $1
		  AND status = 'active'
		  AND expires_at > NOW()
		ORDER BY COALESCE(last_seen_at, created_at) DESC, created_at DESC
	`)).WithArgs(collab).WillReturnRows(sqlmock.NewRows([]string{
		"id", "collaborator_id", "status", "last_seen_at", "expires_at",
		"created_at", "user_agent", "ip_address", "device_fingerprint",
	}).
		AddRow(id1, collab, "active", now.Add(-1*time.Minute), now.Add(24*time.Hour), now.Add(-2*time.Hour), "Mozilla/5.0", "203.0.113.10", "fp-laptop").
		AddRow(id2, collab, "active", now.Add(-10*time.Minute), now.Add(48*time.Hour), now.Add(-5*time.Hour), "okhttp/4.x", "203.0.113.99", "fp-phone"))

	out, err := ListActiveSessionsForCollaborator(context.Background(), db, collab)
	if err != nil {
		t.Fatalf("ListActiveSessionsForCollaborator: %v", err)
	}
	if len(out) != 2 {
		t.Fatalf("expected 2 sessions, got %d", len(out))
	}
	if out[0].ID != id1 || out[1].ID != id2 {
		t.Fatalf("order wrong: %v %v", out[0].ID, out[1].ID)
	}
	if out[0].UserAgent != "Mozilla/5.0" {
		t.Errorf("expected first user_agent Mozilla/5.0, got %q", out[0].UserAgent)
	}
	if out[1].IPAddress != "203.0.113.99" {
		t.Errorf("expected second ip 203.0.113.99, got %q", out[1].IPAddress)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

// TestRevokeSessionByIDForCollaborator_ReturnsSessionWhenOwned verifies
// the revoke succeeds and returns the session row.
func TestRevokeSessionByIDForCollaborator_ReturnsSessionWhenOwned(t *testing.T) {
	t.Parallel()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	sessionID := uuid.New()
	collab := uuid.New()
	now := time.Now().UTC()

	mock.ExpectQuery(regexp.QuoteMeta(`
		UPDATE public.auth_sessions
		SET status = 'revoked',
		    revoked_at = NOW(),
		    updated_at = NOW()
		WHERE id = $1
		  AND collaborator_id = $2
		  AND status = 'active'
		RETURNING
			id,
			collaborator_id,
			status,
			metadata,
			last_seen_at,
			expires_at,
			revoked_at,
			created_at,
			updated_at
	`)).WithArgs(sessionID, collab).WillReturnRows(sqlmock.NewRows([]string{
		"id", "collaborator_id", "status", "metadata", "last_seen_at",
		"expires_at", "revoked_at", "created_at", "updated_at",
	}).AddRow(sessionID, collab, "revoked", []byte("{}"), nil, now.Add(24*time.Hour), now, now.Add(-time.Hour), now))

	got, err := RevokeSessionByIDForCollaborator(context.Background(), db, sessionID, collab)
	if err != nil {
		t.Fatalf("RevokeSessionByIDForCollaborator: %v", err)
	}
	if got == nil {
		t.Fatalf("expected revoked session, got nil")
	}
	if got.ID != sessionID {
		t.Fatalf("unexpected id: %v", got.ID)
	}
	if got.Status != "revoked" {
		t.Errorf("expected status=revoked, got %q", got.Status)
	}
}

// TestRevokeSessionByIDForCollaborator_ReturnsNilWhenNotFound verifies
// the not-found branch returns nil + nil (handler emits 404).
func TestRevokeSessionByIDForCollaborator_ReturnsNilWhenNotFound(t *testing.T) {
	t.Parallel()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	mock.ExpectQuery(regexp.QuoteMeta(`
		UPDATE public.auth_sessions
		SET status = 'revoked',
		    revoked_at = NOW(),
		    updated_at = NOW()
		WHERE id = $1
		  AND collaborator_id = $2
		  AND status = 'active'
		RETURNING
			id,
			collaborator_id,
			status,
			metadata,
			last_seen_at,
			expires_at,
			revoked_at,
			created_at,
			updated_at
	`)).WithArgs(uuid.Nil, uuid.Nil).WillReturnRows(sqlmock.NewRows([]string{
		"id", "collaborator_id", "status", "metadata", "last_seen_at",
		"expires_at", "revoked_at", "created_at", "updated_at",
	}))

	got, err := RevokeSessionByIDForCollaborator(context.Background(), db, uuid.Nil, uuid.Nil)
	if err != nil {
		t.Fatalf("expected nil error on not-found, got %v", err)
	}
	if got != nil {
		t.Fatalf("expected nil session on not-found, got %v", got)
	}
}
