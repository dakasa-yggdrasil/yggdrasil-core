package repository

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/coreauth"
	"github.com/google/uuid"
)

func statusGateCollaboratorRow(id uuid.UUID, status string) *sqlmock.Rows {
	now := time.Now().UTC()
	return sqlmock.NewRows([]string{
		"id", "slug", "status", "display_name", "primary_email", "manager_id", "primary_team_id",
		"personal_data", "employment_data", "third_party_identities", "traits", "metadata", "version",
		"created_at", "updated_at",
	}).AddRow(id.String(), "status-gate-ci", status, "Status Gate CI", "status-gate@example.test", nil, nil,
		[]byte(`{}`), []byte(`{}`), []byte(`{}`), []byte(`{}`), []byte(`{}`), 1, now, now)
}

// A session is valid only while its collaborator can sign in (ADR-0087).
// Resolution reads the session, touches last_seen_at and reads the current
// collaborator, exactly as before; a collaborator who is not active is then
// refused with the unwrapped ErrAuthSessionNotFound (so every caller answers
// 401 and clears the cookie) and no further statement runs.
func TestResolveAuthSessionRefusesCollaboratorsWhoCannotSignIn(t *testing.T) {
	for _, status := range []string{"pending_start", "on_leave", "suspended", "offboarded", "active"} {
		t.Run(status, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatalf("sqlmock.New: %v", err)
			}
			defer db.Close()

			const token = "ys_status_gate_fixture_token"
			sessionID := uuid.New()
			collaboratorID := uuid.New()
			now := time.Now().UTC()
			mock.ExpectQuery(`FROM public\.auth_sessions\s+WHERE token_hash = \$1`).
				WithArgs(coreauth.HashSessionToken(token)).
				WillReturnRows(sqlmock.NewRows([]string{
					"id", "collaborator_id", "status", "metadata", "last_seen_at",
					"expires_at", "revoked_at", "created_at", "updated_at",
				}).AddRow(sessionID.String(), collaboratorID.String(), "active", []byte(`{}`), nil,
					now.Add(time.Hour), nil, now.Add(-time.Hour), now))
			mock.ExpectExec(`UPDATE public\.auth_sessions SET last_seen_at = \$2`).
				WithArgs(sessionID, sqlmock.AnyArg()).
				WillReturnResult(sqlmock.NewResult(0, 1))
			mock.ExpectQuery(`FROM public\.collaborators\s+WHERE id = \$1`).
				WithArgs(collaboratorID).
				WillReturnRows(statusGateCollaboratorRow(collaboratorID, status))

			session, collaborator, err := ResolveAuthSession(context.Background(), db, token)
			if status == "active" {
				if err != nil {
					t.Fatalf("an active collaborator's session was refused: %v", err)
				}
				if session.ID != sessionID || collaborator.ID != collaboratorID {
					t.Fatalf("resolved session=%s collaborator=%s", session.ID, collaborator.ID)
				}
			} else {
				if err != ErrAuthSessionNotFound {
					t.Fatalf("status %q: err = %v, want the unwrapped ErrAuthSessionNotFound", status, err)
				}
				if session.ID != uuid.Nil || collaborator.ID != uuid.Nil {
					t.Fatalf("status %q: a refused resolution returned identity session=%s collaborator=%s", status, session.ID, collaborator.ID)
				}
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

// The OIDC mint gate reads status and the phone requirement in one
// statement. A status that cannot sign in wins over a pending phone profile,
// and an unreadable subject is unavailable, as RequirePhoneProfileComplete
// answers today.
func TestRequireIssuableSubject(t *testing.T) {
	const query = `SELECT status, phone_profile_required FROM public\.collaborators WHERE id=\$1`
	cases := []struct {
		name    string
		status  string
		pending bool
		want    error
	}{
		{name: "suspended with a pending profile", status: "suspended", pending: true, want: ErrCollaboratorCannotSignIn},
		{name: "offboarded", status: "offboarded", want: ErrCollaboratorCannotSignIn},
		{name: "on_leave", status: "on_leave", want: ErrCollaboratorCannotSignIn},
		{name: "pending_start", status: "pending_start", want: ErrCollaboratorCannotSignIn},
		{name: "active with a pending profile", status: "active", pending: true, want: ErrPhoneProfileRequired},
		{name: "active", status: "active"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatalf("sqlmock.New: %v", err)
			}
			defer db.Close()
			id := uuid.New()
			mock.ExpectQuery(query).WithArgs(id).
				WillReturnRows(sqlmock.NewRows([]string{"status", "phone_profile_required"}).AddRow(tc.status, tc.pending))
			if got := RequireIssuableSubject(context.Background(), db, id); !errors.Is(got, tc.want) || (tc.want == nil && got != nil) {
				t.Fatalf("RequireIssuableSubject = %v, want %v", got, tc.want)
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatal(err)
			}
		})
	}

	t.Run("missing row", func(t *testing.T) {
		db, mock, err := sqlmock.New()
		if err != nil {
			t.Fatalf("sqlmock.New: %v", err)
		}
		defer db.Close()
		id := uuid.New()
		mock.ExpectQuery(query).WithArgs(id).WillReturnError(sql.ErrNoRows)
		if got := RequireIssuableSubject(context.Background(), db, id); !errors.Is(got, ErrPhoneUnavailable) {
			t.Fatalf("missing subject: %v, want ErrPhoneUnavailable", got)
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("no database or nil subject", func(t *testing.T) {
		db, mock, err := sqlmock.New()
		if err != nil {
			t.Fatalf("sqlmock.New: %v", err)
		}
		defer db.Close()
		if got := RequireIssuableSubject(context.Background(), nil, uuid.New()); !errors.Is(got, ErrPhoneUnavailable) {
			t.Fatalf("nil db: %v", got)
		}
		if got := RequireIssuableSubject(context.Background(), db, uuid.Nil); !errors.Is(got, ErrPhoneUnavailable) {
			t.Fatalf("nil subject: %v", got)
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Fatal(err)
		}
	})
}
