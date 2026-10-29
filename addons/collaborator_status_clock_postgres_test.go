package addons

import (
	"context"
	"database/sql"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	"github.com/google/uuid"
	_ "github.com/lib/pq"
)

func statusClockSessionPostgres(t *testing.T) *sql.DB {
	t.Helper()
	dsn := os.Getenv("DB_URL")
	if dsn == "" {
		if os.Getenv("REQUIRE_SESSION_LIFECYCLE_POSTGRES") == "true" {
			t.Fatal("DB_URL is required by the session lifecycle PostgreSQL gate")
		}
		t.Skip("PostgreSQL runs in CI")
	}
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatalf("open PostgreSQL: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := db.Ping(); err != nil {
		t.Fatalf("PostgreSQL unavailable: %v", err)
	}
	return db
}

func statusClockSessionPerson(t *testing.T, db *sql.DB, status string, employment map[string]any) (model.Collaborator, string) {
	t.Helper()
	ctx := context.Background()
	id := uuid.NewString()
	c, err := repository.CreateCollaborator(ctx, db, model.CreateCollaboratorRequest{
		Slug: "clock-session-" + id, DisplayName: "Clock Session CI", PrimaryEmail: id + "@example.test",
		Status: status, EmploymentData: employment,
	})
	if err != nil {
		t.Fatalf("collaborator fixture failed: %v", err)
	}
	t.Cleanup(func() { _, _ = db.Exec(`DELETE FROM public.collaborators WHERE id=$1`, c.ID) })
	_, token, err := repository.CreateAuthSession(ctx, db, c.ID, nil, time.Hour)
	if err != nil {
		t.Fatalf("session fixture failed: %v", err)
	}
	return c, token
}

func statusClockSessionCounts(t *testing.T, db *sql.DB, id uuid.UUID) (live, terminated int, revocations []map[string]any) {
	t.Helper()
	if err := db.QueryRow(`SELECT COUNT(*) FROM public.auth_sessions WHERE collaborator_id=$1 AND revoked_at IS NULL`, id).Scan(&live); err != nil {
		t.Fatalf("count sessions: %v", err)
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM public.event_log WHERE type=$1 AND aggregate_id=$2`, repository.EventTypeCollaboratorSessionTerminated, id.String()).Scan(&terminated); err != nil {
		t.Fatalf("count session.terminated: %v", err)
	}
	rows, err := db.Query(`SELECT reason, metadata FROM public.session_revocation WHERE collaborator_id=$1`, id)
	if err != nil {
		t.Fatalf("read revocations: %v", err)
	}
	defer rows.Close()
	for rows.Next() {
		var reason string
		var raw []byte
		if err := rows.Scan(&reason, &raw); err != nil {
			t.Fatalf("scan revocation: %v", err)
		}
		m := map[string]any{}
		if err := json.Unmarshal(raw, &m); err != nil {
			t.Fatalf("decode revocation metadata: %v", err)
		}
		m["reason"] = reason
		revocations = append(revocations, m)
	}
	return live, terminated, revocations
}

// Both branches of the status clock write the status through
// repository.UpdateCollaborator, so they apply the session policy of
// ADR-0087: an auto-offboard terminates every session once, and an
// auto-promotion revokes leftovers without recording a termination.
func TestStatusClockOffboardTerminatesSessionsPostgres(t *testing.T) {
	db := statusClockSessionPostgres(t)
	ctx := context.Background()
	yesterday := time.Now().AddDate(0, 0, -1).Format("2006-01-02")

	t.Run("offboard_terminates_sessions", func(t *testing.T) {
		c, token := statusClockSessionPerson(t, db, "active", map[string]any{"end_date": yesterday})
		if err := RunCollaboratorStatusClockTick(ctx, db); err != nil {
			t.Fatalf("tick: %v", err)
		}
		got, err := repository.GetCollaborator(ctx, db, c.ID.String())
		if err != nil || got.Status != "offboarded" {
			t.Fatalf("status=%q err=%v, want offboarded", got.Status, err)
		}
		live, terminated, revocations := statusClockSessionCounts(t, db, c.ID)
		if live != 0 || terminated != 1 || len(revocations) != 1 {
			t.Fatalf("auto-offboard: live=%d terminated=%d revocations=%d, want 0/1/1", live, terminated, len(revocations))
		}
		rev := revocations[0]
		if rev["reason"] != repository.SessionRevocationReasonOffboarded || rev["source"] != "collaborator_status_change" || rev["from_status"] != "active" || rev["to_status"] != "offboarded" {
			t.Fatalf("auto-offboard revocation: %v", rev)
		}
		if _, _, err := repository.ResolveAuthSession(ctx, db, token); err != repository.ErrAuthSessionNotFound {
			t.Fatalf("the session survived the auto-offboard: %v", err)
		}
	})

	t.Run("promotion_revokes_leftovers_without_an_event", func(t *testing.T) {
		c, token := statusClockSessionPerson(t, db, "pending_start", map[string]any{"start_date": yesterday})
		if err := RunCollaboratorStatusClockTick(ctx, db); err != nil {
			t.Fatalf("tick: %v", err)
		}
		got, err := repository.GetCollaborator(ctx, db, c.ID.String())
		if err != nil || got.Status != "active" {
			t.Fatalf("status=%q err=%v, want active", got.Status, err)
		}
		live, terminated, revocations := statusClockSessionCounts(t, db, c.ID)
		if live != 0 || terminated != 0 || len(revocations) != 0 {
			t.Fatalf("auto-promotion: live=%d terminated=%d revocations=%d, want 0/0/0", live, terminated, len(revocations))
		}
		if _, _, err := repository.ResolveAuthSession(ctx, db, token); err != repository.ErrAuthSessionNotFound {
			t.Fatalf("a session opened before the start date survived the promotion: %v", err)
		}
	})
}
