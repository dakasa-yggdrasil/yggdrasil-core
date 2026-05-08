package addons

import (
	"context"
	"database/sql"
	"os"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	_ "github.com/lib/pq"
)

func dbForStatusClockTest(t *testing.T) *sql.DB {
	t.Helper()
	dsn := os.Getenv("DB_URL")
	if dsn == "" {
		t.Skip("DB_URL not set; skipping status clock test")
	}
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	if err := db.Ping(); err != nil {
		t.Fatalf("ping db: %v", err)
	}
	return db
}

func cleanCollabsForStatusClock(t *testing.T, db *sql.DB) {
	t.Helper()
	if _, err := db.Exec(`DELETE FROM public.lifecycle_events WHERE collaborator_id IN (SELECT id FROM public.collaborators WHERE slug LIKE 'clock-test-%')`); err != nil {
		t.Fatalf("delete lifecycle_events: %v", err)
	}
	if _, err := db.Exec(`DELETE FROM public.collaborators WHERE slug LIKE 'clock-test-%'`); err != nil {
		t.Fatalf("clean collaborators: %v", err)
	}
}

func TestStatusClockTick_PromotesPendingStart(t *testing.T) {
	db := dbForStatusClockTest(t)
	defer func() { _ = db.Close() }()
	cleanCollabsForStatusClock(t, db)

	yesterday := time.Now().AddDate(0, 0, -1).Format("2006-01-02")
	collab, err := repository.CreateCollaborator(context.Background(), db, model.CreateCollaboratorRequest{
		Slug:           "clock-test-pending",
		DisplayName:    "Pending Start",
		Status:         "pending_start",
		EmploymentData: map[string]any{"start_date": yesterday},
	})
	if err != nil {
		t.Fatalf("seed: %v", err)
	}

	if err := RunCollaboratorStatusClockTick(context.Background(), db); err != nil {
		t.Fatalf("RunCollaboratorStatusClockTick: %v", err)
	}

	got, err := repository.GetCollaborator(context.Background(), db, collab.ID.String())
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Status != "active" {
		t.Fatalf("expected active after start_date passed, got %q", got.Status)
	}
}

func TestStatusClockTick_OffboardsPastEndDate(t *testing.T) {
	db := dbForStatusClockTest(t)
	defer func() { _ = db.Close() }()
	cleanCollabsForStatusClock(t, db)

	yesterday := time.Now().AddDate(0, 0, -1).Format("2006-01-02")
	collab, err := repository.CreateCollaborator(context.Background(), db, model.CreateCollaboratorRequest{
		Slug:        "clock-test-offboard",
		DisplayName: "End Date",
		Status:      "active",
		EmploymentData: map[string]any{
			"start_date": "2026-01-01",
			"end_date":   yesterday,
		},
	})
	if err != nil {
		t.Fatalf("seed: %v", err)
	}

	if err := RunCollaboratorStatusClockTick(context.Background(), db); err != nil {
		t.Fatalf("RunCollaboratorStatusClockTick: %v", err)
	}

	got, err := repository.GetCollaborator(context.Background(), db, collab.ID.String())
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Status != "offboarded" {
		t.Fatalf("expected offboarded, got %q", got.Status)
	}

	events, _ := repository.ListLifecycleEventsByCollaborator(context.Background(), db, model.ListLifecycleEventsRequest{
		CollaboratorID: collab.ID,
	})
	var found bool
	for _, e := range events {
		if e.EventType == model.LifecycleEventOffboarded && e.Payload["reason"] == "contract-end" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected offboarded event with reason=contract-end recorded by clock")
	}
}

func TestStatusClockTick_LeavesFutureDatesAlone(t *testing.T) {
	db := dbForStatusClockTest(t)
	defer func() { _ = db.Close() }()
	cleanCollabsForStatusClock(t, db)

	tomorrow := time.Now().AddDate(0, 0, 1).Format("2006-01-02")
	collab, err := repository.CreateCollaborator(context.Background(), db, model.CreateCollaboratorRequest{
		Slug:           "clock-test-future",
		DisplayName:    "Future Start",
		Status:         "pending_start",
		EmploymentData: map[string]any{"start_date": tomorrow},
	})
	if err != nil {
		t.Fatalf("seed: %v", err)
	}

	if err := RunCollaboratorStatusClockTick(context.Background(), db); err != nil {
		t.Fatalf("RunCollaboratorStatusClockTick: %v", err)
	}

	got, err := repository.GetCollaborator(context.Background(), db, collab.ID.String())
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Status != "pending_start" {
		t.Fatalf("expected status unchanged, got %q", got.Status)
	}
}
