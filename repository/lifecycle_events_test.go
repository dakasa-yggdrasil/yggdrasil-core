package repository

import (
	"context"
	"database/sql"
	"os"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
	_ "github.com/lib/pq"
)

func dbForLifecycleTest(t *testing.T) *sql.DB {
	t.Helper()
	dsn := os.Getenv("DB_URL")
	if dsn == "" {
		t.Skip("DB_URL not set; skipping lifecycle_events repository integration test")
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

func cleanLifecycleAndCollaborators(t *testing.T, db *sql.DB) {
	t.Helper()
	if _, err := db.Exec(`DELETE FROM public.lifecycle_events WHERE collaborator_id IN (SELECT id FROM public.collaborators WHERE slug LIKE 'lifecycle-test-%')`); err != nil {
		t.Fatalf("clean lifecycle_events: %v", err)
	}
	if _, err := db.Exec(`DELETE FROM public.collaborators WHERE slug LIKE 'lifecycle-test-%'`); err != nil {
		t.Fatalf("clean collaborators: %v", err)
	}
}

func seedTestCollaborator(t *testing.T, db *sql.DB, slugSuffix string) uuid.UUID {
	t.Helper()
	collab, err := CreateCollaborator(context.Background(), db, model.CreateCollaboratorRequest{
		Slug:        "lifecycle-test-" + slugSuffix,
		DisplayName: "Lifecycle Test " + slugSuffix,
	})
	if err != nil {
		t.Fatalf("seed collaborator: %v", err)
	}
	return collab.ID
}

func TestAppendLifecycleEvent_BasicInsert(t *testing.T) {
	db := dbForLifecycleTest(t)
	defer func() { _ = db.Close() }()
	cleanLifecycleAndCollaborators(t, db)

	collabID := seedTestCollaborator(t, db, "basic")

	ctx := context.Background()
	event, err := AppendLifecycleEvent(ctx, db, model.AppendLifecycleEventRequest{
		CollaboratorID: collabID,
		EventType:      model.LifecycleEventHired,
		Payload: map[string]any{
			"start_date": "2026-05-08",
			"role":       "engineer",
		},
		ActorType: model.ActorTypeAPI,
		ActorID:   "operator@dakasa.me",
	})
	if err != nil {
		t.Fatalf("AppendLifecycleEvent: %v", err)
	}
	if event.ID == uuid.Nil {
		t.Fatalf("expected non-nil ID")
	}
	if event.EventType != model.LifecycleEventHired {
		t.Fatalf("expected event_type=hired, got %q", event.EventType)
	}
	if event.OccurredAt.IsZero() {
		t.Fatalf("expected non-zero OccurredAt")
	}
	if event.Payload["role"] != "engineer" {
		t.Fatalf("expected payload.role=engineer, got %v", event.Payload["role"])
	}
}

func TestAppendLifecycleEvent_RejectsInvalidActorType(t *testing.T) {
	db := dbForLifecycleTest(t)
	defer func() { _ = db.Close() }()
	cleanLifecycleAndCollaborators(t, db)

	collabID := seedTestCollaborator(t, db, "bad-actor")

	_, err := AppendLifecycleEvent(context.Background(), db, model.AppendLifecycleEventRequest{
		CollaboratorID: collabID,
		EventType:      model.LifecycleEventHired,
		ActorType:      "alien",
	})
	if err == nil {
		t.Fatalf("expected error for invalid actor_type, got nil")
	}
}

func TestAppendLifecycleEvent_FutureEffectiveAt(t *testing.T) {
	db := dbForLifecycleTest(t)
	defer func() { _ = db.Close() }()
	cleanLifecycleAndCollaborators(t, db)

	collabID := seedTestCollaborator(t, db, "future")

	future := time.Now().Add(72 * time.Hour)
	event, err := AppendLifecycleEvent(context.Background(), db, model.AppendLifecycleEventRequest{
		CollaboratorID: collabID,
		EventType:      model.LifecycleEventOffboarded,
		ActorType:      model.ActorTypeAPI,
		EffectiveAt:    &future,
	})
	if err != nil {
		t.Fatalf("AppendLifecycleEvent: %v", err)
	}
	if event.EffectiveAt.Before(time.Now().Add(70 * time.Hour)) {
		t.Fatalf("expected EffectiveAt ~72h in future, got %v", event.EffectiveAt)
	}
}

func TestListLifecycleEventsByCollaborator_OrdersByOccurredDesc(t *testing.T) {
	db := dbForLifecycleTest(t)
	defer func() { _ = db.Close() }()
	cleanLifecycleAndCollaborators(t, db)

	collabID := seedTestCollaborator(t, db, "list")

	ctx := context.Background()
	for _, et := range []string{model.LifecycleEventHired, model.LifecycleEventRoleChanged, model.LifecycleEventTeamJoined} {
		if _, err := AppendLifecycleEvent(ctx, db, model.AppendLifecycleEventRequest{
			CollaboratorID: collabID,
			EventType:      et,
			ActorType:      model.ActorTypeAPI,
		}); err != nil {
			t.Fatalf("seed %s: %v", et, err)
		}
		time.Sleep(2 * time.Millisecond)
	}

	events, err := ListLifecycleEventsByCollaborator(ctx, db, model.ListLifecycleEventsRequest{
		CollaboratorID: collabID,
	})
	if err != nil {
		t.Fatalf("ListLifecycleEventsByCollaborator: %v", err)
	}
	if len(events) != 3 {
		t.Fatalf("expected 3 events, got %d", len(events))
	}
	if events[0].EventType != model.LifecycleEventTeamJoined {
		t.Fatalf("expected newest first (team-joined), got %q", events[0].EventType)
	}
	if events[2].EventType != model.LifecycleEventHired {
		t.Fatalf("expected oldest last (hired), got %q", events[2].EventType)
	}
}

func TestListLifecycleEventsByCollaborator_FilterByEventType(t *testing.T) {
	db := dbForLifecycleTest(t)
	defer func() { _ = db.Close() }()
	cleanLifecycleAndCollaborators(t, db)

	collabID := seedTestCollaborator(t, db, "filter")

	ctx := context.Background()
	for _, et := range []string{model.LifecycleEventHired, model.LifecycleEventRoleChanged, model.LifecycleEventRoleChanged} {
		if _, err := AppendLifecycleEvent(ctx, db, model.AppendLifecycleEventRequest{
			CollaboratorID: collabID,
			EventType:      et,
			ActorType:      model.ActorTypeAPI,
		}); err != nil {
			t.Fatalf("seed %s: %v", et, err)
		}
	}

	events, err := ListLifecycleEventsByCollaborator(ctx, db, model.ListLifecycleEventsRequest{
		CollaboratorID: collabID,
		EventType:      model.LifecycleEventRoleChanged,
	})
	if err != nil {
		t.Fatalf("ListLifecycleEventsByCollaborator: %v", err)
	}
	if len(events) != 2 {
		t.Fatalf("expected 2 role-changed events, got %d", len(events))
	}
}
