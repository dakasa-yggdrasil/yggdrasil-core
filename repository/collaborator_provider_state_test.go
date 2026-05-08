package repository

import (
	"context"
	"database/sql"
	"os"
	"testing"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	_ "github.com/lib/pq"
)

func dbForProviderStateTest(t *testing.T) *sql.DB {
	t.Helper()
	dsn := os.Getenv("DB_URL")
	if dsn == "" {
		t.Skip("DB_URL not set; skipping collaborator_provider_state integration test")
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

func cleanProviderStateAndCollaborators(t *testing.T, db *sql.DB) {
	t.Helper()
	if _, err := db.Exec(`DELETE FROM public.collaborator_provider_state WHERE collaborator_id IN (SELECT id FROM public.collaborators WHERE slug LIKE 'provstate-test-%')`); err != nil {
		t.Fatalf("clean collaborator_provider_state: %v", err)
	}
	if _, err := db.Exec(`DELETE FROM public.collaborators WHERE slug LIKE 'provstate-test-%'`); err != nil {
		t.Fatalf("clean collaborators: %v", err)
	}
}

func TestUpsertCollaboratorProviderState_CreateAndUpdate(t *testing.T) {
	db := dbForProviderStateTest(t)
	defer func() { _ = db.Close() }()
	cleanProviderStateAndCollaborators(t, db)

	collab, err := CreateCollaborator(context.Background(), db, model.CreateCollaboratorRequest{
		Slug:        "provstate-test-create",
		DisplayName: "Provider State Test",
	})
	if err != nil {
		t.Fatalf("seed collaborator: %v", err)
	}

	ctx := context.Background()
	state, err := UpsertCollaboratorProviderState(ctx, db, model.UpsertProviderStateRequest{
		CollaboratorID: collab.ID,
		Provider:       "github",
		ExternalID:     "gh:12345",
		DesiredState:   map[string]any{"role": "engineer", "teams": []string{"platform"}},
	})
	if err != nil {
		t.Fatalf("UpsertCollaboratorProviderState (create): %v", err)
	}
	if state.Provider != "github" || state.ExternalID != "gh:12345" {
		t.Fatalf("unexpected state after create: %+v", state)
	}
	if state.ErrorCount != 0 {
		t.Fatalf("expected error_count=0 on fresh row, got %d", state.ErrorCount)
	}

	updated, err := UpsertCollaboratorProviderState(ctx, db, model.UpsertProviderStateRequest{
		CollaboratorID: collab.ID,
		Provider:       "github",
		ExternalID:     "gh:12345",
		DesiredState:   map[string]any{"role": "engineer", "teams": []string{"platform", "billing"}},
		PendingAction:  model.PendingActionUpdate,
	})
	if err != nil {
		t.Fatalf("UpsertCollaboratorProviderState (update): %v", err)
	}
	if updated.PendingAction != model.PendingActionUpdate {
		t.Fatalf("expected pending_action=update, got %q", updated.PendingAction)
	}
	teams := updated.DesiredState["teams"].([]any)
	if len(teams) != 2 {
		t.Fatalf("expected 2 teams in desired_state, got %d", len(teams))
	}
}

func TestListProviderStateByCollaborator_AllProviders(t *testing.T) {
	db := dbForProviderStateTest(t)
	defer func() { _ = db.Close() }()
	cleanProviderStateAndCollaborators(t, db)

	collab, err := CreateCollaborator(context.Background(), db, model.CreateCollaboratorRequest{
		Slug:        "provstate-test-list",
		DisplayName: "List Test",
	})
	if err != nil {
		t.Fatalf("seed collaborator: %v", err)
	}

	ctx := context.Background()
	for _, p := range []string{"github", "slack", "google-workspace"} {
		if _, err := UpsertCollaboratorProviderState(ctx, db, model.UpsertProviderStateRequest{
			CollaboratorID: collab.ID,
			Provider:       p,
			DesiredState:   map[string]any{"role": "engineer"},
		}); err != nil {
			t.Fatalf("seed %s: %v", p, err)
		}
	}

	states, err := ListProviderStateByCollaborator(ctx, db, collab.ID)
	if err != nil {
		t.Fatalf("ListProviderStateByCollaborator: %v", err)
	}
	if len(states) != 3 {
		t.Fatalf("expected 3 states, got %d", len(states))
	}
}

func TestMarkProviderStateError_IncrementsCount(t *testing.T) {
	db := dbForProviderStateTest(t)
	defer func() { _ = db.Close() }()
	cleanProviderStateAndCollaborators(t, db)

	collab, err := CreateCollaborator(context.Background(), db, model.CreateCollaboratorRequest{
		Slug:        "provstate-test-error",
		DisplayName: "Error Test",
	})
	if err != nil {
		t.Fatalf("seed collaborator: %v", err)
	}
	ctx := context.Background()
	if _, err := UpsertCollaboratorProviderState(ctx, db, model.UpsertProviderStateRequest{
		CollaboratorID: collab.ID,
		Provider:       "slack",
		DesiredState:   map[string]any{},
	}); err != nil {
		t.Fatalf("seed state: %v", err)
	}

	if err := MarkProviderStateError(ctx, db, collab.ID, "slack", "rate limited"); err != nil {
		t.Fatalf("MarkProviderStateError: %v", err)
	}
	if err := MarkProviderStateError(ctx, db, collab.ID, "slack", "rate limited again"); err != nil {
		t.Fatalf("MarkProviderStateError: %v", err)
	}

	states, err := ListProviderStateByCollaborator(ctx, db, collab.ID)
	if err != nil {
		t.Fatalf("ListProviderStateByCollaborator: %v", err)
	}
	if len(states) != 1 {
		t.Fatalf("expected 1 state, got %d", len(states))
	}
	if states[0].ErrorCount != 2 {
		t.Fatalf("expected error_count=2, got %d", states[0].ErrorCount)
	}
	if states[0].LastError != "rate limited again" {
		t.Fatalf("expected last_error='rate limited again', got %q", states[0].LastError)
	}
}
