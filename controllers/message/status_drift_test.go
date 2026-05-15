package message

import (
	"testing"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

func collabActive(t *testing.T) model.Collaborator {
	t.Helper()
	id := uuid.New()
	return model.Collaborator{
		ID:           id,
		Slug:         "alice",
		PrimaryEmail: "alice@dakasa.me",
		Status:       "active",
	}
}

func TestObservedShowsStatusDrift_GoogleSuspendedTriggers(t *testing.T) {
	drifted, signal := observedShowsStatusDrift(
		"google-workspace",
		map[string]any{"suspended": true, "primaryEmail": "alice@dakasa.me"},
		collabActive(t),
	)
	if !drifted {
		t.Fatal("expected drift for google.suspended=true vs collaborator.status=active")
	}
	if signal != "suspended" {
		t.Fatalf("signal=%q want suspended", signal)
	}
}

func TestObservedShowsStatusDrift_SlackDeletedTriggers(t *testing.T) {
	drifted, signal := observedShowsStatusDrift(
		"slack",
		map[string]any{"deleted": true, "id": "U1"},
		collabActive(t),
	)
	if !drifted || signal != "deleted" {
		t.Fatalf("expected (true, deleted), got (%v, %q)", drifted, signal)
	}
}

func TestObservedShowsStatusDrift_NoSignalWhenAligned(t *testing.T) {
	cases := []struct {
		name     string
		provider string
		observed map[string]any
	}{
		{"google not suspended", "google-workspace", map[string]any{"suspended": false}},
		{"google missing suspended", "google-workspace", map[string]any{"primaryEmail": "x@y"}},
		{"slack not deleted", "slack", map[string]any{"deleted": false}},
		{"unknown provider", "github", map[string]any{"suspended": true}},
		{"nil observed", "google-workspace", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			drifted, _ := observedShowsStatusDrift(tc.provider, tc.observed, collabActive(t))
			if drifted {
				t.Fatalf("expected no drift, got true for %v", tc.observed)
			}
		})
	}
}

func TestObservedShowsStatusDrift_SkipsWhenCollaboratorNotActive(t *testing.T) {
	cases := []string{"suspended", "offboarded", "on_leave", ""}
	for _, status := range cases {
		t.Run("status="+status, func(t *testing.T) {
			col := collabActive(t)
			col.Status = status
			drifted, _ := observedShowsStatusDrift(
				"google-workspace",
				map[string]any{"suspended": true},
				col,
			)
			if drifted {
				t.Fatalf("expected no drift when canonical status=%q (provider already aligned)", status)
			}
		})
	}
}
