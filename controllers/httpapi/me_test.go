package httpapi

import (
	"encoding/json"
	"testing"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

// TestBuildMeResponseIncludesPermissions locks down the /me contract the
// surface relies on for capability-aware rendering: the response carries
// the viewer's effective yggdrasil:* permissions — the SAME flat, sorted,
// de-duplicated list the ops gates resolve via
// repository.ResolveYggdrasilPermissions — under a top-level
// `permissions` field, alongside the collaborator and memberships.
func TestBuildMeResponseIncludesPermissions(t *testing.T) {
	collab := model.Collaborator{
		ID:          uuid.New(),
		Slug:        "gio",
		DisplayName: "Giovanni",
	}
	memberships := []model.TeamMembership{
		{ID: uuid.New(), CollaboratorID: collab.ID, Role: "lead"},
	}
	// Union of effective ops across the viewer's active memberships — the
	// exact shape ResolveYggdrasilPermissions returns (sorted, de-duped).
	perms := []string{"yggdrasil:manage_teams", "yggdrasil:view_people"}

	resp := buildMeResponse(collab, memberships, perms)

	// Round-trip through JSON so we assert the WIRE contract the surface
	// sees, not just the in-memory map.
	raw, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("marshal me response: %v", err)
	}

	var decoded struct {
		Collaborator *model.Collaborator     `json:"collaborator"`
		Memberships  []model.TeamMembership  `json:"memberships"`
		Permissions  []string                `json:"permissions"`
	}
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("unmarshal me response: %v", err)
	}

	if decoded.Permissions == nil {
		t.Fatalf("response missing `permissions` field; body=%s", raw)
	}
	if len(decoded.Permissions) != 2 {
		t.Fatalf("permissions = %v, want 2 entries", decoded.Permissions)
	}
	want := map[string]bool{"yggdrasil:view_people": false, "yggdrasil:manage_teams": false}
	for _, p := range decoded.Permissions {
		if _, ok := want[p]; !ok {
			t.Errorf("unexpected permission %q in /me response", p)
			continue
		}
		want[p] = true
	}
	for p, seen := range want {
		if !seen {
			t.Errorf("expected permission %q in /me response, not found (got %v)", p, decoded.Permissions)
		}
	}

	if decoded.Collaborator == nil || decoded.Collaborator.ID != collab.ID {
		t.Errorf("collaborator not echoed back correctly: %+v", decoded.Collaborator)
	}
	if len(decoded.Memberships) != 1 {
		t.Errorf("memberships = %v, want 1 entry", decoded.Memberships)
	}
}

// TestBuildMeResponseEmptyPermissionsIsAlwaysArray guards the fail-closed
// contract: a viewer with no grants must still get `permissions: []` (a
// JSON array, never null), so the surface can iterate without a null guard
// and so "no permissions" reliably hides every gated control.
func TestBuildMeResponseEmptyPermissionsIsAlwaysArray(t *testing.T) {
	collab := model.Collaborator{ID: uuid.New(), Slug: "no-grants"}

	resp := buildMeResponse(collab, nil, nil)
	raw, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("marshal me response: %v", err)
	}

	var decoded map[string]json.RawMessage
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("unmarshal me response: %v", err)
	}
	got, ok := decoded["permissions"]
	if !ok {
		t.Fatalf("response missing `permissions` field; body=%s", raw)
	}
	if string(got) != "[]" {
		t.Fatalf("permissions should serialize as [] for a viewer with no grants, got %s", got)
	}
}
