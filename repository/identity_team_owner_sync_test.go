package repository

import (
	"context"
	"fmt"
	"testing"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

// TestCreateTeam_NewOwnerBecomesLeadMember asserts that creating a team with an
// owner who has NO prior membership inserts a fresh membership row with
// role='lead' and active=true (the INSERT path of ensureOwnerMemberships).
func TestCreateTeam_NewOwnerBecomesLeadMember(t *testing.T) {
	db := openTestDB(t) // skips when DB_URL is unset
	t.Cleanup(func() { _ = db.Close() })

	ctx := context.Background()

	collabSlug := fmt.Sprintf("owner-sync-new-%s", uuid.New().String()[:8])
	collab, err := CreateCollaborator(ctx, db, model.CreateCollaboratorRequest{
		Slug:        collabSlug,
		DisplayName: "Owner Sync New Lead",
		Status:      "active",
	})
	if err != nil {
		t.Fatalf("seed collaborator: %v", err)
	}
	t.Cleanup(func() {
		_, _ = db.Exec(`DELETE FROM public.collaborators WHERE id = $1`, collab.ID)
	})

	team, err := CreateTeam(ctx, db, model.CreateTeamRequest{
		Slug:   "t-newlead-" + collab.ID.String()[:8],
		Name:   "new lead owner sync",
		Owners: []string{collab.ID.String()},
	})
	if err != nil {
		t.Fatalf("create team: %v", err)
	}
	t.Cleanup(func() {
		_, _ = db.Exec(`DELETE FROM public.team_memberships WHERE team_id = $1`, team.ID)
		_, _ = db.Exec(`DELETE FROM public.teams WHERE id = $1`, team.ID)
	})

	memberships, err := ListTeamMemberships(ctx, db, model.ListTeamMembershipsRequest{
		TeamID: team.ID.String(),
	})
	if err != nil {
		t.Fatalf("list team memberships: %v", err)
	}

	var found *model.TeamMembership
	for i := range memberships {
		if memberships[i].CollaboratorID == collab.ID {
			found = &memberships[i]
			break
		}
	}
	if found == nil {
		t.Fatalf("expected a membership row for new owner %s, got %d memberships: %+v", collab.ID, len(memberships), memberships)
	}
	if found.Role != "lead" {
		t.Fatalf("expected brand-new owner membership role 'lead', got %q", found.Role)
	}
	if !found.Active {
		t.Fatalf("expected new owner membership to be active, got active=false")
	}
}

// TestCreateTeam_PreservesExistingMemberRole asserts that promoting an EXISTING
// member to owner preserves their original role (does NOT clobber it to 'lead').
// The collaborator is first added as a 'member' (source='manual'); after the
// team gains them as an owner, their membership must still read role='member'
// and remain active — the ON CONFLICT path only (re)activates.
func TestCreateTeam_PreservesExistingMemberRole(t *testing.T) {
	db := openTestDB(t) // skips when DB_URL is unset
	t.Cleanup(func() { _ = db.Close() })

	ctx := context.Background()

	collabSlug := fmt.Sprintf("owner-sync-preserve-%s", uuid.New().String()[:8])
	collab, err := CreateCollaborator(ctx, db, model.CreateCollaboratorRequest{
		Slug:        collabSlug,
		DisplayName: "Owner Sync Preserve Role",
		Status:      "active",
	})
	if err != nil {
		t.Fatalf("seed collaborator: %v", err)
	}
	t.Cleanup(func() {
		_, _ = db.Exec(`DELETE FROM public.collaborators WHERE id = $1`, collab.ID)
	})

	// Create a team WITHOUT the collaborator as owner.
	team, err := CreateTeam(ctx, db, model.CreateTeamRequest{
		Slug:   "t-preserve-" + collab.ID.String()[:8],
		Name:   "preserve role owner sync",
		Owners: []string{},
	})
	if err != nil {
		t.Fatalf("create team: %v", err)
	}
	t.Cleanup(func() {
		_, _ = db.Exec(`DELETE FROM public.team_memberships WHERE team_id = $1`, team.ID)
		_, _ = db.Exec(`DELETE FROM public.teams WHERE id = $1`, team.ID)
	})

	// Add the collaborator as a plain 'member' via the manual upsert path.
	if _, err := UpsertTeamMembership(ctx, db, model.UpsertTeamMembershipRequest{
		TeamID:         team.ID.String(),
		CollaboratorID: collab.ID.String(),
		Role:           "member",
		Source:         "manual",
	}); err != nil {
		t.Fatalf("seed manual member membership: %v", err)
	}

	// Now promote them to owner via UpdateTeam.
	owners := []string{collab.ID.String()}
	if _, err := UpdateTeam(ctx, db, model.UpdateTeamRequest{
		ID:     team.ID.String(),
		Owners: &owners,
	}); err != nil {
		t.Fatalf("update team to add owner: %v", err)
	}

	memberships, err := ListTeamMemberships(ctx, db, model.ListTeamMembershipsRequest{
		TeamID: team.ID.String(),
	})
	if err != nil {
		t.Fatalf("list team memberships: %v", err)
	}

	var found *model.TeamMembership
	for i := range memberships {
		if memberships[i].CollaboratorID == collab.ID {
			found = &memberships[i]
			break
		}
	}
	if found == nil {
		t.Fatalf("expected the existing member %s to keep their membership, got %d memberships: %+v", collab.ID, len(memberships), memberships)
	}
	if found.Role != "member" {
		t.Fatalf("expected existing member role to be PRESERVED as 'member' (not clobbered to 'lead'), got %q", found.Role)
	}
	if !found.Active {
		t.Fatalf("expected promoted member membership to be active, got active=false")
	}
}

// TestUpdateTeam_RemovedOwnerDeactivatesOwnerSyncMembership asserts that
// removing a collaborator from teams.owners deactivates the membership that
// existed solely because of ownership (source='owner-sync'). The brand-new
// owner had no prior membership, so the owner-sync row created on CreateTeam is
// the one that must flip to active=false.
func TestUpdateTeam_RemovedOwnerDeactivatesOwnerSyncMembership(t *testing.T) {
	db := openTestDB(t) // skips when DB_URL is unset
	t.Cleanup(func() { _ = db.Close() })

	ctx := context.Background()

	collabSlug := fmt.Sprintf("owner-sync-deactivate-%s", uuid.New().String()[:8])
	collab, err := CreateCollaborator(ctx, db, model.CreateCollaboratorRequest{
		Slug:        collabSlug,
		DisplayName: "Owner Sync Deactivate",
		Status:      "active",
	})
	if err != nil {
		t.Fatalf("seed collaborator: %v", err)
	}
	t.Cleanup(func() {
		_, _ = db.Exec(`DELETE FROM public.collaborators WHERE id = $1`, collab.ID)
	})

	team, err := CreateTeam(ctx, db, model.CreateTeamRequest{
		Slug:   "t-deactivate-" + collab.ID.String()[:8],
		Name:   "deactivate owner sync",
		Owners: []string{collab.ID.String()},
	})
	if err != nil {
		t.Fatalf("create team: %v", err)
	}
	t.Cleanup(func() {
		_, _ = db.Exec(`DELETE FROM public.team_memberships WHERE team_id = $1`, team.ID)
		_, _ = db.Exec(`DELETE FROM public.teams WHERE id = $1`, team.ID)
	})

	// Remove the owner via UpdateTeam (Owners=[]).
	emptyOwners := []string{}
	if _, err := UpdateTeam(ctx, db, model.UpdateTeamRequest{
		ID:     team.ID.String(),
		Owners: &emptyOwners,
	}); err != nil {
		t.Fatalf("update team to remove owner: %v", err)
	}

	memberships, err := ListTeamMemberships(ctx, db, model.ListTeamMembershipsRequest{
		TeamID: team.ID.String(),
	})
	if err != nil {
		t.Fatalf("list team memberships: %v", err)
	}

	var found *model.TeamMembership
	for i := range memberships {
		if memberships[i].CollaboratorID == collab.ID {
			found = &memberships[i]
			break
		}
	}
	if found == nil {
		t.Fatalf("expected the owner-sync membership row for %s to still exist (deactivated, not deleted), got %d memberships: %+v", collab.ID, len(memberships), memberships)
	}
	if found.Active {
		t.Fatalf("expected removed owner's owner-sync membership to be deactivated (active=false), got active=true")
	}
}

// TestUpdateTeam_RemovedOwnerPreservesManualMembership asserts that removing an
// owner who was ALSO a real, manually-created member (source='manual') leaves
// that membership fully intact. Because the deactivate is gated on
// source='owner-sync', a manual membership survives the owner removal: the
// collaborator stays an active 'member'.
func TestUpdateTeam_RemovedOwnerPreservesManualMembership(t *testing.T) {
	db := openTestDB(t) // skips when DB_URL is unset
	t.Cleanup(func() { _ = db.Close() })

	ctx := context.Background()

	collabSlug := fmt.Sprintf("owner-sync-manual-%s", uuid.New().String()[:8])
	collab, err := CreateCollaborator(ctx, db, model.CreateCollaboratorRequest{
		Slug:        collabSlug,
		DisplayName: "Owner Sync Manual Survives",
		Status:      "active",
	})
	if err != nil {
		t.Fatalf("seed collaborator: %v", err)
	}
	t.Cleanup(func() {
		_, _ = db.Exec(`DELETE FROM public.collaborators WHERE id = $1`, collab.ID)
	})

	// Create a team WITHOUT the collaborator as owner.
	team, err := CreateTeam(ctx, db, model.CreateTeamRequest{
		Slug:   "t-manual-" + collab.ID.String()[:8],
		Name:   "manual survives owner sync",
		Owners: []string{},
	})
	if err != nil {
		t.Fatalf("create team: %v", err)
	}
	t.Cleanup(func() {
		_, _ = db.Exec(`DELETE FROM public.team_memberships WHERE team_id = $1`, team.ID)
		_, _ = db.Exec(`DELETE FROM public.teams WHERE id = $1`, team.ID)
	})

	// Seed a manual 'member' membership (source='manual').
	if _, err := UpsertTeamMembership(ctx, db, model.UpsertTeamMembershipRequest{
		TeamID:         team.ID.String(),
		CollaboratorID: collab.ID.String(),
		Role:           "member",
		Source:         "manual",
	}); err != nil {
		t.Fatalf("seed manual member membership: %v", err)
	}

	// Promote to owner, then remove as owner.
	owners := []string{collab.ID.String()}
	if _, err := UpdateTeam(ctx, db, model.UpdateTeamRequest{
		ID:     team.ID.String(),
		Owners: &owners,
	}); err != nil {
		t.Fatalf("update team to add owner: %v", err)
	}
	emptyOwners := []string{}
	if _, err := UpdateTeam(ctx, db, model.UpdateTeamRequest{
		ID:     team.ID.String(),
		Owners: &emptyOwners,
	}); err != nil {
		t.Fatalf("update team to remove owner: %v", err)
	}

	memberships, err := ListTeamMemberships(ctx, db, model.ListTeamMembershipsRequest{
		TeamID: team.ID.String(),
	})
	if err != nil {
		t.Fatalf("list team memberships: %v", err)
	}

	var found *model.TeamMembership
	for i := range memberships {
		if memberships[i].CollaboratorID == collab.ID {
			found = &memberships[i]
			break
		}
	}
	if found == nil {
		t.Fatalf("expected the manual membership for %s to survive owner removal, got %d memberships: %+v", collab.ID, len(memberships), memberships)
	}
	if !found.Active {
		t.Fatalf("expected manual membership to remain active after owner removal (source≠'owner-sync'), got active=false")
	}
	if found.Role != "member" {
		t.Fatalf("expected manual membership role to remain 'member' after owner removal, got %q", found.Role)
	}
}
