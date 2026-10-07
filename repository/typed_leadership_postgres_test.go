package repository

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/contactphone"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

func TestTypedTeamLeadershipPostgres(t *testing.T) {
	db := phoneDirectoryPostgres(t)
	ctx := context.Background()
	t.Setenv(contactphone.EnrollmentPolicyEnv, "false")
	person := phoneFixture(t, db, false)
	owners := []string{person.Slug}
	refusedSlug := "lead-refused-" + uuid.NewString()
	if _, err := CreateTeam(ctx, db, model.CreateTeamRequest{Slug: refusedSlug, Name: "Refused", Owners: owners}); !errors.Is(err, ErrLeadershipAssertionRequired) {
		t.Fatal("creation granted leadership without explicit intent")
	}
	var exists bool
	if db.QueryRow(`SELECT EXISTS(SELECT 1 FROM teams WHERE slug=$1)`, refusedSlug).Scan(&exists) != nil || exists {
		t.Fatal("refused creation left a team")
	}
	team, err := CreateTeam(ctx, db, model.CreateTeamRequest{Slug: "lead-ci-" + uuid.NewString(), Name: "Leadership CI"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = db.Exec(`DELETE FROM teams WHERE id=$1`, team.ID) })
	member, err := UpsertTeamMembership(ctx, db, model.UpsertTeamMembershipRequest{TeamID: team.ID.String(), CollaboratorID: person.ID.String(), Role: "founder", Source: "manual"})
	if err != nil {
		t.Fatal(err)
	}
	if member.IsLead {
		t.Fatal("free-form rank granted leadership")
	}
	// Simulate pre54 administrative input. It is not consumer authority.
	if _, err := db.Exec(`UPDATE teams SET owners=$2::jsonb WHERE id=$1`, team.ID, `["`+person.Slug+`"]`); err != nil {
		t.Fatal(err)
	}
	fresh := func() model.Team {
		t.Helper()
		v, e := GetTeam(ctx, db, team.ID.String())
		if e != nil {
			t.Fatal(e)
		}
		return v
	}
	assertLeader := func(at time.Time, want bool) {
		t.Helper()
		s, e := LoadDirectorySnapshotAt(ctx, db, nil, false, nil, at)
		if e != nil {
			t.Fatal(e)
		}
		for _, v := range s.Teams {
			if v.ID == team.ID.String() {
				if (len(v.OwnerIDs) == 1) != want || want && v.OwnerIDs[0] != person.ID.String() {
					t.Fatal("typed/window leadership mismatch")
				}
				return
			}
		}
		t.Fatal("team missing")
	}
	at := time.Date(2030, 1, 1, 12, 0, 0, 0, time.UTC)
	assertLeader(at, false)
	team = fresh()
	name := "Ordinary rename"
	updated, err := UpdateTeam(ctx, db, model.UpdateTeamRequest{ID: team.ID.String(), Name: &name})
	if err != nil {
		t.Fatal(err)
	}
	assertLeader(at, false)
	metadata := map[string]any{"cannot": "commit"}
	absent := model.UpdateTeamRequest{ID: team.ID.String(), Name: &name, Owners: &owners, Metadata: &metadata}
	if _, err := UpdateTeam(ctx, db, absent); !errors.Is(err, ErrLeadershipAssertionRequired) {
		t.Fatal("cached full update did not refuse")
	}
	stale := team.UpdatedAt.Add(-time.Hour)
	absent.AssertLeadership = true
	absent.ExpectedUpdatedAt = &stale
	if _, err := UpdateTeam(ctx, db, absent); !errors.Is(err, ErrLeadershipVersionConflict) {
		t.Fatal("stale assertion did not refuse")
	}
	unchanged := fresh()
	if !unchanged.UpdatedAt.Equal(updated.UpdatedAt) || unchanged.Metadata["cannot"] != nil {
		t.Fatal("refused assertion partially wrote")
	}
	// Repair is explicit even when historical input is unchanged, and preserves
	// the original rank and source instead of rewriting founder/CEO semantics.
	req := model.UpdateTeamRequest{ID: team.ID.String(), Owners: &owners, AssertLeadership: true, ExpectedUpdatedAt: &unchanged.UpdatedAt}
	team, err = UpdateTeam(ctx, db, req)
	if err != nil {
		t.Fatal(err)
	}
	memberships, err := ListTeamMemberships(ctx, db, model.ListTeamMembershipsRequest{TeamID: team.ID.String()})
	if err != nil || len(memberships) != 1 {
		t.Fatal("membership missing")
	}
	if !memberships[0].IsLead || memberships[0].Role != "founder" || memberships[0].Source != "manual" {
		t.Fatal("repair clobbered rank/source or did not assert typed bit")
	}
	assertLeader(at, true)
	for _, scenario := range []struct {
		name         string
		active, lead bool
		start, end   *time.Time
		teamStatus   string
		want         bool
	}{
		{"inclusive", true, true, &at, &at, "active", true},
		{"inactive", false, true, nil, nil, "active", false},
		{"demoted", true, false, nil, nil, "active", false},
		{"expired", true, true, nil, timePtr(at.Add(-time.Second)), "active", false},
		{"future", true, true, timePtr(at.Add(time.Second)), nil, "active", false},
		{"archived_team", true, true, nil, nil, "archived", false},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			if _, e := db.Exec(`UPDATE team_memberships SET active=$2,is_lead=$3,starts_at=$4,ends_at=$5 WHERE id=$1`, member.ID, scenario.active, scenario.lead, scenario.start, scenario.end); e != nil {
				t.Fatal(e)
			}
			if _, e := db.Exec(`UPDATE teams SET status=$2 WHERE id=$1`, team.ID, scenario.teamStatus); e != nil {
				t.Fatal(e)
			}
			assertLeader(at, scenario.want)
		})
	}
	if _, err := db.Exec(`UPDATE team_memberships SET active=TRUE,is_lead=TRUE,starts_at=NULL,ends_at=$2 WHERE id=$1`, member.ID, at); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE teams SET status='active' WHERE id=$1`, team.ID); err != nil {
		t.Fatal(err)
	}
	assertLeader(at, true)
	assertLeader(at.Add(time.Second), false)
	assertLeader(at, true)
	team = fresh()
	empty := []string{}
	team, err = UpdateTeam(ctx, db, model.UpdateTeamRequest{ID: team.ID.String(), Owners: &empty, AssertLeadership: true, ExpectedUpdatedAt: &team.UpdatedAt})
	if err != nil {
		t.Fatal(err)
	}
	var lead, active bool
	var role, source string
	if db.QueryRow(`SELECT is_lead,active,role,source FROM team_memberships WHERE id=$1`, member.ID).Scan(&lead, &active, &role, &source) != nil || lead || !active || role != "founder" || source != "manual" {
		t.Fatal("removal destroyed manual membership/rank/source")
	}
	// Invalid owner and the caller's other changes share one transaction.
	bad := []string{uuid.NewString()}
	badName := "Must roll back"
	if _, err := UpdateTeam(ctx, db, model.UpdateTeamRequest{ID: team.ID.String(), Owners: &bad, Name: &badName, Metadata: &metadata, AssertLeadership: true, ExpectedUpdatedAt: &team.UpdatedAt}); err == nil {
		t.Fatal("unresolved owner accepted")
	}
	after := fresh()
	if after.Name != team.Name || after.Metadata["cannot"] != nil || !after.UpdatedAt.Equal(team.UpdatedAt) {
		t.Fatal("failed membership assertion partially committed team")
	}
	if _, err := UpdateTeam(ctx, db, model.UpdateTeamRequest{ID: uuid.NewString(), Name: &name}); !errors.Is(err, ErrTeamNotFound) {
		t.Fatal("missing team lost its canonical not-found error")
	}
	// Root-admin promotion cannot turn an existing formal leader into an owner
	// of the privileged access group, even when owners is omitted.
	if _, err := db.Exec(`UPDATE team_memberships SET is_lead=TRUE WHERE id=$1`, member.ID); err != nil {
		t.Fatal(err)
	}
	rootTraits := map[string]any{"is_root_admin": true}
	if _, err := UpdateTeam(ctx, db, model.UpdateTeamRequest{ID: team.ID.String(), Traits: &rootTraits}); err == nil {
		t.Fatal("root-admin promotion retained formal leadership")
	}
}

func timePtr(v time.Time) *time.Time { return &v }
