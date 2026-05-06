package oidc

import (
	"context"
	"database/sql"
	"os"
	"testing"

	"github.com/google/uuid"
	_ "github.com/lib/pq"
)

func dbForClaimsTest(t *testing.T) *sql.DB {
	t.Helper()
	dsn := os.Getenv("DB_URL")
	if dsn == "" {
		t.Skip("DB_URL not set; skipping OIDC claims test")
	}
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	if err := db.Ping(); err != nil {
		t.Fatalf("ping db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// seedClaimsFixtures provisions a throwaway collaborator and two teams,
// returning their identifiers. All rows are removed via t.Cleanup so the
// helper is safe to use under -shuffle/-count without polluting other tests.
func seedClaimsFixtures(t *testing.T, db *sql.DB) (collabID uuid.UUID, teamA, teamB string) {
	t.Helper()
	ctx := context.Background()
	suffix := uuid.NewString()[:8]
	collabSlug := "oidc-claims-test-" + suffix
	teamA = "oidc-claims-test-team-a-" + suffix
	teamB = "oidc-claims-test-team-b-" + suffix

	t.Cleanup(func() {
		ctx := context.Background()
		_, _ = db.ExecContext(ctx, `DELETE FROM team_memberships WHERE collaborator_id IN (SELECT id FROM collaborators WHERE slug=$1)`, collabSlug)
		_, _ = db.ExecContext(ctx, `DELETE FROM teams WHERE slug IN ($1, $2)`, teamA, teamB)
		_, _ = db.ExecContext(ctx, `DELETE FROM collaborators WHERE slug=$1`, collabSlug)
	})

	if err := db.QueryRowContext(ctx, `
		INSERT INTO collaborators (slug, status, display_name, primary_email)
		VALUES ($1, 'active', 'Claims Test', $2)
		RETURNING id
	`, collabSlug, collabSlug+"@dakasa.me").Scan(&collabID); err != nil {
		t.Fatalf("insert collab: %v", err)
	}
	for _, slug := range []string{teamA, teamB} {
		if _, err := db.ExecContext(ctx, `
			INSERT INTO teams (slug, name, type, status)
			VALUES ($1, $1, 'access_group', 'active')
		`, slug); err != nil {
			t.Fatalf("insert team %s: %v", slug, err)
		}
	}
	return collabID, teamA, teamB
}

func TestBuildTeamsClaim_ReturnsActiveTeamsSorted(t *testing.T) {
	db := dbForClaimsTest(t)
	cid, teamA, teamB := seedClaimsFixtures(t, db)
	ctx := context.Background()

	if _, err := db.ExecContext(ctx, `
		INSERT INTO team_memberships (team_id, collaborator_id, active)
		SELECT id, $1, TRUE FROM teams WHERE slug IN ($2, $3)
	`, cid, teamA, teamB); err != nil {
		t.Fatalf("insert memberships: %v", err)
	}

	got, err := buildTeamsClaim(ctx, db, cid)
	if err != nil {
		t.Fatalf("buildTeamsClaim: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d teams, want 2: %v", len(got), got)
	}
	// Slugs sorted ASC; teamA < teamB by construction (ends "...-a-..." < "...-b-...")
	if got[0] != teamA || got[1] != teamB {
		t.Errorf("teams not sorted: got %v, want [%s %s]", got, teamA, teamB)
	}
}

func TestBuildTeamsClaim_NoMemberships_ReturnsEmptySlice(t *testing.T) {
	db := dbForClaimsTest(t)
	cid, _, _ := seedClaimsFixtures(t, db)

	got, err := buildTeamsClaim(context.Background(), db, cid)
	if err != nil {
		t.Fatalf("buildTeamsClaim: %v", err)
	}
	if got == nil {
		t.Fatal("got nil slice; helper guarantees non-nil empty slice")
	}
	if len(got) != 0 {
		t.Errorf("expected empty slice, got %v", got)
	}
}

func TestBuildTeamsClaim_ExcludesInactiveMemberships(t *testing.T) {
	db := dbForClaimsTest(t)
	cid, teamA, teamB := seedClaimsFixtures(t, db)
	ctx := context.Background()

	if _, err := db.ExecContext(ctx, `
		INSERT INTO team_memberships (team_id, collaborator_id, active)
		SELECT id, $1, TRUE FROM teams WHERE slug=$2
	`, cid, teamA); err != nil {
		t.Fatalf("insert active membership: %v", err)
	}
	if _, err := db.ExecContext(ctx, `
		INSERT INTO team_memberships (team_id, collaborator_id, active)
		SELECT id, $1, FALSE FROM teams WHERE slug=$2
	`, cid, teamB); err != nil {
		t.Fatalf("insert inactive membership: %v", err)
	}

	got, err := buildTeamsClaim(ctx, db, cid)
	if err != nil {
		t.Fatalf("buildTeamsClaim: %v", err)
	}
	if len(got) != 1 || got[0] != teamA {
		t.Errorf("inactive membership leaked into claim: got %v, want [%s]", got, teamA)
	}
}

func TestScopesContains(t *testing.T) {
	cases := []struct {
		name   string
		scopes []string
		needle string
		want   bool
	}{
		{"present", []string{"openid", "email", "roles"}, "roles", true},
		{"absent", []string{"openid", "email"}, "roles", false},
		{"empty_list", nil, "roles", false},
		{"empty_needle", []string{"openid"}, "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := scopesContains(tc.scopes, tc.needle); got != tc.want {
				t.Errorf("scopesContains(%v, %q) = %v, want %v", tc.scopes, tc.needle, got, tc.want)
			}
		})
	}
}
