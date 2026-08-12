package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"testing"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
	_ "github.com/lib/pq"
)

// openYggPermTestDB mirrors the DB_URL-gated convention used by the other
// real-Postgres repository tests (see team_provisioning_log_test.go). The
// resolver query cannot be exercised with sqlmock because it hinges on the
// exact manifests namespace/name COLUMN join + JSON type_ref matching that
// only a real Postgres evaluates.
func openYggPermTestDB(t *testing.T) *sql.DB {
	t.Helper()
	dsn := os.Getenv("DB_URL")
	if dsn == "" {
		t.Skip("DB_URL not set; skipping yggdrasil_permissions integration test")
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

// seedManifestVersion inserts one manifest version and registers cleanup.
func seedManifestVersion(t *testing.T, db *sql.DB, kind, namespace, name string, spec any) uuid.UUID {
	t.Helper()
	raw, err := json.Marshal(spec)
	if err != nil {
		t.Fatalf("marshal %s spec: %v", kind, err)
	}
	tx, err := db.Begin()
	if err != nil {
		t.Fatalf("begin tx: %v", err)
	}
	m, err := CreateManifestVersionTx(context.Background(), tx, model.ManifestDocument{
		APIVersion: "yggdrasil.io/v1",
		Kind:       kind,
		Metadata:   model.ManifestMetadataInput{Name: name, Namespace: namespace},
		Spec:       raw,
	}, "sha256:ygg-perm-test")
	if err != nil {
		_ = tx.Rollback()
		t.Fatalf("seed %s manifest: %v", kind, err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit %s seed: %v", kind, err)
	}
	t.Cleanup(func() {
		_, _ = db.Exec(`DELETE FROM public.manifests WHERE id = $1`, m.ID)
	})
	return m.ID
}

// TestResolveYggdrasilPermissions_TeamGrantResolves is the regression guard
// for the dead-resolver bug: a team grant on a yggdrasil-self instance must
// actually resolve into the granted actions. Before the fix the resolver
// joined manifests by a never-populated metadata annotations blob and by a
// type_ref "id" key that stored instances never write, so every non-god
// grant resolved EMPTY.
func TestResolveYggdrasilPermissions_TeamGrantResolves(t *testing.T) {
	db := openYggPermTestDB(t)
	t.Cleanup(func() { _ = db.Close() })

	ctx := context.Background()
	suffix := uuid.New().String()[:8]
	ns := fmt.Sprintf("ygg-self-test-%s", suffix)
	const instanceName = "yggdrasil-self"

	// integration_type named yggdrasil-self (the resolver hardcodes this
	// name) in the test namespace.
	seedManifestVersion(t, db, "integration_type", ns, instanceName, map[string]any{
		"provider": "yggdrasil-self",
	})

	// integration_instance whose spec.type_ref points at the type by
	// (namespace, name) COLUMNS - exactly how InsertManifest persists it.
	seedManifestVersion(t, db, "integration_instance", ns, instanceName, map[string]any{
		"type_ref": map[string]any{"namespace": ns, "name": instanceName},
		"status":   "active",
	})

	// Team + collaborator + active membership.
	team, err := CreateTeam(ctx, db, model.CreateTeamRequest{
		Slug:   fmt.Sprintf("ygg-perm-team-%s", suffix),
		Name:   "Ygg Perm Test Team",
		Type:   "team",
		Status: "active",
	})
	if err != nil {
		t.Fatalf("create team: %v", err)
	}
	t.Cleanup(func() { _, _ = db.Exec(`DELETE FROM public.teams WHERE id = $1`, team.ID) })

	collab, err := CreateCollaborator(ctx, db, model.CreateCollaboratorRequest{
		Slug:        fmt.Sprintf("ygg-perm-user-%s", suffix),
		Status:      "active",
		DisplayName: "Ygg Perm User",
	})
	if err != nil {
		t.Fatalf("create collaborator: %v", err)
	}
	t.Cleanup(func() { _, _ = db.Exec(`DELETE FROM public.collaborators WHERE id = $1`, collab.ID) })

	if _, err := db.ExecContext(ctx, `
		INSERT INTO public.team_memberships (team_id, collaborator_id, role, active, source)
		VALUES ($1, $2, 'member', true, 'manual')
	`, team.ID, collab.ID); err != nil {
		t.Fatalf("insert membership: %v", err)
	}
	t.Cleanup(func() { _, _ = db.Exec(`DELETE FROM public.team_memberships WHERE team_id = $1`, team.ID) })

	insertGrant := func(action string) {
		t.Helper()
		if _, err := db.ExecContext(ctx, `
			INSERT INTO public.team_grants
				(team_id, integration_instance_namespace, integration_instance_name, action_name)
			VALUES ($1, $2, $3, $4)
			ON CONFLICT (team_id, integration_instance_namespace, integration_instance_name, action_name)
			DO NOTHING
		`, team.ID, ns, instanceName, action); err != nil {
			t.Fatalf("insert grant %q: %v", action, err)
		}
	}
	t.Cleanup(func() { _, _ = db.Exec(`DELETE FROM public.team_grants WHERE team_id = $1`, team.ID) })

	// Two concrete action grants must resolve to exactly those actions.
	insertGrant("yggdrasil:manage_teams")
	insertGrant("yggdrasil:view_workflows")

	got, err := ResolveYggdrasilPermissions(ctx, db, collab.ID, nil)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	sort.Strings(got)
	want := []string{"yggdrasil:manage_teams", "yggdrasil:view_workflows"}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("expected %v, got %v (dead-resolver regression)", want, got)
	}

	// A "*" grant on the same instance must collapse to god mode.
	insertGrant("*")
	got, err = ResolveYggdrasilPermissions(ctx, db, collab.ID, nil)
	if err != nil {
		t.Fatalf("resolve after wildcard: %v", err)
	}
	if len(got) != 1 || got[0] != YggdrasilGodModeAction {
		t.Fatalf("expected wildcard to collapse to [%s], got %v", YggdrasilGodModeAction, got)
	}
}

// TestResolveYggdrasilPermissions_NoInstanceResolvesEmpty proves the join is
// not accidentally permissive: a grant that references an instance which does
// not exist must resolve to no permissions (fail-closed).
func TestResolveYggdrasilPermissions_NoInstanceResolvesEmpty(t *testing.T) {
	db := openYggPermTestDB(t)
	t.Cleanup(func() { _ = db.Close() })

	ctx := context.Background()
	suffix := uuid.New().String()[:8]
	ns := fmt.Sprintf("ygg-self-orphan-%s", suffix)

	team, err := CreateTeam(ctx, db, model.CreateTeamRequest{
		Slug:   fmt.Sprintf("ygg-orphan-team-%s", suffix),
		Name:   "Ygg Orphan Team",
		Type:   "team",
		Status: "active",
	})
	if err != nil {
		t.Fatalf("create team: %v", err)
	}
	t.Cleanup(func() { _, _ = db.Exec(`DELETE FROM public.teams WHERE id = $1`, team.ID) })

	collab, err := CreateCollaborator(ctx, db, model.CreateCollaboratorRequest{
		Slug:        fmt.Sprintf("ygg-orphan-user-%s", suffix),
		Status:      "active",
		DisplayName: "Ygg Orphan User",
	})
	if err != nil {
		t.Fatalf("create collaborator: %v", err)
	}
	t.Cleanup(func() { _, _ = db.Exec(`DELETE FROM public.collaborators WHERE id = $1`, collab.ID) })

	if _, err := db.ExecContext(ctx, `
		INSERT INTO public.team_memberships (team_id, collaborator_id, role, active, source)
		VALUES ($1, $2, 'member', true, 'manual')
	`, team.ID, collab.ID); err != nil {
		t.Fatalf("insert membership: %v", err)
	}
	t.Cleanup(func() { _, _ = db.Exec(`DELETE FROM public.team_memberships WHERE team_id = $1`, team.ID) })

	// Grant references (ns, yggdrasil-self) but no such instance manifest exists.
	if _, err := db.ExecContext(ctx, `
		INSERT INTO public.team_grants
			(team_id, integration_instance_namespace, integration_instance_name, action_name)
		VALUES ($1, $2, 'yggdrasil-self', 'yggdrasil:manage_teams')
	`, team.ID, ns); err != nil {
		t.Fatalf("insert grant: %v", err)
	}
	t.Cleanup(func() { _, _ = db.Exec(`DELETE FROM public.team_grants WHERE team_id = $1`, team.ID) })

	got, err := ResolveYggdrasilPermissions(ctx, db, collab.ID, nil)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("expected no permissions for orphan grant, got %v", got)
	}
}
