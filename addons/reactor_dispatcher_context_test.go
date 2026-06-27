package addons

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"testing"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	"github.com/google/uuid"
	_ "github.com/lib/pq"
)

// openContextTestDB returns a real *sql.DB when DB_URL is set, otherwise skips.
func openContextTestDB(t *testing.T) *sql.DB {
	t.Helper()
	dsn := os.Getenv("DB_URL")
	if dsn == "" {
		t.Skip("DB_URL not set; skipping embedTeamContext integration test")
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

// seedTeamForContext inserts a minimal team and returns (id, slug).
func seedTeamForContext(t *testing.T, db *sql.DB) (uuid.UUID, string) {
	t.Helper()
	slug := fmt.Sprintf("ctx-test-team-%s", uuid.New().String()[:8])
	team, err := repository.CreateTeam(context.Background(), db, model.CreateTeamRequest{
		Slug:   slug,
		Name:   "Context Test Team",
		Type:   "team",
		Status: "active",
	})
	if err != nil {
		t.Fatalf("seed team: %v", err)
	}
	t.Cleanup(func() {
		_, _ = db.Exec(`DELETE FROM public.teams WHERE id = $1`, team.ID)
	})
	return team.ID, team.Slug
}

// seedIntegrationInstanceForContext inserts a minimal integration_instance
// manifest and returns its manifest ID (the id referenced by
// team_provisioning_log.integration_instance_id).
func seedIntegrationInstanceForContext(t *testing.T, db *sql.DB) uuid.UUID {
	t.Helper()
	name := fmt.Sprintf("ctx-test-instance-%s", uuid.New().String()[:8])
	tx, err := db.Begin()
	if err != nil {
		t.Fatalf("begin tx for integration_instance seed: %v", err)
	}
	doc := model.ManifestDocument{
		APIVersion: "yggdrasil.io/v1",
		Kind:       "integration_instance",
		Metadata: model.ManifestMetadataInput{
			Name:      name,
			Namespace: "ctx-test",
		},
		Spec: []byte(`{}`),
	}
	m, err := repository.CreateManifestVersionTx(context.Background(), tx, doc, "sha256:test")
	if err != nil {
		_ = tx.Rollback()
		t.Fatalf("seed integration_instance manifest: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit integration_instance seed: %v", err)
	}
	t.Cleanup(func() {
		_, _ = db.Exec(`DELETE FROM public.manifests WHERE id = $1`, m.ID)
	})
	return m.ID
}

// TestEmbedTeamContext_MembershipKeysOnTeamID proves the canonical _context
// enrichment fires for team_membership reactions, which carry the team under
// `team_id` (NOT `id`). It asserts BOTH halves:
//   - _context.team.slug            == the seeded team slug  (GetTeam path)
//   - _context.team_provisioned.external_id == "grp-ext-123" (provisioning-log path)
//
// Before the rename+extend (when the function keyed only on input["id"] and was
// named embedTeamProvisioned), a team_id-only payload early-returned and no
// _context was injected — so this test is RED against the old behavior and
// GREEN after keying on `id` OR `team_id`.
func TestEmbedTeamContext_MembershipKeysOnTeamID(t *testing.T) {
	db := openContextTestDB(t)
	t.Cleanup(func() { _ = db.Close() })

	teamID, teamSlug := seedTeamForContext(t, db)
	instanceID := seedIntegrationInstanceForContext(t, db)

	if _, err := repository.UpsertTeamProvisioningLog(context.Background(), db, model.UpsertTeamProvisioningLogRequest{
		TeamID:                teamID,
		IntegrationInstanceID: instanceID,
		ExternalID:            "grp-ext-123",
		ExternalMetadata:      map[string]any{"group_name": "context-test-group"},
		LastEventType:         "team_membership.added",
	}); err != nil {
		t.Fatalf("seed team_provisioning_log: %v", err)
	}
	t.Cleanup(func() {
		_, _ = db.Exec(`DELETE FROM public.team_provisioning_log WHERE team_id = $1`, teamID)
	})

	c := &rabbitmqReactorCaller{db: db}

	// Membership payload: team under `team_id`, NO `id`.
	input := map[string]any{
		"team_id":         teamID.String(),
		"collaborator_id": uuid.New().String(),
	}

	c.embedTeamContext(context.Background(), "on_team_membership_added", instanceID.String(), input)

	ctxBlock, ok := input["_context"].(map[string]any)
	if !ok {
		t.Fatalf("expected _context to be injected, got %T (%v)", input["_context"], input["_context"])
	}

	// _context.team.slug
	teamBlock, ok := ctxBlock["team"].(map[string]any)
	if !ok {
		t.Fatalf("expected _context.team map, got %T (%v)", ctxBlock["team"], ctxBlock["team"])
	}
	if got := teamBlock["slug"]; got != teamSlug {
		t.Fatalf("_context.team.slug = %v, want %q", got, teamSlug)
	}
	if got := teamBlock["id"]; got != teamID.String() {
		t.Fatalf("_context.team.id = %v, want %q", got, teamID.String())
	}

	// _context.team_provisioned.external_id
	tpBlock, ok := ctxBlock["team_provisioned"].(map[string]any)
	if !ok {
		t.Fatalf("expected _context.team_provisioned map, got %T (%v)", ctxBlock["team_provisioned"], ctxBlock["team_provisioned"])
	}
	if got := tpBlock["external_id"]; got != "grp-ext-123" {
		t.Fatalf("_context.team_provisioned.external_id = %v, want %q", got, "grp-ext-123")
	}
}
