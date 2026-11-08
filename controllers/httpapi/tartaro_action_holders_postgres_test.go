package httpapi

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/contactphone"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	"github.com/google/uuid"
	_ "github.com/lib/pq"
)

// requireTartaroActionHoldersPostgresEnv turns the DB_URL skip into a failure
// where CI promises a migrated PostgreSQL (the native-oidc-postgres job), so
// the roster predicate can never silently stop being proven there.
const requireTartaroActionHoldersPostgresEnv = "REQUIRE_TARTARO_ACTION_HOLDERS_POSTGRES"

func tartaroActionHoldersPostgres(t *testing.T) *sql.DB {
	t.Helper()
	dsn := os.Getenv("DB_URL")
	if dsn == "" {
		if os.Getenv(requireTartaroActionHoldersPostgresEnv) == "true" {
			t.Fatalf("%s=true but DB_URL is not set", requireTartaroActionHoldersPostgresEnv)
		}
		t.Skip("PostgreSQL runs in CI")
	}
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatalf("open PostgreSQL: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := db.Ping(); err != nil {
		t.Fatalf("PostgreSQL unavailable: %v", err)
	}
	return db
}

// TestTartaroActionHoldersHTTPPostgres proves, through the real router and
// console gate against the migrated schema, that the roster counts exactly
// the collaborators the effective-actions read authorizes (ADR-0107).
func TestTartaroActionHoldersHTTPPostgres(t *testing.T) {
	db := tartaroActionHoldersPostgres(t)
	ctx := context.Background()
	t.Setenv(contactphone.EnrollmentPolicyEnv, "false")
	suffix := uuid.NewString()[:8]
	const action = "tartaro:suspend_user"
	unlisted := "tartaro:unlisted_" + suffix

	// A private instance identity, so no other fixture's grant or manifest
	// can reach this roster. The handler reads these at request time.
	previousNamespace, previousName := tartaroInstanceNamespace, tartaroInstanceName
	tartaroInstanceNamespace, tartaroInstanceName = "adr0107-"+suffix, "tartaro-"+suffix
	t.Cleanup(func() { tartaroInstanceNamespace, tartaroInstanceName = previousNamespace, previousName })
	namespace, name := tartaroInstanceNamespace, tartaroInstanceName

	person := func(label, status string, traits map[string]any) uuid.UUID {
		t.Helper()
		id := uuid.NewString()
		c, err := repository.CreateCollaborator(ctx, db, model.CreateCollaboratorRequest{
			Slug: "holders-" + label + "-" + id, DisplayName: "Holders " + label, PrimaryEmail: id + "@example.test",
			Status: status, Traits: traits,
		})
		if err != nil {
			t.Fatalf("collaborator %s fixture: %v", label, err)
		}
		t.Cleanup(func() { _, _ = db.Exec(`DELETE FROM public.collaborators WHERE id=$1`, c.ID) })
		return c.ID
	}
	team := func(label, status string) uuid.UUID {
		t.Helper()
		var id uuid.UUID
		if err := db.QueryRow(`INSERT INTO public.teams (slug, type, status, name) VALUES ($1, 'access_group', $2, $3) RETURNING id`,
			"holders-"+label+"-"+suffix, status, "Holders "+label).Scan(&id); err != nil {
			t.Fatalf("team %s fixture: %v", label, err)
		}
		t.Cleanup(func() { _, _ = db.Exec(`DELETE FROM public.teams WHERE id=$1`, id) })
		return id
	}
	grant := func(teamID uuid.UUID, grantNamespace, grantName, grantAction string) {
		t.Helper()
		if _, err := db.Exec(`INSERT INTO public.team_grants (team_id, integration_instance_namespace, integration_instance_name, action_name) VALUES ($1, $2, $3, $4)`,
			teamID, grantNamespace, grantName, grantAction); err != nil {
			t.Fatalf("grant fixture: %v", err)
		}
	}
	member := func(teamID, collaboratorID uuid.UUID, active bool, startsAt, endsAt *time.Time) {
		t.Helper()
		if _, err := db.Exec(`INSERT INTO public.team_memberships (team_id, collaborator_id, active, starts_at, ends_at) VALUES ($1, $2, $3, $4, $5)`,
			teamID, collaboratorID, active, startsAt, endsAt); err != nil {
			t.Fatalf("membership fixture: %v", err)
		}
	}
	at := func(offset time.Duration) *time.Time {
		value := time.Now().UTC().Add(offset)
		return &value
	}

	exactTeam := team("exact", "active")
	wildcardTeam := team("wildcard", "active")
	otherInstanceTeam := team("other-instance", "active")
	inactiveTeam := team("inactive", "archived")
	grant(exactTeam, namespace, name, action)
	grant(wildcardTeam, namespace, name, "*")
	grant(otherInstanceTeam, namespace, "other-"+suffix, action)
	grant(otherInstanceTeam, "other-"+suffix, name, action)
	grant(inactiveTeam, namespace, name, action)

	exactHolder := person("exact", "active", nil)
	member(exactTeam, exactHolder, true, nil, nil)
	windowHolder := person("window", "active", nil)
	member(exactTeam, windowHolder, true, at(-time.Hour), at(time.Hour))
	wildcardHolder := person("wildcard", "active", nil)
	member(wildcardTeam, wildcardHolder, true, nil, nil)
	suspendedMember := person("suspended", "suspended", nil)
	member(exactTeam, suspendedMember, true, nil, nil)
	onLeaveMember := person("on-leave", "on_leave", nil)
	member(exactTeam, onLeaveMember, true, nil, nil)
	expiredMember := person("expired", "active", nil)
	member(exactTeam, expiredMember, true, at(-2*time.Hour), at(-time.Hour))
	futureMember := person("future", "active", nil)
	member(exactTeam, futureMember, true, at(time.Hour), nil)
	deactivatedMember := person("deactivated", "active", nil)
	member(exactTeam, deactivatedMember, false, nil, nil)
	inactiveTeamMember := person("inactive-team", "active", nil)
	member(inactiveTeam, inactiveTeamMember, true, nil, nil)
	otherInstanceMember := person("other-instance", "active", nil)
	member(otherInstanceTeam, otherInstanceMember, true, nil, nil)
	godOnly := person("god", "active", map[string]any{"yggdrasil_admin": true})
	godString := person("god-string", "active", map[string]any{"yggdrasil_admin": "1"})
	godAndGrant := person("god-and-grant", "active", map[string]any{"yggdrasil_admin": "true"})
	member(exactTeam, godAndGrant, true, nil, nil)
	member(wildcardTeam, godAndGrant, true, nil, nil)
	notGodUpper := person("not-god-upper", "active", map[string]any{"yggdrasil_admin": "TRUE"})
	notGodNumber := person("not-god-number", "active", map[string]any{"yggdrasil_admin": 1})
	notGodFalse := person("not-god-false", "active", map[string]any{"yggdrasil_admin": false})
	suspendedGod := person("suspended-god", "suspended", map[string]any{"yggdrasil_admin": true})

	// The caller: an authenticated human with MFA and no ops permission.
	caller := person("caller", "active", nil)
	if _, err := db.Exec(`UPDATE public.auth_identities SET mfa_enrolled_at=NOW() WHERE collaborator_id=$1`, caller); err != nil {
		t.Fatalf("caller MFA fixture: %v", err)
	}
	_, token, err := repository.CreateAuthSession(ctx, db, caller, nil, time.Hour)
	if err != nil {
		t.Fatalf("caller session fixture: %v", err)
	}
	handler := directoryHTTPHandler(t, db)
	get := func(rawQuery string, authenticated bool) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodGet, tartaroActionHoldersPath+"?"+rawQuery, nil)
		if authenticated {
			r.AddCookie(&http.Cookie{Name: authSessionCookieName(), Value: token})
		}
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		return w
	}
	roster := func(t *testing.T, rawQuery string) map[uuid.UUID][]string {
		t.Helper()
		body := decodeTartaroActionHolders(t, get(rawQuery, true))
		if body.IntegrationInstance.Namespace != namespace || body.IntegrationInstance.Name != name {
			t.Fatalf("integration_instance=%+v", body.IntegrationInstance)
		}
		out := map[uuid.UUID][]string{}
		for _, holder := range body.Holders {
			id, err := uuid.Parse(holder.CollaboratorID)
			if err != nil {
				t.Fatal(err)
			}
			if _, dup := out[id]; dup {
				t.Fatalf("holder %s listed twice", id)
			}
			out[id] = holder.Sources
		}
		return out
	}
	requireSources := func(t *testing.T, got map[uuid.UUID][]string, id uuid.UUID, label string, want ...string) {
		t.Helper()
		sources, present := got[id]
		if len(want) == 0 {
			if present {
				t.Fatalf("%s must not hold the action, got sources %v", label, sources)
			}
			return
		}
		if !reflect.DeepEqual(sources, want) {
			t.Fatalf("%s sources=%v, want %v", label, sources, want)
		}
	}

	t.Run("unauthenticated_caller_is_refused", func(t *testing.T) {
		w := get("action="+action, false)
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
		}
	})

	t.Run("malformed_query_is_refused", func(t *testing.T) {
		for _, rawQuery := range []string{"", "action=*", "action=" + action + "&role=risk", "action=%20" + action} {
			w := get(rawQuery, true)
			var body map[string]any
			if w.Code != http.StatusBadRequest || json.Unmarshal(w.Body.Bytes(), &body) != nil || body["error"] == nil {
				t.Fatalf("query %q status=%d body=%s", rawQuery, w.Code, w.Body.String())
			}
		}
	})

	// No integration_instance manifest exists yet for the private instance,
	// so the wildcard grant on it cannot be expanded.
	t.Run("wildcard_without_resolvable_catalog_is_unavailable", func(t *testing.T) {
		w := get("action="+action, true)
		var body map[string]any
		if w.Code != http.StatusServiceUnavailable || json.Unmarshal(w.Body.Bytes(), &body) != nil || body["error"] == nil || body["holders"] != nil {
			t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
		}
	})

	typeNamespace, typeName := "adr0107-types-"+suffix, "tartaro-type-"+suffix
	seedTartaroHoldersManifest(t, db, "integration_type", typeNamespace, typeName, map[string]any{
		"provider": "tartaro",
		"action_catalog": []map[string]any{
			{"name": action, "category": "permission"},
			{"name": "tartaro:read_user", "category": "permission"},
			{"name": unlisted, "category": "capability"},
		},
	})
	seedTartaroHoldersManifest(t, db, "integration_instance", namespace, name, map[string]any{
		"type_ref": map[string]any{"namespace": typeNamespace, "name": typeName},
		"status":   "active",
	})

	t.Run("catalog_action_counts_the_authorized_set", func(t *testing.T) {
		got := roster(t, "action="+action)
		requireSources(t, got, exactHolder, "exact grant holder", "team_grant")
		requireSources(t, got, windowHolder, "holder inside the membership window", "team_grant")
		requireSources(t, got, wildcardHolder, "wildcard holder of a catalog action", "team_grant")
		requireSources(t, got, godOnly, "boolean admin", "god_mode")
		requireSources(t, got, godString, `"1" admin`, "god_mode")
		requireSources(t, got, godAndGrant, "admin with grants", "god_mode", "team_grant")
		requireSources(t, got, suspendedMember, "suspended member")
		requireSources(t, got, onLeaveMember, "on-leave member")
		requireSources(t, got, expiredMember, "expired membership")
		requireSources(t, got, futureMember, "not-yet-started membership")
		requireSources(t, got, deactivatedMember, "deactivated membership")
		requireSources(t, got, inactiveTeamMember, "member of an inactive team")
		requireSources(t, got, otherInstanceMember, "grant on another instance")
		requireSources(t, got, notGodUpper, `"TRUE" admin`)
		requireSources(t, got, notGodNumber, "numeric admin")
		requireSources(t, got, notGodFalse, "false admin")
		requireSources(t, got, suspendedGod, "suspended admin")
		requireSources(t, got, caller, "caller without grants")
	})

	t.Run("wildcard_does_not_count_an_action_outside_the_catalog", func(t *testing.T) {
		// unlisted is in the catalog only as a capability, never a
		// permission, so "*" does not confer it; nobody holds it explicitly.
		got := roster(t, "action="+unlisted)
		requireSources(t, got, wildcardHolder, "wildcard holder of a non-permission action")
		requireSources(t, got, exactHolder, "holder of a different action")
		requireSources(t, got, godAndGrant, "admin with unrelated grants", "god_mode")
		requireSources(t, got, godOnly, "boolean admin", "god_mode")
	})

	t.Run("roster_matches_the_effective_actions_read", func(t *testing.T) {
		// Every team-grant holder of the action is exactly a collaborator whose
		// effective-actions answer lists it, among the fixtures.
		got := roster(t, "action="+action)
		server := &Server{db: db}
		for label, id := range map[string]uuid.UUID{
			"exact": exactHolder, "window": windowHolder, "wildcard": wildcardHolder, "expired": expiredMember,
			"future": futureMember, "deactivated": deactivatedMember, "inactive team": inactiveTeamMember,
			"other instance": otherInstanceMember, "god and grant": godAndGrant,
		} {
			effective, err := server.computeAuthorizedTartaroActions(ctx, id)
			if err != nil {
				t.Fatalf("%s effective actions: %v", label, err)
			}
			listed := false
			for _, computed := range effective.Computed {
				listed = listed || computed == action
			}
			hasTeamGrant := false
			for _, source := range got[id] {
				hasTeamGrant = hasTeamGrant || source == "team_grant"
			}
			if listed != hasTeamGrant {
				t.Fatalf("%s: effective actions list the action=%v, roster team_grant=%v", label, listed, hasTeamGrant)
			}
		}
	})
}

// seedTartaroHoldersManifest writes one active manifest version and removes
// every version of that logical manifest after the test.
func seedTartaroHoldersManifest(t *testing.T, db *sql.DB, kind, namespace, name string, spec any) {
	t.Helper()
	raw, err := json.Marshal(spec)
	if err != nil {
		t.Fatalf("marshal %s spec: %v", kind, err)
	}
	active := true
	tx, err := db.Begin()
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	if _, err := repository.CreateManifestVersionTx(context.Background(), tx, model.ManifestDocument{
		APIVersion: "yggdrasil.io/v1alpha1",
		Kind:       kind,
		Metadata:   model.ManifestMetadataInput{Name: name, Namespace: namespace, Active: &active},
		Spec:       raw,
	}, "sha256:tartaro-action-holders-test"); err != nil {
		_ = tx.Rollback()
		t.Fatalf("seed %s %s/%s: %v", kind, namespace, name, err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit %s seed: %v", kind, err)
	}
	t.Cleanup(func() {
		_, _ = db.Exec(`DELETE FROM public.manifests WHERE kind = $1 AND namespace = $2 AND name = $3`, kind, namespace, name)
	})
}
