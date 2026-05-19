// Migration: yggdrasil-core/scripts/migrate_tartaro_roles_to_actions
//
// Walks collaborators with non-empty traits.tartaro_roles, fetches the
// canonical action set per role from tartaro-operations, find-or-creates
// a "tartaro-legacy-<role>" team with the corresponding team_grants,
// and adds the collaborator as an active member. The team reactor
// framework then naturally materializes traits.tartaro_actions.
//
// Modes:
//   - dry-run: print planned mutations, no DB writes
//   - apply:   execute the migration (idempotent, re-runnable)
//   - validate: compute expected tartaro_actions per collaborator from
//               tartaro_roles + tartaro-ops catalog; exit non-zero on drift
package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	_ "github.com/lib/pq"
)

type config struct {
	dbURL             string
	tartaroOpsBaseURL string
	tartaroOpsToken   string
	hmacSecret        string
	instanceNamespace string
	instanceName      string
	mode              string
	logger            *log.Logger
}

func parseFlags() config {
	var c config
	flag.StringVar(&c.dbURL, "db-url", os.Getenv("YGGDRASIL_DB_URL"), "PostgreSQL DSN for the Yggdrasil DB")
	flag.StringVar(&c.tartaroOpsBaseURL, "tartaro-ops-url", os.Getenv("TARTARO_OPS_URL"), "tartaro-operations base URL (e.g. https://tartaro-operations.dakasa.me)")
	flag.StringVar(&c.tartaroOpsToken, "tartaro-ops-token", os.Getenv("TARTARO_OPS_TOKEN"), "Bearer token for tartaro-operations (optional)")
	flag.StringVar(&c.hmacSecret, "hmac-secret", os.Getenv("DAKASA_HMAC_SECRET"), "DAKASA_HMAC_SECRET for X-Internal-Signature header on internal endpoints")
	flag.StringVar(&c.instanceNamespace, "instance-namespace", "dakasa", "Tartaro integration_instance namespace")
	flag.StringVar(&c.instanceName, "instance-name", "integration-tartaro-dakasa", "Tartaro integration_instance name")
	flag.StringVar(&c.mode, "mode", "dry-run", "Mode: dry-run | validate | apply")
	flag.Parse()
	c.logger = log.New(os.Stdout, "[migrate-tartaro] ", log.LstdFlags)
	return c
}

func main() {
	cfg := parseFlags()
	if cfg.dbURL == "" || cfg.tartaroOpsBaseURL == "" {
		fmt.Fprintln(os.Stderr, "error: -db-url and -tartaro-ops-url are required (or set YGGDRASIL_DB_URL / TARTARO_OPS_URL env vars)")
		os.Exit(2)
	}

	db, err := sql.Open("postgres", cfg.dbURL)
	if err != nil {
		fmt.Fprintln(os.Stderr, "open db:", err)
		os.Exit(2)
	}
	defer db.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	if err := db.PingContext(ctx); err != nil {
		cancel()
		fmt.Fprintln(os.Stderr, "ping db:", err)
		os.Exit(2)
	}
	cancel()

	cfg.logger.Printf("connected: db=ok mode=%s ops=%s instance=%s/%s",
		cfg.mode, cfg.tartaroOpsBaseURL, cfg.instanceNamespace, cfg.instanceName)

	runCtx := context.Background()
	switch cfg.mode {
	case "dry-run":
		if err := runMigration(runCtx, cfg, db, false); err != nil {
			cfg.logger.Println("FAILED:", err)
			os.Exit(1)
		}
	case "apply":
		if err := runMigration(runCtx, cfg, db, true); err != nil {
			cfg.logger.Println("FAILED:", err)
			os.Exit(1)
		}
	case "validate":
		if err := runValidate(runCtx, cfg, db); err != nil {
			cfg.logger.Println("DRIFT:", err)
			os.Exit(1)
		}
	default:
		fmt.Fprintln(os.Stderr, "unknown mode:", cfg.mode, "(expected: dry-run | validate | apply)")
		os.Exit(2)
	}
}

// signInternalHMAC computes the X-Internal-Signature header for a request
// body using the DAKASA_HMAC_SECRET. Matches the verification done by
// dakasa-commons/security.InternalHMAC middleware.
func signInternalHMAC(secret string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	return hex.EncodeToString(mac.Sum(nil))
}

// fetchRoleActions GETs tartaro-operations /internal/admin/roles/{slug}/actions
// and returns the canonical action set for that role. The endpoint is behind
// the InternalHMAC middleware — we sign an empty body when DAKASA_HMAC_SECRET
// is configured.
func fetchRoleActions(ctx context.Context, cfg config, slug string) ([]string, error) {
	u := strings.TrimRight(cfg.tartaroOpsBaseURL, "/") + "/internal/admin/roles/" + slug + "/actions"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	if cfg.tartaroOpsToken != "" {
		req.Header.Set("Authorization", "Bearer "+cfg.tartaroOpsToken)
	}
	if cfg.hmacSecret != "" {
		req.Header.Set("X-Internal-Signature", signInternalHMAC(cfg.hmacSecret, nil))
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("tartaro-ops request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("role %q not in tartaro-ops catalog", slug)
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("tartaro-ops %s: status %d body=%s", u, resp.StatusCode, string(body))
	}
	var out struct {
		Role    string   `json:"role"`
		Actions []string `json:"actions"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("decode tartaro-ops response: %w", err)
	}
	return out.Actions, nil
}

// runMigration walks collaborators with non-empty traits.tartaro_roles,
// fetches the canonical action set per role from tartaro-operations,
// find-or-creates a "tartaro-legacy-<role>" team with corresponding
// team_grants, and adds the collaborator as an active member.
// Idempotent — safe to re-run. apply=false logs intent only (dry-run).
func runMigration(ctx context.Context, cfg config, db *sql.DB, apply bool) error {
	mode := "dry-run"
	if apply {
		mode = "apply"
	}
	cfg.logger.Printf("starting migration mode=%s", mode)

	// 1. SELECT collaborators with non-empty tartaro_roles
	rows, err := db.QueryContext(ctx, `
		SELECT id::text, slug, COALESCE(traits->'tartaro_roles', '[]'::jsonb)::text AS roles_json
		FROM collaborators
		WHERE jsonb_array_length(COALESCE(traits->'tartaro_roles','[]'::jsonb)) > 0
	`)
	if err != nil {
		return fmt.Errorf("select collaborators: %w", err)
	}

	type collabInfo struct {
		id, slug string
		roles    []string
	}
	var collabs []collabInfo
	for rows.Next() {
		var c collabInfo
		var rolesJSON string
		if err := rows.Scan(&c.id, &c.slug, &rolesJSON); err != nil {
			rows.Close()
			return fmt.Errorf("scan collaborator: %w", err)
		}
		if err := json.Unmarshal([]byte(rolesJSON), &c.roles); err != nil {
			rows.Close()
			return fmt.Errorf("decode roles for %s: %w", c.slug, err)
		}
		collabs = append(collabs, c)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate collaborators: %w", err)
	}
	cfg.logger.Printf("found %d collaborators with tartaro_roles", len(collabs))

	// 2. Resolve action sets per distinct role
	distinctRoles := map[string]struct{}{}
	for _, c := range collabs {
		for _, r := range c.roles {
			distinctRoles[r] = struct{}{}
		}
	}
	actionsForRole := map[string][]string{}
	skippedRoles := []string{}
	for role := range distinctRoles {
		actions, err := fetchRoleActions(ctx, cfg, role)
		if err != nil {
			cfg.logger.Printf("WARN role=%s skipped: %v", role, err)
			skippedRoles = append(skippedRoles, role)
			continue
		}
		actionsForRole[role] = actions
		cfg.logger.Printf("resolved role=%s actions=%d", role, len(actions))
	}

	// 3. Find-or-create team + grants per resolved role
	teamForRole := map[string]string{} // role -> team id (or "<dry-run>")
	teamsCreated, grantsCreated := 0, 0
	for role, actions := range actionsForRole {
		teamSlug := "tartaro-legacy-" + role
		var teamID string
		err := db.QueryRowContext(ctx, `SELECT id::text FROM teams WHERE slug = $1`, teamSlug).Scan(&teamID)
		if errors.Is(err, sql.ErrNoRows) {
			if !apply {
				cfg.logger.Printf("DRY-RUN: would create team %s", teamSlug)
				teamForRole[role] = "<dry-run>"
				teamsCreated++
			} else {
				err = db.QueryRowContext(ctx, `
					INSERT INTO teams (slug, name, type, status)
					VALUES ($1, $2, 'role', 'active')
					RETURNING id::text
				`, teamSlug, "Tartaro Legacy: "+role).Scan(&teamID)
				if err != nil {
					return fmt.Errorf("create team %s: %w", teamSlug, err)
				}
				teamForRole[role] = teamID
				teamsCreated++
				cfg.logger.Printf("created team %s id=%s", teamSlug, teamID)
			}
		} else if err != nil {
			return fmt.Errorf("find team %s: %w", teamSlug, err)
		} else {
			teamForRole[role] = teamID
		}

		// Grants
		for _, action := range actions {
			if teamForRole[role] == "<dry-run>" {
				cfg.logger.Printf("DRY-RUN: would grant team=%s action=%s", teamSlug, action)
				grantsCreated++
				continue
			}
			var existsID string
			err := db.QueryRowContext(ctx, `
				SELECT id::text FROM team_grants
				WHERE team_id = $1::uuid
				  AND integration_instance_namespace = $2
				  AND integration_instance_name = $3
				  AND action_name = $4
			`, teamForRole[role], cfg.instanceNamespace, cfg.instanceName, action).Scan(&existsID)
			if errors.Is(err, sql.ErrNoRows) {
				if !apply {
					cfg.logger.Printf("DRY-RUN: would grant team=%s action=%s", teamSlug, action)
					grantsCreated++
					continue
				}
				if _, err := db.ExecContext(ctx, `
					INSERT INTO team_grants (team_id, integration_instance_namespace, integration_instance_name, action_name)
					VALUES ($1::uuid, $2, $3, $4)
				`, teamForRole[role], cfg.instanceNamespace, cfg.instanceName, action); err != nil {
					return fmt.Errorf("grant team=%s action=%s: %w", teamSlug, action, err)
				}
				grantsCreated++
				cfg.logger.Printf("granted team=%s action=%s", teamSlug, action)
			} else if err != nil {
				return fmt.Errorf("find grant team=%s action=%s: %w", teamSlug, action, err)
			}
		}
	}

	// 4. Find-or-create active memberships per (collab, role)
	// Note: team_memberships has UNIQUE (team_id, collaborator_id) so we
	// query for any existing row (active or not) and only insert if absent.
	membershipsCreated := 0
	for _, c := range collabs {
		for _, role := range c.roles {
			teamID, ok := teamForRole[role]
			if !ok {
				continue // role was skipped (not in catalog)
			}
			if teamID == "<dry-run>" {
				cfg.logger.Printf("DRY-RUN: would add %s to team tartaro-legacy-%s", c.slug, role)
				membershipsCreated++
				continue
			}
			var existsID string
			err := db.QueryRowContext(ctx, `
				SELECT id::text FROM team_memberships
				WHERE collaborator_id = $1::uuid AND team_id = $2::uuid
			`, c.id, teamID).Scan(&existsID)
			if errors.Is(err, sql.ErrNoRows) {
				if !apply {
					cfg.logger.Printf("DRY-RUN: would add %s to team tartaro-legacy-%s", c.slug, role)
					membershipsCreated++
					continue
				}
				if _, err := db.ExecContext(ctx, `
					INSERT INTO team_memberships (collaborator_id, team_id, role, active, source)
					VALUES ($1::uuid, $2::uuid, 'member', true, 'tartaro-roles-migration')
				`, c.id, teamID); err != nil {
					return fmt.Errorf("add membership %s->%s: %w", c.slug, teamID, err)
				}
				membershipsCreated++
				cfg.logger.Printf("added %s to team tartaro-legacy-%s", c.slug, role)
			} else if err != nil {
				return fmt.Errorf("find membership %s->%s: %w", c.slug, teamID, err)
			}
		}
	}

	cfg.logger.Printf("DONE mode=%s users=%d roles_resolved=%d roles_skipped=%d teams=%d grants=%d memberships=%d",
		mode, len(collabs), len(actionsForRole), len(skippedRoles),
		teamsCreated, grantsCreated, membershipsCreated)
	if len(skippedRoles) > 0 {
		cfg.logger.Printf("skipped roles (not in tartaro-ops catalog): %v", skippedRoles)
	}
	return nil
}

func runValidate(ctx context.Context, cfg config, db *sql.DB) error {
	cfg.logger.Println("starting validate")

	rows, err := db.QueryContext(ctx, `
		SELECT id, slug,
		       COALESCE(traits->'tartaro_roles', '[]'::jsonb)::text   AS roles_json,
		       COALESCE(traits->'tartaro_actions','[]'::jsonb)::text  AS actions_json
		FROM collaborators
		WHERE jsonb_array_length(COALESCE(traits->'tartaro_roles','[]'::jsonb)) > 0
		   OR jsonb_array_length(COALESCE(traits->'tartaro_actions','[]'::jsonb)) > 0
	`)
	if err != nil {
		return fmt.Errorf("select collaborators: %w", err)
	}
	defer rows.Close()

	roleActionsCache := map[string][]string{}
	driftCount, checked := 0, 0

	for rows.Next() {
		var id, slug, rolesJSON, actionsJSON string
		if err := rows.Scan(&id, &slug, &rolesJSON, &actionsJSON); err != nil {
			return fmt.Errorf("scan collaborator: %w", err)
		}

		var roles, actualActions []string
		if err := json.Unmarshal([]byte(rolesJSON), &roles); err != nil {
			cfg.logger.Printf("WARN collab=%s decode roles failed: %v", slug, err)
			continue
		}
		if err := json.Unmarshal([]byte(actionsJSON), &actualActions); err != nil {
			cfg.logger.Printf("WARN collab=%s decode actions failed: %v", slug, err)
			continue
		}

		// Compute expected = UNION(roleActions(role) for role in roles)
		expected := map[string]struct{}{}
		for _, r := range roles {
			as, ok := roleActionsCache[r]
			if !ok {
				as, err = fetchRoleActions(ctx, cfg, r)
				if err != nil {
					cfg.logger.Printf("WARN role=%s skipped: %v", r, err)
					roleActionsCache[r] = nil // cache the miss so we don't refetch
					continue
				}
				roleActionsCache[r] = as
			}
			for _, a := range as {
				expected[a] = struct{}{}
			}
		}
		expSlice := make([]string, 0, len(expected))
		for a := range expected {
			expSlice = append(expSlice, a)
		}

		if !sameStringSet(actualActions, expSlice) {
			driftCount++
			cfg.logger.Printf("DRIFT collab=%s slug=%s expected=%v actual=%v",
				id, slug, expSlice, actualActions)
		}
		checked++
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate collaborators: %w", err)
	}

	cfg.logger.Printf("validate: checked=%d drift=%d", checked, driftCount)
	if driftCount > 0 {
		return fmt.Errorf("%d users have drift between tartaro_roles and tartaro_actions", driftCount)
	}
	return nil
}

// sameStringSet returns true when a and b have the same set of strings
// (order/duplicates ignored).
func sameStringSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	m := map[string]struct{}{}
	for _, s := range a {
		m[s] = struct{}{}
	}
	for _, s := range b {
		if _, ok := m[s]; !ok {
			return false
		}
	}
	return true
}
