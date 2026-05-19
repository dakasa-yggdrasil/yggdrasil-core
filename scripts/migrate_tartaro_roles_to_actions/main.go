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
	"database/sql"
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

// fetchRoleActions GETs tartaro-operations /internal/admin/roles/{slug}/actions
// and returns the canonical action set for that role.
func fetchRoleActions(ctx context.Context, cfg config, slug string) ([]string, error) {
	u := strings.TrimRight(cfg.tartaroOpsBaseURL, "/") + "/internal/admin/roles/" + slug + "/actions"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	if cfg.tartaroOpsToken != "" {
		req.Header.Set("Authorization", "Bearer "+cfg.tartaroOpsToken)
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

// runMigration is implemented in T11.
func runMigration(_ context.Context, cfg config, _ *sql.DB, apply bool) error {
	mode := "dry-run"
	if apply {
		mode = "apply"
	}
	cfg.logger.Printf("runMigration mode=%s — TODO T11 implements this", mode)
	return errors.New("runMigration not implemented (T11)")
}

// runValidate is implemented in T12.
func runValidate(_ context.Context, cfg config, _ *sql.DB) error {
	cfg.logger.Println("runValidate — TODO T12 implements this")
	return errors.New("runValidate not implemented (T12)")
}
