// Built from the exact legacy Core source only in disposable CI; no AWS.
package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	_ "github.com/lib/pq"
)

func run() error {
	if len(os.Args) != 3 {
		return fmt.Errorf("fixture IDs required")
	}
	dsn := os.Getenv("ORIGINAL_CREATE_DISPOSITION_PG_DSN")
	if !strings.Contains(dsn, "host=/") || !strings.Contains(dsn, "dbname=original_disposition_test_") {
		return fmt.Errorf("isolated unix DB required")
	}
	var policy model.Manifest
	if e := json.NewDecoder(os.Stdin).Decode(&policy); e != nil {
		return e
	}
	db, e := sql.Open("postgres", dsn)
	if e != nil {
		return e
	}
	defer db.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var name string
	var local bool
	if e = db.QueryRowContext(ctx, `SELECT current_database(),inet_server_addr() IS NULL`).Scan(&name, &local); e != nil || !local || !strings.HasPrefix(name, "original_disposition_test_") {
		return fmt.Errorf("foreign db")
	}
	store := repository.CapacityStore{DB: db}
	result, e := store.ReadFailedOriginalDisposition(ctx, os.Args[1])
	if e != nil {
		return fmt.Errorf("legacy GET: %w", e)
	}
	if !result.OriginalAcceptedUnchanged || !result.OriginalWitnessPreserved || !result.OriginalUnknownACKPreserved || result.HistoricalWriterStartState != "unknown" || result.ServingOrBusinessOrSavingsAuthority {
		return fmt.Errorf("legacy relabelled disposition")
	}
	current, e := store.Observe(ctx, policy)
	if e != nil {
		return fmt.Errorf("legacy observe: %w", e)
	}
	if current.Phase != "reconciled_failed_floor" || !current.FloorDegraded || current.LeaseOwner != "" || current.LeaseExpiresAt != nil || current.Decision.ExecutionPermitted {
		return fmt.Errorf("legacy changed terminal intent")
	}
	if owner, e := store.BeginFailedOriginalDisposition(ctx, os.Args[1], os.Args[2], "collaborator:rollback-fixture"); e == nil || owner != nil {
		return fmt.Errorf("legacy reopened disposition")
	}
	fmt.Println("LEGACY_READ_AND_REOPEN_REFUSAL_PASS diagnostic_fixture_only")
	return nil
}
func main() {
	if e := run(); e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
}
