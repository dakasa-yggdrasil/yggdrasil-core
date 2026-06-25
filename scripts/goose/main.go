package main

import (
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/psql"

	_ "github.com/lib/pq"
	"github.com/pressly/goose/v3"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}

	action := os.Args[1]
	switch action {
	case "up", "down", "status", "new":
	default:
		usage()
		os.Exit(1)
	}

	if action == "new" {
		name := migrationNameFromArgs(os.Args[2:])
		if name == "" {
			panic(errors.New("migration name is required (use --name <value>)"))
		}

		path, err := createMigrationFile(filepath.Join("db", "migrations"), name)
		if err != nil {
			panic(err)
		}
		fmt.Println(path)
		return
	}

	db, err := openDB()
	if err != nil {
		panic(err)
	}
	defer func() { _ = db.Close() }()

	if err := waitForPostgres(db.Ping, 90*time.Second, 3*time.Second); err != nil {
		panic(err)
	}

	if err := goose.SetDialect("postgres"); err != nil {
		panic(err)
	}

	dir := filepath.Join("db", "migrations")
	switch action {
	case "up":
		if err := goose.Up(db, dir); err != nil {
			panic(err)
		}
	case "down":
		if err := goose.Down(db, dir); err != nil {
			panic(err)
		}
	case "status":
		if err := goose.Status(db, dir); err != nil {
			panic(err)
		}
	}
}

func usage() {
	fmt.Println("usage: go run ./scripts/goose [up|down|status|new --name migration_name]")
}

func openDB() (*sql.DB, error) {
	return sql.Open("postgres", psql.LoadConfig().DSN())
}

var errPostgresUnreachable = errors.New("postgres unreachable")

// waitForPostgres polls ping until it succeeds or the timeout elapses,
// sleeping interval between attempts. It always attempts at least once.
// Returns errPostgresUnreachable (wrapping the last ping error) on timeout.
// This lets the entrypoint wait for a not-yet-ready Postgres instead of
// panicking and forcing a pod restart loop.
func waitForPostgres(ping func() error, timeout, interval time.Duration) error {
	deadline := time.Now().Add(timeout)
	var lastErr error
	for {
		if err := ping(); err == nil {
			return nil
		} else {
			lastErr = err
		}
		if !time.Now().Before(deadline) {
			return fmt.Errorf("%w after %s: %v", errPostgresUnreachable, timeout, lastErr)
		}
		time.Sleep(interval)
	}
}

func migrationNameFromArgs(args []string) string {
	for i := 0; i < len(args); i++ {
		if args[i] == "--name" && i+1 < len(args) {
			return strings.TrimSpace(args[i+1])
		}
	}
	return ""
}

var migrationNamePattern = regexp.MustCompile(`[^a-z0-9]+`)

func createMigrationFile(dir, rawName string) (string, error) {
	name := sanitizeMigrationName(rawName)
	if name == "" {
		return "", fmt.Errorf("invalid migration name %q", rawName)
	}

	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}

	filename := fmt.Sprintf("%s_%s.sql", time.Now().UTC().Format("20060102150405"), name)
	path := filepath.Join(dir, filename)
	content := `-- +goose Up
-- +goose StatementBegin
SELECT 1;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
SELECT 1;
-- +goose StatementEnd
`

	return path, os.WriteFile(path, []byte(content), 0o644)
}

func sanitizeMigrationName(input string) string {
	normalized := strings.ToLower(strings.TrimSpace(input))
	normalized = strings.Trim(normalized, "_- ")
	if normalized == "" {
		return ""
	}
	normalized = migrationNamePattern.ReplaceAllString(normalized, "_")
	return strings.Trim(normalized, "_")
}
