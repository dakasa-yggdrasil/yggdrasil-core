package main

import (
	"context"
	"database/sql"
	"errors"
	"flag"
	"fmt"
	"strings"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/psql"

	"github.com/lib/pq"
)

func main() {
	ensureDB := flag.Bool("ensure-db", false, "Create the configured database if it does not exist")
	flag.Parse()

	cfg := psql.LoadConfig()
	db, err := psql.Open()
	if err != nil {
		panic(err)
	}
	defer db.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := db.PingContext(ctx); err != nil {
		if !*ensureDB || !isMissingDatabaseError(err) {
			panic(err)
		}

		if err := ensureDatabase(ctx, cfg); err != nil {
			panic(err)
		}

		if err := db.PingContext(ctx); err != nil {
			panic(err)
		}

		fmt.Printf("postgres: created database %s\n", cfg.Name)
	}

	fmt.Println("postgres: ok")
}

func ensureDatabase(ctx context.Context, cfg psql.Config) error {
	adminCfg := cfg
	adminCfg.Name = "postgres"
	if strings.EqualFold(cfg.Name, "postgres") {
		adminCfg.Name = "template1"
	}

	admin, err := sql.Open("postgres", adminCfg.DSN())
	if err != nil {
		return err
	}
	defer admin.Close()

	if err := admin.PingContext(ctx); err != nil {
		return err
	}

	var exists bool
	if err := admin.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM pg_database WHERE datname = $1)`, cfg.Name).Scan(&exists); err != nil {
		return err
	}
	if exists {
		return nil
	}

	_, err = admin.ExecContext(ctx, `CREATE DATABASE "`+strings.ReplaceAll(cfg.Name, `"`, `""`)+`"`)
	return err
}

func isMissingDatabaseError(err error) bool {
	var pqErr *pq.Error
	if errors.As(err, &pqErr) {
		return string(pqErr.Code) == "3D000"
	}
	return strings.Contains(strings.ToLower(err.Error()), "does not exist")
}
