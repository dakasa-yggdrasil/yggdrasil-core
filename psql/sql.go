package psql

import (
	"database/sql"
	"os"
	"strconv"
	"time"

	_ "github.com/lib/pq"
)

// Pool configuration defaults — chosen for a single-pod yggdrasil-core
// deployment fronting a Postgres with default `max_connections=100`.
// One core pod consumes at most DefaultMaxOpenConns; the remaining budget
// is left for goose migrations, the bootstrap CLI, and direct ops queries
// the operator runs out-of-band.
//
// Override via env:
//
//	YGGDRASIL_PG_MAX_CONNS         (default 25)
//	YGGDRASIL_PG_MIN_CONNS         (default 2)
//	YGGDRASIL_PG_MAX_CONN_LIFETIME (default 30m)
//	YGGDRASIL_PG_MAX_IDLE_TIME     (default 5m)
//
// All values are parsed once at process start; subsequent edits require a
// pod restart (the addon bootstrap path runs exactly once).
const (
	DefaultMaxOpenConns    = 25
	DefaultMinOpenConns    = 2
	DefaultMaxConnLifetime = 30 * time.Minute
	DefaultMaxConnIdleTime = 5 * time.Minute
)

// PoolConfig holds the tunable pool parameters. Loaded by LoadPoolConfig.
type PoolConfig struct {
	MaxOpenConns    int
	MinOpenConns    int
	MaxConnLifetime time.Duration
	MaxConnIdleTime time.Duration
}

// LoadPoolConfig reads pool tunables from the environment, applying the
// documented defaults when a var is unset or unparseable.
func LoadPoolConfig() PoolConfig {
	return PoolConfig{
		MaxOpenConns:    envIntDefault("YGGDRASIL_PG_MAX_CONNS", DefaultMaxOpenConns),
		MinOpenConns:    envIntDefault("YGGDRASIL_PG_MIN_CONNS", DefaultMinOpenConns),
		MaxConnLifetime: envDurationDefault("YGGDRASIL_PG_MAX_CONN_LIFETIME", DefaultMaxConnLifetime),
		MaxConnIdleTime: envDurationDefault("YGGDRASIL_PG_MAX_IDLE_TIME", DefaultMaxConnIdleTime),
	}
}

// Open returns a PostgreSQL connection pool with the documented defaults
// applied (or the env-tuned values if YGGDRASIL_PG_* are set). The pool
// is configured but NOT pinged here — callers ping in the bootstrap
// path so a startup failure surfaces with a clear error.
func Open() (*sql.DB, error) {
	db, err := sql.Open("postgres", LoadConfig().DSN())
	if err != nil {
		return nil, err
	}
	ApplyPoolConfig(db, LoadPoolConfig())
	return db, nil
}

// ApplyPoolConfig applies the given pool tunables to an existing *sql.DB.
// Exposed so scripts/* binaries (bootstrap, goose, …) can reuse the same
// defaults without re-deriving them.
//
// MinConns is implemented as the warm-up target for `SetMaxIdleConns`
// (database/sql does not expose a true min, but keeping at least N idle
// connections approximates the same behaviour: the pool will eagerly fill
// up to MaxIdleConns on demand and not shrink below that without the
// idle timeout kicking in).
func ApplyPoolConfig(db *sql.DB, cfg PoolConfig) {
	if cfg.MaxOpenConns > 0 {
		db.SetMaxOpenConns(cfg.MaxOpenConns)
	}
	if cfg.MinOpenConns > 0 {
		db.SetMaxIdleConns(cfg.MinOpenConns)
	}
	if cfg.MaxConnLifetime > 0 {
		db.SetConnMaxLifetime(cfg.MaxConnLifetime)
	}
	if cfg.MaxConnIdleTime > 0 {
		db.SetConnMaxIdleTime(cfg.MaxConnIdleTime)
	}
}

func envIntDefault(key string, fallback int) int {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	n, err := strconv.Atoi(v)
	if err != nil || n <= 0 {
		return fallback
	}
	return n
}

func envDurationDefault(key string, fallback time.Duration) time.Duration {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	d, err := time.ParseDuration(v)
	if err != nil || d <= 0 {
		return fallback
	}
	return d
}
