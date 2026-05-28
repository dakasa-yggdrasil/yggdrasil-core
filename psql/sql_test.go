package psql

import (
	"testing"
	"time"
)

func TestLoadPoolConfig_Defaults(t *testing.T) {
	t.Setenv("YGGDRASIL_PG_MAX_CONNS", "")
	t.Setenv("YGGDRASIL_PG_MIN_CONNS", "")
	t.Setenv("YGGDRASIL_PG_MAX_CONN_LIFETIME", "")
	t.Setenv("YGGDRASIL_PG_MAX_IDLE_TIME", "")

	cfg := LoadPoolConfig()
	if cfg.MaxOpenConns != DefaultMaxOpenConns {
		t.Errorf("MaxOpenConns=%d, want %d", cfg.MaxOpenConns, DefaultMaxOpenConns)
	}
	if cfg.MinOpenConns != DefaultMinOpenConns {
		t.Errorf("MinOpenConns=%d, want %d", cfg.MinOpenConns, DefaultMinOpenConns)
	}
	if cfg.MaxConnLifetime != DefaultMaxConnLifetime {
		t.Errorf("MaxConnLifetime=%v, want %v", cfg.MaxConnLifetime, DefaultMaxConnLifetime)
	}
	if cfg.MaxConnIdleTime != DefaultMaxConnIdleTime {
		t.Errorf("MaxConnIdleTime=%v, want %v", cfg.MaxConnIdleTime, DefaultMaxConnIdleTime)
	}
}

func TestLoadPoolConfig_Overrides(t *testing.T) {
	t.Setenv("YGGDRASIL_PG_MAX_CONNS", "50")
	t.Setenv("YGGDRASIL_PG_MIN_CONNS", "5")
	t.Setenv("YGGDRASIL_PG_MAX_CONN_LIFETIME", "1h")
	t.Setenv("YGGDRASIL_PG_MAX_IDLE_TIME", "10m")

	cfg := LoadPoolConfig()
	if cfg.MaxOpenConns != 50 {
		t.Errorf("MaxOpenConns=%d, want 50", cfg.MaxOpenConns)
	}
	if cfg.MinOpenConns != 5 {
		t.Errorf("MinOpenConns=%d, want 5", cfg.MinOpenConns)
	}
	if cfg.MaxConnLifetime != time.Hour {
		t.Errorf("MaxConnLifetime=%v, want 1h", cfg.MaxConnLifetime)
	}
	if cfg.MaxConnIdleTime != 10*time.Minute {
		t.Errorf("MaxConnIdleTime=%v, want 10m", cfg.MaxConnIdleTime)
	}
}

func TestLoadPoolConfig_InvalidFallsBackToDefault(t *testing.T) {
	t.Setenv("YGGDRASIL_PG_MAX_CONNS", "not-an-int")
	t.Setenv("YGGDRASIL_PG_MIN_CONNS", "-3")
	t.Setenv("YGGDRASIL_PG_MAX_CONN_LIFETIME", "garbage")
	t.Setenv("YGGDRASIL_PG_MAX_IDLE_TIME", "")

	cfg := LoadPoolConfig()
	if cfg.MaxOpenConns != DefaultMaxOpenConns {
		t.Errorf("MaxOpenConns=%d, want default %d", cfg.MaxOpenConns, DefaultMaxOpenConns)
	}
	if cfg.MinOpenConns != DefaultMinOpenConns {
		t.Errorf("MinOpenConns=%d, want default %d", cfg.MinOpenConns, DefaultMinOpenConns)
	}
	if cfg.MaxConnLifetime != DefaultMaxConnLifetime {
		t.Errorf("MaxConnLifetime=%v, want default %v", cfg.MaxConnLifetime, DefaultMaxConnLifetime)
	}
	if cfg.MaxConnIdleTime != DefaultMaxConnIdleTime {
		t.Errorf("MaxConnIdleTime=%v, want default %v", cfg.MaxConnIdleTime, DefaultMaxConnIdleTime)
	}
}
