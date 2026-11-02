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

// The idle cap must stay at ten connections (it replaced two, which made
// the single Core pod reconnect ~110 times a minute) and below the open cap.
func TestPoolDefaultKeepsTenWarmConnections(t *testing.T) {
	if DefaultMinOpenConns != 10 {
		t.Fatalf("DefaultMinOpenConns=%d, want 10", DefaultMinOpenConns)
	}
	if DefaultMaxOpenConns != 25 || DefaultMinOpenConns > DefaultMaxOpenConns {
		t.Fatalf("idle pool %d must stay within the open cap %d (want 25)", DefaultMinOpenConns, DefaultMaxOpenConns)
	}
	t.Setenv("YGGDRASIL_PG_MIN_CONNS", "")
	if got := LoadPoolConfig().MinOpenConns; got != 10 {
		t.Fatalf("unset YGGDRASIL_PG_MIN_CONNS loaded %d, want 10", got)
	}
	t.Setenv("YGGDRASIL_PG_MIN_CONNS", "3")
	if got := LoadPoolConfig().MinOpenConns; got != 3 {
		t.Fatalf("YGGDRASIL_PG_MIN_CONNS=3 loaded %d, want the override", got)
	}
}

// The idle cap logged at startup is what database/sql applies: an open cap
// below the idle default lowers it.
func TestPoolEffectiveIdleConnsFollowsTheOpenCap(t *testing.T) {
	for _, c := range []struct{ open, idle, want int }{{25, 10, 10}, {5, 10, 5}, {10, 10, 10}, {0, 10, 10}} {
		if got := (PoolConfig{MaxOpenConns: c.open, MinOpenConns: c.idle}).EffectiveIdleConns(); got != c.want {
			t.Fatalf("open=%d idle=%d effective=%d, want %d", c.open, c.idle, got, c.want)
		}
	}
}
