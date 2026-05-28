// Per-client AccessTokenLifetime tests — audit 2026-05-27 A10.
//
// Locks down the contract that clientView.AccessTokenLifetime() honors a
// model.OIDCClient.AccessTokenLifetimeSeconds override when set, otherwise
// falls back to the global default (controllers/oidc/storage.go::AccessTokenLifetime,
// currently 15 minutes).
//
// These are unit tests on the clientView shape — they don't touch the DB.
// Repository round-trip + DB CHECK constraint are covered by the integration
// test in repository/oidc_clients_test.go.

package oidc

import (
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

// TestAccessTokenLifetime_DefaultWhenNil: a client with no override
// uses the global default. Backward-compat smoke — every pre-A10 client
// hits this path.
func TestAccessTokenLifetime_DefaultWhenNil(t *testing.T) {
	c := newClientView(model.OIDCClient{
		ClientID:                   "client-default",
		AccessTokenLifetimeSeconds: nil,
	}, "https://yggdrasil.test")
	if got := c.AccessTokenLifetime(); got != AccessTokenLifetime {
		t.Fatalf("nil override should fall back to global %v, got %v", AccessTokenLifetime, got)
	}
}

// TestAccessTokenLifetime_HonorsOverride: a client with seconds=120
// mints 2-minute tokens. High-trust clients use this to shrink the
// blast radius of a leaked JWT.
func TestAccessTokenLifetime_HonorsOverride(t *testing.T) {
	seconds := 120
	c := newClientView(model.OIDCClient{
		ClientID:                   "client-short-ttl",
		AccessTokenLifetimeSeconds: &seconds,
	}, "https://yggdrasil.test")
	if got := c.AccessTokenLifetime(); got != 120*time.Second {
		t.Fatalf("override 120s should produce 2m, got %v", got)
	}
}

// TestAccessTokenLifetime_Override60sMinimum: the lower bound (60s) is
// the DB CHECK minimum. Smaller values can't reach the row, but if one
// did via a bypass, the clientView still honors it — we'd rather emit a
// short-but-usable token than fall back to the longer default.
func TestAccessTokenLifetime_Override60sMinimum(t *testing.T) {
	seconds := 60
	c := newClientView(model.OIDCClient{
		ClientID:                   "client-1min",
		AccessTokenLifetimeSeconds: &seconds,
	}, "https://yggdrasil.test")
	if got := c.AccessTokenLifetime(); got != time.Minute {
		t.Fatalf("override 60s should produce 1m, got %v", got)
	}
}

// TestAccessTokenLifetime_Override86400sMaximum: the upper bound (1 day)
// also flows through. Beyond that DB rejects; here we're testing the
// view layer behavior.
func TestAccessTokenLifetime_Override86400sMaximum(t *testing.T) {
	seconds := 86400
	c := newClientView(model.OIDCClient{
		ClientID:                   "client-1day",
		AccessTokenLifetimeSeconds: &seconds,
	}, "https://yggdrasil.test")
	if got := c.AccessTokenLifetime(); got != 24*time.Hour {
		t.Fatalf("override 86400s should produce 24h, got %v", got)
	}
}

// TestAccessTokenLifetime_OverrideZeroFallsBack: a misconfigured row
// with seconds=0 (or negative) silently reverts to the global default.
// Fail-open is the right move — the only consequence is "longer-than-
// intended TTL", not an outage.
func TestAccessTokenLifetime_OverrideZeroFallsBack(t *testing.T) {
	for _, badVal := range []int{0, -1, -3600} {
		v := badVal
		c := newClientView(model.OIDCClient{
			ClientID:                   "client-bad-override",
			AccessTokenLifetimeSeconds: &v,
		}, "https://yggdrasil.test")
		if got := c.AccessTokenLifetime(); got != AccessTokenLifetime {
			t.Errorf("override %d should fall back to global, got %v", badVal, got)
		}
	}
}

// TestAccessTokenLifetime_OverridePreservedAcrossViews: the override
// survives newClientView wrapping — important because every authorize
// call instantiates a fresh view from a freshly-loaded row.
func TestAccessTokenLifetime_OverridePreservedAcrossViews(t *testing.T) {
	seconds := 300
	row := model.OIDCClient{
		ClientID:                   "client-stable",
		AccessTokenLifetimeSeconds: &seconds,
	}
	v1 := newClientView(row, "https://yggdrasil.test")
	v2 := newClientView(row, "https://yggdrasil.test")
	if v1.AccessTokenLifetime() != v2.AccessTokenLifetime() {
		t.Fatalf("two views of the same row should agree on TTL")
	}
	if v1.AccessTokenLifetime() != 5*time.Minute {
		t.Fatalf("expected 5m, got %v", v1.AccessTokenLifetime())
	}
}
