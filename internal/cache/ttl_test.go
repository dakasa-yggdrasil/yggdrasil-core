package cache

import (
	"testing"
	"time"
)

// TestTTL_PolicyValues pins the cache-TTL contract.  Changing any of
// these intentionally requires also editing the test so the diff
// surfaces in code review (silent TTL drift is a known regression
// vector — the surface PermissionCacheProvider once drifted to 5min
// while server-side stayed at 30s, producing a stale-permission
// window during the 2026-05-27 audit).
func TestTTL_PolicyValues(t *testing.T) {
	tests := []struct {
		name string
		got  time.Duration
		want time.Duration
	}{
		{"IntegrationManifestTTL", IntegrationManifestTTL, 5 * time.Minute},
		{"PermissionCheckTTL", PermissionCheckTTL, 30 * time.Second},
		{"DescribeOutputTTL", DescribeOutputTTL, 1 * time.Minute},
		{"SessionLookupTTL", SessionLookupTTL, 0},
	}
	for _, tc := range tests {
		if tc.got != tc.want {
			t.Errorf("%s = %v, want %v", tc.name, tc.got, tc.want)
		}
	}
}

// TestTTL_SessionsNeverCached is the security-critical assertion: if
// SessionLookupTTL ever drifts off zero, an admin revoke takes >0s to
// land, violating §13.
func TestTTL_SessionsNeverCached(t *testing.T) {
	if SessionLookupTTL != 0 {
		t.Fatalf("SessionLookupTTL must be 0 (sessions never cached) — got %v", SessionLookupTTL)
	}
}
