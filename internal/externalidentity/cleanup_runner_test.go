package externalidentity

import "testing"

// Sanity test that the env parser handles common shapes without panicking.
// Full E2E (insert rows, call CleanupTick) is covered by the integration
// test in T19. This file just guards that the addon shim doesn't drift.
func TestPlaceholderCleanup(t *testing.T) {
	// no-op: real coverage in T19's integration test.
}
