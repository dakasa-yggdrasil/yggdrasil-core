package message

import (
	"errors"
	"testing"
)

// TestIsLikelyAdapterVersionMismatch_PositiveSignals locks in the heuristics
// the describe handshake uses to decide whether a transport-level RPC failure
// is actually a forward-drift signal (adapter rejected the describe because
// the request's ExpectedVersion no longer matches the adapter's live version).
//
// When this returns true, the describe handler nudges manifest_sync so the
// drift is auto-healed before the next handshake — without waiting for the
// 1h cron safety-net.
func TestIsLikelyAdapterVersionMismatch_PositiveSignals(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		err  error
	}{
		{
			name: "adapter SDK 'expected version X but adapter is Y' wrapper",
			err:  errors.New(`describe integration type github/main through transport "amqp": expected version "1.7.0" but adapter is "1.7.1"`),
		},
		{
			name: "raw adapter failure code 'version_mismatch'",
			err:  errors.New(`adapter returned failure: code="version_mismatch" msg="expected 1.7.0 got 1.7.1"`),
		},
		{
			name: "case-insensitive match (upper)",
			err:  errors.New(`Expected Version "1.7.0" but adapter is "1.7.1"`),
		},
		{
			name: "padded / multi-line transport error",
			err:  errors.New("  rpc call failed: expected_version mismatch: 1.7.0 vs 1.7.1  "),
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if !isLikelyAdapterVersionMismatch(tc.err) {
				t.Fatalf("isLikelyAdapterVersionMismatch(%q) = false, want true", tc.err.Error())
			}
		})
	}
}

// TestIsLikelyAdapterVersionMismatch_NegativeSignals confirms the heuristic
// does NOT false-positive on unrelated transport errors. False positives are
// cheap (they would trigger a redundant sync Notify which the runner dedups
// via per-typeID mutex) but we still want the function to be precise.
func TestIsLikelyAdapterVersionMismatch_NegativeSignals(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		err  error
	}{
		{name: "nil error", err: nil},
		{name: "generic timeout", err: errors.New("context deadline exceeded")},
		{name: "amqp connection closed", err: errors.New("amqp: connection closed")},
		{name: "describe route missing", err: errors.New("integration type github/main has no describe route")},
		{name: "validate request rejected", err: errors.New("validate integration describe request: schema violation")},
		{name: "live contract invalid", err: errors.New("live describe contract for integration type X/Y is invalid")},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if isLikelyAdapterVersionMismatch(tc.err) {
				t.Fatalf("isLikelyAdapterVersionMismatch(%q) = true, want false", tc.err)
			}
		})
	}
}
