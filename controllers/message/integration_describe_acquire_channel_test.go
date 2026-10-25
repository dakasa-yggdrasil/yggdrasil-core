package message

import (
	"strings"
	"testing"
)

func TestAcquireConnectivityChannel_NilConn_NoBrokerURL_ReturnsUnavailable(t *testing.T) {
	t.Setenv("BROKER_URL", "")

	_, closer, err := acquireConnectivityChannel(nil)
	if closer == nil {
		t.Fatal("closer must never be nil (even on error)")
	}
	closer()
	if err == nil {
		t.Fatal("expected error when conn nil and BROKER_URL empty")
	}
	if !strings.Contains(err.Error(), "session is unavailable") {
		t.Fatalf("expected unavailable session, got: %v", err)
	}
}

func TestAcquireConnectivityChannel_NilConn_WithBrokerURL_DoesNotRedial(t *testing.T) {
	// An invalid URL makes a regression fail locally during parsing, without
	// contacting any broker. A probe must ignore this independent dial path.
	t.Setenv("BROKER_URL", "invalid-scheme://not-a-broker")

	_, closer, err := acquireConnectivityChannel(nil)
	if closer == nil {
		t.Fatal("closer must never be nil (even on error)")
	}
	closer()
	if err == nil {
		t.Fatal("expected unavailable session")
	}
	if !strings.Contains(err.Error(), "session is unavailable") || strings.Contains(err.Error(), "redial") {
		t.Fatalf("probe attempted an independent connection: %v", err)
	}
}
