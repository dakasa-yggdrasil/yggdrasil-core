// Regression guard for the 2026-05-20 rabbit-restart cascade. When the
// cached *amqp.Connection in StartIntegrationRuntimeMonitor goes stale,
// acquireConnectivityChannel must attempt to redial from BROKER_URL
// instead of letting every integration probe fail forever with 504
// "channel/connection is not open".

package message

import (
	"strings"
	"testing"
)

func TestAcquireConnectivityChannel_NilConn_NoBrokerURL_ReturnsConfigError(t *testing.T) {
	t.Setenv("BROKER_URL", "")

	_, closer, err := acquireConnectivityChannel(nil)
	if closer == nil {
		t.Fatal("closer must never be nil (even on error)")
	}
	closer()
	if err == nil {
		t.Fatal("expected error when conn nil and BROKER_URL empty")
	}
	if !strings.Contains(err.Error(), "not configured") {
		t.Fatalf("expected config error, got: %v", err)
	}
}

func TestAcquireConnectivityChannel_NilConn_WithBrokerURL_AttemptsRedial(t *testing.T) {
	// Point at an unreachable broker so the dial fails fast; we only care
	// that the redial path is taken (not that it succeeds).
	t.Setenv("BROKER_URL", "amqp://no:no@127.0.0.1:65530/")

	_, closer, err := acquireConnectivityChannel(nil)
	if closer == nil {
		t.Fatal("closer must never be nil (even on error)")
	}
	closer()
	if err == nil {
		t.Fatal("expected dial failure error")
	}
	if !strings.Contains(err.Error(), "redial") {
		t.Fatalf("expected redial-attempted error, got: %v", err)
	}
}
