//go:build nativequalification

package capacityqualification

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestReadDiagnosticClosedVocabulary(t *testing.T) {
	valid := map[string][]string{
		"client":   {"catalog", "transport", "status", "decode", "contract_request", "transport_setup", "rpc_marshal", "rpc_roundtrip", "rpc_response", "contract_response", "operation", "capability", "explicit_status", "context"},
		"consumer": {"envelope", "ordinal", "callee", "metadata", "request_publish", "response_encode", "response_publish", "reply_ack", "return_publish"},
		"callee":   {"scope", "policy", "input", "slot_type", "slot", "keys", "realm", "prereg_query", "prereg_compare", "original", "binding", "ids", "instance", "type", "receipt", "expected", "native_read", "native_identity", "approved", "publish", "action", "context"},
	}
	for origin, stages := range valid {
		for _, stage := range stages {
			d, err := NewReadDiagnostic(origin, stage)
			if err != nil || d.Origin != origin || d.Stage != stage {
				t.Fatalf("invalid allowed stage %s/%s", origin, stage)
			}
			b, e := json.Marshal(d)
			if e != nil || strings.Contains(string(b), "synthetic-secret") {
				t.Fatal("closed diagnostic serialization failed")
			}
		}
	}
	for _, x := range [][2]string{{"client", "realm"}, {"consumer", "transport"}, {"callee", "unknown"}, {"callee", "scope\nsecret"}, {"other", "scope"}, {"", ""}} {
		if _, err := NewReadDiagnostic(x[0], x[1]); err == nil {
			t.Fatalf("unapproved stage accepted: %q/%q", x[0], x[1])
		}
	}
}
