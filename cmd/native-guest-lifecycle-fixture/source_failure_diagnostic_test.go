//go:build linux && nativequalification

package main

import "testing"

func TestSourceFailureDiagnosticClosed(t *testing.T) {
	for _, stage := range []string{"witness", "client", "transport", "http_pending", "http_unexpected", "decode", "validation", "record", "publish", "timeout"} {
		if sourceFailureDiagnosticStage(stage) != stage {
			t.Fatal("closed stage omitted", stage)
		}
	}
	for _, stage := range []string{"", "unexpected private material", "transport ", "HTTP_PENDING"} {
		if sourceFailureDiagnosticStage(stage) != "" {
			t.Fatal("unexpected stage admitted")
		}
	}
}
