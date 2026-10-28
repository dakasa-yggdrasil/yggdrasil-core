//go:build linux && nativequalification

package main

import "log"

// Emits a fixed classification only, never a body, key, identity or error.
func sourceFailureDiagnostic(stage string) {
	if sourceFailureDiagnosticStage(stage) != "" {
		log.Printf("canonical_source_failure_diagnostic_v1 stage=%s", stage)
	}
}
func sourceFailureDiagnosticStage(stage string) string {
	switch stage {
	case "witness", "client", "transport", "http_pending", "http_unexpected", "decode", "validation", "record", "publish", "timeout":
		return stage
	default:
		return ""
	}
}
