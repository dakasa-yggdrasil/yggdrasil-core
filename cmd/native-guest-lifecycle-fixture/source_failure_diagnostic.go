//go:build linux && nativequalification

package main

import (
	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"log"
	"net/http"
)

// Emits a fixed classification only, never a body, key, identity or error.
func sourceFailureDiagnostic(stage string) {
	if sourceFailureDiagnosticStage(stage) != "" {
		log.Printf("canonical_source_failure_diagnostic_v1 stage=%s", stage)
	}
}
func sourceFailureDiagnosticStage(stage string) string {
	switch stage {
	case "witness", "client", "transport", "http_pending", "http_unexpected", "decode", "validation", "record", "publish", "timeout", "http_context", "http_preflight", "http_transport", "http_read", "http_close", "http_auth", "http_not_found", "http_client", "http_409_complete", "http_409_other", "http_server", "http_other":
		return stage
	default:
		return ""
	}
}

// Uses the existing closed classifier on the SAME original return. This is a
// diagnostic only: original errors, retry loop, timestamps and body stay intact.
func sourceFailureHTTPStage(r capacity.GuestOriginalHTTPReturn, cause error) string {
	if cause == nil {
		return ""
	}
	switch capacity.GuestQualificationPredicate(capacity.GuestQualificationHTTPRefusal(r, cause)) {
	case "original-guest-step-90":
		return "http_preflight"
	case "original-guest-step-91":
		return "http_context"
	case "original-guest-step-92":
		return "http_transport"
	case "original-guest-step-93":
		return "http_read"
	case "original-guest-step-94":
		return "http_close"
	case "original-guest-step-95":
		return "http_auth"
	case "original-guest-step-96":
		return "http_not_found"
	case "original-guest-step-97":
		if r.Status == http.StatusConflict {
			if r.ResponseBodyScope == capacity.GuestOriginalBodyCompleteRead {
				return "http_409_complete"
			}
			return "http_409_other"
		}
		return "http_client"
	case "original-guest-step-50", "original-guest-step-51", "original-guest-step-52", "original-guest-step-53", "original-guest-step-54", "original-guest-step-55", "original-guest-step-98":
		return "http_server"
	default:
		return "http_other"
	}
}
