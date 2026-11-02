//go:build linux && nativequalification

package main

import (
	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"log"
	"net/http"
	"strings"
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

// The history records only classifications of actual completed calls. It is
// private to one source owner and never holds a response, error or identity.
type sourceFailureHTTPHistory struct {
	calls uint64
	last  string
}

func (h *sourceFailureHTTPHistory) observe(r capacity.GuestOriginalHTTPReturn, cause error) string {
	if h.calls < ^uint64(0) {
		h.calls++
	}
	stage := sourceFailureHTTPStage(r, cause)
	h.last = stage
	return stage
}

func (h sourceFailureHTTPHistory) lastClass() string {
	if h.calls == 0 {
		return "no_call"
	}
	if !strings.HasPrefix(h.last, "http_") || sourceFailureDiagnosticStage(h.last) != h.last {
		return "unclassified"
	}
	return h.last
}

// Keep the existing timeout label and add one closed summary in the same log
// write, after the original context is done; no retry or deadline is changed.
func sourceFailureHTTPTimeoutDiagnostic(h sourceFailureHTTPHistory) {
	log.Printf("canonical_source_failure_diagnostic_v1 stage=timeout\ncanonical_source_failure_http_last_v1 attempts=%d last_class=%s", h.calls, h.lastClass())
}
