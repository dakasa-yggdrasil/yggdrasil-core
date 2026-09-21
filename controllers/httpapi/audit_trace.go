package httpapi

import (
	"net/http"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/tracecontext"
)

// requestTraceIDs returns the trace reference every audit writer in this
// package stores: the trace-id and parent-id of the request's W3C traceparent
// header when it is well formed, or empty strings when the request is nil or
// the header is absent or malformed. Storing the header raw let a caller pick
// a value the audit_events columns reject, which erased the row of the very
// action being audited (a login, an MFA verification, a manifest write).
func requestTraceIDs(r *http.Request) (traceID, spanID string) {
	if r == nil {
		return "", ""
	}
	return tracecontext.ParseTraceparent(r.Header.Get("traceparent"))
}
