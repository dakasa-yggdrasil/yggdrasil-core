// Package tracecontext reads the W3C Trace Context traceparent header into
// the trace reference the audit_events rows store.
//
// Every audit writer takes trace_id and span_id from this parser and from
// nothing else. The header is caller-controlled: stored raw, a long or
// malformed value makes Postgres reject the whole audit row (trace_id is
// VARCHAR(64), span_id VARCHAR(32)), which erases the trail of the action
// that produced it. Anything that is not a well-formed traceparent is
// therefore dropped, never truncated and never stored.
package tracecontext

import (
	"regexp"
	"strings"
)

// traceparentPattern is the W3C Trace Context header form:
// version-traceid-parentid-flags, all lowercase hex.
var traceparentPattern = regexp.MustCompile(`^[0-9a-f]{2}-[0-9a-f]{32}-[0-9a-f]{16}-[0-9a-f]{2}$`)

// ParseTraceparent returns the trace-id and parent-id of a well-formed W3C
// traceparent header, or empty strings when the header is absent, malformed,
// uses the reserved version ff, or carries an all-zero id. Surrounding
// whitespace is tolerated; a trailing field, uppercase hex, or any other
// deviation is not.
func ParseTraceparent(header string) (traceID, spanID string) {
	header = strings.TrimSpace(header)
	if !traceparentPattern.MatchString(header) {
		return "", ""
	}
	parts := strings.Split(header, "-")
	if parts[0] == "ff" || parts[1] == strings.Repeat("0", 32) || parts[2] == strings.Repeat("0", 16) {
		return "", ""
	}
	return parts[1], parts[2]
}
