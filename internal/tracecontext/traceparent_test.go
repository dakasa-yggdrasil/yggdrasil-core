package tracecontext

import (
	"strings"
	"testing"
)

// The audit_events columns the parsed ids are stored in (migration 00017).
const (
	traceIDColumnWidth = 64
	spanIDColumnWidth  = 32
)

func TestParseTraceparent(t *testing.T) {
	t.Parallel()

	const valid = "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01"
	cases := []struct {
		name      string
		header    string
		wantTrace string
		wantSpan  string
	}{
		{name: "absent"},
		{name: "well formed", header: valid, wantTrace: "0af7651916cd43dd8448eb211c80319c", wantSpan: "b7ad6b7169203331"},
		{name: "surrounding whitespace", header: "  " + valid + "  ", wantTrace: "0af7651916cd43dd8448eb211c80319c", wantSpan: "b7ad6b7169203331"},
		{name: "uppercase hex", header: "00-0AF7651916CD43DD8448EB211C80319C-B7AD6B7169203331-01"},
		{name: "trailing field", header: valid + "-extra"},
		{name: "reserved version ff", header: "ff-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01"},
		{name: "all zero trace id", header: "00-00000000000000000000000000000000-b7ad6b7169203331-01"},
		{name: "all zero parent id", header: "00-0af7651916cd43dd8448eb211c80319c-0000000000000000-01"},
		{name: "prose", header: "trace me please"},
		{name: "one past the trace_id column", header: strings.Repeat("0", traceIDColumnWidth+1)},
		{name: "oversized garbage", header: strings.Repeat("a", 200)},
		{name: "oversized with a valid prefix", header: valid + strings.Repeat("-00", 20)},
		{name: "inner whitespace", header: "00-0af7651916cd43dd8448eb211c80319c\t-b7ad6b7169203331-01"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			trace, span := ParseTraceparent(tc.header)
			if trace != tc.wantTrace || span != tc.wantSpan {
				t.Fatalf("ParseTraceparent(%q)=(%q,%q), want (%q,%q)", tc.header, trace, span, tc.wantTrace, tc.wantSpan)
			}
			if len(trace) > traceIDColumnWidth || len(span) > spanIDColumnWidth {
				t.Fatalf("ParseTraceparent(%q) exceeds the audit_events columns", tc.header)
			}
		})
	}
}

// TestParseTraceparentNeverExceedsTheColumns pins the property the audit
// writers rely on: whatever the header, the returned ids fit trace_id
// VARCHAR(64) and span_id VARCHAR(32), so the header alone can never make
// Postgres reject an audit row.
func TestParseTraceparentNeverExceedsTheColumns(t *testing.T) {
	t.Parallel()

	for n := 0; n <= 300; n++ {
		for _, fill := range []string{"a", "0", "-", "00-"} {
			header := strings.Repeat(fill, n)
			trace, span := ParseTraceparent(header)
			if len(trace) > traceIDColumnWidth || len(span) > spanIDColumnWidth {
				t.Fatalf("ParseTraceparent(%d x %q) exceeds the audit_events columns", n, fill)
			}
			if trace == "" && span != "" || trace != "" && span == "" {
				t.Fatalf("ParseTraceparent(%d x %q) returned half a reference", n, fill)
			}
		}
	}
}
