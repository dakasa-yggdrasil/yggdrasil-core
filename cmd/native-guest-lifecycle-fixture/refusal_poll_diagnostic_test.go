//go:build linux && nativequalification

package main

import (
	"errors"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
)

func TestRefusalPollDiagnosticCountsOnlyClosedTransportFacts(t *testing.T) {
	start := time.Date(2026, 10, 31, 0, 0, 0, 0, time.UTC)
	d := refusalPollDiagnostic{Schema: "native_qualification_refusal_poll_diagnostic_v1", Case: "held_ack_after_owned_original_deadline"}
	d.observe(capacity.GuestOriginalHTTPReturn{Status: 409, DriverReturnedAt: start}, nil)
	d.observe(capacity.GuestOriginalHTTPReturn{Status: 0, DriverReturnedAt: start.Add(time.Second), DoFailed: true, OriginalContextFailed: true}, errors.New("not retained"))
	d.observe(capacity.GuestOriginalHTTPReturn{Status: 200, DriverReturnedAt: start.Add(2 * time.Second)}, nil)
	if d.Calls != 3 || d.StatusConflict != 1 || d.StatusAbsent != 1 || d.StatusOK != 1 || d.StatusOther != 0 || d.CallErrors != 1 || d.DoFailures != 1 || d.ContextFailures != 1 || d.ProductionQualified || !d.FirstReturnedAt.Equal(start) || !d.LastReturnedAt.Equal(start.Add(2*time.Second)) {
		t.Fatalf("unexpected closed transport census: %+v", d)
	}
}
