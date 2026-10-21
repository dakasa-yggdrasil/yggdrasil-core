package capacity

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func temporalBody(d *GuestProbeTemporalDiagnostic) []byte {
	b, _ := json.Marshal(struct {
		Code     string                        `json:"code"`
		Status   int                           `json:"status"`
		Title    string                        `json:"title"`
		Detail   string                        `json:"detail"`
		Stage    string                        `json:"stage"`
		Temporal *GuestProbeTemporalDiagnostic `json:"temporal,omitempty"`
	}{"qualification_probe.authority_held", 409, "Guest retirement held", "The original Guest retirement requires its enrolled authority and complete original results.", "challenge_deadline", d})
	return append(b, '\n')
}
func temporalFixture(reason string, issued, deadline, now time.Time) GuestProbeTemporalDiagnostic {
	e, ec := probeTemporalDelta(now.Sub(issued))
	r, rc := probeTemporalDelta(deadline.Sub(now))
	return GuestProbeTemporalDiagnostic{"guest_probe_temporal_diagnostic_v1", "request_times_unverified", reason, issued, deadline, now, e, r, ec || rc}
}
func TestProbeTemporalClosedProjection(t *testing.T) {
	now := time.Date(2026, 10, 21, 3, 41, 24, 753705548, time.UTC)
	cases := []GuestProbeTemporalDiagnostic{
		temporalFixture("issued_zero", time.Time{}, now.Add(time.Second), now),
		temporalFixture("issued_future", now.Add(time.Nanosecond), now.Add(time.Second), now),
		temporalFixture("deadline_not_after_issue", now, now, now),
		temporalFixture("duration_over_limit", now, now.Add(5*time.Second+time.Nanosecond), now),
		temporalFixture("deadline_reached", now.Add(-time.Second), now, now),
	}
	for _, tc := range cases {
		t.Run(tc.Reason, func(t *testing.T) {
			body := temporalBody(&tc)
			got := GuestProbeDiagnostic(GuestOriginalHTTPReturn{Status: 409, Body: body, OriginalContextFailed: true})
			if got.Temporal == nil || *got.Temporal != tc || !got.ContextFailed || got.Stage != "challenge_deadline" {
				t.Fatalf("lost exact diagnostic: %+v", got)
			}
			for _, field := range []string{"schema", "trust", "reason", "issued_at", "deadline", "validated_at", "elapsed_since_issue_ns", "remaining_ns", "deltas_clamped"} {
				var obj map[string]json.RawMessage
				json.Unmarshal(body, &obj)
				var inner map[string]json.RawMessage
				json.Unmarshal(obj["temporal"], &inner)
				fragment := `"` + field + `":` + string(inner[field])
				bad := strings.Replace(string(body), fragment+",", "", 1)
				if bad == string(body) {
					bad = strings.Replace(string(body), ","+fragment, "", 1)
				}
				if bad == string(body) {
					t.Fatal("missing-field fixture did not remove", field)
				}
				if d := GuestProbeDiagnostic(GuestOriginalHTTPReturn{Status: 409, Body: []byte(bad)}); d.Temporal != nil || d.Code != "" {
					t.Fatal("missing field accepted", field)
				}
			}
			for _, bad := range []string{
				strings.Replace(string(body), `"reason":"`+tc.Reason+`"`, `"reason":"SECRET"`, 1),
				strings.Replace(string(body), `"trust":"request_times_unverified"`, `"trust":"authenticated"`, 1),
				strings.Replace(string(body), `"temporal":{`, `"temporal":{"secret":"SECRET",`, 1),
				strings.Replace(string(body), `"stage":"challenge_deadline"`, `"stage":"challenge_signature"`, 1),
				string(body) + "SECRET",
			} {
				d := GuestProbeDiagnostic(GuestOriginalHTTPReturn{Status: 409, Body: []byte(bad)})
				out, _ := json.Marshal(d)
				if d.Temporal != nil || d.Code != "" || strings.Contains(string(out), "SECRET") {
					t.Fatal("unsafe diagnostic retained")
				}
			}
			for _, mutate := range []func(*GuestProbeTemporalDiagnostic){func(d *GuestProbeTemporalDiagnostic) { d.ElapsedSinceIssueNS++ }, func(d *GuestProbeTemporalDiagnostic) { d.RemainingNS-- }, func(d *GuestProbeTemporalDiagnostic) { d.DeltasClamped = !d.DeltasClamped }} {
				bad := tc
				mutate(&bad)
				if d := GuestProbeDiagnostic(GuestOriginalHTTPReturn{Status: 409, Body: temporalBody(&bad)}); d.Temporal != nil {
					t.Fatal("inconsistent delta accepted")
				}
			}
		})
	}
	if d := GuestProbeDiagnostic(GuestOriginalHTTPReturn{Status: 409, Body: temporalBody(nil)}); d.Stage != "challenge_deadline" || d.Temporal != nil {
		t.Fatal("legacy stage-only lost")
	}
	for _, d := range []GuestOriginalHTTPReturn{{Status: 409, Body: temporalBody(&cases[1]), ReadFailed: true}, {Status: 409, Body: temporalBody(&cases[1]), CloseFailed: true}, {Status: 409, Body: temporalBody(&cases[1]), DoFailed: true}, {Status: 409, Body: temporalBody(&cases[1]), PreflightFailed: true}} {
		if got := GuestProbeDiagnostic(d); got.Temporal != nil {
			t.Fatal("incomplete transport accepted")
		}
	}
}
func TestProbeTemporalClampBoundaries(t *testing.T) {
	for _, tc := range []struct {
		d     time.Duration
		want  int64
		clamp bool
	}{{24 * time.Hour, int64(24 * time.Hour), false}, {24*time.Hour + 1, int64(24 * time.Hour), true}, {-24 * time.Hour, -int64(24 * time.Hour), false}, {-24*time.Hour - 1, -int64(24 * time.Hour), true}} {
		got, c := probeTemporalDelta(tc.d)
		if got != tc.want || c != tc.clamp {
			t.Fatal("bad clamp")
		}
	}
}
