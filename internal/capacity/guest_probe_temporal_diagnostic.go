package capacity

import "time"

// GuestProbeTemporalDiagnostic contains only unverified request times and the
// Guest's validation sample. It is never an authority or a clock-offset proof.
type GuestProbeTemporalDiagnostic struct {
	Schema              string    `json:"schema"`
	Trust               string    `json:"trust"`
	Reason              string    `json:"reason"`
	IssuedAt            time.Time `json:"issued_at"`
	Deadline            time.Time `json:"deadline"`
	ValidatedAt         time.Time `json:"validated_at"`
	ElapsedSinceIssueNS int64     `json:"elapsed_since_issue_ns"`
	RemainingNS         int64     `json:"remaining_ns"`
	DeltasClamped       bool      `json:"deltas_clamped"`
}

func probeTemporalDelta(d time.Duration) (int64, bool) {
	const limit = 24 * time.Hour
	if d > limit {
		return int64(limit), true
	}
	if d < -limit {
		return -int64(limit), true
	}
	return int64(d), false
}
func (d GuestProbeTemporalDiagnostic) valid() bool {
	if d.Schema != "guest_probe_temporal_diagnostic_v1" || d.Trust != "request_times_unverified" {
		return false
	}
	elapsed, ec := probeTemporalDelta(d.ValidatedAt.Sub(d.IssuedAt))
	remaining, rc := probeTemporalDelta(d.Deadline.Sub(d.ValidatedAt))
	if d.ElapsedSinceIssueNS != elapsed || d.RemainingNS != remaining || d.DeltasClamped != (ec || rc) {
		return false
	}
	reason := ""
	switch {
	case d.IssuedAt.IsZero():
		reason = "issued_zero"
	case d.IssuedAt.After(d.ValidatedAt):
		reason = "issued_future"
	case !d.Deadline.After(d.IssuedAt):
		reason = "deadline_not_after_issue"
	case d.Deadline.Sub(d.IssuedAt) > 5*time.Second:
		reason = "duration_over_limit"
	case !d.ValidatedAt.Before(d.Deadline):
		reason = "deadline_reached"
	}
	return reason != "" && d.Reason == reason
}
