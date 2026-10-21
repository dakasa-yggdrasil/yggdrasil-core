package capacity

import (
	"bytes"
	"encoding/json"
	"time"
)

type GuestProbeHTTPDiagnostic struct {
	Schema          string                        `json:"schema"`
	Status          int                           `json:"status"`
	Code            string                        `json:"code"`
	Stage           string                        `json:"stage"`
	ReadReturnedAt  time.Time                     `json:"read_returned_at"`
	CloseReturnedAt time.Time                     `json:"close_returned_at"`
	ContextFailed   bool                          `json:"context_failed"`
	PreflightFailed bool                          `json:"preflight_failed"`
	DoFailed        bool                          `json:"do_failed"`
	ReadFailed      bool                          `json:"read_failed"`
	CloseFailed     bool                          `json:"close_failed"`
	Temporal        *GuestProbeTemporalDiagnostic `json:"temporal,omitempty"`
}

var GuestProbeStages = map[string][]string{
	"qualification_probe.closed_request_required": {"request_read", "request_close", "request_bound", "request_schema", "request_canonical", "request_unknown"},
	"qualification_probe.authority_held":          {"actor_config", "actor_key_read", "actor_key_decode", "actor_authority_client", "authority_unknown", "actor_load", "challenge_schema", "challenge_deadline", "challenge_identity", "challenge_signature"},
	"qualification_probe.original_held":           {"enrollment_validate", "challenge_schema", "challenge_deadline", "challenge_identity", "challenge_signature", "journal_read", "journal_shape", "journal_enrollment", "lifetime_actor", "lifetime_runtime", "lifetime_writer", "writer_parent", "census_before", "census_before_validate", "socket_connect", "socket_deadline", "socket_peer", "socket_identity", "socket_write", "socket_close_write", "socket_read", "socket_bound", "socket_decode", "socket_canonical", "socket_schema", "socket_challenge", "socket_writer", "socket_echo", "socket_echo_challenge", "socket_echo_writer", "socket_response", "socket_close", "census_after", "journal_after", "census_after_validate", "census_changed", "journal_changed", "deadline", "observation_key", "time_order", "original_unknown"},
}

func GuestProbeDiagnostic(r GuestOriginalHTTPReturn) GuestProbeHTTPDiagnostic {
	d := GuestProbeHTTPDiagnostic{Schema: "guest_probe_http_diagnostic_v1", Status: r.Status, ReadReturnedAt: r.ReadReturnedAt, CloseReturnedAt: r.CloseReturnedAt, ContextFailed: r.OriginalContextFailed, PreflightFailed: r.PreflightFailed, DoFailed: r.DoFailed, ReadFailed: r.ReadFailed, CloseFailed: r.CloseFailed}
	// A complete bounded response remains diagnostic evidence if the child
	// context expires after the read. ContextFailed stays true; no success is inferred.
	if r.PreflightFailed || r.DoFailed || r.ReadFailed || r.CloseFailed || len(r.Body) > 2048 {
		return d
	}
	var body struct {
		Code     string                        `json:"code"`
		Status   int                           `json:"status"`
		Title    string                        `json:"title"`
		Detail   string                        `json:"detail"`
		Stage    string                        `json:"stage"`
		Temporal *GuestProbeTemporalDiagnostic `json:"temporal,omitempty"`
	}
	dec := json.NewDecoder(bytes.NewReader(r.Body))
	dec.DisallowUnknownFields()
	if dec.Decode(&body) != nil {
		return d
	}
	canonical, _ := json.Marshal(body)
	if !bytes.Equal(r.Body, append(canonical, '\n')) || body.Status != r.Status || body.Title != "Guest retirement held" || body.Detail != "The original Guest retirement requires its enrolled authority and complete original results." {
		return d
	}
	if body.Temporal != nil && (body.Stage != "challenge_deadline" || !body.Temporal.valid()) {
		return d
	}
	expected := 409
	if body.Code == "qualification_probe.closed_request_required" {
		expected = 400
	}
	if r.Status != expected {
		return d
	}
	for _, stage := range GuestProbeStages[body.Code] {
		if stage == body.Stage {
			d.Code = body.Code
			d.Stage = stage
			d.Temporal = body.Temporal
			break
		}
	}
	return d
}
