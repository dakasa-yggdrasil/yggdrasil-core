package capacity

import (
	"bytes"
	"encoding/json"
	"net/http"
)

// The closed problem codes the original Guest nonce handler answers, each
// with its only status (integration-guest-bootstrap notify_canary_nonce_linux).
var guestNotifyNonceProblems = map[string]int{
	"guest_notify.unavailable":               http.StatusForbidden,
	"guest_notify.original_busy":             http.StatusConflict,
	"guest_notify.closed_challenge_required": http.StatusBadRequest,
	"guest_notify.original_actor_held":       http.StatusConflict,
	"guest_notify.original_return_held":      http.StatusConflict,
	"guest_notify.original_nonce_held":       http.StatusConflict,
}

// GuestNotifyNonceDiagnostic is the secret-free projection of one original
// Guest nonce GET (ADR-0093). Status is the HTTP status actually received (0
// when no response was read). Code is set only when the body is exactly the
// Guest's canonical problem document, with a known code and its own status.
// Neither the body, the transport error nor any identity is retained.
type GuestNotifyNonceDiagnostic struct {
	Status int
	Code   string
}

func GuestNotifyNonceHTTPDiagnostic(r GuestOriginalHTTPReturn) GuestNotifyNonceDiagnostic {
	d := GuestNotifyNonceDiagnostic{}
	if r.PreflightFailed || r.DoFailed || r.Status < 100 || r.Status > 599 {
		return d
	}
	d.Status = r.Status
	if r.ReadFailed || r.CloseFailed || len(r.Body) > 2048 {
		return d
	}
	var body struct {
		Code   string `json:"code"`
		Status int    `json:"status"`
		Title  string `json:"title"`
		Detail string `json:"detail"`
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
	if status, ok := guestNotifyNonceProblems[body.Code]; ok && status == r.Status {
		d.Code = body.Code
	}
	return d
}
