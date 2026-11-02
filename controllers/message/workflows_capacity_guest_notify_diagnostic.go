package message

import (
	"errors"
	"fmt"
	"io"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
)

// A closed phase survives the generic public workflow error. The underlying
// private transport/credential error remains in the in-process cause only.
type originalGuestNotifyProbeFailure struct {
	stage string
	cause error
	// Only for nonce_acquire: the secret-free Guest HTTP status and closed
	// problem code (ADR-0093). Never the body or the transport error.
	nonce *capacity.GuestNotifyNonceDiagnostic
}

func (e *originalGuestNotifyProbeFailure) Error() string    { return "original Guest Notify probe held" }
func (e *originalGuestNotifyProbeFailure) Unwrap() error    { return e.cause }
func (e *originalGuestNotifyProbeFailure) GoString() string { return e.Error() }
func (e *originalGuestNotifyProbeFailure) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, e.Error())
}
func guestNotifyProbeHeld(stage string, err error) error {
	return &originalGuestNotifyProbeFailure{stage: stage, cause: err}
}
func guestNotifyNonceHeld(returned capacity.GuestOriginalHTTPReturn, err error) error {
	d := capacity.GuestNotifyNonceHTTPDiagnostic(returned)
	return &originalGuestNotifyProbeFailure{stage: "nonce_acquire", cause: err, nonce: &d}
}

// The nonce_acquire diagnostic, when the failure carries one.
func originalGuestNotifyNonceDiagnostic(err error) (capacity.GuestNotifyNonceDiagnostic, bool) {
	var e *originalGuestNotifyProbeFailure
	if !errors.As(err, &e) || e.stage != "nonce_acquire" || e.nonce == nil {
		return capacity.GuestNotifyNonceDiagnostic{}, false
	}
	return *e.nonce, true
}
func originalGuestNotifyProbeStage(err error) string {
	var e *originalGuestNotifyProbeFailure
	if !errors.As(err, &e) {
		return ""
	}
	switch e.stage {
	case "issue_publication", "source_client", "stored_enrollment", "nonce_acquire", "nonce_finalize", "reserve_send", "original_HTTP_or_return", "issue_read":
		return e.stage
	}
	return ""
}
