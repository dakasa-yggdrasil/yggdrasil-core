package message

import (
	"errors"
	"fmt"
	"io"
)

// A closed phase survives the generic public workflow error. The underlying
// private transport/credential error remains in the in-process cause only.
type originalGuestNotifyProbeFailure struct {
	stage string
	cause error
}

func (e *originalGuestNotifyProbeFailure) Error() string    { return "original Guest Notify probe held" }
func (e *originalGuestNotifyProbeFailure) Unwrap() error    { return e.cause }
func (e *originalGuestNotifyProbeFailure) GoString() string { return e.Error() }
func (e *originalGuestNotifyProbeFailure) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, e.Error())
}
func guestNotifyProbeHeld(stage string, err error) error {
	return &originalGuestNotifyProbeFailure{stage, err}
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
