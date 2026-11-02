package message

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestGuestNotifyClosedDiagnosticNeverExposesPrivateCause(t *testing.T) {
	private := "password=PRIVATE-DO-NOT-LOG x509: private raw endpoint"
	for _, stage := range []string{"issue_publication", "source_client", "stored_enrollment", "nonce_acquire", "nonce_finalize", "reserve_send", "original_HTTP_or_return", "issue_read"} {
		err := guestNotifyProbeHeld(stage, errors.New(private))
		if originalGuestNotifyProbeStage(err) != stage || strings.Contains(fmt.Sprintf("%v %+v %#v", err, err, err), "PRIVATE") || strings.Contains(err.Error(), "password") {
			t.Fatal("closed diagnostic leaked private cause or lost phase")
		}
	}
	if originalGuestNotifyProbeStage(guestNotifyProbeHeld(private, errors.New(private))) != "" {
		t.Fatal("unapproved phase escaped")
	}
}
