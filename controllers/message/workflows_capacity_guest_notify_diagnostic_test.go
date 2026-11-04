package message

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
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

// ADR-0093: only nonce_acquire carries the projected Guest status and closed
// problem code; the private cause and the response body never surface.
func TestGuestNotifyNonceHoldCarriesOnlyClosedDiagnostic(t *testing.T) {
	private := "password=PRIVATE-DO-NOT-LOG x509: private raw endpoint"
	body := []byte(`{"code":"guest_notify.closed_challenge_required","status":400,"title":"Guest retirement held","detail":"The original Guest retirement requires its enrolled authority and complete original results."}` + "\n")
	err := guestNotifyNonceHeld(capacity.GuestOriginalHTTPReturn{Status: 400, Body: body}, errors.New(private))
	d, ok := originalGuestNotifyNonceDiagnostic(err)
	if !ok || originalGuestNotifyProbeStage(err) != "nonce_acquire" || d.Status != 400 || d.Code != "guest_notify.closed_challenge_required" {
		t.Fatal("nonce hold lost its stage or closed diagnostic", d, ok)
	}
	if strings.Contains(fmt.Sprintf("%v %+v %#v", err, err, err), "PRIVATE") {
		t.Fatal("nonce hold leaked its private cause")
	}
	leaky := guestNotifyNonceHeld(capacity.GuestOriginalHTTPReturn{Status: 409, Body: []byte(private)}, errors.New(private))
	if d, ok = originalGuestNotifyNonceDiagnostic(leaky); !ok || d.Status != 409 || d.Code != "" {
		t.Fatal("unrecognized nonce body produced a problem code", d)
	}
	for _, stage := range []string{"issue_publication", "nonce_acquire", "reserve_send"} {
		if _, ok = originalGuestNotifyNonceDiagnostic(guestNotifyProbeHeld(stage, errors.New(private))); ok {
			t.Fatal("a hold without a nonce return claimed a nonce diagnostic")
		}
	}
	if _, ok = originalGuestNotifyNonceDiagnostic(errors.New(private)); ok {
		t.Fatal("an unrelated error claimed a nonce diagnostic")
	}
}
