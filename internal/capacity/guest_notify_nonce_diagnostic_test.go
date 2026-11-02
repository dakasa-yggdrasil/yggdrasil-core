package capacity

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func guestNotifyProblemBody(t *testing.T, code string, status int) []byte {
	t.Helper()
	raw, err := json.Marshal(struct {
		Code   string `json:"code"`
		Status int    `json:"status"`
		Title  string `json:"title"`
		Detail string `json:"detail"`
	}{code, status, "Guest retirement held", "The original Guest retirement requires its enrolled authority and complete original results."})
	if err != nil {
		t.Fatal(err)
	}
	return append(raw, '\n')
}

// ADR-0093: the nonce_acquire hold keeps only the HTTP status and a closed,
// status-consistent Guest problem code; never the body or any other text.
func TestGuestNotifyNonceDiagnosticKeepsOnlyClosedStatusAndCode(t *testing.T) {
	for _, test := range []struct {
		name   string
		r      GuestOriginalHTTPReturn
		status int
		code   string
	}{
		{"closed_challenge_required", GuestOriginalHTTPReturn{Status: 400, Body: guestNotifyProblemBody(t, "guest_notify.closed_challenge_required", 400)}, 400, "guest_notify.closed_challenge_required"},
		{"actor_held", GuestOriginalHTTPReturn{Status: 409, Body: guestNotifyProblemBody(t, "guest_notify.original_actor_held", 409)}, 409, "guest_notify.original_actor_held"},
		{"unavailable", GuestOriginalHTTPReturn{Status: 403, Body: guestNotifyProblemBody(t, "guest_notify.unavailable", 403)}, 403, "guest_notify.unavailable"},
		{"code_with_foreign_status", GuestOriginalHTTPReturn{Status: 409, Body: guestNotifyProblemBody(t, "guest_notify.closed_challenge_required", 409)}, 409, ""},
		{"body_status_differs", GuestOriginalHTTPReturn{Status: 400, Body: guestNotifyProblemBody(t, "guest_notify.closed_challenge_required", 409)}, 400, ""},
		{"unknown_code", GuestOriginalHTTPReturn{Status: 409, Body: guestNotifyProblemBody(t, "password=PRIVATE", 409)}, 409, ""},
		{"extra_member", GuestOriginalHTTPReturn{Status: 400, Body: []byte(strings.TrimSuffix(string(guestNotifyProblemBody(t, "guest_notify.closed_challenge_required", 400)), "}\n") + `,"secret":"PRIVATE"}` + "\n")}, 400, ""},
		{"no_newline", GuestOriginalHTTPReturn{Status: 400, Body: []byte(strings.TrimSuffix(string(guestNotifyProblemBody(t, "guest_notify.closed_challenge_required", 400)), "\n"))}, 400, ""},
		{"read_failed", GuestOriginalHTTPReturn{Status: 400, ReadFailed: true, Body: guestNotifyProblemBody(t, "guest_notify.closed_challenge_required", 400)}, 400, ""},
		{"ok_nonce_refused_by_core", GuestOriginalHTTPReturn{Status: http.StatusOK, Body: []byte(`{"schema":"PRIVATE"}`)}, 200, ""},
		{"transport_failed", GuestOriginalHTTPReturn{Status: 0, DoFailed: true}, 0, ""},
		{"preflight_failed", GuestOriginalHTTPReturn{Status: 400, PreflightFailed: true}, 0, ""},
		{"no_return", GuestOriginalHTTPReturn{}, 0, ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			d := GuestNotifyNonceHTTPDiagnostic(test.r)
			if d.Status != test.status || d.Code != test.code {
				t.Fatalf("diagnostic %+v, want status %d code %q", d, test.status, test.code)
			}
			if strings.Contains(d.Code, "PRIVATE") {
				t.Fatal("diagnostic copied response text")
			}
		})
	}
}
