package capacity

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

type guestOriginalTestTransport func(*http.Request) (*http.Response, error)

func (f guestOriginalTestTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type guestOriginalLateErrContext struct{ context.Context }

func (guestOriginalLateErrContext) Err() error { return nil }

type guestOriginalDeadlineBody struct {
	io.Reader
	deadline time.Time
}

func (b guestOriginalDeadlineBody) Close() error {
	timer := time.NewTimer(time.Until(b.deadline) + time.Millisecond)
	defer timer.Stop()
	<-timer.C
	return nil
}

func TestGuestOriginalHTTPLateCloseCannotRenewBudget(t *testing.T) {
	base, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	deadline, _ := base.Deadline()
	ctx := guestOriginalLateErrContext{base}
	calls := 0
	client := &GuestOriginalHTTPClient{origin: "https://unit.invalid", client: &http.Client{Transport: guestOriginalTestTransport(func(*http.Request) (*http.Response, error) {
		calls++
		return &http.Response{StatusCode: 200, Body: guestOriginalDeadlineBody{strings.NewReader(`{"ok":true}`), deadline}}, nil
	})}}
	returned, err := client.Original(ctx, http.MethodGet, GuestNotifyCanaryPath, []byte(`{}`))
	if calls != 1 || err == nil || !returned.OriginalContextFailed || returned.CloseReturnedAt.Before(deadline) || returned.ResponseBodyScope != GuestOriginalBodyCompleteRead {
		t.Fatal("late original Close accepted or native bounded read facts lost", err, returned)
	}
	var decoded struct {
		OK bool `json:"ok"`
	}
	if GuestOriginalHTTPDecode(returned, &decoded) == nil {
		t.Fatal("late original admitted")
	}
}

func TestGuestOriginalHTTPOnlyClosedCanaryRoutes(t *testing.T) {
	for _, test := range []struct {
		method, path string
		allowed      bool
	}{{http.MethodGet, GuestNotifyCanaryNoncePath, true}, {http.MethodGet, GuestNotifyCanaryPath, true}, {http.MethodPost, GuestNotifyCanaryPublicationPath, true}, {http.MethodPost, GuestNotifyCanaryPath, false}, {http.MethodGet, GuestNotifyCanaryPublicationPath, false}, {http.MethodPost, GuestNotifyCanaryNoncePath, false}, {http.MethodGet, GuestNotifyCanaryPath + "?caller=1", false}} {
		t.Run(test.method+test.path, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			calls := 0
			client := &GuestOriginalHTTPClient{origin: "https://unit.invalid", client: &http.Client{Transport: guestOriginalTestTransport(func(*http.Request) (*http.Response, error) {
				calls++
				return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{}`))}, nil
			})}}
			_, err := client.Original(ctx, test.method, test.path, []byte(`{}`))
			if (err == nil) != test.allowed || calls != map[bool]int{true: 1, false: 0}[test.allowed] {
				t.Fatalf("closed route escaped: %v calls%d", err, calls)
			}
		})
	}
}
