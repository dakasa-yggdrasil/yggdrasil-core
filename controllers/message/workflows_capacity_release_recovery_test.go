package message

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// These real TLS streams qualify ORIGINAL caller ownership, not a native API
// result or PostgreSQL acknowledgement. The joint KinD gate joins all three.
func TestCapacityReleaseOriginalCaller(t *testing.T) {
	for _, name := range []string{"original_complete_return", "held_original_close", "original_close_failure", "response_and_error_original_close", "non200_no_ack"} {
		t.Run(name, func(t *testing.T) {
			var receiving, closes, ack atomic.Int32
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				receiving.Add(1)
				if name == "non200_no_ack" {
					w.WriteHeader(409)
				}
				_, _ = io.WriteString(w, `{"ok":true,"data":{"status":"blocked"}}`)
			}))
			defer server.Close()
			parent, cancelParent := context.WithTimeout(t.Context(), 3*time.Second)
			defer cancelParent()
			cause := guestNativePrivateCause("private-original-caller-close")
			ctx, cancel := context.WithTimeoutCause(parent, 500*time.Millisecond, cause)
			defer cancel()
			entered, release := make(chan struct{}), make(chan struct{})
			var stopOnce sync.Once
			stop := func() { stopOnce.Do(func() { close(release) }) }
			defer stop()
			client := *server.Client()
			base := client.Transport
			client.Transport = nativeCanaryRoundTrip(func(r *http.Request) (*http.Response, error) {
				if r.GetBody != nil {
					t.Error("original release caller became replayable")
				}
				resp, err := base.RoundTrip(r)
				if resp != nil && resp.Body != nil {
					body := resp.Body
					resp.Body = nativeCanaryBody{ReadCloser: body, close: func() error {
						if name == "held_original_close" {
							close(entered)
							<-release
						}
						closes.Add(1)
						e := body.Close()
						if name == "original_close_failure" || name == "response_and_error_original_close" {
							return errors.Join(e, cause)
						}
						return e
					}}
				}
				if name == "response_and_error_original_close" {
					err = cause
				}
				return resp, err
			})
			policy := adapterCallPolicy{detailFreeErrors: true, native: &nativeAdapterHTTPPolicy{limit: 8192, parent: parent, ownerDeadline: ctxDeadline(ctx), parentDeadline: ctxDeadline(parent), originalReturn: func(joined bool) {
				if joined {
					ack.Add(1)
				}
			}}}
			transport := &adapterTransportClient{httpClient: &client}
			returned := make(chan error, 1)
			go func() {
				var out map[string]any
				returned <- transport.callNativeHTTPJSON(ctx, server.URL, map[string]any{"operation": "destroy_capacity_pod_drain_protection"}, &out, policy)
			}()
			joined := false
			defer func() {
				stop()
				if !joined {
					<-returned
				}
			}()
			if name == "held_original_close" {
				select {
				case <-entered:
				case <-parent.Done():
					t.Fatal("original caller Close not entered")
				}
				<-ctx.Done()
				if ack.Load() != 0 {
					t.Fatal("row/status visibility became an early ACK")
				}
				select {
				case <-returned:
					joined = true
					t.Fatal("original held Close returned early")
				default:
				}
				stop()
			}
			err := <-returned
			joined = true
			if receiving.Load() != 1 || closes.Load() != 1 {
				t.Fatal("original caller Do/Close not joined once")
			}
			if name == "original_complete_return" {
				if err != nil || ack.Load() != 1 {
					t.Fatal("original caller return refused")
				}
				return
			}
			if err == nil || ack.Load() != 0 {
				t.Fatal("unknown/late original caller result became an ACK")
			}
			if name == "held_original_close" && (!errors.Is(err, cause) || !errors.Is(err, context.DeadlineExceeded) || parent.Err() != nil) {
				t.Fatal("original child/parent cause lost")
			}
			if name == "original_close_failure" || name == "response_and_error_original_close" {
				if !errors.Is(err, cause) {
					t.Fatal("original Close cause lost")
				}
			}
		})
	}
}

func ctxDeadline(ctx context.Context) time.Time { d, _ := ctx.Deadline(); return d }
