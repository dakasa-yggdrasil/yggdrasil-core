package message

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

type nativeCanaryRoundTrip func(*http.Request) (*http.Response, error)

func (f nativeCanaryRoundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type nativeCanaryBody struct {
	io.ReadCloser
	read  func([]byte) (int, error)
	close func() error
}

func (b *nativeCanaryBody) Read(p []byte) (int, error) {
	if b.read != nil {
		return b.read(p)
	}
	return b.ReadCloser.Read(p)
}
func (b *nativeCanaryBody) Close() error {
	if b.close != nil {
		return b.close()
	}
	return b.ReadCloser.Close()
}

func TestCapacityNativeAdapterOriginalHTTP(t *testing.T) {
	token := strings.Repeat("n", 32)
	var wire atomic.Value
	wire.Store(`{"value":"original"}`)
	var status atomic.Int32
	status.Store(200)
	var requests atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.Method != http.MethodGet || r.Header.Get("X-Capacity-Canary-Read-Key") != token {
			t.Error("fixed native GET credential absent")
		}
		w.WriteHeader(int(status.Load()))
		_, _ = io.WriteString(w, wire.Load().(string))
	}))
	t.Cleanup(server.Close)
	run := func(ctx context.Context, client *http.Client, limit int64) (string, error) {
		var out struct {
			Value string `json:"value"`
		}
		c := &adapterTransportClient{httpClient: client}
		err := c.callNativeHTTPJSON(ctx, server.URL, nil, &out, adapterCallPolicy{detailFreeErrors: true, native: &nativeAdapterHTTPPolicy{limit: limit, get: true, requireTLS: true, exactURL: server.URL, readToken: token, parent: ctx}})
		return out.Value, err
	}
	owner := func() (context.Context, context.CancelFunc) { return context.WithTimeout(t.Context(), 5*time.Second) }
	t.Run("verified_tls_fixed_original_origin", func(t *testing.T) {
		ctx, done := owner()
		defer done()
		v, err := run(ctx, server.Client(), 1024)
		if err != nil || v != "original" {
			t.Fatal("actual verified TLS source unavailable", err)
		}
	})
	t.Run("closed_duplicate_casefold_and_byte_cap", func(t *testing.T) {
		defer wire.Store(`{"value":"original"}`)
		for _, body := range []string{`{"value":"a","value":"b"}`, `{"Value":"a"}`, `{"value":null}`, `{"value":"a","unknown":true}`, `{"value":"a"} {"value":"b"}`, `{"value":"` + strings.Repeat("a", 1024) + `"}`} {
			wire.Store(body)
			ctx, done := owner()
			_, err := run(ctx, server.Client(), 1024)
			done()
			if err == nil {
				t.Fatal("closed/capped source accepted")
			}
		}
	})
	t.Run("unauthorized_does_not_read_body", func(t *testing.T) {
		status.Store(401)
		defer status.Store(200)
		var reads, closes atomic.Int32
		client := *server.Client()
		native := client.Transport
		client.Transport = nativeCanaryRoundTrip(func(r *http.Request) (*http.Response, error) {
			reply, err := native.RoundTrip(r)
			if reply != nil && reply.Body != nil {
				body := reply.Body
				reply.Body = &nativeCanaryBody{ReadCloser: body, read: func(p []byte) (int, error) { reads.Add(1); return body.Read(p) }, close: func() error { closes.Add(1); return body.Close() }}
			}
			return reply, err
		})
		ctx, done := owner()
		defer done()
		_, err := run(ctx, &client, 1024)
		if err == nil || reads.Load() != 0 || closes.Load() != 1 {
			t.Fatal("private unauthorized body read or original Close lost")
		}
	})
	for _, phase := range []string{"read", "close"} {
		t.Run("held_original_"+phase+"_retains_cause", func(t *testing.T) {
			ctx, cancel := context.WithCancelCause(t.Context())
			defer cancel(nil)
			bounded, done := context.WithTimeout(ctx, 5*time.Second)
			defer done()
			entered, release := make(chan struct{}), make(chan struct{})
			var once sync.Once
			defer once.Do(func() { close(release) })
			private := errors.New("private-token-URL-body")
			client := *server.Client()
			native := client.Transport
			var closes atomic.Int32
			client.Transport = nativeCanaryRoundTrip(func(r *http.Request) (*http.Response, error) {
				reply, err := native.RoundTrip(r)
				if reply != nil && reply.Body != nil {
					body := reply.Body
					wrapped := &nativeCanaryBody{ReadCloser: body, close: func() error {
						closes.Add(1)
						if phase == "close" {
							close(entered)
							<-release
						}
						return errors.Join(body.Close(), private)
					}}
					if phase == "read" {
						var first sync.Once
						wrapped.read = func(p []byte) (int, error) { first.Do(func() { close(entered); <-release }); return body.Read(p) }
					}
					reply.Body = wrapped
				}
				return reply, err
			})
			returned := make(chan error, 1)
			go func() { _, err := run(bounded, &client, 1024); returned <- err }()
			select {
			case <-entered:
			case <-time.After(3 * time.Second):
				t.Fatal("original body did not enter")
			}
			cancel(private)
			select {
			case <-returned:
				t.Fatal("cancel substituted for actual body return")
			default:
			}
			once.Do(func() { close(release) })
			err := <-returned
			if err == nil || !errors.Is(err, private) || !errors.Is(err, context.Canceled) || closes.Load() != 1 {
				t.Fatal("original body/cause not retained")
			}
			for _, v := range []string{fmt.Sprint(err), fmt.Sprintf("%+v", err), fmt.Sprintf("%#v", err)} {
				if strings.Contains(v, "private-token") {
					t.Fatal("private error exposed")
				}
			}
			raw, _ := json.Marshal(err)
			if strings.Contains(string(raw), "private-token") {
				t.Fatal("JSON exposed private cause")
			}
		})
	}
	t.Run("foreign_response_origin_refused_before_read", func(t *testing.T) {
		client := *server.Client()
		native := client.Transport
		var reads, closes atomic.Int32
		client.Transport = nativeCanaryRoundTrip(func(r *http.Request) (*http.Response, error) {
			reply, err := native.RoundTrip(r)
			body := reply.Body
			copy := r.Clone(r.Context())
			copy.URL = copy.URL.JoinPath("foreign")
			reply.Request = copy
			reply.Body = &nativeCanaryBody{ReadCloser: body, read: func(p []byte) (int, error) { reads.Add(1); return body.Read(p) }, close: func() error { closes.Add(1); return body.Close() }}
			return reply, err
		})
		ctx, done := owner()
		defer done()
		_, err := run(ctx, &client, 1024)
		if err == nil || reads.Load() != 0 || closes.Load() != 1 {
			t.Fatal("foreign original response accepted/read")
		}
	})
	t.Run("expired_entry_has_zero_original_calls", func(t *testing.T) {
		ctx, done := context.WithDeadline(t.Context(), time.Now().Add(-time.Second))
		defer done()
		before := requests.Load()
		_, err := run(ctx, server.Client(), 1024)
		if !errors.Is(err, context.DeadlineExceeded) || requests.Load() != before {
			t.Fatal("expired owner reached source")
		}
	})
	t.Run("original_parent_deadline_without_err_is_retained", func(t *testing.T) {
		parent := &capacityVMNodeAbsoluteContext{Context: t.Context(), deadline: time.Now().Add(5 * time.Second)}
		owner, done := context.WithTimeout(parent, 5*time.Second)
		defer done()
		client := *server.Client()
		native := client.Transport
		client.Transport = nativeCanaryRoundTrip(func(r *http.Request) (*http.Response, error) {
			reply, err := native.RoundTrip(r)
			body := reply.Body
			reply.Body = &nativeCanaryBody{ReadCloser: body, close: func() error { err := body.Close(); parent.expire(); return err }}
			return reply, err
		})
		var out struct {
			Value string `json:"value"`
		}
		c := &adapterTransportClient{httpClient: &client}
		err := c.callNativeHTTPJSON(owner, server.URL, nil, &out, adapterCallPolicy{detailFreeErrors: true, native: &nativeAdapterHTTPPolicy{limit: 1024, get: true, requireTLS: true, exactURL: server.URL, readToken: token, parent: parent}})
		if !errors.Is(err, context.DeadlineExceeded) || parent.Err() != nil {
			t.Fatal("late original parent accepted or cancellation fabricated")
		}
	})
}

func TestCapacityNativeAdapterLegacyHTTPPreserved(t *testing.T) {
	var headers http.Header
	requestDone := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		headers = r.Header.Clone()
		_, _ = io.WriteString(w, `{"value":"legacy"}`)
		close(requestDone)
	}))
	defer server.Close()
	client := newAdapterTransportClient(nil)
	var reply struct {
		Value string `json:"value"`
	}
	err := client.callHTTPJSONWithPolicy(t.Context(), "/execute", model.IntegrationInstanceManifestSpec{Config: map[string]any{"base_url": server.URL}}, map[string]any{}, &reply, adapterCallPolicy{})
	select {
	case <-requestDone:
	case <-time.After(5 * time.Second):
		t.Fatal("ordinary transport handler did not return")
	}
	if err != nil || reply.Value != "legacy" || headers.Get("X-Capacity-Canary-Read-Key") != "" {
		t.Fatal("ordinary transport changed", err)
	}
}
