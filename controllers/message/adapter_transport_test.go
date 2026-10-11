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

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

type nativeCanaryRoundTrip func(*http.Request) (*http.Response, error)

func (f nativeCanaryRoundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type nativeCanaryBody struct {
	io.ReadCloser
	read  func([]byte) (int, error)
	close func() error
}

type guestNativePrivateCause string

func (e guestNativePrivateCause) Error() string { return string(e) }

// TLS and original Do/Read/Close are real; represented Guest records here are
// protocol fixtures and carry no enrollment or physical-capacity certificate.
func TestCapacityGuestNativeAdapterOriginalHTTP(t *testing.T) {
	token := strings.Repeat("g", 32)
	var requests, redirected atomic.Int32
	var wire atomic.Value
	result := model.CapacityGuestBootstrapResult{BindingName: "fixed", EnrollmentSourceClass: "native_qemu_qualification", Observation: model.CapacityGuestObservation{Journal: model.CapacityGuestJournal{ParentAncestry: []int{1}}}}
	body, err := json.Marshal(map[string]any{"operation": capacity.ObserveGuestBootstrap, "capability": capacity.ObserveGuestBootstrap, "status": "observed", "output": result, "metadata": map[string]any{}})
	if err != nil {
		t.Fatal(err)
	}
	wire.Store(string(body))
	var redirect atomic.Bool
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.URL.Path == "/foreign" {
			redirected.Add(1)
			w.WriteHeader(200)
			return
		}
		if r.Header.Get("Authorization") != "Bearer "+token || r.Header.Get("X-Capacity-Canary-Read-Key") != "" {
			t.Error("private header binding unavailable")
		}
		if redirect.Load() {
			w.Header().Set("Location", "/foreign")
			w.WriteHeader(308)
			return
		}
		if r.URL.Path == "/healthz" {
			_, _ = io.WriteString(w, "ok")
			return
		}
		request, e := io.ReadAll(io.LimitReader(r.Body, 4097))
		if e != nil || strings.Contains(string(request), token) {
			t.Error("bearer appeared in request body")
		}
		_, _ = io.WriteString(w, wire.Load().(string))
	}))
	t.Cleanup(server.Close)
	run := func(ctx, parent context.Context, client *http.Client, get bool) error {
		target := server.URL + "/rpc/execute"
		var response any = &model.AdapterExecuteIntegrationResponse{}
		if get {
			target, response = server.URL+"/healthz", nil
		}
		return (&adapterTransportClient{httpClient: client}).callNativeHTTPJSON(ctx, target, map[string]any{"input": map[string]any{"binding_name": "fixed"}}, response, adapterCallPolicy{detailFreeErrors: true, native: &nativeAdapterHTTPPolicy{limit: capacity.GuestBootstrapLimit, get: get, requireTLS: true, parent: parent, guest: &capacityGuestHTTPPolicy{baseURL: server.URL, bearer: token}}})
	}
	t.Run("fixed_bearer_original_typed_reply", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
		defer cancel()
		if err := run(ctx, ctx, server.Client(), false); err != nil {
			t.Fatal("original typed TLS reply unavailable", err)
		}
	})
	t.Run("connectivity_owns_read_and_close", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
		defer cancel()
		var reads, closes atomic.Int32
		client := *server.Client()
		native := client.Transport
		client.Transport = nativeCanaryRoundTrip(func(r *http.Request) (*http.Response, error) {
			response, e := native.RoundTrip(r)
			if response != nil && response.Body != nil {
				body := response.Body
				response.Body = &nativeCanaryBody{ReadCloser: body, read: func(p []byte) (int, error) { reads.Add(1); return body.Read(p) }, close: func() error { closes.Add(1); return body.Close() }}
			}
			return response, e
		})
		if err := run(ctx, ctx, &client, true); err != nil || reads.Load() == 0 || closes.Load() != 1 {
			t.Fatal("owning connectivity read/Close lost", err)
		}
	})
	t.Run("raw_alias_null_and_duplicate_refused", func(t *testing.T) {
		defer wire.Store(string(body))
		for _, bad := range []string{strings.Replace(string(body), `"original_context_failed":false`, `"original_context_failed":true,"Original_Context_Failed":false`, 1), strings.Replace(string(body), `"cloud_init_has_errors":false`, `"cloud_init_has_errors":null`, 1), strings.Replace(string(body), `"warm_resources_known":false`, `"warm_resources_known":true,"warm_resources_known":false`, 1)} {
			wire.Store(bad)
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			err := run(ctx, ctx, server.Client(), false)
			cancel()
			if err == nil {
				t.Fatal("original key ambiguity disappeared before typed decode")
			}
		}
	})
	t.Run("redirect_no_replay_and_getbody_nil", func(t *testing.T) {
		redirect.Store(true)
		defer redirect.Store(false)
		before := requests.Load()
		ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
		defer cancel()
		client := *server.Client()
		native := client.Transport
		client.Transport = nativeCanaryRoundTrip(func(r *http.Request) (*http.Response, error) {
			if r.GetBody != nil {
				t.Error("replay body retained")
			}
			return native.RoundTrip(r)
		})
		if err := run(ctx, ctx, &client, false); err == nil || requests.Load()-before != 1 || redirected.Load() != 0 {
			t.Fatal("native redirect/replay admitted")
		}
	})
	for _, phase := range []string{"do", "read", "close"} {
		t.Run("held_original_"+phase+"_private_cause", func(t *testing.T) {
			cause := guestNativePrivateCause("private-SSH-key-bearer-URL")
			parent, cancel := context.WithCancelCause(t.Context())
			defer cancel(nil)
			ctx, done := context.WithTimeout(parent, 5*time.Second)
			defer done()
			entered, release := make(chan struct{}), make(chan struct{})
			var releaseOnce, enterOnce sync.Once
			defer releaseOnce.Do(func() { close(release) })
			var calls, closes atomic.Int32
			client := *server.Client()
			native := client.Transport
			client.Transport = nativeCanaryRoundTrip(func(r *http.Request) (*http.Response, error) {
				calls.Add(1)
				response, e := native.RoundTrip(r)
				if response != nil && response.Body != nil {
					body := response.Body
					wrapped := &nativeCanaryBody{ReadCloser: body, close: func() error {
						closes.Add(1)
						if phase == "close" {
							enterOnce.Do(func() { close(entered) })
							<-release
						}
						return errors.Join(body.Close(), cause)
					}}
					if phase == "read" {
						wrapped.read = func(p []byte) (int, error) { enterOnce.Do(func() { close(entered); <-release }); return body.Read(p) }
					}
					response.Body = wrapped
				}
				if phase == "do" {
					enterOnce.Do(func() { close(entered) })
					<-release
				}
				return response, e
			})
			returned := make(chan error, 1)
			go func() { returned <- run(ctx, parent, &client, false) }()
			select {
			case <-entered:
			case <-time.After(3 * time.Second):
				t.Fatal("original stage did not enter")
			}
			cancel(cause)
			select {
			case <-returned:
				t.Fatal("cancel substituted for actual original return")
			default:
			}
			releaseOnce.Do(func() { close(release) })
			err := <-returned
			var original guestNativePrivateCause
			if err == nil || !errors.Is(err, cause) || !errors.As(err, &original) || original != cause || !errors.Is(err, context.Canceled) || calls.Load() != 1 || closes.Load() != 1 {
				t.Fatal("owning return/cause/no-replay fence lost")
			}
			for _, format := range []string{"%v", "%+v", "%#v", "%s", "%q"} {
				if strings.Contains(fmt.Sprintf(format, err), string(cause)) {
					t.Fatal("private original cause leaked")
				}
			}
			raw, _ := json.Marshal(err)
			if strings.Contains(string(raw), string(cause)) {
				t.Fatal("private JSON cause leaked")
			}
		})
	}
	t.Run("owning_deadline_before_live_parent", func(t *testing.T) {
		parent, done := context.WithTimeout(t.Context(), 5*time.Second)
		defer done()
		ctx, cancel := context.WithTimeout(parent, 30*time.Millisecond)
		defer cancel()
		client := *server.Client()
		native := client.Transport
		client.Transport = nativeCanaryRoundTrip(func(r *http.Request) (*http.Response, error) {
			response, e := native.RoundTrip(r)
			if response != nil && response.Body != nil {
				body := response.Body
				response.Body = &nativeCanaryBody{ReadCloser: body, close: func() error { <-ctx.Done(); return body.Close() }}
			}
			return response, e
		})
		if err := run(ctx, parent, &client, false); !errors.Is(err, context.DeadlineExceeded) || parent.Err() != nil {
			t.Fatal("original child deadline lost or parent invented")
		}
	})
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
