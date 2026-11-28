package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

func TestNativeWorkerNetworkMachineAuthenticationPrecedesOriginalBody(t *testing.T) {
	const token = "ci-private-network-writer"
	s := &Server{capacityMutationPrincipals: capacityMutationTestPrincipal(t, token, uuid.NewString())}
	h := s.requireAuthenticatedConsoleAPIs(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("network authority reached unrelated or human route")
	}))
	for _, credential := range []string{"", "human-cookie", "wrong-machine", token} {
		for _, source := range []string{"", "caller-selected-source", strings.Repeat("e", 40)} {
			r := httptest.NewRequest(http.MethodPost, "https://core.example"+nativeWorkerNetworkBasePath+"receive", nil)
			r.Body = nativePhaseUnreadableBody{t}
			r.AddCookie(&http.Cookie{Name: authSessionCookieName(), Value: "human-cookie"})
			if credential != "" {
				r.Header.Set("Authorization", "Bearer "+credential)
			}
			if source != "" {
				r.Header.Set(nativeWorkerAdapterSourceHeader, source)
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code >= 200 && w.Code < 300 || strings.Contains(w.Body.String(), token) || w.Header().Get("Cache-Control") != "no-store" {
				t.Fatal("unbound network caller reached private body", w.Code)
			}
			if credential == "" && w.Code != http.StatusUnauthorized {
				t.Fatal("anonymous network authority was not unauthorized", w.Code)
			}
		}
	}
	s.capacityMutationPrincipals[0].base.expiresAt = time.Now().Add(-time.Second)
	r := httptest.NewRequest(http.MethodPost, "https://core.example"+nativeWorkerNetworkBasePath+"receive", nil)
	r.Header.Set("Authorization", "Bearer "+token)
	r.Header.Set(nativeWorkerAdapterSourceHeader, strings.Repeat("e", 40))
	r.Body = nativePhaseUnreadableBody{t}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Fatal("expired network caller reached custody", w.Code)
	}
}

func TestNativeWorkerNetworkClosedSelectorsAndBoundedOriginalCustody(t *testing.T) {
	v := nativeWorkerNetworkRequest{BindingName: "floor-network-write", PermitID: uuid.New()}
	raw, _ := json.Marshal(v)
	if _, e := decodeNativeWorkerNetworkRequest(raw); e != nil {
		t.Fatal(e)
	}
	for _, bad := range [][]byte{append(append([]byte{}, raw...), []byte(` {}`)...), bytes.Replace(raw, []byte(`"permit_id":`), []byte(`"permit_id":"foreign","permit_id":`), 1), bytes.Replace(raw, []byte(`"binding_name":`), []byte(`"Binding_Name":`), 1), bytes.Replace(raw, []byte(`"permit_id":`), []byte(`"policy_id":`), 1), []byte(`{"binding_name":"floor-network-write","permit_id":null}`)} {
		if _, e := decodeNativeWorkerNetworkRequest(bad); e == nil {
			t.Fatal("caller selected or ambiguous network authority accepted")
		}
	}
	original := model.CapacityNativeWorkerNetworkOriginalReturn{Schema: "native_worker_network_receive_v1", PermitID: v.PermitID.String(), BindingName: v.BindingName, OriginalReturn: bytes.Repeat([]byte("x"), 1<<20), CaptureComplete: false, ErrorClass: "HOST_BATCH_UNCERTAIN"}
	raw, _ = json.Marshal(original)
	got, e := decodeNativeWorkerNetworkReceive(raw)
	if e != nil || !bytes.Equal(got.OriginalReturn, original.OriginalReturn) || got.CaptureComplete || len(raw) >= 2<<20 {
		t.Fatal("bounded private partial custody changed", e)
	}
	original.OriginalReturn = []byte("private batch return")
	original.ErrorClass = ""
	raw, _ = json.Marshal(original)
	if _, e = decodeNativeWorkerNetworkReceive(raw); e != nil {
		t.Fatal("producer optional empty error_class wire refused", e)
	}
	for _, bad := range [][]byte{append(append([]byte{}, raw...), []byte(` {}`)...), bytes.Replace(raw, []byte(`"capture_complete":false`), []byte(`"capture_complete":null`), 1), bytes.Replace(raw, []byte(`"original_return":`), []byte(`"Original_Return":`), 1), bytes.Replace(raw, []byte(`"capture_complete":false`), []byte(`"capture_complete":false,"capture_complete":true`), 1), bytes.Replace(raw, []byte(`"schema":`), []byte(`"original_caller_closed":true,"schema":`), 1)} {
		if _, e := decodeNativeWorkerNetworkReceive(bad); e == nil {
			t.Fatal("ambiguous custody or caller-selected process closure accepted")
		}
	}
	original.OriginalReturn = make([]byte, 1<<20+1)
	raw, _ = json.Marshal(original)
	if _, e = decodeNativeWorkerNetworkReceive(raw); e == nil {
		t.Fatal("oversized original network batch accepted")
	}
}

func TestNativeWorkerNetworkAuthorityRoutesAreNeverAPIWorkerRoutes(t *testing.T) {
	for _, method := range []string{http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodPost} {
		for _, action := range []string{"read", "redeem", "receive", "reconcile", "unknown"} {
			if (&Server{}).workerRouteAllowed(httptest.NewRequest(method, nativeWorkerNetworkBasePath+action, nil)) {
				t.Fatal("API worker acquired network mutation authority", method, action)
			}
		}
	}
	if (&Server{}).nativeWorkerNetworkRuntime != nil {
		t.Fatal("network runtime enabled by default")
	}
}

type nativeNetworkIncomingBody struct {
	io.Reader
	closed   int
	closeErr error
	cancel   context.CancelFunc
}

func (b *nativeNetworkIncomingBody) Close() error {
	b.closed++
	if b.cancel != nil {
		b.cancel()
	}
	return b.closeErr
}
func TestNativeWorkerNetworkOriginalBodyMustReadCloseAndKeepContext(t *testing.T) {
	for _, fault := range []string{"none", "close", "limit", "cancel"} {
		t.Run(fault, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			b := &nativeNetworkIncomingBody{Reader: strings.NewReader("original-body")}
			if fault == "close" {
				b.closeErr = errors.New("original close failure")
			}
			if fault == "cancel" {
				b.cancel = cancel
			}
			limit := int64(32)
			if fault == "limit" {
				limit = 2
			}
			raw, e := readNativeWorkerNetworkBody(ctx, http.MaxBytesReader(httptest.NewRecorder(), b, limit))
			if b.closed != 1 {
				t.Fatal("original body was not closed exactly once")
			}
			if fault == "none" {
				if e != nil || string(raw) != "original-body" {
					t.Fatal("complete original body refused", e)
				}
			} else if e == nil || raw != nil {
				t.Fatal("incomplete original body authorized a mutation")
			}
		})
	}
}
