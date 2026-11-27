package httpapi

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

func TestNativeWorkerAbortHTTPAuthenticatesBeforeOriginalBody(t *testing.T) {
	const token = "ci-private-native-recovery"
	s := &Server{capacityMutationPrincipals: capacityMutationTestPrincipal(t, token, uuid.NewString())}
	h := s.requireAuthenticatedConsoleAPIs(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Fatal("recovery entered an unrelated or human route") }))
	for _, credential := range []string{"", "human-cookie", "wrong-machine", token} {
		for _, source := range []string{"", "caller-invented-source", strings.Repeat("e", 40)} {
			r := httptest.NewRequest(http.MethodPost, "https://core.example"+nativeWorkerAbortBasePath+"receive", nil)
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
				t.Fatal("unbound recovery credential exposed private body or crossed authentication", w.Code)
			}
			if credential == "" && w.Code != http.StatusUnauthorized {
				t.Fatal("anonymous recovery was not rejected as unauthorized", w.Code)
			}
		}
	}
	s.capacityMutationPrincipals[0].base.expiresAt = time.Now().Add(-time.Second)
	r := httptest.NewRequest(http.MethodPost, "https://core.example"+nativeWorkerAbortBasePath+"receive", nil)
	r.Header.Set("Authorization", "Bearer "+token)
	r.Header.Set(nativeWorkerAdapterSourceHeader, strings.Repeat("e", 40))
	r.Body = nativePhaseUnreadableBody{t}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Fatal("expired machine reached a private original return", w.Code)
	}
}

func TestNativeWorkerAbortClosedRequestAndPrivateCustodyWire(t *testing.T) {
	request := nativeWorkerAbortRequest{BindingName: "ci-native-writer", PermitID: uuid.New()}
	raw, _ := json.Marshal(request)
	if _, err := decodeNativeWorkerAbortRequest(raw); err != nil {
		t.Fatal(err)
	}
	for _, bad := range [][]byte{append(append([]byte{}, raw...), []byte(` {}`)...), bytes.Replace(raw, []byte(`"permit_id":`), []byte(`"permit_id":"different","permit_id":`), 1), bytes.Replace(raw, []byte(`"binding_name":`), []byte(`"Binding_Name":`), 1), bytes.Replace(raw, []byte(`"permit_id":`), []byte(`"workflow_id":`), 1), []byte(`{"binding_name":"writer","permit_id":null}`)} {
		if _, err := decodeNativeWorkerAbortRequest(bad); err == nil {
			t.Fatal("caller-supplied or ambiguous recovery authority accepted")
		}
	}
	value := model.CapacityNativeWorkerAbortReceive{PermitID: request.PermitID, BindingName: request.BindingName, SettlementToken: strings.Repeat("x", 43), OriginalReturn: bytes.Repeat([]byte("x"), 1<<20), CaptureComplete: false, ErrorClass: "ORIGINAL_CAPTURE_BOUND_EXCEEDED"}
	raw, _ = json.Marshal(value)
	got, err := decodeNativeWorkerAbortReceive(raw)
	if err != nil || len(raw) >= 2<<20 || !bytes.Equal(got.OriginalReturn, value.OriginalReturn) || got.CaptureComplete {
		t.Fatal("bounded original incomplete custody changed", err)
	}
	value.OriginalReturn = []byte("private original delete response")
	raw, _ = json.Marshal(value)
	for _, bad := range [][]byte{append(append([]byte{}, raw...), []byte(` {}`)...), bytes.Replace(raw, []byte(`"capture_complete":false`), []byte(`"capture_complete":null`), 1), bytes.Replace(raw, []byte(`"settlement_token":`), []byte(`"Settlement_Token":`), 1), bytes.Replace(raw, []byte(`"error_class":`), []byte(`"absence_proven":`), 1), bytes.Replace(raw, []byte(`"capture_complete":false`), []byte(`"capture_complete":false,"capture_complete":true`), 1), bytes.Replace(raw, []byte(`"capture_complete":false`), []byte(`"capture_complete":true`), 1)} {
		if _, err := decodeNativeWorkerAbortReceive(bad); err == nil {
			t.Fatal("ambiguous private custody or invented successful completion accepted")
		}
	}
	value.OriginalReturn = make([]byte, 1<<20+1)
	raw, _ = json.Marshal(value)
	if _, err := decodeNativeWorkerAbortReceive(raw); err == nil {
		t.Fatal("oversized private original escaped the custody bound")
	}
}

func TestNativeWorkerAbortRoutesRequireControlAuthorityAndExplicitRuntime(t *testing.T) {
	for _, method := range []string{http.MethodGet, http.MethodPost, http.MethodHead, http.MethodOptions} {
		for _, action := range []string{"read", "redeem", "receive", "reconcile", "unknown"} {
			if (&Server{}).workerRouteAllowed(httptest.NewRequest(method, nativeWorkerAbortBasePath+action, nil)) {
				t.Fatal("API worker acquired destructive recovery authority", method, action)
			}
		}
	}
	if (&Server{}).nativeWorkerAbortRuntime != nil {
		t.Fatal("a recovery runtime was activated by default")
	}
}
