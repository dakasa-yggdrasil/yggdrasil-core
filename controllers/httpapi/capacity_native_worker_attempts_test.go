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

func TestNativeWorkerAttemptHTTPAuthenticateBeforeBody(t *testing.T) {
	token := "ci-private-native-creator"
	s := &Server{capacityMutationPrincipals: capacityMutationTestPrincipal(t, token, uuid.NewString())}
	h := s.requireAuthenticatedConsoleAPIs(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Fatal("Native attempt entered a human or unrelated route") }))
	for _, tc := range []struct {
		name, credential, source string
		duplicate                bool
	}{{"anonymous", "", "", false}, {"human-cookie", "human-session", "", false}, {"missing-sdk-source", token, "", false}, {"bad-sdk-source", token, "environment-override", false}, {"multiple-sdk-sources", token, strings.Repeat("e", 40), true}, {"generic-writer-no-native-context", token, strings.Repeat("e", 40), false}} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPost, "https://core.example"+nativeWorkerAttemptBasePath+"receive", nil)
			r.Body = nativePhaseUnreadableBody{t}
			r.AddCookie(&http.Cookie{Name: authSessionCookieName(), Value: "human-cookie"})
			if tc.credential != "" {
				r.Header.Set("Authorization", "Bearer "+tc.credential)
			}
			if tc.source != "" {
				r.Header.Set(nativeWorkerAdapterSourceHeader, tc.source)
			}
			if tc.duplicate {
				r.Header.Add(nativeWorkerAdapterSourceHeader, tc.source)
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code >= 200 && w.Code < 300 || strings.Contains(w.Body.String(), token) {
				t.Fatal("unauthorized context/body accepted or credential leaked", w.Code)
			}
		})
	}
	s.capacityMutationPrincipals[0].base.expiresAt = time.Now().Add(-time.Second)
	r := httptest.NewRequest(http.MethodPost, "https://core.example"+nativeWorkerAttemptBasePath+"receive", nil)
	r.Header.Set("Authorization", "Bearer "+token)
	r.Header.Set(nativeWorkerAdapterSourceHeader, strings.Repeat("e", 40))
	r.Body = nativePhaseUnreadableBody{t}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Fatal("expired credential reached original body", w.Code)
	}
}

func TestNativeWorkerAttemptCommandClosedWire(t *testing.T) {
	request := nativeWorkerAttemptRequest{BindingName: "ci-writer", AttemptID: uuid.New()}
	raw, _ := json.Marshal(request)
	if _, err := decodeNativeWorkerAttemptRequest(raw); err != nil {
		t.Fatal(err)
	}
	long := request
	long.BindingName = strings.Repeat("b", 256)
	longWire, _ := json.Marshal(long)
	if _, err := decodeNativeWorkerAttemptRequest(longWire); err != nil {
		t.Fatal("valid Source binding length was narrowed by the callback", err)
	}
	long.BindingName += "b"
	longWire, _ = json.Marshal(long)
	if _, err := decodeNativeWorkerAttemptRequest(longWire); err == nil {
		t.Fatal("binding beyond Source contract bound accepted")
	}
	for _, bad := range [][]byte{append(append([]byte{}, raw...), []byte(` {}`)...), bytes.Replace(raw, []byte(`"binding_name":`), []byte(`"binding_name":"other","binding_name":`), 1), bytes.Replace(raw, []byte(`"binding_name":`), []byte(`"Binding_Name":`), 1), bytes.Replace(raw, []byte(`"binding_name":`), []byte(`"workflow_id":`), 1), []byte(`{"binding_name":"ci-writer","attempt_id":null}`)} {
		if _, err := decodeNativeWorkerAttemptRequest(bad); err == nil {
			t.Fatal("ambiguous/extra command authority accepted")
		}
	}
	received := model.CapacityNativeWorkerCommandReceive{BindingName: request.BindingName, AttemptID: request.AttemptID, OriginalReturn: bytes.Repeat([]byte("x"), 1<<20), CaptureComplete: false, ErrorClass: "ORIGINAL_CAPTURE_BOUND_EXCEEDED"}
	raw, _ = json.Marshal(received)
	if len(raw) <= 1<<20 || len(raw) >= 2<<20 {
		t.Fatal("fixture does not exercise base64 envelope")
	}
	got, err := decodeNativeWorkerAttemptReceive(raw)
	if err != nil || !bytes.Equal(got.OriginalReturn, received.OriginalReturn) || got.CaptureComplete {
		t.Fatal("bounded incomplete prefix lost", err)
	}
	received.OriginalReturn = []byte("original-private")
	raw, _ = json.Marshal(received)
	for _, bad := range [][]byte{append(append([]byte{}, raw...), []byte(` {}`)...), bytes.Replace(raw, []byte(`"capture_complete":false`), []byte(`"capture_complete":null`), 1), bytes.Replace(raw, []byte(`"original_return":`), []byte(`"Original_Return":`), 1), bytes.Replace(raw, []byte(`"error_class":`), []byte(`"admitted":`), 1), bytes.Replace(raw, []byte(`"capture_complete":false`), []byte(`"capture_complete":false,"capture_complete":true`), 1)} {
		if _, err := decodeNativeWorkerAttemptReceive(bad); err == nil {
			t.Fatal("ambiguous original or caller lifecycle proof accepted")
		}
	}
	received.OriginalReturn = make([]byte, (1<<20)+1)
	raw, _ = json.Marshal(received)
	if _, err := decodeNativeWorkerAttemptReceive(raw); err == nil {
		t.Fatal("oversized original bypassed Core custody limit")
	}
}

func TestNativeWorkerAttemptRoutesRequireControlAuthority(t *testing.T) {
	for _, method := range []string{http.MethodGet, http.MethodPost, http.MethodHead} {
		for _, action := range []string{"read", "redeem", "receive", "unknown"} {
			if (&Server{}).workerRouteAllowed(httptest.NewRequest(method, nativeWorkerAttemptBasePath+action, nil)) {
				t.Fatal("API worker accepted Native creator callback", method, action)
			}
		}
	}
}
