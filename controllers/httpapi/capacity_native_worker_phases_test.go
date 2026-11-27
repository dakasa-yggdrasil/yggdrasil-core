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

type nativePhaseUnreadableBody struct{ t *testing.T }

func (b nativePhaseUnreadableBody) Read([]byte) (int, error) {
	b.t.Fatal("unauthorized original-return body was read")
	return 0, nil
}
func (nativePhaseUnreadableBody) Close() error { return nil }

func TestNativeWorkerPhaseHTTPAuthenticateBeforeBody(t *testing.T) {
	token := "ci-private-native-writer-token"
	principals := capacityMutationTestPrincipal(t, token, uuid.NewString())
	s := &Server{capacityMutationPrincipals: principals}
	h := s.requireAuthenticatedConsoleAPIs(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Fatal("native callback reached another auth surface") }))
	for _, credential := range []string{"", "human-session", token} {
		r := httptest.NewRequest(http.MethodPost, "https://core.example"+nativeWorkerPhaseBasePath+"receive", nil)
		r.Body = nativePhaseUnreadableBody{t}
		if credential != "" {
			r.Header.Set("Authorization", "Bearer "+credential)
		}
		r.AddCookie(&http.Cookie{Name: authSessionCookieName(), Value: "human-cookie"})
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != http.StatusUnauthorized || strings.Contains(w.Body.String(), token) {
			t.Fatal("non-writer credential reached Native custody", w.Code)
		}
	}
	s.capacityMutationPrincipals[0].capabilities["ensure_native_worker_pool"] = true
	s.capacityMutationPrincipals[0].base.status = "revoked"
	r := httptest.NewRequest(http.MethodPost, "https://core.example"+nativeWorkerPhaseBasePath+"receive", nil)
	r.Body = nativePhaseUnreadableBody{t}
	r.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Fatal("revoked writer accepted", w.Code)
	}
}

func TestNativeWorkerPhaseOriginalReceiveClosedAndBounded(t *testing.T) {
	v := model.CapacityNativeWorkerPhaseReceive{PermitID: uuid.New(), BindingName: "ci-pool", SettlementToken: "ci-private-settlement", HTTPStatus: 200, TransportCompleted: true, OriginalReturn: bytes.Repeat([]byte("x"), 1700000), CompletedAt: time.Now().UTC()}
	raw, _ := json.Marshal(v)
	if len(raw) <= 2<<20 || len(raw) >= 4<<20 {
		t.Fatal("fixture does not exercise base64 body envelope")
	}
	got, err := decodeNativeWorkerPhaseReceive(raw)
	if err != nil || !bytes.Equal(got.OriginalReturn, v.OriginalReturn) {
		t.Fatal("complete original wire was changed or refused", err)
	}
	v.OriginalReturn = []byte("private-original")
	raw, _ = json.Marshal(v)
	for _, bad := range [][]byte{
		append(append([]byte{}, raw...), []byte(` {}`)...),
		bytes.Replace(raw, []byte(`"binding_name":`), []byte(`"binding_name":"other","binding_name":`), 1),
		bytes.Replace(raw, []byte(`"http_status":200`), []byte(`"http_status":null`), 1),
		bytes.Replace(raw, []byte(`"transport_completed":true`), []byte(`"transport_completed":"true"`), 1),
		bytes.Replace(raw, []byte(`"binding_name":`), []byte(`"Binding_Name":`), 1),
		bytes.Replace(raw, []byte(`"settlement_token":`), []byte(`"caller_proof":`), 1),
	} {
		if _, err := decodeNativeWorkerPhaseReceive(bad); err == nil {
			t.Fatal("ambiguous original-return envelope accepted")
		}
	}
	v.OriginalReturn = make([]byte, (2<<20)+1)
	raw, _ = json.Marshal(v)
	if _, err := decodeNativeWorkerPhaseReceive(raw); err == nil {
		t.Fatal("oversize original wire accepted")
	}
}

func TestNativeWorkerPhaseAdapterSourceIsCanonicalBeforeBody(t *testing.T) {
	principals := capacityMutationTestPrincipal(t, "ci-native-source-token", uuid.NewString())
	principals[0].capabilities["ensure_native_worker_pool"] = true
	s := &Server{capacityMutationPrincipals: principals}
	want := strings.Repeat("a", 40)
	for _, tc := range []struct {
		name   string
		values []string
	}{
		{"absent", nil},
		{"duplicate", []string{want, want}},
		{"comma", []string{want + "," + want}},
		{"uppercase", []string{strings.ToUpper(want)}},
		{"short", []string{want[:39]}},
		{"long", []string{want + "0"}},
		{"space", []string{" " + want}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPost, "https://core.example"+nativeWorkerPhaseBasePath+"receive", nil)
			r.Body = nativePhaseUnreadableBody{t}
			r.Header.Set("Authorization", "Bearer ci-native-source-token")
			for _, value := range tc.values {
				r.Header.Add(nativeWorkerPhaseAdapterSourceHeader, value)
			}
			w := httptest.NewRecorder()
			s.serveNativeWorkerPhaseRequest(w, r, &principals[0])
			if w.Code != http.StatusForbidden {
				t.Fatal("invalid compiled adapter Source reached body or authority", w.Code)
			}
		})
	}
	r := httptest.NewRequest(http.MethodGet, "https://core.example"+nativeWorkerPhaseBasePath+"read", nil)
	r.Header.Set(nativeWorkerPhaseAdapterSourceHeader, want)
	if got, ok := nativeWorkerPhaseAdapterSource(r); !ok || got != want {
		t.Fatal("single canonical compiled Source was not preserved exactly")
	}
}

func TestNativeWorkerPhaseRoutesRequireControlAuthority(t *testing.T) {
	for _, method := range []string{http.MethodGet, http.MethodPost, http.MethodHead} {
		for _, action := range []string{"read", "redeem", "receive", "unknown"} {
			r := httptest.NewRequest(method, nativeWorkerPhaseBasePath+action, nil)
			if (&Server{}).workerRouteAllowed(r) {
				t.Fatal("API worker allowed Native authority callback", method, action)
			}
		}
	}
}
