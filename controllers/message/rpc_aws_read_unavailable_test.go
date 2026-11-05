package message

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

func TestOriginalAWSReadUnavailableClosedRPC(t *testing.T) {
	const exact = `{"ok":false,"error":{"code":"execute_failed","message":"original_ec2_readiness_native_read_failed"}}`
	cases := []struct {
		name, body string
		enabled    bool
		status     int
		truncated  bool
		outer      string
		want       bool
	}{
		{name: "original_observe_unavailable", body: exact, enabled: true, status: 200, want: true},
		{name: "SDK_known_metadata", body: exact, enabled: true, status: 200, want: true, outer: "metadata"},
		{name: "SDK_unknown_field", body: exact, enabled: true, status: 200, outer: "unknown"},
		{name: "SDK_duplicate_body", body: exact, enabled: true, status: 200, outer: "duplicate"},
		{name: "SDK_noncanonical_body", body: exact, enabled: true, status: 200, outer: "case"},
		{name: "SDK_wrong_content_type", body: exact, enabled: true, status: 200, outer: "content_type"},
		{name: "other_consumer", body: exact, status: 200},
		{name: "other_code", body: strings.Replace(exact, "execute_failed", "bad_request", 1), enabled: true, status: 200},
		{name: "physical_proof_failure", body: strings.Replace(exact, "original_ec2_readiness_native_read_failed", "original_ec2_full_physical_proof_failed", 1), enabled: true, status: 200},
		{name: "context_failure", body: strings.Replace(exact, "original_ec2_readiness_native_read_failed", "original_ec2_readiness_context_or_pause_stopped", 1), enabled: true, status: 200},
		{name: "malformed_JSON", body: exact[:len(exact)-1], enabled: true, status: 200},
		{name: "trailing_JSON", body: exact + `{}`, enabled: true, status: 200},
		{name: "unknown_envelope_field", body: strings.Replace(exact, `"ok":false`, `"extra":true,"ok":false`, 1), enabled: true, status: 200},
		{name: "unknown_error_field", body: strings.Replace(exact, `"code":`, `"extra":true,"code":`, 1), enabled: true, status: 200},
		{name: "duplicate_ok", body: strings.Replace(exact, `"ok":false`, `"ok":false,"ok":false`, 1), enabled: true, status: 200},
		{name: "duplicate_message", body: strings.Replace(exact, `"message":`, `"message":"original_ec2_readiness_native_read_failed","message":`, 1), enabled: true, status: 200},
		{name: "noncanonical_case", body: strings.Replace(exact, `"ok":`, `"OK":`, 1), enabled: true, status: 200},
		{name: "missing_ok", body: strings.Replace(exact, `"ok":false,`, ``, 1), enabled: true, status: 200},
		{name: "success_with_error", body: strings.Replace(exact, `"ok":false`, `"ok":true`, 1), enabled: true, status: 200},
		{name: "failure_with_data", body: strings.Replace(exact, `"ok":false`, `"data":null,"ok":false`, 1), enabled: true, status: 200},
		{name: "HTTP_failure", body: exact, enabled: true, status: 503},
		{name: "incomplete_HTTP_body", body: exact, enabled: true, status: 200, truncated: true},
		{name: "malformed_success_DTO", body: `{"ok":true,"data":{"operation":"observe_ec2_instance","unknown":true}}`, enabled: true, status: 200},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var calls atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				if r.Method != http.MethodPost || r.URL.Path != "/rpc/execute" {
					t.Error("unexpected original HTTP request")
				}
				// Use the actual SDK HTTP envelope around the original RPC body.
				payload, err := json.Marshal(struct {
					ContentType string `json:"content_type"`
					Body        []byte `json:"body"`
				}{"application/json", []byte(tc.body)})
				if err != nil {
					t.Error(err)
					return
				}
				switch tc.outer {
				case "metadata":
					payload = []byte(strings.Replace(string(payload), `"content_type":`, `"correlation_id":"synthetic-correlation","content_type":`, 1))
				case "unknown":
					payload = []byte(strings.Replace(string(payload), `"content_type":`, `"unknown":true,"content_type":`, 1))
				case "duplicate":
					payload = []byte(strings.Replace(string(payload), `"body":`, `"body":"e30=","body":`, 1))
				case "case":
					payload = []byte(strings.Replace(string(payload), `"body":`, `"BODY":`, 1))
				case "content_type":
					payload = []byte(strings.Replace(string(payload), `"application/json"`, `"text/plain"`, 1))
				}
				if tc.truncated {
					w.Header().Set("Content-Length", strconv.Itoa(len(payload)+1))
				}
				w.WriteHeader(tc.status)
				_, _ = w.Write(payload)
			}))
			defer server.Close()
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			policy := adapterCallPolicy{detailFreeErrors: true, native: &nativeAdapterHTTPPolicy{
				limit: 2 << 20, parent: ctx, originalAWSReadUnavailable: tc.enabled,
			}}
			var response model.AdapterExecuteIntegrationResponse
			err := newAdapterTransportClient(nil).callNativeHTTPJSON(ctx, server.URL+"/rpc/execute", map[string]any{"operation": "observe_ec2_instance"}, &response, policy)
			var unavailable *originalAWSReadUnavailableError
			if err == nil || errors.As(err, &unavailable) != tc.want || calls.Load() != 1 {
				t.Fatal("read failure classification or one-call custody drift", err, calls.Load())
			}
			if err.Error() != errAdapterCallFailed.Error() || fmt.Sprintf("%+v", err) != errAdapterCallFailed.Error() {
				t.Fatal("private adapter failure leaked into public diagnostics")
			}
		})
	}
}
