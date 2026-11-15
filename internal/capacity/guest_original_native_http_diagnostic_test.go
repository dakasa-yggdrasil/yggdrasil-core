package capacity

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"
)

// Invoked by the existing TestGuestOriginalHTTPLateCloseCannotRenewBudget root.
// Pure formatting of already returned facts: no HTTP calls, SQL or new clock facts.
func guestOriginalNativeHTTPFailureDiagnosticContracts(t *testing.T) {
	t.Run("closed_return_projection_preserves_actual_facts", func(t *testing.T) {
		at := time.Date(2026, 11, 14, 0, 0, 0, 0, time.UTC)
		ctx, cancel := context.WithDeadline(context.Background(), at.Add(time.Minute))
		defer cancel()
		returned := GuestOriginalHTTPReturn{StartedAt: at, DoStartedAt: at.Add(time.Second), DoReturnedAt: at.Add(2 * time.Second), ReadReturnedAt: at.Add(3 * time.Second), CloseReturnedAt: at.Add(4 * time.Second), DriverReturnedAt: at.Add(5 * time.Second), Status: 503, Body: []byte("secret-body-never-export"), ReceivedBodyBytes: 25, ResponseSHA256: strings.Repeat("a", 64), ResponseBodyScope: GuestOriginalBodyCompleteRead, RetainedPrefixBytes: 25, RetainedPrefixSHA256: strings.Repeat("a", 64)}
		before := returned
		cancel() // Later context failure must not replace the stored original flag.
		for _, route := range []struct{ method, path, name string }{{http.MethodPost, "/v1/retirement", "retirement_post"}, {http.MethodGet, "/v1/qualification-serving-probe-nonce", "qualification_serving_probe_nonce"}} {
			d, ok := guestOriginalNativeHTTPFailureProjection(ctx, route.method, route.path, returned, errors.New("secret-transport-error"), 7)
			if !ok || d.Route != route.name || d.ErrorClass != "status" || d.OriginalContextFailed || !d.DeadlinePresent || !d.OriginalDeadline.Equal(at.Add(time.Minute)) || d.Ordinal != 7 {
				t.Fatal("actual facts replaced", d)
			}
			if d.StartedAt != returned.StartedAt || d.DoStartedAt != returned.DoStartedAt || d.DoReturnedAt != returned.DoReturnedAt || d.ReadReturnedAt != returned.ReadReturnedAt || d.CloseReturnedAt != returned.CloseReturnedAt || d.DriverReturnedAt != returned.DriverReturnedAt || d.ResponseSHA256 != returned.ResponseSHA256 || d.ReceivedBodyBytes != returned.ReceivedBodyBytes || d.ResponseBodyScope != returned.ResponseBodyScope || d.RetainedPrefixBytes != returned.RetainedPrefixBytes || d.RetainedPrefixSHA256 != returned.RetainedPrefixSHA256 {
				t.Fatal("original transport fact lost")
			}
			wire, err := json.Marshal(d)
			if err != nil {
				t.Fatal(err)
			}
			var fields map[string]json.RawMessage
			if json.Unmarshal(wire, &fields) != nil || len(fields) != 24 {
				t.Fatal("HTTP diagnostic ABI is not24 fields")
			}
			for _, key := range []string{"schema", "ordinal", "method", "route", "deadline_present", "error_class", "started_at", "do_started_at", "do_returned_at", "read_returned_at", "close_returned_at", "driver_returned_at", "original_deadline", "preflight_failed", "do_failed", "read_failed", "close_failed", "original_context_failed", "status", "received_body_bytes", "response_sha256", "response_body_scope", "retained_prefix_bytes", "retained_prefix_sha256"} {
				if _, ok := fields[key]; !ok {
					t.Fatal("missing closed field", key)
				}
			}
			if strings.Contains(string(wire), "secret-") || strings.Contains(string(wire), "Body") {
				t.Fatal("private data escaped")
			}
		}
		if !reflect.DeepEqual(before, returned) {
			t.Fatal("formatter mutated original return")
		}
		for _, bad := range []struct {
			method, path string
			err          error
		}{{http.MethodPost, "/v1/retirement", nil}, {http.MethodGet, "/v1/retirement", errors.New("x")}, {http.MethodPost, "/v1/retirement?secret", errors.New("x")}, {http.MethodGet, "https://private.invalid/v1/qualification-serving-probe-nonce", errors.New("x")}} {
			if _, ok := guestOriginalNativeHTTPFailureProjection(ctx, bad.method, bad.path, returned, bad.err, 1); ok {
				t.Fatal("success or nonclosed route accepted")
			}
		}
	})
	t.Run("closed_transport_error_classes", func(t *testing.T) {
		for _, test := range []struct {
			returned GuestOriginalHTTPReturn
			err      error
			class    string
		}{
			{GuestOriginalHTTPReturn{}, nil, "none"},
			{GuestOriginalHTTPReturn{PreflightFailed: true}, context.Canceled, "preflight"},
			{GuestOriginalHTTPReturn{}, context.Canceled, "cancelled"},
			{GuestOriginalHTTPReturn{}, context.DeadlineExceeded, "deadline"},
			{GuestOriginalHTTPReturn{DoFailed: true}, ErrGuestOriginalTransport, "do"},
			{GuestOriginalHTTPReturn{ReadFailed: true}, ErrGuestOriginalTransport, "read"},
			{GuestOriginalHTTPReturn{CloseFailed: true}, ErrGuestOriginalTransport, "close"},
			{GuestOriginalHTTPReturn{Status: 503}, ErrGuestOriginalTransport, "status"},
			{GuestOriginalHTTPReturn{Status: 200, OriginalContextFailed: true}, ErrGuestOriginalTransport, "other_transport"},
		} {
			if got := guestOriginalNativeHTTPFailureClass(test.returned, test.err); got != test.class {
				t.Fatal("transport class changed", got, test.class)
			}
		}
	})
}
