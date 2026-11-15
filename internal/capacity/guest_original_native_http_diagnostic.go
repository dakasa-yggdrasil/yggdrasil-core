package capacity

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"sync/atomic"
	"time"
)

const guestOriginalNativeHTTPFailureSchema = "original_guest_native_http_return_diagnostic_v1"

var guestOriginalNativeHTTPFailureOrdinal atomic.Uint64

// This projection observes only the already returned transport. Its fixed
// routes contain no host, identifiers, request bytes, response body or error.
type guestOriginalNativeHTTPFailureDiagnostic struct {
	Schema                string    `json:"schema"`
	Ordinal               uint64    `json:"ordinal"`
	Method                string    `json:"method"`
	Route                 string    `json:"route"`
	DeadlinePresent       bool      `json:"deadline_present"`
	ErrorClass            string    `json:"error_class"`
	StartedAt             time.Time `json:"started_at"`
	DoStartedAt           time.Time `json:"do_started_at"`
	DoReturnedAt          time.Time `json:"do_returned_at"`
	ReadReturnedAt        time.Time `json:"read_returned_at"`
	CloseReturnedAt       time.Time `json:"close_returned_at"`
	DriverReturnedAt      time.Time `json:"driver_returned_at"`
	OriginalDeadline      time.Time `json:"original_deadline"`
	PreflightFailed       bool      `json:"preflight_failed"`
	DoFailed              bool      `json:"do_failed"`
	ReadFailed            bool      `json:"read_failed"`
	CloseFailed           bool      `json:"close_failed"`
	OriginalContextFailed bool      `json:"original_context_failed"`
	Status                int       `json:"status"`
	ReceivedBodyBytes     int       `json:"received_body_bytes"`
	ResponseSHA256        string    `json:"response_sha256"`
	ResponseBodyScope     string    `json:"response_body_scope"`
	RetainedPrefixBytes   int       `json:"retained_prefix_bytes"`
	RetainedPrefixSHA256  string    `json:"retained_prefix_sha256"`
}

func guestOriginalNativeHTTPFailureClass(r GuestOriginalHTTPReturn, err error) string {
	switch {
	case err == nil:
		return "none"
	case r.PreflightFailed:
		return "preflight"
	case errors.Is(err, context.Canceled):
		return "cancelled"
	case errors.Is(err, context.DeadlineExceeded):
		return "deadline"
	case r.DoFailed:
		return "do"
	case r.ReadFailed:
		return "read"
	case r.CloseFailed:
		return "close"
	case r.Status != http.StatusOK:
		return "status"
	default:
		return "other_transport"
	}
}

func guestOriginalNativeHTTPFailureProjection(ctx context.Context, method, path string, r GuestOriginalHTTPReturn, err error, ordinal uint64) (guestOriginalNativeHTTPFailureDiagnostic, bool) {
	route := ""
	switch {
	case method == http.MethodPost && path == "/v1/retirement":
		route = "retirement_post"
	case method == http.MethodGet && path == "/v1/qualification-serving-probe-nonce":
		route = "qualification_serving_probe_nonce"
	}
	if err == nil || route == "" {
		return guestOriginalNativeHTTPFailureDiagnostic{}, false
	}
	var deadline time.Time
	var present bool
	if ctx != nil {
		deadline, present = ctx.Deadline()
	}
	return guestOriginalNativeHTTPFailureDiagnostic{
		Schema: guestOriginalNativeHTTPFailureSchema, Ordinal: ordinal, Method: method, Route: route, DeadlinePresent: present, ErrorClass: guestOriginalNativeHTTPFailureClass(r, err),
		StartedAt: r.StartedAt, DoStartedAt: r.DoStartedAt, DoReturnedAt: r.DoReturnedAt, ReadReturnedAt: r.ReadReturnedAt, CloseReturnedAt: r.CloseReturnedAt, DriverReturnedAt: r.DriverReturnedAt, OriginalDeadline: deadline,
		PreflightFailed: r.PreflightFailed, DoFailed: r.DoFailed, ReadFailed: r.ReadFailed, CloseFailed: r.CloseFailed, OriginalContextFailed: r.OriginalContextFailed,
		Status: r.Status, ReceivedBodyBytes: r.ReceivedBodyBytes, ResponseSHA256: r.ResponseSHA256, ResponseBodyScope: r.ResponseBodyScope, RetainedPrefixBytes: r.RetainedPrefixBytes, RetainedPrefixSHA256: r.RetainedPrefixSHA256,
	}, true
}

// Call only after Original has actually returned. The production gate precedes
// formatting/logging/ordinal work; the original driver/defer performs no I/O.
func LogGuestOriginalNativeHTTPFailure(ctx context.Context, method, fixedPath string, returned GuestOriginalHTTPReturn, callErr error) {
	if !GuestOriginalNativeQEMUProviderEnabled("native-qemu") {
		return
	}
	d, ok := guestOriginalNativeHTTPFailureProjection(ctx, method, fixedPath, returned, callErr, 0)
	if !ok {
		return
	}
	d.Ordinal = guestOriginalNativeHTTPFailureOrdinal.Add(1)
	wire, err := json.Marshal(d)
	if err == nil {
		log.Printf("%s %s", guestOriginalNativeHTTPFailureSchema, wire)
	}
}
