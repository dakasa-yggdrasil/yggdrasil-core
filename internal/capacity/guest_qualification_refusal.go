package capacity

import "errors"

// A closed source-stage diagnostic. It carries no permission and never exposes
// the underlying error text, request, response, credential, or SQL value.
type guestQualificationRefusal struct {
	stage string
	cause error
}

func (e *guestQualificationRefusal) Error() string {
	return "protected original Guest qualification unavailable"
}
func (e *guestQualificationRefusal) Unwrap() error { return e.cause }

func GuestQualificationRefusal(stage string, cause error) error {
	if cause == nil {
		return nil
	}
	return &guestQualificationRefusal{stage: stage, cause: cause}
}

// The existing public caller accepts these fixed two-digit predicates. Unknown
// and untyped errors keep the original generic predicate; no error is promoted.
func GuestQualificationPredicate(err error) string {
	var refusal *guestQualificationRefusal
	if !errors.As(err, &refusal) || refusal == nil {
		return "original-guest-step-17"
	}
	switch refusal.stage {
	case "observe":
		return "original-guest-step-60"
	case "lease_missing":
		return "original-guest-step-61"
	case "generation":
		return "original-guest-step-62"
	case "fence":
		return "original-guest-step-63"
	case "phase":
		return "original-guest-step-64"
	case "binding":
		return "original-guest-step-65"
	case "owned_slots":
		return "original-guest-step-66"
	case "member":
		return "original-guest-step-67"
	case "client":
		return "original-guest-step-68"
	case "probe":
		return "original-guest-step-69"
	case "fresh_native":
		return "original-guest-step-70"
	case "projection":
		return "original-guest-step-71"
	case "projection_encode":
		return "original-guest-step-72"
	case "record_slot":
		return "original-guest-step-73"
	case "advance_prepared":
		return "original-guest-step-74"
	case "advance_canary":
		return "original-guest-step-75"
	case "advance_promoted":
		return "original-guest-step-76"
	case "realm_profile":
		return "original-guest-step-77"
	case "enrollment":
		return "original-guest-step-78"
	case "key_writers":
		return "original-guest-step-79"
	case "deadline":
		return "original-guest-step-80"
	case "nonce":
		return "original-guest-step-81"
	case "signature":
		return "original-guest-step-82"
	case "request_encode":
		return "original-guest-step-83"
	case "reserve_probe":
		return "original-guest-step-84"
	case "probe_http":
		return "original-guest-step-85"
	case "probe_decode":
		return "original-guest-step-86"
	case "probe_validate":
		return "original-guest-step-87"
	case "finish_probe":
		return "original-guest-step-88"
	case "probe_http_preflight":
		return "original-guest-step-90"
	case "probe_http_context":
		return "original-guest-step-91"
	case "probe_http_transport":
		return "original-guest-step-92"
	case "probe_http_read":
		return "original-guest-step-93"
	case "probe_http_close":
		return "original-guest-step-94"
	case "probe_http_auth_status":
		return "original-guest-step-95"
	case "probe_http_not_found":
		return "original-guest-step-96"
	case "probe_http_client_status":
		return "original-guest-step-97"
	case "probe_http_server_status":
		return "original-guest-step-98"
	case "probe_http_other_status":
		return "original-guest-step-99"
	case "publish_probe":
		return "original-guest-step-89"
	}
	return "original-guest-step-17"
}

// GuestQualificationHTTPRefusal classifies only a failed original call. Context
// takes precedence over I/O symptoms; remaining precedence follows the original
// client guards. Categories do not assert a unique cause when facts overlap.
// No body, header, URL, error text, or hash is retained by this projection.
func GuestQualificationHTTPRefusal(r GuestOriginalHTTPReturn, cause error) error {
	if cause == nil {
		return nil
	}
	stage := "probe_http"
	switch {
	case r.OriginalContextFailed:
		stage = "probe_http_context"
	case r.PreflightFailed:
		stage = "probe_http_preflight"
	case r.DoFailed:
		stage = "probe_http_transport"
	case r.ReadFailed:
		stage = "probe_http_read"
	case r.CloseFailed:
		stage = "probe_http_close"
	case r.Status == 401 || r.Status == 403:
		stage = "probe_http_auth_status"
	case r.Status == 404:
		stage = "probe_http_not_found"
	case r.Status >= 400 && r.Status <= 499:
		stage = "probe_http_client_status"
	case r.Status >= 500 && r.Status <= 599:
		stage = "probe_http_server_status"
	case r.Status != 200:
		stage = "probe_http_other_status"
	}
	return GuestQualificationRefusal(stage, cause)
}
