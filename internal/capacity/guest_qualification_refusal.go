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
	case "publish_probe":
		return "original-guest-step-89"
	}
	return "original-guest-step-17"
}
