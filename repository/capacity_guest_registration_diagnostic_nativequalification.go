//go:build linux && nativequalification

package repository

import "errors"

type guestRegistrationDiagnostic struct {
	stage string
	cause error
}

func (e *guestRegistrationDiagnostic) Error() string { return "original Guest registration held" }
func (e *guestRegistrationDiagnostic) Unwrap() error { return e.cause }
func guestRegistrationFailure(stage string, err error) error {
	switch stage {
	case "principal", "current", "witness_load", "production_clock", "keys", "witness_validation", "registration_validation", "enrollment_validation":
		return &guestRegistrationDiagnostic{stage: stage, cause: err}
	default:
		return err
	}
}
func GuestRegistrationDiagnostic(err error) string {
	var d *guestRegistrationDiagnostic
	if errors.As(err, &d) {
		return d.stage
	}
	return ""
}
