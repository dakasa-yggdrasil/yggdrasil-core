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
	case "principal", "current", "witness_load", "production_clock", "keys", "witness_validation", "registration_validation", "registration_clock", "registration_protected", "registration_census", "registration_placement", "registration_enrollment", "registration_signature", "enrollment_validation":
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

// Only source-owned constant errors are mapped; unknown errors remain one
// closed stage. Neither raw errors nor request data reach the serial sink.
func guestRegistrationValidationFailure(err error) error {
	stage := "registration_validation"
	if err != nil {
		switch err.Error() {
		case "production requires the explicit original boot clock", "explicit original production clock required":
			stage = "registration_clock"
		case "complete original protected provisioning required":
			stage = "registration_protected"
		case "full original pre-admission writer census required":
			stage = "registration_census"
		case "source-approved original writer placement required":
			stage = "registration_placement"
		case "separate original enrollment statement required":
			stage = "registration_enrollment"
		case "original provisioning callback signature refused":
			stage = "registration_signature"
		}
	}
	return guestRegistrationFailure(stage, ErrCapacityConflict)
}
