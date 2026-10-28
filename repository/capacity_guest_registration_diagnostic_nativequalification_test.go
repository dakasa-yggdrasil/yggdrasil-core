//go:build linux && nativequalification

package repository

import (
	"errors"
	"strings"
	"testing"
)

func TestGuestRegistrationDiagnosticClosed(t *testing.T) {
	for _, stage := range []string{"principal", "current", "witness_load", "production_clock", "keys", "witness_validation", "registration_validation", "enrollment_validation"} {
		err := guestRegistrationFailure(stage, ErrCapacityConflict)
		if !errors.Is(err, ErrCapacityConflict) || GuestRegistrationDiagnostic(err) != stage || strings.Contains(err.Error(), stage) {
			t.Fatal("diagnostic changed or exposed source guard", stage)
		}
	}
	err := errors.New("private material")
	if guestRegistrationFailure("private material", err) != err || GuestRegistrationDiagnostic(err) != "" {
		t.Fatal("unknown diagnostic admitted")
	}
}

func TestGuestRegistrationValidationDiagnosticClosed(t *testing.T) {
	for _, item := range []struct{ message, stage string }{
		{"production requires the explicit original boot clock", "registration_clock"},
		{"explicit original production clock required", "registration_clock"},
		{"complete original protected provisioning required", "registration_protected"},
		{"full original pre-admission writer census required", "registration_census"},
		{"source-approved original writer placement required", "registration_placement"},
		{"separate original enrollment statement required", "registration_enrollment"},
		{"original provisioning callback signature refused", "registration_signature"},
		{"private material", "registration_validation"},
	} {
		err := guestRegistrationValidationFailure(errors.New(item.message))
		if !errors.Is(err, ErrCapacityConflict) || GuestRegistrationDiagnostic(err) != item.stage || strings.Contains(err.Error(), item.message) {
			t.Fatal("validation diagnostic changed or exposed guard", item.stage)
		}
	}
}
