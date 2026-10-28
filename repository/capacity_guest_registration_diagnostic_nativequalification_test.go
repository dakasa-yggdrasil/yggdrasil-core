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
