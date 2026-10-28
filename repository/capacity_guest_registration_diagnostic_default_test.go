//go:build !linux || !nativequalification

package repository

import (
	"errors"
	"testing"
)

func TestGuestRegistrationDiagnosticDefaultUnchanged(t *testing.T) {
	err := errors.New("original")
	if guestRegistrationFailure("current", err) != err || GuestRegistrationDiagnostic(err) != "" || guestRegistrationValidationFailure(err) != ErrCapacityConflict {
		t.Fatal("default error changed")
	}
}
