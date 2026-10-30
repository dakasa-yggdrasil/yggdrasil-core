//go:build !linux || !nativequalification

package repository

import (
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"time"
)

func guestRegistrationFailure(_ string, err error) error { return err }
func GuestRegistrationDiagnostic(error) string           { return "" }

func guestRegistrationValidationFailure(error) error { return ErrCapacityConflict }

func guestRegistrationValidationFailureDetail(err error, _ model.CapacityPolicySpec, _ model.CapacityGuestRetirementBinding, _ model.CapacityGuestRetirementMemberBinding, _ model.CapacityGuestOriginalCreateWitness, _ model.CapacityGuestOriginalProvisioningRegistration, _ time.Time) error {
	return guestRegistrationValidationFailure(err)
}
func GuestRegistrationDiagnosticDetail(error) string { return "" }
