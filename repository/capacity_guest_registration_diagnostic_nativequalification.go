//go:build linux && nativequalification

package repository

import (
	"errors"
	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"time"
)

type guestRegistrationDiagnostic struct {
	stage  string
	detail string
	cause  error
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

// The original validation runs first. This qualification-only explanation uses
// its same captured now and only reports the first fixed V1 predicate group.
func guestRegistrationValidationFailureDetail(err error, p model.CapacityPolicySpec, b model.CapacityGuestRetirementBinding, member model.CapacityGuestRetirementMemberBinding, w model.CapacityGuestOriginalCreateWitness, registration model.CapacityGuestOriginalProvisioningRegistration, now time.Time) error {
	out := guestRegistrationValidationFailure(err)
	var d *guestRegistrationDiagnostic
	if err == nil || err.Error() != "complete original protected provisioning required" || !errors.As(out, &d) {
		return out
	}
	r, profile := registration.Result, b.ProfileManifest
	// The V2 route has its own validator and must never be assigned V1 details.
	if r.Schema == capacity.GuestProvisioningV2Schema || r.ProductionClock != nil || registration.EnrollmentStatement.OriginalProvisioningClockSHA256 != "" {
		return out
	}
	switch {
	case capacity.ValidateGuestRetirementBinding(p, &b) != nil:
		d.detail = "binding"
	case r.Schema != capacity.GuestOriginalProvisioningSchema:
		d.detail = "schema"
	case r.BindingName != member.Name || r.BindingName != w.BindingName || r.SourceClass != b.EvidenceClass || r.ProvisionerSourceCommit != b.ProvisionerSourceCommit:
		d.detail = "binding_source"
	case r.OriginalCreateGrantID != w.OriginalCreateGrantID || r.OriginalCreateAttemptID != w.OriginalCreateAttemptID || r.OriginalCreateSettlementSHA256 != w.OriginalCreateSettlementSHA256 || r.PreregistrationID != w.PreregistrationID || r.PreregistrationNonceSHA256 != w.PreregistrationNonceSHA256 || r.Tuple != w.Tuple || r.ProfileManifestSHA256 != b.ProfileManifestSHA256:
		d.detail = "original_identity"
	case !capacity.GuestRetirementLifetime(r.Actor) || !capacity.GuestRetirementLifetime(r.Runtime):
		d.detail = "actor_runtime_lifetime"
	case r.Actor.SourceCommit != profile.ActorSourceCommit || r.Actor.BinarySHA256 != profile.ActorBinarySHA256:
		d.detail = "actor_source"
	case r.Runtime.SourceCommit != profile.OwnerSourceCommit || r.Runtime.BinarySHA256 != profile.OwnerBinarySHA256 || r.Runtime.BootID != r.Actor.BootID || r.Actor.PID == r.Runtime.PID:
		d.detail = "runtime_source_boot"
	case len(r.Writers) != len(profile.Writers) || len(r.WriterPlacements) != len(r.Writers) || r.WriterRosterSHA256 != capacity.GuestRetirementSHA(r.Writers):
		d.detail = "writer_roster"
	case r.AdmissionOpened:
		d.detail = "admission_opened"
	case guestRegistrationProtectedTimeDetail(r, w, now) != "":
		d.detail = guestRegistrationProtectedTimeDetail(r, w, now)
	case capacity.GuestOriginalBootstrap(w, profile, r.BootstrapOriginalJournal, r.BootstrapOriginalObservation, r.OriginalReturnedAt) != nil:
		d.detail = "bootstrap"
	}
	return out
}
func GuestRegistrationDiagnosticDetail(err error) string {
	var d *guestRegistrationDiagnostic
	if !errors.As(err, &d) {
		return ""
	}
	switch d.detail {
	case "binding", "schema", "binding_source", "original_identity", "actor_runtime_lifetime", "actor_source", "runtime_source_boot", "writer_roster", "admission_opened", "result_time_zero", "result_time_future", "result_time_deadline", "result_time_bootstrap", "bootstrap":
		return d.detail
	}
	return ""
}

func guestRegistrationProtectedTimeDetail(r model.CapacityGuestOriginalProvisioningResult, w model.CapacityGuestOriginalCreateWitness, now time.Time) string {
	switch {
	case r.OriginalReturnedAt.IsZero():
		return "result_time_zero"
	case r.OriginalReturnedAt.After(now):
		return "result_time_future"
	case !r.OriginalReturnedAt.Before(w.OriginalDeadline):
		return "result_time_deadline"
	case r.OriginalReturnedAt.Before(r.BootstrapOriginalObservation.ObservedAt):
		return "result_time_bootstrap"
	}
	return ""
}
