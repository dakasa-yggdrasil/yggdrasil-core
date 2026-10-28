//go:build linux && nativequalification

package repository

import (
	"errors"
	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"strings"
	"testing"
	"time"
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

func TestGuestRegistrationProtectedGroupClosed(t *testing.T) {
	now := time.Now().UTC()
	p := model.CapacityPolicySpec{}
	b := model.CapacityGuestRetirementBinding{}
	m := model.CapacityGuestRetirementMemberBinding{}
	w := model.CapacityGuestOriginalCreateWitness{}
	r := model.CapacityGuestOriginalProvisioningRegistration{}
	original := capacity.GuestOriginalRegistration(p, b, m, w, r, now)
	if original == nil || original.Error() != "complete original protected provisioning required" {
		t.Fatal("expected actual V1 protected refusal")
	}
	got := guestRegistrationValidationFailureDetail(original, p, b, m, w, r, now)
	if !errors.Is(got, ErrCapacityConflict) || GuestRegistrationDiagnostic(got) != "registration_protected" || GuestRegistrationDiagnosticDetail(got) != "binding" {
		t.Fatal("actual guard explanation or conflict changed")
	}
	for _, detail := range []string{"binding", "schema", "binding_source", "original_identity", "actor_runtime_lifetime", "actor_source", "runtime_source_boot", "writer_roster", "admission_opened", "result_time_zero", "result_time_future", "result_time_deadline", "result_time_bootstrap", "bootstrap"} {
		if GuestRegistrationDiagnosticDetail(&guestRegistrationDiagnostic{detail: detail}) != detail {
			t.Fatal("missing closed group")
		}
	}
	// Two failures still report the first actual V1 guard.
	bad := r
	bad.Result.BindingName = "foreign"
	bad.Result.OriginalReturnedAt = now.Add(time.Second)
	actual := capacity.GuestOriginalRegistration(p, b, m, w, bad, now)
	both := guestRegistrationValidationFailureDetail(actual, p, b, m, w, bad, now)
	if !errors.Is(both, ErrCapacityConflict) || GuestRegistrationDiagnosticDetail(both) != "binding" {
		t.Fatal("guard precedence changed")
	}
	clockResult := model.CapacityGuestOriginalProvisioningResult{OriginalReturnedAt: now.Add(time.Second)}
	if guestRegistrationProtectedTimeDetail(clockResult, w, now) != "result_time_future" {
		t.Fatal("future-time classification changed")
	}
	v2 := r
	v2.Result.Schema = capacity.GuestProvisioningV2Schema
	v2out := guestRegistrationValidationFailureDetail(original, p, b, m, w, v2, now)
	if !errors.Is(v2out, ErrCapacityConflict) || GuestRegistrationDiagnosticDetail(v2out) != "" {
		t.Fatal("V2 received V1 details")
	}
	if GuestRegistrationDiagnosticDetail(&guestRegistrationDiagnostic{detail: "raw secret"}) != "" {
		t.Fatal("arbitrary detail leaked")
	}
	other := guestRegistrationValidationFailureDetail(errors.New("private detail"), p, b, m, w, r, now)
	if !errors.Is(other, ErrCapacityConflict) || GuestRegistrationDiagnostic(other) != "registration_validation" || GuestRegistrationDiagnosticDetail(other) != "" {
		t.Fatal("unrelated error changed")
	}
}
