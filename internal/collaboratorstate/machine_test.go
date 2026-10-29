package collaboratorstate

import (
	"errors"
	"testing"
)

func TestValidateTransition_AcceptsCanonicalEdges(t *testing.T) {
	cases := []struct {
		from Status
		to   Status
	}{
		{StatusPendingStart, StatusActive},
		{StatusActive, StatusOnLeave},
		{StatusOnLeave, StatusActive},
		{StatusActive, StatusSuspended},
		{StatusSuspended, StatusActive},
		{StatusOnLeave, StatusSuspended},
		{StatusSuspended, StatusOnLeave},
		{StatusActive, StatusOffboarded},
		{StatusOnLeave, StatusOffboarded},
		{StatusSuspended, StatusOffboarded},
		{StatusPendingStart, StatusOffboarded},
		{StatusOffboarded, StatusPendingStart},
	}
	for _, c := range cases {
		t.Run(string(c.from)+"_to_"+string(c.to), func(t *testing.T) {
			if err := ValidateTransition(c.from, c.to); err != nil {
				t.Fatalf("expected transition %s -> %s allowed, got error: %v", c.from, c.to, err)
			}
		})
	}
}

func TestValidateTransition_RejectsNonCanonicalEdges(t *testing.T) {
	cases := []struct {
		from Status
		to   Status
	}{
		{StatusPendingStart, StatusOnLeave},
		{StatusPendingStart, StatusSuspended},
		{StatusActive, StatusPendingStart},
		{StatusOffboarded, StatusActive},
		{StatusOffboarded, StatusOnLeave},
		{StatusOffboarded, StatusSuspended},
	}
	for _, c := range cases {
		t.Run(string(c.from)+"_to_"+string(c.to), func(t *testing.T) {
			err := ValidateTransition(c.from, c.to)
			if err == nil {
				t.Fatalf("expected transition %s -> %s rejected, got nil error", c.from, c.to)
			}
			if !errors.Is(err, ErrInvalidTransition) {
				t.Fatalf("expected ErrInvalidTransition, got %v", err)
			}
		})
	}
}

func TestValidateTransition_RejectsUnknownStatus(t *testing.T) {
	err := ValidateTransition(Status("garbage"), StatusActive)
	if !errors.Is(err, ErrUnknownStatus) {
		t.Fatalf("expected ErrUnknownStatus, got %v", err)
	}
}

func TestValidateTransition_NoOpSameStatus(t *testing.T) {
	if err := ValidateTransition(StatusActive, StatusActive); err != nil {
		t.Fatalf("expected same-status transition to be a no-op (nil), got %v", err)
	}
}

// CanSignIn is the login rule every session, session reuse and token mint
// shares: exactly "active" (case and surrounding whitespace tolerated) signs
// in, and every other canonical status and the empty value do not.
func TestCanSignInIsTheLoginRule(t *testing.T) {
	for status, want := range map[string]bool{
		"active":        true,
		" Active ":      true,
		"ACTIVE":        true,
		"":              false,
		"pending_start": false,
		"on_leave":      false,
		"suspended":     false,
		"offboarded":    false,
		"activated":     false,
	} {
		if got := CanSignIn(status); got != want {
			t.Errorf("CanSignIn(%q) = %v, want %v", status, got, want)
		}
	}
	for _, status := range AllStatuses() {
		if got, want := CanSignIn(string(status)), status == StatusActive; got != want {
			t.Errorf("CanSignIn(%q) = %v, want %v", status, got, want)
		}
	}
}
