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
