// Package collaboratorstate is the canonical state machine for
// collaborators.status transitions. It is the only place that decides
// whether a status change is allowed; HTTP handlers and the daily
// status clock both call ValidateTransition before issuing UPDATEs.
//
// Transitions are intentionally explicit (not "anything to anything").
// offboarded is soft-terminal: the only edge out is to pending_start,
// modeling re-onboarding while preserving the lifecycle log.
package collaboratorstate

import (
	"errors"
	"fmt"
)

type Status string

const (
	StatusPendingStart Status = "pending_start"
	StatusActive       Status = "active"
	StatusOnLeave      Status = "on_leave"
	StatusSuspended    Status = "suspended"
	StatusOffboarded   Status = "offboarded"
)

var (
	// ErrUnknownStatus is returned when ValidateTransition receives a
	// value not in the canonical set.
	ErrUnknownStatus = errors.New("unknown collaborator status")
	// ErrInvalidTransition is returned when the (from, to) pair is not
	// in the allowed transitions map.
	ErrInvalidTransition = errors.New("invalid collaborator status transition")
)

// allowedTransitions encodes the diagram in spec §5.4. Each key is a
// source status; the value lists every destination status that's a
// valid transition from there. Same-status (no-op) transitions are
// validated separately and always allowed.
var allowedTransitions = map[Status]map[Status]struct{}{
	StatusPendingStart: {
		StatusActive:     {},
		StatusOffboarded: {},
	},
	StatusActive: {
		StatusOnLeave:    {},
		StatusSuspended:  {},
		StatusOffboarded: {},
	},
	StatusOnLeave: {
		StatusActive:     {},
		StatusSuspended:  {},
		StatusOffboarded: {},
	},
	StatusSuspended: {
		StatusActive:     {},
		StatusOnLeave:    {},
		StatusOffboarded: {},
	},
	StatusOffboarded: {
		StatusPendingStart: {},
	},
}

// IsKnown reports whether s is one of the canonical status values.
func IsKnown(s Status) bool {
	_, ok := allowedTransitions[s]
	return ok
}

// ValidateTransition returns nil when from→to is allowed. Same-status
// is treated as a no-op (no error). Unknown statuses return
// ErrUnknownStatus; otherwise ErrInvalidTransition is wrapped with
// detail for logging.
func ValidateTransition(from, to Status) error {
	if from == to {
		if !IsKnown(from) {
			return fmt.Errorf("%w: %q", ErrUnknownStatus, from)
		}
		return nil
	}
	dests, ok := allowedTransitions[from]
	if !ok {
		return fmt.Errorf("%w: %q", ErrUnknownStatus, from)
	}
	if !IsKnown(to) {
		return fmt.Errorf("%w: %q", ErrUnknownStatus, to)
	}
	if _, allowed := dests[to]; !allowed {
		return fmt.Errorf("%w: %s -> %s", ErrInvalidTransition, from, to)
	}
	return nil
}

// AllStatuses returns every canonical status value (sorted by string
// for deterministic output). Useful for OpenAPI enum generation and
// CLI help text.
func AllStatuses() []Status {
	return []Status{
		StatusPendingStart,
		StatusActive,
		StatusOnLeave,
		StatusSuspended,
		StatusOffboarded,
	}
}
