// repository/event_types_lifecycle.go
package repository

// Canon lifecycle events that drive the reactor framework.
// These must remain stable — changing a value is a breaking change for every
// integration that has reactors declared against them.
const (
	EventTypeCollaboratorCreated          = "collaborator.created"
	EventTypeCollaboratorOffboarded       = "collaborator.offboarded"
	EventTypeCollaboratorAbsenceStarted   = "collaborator.absence_started"
	EventTypeCollaboratorAbsenceEnded     = "collaborator.absence_ended"
	EventTypeCollaboratorRoleChanged      = "collaborator.role_changed"
	EventTypeCollaboratorReOnboarded      = "collaborator.re_onboarded"
	EventTypeTeamCreated                  = "team.created"
	EventTypeTeamUpdated                  = "team.updated"
	EventTypeTeamDeleted                  = "team.deleted"
	EventTypeTeamMembershipAdded          = "team_membership.added"
	EventTypeTeamMembershipRemoved        = "team_membership.removed"

	// EventTypeReactorDeadLettered is emitted by the Runner when a reaction
	// exhausts retries. It is NOT a canon lifecycle event — the prefix
	// "reactor.*" is reserved and the Materializer skips it (no infinite loop).
	EventTypeReactorDeadLettered = "reactor.dead_lettered"
)

// CanonLifecycleEventTypes is the closed set of events that may have reactors.
// The Materializer consults this set; the manifest validator rejects reactor
// declarations using any event_type outside it.
var CanonLifecycleEventTypes = map[string]struct{}{
	EventTypeCollaboratorCreated:        {},
	EventTypeCollaboratorOffboarded:     {},
	EventTypeCollaboratorAbsenceStarted: {},
	EventTypeCollaboratorAbsenceEnded:   {},
	EventTypeCollaboratorRoleChanged:    {},
	EventTypeCollaboratorReOnboarded:    {},
	EventTypeTeamCreated:                {},
	EventTypeTeamUpdated:                {},
	EventTypeTeamDeleted:                {},
	EventTypeTeamMembershipAdded:        {},
	EventTypeTeamMembershipRemoved:      {},
}

// IsCanonLifecycleEvent returns true when t is in the closed canon set.
func IsCanonLifecycleEvent(t string) bool {
	_, ok := CanonLifecycleEventTypes[t]
	return ok
}
