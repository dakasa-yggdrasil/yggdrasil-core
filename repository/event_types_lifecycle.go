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
	EventTypeTeamGrantAdded               = "team_grant.added"
	EventTypeTeamGrantRevoked             = "team_grant.revoked"

	// EventTypeReactorDeadLettered is emitted by the Runner when a reaction
	// exhausts retries. It is NOT a canon lifecycle event — the prefix
	// "reactor.*" is reserved and the Materializer skips it (no infinite loop).
	EventTypeReactorDeadLettered = "reactor.dead_lettered"

	// Sync framework events — infrastructure, NOT canon lifecycle.
	// The Materializer must skip these (no integration reaction allowed against
	// manifest sync activity), enforced by the test
	// TestSyncEventTypesAreNotCanonLifecycle.
	EventTypeRuntimeStateContractMismatchDetected = "runtime_state.contract_mismatch_detected"
	EventTypeIntegrationTypeSynced                = "integration_type.synced"
	EventTypeIntegrationTypeSyncNoOp              = "integration_type.sync_no_op"
	EventTypeIntegrationTypeSyncSkipped           = "integration_type.sync_skipped"

	// External identity framework events — infrastructure, NOT canon lifecycle.
	EventTypeExternalIdentityLinked            = "collaborator_external_identity.linked"
	EventTypeExternalIdentityUnlinked          = "collaborator_external_identity.unlinked"
	EventTypeExternalIdentityDriftDetected     = "collaborator_external_identity.drift_detected"
	EventTypeExternalIdentityUnknownExternal   = "collaborator_external_identity.unknown_external"
	EventTypeExternalIdentityPurged            = "collaborator_external_identity.purged"
	EventTypeExternalIdentityConflictDetected  = "collaborator_external_identity.conflict_detected"
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
	EventTypeTeamGrantAdded:             {},
	EventTypeTeamGrantRevoked:           {},
}

// IsCanonLifecycleEvent returns true when t is in the closed canon set.
func IsCanonLifecycleEvent(t string) bool {
	_, ok := CanonLifecycleEventTypes[t]
	return ok
}
