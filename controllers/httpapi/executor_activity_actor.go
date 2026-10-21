package httpapi

import (
	"context"
)

// actor comes from authenticateWorkflowRunRequest, never inputs/metadata.
func (s *Server) withExecutorActivityActor(ctx context.Context, actor workflowRunActor) context.Context {
	id := executorActivityIdentity{PrincipalID: actor.MachinePrincipalID, SubjectID: actor.Subject.ID, SubjectType: actor.Subject.Type, Legacy: actor.LegacyMigration}
	if actor.MachinePrincipal != nil {
		id.ConfiguredID = actor.MachinePrincipal.PrincipalID
	}
	ctx = executorActivityContext(ctx, id)
	ctx = executorPowerOperatorContext(ctx, actor.CollaboratorID, actor.MachinePrincipalID, actor.MachinePrincipal != nil, actor.LegacyMigration)
	return ctx
}
