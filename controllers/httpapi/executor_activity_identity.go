package httpapi

import (
	"context"
	messagecontroller "github.com/dakasa-yggdrasil/yggdrasil-core/controllers/message"
)

// Private carrier populated only from the existing authenticated workflow actor.
// It is not decoded from headers, request inputs or metadata.
type executorActivityIdentity struct {
	PrincipalID, ConfiguredID, SubjectID, SubjectType string
	Legacy                                            bool
}

func executorActivityContext(ctx context.Context, id executorActivityIdentity) context.Context {
	if id.ConfiguredID == "" || id.PrincipalID == "" || id.Legacy || id.ConfiguredID != id.PrincipalID || id.SubjectType != "service" || id.SubjectID != id.PrincipalID {
		return ctx
	}
	return messagecontroller.WithExecutorActivityMachinePrincipal(ctx, id.PrincipalID)
}
