package httpapi

import (
	"context"
	messagecontroller "github.com/dakasa-yggdrasil/yggdrasil-core/controllers/message"
	"github.com/google/uuid"
)

func executorPowerOperatorContext(ctx context.Context, collaboratorID, machineID string, hasMachine, legacy bool) context.Context {
	id, err := uuid.Parse(collaboratorID)
	if err != nil || id == uuid.Nil || id.String() != collaboratorID || machineID != "" || hasMachine || legacy {
		return ctx
	}
	return messagecontroller.WithExecutorPowerOperator(ctx, collaboratorID)
}
