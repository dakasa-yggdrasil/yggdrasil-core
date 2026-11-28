package message

import (
	"context"
	"database/sql"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	"github.com/google/uuid"
	amqp "github.com/rabbitmq/amqp091-go"
)

func NewNativeWorkerMemberProviderAbortPort(db *sql.DB, broker func() *amqp.Connection, clients map[string]*capacity.NativeWorkerRPCClient) repository.NativeWorkerMemberPrepareProviderFunc {
	owned := make(map[string]*capacity.NativeWorkerRPCClient, len(clients))
	for k, v := range clients {
		owned[k] = v
	}
	return func(ctx context.Context, a model.CapacityNativeWorkerAttempt, p model.CapacityNativeWorkerAbortPermit) (func() error, error) {
		if db == nil || broker == nil || ctx == nil || ctx.Err() != nil || p.AttemptID != a.ID || p.PermitID == uuid.Nil || p.State != "issued" || p.Capability != "destroy_native_worker" || a.Execution.DestroyCapability != p.Capability || a.Execution.BindingName != p.BindingName || a.Execution.SDKSourceCommit != p.SDKSourceCommit || a.Execution.ScopeSHA256 != p.ExecutionScopeSHA256 {
			return nil, errCapacityBoundAssessment
		}
		conn := broker()
		if conn == nil || conn.IsClosed() {
			return nil, errCapacityBoundAssessment
		}
		return prepareNativeWorkerExecutionRPC(ctx, conn, db, owned[a.Profile], a.Execution.Adapter, a.Profile, a.Execution.BindingName, a.Execution.SDKSourceCommit, a.Execution.ScopeSHA256, p.Capability, map[string]any{"binding_name": p.BindingName, "permit_id": p.PermitID.String()})
	}
}
