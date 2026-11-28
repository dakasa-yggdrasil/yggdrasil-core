package message

import (
	"context"
	"database/sql"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
)

// NativeWorkerExecutionScope is borrowed only for the resolver's synchronous
// callback. It carries no executor, lease, endpoints, credentials or authority.
// Do not retain a handle, map or callback in a goroutine after the callback ends.
// All opaque handles keep their existing shared Close fences.
type NativeWorkerExecutionScope struct {
	Workers               *repository.NativeWorkerConcreteRuntime
	Network               *repository.NativeWorkerConcreteNetworkRuntime
	Abort                 *repository.NativeWorkerConcreteAbortRuntime
	PoolReader            *capacity.NativeWorkerRPCClient
	PoolReaderScopeSHA256 string
	RegistryWriter        *capacity.NativeWorkerRPCClient
	ProviderMutations     map[string]*capacity.NativeWorkerRPCClient
}

func (NativeWorkerExecutionScope) String() string     { return "[private Native worker execution scope]" }
func (s NativeWorkerExecutionScope) GoString() string { return s.String() }
func (NativeWorkerExecutionScope) MarshalJSON() ([]byte, error) {
	return []byte(`{"native_worker_execution_scope":"private"}`), nil
}

// NativeWorkerExecutionResolver is installed only by protected process
// composition. It resolves the current owner by operation, matches the exact
// database and original persisted policy, copies maps and keeps its owner fence
// for the ENTIRE callback. Before installation, replacement or after Close it
// refuses. No workflow/RPC input can install this context key or choose a handle.
type NativeWorkerExecutionResolver func(context.Context, *sql.DB, model.Manifest, func(context.Context, NativeWorkerExecutionScope) error) error

type nativeWorkerExecutionResolverKey struct{}

func WithNativeWorkerExecutionResolver(ctx context.Context, resolver NativeWorkerExecutionResolver) context.Context {
	if ctx == nil {
		return nil
	}
	return context.WithValue(ctx, nativeWorkerExecutionResolverKey{}, resolver)
}

func withNativeWorkerExecutionScope(ctx context.Context, db *sql.DB, policy model.Manifest, use func(context.Context, NativeWorkerExecutionScope) error) error {
	if ctx == nil || ctx.Err() != nil || db == nil || use == nil || policy.Kind != "capacity_policy" || !policy.Metadata.Active {
		return errCapacityBoundAssessment
	}
	resolve, _ := ctx.Value(nativeWorkerExecutionResolverKey{}).(NativeWorkerExecutionResolver)
	if resolve == nil {
		return errCapacityBoundAssessment
	}
	return resolve(ctx, db, policy, use)
}
