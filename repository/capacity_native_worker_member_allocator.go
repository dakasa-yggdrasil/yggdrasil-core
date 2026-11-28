package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

type nativeMemberAllocatorPreflight struct {
	Context     model.CapacityNativeWorkerAllocatorFenceContext
	Observation model.CapacityNativeWorkerAllocatorFenceObservation
}

func nativeMemberFenceContext(ctx context.Context, db *sql.DB, policy model.Manifest, p model.CapacityPolicySpec, a model.CapacityNativeWorkerAttempt) (model.CapacityNativeWorkerAllocatorFenceContext, error) {
	var zero model.CapacityNativeWorkerAllocatorFenceContext
	var raw []byte
	var parent nativeWorkerCommandContext
	if p.NativeWorkerLifecycleBinding == nil || p.NativeWorkerLifecycleBinding.Members == nil || p.NativeWorkerPoolBinding == nil || a.PolicyID != policy.ID || a.PolicyChecksum != policy.Checksum {
		return zero, errNativeMember
	}
	if e := db.QueryRowContext(ctx, `SELECT record FROM public.capacity_native_worker_command_contexts WHERE attempt_id=$1`, a.ID).Scan(&raw); e != nil || json.Unmarshal(raw, &parent) != nil || parent.AttemptID != a.ID || parent.PolicyID != a.PolicyID || parent.PolicyChecksum != a.PolicyChecksum || parent.Namespace != a.Namespace || parent.Generation != a.Generation || parent.FencingToken != a.FencingToken || !capacity.NativeWorkerSameExecution(parent.Execution, a.Execution) {
		return zero, errNativeMember
	}
	b, pool := p.NativeWorkerLifecycleBinding.Members, p.NativeWorkerPoolBinding
	return model.CapacityNativeWorkerAllocatorFenceContext{Schema: model.CapacityNativeWorkerAllocatorFenceContextSchema, CreatorPermitID: a.ID.String(), AttemptID: a.ID.String(), CoreSourceCommit: a.SourceCommit, Observer: capacity.NativeWorkerMemberEndpoint(b.AllocatorFenceReader, "observe_native_worker_allocator_fence"), PolicyID: a.PolicyID.String(), PolicyChecksum: a.PolicyChecksum, IntentGeneration: a.Generation, FencingToken: a.FencingToken, RealmUID: pool.RealmUID, PoolUID: pool.PoolUID, Owner: pool.Owner, Epoch: pool.ExpectedPoolEpoch, BootstrapPolicySHA256: b.BootstrapPolicySHA256, NotAfter: parent.ExpiresAt}, nil
}
func (s *CapacityNativeWorkerMemberStore) allocatorPreflight(ctx context.Context, a model.CapacityNativeWorkerAttempt) (nativeMemberAllocatorPreflight, error) {
	var zero nativeMemberAllocatorPreflight
	st, e := s.acquire()
	if e != nil {
		return zero, e
	}
	runtime := st.runtime
	st.mu.RUnlock()
	c, o, e := runtime.AllocatorFence(ctx, a)
	if e != nil || ctx.Err() != nil {
		return zero, errNativeMember
	}
	st, e = s.acquire()
	if e != nil {
		return zero, e
	}
	defer st.mu.RUnlock()
	p, e := parseCapacityPolicy(st.policy)
	if e != nil || st.sealed.Load() || c.AttemptID != a.ID.String() || c.PolicyID != a.PolicyID.String() || c.PolicyChecksum != a.PolicyChecksum || c.CoreSourceCommit != a.SourceCommit || !capacity.NativeWorkerAllocatorFenceValid(p, c, o, st.authority, time.Now().UTC()) {
		return zero, errNativeMember
	}
	return nativeMemberAllocatorPreflight{c, o}, nil
}
func (s *CapacityNativeWorkerMemberStore) allocatorCurrentTx(ctx context.Context, tx *sql.Tx, p model.CapacityPolicySpec, a model.CapacityNativeWorkerAttempt, f *nativeMemberAllocatorPreflight, now time.Time) error {
	st, e := s.acquire()
	if e != nil {
		return e
	}
	defer st.mu.RUnlock()
	if st.sealed.Load() || f == nil || f.Context.AttemptID != a.ID.String() || f.Context.PolicyID != a.PolicyID.String() || f.Context.PolicyChecksum != a.PolicyChecksum || f.Context.CoreSourceCommit != a.SourceCommit || f.Context.IntentGeneration != a.Generation || f.Context.FencingToken != a.FencingToken || !capacity.NativeWorkerAllocatorFenceValid(p, f.Context, f.Observation, st.authority, now) {
		return errNativeMember
	}
	var raw []byte
	var command nativeWorkerCommandContext
	if e = tx.QueryRowContext(ctx, `SELECT record FROM public.capacity_native_worker_command_contexts WHERE attempt_id=$1`, a.ID).Scan(&raw); e != nil || json.Unmarshal(raw, &command) != nil || !command.ExpiresAt.Equal(f.Context.NotAfter) || command.AttemptID != a.ID || command.PolicyID != a.PolicyID || command.PolicyChecksum != a.PolicyChecksum || !capacity.NativeWorkerSameExecution(command.Execution, a.Execution) {
		return errNativeMember
	}
	return nil
}
