package repository

import (
	"context"
	"crypto/subtle"
	"database/sql"
	"encoding/json"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

const NativeMemberWriterRole = "kube_member_writer"
const NativeMemberReaderRole = "kube_member_reader"
const NativeAllocatorFenceReaderRole = "kube_allocator_fence_reader"
const NativeMemberControllerRole = "member_controller"
const NativeMemberSchedulerRole = "stock_scheduler"

// Installed by the authenticated listener/owner, never decoded from HTTP body.
// The stock scheduler uses a distinct mTLS principal without SDK headers/token.
type NativeWorkerMemberCaller struct {
	Role    string
	Binding model.CapacityNativeWorkerProbeResourceBinding
}

func nativeMemberCaller(c model.CapacityNativeWorkerMemberContext, caller NativeWorkerMemberCaller, writer bool) bool {
	target := c.Observer
	role := NativeMemberReaderRole
	if writer {
		target = c.Actor
		role = NativeMemberWriterRole
	}
	b := caller.Binding
	return caller.Role == role && b.Name == target.BindingName && b.Adapter == target.Adapter && b.SourceCommit == target.SourceCommit && b.ScopeSHA256 == target.ScopeSHA256
}
func nativeMemberSelectors(in model.CapacityNativeWorkerMemberSelectors, caller NativeWorkerMemberCaller) (uuid.UUID, error) {
	if in.BindingName != caller.Binding.Name {
		return uuid.Nil, ErrCapacityMutationAuthorization
	}
	return nativeMemberUUID(in.PermitID)
}

func (s *CapacityNativeWorkerMemberStore) Read(ctx context.Context, in model.CapacityNativeWorkerMemberSelectors, caller NativeWorkerMemberCaller) (model.CapacityNativeWorkerMemberRead, error) {
	var out model.CapacityNativeWorkerMemberRead
	id, e := nativeMemberSelectors(in, caller)
	if e != nil {
		return out, e
	}
	st, e := s.acquire()
	if e != nil {
		return out, e
	}
	defer st.mu.RUnlock()
	if caller.Role == NativeMemberReaderRole {
		done, err := st.enterReadContext()
		if err != nil {
			return out, err
		}
		defer done()
	}
	e = st.effect(ctx, id, func(tx *sql.Tx, p model.CapacityPolicySpec, a model.CapacityNativeWorkerAttempt, r *nativeMemberRecord, now time.Time) error {
		writer := caller.Role == NativeMemberWriterRole
		if !nativeMemberCaller(r.Context, caller, writer) {
			return ErrCapacityMutationAuthorization
		}
		out = model.CapacityNativeWorkerMemberRead{Schema: model.CapacityNativeWorkerMemberReadSchema, BindingName: caller.Binding.Name, Context: r.Context, State: r.State, Redeemable: writer && !st.sealed.Load() && r.State == "issued" && r.DispatchStartedAt != nil && r.Context.NotAfter.After(now)}
		if writer {
			return nil
		}
		readID := uuid.New()
		kind := "kubelet_configz"
		if r.Context.Action == "delete_node" || r.Context.Action == "retire_registry" {
			kind = "member_inventory"
		}
		rr := nativeMemberReadRecord{ReadID: readID, PermitID: id, ContextSHA256: capacity.NativeWorkerMemberContextSHA(r.Context), SubjectNodeUID: r.Context.Node.UID, SDKSourceCommit: caller.Binding.SourceCommit, ScopeSHA256: caller.Binding.ScopeSHA256, Kind: kind, CreatedAt: now}
		raw, e := nativeMemberRecordBytes(rr)
		if e != nil {
			return e
		}
		_, e = tx.ExecContext(ctx, `INSERT INTO public.capacity_native_worker_member_reads(id,permit_id,policy_id,namespace,context_sha256,endpoint_kind,source_commit,scope_sha256,subject_node_uid,state,record,created_at,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,'issued',$10,$11,$11)`, readID, id, st.policy.ID, st.policy.Metadata.Namespace, rr.ContextSHA256, rr.Kind, rr.SDKSourceCommit, rr.ScopeSHA256, rr.SubjectNodeUID, raw, now)
		if e != nil {
			return e
		}
		plan, _ := nativeMemberUUID(r.Context.PlanID)
		if e = nativeMemberEventTx(ctx, tx, st.policy, plan, id, readID, "read_issued", rr, now); e != nil {
			return e
		}
		out.ReadID = readID.String()
		return nil
	})
	return out, e
}

func (s *CapacityNativeWorkerMemberStore) ReadAllocatorFence(ctx context.Context, in model.CapacityNativeWorkerMemberSelectors, caller NativeWorkerMemberCaller) (model.CapacityNativeWorkerAllocatorFenceRead, error) {
	var out model.CapacityNativeWorkerAllocatorFenceRead
	id, e := nativeMemberSelectors(in, caller)
	if e != nil {
		return out, e
	}
	st, e := s.acquire()
	if e != nil {
		return out, e
	}
	defer st.mu.RUnlock()
	p, e := parseCapacityPolicy(st.policy)
	if e != nil || p.NativeWorkerLifecycleBinding == nil || p.NativeWorkerLifecycleBinding.Members == nil || p.NativeWorkerPoolBinding == nil {
		return out, ErrCapacityDisabled
	}
	b, pool := p.NativeWorkerLifecycleBinding.Members, p.NativeWorkerPoolBinding
	if caller.Role != NativeAllocatorFenceReaderRole || caller.Binding != b.AllocatorFenceReader {
		return out, ErrCapacityMutationAuthorization
	}
	a, e := st.workers.Read(ctx, st.policy, id)
	if e != nil || a.State == "absent" || a.State == "no_effect" {
		return out, errNativeMember
	}
	var command []byte
	var c nativeWorkerCommandContext
	e = st.workers.Capacity.DB.QueryRowContext(ctx, `SELECT record FROM public.capacity_native_worker_command_contexts WHERE attempt_id=$1`, id).Scan(&command)
	if e != nil || json.Unmarshal(command, &c) != nil || c.AttemptID != id || c.PolicyID != st.policy.ID || c.PolicyChecksum != st.policy.Checksum || c.Namespace != st.policy.Metadata.Namespace || c.Generation != a.Generation || c.FencingToken != a.FencingToken {
		return out, errNativeMember
	}
	out = model.CapacityNativeWorkerAllocatorFenceRead{Schema: model.CapacityNativeWorkerAllocatorFenceReadSchema, BindingName: caller.Binding.Name, Context: model.CapacityNativeWorkerAllocatorFenceContext{Schema: model.CapacityNativeWorkerAllocatorFenceContextSchema, CreatorPermitID: id.String(), AttemptID: id.String(), CoreSourceCommit: a.SourceCommit, Observer: capacity.NativeWorkerMemberEndpoint(b.AllocatorFenceReader, "observe_native_worker_allocator_fence"), PolicyID: a.PolicyID.String(), PolicyChecksum: a.PolicyChecksum, IntentGeneration: a.Generation, FencingToken: a.FencingToken, RealmUID: pool.RealmUID, PoolUID: pool.PoolUID, Owner: pool.Owner, Epoch: pool.ExpectedPoolEpoch, BootstrapPolicySHA256: b.BootstrapPolicySHA256, NotAfter: c.ExpiresAt}}
	return out, nil
}

func (s *CapacityNativeWorkerMemberStore) Receive(ctx context.Context, received model.CapacityNativeWorkerMemberReceive, caller NativeWorkerMemberCaller) error {
	id, e := nativeMemberUUID(received.PermitID)
	if e != nil {
		return e
	}
	if len(received.OriginalReturn) > model.CapacityNativeWorkerMemberMaxOriginalBytes || received.Schema != model.CapacityNativeWorkerMemberReceiveSchema {
		return errNativeMember
	}
	tokenSHA, ok := nativeReadinessTokenSHA(received.SettlementToken)
	if !ok {
		return errNativeMember
	}
	raw, e := received.PrivateJSON()
	defer clear(raw)
	if e != nil || len(raw) > model.CapacityNativeWorkerMemberMaxReceiveBytes {
		return errNativeMember
	}
	packed, e := nativeMemberPackOriginal(raw, received.OriginalReturn)
	defer clear(packed)
	if e != nil {
		return e
	}
	st, e := s.acquire()
	if e != nil {
		return e
	}
	defer st.mu.RUnlock()
	return st.effect(ctx, id, func(tx *sql.Tx, _ model.CapacityPolicySpec, _ model.CapacityNativeWorkerAttempt, r *nativeMemberRecord, now time.Time) error {
		if !nativeMemberCaller(r.Context, caller, true) || received.BindingName != caller.Binding.Name || subtle.ConstantTimeCompare([]byte(tokenSHA), []byte(r.SettlementTokenSHA256)) != 1 || r.State == "issued" || r.State == "preparing" {
			return ErrCapacityMutationAuthorization
		}
		previous := r.Original
		sealed, e := st.capture(r.Context, "writer-original/"+tokenSHA, r.Original, packed)
		if e != nil {
			return e
		}
		if previous != nil {
			return nil
		}
		r.Original = sealed
		if r.State == "redeemed" {
			r.State = "received"
		}
		r.Revision++
		return nativeMemberWriteTx(ctx, tx, st.policy, *r, false, now)
	})
}

func (s *CapacityNativeWorkerMemberStore) ReceiveRead(ctx context.Context, received model.CapacityNativeWorkerMemberReadOriginal, caller NativeWorkerMemberCaller) error {
	id, e := nativeMemberUUID(received.PermitID)
	if e != nil {
		return e
	}
	readID, e := nativeMemberUUID(received.ReadID)
	if e != nil {
		return e
	}
	if received.Schema != model.CapacityNativeWorkerMemberReadOriginalSchema || received.Kind != "kubelet_configz" || len(received.OriginalReturn) > model.CapacityNativeWorkerMemberMaxOriginalBytes {
		return errNativeMember
	}
	raw, e := received.PrivateJSON()
	defer clear(raw)
	if e != nil || len(raw) > model.CapacityNativeWorkerMemberMaxReceiveBytes {
		return errNativeMember
	}
	packed, e := nativeMemberPackOriginal(raw, received.OriginalReturn)
	defer clear(packed)
	if e != nil {
		return e
	}
	st, e := s.acquire()
	if e != nil {
		return e
	}
	defer st.mu.RUnlock()
	return st.effect(ctx, id, func(tx *sql.Tx, _ model.CapacityPolicySpec, _ model.CapacityNativeWorkerAttempt, r *nativeMemberRecord, now time.Time) error {
		if !nativeMemberCaller(r.Context, caller, false) || received.BindingName != caller.Binding.Name {
			return ErrCapacityMutationAuthorization
		}
		rr, e := nativeMemberReadLoadTx(ctx, tx, st.policy, readID)
		if e != nil || rr.PermitID != id || rr.Kind != received.Kind || rr.ContextSHA256 != capacity.NativeWorkerMemberContextSHA(r.Context) || rr.SubjectNodeUID != r.Context.Node.UID || rr.SDKSourceCommit != caller.Binding.SourceCommit || rr.ScopeSHA256 != caller.Binding.ScopeSHA256 {
			return errNativeMember
		}
		previous := rr.PrivateOriginal
		sealed, e := st.capture(r.Context, "read/"+readID.String(), rr.PrivateOriginal, packed)
		if e != nil {
			return e
		}
		if previous != nil {
			return nil
		}
		rr.PrivateOriginal = sealed
		stored, e := nativeMemberRecordBytes(rr)
		if e != nil {
			return e
		}
		result, e := tx.ExecContext(ctx, `UPDATE public.capacity_native_worker_member_reads SET state='captured',record=$2,updated_at=$3 WHERE id=$1 AND state='issued'`, readID, stored, now)
		if e != nil {
			return e
		}
		n, e := result.RowsAffected()
		if e != nil || n != 1 {
			return errNativeMember
		}
		plan, _ := nativeMemberUUID(r.Context.PlanID)
		return nativeMemberEventTx(ctx, tx, st.policy, plan, id, readID, "read_captured", rr, now)
	})
}
