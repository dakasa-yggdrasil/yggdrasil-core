package repository

import (
	"context"
	"database/sql"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

func (s *CapacityNativeWorkerMemberStore) removeRetirementNetwork(ctx context.Context, planID uuid.UUID, a model.CapacityNativeWorkerAttempt) error {
	st, e := s.acquire()
	if e != nil {
		return e
	}
	if st.abort == nil || st.network == nil {
		st.mu.RUnlock()
		return ErrCapacityDisabled
	}
	abort, network, policy := st.abort, st.network, st.policy
	workers := st.workers
	st.mu.RUnlock()
	_, o, e := abort.observe(ctx, policy, a.ID)
	if e != nil {
		return e
	}
	if o.NetworkPeerAbsent && o.IPAMEntryAbsent {
		return nil
	}
	store := CapacityNativeWorkerNetworkStore{Workers: workers, Runtime: network, AbortRuntime: abort.Runtime, RecoveryWorkflowID: abort.RecoveryWorkflowID, Enabled: abort.Enabled}
	g, e := store.Begin(ctx, policy, a.ID, "remove")
	if e != nil {
		return e
	}
	id, e := nativeMemberUUID(g.PermitID)
	if e != nil {
		return e
	}
	if g.State == "issued" {
		claimed, e := s.claimRetirementRPC(ctx, planID, "network", id, g.ExpiresAt)
		if e != nil {
			return e
		}
		if claimed {
			bounded, cancel := context.WithDeadline(ctx, g.ExpiresAt)
			_, _ = network.RequestNetworkMutation(bounded, policy, "remove", id)
			cancel()
		}
	}
	st, e = s.acquire()
	if e != nil {
		return e
	}
	p, e := parseCapacityPolicy(st.policy)
	st.mu.RUnlock()
	if e != nil {
		return e
	}
	w := p.NativeWorkerLifecycleBinding.Network.Writer
	caller := CapacityNativeWorkerNetworkCaller{PrincipalID: w.PrincipalID, InstanceID: w.AdapterID, SystemSourceCommit: w.SystemSourceCommit, BindingName: w.BindingName, Capability: capacity.NativeWorkerNetworkRemove}
	read, e := store.Reconcile(ctx, policy, id, caller)
	if e != nil || read.State != "observed" {
		return errNativeMember
	}
	return nil
}

func (st *nativeMemberStoreState) joinedMemberEffectsTx(ctx context.Context, tx *sql.Tx, planID uuid.UUID, now time.Time) error {
	rows, e := tx.QueryContext(ctx, `SELECT CASE WHEN octet_length(record::text)<=8388608 THEN record END FROM public.capacity_native_worker_member_permits WHERE plan_id=$1 ORDER BY id FOR UPDATE`, planID)
	if e != nil {
		return e
	}
	defer rows.Close()
	for rows.Next() {
		var raw []byte
		var r nativeMemberRecord
		if rows.Scan(&raw) != nil || nativeMemberDecode(raw, &r) != nil {
			return errNativeMember
		}
		if r.SeedID == uuid.Nil && r.State == "no_effect" {
			continue
		}
		if r.State != "observed" && r.State != "no_effect" {
			return errNativeMember
		}
		if r.SettlementTokenSHA256 == "" {
			if r.DispatchStartedAt != nil {
				return errNativeMember
			}
			continue
		}
		original, e := st.original(r)
		if e != nil || !nativeMemberOriginalCompleted(r, original, now) {
			return errNativeMember
		}
	}
	return rows.Err()
}

// Member completion does not call an early Abort.Reconcile which could release
// IPAM before the member transaction. It preserves that existing exact settled
// predicate and writes its normal Attempt/abort history in this SAME commit.
func (s *CapacityNativeWorkerMemberStore) finishRetirement(ctx context.Context, planID uuid.UUID, last nativeMemberRecord) error {
	st, e := s.acquire()
	if e != nil {
		return e
	}
	if st.abort == nil {
		st.mu.RUnlock()
		return ErrCapacityDisabled
	}
	abort, policy, runtime := st.abort, st.policy, st.runtime
	id, e := nativeMemberUUID(last.Context.AttemptID)
	st.mu.RUnlock()
	if e != nil {
		return e
	}
	a, o, e := abort.observe(ctx, policy, id)
	if e != nil || !capacity.NativeWorkerAbortSettled(o) {
		return errNativeMember
	}
	observed, e := runtime.Observe(ctx, a, last.Context)
	if e != nil {
		return e
	}
	_, fence, e := runtime.AllocatorFence(ctx, a)
	if e != nil {
		return e
	}
	st, e = s.acquire()
	if e != nil {
		return e
	}
	defer st.mu.RUnlock()
	p, e := parseCapacityPolicy(st.policy)
	if e != nil {
		return e
	}
	fc, e := nativeMemberFenceContext(ctx, st.workers.Capacity.DB, policy, p, a)
	if e != nil || !capacity.NativeWorkerMemberCurrentFenceValid(p, fc, fence, st.authority, time.Now().UTC()) || capacity.NativeWorkerMemberCurrentObservationValid(p, a, last.Context, observed, st.authority, time.Now().UTC()) != nil || !nativeMemberEffectObserved(last.Context, observed) {
		return errNativeMember
	}
	return st.workers.tx(ctx, policy, func(tx *sql.Tx, p model.CapacityPolicySpec, now time.Time) error {
		actual, _, e := nativeAttemptLoadTx(ctx, tx, policy, id)
		if e != nil {
			return e
		}
		plan, e := nativeMemberPlanLoadTx(ctx, tx, policy, planID)
		if e != nil {
			return e
		}
		if plan.State == "settled" {
			return nil
		}
		if st.sealed.Load() || actual.Revision != a.Revision || actual.State != "aborting" || plan.Identity.Kind != "retirement" || plan.Identity.Mode != "never_admitted" || plan.PhysicalAbsence == nil || plan.NodeAbsence == nil || plan.ProviderPermitID == uuid.Nil {
			return errNativeMember
		}
		if e = nativeMemberRetirementFenceTx(ctx, tx, policy, actual, now); e != nil {
			return e
		}
		if e = st.joinedMemberEffectsTx(ctx, tx, planID, now); e != nil {
			return e
		}
		original, e := abortLoadTx(ctx, tx, policy, plan.ProviderPermitID)
		if e != nil || original.Context.AttemptID != id || !nativeMemberProviderOriginalComplete(original) {
			return errNativeMember
		}
		if e = abort.current(ctx, tx, policy, p, actual, now); e != nil {
			return e
		}
		if e = tx.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&now); e != nil {
			return e
		}
		if !capacity.NativeWorkerAbortObservationValid(p, actual, o, now) || !capacity.NativeWorkerAbortSettled(o) || !capacity.NativeWorkerMemberCurrentFenceValid(p, fc, fence, st.authority, now) || capacity.NativeWorkerMemberCurrentObservationValid(p, actual, last.Context, observed, st.authority, now) != nil || !nativeMemberEffectObserved(last.Context, observed) {
			return errNativeMember
		}
		// The unique live-IPAM index is released only by this retained absent
		// Attempt transition, after all independent facts and original joins.
		actual.State = "absent"
		actual.Revision++
		actual.UpdatedAt = now
		if e = nativeAttemptWriteTx(ctx, tx, actual, nil, false, nil); e != nil {
			return e
		}
		original.Context.State = "observed"
		original.Observation = &o
		original.Revision++
		if e = abortWriteTx(ctx, tx, original, false, now); e != nil {
			return e
		}
		plan.State = "settled"
		plan.Revision++
		if e = nativeMemberPlanWriteTx(ctx, tx, policy, plan, false, now); e != nil {
			return e
		}
		_, e = EmitEvent(ctx, tx, model.EmitEventRequest{Type: "kubernetes.native_worker_pool_member.destroyed", SchemaVersion: "v1", AggregateType: "native_worker_pool_member", AggregateID: planID.String(), IdempotencyKey: planID.String() + "/" + last.Context.Node.UID + "/composed_destroyed", Payload: map[string]any{"provider": "kubernetes", "resource": "native_worker_pool_member", "verb": "destroyed", "resource_id": last.Context.Node.UID, "instance_id": last.Context.Actor.Adapter.ManifestID, "observed": map[string]any{"plan_id": planID.String(), "attempt_id": id.String(), "node_uid": last.Context.Node.UID, "birth_sha256": a.BirthSHA256, "state": "member_absent", "basis": "complete_independent_provider_node_registry_network_and_original_custody", "observed_at": o.ObservedAt, "automatic_retry_permitted": false}}})
		return e
	})
}
