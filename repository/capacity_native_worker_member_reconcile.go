package repository

import (
	"context"
	"database/sql"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

func (st *nativeMemberStoreState) original(r nativeMemberRecord) (model.CapacityNativeWorkerMemberReceive, error) {
	var out model.CapacityNativeWorkerMemberReceive
	if r.Original == nil || r.SettlementTokenSHA256 == "" {
		return out, errNativeMember
	}
	_, raw, e := st.crypt(r.Context, "writer-original/"+r.SettlementTokenSHA256, r.Original, nil)
	defer clear(raw)
	var envelope nativeMemberPrivateOriginal
	if e != nil || nativeMemberDecode(raw, &envelope) != nil || nativeMemberDecode(envelope.Wire, &out) != nil || envelope.BodySHA256 != nativeMemberRawSHA(out.OriginalReturn) {
		return out, errNativeMember
	}
	return out, nil
}
func nativeMemberOriginalCompleted(r nativeMemberRecord, o model.CapacityNativeWorkerMemberReceive, now time.Time) bool {
	return r.RedeemedAt != nil && o.CaptureComplete && o.TransportCompleted && o.ErrorClass == "" && !o.CompletedAt.Before(*r.RedeemedAt) && !o.CompletedAt.After(now) && !o.CompletedAt.IsZero() && o.HTTPStatus >= 100 && o.HTTPStatus <= 599
}

// Goal readback is distinct from old preimage validation. It changes neither
// the immutable Context nor its expiry. No event claims a provider deletion or
// composed member retirement from a single Node/Pod/Lease ACK.
func nativeMemberEffectObserved(c model.CapacityNativeWorkerMemberContext, o model.CapacityNativeWorkerMemberObservation) bool {
	phase := o.Inventory.Phase
	switch c.Action {
	case "cordon":
		return len(phase.Candidates) == 1 && phase.Candidates[0].NodeUID == c.Node.UID && phase.Candidates[0].Unschedulable
	case "bind_pod":
		if o.SubjectPod == nil || o.SubjectPod.Identity.UID != c.Pod.UID || o.SubjectPod.NodeName != c.Node.Name {
			return false
		}
		for _, pod := range o.Pods {
			if pod.Identity.UID == c.Pod.UID && pod.NodeName == c.Node.Name && pod.Identity.ResourceVersion == o.SubjectPod.Identity.ResourceVersion {
				return true
			}
		}
	case "evict_pod":
		for _, pod := range o.Pods {
			if pod.Identity.UID == c.Pod.UID {
				return false
			}
		}
		return true
	case "delete_node":
		return phase.CandidateAbsenceProven && len(phase.Candidates) == 0 && len(o.Pods) == 0
	case "retire_registry":
		if !phase.CandidateAbsenceProven || len(phase.Candidates) != 0 || len(o.Pods) != 0 {
			return false
		}
		for _, entry := range phase.Registrations {
			if entry.NodeUID == c.Node.UID || entry.ProviderID == c.Physical.ProviderID {
				return false
			}
		}
		return true
	}
	return false
}

func nativeMemberPublicEventTx(ctx context.Context, tx *sql.Tx, r nativeMemberRecord) error {
	c := r.Context
	verb, resource := "", ""
	if c.Action == "cordon" {
		verb, resource = "ensured", "native_worker_pool_member"
	}
	if c.Action == "bind_pod" {
		verb, resource = "ensured", "native_worker_pod_placement"
	}
	if c.Action == "evict_pod" && c.Actor.Capability == "destroy_native_worker_pod_placement" {
		verb, resource = "destroyed", "native_worker_pod_placement"
	}
	if verb == "" {
		return nil
	}
	uid := c.Node.UID
	if c.Pod != nil {
		uid = c.Pod.UID
	}
	safe := map[string]any{"plan_id": c.PlanID, "permit_id": c.PermitID, "action": c.Action, "state": r.State, "node_uid": c.Node.UID, "birth_sha256": c.BirthSHA256, "observed_at": r.Observed.ObservedAt, "basis": "independent_current_read", "automatic_retry_permitted": false}
	_, e := EmitEvent(ctx, tx, model.EmitEventRequest{Type: "kubernetes." + resource + "." + verb, SchemaVersion: "v1", AggregateType: resource, AggregateID: c.PlanID, IdempotencyKey: c.PlanID + "/" + c.PermitID + "/" + uid + "/" + verb, Payload: map[string]any{"provider": "kubernetes", "resource": resource, "verb": verb, "resource_id": uid, "instance_id": c.Actor.Adapter.ManifestID, "observed": safe}})
	return e
}

func (s *CapacityNativeWorkerMemberStore) Reconcile(ctx context.Context, in model.CapacityNativeWorkerMemberSelectors, caller NativeWorkerMemberCaller) (model.CapacityNativeWorkerMemberRead, error) {
	var out model.CapacityNativeWorkerMemberRead
	if caller.Role != NativeMemberControllerRole || in.BindingName != caller.Binding.Name {
		return out, ErrCapacityMutationAuthorization
	}
	id, e := nativeMemberUUID(in.PermitID)
	if e != nil {
		return out, e
	}
	st, e := s.acquire()
	if e != nil {
		return out, e
	}
	r, e := st.snapshot(ctx, id)
	p, pe := parseCapacityPolicy(st.policy)
	var a model.CapacityNativeWorkerAttempt
	if e == nil {
		attempt, parseErr := nativeMemberUUID(r.Context.AttemptID)
		if parseErr != nil {
			e = parseErr
		} else {
			a, e = st.workers.Read(ctx, st.policy, attempt)
		}
	}
	runtime := st.runtime
	st.mu.RUnlock()
	if e != nil || pe != nil || p.NativeWorkerLifecycleBinding == nil || p.NativeWorkerLifecycleBinding.Members == nil || in.BindingName != p.NativeWorkerLifecycleBinding.Members.Name || caller.Binding.SourceCommit != p.NativeWorkerLifecycleBinding.SourceCommit || caller.Binding.ScopeSHA256 != st.scope {
		return out, errNativeMember
	}
	if r.State == "preparing" || r.State == "issued" || r.State == "no_effect" || r.State == "observed" || r.State == "member_absent" {
		return model.CapacityNativeWorkerMemberRead{Schema: model.CapacityNativeWorkerMemberReadSchema, BindingName: in.BindingName, Context: r.Context, State: r.State}, nil
	}
	observed, e := runtime.Observe(ctx, a, r.Context)
	if e != nil || ctx.Err() != nil {
		return out, errNativeMember
	}
	st, e = s.acquire()
	if e != nil {
		return out, e
	}
	defer st.mu.RUnlock()
	if capacity.NativeWorkerMemberCurrentObservationValid(p, a, r.Context, observed, st.authority, time.Now().UTC()) != nil || st.verifyConfigz(ctx, r.Context, observed, time.Now().UTC()) != nil {
		return out, errNativeMember
	}
	e = st.effect(ctx, id, func(tx *sql.Tx, p model.CapacityPolicySpec, actual model.CapacityNativeWorkerAttempt, current *nativeMemberRecord, now time.Time) error {
		if capacity.NativeWorkerMemberContextSHA(current.Context) != capacity.NativeWorkerMemberContextSHA(r.Context) {
			return errNativeMember
		}
		if capacity.NativeWorkerMemberCurrentObservationValid(p, actual, current.Context, observed, st.authority, now) != nil {
			return errNativeMember
		}
		if current.State == "observed" || current.State == "member_absent" || current.State == "no_effect" {
			out = model.CapacityNativeWorkerMemberRead{Schema: model.CapacityNativeWorkerMemberReadSchema, BindingName: in.BindingName, Context: current.Context, State: current.State}
			return nil
		}
		if current.State == "redeemed" {
			current.State = "unknown"
			current.Revision++
			if e := nativeMemberWriteTx(ctx, tx, st.policy, *current, false, now); e != nil {
				return e
			}
		}
		original, originalErr := st.original(*current)
		if originalErr == nil && nativeMemberOriginalCompleted(*current, original, now) && nativeMemberDefinitiveNoEffect(current.Context, original) {
			current.State = "no_effect"
		} else if nativeMemberEffectObserved(current.Context, observed) {
			current.State = "observed"
			current.Observed = &observed
		} else {
			current.State = "unknown"
		}
		current.Revision++
		if e := nativeMemberWriteTx(ctx, tx, st.policy, *current, false, now); e != nil {
			return e
		}
		if current.State == "observed" {
			if e := nativeMemberPublicEventTx(ctx, tx, *current); e != nil {
				return e
			}
		}
		out = model.CapacityNativeWorkerMemberRead{Schema: model.CapacityNativeWorkerMemberReadSchema, BindingName: in.BindingName, Context: current.Context, State: current.State}
		return nil
	})
	return out, e
}

// Only never-exposed rights can be cancelled. The DB row lock excludes a
// concurrent Redeem and the clock is reread after it; a late actor cannot obtain
// a token after the immutable expiry. UNKNOWN/redeemed never expire free.
func (s *CapacityNativeWorkerMemberStore) CancelUnexposed(ctx context.Context, id uuid.UUID) error {
	st, e := s.acquire()
	if e != nil {
		return e
	}
	defer st.mu.RUnlock()
	return st.effect(ctx, id, func(tx *sql.Tx, _ model.CapacityPolicySpec, _ model.CapacityNativeWorkerAttempt, r *nativeMemberRecord, now time.Time) error {
		if r.State != "preparing" && r.State != "issued" || r.SettlementTokenSHA256 != "" || r.Original != nil {
			return errNativeMember
		}
		if e := tx.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&now); e != nil || r.Context.NotAfter.After(now) {
			return errNativeMember
		}
		r.State = "no_effect"
		r.Revision++
		if e := nativeMemberWriteTx(ctx, tx, st.policy, *r, false, now); e != nil {
			return e
		}
		planID, e := nativeMemberUUID(r.Context.PlanID)
		if e != nil {
			return e
		}
		plan, e := nativeMemberPlanLoadTx(ctx, tx, st.policy, planID)
		if e != nil {
			return e
		}
		cancelPlan := plan.Identity.Kind == "placement" || plan.Identity.Kind == "read_preflight"
		if plan.Identity.Kind == "retirement" && r.Context.Action == "cordon" {
			var remaining bool
			if e = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM public.capacity_native_worker_member_permits WHERE plan_id=$1 AND state NOT IN('preparing','no_effect'))`, planID).Scan(&remaining); e != nil {
				return e
			}
			cancelPlan = !remaining
		}
		if cancelPlan && (plan.State == "preparing" || plan.State == "active") {
			plan.State = "cancelled"
			plan.Revision++
			return nativeMemberPlanWriteTx(ctx, tx, st.policy, plan, false, now)
		}
		return nil
	})
}
