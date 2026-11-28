package repository

import (
	"context"
	"database/sql"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

func nativeMemberPhysicalAbsent(o model.CapacityNativeWorkerAbortObservation) bool {
	return (o.ProviderOutcome == "not_found" || o.ProviderOutcome == "terminal_nonbillable") && o.AncillaryChargesClosed && capacity.ValidDigest(o.ProviderEvidenceSHA256) && capacity.ValidDigest(o.ChargeEvidenceSHA256)
}
func nativeMemberEffectiveFactsEnd(p model.CapacityPolicySpec, a model.CapacityNativeWorkerAttempt, f capacity.NativeWorkerMemberFacts) time.Time {
	if f.Absence == nil {
		return capacity.NativeWorkerMemberFactsValidUntil(p, a, f)
	}
	if p.NativeWorkerLifecycleBinding == nil || p.NativeWorkerLifecycleBinding.Members == nil {
		return time.Time{}
	}
	age := time.Duration(p.NativeWorkerLifecycleBinding.Members.MaxReadAgeSeconds) * time.Second
	end := f.Observation.ObservedAt.Add(age)
	for _, at := range []time.Time{f.Observation.Inventory.ObservedAt, f.Observation.Inventory.Phase.ObservedAt, f.Fence.ObservedAt, f.Absence.ObservedAt} {
		if at.IsZero() {
			return time.Time{}
		}
		end = nativeMemberMin(end, at.Add(age))
	}
	if len(f.Fence.Enforcement) == 0 {
		return time.Time{}
	}
	for _, proof := range f.Fence.Enforcement {
		if proof.ObservedAt.IsZero() {
			return time.Time{}
		}
		end = nativeMemberMin(end, proof.ObservedAt.Add(age))
	}
	return end
}
func (st *nativeMemberStoreState) collectFacts(ctx context.Context, a model.CapacityNativeWorkerAttempt, c model.CapacityNativeWorkerMemberContext) (capacity.NativeWorkerMemberFacts, error) {
	if c.Action != "delete_node" && c.Action != "retire_registry" {
		return st.runtime.Facts(ctx, a, c)
	}
	var out capacity.NativeWorkerMemberFacts
	if st.abort == nil {
		return out, ErrCapacityDisabled
	}
	observed, e := st.runtime.Observe(ctx, a, c)
	if e != nil {
		return out, e
	}
	_, absence, e := st.abort.observe(ctx, st.policy, a.ID)
	if e != nil {
		return out, e
	}
	_, fence, e := st.runtime.AllocatorFence(ctx, a)
	if e != nil {
		return out, e
	}
	p, e := parseCapacityPolicy(st.policy)
	if e != nil {
		return out, e
	}
	out = capacity.NativeWorkerMemberFacts{Observation: observed, Fence: fence, Absence: &absence}
	out.ValidUntil = nativeMemberEffectiveFactsEnd(p, a, out)
	return out, nil
}
func (st *nativeMemberStoreState) validateAbsentFacts(ctx context.Context, p model.CapacityPolicySpec, a model.CapacityNativeWorkerAttempt, c model.CapacityNativeWorkerMemberContext, f capacity.NativeWorkerMemberFacts, seed bool, now time.Time) error {
	if f.Absence == nil || !nativeMemberPhysicalAbsent(*f.Absence) || !capacity.NativeWorkerAbortObservationValid(p, a, *f.Absence, now) || capacity.NativeWorkerMemberObservationValid(p, a, c, f.Observation, st.authority, now, seed) != nil || !nativeMemberEffectiveFactsEnd(p, a, f).After(now) {
		return errNativeMember
	}
	fc, e := nativeMemberFenceContext(ctx, st.workers.Capacity.DB, st.policy, p, a)
	if e != nil || !capacity.NativeWorkerMemberCurrentFenceValid(p, fc, f.Fence, st.authority, now) {
		return errNativeMember
	}
	return nil
}

func (st *nativeMemberStoreState) plan(ctx context.Context, id uuid.UUID) (nativeMemberPlanRecord, error) {
	var out nativeMemberPlanRecord
	e := st.workers.tx(ctx, st.policy, func(tx *sql.Tx, _ model.CapacityPolicySpec, _ time.Time) error {
		var attempt uuid.UUID
		if e := tx.QueryRowContext(ctx, `SELECT attempt_id FROM public.capacity_native_worker_member_plans WHERE id=$1 AND policy_id=$2 AND namespace=$3`, id, st.policy.ID, st.policy.Metadata.Namespace).Scan(&attempt); e != nil {
			return e
		}
		if _, _, e := nativeAttemptLoadTx(ctx, tx, st.policy, attempt); e != nil {
			return e
		}
		var e error
		out, e = nativeMemberPlanLoadTx(ctx, tx, st.policy, id)
		return e
	})
	return out, e
}

// Create the next read seed from THIS immutable retirement lineage. The caller
// cannot supply mode, a different Node/Pod, URL or physical-absence claim.
func (s *CapacityNativeWorkerMemberStore) nextRetirementSeed(ctx context.Context, planID uuid.UUID, action string, pod *model.CapacityNativeWorkerMemberPod) (model.CapacityNativeWorkerMemberContext, error) {
	var out model.CapacityNativeWorkerMemberContext
	st, e := s.acquire()
	if e != nil {
		return out, e
	}
	defer st.mu.RUnlock()
	e = st.workers.tx(ctx, st.policy, func(tx *sql.Tx, p model.CapacityPolicySpec, now time.Time) error {
		var attemptID uuid.UUID
		if e := tx.QueryRowContext(ctx, `SELECT attempt_id FROM public.capacity_native_worker_member_plans WHERE id=$1 AND policy_id=$2 AND namespace=$3`, planID, st.policy.ID, st.policy.Metadata.Namespace).Scan(&attemptID); e != nil {
			return e
		}
		a, _, e := nativeAttemptLoadTx(ctx, tx, st.policy, attemptID)
		if e != nil {
			return e
		}
		plan, e := nativeMemberPlanLoadTx(ctx, tx, st.policy, planID)
		if e != nil {
			return e
		}
		if st.sealed.Load() || plan.Identity.Kind != "retirement" || plan.Identity.Mode != "never_admitted" || plan.State != "active" || plan.SealedFacts == nil {
			return errNativeMember
		}
		if e = st.parentCurrentTx(ctx, tx, p, a, "retirement", now); e != nil {
			return e
		}
		cap := capacity.NativeWorkerMemberCapability(action, "retirement")
		if cap == "" || action == "bind_pod" || action == "cordon" {
			return errNativeMember
		}
		var c model.CapacityNativeWorkerMemberContext
		// Reuse sealed semantic identity, not an old mutation Context or token.
		var previous nativeMemberRecord
		var raw []byte
		if e = tx.QueryRowContext(ctx, `SELECT CASE WHEN octet_length(record::text)<=8388608 THEN record END FROM public.capacity_native_worker_member_permits WHERE plan_id=$1 AND state='observed' ORDER BY created_at DESC,id DESC LIMIT 1`, planID).Scan(&raw); e != nil || nativeMemberDecode(raw, &previous) != nil {
			return errNativeMember
		}
		c = previous.Context
		c.PermitID = uuid.NewString()
		c.Action = action
		c.Actor.Capability = cap
		c.Observer.Capability = capacity.NativeWorkerMemberReadCapability(action)
		c.PlacementFenceSHA256 = ""
		c.RegistryResourceVersion = ""
		c.RegistrySHA256 = ""
		c.Pod = nil
		if pod != nil {
			copy := *pod
			c.Pod = &copy
		}
		if action == "evict_pod" && pod == nil {
			return errNativeMember
		}
		if action == "delete_node" || action == "retire_registry" {
			if plan.PhysicalAbsence == nil || !nativeMemberPhysicalAbsent(*plan.PhysicalAbsence) {
				return errNativeMember
			}
			c.PhysicalAbsenceEvidenceSHA256 = nativeMemberDigest(*plan.PhysicalAbsence)
		}
		if action == "retire_registry" {
			if plan.NodeAbsence == nil || !plan.NodeAbsence.Inventory.Phase.CandidateAbsenceProven {
				return errNativeMember
			}
			c.NodeAbsenceEvidenceSHA256 = nativeMemberDigest(*plan.NodeAbsence)
			c.RegistryResourceVersion = plan.NodeAbsence.Inventory.Phase.Registry.ResourceVersion
			c.RegistrySHA256 = plan.NodeAbsence.Inventory.Phase.Registry.AnnotationSHA256
		}
		c.NotAfter = now.Add(time.Duration(p.NativeWorkerLifecycleBinding.Members.MaxPermitSeconds) * time.Second)
		if deadline, ok := ctx.Deadline(); ok {
			c.NotAfter = nativeMemberMin(c.NotAfter, deadline)
		}
		if capacity.NativeWorkerMemberContextValid(p, a, c, now, true) != nil {
			return errNativeMember
		}
		if e = nativeMemberWriteTx(ctx, tx, st.policy, nativeMemberRecord{Context: c, State: "preparing", Revision: 1}, true, now); e != nil {
			return e
		}
		out = c
		return nil
	})
	return out, e
}
