package repository

import (
	"context"
	"database/sql"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

type nativeMemberNetworkPreflight struct {
	PlanID       uuid.UUID
	Context      model.CapacityNativeWorkerMemberContext
	Facts        capacity.NativeWorkerMemberFacts
	FenceContext model.CapacityNativeWorkerAllocatorFenceContext
}

func (s *CapacityNativeWorkerMemberStore) networkPreflight(ctx context.Context, a model.CapacityNativeWorkerAttempt) (*nativeMemberNetworkPreflight, error) {
	st, e := s.acquire()
	if e != nil {
		return nil, e
	}
	var raw []byte
	var r nativeMemberRecord
	e = st.workers.Capacity.DB.QueryRowContext(ctx, `SELECT CASE WHEN octet_length(p.record::text)<=8388608 THEN p.record END FROM public.capacity_native_worker_member_permits p JOIN public.capacity_native_worker_member_plans plan ON plan.id=p.plan_id WHERE p.attempt_id=$1 AND plan.kind='retirement' AND plan.mode='never_admitted' AND plan.state='active' AND p.action='retire_registry' AND p.state='observed' ORDER BY p.created_at DESC,p.id DESC LIMIT 1`, a.ID).Scan(&raw)
	if e != nil || nativeMemberDecode(raw, &r) != nil {
		st.mu.RUnlock()
		return nil, errNativeMember
	}
	st.mu.RUnlock()
	plan, e := nativeMemberUUID(r.Context.PlanID)
	if e != nil {
		return nil, e
	}
	facts, e := st.collectFacts(ctx, a, r.Context)
	if e != nil {
		return nil, e
	}
	st, e = s.acquire()
	if e != nil {
		return nil, e
	}
	defer st.mu.RUnlock()
	p, e := parseCapacityPolicy(st.policy)
	if e != nil {
		return nil, e
	}
	fc, e := nativeMemberFenceContext(ctx, st.workers.Capacity.DB, st.policy, p, a)
	if e != nil || st.sealed.Load() || facts.Absence == nil || !nativeMemberPhysicalAbsent(*facts.Absence) || !capacity.NativeWorkerAbortObservationValid(p, a, *facts.Absence, time.Now().UTC()) || capacity.NativeWorkerMemberCurrentObservationValid(p, a, r.Context, facts.Observation, st.authority, time.Now().UTC()) != nil || !nativeMemberEffectObserved(r.Context, facts.Observation) || !capacity.NativeWorkerMemberCurrentFenceValid(p, fc, facts.Fence, st.authority, time.Now().UTC()) || !nativeMemberEffectiveFactsEnd(p, a, facts).After(time.Now().UTC()) {
		return nil, errNativeMember
	}
	return &nativeMemberNetworkPreflight{PlanID: plan, Context: r.Context, Facts: facts, FenceContext: fc}, nil
}

func (s *CapacityNativeWorkerMemberStore) networkCurrentTx(ctx context.Context, tx *sql.Tx, p model.CapacityPolicySpec, a model.CapacityNativeWorkerAttempt, permit uuid.UUID, f *nativeMemberNetworkPreflight, now time.Time) error {
	st, e := s.acquire()
	if e != nil {
		return e
	}
	defer st.mu.RUnlock()
	if st.sealed.Load() || f == nil || f.Facts.Absence == nil || f.Context.AttemptID != a.ID.String() {
		return errNativeMember
	}
	plan, e := nativeMemberPlanLoadTx(ctx, tx, st.policy, f.PlanID)
	if e != nil || plan.State != "active" || plan.Identity.Mode != "never_admitted" || plan.Identity.Kind != "retirement" || plan.Identity.AttemptID != a.ID || plan.ProviderDispatchStartedAt == nil || plan.NetworkDispatchStartedAt == nil || plan.NetworkPermitID != permit || plan.PhysicalAbsence == nil || plan.NodeAbsence == nil {
		return errNativeMember
	}
	if e = tx.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&now); e != nil {
		return e
	}
	if !nativeMemberPhysicalAbsent(*f.Facts.Absence) || !capacity.NativeWorkerAbortObservationValid(p, a, *f.Facts.Absence, now) || capacity.NativeWorkerMemberCurrentObservationValid(p, a, f.Context, f.Facts.Observation, st.authority, now) != nil || !nativeMemberEffectObserved(f.Context, f.Facts.Observation) || !capacity.NativeWorkerMemberCurrentFenceValid(p, f.FenceContext, f.Facts.Fence, st.authority, now) || !nativeMemberEffectiveFactsEnd(p, a, f.Facts).After(now) {
		return errNativeMember
	}
	return nil
}
