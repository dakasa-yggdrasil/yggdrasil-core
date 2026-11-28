package repository

import (
	"context"
	"database/sql"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

type nativeMemberAbortPreflight struct {
	PlanID  uuid.UUID
	Context model.CapacityNativeWorkerMemberContext
	Facts   capacity.NativeWorkerMemberFacts
}

// The old abort inventory counts active Pods. Members additionally requires
// the complete roster, including terminal/deleting/DaemonSet Pods, and the
// source-owned producer/placement fence before the SAME provider Redeem.
func (s *CapacityNativeWorkerMemberStore) abortPreflight(ctx context.Context, policy model.Manifest, a model.CapacityNativeWorkerAttempt) (*nativeMemberAbortPreflight, error) {
	st, e := s.acquire()
	if e != nil {
		return nil, e
	}
	if st.sealed.Load() || policy.ID != st.policy.ID || policy.Checksum != st.policy.Checksum {
		st.mu.RUnlock()
		return nil, errNativeMember
	}
	var raw []byte
	var r nativeMemberRecord
	e = st.workers.Capacity.DB.QueryRowContext(ctx, `SELECT CASE WHEN octet_length(p.record::text)<=8388608 THEN p.record END FROM public.capacity_native_worker_member_permits p JOIN public.capacity_native_worker_member_plans plan ON plan.id=p.plan_id WHERE p.attempt_id=$1 AND plan.kind='retirement' AND plan.mode='never_admitted' AND plan.state='active' AND p.action='cordon' AND p.state='observed' ORDER BY p.created_at DESC,p.id DESC LIMIT 1`, a.ID).Scan(&raw)
	runtime := st.runtime
	st.mu.RUnlock()
	if e != nil || nativeMemberDecode(raw, &r) != nil {
		return nil, errNativeMember
	}
	plan, e := nativeMemberUUID(r.Context.PlanID)
	if e != nil {
		return nil, e
	}
	facts, e := runtime.Facts(ctx, a, r.Context)
	if e != nil {
		return nil, errNativeMember
	}
	st, e = s.acquire()
	if e != nil {
		return nil, e
	}
	defer st.mu.RUnlock()
	p, e := parseCapacityPolicy(st.policy)
	if e != nil || st.validateCurrentLiveFacts(ctx, p, a, r.Context, facts, time.Now().UTC()) != nil || len(facts.Observation.Pods) != 0 || len(facts.Observation.Inventory.Phase.Candidates) != 1 || !facts.Observation.Inventory.Phase.Candidates[0].Unschedulable {
		return nil, errNativeMember
	}
	return &nativeMemberAbortPreflight{PlanID: plan, Context: r.Context, Facts: facts}, nil
}

func (st *nativeMemberStoreState) validateCurrentLiveFacts(ctx context.Context, p model.CapacityPolicySpec, a model.CapacityNativeWorkerAttempt, c model.CapacityNativeWorkerMemberContext, f capacity.NativeWorkerMemberFacts, now time.Time) error {
	if capacity.NativeWorkerMemberCurrentObservationValid(p, a, c, f.Observation, st.authority, now) != nil || !capacity.NativeWorkerPlacementBootstrapValid(p, a, c, f.Bootstrap, st.authority, now) || !capacity.NativeWorkerMemberPhysicalFactValid(p, a, f.Physical, now) || !capacity.NativeWorkerMemberFactsValidUntil(p, a, f).After(now) {
		return errNativeMember
	}
	if e := st.verifyConfigz(ctx, c, f.Observation, now); e != nil {
		return e
	}
	fc, e := nativeMemberFenceContext(ctx, st.workers.Capacity.DB, st.policy, p, a)
	if e != nil || !capacity.NativeWorkerMemberCurrentFenceValid(p, fc, f.Fence, st.authority, now) {
		return errNativeMember
	}
	return nil
}

func (s *CapacityNativeWorkerMemberStore) abortCurrentTx(ctx context.Context, tx *sql.Tx, p model.CapacityPolicySpec, a model.CapacityNativeWorkerAttempt, permitID uuid.UUID, f *nativeMemberAbortPreflight, now time.Time) error {
	st, e := s.acquire()
	if e != nil {
		return e
	}
	defer st.mu.RUnlock()
	if st.sealed.Load() || f == nil || len(f.Facts.Observation.Pods) != 0 || f.Context.AttemptID != a.ID.String() || f.Context.Mode != "never_admitted" {
		return errNativeMember
	}
	plan, e := nativeMemberPlanLoadTx(ctx, tx, st.policy, f.PlanID)
	if e != nil || plan.State != "active" || plan.Identity.Kind != "retirement" || plan.Identity.Mode != "never_admitted" || plan.Identity.AttemptID != a.ID || plan.Identity.BirthSHA256 != a.BirthSHA256 || plan.ProviderDispatchStartedAt == nil || plan.ProviderPermitID != permitID {
		return errNativeMember
	}
	if e = nativeMemberRetirementFenceTx(ctx, tx, st.policy, a, now); e != nil {
		return e
	}
	if e = tx.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&now); e != nil {
		return e
	}
	if capacity.NativeWorkerMemberCurrentObservationValid(p, a, f.Context, f.Facts.Observation, st.authority, now) != nil || !capacity.NativeWorkerMemberFactsValidUntil(p, a, f.Facts).After(now) {
		return errNativeMember
	}
	return nil
}
