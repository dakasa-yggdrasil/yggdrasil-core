package repository

import (
	"context"
	"database/sql"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

// Private reference to immutable retained facts, never an admission assertion
// supplied by an adapter or a new field in the old phase permit wire.
type nativeMemberPreflight struct {
	SeedID         uuid.UUID `json:"seed_id"`
	EvidenceSHA256 string    `json:"evidence_sha256"`
	ObservedAt     time.Time `json:"observed_at"`
	ValidUntil     time.Time `json:"valid_until"`
}

func (s *CapacityNativeWorkerMemberStore) admissionPreflight(ctx context.Context, a model.CapacityNativeWorkerAttempt) (nativeMemberPreflight, error) {
	var out nativeMemberPreflight
	c, e := s.Seed(ctx, a.ID, "read_preflight", nil)
	if e != nil {
		return out, e
	}
	seedID, e := nativeMemberUUID(c.PermitID)
	if e != nil {
		return out, e
	}
	if !c.NotAfter.After(time.Now().UTC()) {
		_ = s.CancelUnexposed(ctx, seedID)
		return out, errNativeMember
	}
	st, e := s.acquire()
	if e != nil {
		return out, e
	}
	runtime := st.runtime
	st.mu.RUnlock()
	facts, e := runtime.Facts(ctx, a, c)
	if e != nil || ctx.Err() != nil {
		return out, errNativeMember
	}
	st, e = s.acquire()
	if e != nil {
		return out, e
	}
	defer st.mu.RUnlock()
	p, e := parseCapacityPolicy(st.policy)
	if e != nil {
		return out, e
	}
	if e = st.validateFacts(ctx, p, a, c, facts, true, time.Now().UTC()); e != nil {
		return out, e
	}
	e = st.effect(ctx, seedID, func(tx *sql.Tx, p model.CapacityPolicySpec, actual model.CapacityNativeWorkerAttempt, r *nativeMemberRecord, now time.Time) error {
		if r.State != "preparing" || r.DispatchStartedAt != nil || r.SettlementTokenSHA256 != "" || r.Original != nil || actual.Revision != a.Revision {
			return errNativeMember
		}
		planID, e := nativeMemberUUID(c.PlanID)
		if e != nil {
			return e
		}
		plan, e := nativeMemberPlanLoadTx(ctx, tx, st.policy, planID)
		if e != nil || plan.Identity.Kind != "read_preflight" || plan.State != "preparing" {
			return errNativeMember
		}
		until := nativeMemberMin(c.NotAfter, capacity.NativeWorkerMemberFactsValidUntil(p, actual, facts))
		if !until.After(now) {
			return errNativeMember
		}
		mode, receipt, e := nativeMemberModeTx(ctx, tx, actual)
		if e != nil || mode != c.Mode || receipt != c.AdmissionReceiptSHA256 {
			return errNativeMember
		}
		r.Facts = &facts
		r.State = "no_effect"
		r.Revision++
		if e = nativeMemberWriteTx(ctx, tx, st.policy, *r, false, now); e != nil {
			return e
		}
		plan.SealedFacts = &facts
		plan.State = "cancelled"
		plan.Revision++
		if e = nativeMemberPlanWriteTx(ctx, tx, st.policy, plan, false, now); e != nil {
			return e
		}
		// Use the oldest original fact. This does not remint a time after custody.
		observed := facts.Observation.ObservedAt
		for _, v := range []time.Time{facts.Observation.Inventory.ObservedAt, facts.Observation.Inventory.Phase.ObservedAt, facts.Observation.Configuration.ObservedAt, facts.Bootstrap.ObservedAt, facts.Fence.ObservedAt, facts.Physical.ObservedAt} {
			if v.Before(observed) {
				observed = v
			}
		}
		out = nativeMemberPreflight{SeedID: seedID, EvidenceSHA256: capacity.NativeWorkerMemberFactsSHA(facts), ObservedAt: observed, ValidUntil: until}
		return nil
	})
	return out, e
}

func nativeMemberPreflightValidTx(ctx context.Context, tx *sql.Tx, policy model.Manifest, p model.CapacityPolicySpec, a model.CapacityNativeWorkerAttempt, f *nativeMemberPreflight, now time.Time) error {
	if p.NativeWorkerLifecycleBinding == nil || p.NativeWorkerLifecycleBinding.Members == nil {
		return nil
	}
	if f == nil || f.SeedID == uuid.Nil || !f.ValidUntil.After(now) || f.ObservedAt.IsZero() || f.ObservedAt.After(now) {
		return ErrCapacityDisabled
	}
	r, e := nativeMemberLoadTx(ctx, tx, policy, f.SeedID)
	if e != nil || r.State != "no_effect" || r.SeedID != uuid.Nil || r.Context.AttemptID != a.ID.String() || r.Context.PolicyChecksum != a.PolicyChecksum || r.Context.BirthSHA256 != a.BirthSHA256 || r.Context.Node == nil || r.Context.Node.UID != a.NodeUID || r.Facts == nil || r.SettlementTokenSHA256 != "" || r.Original != nil || r.DispatchStartedAt != nil || capacity.NativeWorkerMemberFactsSHA(*r.Facts) != f.EvidenceSHA256 || !nativeMemberMin(r.Context.NotAfter, capacity.NativeWorkerMemberFactsValidUntil(p, a, *r.Facts)).Equal(f.ValidUntil) {
		return errNativeMember
	}
	planID, e := nativeMemberUUID(r.Context.PlanID)
	if e != nil {
		return e
	}
	plan, e := nativeMemberPlanLoadTx(ctx, tx, policy, planID)
	if e != nil || plan.Identity.Kind != "read_preflight" || plan.State != "cancelled" || plan.SealedFacts == nil || capacity.NativeWorkerMemberFactsSHA(*plan.SealedFacts) != f.EvidenceSHA256 {
		return errNativeMember
	}
	return nil
}
