package repository

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

func (st *nativeMemberStoreState) grantCurrentTx(ctx context.Context, tx *sql.Tx, p model.CapacityPolicySpec, a model.CapacityNativeWorkerAttempt, r nativeMemberRecord, now time.Time) error {
	if st.sealed.Load() || r.State != "issued" || r.SettlementTokenSHA256 != "" || r.Original != nil || !r.Context.NotAfter.After(now) || r.Facts == nil {
		return errNativeMember
	}
	planID, e := nativeMemberUUID(r.Context.PlanID)
	if e != nil {
		return e
	}
	plan, e := nativeMemberPlanLoadTx(ctx, tx, st.policy, planID)
	if e != nil || plan.State != "active" || plan.Identity.SourceCommit != a.SourceCommit || plan.Identity.BirthSHA256 != a.BirthSHA256 || plan.Identity.Generation != a.Generation || plan.Identity.Fence != a.FencingToken {
		return errNativeMember
	}
	if e = st.parentCurrentTx(ctx, tx, p, a, plan.Identity.Kind, now); e != nil {
		return e
	}
	mode, receipt, e := nativeMemberModeTx(ctx, tx, a)
	if e != nil || mode != r.Context.Mode || receipt != r.Context.AdmissionReceiptSHA256 {
		return errNativeMember
	}
	if plan.Identity.Kind == "placement" {
		if e = nativeMemberReleasedTx(ctx, tx, a, receipt); e != nil {
			return e
		}
	}
	if plan.Identity.Kind == "placement" && plan.Identity.ParentNotAfter.Before(r.Context.NotAfter) {
		return errNativeMember
	}
	return nil
}

// All GETs happen outside SQL. Immediately before exposure, the database clock
// is read again after row/parent locks, and the original expiry cannot expand.
func (s *CapacityNativeWorkerMemberStore) Redeem(ctx context.Context, in model.CapacityNativeWorkerMemberSelectors, caller NativeWorkerMemberCaller) (model.CapacityNativeWorkerMemberPermit, error) {
	var empty model.CapacityNativeWorkerMemberPermit
	id, e := nativeMemberSelectors(in, caller)
	if e != nil {
		return empty, e
	}
	st, e := s.acquire()
	if e != nil {
		return empty, e
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
	st.mu.RUnlock()
	if e != nil || pe != nil || !nativeMemberCaller(r.Context, caller, true) || r.State != "issued" || r.DispatchStartedAt == nil {
		return empty, errNativeMember
	}
	facts, e := st.collectFacts(ctx, a, r.Context)
	if e != nil || ctx.Err() != nil {
		return empty, errNativeMember
	}
	st, e = s.acquire()
	if e != nil {
		return empty, e
	}
	defer st.mu.RUnlock()
	if e = st.validateFacts(ctx, p, a, r.Context, facts, false, time.Now().UTC()); e != nil {
		return empty, e
	}
	random := make([]byte, 32)
	defer clear(random)
	if _, e = rand.Read(random); e != nil {
		return empty, errNativeMember
	}
	token := base64.RawURLEncoding.EncodeToString(random)
	tokenSHA, ok := nativeReadinessTokenSHA(token)
	if !ok {
		return empty, errNativeMember
	}
	var out model.CapacityNativeWorkerMemberPermit
	e = st.effect(ctx, id, func(tx *sql.Tx, p model.CapacityPolicySpec, actual model.CapacityNativeWorkerAttempt, current *nativeMemberRecord, now time.Time) error {
		if current.Revision != r.Revision || actual.Revision != a.Revision || !nativeMemberCaller(current.Context, caller, true) {
			return errNativeMember
		}
		if e := st.grantCurrentTx(ctx, tx, p, actual, *current, now); e != nil {
			return e
		}
		if e := tx.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&now); e != nil || !current.Context.NotAfter.After(now) || !nativeMemberEffectiveFactsEnd(p, actual, facts).After(now) {
			return errNativeMember
		}
		current.State = "redeemed"
		current.SettlementTokenSHA256 = tokenSHA
		current.RedeemedAt = &now
		current.Revision++
		if e := nativeMemberWriteTx(ctx, tx, st.policy, *current, false, now); e != nil {
			return e
		}
		var e error
		out, e = model.NewCapacityNativeWorkerMemberPermit(current.Context, token)
		return e
	})
	if e != nil {
		return empty, e
	}
	return out, nil
}

// Persist exactly one actor RPC dispatch before invoking it. An uncertain RPC
// never causes another Send; after exposure this method is read-only receiving.
func (s *CapacityNativeWorkerMemberStore) Dispatch(ctx context.Context, id uuid.UUID) error {
	st, e := s.acquire()
	if e != nil {
		return e
	}
	var c model.CapacityNativeWorkerMemberContext
	runtime := st.runtime
	dispatch := false
	e = st.effect(ctx, id, func(tx *sql.Tx, p model.CapacityPolicySpec, a model.CapacityNativeWorkerAttempt, r *nativeMemberRecord, now time.Time) error {
		c = r.Context
		if r.DispatchStartedAt != nil || r.State != "issued" {
			return nil
		}
		if e := st.grantCurrentTx(ctx, tx, p, a, *r, now); e != nil {
			return e
		}
		if e := tx.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&now); e != nil || !c.NotAfter.After(now) {
			return errNativeMember
		}
		r.DispatchStartedAt = &now
		r.Revision++
		if e := nativeMemberWriteTx(ctx, tx, st.policy, *r, false, now); e != nil {
			return e
		}
		dispatch = true
		return nil
	})
	st.mu.RUnlock()
	if e != nil {
		return e
	}
	if !dispatch {
		return nil
	}
	bounded, cancel := context.WithDeadline(ctx, c.NotAfter)
	defer cancel()
	// The runtime owns no replay policy; its SDK call uses the immutable selector.
	return runtime.Send(bounded, c)
}
