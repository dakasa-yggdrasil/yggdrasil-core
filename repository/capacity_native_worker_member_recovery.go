package repository

import (
	"context"
	"database/sql"
	"sort"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

type NativeWorkerMemberRecoveryResult struct {
	PlanID    string `json:"plan_id"`
	AttemptID string `json:"attempt_id"`
	State     string `json:"state"`
}

// Selection is private and deterministic. Neither a workflow nor a scheduler
// can choose a member, mode, URL or cloud resource to retire.
func (st *nativeMemberStoreState) recoverySelection(ctx context.Context) (uuid.UUID, uuid.UUID, error) {
	var plan, attempt uuid.UUID
	e := st.workers.Capacity.DB.QueryRowContext(ctx, `SELECT id,attempt_id FROM public.capacity_native_worker_member_plans WHERE policy_id=$1 AND namespace=$2 AND kind='retirement' AND state NOT IN('settled','cancelled') ORDER BY created_at,id LIMIT 1`, st.policy.ID, st.policy.Metadata.Namespace).Scan(&plan, &attempt)
	if e == nil {
		return plan, attempt, nil
	}
	if e != sql.ErrNoRows {
		return plan, attempt, e
	}
	e = st.workers.Capacity.DB.QueryRowContext(ctx, `SELECT id FROM public.capacity_native_worker_attempts a WHERE policy_id=$1 AND namespace=$2 AND state IN('acknowledged','registered','aborting') AND jsonb_typeof(attempt->'physical')='object' AND NOT EXISTS(SELECT 1 FROM public.capacity_native_worker_phase_permits p WHERE p.attempt_id=a.id AND p.action IN('admit_registry','release_quarantine') AND p.state NOT IN('issued','no_effect')) ORDER BY id LIMIT 1`, st.policy.ID, st.policy.Metadata.Namespace).Scan(&attempt)
	return plan, attempt, e
}

func (st *nativeMemberStoreState) latestPlanEffect(ctx context.Context, plan uuid.UUID) (nativeMemberRecord, error) {
	var out nativeMemberRecord
	var raw []byte
	e := st.workers.Capacity.DB.QueryRowContext(ctx, `SELECT CASE WHEN octet_length(record::text)<=8388608 THEN record END FROM public.capacity_native_worker_member_permits WHERE plan_id=$1 AND state<>'no_effect' ORDER BY created_at DESC,id DESC LIMIT 1`, plan).Scan(&raw)
	if e != nil || nativeMemberDecode(raw, &out) != nil {
		return out, errNativeMember
	}
	return out, nil
}

func (s *CapacityNativeWorkerMemberStore) driveEffect(ctx context.Context, c model.CapacityNativeWorkerMemberContext) (model.CapacityNativeWorkerMemberRead, error) {
	var out model.CapacityNativeWorkerMemberRead
	id, e := nativeMemberUUID(c.PermitID)
	if e != nil {
		return out, e
	}
	st, e := s.acquire()
	if e != nil {
		return out, e
	}
	r, e := st.snapshot(ctx, id)
	caller := st.controllerCaller()
	st.mu.RUnlock()
	if e != nil {
		return out, e
	}
	if (r.State == "preparing" || r.State == "issued") && !r.Context.NotAfter.After(time.Now().UTC()) {
		return out, s.CancelUnexposed(ctx, id)
	}
	if r.State == "preparing" {
		c, e = s.Issue(ctx, id)
		if e != nil {
			return out, e
		}
		id, e = nativeMemberUUID(c.PermitID)
		if e != nil {
			return out, e
		}
	}
	_ = s.Dispatch(ctx, id)
	return s.Reconcile(ctx, model.CapacityNativeWorkerMemberSelectors{BindingName: caller.Binding.Name, PermitID: id.String()}, caller)
}

// One invocation advances at most one external effect. Returning pending does
// not schedule a retry or free any exposed right; the next authorized recovery
// invocation resumes the same immutable plan and performs GET-only receiving.
func (s *CapacityNativeWorkerMemberStore) Recover(ctx context.Context, workflow uuid.UUID) (NativeWorkerMemberRecoveryResult, error) {
	var out NativeWorkerMemberRecoveryResult
	st, e := s.acquire()
	if e != nil {
		return out, e
	}
	if st.sealed.Load() || st.abort == nil || workflow == uuid.Nil || workflow != st.abort.RecoveryWorkflowID || st.network == nil || st.prepareProvider == nil {
		st.mu.RUnlock()
		return out, ErrCapacityDisabled
	}
	planID, attemptID, e := st.recoverySelection(ctx)
	st.mu.RUnlock()
	if e != nil {
		return out, e
	}
	out.AttemptID = attemptID.String()
	out.State = "pending"
	if planID == uuid.Nil {
		seed, e := s.Seed(ctx, attemptID, "retirement", nil)
		if e != nil {
			return out, e
		}
		out.PlanID = seed.PlanID
		_, e = s.driveEffect(ctx, seed)
		return out, e
	}
	out.PlanID = planID.String()
	st, e = s.acquire()
	if e != nil {
		return out, e
	}
	plan, e := st.plan(ctx, planID)
	if e != nil || plan.Identity.Mode != "never_admitted" {
		st.mu.RUnlock()
		return out, ErrCapacityDisabled
	}
	r, e := st.latestPlanEffect(ctx, planID)
	a, ae := st.workers.Read(ctx, st.policy, attemptID)
	st.mu.RUnlock()
	if e != nil || ae != nil {
		return out, errNativeMember
	}
	if r.State != "observed" {
		_, e = s.driveEffect(ctx, r.Context)
		return out, e
	}
	if r.Context.Action == "cordon" || r.Context.Action == "evict_pod" {
		if plan.PhysicalAbsence == nil {
			st, e = s.acquire()
			if e != nil {
				return out, e
			}
			abort := st.abort
			policy := st.policy
			st.mu.RUnlock()
			if plan.ProviderDispatchStartedAt != nil {
				_, absence, e := abort.observe(ctx, policy, attemptID)
				if e != nil {
					return out, e
				}
				if !nativeMemberPhysicalAbsent(absence) {
					return out, nil
				}
				if e = s.retainPhysicalAbsence(ctx, planID, plan.ProviderPermitID, absence); e != nil {
					return out, e
				}
				seed, e := s.nextRetirementSeed(ctx, planID, "delete_node", nil)
				if e != nil {
					return out, e
				}
				_, e = s.driveEffect(ctx, seed)
				return out, e
			}
			// A fresh complete roster, not the old active-Pod count, decides
			// whether another PDB-aware single-Pod eviction is needed.
			f, e := s.retirementCurrent(ctx, a, planID)
			if e != nil {
				return out, e
			}
			if len(f.Observation.Pods) != 0 {
				pods := append([]model.CapacityNativeWorkerMemberPodFact(nil), f.Observation.Pods...)
				sort.Slice(pods, func(i, j int) bool { return pods[i].Identity.UID < pods[j].Identity.UID })
				seed, e := s.nextRetirementSeed(ctx, planID, "evict_pod", &pods[0].Identity)
				if e != nil {
					return out, e
				}
				_, e = s.driveEffect(ctx, seed)
				return out, e
			}
			permit, e := abort.Begin(ctx, policy, attemptID)
			if e != nil {
				return out, e
			}
			_, absence, e := abort.observe(ctx, policy, attemptID)
			if e != nil {
				return out, e
			}
			if nativeMemberPhysicalAbsent(absence) {
				if e = s.retainPhysicalAbsence(ctx, planID, permit.PermitID, absence); e != nil {
					return out, e
				}
			} else {
				if permit.State != "issued" {
					return out, errNativeMember
				}
				st, e = s.acquire()
				if e != nil {
					return out, e
				}
				prepare := st.prepareProvider
				st.mu.RUnlock()
				bounded, cancel := context.WithDeadline(ctx, permit.ExpiresAt)
				defer cancel()
				send, e := prepare(bounded, a, permit)
				if e != nil {
					return out, e
				}
				claimed, e := s.claimRetirementRPC(ctx, planID, "provider", permit.PermitID, permit.ExpiresAt)
				if e != nil {
					return out, e
				}
				if claimed {
					_ = send()
				}
				// No ACK, status or returned safe SDK map is used as absence.
				return out, nil
			}
		}
		seed, e := s.nextRetirementSeed(ctx, planID, "delete_node", nil)
		if e != nil {
			return out, e
		}
		_, e = s.driveEffect(ctx, seed)
		return out, e
	}
	if r.Context.Action == "delete_node" {
		if e = s.retainNodeAbsence(ctx, planID, r); e != nil {
			return out, e
		}
		seed, e := s.nextRetirementSeed(ctx, planID, "retire_registry", nil)
		if e != nil {
			return out, e
		}
		_, e = s.driveEffect(ctx, seed)
		return out, e
	}
	if r.Context.Action != "retire_registry" {
		return out, errNativeMember
	}
	if e = s.removeRetirementNetwork(ctx, planID, a); e != nil {
		return out, e
	}
	if e = s.finishRetirement(ctx, planID, r); e != nil {
		return out, e
	}
	out.State = "member_absent"
	return out, nil
}

func (s *CapacityNativeWorkerMemberStore) retirementCurrent(ctx context.Context, a model.CapacityNativeWorkerAttempt, plan uuid.UUID) (capacity.NativeWorkerMemberFacts, error) {
	var out capacity.NativeWorkerMemberFacts
	st, e := s.acquire()
	if e != nil {
		return out, e
	}
	var raw []byte
	var cordon nativeMemberRecord
	e = st.workers.Capacity.DB.QueryRowContext(ctx, `SELECT CASE WHEN octet_length(record::text)<=8388608 THEN record END FROM public.capacity_native_worker_member_permits WHERE plan_id=$1 AND action='cordon' AND state='observed' ORDER BY created_at DESC,id DESC LIMIT 1`, plan).Scan(&raw)
	if e != nil || nativeMemberDecode(raw, &cordon) != nil {
		st.mu.RUnlock()
		return out, errNativeMember
	}
	runtime := st.runtime
	st.mu.RUnlock()
	out, e = runtime.Facts(ctx, a, cordon.Context)
	if e != nil {
		return out, e
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
	if e = st.validateCurrentLiveFacts(ctx, p, a, cordon.Context, out, time.Now().UTC()); e != nil {
		return out, e
	}
	if len(out.Observation.Inventory.Phase.Candidates) != 1 || !out.Observation.Inventory.Phase.Candidates[0].Unschedulable {
		return out, errNativeMember
	}
	return out, nil
}

func (s *CapacityNativeWorkerMemberStore) claimRetirementRPC(ctx context.Context, planID uuid.UUID, kind string, id uuid.UUID, end time.Time) (bool, error) {
	st, e := s.acquire()
	if e != nil {
		return false, e
	}
	defer st.mu.RUnlock()
	claimed := false
	e = st.workers.tx(ctx, st.policy, func(tx *sql.Tx, p model.CapacityPolicySpec, now time.Time) error {
		var attempt uuid.UUID
		if e := tx.QueryRowContext(ctx, `SELECT attempt_id FROM public.capacity_native_worker_member_plans WHERE id=$1 AND policy_id=$2`, planID, st.policy.ID).Scan(&attempt); e != nil {
			return e
		}
		a, _, e := nativeAttemptLoadTx(ctx, tx, st.policy, attempt)
		if e != nil {
			return e
		}
		plan, e := nativeMemberPlanLoadTx(ctx, tx, st.policy, planID)
		if e != nil {
			return e
		}
		if plan.State != "active" || plan.Identity.Mode != "never_admitted" || id == uuid.Nil || !end.After(now) {
			return errNativeMember
		}
		if e = st.parentCurrentTx(ctx, tx, p, a, "retirement", now); e != nil {
			return e
		}
		if e = tx.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&now); e != nil || !end.After(now) {
			return errNativeMember
		}
		switch kind {
		case "provider":
			if plan.ProviderDispatchStartedAt != nil {
				if plan.ProviderPermitID != id {
					return errNativeMember
				}
				return nil
			}
			plan.ProviderPermitID = id
			plan.ProviderDispatchStartedAt = &now
		case "network":
			if plan.NetworkDispatchStartedAt != nil {
				if plan.NetworkPermitID != id {
					return errNativeMember
				}
				return nil
			}
			plan.NetworkPermitID = id
			plan.NetworkDispatchStartedAt = &now
		default:
			return errNativeMember
		}
		plan.Revision++
		if e = nativeMemberPlanWriteTx(ctx, tx, st.policy, plan, false, now); e != nil {
			return e
		}
		claimed = true
		return nil
	})
	return claimed, e
}

func (s *CapacityNativeWorkerMemberStore) retainPhysicalAbsence(ctx context.Context, planID, permitID uuid.UUID, o model.CapacityNativeWorkerAbortObservation) error {
	st, e := s.acquire()
	if e != nil {
		return e
	}
	defer st.mu.RUnlock()
	return st.workers.tx(ctx, st.policy, func(tx *sql.Tx, p model.CapacityPolicySpec, now time.Time) error {
		var attempt uuid.UUID
		if e := tx.QueryRowContext(ctx, `SELECT attempt_id FROM public.capacity_native_worker_member_plans WHERE id=$1 AND policy_id=$2`, planID, st.policy.ID).Scan(&attempt); e != nil {
			return e
		}
		a, _, e := nativeAttemptLoadTx(ctx, tx, st.policy, attempt)
		if e != nil {
			return e
		}
		plan, e := nativeMemberPlanLoadTx(ctx, tx, st.policy, planID)
		if e != nil {
			return e
		}
		original, e := abortLoadTx(ctx, tx, st.policy, permitID)
		if e != nil || original.Context.AttemptID != a.ID || plan.State != "active" || plan.Identity.Mode != "never_admitted" || plan.ProviderPermitID != permitID || plan.ProviderDispatchStartedAt == nil || !nativeMemberProviderOriginalComplete(original) || !nativeMemberPhysicalAbsent(o) || !capacity.NativeWorkerAbortObservationValid(p, a, o, now) {
			return errNativeMember
		}
		if plan.PhysicalAbsence != nil {
			return nil
		}
		plan.PhysicalAbsence = &o
		plan.Revision++
		return nativeMemberPlanWriteTx(ctx, tx, st.policy, plan, false, now)
	})
}

func (s *CapacityNativeWorkerMemberStore) retainNodeAbsence(ctx context.Context, planID uuid.UUID, r nativeMemberRecord) error {
	st, e := s.acquire()
	if e != nil {
		return e
	}
	defer st.mu.RUnlock()
	id, e := nativeMemberUUID(r.Context.PermitID)
	if e != nil {
		return e
	}
	return st.effect(ctx, id, func(tx *sql.Tx, _ model.CapacityPolicySpec, _ model.CapacityNativeWorkerAttempt, current *nativeMemberRecord, now time.Time) error {
		if current.State != "observed" || current.Context.Action != "delete_node" || current.Observed == nil || !nativeMemberEffectObserved(current.Context, *current.Observed) {
			return errNativeMember
		}
		plan, e := nativeMemberPlanLoadTx(ctx, tx, st.policy, planID)
		if e != nil || plan.State != "active" {
			return errNativeMember
		}
		if plan.NodeAbsence != nil {
			return nil
		}
		plan.NodeAbsence = current.Observed
		plan.Revision++
		return nativeMemberPlanWriteTx(ctx, tx, st.policy, plan, false, now)
	})
}
