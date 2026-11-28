package repository

import (
	"context"
	"database/sql"
	"strings"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

// Go-only translation of the authenticated stock ExtenderBindingArgs. It is
// not a workload admission server, free target API, or scheduling algorithm.
type NativeWorkerMemberPlacementRequest struct {
	PodName, PodNamespace, PodUID, Node string
}

func (st *nativeMemberStoreState) controllerCaller() NativeWorkerMemberCaller {
	p, _ := parseCapacityPolicy(st.policy)
	return NativeWorkerMemberCaller{Role: NativeMemberControllerRole, Binding: model.CapacityNativeWorkerProbeResourceBinding{Name: p.NativeWorkerLifecycleBinding.Members.Name, SourceCommit: p.NativeWorkerLifecycleBinding.SourceCommit, ScopeSHA256: st.scope}}
}

func nativeMemberReleasedTx(ctx context.Context, tx *sql.Tx, a model.CapacityNativeWorkerAttempt, receipt string) error {
	var raw []byte
	var released nativeWorkerPhaseRecord
	e := tx.QueryRowContext(ctx, `SELECT CASE WHEN octet_length(record::text)<=2097152 THEN record END FROM public.capacity_native_worker_phase_permits WHERE attempt_id=$1 AND action='release_quarantine' AND state='observed' ORDER BY issued_at DESC LIMIT 1`, a.ID).Scan(&raw)
	if e != nil || nativeMemberDecode(raw, &released) != nil || released.Context.AttemptID != a.ID || released.Context.Node.UID != a.NodeUID || released.Context.Node.ProviderID != a.Physical.ProviderID || released.Context.Node.CreationProofSHA256 != a.BirthSHA256 || released.Context.Admission.ReceiptSHA256 != receipt || released.Observed == nil {
		return errNativeMember
	}
	return nil
}

func (s *CapacityNativeWorkerMemberStore) placementAttempt(ctx context.Context, in NativeWorkerMemberPlacementRequest) (model.CapacityNativeWorkerAttempt, error) {
	var a model.CapacityNativeWorkerAttempt
	if !strings.HasPrefix(in.PodName, "nw-") || !strings.HasPrefix(in.Node, "nw-") || in.PodNamespace == "" {
		return a, errNativeMember
	}
	if _, e := nativeMemberUUID(in.PodUID); e != nil {
		return a, e
	}
	st, e := s.acquire()
	if e != nil {
		return a, e
	}
	defer st.mu.RUnlock()
	if st.sealed.Load() {
		return a, errNativeMember
	}
	// This is an exact selector over the sealed physical identity, not a supplied
	// expected UID. Refuse ambiguity rather than selecting one row arbitrarily.
	return st.placementAttemptByName(ctx, in.Node)
}
func (st *nativeMemberStoreState) placementAttemptByName(ctx context.Context, node string) (model.CapacityNativeWorkerAttempt, error) {
	var out model.CapacityNativeWorkerAttempt
	rows, e := st.workers.Capacity.DB.QueryContext(ctx, `SELECT CASE WHEN octet_length(attempt::text)<=2097152 THEN attempt END FROM public.capacity_native_worker_attempts WHERE policy_id=$1 AND namespace=$2 AND state='admitted' AND ('nw-'||substr(replace(id::text,'-',''),1,12)||'-'||(attempt#>>'{physical,resource_id}'))=$3 LIMIT 2`, st.policy.ID, st.policy.Metadata.Namespace, node)
	if e != nil {
		return out, e
	}
	defer rows.Close()
	count := 0
	for rows.Next() {
		var raw []byte
		if rows.Scan(&raw) != nil || nativeMemberDecode(raw, &out) != nil {
			return model.CapacityNativeWorkerAttempt{}, errNativeMember
		}
		count++
	}
	if rows.Err() != nil || count != 1 || out.NodeUID == "" || out.Physical == nil {
		return model.CapacityNativeWorkerAttempt{}, errNativeMember
	}
	return out, nil
}

// Bind has one durable dispatch, then only GET-only receiving. Stock retries
// cannot select another Node while the same PodUID has exposed/unknown rights.
func (s *CapacityNativeWorkerMemberStore) Bind(ctx context.Context, in NativeWorkerMemberPlacementRequest) error {
	a, e := s.placementAttempt(ctx, in)
	if e != nil {
		return e
	}
	st, e := s.acquire()
	if e != nil {
		return e
	}
	p, e := parseCapacityPolicy(st.policy)
	if e != nil {
		st.mu.RUnlock()
		return e
	}
	caller := st.controllerCaller()
	var existing uuid.UUID
	e = st.workers.Capacity.DB.QueryRowContext(ctx, `SELECT id FROM public.capacity_native_worker_member_permits WHERE action='bind_pod' AND subject_uid=$1 AND context->>'realm_uid'=$2 AND state NOT IN('preparing','no_effect','member_absent') ORDER BY created_at DESC LIMIT 1`, in.PodUID, p.NativeWorkerPoolBinding.RealmUID).Scan(&existing)
	var prior nativeMemberRecord
	if e == nil {
		prior, e = st.snapshot(ctx, existing)
	}
	st.mu.RUnlock()
	if e != nil && e != sql.ErrNoRows {
		return e
	}
	var final model.CapacityNativeWorkerMemberContext
	if e == nil {
		if prior.Context.AttemptID != a.ID.String() || prior.Context.Node == nil || prior.Context.Node.Name != in.Node || prior.Context.Pod == nil || prior.Context.Pod.UID != in.PodUID || prior.Context.Pod.Namespace != in.PodNamespace || prior.Context.Pod.Name != in.PodName {
			return ErrCapacityConflict
		}
		if prior.State == "observed" {
			return nil
		}
		if prior.State == "issued" && prior.SettlementTokenSHA256 == "" && !prior.Context.NotAfter.After(time.Now().UTC()) {
			if e = s.CancelUnexposed(ctx, existing); e != nil {
				return e
			}
			return errNativeMember
		}
		final = prior.Context
	} else {
		seed, e := s.Seed(ctx, a.ID, "placement", &model.CapacityNativeWorkerMemberPod{Namespace: in.PodNamespace, Name: in.PodName, UID: in.PodUID})
		if e != nil {
			return e
		}
		seedID, e := nativeMemberUUID(seed.PermitID)
		if e != nil {
			return e
		}
		if seed.PlacementFenceSHA256 == "" {
			final, e = s.Issue(ctx, seedID)
			if e != nil {
				return e
			}
		} else {
			final = seed
		}
	}
	id, e := nativeMemberUUID(final.PermitID)
	if e != nil {
		return e
	}
	// Dispatch's persisted barrier makes every later invocation readback-only.
	_ = s.Dispatch(ctx, id)
	out, e := s.Reconcile(ctx, model.CapacityNativeWorkerMemberSelectors{BindingName: caller.Binding.Name, PermitID: id.String()}, caller)
	if e != nil || out.State != "observed" {
		return errNativeMember
	}
	return nil
}
