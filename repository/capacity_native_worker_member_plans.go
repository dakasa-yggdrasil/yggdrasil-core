package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

func (st *nativeMemberStoreState) snapshot(ctx context.Context, id uuid.UUID) (nativeMemberRecord, error) {
	var r nativeMemberRecord
	var raw []byte
	e := st.workers.Capacity.DB.QueryRowContext(ctx, `SELECT CASE WHEN octet_length(record::text)<=8388608 THEN record END FROM public.capacity_native_worker_member_permits WHERE id=$1 AND policy_id=$2 AND namespace=$3`, id, st.policy.ID, st.policy.Metadata.Namespace).Scan(&raw)
	if e != nil || nativeMemberDecode(raw, &r) != nil || r.Context.PermitID != id.String() {
		return r, errNativeMember
	}
	return r, nil
}
func nativeMemberMin(end time.Time, others ...time.Time) time.Time {
	for _, v := range others {
		if v.IsZero() {
			return time.Time{}
		}
		if v.Before(end) {
			end = v
		}
	}
	return end
}
func nativeMemberPlanWriteTx(ctx context.Context, tx *sql.Tx, p model.Manifest, r nativeMemberPlanRecord, insert bool, now time.Time) error {
	raw, e := nativeMemberRecordBytes(r)
	if e != nil {
		return e
	}
	id := r.Identity
	if insert {
		identity, e := nativeMemberRecordBytes(id)
		if e != nil {
			return e
		}
		_, e = tx.ExecContext(ctx, `INSERT INTO public.capacity_native_worker_member_plans(id,attempt_id,policy_id,namespace,kind,mode,subject_uid,state,revision,identity,record,created_at,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$12)`, id.PlanID, id.AttemptID, p.ID, p.Metadata.Namespace, id.Kind, id.Mode, id.SubjectUID, r.State, r.Revision, identity, raw, now)
		if e != nil {
			return e
		}
	} else {
		result, e := tx.ExecContext(ctx, `UPDATE public.capacity_native_worker_member_plans SET state=$2,revision=$3,record=$4,updated_at=$5 WHERE id=$1 AND revision=$6`, id.PlanID, r.State, r.Revision, raw, now, r.Revision-1)
		if e != nil {
			return e
		}
		n, e := result.RowsAffected()
		if e != nil || n != 1 {
			return errNativeMember
		}
	}
	return nativeMemberEventTx(ctx, tx, p, id.PlanID, uuid.Nil, uuid.Nil, "plan_"+r.State, r, now)
}

// A continuous placement parent is the distinct authenticated stock scheduler,
// active policy and current member epoch. It is not a completed grow lease.
func (st *nativeMemberStoreState) parentCurrentTx(ctx context.Context, tx *sql.Tx, p model.CapacityPolicySpec, a model.CapacityNativeWorkerAttempt, kind string, now time.Time) error {
	var checksum string
	var active bool
	if e := tx.QueryRowContext(ctx, `SELECT checksum,active FROM public.manifests WHERE id=$1 AND kind='capacity_policy' AND namespace=$2 FOR SHARE`, st.policy.ID, st.policy.Metadata.Namespace).Scan(&checksum, &active); e != nil || !active || checksum != st.policy.Checksum {
		return errNativeMember
	}
	if st.sealed.Load() || p.NativeWorkerLifecycleBinding == nil || p.NativeWorkerLifecycleBinding.Members == nil || p.NativeWorkerPoolBinding == nil || st.runtime.SourceCommit() != p.NativeWorkerLifecycleBinding.SourceCommit || a.PolicyID != st.policy.ID || a.PolicyChecksum != checksum || a.PoolUID != p.NativeWorkerPoolBinding.PoolUID || a.PoolEpoch != p.NativeWorkerPoolBinding.ExpectedPoolEpoch {
		return errNativeMember
	}
	if kind == "retirement" {
		if st.abort == nil {
			return ErrCapacityDisabled
		}
		return st.abort.current(ctx, tx, st.policy, p, a, now)
	}
	if kind == "read_preflight" {
		return nil
	}
	if kind != "placement" {
		return errNativeMember
	}
	return nativeMemberGrowthAllowedTx(ctx, tx, p, a)
}

// Seed is an owner-only selection. HTTP/SDK callers have no seed/target route.
// A real independent phase read supplies NodeUID BEFORE a member/configz Read.
// No mode, URL, credential, expected observation or mutation grant is accepted.
func (s *CapacityNativeWorkerMemberStore) Seed(ctx context.Context, attemptID uuid.UUID, kind string, pod *model.CapacityNativeWorkerMemberPod) (model.CapacityNativeWorkerMemberContext, error) {
	var out model.CapacityNativeWorkerMemberContext
	st, e := s.acquire()
	if e != nil {
		return out, e
	}
	p, e := parseCapacityPolicy(st.policy)
	if e != nil {
		st.mu.RUnlock()
		return out, e
	}
	a, e := st.workers.Read(ctx, st.policy, attemptID)
	runtime := st.runtime
	st.mu.RUnlock()
	if e != nil || a.Physical == nil || kind != "retirement" && kind != "placement" && kind != "read_preflight" || kind == "placement" && (pod == nil || pod.UID == "") || kind != "placement" && pod != nil {
		return out, errNativeMember
	}
	target, e := runtime.Target(ctx, a)
	if e != nil || capacity.NativeWorkerPhaseHeaderValid(p, target, time.Now().UTC()) != nil || !target.CandidateSelected || target.CandidateAbsenceProven || len(target.Candidates) != 1 || target.RequestedProviderID != a.Physical.ProviderID || target.RequestedCreationProofSHA256 != a.BirthSHA256 {
		return out, errNativeMember
	}
	n := target.Candidates[0]
	name, e := capacity.NativeWorkerBootstrapNodeName(a)
	if e != nil || n.NodeName != name || n.NodeUID == "" || n.NodeResourceVersion == "" || n.ProviderID != a.Physical.ProviderID || a.NodeUID != "" && a.NodeUID != n.NodeUID {
		return out, errNativeMember
	}
	st, e = s.acquire()
	if e != nil {
		return out, e
	}
	defer st.mu.RUnlock()
	e = st.workers.tx(ctx, st.policy, func(tx *sql.Tx, p model.CapacityPolicySpec, now time.Time) error {
		actual, _, e := nativeAttemptLoadTx(ctx, tx, st.policy, a.ID)
		if e != nil {
			return e
		}
		if actual.Revision != a.Revision || !target.ObservedAt.Add(time.Duration(p.NativeWorkerLifecycleBinding.Members.MaxReadAgeSeconds)*time.Second).After(now) {
			return errNativeMember
		}
		if e = st.parentCurrentTx(ctx, tx, p, actual, kind, now); e != nil {
			return e
		}
		mode, receipt, e := nativeMemberModeTx(ctx, tx, actual)
		if e != nil {
			return e
		}
		// Admitted drain/provider retirement is deliberately not implemented.
		if kind == "retirement" && mode != "never_admitted" || kind == "placement" && mode != "admitted" {
			return ErrCapacityDisabled
		}
		if kind == "placement" {
			if e = nativeMemberReleasedTx(ctx, tx, actual, receipt); e != nil {
				return e
			}
		}
		subject := n.NodeUID
		action := "cordon"
		parentKind := "recovery_workflow_v1"
		if kind == "read_preflight" {
			parentKind = "read_preflight_v1"
		}
		if kind == "placement" {
			subject = pod.UID
			action = "bind_pod"
			parentKind = "stock_scheduler_v1"
		}
		if _, e = nativeMemberUUID(subject); e != nil {
			return e
		}
		var existing uuid.UUID
		e = tx.QueryRowContext(ctx, `SELECT id FROM public.capacity_native_worker_member_plans WHERE attempt_id=$1 AND kind=$2 AND subject_uid=$3 AND state NOT IN('settled','cancelled') FOR UPDATE`, a.ID, kind, subject).Scan(&existing)
		if e == nil {
			var id uuid.UUID
			e = tx.QueryRowContext(ctx, `SELECT id FROM public.capacity_native_worker_member_permits WHERE plan_id=$1 AND action=$2 AND state<>'no_effect' ORDER BY created_at,id LIMIT 1`, existing, action).Scan(&id)
			if e != nil {
				return errNativeMember
			}
			r, e := nativeMemberLoadTx(ctx, tx, st.policy, id)
			if e == nil {
				out = r.Context
			}
			return e
		} else if e != sql.ErrNoRows {
			return e
		}
		switch kind {
		case "retirement":
			if e = nativeMemberRetirementFenceTx(ctx, tx, st.policy, actual, now); e != nil {
				return e
			}
		case "placement":
			if e = nativeMemberBindFreeTx(ctx, tx, p, subject); e != nil {
				return e
			}
		}
		b, pool := p.NativeWorkerLifecycleBinding.Members, p.NativeWorkerPoolBinding
		if e = tx.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&now); e != nil {
			return e
		}
		if !target.ObservedAt.Add(time.Duration(b.MaxReadAgeSeconds) * time.Second).After(now) {
			return errNativeMember
		}
		end := now.Add(time.Duration(b.MaxPermitSeconds) * time.Second)
		end = nativeMemberMin(end, target.ObservedAt.Add(time.Duration(b.MaxReadAgeSeconds)*time.Second))
		if deadline, ok := ctx.Deadline(); ok {
			end = nativeMemberMin(end, deadline)
		}
		if !end.After(now) {
			return errNativeMember
		}
		plan := nativeMemberPlanRecord{Identity: nativeMemberPlanIdentity{Schema: "native_worker_member_plan_v1", PlanID: uuid.New(), AttemptID: a.ID, PolicyID: a.PolicyID, PolicyChecksum: a.PolicyChecksum, Namespace: a.Namespace, Kind: kind, Mode: mode, SubjectUID: subject, SourceCommit: a.SourceCommit, BirthSHA256: a.BirthSHA256, Generation: a.Generation, Fence: a.FencingToken, ParentKind: parentKind, RealmUID: pool.RealmUID, PoolUID: pool.PoolUID, Epoch: pool.ExpectedPoolEpoch, ExecutorID: st.workers.Capacity.ExecutorID}, State: "preparing", Revision: 1}
		switch kind {
		case "placement":
			plan.Identity.ParentNotAfter = end
		case "retirement":
			plan.Identity.WorkflowID = st.abort.RecoveryWorkflowID
		}
		if e = nativeMemberPlanWriteTx(ctx, tx, st.policy, plan, true, now); e != nil {
			return e
		}
		c := model.CapacityNativeWorkerMemberContext{Schema: model.CapacityNativeWorkerMemberContextSchema, PlanID: plan.Identity.PlanID.String(), PermitID: uuid.NewString(), AttemptID: a.ID.String(), CoreSourceCommit: a.SourceCommit, Mode: mode, Action: action, Actor: capacity.NativeWorkerMemberEndpoint(b.Writer, capacity.NativeWorkerMemberCapability(action, nativeMemberCapabilityPlan(kind))), Observer: capacity.NativeWorkerMemberEndpoint(b.Reader, capacity.NativeWorkerMemberReadCapability(action)), PolicyID: a.PolicyID.String(), PolicyChecksum: a.PolicyChecksum, IntentGeneration: a.Generation, FencingToken: a.FencingToken, RealmNamespace: pool.RegistryRef.Namespace, RealmUID: pool.RealmUID, PoolUID: pool.PoolUID, Owner: pool.Owner, Epoch: pool.ExpectedPoolEpoch, Profile: a.Profile, BirthSHA256: a.BirthSHA256, Physical: *a.Physical, OverlayIPv4: a.OverlayIPv4, Node: &model.CapacityNativeWorkerMemberNode{Name: n.NodeName, UID: n.NodeUID, ResourceVersion: n.NodeResourceVersion, ProviderID: n.ProviderID}, Registry: a.Registry, BootstrapPolicySHA256: b.BootstrapPolicySHA256, AdmissionReceiptSHA256: receipt, NotAfter: end}
		if pod != nil {
			copy := *pod
			c.Pod = &copy
		}
		if capacity.NativeWorkerMemberContextValid(p, actual, c, now, true) != nil {
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

// Pending Pod reads do not settle old Bind exposure. This cross-Attempt query
// complements the SQL realm+PodUID uniqueness even when another Node is chosen.
func nativeMemberBindFreeTx(ctx context.Context, tx *sql.Tx, p model.CapacityPolicySpec, podUID string) error {
	var blocked bool
	e := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM public.capacity_native_worker_member_permits WHERE action='bind_pod' AND subject_uid=$1 AND context->>'realm_uid'=$2 AND state NOT IN('preparing','no_effect','observed','member_absent'))`, podUID, p.NativeWorkerPoolBinding.RealmUID).Scan(&blocked)
	if e != nil {
		return e
	}
	if blocked {
		return ErrCapacityConflict
	}
	return nil
}

func (st *nativeMemberStoreState) validateFacts(ctx context.Context, p model.CapacityPolicySpec, a model.CapacityNativeWorkerAttempt, c model.CapacityNativeWorkerMemberContext, f capacity.NativeWorkerMemberFacts, seed bool, now time.Time) error {
	if c.Action == "delete_node" || c.Action == "retire_registry" {
		return st.validateAbsentFacts(ctx, p, a, c, f, seed, now)
	}
	if capacity.NativeWorkerMemberObservationValid(p, a, c, f.Observation, st.authority, now, seed) != nil || !capacity.NativeWorkerPlacementBootstrapValid(p, a, c, f.Bootstrap, st.authority, now) || !capacity.NativeWorkerMemberPhysicalFactValid(p, a, f.Physical, now) || !capacity.NativeWorkerMemberFactsValidUntil(p, a, f).After(now) {
		return errNativeMember
	}
	if e := st.verifyConfigz(ctx, c, f.Observation, now); e != nil {
		return e
	}
	// Fence context is resolved from the original immutable creator selector. It
	// remains read-only after birth and does not renew that creator permission.
	var command []byte
	var parent nativeWorkerCommandContext
	if e := st.workers.Capacity.DB.QueryRowContext(ctx, `SELECT record FROM public.capacity_native_worker_command_contexts WHERE attempt_id=$1`, a.ID).Scan(&command); e != nil || json.Unmarshal(command, &parent) != nil {
		return errNativeMember
	}
	b, pool := p.NativeWorkerLifecycleBinding.Members, p.NativeWorkerPoolBinding
	fc := model.CapacityNativeWorkerAllocatorFenceContext{Schema: model.CapacityNativeWorkerAllocatorFenceContextSchema, CreatorPermitID: a.ID.String(), AttemptID: a.ID.String(), CoreSourceCommit: a.SourceCommit, Observer: capacity.NativeWorkerMemberEndpoint(b.AllocatorFenceReader, "observe_native_worker_allocator_fence"), PolicyID: a.PolicyID.String(), PolicyChecksum: a.PolicyChecksum, IntentGeneration: a.Generation, FencingToken: a.FencingToken, RealmUID: pool.RealmUID, PoolUID: pool.PoolUID, Owner: pool.Owner, Epoch: pool.ExpectedPoolEpoch, BootstrapPolicySHA256: b.BootstrapPolicySHA256, NotAfter: parent.ExpiresAt}
	if !capacity.NativeWorkerMemberCurrentFenceValid(p, fc, f.Fence, st.authority, now) {
		return errNativeMember
	}
	return nil
}

// A NEW immutable permit is created after seed facts; the old context cannot
// become a grant. The final actor still must refresh all facts before Redeem.
func (s *CapacityNativeWorkerMemberStore) Issue(ctx context.Context, seedID uuid.UUID) (model.CapacityNativeWorkerMemberContext, error) {
	var out model.CapacityNativeWorkerMemberContext
	st, e := s.acquire()
	if e != nil {
		return out, e
	}
	seed, e := st.snapshot(ctx, seedID)
	p, pe := parseCapacityPolicy(st.policy)
	var a model.CapacityNativeWorkerAttempt
	if e == nil {
		attempt, parseErr := nativeMemberUUID(seed.Context.AttemptID)
		if parseErr != nil {
			e = parseErr
		} else {
			a, e = st.workers.Read(ctx, st.policy, attempt)
		}
	}
	st.mu.RUnlock()
	if e != nil || pe != nil || seed.State != "preparing" {
		return out, errNativeMember
	}
	facts, e := st.collectFacts(ctx, a, seed.Context)
	if e != nil || ctx.Err() != nil {
		return out, errNativeMember
	}
	st, e = s.acquire()
	if e != nil {
		return out, e
	}
	defer st.mu.RUnlock()
	if e = st.validateFacts(ctx, p, a, seed.Context, facts, true, time.Now().UTC()); e != nil {
		return out, e
	}
	e = st.effect(ctx, seedID, func(tx *sql.Tx, p model.CapacityPolicySpec, actual model.CapacityNativeWorkerAttempt, current *nativeMemberRecord, now time.Time) error {
		if current.Revision != seed.Revision || current.State != "preparing" || !current.Context.NotAfter.After(now) || actual.Revision != a.Revision {
			return errNativeMember
		}
		planID, _ := nativeMemberUUID(current.Context.PlanID)
		plan, e := nativeMemberPlanLoadTx(ctx, tx, st.policy, planID)
		if e != nil {
			return e
		}
		if plan.Identity.Kind == "read_preflight" {
			return ErrCapacityDisabled
		}
		if e = st.parentCurrentTx(ctx, tx, p, actual, plan.Identity.Kind, now); e != nil {
			return e
		}
		mode, receipt, e := nativeMemberModeTx(ctx, tx, actual)
		if e != nil || mode != plan.Identity.Mode || receipt != current.Context.AdmissionReceiptSHA256 {
			return errNativeMember
		}
		if plan.Identity.Kind == "placement" {
			if e = nativeMemberBindFreeTx(ctx, tx, p, current.Context.Pod.UID); e != nil {
				return e
			}
		}
		if e = tx.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&now); e != nil {
			return e
		}
		c := current.Context
		c.PermitID = uuid.NewString()
		c.PlacementFenceSHA256 = nativeMemberDigest(facts.Fence)
		if len(facts.Observation.Inventory.Phase.Candidates) == 1 {
			n := facts.Observation.Inventory.Phase.Candidates[0]
			node := *c.Node
			node.UID, node.ResourceVersion = n.NodeUID, n.NodeResourceVersion
			c.Node = &node
		}
		if c.Pod != nil {
			pod := *c.Pod
			if c.Action == "bind_pod" {
				pod = facts.Observation.SubjectPod.Identity
			} else {
				for _, p := range facts.Observation.Pods {
					if p.Identity.UID == pod.UID {
						pod = p.Identity
					}
				}
			}
			c.Pod = &pod
		}
		if c.Action == "retire_registry" {
			c.RegistryResourceVersion = facts.Observation.Inventory.Phase.Registry.ResourceVersion
			c.RegistrySHA256 = facts.Observation.Inventory.Phase.Registry.AnnotationSHA256
		}
		c.NotAfter = nativeMemberMin(c.NotAfter, nativeMemberEffectiveFactsEnd(p, actual, facts))
		if plan.Identity.Kind == "placement" {
			c.NotAfter = nativeMemberMin(c.NotAfter, plan.Identity.ParentNotAfter)
		}
		if c.Action == "bind_pod" {
			c.UsefulCapacityEvidenceSHA256 = nativeMemberDigest(facts.Observation.Inventory.Phase)
		}
		if !c.NotAfter.After(now) || capacity.NativeWorkerMemberContextValid(p, actual, c, now, false) != nil {
			return errNativeMember
		}
		issued := nativeMemberRecord{Context: c, State: "issued", Revision: 1, SeedID: seedID, Facts: &facts}
		if e = nativeMemberWriteTx(ctx, tx, st.policy, issued, true, now); e != nil {
			return e
		}
		current.State = "no_effect"
		current.Revision++
		if e = nativeMemberWriteTx(ctx, tx, st.policy, *current, false, now); e != nil {
			return e
		}
		if plan.State == "preparing" {
			plan.State = "active"
			plan.SealedFacts = &facts
			plan.Revision++
			if e = nativeMemberPlanWriteTx(ctx, tx, st.policy, plan, false, now); e != nil {
				return e
			}
		}
		out = c
		return nil
	})
	return out, e
}

func nativeMemberCapabilityPlan(kind string) string {
	if kind == "read_preflight" {
		return "retirement"
	}
	return kind
}
