package repository

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"reflect"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

type FailedExpansionRead struct {
	Schema               string    `json:"schema"`
	ReadID               string    `json:"read_id"`
	CleanupID            string    `json:"cleanup_id"`
	Kind                 string    `json:"kind"`
	ClaimSequence        int64     `json:"claim_sequence"`
	AdmissionSHA256      string    `json:"admission_sha256"`
	ChildGrantID         string    `json:"child_grant_id"`
	IssuedAtCore         time.Time `json:"issued_at_core"`
	OriginalDeadlineCore time.Time `json:"original_deadline_core"`
}
type FailedExpansionReadReturn struct {
	ReadWire               []byte                                 `json:"read_wire"`
	ReceiptWire            []byte                                 `json:"receipt_wire,omitempty"`
	Schema                 string                                 `json:"schema"`
	Read                   FailedExpansionRead                    `json:"read"`
	Status                 string                                 `json:"status"`
	Plan                   *model.CapacityVMFleetPlan             `json:"plan,omitempty"`
	Receipt                *model.CapacityMutationReceipt         `json:"receipt,omitempty"`
	Observation            *model.CapacityVMRetirementObservation `json:"observation,omitempty"`
	ObserverSourceCommit   string                                 `json:"observer_source_commit,omitempty"`
	OriginalObserverReturn []byte                                 `json:"original_observer_return,omitempty"`
	StartedAtCore          time.Time                              `json:"started_at_core"`
	ReturnedAtCore         time.Time                              `json:"returned_at_core"`
	CallFailed             bool                                   `json:"call_failed"`
	OriginalContextFailed  bool                                   `json:"original_context_failed"`
	Pending                bool                                   `json:"pending"`
	Complete               bool                                   `json:"complete"`
}

func failedExpansionDestroyPlan(p model.CapacityPolicySpec, a FailedUnwitnessedExpansionCleanup) (capacity.MutationPlan, error) {
	b, err := capacity.VMObservationBinding(p, a.BindingName)
	if err != nil {
		return capacity.MutationPlan{}, err
	}
	for _, slot := range b.Slots {
		if slot.Slot == a.Slot && slot.DesiredSpec != nil {
			desired := *slot.DesiredSpec
			desired.Capability = b.DestroyCapability
			desired.ExpectedResourceID = a.ResourceID
			desired.ExpectedResourceCreatedAt = a.ResourceCreatedAt
			raw, e := json.Marshal(desired)
			if e != nil {
				return capacity.MutationPlan{}, e
			}
			plan, err := capacity.PrepareMutationPlan(p, model.CapacityMutationIssue{BindingName: b.Name, DesiredSpec: raw})
			if err != nil {
				return plan, err
			}
			return capacity.BindMutationDestroyPlan(plan, a.ResourceID, a.ResourceCreatedAt)
		}
	}
	return capacity.MutationPlan{}, ErrCapacityConflict
}

func (s CapacityStore) PrepareFailedExpansionRead(ctx context.Context, policy model.Manifest, kind string) (FailedExpansionRead, error) {
	var out FailedExpansionRead
	if kind != "inventory" && kind != "absence" {
		return out, ErrCapacityConflict
	}
	err := s.failedExpansionTransaction(ctx, policy, func(tx *sql.Tx, p model.CapacityPolicySpec, current model.CapacityIntent, a FailedUnwitnessedExpansionCleanup, c FailedUnwitnessedExpansionCleanupEvent, now time.Time) error {
		if s.guestNotifyOrigin == nil || s.guestNotifyOrigin.source != capacity.CurrentGuestCoreSource() || (s.guestNotifyOrigin.step.Use.Operation != capacity.RetireOriginalGuestOperation && s.guestNotifyOrigin.step.Use.Operation != "capacity.finish_original_guest_retirement") {
			return ErrCapacityConflict
		}
		_, events, e := loadFailedExpansionTx(ctx, tx, a.ID)
		if e != nil {
			return e
		}
		for _, old := range events {
			if old.Stage == kind+"_prepared" {
				var read FailedExpansionRead
				if json.Unmarshal(old.Evidence, &read) != nil {
					return ErrCapacityConflict
				}
				returned := false
				for _, r := range events {
					if r.Stage == kind+"_returned" {
						var v FailedExpansionReadReturn
						if json.Unmarshal(r.Evidence, &v) == nil && v.Read.ReadID == read.ReadID {
							returned = true
						}
					}
				}
				if !returned {
					return ErrCapacityConflict
				}
			}
		}
		if kind == "inventory" {
			for _, e := range events {
				if e.Stage == "issued" || e.Stage == "possible_send" {
					return ErrCapacityConflict
				}
			}
		} else {
			child, e := failedExpansionChildTx(ctx, tx, a)
			if e != nil || child.Grant.State != "settled" || child.Settlement == nil || child.Settlement.Outcome != "accepted" || !child.Settlement.AuxiliaryInventoryComplete {
				return ErrCapacityConflict
			}
		}
		deadline, ok := ctx.Deadline()
		issued := time.Now().UTC()
		budget := min(5*time.Second, time.Until(deadline), c.LeaseExpiresAt.Sub(now))
		if !ok || budget <= 0 || ctx.Err() != nil {
			return ErrCapacityLease
		}
		out = FailedExpansionRead{Schema: "failed_unwitnessed_expansion_native_read_v1", ReadID: uuid.NewString(), CleanupID: a.ID, Kind: kind, ClaimSequence: c.Sequence, AdmissionSHA256: capacity.GuestRetirementSHA(a), ChildGrantID: a.ChildGrantID, IssuedAtCore: issued, OriginalDeadlineCore: issued.Add(budget)}
		return s.appendFailedExpansionStageTx(ctx, tx, a, c, kind+"_prepared", out, now)
	})
	return out, err
}

func failedExpansionReadContent(r FailedExpansionReadReturn, p model.CapacityPolicySpec, a FailedUnwitnessedExpansionCleanup) (model.CapacityMutationProof, bool, error) {
	var proof model.CapacityMutationProof
	c := r.Read
	readWire, e := json.Marshal(c)
	if e != nil || !bytes.Equal(readWire, r.ReadWire) {
		return proof, false, ErrCapacityConflict
	}
	if r.Schema != "failed_unwitnessed_expansion_native_return_v1" || c.Schema != "failed_unwitnessed_expansion_native_read_v1" || !validCapacityExecutor(c.ReadID) || c.CleanupID != a.ID || c.ChildGrantID != a.ChildGrantID || c.AdmissionSHA256 != capacity.GuestRetirementSHA(a) || c.IssuedAtCore.IsZero() || !c.OriginalDeadlineCore.After(c.IssuedAtCore) || c.OriginalDeadlineCore.Sub(c.IssuedAtCore) > 5*time.Second || r.StartedAtCore.Before(c.IssuedAtCore) || r.ReturnedAtCore.Before(r.StartedAtCore) || !r.ReturnedAtCore.Before(c.OriginalDeadlineCore) || r.CallFailed || r.OriginalContextFailed {
		return proof, false, ErrCapacityConflict
	}
	plan, err := failedExpansionDestroyPlan(p, a)
	if err != nil {
		return proof, false, err
	}
	b := plan.Binding
	if c.Kind == "inventory" {
		v := r.Plan
		var desired model.CapacityMutationSpecV1
		if json.Unmarshal(plan.CanonicalSpec, &desired) != nil {
			return proof, false, ErrCapacityConflict
		}
		if r.Status != "dry_run" || v == nil || v.Server == nil || v.RequestSHA256 != plan.RequestSHA256 || !reflect.DeepEqual(v.DesiredSpec, desired) || v.Protected || v.CompensationOf != "" || v.CompensationIdentityVerified || v.ProviderFencingEvidence || v.WarmReadinessEvidence || v.BusinessReadyEvidence || v.Server.ID != a.ResourceID || v.Server.CreatedAt != a.ResourceCreatedAt || !v.Server.PhysicalSpecVerified || !v.Server.AuxiliaryInventoryComplete || v.Server.IndependentBillableResources || v.Server.ProtectedFromDelete || v.Server.Locked || v.Server.Labels["yggdrasil.io/intent"] != a.GrantID {
			return proof, false, ErrCapacityConflict
		}
		return proof, false, nil
	}
	if c.Kind != "absence" || r.Status != "observed" || r.Receipt == nil || r.Observation == nil || r.Receipt.Grant.GrantID != a.ChildGrantID || r.Receipt.Grant.ExpectedResourceID != a.ResourceID || r.Receipt.Grant.ExpectedResourceCreatedAt != a.ResourceCreatedAt || r.Receipt.Grant.CompensationOf != "" || r.ObserverSourceCommit != RetirementReadonlyAWSObserverSource() || !retirementReadonlyJoinValid(r.ObserverSourceCommit, b.OriginalProviderSourceCommit, c.ReadID, c, r.Receipt, r.Observation, r.OriginalObserverReturn) {
		return proof, false, ErrCapacityConflict
	}
	g := r.Receipt.Grant
	if g.State != "settled" || g.BindingName != b.Name || g.IntegrationInstanceID != b.IntegrationInstanceID || g.ScopeChecksum != b.ScopeChecksum || g.ProfileName != b.ProfileName || g.Capability != b.DestroyCapability || g.Slot != a.Slot || g.RequestSHA256 != plan.RequestSHA256 {
		return proof, false, ErrCapacityConflict
	}
	receiptWire, e := json.Marshal(r.Receipt)
	if e != nil || !bytes.Equal(receiptWire, r.ReceiptWire) {
		return proof, false, ErrCapacityConflict
	}
	o := r.Observation
	start, e1 := time.Parse(time.RFC3339Nano, o.ObservationStartedAt)
	server, e2 := time.Parse(time.RFC3339Nano, o.ServerObservedAt)
	end, e3 := time.Parse(time.RFC3339Nano, o.ObservedAt)
	if e1 != nil || e2 != nil || e3 != nil || start.IsZero() || start.After(server) || server.After(end) || end.Sub(start) > 60*time.Second || start.UTC().Format(time.RFC3339Nano) != o.ObservationStartedAt || end.UTC().Format(time.RFC3339Nano) != o.ObservedAt {
		return proof, false, ErrCapacityConflict
	}
	for _, aux := range o.AuxiliaryResources {
		at, e := time.Parse(time.RFC3339Nano, aux.ObservedAt)
		if e != nil || at.Before(start) || at.After(end) || at.UTC().Format(time.RFC3339Nano) != aux.ObservedAt {
			return proof, false, ErrCapacityConflict
		}
	}
	proof, err = capacity.GuestRetirementV2NativeAbsenceContent(p, b, *r.Receipt, *r.Observation, "failed-expansion-absence:"+c.ReadID)
	if err == nil {
		return proof, false, nil
	}
	if guestForwardAWSAbsencePending(*r.Observation, *r.Receipt) {
		return model.CapacityMutationProof{}, true, nil
	}
	return model.CapacityMutationProof{}, false, ErrCapacityConflict
}

// Persist the complete actual return before deciding whether it conveys fresh
// authority. Failed/late/malformed reads are durable and never reopen a send.
func (s CapacityStore) RecordFailedExpansionRead(ctx context.Context, policy model.Manifest, r FailedExpansionReadReturn) (model.CapacityMutationProof, bool, error) {
	var proof model.CapacityMutationProof
	if r.Pending || r.Complete {
		return proof, false, ErrCapacityConflict
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return proof, false, err
	}
	defer tx.Rollback()
	// Raw custody uses the same scope -> profile -> intent -> admission order,
	// without requiring a still-live lease. Qualification happens afterwards.
	var ns, env, domain, dimension string
	var policyRaw []byte
	if err = tx.QueryRowContext(ctx, `SELECT a.namespace,a.environment,a.domain,a.dimension,m.spec FROM public.capacity_failed_unwitnessed_expansion_cleanups a JOIN public.manifests m ON m.id=a.policy_id WHERE a.id=$1`, r.Read.CleanupID).Scan(&ns, &env, &domain, &dimension, &policyRaw); err != nil {
		return proof, false, err
	}
	var lockPolicy model.CapacityPolicySpec
	if json.Unmarshal(policyRaw, &lockPolicy) != nil || lockPolicy.Environment != env || lockPolicy.Domain != domain || lockPolicy.Dimension != dimension {
		return proof, false, ErrCapacityConflict
	}
	if err = lockMutationScope(ctx, tx, ns, lockPolicy); err != nil {
		return proof, false, err
	}
	if err = lockRetirementForwardBindingsTx(ctx, tx, lockPolicy.MutationBindings); err != nil {
		return proof, false, err
	}
	if _, err = loadCapacityIntent(ctx, tx, ns, lockPolicy, true); err != nil {
		return proof, false, err
	}
	a, events, err := loadFailedExpansionTx(ctx, tx, r.Read.CleanupID)
	if err != nil {
		return proof, false, err
	}
	var prepared FailedUnwitnessedExpansionCleanupEvent
	found := false
	for _, e := range events {
		if e.Stage == r.Read.Kind+"_prepared" {
			var c FailedExpansionRead
			if json.Unmarshal(e.Evidence, &c) == nil && reflect.DeepEqual(c, r.Read) {
				prepared = e
				found = true
			}
		}
		if e.Stage == r.Read.Kind+"_returned" {
			var old FailedExpansionReadReturn
			if json.Unmarshal(e.Evidence, &old) == nil && old.Read.ReadID == r.Read.ReadID {
				return proof, false, ErrCapacityConflict
			}
		}
	}
	if !found {
		return proof, false, ErrCapacityConflict
	}
	claim, ok := latestFailedExpansionClaim(events)
	if !ok || claim.Sequence != r.Read.ClaimSequence {
		return proof, false, ErrCapacityConflict
	}
	var recorded time.Time
	if err = tx.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&recorded); err != nil {
		return proof, false, err
	}
	if err = s.appendFailedExpansionStageTx(ctx, tx, a, claim, r.Read.Kind+"_returned", r, recorded); err != nil {
		return proof, false, err
	}
	if err = tx.Commit(); err != nil {
		return proof, false, err
	}
	pending := false
	err = s.failedExpansionTransaction(ctx, policy, func(tx *sql.Tx, p model.CapacityPolicySpec, current model.CapacityIntent, a FailedUnwitnessedExpansionCleanup, c FailedUnwitnessedExpansionCleanupEvent, now time.Time) error {
		if c.Sequence != r.Read.ClaimSequence || recorded.Before(prepared.RecordedAt) || recorded.Sub(prepared.RecordedAt)+5*time.Second > time.Duration(p.MaxEvidenceAgeSeconds)*time.Second || !capacity.Fresh(recorded, now, p.MaxEvidenceAgeSeconds) {
			return ErrCapacityConflict
		}
		var e error
		proof, pending, e = failedExpansionReadContent(r, p, a)
		if e != nil {
			return e
		}
		if r.Read.Kind == "absence" {
			child, e := failedExpansionChildTx(ctx, tx, a)
			if e != nil || !reflect.DeepEqual(guestMutationReceiptV2(child), *r.Receipt) {
				return ErrCapacityConflict
			}
		}
		stage := "inventory_qualified"
		if r.Read.Kind == "absence" {
			r.Pending = pending
			r.Complete = !pending
			stage = "absence_complete"
			if pending {
				stage = "pending_absence"
			}
			proof.ObservedAt = recorded
		}
		return s.appendFailedExpansionStageTx(ctx, tx, a, c, stage, r, now)
	})
	if err != nil {
		return model.CapacityMutationProof{}, false, err
	}
	return proof, pending, nil
}

func failedExpansionChildTx(ctx context.Context, tx *sql.Tx, a FailedUnwitnessedExpansionCleanup) (capacityMutationRecord, error) {
	var r capacityMutationRecord
	var raw []byte
	var linked string
	err := tx.QueryRowContext(ctx, `SELECT grant_record,failed_unwitnessed_expansion_cleanup_id::text FROM public.capacity_mutation_grants WHERE id=$1 FOR UPDATE`, a.ChildGrantID).Scan(&raw, &linked)
	if err != nil {
		return r, err
	}
	if json.Unmarshal(raw, &r) != nil || linked != a.ID || r.FailedUnwitnessedExpansionCleanupID != a.ID || r.Grant.CompensationOf != "" || r.Grant.GrantID != a.ChildGrantID || r.Grant.ExpectedResourceID != a.ResourceID || r.Grant.ExpectedResourceCreatedAt != a.ResourceCreatedAt || r.Grant.Slot != a.Slot || r.Grant.Capability != r.Binding.DestroyCapability {
		return r, ErrCapacityConflict
	}
	return r, nil
}

func (s CapacityStore) FailedExpansionDestroyReceipt(ctx context.Context, policy model.Manifest) (model.CapacityMutationReceipt, bool, error) {
	var out model.CapacityMutationReceipt
	found := false
	err := s.failedExpansionTransaction(ctx, policy, func(tx *sql.Tx, p model.CapacityPolicySpec, current model.CapacityIntent, a FailedUnwitnessedExpansionCleanup, c FailedUnwitnessedExpansionCleanupEvent, now time.Time) error {
		r, e := failedExpansionChildTx(ctx, tx, a)
		if e == sql.ErrNoRows {
			return nil
		}
		if e != nil {
			return e
		}
		out = guestMutationReceiptV2(r)
		found = true
		return nil
	})
	return out, found, err
}

func (s CapacityStore) IssueFailedExpansionDestroy(ctx context.Context, policy model.Manifest) (model.CapacityMutationGrant, error) {
	var out model.CapacityMutationGrant
	err := s.failedExpansionTransaction(ctx, policy, func(tx *sql.Tx, p model.CapacityPolicySpec, current model.CapacityIntent, a FailedUnwitnessedExpansionCleanup, c FailedUnwitnessedExpansionCleanupEvent, now time.Time) error {
		if !failedExpansionOriginalIntentEqual(a, current) || !capacityProfileCurrent(p, current.Decision, now) {
			return ErrCapacityConflict
		}
		_, events, e := loadFailedExpansionTx(ctx, tx, a.ID)
		if e != nil {
			return e
		}
		var inventory FailedExpansionReadReturn
		qualified := false
		for _, e := range events {
			if e.Stage == "issued" || e.Stage == "possible_send" {
				return ErrCapacityConflict
			}
			if e.Stage == "inventory_qualified" && e.Sequence > c.Sequence && json.Unmarshal(e.Evidence, &inventory) == nil && inventory.Read.ClaimSequence == c.Sequence && capacity.Fresh(e.RecordedAt, now, p.MaxEvidenceAgeSeconds) {
				qualified = true
			}
		}
		if !qualified {
			return ErrCapacityConflict
		}
		if _, _, e = failedExpansionReadContent(inventory, p, a); e != nil {
			return e
		}
		if e = s.guestNotifyRetirementFloorTx(ctx, tx, policy, p, current, a.Slot, now, "before_retirement_floor", ""); e != nil {
			return e
		}
		plan, e := failedExpansionDestroyPlan(p, a)
		if e != nil {
			return e
		}
		if e = checkMutationIntegration(ctx, tx, plan.Binding); e != nil {
			return e
		}
		provider, resource, e := capacityMutationEventIdentity(ctx, tx, plan.Binding)
		if e != nil || provider != "aws" {
			return ErrCapacityConflict
		}
		expires := minTime(now.Add(60*time.Second), *current.LeaseExpiresAt)
		out = model.CapacityMutationGrant{GrantID: a.ChildGrantID, BindingName: plan.Binding.Name, IntegrationInstanceID: plan.Binding.IntegrationInstanceID, ScopeChecksum: plan.Binding.ScopeChecksum, ProfileName: plan.Binding.ProfileName, Slot: a.Slot, Capability: plan.Capability, RequestSHA256: plan.RequestSHA256, ExpectedResourceID: a.ResourceID, ExpectedResourceCreatedAt: a.ResourceCreatedAt, ExpiresAt: expires, State: "issued"}
		r := capacityMutationRecord{FailedUnwitnessedExpansionCleanupID: a.ID, Grant: out, Binding: plan.Binding, PolicyID: policy.ID, PolicyChecksum: policy.Checksum, WorkflowID: s.WorkflowID, Generation: current.Generation, FencingToken: current.FencingToken, LeaseOwner: current.LeaseOwner, ExecutorID: s.ExecutorID, CreatedAt: now, EventProvider: provider, EventResource: resource}
		raw, e := json.Marshal(r)
		if e != nil {
			return e
		}
		if _, e = tx.ExecContext(ctx, `INSERT INTO public.capacity_mutation_grants(id,namespace,environment,domain,dimension,generation,integration_instance_id,scope_checksum,profile_name,slot,state,grant_record,expires_at,failed_unwitnessed_expansion_cleanup_id) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,'issued',$11::jsonb,$12,$13)`, out.GrantID, a.Namespace, a.Environment, a.Domain, a.Dimension, current.Generation, out.IntegrationInstanceID, out.ScopeChecksum, out.ProfileName, out.Slot, string(raw), expires, a.ID); e != nil {
			return e
		}
		return s.appendFailedExpansionStageTx(ctx, tx, a, c, "issued", out, now)
	})
	return out, err
}
func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}

func (s CapacityStore) MarkFailedExpansionPossibleSend(ctx context.Context, policy model.Manifest) error {
	return s.failedExpansionTransaction(ctx, policy, func(tx *sql.Tx, p model.CapacityPolicySpec, current model.CapacityIntent, a FailedUnwitnessedExpansionCleanup, c FailedUnwitnessedExpansionCleanupEvent, now time.Time) error {
		r, e := failedExpansionChildTx(ctx, tx, a)
		if e != nil || r.Grant.State != "issued" || !now.Before(r.Grant.ExpiresAt) {
			return ErrCapacityConflict
		}
		_, events, e := loadFailedExpansionTx(ctx, tx, a.ID)
		if e != nil {
			return e
		}
		for _, e := range events {
			if e.Stage == "possible_send" {
				return ErrCapacityConflict
			}
		}
		if e = s.guestNotifyRetirementFloorTx(ctx, tx, policy, p, current, a.Slot, now, "before_retirement_floor", ""); e != nil {
			return e
		}
		return s.appendFailedExpansionStageTx(ctx, tx, a, c, "possible_send", map[string]any{"grant_id": r.Grant.GrantID, "compensation_of": "", "inventory_basis": "pre_terminate_owned_attached_inventory", "original_auxiliary_inventory_complete": a.OriginalAuxiliaryKnown}, now)
	})
}

func (s CapacityStore) redeemFailedExpansionCleanupTx(ctx context.Context, tx *sql.Tx, r *capacityMutationRecord, p model.CapacityPolicySpec, now time.Time, request model.CapacityMutationRedeemRequest, response *model.CapacityMutationRedeemResponse) error {
	a, events, err := loadFailedExpansionTx(ctx, tx, r.FailedUnwitnessedExpansionCleanupID)
	if err != nil {
		return err
	}
	c, ok := latestFailedExpansionClaim(events)
	if !ok || r.Grant.GrantID != a.ChildGrantID || r.Grant.CompensationOf != "" || r.FencingToken != c.FencingToken || r.Generation != c.Generation || r.LeaseOwner != c.LeaseOwner || r.ExecutorID != c.ExecutorID {
		return ErrCapacityConflict
	}
	store := s
	store.failedExpansionOwner = &failedExpansionOwner{id: a.ID, claim: c.Sequence}
	store.WorkflowID = uuid.MustParse(a.WorkflowID)
	store.ExecutorID = c.ExecutorID
	store.OriginalRunID = uuid.MustParse(c.RunID)
	var policy model.Manifest
	policy.ID = uuid.MustParse(a.PolicyID)
	policy.Checksum = a.PolicyChecksum
	policy.Metadata.Namespace = a.Namespace
	if err = tx.QueryRowContext(ctx, `SELECT name,spec,version FROM public.manifests WHERE id=$1`, policy.ID).Scan(&policy.Metadata.Name, &policy.Spec, &policy.Version); err != nil {
		return err
	}
	var wf model.Manifest
	if err = tx.QueryRowContext(ctx, `SELECT id,namespace,name,version,checksum,spec,active FROM public.manifests WHERE id=$1 AND kind='workflow'`, a.WorkflowID).Scan(&wf.ID, &wf.Metadata.Namespace, &wf.Metadata.Name, &wf.Version, &wf.Checksum, &wf.Spec, &wf.Metadata.Active); err != nil || !wf.Metadata.Active {
		return ErrCapacityConflict
	}
	store.guestReconcile = &guestReconcileSource{workflow: wf, source: capacity.CurrentGuestCoreSource()}
	current, err := loadCapacityIntent(ctx, tx, a.Namespace, p, true)
	if err != nil {
		return err
	}
	if _, _, _, err = store.failedExpansionActiveClaimTx(ctx, tx, policy, current, now); err != nil {
		return err
	}
	sent := false
	for _, e := range events {
		sent = sent || e.Stage == "possible_send" && e.Sequence > c.Sequence
	}
	if !sent {
		return ErrCapacityConflict
	}
	if err = store.guestNotifyRetirementFloorTx(ctx, tx, policy, p, current, a.Slot, now, "before_retirement_floor", ""); err != nil {
		return err
	}
	r.AttemptID = request.AttemptID
	r.SettlementTokenSHA256 = request.SettlementTokenSHA256
	r.Grant.State = "redeemed"
	response.Mode = "write_once"
	return nil
}

func (s CapacityStore) failedExpansionAbsenceAfterPGTx(ctx context.Context, tx *sql.Tx, id string) (time.Time, error) {
	a, events, err := loadFailedExpansionTx(ctx, tx, id)
	if err != nil {
		return time.Time{}, err
	}
	for i := len(events) - 1; i >= 0; i-- {
		if events[i].Stage == "absence_complete" {
			var r FailedExpansionReadReturn
			if json.Unmarshal(events[i].Evidence, &r) != nil || !r.Complete || r.Pending {
				return time.Time{}, ErrCapacityConflict
			}
			var raw []byte
			if err = tx.QueryRowContext(ctx, `SELECT spec FROM public.manifests WHERE id=$1`, a.PolicyID).Scan(&raw); err != nil {
				return time.Time{}, err
			}
			var p model.CapacityPolicySpec
			if json.Unmarshal(raw, &p) != nil {
				return time.Time{}, ErrCapacityConflict
			}
			if _, pending, e := failedExpansionReadContent(r, p, a); e != nil || pending {
				return time.Time{}, ErrCapacityConflict
			}
			child, e := failedExpansionChildTx(ctx, tx, a)
			if e != nil || !reflect.DeepEqual(guestMutationReceiptV2(child), *r.Receipt) {
				return time.Time{}, ErrCapacityConflict
			}
			return events[i].RecordedAt, nil
		}
	}
	return time.Time{}, ErrCapacityConflict
}

func (s CapacityStore) CompleteFailedExpansionCleanup(ctx context.Context, policy model.Manifest) (model.CapacityIntent, error) {
	var out model.CapacityIntent
	err := s.failedExpansionTransaction(ctx, policy, func(tx *sql.Tx, p model.CapacityPolicySpec, current model.CapacityIntent, a FailedUnwitnessedExpansionCleanup, c FailedUnwitnessedExpansionCleanupEvent, now time.Time) error {
		at, e := s.failedExpansionAbsenceAfterPGTx(ctx, tx, a.ID)
		if e != nil || !capacity.Fresh(at, now, p.MaxEvidenceAgeSeconds) {
			return ErrCapacityConflict
		}
		if e = s.guestNotifyRetirementFloorTx(ctx, tx, policy, p, current, a.Slot, now, "after_retirement_floor", ""); e != nil {
			return e
		}
		child, e := failedExpansionChildTx(ctx, tx, a)
		if e != nil || child.Grant.State != "settled" {
			return ErrCapacityConflict
		}
		// Terminal evidence closes only this admitted failed expansion. It does
		// not promote the old desiredN2 or issue an enrolled Guest success.
		if e = s.appendFailedExpansionStageTx(ctx, tx, a, c, "terminal", map[string]any{"child_grant_id": a.ChildGrantID, "absence_recorded_at": at, "original_guest_success": false, "clean_cycle_credit": false, "serving_or_business_or_savings_authority": false}, now); e != nil {
			return e
		}
		child.Grant.State = "confirmed"
		if e = saveMutationGrant(ctx, tx, child); e != nil {
			return e
		}
		// Original accepted SDK/settlement remain byte-identical. Only its final
		// ledger state is closed, after exact child+paid-aux absence and real floor.
		var raw []byte
		if e = tx.QueryRowContext(ctx, `SELECT grant_record FROM public.capacity_mutation_grants WHERE id=$1 FOR UPDATE`, a.GrantID).Scan(&raw); e != nil {
			return e
		}
		var parent capacityMutationRecord
		if json.Unmarshal(raw, &parent) != nil {
			return ErrCapacityConflict
		}
		parent.Grant.State = "cleanup_closed"
		if e = saveMutationGrant(ctx, tx, parent); e != nil {
			return e
		}
		out = current
		out.Phase = "hold"
		out.Decision.Action = "hold"
		out.Decision.Reason = "failed_expansion_cleaned_original_failure_preserved"
		out.Decision.Units = a.SurvivorCount
		out.Decision.ExecutionPermitted = false
		out.LeaseOwner = ""
		out.LeaseExecutorID = ""
		out.LeaseExpiresAt = nil
		out.UpdatedAt = now
		return persistRetirementForwardIntentTx(ctx, tx, current, out, "failed-unwitnessed-expansion:"+a.ID+":terminal")
	})
	return out, err
}
