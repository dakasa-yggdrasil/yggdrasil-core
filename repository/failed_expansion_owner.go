package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"reflect"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

// This selector is never decoded from JSON. Only a locked real claim installs
// it. Ordinary and historical-schema93 canary paths do not touch M94 tables.
type failedExpansionOwner struct {
	id    string
	claim int64
}

func loadFailedExpansionTx(ctx context.Context, tx *sql.Tx, id string) (FailedUnwitnessedExpansionCleanup, []FailedUnwitnessedExpansionCleanupEvent, error) {
	var a FailedUnwitnessedExpansionCleanup
	var raw []byte
	var sha string
	if err := tx.QueryRowContext(ctx, `SELECT original_wire,admission_sha256 FROM public.capacity_failed_unwitnessed_expansion_cleanups WHERE id=$1 FOR UPDATE`, id).Scan(&raw, &sha); err != nil {
		return a, nil, err
	}
	if originalDispositionDigest(raw) != sha || capacity.DecodeGuestLifecycle(raw, &a) != nil || a.ID != id || a.Schema != FailedUnwitnessedExpansionCleanupSchema {
		return a, nil, ErrCapacityConflict
	}
	rows, err := tx.QueryContext(ctx, `SELECT original_wire,event_sha256 FROM public.capacity_failed_unwitnessed_expansion_cleanup_events WHERE cleanup_id=$1 ORDER BY sequence`, id)
	if err != nil {
		return a, nil, err
	}
	defer rows.Close()
	var out []FailedUnwitnessedExpansionCleanupEvent
	for rows.Next() {
		var e FailedUnwitnessedExpansionCleanupEvent
		if rows.Scan(&raw, &sha) != nil || originalDispositionDigest(raw) != sha || capacity.DecodeGuestLifecycle(raw, &e) != nil || e.CleanupID != id || e.Sequence != int64(len(out)+1) {
			return a, nil, ErrCapacityConflict
		}
		out = append(out, e)
	}
	return a, out, rows.Err()
}

func latestFailedExpansionClaim(events []FailedUnwitnessedExpansionCleanupEvent) (FailedUnwitnessedExpansionCleanupEvent, bool) {
	for i := len(events) - 1; i >= 0; i-- {
		if events[i].Stage == "claimed" {
			return events[i], true
		}
	}
	return FailedUnwitnessedExpansionCleanupEvent{}, false
}

func (s CapacityStore) failedExpansionActiveClaimTx(ctx context.Context, tx *sql.Tx, policy model.Manifest, current model.CapacityIntent, now time.Time) (FailedUnwitnessedExpansionCleanup, FailedUnwitnessedExpansionCleanupEvent, bool, error) {
	var a FailedUnwitnessedExpansionCleanup
	var c FailedUnwitnessedExpansionCleanupEvent
	if s.failedExpansionOwner == nil {
		return a, c, false, nil
	}
	if current.FailedUnwitnessedExpansionCleanupID != s.failedExpansionOwner.id || current.Decision.Reason != FailedUnwitnessedExpansionCleanupMode {
		return a, c, true, ErrCapacityConflict
	}
	a, events, err := loadFailedExpansionTx(ctx, tx, s.failedExpansionOwner.id)
	if err != nil {
		return a, c, true, err
	}
	c, ok := latestFailedExpansionClaim(events)
	if !ok || c.Sequence != s.failedExpansionOwner.claim || events[len(events)-1].Stage == "terminal" || a.PolicyID != policy.ID.String() || a.PolicyChecksum != policy.Checksum || a.WorkflowID != s.WorkflowID.String() || c.RunID != s.OriginalRunID.String() || c.Generation != current.Generation || c.FencingToken != current.FencingToken || c.LeaseOwner != current.LeaseOwner || c.ExecutorID != current.LeaseExecutorID || c.ExecutorID != s.ExecutorID || c.LeaseExpiresAt == nil || current.LeaseExpiresAt == nil || !c.LeaseExpiresAt.Equal(*current.LeaseExpiresAt) || !now.Before(*c.LeaseExpiresAt) {
		return a, c, true, ErrCapacityLease
	}
	if !failedExpansionOriginalIntentEqual(a, current) {
		return a, c, true, ErrCapacityConflict
	}
	if err = failedExpansionRosterCurrentTx(ctx, tx, a); err != nil {
		return a, c, true, err
	}
	if err = failedExpansionOriginalsTx(ctx, tx, a); err != nil {
		return a, c, true, err
	}
	var policyID, sha string
	var active bool
	if tx.QueryRowContext(ctx, `SELECT id::text,checksum,active FROM public.manifests WHERE kind='capacity_policy' AND namespace=$1 AND name=$2 ORDER BY version DESC,id DESC LIMIT 1 FOR SHARE`, policy.Metadata.Namespace, policy.Metadata.Name).Scan(&policyID, &sha, &active) != nil || !active || policyID != a.PolicyID || sha != a.PolicyChecksum {
		return a, c, true, ErrCapacityConflict
	}
	var p model.CapacityPolicySpec
	if json.Unmarshal(policy.Spec, &p) != nil {
		return a, c, true, ErrCapacityConflict
	}
	if err = s.installedGuestDispatchRunTx(ctx, tx, policy, p, s.OriginalRunID, nil); err != nil {
		return a, c, true, err
	}
	if err = failedExpansionQuietTx(ctx, tx, a, s.OriginalRunID.String()); err != nil {
		return a, c, true, err
	}
	return a, c, true, nil
}

// Preserve every original grant/SDK/preregistration/job/run byte. Only the
// append-only cleanup ledger and its explicitly linked new child may change.
func failedExpansionOriginalsTx(ctx context.Context, tx *sql.Tx, a FailedUnwitnessedExpansionCleanup) error {
	var good bool
	err := tx.QueryRowContext(ctx, `SELECT g.state='settled' AND encode(sha256(convert_to(g.grant_record::text,'UTF8')),'hex')=$2 AND encode(sha256(p.original_wire),'hex')=$3 AND encode(sha256(convert_to(to_jsonb(j)::text,'UTF8')),'hex')=$4 AND encode(sha256(convert_to(to_jsonb(w)::text,'UTF8')),'hex')=$5 AND NOT EXISTS(SELECT 1 FROM public.capacity_guest_original_create_witnesses WHERE preregistration_id=p.id) AND NOT EXISTS(SELECT 1 FROM public.capacity_vm_original_enrollments WHERE preregistration_id=p.id) AND NOT EXISTS(SELECT 1 FROM public.capacity_guest_original_installations WHERE preregistration_id=p.id) AND NOT EXISTS(SELECT 1 FROM public.capacity_vm_retirement_intents WHERE preregistration_id=p.id) FROM public.capacity_mutation_grants g JOIN public.capacity_vm_provisioning_preregistrations p ON p.id=$6 AND p.create_grant_id=g.id JOIN public.capacity_dispatch_jobs j ON j.id=$7 JOIN public.workflow_runs w ON w.id=j.run_id WHERE g.id=$1`, a.GrantID, a.OriginalGrantSHA256, a.OriginalPreregSHA256, a.OriginalDispatchSHA256, a.OriginalRunSHA256, a.PreregistrationID, a.JobID).Scan(&good)
	if err != nil {
		return err
	}
	if !good {
		return ErrCapacityConflict
	}
	return nil
}

// Count logical workflows as well as all physical dispatch states. Only the
// genuine currently started owning run may be excluded, after Source checks.
func failedExpansionQuietTx(ctx context.Context, tx *sql.Tx, a FailedUnwitnessedExpansionCleanup, own string) error {
	var busy bool
	err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM public.capacity_dispatch_jobs j WHERE j.realm=$1 AND j.environment=$2 AND j.domain=$3 AND j.dimension=$4 AND j.run_id::text IS DISTINCT FROM NULLIF($5,'') AND(j.state IN('queued','started','unknown') OR j.state='returned' AND j.finalization_ack_at IS NULL)) OR EXISTS(SELECT 1 FROM public.workflow_runs w WHERE w.workflow_namespace=(SELECT namespace FROM public.manifests WHERE id=$6::uuid) AND w.workflow_name=(SELECT name FROM public.manifests WHERE id=$6::uuid) AND w.id::text IS DISTINCT FROM NULLIF($5,'') AND(COALESCE(w.status,'') NOT IN('succeeded','failed','cancelled') OR w.finished_at IS NULL)) OR EXISTS(SELECT 1 FROM public.capacity_mutation_grants g WHERE g.namespace=$1 AND g.environment=$2 AND g.domain=$3 AND g.dimension=$4 AND g.id<>$7::uuid AND g.id<>$8::uuid AND `+capacityGrantUndisposedSQL+` AND g.state IN('issued','redeemed','settled','compensating'))`, a.Namespace, a.Environment, a.Domain, a.Dimension, own, a.WorkflowID, a.GrantID, a.ChildGrantID).Scan(&busy)
	if err != nil {
		return err
	}
	if busy {
		return ErrCapacityConflict
	}
	return nil
}

func (s CapacityStore) BindFailedExpansionCleanup(ctx context.Context, policy model.Manifest, generation, fence int64, owner string) (CapacityStore, FailedUnwitnessedExpansionCleanup, bool, error) {
	var a FailedUnwitnessedExpansionCleanup
	p, err := parseCapacityPolicy(policy)
	if err != nil {
		return s, a, false, err
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return s, a, false, err
	}
	defer tx.Rollback()
	if err = lockMutationScope(ctx, tx, policy.Metadata.Namespace, p); err != nil {
		return s, a, false, err
	}
	current, err := loadCapacityIntent(ctx, tx, policy.Metadata.Namespace, p, true)
	if err != nil {
		return s, a, false, err
	}
	if current.FailedUnwitnessedExpansionCleanupID == "" {
		return s, a, false, nil
	}
	if generation != current.Generation || fence != current.FencingToken || owner != current.LeaseOwner {
		return s, a, true, ErrCapacityConflict
	}
	a, events, err := loadFailedExpansionTx(ctx, tx, current.FailedUnwitnessedExpansionCleanupID)
	if err != nil {
		return s, a, true, err
	}
	c, ok := latestFailedExpansionClaim(events)
	if !ok {
		return s, a, true, ErrCapacityConflict
	}
	s.failedExpansionOwner = &failedExpansionOwner{id: a.ID, claim: c.Sequence}
	var now time.Time
	if err = tx.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		return s, a, true, err
	}
	if s.guestReconcile == nil {
		if s.guestNotifyOrigin == nil || s.guestNotifyOrigin.source != capacity.CurrentGuestCoreSource() || (s.guestNotifyOrigin.step.Use.Operation != capacity.RetireOriginalGuestOperation && s.guestNotifyOrigin.step.Use.Operation != "capacity.finish_original_guest_retirement") {
			return s, a, true, ErrCapacityConflict
		}
		var wf model.Manifest
		if err = tx.QueryRowContext(ctx, `SELECT id,namespace,name,version,checksum,spec,active FROM public.manifests WHERE id=$1 AND kind='workflow'`, a.WorkflowID).Scan(&wf.ID, &wf.Metadata.Namespace, &wf.Metadata.Name, &wf.Version, &wf.Checksum, &wf.Spec, &wf.Metadata.Active); err != nil || !wf.Metadata.Active {
			return s, a, true, ErrCapacityConflict
		}
		var graph model.WorkflowManifestSpec
		if json.Unmarshal(wf.Spec, &graph) != nil {
			return s, a, true, ErrCapacityConflict
		}
		found := false
		for _, step := range graph.Steps {
			found = found || reflect.DeepEqual(step, s.guestNotifyOrigin.step)
		}
		if !found {
			return s, a, true, ErrCapacityConflict
		}
		s.guestReconcile = &guestReconcileSource{workflow: wf, step: s.guestNotifyOrigin.step, source: capacity.CurrentGuestCoreSource()}
	}
	_, _, _, err = s.failedExpansionActiveClaimTx(ctx, tx, policy, current, now)
	return s, a, true, err
}

// M94 is selected by its typed intent marker. Ordinary93 intents return before
// any M94 table access; historical fixtures are not reclassified as schema94.
func (s CapacityStore) TryClaimFailedExpansionCleanup(ctx context.Context, policy model.Manifest) (CapacityStore, model.CapacityIntent, FailedUnwitnessedExpansionCleanup, bool, error) {
	var zero model.CapacityIntent
	var a FailedUnwitnessedExpansionCleanup
	if s.DB == nil || s.guestReconcile == nil || s.guestReconcile.step.Use.Operation != capacity.PlanOriginalGuestOperation || !guestReconcileLive(ctx) || s.OriginalRunID == uuid.Nil {
		return s, zero, a, false, ErrCapacityConflict
	}
	p, err := parseCapacityPolicy(policy)
	if err != nil {
		return s, zero, a, false, err
	}
	if !s.ExecutionEnabled || !p.ExecutionEnabled {
		return s, zero, a, false, ErrCapacityDisabled
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return s, zero, a, false, err
	}
	defer tx.Rollback()
	if err = lockMutationScope(ctx, tx, policy.Metadata.Namespace, p); err != nil {
		return s, zero, a, false, err
	}
	if err = lockRetirementForwardBindingsTx(ctx, tx, p.MutationBindings); err != nil {
		return s, zero, a, false, err
	}
	current, err := loadCapacityIntent(ctx, tx, policy.Metadata.Namespace, p, true)
	if errors.Is(err, sql.ErrNoRows) {
		return s, zero, a, false, nil
	}
	if err != nil {
		return s, zero, a, false, err
	}
	if current.FailedUnwitnessedExpansionCleanupID == "" {
		return s, zero, a, false, nil
	}
	a, events, err := loadFailedExpansionTx(ctx, tx, current.FailedUnwitnessedExpansionCleanupID)
	if err != nil {
		return s, zero, a, true, err
	}
	if len(events) == 0 {
		return s, zero, a, true, ErrCapacityConflict
	}
	if events[len(events)-1].Stage == "terminal" {
		if current.PolicyID != policy.ID || current.PolicyChecksum != policy.Checksum {
			return s, current, a, false, nil
		}
		return s, current, a, true, nil
	}
	if err = s.guestReconcileSourceTx(ctx, tx, policy, p); err != nil {
		return s, zero, a, true, err
	}
	if err = s.installedGuestDispatchRunTx(ctx, tx, policy, p, s.OriginalRunID, nil); err != nil {
		return s, zero, a, true, err
	}
	var now time.Time
	if err = tx.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		return s, zero, a, true, err
	}
	if current.PolicyID != policy.ID || current.PolicyChecksum != policy.Checksum || current.FencingToken >= maxCapacityGeneration || current.LeaseExpiresAt == nil || !now.After(*current.LeaseExpiresAt) || current.Generation != a.OriginalGeneration || current.Decision.Reason != FailedUnwitnessedExpansionCleanupMode {
		return s, zero, a, true, ErrCapacityLease
	}
	if err = failedExpansionOriginalsTx(ctx, tx, a); err != nil {
		return s, zero, a, true, err
	}
	if err = failedExpansionQuietTx(ctx, tx, a, s.OriginalRunID.String()); err != nil {
		return s, zero, a, true, err
	}
	if !failedExpansionOriginalIntentEqual(a, current) {
		return s, zero, a, true, ErrCapacityConflict
	}
	if err = failedExpansionRosterCurrentTx(ctx, tx, a); err != nil {
		return s, zero, a, true, err
	}
	if events[len(events)-1].Stage != "requested" {
		// Later ownership can only continue an authenticated Pending or complete read
		// of the same settled child, after its actual failed workflow ACK/expiry.
		old, ok := latestFailedExpansionClaim(events)
		if !ok {
			return s, zero, a, true, ErrCapacityConflict
		}
		if err = failedExpansionClosedOwnerTx(ctx, tx, old); err != nil {
			return s, zero, a, true, err
		}
		var pending FailedExpansionReadReturn
		if (events[len(events)-1].Stage != "pending_absence" && events[len(events)-1].Stage != "absence_complete") || json.Unmarshal(events[len(events)-1].Evidence, &pending) != nil || pending.Pending == pending.Complete {
			return s, zero, a, true, ErrCapacityConflict
		}
		child, childErr := failedExpansionChildTx(ctx, tx, a)
		if childErr != nil || pending.Receipt == nil || !reflect.DeepEqual(guestMutationReceiptV2(child), *pending.Receipt) {
			return s, zero, a, true, ErrCapacityConflict
		}
		if _, actualPending, contentErr := failedExpansionReadContent(pending, p, a); contentErr != nil || actualPending != pending.Pending {
			err = ErrCapacityConflict
			return s, zero, a, true, err
		}
	}
	// Original failed N2 decision/baseline remain unchanged. Only this distinct
	// ownership epoch and its typed reason are advanced; the old lease is not renewed.
	next := current
	next.FencingToken++
	next.LeaseOwner = uuid.NewString()
	next.LeaseExecutorID = s.ExecutorID
	expires := now.Add(time.Duration(p.LeaseSeconds) * time.Second)
	next.LeaseExpiresAt = &expires
	next.UpdatedAt = now
	c := FailedUnwitnessedExpansionCleanupEvent{Schema: FailedUnwitnessedExpansionCleanupSchema, CleanupID: a.ID, Sequence: int64(len(events) + 1), Stage: "claimed", RunID: s.OriginalRunID.String(), Generation: next.Generation, FencingToken: next.FencingToken, LeaseOwner: next.LeaseOwner, ExecutorID: s.ExecutorID, LeaseExpiresAt: &expires, ChildGrantID: a.ChildGrantID, RecordedAt: now}
	if err = s.appendFailedExpansionEventTx(ctx, tx, c); err != nil {
		return s, zero, a, true, err
	}
	if err = persistRetirementForwardIntentTx(ctx, tx, current, next, "failed-unwitnessed-expansion:"+a.ID+":claimed"); err != nil {
		return s, zero, a, true, err
	}
	if err = tx.Commit(); err != nil {
		return s, zero, a, true, err
	}
	s.failedExpansionOwner = &failedExpansionOwner{id: a.ID, claim: c.Sequence}
	return s, next, a, true, nil
}

func failedExpansionClosedOwnerTx(ctx context.Context, tx *sql.Tx, c FailedUnwitnessedExpansionCleanupEvent) error {
	var ok bool
	err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM public.capacity_dispatch_jobs j JOIN public.workflow_runs w ON w.id=j.run_id WHERE j.run_id=$1::uuid AND j.state='returned' AND j.return_status='failed' AND j.finalization_ack_at>=j.returned_at AND w.status='failed' AND w.finished_at=j.returned_at)`, c.RunID).Scan(&ok)
	if err != nil {
		return err
	}
	if !ok {
		return ErrCapacityConflict
	}
	return nil
}

func (s CapacityStore) failedExpansionTransaction(ctx context.Context, policy model.Manifest, fn func(*sql.Tx, model.CapacityPolicySpec, model.CapacityIntent, FailedUnwitnessedExpansionCleanup, FailedUnwitnessedExpansionCleanupEvent, time.Time) error) error {
	if s.failedExpansionOwner == nil {
		return ErrCapacityConflict
	}
	p, err := parseCapacityPolicy(policy)
	if err != nil {
		return err
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err = lockMutationScope(ctx, tx, policy.Metadata.Namespace, p); err != nil {
		return err
	}
	if err = lockRetirementForwardBindingsTx(ctx, tx, p.MutationBindings); err != nil {
		return err
	}
	current, err := loadCapacityIntent(ctx, tx, policy.Metadata.Namespace, p, true)
	if err != nil {
		return err
	}
	var now time.Time
	if err = tx.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		return err
	}
	a, c, active, err := s.failedExpansionActiveClaimTx(ctx, tx, policy, current, now)
	if err != nil {
		return err
	}
	if !active {
		return ErrCapacityConflict
	}
	if err = s.checkLease(p, policy, &current, c.Generation, c.FencingToken, c.LeaseOwner, now); err != nil {
		return err
	}
	if err = fn(tx, p, current, a, c, now.UTC()); err != nil {
		return err
	}
	return tx.Commit()
}

func (s CapacityStore) appendFailedExpansionStageTx(ctx context.Context, tx *sql.Tx, a FailedUnwitnessedExpansionCleanup, c FailedUnwitnessedExpansionCleanupEvent, stage string, evidence any, now time.Time) error {
	_, events, err := loadFailedExpansionTx(ctx, tx, a.ID)
	if err != nil {
		return err
	}
	raw, err := json.Marshal(evidence)
	if err != nil {
		return err
	}
	c.Sequence = int64(len(events) + 1)
	c.Stage = stage
	c.RecordedAt = now
	c.Evidence = raw
	return s.appendFailedExpansionEventTx(ctx, tx, c)
}

// The field equality is stronger than a slot count. Updating only observed_at
// and receipt_ref after a complete authenticated native inventory is allowed;
// identity, registered birth, profile and sealed enrollment never change.
func (s CapacityStore) RefreshFailedExpansionSurvivors(ctx context.Context, policy model.Manifest, inv model.CapacityVMFleetInventory) error {
	return s.failedExpansionTransaction(ctx, policy, func(tx *sql.Tx, p model.CapacityPolicySpec, current model.CapacityIntent, a FailedUnwitnessedExpansionCleanup, c FailedUnwitnessedExpansionCleanupEvent, now time.Time) error {
		b, err := capacity.VMObservationBinding(p, a.BindingName)
		if err != nil {
			return err
		}
		proofs, err := capacity.VMInventoryProofs(p, b, inv, "", 0, now, "failed-expansion-native-survivors:"+a.ID)
		if err != nil {
			return err
		}
		found := map[int]bool{}
		target := false
		for _, proof := range proofs {
			if proof.Slot == a.Slot {
				if proof.ResourceID != a.ResourceID || proof.ResourceCreatedAt != a.ResourceCreatedAt {
					return ErrCapacityConflict
				}
				target = true
				continue
			}
			if proof.Slot < 1 || proof.Slot >= a.Slot {
				return ErrCapacityConflict
			}
			slot, exists, e := loadMutationSlot(ctx, tx, a.Namespace, p, b, proof.Slot)
			if e != nil || !exists || slot.Tombstone || slot.ResourceID != proof.ResourceID || slot.ResourceCreatedAt != proof.ResourceCreatedAt || slot.BindingName != b.Name || slot.ProfileName != b.ProfileName || slot.DesiredSpecSHA256 != proof.RequestSHA256 {
				return ErrCapacityConflict
			}
			slot.ObservedAt = proof.ObservedAt
			slot.ReceiptRef = proof.ReceiptRef
			if e = saveMutationSlot(ctx, tx, a.Namespace, p, b, proof.Slot, slot); e != nil {
				return e
			}
			found[proof.Slot] = true
		}
		if len(found) != a.SurvivorCount {
			return ErrCapacityConflict
		}
		_, events, err := loadFailedExpansionTx(ctx, tx, a.ID)
		if err != nil {
			return err
		}
		absent := false
		for _, e := range events {
			if e.Stage == "absence_complete" {
				var r FailedExpansionReadReturn
				if json.Unmarshal(e.Evidence, &r) == nil && r.Complete {
					absent = true
				}
			}
		}
		if absent && target {
			return ErrCapacityConflict
		}
		if !target && !absent {
			// A previously accepted child may already have removed the VM
			// while its sealed paid auxiliary remains Pending. Inventory
			// refresh grants survivor freshness only, never paid absence.
			child, e := failedExpansionChildTx(ctx, tx, a)
			if e != nil || child.Grant.State != "settled" || child.Settlement == nil || child.Settlement.Outcome != "accepted" || !child.Settlement.AuxiliaryInventoryComplete {
				return ErrCapacityConflict
			}
			knownPending := false
			for _, e := range events {
				if e.Stage == "pending_absence" {
					var r FailedExpansionReadReturn
					if json.Unmarshal(e.Evidence, &r) == nil {
						_, pending, readErr := failedExpansionReadContent(r, p, a)
						knownPending = knownPending || readErr == nil && pending
					}
				}
			}
			if !knownPending {
				return ErrCapacityConflict
			}
		}
		return nil
	})
}

// Prevent mutation of the admitted intent by generic callers, while preserving
// a separately authorized later policy version after real terminal cleanup.
func failedExpansionOriginalIntentEqual(a FailedUnwitnessedExpansionCleanup, current model.CapacityIntent) bool {
	var old model.CapacityIntent
	if capacity.DecodeGuestLifecycle(a.OriginalIntentWire, &old) != nil {
		return false
	}
	old.FailedUnwitnessedExpansionCleanupID = current.FailedUnwitnessedExpansionCleanupID
	old.Decision.Reason = current.Decision.Reason
	old.FencingToken = current.FencingToken
	old.LeaseOwner = current.LeaseOwner
	old.LeaseExecutorID = current.LeaseExecutorID
	old.LeaseExpiresAt = current.LeaseExpiresAt
	old.UpdatedAt = current.UpdatedAt
	return reflect.DeepEqual(old, current)
}

func failedExpansionRosterCurrentTx(ctx context.Context, tx *sql.Tx, a FailedUnwitnessedExpansionCleanup) error {
	if originalDispositionDigest(a.SurvivorRosterWire) != a.SurvivorRosterSHA256 {
		return ErrCapacityConflict
	}
	var old []capacityResourceSlot
	if json.Unmarshal(a.SurvivorRosterWire, &old) != nil || len(old) != a.SurvivorCount {
		return ErrCapacityConflict
	}
	rows, err := tx.QueryContext(ctx, `SELECT slot,slot_record FROM public.capacity_resource_slots WHERE namespace=$1 AND environment=$2 AND domain=$3 AND dimension=$4 AND resource_id<>'' ORDER BY slot FOR SHARE`, a.Namespace, a.Environment, a.Domain, a.Dimension)
	if err != nil {
		return err
	}
	defer rows.Close()
	n := 0
	for rows.Next() {
		var slot int
		var raw []byte
		var current capacityResourceSlot
		if rows.Scan(&slot, &raw) != nil || json.Unmarshal(raw, &current) != nil || slot != n+1 || n >= len(old) {
			return ErrCapacityConflict
		}
		original := old[n]
		original.ObservedAt = current.ObservedAt
		original.ReceiptRef = current.ReceiptRef
		if !reflect.DeepEqual(original, current) {
			return ErrCapacityConflict
		}
		n++
	}
	if rows.Err() != nil {
		return rows.Err()
	}
	if n != a.SurvivorCount {
		return ErrCapacityConflict
	}
	return nil
}

// Same publication-budget query and gap as the existing native-forward lane.
// Waiting spends only the current original context/lease; Issue still owns the
// one actual publication attempt and independently rechecks the entire budget.
func (s CapacityStore) FailedExpansionPublicationDelay(ctx context.Context, policy model.Manifest, preID string) (time.Duration, error) {
	var delay time.Duration
	err := s.failedExpansionTransaction(ctx, policy, func(tx *sql.Tx, p model.CapacityPolicySpec, current model.CapacityIntent, a FailedUnwitnessedExpansionCleanup, c FailedUnwitnessedExpansionCleanupEvent, now time.Time) error {
		if s.guestNotifyOrigin == nil || p.GuestNotifyCanaryBinding == nil || preID == a.PreregistrationID {
			return ErrCapacityConflict
		}
		stored, _, err := s.guestNotifyStoredTx(ctx, tx, policy, p, preID)
		if err != nil || stored.pre.Slot >= a.Slot {
			return ErrCapacityConflict
		}
		var spent, attempts, streak int
		var latest sql.NullTime
		if err = tx.QueryRowContext(ctx, guestNotifyPublicationBudgetQuery, preID, now, now.Add(-time.Hour)).Scan(&spent, &attempts, &latest, &streak); err != nil {
			return err
		}
		b := *p.GuestNotifyCanaryBinding
		if spent >= b.MaximumPublicationsPerHour || attempts >= guestNotifyPublicationAttemptCeiling {
			return ErrCapacityConflict
		}
		if latest.Valid {
			delay = max(0, guestNotifyPublicationGap(b.MinimumPublicationIntervalSeconds, streak)-now.Sub(latest.Time))
		}
		if current.LeaseExpiresAt == nil || !current.LeaseExpiresAt.After(now.Add(delay)) {
			return ErrCapacityLease
		}
		return nil
	})
	return delay, err
}
