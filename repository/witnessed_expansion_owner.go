package repository

import (
	"bytes"
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
// it. Ordinary canary paths without this typed selector do not touch its ledger.
type witnessedExpansionOwner struct {
	id    string
	claim int64
}

func loadWitnessedExpansionTx(ctx context.Context, tx *sql.Tx, id string) (WitnessedUnenrolledExpansionCleanup, []WitnessedUnenrolledExpansionCleanupEvent, error) {
	var a WitnessedUnenrolledExpansionCleanup
	var raw []byte
	var sha string
	if err := tx.QueryRowContext(ctx, `SELECT original_wire,admission_sha256 FROM public.capacity_witnessed_unenrolled_expansion_cleanups WHERE id=$1 FOR UPDATE`, id).Scan(&raw, &sha); err != nil {
		return a, nil, err
	}
	if originalDispositionDigest(raw) != sha || capacity.DecodeGuestLifecycle(raw, &a) != nil || a.ID != id || a.Schema != WitnessedUnenrolledExpansionCleanupSchema {
		return a, nil, ErrCapacityConflict
	}
	rows, err := tx.QueryContext(ctx, `SELECT original_wire,event_sha256 FROM public.capacity_witnessed_unenrolled_expansion_cleanup_events WHERE cleanup_id=$1 ORDER BY sequence`, id)
	if err != nil {
		return a, nil, err
	}
	defer rows.Close()
	var out []WitnessedUnenrolledExpansionCleanupEvent
	for rows.Next() {
		var e WitnessedUnenrolledExpansionCleanupEvent
		if rows.Scan(&raw, &sha) != nil || originalDispositionDigest(raw) != sha || json.Unmarshal(raw, &e) != nil || e.CleanupID != id || e.Sequence != int64(len(out)+1) {
			return a, nil, ErrCapacityConflict
		}
		out = append(out, e)
	}
	return a, out, rows.Err()
}

func latestWitnessedExpansionClaim(events []WitnessedUnenrolledExpansionCleanupEvent) (WitnessedUnenrolledExpansionCleanupEvent, bool) {
	for i := len(events) - 1; i >= 0; i-- {
		if events[i].Stage == "claimed" {
			return events[i], true
		}
	}
	return WitnessedUnenrolledExpansionCleanupEvent{}, false
}

func (s CapacityStore) witnessedExpansionActiveClaimTx(ctx context.Context, tx *sql.Tx, policy model.Manifest, current model.CapacityIntent, now time.Time) (WitnessedUnenrolledExpansionCleanup, WitnessedUnenrolledExpansionCleanupEvent, bool, error) {
	var a WitnessedUnenrolledExpansionCleanup
	var c WitnessedUnenrolledExpansionCleanupEvent
	if s.witnessedExpansionOwner == nil {
		return a, c, false, nil
	}
	if current.WitnessedUnenrolledExpansionCleanupID != s.witnessedExpansionOwner.id || current.Decision.Reason != WitnessedUnenrolledExpansionCleanupMode {
		return a, c, true, ErrCapacityConflict
	}
	a, events, err := loadWitnessedExpansionTx(ctx, tx, s.witnessedExpansionOwner.id)
	if err != nil {
		return a, c, true, err
	}
	c, ok := latestWitnessedExpansionClaim(events)
	if !ok || c.Sequence != s.witnessedExpansionOwner.claim || events[len(events)-1].Stage == "terminal" || a.PolicyID != policy.ID.String() || a.PolicyChecksum != policy.Checksum || a.WorkflowID != s.WorkflowID.String() || c.RunID != s.OriginalRunID.String() || c.Generation != current.Generation || c.FencingToken != current.FencingToken || c.LeaseOwner != current.LeaseOwner || c.ExecutorID != current.LeaseExecutorID || c.ExecutorID != s.ExecutorID || c.LeaseExpiresAt == nil || current.LeaseExpiresAt == nil || !c.LeaseExpiresAt.Equal(*current.LeaseExpiresAt) || !now.Before(*c.LeaseExpiresAt) {
		return a, c, true, ErrCapacityLease
	}
	if !witnessedExpansionOriginalIntentEqual(a, current) {
		return a, c, true, ErrCapacityConflict
	}
	if err = witnessedExpansionRosterCurrentTx(ctx, tx, a); err != nil {
		return a, c, true, err
	}
	if err = witnessedExpansionOriginalsTx(ctx, tx, a); err != nil {
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
	if err = witnessedExpansionQuietTx(ctx, tx, a, s.OriginalRunID.String()); err != nil {
		return a, c, true, err
	}
	return a, c, true, nil
}

// Preserve every original grant/SDK/preregistration/job/run byte. Only the
// append-only cleanup ledger and its explicitly linked new child may change.
func witnessedExpansionOriginalsTx(ctx context.Context, tx *sql.Tx, a WitnessedUnenrolledExpansionCleanup) error {
	var good bool
	err := tx.QueryRowContext(ctx, `SELECT public.witnessed_unenrolled_expansion_parent_valid106($1::uuid)`, a.ID).Scan(&good)
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
func witnessedExpansionQuietTx(ctx context.Context, tx *sql.Tx, a WitnessedUnenrolledExpansionCleanup, own string) error {
	var busy bool
	err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM public.capacity_dispatch_jobs j WHERE j.realm=$1 AND j.environment=$2 AND j.domain=$3 AND j.dimension=$4 AND j.run_id::text IS DISTINCT FROM NULLIF($5,'') AND NOT(j.id=$9::uuid AND public.witnessed_unenrolled_expansion_parent_valid106($10::uuid)) AND(j.state IN('queued','started','unknown') OR j.state='returned' AND j.finalization_ack_at IS NULL)) OR EXISTS(SELECT 1 FROM public.workflow_runs w WHERE w.workflow_namespace=(SELECT namespace FROM public.manifests WHERE id=$6::uuid) AND w.workflow_name=(SELECT name FROM public.manifests WHERE id=$6::uuid) AND w.id::text IS DISTINCT FROM NULLIF($5,'') AND(COALESCE(w.status,'') NOT IN('succeeded','failed','cancelled') OR w.finished_at IS NULL)) OR EXISTS(SELECT 1 FROM public.capacity_mutation_grants g WHERE g.namespace=$1 AND g.environment=$2 AND g.domain=$3 AND g.dimension=$4 AND g.id<>$7::uuid AND g.id<>$8::uuid AND `+capacityGrantUndisposedSQL+` AND g.state IN('issued','redeemed','settled','compensating'))`, a.Namespace, a.Environment, a.Domain, a.Dimension, own, a.WorkflowID, a.GrantID, a.ChildGrantID, a.JobID, a.ID).Scan(&busy)
	if err != nil {
		return err
	}
	if busy {
		return ErrCapacityConflict
	}
	return nil
}

func (s CapacityStore) BindWitnessedExpansionCleanup(ctx context.Context, policy model.Manifest, generation, fence int64, owner string) (CapacityStore, WitnessedUnenrolledExpansionCleanup, bool, error) {
	var a WitnessedUnenrolledExpansionCleanup
	p, err := parseCapacityPolicy(policy)
	if err != nil {
		return s, a, false, err
	}
	tx, err := beginWitnessedExpansionTx(ctx, s.DB)
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
	if current.WitnessedUnenrolledExpansionCleanupID == "" {
		return s, a, false, nil
	}
	if generation != current.Generation || fence != current.FencingToken || owner != current.LeaseOwner {
		return s, a, true, ErrCapacityConflict
	}
	a, events, err := loadWitnessedExpansionTx(ctx, tx, current.WitnessedUnenrolledExpansionCleanupID)
	if err != nil {
		return s, a, true, err
	}
	c, ok := latestWitnessedExpansionClaim(events)
	if !ok {
		return s, a, true, ErrCapacityConflict
	}
	s.witnessedExpansionOwner = &witnessedExpansionOwner{id: a.ID, claim: c.Sequence}
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
	_, _, _, err = s.witnessedExpansionActiveClaimTx(ctx, tx, policy, current, now)
	return s, a, true, err
}

// The new lane is selected only by its typed intent marker. Ordinary intents
// return before any new ledger access; old fixtures retain their own schema.
func (s CapacityStore) TryClaimWitnessedExpansionCleanup(ctx context.Context, policy model.Manifest) (CapacityStore, model.CapacityIntent, WitnessedUnenrolledExpansionCleanup, bool, error) {
	var zero model.CapacityIntent
	var a WitnessedUnenrolledExpansionCleanup
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
	tx, err := beginWitnessedExpansionTx(ctx, s.DB)
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
	if current.WitnessedUnenrolledExpansionCleanupID == "" {
		return s, zero, a, false, nil
	}
	a, events, err := loadWitnessedExpansionTx(ctx, tx, current.WitnessedUnenrolledExpansionCleanupID)
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
	if current.PolicyID != policy.ID || current.PolicyChecksum != policy.Checksum || current.FencingToken >= maxCapacityGeneration || current.LeaseExpiresAt == nil || !now.After(*current.LeaseExpiresAt) || current.Generation != a.OriginalGeneration || current.Decision.Reason != WitnessedUnenrolledExpansionCleanupMode {
		return s, zero, a, true, ErrCapacityLease
	}
	if err = witnessedExpansionOriginalsTx(ctx, tx, a); err != nil {
		return s, zero, a, true, err
	}
	if err = witnessedExpansionQuietTx(ctx, tx, a, s.OriginalRunID.String()); err != nil {
		return s, zero, a, true, err
	}
	if !witnessedExpansionOriginalIntentEqual(a, current) {
		return s, zero, a, true, ErrCapacityConflict
	}
	if err = witnessedExpansionRosterCurrentTx(ctx, tx, a); err != nil {
		return s, zero, a, true, err
	}
	if events[len(events)-1].Stage != "requested" {
		// Later ownership can only continue an authenticated Pending or complete read
		// of the same settled child, after its actual failed workflow ACK/expiry.
		old, ok := latestWitnessedExpansionClaim(events)
		if !ok {
			return s, zero, a, true, ErrCapacityConflict
		}
		if err = witnessedExpansionClosedOwnerTx(ctx, tx, old); err != nil {
			return s, zero, a, true, err
		}
		child, childErr := witnessedExpansionChildTx(ctx, tx, a)
		if childErr != nil {
			return s, zero, a, true, ErrCapacityConflict
		}
		qualified := events[len(events)-1]
		if qualified.Stage == "absence_returned" {
			// The failed read remains raw custody. Only its preceding qualified
			// same-owner read may anchor a fresh read-only successor.
			if !witnessedExpansionDeadlineReturnContinuation(events, old, a, child, p, now) {
				return s, zero, a, true, ErrCapacityConflict
			}
			qualified = events[len(events)-3]
			var returnedBeforeACK bool
			if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM public.capacity_dispatch_jobs j JOIN public.workflow_runs w ON w.id=j.run_id WHERE j.run_id=$1::uuid AND j.state='returned' AND j.return_status='failed' AND j.finalization_ack_at>=j.returned_at AND w.status='failed' AND w.finished_at=j.returned_at AND j.returned_at>=$2)`, old.RunID, events[len(events)-1].RecordedAt).Scan(&returnedBeforeACK); err != nil {
				return s, zero, a, true, err
			}
			if !returnedBeforeACK {
				return s, zero, a, true, ErrCapacityConflict
			}
		}
		var pending WitnessedExpansionReadReturn
		if (qualified.Stage != "pending_absence" && qualified.Stage != "absence_complete") || json.Unmarshal(qualified.Evidence, &pending) != nil || pending.Pending == pending.Complete {
			return s, zero, a, true, ErrCapacityConflict
		}
		if pending.Receipt == nil || !reflect.DeepEqual(guestMutationReceiptV2(child), *pending.Receipt) {
			return s, zero, a, true, ErrCapacityConflict
		}
		if _, actualPending, contentErr := witnessedExpansionReadContent(pending, p, a); contentErr != nil || actualPending != pending.Pending {
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
	c := WitnessedUnenrolledExpansionCleanupEvent{Schema: WitnessedUnenrolledExpansionCleanupSchema, CleanupID: a.ID, Sequence: int64(len(events) + 1), Stage: "claimed", RunID: s.OriginalRunID.String(), Generation: next.Generation, FencingToken: next.FencingToken, LeaseOwner: next.LeaseOwner, ExecutorID: s.ExecutorID, LeaseExpiresAt: &expires, ChildGrantID: a.ChildGrantID, RecordedAt: now}
	if err = s.appendWitnessedExpansionEventTx(ctx, tx, c); err != nil {
		return s, zero, a, true, err
	}
	if err = persistRetirementForwardIntentTx(ctx, tx, current, next, "witnessed-unenrolled-expansion:"+a.ID+":claimed"); err != nil {
		return s, zero, a, true, err
	}
	if err = tx.Commit(); err != nil {
		return s, zero, a, true, err
	}
	s.witnessedExpansionOwner = &witnessedExpansionOwner{id: a.ID, claim: c.Sequence}
	return s, next, a, true, nil
}

// A deadline-failed read is never absence evidence. This exact contiguous
// same-owner suffix merely permits another finite owner to issue a NEW read of
// the already accepted settled child after the old run/lease have closed.
func witnessedExpansionDeadlineReturnContinuation(events []WitnessedUnenrolledExpansionCleanupEvent, claim WitnessedUnenrolledExpansionCleanupEvent, a WitnessedUnenrolledExpansionCleanup, child capacityMutationRecord, p model.CapacityPolicySpec, now time.Time) bool {
	if len(events) < 3 || claim.LeaseExpiresAt == nil || child.Grant.State != "settled" || child.Settlement == nil {
		return false
	}
	qualified, prepared, returned := events[len(events)-3], events[len(events)-2], events[len(events)-1]
	if (qualified.Stage != "pending_absence" && qualified.Stage != "absence_complete") || prepared.Stage != "absence_prepared" || returned.Stage != "absence_returned" || prepared.Sequence != qualified.Sequence+1 || returned.Sequence != prepared.Sequence+1 || qualified.Sequence <= claim.Sequence {
		return false
	}
	for _, event := range []WitnessedUnenrolledExpansionCleanupEvent{qualified, prepared, returned} {
		if event.CleanupID != a.ID || event.ChildGrantID != a.ChildGrantID || event.RunID != claim.RunID || event.Generation != claim.Generation || event.FencingToken != claim.FencingToken || event.LeaseOwner != claim.LeaseOwner || event.ExecutorID != claim.ExecutorID || event.LeaseExpiresAt == nil || !event.LeaseExpiresAt.Equal(*claim.LeaseExpiresAt) || event.RecordedAt.Before(claim.RecordedAt) || event.RecordedAt.After(now) {
			return false
		}
	}
	var read WitnessedExpansionRead
	var raw, prior WitnessedExpansionReadReturn
	if capacity.DecodeGuestLifecycle(prepared.Evidence, &read) != nil || capacity.DecodeGuestLifecycle(returned.Evidence, &raw) != nil || json.Unmarshal(qualified.Evidence, &prior) != nil {
		return false
	}
	wire, err := json.Marshal(read)
	receipt := guestMutationReceiptV2(child)
	receiptWire, receiptErr := json.Marshal(receipt)
	if err != nil || receiptErr != nil || !reflect.DeepEqual(raw.Read, read) || !bytes.Equal(raw.ReadWire, wire) || raw.Receipt == nil || !reflect.DeepEqual(*raw.Receipt, receipt) || !bytes.Equal(raw.ReceiptWire, receiptWire) || prior.Receipt == nil || !reflect.DeepEqual(*prior.Receipt, receipt) || prior.Read.ClaimSequence != claim.Sequence || prior.Read.ReadID == read.ReadID {
		return false
	}
	if raw.Schema != "witnessed_unenrolled_expansion_native_return_v1" || read.Schema != "witnessed_unenrolled_expansion_native_read_v1" || read.Kind != "absence" || !validCapacityExecutor(read.ReadID) || read.CleanupID != a.ID || read.ChildGrantID != a.ChildGrantID || read.ClaimSequence != claim.Sequence || read.AdmissionSHA256 != capacity.GuestRetirementSHA(a) || !raw.CallFailed || !raw.OriginalContextFailed || raw.Pending || raw.Complete || raw.Status != "" || raw.Plan != nil || raw.Observation != nil || raw.ObserverSourceCommit != "" || len(raw.OriginalObserverReturn) != 0 {
		return false
	}
	if read.IssuedAtCore.IsZero() || !read.OriginalDeadlineCore.After(read.IssuedAtCore) || read.OriginalDeadlineCore.Sub(read.IssuedAtCore) > 5*time.Second || read.OriginalDeadlineCore.After(*claim.LeaseExpiresAt) || raw.StartedAtCore.Before(read.IssuedAtCore) || !raw.StartedAtCore.Before(read.OriginalDeadlineCore) || raw.ReturnedAtCore.Before(read.OriginalDeadlineCore) || raw.ReturnedAtCore.After(returned.RecordedAt) || prepared.RecordedAt.Before(qualified.RecordedAt) || returned.RecordedAt.Before(prepared.RecordedAt) {
		return false
	}
	// HZN has its ordinary accepted settlement and native readback, not an
	// AWS-specific SDK terminate return. Revalidate the same qualified HZN
	// read with the production content/pending consumer before a new read.
	if child.Binding.OriginalProviderSourceCommit != failedOriginalHetznerCreator || child.Settlement.OriginalProviderDestroyReturn != nil || child.Settlement.OriginalProviderCreateReturn != nil {
		return false
	}
	_, pending, err := witnessedExpansionReadContent(prior, p, a)
	return err == nil && pending == prior.Pending && prior.Pending != prior.Complete
}

func witnessedExpansionClosedOwnerTx(ctx context.Context, tx *sql.Tx, c WitnessedUnenrolledExpansionCleanupEvent) error {
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

func (s CapacityStore) witnessedExpansionTransaction(ctx context.Context, policy model.Manifest, fn func(*sql.Tx, model.CapacityPolicySpec, model.CapacityIntent, WitnessedUnenrolledExpansionCleanup, WitnessedUnenrolledExpansionCleanupEvent, time.Time) error) error {
	if s.witnessedExpansionOwner == nil {
		return ErrCapacityConflict
	}
	p, err := parseCapacityPolicy(policy)
	if err != nil {
		return err
	}
	tx, err := beginWitnessedExpansionTx(ctx, s.DB)
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
	a, c, active, err := s.witnessedExpansionActiveClaimTx(ctx, tx, policy, current, now)
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

func (s CapacityStore) appendWitnessedExpansionStageTx(ctx context.Context, tx *sql.Tx, a WitnessedUnenrolledExpansionCleanup, c WitnessedUnenrolledExpansionCleanupEvent, stage string, evidence any, now time.Time) error {
	_, events, err := loadWitnessedExpansionTx(ctx, tx, a.ID)
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
	return s.appendWitnessedExpansionEventTx(ctx, tx, c)
}

// The field equality is stronger than a slot count. Updating only observed_at
// and receipt_ref after a complete authenticated native inventory is allowed;
// identity, registered birth, profile and sealed enrollment never change.
func (s CapacityStore) RefreshWitnessedExpansionSurvivors(ctx context.Context, policy model.Manifest, inv model.CapacityVMFleetInventory) error {
	return s.witnessedExpansionTransaction(ctx, policy, func(tx *sql.Tx, p model.CapacityPolicySpec, current model.CapacityIntent, a WitnessedUnenrolledExpansionCleanup, c WitnessedUnenrolledExpansionCleanupEvent, now time.Time) error {
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
		_, events, err := loadWitnessedExpansionTx(ctx, tx, a.ID)
		if err != nil {
			return err
		}
		absent := false
		for _, e := range events {
			if e.Stage == "absence_complete" {
				var r WitnessedExpansionReadReturn
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
			child, e := witnessedExpansionChildTx(ctx, tx, a)
			if e != nil || child.Grant.State != "settled" || child.Settlement == nil || child.Settlement.Outcome != "accepted" || !child.Settlement.AuxiliaryInventoryComplete {
				return ErrCapacityConflict
			}
			knownPending := false
			for _, e := range events {
				if e.Stage == "pending_absence" {
					var r WitnessedExpansionReadReturn
					if json.Unmarshal(e.Evidence, &r) == nil {
						_, pending, readErr := witnessedExpansionReadContent(r, p, a)
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
func witnessedExpansionOriginalIntentEqual(a WitnessedUnenrolledExpansionCleanup, current model.CapacityIntent) bool {
	var old model.CapacityIntent
	if json.Unmarshal(a.OriginalIntentWire, &old) != nil {
		return false
	}
	old.WitnessedUnenrolledExpansionCleanupID = current.WitnessedUnenrolledExpansionCleanupID
	old.Decision.Reason = current.Decision.Reason
	old.FencingToken = current.FencingToken
	old.LeaseOwner = current.LeaseOwner
	old.LeaseExecutorID = current.LeaseExecutorID
	old.LeaseExpiresAt = current.LeaseExpiresAt
	old.UpdatedAt = current.UpdatedAt
	return reflect.DeepEqual(old, current)
}

func witnessedExpansionRosterCurrentTx(ctx context.Context, tx *sql.Tx, a WitnessedUnenrolledExpansionCleanup) error {
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
func (s CapacityStore) WitnessedExpansionPublicationDelay(ctx context.Context, policy model.Manifest, preID string) (time.Duration, error) {
	var delay time.Duration
	err := s.witnessedExpansionTransaction(ctx, policy, func(tx *sql.Tx, p model.CapacityPolicySpec, current model.CapacityIntent, a WitnessedUnenrolledExpansionCleanup, c WitnessedUnenrolledExpansionCleanupEvent, now time.Time) error {
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

func (s CapacityStore) witnessedExpansionSurvivorFloorTx(ctx context.Context, tx *sql.Tx, policy model.Manifest, p model.CapacityPolicySpec, current model.CapacityIntent, cleanup WitnessedUnenrolledExpansionCleanup, claim WitnessedUnenrolledExpansionCleanupEvent, now time.Time, usage string) error {
	if p.GuestNotifyCanaryBinding == nil || p.GuestRetirementBinding == nil || current.RecoveryOnly || current.FloorDegraded || cleanup.Slot < 2 || cleanup.SurvivorCount != cleanup.Slot-1 || cleanup.SurvivorCount < p.Floor || claim.RecordedAt.IsZero() || (usage != "before_retirement_floor" && usage != "after_retirement_floor") {
		return ErrCapacityConflict
	}
	afterPG := claim.RecordedAt
	if usage == "after_retirement_floor" {
		var err error
		afterPG, err = s.witnessedExpansionAbsenceAfterPGTx(ctx, tx, cleanup.ID)
		if err != nil {
			return err
		}
		if !afterPG.After(claim.RecordedAt) {
			return ErrCapacityConflict
		}
	}
	useful, err := s.guestNotifyUsefulMembersTx(ctx, tx, policy, p, current, cleanup.Slot, now, usage, afterPG)
	if err != nil {
		return err
	}
	if useful != cleanup.SurvivorCount || useful < p.Floor {
		return ErrCapacityConflict
	}
	return nil
}

func (s CapacityStore) witnessedExpansionFloorMembers(ctx context.Context, policy model.Manifest, generation, fence int64, owner string, excludedSlot int) ([]GuestNotifyFloorMember, error) {
	var out []GuestNotifyFloorMember
	err := s.mutationTransaction(ctx, policy, false, generation, fence, owner, func(tx *sql.Tx, p model.CapacityPolicySpec, current model.CapacityIntent, now time.Time) error {
		cleanup, _, cleanupActive, err := s.witnessedExpansionActiveClaimTx(ctx, tx, policy, current, now)
		if err != nil {
			return err
		}
		if s.guestNotifyOrigin == nil || s.guestNotifyOrigin.source != capacity.CurrentGuestCoreSource() || p.GuestNotifyCanaryBinding == nil || p.GuestRetirementBinding == nil || current.RecoveryOnly || current.FloorDegraded || !cleanupActive && (!capacityIntentReduction(current) || current.Phase != "draining" && current.Phase != "drained") {
			return ErrCapacityConflict
		}
		if cleanupActive && (excludedSlot != cleanup.Slot || cleanup.Slot < 2 || cleanup.SurvivorCount != cleanup.Slot-1 || cleanup.SurvivorCount < p.Floor) {
			return ErrCapacityConflict
		}
		if current.FailedInstalledDisposal != nil {
			valid, err := s.failedInstalledDisposalActiveTx(ctx, tx, policy, p, current, excludedSlot, now)
			if err != nil || !valid {
				return ErrCapacityConflict
			}
			if excludedSlot == 1 {
				return nil
			}
		}
		r := *p.GuestRetirementBinding
		b, err := capacity.VMObservationBinding(p, r.MutationBindingName)
		if err != nil || checkMutationIntegration(ctx, tx, b) != nil {
			return ErrCapacityConflict
		}
		provider := ""
		for _, profile := range p.Profiles {
			if profile.Name == b.ProfileName {
				provider = profile.Provider
			}
		}
		if !capacity.GuestOriginalProfileEnabled(p, r, provider) {
			return ErrCapacityConflict
		}
		for _, member := range r.Members {
			if member.Slot == excludedSlot || cleanupActive && member.Slot >= cleanup.Slot {
				continue
			}
			slot, exists, err := loadMutationSlot(ctx, tx, policy.Metadata.Namespace, p, b, member.Slot)
			if err != nil {
				return err
			}
			if !exists || slot.Tombstone || slot.ResourceID == "" {
				continue
			}
			var pending int
			if err = tx.QueryRowContext(ctx, `SELECT count(*) FROM public.capacity_mutation_grants WHERE `+capacityGrantUndisposedSQL+` AND NOT(grant_record ? 'authority_kind') AND namespace=$1 AND environment=$2 AND domain=$3 AND dimension=$4 AND slot=$5 AND state IN ('issued','redeemed','settled','compensating') AND grant_record->'grant'->>'capability'=$6`, policy.Metadata.Namespace, p.Environment, p.Domain, p.Dimension, member.Slot, b.DestroyCapability).Scan(&pending); err != nil {
				return err
			}
			if pending != 0 {
				continue
			}
			receipt, err := guestNotifyMemberReceiptTx(ctx, tx, policy, p, member, slot)
			if err != nil {
				return err
			}
			if _, _, err = s.guestNotifyStoredTx(ctx, tx, policy, p, receipt.PreregistrationID); err != nil {
				return err
			}
			out = append(out, GuestNotifyFloorMember{member.Slot, receipt.PreregistrationID})
		}
		if cleanupActive {
			// The failed expansion's desired N2 remains historical truth. Its
			// unwitnessed target is never counted or probed as a survivor.
			if len(out) != cleanup.SurvivorCount {
				return ErrCapacityConflict
			}
		} else if len(out) < p.Floor || len(out) < current.Decision.Units {
			return ErrCapacityConflict
		}
		return nil
	})
	return out, err
}
