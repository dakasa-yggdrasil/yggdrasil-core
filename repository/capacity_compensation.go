package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

// compensationTransaction is a separate fixed-workflow authority. It never
// adopts, renews or converts a historical capacity intent's recovery lease.
func (s CapacityStore) compensationTransaction(ctx context.Context, policy model.Manifest, historical bool, fn func(*sql.Tx, model.CapacityPolicySpec, time.Time) error) error {
	p, err := parseCapacityPolicy(policy)
	if err != nil {
		return err
	}
	if !validCapacityExecutor(s.ExecutorID) || s.WorkflowID == uuid.Nil {
		return ErrCapacityMutationAuthorization
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err = lockMutationScope(ctx, tx, policy.Metadata.Namespace, p); err != nil {
		return err
	}
	var checksum string
	var active bool
	if err = tx.QueryRowContext(ctx, `SELECT checksum,active FROM public.manifests WHERE id=$1 AND kind='capacity_policy' AND namespace=$2 AND name=$3 FOR SHARE`, policy.ID, policy.Metadata.Namespace, policy.Metadata.Name).Scan(&checksum, &active); err != nil {
		return err
	}
	if checksum != policy.Checksum || (!historical && (!active || !s.ExecutionEnabled || !p.ExecutionEnabled)) {
		return ErrCapacityDisabled
	}
	if err = tx.QueryRowContext(ctx, `SELECT active FROM public.manifests WHERE id=$1 AND kind='workflow' AND namespace=$2 AND name=$3 AND jsonb_typeof(spec->'authorization')='object' FOR SHARE`, s.WorkflowID, p.Workflow.Namespace, p.Workflow.Name).Scan(&active); err != nil {
		return err
	}
	if !active {
		return ErrCapacityMutationAuthorization
	}
	var now time.Time
	if err = tx.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		return err
	}
	if err = fn(tx, p, now.UTC()); err != nil {
		return err
	}
	return tx.Commit()
}

func loadCompensationRecord(ctx context.Context, tx *sql.Tx, policy model.Manifest, p model.CapacityPolicySpec, id string) (capacityMutationRecord, error) {
	var record capacityMutationRecord
	if !validCapacityExecutor(id) {
		return record, ErrCapacityConflict
	}
	var raw []byte
	if err := tx.QueryRowContext(ctx, `SELECT grant_record FROM public.capacity_mutation_grants WHERE id=$1 AND namespace=$2 AND environment=$3 AND domain=$4 AND dimension=$5 FOR UPDATE`, id, policy.Metadata.Namespace, p.Environment, p.Domain, p.Dimension).Scan(&raw); err != nil {
		return record, err
	}
	if err := json.Unmarshal(raw, &record); err != nil {
		return record, err
	}
	return record, nil
}

func sameCompensationBinding(current, parent model.CapacityMutationBinding) bool {
	current.CompensationEnabled, parent.CompensationEnabled = false, false
	a, _ := json.Marshal(current)
	b, _ := json.Marshal(parent)
	return string(a) == string(b)
}

func completeMutationActionProof(record capacityMutationRecord, proof model.CapacityMutationProof) bool {
	if record.Settlement == nil || !record.Settlement.TransportCompleted || !proof.ActionsTerminal || len(proof.ActionIDs) == 0 || len(proof.ActionIDs) > 64 {
		return false
	}
	seen := map[string]bool{}
	for _, id := range proof.ActionIDs {
		if id == "" || len(id) > 256 || seen[id] {
			return false
		}
		seen[id] = true
	}
	for _, id := range append([]string{record.Settlement.ActionID}, record.Settlement.NextActionIDs...) {
		if id != "" && !slices.Contains(proof.ActionIDs, id) {
			return false
		}
	}
	return true
}

func validFailedCreationProof(p model.CapacityPolicySpec, record capacityMutationRecord, proof model.CapacityMutationProof, now time.Time) bool {
	g, b := record.Grant, record.Binding
	if record.Settlement == nil || (record.Settlement.Outcome != "accepted" && record.Settlement.Outcome != "uncertain") || g.Capability != b.EnsureCapability || g.CompensationOf != "" || proof.GrantID != g.GrantID || proof.BindingName != b.Name || proof.Slot != g.Slot || proof.RequestSHA256 != g.RequestSHA256 || !proof.OwnerVerified || !proof.CompensationIdentityVerified || proof.ResourceAbsent || proof.ObservedCreationGrantID != g.GrantID || !proof.ActionsFailed || proof.ActionsSuccessful || !completeMutationActionProof(record, proof) || !capacity.Fresh(proof.ObservedAt, now, p.MaxEvidenceAgeSeconds) || proof.ReceiptRef == "" || len(proof.ReceiptRef) > 512 || !validMutationIdentity(proof.ResourceID, proof.ResourceCreatedAt, true) {
		return false
	}
	// Unknown transport identity is not rewritten. A separate exact native
	// readback may recover it, but only a complete failed action history can
	// discharge the ambiguity of a lost or uncertain create response.
	if record.Settlement.ResourceID != "" && (proof.ResourceID != record.Settlement.ResourceID || proof.ResourceCreatedAt != record.Settlement.ResourceCreatedAt) {
		return false
	}
	// Once admitted, native readback pins one lifetime independently of an
	// unknown transport response or a child's never-redeemed expiration.
	if record.Proof != nil && (proof.ResourceID != record.Proof.ResourceID || proof.ResourceCreatedAt != record.Proof.ResourceCreatedAt || proof.ObservedCreationGrantID != record.Proof.ObservedCreationGrantID || proof.RequestSHA256 != record.Proof.RequestSHA256) {
		return false
	}
	if (record.Settlement.Outcome == "uncertain" || record.Settlement.ResourceID == "" || record.Settlement.ActionID == "") && !proof.ActionHistoryComplete {
		return false
	}
	created, _ := time.Parse(time.RFC3339Nano, proof.ResourceCreatedAt)
	return !created.Before(record.CreatedAt.Add(-5*time.Second)) && !created.After(proof.ObservedAt.Add(5*time.Second))
}

func validateCompensationDrain(ctx context.Context, tx *sql.Tx, namespace string, p model.CapacityPolicySpec, proof model.CapacityTransitionProof, now time.Time, generation int64) error {
	if !proof.Healthy || !proof.MembershipComplete || !proof.AdmissionClosed || !proof.RoutingWithdrawn || proof.Inflight == nil || *proof.Inflight != 0 || proof.NativeActionsInflight == nil || *proof.NativeActionsInflight != 0 || !capacity.Fresh(proof.ObservedAt, now, p.MaxEvidenceAgeSeconds) || proof.ReceiptRef == "" || len(proof.ReceiptRef) > 512 {
		return fmt.Errorf("%w: compensation requires fresh healthy protected membership, closed admission, withdrawn routing and zero native/business work", ErrCapacityConflict)
	}
	if err := capacity.ValidateSnapshot(p, proof.Assessment, now); err != nil {
		return err
	}
	intent, err := loadCapacityIntent(ctx, tx, namespace, p, true)
	if err != nil {
		return err
	}
	if intent.Generation != generation || !validCapacityBaseline(p, intent) || !sameCapacityResourceIdentity(intent.BaselineSnapshot, proof.Assessment.Snapshot) {
		return ErrCapacityConflict
	}
	// Cleaning a never-serving failed create cannot remove healthy members.
	// A failed floor repair may therefore preserve its exact degraded baseline
	// instead of deadlocking on a floor it was already trying to restore.
	if proof.Assessment.Snapshot.Units < p.Floor && (intent.Decision.Reason != "protected_floor_recovery" || capacityIntentReduction(intent) || intent.BaselineSnapshot.Units >= p.Floor || proof.Assessment.Snapshot.Units != intent.BaselineSnapshot.Units || proof.Assessment.Snapshot.Profile != intent.BaselineSnapshot.Profile || intent.Decision.Profile != intent.BaselineSnapshot.Profile) {
		return fmt.Errorf("%w: failed floor cleanup cannot lose healthy baseline membership", ErrCapacityConflict)
	}
	var live, fresh, sameProfile int
	if err := tx.QueryRowContext(ctx, `SELECT count(*),count(*) FILTER(WHERE (slot_record->>'observed_at')::timestamptz BETWEEN $5 AND $6),count(*) FILTER(WHERE profile_name=$7) FROM public.capacity_resource_slots WHERE namespace=$1 AND environment=$2 AND domain=$3 AND dimension=$4 AND resource_id<>''`, namespace, p.Environment, p.Domain, p.Dimension, now.Add(-time.Duration(p.MaxEvidenceAgeSeconds)*time.Second), now.Add(5*time.Second), proof.Assessment.Snapshot.Profile).Scan(&live, &fresh, &sameProfile); err != nil {
		return err
	}
	if live != proof.Assessment.Snapshot.Units || fresh != live || sameProfile != live {
		return ErrCapacityConflict
	}
	return nil
}

// IssueCompensation admits only deletion of one failed, never-registered create.
// The parent remains reserved. A paused/historical parent's lease cannot grant
// this write; the current active protected workflow and opt-in binding do.
func (s CapacityStore) IssueCompensation(ctx context.Context, policy model.Manifest, issue model.CapacityCompensationIssue) (model.CapacityMutationGrant, error) {
	var result model.CapacityMutationGrant
	err := s.compensationTransaction(ctx, policy, false, func(tx *sql.Tx, p model.CapacityPolicySpec, now time.Time) error {
		plan, err := capacity.PrepareCompensationPlan(p, issue.Mutation)
		if err != nil {
			return err
		}
		b := plan.Binding
		if err = lockNativeMutationSlot(ctx, tx, b, plan.Slot); err != nil {
			return err
		}
		if err = checkMutationIntegration(ctx, tx, b); err != nil {
			return err
		}
		parent, err := loadCompensationRecord(ctx, tx, policy, p, issue.ParentGrantID)
		if err != nil {
			return err
		}
		if (parent.Grant.State != "settled" && parent.Grant.State != "compensating") || !sameCompensationBinding(b, parent.Binding) || parent.Grant.Slot != plan.Slot || !validFailedCreationProof(p, parent, issue.FailedProof, now) {
			return ErrCapacityConflict
		}
		plan, err = capacity.BindMutationDestroyPlan(plan, issue.FailedProof.ResourceID, issue.FailedProof.ResourceCreatedAt)
		if err != nil {
			return ErrCapacityConflict
		}
		var registered int
		if err = tx.QueryRowContext(ctx, `SELECT count(*) FROM public.capacity_resource_slots WHERE integration_instance_id=$1 AND resource_id=$2`, b.IntegrationInstanceID, issue.FailedProof.ResourceID).Scan(&registered); err != nil {
			return err
		}
		if registered != 0 {
			return ErrCapacityConflict
		}
		slot, exists, err := loadMutationSlot(ctx, tx, policy.Metadata.Namespace, p, b, plan.Slot)
		if err != nil || (exists && slot.ResourceID != "") {
			return ErrCapacityConflict
		}
		if err = validateCompensationDrain(ctx, tx, policy.Metadata.Namespace, p, issue.DrainProof, now, parent.Generation); err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, `UPDATE public.capacity_mutation_grants SET state='expired',grant_record=jsonb_set(grant_record,'{grant,state}','"expired"'),updated_at=$2 WHERE state='issued' AND expires_at<=$2 AND grant_record->'grant'->>'compensation_of'=$1`, parent.Grant.GrantID, now); err != nil {
			return err
		}
		var raw []byte
		err = tx.QueryRowContext(ctx, `SELECT grant_record FROM public.capacity_mutation_grants WHERE state IN ('issued','redeemed','settled') AND grant_record->'grant'->>'compensation_of'=$1 FOR UPDATE`, parent.Grant.GrantID).Scan(&raw)
		if err == nil {
			var existing capacityMutationRecord
			if err = json.Unmarshal(raw, &existing); err != nil {
				return err
			}
			if existing.PolicyID != policy.ID || existing.PolicyChecksum != policy.Checksum || existing.WorkflowID != s.WorkflowID || existing.ExecutorID != s.ExecutorID || existing.Grant.RequestSHA256 != plan.RequestSHA256 {
				return ErrCapacityConflict
			}
			if existing.Grant.State == "issued" {
				parent.Proof, existing.CompensationDrainProof = &issue.FailedProof, &issue.DrainProof
				if err = saveMutationGrant(ctx, tx, parent); err != nil {
					return err
				}
				if err = saveMutationGrant(ctx, tx, existing); err != nil {
					return err
				}
			}
			result = existing.Grant
			return nil
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		provider, resource, err := capacityMutationEventIdentity(ctx, tx, b)
		if err != nil {
			return err
		}
		result = model.CapacityMutationGrant{GrantID: uuid.NewString(), BindingName: b.Name, IntegrationInstanceID: b.IntegrationInstanceID, ScopeChecksum: b.ScopeChecksum, ProfileName: b.ProfileName, Slot: plan.Slot, Capability: b.DestroyCapability, RequestSHA256: plan.RequestSHA256, ExpectedResourceID: plan.ExpectedResourceID, ExpectedResourceCreatedAt: plan.ExpectedResourceCreatedAt, CompensationOf: parent.Grant.GrantID, ExpiresAt: now.Add(60 * time.Second), State: "issued"}
		parent.Grant.State, parent.Proof = "compensating", &issue.FailedProof
		if err = saveMutationGrant(ctx, tx, parent); err != nil {
			return err
		}
		record := capacityMutationRecord{Grant: result, Binding: b, PolicyID: policy.ID, PolicyChecksum: policy.Checksum, WorkflowID: s.WorkflowID, Generation: parent.Generation, ExecutorID: s.ExecutorID, CreatedAt: now, EventProvider: provider, EventResource: resource, CompensationDrainProof: &issue.DrainProof}
		raw, err = json.Marshal(record)
		if err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO public.capacity_mutation_grants(id,namespace,environment,domain,dimension,generation,integration_instance_id,scope_checksum,profile_name,slot,state,grant_record,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,'issued',$11::jsonb,$12)`, result.GrantID, policy.Metadata.Namespace, p.Environment, p.Domain, p.Dimension, parent.Generation, b.IntegrationInstanceID, b.ScopeChecksum, b.ProfileName, plan.Slot, raw, result.ExpiresAt)
		return err
	})
	return result, err
}

func redeemCompensation(ctx context.Context, tx *sql.Tx, record *capacityMutationRecord, p model.CapacityPolicySpec, now time.Time, request model.CapacityMutationRedeemRequest, response *model.CapacityMutationRedeemResponse) error {
	g := record.Grant
	if !record.Binding.CompensationEnabled || g.Capability != record.Binding.DestroyCapability || record.CompensationDrainProof == nil || !validCapacityExecutor(record.ExecutorID) {
		return ErrCapacityConflict
	}
	var raw []byte
	if err := tx.QueryRowContext(ctx, `SELECT grant_record FROM public.capacity_mutation_grants WHERE id=$1 FOR UPDATE`, g.CompensationOf).Scan(&raw); err != nil {
		return err
	}
	var parent capacityMutationRecord
	if err := json.Unmarshal(raw, &parent); err != nil {
		return err
	}
	if parent.Grant.State != "compensating" || parent.Proof == nil || !validFailedCreationProof(p, parent, *parent.Proof, now) || parent.Proof.ResourceID != g.ExpectedResourceID || parent.Proof.ResourceCreatedAt != g.ExpectedResourceCreatedAt || !sameCompensationBinding(record.Binding, parent.Binding) {
		return ErrCapacityConflict
	}
	var ns string
	if err := tx.QueryRowContext(ctx, `SELECT namespace FROM public.capacity_mutation_grants WHERE id=$1`, g.GrantID).Scan(&ns); err != nil {
		return err
	}
	if err := validateCompensationDrain(ctx, tx, ns, p, *record.CompensationDrainProof, now, parent.Generation); err != nil {
		return err
	}
	record.AttemptID, record.SettlementTokenSHA256, record.Grant.State = request.AttemptID, request.SettlementTokenSHA256, "redeemed"
	response.Mode = "write_once"
	return nil
}

// ConfirmCompensation remains available after pause. It closes only the exact
// settled child and its failed parent; it cannot create serving membership.
func (s CapacityStore) ConfirmCompensation(ctx context.Context, policy model.Manifest, proof model.CapacityMutationProof) (model.CapacityMutationGrant, error) {
	var result model.CapacityMutationGrant
	err := s.compensationTransaction(ctx, policy, true, func(tx *sql.Tx, p model.CapacityPolicySpec, now time.Time) error {
		child, err := loadCompensationRecord(ctx, tx, policy, p, proof.GrantID)
		if err != nil {
			return err
		}
		g, b := child.Grant, child.Binding
		if child.PolicyID != policy.ID || child.PolicyChecksum != policy.Checksum || child.WorkflowID != s.WorkflowID || g.CompensationOf == "" {
			return ErrCapacityConflict
		}
		if err = lockNativeMutationSlot(ctx, tx, b, g.Slot); err != nil {
			return err
		}
		if g.State == "confirmed" && child.Proof != nil {
			previous, _ := json.Marshal(child.Proof)
			requested, _ := json.Marshal(proof)
			if string(previous) == string(requested) {
				result = g
				return nil
			}
		}
		if g.State != "settled" || g.Capability != b.DestroyCapability || proof.BindingName != b.Name || proof.Slot != g.Slot || proof.RequestSHA256 != g.RequestSHA256 || !proof.OwnerVerified || !proof.CompensationIdentityVerified || !capacity.Fresh(proof.ObservedAt, now, p.MaxEvidenceAgeSeconds) || proof.ReceiptRef == "" || len(proof.ReceiptRef) > 512 || !validMutationIdentity(proof.ResourceID, proof.ResourceCreatedAt, true) || !proof.ResourceAbsent || proof.ResourceID != g.ExpectedResourceID || proof.ResourceCreatedAt != g.ExpectedResourceCreatedAt || !proof.ActionsSuccessful || proof.ActionsFailed || !completeMutationActionProof(child, proof) || child.Settlement == nil || child.Settlement.ResourceID != g.ExpectedResourceID || child.Settlement.ResourceCreatedAt != g.ExpectedResourceCreatedAt || !child.Settlement.AuxiliaryInventoryComplete || !validMutationAuxiliaries(proof.AuxiliaryAbsent) {
			return ErrCapacityConflict
		}
		for _, aux := range child.Settlement.AuxiliaryResources {
			if aux.RequiresAbsence && !slices.ContainsFunc(proof.AuxiliaryAbsent, func(absent model.CapacityMutationAuxiliaryResource) bool {
				return absent.Kind == aux.Kind && absent.ID == aux.ID
			}) {
				return ErrCapacityConflict
			}
		}
		parent, err := loadCompensationRecord(ctx, tx, policy, p, g.CompensationOf)
		if err != nil {
			return err
		}
		if parent.Grant.State != "compensating" || parent.Proof == nil || parent.Proof.ResourceID != g.ExpectedResourceID || parent.Proof.ResourceCreatedAt != g.ExpectedResourceCreatedAt || !sameCompensationBinding(b, parent.Binding) {
			return ErrCapacityConflict
		}
		var registered int
		if err = tx.QueryRowContext(ctx, `SELECT count(*) FROM public.capacity_resource_slots WHERE integration_instance_id=$1 AND resource_id=$2`, b.IntegrationInstanceID, g.ExpectedResourceID).Scan(&registered); err != nil {
			return err
		}
		if registered != 0 {
			return ErrCapacityConflict
		}
		if err = saveMutationSlot(ctx, tx, policy.Metadata.Namespace, p, b, g.Slot, capacityResourceSlot{BindingName: b.Name, ProfileName: b.ProfileName, DesiredSpecSHA256: parent.Grant.RequestSHA256, ResourceCreatedAt: g.ExpectedResourceCreatedAt, Tombstone: true, ObservedAt: proof.ObservedAt, ReceiptRef: proof.ReceiptRef}); err != nil {
			return err
		}
		parent.Grant.State, child.Grant.State, child.Proof = "compensated", "confirmed", &proof
		if err = saveMutationGrant(ctx, tx, parent); err != nil {
			return err
		}
		if err = saveMutationGrant(ctx, tx, child); err != nil {
			return err
		}
		result = child.Grant
		return emitCapacityMutationEvent(ctx, tx, policy.Metadata.Namespace, p, child, proof, now)
	})
	return result, err
}
