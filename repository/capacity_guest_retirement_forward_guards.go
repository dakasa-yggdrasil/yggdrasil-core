package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"reflect"
	"sort"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

func lockRetirementForwardBindingsTx(ctx context.Context, tx *sql.Tx, bindings []model.CapacityMutationBinding) error {
	ordered := append([]model.CapacityMutationBinding(nil), bindings...)
	sort.Slice(ordered, func(i, j int) bool {
		return ordered[i].IntegrationInstanceID+"/"+ordered[i].ScopeChecksum+"/"+ordered[i].ProfileName < ordered[j].IntegrationInstanceID+"/"+ordered[j].ScopeChecksum+"/"+ordered[j].ProfileName
	})
	for _, b := range ordered {
		if err := lockRetirementForwardProfileTx(ctx, tx, b); err != nil {
			return err
		}
	}
	return nil
}
func lockRetirementForwardProfileTx(ctx context.Context, tx *sql.Tx, b model.CapacityMutationBinding) error {
	key, _ := json.Marshal([]string{"capacity-retirement-forward-profile", b.IntegrationInstanceID, b.ScopeChecksum, b.ProfileName})
	_, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, string(key))
	return err
}
func guardRetirementForwardSlotTx(ctx context.Context, tx *sql.Tx, b model.CapacityMutationBinding, slot int) error {
	// A genuinely absent marker uses only the existing intent table. Callers
	// hold the physical-profile lock, so a same-profile admission cannot race
	// this check. Every present marker requires its ledger; errors never open it.
	var present bool
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM public.capacity_intents WHERE intent ? 'retirement_forward' AND intent->'retirement_forward'<>'null'::jsonb)`).Scan(&present); err != nil {
		return err
	}
	if !present {
		return nil
	}
	rows, err := tx.QueryContext(ctx, `SELECT f.id::text,f.slot,f.stage,COALESCE(c.intent->'retirement_forward'=jsonb_build_object('schema',f.original_record->>'schema','id',f.id::text,'retirement_request_id',f.retirement_request_id::text,'preregistration_id',f.preregistration_id::text,'mode',f.original_record->>'mode','stage',f.stage,'original_intent_sha256',f.original_record->>'original_intent_sha256','original_generation',f.original_record->'original_generation','original_fence',f.original_record->'original_fence'),false) FROM public.capacity_intents c LEFT JOIN public.capacity_guest_retirement_forwards f ON c.namespace=f.namespace AND c.environment=f.environment AND c.domain=f.domain AND c.dimension=f.dimension AND c.intent#>>'{retirement_forward,id}'=f.id::text AND f.stage=c.intent#>>'{retirement_forward,stage}' WHERE c.intent ? 'retirement_forward' AND c.intent->'retirement_forward'<>'null'::jsonb AND (f.id IS NULL OR (f.integration_instance_id=$1 AND f.scope_checksum=$2 AND f.profile_name=$3))`, b.IntegrationInstanceID, b.ScopeChecksum, b.ProfileName)
	if err != nil {
		return err
	}
	defer rows.Close()
	n := 0
	for rows.Next() {
		var id, stage string
		var target int
		var markerMatches bool
		if err = rows.Scan(&id, &target, &stage, &markerMatches); err != nil {
			return err // NULL/unknown/malformed marker cannot disappear in a join.
		}
		if !markerMatches {
			return ErrCapacityConflict
		}
		if stage == "terminal" {
			continue // Exact immutable terminal is history, not an active fence.
		}
		n++
		scope, ok := ctx.Value(retirementForwardScopeKey{}).(retirementForwardScope)
		if !ok || scope.id != id || scope.slot != target || slot != target {
			return ErrCapacityConflict
		}
	}
	if n > 1 {
		return ErrCapacityConflict
	}
	return rows.Err()
}

func forwardMutationContext(ctx context.Context, s CapacityStore, current model.CapacityIntent, b model.CapacityMutationBinding, slot int, capability string) (context.Context, error) {
	if !retirementForwardActive(&current) {
		return ctx, nil
	}
	m := current.RetirementForward
	if !forwardSourceOrigin(s, "capacity.finish_original_guest_retirement") || capability != b.DestroyCapability || slot != current.Decision.Units+1 || (m.Stage != "off_qualified" && m.Stage != "admitted") {
		return ctx, ErrCapacityConflict
	}
	return context.WithValue(ctx, retirementForwardScopeKey{}, retirementForwardScope{id: m.ID, slot: slot}), nil
}

// Callback callers have no workflow Source context. Under the already-held
// scope/profile locks, only the exact immutable owning DELETE can reconstruct
// the private slot scope. All callback authentication/state checks still follow.
func retirementForwardCallbackContextTx(ctx context.Context, tx *sql.Tx, record capacityMutationRecord, namespace string, p model.CapacityPolicySpec) (context.Context, error) {
	var raw []byte
	err := tx.QueryRowContext(ctx, `SELECT intent FROM public.capacity_intents WHERE namespace=$1 AND environment=$2 AND domain=$3 AND dimension=$4 AND intent ? 'retirement_forward' AND intent->'retirement_forward'<>'null'::jsonb FOR UPDATE`, namespace, p.Environment, p.Domain, p.Dimension).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return ctx, nil // Existing schema86/no-marker callbacks need no ledger90.
	}
	if err != nil {
		return ctx, err
	}
	var current model.CapacityIntent
	if json.Unmarshal(raw, &current) != nil || current.RetirementForward == nil {
		return ctx, ErrCapacityConflict
	}
	m := current.RetirementForward
	if m.Stage == "terminal" {
		return ctx, nil // The existing slot guard still authenticates terminal history.
	}
	if (m.Stage != "admitted" && m.Stage != "off_qualified") || current.Namespace != namespace || current.Environment != p.Environment || current.Domain != p.Domain || current.Dimension != p.Dimension || current.PolicyID != record.PolicyID || current.PolicyChecksum != record.PolicyChecksum || current.Generation != record.Generation || current.FencingToken != record.FencingToken || current.LeaseOwner != record.LeaseOwner || current.LeaseExecutorID != record.ExecutorID || current.Phase != "drained" || current.RecoveryOnly || record.Grant.Capability != record.Binding.DestroyCapability || record.Grant.CompensationOf != "" {
		return ctx, ErrCapacityConflict
	}
	r, _, err := loadRetirementForwardTx(ctx, tx, m.ID, m.Stage)
	if err != nil {
		return ctx, err
	}
	if !reflect.DeepEqual(m, retirementForwardMarker(r)) || r.ActualCoreSource != capacity.CurrentGuestCoreSource() || r.Namespace != namespace || r.Environment != p.Environment || r.Domain != p.Domain || r.Dimension != p.Dimension || r.Generation != current.Generation || r.Fence != current.FencingToken || r.LeaseOwner != current.LeaseOwner || r.ExecutorID != current.LeaseExecutorID || record.WorkflowID.String() != r.Original.Request.Intent.WorkflowID || r.DestroyGrantID != "" {
		return ctx, ErrCapacityConflict
	}
	// Historical parent receipts may be read/confirmed by a child, never used
	// to reconstruct a callback scope under the child's different admission.
	var sameAdmission bool
	err = tx.QueryRowContext(ctx, `SELECT convert_from(original_wire,'UTF8')::jsonb->>'admission_id'=$3 FROM public.capacity_vm_retirement_delete_bindings WHERE intent_id=$1 AND destroy_grant_id=$2 FOR SHARE`, r.RetirementRequestID, record.Grant.GrantID, r.ID).Scan(&sameAdmission)
	if err != nil {
		return ctx, err
	}
	if !sameAdmission {
		return ctx, ErrCapacityConflict
	}
	owned, err := retirementForwardDestroyRecordTx(ctx, tx, r, record.Grant.GrantID)
	if err != nil {
		return ctx, err
	}
	// State may have advanced before these ordered profile locks were acquired.
	// Compare every immutable grant field; the actual state is reloaded FOR
	// UPDATE and checked by the unchanged callback body before any mutation.
	g := owned.Grant
	g.State = record.Grant.State
	if !reflect.DeepEqual(g, record.Grant) || !reflect.DeepEqual(owned.Binding, record.Binding) || owned.PolicyID != record.PolicyID || owned.PolicyChecksum != record.PolicyChecksum || owned.WorkflowID != record.WorkflowID || owned.Generation != record.Generation || owned.FencingToken != record.FencingToken || owned.LeaseOwner != record.LeaseOwner || owned.ExecutorID != record.ExecutorID || !owned.CreatedAt.Equal(record.CreatedAt) {
		return ctx, ErrCapacityConflict
	}
	return context.WithValue(ctx, retirementForwardScopeKey{}, retirementForwardScope{id: m.ID, slot: record.Grant.Slot}), nil
}

// This new Source-only inventory path refreshes exact already-owned slots; it
// cannot create/adopt membership, clear tombstones or confer useful capacity.
func (s CapacityStore) RefreshGuestRetirementForwardInventory(ctx context.Context, policy model.Manifest, generation, fence int64, owner, id string, inv model.CapacityVMFleetInventory) error {
	if !forwardSourceOrigin(s, "capacity.finish_original_guest_retirement") {
		return ErrCapacityConflict
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	x, r, _, err := s.retirementForwardCurrentTx(ctx, tx, id)
	if err != nil {
		return err
	}
	if x.policy.ID != policy.ID || x.policy.Checksum != policy.Checksum || r.Generation != generation || r.Fence != fence || r.LeaseOwner != owner {
		return ErrCapacityConflict
	}
	proofs, err := capacity.VMInventoryProofs(x.spec, x.binding, inv, "", 0, x.now, "retirement-forward-inventory:"+r.ID)
	if err != nil {
		return err
	}
	want := x.current.BaselineSnapshot.Units
	adopted := r.DestroyGrantID
	if adopted != "" {
		want = x.current.Decision.Units
		missing := false
		for _, slot := range inv.MissingSlots {
			missing = missing || slot == x.original.Request.Intent.Slot
		}
		if !missing {
			return ErrCapacityConflict
		}
	}
	if len(proofs) != want {
		return ErrCapacityConflict
	}
	seen := map[int]bool{}
	for _, proof := range proofs {
		if seen[proof.Slot] || proof.Slot < 1 || proof.Slot > x.original.Request.Intent.Slot || !proof.OwnerVerified || !proof.SpecVerified || proof.ResourceAbsent {
			return ErrCapacityConflict
		}
		seen[proof.Slot] = true
		slot, exists, e := loadMutationSlot(ctx, tx, x.policy.Metadata.Namespace, x.spec, x.binding, proof.Slot)
		if e != nil || !exists || slot.Tombstone || slot.ResourceID != proof.ResourceID || slot.ResourceCreatedAt != proof.ResourceCreatedAt || slot.ProfileName != x.binding.ProfileName || slot.DesiredSpecSHA256 != proof.RequestSHA256 {
			return ErrCapacityConflict
		}
		slot.ObservedAt = x.now
		if err = saveMutationSlot(ctx, tx, x.policy.Metadata.Namespace, x.spec, x.binding, proof.Slot, slot); err != nil {
			return err
		}
	}
	if ctx.Err() != nil {
		return ErrCapacityLease
	}
	return tx.Commit()
}

func (s CapacityStore) guardRetirementForwardTransitionTx(ctx context.Context, tx *sql.Tx, policy model.Manifest, p model.CapacityPolicySpec, old *model.CapacityIntent, next *model.CapacityIntent, now time.Time) error {
	if !retirementForwardActive(old) {
		return nil
	}
	if next.Generation != old.Generation || next.FencingToken != old.FencingToken || !reflect.DeepEqual(next.RetirementForward, old.RetirementForward) {
		return ErrCapacityConflict
	}
	if next.Phase == old.Phase {
		// Ordinary observation/no-op or same-owner live lease renewal only. Generic
		// Recover must never rearm the Guest or convert this marker into broad power.
		copy := *old
		copy.UpdatedAt = next.UpdatedAt
		copy.LeaseExpiresAt = next.LeaseExpiresAt
		if !reflect.DeepEqual(copy, *next) || old.LeaseExpiresAt == nil || !old.LeaseExpiresAt.After(now) {
			return ErrCapacityConflict
		}
		return nil
	}
	if next.Phase != "promoted" || s.guestReconcile == nil || s.guestReconcile.mode != "retire" || s.guestReconcile.step.Use.Operation != capacity.CompleteOriginalGuestOperation {
		return ErrCapacityConflict
	}
	r, sha, err := loadRetirementForwardTx(ctx, tx, old.RetirementForward.ID, "admitted")
	if err != nil {
		return err
	}
	if err = s.guestForwardCompletionTx(ctx, tx, policy, p, *old, r, now); err != nil {
		return err
	}
	terminal := r
	terminal.Stage = "terminal"
	terminal.RecordedAt = now
	terminal.AdmissionSHA256 = sha
	// Terminal points to the actual confirmed owned destroy and absence proof.
	var grant string
	if err = tx.QueryRowContext(ctx, `SELECT destroy_grant_id::text FROM public.capacity_vm_retirement_delete_bindings WHERE intent_id=$1`, r.RetirementRequestID).Scan(&grant); err != nil {
		return err
	}
	original, err := retirementForwardDestroyRecordTx(ctx, tx, r, grant)
	if err != nil {
		return err
	}
	terminal.DestroyGrantID = grant
	_, absenceSHA, e := s.retirementForwardLatestAbsenceTx(ctx, tx, r, p, original, now)
	if e != nil {
		return e
	}
	terminal.NativeAbsenceSHA256 = absenceSHA
	next.RetirementForward = retirementForwardMarker(terminal)
	raw, err := json.Marshal(next)
	if err != nil {
		return err
	}
	terminal.TerminalIntentSHA256 = capacity.BusinessCreationSHA256(raw)
	terminal.TerminalIntentWire = raw
	_, err = insertRetirementForwardTx(ctx, tx, terminal)
	return err
}
func (s CapacityStore) guestForwardCompletionTx(ctx context.Context, tx *sql.Tx, policy model.Manifest, p model.CapacityPolicySpec, current model.CapacityIntent, r GuestRetirementForward, now time.Time) error {
	if r.Generation != current.Generation || r.Fence != current.FencingToken || r.ExecutorID != s.ExecutorID || r.LeaseOwner != current.LeaseOwner || r.RunID != s.OriginalRunID.String() {
		return ErrCapacityConflict
	}
	var grant string
	if err := tx.QueryRowContext(ctx, `SELECT destroy_grant_id::text FROM public.capacity_vm_retirement_delete_bindings WHERE intent_id=$1`, r.RetirementRequestID).Scan(&grant); err != nil {
		return err
	}
	original, err := retirementForwardDestroyRecordTx(ctx, tx, r, grant)
	if err != nil || original.Grant.State != "confirmed" || original.Proof == nil {
		return ErrCapacityConflict
	}
	if _, _, err = s.retirementForwardLatestAbsenceTx(ctx, tx, r, p, original, now); err != nil {
		return err
	}
	if err = s.retirementForwardUsefulFloorTx(ctx, tx, retirementForwardSnapshot{original: r.Original, policy: policy, spec: p, current: current, binding: original.Binding, now: now}, r); err != nil {
		return err
	}
	// Reprove the original signed prefix/frame after native effects, never
	// silently accept a late or unrelated appended historical observation.
	stored, err := loadGuestRetirementV2Tx(ctx, tx, r.RetirementRequestID, true)
	if err != nil {
		return err
	}
	var evidence guestRetirementForwardEvidence
	if r.NormalFinishRecovery != nil {
		evidence, err = guestRetirementNormalFinishEvidenceTx(ctx, tx, stored)
	} else {
		evidence, err = guestRetirementForwardEvidenceTx(ctx, tx, stored)
	}
	if err != nil || !reflect.DeepEqual(evidence, r.Evidence) {
		return ErrCapacityConflict
	}
	return nil
}

// Snapshot may inspect the original tuple after its exact confirmed owned
// destroy tombstoned it, solely for final readback/completion.
func forwardConfirmedTombstoneTx(ctx context.Context, tx *sql.Tx, current model.CapacityIntent, slot capacityResourceSlot) bool {
	if !retirementForwardActive(&current) || !slot.Tombstone || slot.ResourceID != "" {
		return false
	}
	stage := "admitted"
	if current.RetirementForward.Stage == "requested" {
		stage = "requested"
	}
	r, _, err := loadRetirementForwardTx(ctx, tx, current.RetirementForward.ID, stage)
	if err != nil {
		return false
	}
	var id string
	err = tx.QueryRowContext(ctx, `SELECT destroy_grant_id::text FROM public.capacity_vm_retirement_delete_bindings WHERE intent_id=$1`, r.RetirementRequestID).Scan(&id)
	if err != nil {
		return false
	}
	g, err := retirementForwardDestroyRecordTx(ctx, tx, r, id)
	return err == nil && g.Grant.State == "confirmed" && g.Proof != nil && g.Proof.ResourceAbsent
}

// This only computes a wait before the ONE publication attempt; the ordinary
// issue path still rechecks every budget/pin/lease gate after the wait.
func (s CapacityStore) GuestRetirementForwardPublicationDelay(ctx context.Context, policy model.Manifest, generation, fence int64, owner, id, preID string) (time.Duration, error) {
	if !forwardSourceOrigin(s, "capacity.finish_original_guest_retirement") {
		return 0, ErrCapacityConflict
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	x, r, _, err := s.retirementForwardCurrentTx(ctx, tx, id)
	if err != nil {
		return 0, err
	}
	if policy.ID != x.policy.ID || policy.Checksum != x.policy.Checksum || r.Generation != generation || r.Fence != fence || r.LeaseOwner != owner || preID == r.PreregistrationID {
		return 0, ErrCapacityConflict
	}
	stored, _, err := s.guestNotifyStoredTx(ctx, tx, policy, x.spec, preID)
	if err != nil || stored.pre.Slot >= x.original.Request.Intent.Slot || x.spec.GuestNotifyCanaryBinding == nil {
		return 0, ErrCapacityConflict
	}
	var spent, attempts, streak int
	var latest sql.NullTime
	err = tx.QueryRowContext(ctx, guestNotifyPublicationBudgetQuery, preID, x.now, x.now.Add(-time.Hour)).Scan(&spent, &attempts, &latest, &streak)
	b := *x.spec.GuestNotifyCanaryBinding
	if err != nil || spent >= b.MaximumPublicationsPerHour || attempts >= guestNotifyPublicationAttemptCeiling {
		return 0, ErrCapacityConflict
	}
	if !latest.Valid {
		return 0, nil
	}
	delay := guestNotifyPublicationGap(b.MinimumPublicationIntervalSeconds, streak) - x.now.Sub(latest.Time)
	if delay < 0 {
		delay = 0
	}
	if x.current.LeaseExpiresAt == nil || !x.current.LeaseExpiresAt.After(x.now.Add(delay)) {
		return 0, ErrCapacityLease
	}
	return delay, nil
}
