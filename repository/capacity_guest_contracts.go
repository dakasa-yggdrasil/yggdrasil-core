package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"reflect"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

// birth is retained separately from the current-policy computational view.
// No Manifest spec/checksum or signed enrollment is rewritten.
type guestResolvedContract struct {
	birth  model.Manifest
	spec   model.CapacityPolicySpec
	digest string
}

func guestContractDigest(p model.CapacityPolicySpec) string {
	if p.GuestRetirementBinding == nil || len(p.Profiles) != 1 {
		return ""
	}
	return capacity.GuestProductionProfileContractSHA256(p, *p.GuestRetirementBinding, p.Profiles[0].Provider)
}

func guestContractLockBindingsTx(ctx context.Context, tx *sql.Tx, policy model.Manifest, p model.CapacityPolicySpec) error {
	if p.GuestContractSuccessor == nil {
		return lockRetirementForwardBindingsTx(ctx, tx, p.MutationBindings)
	}
	cs, err := guestContractSetTx(ctx, tx, policy, p)
	if err != nil {
		return err
	}
	var bindings []model.CapacityMutationBinding
	for _, c := range cs {
		bindings = append(bindings, c.spec.MutationBindings...)
	}
	if err = lockRetirementForwardBindingsTx(ctx, tx, bindings); err != nil {
		return err
	}
	for _, b := range bindings {
		if err = checkMutationIntegration(ctx, tx, b); err != nil {
			return err
		}
	}
	return nil
}

func guestContractSetTx(ctx context.Context, q guestPolicyContinuityQueryer, policy model.Manifest, p model.CapacityPolicySpec) ([]guestResolvedContract, error) {
	return guestContractSetAtPolicyTx(ctx, q, policy, p, true)
}

func guestContractSetAtPolicyTx(ctx context.Context, q guestPolicyContinuityQueryer, policy model.Manifest, p model.CapacityPolicySpec, currentRequired bool) ([]guestResolvedContract, error) {
	if p.GuestContractSuccessor == nil {
		return []guestResolvedContract{{birth: policy, spec: p, digest: guestContractDigest(p)}}, nil
	}
	// Re-read the actual policy; p may already be a verified member view.
	var raw []byte
	var version int
	var checksum string
	var active bool
	if err := q.QueryRowContext(ctx, `SELECT spec,version,checksum,active FROM public.manifests WHERE id=$1 AND kind='capacity_policy' AND namespace=$2 AND name=$3 FOR SHARE`, policy.ID, policy.Metadata.Namespace, policy.Metadata.Name).Scan(&raw, &version, &checksum, &active); err != nil {
		return nil, err
	}
	var current model.CapacityPolicySpec
	if capacity.ValidateGuestContractSuccessorJSON(raw) != nil || json.Unmarshal(raw, &current) != nil || capacity.ValidateGuestContractSuccessor(current) != nil || current.GuestContractSuccessor == nil || checksum != policy.Checksum || currentRequired && !active || current.GuestRetirementBinding == nil || !capacity.GuestBindingAuthorityCurrent(current, *current.GuestRetirementBinding) {
		return nil, ErrCapacityConflict
	}
	var newer bool
	if currentRequired {
		if err := q.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM public.manifests WHERE kind='capacity_policy' AND namespace=$1 AND name=$2 AND (version>$3 OR active AND id<>$4))`, policy.Metadata.Namespace, policy.Metadata.Name, version, policy.ID).Scan(&newer); err != nil || newer {
			return nil, ErrCapacityConflict
		}
	}
	out := []guestResolvedContract{{birth: policy, spec: current, digest: guestContractDigest(current)}}
	seen := map[string]bool{out[0].digest: true}
	targets := map[string]bool{current.MutationBindings[0].IntegrationInstanceID + "/" + current.MutationBindings[0].ScopeChecksum: true}
	for _, r := range current.GuestContractSuccessor.RetainedPolicyContracts {
		var birth model.Manifest
		birth.ID, _ = uuid.Parse(r.PolicyID)
		birth.Kind = "capacity_policy"
		var priorVersion int
		if err := q.QueryRowContext(ctx, `SELECT namespace,name,version,checksum,spec FROM public.manifests WHERE id=$1 AND kind='capacity_policy' FOR SHARE`, birth.ID).Scan(&birth.Metadata.Namespace, &birth.Metadata.Name, &priorVersion, &birth.Checksum, &birth.Spec); err != nil {
			return nil, err
		}
		var prior model.CapacityPolicySpec
		if birth.Metadata.Namespace != policy.Metadata.Namespace || birth.Metadata.Name != policy.Metadata.Name || birth.Checksum != r.PolicyChecksum || priorVersion >= version || json.Unmarshal(birth.Spec, &prior) != nil || prior.GuestRetirementBinding == nil || guestContractDigest(prior) != r.ContractSHA256 || !capacity.GuestBindingAuthorityCurrent(prior, *prior.GuestRetirementBinding) || seen[r.ContractSHA256] {
			return nil, ErrCapacityConflict
		}
		view, err := capacity.GuestContractView(current, prior)
		if err != nil {
			return nil, ErrCapacityConflict
		}
		b := view.MutationBindings[0]
		key := b.IntegrationInstanceID + "/" + b.ScopeChecksum
		if targets[key] {
			return nil, ErrCapacityConflict
		}
		seen[r.ContractSHA256], targets[key] = true, true
		out = append(out, guestResolvedContract{birth: birth, spec: view, digest: r.ContractSHA256})
	}
	return out, nil
}

// Guest contract succession is member-specific. Every stored intermediate row
// must carry that same default contract or explicitly retain its immutable row.
func guestContractLineageTx(ctx context.Context, q guestPolicyContinuityQueryer, policy model.Manifest, p model.CapacityPolicySpec, priorID, priorSHA string) error {
	var prior model.Manifest
	prior.ID, _ = uuid.Parse(priorID)
	prior.Kind = "capacity_policy"
	var from, to int
	if err := q.QueryRowContext(ctx, `SELECT namespace,name,version,checksum,spec FROM public.manifests WHERE id=$1 AND kind='capacity_policy'`, prior.ID).Scan(&prior.Metadata.Namespace, &prior.Metadata.Name, &from, &prior.Checksum, &prior.Spec); err != nil {
		return err
	}
	if prior.Metadata.Namespace != policy.Metadata.Namespace || prior.Metadata.Name != policy.Metadata.Name || prior.Checksum != priorSHA {
		return ErrCapacityConflict
	}
	var birth model.CapacityPolicySpec
	if json.Unmarshal(prior.Spec, &birth) != nil || birth.GuestRetirementBinding == nil || !capacity.GuestBindingAuthorityCurrent(birth, *birth.GuestRetirementBinding) {
		return ErrCapacityConflict
	}
	if err := q.QueryRowContext(ctx, `SELECT version FROM public.manifests WHERE id=$1 AND kind='capacity_policy' AND checksum=$2`, policy.ID, policy.Checksum).Scan(&to); err != nil {
		return err
	}
	if from > to {
		return ErrCapacityConflict
	}
	rows, err := q.QueryContext(ctx, `SELECT id,version,spec FROM public.manifests WHERE kind='capacity_policy' AND namespace=$1 AND name=$2 AND version>=$3 AND version<=$4 ORDER BY version,id`, policy.Metadata.Namespace, policy.Metadata.Name, from, to)
	if err != nil {
		return err
	}
	type row struct {
		id      uuid.UUID
		version int
		raw     []byte
	}
	var all []row
	for rows.Next() {
		var r row
		if err = rows.Scan(&r.id, &r.version, &r.raw); err != nil {
			rows.Close()
			return err
		}
		all = append(all, r)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	if len(all) != to-from+1 {
		return ErrCapacityConflict
	}
	sawPrior, sawCurrent := false, false
	for i, r := range all {
		if r.version != from+i {
			return ErrCapacityConflict
		}
		var v model.CapacityPolicySpec
		if capacity.ValidateGuestContractSuccessorJSON(r.raw) != nil || json.Unmarshal(r.raw, &v) != nil || capacity.ValidateGuestContractSuccessor(v) != nil || v.GuestRetirementBinding == nil || !capacity.GuestBindingAuthorityCurrent(v, *v.GuestRetirementBinding) {
			return ErrCapacityConflict
		}
		if !capacity.GuestPolicyContinuous(birth, v) {
			if capacity.ValidateGuestContractSuccessor(v) != nil || v.GuestContractSuccessor == nil {
				return ErrCapacityConflict
			}
			retained := false
			for _, ref := range v.GuestContractSuccessor.RetainedPolicyContracts {
				var raw []byte
				var vnum int
				if err = q.QueryRowContext(ctx, `SELECT spec,version FROM public.manifests WHERE id=$1 AND kind='capacity_policy' AND namespace=$2 AND name=$3 AND checksum=$4`, ref.PolicyID, policy.Metadata.Namespace, policy.Metadata.Name, ref.PolicyChecksum).Scan(&raw, &vnum); err != nil {
					return err
				}
				var old model.CapacityPolicySpec
				if vnum >= r.version || json.Unmarshal(raw, &old) != nil || old.GuestRetirementBinding == nil || !capacity.GuestBindingAuthorityCurrent(old, *old.GuestRetirementBinding) || guestContractDigest(old) != ref.ContractSHA256 {
					return ErrCapacityConflict
				}
				if _, e := capacity.GuestContractView(v, old); e != nil {
					return ErrCapacityConflict
				}
				retained = retained || capacity.GuestPolicyContinuous(birth, old)
			}
			if !retained {
				return ErrCapacityConflict
			}
		}
		sawPrior = sawPrior || r.id == prior.ID
		sawCurrent = sawCurrent || r.id == policy.ID
	}
	if !sawPrior || !sawCurrent {
		return ErrCapacityConflict
	}
	return nil
}

func (s CapacityStore) guestReconcileContractMembersTx(ctx context.Context, tx *sql.Tx, policy model.Manifest, p model.CapacityPolicySpec, now time.Time, refresh bool) ([]GuestNotifyFloorMember, error) {
	cs, err := guestContractSetTx(ctx, tx, policy, p)
	if err != nil {
		return nil, err
	}
	views := make([]model.CapacityPolicySpec, len(cs))
	for i, c := range cs {
		views[i] = c.spec
	}
	if _, _, err = capacity.GuestContractReconcileSnapshot(policy, p, views, s.guestReconcile.inventories, now); err != nil {
		return nil, err
	}
	var all []GuestNotifyFloorMember
	seen := map[int]bool{}
	for i, c := range cs {
		members, e := s.guestReconcileSingleContractMembersTx(ctx, tx, policy, c.spec, s.guestReconcile.inventories[i].Inventory, now, refresh)
		if e != nil {
			return nil, e
		}
		for _, m := range members {
			logical, e := guestLogicalSlotTx(ctx, tx, policy, p, m.Slot)
			if e != nil || !logical.exists || !reflect.DeepEqual(logical.binding, c.spec.MutationBindings[0]) {
				return nil, ErrCapacityConflict
			}
			if seen[m.Slot] {
				return nil, ErrCapacityConflict
			}
			seen[m.Slot] = true
			all = append(all, m)
		}
	}
	for slot := 1; slot <= p.Ceiling; slot++ {
		logical, e := guestLogicalSlotTx(ctx, tx, policy, p, slot)
		if e != nil || logical.exists != seen[slot] {
			return nil, ErrCapacityConflict
		}
	}
	return all, nil
}

func guestContractPendingDestroyTx(ctx context.Context, tx *sql.Tx, policy model.Manifest, p model.CapacityPolicySpec, b model.CapacityMutationBinding, slot int) (bool, error) {
	var pending int
	err := tx.QueryRowContext(ctx, `SELECT count(*) FROM public.capacity_mutation_grants WHERE `+capacityGrantUndisposedSQL+` AND namespace=$1 AND environment=$2 AND domain=$3 AND dimension=$4 AND slot=$5 AND state IN('issued','redeemed','settled','compensating') AND grant_record->'grant'->>'capability'=$6`, policy.Metadata.Namespace, p.Environment, p.Domain, p.Dimension, slot, b.DestroyCapability).Scan(&pending)
	return pending != 0, err
}

func (s CapacityStore) guestContractFloorMembersTx(ctx context.Context, tx *sql.Tx, policy model.Manifest, p model.CapacityPolicySpec, excludedSlot int) ([]GuestNotifyFloorMember, error) {
	var out []GuestNotifyFloorMember
	for slot := 1; slot <= p.Ceiling; slot++ {
		if slot == excludedSlot {
			continue
		}
		logical, err := guestLogicalSlotTx(ctx, tx, policy, p, slot)
		if err != nil {
			return nil, err
		}
		if !logical.exists {
			continue
		}
		if err = checkMutationIntegration(ctx, tx, logical.binding); err != nil {
			return nil, err
		}
		pending, err := guestContractPendingDestroyTx(ctx, tx, policy, p, logical.binding, slot)
		if err != nil {
			return nil, err
		}
		if pending {
			continue
		}
		member, err := guestMember(*logical.spec.GuestRetirementBinding, slot)
		if err != nil {
			return nil, err
		}
		receipt, err := guestNotifyMemberReceiptTx(ctx, tx, policy, logical.spec, member, logical.slot)
		if err != nil {
			return nil, err
		}
		if _, _, err = s.guestNotifyStoredTx(ctx, tx, policy, p, receipt.PreregistrationID); err != nil {
			return nil, err
		}
		out = append(out, GuestNotifyFloorMember{Slot: slot, PreregistrationID: receipt.PreregistrationID})
	}
	// The caller's unchanged reduction/lease checks own the required count.
	return out, nil
}

func (s CapacityStore) guestContractUsefulMembersTx(ctx context.Context, tx *sql.Tx, policy model.Manifest, p model.CapacityPolicySpec, current model.CapacityIntent, excludedSlot int, now time.Time, usage string, afterPG time.Time) (int, error) {
	var proofs []guestNotifyUsefulMemberProof
	for slot := 1; slot <= p.Ceiling; slot++ {
		if slot == excludedSlot {
			continue
		}
		logical, err := guestLogicalSlotTx(ctx, tx, policy, p, slot)
		if err != nil {
			return 0, err
		}
		if !logical.exists {
			continue
		}
		if err = checkMutationIntegration(ctx, tx, logical.binding); err != nil {
			return 0, err
		}
		pending, err := guestContractPendingDestroyTx(ctx, tx, policy, p, logical.binding, slot)
		if err != nil {
			return 0, err
		}
		if pending {
			continue
		}
		member, err := guestMember(*logical.spec.GuestRetirementBinding, slot)
		if err != nil {
			return 0, err
		}
		receipt, err := guestNotifyMemberReceiptTx(ctx, tx, policy, logical.spec, member, logical.slot)
		if err != nil {
			return 0, err
		}
		proof, err := loadFreshGuestNotifyBusinessTx(ctx, tx, policy, logical.spec, current, receipt.PreregistrationID, receipt, now, usage, afterPG)
		if err != nil {
			return 0, err
		}
		proof.nativeSlotObserved = logical.slot.ObservedAt
		proofs = append(proofs, proof)
	}
	var freshPG time.Time
	if err := tx.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&freshPG); err != nil {
		return 0, err
	}
	for _, proof := range proofs {
		if !capacity.Fresh(proof.nativeSlotObserved, freshPG, p.MaxEvidenceAgeSeconds) || !capacity.GuestNotifyBusinessStillFresh(proof.business, proof.recordedPG, freshPG, p.MaxEvidenceAgeSeconds) {
			return 0, ErrCapacityConflict
		}
	}
	return len(proofs), nil
}

// The same forward owner refreshes all original physical receipts. A collection
// is not a new adapter return, permission, clock or retirement authority.
func (s CapacityStore) RefreshGuestRetirementForwardContractInventories(ctx context.Context, policy model.Manifest, generation, fence int64, owner, id string, originals []capacity.GuestContractInventory) error {
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
	p, err := parseCapacityPolicy(x.policy)
	if err != nil || p.GuestContractSuccessor == nil {
		return ErrCapacityConflict
	}
	cs, err := guestContractSetTx(ctx, tx, x.policy, p)
	if err != nil {
		return err
	}
	views := make([]model.CapacityPolicySpec, len(cs))
	for i, c := range cs {
		views[i] = c.spec
	}
	snapshot, missing, err := capacity.GuestContractReconcileSnapshot(x.policy, p, views, originals, x.now)
	if err != nil {
		return err
	}
	want := x.current.BaselineSnapshot.Units
	if r.DestroyGrantID != "" {
		want = x.current.Decision.Units
		absent := false
		for _, slot := range missing {
			absent = absent || slot == x.original.Request.Intent.Slot
		}
		if !absent {
			return ErrCapacityConflict
		}
	}
	if snapshot.Units != want {
		return ErrCapacityConflict
	}
	seen := map[int]bool{}
	for i, c := range cs {
		b := c.spec.MutationBindings[0]
		proofs, e := capacity.VMInventoryProofs(c.spec, b, originals[i].Inventory, "", 0, x.now, "retirement-forward-inventory:"+r.ID)
		if e != nil {
			return e
		}
		for _, proof := range proofs {
			if seen[proof.Slot] || proof.Slot < 1 || proof.Slot > x.original.Request.Intent.Slot || !proof.OwnerVerified || !proof.SpecVerified || proof.ResourceAbsent {
				return ErrCapacityConflict
			}
			seen[proof.Slot] = true
			logical, e := guestLogicalSlotTx(ctx, tx, x.policy, p, proof.Slot)
			if e != nil || !logical.exists || !reflect.DeepEqual(logical.binding, b) || logical.slot.ResourceID != proof.ResourceID || logical.slot.ResourceCreatedAt != proof.ResourceCreatedAt || logical.slot.DesiredSpecSHA256 != proof.RequestSHA256 {
				return ErrCapacityConflict
			}
			slot := logical.slot
			slot.ObservedAt = x.now
			if e = saveMutationSlot(ctx, tx, x.policy.Metadata.Namespace, c.spec, b, proof.Slot, slot); e != nil {
				return e
			}
		}
	}
	for slot := 1; slot <= p.Ceiling; slot++ {
		logical, e := guestLogicalSlotTx(ctx, tx, x.policy, p, slot)
		if e != nil {
			return e
		}
		if logical.exists && !seen[slot] && !(r.DestroyGrantID != "" && slot == x.original.Request.Intent.Slot) {
			return ErrCapacityConflict
		}
	}
	if ctx.Err() != nil {
		return ErrCapacityLease
	}
	return tx.Commit()
}

func guestStoredContractSpecTx(ctx context.Context, q guestPolicyContinuityQueryer, policy model.Manifest, p model.CapacityPolicySpec, stored guestOriginalStored) (model.CapacityPolicySpec, error) {
	if p.GuestContractSuccessor == nil {
		return p, nil
	}
	contracts, err := guestContractSetTx(ctx, q, policy, p)
	if err != nil {
		return p, err
	}
	var selected *model.CapacityPolicySpec
	for _, c := range contracts {
		if c.spec.GuestRetirementBinding != nil && reflect.DeepEqual(*c.spec.GuestRetirementBinding, stored.binding) {
			view := c.spec
			if selected != nil {
				return p, ErrCapacityConflict
			}
			selected = &view
		}
	}
	if selected == nil || guestContractLineageTx(ctx, q, policy, p, stored.pre.PolicyID, stored.pre.PolicyChecksum) != nil {
		return p, ErrCapacityConflict
	}
	return *selected, nil
}

func guestContractForPreTx(ctx context.Context, tx *sql.Tx, policy model.Manifest, p model.CapacityPolicySpec, id string) (model.CapacityPolicySpec, error) {
	if p.GuestContractSuccessor == nil {
		return p, nil
	}
	stored, err := loadGuestOriginalTx(ctx, tx, id)
	if err != nil {
		return p, err
	}
	return guestStoredContractSpecTx(ctx, tx, policy, p, stored)
}

// OriginalGuestContractSpecs is a readonly source-executor lookup. Authority is
// re-derived under the mutation scope in each store method using these receipts.
func (s CapacityStore) OriginalGuestContractSpecs(ctx context.Context, policy model.Manifest) ([]model.CapacityPolicySpec, error) {
	p, err := parseCapacityPolicy(policy)
	if err != nil {
		return nil, err
	}
	if len(p.MutationBindings) != 1 {
		return nil, ErrCapacityConflict
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if err = lockMutationScope(ctx, tx, policy.Metadata.Namespace, p); err != nil {
		return nil, err
	}
	cs, err := guestContractSetTx(ctx, tx, policy, p)
	if err != nil {
		return nil, err
	}
	var out []model.CapacityPolicySpec
	for _, c := range cs {
		if err = checkMutationIntegration(ctx, tx, c.spec.MutationBindings[0]); err != nil {
			return nil, err
		}
		out = append(out, c.spec)
	}
	return out, nil
}

// This is a computational view, not member admission or I/O authority. No
// selector or effective binding is accepted. Ordinary canary/retire admissions
// separately require the current occupant; typed finish and M106 cleanup must
// still resolve their sealed origin after DELETE or before enrollment.
func (s CapacityStore) OriginalGuestMemberContract(ctx context.Context, policy model.Manifest, preID string, slot int) (model.CapacityPolicySpec, error) {
	p, err := parseCapacityPolicy(policy)
	if err != nil || p.GuestContractSuccessor == nil {
		return p, err
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return p, err
	}
	defer tx.Rollback()
	if err = lockMutationScope(ctx, tx, policy.Metadata.Namespace, p); err != nil {
		return p, err
	}
	if err = guestContractLockBindingsTx(ctx, tx, policy, p); err != nil {
		return p, err
	}
	if preID == "" {
		var member guestLogicalMember
		member, err = guestLogicalSlotTx(ctx, tx, policy, p, slot)
		if err != nil || !member.exists {
			return p, ErrCapacityConflict
		}
		preID, err = guestMemberPreregistrationTx(ctx, tx, policy, p, slot, member.slot.ResourceID, member.slot.ResourceCreatedAt)
		if err != nil {
			return p, err
		}
	}
	stored, err := loadGuestOriginalTx(ctx, tx, preID)
	if err != nil || stored.pre.Slot != slot {
		return p, ErrCapacityConflict
	}
	return guestStoredContractSpecTx(ctx, tx, policy, p, stored)
}

// Only the ordinary retirement's new original nonce/POST admission uses this
// active-member guard. Historical finish/readback and unenrolled cleanup keep
// their own exact retained request/child/epoch proofs instead.
func guestRequireCurrentContractMemberTx(ctx context.Context, tx *sql.Tx, policy model.Manifest, p model.CapacityPolicySpec, stored guestOriginalStored) error {
	if p.GuestContractSuccessor == nil {
		return nil
	}
	logical, err := guestLogicalSlotTx(ctx, tx, policy, p, stored.pre.Slot)
	if err != nil || !logical.exists || !reflect.DeepEqual(logical.binding, p.MutationBindings[0]) {
		return ErrCapacityConflict
	}
	if err = loadGuestWitnessTx(ctx, tx, &stored); err != nil {
		return err
	}
	tuple := stored.witness.Tuple
	if tuple.ResourceID != logical.slot.ResourceID || tuple.CreatedAt != logical.slot.ResourceCreatedAt || tuple.Slot != stored.pre.Slot || tuple.InstanceID != logical.binding.IntegrationInstanceID || tuple.ScopeChecksum != logical.binding.ScopeChecksum || tuple.Profile != logical.binding.ProfileName || logical.slot.DesiredSpecSHA256 != stored.pre.OriginalCreateRequestSHA256 {
		return ErrCapacityConflict
	}
	id, err := guestMemberPreregistrationTx(ctx, tx, policy, p, stored.pre.Slot, logical.slot.ResourceID, logical.slot.ResourceCreatedAt)
	if err != nil || id != stored.pre.PreregistrationID {
		return ErrCapacityConflict
	}
	return nil
}

type guestLogicalMember struct {
	spec    model.CapacityPolicySpec
	binding model.CapacityMutationBinding
	slot    capacityResourceSlot
	exists  bool
}

// Scope lock precedes discovery. Every physical binding is checked, including
// empty/tombstoned slots; a new instance cannot hide an old logical occupant.
func guestLogicalSlotTx(ctx context.Context, tx *sql.Tx, policy model.Manifest, p model.CapacityPolicySpec, slot int) (guestLogicalMember, error) {
	var found guestLogicalMember
	cs, err := guestContractSetTx(ctx, tx, policy, p)
	if err != nil {
		return found, err
	}
	var bindings []model.CapacityMutationBinding
	for _, c := range cs {
		bindings = append(bindings, c.spec.MutationBindings...)
	}
	if err = lockRetirementForwardBindingsTx(ctx, tx, bindings); err != nil {
		return found, err
	}
	for _, c := range cs {
		b := c.spec.MutationBindings[0]
		sl, exists, e := loadMutationSlot(ctx, tx, policy.Metadata.Namespace, c.spec, b, slot)
		if e != nil {
			return found, e
		}
		if !exists || sl.Tombstone || sl.ResourceID == "" {
			continue
		}
		if found.exists {
			return found, ErrCapacityConflict
		}
		found = guestLogicalMember{spec: c.spec, binding: b, slot: sl, exists: true}
	}
	var rows int
	if err = tx.QueryRowContext(ctx, `SELECT count(*) FROM public.capacity_resource_slots WHERE namespace=$1 AND environment=$2 AND domain=$3 AND dimension=$4 AND slot=$5 AND resource_id<>'' AND COALESCE(slot_record->>'tombstone','false')='false'`, policy.Metadata.Namespace, p.Environment, p.Domain, p.Dimension, slot).Scan(&rows); err != nil {
		return found, err
	}
	if rows > 1 || rows == 1 && !found.exists {
		return found, ErrCapacityConflict
	}
	return found, nil
}

func (s CapacityStore) guestContractSnapshotTx(ctx context.Context, tx *sql.Tx, policy model.Manifest, p model.CapacityPolicySpec, now time.Time) (model.CapacitySnapshot, error) {
	if p.GuestContractSuccessor == nil {
		return capacity.GuestReconcileSnapshot(policy, p, s.guestReconcile.inventory, now)
	}
	cs, err := guestContractSetTx(ctx, tx, policy, p)
	if err != nil {
		return model.CapacitySnapshot{}, err
	}
	views := make([]model.CapacityPolicySpec, len(cs))
	for i, c := range cs {
		views[i] = c.spec
	}
	snapshot, _, err := capacity.GuestContractReconcileSnapshot(policy, p, views, s.guestReconcile.inventories, now)
	return snapshot, err
}

func guestMutationContractTx(ctx context.Context, tx *sql.Tx, policy model.Manifest, p model.CapacityPolicySpec, issue model.CapacityMutationIssue) (model.CapacityPolicySpec, error) {
	if p.GuestContractSuccessor == nil {
		return p, nil
	}
	var spec model.CapacityMutationSpecV1
	if capacity.DecodeNativeCapacity(issue.DesiredSpec, &spec) != nil || spec.Slot < 1 || spec.Slot > p.Ceiling {
		return p, ErrCapacityConflict
	}
	member, err := guestLogicalSlotTx(ctx, tx, policy, p, spec.Slot)
	if err != nil {
		return p, err
	}
	if spec.Capability == p.MutationBindings[0].EnsureCapability {
		if member.exists {
			return p, ErrCapacityConflict
		}
		var pending int
		if err = tx.QueryRowContext(ctx, `SELECT count(*) FROM public.capacity_mutation_grants WHERE `+capacityGrantUndisposedSQL+` AND namespace=$1 AND environment=$2 AND domain=$3 AND dimension=$4 AND slot=$5 AND state IN('issued','redeemed','settled','compensating')`, policy.Metadata.Namespace, p.Environment, p.Domain, p.Dimension, spec.Slot).Scan(&pending); err != nil || pending != 0 {
			return p, ErrCapacityConflict
		}
		cs, e := guestContractSetTx(ctx, tx, policy, p)
		if e != nil {
			return p, e
		}
		return cs[0].spec, nil
	}
	if !member.exists || spec.Capability != member.binding.DestroyCapability {
		return p, ErrCapacityConflict
	}
	id, err := guestMemberPreregistrationTx(ctx, tx, policy, p, spec.Slot, member.slot.ResourceID, member.slot.ResourceCreatedAt)
	if err != nil {
		return p, err
	}
	return guestContractForPreTx(ctx, tx, policy, p, id)
}

func guestGrantContractTx(ctx context.Context, tx *sql.Tx, policy model.Manifest, p model.CapacityPolicySpec, record capacityMutationRecord) (model.CapacityPolicySpec, error) {
	if p.GuestContractSuccessor == nil {
		return p, nil
	}
	cs, err := guestContractSetTx(ctx, tx, policy, p)
	if err != nil {
		return p, err
	}
	for i, c := range cs {
		if reflect.DeepEqual(c.spec.MutationBindings[0], record.Binding) {
			if i != 0 && record.Grant.Capability != record.Binding.DestroyCapability {
				return p, ErrCapacityConflict
			}
			return c.spec, nil
		}
	}
	return p, ErrCapacityConflict
}
