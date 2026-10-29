//go:build linux && nativequalification

package message

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	q "github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacitynativeqemu"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	"path/filepath"
	"time"
)

// These assertions consume only the original producer's private closed records
// after its calls return. They do not supply nonce, proof, time or authority.
// Retention and qualified/default wiring are owned by the PG17 integrator.
type pg17MutationRecord struct {
	Grant          model.CapacityMutationGrant          `json:"grant"`
	PolicyID       string                               `json:"policy_id"`
	PolicyChecksum string                               `json:"policy_checksum"`
	WorkflowID     string                               `json:"workflow_id"`
	Generation     int64                                `json:"generation"`
	FencingToken   int64                                `json:"fencing_token"`
	LeaseOwner     string                               `json:"lease_owner"`
	ExecutorID     string                               `json:"executor_id"`
	AttemptID      string                               `json:"attempt_id"`
	Settlement     *model.CapacityMutationSettleRequest `json:"settlement"`
	EventProvider  string                               `json:"event_provider"`
	EventResource  string                               `json:"event_resource"`
}

func pg17MutationGrant(ctx context.Context, store repository.CapacityStore, policy model.Manifest, input guestOriginalStepInput, grant model.CapacityMutationGrant) (pg17MutationRecord, []byte, error) {
	var r pg17MutationRecord
	var raw []byte
	if ctx.Err() != nil || originalGuestNativeRealm == nil || grant.Slot != input.Slot || grant.Slot < 1 || grant.Slot > 2 {
		return r, nil, errOriginalGuestStep
	}
	err := store.DB.QueryRowContext(ctx, `SELECT grant_record FROM public.capacity_mutation_grants WHERE id=$1 AND namespace=$2 AND generation=$3`, grant.GrantID, policy.Metadata.Namespace, input.Generation).Scan(&raw)
	if err != nil {
		return r, nil, err
	}
	if json.Unmarshal(raw, &r) != nil || r.Grant.GrantID != grant.GrantID || r.Grant.RequestSHA256 != grant.RequestSHA256 || r.Grant.Slot != input.Slot || r.PolicyID != policy.ID.String() || r.PolicyChecksum != policy.Checksum || r.Generation != input.Generation || r.WorkflowID == "" || r.LeaseOwner != input.LeaseOwner || r.FencingToken != input.FencingToken || r.ExecutorID != store.ExecutorID {
		return r, nil, errOriginalGuestStep
	}
	return r, raw, nil
}

func pg17MutationResult(id int, policy model.Manifest, workflow string, checks []string, pins ...string) PG17AssertionResult {
	return PG17AssertionResult{Schema: "core_pg17_assertion_v1", CaseID: id, OriginalTest: pg17OriginalNames[id], SourceCase: originalGuestNativeRealm.Request.NativeCase, CoreSource: capacity.CurrentGuestCoreSource(), PolicyID: policy.ID.String(), WorkflowID: workflow, Checks: checks, EvidenceSHA256: pins, NativeQualified: false}
}

// ReadPrivate owns FD/no-follow/identity/EOF/Close custody. The explicit keyset
// rejects additional, missing and duplicate fields; typed comparisons reject
// bool/int aliases. Only fixed producer paths are selected here.
func pg17MutationContract(ctx context.Context, slot int, name, keys string) (map[string]json.RawMessage, []byte, error) {
	var out map[string]json.RawMessage
	if originalGuestNativeRealm == nil || ctx.Err() != nil {
		return nil, nil, errOriginalGuestStep
	}
	dir := originalGuestNativeRealm.PrivateDirectory
	if slot != 0 {
		if slot < 1 || slot > 2 {
			return nil, nil, errOriginalGuestStep
		}
		dir = q.SlotDirectory(dir, slot)
	}
	raw, err := q.ReadPrivate(ctx, filepath.Join(dir, name), &out)
	if err != nil {
		return nil, nil, err
	}
	var expected []string
	if json.Unmarshal([]byte(keys), &expected) != nil || len(expected) != len(out) {
		return nil, nil, errOriginalGuestStep
	}
	for _, key := range expected {
		if _, ok := out[key]; !ok {
			return nil, nil, errOriginalGuestStep
		}
	}
	return out, raw, nil
}
func pg17MutationEqual(m map[string]json.RawMessage, key string, v any) bool {
	raw, err := json.Marshal(v)
	return err == nil && bytes.Equal(bytes.TrimSpace(m[key]), raw)
}
func pg17MutationDigest(m map[string]json.RawMessage, key string) string {
	var value string
	if json.Unmarshal(m[key], &value) != nil || !capacity.ValidDigest(value) {
		return ""
	}
	return value
}
func pg17MutationCommon(m map[string]json.RawMessage, schema string, slot int, grant string) bool {
	return pg17MutationEqual(m, "schema", schema) && pg17MutationEqual(m, "core_source", capacity.CurrentGuestCoreSource()) && pg17MutationEqual(m, "slot", slot) && pg17MutationEqual(m, "grant_id", grant)
}

// pg17OriginalUnsentRecordValid consumes the already stored first grant. The
// canonical callback ledger records rejected_before_send as rejected, not settled.
// This assertion grants no authority and preserves the original record/hash joins.
func pg17OriginalUnsentRecordValid(old pg17MutationRecord, policyID, workflowID, settlementSHA string) bool {
	return old.PolicyID == policyID && old.WorkflowID == workflowID && old.Grant.State == "rejected" && old.Settlement != nil && old.Settlement.Outcome == "rejected_before_send" && old.Settlement.ResourceID == "" && settlementSHA == capacity.GuestRetirementSHA(*old.Settlement)
}

func guestPG17MutationAfterCreate(ctx context.Context, store repository.CapacityStore, policy model.Manifest, p model.CapacityPolicySpec, binding model.CapacityMutationBinding, input guestOriginalStepInput, grant model.CapacityMutationGrant, pre model.CapacityGuestOriginalProvisioningPreregistration, proof model.CapacityMutationProof) ([]PG17AssertionResult, error) {
	r, raw, err := pg17MutationGrant(ctx, store, policy, input, grant)
	if err != nil {
		return nil, err
	}
	if r.WorkflowID != pre.WorkflowID || grant.BindingName != binding.Name || grant.IntegrationInstanceID != binding.IntegrationInstanceID || grant.ScopeChecksum != binding.ScopeChecksum || grant.ProfileName != binding.ProfileName || pre.OriginalCreateGrantID != grant.GrantID || pre.Generation != input.Generation || pre.Fence != input.FencingToken || pre.LeaseOwner != input.LeaseOwner || pre.ExecutorID != store.ExecutorID || r.Grant.State != "settled" || r.Settlement == nil || r.AttemptID == "" || r.Settlement.GrantID != grant.GrantID || r.Settlement.AttemptID != r.AttemptID || !r.Settlement.TransportCompleted || (r.Settlement.Outcome == "accepted" && r.Settlement.ResourceID != proof.ResourceID) || proof.GrantID != grant.GrantID {
		return nil, errOriginalGuestStep
	}
	logical, lraw, err := pg17MutationContract(ctx, input.Slot, "logical-reservation-contract.json", `["schema","core_source","slot","contenders","returned","grant_id","grant_sha256","active_grant_rows","historical_grant_rows","preregistrations"]`)
	if err != nil {
		return nil, err
	}
	history := 1
	if q.PositiveCase(originalGuestNativeRealm.Request.NativeCase) {
		history = 2
	}
	if !pg17MutationCommon(logical, "original_guest_logical_reservation_concurrency_v1", input.Slot, grant.GrantID) || !pg17MutationEqual(logical, "contenders", 20) || !pg17MutationEqual(logical, "returned", 20) || !pg17MutationEqual(logical, "active_grant_rows", 1) || !pg17MutationEqual(logical, "historical_grant_rows", history) || !pg17MutationEqual(logical, "preregistrations", 1) || pg17MutationDigest(logical, "grant_sha256") != capacity.GuestRetirementSHA(grant) {
		return nil, errOriginalGuestStep
	}
	redemption, draw, err := pg17MutationContract(ctx, input.Slot, "redemption-concurrency-contract.json", `["schema","core_source","slot","grant_id","write_once","read_only","facts","same_attempt_replay_mode","same_attempt_typed_response_sha256"]`)
	if err != nil {
		return nil, err
	}
	if !pg17MutationCommon(redemption, "original_guest_redemption_concurrency_v1", input.Slot, grant.GrantID) || !pg17MutationEqual(redemption, "write_once", 1) || !pg17MutationEqual(redemption, "read_only", 19) || !pg17MutationEqual(redemption, "same_attempt_replay_mode", "read_only") || pg17MutationDigest(redemption, "same_attempt_typed_response_sha256") == "" {
		return nil, errOriginalGuestStep
	}
	var facts []struct {
		AttemptID  string    `json:"attempt_id"`
		Mode       string    `json:"mode"`
		StartedAt  time.Time `json:"started_at"`
		ReturnedAt time.Time `json:"returned_at"`
		SHA        string    `json:"typed_response_sha256"`
	}
	if json.Unmarshal(redemption["facts"], &facts) != nil || len(facts) != 20 {
		return nil, errOriginalGuestStep
	}
	seen := map[string]bool{}
	writes, reads := 0, 0
	for _, f := range facts {
		if f.AttemptID == "" || seen[f.AttemptID] || f.StartedAt.IsZero() || f.ReturnedAt.Before(f.StartedAt) || f.ReturnedAt.After(pre.OriginalDeadline) || !capacity.ValidDigest(f.SHA) {
			return nil, errOriginalGuestStep
		}
		seen[f.AttemptID] = true
		switch f.Mode {
		case "write_once":
			writes++
			if f.AttemptID != r.AttemptID {
				return nil, errOriginalGuestStep
			}
		case "read_only":
			reads++
		default:
			return nil, errOriginalGuestStep
		}
	}
	if writes != 1 || reads != 19 {
		return nil, errOriginalGuestStep
	}
	rows := []PG17AssertionResult{pg17MutationResult(7, policy, r.WorkflowID, []string{"actual_twenty_issue_owners_one_grant_one_preregistration", "actual_twenty_redeem_owners_one_write_once_nineteen_read_only", "same_winning_attempt_replay_read_only_settlement_owned"}, capacity.BusinessCreationSHA256(lraw), capacity.BusinessCreationSHA256(draw), capacity.BusinessCreationSHA256(raw))}
	if !q.PositiveCase(originalGuestNativeRealm.Request.NativeCase) {
		return rows, nil
	}
	if r.Settlement.Outcome != "accepted" || r.Settlement.ResourceID != proof.ResourceID {
		return nil, errOriginalGuestStep
	}
	scope, sraw, err := pg17MutationContract(ctx, input.Slot, "settlement-scope-contract.json", `["schema","core_source","slot","grant_id","settlement_sha256","receipt_sha256","wrong_principal_refused","wrong_nonce_refused","paused_original_settlement_accepted","private_fields_absent","foreign_receipt_refused","conflict_refused","receipt_unchanged"]`)
	if err != nil {
		return nil, err
	}
	if !pg17MutationCommon(scope, "original_guest_settlement_scope_contract_v1", input.Slot, grant.GrantID) || pg17MutationDigest(scope, "settlement_sha256") != capacity.GuestRetirementSHA(*r.Settlement) {
		return nil, errOriginalGuestStep
	}
	for _, k := range []string{"wrong_principal_refused", "wrong_nonce_refused", "paused_original_settlement_accepted", "private_fields_absent", "foreign_receipt_refused", "conflict_refused", "receipt_unchanged"} {
		if !pg17MutationEqual(scope, k, true) {
			return nil, errOriginalGuestStep
		}
	}
	receipt, err := store.MutationReceipt(ctx, binding.AdapterPrincipalID, grant.GrantID)
	if err != nil {
		return nil, err
	}
	rw, err := json.Marshal(receipt)
	if err != nil || pg17MutationDigest(scope, "receipt_sha256") != capacity.BusinessCreationSHA256(rw) || receipt.ResourceID != proof.ResourceID || receipt.ActionID != r.Settlement.ActionID || !receipt.TransportCompleted {
		return nil, errOriginalGuestStep
	}
	rows = append(rows, pg17MutationResult(9, policy, r.WorkflowID, []string{"original_nonce_and_principal_refused_exact_authorization", "owning_settlement_disabled_store_copy_not_administrative_pause", "receipt_authorization_privacy_conflict_and_durable_hash_joined"}, capacity.BusinessCreationSHA256(sraw), capacity.BusinessCreationSHA256(rw)))
	before, braw, err := pg17MutationContract(ctx, input.Slot, "native-before-settlement-contract.json", `["schema","core_source","grant_id","slot","original_native_proof_sha256","grant_record_sha256","state","canonical_events","canonical_members","record_unchanged"]`)
	if err != nil {
		return nil, err
	}
	if !pg17MutationCommon(before, "original_guest_native_before_settlement_contract_v1", input.Slot, grant.GrantID) || pg17MutationDigest(before, "original_native_proof_sha256") != capacity.GuestRetirementSHA(proof) || pg17MutationDigest(before, "grant_record_sha256") == "" || !pg17MutationEqual(before, "state", "redeemed") || !pg17MutationEqual(before, "canonical_events", 0) || !pg17MutationEqual(before, "canonical_members", 0) || !pg17MutationEqual(before, "record_unchanged", true) {
		return nil, errOriginalGuestStep
	}
	rows = append(rows, pg17MutationResult(11, policy, r.WorkflowID, []string{"native_proof_before_settlement_refused_unchanged_zero_effects_not_exclusive_order"}, capacity.BusinessCreationSHA256(braw)))
	if q.PositiveCase(originalGuestNativeRealm.Request.NativeCase) {
		unsent, uw, err := pg17MutationContract(ctx, input.Slot, "unsent-terminal-contract.json", `["schema","core_source","slot","grant_id","first_mode","replay_mode","outcome","settlement_sha256","first_return_sha256","repeated_return_sha256","provider_create_called"]`)
		if err != nil {
			return nil, err
		}
		reissue, iw, err := pg17MutationContract(ctx, input.Slot, "unsent-reissue-contract.json", `["schema","core_source","slot","first_grant_id","reissued_grant_id","original_deadline","reissued_deadline"]`)
		if err != nil {
			return nil, err
		}
		var first string
		var oldDeadline, newDeadline time.Time
		if json.Unmarshal(reissue["first_grant_id"], &first) != nil || first == "" || first == grant.GrantID || !pg17MutationCommon(unsent, "original_guest_unsent_terminal_contract_v1", input.Slot, first) || !pg17MutationEqual(unsent, "first_mode", "write_once") || !pg17MutationEqual(unsent, "replay_mode", "read_only") || !pg17MutationEqual(unsent, "outcome", "rejected_before_send") || !pg17MutationEqual(unsent, "provider_create_called", false) || pg17MutationDigest(unsent, "first_return_sha256") == "" || pg17MutationDigest(unsent, "first_return_sha256") != pg17MutationDigest(unsent, "repeated_return_sha256") || !pg17MutationEqual(reissue, "schema", "original_guest_unsent_reissue_contract_v1") || !pg17MutationEqual(reissue, "core_source", capacity.CurrentGuestCoreSource()) || !pg17MutationEqual(reissue, "slot", input.Slot) || !pg17MutationEqual(reissue, "reissued_grant_id", grant.GrantID) || json.Unmarshal(reissue["original_deadline"], &oldDeadline) != nil || json.Unmarshal(reissue["reissued_deadline"], &newDeadline) != nil || oldDeadline.IsZero() || newDeadline.After(oldDeadline) || !newDeadline.Equal(pre.OriginalDeadline) {
			return nil, errOriginalGuestStep
		}
		var old pg17MutationRecord
		var oldRaw []byte
		if err = store.DB.QueryRowContext(ctx, `SELECT grant_record FROM public.capacity_mutation_grants WHERE id=$1 AND namespace=$2 AND generation=$3`, first, policy.Metadata.Namespace, input.Generation).Scan(&oldRaw); err != nil {
			return nil, err
		}
		if json.Unmarshal(oldRaw, &old) != nil || !pg17OriginalUnsentRecordValid(old, policy.ID.String(), r.WorkflowID, pg17MutationDigest(unsent, "settlement_sha256")) {
			return nil, errOriginalGuestStep
		}
		rows = append(rows, pg17MutationResult(8, policy, r.WorkflowID, []string{"actual_unsent_first_write_once_same_attempt_read_only", "same_rejected_before_send_settlement_without_provider_create", "distinct_replacement_grant_nonextended_deadline_same_workflow"}, capacity.BusinessCreationSHA256(uw), capacity.BusinessCreationSHA256(iw), capacity.BusinessCreationSHA256(oldRaw)))
	}
	return rows, nil
}

// Classify the existing settlement without changing it or manufacturing a reply.
func pg17ConfirmSettlementClass(nativeCase string, slot int, settlement *model.CapacityMutationSettleRequest, proof model.CapacityMutationProof) int {
	if settlement == nil {
		return 0
	}
	if settlement.Outcome == "accepted" {
		if settlement.ResourceID == proof.ResourceID {
			return 1
		}
		return 0
	}
	if q.PostlossSourceCase(nativeCase) && slot == q.SourceFailureSlot(nativeCase) && settlement.Outcome == "uncertain" && settlement.TransportCompleted && settlement.ResourceID == "" && settlement.ResourceCreatedAt == "" && settlement.ActionID == "" && len(settlement.NextActionIDs) == 0 && len(settlement.AuxiliaryResources) == 0 && !settlement.AuxiliaryInventoryComplete && settlement.OriginalProviderCreateReturn == nil && settlement.OriginalProviderDestroyReturn == nil {
		return 2
	}
	return 0
}

func guestPG17MutationAfterConfirm(ctx context.Context, store repository.CapacityStore, policy model.Manifest, p model.CapacityPolicySpec, binding model.CapacityMutationBinding, input guestOriginalStepInput, grant model.CapacityMutationGrant, proof, guestProof model.CapacityMutationProof) ([]PG17AssertionResult, error) {
	if originalGuestNativeRealm == nil {
		return nil, errOriginalGuestStep
	}
	r, raw, err := pg17MutationGrant(ctx, store, policy, input, grant)
	if err != nil {
		return nil, err
	}
	if r.Grant.State != "confirmed" || r.Settlement == nil || r.EventProvider == "" || r.EventResource == "" {
		return nil, errOriginalGuestStep
	}
	switch pg17ConfirmSettlementClass(originalGuestNativeRealm.Request.NativeCase, input.Slot, r.Settlement, proof) {
	case 1: // Original accepted settlement must match the confirmed resource.
	case 2: // Exact witness and independent native read remain required.
		if store.VerifyCanonicalPostlossConfirmed(ctx, policy, p, originalGuestNativeRealm.Request.NativeCase, grant, proof) != nil {
			return nil, errOriginalGuestStep
		}
	default:
		return nil, errOriginalGuestStep
	}
	var count int
	var typ, aggregate, resource, provider, resourceKind, instance string
	if err = store.DB.QueryRowContext(ctx, `SELECT count(*) FROM public.event_log WHERE idempotency_key=$1 AND metadata->>'namespace'=$2`, "capacity-mutation/"+grant.GrantID, policy.Metadata.Namespace).Scan(&count); err != nil {
		return nil, err
	}
	if count != 1 {
		return nil, errOriginalGuestStep
	}
	if err = store.DB.QueryRowContext(ctx, `SELECT type,aggregate_type,aggregate_id,payload->>'provider',payload->>'resource',payload->>'instance_id' FROM public.event_log WHERE idempotency_key=$1 AND metadata->>'namespace'=$2`, "capacity-mutation/"+grant.GrantID, policy.Metadata.Namespace).Scan(&typ, &aggregate, &resource, &provider, &resourceKind, &instance); err != nil {
		return nil, err
	}
	if typ != r.EventProvider+"."+r.EventResource+".ensured" || aggregate != r.EventProvider+"_"+r.EventResource || resource != proof.ResourceID || provider != r.EventProvider || resourceKind != r.EventResource || instance != grant.IntegrationInstanceID {
		return nil, errOriginalGuestStep
	}
	apply, aw, err := pg17MutationContract(ctx, input.Slot, "canonical-apply-contract.json", `["schema","core_source","slot","grant_id","resource_id","proof_sha256","canonical_events","registered_members"]`)
	if err != nil {
		return nil, err
	}
	if !pg17MutationCommon(apply, "original_guest_canonical_apply_once_v1", input.Slot, grant.GrantID) || !pg17MutationEqual(apply, "resource_id", proof.ResourceID) || pg17MutationDigest(apply, "proof_sha256") != capacity.GuestRetirementSHA(proof) || !pg17MutationEqual(apply, "canonical_events", 1) || !pg17MutationEqual(apply, "registered_members", 1) {
		return nil, errOriginalGuestStep
	}
	refusal, nw, err := pg17MutationContract(ctx, input.Slot, "native-refusal-contract.json", `["schema","core_source","slot","grant_id","resource_id","original_proof_sha256","refused","canonical_events","canonical_members"]`)
	if err != nil {
		return nil, err
	}
	if !pg17MutationCommon(refusal, "original_guest_native_refusal_contract_v1", input.Slot, grant.GrantID) || !pg17MutationEqual(refusal, "resource_id", proof.ResourceID) || pg17MutationDigest(refusal, "original_proof_sha256") != capacity.GuestRetirementSHA(guestProof) || !pg17MutationEqual(refusal, "canonical_events", 0) || !pg17MutationEqual(refusal, "canonical_members", 0) {
		return nil, errOriginalGuestStep
	}
	var members int
	if err = store.DB.QueryRowContext(ctx, `SELECT count(*) FROM public.capacity_resource_slots WHERE namespace=$1 AND integration_instance_id=$2 AND scope_checksum=$3 AND profile_name=$4 AND slot=$5 AND resource_id=$6`, policy.Metadata.Namespace, grant.IntegrationInstanceID, grant.ScopeChecksum, grant.ProfileName, grant.Slot, proof.ResourceID).Scan(&members); err != nil {
		return nil, err
	}
	if members != 1 {
		return nil, errOriginalGuestStep
	}
	var refused []string
	if json.Unmarshal(refusal["refused"], &refused) != nil {
		return nil, errOriginalGuestStep
	}
	expected := []string{"creation_grant_missing", "creation_grant_foreign", "resource_foreign", "creation_epoch_foreign", "actions_empty", "required_action_missing", "actions_nonterminal", "actions_unsuccessful", "owner_unverified", "spec_unverified", "request_foreign"}
	if len(refused) != len(expected) {
		return nil, errOriginalGuestStep
	}
	seen := map[string]bool{}
	for _, v := range refused {
		if seen[v] {
			return nil, errOriginalGuestStep
		}
		seen[v] = true
	}
	for _, v := range expected {
		if !seen[v] {
			return nil, errOriginalGuestStep
		}
	}
	return []PG17AssertionResult{pg17MutationResult(11, policy, r.WorkflowID, []string{"post_settlement_proof_covariates_refused_without_effects", "confirm_replay_one_event_actual_provider_resource_instance", "one_registered_member_original_transport_settlement_required"}, capacity.BusinessCreationSHA256(raw), capacity.BusinessCreationSHA256(aw), capacity.BusinessCreationSHA256(nw))}, nil
}

func guestPG17MutationAfterTerminal(ctx context.Context, store repository.CapacityStore, policy model.Manifest, p model.CapacityPolicySpec, binding model.CapacityMutationBinding, input guestOriginalStepInput, grant model.CapacityMutationGrant, pre model.CapacityGuestOriginalProvisioningPreregistration, output any) ([]PG17AssertionResult, error) {
	if originalGuestNativeRealm == nil || ctx.Err() != nil {
		return nil, errOriginalGuestStep
	}
	actual, ok := output.(q.SourceTerminalContract)
	if !ok {
		return nil, errOriginalGuestStep
	}
	var retained q.SourceTerminalContract
	wire, err := q.ReadPrivate(ctx, filepath.Join(originalGuestNativeRealm.PrivateDirectory, "source-terminal-contract.json"), &retained)
	if err != nil {
		return nil, err
	}
	if capacity.GuestRetirementSHA(retained) != capacity.GuestRetirementSHA(actual) || retained.CoreSource != capacity.CurrentGuestCoreSource() || retained.Case != originalGuestNativeRealm.Request.NativeCase || retained.PolicyID != policy.ID.String() || retained.GrantID != grant.GrantID || retained.Generation != input.Generation || retained.RecoveryFence <= input.FencingToken || retained.NativeQualified || retained.CheckedAt.Before(retained.LeaseExpiredObservedAt) || retained.LeaseExpiredObservedAt.Before(grant.ExpiresAt) || retained.CheckedAt.After(pre.OriginalDeadline) || retained.OriginalDeadline.After(pre.OriginalDeadline) {
		return nil, errOriginalGuestStep
	}
	r, raw, err := pg17MutationGrant(ctx, store, policy, input, grant)
	if err != nil {
		return nil, err
	}
	var intentRaw []byte
	var intent model.CapacityIntent
	if err = store.DB.QueryRowContext(ctx, `SELECT intent FROM public.capacity_intents WHERE namespace=$1 AND environment=$2 AND domain=$3 AND dimension=$4`, policy.Metadata.Namespace, p.Environment, p.Domain, p.Dimension).Scan(&intentRaw); err != nil {
		return nil, err
	}
	if json.Unmarshal(intentRaw, &intent) != nil || intent.PolicyID != policy.ID || intent.PolicyChecksum != policy.Checksum || intent.Generation != input.Generation || intent.FencingToken != retained.RecoveryFence || !intent.RecoveryOnly || intent.LeaseOwner == input.LeaseOwner || intent.LeaseExecutorID == store.ExecutorID || intent.Decision.ExecutionPermitted {
		return nil, errOriginalGuestStep
	}
	var physical model.CapacityMutationProof
	pw, err := q.ReadPrivate(ctx, filepath.Join(originalGuestNativeRealm.PrivateDirectory, "source-terminal-physical-proof.json"), &physical)
	if err != nil {
		return nil, err
	}
	if capacity.GuestRetirementSHA(physical) != retained.PhysicalSHA256 || physical.ResourceID == "" || physical.Slot != 1 {
		return nil, errOriginalGuestStep
	}
	pins := []string{capacity.BusinessCreationSHA256(wire), capacity.BusinessCreationSHA256(raw), capacity.BusinessCreationSHA256(intentRaw), capacity.BusinessCreationSHA256(pw)}
	if retained.Case == "source_live_unredeemed_abort" {
		current, err := repository.GetManifestByID(ctx, store.DB, policy.ID)
		if err != nil {
			return nil, err
		}
		if current.Metadata.Active || current.Checksum != policy.Checksum || r.Grant.State != "expired" || r.AttemptID != "" || r.Settlement != nil || retained.GrantState != "expired" || retained.Terminal != "aborted" || retained.TerminalRefused {
			return nil, errOriginalGuestStep
		}
		noFence, nw, err := pg17MutationContract(ctx, 0, "pg17-no-native-fence-reconcile.json", `["schema","core_source","grant_id","generation","fence","no_private_native_store","same_context","execution_enabled","outcome","proof_sha256","recovered_intent_sha256","result_sha256"]`)
		if err != nil {
			return nil, err
		}
		if !pg17MutationEqual(noFence, "schema", "core_pg17_no_native_fence_reconcile_v1") || !pg17MutationEqual(noFence, "core_source", capacity.CurrentGuestCoreSource()) || !pg17MutationEqual(noFence, "grant_id", grant.GrantID) || !pg17MutationEqual(noFence, "generation", input.Generation) || !pg17MutationEqual(noFence, "fence", retained.RecoveryFence) || !pg17MutationEqual(noFence, "no_private_native_store", true) || !pg17MutationEqual(noFence, "same_context", true) || !pg17MutationEqual(noFence, "execution_enabled", false) || !pg17MutationEqual(noFence, "outcome", "aborted") || pg17MutationDigest(noFence, "proof_sha256") != retained.ProofSHA256 || pg17MutationDigest(noFence, "recovered_intent_sha256") == "" || pg17MutationDigest(noFence, "result_sha256") == "" {
			return nil, errOriginalGuestStep
		}
		pins = append(pins, capacity.BusinessCreationSHA256(nw))
		return []PG17AssertionResult{pg17MutationResult(6, policy, r.WorkflowID, []string{"actual_persisted_policy_inactive_readback", "actual_grant_and_lease_expiry_without_edits_new_recovery_fence", "unredeemed_grant_expired_without_attempt_or_settlement_aborted", "ordinary_reconcile_without_private_native_store_same_context_lease_db_deadline"}, pins...)}, nil
	}
	if retained.Case != "source_live_unresolved_terminal" || r.Grant.State != "redeemed" || r.AttemptID == "" || r.Settlement != nil || retained.GrantState != "redeemed" || !retained.TerminalRefused {
		return nil, errOriginalGuestStep
	}
	var replay model.CapacityMutationRedeemResponse
	rw, err := q.ReadPrivate(ctx, filepath.Join(originalGuestNativeRealm.PrivateDirectory, "source-terminal-replay-typed-return.json"), &replay)
	if err != nil {
		return nil, err
	}
	if capacity.BusinessCreationSHA256(rw) != retained.ReplaySHA256 || replay.Mode != "read_only" || replay.GrantID != grant.GrantID || replay.AttemptID != r.AttemptID || replay.RequestSHA256 != grant.RequestSHA256 {
		return nil, errOriginalGuestStep
	}
	advance, adw, err := pg17MutationContract(ctx, 0, "pg17-unresolved-advance-contract.json", `["schema","core_source","grant_id","slot","prepared","canary","promoted_refused","predicate","native_baseline_units","negative_request_units","negative_is_physical_evidence","probe_sha256","canary_sha256","grant_sha256","refusal_sha256"]`)
	if err != nil {
		return nil, err
	}
	if !pg17MutationCommon(advance, "core_pg17_unresolved_advance_v1", 2, grant.GrantID) || !pg17MutationEqual(advance, "prepared", true) || !pg17MutationEqual(advance, "canary", true) || !pg17MutationEqual(advance, "promoted_refused", true) || !pg17MutationEqual(advance, "predicate", "unresolved_provider_mutation_authority") || !pg17MutationEqual(advance, "native_baseline_units", 1) || !pg17MutationEqual(advance, "negative_request_units", 2) || !pg17MutationEqual(advance, "negative_is_physical_evidence", false) || pg17MutationDigest(advance, "grant_sha256") != capacity.BusinessCreationSHA256(raw) || pg17MutationDigest(advance, "probe_sha256") == "" || pg17MutationDigest(advance, "canary_sha256") == "" || pg17MutationDigest(advance, "refusal_sha256") == "" {
		return nil, errOriginalGuestStep
	}
	pins = append(pins, capacity.BusinessCreationSHA256(rw), capacity.BusinessCreationSHA256(adw))
	return []PG17AssertionResult{pg17MutationResult(10, policy, r.WorkflowID, []string{"unresolved_same_grant_issue_retains_permission_before_expiry", "actual_expiry_preserves_redeemed_same_attempt_read_only_without_settlement", "actual_advance_prepared_canary_baseline_one_promoted_negative_exact_unresolved_rollback", "target_two_refused_request_not_physical_evidence_recovery_refusal_retained"}, pins...)}, nil
}

func guestPG17MutationAfterHistorical(ctx context.Context, store repository.CapacityStore, policy model.Manifest, p model.CapacityPolicySpec, binding model.CapacityMutationBinding, input guestOriginalStepInput, grant model.CapacityMutationGrant, pre model.CapacityGuestOriginalProvisioningPreregistration, output any) ([]PG17AssertionResult, error) {
	if originalGuestNativeRealm == nil || ctx.Err() != nil {
		return nil, errOriginalGuestStep
	}
	actual, ok := output.(q.SourceHistoricalConfirmContract)
	if !ok {
		return nil, errOriginalGuestStep
	}
	var retained q.SourceHistoricalConfirmContract
	wire, err := q.ReadPrivate(ctx, filepath.Join(originalGuestNativeRealm.PrivateDirectory, "source-historical-confirm-contract.json"), &retained)
	if err != nil {
		return nil, err
	}
	if capacity.GuestRetirementSHA(retained) != capacity.GuestRetirementSHA(actual) || retained.CoreSource != capacity.CurrentGuestCoreSource() || retained.PolicyID != policy.ID.String() || retained.GrantID != grant.GrantID || retained.PreregistrationID != pre.PreregistrationID || retained.Generation != input.Generation || retained.RecoveryFence <= input.FencingToken || retained.PauseRows != 1 || retained.PolicyActiveAfter || retained.RecoveryExecutionEnabled || retained.NativeQualified || retained.StateAfter != "confirmed" || retained.CanonicalEvents != 1 || !retained.OldObservationRefused || retained.CheckedAt.Before(retained.LeaseExpiredObservedAt) || retained.CheckedAt.After(pre.OriginalDeadline) {
		return nil, errOriginalGuestStep
	}
	current, err := repository.GetManifestByID(ctx, store.DB, policy.ID)
	if err != nil {
		return nil, err
	}
	if current.Metadata.Active || current.Checksum != policy.Checksum {
		return nil, errOriginalGuestStep
	}
	r, raw, err := pg17MutationGrant(ctx, store, policy, input, grant)
	if err != nil {
		return nil, err
	}
	if r.Grant.State != "confirmed" || r.Settlement == nil || r.Settlement.Outcome != "accepted" || !r.Settlement.TransportCompleted {
		return nil, errOriginalGuestStep
	}
	receipt, err := store.MutationReceipt(ctx, binding.AdapterPrincipalID, grant.GrantID)
	if err != nil {
		return nil, err
	}
	rw, err := json.Marshal(receipt)
	if err != nil || capacity.BusinessCreationSHA256(rw) != retained.ConfirmedReceiptSHA256 || receipt.Grant.State != "confirmed" || receipt.ResourceID != r.Settlement.ResourceID {
		return nil, errOriginalGuestStep
	}
	for _, sha := range []string{retained.OriginalProofSHA256, retained.FreshPhysicalSHA256, retained.FreshConfirmSHA256, retained.OriginalReceiptSHA256, retained.DiagnosticSHA256} {
		if !capacity.ValidDigest(sha) {
			return nil, errOriginalGuestStep
		}
	}
	var count int
	if err = store.DB.QueryRowContext(ctx, `SELECT count(*) FROM public.event_log WHERE idempotency_key=$1 AND metadata->>'namespace'=$2`, "capacity-mutation/"+grant.GrantID, policy.Metadata.Namespace).Scan(&count); err != nil {
		return nil, err
	}
	if count != 1 {
		return nil, errOriginalGuestStep
	}
	return []PG17AssertionResult{pg17MutationResult(12, policy, r.WorkflowID, []string{"actual_settled_parent_preserved_across_policy_pause", "actual_lease_expiry_new_recovery_owner_fence_execution_disabled", "old_observation_refused_fresh_membership_same_grant_action_lineage", "actual_historical_confirm_replay_one_canonical_event"}, capacity.BusinessCreationSHA256(wire), capacity.BusinessCreationSHA256(raw), capacity.BusinessCreationSHA256(rw))}, nil
}

// Called immediately after slot2's real TerminalRedeem/same-grant Issue,
// BEFORE the existing actual lease-expiry wait. Baseline1 is real; the only
// units2 value below is an explicitly refused promotion request covariate.
// It is never published as physical membership or accepted proof.
func guestPG17MutationUnresolvedAdvance(ctx context.Context, store repository.CapacityStore, policy model.Manifest, p model.CapacityPolicySpec, binding model.CapacityMutationBinding, input guestOriginalStepInput, grant model.CapacityMutationGrant, key ed25519.PrivateKey) error {
	if originalGuestNativeRealm == nil || originalGuestNativeRealm.Request.NativeCase != "source_live_unresolved_terminal" || input.Slot != 2 || ctx.Err() != nil {
		return errOriginalGuestStep
	}
	r, raw, err := pg17MutationGrant(ctx, store, policy, input, grant)
	if err != nil {
		return err
	}
	if r.Grant.State != "redeemed" || r.AttemptID == "" || r.Settlement != nil {
		return errOriginalGuestStep
	}
	readIntent := func() ([]byte, model.CapacityIntent, error) {
		var wire []byte
		var value model.CapacityIntent
		err := store.DB.QueryRowContext(ctx, `SELECT intent FROM public.capacity_intents WHERE namespace=$1 AND environment=$2 AND domain=$3 AND dimension=$4`, policy.Metadata.Namespace, p.Environment, p.Domain, p.Dimension).Scan(&wire)
		if err != nil {
			return nil, value, err
		}
		if json.Unmarshal(wire, &value) != nil {
			return nil, value, errOriginalGuestStep
		}
		return wire, value, nil
	}
	_, before, err := readIntent()
	if err != nil {
		return err
	}
	if before.Phase != "preparing" || before.RecoveryOnly || before.Generation != input.Generation || before.FencingToken != input.FencingToken || before.LeaseOwner != input.LeaseOwner || before.LeaseExecutorID != store.ExecutorID || before.LeaseExpiresAt == nil || !before.LeaseExpiresAt.After(time.Now().UTC()) || before.BaselineSnapshot.Units != 1 || before.Decision.Units != 2 {
		return errOriginalGuestStep
	}
	probe, err := sourceNativeBaseline(ctx, store, policy, p, input, key)
	if err != nil {
		return err
	}
	zero := 0
	proof := model.CapacityTransitionProof{Assessment: q.QualificationAssessment(p, 1, 0.1, probe.OriginalNativeAfterReturnedAt), ObservedAt: probe.OriginalNativeAfterReturnedAt, ReceiptRef: "original-pg17-unresolved-advance:" + capacity.GuestRetirementSHA(probe), Healthy: true, Inflight: &zero}
	// This is the same Source qualification baseline/echo used by the existing
	// producer, never a caller-created healthy provider or new profile.
	for _, phase := range []string{"prepared", "canary"} {
		result, err := store.Advance(ctx, policy, input.Generation, input.FencingToken, input.LeaseOwner, phase, proof)
		if err != nil {
			return err
		}
		if result.Phase != phase || result.Generation != input.Generation || result.FencingToken != input.FencingToken || result.LeaseOwner != input.LeaseOwner || result.RecoveryOnly {
			return errOriginalGuestStep
		}
	}
	canaryRaw, canary, err := readIntent()
	if err != nil {
		return err
	}
	if canary.Phase != "canary" || canary.Decision.Units != 2 {
		return errOriginalGuestStep
	}
	negative := proof
	negative.Assessment.Snapshot.Units = canary.Decision.Units
	_, refused := store.Advance(ctx, policy, input.Generation, input.FencingToken, input.LeaseOwner, "promoted", negative)
	expected := repository.ErrCapacityConflict.Error() + ": unresolved provider mutation authority"
	if !errors.Is(refused, repository.ErrCapacityConflict) || refused.Error() != expected {
		return errOriginalGuestStep
	}
	afterRaw, after, err := readIntent()
	if err != nil {
		return err
	}
	if !bytes.Equal(canaryRaw, afterRaw) || after.Phase != "canary" {
		return errOriginalGuestStep
	}
	_, grantAfter, err := pg17MutationGrant(ctx, store, policy, input, grant)
	if err != nil {
		return err
	}
	if !bytes.Equal(raw, grantAfter) {
		return errOriginalGuestStep
	}
	contract := struct {
		Schema                     string `json:"schema"`
		CoreSource                 string `json:"core_source"`
		GrantID                    string `json:"grant_id"`
		Slot                       int    `json:"slot"`
		Prepared                   bool   `json:"prepared"`
		Canary                     bool   `json:"canary"`
		PromotedRefused            bool   `json:"promoted_refused"`
		Predicate                  string `json:"predicate"`
		NativeBaselineUnits        int    `json:"native_baseline_units"`
		NegativeRequestUnits       int    `json:"negative_request_units"`
		NegativeIsPhysicalEvidence bool   `json:"negative_is_physical_evidence"`
		ProbeSHA256                string `json:"probe_sha256"`
		CanarySHA256               string `json:"canary_sha256"`
		GrantSHA256                string `json:"grant_sha256"`
		RefusalSHA256              string `json:"refusal_sha256"`
	}{"core_pg17_unresolved_advance_v1", capacity.CurrentGuestCoreSource(), grant.GrantID, 2, true, true, true, "unresolved_provider_mutation_authority", 1, 2, false, capacity.GuestRetirementSHA(probe), capacity.BusinessCreationSHA256(canaryRaw), capacity.BusinessCreationSHA256(raw), capacity.BusinessCreationSHA256([]byte(refused.Error()))}
	_, err = q.Publish(ctx, filepath.Join(originalGuestNativeRealm.PrivateDirectory, "pg17-unresolved-advance-contract.json"), contract)
	return err
}

// SAME original context, cancellation and deadline. No context values are
// removed or created. The new ordinary store carries the ACTUAL recovered SQL
// owner; absence of private native pointers is established by construction.
// All original Reconcile/manifest/SQL/lease guards execute unchanged.
func guestPG17MutationTerminalReconcile(ctx context.Context, recovery repository.CapacityStore, policy model.Manifest, generation, fence int64, owner, outcome string, proof model.CapacityTransitionProof, grant model.CapacityMutationGrant, pre model.CapacityGuestOriginalProvisioningPreregistration) (model.CapacityIntent, error) {
	if originalGuestNativeRealm == nil {
		return model.CapacityIntent{}, errOriginalGuestStep
	}
	if originalGuestNativeRealm.Request.NativeCase != "source_live_unredeemed_abort" {
		return recovery.Reconcile(ctx, policy, generation, fence, owner, outcome, proof)
	}
	var p model.CapacityPolicySpec
	if json.Unmarshal(policy.Spec, &p) != nil || ctx.Err() != nil || outcome != "aborted" || recovery.ExecutionEnabled || generation != pre.Generation || fence <= pre.Fence || owner == "" || owner == pre.LeaseOwner || recovery.ExecutorID == "" || recovery.ExecutorID == pre.ExecutorID || !proof.NoMutationVerified || proof.ProviderFencingToken != 0 || proof.MutationAuthorityKind != "core_mutation_grants" || proof.MutationInflight == nil || *proof.MutationInflight != 0 {
		return model.CapacityIntent{}, errOriginalGuestStep
	}
	deadline, ok := ctx.Deadline()
	if !ok || deadline.After(pre.OriginalDeadline) || !time.Now().UTC().Before(deadline) {
		return model.CapacityIntent{}, errOriginalGuestStep
	}
	var raw []byte
	var current model.CapacityIntent
	var now time.Time
	if err := recovery.DB.QueryRowContext(ctx, `SELECT intent,clock_timestamp() FROM public.capacity_intents WHERE namespace=$1 AND environment=$2 AND domain=$3 AND dimension=$4`, policy.Metadata.Namespace, p.Environment, p.Domain, p.Dimension).Scan(&raw, &now); err != nil {
		return model.CapacityIntent{}, err
	}
	if json.Unmarshal(raw, &current) != nil || !current.RecoveryOnly || current.PolicyID != policy.ID || current.PolicyChecksum != policy.Checksum || current.Generation != generation || current.FencingToken != fence || current.LeaseOwner != owner || current.LeaseExecutorID != recovery.ExecutorID || current.Decision.ExecutionPermitted || current.LeaseExpiresAt == nil || !current.LeaseExpiresAt.After(now) || now.Before(grant.ExpiresAt) {
		return model.CapacityIntent{}, errOriginalGuestStep
	}
	var grantRaw []byte
	var record pg17MutationRecord
	if err := recovery.DB.QueryRowContext(ctx, `SELECT grant_record FROM public.capacity_mutation_grants WHERE id=$1 AND namespace=$2 AND generation=$3`, grant.GrantID, policy.Metadata.Namespace, generation).Scan(&grantRaw); err != nil {
		return model.CapacityIntent{}, err
	}
	if json.Unmarshal(grantRaw, &record) != nil || record.Grant.GrantID != grant.GrantID || record.PolicyID != policy.ID.String() || record.WorkflowID != recovery.WorkflowID.String() || record.Grant.State != "issued" || record.AttemptID != "" || record.Settlement != nil {
		return model.CapacityIntent{}, errOriginalGuestStep
	}
	ordinary := repository.CapacityStore{DB: recovery.DB, WorkflowID: recovery.WorkflowID, ExecutorID: recovery.ExecutorID, ExecutionEnabled: false, AdmissionOnly: recovery.AdmissionOnly}
	result, err := ordinary.Reconcile(ctx, policy, generation, fence, owner, outcome, proof)
	if err != nil {
		return model.CapacityIntent{}, err
	}
	if result.Phase != "aborted" || result.Decision.ExecutionPermitted {
		return model.CapacityIntent{}, errOriginalGuestStep
	}
	contract := struct {
		Schema                string `json:"schema"`
		CoreSource            string `json:"core_source"`
		GrantID               string `json:"grant_id"`
		Generation            int64  `json:"generation"`
		Fence                 int64  `json:"fence"`
		NoPrivateNativeStore  bool   `json:"no_private_native_store"`
		SameContext           bool   `json:"same_context"`
		ExecutionEnabled      bool   `json:"execution_enabled"`
		Outcome               string `json:"outcome"`
		ProofSHA256           string `json:"proof_sha256"`
		RecoveredIntentSHA256 string `json:"recovered_intent_sha256"`
		ResultSHA256          string `json:"result_sha256"`
	}{"core_pg17_no_native_fence_reconcile_v1", capacity.CurrentGuestCoreSource(), grant.GrantID, generation, fence, true, true, false, result.Phase, capacity.GuestRetirementSHA(proof), capacity.BusinessCreationSHA256(raw), capacity.GuestRetirementSHA(result)}
	_, err = q.Publish(ctx, filepath.Join(originalGuestNativeRealm.PrivateDirectory, "pg17-no-native-fence-reconcile.json"), contract)
	return result, err
}
