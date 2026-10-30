//go:build linux && nativequalification

package message

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacitynativeqemu"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	amqp "github.com/rabbitmq/amqp091-go"
)

// AssertPG17SourceFence reads the SAME disposable Source namespace after the
// original revoked-authority caller returned. It performs no authority mutation,
// expiry substitution, executor recovery or physical operation.
func AssertPG17SourceFence(ctx context.Context, store repository.CapacityStore, policy model.Manifest, fact capacitynativeqemu.SourceFenceContract) (PG17AssertionResult, error) {
	out := PG17AssertionResult{}
	if originalGuestNativeRealm == nil || store.DB == nil || ctx.Err() != nil {
		return out, errOriginalGuestStep
	}
	if fact.Case == "source_contract_executor_fence" {
		return assertPG17OriginalExecutorFence(ctx, store, policy, fact)
	}
	id, kind := policy.ID.String(), "capacity_policy"
	row := 15
	switch fact.Case {
	case "source_contract_policy_fence":
	case "source_contract_instance_fence":
		row, kind = 16, "integration_instance"
	case "source_contract_type_fence":
		row, kind = 17, "integration_type"
	default:
		return out, errOriginalGuestStep
	}
	deadline, ok := ctx.Deadline()
	if !ok || deadline.After(fact.OriginalDeadline) || fact.CheckedAt.IsZero() || !fact.CheckedAt.Before(fact.OriginalDeadline) || !time.Now().Before(fact.OriginalDeadline) || fact.Schema != "core_original_source_fence_contract_v1" || fact.Scope != "SOURCE_CONTRACT_ONLY_NO_NATIVE_AUTHORITY" || fact.CoreSource != capacity.CurrentGuestCoreSource() || fact.GuestSource != originalGuestNativeRealm.Request.SourceCommit || fact.Namespace != policy.Metadata.Namespace || fact.PolicyID != policy.ID.String() || fact.WorkflowID != store.WorkflowID.String() || fact.Slot != 1 || fact.Generation < 1 || fact.FenceBefore < 1 || fact.FenceBefore != fact.FenceAfter || fact.NativeQualified || fact.RecoveryOnly || fact.ExecutorChanged || fact.LeaseOwnerChanged || fact.OriginalGrantExpired || fact.OldIssueRefused || fact.RevokedKind != kind || fact.RevocationRows != 1 || fact.RevokedActiveAfter || fact.RepositoryRedeemResult != "revoked_scope_refused" || fact.GrantTransition != "byte_exact_unchanged" || fact.GrantBeforeSHA256 == "" || fact.GrantBeforeSHA256 != fact.GrantAfterSHA256 {
		return out, errOriginalGuestStep
	}
	var raw, preRaw []byte
	if err := store.DB.QueryRowContext(ctx, `SELECT grant_record FROM public.capacity_mutation_grants WHERE id=$1 AND namespace=$2`, fact.GrantID, policy.Metadata.Namespace).Scan(&raw); err != nil {
		return out, err
	}
	var record struct {
		Grant      model.CapacityMutationGrant `json:"grant"`
		ExecutorID string                      `json:"executor_id"`
	}
	if json.Unmarshal(raw, &record) != nil || record.Grant.GrantID != fact.GrantID || record.Grant.Slot != 1 || record.Grant.State != "issued" || record.ExecutorID == "" || !record.Grant.ExpiresAt.After(time.Now().UTC()) || capacity.BusinessCreationSHA256(raw) != fact.GrantAfterSHA256 {
		return out, errOriginalGuestStep
	}
	if row == 16 {
		id = record.Grant.IntegrationInstanceID
	}
	if row == 17 {
		var spec model.CapacityPolicySpec
		if json.Unmarshal(policy.Spec, &spec) != nil {
			return out, errOriginalGuestStep
		}
		binding, err := capacity.VMObservationBinding(spec, record.Grant.BindingName)
		if err != nil {
			return out, err
		}
		id = binding.IntegrationTypeID
	}
	var storedID, storedKind, namespace string
	var active bool
	if err := store.DB.QueryRowContext(ctx, `SELECT id::text,kind,namespace,active FROM public.manifests WHERE id=$1`, id).Scan(&storedID, &storedKind, &namespace, &active); err != nil {
		return out, err
	}
	if storedID != fact.RevokedID || storedKind != kind || namespace != policy.Metadata.Namespace || active {
		return out, errOriginalGuestStep
	}
	if err := store.DB.QueryRowContext(ctx, `SELECT preregistration_record FROM public.capacity_vm_provisioning_preregistrations WHERE id=$1 AND create_grant_id=$2`, fact.PreregistrationID, fact.GrantID).Scan(&preRaw); err != nil {
		return out, err
	}
	var pre model.CapacityGuestOriginalProvisioningPreregistration
	if json.Unmarshal(preRaw, &pre) != nil || pre.PreregistrationID != fact.PreregistrationID || pre.OriginalCreateGrantID != fact.GrantID || pre.PolicyID != policy.ID.String() || pre.WorkflowID != store.WorkflowID.String() || pre.ExecutorID != record.ExecutorID || pre.Generation != fact.Generation || pre.Fence != fact.FenceBefore || pre.Slot != 1 || pre.CoreSourceCommit != fact.CoreSource || fact.OriginalDeadline.After(pre.OriginalDeadline) {
		return out, errOriginalGuestStep
	}
	var witnesses, returns, members int
	if err := store.DB.QueryRowContext(ctx, `SELECT (SELECT count(*) FROM public.capacity_guest_original_create_witnesses WHERE preregistration_id=$1),(SELECT count(*) FROM public.capacity_guest_qualification_native_source_returns WHERE preregistration_id=$1),(SELECT count(*) FROM public.capacity_resource_slots WHERE namespace=$2)`, fact.PreregistrationID, policy.Metadata.Namespace).Scan(&witnesses, &returns, &members); err != nil {
		return out, err
	}
	h := fact.HTTP
	if witnesses != 0 || returns != 0 || members != 0 || h.BodyBytes <= 0 || h.BodyBytes >= 2<<20 || h.BodySHA256 == "" || h.StartedAt.IsZero() || h.DoReturnedAt.Before(h.StartedAt) || h.ReadReturnedAt.Before(h.DoReturnedAt) || h.CloseReturnedAt.Before(h.ReadReturnedAt) || h.CloseReturnedAt.After(fact.CheckedAt) || !((h.Status == 403 && h.ProblemCode == "capacity.mutation_scope_denied") || (h.Status == 409 && h.ProblemCode == "capacity.mutation_conflict")) || ctx.Err() != nil {
		return out, errOriginalGuestStep
	}
	out = PG17AssertionResult{Schema: "core_pg17_assertion_v1", CaseID: row, OriginalTest: "TestCapacityMutationPostgres/policy_instance_type_and_executor_fences/" + map[int]string{15: "policy", 16: "instance", 17: "type"}[row], SourceCase: fact.Case, CoreSource: fact.CoreSource, PolicyID: fact.PolicyID, WorkflowID: fact.WorkflowID, Checks: []string{"actual_exact_manifest_inactive", "one_original_revocation", "unexpired_issued_grant_byte_unchanged", "original_preregistration_owner_join", "repository_refused", "authenticated_http_refused_complete_returns", "zero_source_witness_native_returns_members"}, EvidenceSHA256: []string{fact.GrantAfterSHA256, capacity.BusinessCreationSHA256(preRaw), capacity.GuestRetirementSHA(fact)}, NativeQualified: false}
	return out, nil
}

// AssertPG17NativeWorkflow invokes the original fixed native handler twice using
// the owning engine's existing invocation context, workflow reference and resolved
// input. No executor/lease/assessment is installed here. Integrate BEFORE the
// first canonical Confirm, only for the actual positive slot2 after settlement.
func AssertPG17NativeWorkflow(ctx context.Context, conn *amqp.Connection, store repository.CapacityStore, policy model.Manifest, workflow model.ManifestReference, step model.WorkflowRunStepResult, input map[string]any, guestInput guestOriginalStepInput, binding model.CapacityMutationBinding, grant model.CapacityMutationGrant, guestProof model.CapacityMutationProof) (PG17AssertionResult, model.CapacityMutationProof, error) {
	out := PG17AssertionResult{}
	executor, _ := ctx.Value(capacityInvocationKey{}).(string)
	if originalGuestNativeRealm == nil || originalGuestNativeRealm.Request.NativeCase != "positive_original_lifecycle" || executor == "" || executor != store.ExecutorID || ctx.Err() != nil || store.DB == nil || step.Operation != "capacity.confirm_native_mutation" || grant.Slot != 2 || input["grant_id"] != grant.GrantID {
		return out, model.CapacityMutationProof{}, pg17ConfirmFailure("check-01")
	}
	count := func() (int, int, error) {
		var events, members int
		err := store.DB.QueryRowContext(ctx, `SELECT (SELECT count(*) FROM public.event_log WHERE idempotency_key=$1 AND metadata->>'namespace'=$2),(SELECT count(*) FROM public.capacity_resource_slots WHERE namespace=$2)`, "capacity-mutation/"+grant.GrantID, policy.Metadata.Namespace).Scan(&events, &members)
		return events, members, err
	}
	events, members, err := count()
	if err != nil {
		return out, model.CapacityMutationProof{}, err
	}
	if events != 0 || members != 1 {
		return out, model.CapacityMutationProof{}, pg17ConfirmFailure("check-02")
	}
	first := executeCapacityNativeWorkflowStep(ctx, conn, store.DB, workflow, step, input)
	if first.Status != "succeeded" || first.Metadata["useful_capacity_known"] != false {
		return out, model.CapacityMutationProof{}, pg17NativeResultFailure(first)
	}
	events, members, err = count()
	if err != nil {
		return out, model.CapacityMutationProof{}, err
	}
	if events != 1 || members != 2 {
		return out, model.CapacityMutationProof{}, pg17ConfirmFailure("check-04")
	}
	replay := executeCapacityNativeWorkflowStep(ctx, conn, store.DB, workflow, step, input)
	if replay.Status != "succeeded" || replay.Metadata["useful_capacity_known"] != false {
		return out, model.CapacityMutationProof{}, pg17ConfirmFailure("check-05")
	}
	events, members, err = count()
	if err != nil {
		return out, model.CapacityMutationProof{}, err
	}
	if events != 1 || members != 2 || ctx.Err() != nil {
		return out, model.CapacityMutationProof{}, pg17ConfirmFailure("check-06")
	}
	// Full typed handler returns remain private originals. The public assertion
	// exports only their body hashes, not a replacement success boolean.
	privateSlot := capacitynativeqemu.SlotDirectory(originalGuestNativeRealm.PrivateDirectory, grant.Slot)
	firstWire, err := capacitynativeqemu.Publish(ctx, filepath.Join(privateSlot, "pg17-native-workflow-first.json"), first)
	if err != nil {
		return out, model.CapacityMutationProof{}, err
	}
	replayWire, err := capacitynativeqemu.Publish(ctx, filepath.Join(privateSlot, "pg17-native-workflow-replay.json"), replay)
	if err != nil {
		return out, model.CapacityMutationProof{}, err
	}
	// Join both independently returned native reads to the separately retained
	// Guest enrollment read before replaying the exact proof already committed.
	var firstResult, replayResult pg17NativeProofReturn
	firstJSON, firstErr := json.Marshal(first.Metadata)
	replayJSON, replayErr := json.Marshal(replay.Metadata)
	if firstErr != nil || replayErr != nil || json.Unmarshal(firstJSON, &firstResult) != nil || json.Unmarshal(replayJSON, &replayResult) != nil || pg17JoinNativeProofs(binding, grant, guestProof, firstResult, replayResult, "core-native:"+workflow.ID.String()+":"+binding.IntegrationInstanceID+":capacity.confirm_native_mutation") != nil {
		return out, model.CapacityMutationProof{}, pg17ConfirmFailure("proof-join")
	}
	// Confirming a different Guest receipt after the handler committed must
	// remain a conflict. The write attempt is the real repository operation;
	// database reads only demonstrate that the rejected attempt changed nothing.
	var beforeConflict, afterConflict []byte
	if err := store.DB.QueryRowContext(ctx, `SELECT grant_record FROM public.capacity_mutation_grants WHERE id=$1 AND namespace=$2`, grant.GrantID, policy.Metadata.Namespace).Scan(&beforeConflict); err != nil {
		return out, model.CapacityMutationProof{}, err
	}
	_, conflictErr := store.ConfirmMutation(ctx, policy, guestInput.Generation, guestInput.FencingToken, guestInput.LeaseOwner, guestProof)
	if !errors.Is(conflictErr, repository.ErrCapacityConflict) || ctx.Err() != nil {
		return out, model.CapacityMutationProof{}, pg17ConfirmFailure("guest-conflict")
	}
	if err := store.DB.QueryRowContext(ctx, `SELECT grant_record FROM public.capacity_mutation_grants WHERE id=$1 AND namespace=$2`, grant.GrantID, policy.Metadata.Namespace).Scan(&afterConflict); err != nil {
		return out, model.CapacityMutationProof{}, err
	}
	events, members, err = count()
	if err != nil || !bytes.Equal(beforeConflict, afterConflict) || events != 1 || members != 2 || ctx.Err() != nil {
		return out, model.CapacityMutationProof{}, pg17ConfirmFailure("guest-conflict")
	}
	// Slot 1 completed the normal Guest path: its exact refreshed Guest proof
	// was confirmed and retried by guestOriginalSourceAssertApply. Join the
	// retained apply contract to its independent enrollment lineage explicitly.
	var slotOne capacitynativeqemu.EnrollmentConfirmProofLineage
	slotOnePath := filepath.Join(capacitynativeqemu.SlotDirectory(originalGuestNativeRealm.PrivateDirectory, 1), "enrollment-confirm-proof-lineage.json")
	lineageWire, err := capacitynativeqemu.ReadPrivate(ctx, slotOnePath, &slotOne)
	if err != nil {
		return out, model.CapacityMutationProof{}, err
	}
	apply, applyWire, err := pg17MutationContract(ctx, 1, "canonical-apply-contract.json", `["schema","core_source","slot","grant_id","resource_id","proof_sha256","canonical_events","registered_members"]`)
	if err != nil || slotOne.Schema != "core_original_enrollment_confirm_proof_lineage_v1" || slotOne.CoreSource != capacity.CurrentGuestCoreSource() || slotOne.Slot != 1 || slotOne.GrantID == "" || slotOne.GrantID == grant.GrantID || slotOne.ConfirmationProof.GrantID != slotOne.GrantID || slotOne.ConfirmationProof.Slot != 1 || slotOne.ConfirmationProofSHA256 != capacity.GuestRetirementSHA(slotOne.ConfirmationProof) || !pg17MutationCommon(apply, "original_guest_canonical_apply_once_v1", 1, slotOne.GrantID) || !pg17MutationEqual(apply, "resource_id", slotOne.ConfirmationProof.ResourceID) || pg17MutationDigest(apply, "proof_sha256") != slotOne.ConfirmationProofSHA256 || !pg17MutationEqual(apply, "canonical_events", 1) || !pg17MutationEqual(apply, "registered_members", 1) {
		return out, model.CapacityMutationProof{}, pg17ConfirmFailure("guest-slot-one")
	}
	// Publish only hashes of the actual handler returns, never private input.
	out = PG17AssertionResult{Schema: "core_pg17_assertion_v1", CaseID: 19, OriginalTest: "TestCapacityMutationNativeWorkflowPostgres/native_reads_confirm_once_without_readiness_claim", SourceCase: originalGuestNativeRealm.Request.NativeCase, CoreSource: capacity.CurrentGuestCoreSource(), PolicyID: policy.ID.String(), WorkflowID: store.WorkflowID.String(), Checks: []string{"original_fixed_native_handler_twice", "owning_invocation_context_preserved", "registered_1_to_2_then_2", "canonical_event_0_to_1_then_1", "useful_capacity_known_false_both", "guest_and_both_native_returns_exact_identity_action_profile_join", "slot_one_guest_proof_first_confirm_and_idempotent_retry", "slot_two_different_guest_proof_rejected_without_changes"}, EvidenceSHA256: []string{capacity.BusinessCreationSHA256(firstWire), capacity.BusinessCreationSHA256(replayWire), capacity.GuestRetirementSHA(guestProof), capacity.BusinessCreationSHA256(lineageWire), capacity.BusinessCreationSHA256(applyWire), capacity.BusinessCreationSHA256(beforeConflict), capacity.BusinessCreationSHA256(afterConflict)}, NativeQualified: false}
	return out, firstResult.Proof, nil
}

// AssertPG17HTTPReturns consumes only the original Source-owned closed contract
// and all five complete original HTTP bodies. It runs immediately after Create,
// BEFORE first canonical Confirm, so the current grant must still be settled.
func AssertPG17HTTPReturns(ctx context.Context, store repository.CapacityStore, policy model.Manifest, grant model.CapacityMutationGrant, pre model.CapacityGuestOriginalProvisioningPreregistration) (PG17AssertionResult, error) {
	out := PG17AssertionResult{}
	if originalGuestNativeRealm == nil || originalGuestNativeRealm.Request.NativeCase != "positive_original_lifecycle" || store.DB == nil || ctx.Err() != nil || grant.Slot != 2 || pre.OriginalCreateGrantID != grant.GrantID || pre.PolicyID != policy.ID.String() || pre.WorkflowID != store.WorkflowID.String() || pre.ExecutorID != store.ExecutorID {
		return out, errOriginalGuestStep
	}
	var contract capacitynativeqemu.PG17HTTPContract
	wire, err := capacitynativeqemu.ReadPrivate(ctx, filepath.Join(capacitynativeqemu.SlotDirectory(originalGuestNativeRealm.PrivateDirectory, grant.Slot), "pg17-http-callback-contract.json"), &contract)
	if err != nil {
		return out, err
	}
	if contract.Schema != "pg17_actual_HTTP_callbacks_v1" || contract.CaseID != 20 || contract.SourceCase != originalGuestNativeRealm.Request.NativeCase || contract.CoreSource != capacity.CurrentGuestCoreSource() || contract.PolicyID != policy.ID.String() || contract.WorkflowID != store.WorkflowID.String() || contract.GrantID != grant.GrantID || !contract.ServerPaused || !contract.PrivateFieldsAbsent || contract.NativeQualified {
		return out, errOriginalGuestStep
	}
	readBody := func(fact capacitynativeqemu.PG17HTTPReturn, target any) ([]byte, error) {
		if filepath.Base(fact.PrivateBodyFile) != fact.PrivateBodyFile || len(fact.PrivateBodyFile) > 100 || !strings.HasPrefix(fact.PrivateBodyFile, "pg17-HTTP-original-") || !strings.HasSuffix(fact.PrivateBodyFile, ".json") || fact.BodyBytes <= 0 || fact.BodyBytes >= 2<<20 || fact.StartedAt.IsZero() || fact.DoReturnedAt.Before(fact.StartedAt) || fact.ReadReturnedAt.Before(fact.DoReturnedAt) || fact.CloseReturnedAt.Before(fact.ReadReturnedAt) || !fact.CloseReturnedAt.Before(pre.OriginalDeadline) {
			return nil, errOriginalGuestStep
		}
		body, err := capacitynativeqemu.ReadPrivate(ctx, filepath.Join(originalGuestNativeRealm.PrivateDirectory, fact.PrivateBodyFile), target)
		if err != nil {
			return nil, err
		}
		if len(body) != fact.BodyBytes || capacity.BusinessCreationSHA256(body) != fact.BodySHA256 {
			return nil, errOriginalGuestStep
		}
		return body, nil
	}
	for i, returned := range []capacitynativeqemu.PG17HTTPRedeemReturn{contract.First, contract.Replay} {
		var actual model.CapacityMutationRedeemResponse
		if _, err := readBody(returned.HTTP, &actual); err != nil {
			return out, err
		}
		mode := "write_once"
		if i == 1 {
			mode = "read_only"
		}
		if returned.HTTP.Method != "POST" || returned.HTTP.Route != "/api/v1/capacity/mutations/redeem" || returned.HTTP.Status != 200 || returned.HTTP.CallbackOwnerLabel != "" || actual.Mode != mode || actual.GrantID != grant.GrantID || actual.AttemptID == "" || actual.AttemptID != contract.First.Returned.AttemptID || actual.RequestSHA256 != grant.RequestSHA256 || capacity.GuestRetirementSHA(actual) != capacity.GuestRetirementSHA(returned.Returned) {
			return out, errOriginalGuestStep
		}
	}
	var denied struct {
		Type   string `json:"type"`
		Title  string `json:"title"`
		Status int    `json:"status"`
		Detail string `json:"detail"`
		Code   string `json:"code"`
	}
	if _, err := readBody(contract.WrongNonce, &denied); err != nil {
		return out, err
	}
	if contract.WrongNonce.Method != "POST" || contract.WrongNonce.Route != "/api/v1/capacity/mutations/settle" || contract.WrongNonce.Status != 403 || contract.WrongNonce.CallbackOwnerLabel != "pg17-paused-callback-v1" || denied.Status != 403 || denied.Code != "capacity.mutation_scope_denied" {
		return out, errOriginalGuestStep
	}
	var settled struct {
		GrantID       string `json:"grant_id"`
		AttemptID     string `json:"attempt_id"`
		RequestSHA256 string `json:"request_sha256"`
		Status        string `json:"status"`
	}
	if _, err := readBody(contract.Settlement, &settled); err != nil {
		return out, err
	}
	if contract.Settlement.Method != "POST" || contract.Settlement.Route != "/api/v1/capacity/mutations/settle" || contract.Settlement.Status != 200 || contract.Settlement.CallbackOwnerLabel != "pg17-paused-callback-v1" || settled.GrantID != grant.GrantID || settled.AttemptID != contract.First.Returned.AttemptID || settled.RequestSHA256 != grant.RequestSHA256 || settled.Status != "settled" {
		return out, errOriginalGuestStep
	}
	var receipt model.CapacityMutationReceipt
	body, err := readBody(contract.Receipt, &receipt)
	if err != nil {
		return out, err
	}
	if contract.Receipt.Method != "GET" || contract.Receipt.Route != "/api/v1/capacity/mutations/"+grant.GrantID || contract.Receipt.Status != 200 || contract.Receipt.CallbackOwnerLabel != "pg17-paused-callback-v1" || receipt.Grant.GrantID != grant.GrantID || receipt.AttemptID != settled.AttemptID || receipt.Outcome != "accepted" || !receipt.TransportCompleted || receipt.ResourceID == "" || receipt.ResourceCreatedAt == "" || receipt.ActionID == "" {
		return out, errOriginalGuestStep
	}
	for _, secret := range []string{pre.LeaseOwner, pre.ExecutorID} {
		if secret == "" || bytes.Contains(body, []byte(secret)) {
			return out, errOriginalGuestStep
		}
	}
	var current []byte
	if err := store.DB.QueryRowContext(ctx, `SELECT grant_record FROM public.capacity_mutation_grants WHERE id=$1 AND namespace=$2`, grant.GrantID, policy.Metadata.Namespace).Scan(&current); err != nil {
		return out, err
	}
	var recorded struct {
		Grant      model.CapacityMutationGrant          `json:"grant"`
		Settlement *model.CapacityMutationSettleRequest `json:"settlement"`
		PolicyID   string                               `json:"policy_id"`
		WorkflowID string                               `json:"workflow_id"`
		ExecutorID string                               `json:"executor_id"`
	}
	if json.Unmarshal(current, &recorded) != nil || recorded.Grant.State != "settled" || recorded.Grant.GrantID != grant.GrantID || recorded.PolicyID != policy.ID.String() || recorded.WorkflowID != store.WorkflowID.String() || recorded.ExecutorID != store.ExecutorID || recorded.Settlement == nil || recorded.Settlement.GrantID != grant.GrantID || recorded.Settlement.AttemptID != receipt.AttemptID || recorded.Settlement.RequestSHA256 != grant.RequestSHA256 || recorded.Settlement.ResourceID != receipt.ResourceID || recorded.Settlement.ResourceCreatedAt != receipt.ResourceCreatedAt || recorded.Settlement.ActionID != receipt.ActionID || recorded.Settlement.Outcome != receipt.Outcome || recorded.Settlement.TransportCompleted != receipt.TransportCompleted || capacity.BusinessCreationSHA256(current) != contract.CurrentGrantSHA256 || ctx.Err() != nil {
		return out, errOriginalGuestStep
	}
	out = PG17AssertionResult{Schema: "core_pg17_assertion_v1", CaseID: 20, OriginalTest: "TestCapacityMutationHTTPPostgres", SourceCase: contract.SourceCase, CoreSource: contract.CoreSource, PolicyID: contract.PolicyID, WorkflowID: contract.WorkflowID, Checks: []string{"actual_http_first_write_once_replay_read_only", "actual_server_paused_wrong_nonce_403", "owning_paused_settlement_200_exact_echo", "actual_get_private_fields_absent", "full_private_http_body_hash_custody", "same_current_settled_grant"}, EvidenceSHA256: []string{capacity.BusinessCreationSHA256(wire), contract.CurrentGrantSHA256, contract.First.HTTP.BodySHA256, contract.Replay.HTTP.BodySHA256, contract.WrongNonce.BodySHA256, contract.Settlement.BodySHA256, contract.Receipt.BodySHA256}, NativeQualified: false}
	return out, nil
}
