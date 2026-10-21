//go:build linux && nativequalification

package message

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	q "github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacitynativeqemu"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	"github.com/google/uuid"
)

// These assertions consume the same original caller's store and signed Source
// records. They never mint a private context, lease, profile or native fact.
// The shared PG17AssertionResult and retention function are supplied by the
// integrator's disjoint contract file, not a production API.
func pg17CompensationIdentity(ctx context.Context, realm *q.Realm, store repository.CapacityStore, policy model.Manifest) (int, string, error) {
	if realm == nil || store.DB == nil || store.WorkflowID == uuid.Nil || ctx.Err() != nil || realm.Request.SourceCommit == "" || policy.Metadata.Namespace == "" {
		return 0, "", errors.New("pg17 original compensation identity required")
	}
	deadline, ok := ctx.Deadline()
	if !ok || deadline.After(realm.Request.OriginalContextDeadline) || !time.Now().UTC().Before(deadline) {
		return 0, "", errors.New("pg17 original compensation deadline required")
	}
	switch realm.Request.NativeCase {
	case "canonical_compensation_unprotected_failed_create":
		return 1, "TestCapacityMutationCompensationPostgres/unprotected_failed_create", nil
	case "canonical_compensation_protected_failed_create":
		return 2, "TestCapacityMutationCompensationPostgres/protected_failed_create_without_serving_membership", nil
	case "canonical_postloss_unprotected_failed_create_reissue":
		return 3, "TestCapacityMutationCompensationPostgres/lost_create_reply_uses_separate_native_readback", nil
	case "canonical_postloss_protected_failed_create_reissue":
		return 4, "TestCapacityMutationCompensationPostgres/protected_lost_create_reply", nil
	case "canonical_failed_floor_recovery":
		return 5, "TestCapacityMutationFailedFloorRecoveryPostgres", nil
	}
	return 0, "", errors.New("pg17 closed original compensation case required")
}

// Hash only: private grant/lease/token values never enter the returned DTO.
// Fixed queries cover all durable mutation state touched by the tested calls.
func pg17CompensationState(ctx context.Context, store repository.CapacityStore, namespace string) (string, error) {
	queries := []string{
		`SELECT COALESCE(jsonb_agg(to_jsonb(x) ORDER BY to_jsonb(x)::text),'[]'::jsonb)::text FROM public.capacity_mutation_grants x WHERE namespace=$1`,
		`SELECT COALESCE(jsonb_agg(to_jsonb(x) ORDER BY to_jsonb(x)::text),'[]'::jsonb)::text FROM public.capacity_resource_slots x WHERE namespace=$1`,
		`SELECT COALESCE(jsonb_agg(to_jsonb(x) ORDER BY to_jsonb(x)::text),'[]'::jsonb)::text FROM public.capacity_intents x WHERE namespace=$1`,
		`SELECT COALESCE(jsonb_agg(to_jsonb(x) ORDER BY to_jsonb(x)::text),'[]'::jsonb)::text FROM public.event_log x WHERE metadata->>'namespace'=$1`,
	}
	values := make([]string, 0, len(queries))
	for _, query := range queries {
		var value string
		if err := store.DB.QueryRowContext(ctx, query, namespace).Scan(&value); err != nil {
			return "", err
		}
		values = append(values, value)
	}
	if ctx.Err() != nil {
		return "", ctx.Err()
	}
	return capacity.GuestRetirementSHA(values), nil
}
func pg17CompensationResult(ctx context.Context, realm *q.Realm, store repository.CapacityStore, policy model.Manifest, checks, evidence []string) ([]PG17AssertionResult, error) {
	id, test, err := pg17CompensationIdentity(ctx, realm, store, policy)
	if err != nil {
		return nil, err
	}
	return []PG17AssertionResult{{Schema: "core_pg17_assertion_v1", CaseID: id, OriginalTest: test, SourceCase: realm.Request.NativeCase, CoreSource: capacity.CurrentGuestCoreSource(), PolicyID: policy.ID.String(), WorkflowID: store.WorkflowID.String(), Checks: checks, EvidenceSHA256: evidence, NativeQualified: false}}, nil
}
func pg17CompensationRefused(ctx context.Context, store repository.CapacityStore, policy model.Manifest, label string, call func() error) (string, error) {
	before, err := pg17CompensationState(ctx, store, policy.Metadata.Namespace)
	if err != nil {
		return "", err
	}
	if err = call(); err == nil {
		return "", fmt.Errorf("pg17 compensation refusal missing: %s", label)
	}
	after, err := pg17CompensationState(ctx, store, policy.Metadata.Namespace)
	if err != nil {
		return "", err
	}
	if before != after {
		return "", fmt.Errorf("pg17 compensation refusal changed durable state: %s", label)
	}
	return before, nil
}

// Hook: after actual current policy/eligibility/baseline probe, BEFORE the
// first child Issue. Inputs are the producer's genuine issue, not test proofs.
func PG17AssertCompensationEligibility(ctx context.Context, realm *q.Realm, issuer repository.CapacityStore, current model.Manifest, issue model.CapacityCompensationIssue) ([]PG17AssertionResult, error) {
	id, _, err := pg17CompensationIdentity(ctx, realm, issuer, current)
	if err != nil {
		return nil, err
	}
	wire, err := issuer.CanonicalSourceEligibilityWire(ctx, issue.ParentGrantID)
	if err != nil {
		return nil, err
	}
	var envelope repository.SourceFailureCleanupAuthority
	var eligible repository.CanonicalSourceEligibility
	if capacity.DecodeGuestLifecycle(wire, &envelope) != nil || envelope.Signature == "" || capacity.DecodeGuestLifecycle(envelope.Body, &eligible) != nil || eligible.Schema != "canonical_source_failed_owner_eligibility_v1" || eligible.Scope != "NATIVEQUALIFICATION_FAILED_OWNER_CHILD_OWNS_PHYSICAL_EFFECTS_NOT_POSITIVE_QUIESCENCE" || eligible.NativeCase != realm.Request.NativeCase || eligible.ParentGrantID != issue.ParentGrantID || eligible.Namespace != current.Metadata.Namespace || eligible.CoreSource != capacity.CurrentGuestCoreSource() || eligible.GuestSource != realm.Request.SourceCommit || eligible.ProductionQualified || eligible.PositiveQuiescence || !eligible.ChildOwnsPhysicalEffects || capacity.GuestRetirementSHA(eligible.Aggregate) != capacity.GuestRetirementSHA(issue.FailedProof) {
		return nil, errors.New("pg17 actual signed failed payload aggregate differs")
	}
	// The successful native Start and failed signed payload are two REAL actions.
	// Neither successful Start nor an uncertain transport alone becomes failure.
	successes, failures := 0, 0
	seen := map[string]bool{}
	for _, a := range eligible.Actions {
		if a.ID == "" || seen[a.ID] || !capacity.ValidDigest(a.OriginalSHA256) || a.ReturnedAt.IsZero() {
			return nil, errors.New("pg17 complete actual action roster required")
		}
		seen[a.ID] = true
		switch a.Outcome {
		case "success":
			if a.Kind != "original_native_create" {
				return nil, errors.New("pg17 native start action kind differs")
			}
			successes++
		case "failed_exit_1":
			if a.Kind != "original_enrolled_payload" {
				return nil, errors.New("pg17 enrolled payload action kind differs")
			}
			failures++
		default:
			return nil, errors.New("pg17 actual action status refused")
		}
	}
	if successes != 1 || failures != 1 || !issue.FailedProof.ActionsFailed || issue.FailedProof.ActionsSuccessful || !issue.FailedProof.ActionsTerminal || !issue.FailedProof.CompensationIdentityVerified || issue.FailedProof.ResourceAbsent || issue.FailedProof.Slot != 2 {
		return nil, errors.New("pg17 failed original operation must preserve native start success")
	}
	variants := []string{"unknown_action", "successful_action", "wrong_parent", "wrong_creation_label", "missing_identity", "running_business", "running_native", "open_admission", "routed", "incomplete_inventory", "below_floor", "wrong_tuple"}
	if q.PostlossSourceCase(realm.Request.NativeCase) {
		variants = append(variants, "incomplete_action_history")
	}
	if id == 5 {
		variants = append(variants, "baseline_lost", "incomplete", "wrong_profile", "native_running", "business_running")
	}
	checks := []string{"same_original_signed_failed_payload_and_native_start_success"}
	evidence := []string{capacity.BusinessCreationSHA256(wire)}
	for _, variant := range variants {
		bad := issue
		switch variant {
		case "unknown_action":
			bad.FailedProof.ActionsTerminal = false
		case "successful_action":
			bad.FailedProof.ActionsSuccessful = true
		case "wrong_parent":
			bad.ParentGrantID = uuid.NewString()
		case "wrong_creation_label":
			bad.FailedProof.ObservedCreationGrantID = uuid.NewString()
		case "missing_identity":
			bad.FailedProof.CompensationIdentityVerified = false
		case "running_business", "business_running":
			one := 1
			bad.DrainProof.Inflight = &one
		case "running_native", "native_running":
			one := 1
			bad.DrainProof.NativeActionsInflight = &one
		case "open_admission":
			bad.DrainProof.AdmissionClosed = false
		case "routed":
			bad.DrainProof.RoutingWithdrawn = false
		case "incomplete_inventory", "incomplete":
			bad.DrainProof.MembershipComplete = false
		case "below_floor", "baseline_lost":
			bad.DrainProof.Assessment.Snapshot.Units = 0
		case "wrong_tuple":
			bad.FailedProof.ResourceID = "pg17-foreign-not-an-actual-resource"
		case "incomplete_action_history":
			bad.FailedProof.ActionHistoryComplete = false
		case "wrong_profile":
			bad.DrainProof.Assessment.Snapshot.Profile = "pg17-foreign-not-an-approved-profile"
		}
		pin, err := pg17CompensationRefused(ctx, issuer, current, variant, func() error { _, e := issuer.IssueCompensation(ctx, current, bad); return e })
		if err != nil {
			return nil, err
		}
		checks = append(checks, "refused_"+variant+"_durable_state_unchanged")
		evidence = append(evidence, pin)
	}
	return pg17CompensationResult(ctx, realm, issuer, current, checks, evidence)
}

// Hook: physical read/absence is genuine, but owning child Settle has NOT run.
// This tests the original transport-vs-readback separation without a new effect.
func PG17AssertCompensationPreSettlement(ctx context.Context, realm *q.Realm, issuer repository.CapacityStore, current model.Manifest, child model.CapacityMutationGrant) ([]PG17AssertionResult, error) {
	if _, _, err := pg17CompensationIdentity(ctx, realm, issuer, current); err != nil {
		return nil, err
	}
	var state string
	var noSettlement bool
	if err := issuer.DB.QueryRowContext(ctx, `SELECT state,NOT(grant_record ? 'settlement') OR grant_record->'settlement'='null'::jsonb FROM public.capacity_mutation_grants WHERE id=$1 AND namespace=$2`, child.GrantID, current.Metadata.Namespace).Scan(&state, &noSettlement); err != nil {
		return nil, err
	}
	if state != "redeemed" || !noSettlement || child.CompensationOf == "" {
		return nil, errors.New("pg17 before-settlement child identity refused")
	}
	var principal string
	if err := issuer.DB.QueryRowContext(ctx, `SELECT grant_record->'binding'->>'adapter_principal_id' FROM public.capacity_mutation_grants WHERE id=$1 AND namespace=$2`, child.GrantID, current.Metadata.Namespace).Scan(&principal); err != nil {
		return nil, err
	}
	wrong := model.CapacityMutationRedeemRequest{GrantID: child.GrantID, AttemptID: uuid.NewString(), SettlementTokenSHA256: capacity.BusinessCreationSHA256([]byte(uuid.NewString())), Capability: child.Capability, IntegrationInstanceID: child.IntegrationInstanceID, ScopeChecksum: child.ScopeChecksum, ProfileName: child.ProfileName, Slot: child.Slot, RequestSHA256: child.RequestSHA256, ExpectedResourceID: child.ExpectedResourceID, ExpectedResourceCreatedAt: child.ExpectedResourceCreatedAt, CompensationOf: ""}
	identityPin, err := pg17CompensationRefused(ctx, issuer, current, "child-redemption-omitted-parent", func() error {
		_, e := issuer.RedeemMutation(ctx, principal, wrong)
		if !errors.Is(e, repository.ErrCapacityMutationAuthorization) {
			return nil
		}
		return e
	})
	if err != nil {
		return nil, err
	}
	observed, err := issuer.ObserveCanonicalSourceCompensation(ctx, current, child.GrantID)
	if err != nil {
		return nil, err
	}
	if observed.GrantID != child.GrantID || observed.ResourceID != child.ExpectedResourceID || observed.ResourceCreatedAt != child.ExpectedResourceCreatedAt || !observed.ResourceAbsent {
		return nil, errors.New("pg17 actual original absence required")
	}
	pin, err := pg17CompensationRefused(ctx, issuer, current, "absence-without-owning-child-settlement", func() error { _, e := issuer.ConfirmCompensation(ctx, current, observed); return e })
	if err != nil {
		return nil, err
	}
	return pg17CompensationResult(ctx, realm, issuer, current, []string{"actual_child_redemption_without_parent_identity_refused", "actual_original_absence_does_not_replace_owning_transport_settlement"}, []string{identityPin, capacity.GuestRetirementSHA(observed), pin})
}

// Hook: original first Confirm completed. Verify its exact lineage and execute
// the paused identical replay; no policy flag is changed or re-enabled here.
func PG17AssertCompensationAfterConfirm(ctx context.Context, realm *q.Realm, issuer repository.CapacityStore, current model.Manifest, parentBefore model.CapacityMutationReceipt, deleted model.CapacityMutationProof, child model.CapacityMutationGrant) ([]PG17AssertionResult, error) {
	if _, _, err := pg17CompensationIdentity(ctx, realm, issuer, current); err != nil {
		return nil, err
	}
	if child.CompensationOf != parentBefore.Grant.GrantID || deleted.GrantID != child.GrantID {
		return nil, errors.New("pg17 child-parent lineage required")
	}
	paused := issuer
	paused.ExecutionEnabled = false
	before, err := pg17CompensationState(ctx, issuer, current.Metadata.Namespace)
	if err != nil {
		return nil, err
	}
	returned, err := paused.ConfirmCompensation(ctx, current, deleted)
	if err != nil || returned.State != "confirmed" || returned.GrantID != child.GrantID {
		return nil, errors.New("pg17 paused exact confirmation replay refused")
	}
	after, err := pg17CompensationState(ctx, issuer, current.Metadata.Namespace)
	if err != nil {
		return nil, err
	}
	if before != after {
		return nil, errors.New("pg17 paused replay changed durable state")
	}
	var parentWire, childWire []byte
	if err = issuer.DB.QueryRowContext(ctx, `SELECT grant_record FROM public.capacity_mutation_grants WHERE id=$1 AND namespace=$2`, parentBefore.Grant.GrantID, current.Metadata.Namespace).Scan(&parentWire); err != nil {
		return nil, err
	}
	if err = issuer.DB.QueryRowContext(ctx, `SELECT grant_record FROM public.capacity_mutation_grants WHERE id=$1 AND namespace=$2`, child.GrantID, current.Metadata.Namespace).Scan(&childWire); err != nil {
		return nil, err
	}
	var parentRecord struct {
		Grant      model.CapacityMutationGrant          `json:"grant"`
		Settlement *model.CapacityMutationSettleRequest `json:"settlement"`
		Proof      *model.CapacityMutationProof         `json:"proof"`
	}
	var childRecord struct {
		Grant model.CapacityMutationGrant  `json:"grant"`
		Proof *model.CapacityMutationProof `json:"proof"`
	}
	if json.Unmarshal(parentWire, &parentRecord) != nil || json.Unmarshal(childWire, &childRecord) != nil || parentRecord.Grant.State != "compensated" || childRecord.Grant.State != "confirmed" || childRecord.Grant.GrantID != child.GrantID || childRecord.Grant.CompensationOf != parentBefore.Grant.GrantID || parentRecord.Proof == nil || childRecord.Proof == nil || parentRecord.Proof.ResourceID != deleted.ResourceID || parentRecord.Proof.ResourceCreatedAt != deleted.ResourceCreatedAt || capacity.GuestRetirementSHA(*childRecord.Proof) != capacity.GuestRetirementSHA(deleted) {
		return nil, errors.New("pg17 exact compensated parent and confirmed child required")
	}
	// Read the original private binding principal from the same durable child.
	var principal string
	if err = issuer.DB.QueryRowContext(ctx, `SELECT grant_record->'binding'->>'adapter_principal_id' FROM public.capacity_mutation_grants WHERE id=$1`, child.GrantID).Scan(&principal); err != nil {
		return nil, err
	}
	actual, err := issuer.MutationReceipt(ctx, principal, parentBefore.Grant.GrantID)
	if err != nil || actual.Grant.State != "compensated" || actual.NativeReadback == nil || actual.NativeReadback.ResourceID != deleted.ResourceID || actual.NativeReadback.ResourceCreatedAt != deleted.ResourceCreatedAt {
		return nil, errors.New("pg17 original receipt readback differs")
	}
	compare := actual
	compare.Grant = parentBefore.Grant
	compare.NativeReadback = parentBefore.NativeReadback
	if !reflect.DeepEqual(compare, parentBefore) {
		return nil, errors.New("pg17 owning transport receipt overwritten")
	}
	var members, failedMembers, parentEvents, childEvents int
	var eventParent string
	if err = issuer.DB.QueryRowContext(ctx, `SELECT count(*) FILTER(WHERE resource_id<>''),count(*) FILTER(WHERE slot=2 AND resource_id<>'') FROM public.capacity_resource_slots WHERE namespace=$1`, current.Metadata.Namespace).Scan(&members, &failedMembers); err != nil {
		return nil, err
	}
	if err = issuer.DB.QueryRowContext(ctx, `SELECT count(*) FILTER(WHERE idempotency_key=$2),count(*) FILTER(WHERE idempotency_key=$3) FROM public.event_log WHERE metadata->>'namespace'=$1`, current.Metadata.Namespace, "capacity-mutation/"+parentBefore.Grant.GrantID, "capacity-mutation/"+child.GrantID).Scan(&parentEvents, &childEvents); err != nil {
		return nil, err
	}
	if err = issuer.DB.QueryRowContext(ctx, `SELECT payload->'observed'->>'compensation_of' FROM public.event_log WHERE metadata->>'namespace'=$1 AND idempotency_key=$2`, current.Metadata.Namespace, "capacity-mutation/"+child.GrantID).Scan(&eventParent); err != nil {
		return nil, err
	}
	if members != 1 || failedMembers != 0 || parentEvents != 0 || childEvents != 1 || eventParent != parentBefore.Grant.GrantID {
		return nil, errors.New("pg17 compensation serving/event projection differs")
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	checks := []string{"paused_identical_confirmation_replay_no_durable_change", "parent_compensated_child_confirmed", "original_accepted_or_uncertain_transport_fields_preserved", "failed_slot_never_serving", "one_destroyed_event_with_parent_lineage_no_parent_ensured_event"}
	evidence := []string{before, capacity.BusinessCreationSHA256(parentWire), capacity.BusinessCreationSHA256(childWire), capacity.GuestRetirementSHA(actual)}
	id, _, err := pg17CompensationIdentity(ctx, realm, issuer, current)
	if err != nil {
		return nil, err
	}
	if id != 5 {
		var first pg17FirstConfirmationEvidence
		raw, readErr := q.ReadPrivate(ctx, realm.PrivateDirectory+"/pg17-inactive-paused-first-confirmation.json", &first)
		if readErr != nil {
			return nil, readErr
		}
		inactive, readErr := repository.GetManifestByID(ctx, issuer.DB, current.ID)
		if readErr != nil {
			return nil, readErr
		}
		if first.Schema != "pg17_inactive_paused_first_confirmation_v1" || first.Case != realm.Request.NativeCase || first.PolicyID != current.ID.String() || first.PolicyChecksum != current.Checksum || first.ChildID != child.GrantID || first.BeforeState != "settled" || first.AfterState != "confirmed" || !first.PolicyInactive || !first.ProcessPaused || inactive.Metadata.Active || capacity.GuestRetirementSHA(inactive) != first.InactivePolicySHA256 || capacity.GuestRetirementSHA(returned) != first.ConfirmedSHA256 {
			return nil, errors.New("pg17 actual inactive-policy paused first-confirmation evidence differs")
		}
		checks = append(checks, "first_confirmation_after_original_policy_inactive_and_process_paused")
		evidence = append(evidence, capacity.BusinessCreationSHA256(raw))
	}
	return pg17CompensationResult(ctx, realm, issuer, current, checks, evidence)
}

// Hook: inside the producer's ORIGINAL recovery epoch, before its terminal
// Reconcile. No old lease, timestamp or executor is reconstructed from SQL.
func PG17AssertFailedFloorTerminalNegatives(ctx context.Context, realm *q.Realm, recovery repository.CapacityStore, policy model.Manifest, intent model.CapacityIntent, proof model.CapacityTransitionProof) ([]PG17AssertionResult, error) {
	id, _, err := pg17CompensationIdentity(ctx, realm, recovery, policy)
	if err != nil {
		return nil, err
	}
	if id != 5 || !intent.RecoveryOnly || intent.LeaseExecutorID != recovery.ExecutorID || intent.LeaseOwner == "" || intent.LeaseExpiresAt == nil || !intent.LeaseExpiresAt.After(time.Now().UTC()) || !proof.MembershipComplete || !proof.Healthy || proof.Assessment.Snapshot.Units != 1 || proof.NoMutationVerified {
		return nil, errors.New("pg17 actual failed-floor recovery owner/probe required")
	}
	var originalIntent []byte
	var actualIntent model.CapacityIntent
	if err = recovery.DB.QueryRowContext(ctx, `SELECT intent FROM public.capacity_intents WHERE namespace=$1 AND environment=$2 AND domain=$3 AND dimension=$4`, policy.Metadata.Namespace, intent.Environment, intent.Domain, intent.Dimension).Scan(&originalIntent); err != nil {
		return nil, err
	}
	if json.Unmarshal(originalIntent, &actualIntent) != nil || capacity.GuestRetirementSHA(actualIntent) != capacity.GuestRetirementSHA(intent) {
		return nil, errors.New("pg17 actual original recovery intent differs")
	}
	var probe q.QualificationProbeReceipt
	if _, err = q.ReadPrivate(ctx, realm.PrivateDirectory+"/canonical-floor-baseline-probe.json", &probe); err != nil {
		return nil, err
	}
	if !proof.ObservedAt.Equal(probe.OriginalNativeAfterReturnedAt) || proof.ReceiptRef != "source-failed-floor-signed-baseline:"+capacity.GuestRetirementSHA(probe) {
		return nil, errors.New("pg17 original failed-floor probe differs")
	}
	checks := []string{}
	evidence := []string{capacity.BusinessCreationSHA256(originalIntent), capacity.GuestRetirementSHA(probe)}
	for _, variant := range []string{"baseline_lost", "incomplete", "wrong_profile", "no_mutation", "ordinary_partial", "aborted_no_mutation"} {
		bad := proof
		phase := "reconciled_failed_floor"
		switch variant {
		case "baseline_lost":
			bad.Assessment.Snapshot.Units = 0
		case "incomplete":
			bad.MembershipComplete = false
		case "wrong_profile":
			bad.Assessment.Snapshot.Profile = "pg17-foreign-not-an-approved-profile"
		case "no_mutation":
			bad.NoMutationVerified = true
		case "ordinary_partial":
			phase = "reconciled_partial"
		case "aborted_no_mutation":
			phase = "aborted"
			bad.NoMutationVerified = true
		}
		pin, err := pg17CompensationRefused(ctx, recovery, policy, variant, func() error {
			_, e := recovery.Reconcile(ctx, policy, intent.Generation, intent.FencingToken, intent.LeaseOwner, phase, bad)
			return e
		})
		if err != nil {
			return nil, err
		}
		checks = append(checks, "failed_floor_refused_"+variant+"_durable_state_unchanged")
		evidence = append(evidence, pin)
	}
	return pg17CompensationResult(ctx, realm, recovery, policy, checks, evidence)
}

// Hook: AFTER the producer publishes its actual full-floor result. This only
// joins retained originals to SAME database state; next grant is permission,
// not provider Prepare/Create, useful capacity or a second Native execution.
func PG17AssertFailedFloorAfterCompletion(ctx context.Context, realm *q.Realm, store repository.CapacityStore, policy model.Manifest, parentID string) ([]PG17AssertionResult, error) {
	id, _, err := pg17CompensationIdentity(ctx, realm, store, policy)
	if err != nil {
		return nil, err
	}
	if id != 5 {
		return nil, errors.New("pg17 original failed-floor case required")
	}
	var result struct {
		Schema                string   `json:"schema"`
		Scope                 string   `json:"scope"`
		Case                  string   `json:"case"`
		CoreSource            string   `json:"core_source"`
		GuestSource           string   `json:"guest_source"`
		ParentGrantID         string   `json:"parent_grant_id"`
		ChildGrantID          string   `json:"child_grant_id"`
		CompensationResultSHA string   `json:"compensation_result_sha256"`
		PolicyBridgeSHA       string   `json:"policy_bridge_sha256"`
		BaselineProbeSHA      string   `json:"baseline_probe_sha256"`
		BaselinePhysicalSHA   string   `json:"baseline_physical_sha256"`
		FailedSlotReadSHA     string   `json:"failed_slot_current_read_sha256"`
		TerminalSHA           string   `json:"terminal_intent_sha256"`
		NextIntentSHA         string   `json:"next_intent_sha256"`
		NextGrantSHA          string   `json:"next_grant_sha256"`
		ParentState           string   `json:"parent_state"`
		ChildState            string   `json:"child_state"`
		Phase                 string   `json:"phase"`
		BaselineUnits         int      `json:"baseline_units"`
		FloorUnits            int      `json:"floor_units"`
		NextGeneration        int64    `json:"next_generation"`
		Refused               []string `json:"refused"`
		NextGrantState        string   `json:"next_grant_state"`
		NextGrantRedeemed     bool     `json:"next_grant_redeemed"`
		NativeQualified       bool     `json:"native_qualified"`
		ProductionQualified   bool     `json:"production_qualified"`
	}
	wire, err := q.ReadPrivate(ctx, realm.PrivateDirectory+"/canonical-source-failed-floor-result.json", &result)
	if err != nil {
		return nil, err
	}
	if result.Schema != "canonical_source_failed_floor_v1" || result.Scope != "SOURCE_ONLY_ORDINARY_RECONCILE_AFTER_GENERIC_COMPENSATION" || result.Case != realm.Request.NativeCase || result.CoreSource != capacity.CurrentGuestCoreSource() || result.GuestSource != realm.Request.SourceCommit || result.ParentGrantID != parentID || result.ParentState != "compensated" || result.ChildState != "confirmed" || result.Phase != "reconciled_failed_floor" || result.BaselineUnits != 1 || result.FloorUnits != 2 || result.NextGrantState != "issued" || result.NextGrantRedeemed || result.NativeQualified || result.ProductionQualified {
		return nil, errors.New("pg17 original full-floor result differs")
	}
	var terminal model.CapacityIntent
	terminalWire, err := q.ReadPrivate(ctx, realm.PrivateDirectory+"/canonical-floor-terminal-intent.json", &terminal)
	if err != nil {
		return nil, err
	}
	if capacity.BusinessCreationSHA256(terminalWire) != result.TerminalSHA || terminal.Phase != "reconciled_failed_floor" || !terminal.FloorDegraded || terminal.Assessment.Snapshot.Units != 1 || terminal.Decision.Units != 2 || terminal.Decision.ExecutionPermitted || terminal.LeaseOwner != "" || terminal.LeaseExecutorID != "" || terminal.LeaseExpiresAt != nil {
		return nil, errors.New("pg17 failed floor terminal authority not cleared")
	}
	var persistedTerminal []byte
	var terminalSHA string
	if err = store.DB.QueryRowContext(ctx, `SELECT terminal_wire,terminal_sha256 FROM public.capacity_canonical_source_floor_terminal WHERE parent_grant_id=$1`, parentID).Scan(&persistedTerminal, &terminalSHA); err != nil {
		return nil, err
	}
	if !reflect.DeepEqual(persistedTerminal, terminalWire) || terminalSHA != result.TerminalSHA {
		return nil, errors.New("pg17 actual database historical terminal differs")
	}
	var next model.CapacityIntent
	nextWire, err := q.ReadPrivate(ctx, realm.PrivateDirectory+"/canonical-floor-next-intent.json", &next)
	if err != nil {
		return nil, err
	}
	if capacity.BusinessCreationSHA256(nextWire) != result.NextIntentSHA || next.Generation != terminal.Generation+1 || next.Generation != result.NextGeneration || next.Phase != "preparing" || next.Decision.Reason != "protected_floor_recovery" || next.Decision.Units != 2 || next.BaselineSnapshot.Units != 1 || next.RecoveryOnly {
		return nil, errors.New("pg17 fresh independent floor repair generation differs")
	}
	var currentWire []byte
	if err = store.DB.QueryRowContext(ctx, `SELECT intent FROM public.capacity_intents WHERE namespace=$1 AND environment=$2 AND domain=$3 AND dimension=$4`, policy.Metadata.Namespace, next.Environment, next.Domain, next.Dimension).Scan(&currentWire); err != nil {
		return nil, err
	}
	var current model.CapacityIntent
	if json.Unmarshal(currentWire, &current) != nil || capacity.GuestRetirementSHA(current) != capacity.GuestRetirementSHA(next) {
		return nil, errors.New("pg17 actual next floor repair intent differs")
	}
	var grant model.CapacityMutationGrant
	grantWire, err := q.ReadPrivate(ctx, realm.PrivateDirectory+"/canonical-floor-next-grant.json", &grant)
	if err != nil {
		return nil, err
	}
	if capacity.BusinessCreationSHA256(grantWire) != result.NextGrantSHA || grant.State != "issued" || grant.CompensationOf != "" || grant.GrantID == parentID || grant.Slot != 2 {
		return nil, errors.New("pg17 next floor permission is not fresh issued-only")
	}
	var raw []byte
	var state string
	if err = store.DB.QueryRowContext(ctx, `SELECT state,grant_record FROM public.capacity_mutation_grants WHERE id=$1 AND namespace=$2`, grant.GrantID, policy.Metadata.Namespace).Scan(&state, &raw); err != nil {
		return nil, err
	}
	var stored struct {
		Grant              model.CapacityMutationGrant          `json:"grant"`
		AttemptID          string                               `json:"attempt_id"`
		SettlementTokenSHA string                               `json:"settlement_token_sha256"`
		Settlement         *model.CapacityMutationSettleRequest `json:"settlement"`
		Proof              *model.CapacityMutationProof         `json:"proof"`
	}
	if json.Unmarshal(raw, &stored) != nil || state != "issued" || stored.Grant != grant || stored.AttemptID != "" || stored.SettlementTokenSHA != "" || stored.Settlement != nil || stored.Proof != nil {
		return nil, errors.New("pg17 next floor permission was redeemed or relabeled")
	}
	var parentState, childState string
	var preregistrations, failedMembers int
	if err = store.DB.QueryRowContext(ctx, `SELECT state FROM public.capacity_mutation_grants WHERE id=$1 AND namespace=$2`, parentID, policy.Metadata.Namespace).Scan(&parentState); err != nil {
		return nil, err
	}
	if err = store.DB.QueryRowContext(ctx, `SELECT state FROM public.capacity_mutation_grants WHERE id=$1 AND namespace=$2 AND grant_record->'grant'->>'compensation_of'=$3`, result.ChildGrantID, policy.Metadata.Namespace, parentID).Scan(&childState); err != nil {
		return nil, err
	}
	if err = store.DB.QueryRowContext(ctx, `SELECT count(*) FROM public.capacity_vm_provisioning_preregistrations WHERE create_grant_id=$1 AND (preregistration_record->>'generation')::bigint=$2`, grant.GrantID, next.Generation).Scan(&preregistrations); err != nil {
		return nil, err
	}
	if err = store.DB.QueryRowContext(ctx, `SELECT count(*) FROM public.capacity_resource_slots WHERE namespace=$1 AND slot=2 AND resource_id<>''`, policy.Metadata.Namespace).Scan(&failedMembers); err != nil {
		return nil, err
	}
	if parentState != "compensated" || childState != "confirmed" || preregistrations != 1 || failedMembers != 0 || ctx.Err() != nil {
		return nil, errors.New("pg17 actual floor compensated lineage or next preregistration differs")
	}
	return pg17CompensationResult(ctx, realm, store, policy, []string{"ordinary_failed_floor_terminal_clears_authority_and_retains_degraded_floor", "actual_historical_terminal_readback", "new_independent_generation_original_assess_claim_issue", "next_grant_issued_not_redeemed_not_provider_prepare_or_create", "failed_original_slot_never_serving"}, []string{capacity.BusinessCreationSHA256(wire), result.TerminalSHA, result.NextIntentSHA, result.NextGrantSHA, capacity.BusinessCreationSHA256(raw)})
}

// Hook: original first child expired without redemption and genuine fresh
// eligibility/baseline read completed, immediately BEFORE actual second Issue.
// Timestamp changes below are adversarial copies, never SQL clocks or facts.
func PG17AssertPostlossReissueIdentity(ctx context.Context, realm *q.Realm, issuer repository.CapacityStore, policy model.Manifest, issue model.CapacityCompensationIssue, first model.CapacityMutationGrant) ([]PG17AssertionResult, error) {
	id, _, err := pg17CompensationIdentity(ctx, realm, issuer, policy)
	if err != nil {
		return nil, err
	}
	if (id != 3 && id != 4) || first.CompensationOf != issue.ParentGrantID {
		return nil, errors.New("pg17 original postloss unused child required")
	}
	var beforeRecord, afterRecord map[string]json.RawMessage
	beforeWire, err := q.ReadPrivate(ctx, realm.PrivateDirectory+"/canonical-postloss-child-first-before.json", &beforeRecord)
	if err != nil {
		return nil, err
	}
	afterWire, err := q.ReadPrivate(ctx, realm.PrivateDirectory+"/canonical-postloss-child-first-after.json", &afterRecord)
	if err != nil {
		return nil, err
	}
	var oldGrant, newGrant model.CapacityMutationGrant
	if json.Unmarshal(beforeRecord["grant"], &oldGrant) != nil || json.Unmarshal(afterRecord["grant"], &newGrant) != nil || oldGrant != first || newGrant.State != "expired" {
		return nil, errors.New("pg17 original first child identity differs")
	}
	var originalGrantFields, currentGrantFields map[string]json.RawMessage
	if json.Unmarshal(beforeRecord["grant"], &originalGrantFields) != nil || json.Unmarshal(afterRecord["grant"], &currentGrantFields) != nil {
		return nil, errors.New("pg17 original child fields required")
	}
	currentGrantFields["state"] = json.RawMessage(`"issued"`)
	if !reflect.DeepEqual(originalGrantFields, currentGrantFields) {
		return nil, errors.New("pg17 first child changed beyond expiry state")
	}
	beforeRecord["grant"], afterRecord["grant"] = nil, nil
	if !reflect.DeepEqual(beforeRecord, afterRecord) {
		return nil, errors.New("pg17 original child private fields changed")
	}
	var dbNow time.Time
	var actualWire []byte
	var state string
	var effectAuthorities int
	if err = issuer.DB.QueryRowContext(ctx, `SELECT clock_timestamp(),state,grant_record FROM public.capacity_mutation_grants WHERE id=$1 AND namespace=$2`, first.GrantID, policy.Metadata.Namespace).Scan(&dbNow, &state, &actualWire); err != nil {
		return nil, err
	}
	var unused struct {
		Grant      model.CapacityMutationGrant          `json:"grant"`
		AttemptID  string                               `json:"attempt_id"`
		Token      string                               `json:"settlement_token_sha256"`
		Settlement *model.CapacityMutationSettleRequest `json:"settlement"`
		Proof      *model.CapacityMutationProof         `json:"proof"`
	}
	if json.Unmarshal(actualWire, &unused) != nil || state != "expired" || unused.Grant != newGrant || unused.AttemptID != "" || unused.Token != "" || unused.Settlement != nil || unused.Proof != nil || dbNow.Before(first.ExpiresAt) {
		return nil, errors.New("pg17 actual first child was not genuinely expired unused")
	}
	if err = issuer.DB.QueryRowContext(ctx, `SELECT count(*) FROM public.capacity_canonical_source_effect_authorities WHERE child_grant_id=$1`, first.GrantID).Scan(&effectAuthorities); err != nil {
		return nil, err
	}
	if effectAuthorities != 0 {
		return nil, errors.New("pg17 unused child already owns effects")
	}
	currentEligibility, err := issuer.CanonicalSourceEligibilityWire(ctx, issue.ParentGrantID)
	if err != nil {
		return nil, err
	}
	var signed repository.SourceFailureCleanupAuthority
	var eligibility repository.CanonicalSourceEligibility
	if capacity.DecodeGuestLifecycle(currentEligibility, &signed) != nil || capacity.DecodeGuestLifecycle(signed.Body, &eligibility) != nil || eligibility.NativeCase != realm.Request.NativeCase || eligibility.ParentGrantID != issue.ParentGrantID || capacity.GuestRetirementSHA(eligibility.Aggregate) != capacity.GuestRetirementSHA(issue.FailedProof) {
		return nil, errors.New("pg17 genuine fresh postloss eligibility differs")
	}
	var desired model.CapacityMutationSpecV1
	if json.Unmarshal(issue.Mutation.DesiredSpec, &desired) != nil {
		return nil, errors.New("pg17 original cleanup desired spec required")
	}
	checks := []string{"original_first_child_genuine_db_expiry_never_redeemed_no_effect_authority", "all_first_child_fields_immutable_except_expired_state"}
	evidence := []string{capacity.BusinessCreationSHA256(beforeWire), capacity.BusinessCreationSHA256(afterWire), capacity.BusinessCreationSHA256(actualWire), capacity.BusinessCreationSHA256(currentEligibility)}
	for _, variant := range []string{"changed_resource_id", "changed_created_at"} {
		bad := issue
		changed := desired
		if variant == "changed_resource_id" {
			bad.FailedProof.ResourceID = "pg17-foreign-not-an-actual-resource"
			changed.ExpectedResourceID = bad.FailedProof.ResourceID
		} else {
			created, err := time.Parse(time.RFC3339Nano, issue.FailedProof.ResourceCreatedAt)
			if err != nil {
				return nil, err
			}
			bad.FailedProof.ResourceCreatedAt = created.Add(time.Second).Format(time.RFC3339Nano)
			changed.ExpectedResourceCreatedAt = bad.FailedProof.ResourceCreatedAt
		}
		encoded, err := json.Marshal(changed)
		if err != nil {
			return nil, err
		}
		bad.Mutation.DesiredSpec = encoded
		pin, err := pg17CompensationRefused(ctx, issuer, policy, variant, func() error { _, e := issuer.IssueCompensation(ctx, policy, bad); return e })
		if err != nil {
			return nil, err
		}
		checks = append(checks, "expired_child_reissue_refused_"+variant+"_no_durable_change")
		evidence = append(evidence, pin)
	}
	return pg17CompensationResult(ctx, realm, issuer, policy, checks, evidence)
}

// Called IN PLACE OF the first original Confirm, after actual Settle. Only the
// four completed compensation tails soft-delete their own Source policy. The
// floor case keeps the original active policy for its later recovery/Claim.
// No policy is reactivated by SQL and no new version/cohort is manufactured.
func PG17ConfirmCompensationOriginal(ctx context.Context, realm *q.Realm, issuer repository.CapacityStore, current model.Manifest, deleted model.CapacityMutationProof) (model.CapacityMutationGrant, error) {
	id, _, err := pg17CompensationIdentity(ctx, realm, issuer, current)
	if err != nil {
		return model.CapacityMutationGrant{}, err
	}
	if id == 5 {
		return issuer.ConfirmCompensation(ctx, current, deleted)
	}
	actual, err := repository.GetManifestByID(ctx, issuer.DB, current.ID)
	if err != nil {
		return model.CapacityMutationGrant{}, err
	}
	if !actual.Metadata.Active || actual.ID != current.ID || actual.Checksum != current.Checksum || actual.Kind != current.Kind || !reflect.DeepEqual(actual.Spec, current.Spec) || !reflect.DeepEqual(actual.Metadata, current.Metadata) {
		return model.CapacityMutationGrant{}, errors.New("pg17 active exact original policy required before first confirmation")
	}
	var raw []byte
	if err = issuer.DB.QueryRowContext(ctx, `SELECT grant_record FROM public.capacity_mutation_grants WHERE id=$1 AND namespace=$2`, deleted.GrantID, current.Metadata.Namespace).Scan(&raw); err != nil {
		return model.CapacityMutationGrant{}, err
	}
	var record struct {
		Grant      model.CapacityMutationGrant          `json:"grant"`
		Settlement *model.CapacityMutationSettleRequest `json:"settlement"`
		Proof      *model.CapacityMutationProof         `json:"proof"`
	}
	if json.Unmarshal(raw, &record) != nil || record.Grant.GrantID != deleted.GrantID || record.Grant.State != "settled" || record.Grant.CompensationOf == "" || record.Settlement == nil || record.Proof != nil {
		return model.CapacityMutationGrant{}, errors.New("pg17 actual settled and never-confirmed compensation child required")
	}
	n, err := repository.MarkManifestInactiveByID(ctx, issuer.DB, current.ID)
	if err != nil {
		return model.CapacityMutationGrant{}, err
	}
	if n != 1 {
		return model.CapacityMutationGrant{}, errors.New("pg17 exactly one active Source policy must become inactive")
	}
	inactive, err := repository.GetManifestByID(ctx, issuer.DB, current.ID)
	if err != nil {
		return model.CapacityMutationGrant{}, err
	}
	expected := actual
	expected.Metadata.Active = false
	expected.UpdatedAt = inactive.UpdatedAt
	if !reflect.DeepEqual(expected, inactive) {
		return model.CapacityMutationGrant{}, errors.New("pg17 policy soft-delete changed original specification or identity")
	}
	paused := issuer
	paused.ExecutionEnabled = false
	confirmed, err := paused.ConfirmCompensation(ctx, current, deleted)
	if err != nil {
		return model.CapacityMutationGrant{}, err
	}
	if confirmed.State != "confirmed" || confirmed.GrantID != deleted.GrantID || confirmed.CompensationOf != record.Grant.CompensationOf {
		return model.CapacityMutationGrant{}, errors.New("pg17 inactive-policy paused first confirmation differs")
	}
	after, err := repository.GetManifestByID(ctx, issuer.DB, current.ID)
	if err != nil {
		return model.CapacityMutationGrant{}, err
	}
	if !reflect.DeepEqual(after, inactive) {
		return model.CapacityMutationGrant{}, errors.New("pg17 historical confirmation mutated inactive policy")
	}
	evidence := pg17FirstConfirmationEvidence{Schema: "pg17_inactive_paused_first_confirmation_v1", Case: realm.Request.NativeCase, PolicyID: current.ID.String(), PolicyChecksum: current.Checksum, ChildID: deleted.GrantID, BeforeState: "settled", AfterState: "confirmed", PolicyInactive: true, ProcessPaused: true, BeforeChildSHA256: capacity.BusinessCreationSHA256(raw), InactivePolicySHA256: capacity.GuestRetirementSHA(inactive), ConfirmedSHA256: capacity.GuestRetirementSHA(confirmed)}
	if _, err = q.Publish(ctx, realm.PrivateDirectory+"/pg17-inactive-paused-first-confirmation.json", evidence); err != nil {
		return model.CapacityMutationGrant{}, err
	}
	return confirmed, nil
}

type pg17FirstConfirmationEvidence struct {
	Schema               string `json:"schema"`
	Case                 string `json:"case"`
	PolicyID             string `json:"policy_id"`
	PolicyChecksum       string `json:"policy_checksum"`
	ChildID              string `json:"child_id"`
	BeforeState          string `json:"before_state"`
	AfterState           string `json:"after_state"`
	PolicyInactive       bool   `json:"policy_inactive"`
	ProcessPaused        bool   `json:"process_paused"`
	BeforeChildSHA256    string `json:"before_child_sha256"`
	InactivePolicySHA256 string `json:"inactive_policy_sha256"`
	ConfirmedSHA256      string `json:"confirmed_sha256"`
}
