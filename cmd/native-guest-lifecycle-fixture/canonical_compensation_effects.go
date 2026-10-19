//go:build linux && nativequalification

package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	message "github.com/dakasa-yggdrasil/yggdrasil-core/controllers/message"
	"net/http"
	"path/filepath"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	q "github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacitynativeqemu"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
)

// Runs inside the SAME original fixture, never a provider or production API.
// It preserves accepted/uncertain create transport and never fabricates a
// positive enrollment for an uncertain reply. The frontend owns its actual
// child, original Wait and pipe owners; signed source authority is durable
// BEFORE any separately labelled host cleanup action.
func (f *fixture) finishOriginalCanonicalSourceCompensation(ctx context.Context, p model.CapacityPolicySpec, baseline, burst model.WorkflowRunRecord, runIDs []string, returns []originalPublicReturn) error {
	if !q.CanonicalSourceCompensationCase(f.request.NativeCase) || q.SourceLostCreateCase(f.request.NativeCase) || baseline.Status != "succeeded" || burst.Status != "failed" || p.Ceiling != 2 || p.Floor < 1 || p.Floor > 2 {
		return q.ErrOriginalUnknown
	}
	pre, err := f.realm.OriginalPreregistration(2)
	if err != nil {
		return err
	}
	store := repository.CapacityStore{DB: f.db, WorkflowID: f.workflow.ID}
	failureSHA, enrollmentSHA := "", ""
	if !q.SourceLostCreateCase(f.request.NativeCase) {
		var witness model.CapacityGuestOriginalCreateWitness
		var wire []byte
		if err = f.db.QueryRowContext(ctx, `SELECT original_wire FROM public.capacity_guest_original_create_witnesses WHERE preregistration_id=$1`, pre.PreregistrationID).Scan(&wire); err != nil || capacity.DecodeGuestLifecycle(wire, &witness) != nil {
			return q.ErrOriginalUnknown
		}
		client, err := f.sourceClient(2)
		if err != nil {
			return err
		}
		defer client.Close()
		for {
			read, cancel := context.WithTimeout(ctx, 5*time.Second)
			returned, callErr := client.Original(read, http.MethodGet, "/v1/qualification-source-refusal", []byte("{}"))
			cancel()
			if callErr == nil && returned.Status == 200 {
				var failed q.QualificationFailureRecord
				if capacity.GuestOriginalHTTPDecode(returned, &failed) != nil || f.realm.ValidateOriginalFailure(failed, pre, witness, f.binding.ProvisionerPublicKey, returned.DriverReturnedAt) != nil {
					return q.ErrOriginalUnknown
				}
				if err = store.RecordGuestQualificationSourceReturn(ctx, pre.PreregistrationID, "source_refusal", returned.Body); err != nil {
					return err
				}
				failureSHA = capacity.BusinessCreationSHA256(returned.Body)
				if _, err = q.PublishBytes(ctx, filepath.Join(q.SlotDirectory(f.private, 2), "core-original-failed-owner-diagnostic.json"), returned.Body); err != nil {
					return err
				}
				break
			}
			if ctx.Err() != nil || (callErr == nil && returned.Status != 409) {
				return q.ErrOriginalUnknown
			}
			select {
			case <-ctx.Done():
				return q.ErrOriginalUnknown
			case <-time.After(20 * time.Millisecond):
			}
		}
		if err = f.db.QueryRowContext(ctx, `SELECT enrollment_sha256 FROM public.capacity_vm_original_enrollments WHERE preregistration_id=$1`, pre.PreregistrationID).Scan(&enrollmentSHA); err != nil {
			return err
		}
	} else {
		var enrolled int
		if err = f.db.QueryRowContext(ctx, `SELECT count(*) FROM public.capacity_vm_original_enrollments WHERE preregistration_id=$1`, pre.PreregistrationID).Scan(&enrolled); err != nil || enrolled != 0 {
			return q.ErrOriginalUnknown
		}
	}
	baselineClient, err := f.sourceClient(1)
	if err != nil {
		return err
	}
	defer baselineClient.Close()
	useful, err := f.realm.DiagnosticProbe(ctx, store, 1, f.corePrivate, baselineClient)
	if err != nil {
		return err
	}
	if err = f.prepareOriginalRecoveryCleanupChronology(ctx, p, pre); err != nil {
		return err
	}
	recoverySession, err := f.realm.OriginalRecoveryCleanupSession(ctx)
	if err != nil {
		return err
	}
	store = recoverySession.Store
	authority, body, err := f.realm.PrepareSourceRecoveryFailureCleanup(ctx, store, f.policy, pre, failureSHA, enrollmentSHA, f.corePrivate)
	if err != nil {
		return err
	}
	// Source-scoped table is constructed by this exact nativequalification
	// fixture only. Ordinary production grants/registry are not modified.
	_, err = f.db.ExecContext(ctx, `CREATE TABLE public.capacity_source_failure_cleanup_originals(parent_grant_id uuid PRIMARY KEY,authority_id uuid UNIQUE NOT NULL,namespace text NOT NULL,authority_wire bytea NOT NULL,authority_sha256 text NOT NULL); CREATE TABLE public.capacity_source_failure_cleanup_physical(parent_grant_id uuid PRIMARY KEY REFERENCES public.capacity_source_failure_cleanup_originals(parent_grant_id),physical_wire bytea NOT NULL,physical_sha256 text NOT NULL); CREATE TABLE public.capacity_source_failure_cleanup_terminals(parent_grant_id uuid PRIMARY KEY REFERENCES public.capacity_source_failure_cleanup_physical(parent_grant_id),terminal_wire bytea NOT NULL); CREATE TABLE public.capacity_source_failure_cleanup_reads(read_id uuid PRIMARY KEY,parent_grant_id uuid NOT NULL REFERENCES public.capacity_source_failure_cleanup_terminals(parent_grant_id),generation bigint NOT NULL,fencing_token bigint NOT NULL,read_wire bytea NOT NULL,read_sha256 text NOT NULL UNIQUE,UNIQUE(parent_grant_id,generation,fencing_token)); CREATE FUNCTION public.source_cleanup_original_immutable() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'immutable source cleanup original'; END $$; CREATE TRIGGER immutable_source_cleanup_authority BEFORE UPDATE OR DELETE ON public.capacity_source_failure_cleanup_originals FOR EACH ROW EXECUTE FUNCTION public.source_cleanup_original_immutable(); CREATE TRIGGER immutable_source_cleanup_physical BEFORE UPDATE OR DELETE ON public.capacity_source_failure_cleanup_physical FOR EACH ROW EXECUTE FUNCTION public.source_cleanup_original_immutable(); CREATE TRIGGER immutable_source_cleanup_reads BEFORE UPDATE OR DELETE ON public.capacity_source_failure_cleanup_reads FOR EACH ROW EXECUTE FUNCTION public.source_cleanup_original_immutable(); CREATE TRIGGER immutable_source_cleanup_terminal BEFORE UPDATE OR DELETE ON public.capacity_source_failure_cleanup_terminals FOR EACH ROW EXECUTE FUNCTION public.source_cleanup_original_immutable()`)
	if err != nil {
		return err
	}
	authorityWire, err := json.Marshal(authority)
	if err != nil {
		return err
	}
	inserted, err := f.db.ExecContext(ctx, `INSERT INTO public.capacity_source_failure_cleanup_originals(parent_grant_id,authority_id,namespace,authority_wire,authority_sha256) VALUES($1,$2,$3,$4,$5)`, pre.OriginalCreateGrantID, body.AuthorityID, f.namespace, authorityWire, capacity.BusinessCreationSHA256(authorityWire))
	if err != nil {
		return err
	}
	n, err := inserted.RowsAffected()
	if err != nil || n != 1 {
		return q.ErrOriginalUnknown
	}
	var authorityReadback []byte
	if err = f.db.QueryRowContext(ctx, `SELECT authority_wire FROM public.capacity_source_failure_cleanup_originals WHERE parent_grant_id=$1`, pre.OriginalCreateGrantID).Scan(&authorityReadback); err != nil || !bytes.Equal(authorityReadback, authorityWire) {
		return q.ErrOriginalUnknown
	}
	parentBefore, err := f.realm.OriginalMutationReceipt(ctx, pre.OriginalCreateGrantID)
	if err != nil {
		return err
	}
	issuer, currentPolicy, child, session, err := f.prepareCanonicalSourceChild(ctx, p, pre)
	if err != nil {
		return err
	}
	eligibilityWire, err := issuer.CanonicalSourceEligibilityWire(ctx, pre.OriginalCreateGrantID)
	if err != nil {
		return err
	}
	if _, err = q.PublishBytes(ctx, filepath.Join(f.private, "canonical-source-eligibility.json"), eligibilityWire); err != nil {
		return err
	}
	// Signed actual-child authority precedes the existing Source ready-file.
	if _, err = q.PublishBytes(ctx, filepath.Join(q.SlotDirectory(f.private, 2), "canonical-source-child-authority.json"), session.Authority); err != nil {
		return err
	}
	if _, err = q.PublishBytes(ctx, filepath.Join(q.SlotDirectory(f.private, 2), "source-failure-cleanup-authority.json"), authorityWire); err != nil {
		return err
	}
	physical, err := f.realm.ReadSourceRecoveryFailureCleanup(ctx, authority, body, issuer, currentPolicy, session)
	if err != nil {
		return err
	}
	var retainedPhysical q.SourceFailureCleanupPhysical
	physicalWire, err := q.Await(ctx, filepath.Join(q.SlotDirectory(f.private, 2), "source-failure-cleanup-physical.json"), &retainedPhysical)
	if err != nil || capacity.GuestRetirementSHA(retainedPhysical) != capacity.GuestRetirementSHA(physical) {
		return q.ErrOriginalUnknown
	}
	insertedPhysical, err := f.db.ExecContext(ctx, `INSERT INTO public.capacity_source_failure_cleanup_physical(parent_grant_id,physical_wire,physical_sha256) VALUES($1,$2,$3)`, pre.OriginalCreateGrantID, physicalWire, capacity.BusinessCreationSHA256(physicalWire))
	if err != nil {
		return err
	}
	n, err = insertedPhysical.RowsAffected()
	if err != nil || n != 1 {
		return q.ErrOriginalUnknown
	}
	parent := parentBefore
	if capacity.GuestRetirementSHA(parent) != body.OriginalReceiptSHA256 {
		return q.ErrOriginalUnknown
	}
	var members, failed, events int
	if err = f.db.QueryRowContext(ctx, `SELECT count(*) FILTER(WHERE resource_id<>''),count(*) FILTER(WHERE slot=2 AND resource_id<>'') FROM public.capacity_resource_slots WHERE namespace=$1`, f.namespace).Scan(&members, &failed); err != nil || members != 1 || failed != 0 {
		return q.ErrOriginalUnknown
	}
	if err = f.db.QueryRowContext(ctx, `SELECT count(*) FROM public.event_log WHERE idempotency_key=$1`, "capacity-mutation/"+pre.OriginalCreateGrantID).Scan(&events); err != nil || events != 0 {
		return q.ErrOriginalUnknown
	}
	var parentRaw []byte
	if err = f.db.QueryRowContext(ctx, `SELECT grant_record FROM public.capacity_mutation_grants WHERE id=$1`, pre.OriginalCreateGrantID).Scan(&parentRaw); err != nil {
		return err
	}
	var ownerLease struct {
		Generation   int64  `json:"generation"`
		FencingToken int64  `json:"fencing_token"`
		LeaseOwner   string `json:"lease_owner"`
		ExecutorID   string `json:"executor_id"`
	}
	if err = json.Unmarshal(parentRaw, &ownerLease); err != nil || ownerLease.Generation <= 0 || ownerLease.FencingToken <= 0 || ownerLease.LeaseOwner == "" || ownerLease.ExecutorID == "" {
		return q.ErrOriginalUnknown
	}
	terminal := repository.SourceFailureCleanupTerminal{Schema: "original_source_failure_cleanup_terminal_v1", OriginalGeneration: ownerLease.Generation, OriginalFencingToken: ownerLease.FencingToken, OriginalLeaseOwner: ownerLease.LeaseOwner, OriginalExecutorID: ownerLease.ExecutorID, ParentGrantID: pre.OriginalCreateGrantID, AuthoritySHA256: capacity.GuestRetirementSHA(authority), PhysicalSHA256: capacity.BusinessCreationSHA256(physicalWire), OriginalReceiptSHA256: capacity.GuestRetirementSHA(parent), CoreSource: body.CoreSource, GuestSource: body.GuestSource, SourceTerminal: true, CanonicalParentTerminal: false, ProductionQualified: false, ReturnedAt: time.Now().UTC()}
	terminalBody, err := json.Marshal(terminal)
	if err != nil {
		return err
	}
	signedTerminal := q.SourceFailureCleanupAuthority{Body: terminalBody, Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(f.corePrivate, terminalBody))}
	terminalWire, err := json.Marshal(signedTerminal)
	if err != nil {
		return err
	}
	if _, err = f.db.ExecContext(ctx, `INSERT INTO public.capacity_source_failure_cleanup_terminals(parent_grant_id,terminal_wire) VALUES($1,$2)`, pre.OriginalCreateGrantID, terminalWire); err != nil {
		return err
	}
	if _, err = q.PublishBytes(ctx, filepath.Join(f.private, "source-failure-cleanup-terminal.json"), terminalWire); err != nil {
		return err
	}
	result := struct {
		Schema                  string                                  `json:"schema"`
		NativeCase              string                                  `json:"native_case"`
		CoreSource              string                                  `json:"core_source"`
		GuestSource             string                                  `json:"guest_source"`
		PolicyID                string                                  `json:"policy_id"`
		PolicyChecksum          string                                  `json:"policy_checksum"`
		OriginalRunIDs          []string                                `json:"original_run_ids"`
		Parent                  model.CapacityMutationReceipt           `json:"original_parent_receipt"`
		Authority               q.SourceFailureCleanupAuthority         `json:"source_cleanup_authority"`
		Physical                q.SourceFailureCleanupPhysical          `json:"physical_cleanup"`
		BaselineProbeSHA256     string                                  `json:"baseline_probe_sha256"`
		CanonicalParentTerminal bool                                    `json:"canonical_parent_terminal"`
		SourceTerminal          repository.SourceFailureCleanupTerminal `json:"source_terminal"`
		ProductionQualified     bool                                    `json:"production_qualified"`
		PositiveRetirement      bool                                    `json:"positive_retirement"`
	}{"original_source_compensation_corpus_v1", f.request.NativeCase, capacity.CurrentGuestCoreSource(), f.request.SourceCommit, f.policy.ID.String(), f.policy.Checksum, runIDs, parent, authority, physical, capacity.GuestRetirementSHA(useful), false, terminal, false, false}
	wire, err := q.Publish(ctx, filepath.Join(f.private, "source-original-compensation-result.json"), result)
	if err != nil {
		return err
	}
	if _, err = q.Publish(ctx, filepath.Join(f.private, "core-original-public-caller-returns.json"), returns); err != nil {
		return err
	}
	pg17Pre, pg17Err := message.PG17AssertCompensationPreSettlement(ctx, f.realm, issuer, currentPolicy, child)
	if pg17Err != nil {
		return pg17Err
	}
	if err = message.PG17RetainAssertions(ctx, f.realm, currentPolicy, f.workflow.ID.String(), 0, "compensation-pre-settlement", pg17Pre); err != nil {
		return err
	}
	deleted, apiWire, err := f.realm.SettleCanonicalSourceChild(ctx, issuer, currentPolicy, session)
	if err != nil {
		return err
	}
	confirmed, err := message.PG17ConfirmCompensationOriginal(ctx, f.realm, issuer, currentPolicy, deleted)
	if err != nil || confirmed.State != "confirmed" {
		return q.ErrOriginalUnknown
	}
	if _, err = issuer.ConfirmCompensation(ctx, currentPolicy, deleted); err != nil {
		return err
	}
	after, err := f.realm.OriginalMutationReceipt(ctx, pre.OriginalCreateGrantID)
	if err != nil || after.Grant.State != "compensated" || after.NativeReadback == nil || after.NativeReadback.ResourceID != body.ResourceID {
		return q.ErrOriginalUnknown
	}
	pg17After, pg17AfterErr := message.PG17AssertCompensationAfterConfirm(ctx, f.realm, issuer, currentPolicy, parentBefore, deleted, child)
	if pg17AfterErr != nil {
		return pg17AfterErr
	}
	if err = message.PG17RetainAssertions(ctx, f.realm, currentPolicy, f.workflow.ID.String(), 0, "compensation-confirm", pg17After); err != nil {
		return err
	}
	// Compare all original accepted transport fields; only original grant state
	// and separately appended readback can change through generic Confirm.
	compare := after
	compare.Grant = parentBefore.Grant
	compare.NativeReadback = parentBefore.NativeReadback
	if capacity.GuestRetirementSHA(compare) != capacity.GuestRetirementSHA(parentBefore) {
		return q.ErrOriginalUnknown
	}
	afterWire, err := q.Publish(ctx, filepath.Join(f.private, "canonical-source-parent-receipt-after.json"), after)
	if err != nil {
		return err
	}
	deletedWire, err := q.Publish(ctx, filepath.Join(f.private, "canonical-source-deleted-proof.json"), deleted)
	if err != nil {
		return err
	}
	if err = f.db.QueryRowContext(ctx, `SELECT count(*) FILTER(WHERE resource_id<>''),count(*) FILTER(WHERE slot=2 AND resource_id<>'') FROM public.capacity_resource_slots WHERE namespace=$1`, f.namespace).Scan(&members, &failed); err != nil || members != 1 || failed != 0 {
		return q.ErrOriginalUnknown
	}
	var ensured, destroyed int
	if err = f.db.QueryRowContext(ctx, `SELECT count(*) FILTER(WHERE idempotency_key=$2),count(*) FILTER(WHERE idempotency_key=$3) FROM public.event_log WHERE metadata->>'namespace'=$1`, f.namespace, "capacity-mutation/"+pre.OriginalCreateGrantID, "capacity-mutation/"+child.GrantID).Scan(&ensured, &destroyed); err != nil || ensured != 0 || destroyed != 1 {
		return q.ErrOriginalUnknown
	}
	contract := map[string]any{"schema": "canonical_source_compensation_result_v2", "scope": "SOURCE_ONLY_ACTUAL_CHILD_OWNED_CLEANUP_AND_GENERIC_CONFIRM_NOT_POSITIVE_QUIESCENCE", "case": f.request.NativeCase, "core_source": body.CoreSource, "guest_source": body.GuestSource, "parent_grant_id": pre.OriginalCreateGrantID, "child_grant_id": child.GrantID, "parent_state": "compensated", "child_state": "confirmed", "original_parent_receipt_sha256": body.OriginalReceiptSHA256, "failure_sha256": failureSHA, "eligibility_sha256": capacity.BusinessCreationSHA256(eligibilityWire), "child_authority_sha256": capacity.BusinessCreationSHA256(session.Authority), "physical_sha256": capacity.BusinessCreationSHA256(physicalWire), "api_returns_sha256": capacity.BusinessCreationSHA256(apiWire), "deleted_proof_sha256": capacity.BusinessCreationSHA256(deletedWire), "parent_receipt_after_sha256": capacity.BusinessCreationSHA256(afterWire), "current_policy_id": currentPolicy.ID.String(), "current_policy_checksum": currentPolicy.Checksum, "original_policy_id": f.policy.ID.String(), "baseline_members": members, "failed_slot_members": failed, "destroyed_events": destroyed, "ensured_events": ensured, "parent_settlement_unchanged": true, "physical_effect_owned_by_child": true, "generic_confirmed": true, "production_qualified": false, "native_qualified": false}
	contractWire, err := q.Publish(ctx, filepath.Join(f.private, "canonical-source-compensation-result.json"), contract)
	if err != nil {
		return err
	}
	if f.request.NativeCase != "canonical_failed_floor_recovery" {
		if err = f.finishOriginalKnownRecoveryTerminal(ctx, p, pre); err != nil {
			return err
		}
	}
	f.completed = q.SourceCaseStage{Schema: q.FixtureSchema, Stage: "original-native-caller-completed.json", NativeCase: f.request.NativeCase, CaseOutcome: "CANONICAL_RECOVERY_FAILED_OWNER_CHILD_CLEANUP_AND_CONFIRM_COMPLETE", NativeCorpusReceiptSHA256: capacity.BusinessCreationSHA256(contractWire)}
	_ = wire
	return nil
}
