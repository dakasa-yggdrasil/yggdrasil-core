//go:build linux && nativequalification

package main

import (
	"context"
	"database/sql"
	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	q "github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacitynativeqemu"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	"net/http"
	"path/filepath"
	"time"
)

func (f *fixture) sourceClient(slot int) (*capacity.GuestOriginalHTTPClient, error) {
	for _, member := range f.binding.Members {
		if member.Slot == slot {
			return capacity.NewGuestOriginalHTTPClient(member, f.caPEM, f.callerCertificate, f.callerKey)
		}
	}
	return nil, q.ErrOriginalUnknown
}
func (f *fixture) finishExpectedOriginalHold(ctx context.Context, p model.CapacityPolicySpec, baseline, burst model.WorkflowRunRecord, runIDs []string, returns []originalPublicReturn) error {
	if q.PositiveCase(f.request.NativeCase) || baseline.Status != "succeeded" || burst.Status != "failed" {
		return q.ErrOriginalUnknown
	}
	pre, err := f.realm.OriginalPreregistration(2)
	if err != nil {
		return err
	}
	var witness model.CapacityGuestOriginalCreateWitness
	var witnessWire []byte
	if err = f.db.QueryRowContext(ctx, `SELECT original_wire FROM public.capacity_guest_original_create_witnesses WHERE preregistration_id=$1`, pre.PreregistrationID).Scan(&witnessWire); err != nil || capacity.DecodeGuestLifecycle(witnessWire, &witness) != nil {
		return q.ErrOriginalUnknown
	}
	client, err := f.sourceClient(2)
	if err != nil {
		return err
	}
	defer client.Close()
	timer := time.NewTicker(100 * time.Millisecond)
	defer timer.Stop()
	var record q.QualificationFailureRecord
	var raw []byte
	// Failed workflow/expired lease does not close a child owner. Keep the
	// SAME original 600 context and read its signed diagnostic after Wait and
	// both EOF/Close owners actually return, possibly after its 420 deadline.
	for {
		read, cancel := context.WithTimeout(ctx, 5*time.Second)
		returned, callErr := client.Original(read, http.MethodGet, "/v1/qualification-source-refusal", []byte("{}"))
		cancel()
		if callErr == nil && returned.Status == http.StatusOK {
			if capacity.GuestOriginalHTTPDecode(returned, &record) != nil || f.realm.ValidateOriginalFailure(record, pre, witness, f.binding.ProvisionerPublicKey, returned.DriverReturnedAt) != nil {
				return q.ErrOriginalUnknown
			}
			raw = returned.Body
			break
		}
		if returned.Status != http.StatusConflict && callErr == nil {
			return q.ErrOriginalUnknown
		}
		select {
		case <-ctx.Done():
			return q.ErrOriginalUnknown
		case <-timer.C:
		}
	}
	store := repository.CapacityStore{DB: f.db, WorkflowID: f.workflow.ID}
	if err = store.RecordGuestQualificationSourceReturn(ctx, pre.PreregistrationID, "source_refusal", raw); err != nil {
		return err
	}
	if _, err = q.PublishBytes(ctx, filepath.Join(q.SlotDirectory(f.private, 2), "core-original-failed-owner-diagnostic.json"), raw); err != nil {
		return err
	}
	for slot := 1; slot <= 2; slot++ {
		fresh, err := f.realm.FreshOriginalNative(ctx, slot)
		if err != nil {
			return err
		}
		fresh.OriginalCreatorSHA256, err = q.FileSHA(ctx, filepath.Join(q.SlotDirectory(f.private, slot), "creator-original.json"), 2<<20)
		if err != nil {
			return err
		}
		freshWire, publishErr := q.Publish(ctx, filepath.Join(q.SlotDirectory(f.private, slot), "core-original-expected-hold-native-alive.json"), fresh)
		if publishErr != nil {
			return publishErr
		}
		originalPre, loadErr := f.realm.OriginalPreregistration(slot)
		if loadErr != nil {
			return loadErr
		}
		if err = store.RecordGuestQualificationSourceReturn(ctx, originalPre.PreregistrationID, "diagnostic_native_read", freshWire); err != nil {
			return err
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
	// Diagnostic echo remains observational. It cannot refresh the failed
	// epoch's capacity phase, useful-floor row, admission, grant or noStart.
	var forbidden int
	if err = f.db.QueryRowContext(ctx, `SELECT count(*) FROM public.capacity_vm_retirement_intents WHERE preregistration_id=$1`, pre.PreregistrationID).Scan(&forbidden); err != nil || (f.request.NativeCase == "held_ack_after_owned_original_deadline" && forbidden != 1) || (f.request.NativeCase != "held_ack_after_owned_original_deadline" && forbidden != 0) {
		return q.ErrOriginalUnknown
	}
	if err = f.db.QueryRowContext(ctx, `SELECT count(*) FROM public.capacity_mutation_grants WHERE grant_record->>'policy_id'=$1 AND grant_record->'grant'->>'capability'='destroy_server'`, f.policy.ID.String()).Scan(&forbidden); err != nil || forbidden != 0 {
		return q.ErrOriginalUnknown
	}
	corpus, err := f.originalCorpus(ctx, runIDs)
	if err != nil {
		return err
	}
	corpus.CaseOutcome = "ORIGINAL_EXPECTED_HOLD_OWNERS_JOINED"
	corpus.FailedOwnerDiagnosticSHA256 = capacity.BusinessCreationSHA256(raw)
	if f.request.NativeCase == "held_ack_after_owned_original_deadline" {
		failed := &q.CorpusFailedRetirementAttempt{}
		if err = f.db.QueryRowContext(ctx, `SELECT i.id::text,i.intent_sha256,c.return_sha256 FROM public.capacity_vm_retirement_intents i JOIN public.capacity_guest_original_caller_returns c ON c.intent_id=i.id WHERE i.preregistration_id=$1`, pre.PreregistrationID).Scan(&failed.RequestID, &failed.IntentSHA256, &failed.CallerReturnSHA256); err != nil {
			return err
		}
		corpus.FailedRetirementAttempt = failed
	}
	corpus.BaselineServingProbeSHA256 = capacity.GuestRetirementSHA(useful)
	return f.retainOriginalCorpus(ctx, corpus, returns)
}

func (f *fixture) originalCorpus(ctx context.Context, runs []string) (q.Corpus, error) {
	corpus := q.Corpus{Schema: "core_original_guest_native_qemu_corpus_v1", ActualCoreSourceCommit: capacity.CurrentGuestCoreSource(), GuestSourceCommit: f.request.SourceCommit, NativeCase: f.request.NativeCase, PolicyID: f.policy.ID.String(), PolicyChecksum: f.policy.Checksum, WorkflowID: f.workflow.ID.String(), WorkflowChecksum: f.workflow.Checksum, Namespace: f.namespace, ProfileManifestSHA256: f.binding.ProfileManifestSHA256, OriginalRunIDs: runs, OriginalPreregistrationIDs: []string{}, NativeResources: []q.CorpusResource{}}
	for slot := 1; slot <= 2; slot++ {
		pre, err := f.realm.OriginalPreregistration(slot)
		if err != nil {
			return corpus, err
		}
		corpus.OriginalPreregistrationIDs = append(corpus.OriginalPreregistrationIDs, pre.PreregistrationID)
		var wire []byte
		var digest string
		if err = f.db.QueryRowContext(ctx, `SELECT original_wire,return_sha256 FROM public.capacity_guest_qualification_native_source_returns WHERE preregistration_id=$1 AND native_stage='native_read'`, pre.PreregistrationID).Scan(&wire, &digest); err != nil {
			return corpus, err
		}
		var native q.IndependentReturn
		if capacity.DecodeGuestLifecycle(wire, &native) != nil || capacity.BusinessCreationSHA256(wire) != digest {
			return corpus, q.ErrOriginalUnknown
		}
		resource := q.CorpusResource{Slot: slot, ResourceID: native.Original.ResourceID, ResourceCreatedAt: native.Original.OriginalCreateReturnedAt.UTC().Format(time.RFC3339Nano), CreatorOriginalSHA256: native.OriginalCreatorSHA256, CoreNativeOriginalReadSHA256: digest}
		var enrollmentWire []byte
		err = f.db.QueryRowContext(ctx, `SELECT receipt_wire,original_provisioning_sha256,enrollment_sha256 FROM public.capacity_vm_original_enrollments WHERE preregistration_id=$1`, pre.PreregistrationID).Scan(&enrollmentWire, &resource.RegistrationSHA256, &resource.EnrollmentSHA256)
		if err != nil && err != sql.ErrNoRows {
			return corpus, err
		}
		if err == nil {
			var receipt model.CapacityGuestOriginalProvisioningReceipt
			if capacity.DecodeGuestLifecycle(enrollmentWire, &receipt) != nil || capacity.GuestRetirementSHA(receipt.Enrollment) != resource.EnrollmentSHA256 || receipt.OriginalProvisioningSHA256 != resource.RegistrationSHA256 {
				return corpus, q.ErrOriginalUnknown
			}
		}
		err = f.db.QueryRowContext(ctx, `SELECT return_sha256 FROM public.capacity_guest_qualification_native_source_returns WHERE preregistration_id=$1 AND native_stage='serving_probe' ORDER BY recorded_at DESC LIMIT 1`, pre.PreregistrationID).Scan(&resource.ServingProbeSHA256)
		if err != nil && err != sql.ErrNoRows {
			return corpus, err
		}
		corpus.NativeResources = append(corpus.NativeResources, resource)
		if !q.PositiveCase(f.request.NativeCase) {
			if err = f.db.QueryRowContext(ctx, `SELECT return_sha256 FROM public.capacity_guest_qualification_native_source_returns WHERE preregistration_id=$1 AND native_stage='diagnostic_native_read'`, pre.PreregistrationID).Scan(&corpus.NativeResources[len(corpus.NativeResources)-1].NativeDiagnosticAfterSHA256); err != nil {
				return corpus, err
			}
		}
	}
	return corpus, nil
}

func queryOriginalStrings(ctx context.Context, db *sql.DB, query string, arg any) ([]string, error) {
	rows, err := db.QueryContext(ctx, query, arg)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []string{}
	for rows.Next() {
		var value string
		if err = rows.Scan(&value); err != nil {
			return nil, err
		}
		result = append(result, value)
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	return result, rows.Close()
}
func (f *fixture) finishActualOriginalCorpus(ctx context.Context, p model.CapacityPolicySpec, runIDs []string, returns []originalPublicReturn) error {
	if !q.PositiveCase(f.request.NativeCase) {
		return q.ErrOriginalUnknown
	}
	corpus, err := f.originalCorpus(ctx, runIDs)
	if err != nil {
		return err
	}
	corpus.CaseOutcome = "ORIGINAL_PROTECTED_LIFECYCLE_JOINED"
	retired := &q.CorpusRetirement{}
	if err = f.db.QueryRowContext(ctx, `SELECT id::text,intent_sha256 FROM public.capacity_vm_retirement_intents WHERE preregistration_id=$1`, corpus.OriginalPreregistrationIDs[1]).Scan(&retired.RequestID, &retired.IntentSHA256); err != nil {
		return err
	}
	retired.OriginalRecordSHA256s, err = queryOriginalStrings(ctx, f.db, `SELECT return_sha256 FROM public.capacity_vm_retirement_original_returns WHERE intent_id=$1 ORDER BY sequence`, retired.RequestID)
	if err != nil || len(retired.OriginalRecordSHA256s) != 4 {
		return q.ErrOriginalUnknown
	}
	retired.SnapshotChallengeSHA256s, err = queryOriginalStrings(ctx, f.db, `SELECT challenge_sha256 FROM public.capacity_guest_runtime_snapshot_challenges WHERE intent_id=$1 AND phase='before_start' ORDER BY ordinal`, retired.RequestID)
	if err != nil || len(retired.SnapshotChallengeSHA256s) != 2 {
		return q.ErrOriginalUnknown
	}
	retired.AuthorityReadIDs, err = queryOriginalStrings(ctx, f.db, `SELECT id::text FROM public.capacity_guest_original_authority_reads WHERE intent_id=$1 ORDER BY CASE phase WHEN 'before_start' THEN 0 ELSE 1 END,ordinal`, retired.RequestID)
	if err != nil || len(retired.AuthorityReadIDs) != 4 {
		return q.ErrOriginalUnknown
	}
	if err = f.db.QueryRowContext(ctx, `SELECT count(*) FROM public.capacity_guest_original_authority_transport_returns t JOIN public.capacity_guest_original_authority_reads r ON r.id=t.read_id WHERE r.intent_id=$1`, retired.RequestID).Scan(&retired.AuthorityTransportReturnCount); err != nil || retired.AuthorityTransportReturnCount != 5 {
		return q.ErrOriginalUnknown
	}
	if err = f.db.QueryRowContext(ctx, `SELECT return_sha256 FROM public.capacity_guest_original_caller_returns WHERE intent_id=$1`, retired.RequestID).Scan(&retired.CallerReturnSHA256); err != nil {
		return err
	}
	if err = f.db.QueryRowContext(ctx, `SELECT observation_sha256 FROM public.capacity_guest_original_native_poweroff_reads WHERE intent_id=$1`, retired.RequestID).Scan(&retired.NativeOffReturnSHA256); err != nil {
		return err
	}
	if err = f.db.QueryRowContext(ctx, `SELECT destroy_grant_id::text FROM public.capacity_vm_retirement_delete_bindings WHERE intent_id=$1`, retired.RequestID).Scan(&retired.DestroyGrantID); err != nil {
		return err
	}
	if err = f.db.QueryRowContext(ctx, `SELECT observation_sha256 FROM public.capacity_vm_retirement_native_readbacks WHERE destroy_grant_id=$1`, retired.DestroyGrantID).Scan(&retired.NativeDeleteReadbackSHA256); err != nil {
		return err
	}
	corpus.BurstRetirement = retired
	corpus.BaselineServingProbeSHA256 = corpus.NativeResources[0].ServingProbeSHA256
	var live, deleted int
	if err = f.db.QueryRowContext(ctx, `SELECT count(*) FILTER(WHERE resource_id<>''),count(*) FILTER(WHERE resource_id='' AND slot=2) FROM public.capacity_resource_slots WHERE namespace=$1`, f.namespace).Scan(&live, &deleted); err != nil || live != 1 || deleted != 1 {
		return q.ErrOriginalUnknown
	}
	if _, err = f.realm.FreshOriginalNative(ctx, 1); err != nil {
		return err
	}
	return f.retainOriginalCorpus(ctx, corpus, returns)
}

func (f *fixture) retainOriginalCorpus(ctx context.Context, corpus q.Corpus, returns []originalPublicReturn) error {
	requestID := ""
	if corpus.BurstRetirement != nil {
		requestID = corpus.BurstRetirement.RequestID
	}
	if corpus.FailedRetirementAttempt != nil {
		requestID = corpus.FailedRetirementAttempt.RequestID
	}
	if requestID != "" {
		if err := f.exportOriginalRetirementProjections(ctx, requestID); err != nil {
			return err
		}
	}
	if _, err := q.Publish(ctx, filepath.Join(f.private, "core-original-public-caller-returns.json"), f.publicReturns); err != nil {
		return err
	}
	wire, err := q.Publish(ctx, filepath.Join(f.private, "original-native-corpus-receipt.json"), corpus)
	if err != nil {
		return err
	}
	f.completed = q.SourceCaseStage{Schema: q.FixtureSchema, Stage: "original-native-caller-completed.json", NativeCase: corpus.NativeCase, CaseOutcome: corpus.CaseOutcome, NativeCorpusReceiptSHA256: capacity.BusinessCreationSHA256(wire)}
	return nil
}
