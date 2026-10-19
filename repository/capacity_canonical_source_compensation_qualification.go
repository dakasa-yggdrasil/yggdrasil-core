//go:build linux && nativequalification

package repository

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"reflect"
	"time"
)

type QualificationFailedOwnerReturn struct {
	OriginalReturnedAt time.Time `json:"original_returned_at"`
	OriginalBodySHA256 string    `json:"original_body_sha256"`
	OriginalBodyBytes  int       `json:"original_body_bytes"`
	ErrorClass         string    `json:"error_class"`
}
type QualificationProvisioningRecordRead struct {
	Sequence                int       `json:"sequence"`
	OriginalRecordSHA256    string    `json:"original_record_sha256"`
	OriginalReadReturnedAt  time.Time `json:"original_read_returned_at"`
	OriginalCloseReturnedAt time.Time `json:"original_close_returned_at"`
}
type QualificationProvisioningJournalRead struct {
	LastSequence            int                                   `json:"last_sequence"`
	LastState               string                                `json:"last_state"`
	LastRecordSHA256        string                                `json:"last_record_sha256"`
	EnrollmentSHA256        string                                `json:"enrollment_sha256"`
	AdmissionPossible       bool                                  `json:"admission_possible"`
	AdmissionWriteReturned  bool                                  `json:"admission_write_returned"`
	OriginalReadStartedAt   time.Time                             `json:"original_read_started_at"`
	OriginalReadReturnedAt  time.Time                             `json:"original_read_returned_at"`
	OriginalCloseReturnedAt time.Time                             `json:"original_close_returned_at"`
	Records                 []QualificationProvisioningRecordRead `json:"records"`
}
type CanonicalPayloadPreparation struct {
	Schema                  string    `json:"schema"`
	ActionID                string    `json:"action_id"`
	SessionNonceSHA256      string    `json:"session_nonce_sha256"`
	PreregistrationID       string    `json:"preregistration_id"`
	ParentGrantID           string    `json:"parent_grant_id"`
	CreateWitnessSHA256     string    `json:"create_witness_sha256"`
	GuestSource             string    `json:"guest_source"`
	PreparedAt              time.Time `json:"prepared_at"`
	OriginalWriteReturnedAt time.Time `json:"original_write_returned_at"`
	OriginalReadReturnedAt  time.Time `json:"original_read_returned_at"`
	OriginalBodySHA256      string    `json:"original_body_sha256"`
}
type QualificationFailureRecord struct {
	OriginalPayloadPreparation        *CanonicalPayloadPreparation                  `json:"original_payload_preparation,omitempty"`
	OriginalPayloadActionID           string                                        `json:"original_payload_action_id,omitempty"`
	OriginalPayloadSessionNonceSHA256 string                                        `json:"original_payload_session_nonce_sha256,omitempty"`
	Schema                            string                                        `json:"schema"`
	NativeCase                        string                                        `json:"native_case"`
	SourceCommit                      string                                        `json:"source_commit"`
	Scope                             string                                        `json:"scope"`
	Phase                             string                                        `json:"phase"`
	Tuple                             model.CapacityGuestNativeTuple                `json:"tuple"`
	PreregistrationID                 string                                        `json:"preregistration_id"`
	OriginalCreateWitnessSHA256       string                                        `json:"original_create_witness_sha256"`
	OriginalProvisioningDeadline      time.Time                                     `json:"original_provisioning_deadline"`
	OriginalOperationDeadline         time.Time                                     `json:"original_operation_deadline"`
	Runtime                           model.CapacityGuestRetirementLifetime         `json:"runtime"`
	OriginalChild                     model.CapacityGuestRetirementNativeProcess    `json:"original_child"`
	OriginalStartCalledAt             time.Time                                     `json:"original_start_called_at"`
	OriginalStartReturnedAt           time.Time                                     `json:"original_start_returned_at"`
	OriginalWait                      QualificationFailedOwnerReturn                `json:"original_wait"`
	OriginalExitCode                  *int                                          `json:"original_exit_code"`
	OriginalOutputEOF                 *bool                                         `json:"original_output_eof,omitempty"`
	OriginalOutputCloseSucceeded      *bool                                         `json:"original_output_close_succeeded,omitempty"`
	OriginalDiagnosticEOF             *bool                                         `json:"original_diagnostic_eof,omitempty"`
	OriginalDiagnosticCloseSucceeded  *bool                                         `json:"original_diagnostic_close_succeeded,omitempty"`
	OriginalOutputEOFAndClose         QualificationFailedOwnerReturn                `json:"original_output_eof_and_close"`
	OriginalDiagnosticEOFAndClose     QualificationFailedOwnerReturn                `json:"original_diagnostic_eof_and_close"`
	OriginalProbeRead                 *QualificationFailedOwnerReturn               `json:"original_probe_read,omitempty"`
	ProvisioningJournal               *QualificationProvisioningJournalRead         `json:"provisioning_journal,omitempty"`
	CensusAfter                       *model.CapacityGuestRetirementProtectedCensus `json:"census_after,omitempty"`
	NativeCensusErrorClass            string                                        `json:"native_census_error_class"`
	RecordedAt                        time.Time                                     `json:"recorded_at"`
	ProducerPublicKey                 string                                        `json:"producer_public_key"`
	Signature                         string                                        `json:"signature"`
}

// This distinct qualification contract can close canonical ledger lineage;
// it NEVER reinterprets failure as Guest positive quiescence. Its redeemed
// child owns the sole original physical kill/unlink under a signed cutoff.
type CanonicalSourceAction struct {
	ID             string    `json:"id"`
	Kind           string    `json:"kind"`
	Outcome        string    `json:"outcome"`
	OriginalSHA256 string    `json:"original_sha256"`
	ReturnedAt     time.Time `json:"returned_at"`
}
type CanonicalSourceEligibility struct {
	EligibilityWireSHA256    string                      `json:"-"`
	Schema                   string                      `json:"schema"`
	Scope                    string                      `json:"scope"`
	NativeCase               string                      `json:"native_case"`
	Namespace                string                      `json:"namespace"`
	CoreSource               string                      `json:"core_source"`
	GuestSource              string                      `json:"guest_source"`
	PreregistrationID        string                      `json:"preregistration_id"`
	ParentGrantID            string                      `json:"parent_grant_id"`
	OriginalReceiptSHA256    string                      `json:"original_receipt_sha256"`
	FailureSHA256            string                      `json:"failure_sha256"`
	CleanupAuthoritySHA256   string                      `json:"cleanup_authority_sha256"`
	CleanupTerminalSHA256    string                      `json:"cleanup_terminal_sha256"`
	OriginalNativeReadSHA256 string                      `json:"original_native_read_sha256"`
	Actions                  []CanonicalSourceAction     `json:"actions"`
	Aggregate                model.CapacityMutationProof `json:"aggregate"`
	CreatedAt                time.Time                   `json:"created_at"`
	OriginalDeadline         time.Time                   `json:"original_deadline"`
	ChildOwnsPhysicalEffects bool                        `json:"child_owns_physical_effects"`
	PositiveQuiescence       bool                        `json:"positive_quiescence"`
	ProductionQualified      bool                        `json:"production_qualified"`
}
type CanonicalSourceAbsenceRead struct {
	Schema              string                          `json:"schema"`
	Scope               string                          `json:"scope"`
	ChildGrantID        string                          `json:"child_grant_id"`
	ParentGrantID       string                          `json:"parent_grant_id"`
	RequestSHA256       string                          `json:"request_sha256"`
	EligibilitySHA256   string                          `json:"eligibility_sha256"`
	ActionID            string                          `json:"action_id"`
	Read                SourceFailureCleanupCurrentRead `json:"read"`
	Proof               model.CapacityMutationProof     `json:"proof"`
	ProductionQualified bool                            `json:"production_qualified"`
}

func canonicalKnownFailedCase(c string) bool {
	return canonicalPostlossCase(c) || c == "canonical_compensation_unprotected_failed_create" || c == "canonical_compensation_protected_failed_create" || c == "canonical_failed_floor_recovery"
}
func canonicalSignedBody(ctx context.Context, s CapacityStore, stored guestOriginalStored, wire []byte) ([]byte, error) {
	var signed SourceFailureCleanupAuthority
	if capacity.DecodeGuestLifecycle(wire, &signed) != nil {
		return nil, ErrCapacityConflict
	}
	resolved, err := ResolveSecretRef(ctx, s.DB, stored.binding.IntentSigningKeyRef)
	if err != nil {
		return nil, err
	}
	encoded, ok := resolved.(string)
	if !ok {
		return nil, ErrCapacityConflict
	}
	key, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil || len(key) != ed25519.PrivateKeySize {
		return nil, ErrCapacityConflict
	}
	sig, err := base64.StdEncoding.DecodeString(signed.Signature)
	if err != nil || !ed25519.Verify(ed25519.PrivateKey(key).Public().(ed25519.PublicKey), signed.Body, sig) {
		return nil, ErrCapacityConflict
	}
	return signed.Body, nil
}
func canonicalSign(ctx context.Context, s CapacityStore, stored guestOriginalStored, value any) ([]byte, error) {
	resolved, err := ResolveSecretRef(ctx, s.DB, stored.binding.IntentSigningKeyRef)
	if err != nil {
		return nil, err
	}
	encoded, ok := resolved.(string)
	if !ok {
		return nil, ErrCapacityConflict
	}
	key, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil || len(key) != ed25519.PrivateKeySize {
		return nil, ErrCapacityConflict
	}
	body, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	return json.Marshal(SourceFailureCleanupAuthority{Body: body, Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(ed25519.PrivateKey(key), body))})
}
func canonicalCleanupHistory(ctx context.Context, s CapacityStore, tx *sql.Tx, preID string) (guestOriginalStored, SourceFailureCleanupBody, SourceFailureCleanupTerminal, error) {
	var b SourceFailureCleanupBody
	var t SourceFailureCleanupTerminal
	stored, err := loadGuestOriginalTx(ctx, tx, preID)
	if err != nil {
		return stored, b, t, err
	}
	if stored.binding.EvidenceClass != "native_qemu_qualification" || stored.binding.ProfileManifest.Profile != "qualification-original-echo-writer-v1" || stored.binding.CoreAuthoritySourceCommit != capacity.CurrentGuestCoreSource() || stored.pre.OriginalWorkflowStepTimeoutSeconds != 600 {
		return stored, b, t, ErrCapacityDisabled
	}
	var aw, tw []byte
	if err = tx.QueryRowContext(ctx, `SELECT a.authority_wire,COALESCE(t.terminal_wire,''::bytea) FROM public.capacity_source_failure_cleanup_originals a LEFT JOIN public.capacity_source_failure_cleanup_terminals t USING(parent_grant_id) WHERE a.parent_grant_id=$1`, stored.pre.OriginalCreateGrantID).Scan(&aw, &tw); err != nil {
		return stored, b, t, err
	}
	body, err := canonicalSignedBody(ctx, s, stored, aw)
	if err != nil || capacity.DecodeGuestLifecycle(body, &b) != nil {
		return stored, b, t, ErrCapacityConflict
	}
	if len(tw) > 0 {
		terminal, decodeErr := canonicalSignedBody(ctx, s, stored, tw)
		if decodeErr != nil || capacity.DecodeGuestLifecycle(terminal, &t) != nil {
			return stored, b, t, ErrCapacityConflict
		}
	}
	if !canonicalKnownFailedCase(b.NativeCase) || b.PreregistrationID != preID || b.ParentGrantID != stored.pre.OriginalCreateGrantID || b.CoreSource != capacity.CurrentGuestCoreSource() || b.GuestSource != stored.binding.GuestSourceCommit || !canonicalCleanupMode(b) || b.PositiveQuiescence || b.ProductionQualified {
		return stored, b, t, ErrCapacityConflict
	}
	if len(tw) > 0 {
		if !t.SourceTerminal || t.CanonicalParentTerminal || t.ProductionQualified || t.ParentGrantID != b.ParentGrantID || t.AuthoritySHA256 != capacity.BusinessCreationSHA256(aw) || t.OriginalReceiptSHA256 != b.OriginalReceiptSHA256 || !t.ReturnedAt.Before(b.CleanupDeadline) {
			return stored, b, t, ErrCapacityConflict
		}
		t.TerminalSHA256 = capacity.BusinessCreationSHA256(tw)
	}
	return stored, b, t, nil
}

// Preparation is not an arbitrary proof constructor: every argument is an
// actual immutable original row. Lost/uncertain transport without a real
// failed payload has no ActionsFailed authority and is explicitly refused.
func (s CapacityStore) PrepareCanonicalSourceCompensation(ctx context.Context, policy model.Manifest, parentID string) (CanonicalSourceEligibility, error) {
	var e CanonicalSourceEligibility
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return e, err
	}
	defer tx.Rollback()
	p, err := parseCapacityPolicy(policy)
	if err != nil {
		return e, err
	}
	if !s.ExecutionEnabled || !p.ExecutionEnabled || s.WorkflowID.String() == "00000000-0000-0000-0000-000000000000" {
		return e, ErrCapacityDisabled
	}
	if err = lockMutationScope(ctx, tx, policy.Metadata.Namespace, p); err != nil {
		return e, err
	}
	parent, err := loadCompensationRecord(ctx, tx, policy, p, parentID)
	if err != nil {
		return e, err
	}
	if parent.Grant.State != "settled" || parent.Settlement == nil || !parent.Settlement.TransportCompleted || parent.Grant.CompensationOf != "" {
		return e, ErrCapacityConflict
	}
	var preID string
	if err = tx.QueryRowContext(ctx, `SELECT id::text FROM public.capacity_vm_provisioning_preregistrations WHERE create_grant_id=$1`, parentID).Scan(&preID); err != nil {
		return e, err
	}
	stored, b, t, err := canonicalCleanupHistory(ctx, s, tx, preID)
	if err != nil {
		return e, err
	}
	if t.TerminalSHA256 != "" {
		return e, ErrCapacityConflict
	}
	if parent.Settlement.Outcome != "accepted" && !s.canonicalPostlossParentTx(ctx, tx, stored, parent, b.NativeCase) {
		return e, ErrCapacityConflict
	}
	if stored.pre.WorkflowID != s.WorkflowID.String() || stored.pre.PolicyID != parent.PolicyID.String() || stored.pre.PolicyChecksum != parent.PolicyChecksum {
		return e, ErrCapacityDisabled
	}
	var now time.Time
	if err = tx.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		return e, err
	}
	current, err := loadCapacityIntent(ctx, tx, policy.Metadata.Namespace, p, true)
	if err != nil {
		return e, err
	}
	owner := s
	owner.ExecutorID = parent.ExecutorID
	if b.Recovery != nil {
		if s.ExecutorID != current.LeaseExecutorID {
			return e, ErrCapacityLease
		}
		if _, err = s.sourceRecoveryCleanupLeaseTx(ctx, tx, b, parent, now); err != nil {
			return e, err
		}
	} else {
		if err = owner.checkLease(p, policy, &current, parent.Generation, parent.FencingToken, parent.LeaseOwner, now); err != nil {
			return e, err
		}
	}
	var failureWire, enrollmentWire []byte
	if err = tx.QueryRowContext(ctx, `SELECT original_wire FROM public.capacity_guest_qualification_native_source_returns WHERE preregistration_id=$1 AND native_stage='source_refusal' AND return_sha256=$2 AND original_record=convert_from(original_wire,'UTF8')::jsonb`, preID, b.FailureSHA256).Scan(&failureWire); err != nil {
		return e, err
	}
	var failed QualificationFailureRecord
	if capacity.DecodeGuestLifecycle(failureWire, &failed) != nil || !canonicalKnownFailedCase(failed.NativeCase) || failed.NativeCase != b.NativeCase || failed.Phase != "original_probe_failed_owner_exit" || failed.SourceCommit != b.GuestSource || failed.PreregistrationID != preID || failed.OriginalExitCode == nil || *failed.OriginalExitCode != 1 || failed.OriginalWait.ErrorClass != "original_owner_error" || failed.OriginalOutputEOF == nil || !*failed.OriginalOutputEOF || failed.OriginalOutputCloseSucceeded == nil || !*failed.OriginalOutputCloseSucceeded || failed.OriginalDiagnosticEOF == nil || !*failed.OriginalDiagnosticEOF || failed.OriginalDiagnosticCloseSucceeded == nil || !*failed.OriginalDiagnosticCloseSucceeded || failed.CensusAfter == nil || failed.NativeCensusErrorClass != "" || failed.ProvisioningJournal == nil || failed.ProvisioningJournal.LastSequence != 6 || failed.ProvisioningJournal.LastState != "admitted" || failed.ProvisioningJournal.EnrollmentSHA256 != b.EnrollmentSHA256 || failed.OriginalPayloadActionID != "guest-protected-payload:"+failed.OriginalPayloadSessionNonceSHA256 || !capacity.ValidDigest(failed.OriginalPayloadSessionNonceSHA256) {
		return e, ErrCapacityConflict
	}
	sig := failed.Signature
	failed.Signature = ""
	if !capacity.GuestQualificationSignature(stored.binding.ProvisionerPublicKey, sig, failed) {
		return e, ErrCapacityConflict
	}
	failed.Signature = sig
	if err = tx.QueryRowContext(ctx, `SELECT receipt_wire FROM public.capacity_vm_original_enrollments WHERE preregistration_id=$1 AND enrollment_sha256=$2`, preID, b.EnrollmentSHA256).Scan(&enrollmentWire); err != nil {
		return e, err
	}
	var enrollment model.CapacityGuestOriginalProvisioningReceipt
	if capacity.DecodeGuestLifecycle(enrollmentWire, &enrollment) != nil || len(enrollment.Enrollment.Statement.Writers) != 1 {
		return e, ErrCapacityConflict
	}
	writer := enrollment.Enrollment.Statement.Writers[0].Lifetime
	if !canonicalPayloadLinked(failed, writer) {
		return e, ErrCapacityConflict
	}
	prepared := failed.OriginalPayloadPreparation
	if prepared == nil || prepared.Schema != "canonical_original_payload_preparation_v1" || prepared.ActionID != failed.OriginalPayloadActionID || prepared.SessionNonceSHA256 != writer.ProcessNonceSHA256 || prepared.PreregistrationID != preID || prepared.ParentGrantID != parentID || prepared.CreateWitnessSHA256 != failed.OriginalCreateWitnessSHA256 || prepared.GuestSource != b.GuestSource || prepared.PreparedAt.IsZero() || prepared.OriginalWriteReturnedAt.Before(prepared.PreparedAt) || prepared.OriginalReadReturnedAt.Before(prepared.OriginalWriteReturnedAt) || prepared.OriginalReadReturnedAt.After(failed.OriginalStartCalledAt) {
		return e, ErrCapacityConflict
	}
	originalPreparation := struct {
		Schema              string    `json:"schema"`
		ActionID            string    `json:"action_id"`
		SessionNonceSHA256  string    `json:"session_nonce_sha256"`
		PreregistrationID   string    `json:"preregistration_id"`
		ParentGrantID       string    `json:"parent_grant_id"`
		CreateWitnessSHA256 string    `json:"create_witness_sha256"`
		GuestSource         string    `json:"guest_source"`
		PreparedAt          time.Time `json:"prepared_at"`
	}{prepared.Schema, prepared.ActionID, prepared.SessionNonceSHA256, prepared.PreregistrationID, prepared.ParentGrantID, prepared.CreateWitnessSHA256, prepared.GuestSource, prepared.PreparedAt}
	if capacity.GuestRetirementSHA(originalPreparation) != prepared.OriginalBodySHA256 {
		return e, ErrCapacityConflict
	}

	for _, fact := range []QualificationFailedOwnerReturn{failed.OriginalWait, failed.OriginalOutputEOFAndClose, failed.OriginalDiagnosticEOFAndClose} {
		if fact.OriginalReturnedAt.IsZero() || fact.OriginalReturnedAt.Before(failed.OriginalStartReturnedAt) || !fact.OriginalReturnedAt.Before(failed.OriginalOperationDeadline) || fact.OriginalReturnedAt.After(failed.RecordedAt) || !capacity.ValidDigest(fact.OriginalBodySHA256) {
			return e, ErrCapacityConflict
		}
	}
	for _, process := range failed.CensusAfter.Processes {
		if process.PID == failed.OriginalChild.PID && process.StartTicks == failed.OriginalChild.StartTicks {
			return e, ErrCapacityConflict
		}
	}
	creator, err := guestNativeQEMUIdentityTx(ctx, tx, preID)
	if err != nil {
		return e, err
	}
	var originalNativeWire []byte
	if err = tx.QueryRowContext(ctx, `SELECT original_wire FROM public.capacity_guest_qualification_native_source_returns WHERE preregistration_id=$1 AND native_stage='native_read'`, preID).Scan(&originalNativeWire); err != nil {
		return e, err
	}
	var originalNativeFields map[string]json.RawMessage
	if json.Unmarshal(originalNativeWire, &originalNativeFields) != nil || len(originalNativeFields["original"]) == 0 || capacity.BusinessCreationSHA256(originalNativeWire) != b.NativeReadSHA256 || creator.OriginalCreatorSHA256 != b.CreatorSHA256 {
		return e, ErrCapacityConflict
	}
	// The original native action names Go's exact typed Creator serialization,
	// not the independently retained Python creator-file raw serialization.
	nativeID := "qemu-original-create:" + capacity.BusinessCreationSHA256(originalNativeFields["original"])
	if canonicalPostlossCase(b.NativeCase) {
		if !s.canonicalPostlossParentTx(ctx, tx, stored, parent, b.NativeCase) {
			return e, ErrCapacityConflict
		}
	} else if parent.Settlement.ActionID != nativeID || parent.Settlement.ResourceID != b.ResourceID || parent.Settlement.ResourceCreatedAt != b.ResourceCreatedAt {
		return e, ErrCapacityConflict
	}
	if !now.Before(b.CleanupDeadline) || !capacity.Fresh(canonicalRecoveryObservedAt(b, failed.RecordedAt), now, p.MaxEvidenceAgeSeconds) {
		return e, ErrCapacityConflict
	}
	proof := model.CapacityMutationProof{GrantID: parentID, BindingName: parent.Binding.Name, Slot: parent.Grant.Slot, ResourceID: b.ResourceID, ResourceCreatedAt: b.ResourceCreatedAt, RequestSHA256: parent.Grant.RequestSHA256, ObservedAt: canonicalRecoveryObservedAt(b, failed.RecordedAt), ReceiptRef: "canonical-source-failed-owner:" + b.FailureSHA256, OwnerVerified: true, SpecVerified: true, CompensationIdentityVerified: true, ObservedCreationGrantID: parentID, ActionIDs: []string{nativeID, failed.OriginalPayloadActionID}, ActionsTerminal: true, ActionsSuccessful: false, ActionsFailed: true, ActionHistoryComplete: true}
	if !validFailedCreationProof(p, parent, proof, now) {
		return e, ErrCapacityConflict
	}
	e = CanonicalSourceEligibility{Schema: "canonical_source_failed_owner_eligibility_v1", Scope: "NATIVEQUALIFICATION_FAILED_OWNER_CHILD_OWNS_PHYSICAL_EFFECTS_NOT_POSITIVE_QUIESCENCE", NativeCase: b.NativeCase, Namespace: policy.Metadata.Namespace, CoreSource: b.CoreSource, GuestSource: b.GuestSource, PreregistrationID: preID, ParentGrantID: parentID, OriginalReceiptSHA256: b.OriginalReceiptSHA256, FailureSHA256: b.FailureSHA256, CleanupAuthoritySHA256: capacity.BusinessCreationSHA256(mustCanonicalAuthorityWire(ctx, tx, parentID)), CleanupTerminalSHA256: "", OriginalNativeReadSHA256: b.NativeReadSHA256, Actions: []CanonicalSourceAction{{nativeID, "original_native_create", "success", b.CreatorSHA256, creator.CloseReturnedAt}, {failed.OriginalPayloadActionID, "original_enrolled_payload", "failed_exit_1", b.FailureSHA256, failed.OriginalWait.OriginalReturnedAt}}, Aggregate: proof, CreatedAt: now, OriginalDeadline: b.OriginalContextDeadline, ChildOwnsPhysicalEffects: true, PositiveQuiescence: false, ProductionQualified: false}
	wire, err := canonicalSign(ctx, s, stored, e)
	if err != nil {
		return e, err
	}
	for _, ddl := range []string{`CREATE TABLE public.capacity_canonical_source_floor_terminal(parent_grant_id uuid PRIMARY KEY,terminal_wire bytea NOT NULL,terminal_sha256 text UNIQUE NOT NULL)`, `CREATE TRIGGER canonical_source_floor_terminal_immutable BEFORE UPDATE OR DELETE ON public.capacity_canonical_source_floor_terminal FOR EACH ROW EXECUTE FUNCTION public.source_cleanup_original_immutable()`, `CREATE TABLE public.capacity_canonical_source_effect_authorities(child_grant_id uuid PRIMARY KEY,authority_wire bytea NOT NULL,authority_sha256 text UNIQUE NOT NULL)`, `CREATE TRIGGER canonical_source_effect_authority_immutable BEFORE UPDATE OR DELETE ON public.capacity_canonical_source_effect_authorities FOR EACH ROW EXECUTE FUNCTION public.source_cleanup_original_immutable()`, `CREATE TABLE public.capacity_canonical_source_cleanup_eligibility(parent_grant_id uuid PRIMARY KEY,preregistration_id uuid UNIQUE NOT NULL,namespace text NOT NULL,eligibility_wire bytea NOT NULL,eligibility_sha256 text UNIQUE NOT NULL)`, `CREATE TABLE public.capacity_canonical_source_cleanup_children(child_grant_id uuid PRIMARY KEY,parent_grant_id uuid NOT NULL REFERENCES public.capacity_canonical_source_cleanup_eligibility(parent_grant_id),eligibility_sha256 text NOT NULL)`, `CREATE TABLE public.capacity_canonical_source_cleanup_reads(child_grant_id uuid PRIMARY KEY REFERENCES public.capacity_canonical_source_cleanup_children(child_grant_id),read_wire bytea NOT NULL,read_sha256 text UNIQUE NOT NULL)`, `CREATE TRIGGER canonical_source_eligibility_immutable BEFORE UPDATE OR DELETE ON public.capacity_canonical_source_cleanup_eligibility FOR EACH ROW EXECUTE FUNCTION public.source_cleanup_original_immutable()`, `CREATE TRIGGER canonical_source_child_immutable BEFORE UPDATE OR DELETE ON public.capacity_canonical_source_cleanup_children FOR EACH ROW EXECUTE FUNCTION public.source_cleanup_original_immutable()`, `CREATE TRIGGER canonical_source_read_immutable BEFORE UPDATE OR DELETE ON public.capacity_canonical_source_cleanup_reads FOR EACH ROW EXECUTE FUNCTION public.source_cleanup_original_immutable()`} {
		if _, err = tx.ExecContext(ctx, ddl); err != nil {
			return e, err
		}
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO public.capacity_canonical_source_cleanup_eligibility(parent_grant_id,preregistration_id,namespace,eligibility_wire,eligibility_sha256) VALUES($1,$2,$3,$4,$5)`, parentID, preID, policy.Metadata.Namespace, wire, capacity.BusinessCreationSHA256(wire)); err != nil {
		return e, err
	}
	return e, tx.Commit()
}
func (s CapacityStore) canonicalEligibilityTx(ctx context.Context, tx *sql.Tx, parentID string, now time.Time) (CanonicalSourceEligibility, bool, error) {
	var e CanonicalSourceEligibility
	var relation sql.NullString
	if err := tx.QueryRowContext(ctx, `SELECT to_regclass('public.capacity_canonical_source_cleanup_eligibility')::text`).Scan(&relation); err != nil {
		return e, true, err
	}
	if !relation.Valid {
		return e, false, nil
	}
	var wire []byte
	var preID, sha string
	err := tx.QueryRowContext(ctx, `SELECT preregistration_id::text,eligibility_wire,eligibility_sha256 FROM public.capacity_canonical_source_cleanup_eligibility WHERE parent_grant_id=$1`, parentID).Scan(&preID, &wire, &sha)
	if errors.Is(err, sql.ErrNoRows) {
		return e, false, nil
	}
	if err != nil {
		return e, true, err
	}
	if s.DB == nil {
		return e, true, ErrCapacityConflict
	}
	stored, b, _, err := canonicalCleanupHistory(ctx, s, tx, preID)
	if err != nil {
		return e, true, err
	}
	if canonicalPostlossCase(b.NativeCase) {
		var revisions sql.NullString
		if err = tx.QueryRowContext(ctx, `SELECT to_regclass('public.capacity_canonical_postloss_fresh_reads')::text`).Scan(&revisions); err != nil {
			return e, true, err
		}
		if revisions.Valid {
			var newer, prior string
			var revised []byte
			err = tx.QueryRowContext(ctx, `SELECT eligibility_wire,eligibility_sha256,prior_eligibility_sha256 FROM public.capacity_canonical_postloss_fresh_reads WHERE parent_grant_id=$1 ORDER BY observed_at DESC,read_id DESC LIMIT 1`, parentID).Scan(&revised, &newer, &prior)
			if err == nil {
				if prior != sha {
					return e, true, ErrCapacityConflict
				}
				wire, sha = revised, newer
			} else if !errors.Is(err, sql.ErrNoRows) {
				return e, true, err
			}
		}
	}
	body, err := canonicalSignedBody(ctx, s, stored, wire)
	if err != nil || capacity.DecodeGuestLifecycle(body, &e) != nil || capacity.BusinessCreationSHA256(wire) != sha {
		return e, true, ErrCapacityConflict
	}
	if e.Schema != "canonical_source_failed_owner_eligibility_v1" || e.Scope != "NATIVEQUALIFICATION_FAILED_OWNER_CHILD_OWNS_PHYSICAL_EFFECTS_NOT_POSITIVE_QUIESCENCE" || !canonicalKnownFailedCase(e.NativeCase) || e.ParentGrantID != parentID || e.PreregistrationID != preID || e.CoreSource != capacity.CurrentGuestCoreSource() || e.GuestSource != stored.binding.GuestSourceCommit || e.Namespace == "" || !e.ChildOwnsPhysicalEffects || e.PositiveQuiescence || e.ProductionQualified || e.CleanupAuthoritySHA256 != capacity.BusinessCreationSHA256(mustCanonicalAuthorityWire(ctx, tx, parentID)) || e.CleanupTerminalSHA256 != "" || e.FailureSHA256 != b.FailureSHA256 || e.OriginalReceiptSHA256 != b.OriginalReceiptSHA256 || !now.Before(e.OriginalDeadline) || len(e.Actions) != 2 || e.Actions[0].Outcome != "success" || e.Actions[1].Outcome != "failed_exit_1" || len(e.Aggregate.ActionIDs) != 2 || e.Actions[0].ID != e.Aggregate.ActionIDs[0] || e.Actions[1].ID != e.Aggregate.ActionIDs[1] {
		return e, true, ErrCapacityConflict
	}
	e.EligibilityWireSHA256 = sha
	return e, true, nil
}
func (s CapacityStore) canonicalSourceFailedCleanupTx(ctx context.Context, tx *sql.Tx, p model.CapacityPolicySpec, parent capacityMutationRecord, proof model.CapacityMutationProof, now time.Time, childID string) (bool, error) {
	e, handled, err := s.canonicalEligibilityTx(ctx, tx, parent.Grant.GrantID, now)
	if !handled || err != nil {
		return handled, err
	}
	if !reflect.DeepEqual(e.Aggregate, proof) || !validFailedCreationProof(p, parent, proof, now) || parent.Binding.ProfileName != "qualification-original-echo-writer-v1" {
		return true, ErrCapacityConflict
	}
	_, body, _, readErr := canonicalCleanupHistory(ctx, s, tx, e.PreregistrationID)
	if readErr != nil {
		return true, readErr
	}
	if body.Recovery != nil {
		if _, readErr = s.sourceRecoveryCleanupLeaseTx(ctx, tx, body, parent, now); readErr != nil {
			return true, readErr
		}
	}
	if childID != "" {
		var linked, sha string
		if err = tx.QueryRowContext(ctx, `SELECT parent_grant_id::text,eligibility_sha256 FROM public.capacity_canonical_source_cleanup_children WHERE child_grant_id=$1`, childID).Scan(&linked, &sha); err != nil || linked != parent.Grant.GrantID || sha != e.EligibilityWireSHA256 {
			return true, ErrCapacityConflict
		}
	}
	return true, nil
}
func (s CapacityStore) canonicalSourceBindCompensationTx(ctx context.Context, tx *sql.Tx, child, parent capacityMutationRecord, now time.Time) (bool, error) {
	e, handled, err := s.canonicalEligibilityTx(ctx, tx, parent.Grant.GrantID, now)
	if !handled || err != nil {
		return handled, err
	}
	if parent.Proof == nil || child.Grant.CompensationOf != parent.Grant.GrantID || child.Grant.ExpectedResourceID != parent.Proof.ResourceID || child.Grant.ExpectedResourceCreatedAt != parent.Proof.ResourceCreatedAt {
		return true, ErrCapacityConflict
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO public.capacity_canonical_source_cleanup_children(child_grant_id,parent_grant_id,eligibility_sha256) VALUES($1,$2,$3)`, child.Grant.GrantID, parent.Grant.GrantID, e.EligibilityWireSHA256)
	return true, err
}

func mustCanonicalAuthorityWire(ctx context.Context, tx *sql.Tx, parent string) []byte {
	var raw []byte
	if tx.QueryRowContext(ctx, `SELECT authority_wire FROM public.capacity_source_failure_cleanup_originals WHERE parent_grant_id=$1`, parent).Scan(&raw) != nil {
		return nil
	}
	return raw
}

type CanonicalSourceChildAuthority struct {
	OriginalPolicyID      string    `json:"original_policy_id"`
	CurrentPolicyID       string    `json:"current_policy_id"`
	CurrentPolicyChecksum string    `json:"current_policy_checksum"`
	Schema                string    `json:"schema"`
	Scope                 string    `json:"scope"`
	Case                  string    `json:"case"`
	CoreSource            string    `json:"core_source"`
	GuestSource           string    `json:"guest_source"`
	ParentGrantID         string    `json:"parent_grant_id"`
	ChildGrantID          string    `json:"child_grant_id"`
	RequestSHA256         string    `json:"request_sha256"`
	AttemptID             string    `json:"attempt_id"`
	ActionID              string    `json:"action_id"`
	SourceAuthoritySHA256 string    `json:"source_authority_sha256"`
	EligibilitySHA256     string    `json:"eligibility_sha256"`
	RedeemReturnSHA256    string    `json:"redeem_return_sha256"`
	RedeemMode            string    `json:"redeem_mode"`
	RedeemedAt            time.Time `json:"redeemed_at"`
	OriginalDeadline      time.Time `json:"original_deadline"`
	ProductionQualified   bool      `json:"production_qualified"`
	PositiveQuiescence    bool      `json:"positive_quiescence"`
}

// Records authority only AFTER the original API redeemed this actual child.
// Physical effects are still absent; the signed deadline is bounded by BOTH
// child grant and original current private lease, without renewing either.
func (s CapacityStore) AuthorizeCanonicalSourceChild(ctx context.Context, policy model.Manifest, childID, attempt, redeemSHA string) ([]byte, error) {
	var result []byte
	err := s.compensationTransaction(ctx, policy, false, func(tx *sql.Tx, p model.CapacityPolicySpec, now time.Time) error {
		child, err := loadCompensationRecord(ctx, tx, policy, p, childID)
		if err != nil {
			return err
		}
		if !canonicalRedeemedChild(child, childID, attempt, s.ExecutorID, now) || child.WorkflowID != s.WorkflowID || child.PolicyID != policy.ID || child.PolicyChecksum != policy.Checksum || !capacity.ValidDigest(redeemSHA) {
			return ErrCapacityConflict
		}
		e, handled, err := s.canonicalEligibilityTx(ctx, tx, child.Grant.CompensationOf, now)
		if !handled || err != nil {
			return ErrCapacityConflict
		}
		stored, b, t, err := canonicalCleanupHistory(ctx, s, tx, e.PreregistrationID)
		if err != nil || t.TerminalSHA256 != "" {
			return ErrCapacityConflict
		}
		current, err := loadCapacityIntent(ctx, tx, policy.Metadata.Namespace, p, true)
		if err != nil {
			return err
		}
		parent, err := loadCompensationRecord(ctx, tx, policy, p, e.ParentGrantID)
		if err != nil || parent.Grant.State != "compensating" {
			return ErrCapacityConflict
		}
		owner := s
		owner.ExecutorID = parent.ExecutorID
		// The policy ID may be an explicit compensation-enabled successor, while
		// the original lease and parent remain exactly their original manifest.
		originalPolicy, err := GetManifestByID(ctx, s.DB, parent.PolicyID)
		if err != nil {
			return err
		}
		originalSpec, err := parseCapacityPolicy(originalPolicy)
		if err != nil {
			return err
		}
		if b.Recovery != nil {
			if s.ExecutorID != current.LeaseExecutorID {
				return ErrCapacityLease
			}
			if _, err = s.sourceRecoveryCleanupLeaseTx(ctx, tx, b, parent, now); err != nil {
				return err
			}
		} else {
			if err = owner.checkLease(originalSpec, originalPolicy, &current, parent.Generation, parent.FencingToken, parent.LeaseOwner, now); err != nil {
				return err
			}
		}
		if current.LeaseExpiresAt == nil {
			return ErrCapacityConflict
		}
		deadline, valid := canonicalChildDeadline(now, child.Grant.ExpiresAt, b.CleanupDeadline, *current.LeaseExpiresAt, b.OriginalProvisioningDeadline)
		if !valid {
			return ErrCapacityConflict
		}
		a := CanonicalSourceChildAuthority{OriginalPolicyID: parent.PolicyID.String(), CurrentPolicyID: child.PolicyID.String(), CurrentPolicyChecksum: child.PolicyChecksum, Schema: "canonical_source_failed_owner_child_v1", Scope: "SOURCE_ONLY_CHILD_OWNED_ORIGINAL_KILL_UNLINK_NOT_POSITIVE_QUIESCENCE", Case: e.NativeCase, CoreSource: e.CoreSource, GuestSource: e.GuestSource, ParentGrantID: e.ParentGrantID, ChildGrantID: childID, RequestSHA256: child.Grant.RequestSHA256, AttemptID: attempt, ActionID: "canonical-original-cleanup:" + childID + ":" + attempt, SourceAuthoritySHA256: e.CleanupAuthoritySHA256, EligibilitySHA256: e.EligibilityWireSHA256, RedeemReturnSHA256: redeemSHA, RedeemMode: "write_once", RedeemedAt: now, OriginalDeadline: deadline, ProductionQualified: false, PositiveQuiescence: false}
		if !canonicalChildPolicyJoin(a, child.PolicyID.String(), child.PolicyChecksum, b.PolicyID, b.PolicyChecksum) {
			return ErrCapacityConflict
		}
		result, err = canonicalSign(ctx, s, stored, a)
		if err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO public.capacity_canonical_source_effect_authorities(child_grant_id,authority_wire,authority_sha256) VALUES($1,$2,$3)`, childID, result, capacity.BusinessCreationSHA256(result))
		return err
	})
	return result, err
}
func (s CapacityStore) canonicalOwnedPhysicalTx(ctx context.Context, tx *sql.Tx, child capacityMutationRecord, e CanonicalSourceEligibility, now time.Time) (CanonicalSourceChildAuthority, SourceFailureCleanupBody, SourceFailureCleanupTerminal, error) {
	var a CanonicalSourceChildAuthority
	stored, b, t, err := canonicalCleanupHistory(ctx, s, tx, e.PreregistrationID)
	if err != nil || t.TerminalSHA256 == "" {
		return a, b, t, ErrCapacityConflict
	}
	var wire, physicalWire []byte
	var sha string
	if err = tx.QueryRowContext(ctx, `SELECT authority_wire,authority_sha256 FROM public.capacity_canonical_source_effect_authorities WHERE child_grant_id=$1`, child.Grant.GrantID).Scan(&wire, &sha); err != nil {
		return a, b, t, err
	}
	body, err := canonicalSignedBody(ctx, s, stored, wire)
	if err != nil || capacity.DecodeGuestLifecycle(body, &a) != nil || capacity.BusinessCreationSHA256(wire) != sha {
		return a, b, t, ErrCapacityConflict
	}
	if a.Schema != "canonical_source_failed_owner_child_v1" || a.Scope != "SOURCE_ONLY_CHILD_OWNED_ORIGINAL_KILL_UNLINK_NOT_POSITIVE_QUIESCENCE" || a.Case != e.NativeCase || a.CoreSource != e.CoreSource || a.GuestSource != e.GuestSource || a.ChildGrantID != child.Grant.GrantID || a.ParentGrantID != e.ParentGrantID || a.AttemptID != child.AttemptID || a.RequestSHA256 != child.Grant.RequestSHA256 || a.ActionID != "canonical-original-cleanup:"+a.ChildGrantID+":"+a.AttemptID || a.SourceAuthoritySHA256 != e.CleanupAuthoritySHA256 || a.EligibilitySHA256 != e.EligibilityWireSHA256 || a.RedeemMode != "write_once" || a.ProductionQualified || a.PositiveQuiescence || !canonicalChildPolicyJoin(a, child.PolicyID.String(), child.PolicyChecksum, b.PolicyID, b.PolicyChecksum) || a.OriginalDeadline.After(child.Grant.ExpiresAt) || a.OriginalDeadline.After(b.CleanupDeadline) || b.OriginalProvisioningDeadline.IsZero() || !a.RedeemedAt.Before(b.OriginalProvisioningDeadline) || a.OriginalDeadline.After(b.OriginalProvisioningDeadline) {
		return a, b, t, ErrCapacityConflict
	}
	if err = tx.QueryRowContext(ctx, `SELECT physical_wire FROM public.capacity_source_failure_cleanup_physical WHERE parent_grant_id=$1`, e.ParentGrantID).Scan(&physicalWire); err != nil {
		return a, b, t, err
	}
	var f SourceFailureCleanupPhysical
	if capacity.DecodeGuestLifecycle(physicalWire, &f) != nil || capacity.BusinessCreationSHA256(physicalWire) != t.PhysicalSHA256 || f.AuthoritySHA256 != a.SourceAuthoritySHA256 || f.CoreSource != e.CoreSource || f.GuestSource != e.GuestSource || f.ResourceID != b.ResourceID || !reflect.DeepEqual(f.QEMU, b.QEMU) || !reflect.DeepEqual(f.OriginalDisk, b.OriginalDisk) || f.OriginalSignal != 9 || f.OriginalWaitCode != -9 || !f.OriginalStderrEOF || f.AbsenceClass != "ENOENT" || f.PositiveQuiescence || f.ProductionQualified {
		return a, b, t, ErrCapacityConflict
	}
	if b.Recovery != nil {
		if f.Schema != "original_source_recovery_failure_cleanup_physical_v1" || f.Scope != "host_owned_recovery_failure_cleanup_only_not_positive_retirement" {
			return a, b, t, ErrCapacityConflict
		}
		// Record loader requires the actual policy scope; validate the current lease
		// and two immutable per-effect permits through the dedicated validator.
		if err = s.validateRecoveryPhysicalPermitsTx(ctx, tx, stored, b, child, a, f, now); err != nil {
			return a, b, t, err
		}
	} else if f.Schema != "original_source_failure_cleanup_physical_v1" || f.Scope != "host_owned_failure_cleanup_only_not_positive_retirement" {
		return a, b, t, ErrCapacityConflict
	}
	for _, at := range []time.Time{f.OriginalPinStartedAt, f.OriginalPinReturnedAt, f.OriginalSignalCalledAt, f.OriginalSignalReturnedAt, f.OriginalWaitReturnedAt, f.OriginalStderrCloseReturnedAt, f.OriginalPIDFDOffReturnedAt, f.OriginalPIDFDCloseReturnedAt, f.OriginalUnlinkCalledAt, f.OriginalUnlinkReturnedAt, f.OriginalDirectorySyncReturnedAt, f.OriginalAbsenceReturnedAt, f.OriginalDirectoryCloseReturnedAt} {
		if at.Before(a.RedeemedAt) || !at.Before(a.OriginalDeadline) || at.After(now) {
			return a, b, t, ErrCapacityConflict
		}
	}
	return a, b, t, nil
}
func (s CapacityStore) ObserveCanonicalSourceCompensation(ctx context.Context, policy model.Manifest, childID string) (model.CapacityMutationProof, error) {
	var proof model.CapacityMutationProof
	err := s.compensationTransaction(ctx, policy, false, func(tx *sql.Tx, p model.CapacityPolicySpec, now time.Time) error {
		locator, err := readCompensationRecord(ctx, tx, policy, p, childID, false)
		if err != nil {
			return err
		}
		if err = lockNativeMutationSlot(ctx, tx, locator.Binding, locator.Grant.Slot); err != nil {
			return err
		}
		child, err := loadCompensationRecord(ctx, tx, policy, p, childID)
		if err != nil {
			return err
		}
		if !reflect.DeepEqual(child, locator) || child.Grant.State != "redeemed" || child.ExecutorID != s.ExecutorID || child.WorkflowID != s.WorkflowID {
			return ErrCapacityConflict
		}
		e, handled, err := s.canonicalEligibilityTx(ctx, tx, child.Grant.CompensationOf, now)
		if !handled || err != nil {
			return ErrCapacityConflict
		}
		a, b, t, err := s.canonicalOwnedPhysicalTx(ctx, tx, child, e, now)
		if err != nil {
			return err
		}
		current, err := loadCapacityIntent(ctx, tx, policy.Metadata.Namespace, p, true)
		if err != nil {
			return err
		}
		read, err := sourceFailureCleanupCurrentRead(b, t, current, now)
		if err != nil {
			return err
		}
		proof = model.CapacityMutationProof{GrantID: childID, BindingName: child.Binding.Name, Slot: child.Grant.Slot, ResourceID: child.Grant.ExpectedResourceID, ResourceCreatedAt: child.Grant.ExpectedResourceCreatedAt, RequestSHA256: child.Grant.RequestSHA256, ObservedAt: read.ReturnedAt, ReceiptRef: "canonical-child-owned-cleanup:" + a.ActionID, OwnerVerified: true, SpecVerified: true, ResourceAbsent: true, ActionIDs: []string{a.ActionID}, ActionsTerminal: true, ActionsSuccessful: true, CompensationIdentityVerified: true, ObservedCreationGrantID: e.ParentGrantID}
		observed := CanonicalSourceAbsenceRead{Schema: "canonical_source_compensation_absence_v2", Scope: "ORIGINAL_CHILD_OWNED_KILL_UNLINK_AND_FRESH_ABSENCE", ChildGrantID: childID, ParentGrantID: e.ParentGrantID, RequestSHA256: child.Grant.RequestSHA256, EligibilitySHA256: e.EligibilityWireSHA256, ActionID: a.ActionID, Read: read, Proof: proof, ProductionQualified: false}
		stored, _, _, err := canonicalCleanupHistory(ctx, s, tx, e.PreregistrationID)
		if err != nil {
			return err
		}
		wire, err := canonicalSign(ctx, s, stored, observed)
		if err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO public.capacity_canonical_source_cleanup_reads(child_grant_id,read_wire,read_sha256) VALUES($1,$2,$3)`, childID, wire, capacity.BusinessCreationSHA256(wire))
		return err
	})
	return proof, err
}
func (s CapacityStore) canonicalSourceConfirmedCleanupTx(ctx context.Context, tx *sql.Tx, p model.CapacityPolicySpec, child capacityMutationRecord, proof model.CapacityMutationProof, now time.Time) (bool, error) {
	e, handled, err := s.canonicalEligibilityTx(ctx, tx, child.Grant.CompensationOf, now)
	if !handled || err != nil {
		return handled, err
	}
	a, _, _, err := s.canonicalOwnedPhysicalTx(ctx, tx, child, e, now)
	if err != nil {
		return true, err
	}
	var wire []byte
	var sha string
	if err = tx.QueryRowContext(ctx, `SELECT read_wire,read_sha256 FROM public.capacity_canonical_source_cleanup_reads WHERE child_grant_id=$1`, child.Grant.GrantID).Scan(&wire, &sha); err != nil {
		return true, err
	}
	stored, _, _, err := canonicalCleanupHistory(ctx, s, tx, e.PreregistrationID)
	if err != nil {
		return true, err
	}
	body, err := canonicalSignedBody(ctx, s, stored, wire)
	if err != nil {
		return true, err
	}
	var observed CanonicalSourceAbsenceRead
	if capacity.DecodeGuestLifecycle(body, &observed) != nil || capacity.BusinessCreationSHA256(wire) != sha || observed.Schema != "canonical_source_compensation_absence_v2" || observed.EligibilitySHA256 != e.EligibilityWireSHA256 || observed.RequestSHA256 != child.Grant.RequestSHA256 || observed.ChildGrantID != child.Grant.GrantID || observed.ParentGrantID != e.ParentGrantID || observed.Scope != "ORIGINAL_CHILD_OWNED_KILL_UNLINK_AND_FRESH_ABSENCE" || observed.ProductionQualified || !reflect.DeepEqual(observed.Proof, proof) || child.Settlement == nil || child.Settlement.ActionID != a.ActionID || observed.ActionID != a.ActionID || child.Settlement.ResourceID != proof.ResourceID || observed.Read.PIDFDOpenError != "ESRCH" || observed.Read.DiskAbsence != "ENOENT" || !capacity.Fresh(observed.Read.ReturnedAt, now, p.MaxEvidenceAgeSeconds) {
		return true, ErrCapacityConflict
	}
	return true, nil
}

func (s CapacityStore) CanonicalSourceEligibilityWire(ctx context.Context, parentID string) ([]byte, error) {
	var wire []byte
	var sha string
	err := s.DB.QueryRowContext(ctx, `SELECT eligibility_wire,eligibility_sha256 FROM public.capacity_canonical_source_cleanup_eligibility WHERE parent_grant_id=$1`, parentID).Scan(&wire, &sha)
	if err != nil || capacity.BusinessCreationSHA256(wire) != sha {
		return nil, ErrCapacityConflict
	}
	var revisions sql.NullString
	if err = s.DB.QueryRowContext(ctx, `SELECT to_regclass('public.capacity_canonical_postloss_fresh_reads')::text`).Scan(&revisions); err != nil {
		return nil, err
	}
	if revisions.Valid {
		var next []byte
		var nextSHA, prior string
		err = s.DB.QueryRowContext(ctx, `SELECT eligibility_wire,eligibility_sha256,prior_eligibility_sha256 FROM public.capacity_canonical_postloss_fresh_reads WHERE parent_grant_id=$1`, parentID).Scan(&next, &nextSHA, &prior)
		if err == nil {
			if prior != sha || capacity.BusinessCreationSHA256(next) != nextSHA {
				return nil, ErrCapacityConflict
			}
			wire = next
		} else if !errors.Is(err, sql.ErrNoRows) {
			return nil, err
		}
	}
	return wire, nil
}

func (s CapacityStore) CanonicalSourceFloorCurrentAbsence(ctx context.Context, policy model.Manifest, parentID string, generation, fence int64, owner string) ([]byte, error) {
	var result []byte
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	p, err := parseCapacityPolicy(policy)
	if err != nil {
		return nil, err
	}
	if err = lockMutationScope(ctx, tx, policy.Metadata.Namespace, p); err != nil {
		return nil, err
	}
	current, err := loadCapacityIntent(ctx, tx, policy.Metadata.Namespace, p, true)
	if err != nil {
		return nil, err
	}
	var now time.Time
	if err = tx.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		return nil, err
	}
	if err = s.checkRecoveryLease(policy, &current, generation, fence, owner, now); err != nil {
		return nil, err
	}
	e, handled, err := s.canonicalEligibilityTx(ctx, tx, parentID, now)
	if !handled || err != nil || e.NativeCase != "canonical_failed_floor_recovery" {
		return nil, ErrCapacityConflict
	}
	parent, err := loadCompensationRecord(ctx, tx, policy, p, parentID)
	if err != nil || parent.Grant.State != "compensated" || parent.Proof == nil {
		return nil, ErrCapacityConflict
	}
	var childID string
	if err = tx.QueryRowContext(ctx, `SELECT id::text FROM public.capacity_mutation_grants WHERE grant_record->'grant'->>'compensation_of'=$1 AND state='confirmed'`, parentID).Scan(&childID); err != nil {
		return nil, err
	}
	child, err := loadCompensationRecord(ctx, tx, policy, p, childID)
	if err != nil {
		return nil, err
	}
	_, b, t, err := s.canonicalOwnedPhysicalTx(ctx, tx, child, e, now)
	if err != nil {
		return nil, err
	}
	read, err := sourceFailureCleanupCurrentRead(b, t, current, now)
	if err != nil {
		return nil, err
	}
	stored, _, _, err := canonicalCleanupHistory(ctx, s, tx, e.PreregistrationID)
	if err != nil {
		return nil, err
	}
	result, err = canonicalSign(ctx, s, stored, read)
	if err != nil {
		return nil, err
	}
	// Fresh read is appended immutable; original child/effect deadlines and
	// timestamps are never changed by this recovery-only observation.
	_, err = tx.ExecContext(ctx, `INSERT INTO public.capacity_source_failure_cleanup_reads(read_id,parent_grant_id,generation,fencing_token,read_wire,read_sha256) VALUES($1,$2,$3,$4,$5,$6)`, read.ReadID, parentID, generation, fence, result, capacity.BusinessCreationSHA256(result))
	if err != nil {
		return nil, err
	}
	return result, tx.Commit()
}

func canonicalChildDeadline(now, grant, cleanup, lease, provisioning time.Time) (time.Time, bool) {
	// provisioning is the ORIGINAL absolute deadline registered before Start,
	// never a new now+420 window. Unknown/expired endpoints grant no effects.
	if grant.IsZero() || cleanup.IsZero() || lease.IsZero() || provisioning.IsZero() {
		return time.Time{}, false
	}
	end := grant
	if cleanup.Before(end) {
		end = cleanup
	}
	if lease.Before(end) {
		end = lease
	}
	if provisioning.Before(end) {
		end = provisioning
	}
	return end, now.Before(end)
}
func canonicalPayloadLinked(f QualificationFailureRecord, w model.CapacityGuestRetirementLifetime) bool {
	if f.OriginalExitCode == nil || *f.OriginalExitCode != 1 || f.Phase != "original_probe_failed_owner_exit" || f.OriginalWait.ErrorClass != "original_owner_error" || f.OriginalOutputEOF == nil || !*f.OriginalOutputEOF || f.OriginalOutputCloseSucceeded == nil || !*f.OriginalOutputCloseSucceeded || f.OriginalDiagnosticEOF == nil || !*f.OriginalDiagnosticEOF || f.OriginalDiagnosticCloseSucceeded == nil || !*f.OriginalDiagnosticCloseSucceeded {
		return false
	}
	return f.OriginalChild.PID == w.PID && f.OriginalChild.StartTicks == w.StartTicks && capacity.ValidDigest(w.ProcessNonceSHA256) && f.OriginalPayloadSessionNonceSHA256 == w.ProcessNonceSHA256 && f.OriginalPayloadActionID == "guest-protected-payload:"+w.ProcessNonceSHA256
}

func canonicalRedeemedChild(child capacityMutationRecord, id, attempt, executor string, now time.Time) bool {
	return child.Grant.GrantID == id && validCapacityExecutor(id) && child.Grant.State == "redeemed" && validCapacityExecutor(child.Grant.CompensationOf) && child.Grant.Slot == 2 && child.Grant.RequestSHA256 != "" && child.Grant.ExpectedResourceID != "" && child.Grant.ExpectedResourceCreatedAt != "" && child.AttemptID == attempt && validCapacityExecutor(attempt) && child.ExecutorID == executor && validCapacityExecutor(executor) && now.Before(child.Grant.ExpiresAt)
}

// Store ONLY the actual ordinary Reconcile return already committed in SQL.
// This immutable prior-generation record is inspected by the SAME original
// workflow step before it can issue the next unredeemed permission.
func (s CapacityStore) RecordCanonicalFloorTerminal(ctx context.Context, policy model.Manifest, parentID string) ([]byte, error) {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	p, err := parseCapacityPolicy(policy)
	if err != nil {
		return nil, err
	}
	if err = lockMutationScope(ctx, tx, policy.Metadata.Namespace, p); err != nil {
		return nil, err
	}
	current, err := loadCapacityIntent(ctx, tx, policy.Metadata.Namespace, p, true)
	if err != nil || current.Phase != "reconciled_failed_floor" || !current.FloorDegraded || current.LeaseOwner != "" || current.LeaseExpiresAt != nil || current.Assessment.Snapshot.Units != 1 || current.Decision.Units != 2 || current.Decision.ExecutionPermitted {
		return nil, ErrCapacityConflict
	}
	var now time.Time
	if err = tx.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		return nil, err
	}
	e, handled, err := s.canonicalEligibilityTx(ctx, tx, parentID, now)
	if !handled || err != nil || e.NativeCase != "canonical_failed_floor_recovery" {
		return nil, ErrCapacityConflict
	}
	parent, err := loadCompensationRecord(ctx, tx, policy, p, parentID)
	if err != nil || parent.Grant.State != "compensated" || parent.WorkflowID != s.WorkflowID || parent.Generation != current.Generation {
		return nil, ErrCapacityConflict
	}
	raw, err := json.Marshal(current)
	if err != nil {
		return nil, err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO public.capacity_canonical_source_floor_terminal(parent_grant_id,terminal_wire,terminal_sha256) VALUES($1,$2,$3)`, parentID, raw, capacity.BusinessCreationSHA256(raw))
	if err != nil {
		return nil, err
	}
	return raw, tx.Commit()
}
func (s CapacityStore) CanonicalFloorNextPermission(ctx context.Context, policy model.Manifest, generation, fence int64, owner string) (bool, error) {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	var relation sql.NullString
	if err = tx.QueryRowContext(ctx, `SELECT to_regclass('public.capacity_canonical_source_floor_terminal')::text`).Scan(&relation); err != nil {
		return false, err
	}
	if !relation.Valid {
		return false, nil
	}
	var parentID string
	var raw []byte
	var sha string
	err = tx.QueryRowContext(ctx, `SELECT parent_grant_id::text,terminal_wire,terminal_sha256 FROM public.capacity_canonical_source_floor_terminal`).Scan(&parentID, &raw, &sha)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return true, err
	}
	p, err := parseCapacityPolicy(policy)
	if err != nil {
		return true, err
	}
	if p.Floor != 2 || p.Ceiling != 2 {
		return true, ErrCapacityConflict
	}
	if err = lockMutationScope(ctx, tx, policy.Metadata.Namespace, p); err != nil {
		return true, err
	}
	var now time.Time
	if err = tx.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		return true, err
	}
	current, err := loadCapacityIntent(ctx, tx, policy.Metadata.Namespace, p, true)
	if err != nil {
		return true, err
	}
	if err = s.checkLease(p, policy, &current, generation, fence, owner, now); err != nil {
		return true, err
	}
	e, handled, err := s.canonicalEligibilityTx(ctx, tx, parentID, now)
	if !handled || err != nil || e.NativeCase != "canonical_failed_floor_recovery" {
		return true, ErrCapacityConflict
	}
	var old model.CapacityIntent
	if capacity.DecodeGuestLifecycle(raw, &old) != nil || capacity.BusinessCreationSHA256(raw) != sha || old.PolicyID != policy.ID || old.PolicyChecksum != policy.Checksum || old.Phase != "reconciled_failed_floor" || !old.FloorDegraded || old.Generation+1 != current.Generation || old.Assessment.Snapshot.Units != 1 || current.BaselineSnapshot.Units != 1 || current.Decision.Reason != "protected_floor_recovery" || current.Decision.Units != 2 || current.Phase != "preparing" {
		return true, ErrCapacityConflict
	}
	parent, err := loadCompensationRecord(ctx, tx, policy, p, parentID)
	if err != nil || parent.Grant.State != "compensated" || parent.WorkflowID != s.WorkflowID || parent.Generation != old.Generation {
		return true, ErrCapacityConflict
	}
	var confirmed int
	if err = tx.QueryRowContext(ctx, `SELECT count(*) FROM public.capacity_mutation_grants WHERE state='confirmed' AND grant_record->'grant'->>'compensation_of'=$1`, parentID).Scan(&confirmed); err != nil || confirmed != 1 {
		return true, ErrCapacityConflict
	}
	return true, tx.Commit()
}

// These facts are read from immutable original parent and actual current
// child rows, not aliases supplied by a runtime caller or result artifact.
// The existing Core signature binds them BEFORE the physical effect.
func canonicalChildPolicyJoin(a CanonicalSourceChildAuthority, childPolicy, childChecksum, originalPolicy, originalChecksum string) bool {
	if !validCapacityExecutor(a.OriginalPolicyID) || !validCapacityExecutor(a.CurrentPolicyID) || !capacity.ValidDigest(a.CurrentPolicyChecksum) || a.OriginalPolicyID != originalPolicy || a.CurrentPolicyID != childPolicy || a.CurrentPolicyChecksum != childChecksum || !capacity.ValidDigest(originalChecksum) {
		return false
	}
	switch a.Case {
	case "canonical_compensation_unprotected_failed_create", "canonical_compensation_protected_failed_create":
		return a.CurrentPolicyID != a.OriginalPolicyID && a.CurrentPolicyChecksum != originalChecksum
	case "canonical_postloss_unprotected_failed_create_reissue", "canonical_postloss_protected_failed_create_reissue", "canonical_failed_floor_recovery":
		return a.CurrentPolicyID == a.OriginalPolicyID && a.CurrentPolicyChecksum == originalChecksum
	}
	return false
}
