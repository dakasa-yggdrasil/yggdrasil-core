package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"reflect"
	"sync/atomic"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

type PartialNativeOffRead struct {
	Schema              string    `json:"schema"`
	ReadID              string    `json:"read_id"`
	ReconciliationID    string    `json:"reconciliation_id"`
	PreregistrationID   string    `json:"preregistration_id"`
	RetirementRequestID string    `json:"retirement_request_id"`
	Ordinal             int       `json:"ordinal"`
	AdmissionSHA256     string    `json:"admission_sha256"`
	EvidenceSHA256      string    `json:"evidence_sha256"`
	IssuedAt            time.Time `json:"issued_at"`
	OriginalDeadline    time.Time `json:"original_deadline"`
}
type PartialNativeOffReturn struct {
	Schema        string                     `json:"schema"`
	Read          PartialNativeOffRead       `json:"read"`
	Status        string                     `json:"status"`
	Plan          *model.CapacityVMFleetPlan `json:"plan,omitempty"`
	StartedAt     time.Time                  `json:"started_at"`
	ReturnedAt    time.Time                  `json:"returned_at"`
	CallFailed    bool                       `json:"call_failed"`
	ContextFailed bool                       `json:"context_failed"`
}
type PartialNativeOffReadSummary struct {
	ReadID           string    `json:"read_id"`
	Ordinal          int       `json:"ordinal"`
	Stage            string    `json:"stage"`
	OriginalDeadline time.Time `json:"original_deadline"`
	Returned         bool      `json:"returned"`
	CallFailed       bool      `json:"call_failed"`
	ContextFailed    bool      `json:"context_failed"`
}
type PartialNativeOffOwner struct {
	db        *sql.DB
	ctx       context.Context
	read      PartialNativeOffRead
	admission FailedInstalledPartialNativeOff
	original  partialNativeOffContext
	used      atomic.Bool
}

func (o *PartialNativeOffOwner) Read() PartialNativeOffRead        { return o.read }
func (o *PartialNativeOffOwner) Original() GuestRetirementOriginal { return o.original.stored }
func (o *PartialNativeOffOwner) Policy() model.Manifest            { return o.original.policy }
func (o *PartialNativeOffOwner) Spec() model.CapacityPolicySpec    { return o.original.spec }

func insertPartialNativeReadTx(ctx context.Context, tx *sql.Tx, r PartialNativeOffRead, stage string, value any) error {
	b, err := json.Marshal(value)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO public.capacity_guest_partial_nativeoff_reads(id,stage,reconciliation_id,ordinal,preregistration_id,retirement_request_id,original_wire,original_record,record_sha256) VALUES($1,$2,$3,$4,$5,$6,$7,$8::jsonb,$9)`, r.ReadID, stage, r.ReconciliationID, r.Ordinal, r.PreregistrationID, r.RetirementRequestID, b, string(b), capacity.BusinessCreationSHA256(b))
	return err
}

// expectedPrevious is a CAS selector from the public ledger, not a supplied
// observation. A duplicate/unknown POST cannot silently consume another read.
func (s CapacityStore) PrepareFailedInstalledPartialNativeOffRead(ctx context.Context, preID, id, expectedPrevious string) (*PartialNativeOffOwner, error) {
	deadline, ok := ctx.Deadline()
	if s.DB == nil || !ok || ctx.Err() != nil || !validCapacityExecutor(preID) || !validCapacityExecutor(id) || (expectedPrevious != "" && !validCapacityExecutor(expectedPrevious)) {
		return nil, ErrCapacityMutationAuthorization
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	var retID string
	if err = tx.QueryRowContext(ctx, `SELECT retirement_request_id::text FROM public.capacity_guest_partial_nativeoff_reconciliations WHERE id=$1 AND stage='admitted' AND preregistration_id=$2`, id, preID).Scan(&retID); err != nil {
		return nil, err
	}
	o, err := partialNativeOffContextTx(ctx, tx, preID, retID)
	if err != nil {
		return nil, err
	}
	admission, admissionSHA, err := loadPartialNativeOffTx(ctx, tx, id, "admitted")
	if err != nil || !samePartialNativeOffAdmission(admission, o) {
		return nil, ErrCapacityConflict
	}
	var qualified bool
	if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM public.capacity_guest_partial_nativeoff_reconciliations WHERE id=$1 AND stage='qualified')`, id).Scan(&qualified); err != nil || qualified {
		return nil, ErrCapacityConflict
	}
	var previousWire []byte
	var previous PartialNativeOffRead
	var previousReturned bool
	ordinal := 1
	err = tx.QueryRowContext(ctx, `SELECT s.original_wire,EXISTS(SELECT 1 FROM public.capacity_guest_partial_nativeoff_reads r WHERE r.id=s.id AND r.stage='returned') FROM public.capacity_guest_partial_nativeoff_reads s WHERE s.reconciliation_id=$1 AND s.stage='started' ORDER BY s.ordinal DESC LIMIT 1`, id).Scan(&previousWire, &previousReturned)
	switch err {
	case nil:
		if decodePrejournalOriginal(previousWire, &previous) != nil || previous.ReadID != expectedPrevious || (!previousReturned && time.Now().Before(previous.OriginalDeadline)) {
			return nil, ErrCapacityConflict
		}
		ordinal = previous.Ordinal + 1
	case sql.ErrNoRows:
		if expectedPrevious != "" {
			return nil, ErrCapacityConflict
		}
	default:
		return nil, err
	}
	issued := time.Now().UTC()
	budget := min(5*time.Second, deadline.Sub(issued))
	if ordinal > PartialNativeOffMaximumReads || budget <= 0 {
		return nil, ErrCapacityConflict
	}
	read := PartialNativeOffRead{Schema: "partial_guest548_native_off_read_v1", ReadID: uuid.NewString(), ReconciliationID: id, PreregistrationID: preID, RetirementRequestID: retID, Ordinal: ordinal, AdmissionSHA256: admissionSHA, EvidenceSHA256: partialEvidenceSHA(o.evidence), IssuedAt: issued, OriginalDeadline: originalGuestCanarySerializedDeadline(issued, budget, deadline)}
	if err = insertPartialNativeReadTx(ctx, tx, read, "started", read); err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return &PartialNativeOffOwner{db: s.DB, ctx: ctx, read: read, admission: admission, original: o}, nil
}

func partialNativeOffContent(r PartialNativeOffReturn, o *PartialNativeOffOwner) bool {
	if r.Schema != "partial_guest548_native_off_return_v1" || r.Read != o.read || r.Read.Schema != "partial_guest548_native_off_read_v1" || r.Read.OriginalDeadline.Sub(r.Read.IssuedAt) > 5*time.Second || !r.Read.OriginalDeadline.After(r.Read.IssuedAt) || r.StartedAt.Before(r.Read.IssuedAt) || r.ReturnedAt.Before(r.StartedAt) || !r.ReturnedAt.Before(r.Read.OriginalDeadline) || r.CallFailed || r.ContextFailed || r.Status != "observed" || r.Plan == nil {
		return false
	}
	return true
}

// Retain the return even after a failed/expired readonly call. Only a complete
// timely off read may qualify; the original Guest deadline is never renewed.
func (s CapacityStore) RecordFailedInstalledPartialNativeOffRead(ctx context.Context, o *PartialNativeOffOwner, r PartialNativeOffReturn) (bool, error) {
	if o == nil || o.db != s.DB || !o.used.CompareAndSwap(false, true) || r.Read != o.read || r.Schema != "partial_guest548_native_off_return_v1" || r.StartedAt.Before(o.read.IssuedAt) || r.ReturnedAt.Before(r.StartedAt) {
		return false, ErrCapacityConflict
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	// Scope serialization also protects the append-only attempt ordinal.
	if err = lockMutationScope(ctx, tx, o.original.policy.Metadata.Namespace, o.original.spec); err != nil {
		return false, err
	}
	var startedWire []byte
	if err = tx.QueryRowContext(ctx, `SELECT original_wire FROM public.capacity_guest_partial_nativeoff_reads WHERE id=$1 AND stage='started' AND reconciliation_id=$2 FOR SHARE`, o.read.ReadID, o.read.ReconciliationID).Scan(&startedWire); err != nil {
		return false, err
	}
	expected, _ := json.Marshal(o.read)
	if !reflect.DeepEqual(startedWire, expected) {
		return false, ErrCapacityConflict
	}
	if err = insertPartialNativeReadTx(ctx, tx, o.read, "returned", r); err != nil {
		return false, err
	}
	if err = tx.Commit(); err != nil {
		return false, err
	}
	if !partialNativeOffContent(r, o) || o.ctx.Err() != nil || !time.Now().Before(o.read.OriginalDeadline) {
		return false, nil
	}
	// The audit return above survives a refused final qualification. No failed
	// provider read disappears merely because it supplies no cleanup authority.
	return s.qualifyPartialNativeOffRead(ctx, o, r)
}

func (s CapacityStore) qualifyPartialNativeOffRead(ctx context.Context, o *PartialNativeOffOwner, r PartialNativeOffReturn) (bool, error) {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	current, err := partialNativeOffContextTx(ctx, tx, o.read.PreregistrationID, o.read.RetirementRequestID)
	if err != nil {
		return false, err
	}
	var latest int
	if err = tx.QueryRowContext(ctx, `SELECT max(ordinal) FROM public.capacity_guest_partial_nativeoff_reads WHERE reconciliation_id=$1 AND stage='started'`, o.read.ReconciliationID).Scan(&latest); err != nil {
		return false, err
	}
	if latest != o.read.Ordinal || !samePartialNativeOffAdmission(o.admission, current) {
		return false, ErrCapacityConflict
	}
	binding, err := capacity.VMObservationBinding(current.spec, current.stored.Binding.MutationBindingName)
	if err != nil {
		return false, err
	}
	receipt, err := failedInstalledLegacyReceiptTx(ctx, tx, current.stored)
	if err != nil || capacity.GuestRetirementV2NativeOffPlanContent(current.spec, binding, *r.Plan, receipt) != nil {
		return false, ErrCapacityConflict
	}
	admission, admissionSHA, err := loadPartialNativeOffTx(ctx, tx, o.read.ReconciliationID, "admitted")
	if err != nil {
		return false, err
	}
	admission.Stage = "qualified"
	admission.AdmissionSHA256 = admissionSHA
	admission.NativeReadID = o.read.ReadID
	admission.NativeOffSHA256 = capacity.GuestRetirementSHA(r)
	if _, err = insertPartialNativeOffTx(ctx, tx, admission); err != nil {
		return false, err
	}
	current.disposal.NativePoweroffSHA256 = admission.NativeOffSHA256
	if _, err = finishFailedInstalledCleanupTx(ctx, tx, current.disposal, current.current, o.read.RetirementRequestID, time.Now().UTC()); err != nil {
		return false, err
	}
	if o.ctx.Err() != nil || !time.Now().Before(o.read.OriginalDeadline) {
		return false, ErrCapacityLease
	}
	if err = tx.Commit(); err != nil {
		return false, err
	}
	return true, nil
}

func (s CapacityStore) ReadFailedInstalledPartialNativeOffReads(ctx context.Context, id string) ([]PartialNativeOffReadSummary, error) {
	if s.DB == nil || !validCapacityExecutor(id) {
		return nil, ErrCapacityMutationAuthorization
	}
	rows, err := s.DB.QueryContext(ctx, `SELECT s.original_wire,r.original_wire FROM public.capacity_guest_partial_nativeoff_reads s LEFT JOIN public.capacity_guest_partial_nativeoff_reads r ON r.id=s.id AND r.stage='returned' WHERE s.reconciliation_id=$1 AND s.stage='started' ORDER BY s.ordinal`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []PartialNativeOffReadSummary{}
	for rows.Next() {
		var b, ret []byte
		var r PartialNativeOffRead
		var result PartialNativeOffReturn
		if err = rows.Scan(&b, &ret); err != nil {
			return nil, err
		}
		if decodePrejournalOriginal(b, &r) != nil {
			return nil, ErrCapacityConflict
		}
		v := PartialNativeOffReadSummary{ReadID: r.ReadID, Ordinal: r.Ordinal, Stage: "started", OriginalDeadline: r.OriginalDeadline}
		if len(ret) > 0 {
			if decodePrejournalOriginal(ret, &result) != nil || result.Read != r {
				return nil, ErrCapacityConflict
			}
			v.Stage = "returned"
			v.Returned = true
			v.CallFailed = result.CallFailed
			v.ContextFailed = result.ContextFailed
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// The terminal branch revalidates this distinct81 proof. It never routes a
// partial retirement through the normal four-record/caller200 validator.
func partialNativeOffQualifiedTx(ctx context.Context, tx *sql.Tx, r FailedInstalledGuestDisposal, stored GuestRetirementOriginal, p model.CapacityPolicySpec) (bool, error) {
	var id string
	err := tx.QueryRowContext(ctx, `SELECT id::text FROM public.capacity_guest_partial_nativeoff_reconciliations WHERE disposal_id=$1 AND retirement_request_id=$2 AND stage='qualified'`, r.ID, r.RetirementRequestID).Scan(&id)
	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return true, err
	}
	admission, _, err := loadPartialNativeOffTx(ctx, tx, id, "admitted")
	if err != nil {
		return true, err
	}
	qualified, _, err := loadPartialNativeOffTx(ctx, tx, id, "qualified")
	if err != nil {
		return true, err
	}
	expected := admission
	expected.Stage = "qualified"
	expected.AdmissionSHA256 = capacity.GuestRetirementSHA(admission)
	expected.NativeReadID = qualified.NativeReadID
	expected.NativeOffSHA256 = qualified.NativeOffSHA256
	if !reflect.DeepEqual(expected, qualified) || qualified.NativeOffSHA256 != r.NativePoweroffSHA256 || admission.DisposalID != r.ID || admission.PreregistrationID != r.PreregistrationID || admission.RetirementRequestID != stored.Request.Intent.RequestID || r.ClaimedIntent == nil || !reflect.DeepEqual(admission.OriginalClaimedIntent, *r.ClaimedIntent) {
		return true, ErrCapacityConflict
	}
	evidence, err := partialNativeOffEvidenceTx(ctx, tx, stored, time.Now().UTC())
	if err != nil || evidence != admission.Evidence {
		return true, ErrCapacityConflict
	}
	var readWire, returnWire []byte
	if err = tx.QueryRowContext(ctx, `SELECT s.original_wire,v.original_wire FROM public.capacity_guest_partial_nativeoff_reads s JOIN public.capacity_guest_partial_nativeoff_reads v ON v.id=s.id AND v.stage='returned' WHERE s.id=$1 AND s.reconciliation_id=$2 AND s.stage='started'`, qualified.NativeReadID, id).Scan(&readWire, &returnWire); err != nil {
		return true, err
	}
	var read PartialNativeOffRead
	var returned PartialNativeOffReturn
	if decodePrejournalOriginal(readWire, &read) != nil || decodePrejournalOriginal(returnWire, &returned) != nil || capacity.GuestRetirementSHA(returned) != r.NativePoweroffSHA256 || read.AdmissionSHA256 != qualified.AdmissionSHA256 || read.EvidenceSHA256 != partialEvidenceSHA(evidence) {
		return true, ErrCapacityConflict
	}
	o := &PartialNativeOffOwner{read: read}
	if !partialNativeOffContent(returned, o) {
		return true, ErrCapacityConflict
	}
	binding, err := capacity.VMObservationBinding(p, stored.Binding.MutationBindingName)
	if err != nil {
		return true, err
	}
	receipt, err := failedInstalledLegacyReceiptTx(ctx, tx, stored)
	if err != nil || capacity.GuestRetirementV2NativeOffPlanContent(p, binding, *returned.Plan, receipt) != nil {
		return true, ErrCapacityConflict
	}
	return true, nil
}
