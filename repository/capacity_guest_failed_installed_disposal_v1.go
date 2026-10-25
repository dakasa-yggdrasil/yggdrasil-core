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

const failedInstalledV2Mode = "original_production_v2"
const failedInstalledLegacyV1Mode = "legacy_guest548_original_v1"
const failedInstalledLegacyGuestSource = "548734eef627404f10b5117e0ec7f27582ae9048"

// This is not a selectable workflow flag. The exact historical map authenticates
// the WHOLE original two contracts, including keys/profile/catalog/checksums.
func failedInstalledRetirementMode(p model.CapacityPolicySpec, b model.CapacityGuestRetirementBinding) string {
	return failedInstalledRetirementModeForIssuer(p, b, capacity.CurrentGuestCoreSource())
}
func failedInstalledRetirementModeForIssuer(p model.CapacityPolicySpec, b model.CapacityGuestRetirementBinding, issuer string) string {
	if b.GuestSourceCommit != failedInstalledLegacyGuestSource {
		return failedInstalledV2Mode
	}
	if b.EvidenceClass == "owned_provisioner_original" && capacity.GuestBindingApprovedByCompatibilityMap(p, b, issuer, capacity.GuestD12ProtocolCompatibilityMapSHA256) {
		return failedInstalledLegacyV1Mode
	}
	return ""
}

// Only a live, backend-derived disposal claim can select production legacy V1.
// Current issuer remains the actual build; the wire uses original enrollment
// authority and the original V1 30s UTC deadline. No Guest V2 claim is made.
func (s CapacityStore) FailedInstalledGuestLegacyV1(ctx context.Context, policy model.Manifest, generation, fence int64, owner, preID string) (bool, error) {
	legacy := false
	err := s.mutationTransaction(ctx, policy, false, generation, fence, owner, func(tx *sql.Tx, p model.CapacityPolicySpec, current model.CapacityIntent, now time.Time) error {
		if current.FailedInstalledDisposal == nil {
			return nil
		}
		if current.FailedInstalledDisposal.PreregistrationID != preID {
			return ErrCapacityConflict
		}
		valid, err := s.failedInstalledDisposalActiveTx(ctx, tx, policy, p, current, 1, now)
		if err != nil || !valid {
			return ErrCapacityConflict
		}
		r, _, err := loadFailedInstalledDisposalTx(ctx, tx, current.FailedInstalledDisposal.ID, "claimed")
		if err != nil {
			return err
		}
		legacy = r.RetirementMode == failedInstalledLegacyV1Mode
		return nil
	})
	return legacy, err
}

func failedInstalledLegacyJoin(r FailedInstalledGuestDisposal, stored GuestRetirementOriginal, p model.CapacityPolicySpec) bool {
	i := stored.Request.Intent
	return r.RetirementMode == failedInstalledLegacyV1Mode && failedInstalledRetirementMode(p, stored.Binding) == failedInstalledLegacyV1Mode && r.ClaimedIntent != nil && r.PreregistrationID == stored.Preregistration.PreregistrationID && i.Slot == 1 && i.Tuple == stored.Receipt.Enrollment.Statement.Tuple && i.PolicyID == r.OriginalIntent.PolicyID.String() && i.PolicyChecksum == r.OriginalIntent.PolicyChecksum && i.Generation == uint64(r.ClaimedIntent.Generation) && i.Fence == uint64(r.ClaimedIntent.FencingToken) && i.LeaseOwner == r.ClaimedIntent.LeaseOwner && stored.ExecutorID == r.ClaimedIntent.LeaseExecutorID
}

// A distinct V1 native-read record. The provider content validator is shared
// with V2 solely for physical identity/labels/stopped state, not Guest proofs.
type FailedInstalledLegacyNativeRead struct {
	Schema               string    `json:"schema"`
	ReadID               string    `json:"read_id"`
	IntentID             string    `json:"intent_id"`
	IntentSHA256         string    `json:"intent_sha256"`
	OriginalCallerSHA256 string    `json:"original_caller_sha256"`
	AdmissionID          string    `json:"admission_id"`
	BindingSHA256        string    `json:"binding_sha256"`
	IssuedAt             time.Time `json:"issued_at"`
	OriginalDeadline     time.Time `json:"original_deadline"`
}
type FailedInstalledLegacyNativeReturn struct {
	Schema        string                          `json:"schema"`
	Read          FailedInstalledLegacyNativeRead `json:"read"`
	Status        string                          `json:"status"`
	Plan          *model.CapacityVMFleetPlan      `json:"plan,omitempty"`
	StartedAt     time.Time                       `json:"started_at"`
	ReturnedAt    time.Time                       `json:"returned_at"`
	CallFailed    bool                            `json:"call_failed"`
	ContextFailed bool                            `json:"context_failed"`
}
type FailedInstalledLegacyNativeOwner struct {
	db       *sql.DB
	ctx      context.Context
	read     FailedInstalledLegacyNativeRead
	stored   GuestRetirementOriginal
	policy   model.Manifest
	spec     model.CapacityPolicySpec
	snapshot string
	used     atomic.Bool
}

func (o *FailedInstalledLegacyNativeOwner) Original() GuestRetirementOriginal     { return o.stored }
func (o *FailedInstalledLegacyNativeOwner) Policy() model.Manifest                { return o.policy }
func (o *FailedInstalledLegacyNativeOwner) Spec() model.CapacityPolicySpec        { return o.spec }
func (o *FailedInstalledLegacyNativeOwner) Read() FailedInstalledLegacyNativeRead { return o.read }

func (s CapacityStore) failedInstalledLegacyCurrentTx(ctx context.Context, tx *sql.Tx, id, preID, admissionID string) (FailedInstalledGuestDisposal, GuestRetirementOriginal, model.Manifest, model.CapacityPolicySpec, model.CapacityIntent, error) {
	var stored GuestRetirementOriginal
	var policy model.Manifest
	var p model.CapacityPolicySpec
	var current model.CapacityIntent
	r, _, err := loadFailedInstalledDisposalTx(ctx, tx, admissionID, "claimed")
	if err != nil || r.PreregistrationID != preID || r.RetirementMode != failedInstalledLegacyV1Mode || r.ClaimedIntent == nil {
		return r, stored, policy, p, current, ErrCapacityConflict
	}
	if err = lockMutationScope(ctx, tx, r.Namespace, model.CapacityPolicySpec{Environment: r.Environment, Domain: r.Domain, Dimension: r.Dimension}); err != nil {
		return r, stored, policy, p, current, err
	}
	stored, err = loadGuestRetirementTx(ctx, tx, id)
	if err != nil {
		return r, stored, policy, p, current, err
	}
	var now time.Time
	if err = tx.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		return r, stored, policy, p, current, err
	}
	scoped := s
	scoped.WorkflowID = uuid.MustParse(stored.Request.Intent.WorkflowID)
	scoped.ExecutorID = stored.ExecutorID
	policy, p, current, err = scoped.guestRetirementCurrentTx(ctx, tx, stored, now, false)
	if err != nil {
		// Once the actual finish failed with ACK, a new provider GET is allowed;
		// it cannot renew or replay the original Guest V1 retirement write.
		read, e := loadFailedInstalledRetirementReadTx(ctx, tx, id, preID, admissionID)
		if e != nil || read.LegacyOriginal == nil {
			return r, stored, policy, p, current, ErrCapacityConflict
		}
		policy, p, current = read.Policy, read.Spec, read.Current
	}
	if !failedInstalledLegacyJoin(r, stored, p) {
		return r, stored, policy, p, current, ErrCapacityConflict
	}
	if _, err = guestQuiescentProofTx(ctx, tx, stored); err != nil {
		return r, stored, policy, p, current, err
	}
	return r, stored, policy, p, current, nil
}

func (s CapacityStore) PrepareFailedInstalledGuestLegacyNativeRead(ctx context.Context, id, preID, admissionID string) (*FailedInstalledLegacyNativeOwner, error) {
	deadline, ok := ctx.Deadline()
	if s.DB == nil || !ok || ctx.Err() != nil || !time.Now().Before(deadline) {
		return nil, ErrCapacityLease
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	r, stored, policy, p, current, err := s.failedInstalledLegacyCurrentTx(ctx, tx, id, preID, admissionID)
	if err != nil {
		return nil, err
	}
	var callerSHA string
	if err = tx.QueryRowContext(ctx, `SELECT return_sha256 FROM public.capacity_guest_original_caller_returns WHERE intent_id=$1`, id).Scan(&callerSHA); err != nil {
		return nil, err
	}
	b, err := capacity.VMObservationBinding(p, stored.Binding.MutationBindingName)
	if err != nil {
		return nil, err
	}
	issued := time.Now()
	budget := min(5*time.Second, deadline.Sub(issued))
	if budget <= 0 {
		return nil, ErrCapacityLease
	}
	read := FailedInstalledLegacyNativeRead{Schema: "failed_installed_guest548_v1_native_off_read_v1", ReadID: uuid.NewString(), IntentID: id, IntentSHA256: capacity.GuestRetirementSHA(stored.Request.Intent), OriginalCallerSHA256: callerSHA, AdmissionID: admissionID, BindingSHA256: capacity.GuestRetirementSHA(b), IssuedAt: issued.UTC(), OriginalDeadline: originalGuestCanarySerializedDeadline(issued, budget, deadline)}
	raw, err := json.Marshal(read)
	if err != nil {
		return nil, err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO public.capacity_guest_original_native_poweroff_reads(id,intent_id,observation_sha256,original_wire,original_record,recorded_at) VALUES($1,$2,$3,$4,$5::jsonb,clock_timestamp())`, read.ReadID, id, capacity.GuestRetirementSHA(read), raw, string(raw)); err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return &FailedInstalledLegacyNativeOwner{db: s.DB, ctx: ctx, read: read, stored: stored, policy: policy, spec: p, snapshot: capacity.GuestRetirementSHA(struct {
		R FailedInstalledGuestDisposal
		C model.CapacityIntent
	}{r, current})}, nil
}

func failedInstalledLegacyNativeContent(r FailedInstalledLegacyNativeReturn, stored GuestRetirementOriginal, p model.CapacityPolicySpec, b model.CapacityMutationBinding, receipt model.CapacityMutationReceipt) bool {
	c := r.Read
	if r.Schema != "failed_installed_guest548_v1_native_off_return_v1" || c.Schema != "failed_installed_guest548_v1_native_off_read_v1" || !validCapacityExecutor(c.ReadID) || !validCapacityExecutor(c.AdmissionID) || c.IntentID != stored.Request.Intent.RequestID || c.IntentSHA256 != capacity.GuestRetirementSHA(stored.Request.Intent) || !capacity.ValidDigest(c.OriginalCallerSHA256) || c.BindingSHA256 != capacity.GuestRetirementSHA(b) || c.IssuedAt.IsZero() || !c.OriginalDeadline.After(c.IssuedAt) || c.OriginalDeadline.Sub(c.IssuedAt) > 5*time.Second || r.StartedAt.Before(c.IssuedAt) || r.ReturnedAt.Before(r.StartedAt) || !r.ReturnedAt.Before(c.OriginalDeadline) || r.CallFailed || r.ContextFailed || r.Status != "observed" || r.Plan == nil {
		return false
	}
	return capacity.GuestRetirementV2NativeOffPlanContent(p, b, *r.Plan, receipt) == nil
}
func failedInstalledLegacyReceiptTx(ctx context.Context, tx *sql.Tx, stored GuestRetirementOriginal) (model.CapacityMutationReceipt, error) {
	var raw []byte
	var r capacityMutationRecord
	if err := tx.QueryRowContext(ctx, `SELECT grant_record FROM public.capacity_mutation_grants WHERE id=$1`, stored.Preregistration.OriginalCreateGrantID).Scan(&raw); err != nil {
		return model.CapacityMutationReceipt{}, err
	}
	if json.Unmarshal(raw, &r) != nil || r.Settlement == nil || r.Proof == nil || r.Grant.State != "confirmed" || r.Grant.GrantID != stored.Preregistration.OriginalCreateGrantID {
		return model.CapacityMutationReceipt{}, ErrCapacityConflict
	}
	return guestMutationReceiptV2(r), nil
}
func (s CapacityStore) RecordFailedInstalledGuestLegacyNativeRead(ctx context.Context, o *FailedInstalledLegacyNativeOwner, r FailedInstalledLegacyNativeReturn) error {
	if o == nil || o.db != s.DB || ctx != o.ctx || ctx.Err() != nil || r.Read != o.read || !time.Now().Before(o.read.OriginalDeadline) || !o.used.CompareAndSwap(false, true) {
		return ErrCapacityConflict
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	admission, stored, _, p, current, err := s.failedInstalledLegacyCurrentTx(ctx, tx, o.read.IntentID, o.stored.Preregistration.PreregistrationID, o.read.AdmissionID)
	if err != nil || capacity.GuestRetirementSHA(struct {
		R FailedInstalledGuestDisposal
		C model.CapacityIntent
	}{admission, current}) != o.snapshot {
		return ErrCapacityConflict
	}
	b, err := capacity.VMObservationBinding(p, stored.Binding.MutationBindingName)
	if err != nil {
		return err
	}
	receipt, err := failedInstalledLegacyReceiptTx(ctx, tx, stored)
	if err != nil || !failedInstalledLegacyNativeContent(r, stored, p, b, receipt) {
		return ErrCapacityConflict
	}
	raw, err := json.Marshal(r)
	if err != nil {
		return err
	}
	challenge, _ := json.Marshal(o.read)
	_, err = tx.ExecContext(ctx, `INSERT INTO public.capacity_guest_original_native_poweroff_reads(id,intent_id,observation_sha256,original_wire,original_record,original_native_join_wire,recorded_at) VALUES($1,$2,$3,$4,$5::jsonb,$6,clock_timestamp())`, uuid.New(), o.read.IntentID, capacity.GuestRetirementSHA(r), raw, string(raw), challenge)
	if err != nil {
		return err
	}
	if ctx.Err() != nil || !time.Now().Before(o.read.OriginalDeadline) {
		return ErrCapacityLease
	}
	return tx.Commit()
}
func failedInstalledLegacyOffTx(ctx context.Context, tx *sql.Tx, r FailedInstalledGuestDisposal, stored GuestRetirementOriginal, p model.CapacityPolicySpec, fresh bool) (string, error) {
	var raw, join []byte
	var digest string
	var consistent bool
	var recorded, issued, ack, now time.Time
	if err := tx.QueryRowContext(ctx, `SELECT original_wire,original_native_join_wire,observation_sha256,recorded_at,original_record=convert_from(original_wire,'UTF8')::jsonb FROM public.capacity_guest_original_native_poweroff_reads WHERE intent_id=$1 AND original_record->>'schema'='failed_installed_guest548_v1_native_off_return_v1' ORDER BY recorded_at DESC,id DESC LIMIT 1`, stored.Request.Intent.RequestID).Scan(&raw, &join, &digest, &recorded, &consistent); err != nil {
		return "", err
	}
	var off FailedInstalledLegacyNativeReturn
	if !consistent || capacity.BusinessCreationSHA256(raw) != digest || capacity.DecodeGuestLifecycle(raw, &off) != nil || off.Read.AdmissionID != r.ID {
		return "", ErrCapacityConflict
	}
	var original []byte
	var callerSHA string
	if err := tx.QueryRowContext(ctx, `SELECT r.original_wire,r.recorded_at,c.recorded_at,c.return_sha256,clock_timestamp() FROM public.capacity_guest_original_native_poweroff_reads r JOIN public.capacity_guest_original_caller_returns c ON c.intent_id=r.intent_id WHERE r.id=$1 AND r.intent_id=$2`, off.Read.ReadID, off.Read.IntentID).Scan(&original, &issued, &ack, &callerSHA, &now); err != nil || !reflect.DeepEqual(original, join) || !issued.After(ack) || recorded.Before(issued) || off.Read.OriginalCallerSHA256 != callerSHA || fresh && now.Sub(recorded) > 5*time.Second {
		return "", ErrCapacityConflict
	}
	expected, _ := json.Marshal(off.Read)
	if !reflect.DeepEqual(expected, join) {
		return "", ErrCapacityConflict
	}
	b, err := capacity.VMObservationBinding(p, stored.Binding.MutationBindingName)
	if err != nil {
		return "", err
	}
	receipt, err := failedInstalledLegacyReceiptTx(ctx, tx, stored)
	if err != nil || !failedInstalledLegacyNativeContent(off, stored, p, b, receipt) {
		return "", ErrCapacityConflict
	}
	return digest, nil
}

func (s CapacityStore) PrepareFailedInstalledGuestLegacyCleanup(ctx context.Context, policy model.Manifest, generation, fence int64, owner, id string) (FailedInstalledGuestDisposal, error) {
	var out FailedInstalledGuestDisposal
	err := s.mutationTransaction(ctx, policy, false, generation, fence, owner, func(tx *sql.Tx, p model.CapacityPolicySpec, current model.CapacityIntent, now time.Time) error {
		if current.FailedInstalledDisposal == nil || s.guestNotifyOrigin == nil || s.guestNotifyOrigin.source != capacity.CurrentGuestCoreSource() || s.guestNotifyOrigin.step.Use.Operation != "capacity.finish_original_guest_retirement" {
			return ErrCapacityConflict
		}
		r, stored, _, _, _, err := s.failedInstalledLegacyCurrentTx(ctx, tx, id, current.FailedInstalledDisposal.PreregistrationID, current.FailedInstalledDisposal.ID)
		if err != nil {
			return err
		}
		if r.NativePoweroffSHA256, err = failedInstalledLegacyOffTx(ctx, tx, r, stored, p, true); err != nil {
			return err
		}
		out, err = finishFailedInstalledCleanupTx(ctx, tx, r, current, id, now)
		return err
	})
	return out, err
}
func finishFailedInstalledCleanupTx(ctx context.Context, tx *sql.Tx, r FailedInstalledGuestDisposal, current model.CapacityIntent, id string, now time.Time) (FailedInstalledGuestDisposal, error) {
	r.Stage = "quiescent"
	r.RetirementRequestID = id
	if _, err := insertFailedInstalledDisposalTx(ctx, tx, r); err != nil {
		return r, err
	}
	next := current
	m := *next.FailedInstalledDisposal
	m.Stage = "quiescent"
	next.FailedInstalledDisposal = &m
	next.Phase = "failed_installed_cleanup_pending"
	next.LeaseOwner = ""
	next.LeaseExecutorID = ""
	next.LeaseExpiresAt = nil
	next.UpdatedAt = now
	return r, persistFailedInstalledDisposalIntentTx(ctx, tx, current, next)
}
