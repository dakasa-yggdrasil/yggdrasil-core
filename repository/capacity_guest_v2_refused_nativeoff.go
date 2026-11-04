package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"reflect"
	"sync/atomic"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

// ADR-0092. An original_production_v2 failed-installed disposal whose Guest
// answered the V2 nonce, journaled only possible_start and then refused the
// single retirement POST (closed non-200, body not retained) can never meet
// the normal five-row/caller-200 quiescence proof. This lane admits exactly
// that history and quiesces the disposal from one bounded native OFF read of
// the expired intent's own tuple. It never claims writer quiescence and never
// sends a Guest request, a poweroff or a DELETE.

// V2RefusedNativeOffMaximumReads bounds the native observe GETs one admission
// may spend (the operator powers the server off outside Core, then retries).
const V2RefusedNativeOffMaximumReads = 5

const v2RefusedNativeOffSchema = "failed_installed_v2_refused_native_off_quiescence_v1"
const v2RefusedNativeOffOrder = "v2_nonce_then_possible_start_then_closed_caller_refusal_v1"
const v2NativePoweroffChallengeSchema = "original_core_guest_native_poweroff_read_challenge_v2"
const v2NativePoweroffReturnSchema = "original_core_guest_native_poweroff_read_return_v2"

// Historical facts of the refused retirement. None of them is a Guest
// quiescence, a poweroff command return or a caller success.
type V2RefusedNativeOffEvidence struct {
	Order             string    `json:"order"`
	GuestSource       string    `json:"guest_source"`
	IntentSHA256      string    `json:"intent_sha256"`
	ObservationSHA256 [2]string `json:"observation_sha256"`
	CallerSHA256      string    `json:"caller_sha256"`
	CallerStatus      int       `json:"caller_status"`
}

type FailedInstalledV2RefusedNativeOff struct {
	Schema                string                     `json:"schema"`
	ID                    string                     `json:"id"`
	Stage                 string                     `json:"stage"`
	DisposalID            string                     `json:"disposal_id"`
	PreregistrationID     string                     `json:"preregistration_id"`
	RetirementRequestID   string                     `json:"retirement_request_id"`
	Issuer                string                     `json:"issuer"`
	ActualCoreSource      string                     `json:"actual_core_source"`
	OriginalClaimSHA256   string                     `json:"original_claim_sha256"`
	OriginalClaimedIntent model.CapacityIntent       `json:"original_claimed_intent"`
	FailedRun             string                     `json:"failed_run"`
	Evidence              V2RefusedNativeOffEvidence `json:"evidence"`
	AdmissionSHA256       string                     `json:"admission_sha256,omitempty"`
	NativeReadID          string                     `json:"native_read_id,omitempty"`
	NativeOffSHA256       string                     `json:"native_off_sha256,omitempty"`
}

type v2RefusedNativeOffContext struct {
	disposal FailedInstalledGuestDisposal
	claimSHA string
	stored   GuestRetirementOriginalV2
	policy   model.Manifest
	spec     model.CapacityPolicySpec
	current  model.CapacityIntent
	binding  model.CapacityMutationBinding
	evidence V2RefusedNativeOffEvidence
	run      string
}

func insertV2RefusedNativeOffTx(ctx context.Context, tx *sql.Tx, r FailedInstalledV2RefusedNativeOff) (string, error) {
	b, err := json.Marshal(r)
	if err != nil {
		return "", err
	}
	h := capacity.BusinessCreationSHA256(b)
	_, err = tx.ExecContext(ctx, `INSERT INTO public.capacity_guest_v2_refused_nativeoff_quiescences(id,stage,disposal_id,preregistration_id,retirement_request_id,original_wire,original_record,record_sha256) VALUES($1,$2,$3,$4,$5,$6,$7::jsonb,$8)`, r.ID, r.Stage, r.DisposalID, r.PreregistrationID, r.RetirementRequestID, b, string(b), h)
	return h, err
}

func loadV2RefusedNativeOffTx(ctx context.Context, tx *sql.Tx, id, stage string) (FailedInstalledV2RefusedNativeOff, string, time.Time, error) {
	var r FailedInstalledV2RefusedNativeOff
	var b []byte
	var h string
	var recorded time.Time
	var consistent bool
	err := tx.QueryRowContext(ctx, `SELECT original_wire,record_sha256,recorded_at,original_record=convert_from(original_wire,'UTF8')::jsonb FROM public.capacity_guest_v2_refused_nativeoff_quiescences WHERE id=$1 AND stage=$2 FOR SHARE`, id, stage).Scan(&b, &h, &recorded, &consistent)
	if err != nil {
		return r, "", recorded, err
	}
	if !consistent || capacity.BusinessCreationSHA256(b) != h || decodePrejournalOriginal(b, &r) != nil || r.ID != id || r.Stage != stage || r.Schema != v2RefusedNativeOffSchema {
		return r, "", recorded, ErrCapacityConflict
	}
	return r, h, recorded, nil
}

// v2RefusedCallerClosed accepts only the single closed caller answer of the
// original POST: a real non-200 HTTP status, completely read and closed before
// the original deadline, with no retained body. A 200, a persisted body or any
// transport failure is not a refusal and is never reinterpreted as one.
func v2RefusedCallerClosed(c GuestOriginalCallerReturn, i model.CapacityGuestRetirementIntentV2) bool {
	return GuestOriginalCallerBodyFactsValid(c) && c.RequestID == i.RequestID && c.AttemptID == i.AttemptID && c.OriginalDeadline.Equal(i.OriginalDeadline) &&
		!c.StartedAt.Before(i.IssuedAt) && !c.BodyPersisted && len(c.Body) == 0 &&
		!c.PreflightFailed && !c.DoFailed && !c.ReadFailed && !c.CloseFailed && !c.OriginalContextFailed &&
		c.Status != 200 && c.Status >= 400 && c.Status <= 599 &&
		!c.DoStartedAt.Before(c.StartedAt) && !c.DoReturnedAt.Before(c.DoStartedAt) && !c.ReadReturnedAt.IsZero() && !c.ReadReturnedAt.Before(c.DoReturnedAt) &&
		!c.CloseReturnedAt.Before(c.ReadReturnedAt) && !c.DriverReturnedAt.Before(c.CloseReturnedAt) && c.DriverReturnedAt.Before(i.OriginalDeadline)
}

// v2RefusedPossibleStart accepts only the authentic signed first Guest record:
// possible_start, no runtime return, no writer quiescence, no poweroff.
func v2RefusedPossibleStart(o model.CapacityGuestRetirementObservationV2, stored GuestRetirementOriginalV2) bool {
	r := o.Record
	return capacity.GuestRetirementV2Observation(o, stored.Receipt.Enrollment, stored.Request.Intent, false) == nil &&
		r.Sequence == 1 && r.State == "possible_start" && r.PreviousSHA256 == "" && !r.WriterQuiescenceEvidence &&
		!r.PoweroffCommandReturned && !r.PoweredOffObserved && r.PoweroffPossibleStartAt == nil && r.PoweroffOperation == nil && r.RuntimeReturn == nil
}

type v2RefusedClaimPlan struct {
	Mode              string `json:"mode"`
	Reason            string `json:"reason"`
	Slot              int    `json:"slot"`
	Generation        int64  `json:"generation"`
	FencingToken      int64  `json:"fencing_token"`
	LeaseOwner        string `json:"lease_owner"`
	PreregistrationID string `json:"preregistration_id"`
}

// v2RefusedRetireStepError and v2RefusedRetireStepPredicate are what the
// internal retire-original-guest step records when the V2 production
// retirement (executeProductionGuestRetirementV2) returns an error: its fail
// closure replaces the step metadata with exactly this one predicate and
// never records a request_id, so the failed step cannot name its intent.
const (
	v2RefusedRetireStepError     = "protected original Guest source step unavailable; HOLD and recover by exact GET"
	v2RefusedRetireStepPredicate = "original-production-retirement-v2-held"
)

// v2RefusedClaimRunSteps requires the claim run to be the failed seven-step
// run whose plan retired exactly this claimed epoch and whose retire step
// failed inside the V2 production retirement, with every later step skipped
// (finish never ran). The internal plan step stores its plan as the step
// metadata itself (executeOriginalGuestReconcile unmarshals the plan into
// result.Metadata); only adapter steps wrap their output under "output".
func v2RefusedClaimRunSteps(steps []model.WorkflowRunStepResult, current model.CapacityIntent, preID string) bool {
	if len(steps) != 7 {
		return false
	}
	states := map[string]string{}
	var plan, retire *model.WorkflowRunStepResult
	for n := range steps {
		if _, dup := states[steps[n].ID]; dup {
			return false
		}
		states[steps[n].ID] = steps[n].Status
		switch steps[n].ID {
		case "plan-original-guest":
			plan = &steps[n]
		case "retire-original-guest":
			retire = &steps[n]
		}
	}
	if states["plan-original-guest"] != "succeeded" || states["retire-original-guest"] != "failed" || states["finish-original-retirement"] != "skipped" || states["provision-original-notify"] != "skipped" || states["complete-original-provision"] != "skipped" || states["refresh-original-membership"] != "skipped" || states["complete-original-retirement"] != "skipped" || plan == nil || retire == nil {
		return false
	}
	// The failed retire step carries no request id, so it is tied to the
	// admitted retirement by its V2 refusal predicate plus the single V2
	// intent of the preregistration issued under this same epoch.
	if predicate, _ := retire.Metadata["original_guest_refusal_predicate"].(string); retire.Error != v2RefusedRetireStepError || len(retire.Metadata) != 1 || predicate != v2RefusedRetireStepPredicate {
		return false
	}
	if _, wrapped := plan.Metadata["output"]; wrapped {
		return false
	}
	raw, err := json.Marshal(plan.Metadata)
	var out v2RefusedClaimPlan
	if err != nil || json.Unmarshal(raw, &out) != nil {
		return false
	}
	return out.Mode == "retire" && out.Reason == "failed_installed_disposal" && out.Slot == FailedInstalledDisposalClaimSlot(current) && out.Generation == current.Generation && out.FencingToken == current.FencingToken && out.LeaseOwner != "" && out.LeaseOwner == current.LeaseOwner && out.PreregistrationID == preID
}

// v2RefusedEvidenceTx re-derives the append-only refused retirement history.
// It deliberately does not look at native poweroff reads: those are checked
// by the admission and qualification paths themselves.
func v2RefusedEvidenceTx(ctx context.Context, tx *sql.Tx, stored GuestRetirementOriginalV2, disposalID string, now time.Time) (V2RefusedNativeOffEvidence, error) {
	var e V2RefusedNativeOffEvidence
	i := stored.Request.Intent
	var deadline time.Time
	var canonicalDeadline, intentSHA, schema string
	if err := tx.QueryRowContext(ctx, `SELECT original_deadline,intent_record->>'original_deadline',intent_sha256,intent_record->>'schema' FROM public.capacity_vm_retirement_intents WHERE id=$1 AND preregistration_id=$2 FOR SHARE`, i.RequestID, stored.Preregistration.PreregistrationID).Scan(&deadline, &canonicalDeadline, &intentSHA, &schema); err != nil {
		return e, ErrCapacityConflict
	}
	original, err := time.Parse(time.RFC3339Nano, canonicalDeadline)
	if err != nil || schema != capacity.GuestRetirementV2IntentSchema || deadline.After(now) || original.After(now) || i.OriginalDeadline.After(now) {
		return e, ErrCapacityConflict
	}
	var intents, attempts, journal, poweroffAuthority, deletes, recoveries int
	if err = tx.QueryRowContext(ctx, `SELECT
 (SELECT count(*) FROM public.capacity_vm_retirement_intents WHERE preregistration_id=$2),
 (SELECT count(*) FROM public.capacity_guest_original_caller_attempts WHERE intent_id=$1),
 (SELECT count(*) FROM public.capacity_vm_retirement_original_returns WHERE intent_id=$1),
 (SELECT count(*) FROM public.capacity_guest_original_authority_reads WHERE intent_id=$1 AND phase='before_poweroff'),
 (SELECT count(*) FROM public.capacity_vm_retirement_delete_bindings WHERE intent_id=$1),
 (SELECT count(*) FROM public.capacity_guest_presend_retirement_recoveries WHERE disposal_id=$3)+
 (SELECT count(*) FROM public.capacity_guest_prejournal_refusal_recoveries WHERE disposal_id=$3)+
 (SELECT count(*) FROM public.capacity_guest_partial_nativeoff_reconciliations WHERE disposal_id=$3)`, i.RequestID, stored.Preregistration.PreregistrationID, disposalID).Scan(&intents, &attempts, &journal, &poweroffAuthority, &deletes, &recoveries); err != nil {
		return e, err
	}
	if intents != 1 || attempts != 1 || journal != 2 || poweroffAuthority != 0 || deletes != 0 || recoveries != 0 {
		return e, ErrCapacityConflict
	}
	// Exactly [nonce, authentic possible_start]; a third row means the Guest
	// went further and the normal proof (or no lane) applies.
	rows, err := tx.QueryContext(ctx, `SELECT sequence,kind,original_wire,previous_sha256,return_sha256,original_return_record=convert_from(original_wire,'UTF8')::jsonb FROM public.capacity_vm_retirement_original_returns WHERE intent_id=$1 ORDER BY sequence`, i.RequestID)
	if err != nil {
		return e, err
	}
	defer rows.Close()
	count := 0
	for rows.Next() {
		var sequence int
		var kind, previous, digest string
		var raw []byte
		var consistent bool
		if err = rows.Scan(&sequence, &kind, &raw, &previous, &digest, &consistent); err != nil {
			return e, err
		}
		if !consistent || sequence != count+1 || count > 1 {
			return e, ErrCapacityConflict
		}
		if count == 0 {
			var nonce guestRetirementV2NonceReturn
			if kind != guestRetirementV2NonceKind || previous != "" || capacity.DecodeGuestLifecycle(raw, &nonce) != nil || capacity.GuestRetirementSHA(nonce) != digest || !guestRetirementV2NonceJoin(nonce, stored) {
				return e, ErrCapacityConflict
			}
		} else {
			var observed model.CapacityGuestRetirementObservationV2
			if kind != "production_retirement_v2:possible_start" || capacity.DecodeGuestLifecycle(raw, &observed) != nil || previous != observed.Record.PreviousSHA256 || digest != observed.RecordSHA256 || !v2RefusedPossibleStart(observed, stored) {
				return e, ErrCapacityConflict
			}
		}
		e.ObservationSHA256[count] = digest
		count++
	}
	if err = rows.Err(); err != nil {
		return e, err
	}
	if err = rows.Close(); err != nil {
		return e, err
	}
	if count != 2 {
		return e, ErrCapacityConflict
	}
	var attemptID string
	if err = tx.QueryRowContext(ctx, `SELECT attempt_id::text FROM public.capacity_guest_original_caller_attempts WHERE intent_id=$1`, i.RequestID).Scan(&attemptID); err != nil || attemptID != i.AttemptID {
		return e, ErrCapacityConflict
	}
	var wire []byte
	var callerSHA string
	if err = tx.QueryRowContext(ctx, `SELECT original_wire,return_sha256 FROM public.capacity_guest_original_caller_returns WHERE intent_id=$1`, i.RequestID).Scan(&wire, &callerSHA); err != nil {
		return e, ErrCapacityConflict
	}
	var caller GuestOriginalCallerReturn
	if capacity.DecodeGuestLifecycle(wire, &caller) != nil || capacity.GuestRetirementSHA(caller) != callerSHA || !v2RefusedCallerClosed(caller, i) {
		return e, ErrCapacityConflict
	}
	e.Order = v2RefusedNativeOffOrder
	e.GuestSource = stored.Binding.GuestSourceCommit
	e.IntentSHA256 = intentSHA
	e.CallerSHA256 = callerSHA
	e.CallerStatus = caller.Status
	if !capacity.ValidDigest(e.IntentSHA256) || !capacity.ValidDigest(e.CallerSHA256) {
		return e, ErrCapacityConflict
	}
	return e, nil
}

// v2RefusedNativeOffContextTx takes the scope lock and re-derives every fact
// of the claimed V2 disposal, its expired epoch and the refused retirement.
func v2RefusedNativeOffContextTx(ctx context.Context, tx *sql.Tx, preID, admissionID, retID string) (v2RefusedNativeOffContext, error) {
	var o v2RefusedNativeOffContext
	var namespace, environment, domain, dimension string
	if err := tx.QueryRowContext(ctx, `SELECT g.namespace,g.environment,g.domain,g.dimension FROM public.capacity_vm_retirement_intents r JOIN public.capacity_vm_provisioning_preregistrations p ON p.id=r.preregistration_id JOIN public.capacity_mutation_grants g ON g.id=p.create_grant_id WHERE r.id=$1 AND r.preregistration_id=$2`, retID, preID).Scan(&namespace, &environment, &domain, &dimension); err != nil {
		return o, ErrCapacityConflict
	}
	if err := lockMutationScope(ctx, tx, namespace, model.CapacityPolicySpec{Environment: environment, Domain: domain, Dimension: dimension}); err != nil {
		return o, err
	}
	var err error
	o.disposal, o.claimSHA, err = loadFailedInstalledDisposalTx(ctx, tx, admissionID, "claimed")
	if err != nil {
		return o, ErrCapacityConflict
	}
	r := o.disposal
	if r.PreregistrationID != preID || r.RetirementMode != failedInstalledV2Mode || r.ClaimedIntent == nil || r.Namespace != namespace || r.Environment != environment || r.Domain != domain || r.Dimension != dimension {
		return o, ErrCapacityConflict
	}
	o.stored, err = loadGuestRetirementV2Tx(ctx, tx, retID, true)
	if err != nil {
		return o, ErrCapacityConflict
	}
	o.policy.ID = r.OriginalIntent.PolicyID
	o.policy.Kind = "capacity_policy"
	var active bool
	if err = tx.QueryRowContext(ctx, `SELECT namespace,name,version,checksum,spec,active FROM public.manifests WHERE id=$1 AND kind='capacity_policy' FOR SHARE`, o.policy.ID).Scan(&o.policy.Metadata.Namespace, &o.policy.Metadata.Name, &o.policy.Version, &o.policy.Checksum, &o.policy.Spec, &active); err != nil || !active || o.policy.Checksum != r.OriginalIntent.PolicyChecksum {
		return o, ErrCapacityConflict
	}
	o.spec, err = parseCapacityPolicy(o.policy)
	if err != nil || o.policy.Metadata.Namespace != namespace || o.spec.Environment != environment || o.spec.Domain != domain || o.spec.Dimension != dimension {
		return o, ErrCapacityConflict
	}
	o.current, err = loadCapacityIntent(ctx, tx, namespace, o.spec, true)
	if err != nil {
		return o, err
	}
	var now time.Time
	if err = tx.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		return o, err
	}
	now = now.UTC()
	m := o.current.FailedInstalledDisposal
	if m == nil || m.ID != admissionID || m.Stage != "claimed" || m.PreregistrationID != preID || m.RetirementRecoveryID != "" || m.RetirementRefusalRecoveryID != "" || !reflect.DeepEqual(o.current, *r.ClaimedIntent) || o.current.LeaseExpiresAt == nil || o.current.LeaseExpiresAt.After(now) {
		return o, ErrCapacityConflict
	}
	i := o.stored.Request.Intent
	if i.Schema != capacity.GuestRetirementV2IntentSchema || i.RequestID != retID || i.PreregistrationID != preID || i.Slot != failedInstalledDisposalSlot(r) || i.Tuple.Slot != i.Slot || i.PolicyID != o.policy.ID.String() || i.PolicyChecksum != o.policy.Checksum || i.Generation != uint64(o.current.Generation) || i.Fence != uint64(o.current.FencingToken) || i.LeaseOwner != o.current.LeaseOwner || o.stored.ExecutorID != o.current.LeaseExecutorID || failedInstalledRetirementMode(o.spec, o.stored.Binding) != failedInstalledV2Mode {
		return o, ErrCapacityConflict
	}
	workflowID, e := uuid.Parse(i.WorkflowID)
	if e != nil || workflowID == uuid.Nil {
		return o, ErrCapacityConflict
	}
	scoped := CapacityStore{WorkflowID: workflowID, ExecutorID: o.stored.ExecutorID}
	valid, err := scoped.failedInstalledDisposalActiveTx(ctx, tx, o.policy, o.spec, o.current, i.Slot, now)
	if err != nil || !valid {
		return o, ErrCapacityConflict
	}
	o.run, err = scoped.failedRetirementRunTx(ctx, tx, o.policy, o.spec, m.RunID, workflowID, now)
	if err != nil {
		return o, ErrCapacityConflict
	}
	var raw, result []byte
	if err = tx.QueryRowContext(ctx, installedGuestPreviousFailedRunQuery, m.RunID, workflowID, now).Scan(&raw, &result); err != nil {
		return o, ErrCapacityConflict
	}
	var run struct {
		Status string                        `json:"status"`
		Steps  []model.WorkflowRunStepResult `json:"steps"`
	}
	if string(raw) != o.run || json.Unmarshal(result, &run) != nil || run.Status != "failed" || !v2RefusedClaimRunSteps(run.Steps, o.current, preID) {
		return o, ErrCapacityConflict
	}
	if err = failedInstalledZeroUsefulTx(ctx, tx, r, now, m.RunID); err != nil {
		return o, err
	}
	o.binding, err = capacity.VMObservationBinding(o.spec, o.stored.Binding.MutationBindingName)
	if err != nil {
		return o, ErrCapacityConflict
	}
	o.evidence, err = v2RefusedEvidenceTx(ctx, tx, o.stored, r.ID, now)
	return o, err
}

func sameV2RefusedNativeOffAdmission(r FailedInstalledV2RefusedNativeOff, o v2RefusedNativeOffContext) bool {
	return r.DisposalID == o.disposal.ID && r.PreregistrationID == o.disposal.PreregistrationID && r.RetirementRequestID == o.stored.Request.Intent.RequestID && r.OriginalClaimSHA256 == o.claimSHA && reflect.DeepEqual(r.OriginalClaimedIntent, o.current) && r.FailedRun == o.run && r.Evidence == o.evidence
}

// Every native read of the expired intent must belong to this admission: it
// was recorded at or after the admission and its challenge (or the challenge
// a return embeds) joins the refused caller return.
func v2RefusedForeignNativeReadsTx(ctx context.Context, tx *sql.Tx, retID, callerSHA string, admittedAt time.Time) (int, int, error) {
	var foreign, challenges int
	err := tx.QueryRowContext(ctx, `SELECT
 (SELECT count(*) FROM public.capacity_guest_original_native_poweroff_reads WHERE intent_id=$1 AND (recorded_at<$3 OR coalesce(original_record->>'schema','') NOT IN($4,$5) OR coalesce(original_record->>'original_caller_sha256',original_record #>>'{challenge,original_caller_sha256}','')<>$2)),
 (SELECT count(*) FROM public.capacity_guest_original_native_poweroff_reads WHERE intent_id=$1 AND original_record->>'schema'=$4)`, retID, callerSHA, admittedAt, v2NativePoweroffChallengeSchema, v2NativePoweroffReturnSchema).Scan(&foreign, &challenges)
	return foreign, challenges, err
}

type V2RefusedNativeOffOwner struct {
	db        *sql.DB
	ctx       context.Context
	challenge GuestNativePoweroffReadV2
	admission FailedInstalledV2RefusedNativeOff
	original  v2RefusedNativeOffContext
	used      atomic.Bool
}

func (o *V2RefusedNativeOffOwner) Challenge() GuestNativePoweroffReadV2         { return o.challenge }
func (o *V2RefusedNativeOffOwner) Original() GuestRetirementOriginalV2          { return o.original.stored }
func (o *V2RefusedNativeOffOwner) Policy() model.Manifest                       { return o.original.policy }
func (o *V2RefusedNativeOffOwner) Spec() model.CapacityPolicySpec               { return o.original.spec }
func (o *V2RefusedNativeOffOwner) Admission() FailedInstalledV2RefusedNativeOff { return o.admission }

// PrepareFailedInstalledV2RefusedNativeOffRead admits the refused history (or
// reuses this disposal's own admission on a retry) and durably commits one
// bounded native read challenge BEFORE the provider GET. It grants nothing
// else: no Guest request, nonce, lease, fence, poweroff or DELETE.
func (s CapacityStore) PrepareFailedInstalledV2RefusedNativeOffRead(ctx context.Context, preID, admissionID, retID, issuer string) (*V2RefusedNativeOffOwner, error) {
	if ctx == nil {
		return nil, ErrCapacityMutationAuthorization
	}
	deadline, ok := ctx.Deadline()
	if s.DB == nil || !ok || ctx.Err() != nil || !validCapacityExecutor(preID) || !validCapacityExecutor(admissionID) || !validCapacityExecutor(retID) || issuer == "" || len(issuer) > 256 {
		return nil, ErrCapacityMutationAuthorization
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `SET LOCAL TIME ZONE 'UTC'`); err != nil {
		return nil, err
	}
	o, err := v2RefusedNativeOffContextTx(ctx, tx, preID, admissionID, retID)
	if err != nil {
		return nil, err
	}
	var qualified bool
	if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM public.capacity_guest_v2_refused_nativeoff_quiescences WHERE disposal_id=$1 AND stage='qualified')`, o.disposal.ID).Scan(&qualified); err != nil || qualified {
		return nil, ErrCapacityConflict
	}
	var admission FailedInstalledV2RefusedNativeOff
	var existing string
	err = tx.QueryRowContext(ctx, `SELECT id::text FROM public.capacity_guest_v2_refused_nativeoff_quiescences WHERE disposal_id=$1 AND stage='admitted'`, o.disposal.ID).Scan(&existing)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		var reads int
		if err = tx.QueryRowContext(ctx, `SELECT count(*) FROM public.capacity_guest_original_native_poweroff_reads WHERE intent_id=$1`, retID).Scan(&reads); err != nil || reads != 0 {
			return nil, ErrCapacityConflict
		}
		admission = FailedInstalledV2RefusedNativeOff{Schema: v2RefusedNativeOffSchema, ID: uuid.NewString(), Stage: "admitted", DisposalID: o.disposal.ID, PreregistrationID: preID, RetirementRequestID: retID, Issuer: issuer, ActualCoreSource: capacity.CurrentGuestCoreSource(), OriginalClaimSHA256: o.claimSHA, OriginalClaimedIntent: o.current, FailedRun: o.run, Evidence: o.evidence}
		if _, err = insertV2RefusedNativeOffTx(ctx, tx, admission); err != nil {
			return nil, err
		}
	case err != nil:
		return nil, err
	default:
		var admittedAt time.Time
		admission, _, admittedAt, err = loadV2RefusedNativeOffTx(ctx, tx, existing, "admitted")
		if err != nil || !sameV2RefusedNativeOffAdmission(admission, o) {
			return nil, ErrCapacityConflict
		}
		foreign, challenges, e := v2RefusedForeignNativeReadsTx(ctx, tx, retID, o.evidence.CallerSHA256, admittedAt)
		if e != nil || foreign != 0 || challenges >= V2RefusedNativeOffMaximumReads {
			return nil, ErrCapacityConflict
		}
		// One read at a time: a previous challenge must have returned or expired.
		var pending bool
		if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM public.capacity_guest_original_native_poweroff_reads c WHERE c.intent_id=$1 AND c.original_record->>'schema'=$2 AND (c.original_record->>'original_deadline_core')::timestamptz>clock_timestamp() AND NOT EXISTS(SELECT 1 FROM public.capacity_guest_original_native_poweroff_reads r WHERE r.intent_id=c.intent_id AND r.original_record->>'schema'=$3 AND r.original_record #>>'{challenge,read_id}'=c.id::text))`, retID, v2NativePoweroffChallengeSchema, v2NativePoweroffReturnSchema).Scan(&pending); err != nil || pending {
			return nil, ErrCapacityConflict
		}
	}
	issued := time.Now()
	budget := min(5*time.Second, deadline.Sub(issued))
	if budget <= 0 {
		return nil, ErrCapacityLease
	}
	i := o.stored.Request.Intent
	challenge := GuestNativePoweroffReadV2{Schema: v2NativePoweroffChallengeSchema, ReadID: uuid.NewString(), IntentSHA256: capacity.GuestRetirementSHA(i), IntentID: retID, OriginalCallerSHA256: o.evidence.CallerSHA256, MutationBindingSHA256: capacity.GuestRetirementSHA(o.binding), AdapterSourceCommit: o.binding.OriginalProviderSourceCommit, Tuple: i.Tuple, IssuedAtCore: issued.UTC(), OriginalDeadlineCore: issued.Add(budget).UTC()}
	wire, err := json.Marshal(challenge)
	if err != nil {
		return nil, err
	}
	// clock_timestamp() orders the challenge strictly after its admission.
	if _, err = tx.ExecContext(ctx, `INSERT INTO public.capacity_guest_original_native_poweroff_reads(id,intent_id,observation_sha256,original_wire,original_record,recorded_at) VALUES($1,$2,$3,$4,$5::jsonb,clock_timestamp())`, challenge.ReadID, retID, capacity.GuestRetirementSHA(challenge), wire, string(wire)); err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return &V2RefusedNativeOffOwner{db: s.DB, ctx: ctx, challenge: challenge, admission: admission, original: o}, nil
}

// RecordFailedInstalledV2RefusedNativeOffRead retains the actual native read
// return (failed or not) first, then qualifies only a timely exact OFF read,
// writing claimed->quiescent and the cleanup-pending intent with the lease
// cleared in one transaction. A refused qualification changes no state.
func (s CapacityStore) RecordFailedInstalledV2RefusedNativeOffRead(ctx context.Context, o *V2RefusedNativeOffOwner, returned GuestNativePoweroffReturnV2) (FailedInstalledV2RefusedNativeOff, FailedInstalledGuestDisposal, error) {
	var empty FailedInstalledV2RefusedNativeOff
	var disposal FailedInstalledGuestDisposal
	if o == nil || o.db != s.DB || s.DB == nil || !o.used.CompareAndSwap(false, true) || returned.Schema != v2NativePoweroffReturnSchema || !reflect.DeepEqual(returned.Challenge, o.challenge) || returned.StartedAtCore.Before(o.challenge.IssuedAtCore) || returned.OriginalReturnedAtCore.Before(returned.StartedAtCore) {
		return empty, disposal, ErrCapacityConflict
	}
	accepted, err := s.retainV2RefusedNativeOffRead(ctx, o, returned)
	if err != nil {
		return empty, disposal, err
	}
	if !accepted || o.ctx.Err() != nil || !returned.OriginalReturnedAtCore.Before(o.challenge.OriginalDeadlineCore) {
		return empty, disposal, ErrCapacityConflict
	}
	return s.qualifyV2RefusedNativeOffRead(ctx, o)
}

func (s CapacityStore) retainV2RefusedNativeOffRead(ctx context.Context, o *V2RefusedNativeOffOwner, returned GuestNativePoweroffReturnV2) (bool, error) {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	if err = lockMutationScope(ctx, tx, o.original.policy.Metadata.Namespace, o.original.spec); err != nil {
		return false, err
	}
	var wire []byte
	var digest string
	var consistent bool
	if err = tx.QueryRowContext(ctx, `SELECT original_wire,observation_sha256,original_record=convert_from(original_wire,'UTF8')::jsonb FROM public.capacity_guest_original_native_poweroff_reads WHERE id=$1 AND intent_id=$2 FOR SHARE`, o.challenge.ReadID, o.challenge.IntentID).Scan(&wire, &digest, &consistent); err != nil {
		return false, ErrCapacityConflict
	}
	expected, err := json.Marshal(o.challenge)
	if err != nil || !consistent || string(expected) != string(wire) || capacity.GuestRetirementSHA(o.challenge) != digest {
		return false, ErrCapacityConflict
	}
	var already bool
	if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM public.capacity_guest_original_native_poweroff_reads WHERE intent_id=$1 AND original_record->>'schema'=$2 AND original_record #>>'{challenge,read_id}'=$3)`, o.challenge.IntentID, v2NativePoweroffReturnSchema, o.challenge.ReadID).Scan(&already); err != nil || already {
		return false, ErrCapacityConflict
	}
	receipt, err := guestOriginalCreateReceiptV2Tx(ctx, tx, o.original.stored)
	if err != nil {
		return false, err
	}
	accepted := guestNativePoweroffReadV2Content(returned, o.original.spec, o.original.binding, receipt)
	if !accepted {
		returned.Plan = nil // unknown or non-OFF data never becomes retained proof.
	}
	raw, err := json.Marshal(returned)
	if err != nil || len(raw) > 1<<20 {
		return false, ErrCapacityConflict
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO public.capacity_guest_original_native_poweroff_reads(id,intent_id,observation_sha256,original_wire,original_record,original_native_join_wire,recorded_at) VALUES($1,$2,$3,$4,$5::jsonb,$6,clock_timestamp())`, uuid.New(), o.challenge.IntentID, capacity.GuestRetirementSHA(returned), raw, string(raw), wire); err != nil {
		return false, err
	}
	if err = tx.Commit(); err != nil {
		return false, err
	}
	return accepted, nil
}

func (s CapacityStore) qualifyV2RefusedNativeOffRead(ctx context.Context, o *V2RefusedNativeOffOwner) (FailedInstalledV2RefusedNativeOff, FailedInstalledGuestDisposal, error) {
	var empty FailedInstalledV2RefusedNativeOff
	var disposal FailedInstalledGuestDisposal
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return empty, disposal, err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `SET LOCAL TIME ZONE 'UTC'`); err != nil {
		return empty, disposal, err
	}
	current, err := v2RefusedNativeOffContextTx(ctx, tx, o.admission.PreregistrationID, o.admission.DisposalID, o.admission.RetirementRequestID)
	if err != nil {
		return empty, disposal, err
	}
	admission, admissionSHA, admittedAt, err := loadV2RefusedNativeOffTx(ctx, tx, o.admission.ID, "admitted")
	if err != nil || admission.ID != o.admission.ID || admission.Issuer != o.admission.Issuer || !sameV2RefusedNativeOffAdmission(admission, current) || !sameV2RefusedNativeOffAdmission(o.admission, current) {
		return empty, disposal, ErrCapacityConflict
	}
	foreign, _, err := v2RefusedForeignNativeReadsTx(ctx, tx, admission.RetirementRequestID, admission.Evidence.CallerSHA256, admittedAt)
	if err != nil || foreign != 0 {
		return empty, disposal, ErrCapacityConflict
	}
	var latest string
	if err = tx.QueryRowContext(ctx, `SELECT id::text FROM public.capacity_guest_original_native_poweroff_reads WHERE intent_id=$1 AND original_record->>'schema'=$2 ORDER BY recorded_at DESC,id DESC LIMIT 1`, admission.RetirementRequestID, v2NativePoweroffChallengeSchema).Scan(&latest); err != nil || latest != o.challenge.ReadID {
		return empty, disposal, ErrCapacityConflict
	}
	var nowPG time.Time
	if err = tx.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&nowPG); err != nil {
		return empty, disposal, err
	}
	// The shared V2 validator re-reads the newest return, its exact challenge
	// join to the (refused) caller return, freshness and the OFF content.
	if err = guestNativePoweroffV2Tx(ctx, tx, current.stored, current.spec, current.binding, nowPG.UTC()); err != nil {
		return empty, disposal, err
	}
	var readID, offSHA string
	var returnWire []byte
	if err = tx.QueryRowContext(ctx, `SELECT id::text,observation_sha256,original_wire FROM public.capacity_guest_original_native_poweroff_reads WHERE intent_id=$1 AND original_record->>'schema'=$2 ORDER BY recorded_at DESC,id DESC LIMIT 1`, admission.RetirementRequestID, v2NativePoweroffReturnSchema).Scan(&readID, &offSHA, &returnWire); err != nil {
		return empty, disposal, ErrCapacityConflict
	}
	var returned GuestNativePoweroffReturnV2
	if capacity.DecodeGuestLifecycle(returnWire, &returned) != nil || !reflect.DeepEqual(returned.Challenge, o.challenge) || capacity.BusinessCreationSHA256(returnWire) != offSHA {
		return empty, disposal, ErrCapacityConflict
	}
	qualified := admission
	qualified.Stage = "qualified"
	qualified.AdmissionSHA256 = admissionSHA
	qualified.NativeReadID = readID
	qualified.NativeOffSHA256 = offSHA
	if _, err = insertV2RefusedNativeOffTx(ctx, tx, qualified); err != nil {
		return empty, disposal, err
	}
	r := current.disposal
	r.NativePoweroffSHA256 = offSHA
	if disposal, err = finishFailedInstalledCleanupTx(ctx, tx, r, current.current, admission.RetirementRequestID, nowPG.UTC()); err != nil {
		return empty, FailedInstalledGuestDisposal{}, err
	}
	if err = tx.Commit(); err != nil {
		return empty, FailedInstalledGuestDisposal{}, err
	}
	return qualified, disposal, nil
}

// v2RefusedNativeOffQualifiedTx is the terminal-side alternative to
// guestQuiescentProofV2Tx for a quiescent row written by this lane. It never
// routes the refused retirement through the normal five-row/caller-200
// validator; the caller still joins the stored native OFF read afterwards.
func v2RefusedNativeOffQualifiedTx(ctx context.Context, tx *sql.Tx, r FailedInstalledGuestDisposal, stored GuestRetirementOriginalV2) (bool, error) {
	var id string
	err := tx.QueryRowContext(ctx, `SELECT id::text FROM public.capacity_guest_v2_refused_nativeoff_quiescences WHERE disposal_id=$1 AND retirement_request_id=$2 AND stage='qualified'`, r.ID, r.RetirementRequestID).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		var admitted bool
		if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM public.capacity_guest_v2_refused_nativeoff_quiescences WHERE disposal_id=$1)`, r.ID).Scan(&admitted); err != nil {
			return true, err
		}
		if admitted {
			// An admitted disposal is quiesced only by its own lineage.
			return true, ErrCapacityConflict
		}
		return false, nil
	}
	if err != nil {
		return true, err
	}
	admission, admissionSHA, admittedAt, err := loadV2RefusedNativeOffTx(ctx, tx, id, "admitted")
	if err != nil {
		return true, err
	}
	qualified, _, _, err := loadV2RefusedNativeOffTx(ctx, tx, id, "qualified")
	if err != nil {
		return true, err
	}
	expected := admission
	expected.Stage = "qualified"
	expected.AdmissionSHA256 = admissionSHA
	expected.NativeReadID = qualified.NativeReadID
	expected.NativeOffSHA256 = qualified.NativeOffSHA256
	if !reflect.DeepEqual(expected, qualified) || qualified.NativeOffSHA256 != r.NativePoweroffSHA256 || admission.DisposalID != r.ID || admission.PreregistrationID != r.PreregistrationID || admission.RetirementRequestID != stored.Request.Intent.RequestID || r.RetirementMode != failedInstalledV2Mode || r.ClaimedIntent == nil || !reflect.DeepEqual(admission.OriginalClaimedIntent, *r.ClaimedIntent) {
		return true, ErrCapacityConflict
	}
	var now time.Time
	if err = tx.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		return true, err
	}
	evidence, err := v2RefusedEvidenceTx(ctx, tx, stored, r.ID, now.UTC())
	if err != nil || evidence != admission.Evidence {
		return true, ErrCapacityConflict
	}
	foreign, _, err := v2RefusedForeignNativeReadsTx(ctx, tx, stored.Request.Intent.RequestID, evidence.CallerSHA256, admittedAt)
	if err != nil || foreign != 0 {
		return true, ErrCapacityConflict
	}
	var wire, challengeWire []byte
	var digest string
	if err = tx.QueryRowContext(ctx, `SELECT original_wire,original_native_join_wire,observation_sha256 FROM public.capacity_guest_original_native_poweroff_reads WHERE id=$1 AND intent_id=$2`, qualified.NativeReadID, stored.Request.Intent.RequestID).Scan(&wire, &challengeWire, &digest); err != nil {
		return true, ErrCapacityConflict
	}
	var returned GuestNativePoweroffReturnV2
	var challenge GuestNativePoweroffReadV2
	if digest != r.NativePoweroffSHA256 || capacity.DecodeGuestLifecycle(wire, &returned) != nil || capacity.DecodeGuestLifecycle(challengeWire, &challenge) != nil || !reflect.DeepEqual(challenge, returned.Challenge) || challenge.OriginalCallerSHA256 != evidence.CallerSHA256 || challenge.IntentID != stored.Request.Intent.RequestID {
		return true, ErrCapacityConflict
	}
	return true, nil
}

// Public reads expose only typed public IDs, stages and hashes.
func (s CapacityStore) ReadFailedInstalledV2RefusedNativeOff(ctx context.Context, preID string) ([]FailedInstalledV2RefusedNativeOff, error) {
	if s.DB == nil || !validCapacityExecutor(preID) {
		return nil, ErrCapacityMutationAuthorization
	}
	rows, err := s.DB.QueryContext(ctx, `SELECT original_wire,record_sha256 FROM public.capacity_guest_v2_refused_nativeoff_quiescences WHERE preregistration_id=$1 ORDER BY recorded_at,stage`, preID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []FailedInstalledV2RefusedNativeOff{}
	for rows.Next() {
		var b []byte
		var h string
		var r FailedInstalledV2RefusedNativeOff
		if err = rows.Scan(&b, &h); err != nil {
			return nil, err
		}
		if capacity.BusinessCreationSHA256(b) != h || decodePrejournalOriginal(b, &r) != nil || r.Schema != v2RefusedNativeOffSchema {
			return nil, ErrCapacityConflict
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// ReadFailedInstalledV2RefusedNativeOffReads counts the native read
// challenges and returns of one retirement, without any wire.
func (s CapacityStore) ReadFailedInstalledV2RefusedNativeOffReads(ctx context.Context, retID string) (int, int, error) {
	if s.DB == nil || !validCapacityExecutor(retID) {
		return 0, 0, ErrCapacityMutationAuthorization
	}
	var challenges, returns int
	err := s.DB.QueryRowContext(ctx, `SELECT count(*) FILTER (WHERE original_record->>'schema'=$2),count(*) FILTER (WHERE original_record->>'schema'=$3) FROM public.capacity_guest_original_native_poweroff_reads WHERE intent_id=$1`, retID, v2NativePoweroffChallengeSchema, v2NativePoweroffReturnSchema).Scan(&challenges, &returns)
	return challenges, returns, err
}
