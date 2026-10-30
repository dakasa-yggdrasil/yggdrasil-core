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

const PartialNativeOffMaximumReads = 3
const partialNativeOffSchema = "failed_installed_partial_native_off_reconciliation_v1"

// No original Guest command or HTTP success is asserted by this admission.
type FailedInstalledPartialNativeOff struct {
	Schema                string                   `json:"schema"`
	ID                    string                   `json:"id"`
	Stage                 string                   `json:"stage"`
	DisposalID            string                   `json:"disposal_id"`
	PreregistrationID     string                   `json:"preregistration_id"`
	RetirementRequestID   string                   `json:"retirement_request_id"`
	Issuer                string                   `json:"issuer"`
	ActualCoreSource      string                   `json:"actual_core_source"`
	OriginalClaimSHA256   string                   `json:"original_claim_sha256"`
	OriginalClaimedIntent model.CapacityIntent     `json:"original_claimed_intent"`
	FailedRun             string                   `json:"failed_run"`
	Evidence              PartialNativeOffEvidence `json:"evidence"`
	AdmissionSHA256       string                   `json:"admission_sha256,omitempty"`
	NativeReadID          string                   `json:"native_read_id,omitempty"`
	NativeOffSHA256       string                   `json:"native_off_sha256,omitempty"`
}

type partialNativeOffContext struct {
	disposal FailedInstalledGuestDisposal
	stored   GuestRetirementOriginal
	policy   model.Manifest
	spec     model.CapacityPolicySpec
	current  model.CapacityIntent
	evidence PartialNativeOffEvidence
	run      string
	claimSHA string
}

func insertPartialNativeOffTx(ctx context.Context, tx *sql.Tx, r FailedInstalledPartialNativeOff) (string, error) {
	b, err := json.Marshal(r)
	if err != nil {
		return "", err
	}
	h := capacity.BusinessCreationSHA256(b)
	_, err = tx.ExecContext(ctx, `INSERT INTO public.capacity_guest_partial_nativeoff_reconciliations(id,stage,disposal_id,preregistration_id,retirement_request_id,original_wire,original_record,record_sha256) VALUES($1,$2,$3,$4,$5,$6,$7::jsonb,$8)`, r.ID, r.Stage, r.DisposalID, r.PreregistrationID, r.RetirementRequestID, b, string(b), h)
	return h, err
}
func loadPartialNativeOffTx(ctx context.Context, tx *sql.Tx, id, stage string) (FailedInstalledPartialNativeOff, string, error) {
	var r FailedInstalledPartialNativeOff
	var b []byte
	var h string
	var consistent bool
	err := tx.QueryRowContext(ctx, `SELECT original_wire,record_sha256,original_record=convert_from(original_wire,'UTF8')::jsonb FROM public.capacity_guest_partial_nativeoff_reconciliations WHERE id=$1 AND stage=$2 FOR SHARE`, id, stage).Scan(&b, &h, &consistent)
	if err != nil {
		return r, "", err
	}
	if !consistent || capacity.BusinessCreationSHA256(b) != h || decodePrejournalOriginal(b, &r) != nil || r.ID != id || r.Stage != stage || r.Schema != partialNativeOffSchema {
		return r, "", ErrCapacityConflict
	}
	return r, h, nil
}

func partialNativeOffContextTx(ctx context.Context, tx *sql.Tx, preID, retID string) (partialNativeOffContext, error) {
	var o partialNativeOffContext
	var namespace, environment, domain, dimension string
	err := tx.QueryRowContext(ctx, `SELECT g.namespace,g.environment,g.domain,g.dimension FROM public.capacity_vm_retirement_intents r JOIN public.capacity_vm_provisioning_preregistrations p ON p.id=r.preregistration_id JOIN public.capacity_mutation_grants g ON g.id=p.create_grant_id WHERE r.id=$1 AND r.preregistration_id=$2`, retID, preID).Scan(&namespace, &environment, &domain, &dimension)
	if err != nil {
		return o, ErrCapacityConflict
	}
	if err = lockMutationScope(ctx, tx, namespace, model.CapacityPolicySpec{Environment: environment, Domain: domain, Dimension: dimension}); err != nil {
		return o, err
	}
	o.stored, err = loadGuestRetirementTx(ctx, tx, retID)
	if err != nil || o.stored.Preregistration.PreregistrationID != preID {
		return o, ErrCapacityConflict
	}
	o.policy.ID = uuid.MustParse(o.stored.Request.Intent.PolicyID)
	o.policy.Kind = "capacity_policy"
	var active bool
	err = tx.QueryRowContext(ctx, `SELECT namespace,name,version,checksum,spec,active FROM public.manifests WHERE id=$1 AND kind='capacity_policy' FOR SHARE`, o.policy.ID).Scan(&o.policy.Metadata.Namespace, &o.policy.Metadata.Name, &o.policy.Version, &o.policy.Checksum, &o.policy.Spec, &active)
	if err != nil || !active || o.policy.Checksum != o.stored.Request.Intent.PolicyChecksum {
		return o, ErrCapacityConflict
	}
	o.spec, err = parseCapacityPolicy(o.policy)
	if err != nil || namespace != o.policy.Metadata.Namespace || environment != o.spec.Environment || domain != o.spec.Domain || dimension != o.spec.Dimension {
		return o, ErrCapacityConflict
	}
	o.current, err = loadCapacityIntent(ctx, tx, namespace, o.spec, true)
	if err != nil {
		return o, err
	}
	m := o.current.FailedInstalledDisposal
	var now time.Time
	if err = tx.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		return o, err
	}
	now = now.UTC()
	if m == nil || m.Stage != "claimed" || m.PreregistrationID != preID || o.current.LeaseExpiresAt == nil || o.current.LeaseExpiresAt.After(now) || (m.RetirementRecoveryID == "") == (m.RetirementRefusalRecoveryID == "") {
		return o, ErrCapacityConflict
	}
	o.disposal, o.claimSHA, err = loadFailedInstalledDisposalTx(ctx, tx, m.ID, "claimed")
	if err != nil {
		return o, err
	}
	o.disposal, err = effectiveFailedInstalledClaimTx(ctx, tx, o.disposal, o.current)
	if err != nil || !failedInstalledLegacyJoin(o.disposal, o.stored, o.spec) {
		return o, ErrCapacityConflict
	}
	// The existing79/80 successor remains the only Guest request. No further
	// successor, nonce, fence, lease or workflow is produced by81.
	var issued bool
	if m.RetirementRecoveryID != "" {
		err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM public.capacity_guest_presend_retirement_recoveries WHERE id=$1 AND stage='issued' AND disposal_id=$2 AND preregistration_id=$3 AND original_record #>> '{successor_intent,request_id}'=$4)`, m.RetirementRecoveryID, m.ID, preID, retID).Scan(&issued)
	} else {
		err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM public.capacity_guest_prejournal_refusal_recoveries WHERE id=$1 AND stage='issued' AND disposal_id=$2 AND preregistration_id=$3 AND original_record #>> '{successor_intent,request_id}'=$4)`, m.RetirementRefusalRecoveryID, m.ID, preID, retID).Scan(&issued)
	}
	if err != nil || !issued {
		return o, ErrCapacityConflict
	}
	scoped := CapacityStore{WorkflowID: uuid.MustParse(o.stored.Request.Intent.WorkflowID), ExecutorID: o.stored.ExecutorID}
	valid, e := scoped.failedInstalledDisposalActiveTx(ctx, tx, o.policy, o.spec, o.current, 1, now)
	if e != nil || !valid {
		return o, ErrCapacityConflict
	}
	o.run, err = scoped.failedRetirementRunTx(ctx, tx, o.policy, o.spec, m.RunID, scoped.WorkflowID, now)
	if err != nil {
		return o, err
	}
	o.evidence, err = partialNativeOffEvidenceTx(ctx, tx, o.stored, now)
	return o, err
}

func (s CapacityStore) RequestFailedInstalledPartialNativeOff(ctx context.Context, preID, retID, issuer string) (FailedInstalledPartialNativeOff, error) {
	var empty FailedInstalledPartialNativeOff
	if s.DB == nil || !validCapacityExecutor(preID) || !validCapacityExecutor(retID) || issuer == "" || len(issuer) > 256 {
		return empty, ErrCapacityMutationAuthorization
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return empty, err
	}
	defer tx.Rollback()
	o, err := partialNativeOffContextTx(ctx, tx, preID, retID)
	if err != nil {
		return empty, err
	}
	r := FailedInstalledPartialNativeOff{Schema: partialNativeOffSchema, ID: uuid.NewString(), Stage: "admitted", DisposalID: o.disposal.ID, PreregistrationID: preID, RetirementRequestID: retID, Issuer: issuer, ActualCoreSource: capacity.CurrentGuestCoreSource(), OriginalClaimSHA256: o.claimSHA, OriginalClaimedIntent: o.current, FailedRun: o.run, Evidence: o.evidence}
	if _, err = insertPartialNativeOffTx(ctx, tx, r); err != nil {
		return empty, err
	}
	if err = tx.Commit(); err != nil {
		return empty, err
	}
	return r, nil
}

func samePartialNativeOffAdmission(r FailedInstalledPartialNativeOff, o partialNativeOffContext) bool {
	return r.DisposalID == o.disposal.ID && r.PreregistrationID == o.stored.Preregistration.PreregistrationID && r.RetirementRequestID == o.stored.Request.Intent.RequestID && r.OriginalClaimSHA256 == o.claimSHA && reflect.DeepEqual(r.OriginalClaimedIntent, o.current) && r.FailedRun == o.run && r.Evidence == o.evidence
}

// Public reads expose only typed public IDs/stages, never these private wires.
func (s CapacityStore) ReadFailedInstalledPartialNativeOff(ctx context.Context, preID string) ([]FailedInstalledPartialNativeOff, error) {
	if s.DB == nil || !validCapacityExecutor(preID) {
		return nil, ErrCapacityMutationAuthorization
	}
	rows, err := s.DB.QueryContext(ctx, `SELECT original_wire,record_sha256 FROM public.capacity_guest_partial_nativeoff_reconciliations WHERE preregistration_id=$1 ORDER BY recorded_at,stage`, preID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []FailedInstalledPartialNativeOff{}
	for rows.Next() {
		var b []byte
		var h string
		var r FailedInstalledPartialNativeOff
		if err = rows.Scan(&b, &h); err != nil {
			return nil, err
		}
		if capacity.BusinessCreationSHA256(b) != h || decodePrejournalOriginal(b, &r) != nil || r.Schema != partialNativeOffSchema {
			return nil, ErrCapacityConflict
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
