package repository

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

const GuestRetirementForwardSchema = "original_guest_partial_poweroff_forward_v1"
const GuestRetirementForwardReadSchema = "original_core_guest_retirement_forward_read_v1"
const GuestRetirementForwardReadReturnSchema = "original_core_guest_retirement_forward_read_return_v1"

// Only explicitly projected fields belong in a public HTTP summary. The full
// original frame is private retained evidence and can contain caller payloads.
type GuestRetirementForward struct {
	Schema                string                                           `json:"schema"`
	ID                    string                                           `json:"id"`
	RootAdmissionID       string                                           `json:"root_admission_id"`
	ParentAdmissionID     string                                           `json:"parent_admission_id,omitempty"`
	ParentAdmissionSHA256 string                                           `json:"parent_admission_sha256,omitempty"`
	Stage                 string                                           `json:"stage"`
	Mode                  string                                           `json:"mode"`
	PreregistrationID     string                                           `json:"preregistration_id"`
	RetirementRequestID   string                                           `json:"retirement_request_id"`
	AdmissionSHA256       string                                           `json:"admission_sha256,omitempty"`
	PrefixSHA256          string                                           `json:"prefix_sha256"`
	OriginalCallerSHA256  string                                           `json:"original_caller_sha256"`
	NativeOffSHA256       string                                           `json:"native_off_sha256,omitempty"`
	DestroyGrantID        string                                           `json:"destroy_grant_id,omitempty"`
	NativeAbsenceSHA256   string                                           `json:"native_absence_sha256,omitempty"`
	RecordedAt            time.Time                                        `json:"recorded_at"`
	Namespace             string                                           `json:"namespace"`
	Environment           string                                           `json:"environment"`
	Domain                string                                           `json:"domain"`
	Dimension             string                                           `json:"dimension"`
	Issuer                string                                           `json:"issuer"`
	ActualCoreSource      string                                           `json:"actual_core_source"`
	OriginalIntentWire    []byte                                           `json:"original_intent_wire"`
	OriginalIntentSHA256  string                                           `json:"original_intent_sha256"`
	OriginalGeneration    int64                                            `json:"original_generation"`
	OriginalFence         int64                                            `json:"original_fence"`
	Generation            int64                                            `json:"generation"`
	Fence                 int64                                            `json:"fence"`
	LeaseOwner            string                                           `json:"lease_owner"`
	ExecutorID            string                                           `json:"executor_id"`
	RunID                 string                                           `json:"run_id"`
	FailedRun             []byte                                           `json:"failed_run"`
	Original              GuestRetirementOriginalV2                        `json:"original"`
	Evidence              guestRetirementForwardEvidence                   `json:"evidence"`
	Barrier               CapacityDispatchExecutorBarrier                  `json:"barrier"`
	NativeOffReadID       string                                           `json:"native_off_read_id,omitempty"`
	TerminalIntentSHA256  string                                           `json:"terminal_intent_sha256,omitempty"`
	TerminalIntentWire    []byte                                           `json:"terminal_intent_wire,omitempty"`
	Continuation          *GuestRetirementForwardContinuationProof         `json:"continuation,omitempty"`
	NormalFinishRecovery  *GuestRetirementForwardNormalFinishRecoveryProof `json:"normal_finish_recovery,omitempty"`
	PreDestroyRecovery    *GuestRetirementForwardPreDestroyRecoveryProof   `json:"pre_destroy_recovery,omitempty"`
}

type GuestRetirementForwardRead struct {
	Schema                string                         `json:"schema"`
	ReadID                string                         `json:"read_id"`
	AdmissionID           string                         `json:"admission_id"`
	RetirementRequestID   string                         `json:"retirement_request_id"`
	Kind                  string                         `json:"kind"`
	AdmissionSHA256       string                         `json:"admission_sha256"`
	PrefixSHA256          string                         `json:"prefix_sha256"`
	OriginalCallerSHA256  string                         `json:"original_caller_sha256"`
	MutationBindingSHA256 string                         `json:"mutation_binding_sha256"`
	AdapterSourceCommit   string                         `json:"adapter_source_commit"`
	Tuple                 model.CapacityGuestNativeTuple `json:"tuple"`
	DestroyGrantID        string                         `json:"destroy_grant_id"`
	IssuedAtCore          time.Time                      `json:"issued_at_core"`
	OriginalDeadlineCore  time.Time                      `json:"original_deadline_core"`
}
type GuestRetirementForwardReadReturn struct {
	Schema                 string                                 `json:"schema"`
	Read                   GuestRetirementForwardRead             `json:"read"`
	Status                 string                                 `json:"status"`
	Plan                   *model.CapacityVMFleetPlan             `json:"plan,omitempty"`
	Observation            *model.CapacityVMRetirementObservation `json:"observation,omitempty"`
	OriginalDestroyReceipt *model.CapacityMutationReceipt         `json:"original_destroy_receipt,omitempty"`
	StartedAtCore          time.Time                              `json:"started_at_core"`
	OriginalReturnedAtCore time.Time                              `json:"original_returned_at_core"`
	CallFailed             bool                                   `json:"call_failed"`
	OriginalContextFailed  bool                                   `json:"original_context_failed"`
	ObserverSourceCommit   string                                 `json:"observer_source_commit,omitempty"`
	OriginalObserverReturn []byte                                 `json:"original_observer_return,omitempty"`
}

// Public read-only response only: no hydrated request, credential or callback
// bearer is persisted. The original creator Source remains in Read unchanged.
type GuestRetirementReadonlyReturn struct {
	Schema                      string                                `json:"schema"`
	ObserverSourceCommit        string                                `json:"observer_source_commit"`
	OriginalAdapterSourceCommit string                                `json:"original_adapter_source_commit"`
	ReadID                      string                                `json:"read_id"`
	ReadSHA256                  string                                `json:"read_sha256"`
	OriginalReceiptSHA256       string                                `json:"original_receipt_sha256"`
	Observation                 model.CapacityVMRetirementObservation `json:"observation"`
}

const GuestRetirementReadonlyRequestSchema = "original_settled_retirement_absence_read_request_v1"
const GuestRetirementReadonlyReturnSchema = "original_settled_retirement_absence_read_return_v1"

type retirementForwardScopeKey struct{}
type retirementForwardScope struct {
	id   string
	slot int
}
type retirementForwardSnapshot struct {
	original             GuestRetirementOriginalV2
	policy               model.Manifest
	spec                 model.CapacityPolicySpec
	current              model.CapacityIntent
	binding              model.CapacityMutationBinding
	evidence             guestRetirementForwardEvidence
	intentWire           []byte
	now                  time.Time
	normalFinishRecovery *GuestRetirementForwardNormalFinishRecoveryProof
}

// Internal sparse storage JSON is distinct from signed Guest DTO decoding.
func decodeRetirementForward(raw []byte, out any) error {
	target := reflect.ValueOf(out)
	if len(raw) == 0 || raw[0] != '{' || target.Kind() != reflect.Pointer || target.IsNil() {
		return ErrCapacityConflict
	}
	next := reflect.New(target.Elem().Type())
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(next.Interface()); err != nil {
		return err
	}
	if d.Decode(new(any)) != io.EOF {
		return ErrCapacityConflict
	}
	canonical, err := json.Marshal(next.Interface())
	if err != nil || !bytes.Equal(canonical, raw) {
		return ErrCapacityConflict
	}
	target.Elem().Set(next.Elem())
	return nil
}
func insertRetirementForwardTx(ctx context.Context, tx *sql.Tx, r GuestRetirementForward) (string, error) {
	wire, err := json.Marshal(r)
	if err != nil {
		return "", err
	}
	digest := capacity.BusinessCreationSHA256(wire)
	_, err = tx.ExecContext(ctx, `INSERT INTO public.capacity_guest_retirement_forwards(id,stage,retirement_request_id,preregistration_id,namespace,environment,domain,dimension,integration_instance_id,scope_checksum,profile_name,slot,record_sha256,original_wire,original_record,recorded_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15::jsonb,$16)`, r.ID, r.Stage, r.RetirementRequestID, r.PreregistrationID, r.Namespace, r.Environment, r.Domain, r.Dimension, r.Original.Request.Intent.Tuple.InstanceID, r.Original.Request.Intent.Tuple.ScopeChecksum, r.Original.Request.Intent.Tuple.Profile, r.Original.Request.Intent.Slot, digest, wire, string(wire), r.RecordedAt)
	return digest, err
}
func loadRetirementForwardTx(ctx context.Context, tx *sql.Tx, id, stage string) (GuestRetirementForward, string, error) {
	var r GuestRetirementForward
	var raw []byte
	var digest string
	var same bool
	err := tx.QueryRowContext(ctx, `SELECT original_wire,record_sha256,original_record=convert_from(original_wire,'UTF8')::jsonb FROM public.capacity_guest_retirement_forwards WHERE id=$1 AND stage=$2 FOR SHARE`, id, stage).Scan(&raw, &digest, &same)
	if err != nil {
		return r, "", err
	}
	if !same || capacity.BusinessCreationSHA256(raw) != digest || decodeRetirementForward(raw, &r) != nil || r.ID != id || r.Stage != stage || r.Schema != GuestRetirementForwardSchema {
		return r, "", ErrCapacityConflict
	}
	return r, digest, nil
}
func retirementForwardMarker(r GuestRetirementForward) *model.CapacityGuestRetirementForwardMarker {
	return &model.CapacityGuestRetirementForwardMarker{Schema: r.Schema, ID: r.ID, RetirementRequestID: r.RetirementRequestID, PreregistrationID: r.PreregistrationID, Mode: r.Mode, Stage: r.Stage, OriginalIntentSHA256: r.OriginalIntentSHA256, OriginalGeneration: r.OriginalGeneration, OriginalFence: r.OriginalFence}
}
func retirementForwardActive(i *model.CapacityIntent) bool {
	return i != nil && i.RetirementForward != nil && i.RetirementForward.Stage != "terminal"
}
func persistRetirementForwardIntentTx(ctx context.Context, tx *sql.Tx, old, next model.CapacityIntent, receipt string) error {
	before, err := json.Marshal(old)
	if err != nil {
		return err
	}
	after, err := json.Marshal(next)
	if err != nil {
		return err
	}
	result, err := tx.ExecContext(ctx, `UPDATE public.capacity_intents SET intent=$5::jsonb,updated_at=$7 WHERE namespace=$1 AND environment=$2 AND domain=$3 AND dimension=$4 AND intent=$6::jsonb`, old.Namespace, old.Environment, old.Domain, old.Dimension, string(after), string(before), next.UpdatedAt)
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err != nil || n != 1 {
		return ErrCapacityConflict
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO public.capacity_intent_events(namespace,environment,domain,dimension,generation,fencing_token,phase,receipt_ref) VALUES($1,$2,$3,$4,$5,$6,$7,$8)`, next.Namespace, next.Environment, next.Domain, next.Dimension, next.Generation, next.FencingToken, next.Phase, receipt)
	return err
}

func (s CapacityStore) retirementForwardSnapshotTx(ctx context.Context, tx *sql.Tx, id string) (retirementForwardSnapshot, error) {
	return s.retirementForwardSnapshotForNormalFinishTx(ctx, tx, id, false)
}

func (s CapacityStore) retirementForwardSnapshotForNormalFinishTx(ctx context.Context, tx *sql.Tx, id string, normalFinish bool) (retirementForwardSnapshot, error) {
	var x retirementForwardSnapshot
	forwardInspectionStage(ctx, "scope_lookup")
	var ns, env, domain, dim string
	if err := tx.QueryRowContext(ctx, `SELECT g.namespace,g.environment,g.domain,g.dimension FROM public.capacity_vm_retirement_intents r JOIN public.capacity_vm_provisioning_preregistrations p ON p.id=r.preregistration_id JOIN public.capacity_mutation_grants g ON g.id=p.create_grant_id WHERE r.id=$1`, id).Scan(&ns, &env, &domain, &dim); err != nil {
		return x, err
	}
	forwardInspectionStage(ctx, "scope_lock")
	if err := lockMutationScope(ctx, tx, ns, model.CapacityPolicySpec{Environment: env, Domain: domain, Dimension: dim}); err != nil {
		return x, err
	}
	forwardInspectionStage(ctx, "timezone")
	if _, err := tx.ExecContext(ctx, `SET LOCAL TIME ZONE 'UTC'`); err != nil {
		return x, err
	}
	var err error
	forwardInspectionStage(ctx, "original_retirement_load")
	x.original, err = loadGuestRetirementV2Tx(ctx, tx, id, true)
	if err != nil {
		return x, err
	}
	i := x.original.Request.Intent
	forwardInspectionStage(ctx, "original_policy_id")
	x.policy.ID, err = uuid.Parse(i.PolicyID)
	if err != nil {
		return x, err
	}
	x.policy.Kind = "capacity_policy"
	var active bool
	forwardInspectionStage(ctx, "policy_original")
	err = tx.QueryRowContext(ctx, `SELECT namespace,name,version,checksum,spec,active FROM public.manifests WHERE id=$1 AND kind='capacity_policy' FOR SHARE`, x.policy.ID).Scan(&x.policy.Metadata.Namespace, &x.policy.Metadata.Name, &x.policy.Version, &x.policy.Checksum, &x.policy.Spec, &active)
	if err != nil || !active || x.policy.Checksum != i.PolicyChecksum {
		return x, ErrCapacityConflict
	}
	var latestPolicy string
	forwardInspectionStage(ctx, "policy_latest")
	if tx.QueryRowContext(ctx, `SELECT id::text FROM public.manifests WHERE kind='capacity_policy' AND namespace=$1 AND name=$2 ORDER BY version DESC,id DESC LIMIT 1 FOR SHARE`, x.policy.Metadata.Namespace, x.policy.Metadata.Name).Scan(&latestPolicy) != nil || latestPolicy != x.policy.ID.String() {
		return x, ErrCapacityConflict
	}
	forwardInspectionStage(ctx, "policy_parse")
	x.spec, err = parseCapacityPolicy(x.policy)
	if err != nil {
		return x, err
	}
	forwardInspectionStage(ctx, "binding_authority_profile")
	if ns != x.policy.Metadata.Namespace || env != x.spec.Environment || domain != x.spec.Domain || dim != x.spec.Dimension || x.spec.GuestRetirementBinding == nil || !reflect.DeepEqual(*x.spec.GuestRetirementBinding, x.original.Binding) || !capacity.GuestBindingAuthorityCurrent(x.spec, x.original.Binding) || !capacity.GuestOriginalProfileEnabled(x.spec, x.original.Binding, i.Tuple.Provider) {
		return x, ErrCapacityConflict
	}
	var wfChecksum string
	forwardInspectionStage(ctx, "workflow_original")
	err = tx.QueryRowContext(ctx, `SELECT checksum,active FROM public.manifests WHERE id=$1 AND kind='workflow' AND namespace=$2 AND name=$3 AND jsonb_typeof(spec->'authorization')='object' FOR SHARE`, i.WorkflowID, x.spec.Workflow.Namespace, x.spec.Workflow.Name).Scan(&wfChecksum, &active)
	if err != nil || !active || wfChecksum != i.WorkflowChecksum {
		return x, ErrCapacityConflict
	}
	var latestWorkflow string
	forwardInspectionStage(ctx, "workflow_latest")
	if tx.QueryRowContext(ctx, `SELECT id::text FROM public.manifests WHERE kind='workflow' AND namespace=$1 AND name=$2 ORDER BY version DESC,id DESC LIMIT 1 FOR SHARE`, x.spec.Workflow.Namespace, x.spec.Workflow.Name).Scan(&latestWorkflow) != nil || latestWorkflow != i.WorkflowID {
		return x, ErrCapacityConflict
	}
	forwardInspectionStage(ctx, "profile_locks")
	if err = lockRetirementForwardBindingsTx(ctx, tx, x.spec.MutationBindings); err != nil {
		return x, err
	}
	forwardInspectionStage(ctx, "current_intent_decode")
	x.current, err = loadCapacityIntent(ctx, tx, ns, x.spec, true)
	if err != nil {
		return x, err
	}
	forwardInspectionStage(ctx, "current_intent_wire")
	if err = tx.QueryRowContext(ctx, `SELECT intent::text,clock_timestamp() FROM public.capacity_intents WHERE namespace=$1 AND environment=$2 AND domain=$3 AND dimension=$4`, ns, env, domain, dim).Scan(&x.intentWire, &x.now); err != nil {
		return x, err
	}
	forwardInspectionStage(ctx, "integration_binding")
	x.binding, err = capacity.VMObservationBinding(x.spec, x.original.Binding.MutationBindingName)
	if err != nil || checkMutationIntegration(ctx, tx, x.binding) != nil {
		return x, ErrCapacityConflict
	}
	forwardInspectionStage(ctx, "current_intent_predicates")
	if x.current.PolicyID != x.policy.ID || x.current.PolicyChecksum != x.policy.Checksum || x.current.Generation != int64(i.Generation) || x.current.RecoveryOnly || x.current.FloorDegraded || x.current.OriginalNotifyWindow != nil || x.current.FailedInstalledDisposal != nil || x.current.FailedServingDisposal != nil || !capacityIntentReduction(x.current) || (x.current.Phase != "draining" && x.current.Phase != "drained") || i.Slot <= x.binding.ProtectedSlots || i.Slot < 2 || i.Slot > 8 || x.current.BaselineSnapshot.Profile != x.binding.ProfileName || x.current.Decision.Profile != x.binding.ProfileName || x.current.BaselineSnapshot.Units != i.Slot || x.current.Decision.Units != i.Slot-1 || x.current.Decision.Units < x.spec.Floor || !capacityProfileCurrent(x.spec, x.current.Decision, x.now) {
		return x, ErrCapacityConflict
	}
	lockCtx := ctx
	if x.current.RetirementForward != nil {
		lockCtx = context.WithValue(ctx, retirementForwardScopeKey{}, retirementForwardScope{id: x.current.RetirementForward.ID, slot: i.Slot})
	}
	forwardInspectionStage(ctx, "native_slot_lock")
	if err = lockNativeMutationSlot(lockCtx, tx, x.binding, i.Slot); err != nil {
		return x, err
	}
	var slot capacityResourceSlot
	var exists bool
	forwardInspectionStage(ctx, "native_slot_tuple")
	slot, exists, err = loadMutationSlot(ctx, tx, ns, x.spec, x.binding, i.Slot)
	if err != nil || !exists || slot.ProfileName != x.binding.ProfileName {
		return x, ErrCapacityConflict
	}
	if (slot.Tombstone || slot.ResourceID != i.Tuple.ResourceID || slot.ResourceCreatedAt != i.Tuple.CreatedAt) && !forwardConfirmedTombstoneTx(ctx, tx, x.current, slot) {
		return x, ErrCapacityConflict
	}
	// The exact enrolled native tuple and confirmed original create stay owned.
	forwardInspectionStage(ctx, "original_create_receipt")
	original, err := guestOriginalCreateReceiptV2Tx(ctx, tx, x.original)
	if err != nil || original.Grant.State != "confirmed" || original.ResourceID != i.Tuple.ResourceID || original.ResourceCreatedAt != i.Tuple.CreatedAt {
		return x, ErrCapacityConflict
	}
	forwardInspectionStage(ctx, "original_evidence")
	if x.current.RetirementForward != nil {
		m := x.current.RetirementForward
		r, _, loadErr := loadRetirementForwardTx(ctx, tx, m.ID, m.Stage)
		if loadErr != nil {
			return x, loadErr
		}
		x.normalFinishRecovery = r.NormalFinishRecovery
		normalFinish = normalFinish || r.NormalFinishRecovery != nil
	}
	if normalFinish {
		x.evidence, err = guestRetirementNormalFinishEvidenceTx(ctx, tx, x.original)
	} else {
		x.evidence, err = guestRetirementForwardEvidenceTx(ctx, tx, x.original)
	}
	return x, err
}

func (s CapacityStore) GuestRetirementForwardWaiting(ctx context.Context, policy model.Manifest) (GuestRetirementForward, bool, error) {
	var r GuestRetirementForward
	p, err := parseCapacityPolicy(policy)
	if err != nil {
		return r, false, err
	}
	current, err := loadCapacityIntent(ctx, s.DB, policy.Metadata.Namespace, p, false)
	if errors.Is(err, sql.ErrNoRows) {
		return r, false, nil
	}
	if err != nil {
		return r, false, err
	}
	if !retirementForwardActive(&current) {
		return r, false, nil
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return r, false, err
	}
	defer tx.Rollback()
	r, _, err = loadRetirementForwardTx(ctx, tx, current.RetirementForward.ID, current.RetirementForward.Stage)
	return r, err == nil, err
}
func (s CapacityStore) ReadGuestRetirementForwards(ctx context.Context, preID string) ([]GuestRetirementForward, error) {
	if !validCapacityExecutor(preID) {
		return nil, ErrCapacityConflict
	}
	rows, err := s.DB.QueryContext(ctx, `SELECT original_wire,record_sha256 FROM public.capacity_guest_retirement_forwards WHERE preregistration_id=$1 ORDER BY recorded_at,id,stage`, preID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []GuestRetirementForward{}
	for rows.Next() {
		var raw []byte
		var sha string
		var r GuestRetirementForward
		if err = rows.Scan(&raw, &sha); err != nil {
			return nil, err
		}
		if capacity.BusinessCreationSHA256(raw) != sha || decodeRetirementForward(raw, &r) != nil || r.Schema != GuestRetirementForwardSchema {
			return nil, ErrCapacityConflict
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
