package repository

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"strings"
	"sync/atomic"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

const FailedServingGuestQuarantinedPhase = "serving_guest_quarantined"
const FailedServingGuestDisposedPhase = "disposed_failed_serving"
const failedServingSchema = "failed_serving_guest_disposal_v1"

// Private dependency seam for source-only repository tests. Production always
// derives the build from native metadata; no HTTP/config input selects it.
var failedServingCurrentSource = capacity.CurrentGuestCoreSource

type failedServingReadScopeKey struct{}
type failedServingReadScope struct{ admissionID, preregistrationID string }

// Every logical-slot authority takes this shared lock, including other policy
// realms. A quarantined slot cannot be reached by changing the policy selector.
// Only SnapshotTx constructs the private GET-only exception; no caller input or
// store option enables it. Ordinary terminal replacement retains all old gates.
func guardFailedServingSlotTx(ctx context.Context, tx *sql.Tx, b model.CapacityMutationBinding, slot int) error {
	var raw []byte
	err := tx.QueryRowContext(ctx, `SELECT slot_record FROM public.capacity_resource_slots WHERE integration_instance_id=$1 AND scope_checksum=$2 AND profile_name=$3 AND slot=1 FOR SHARE`, b.IntegrationInstanceID, b.ScopeChecksum, b.ProfileName).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	var stored capacityResourceSlot
	if json.Unmarshal(raw, &stored) != nil {
		return ErrCapacityConflict
	}
	if stored.FailedServingDisposalID == "" {
		return nil
	}
	r, err := loadFailedServingTx(ctx, tx, stored.FailedServingDisposalID, "quarantined")
	if err != nil || r.Candidate.Binding.IntegrationInstanceID != b.IntegrationInstanceID || r.Candidate.Binding.ScopeChecksum != b.ScopeChecksum || r.Candidate.Binding.ProfileName != b.ProfileName || r.Candidate.Request.Slot != 1 {
		return ErrCapacityConflict
	}
	if proof, ok := ctx.Value(failedServingReadScopeKey{}).(failedServingReadScope); ok && slot == 1 && proof.admissionID == r.ID && proof.preregistrationID == r.PreregistrationID {
		return nil
	}
	terminal, err := loadFailedServingTx(ctx, tx, r.ID, "terminal")
	if err != nil || terminal.PreregistrationID != r.PreregistrationID || terminal.Absence == nil || terminal.Inventory == nil || !stored.Tombstone || stored.ResourceID != "" {
		return ErrCapacityConflict
	}
	return nil
}

// Every row is immutable. This lineage records actual native reads and an
// observed deficit, never a Guest drain, operator DELETE ACK or zero past use.
type FailedServingGuestDisposal struct {
	Schema                      string                                              `json:"schema"`
	ID                          string                                              `json:"id"`
	RecordID                    string                                              `json:"record_id"`
	Stage                       string                                              `json:"stage"`
	Namespace                   string                                              `json:"namespace"`
	Environment                 string                                              `json:"environment"`
	Domain                      string                                              `json:"domain"`
	Dimension                   string                                              `json:"dimension"`
	PreregistrationID           string                                              `json:"preregistration_id"`
	Issuer                      string                                              `json:"issuer"`
	ActualCoreSource            string                                              `json:"actual_core_source"`
	RecordedAt                  time.Time                                           `json:"recorded_at"`
	OriginalIntentWire          []byte                                              `json:"original_intent_wire"`
	OriginalIntentSHA256        string                                              `json:"original_intent_sha256"`
	QuarantineIntentSHA256      string                                              `json:"quarantine_intent_sha256"`
	TerminalIntentSHA256        string                                              `json:"terminal_intent_sha256,omitempty"`
	Candidate                   model.CapacityOriginalCreateDispositionCandidate    `json:"candidate"`
	Workflow                    model.Manifest                                      `json:"workflow"`
	InstallationSHA256          string                                              `json:"installation_sha256"`
	EnrollmentSHA256            string                                              `json:"enrollment_sha256"`
	HistoricalAcceptedReadCount int                                                 `json:"historical_accepted_read_count"`
	HistoricalPromotedCount     int                                                 `json:"historical_promoted_count"`
	CurrentStableEventSHA256    string                                              `json:"current_stable_event_sha256"`
	NativeOffRecordID           string                                              `json:"native_off_record_id,omitempty"`
	HistoricalUnknowns          json.RawMessage                                     `json:"historical_unknowns"`
	HistoricalCanaries          json.RawMessage                                     `json:"historical_canaries"`
	OriginalSlotSHA256          string                                              `json:"original_slot_sha256"`
	QuarantineSlotSHA256        string                                              `json:"quarantine_slot_sha256"`
	Inventory                   *model.CapacityVMFleetInventory                     `json:"inventory,omitempty"`
	NativeOff                   *model.CapacityVMFleetPlan                          `json:"native_off,omitempty"`
	Absence                     *model.CapacityOriginalCreateDispositionObservation `json:"absence,omitempty"`
	OriginalReadStartedAt       time.Time                                           `json:"original_read_started_at"`
	OriginalReadReturnedAt      time.Time                                           `json:"original_read_returned_at"`
	BusinessEffectsPreserved    bool                                                `json:"business_effects_preserved"`
	CoreOrGuestNativeWriteSent  bool                                                `json:"Core_or_Guest_native_write_sent"`
	GuestWriterDrainClaimed     bool                                                `json:"Guest_writer_drain_claimed"`
}

type failedServingSnapshot struct {
	record     FailedServingGuestDisposal
	policy     model.Manifest
	spec       model.CapacityPolicySpec
	intent     model.CapacityIntent
	intentWire []byte
	slot       capacityResourceSlot
	now        time.Time
}

// The private owner binds one actual bounded GET and its original context.
// It supplies no durable read lease and cannot authorize a provider write.
type FailedServingGuestOwner struct {
	db                 *sql.DB
	ctx                context.Context
	deadline           time.Time
	started            time.Time
	mode               string
	issuer             string
	actualCoreSource   string
	request            model.CapacityFailedServingGuestDisposalRequest
	preID, admissionID string
	snapshot           failedServingSnapshot
	snapshotSHA        string
	used               atomic.Bool
}

func (o *FailedServingGuestOwner) Candidate() model.CapacityOriginalCreateDispositionCandidate {
	var c model.CapacityOriginalCreateDispositionCandidate
	if o != nil {
		raw, _ := json.Marshal(o.snapshot.record.Candidate)
		_ = json.Unmarshal(raw, &c)
	}
	return c
}
func (o *FailedServingGuestOwner) Policy() model.Manifest { return o.Candidate().OriginalPolicy }
func (o *FailedServingGuestOwner) Spec() model.CapacityPolicySpec {
	var p model.CapacityPolicySpec
	if o != nil {
		raw, _ := json.Marshal(o.snapshot.spec)
		_ = json.Unmarshal(raw, &p)
	}
	return p
}

func failedServingIssuer(issuer string) bool {
	return strings.HasPrefix(issuer, "collaborator:") && validCapacityExecutor(strings.TrimPrefix(issuer, "collaborator:"))
}
func failedServingRequestValid(r model.CapacityFailedServingGuestDisposalRequest) bool {
	return validCapacityExecutor(r.PreregistrationID) && validCapacityExecutor(r.PolicyID) && capacity.ValidDigest(r.PolicyChecksum) &&
		r.Generation > 0 && r.FencingToken > 0 && r.FencingToken < maxCapacityGeneration && capacity.ValidDigest(r.IntentSHA256)
}
func failedServingSnapshotSHA(v failedServingSnapshot) string {
	return capacity.GuestRetirementSHA(struct {
		Record FailedServingGuestDisposal
		Intent string
		Slot   capacityResourceSlot
	}{v.record, string(v.intentWire), v.slot})
}
func failedServingJSONSHA(raw []byte) string {
	return capacity.GuestRetirementSHA(json.RawMessage(raw))
}

func insertFailedServingTx(ctx context.Context, tx *sql.Tx, r FailedServingGuestDisposal) error {
	raw, err := json.Marshal(r)
	if err != nil {
		return err
	}
	var offID any
	if r.NativeOffRecordID != "" {
		offID = r.NativeOffRecordID
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO public.capacity_guest_failed_serving_disposals(row_id,admission_id,stage,namespace,environment,domain,dimension,preregistration_id,original_wire,original_record,record_sha256,recorded_at,quiescent_row_id) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10::jsonb,$11,$12,$13)`, r.RecordID, r.ID, r.Stage, r.Namespace, r.Environment, r.Domain, r.Dimension, r.PreregistrationID, raw, string(raw), capacity.BusinessCreationSHA256(raw), r.RecordedAt, offID)
	return err
}

// CapacityIntent is internal sparse storage, not a signed Guest protocol DTO.
// PostgreSQL renders JSONB in its own order and nullable containers are legal;
// retain the original wire separately for the exact SHA and CAS comparisons.
func decodeFailedServingIntent(raw []byte, out *model.CapacityIntent) error {
	if out == nil || len(bytes.TrimSpace(raw)) == 0 || bytes.TrimSpace(raw)[0] != '{' {
		return ErrCapacityConflict
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	var next model.CapacityIntent
	if err := d.Decode(&next); err != nil {
		return err
	}
	if d.Decode(new(any)) != io.EOF {
		return ErrCapacityConflict
	}
	*out = next
	return nil
}

// These immutable records contain manifests and raw historical JSON as well
// as sparse internal intent bytes. Require the exact encoding emitted by this
// store; native Guest authenticity remains in its original typed validators.
func decodeFailedServingDisposal(raw []byte, out *FailedServingGuestDisposal) error {
	if out == nil || len(bytes.TrimSpace(raw)) == 0 || bytes.TrimSpace(raw)[0] != '{' {
		return ErrCapacityConflict
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	var next FailedServingGuestDisposal
	if err := d.Decode(&next); err != nil {
		return err
	}
	if d.Decode(new(any)) != io.EOF {
		return ErrCapacityConflict
	}
	canonical, err := json.Marshal(next)
	if err != nil || !bytes.Equal(canonical, raw) {
		return ErrCapacityConflict
	}
	*out = next
	return nil
}

func loadFailedServingTx(ctx context.Context, tx *sql.Tx, id, stage string) (FailedServingGuestDisposal, error) {
	var out FailedServingGuestDisposal
	var raw []byte
	var hash string
	var same bool
	err := tx.QueryRowContext(ctx, `SELECT original_wire,record_sha256,original_record=convert_from(original_wire,'UTF8')::jsonb FROM public.capacity_guest_failed_serving_disposals WHERE admission_id=$1 AND stage=$2 ORDER BY recorded_at DESC,row_id DESC LIMIT 1 FOR SHARE`, id, stage).Scan(&raw, &hash, &same)
	if err != nil {
		return out, err
	}
	if !same || capacity.BusinessCreationSHA256(raw) != hash || decodeFailedServingDisposal(raw, &out) != nil || out.Schema != failedServingSchema || out.ID != id || out.Stage != stage || !originalDispositionHex(out.ActualCoreSource, 40) || !out.BusinessEffectsPreserved || out.CoreOrGuestNativeWriteSent || out.GuestWriterDrainClaimed {
		return out, ErrCapacityConflict
	}
	return out, nil
}

func failedServingCurrentPolicyTx(ctx context.Context, tx *sql.Tx, id string) (model.Manifest, model.CapacityPolicySpec, error) {
	var policy model.Manifest
	var p model.CapacityPolicySpec
	var active bool
	parsed, err := uuid.Parse(id)
	if err != nil || parsed == uuid.Nil || parsed.String() != id {
		return policy, p, ErrCapacityConflict
	}
	policy.ID, policy.Kind = parsed, "capacity_policy"
	err = tx.QueryRowContext(ctx, `SELECT namespace,name,version,checksum,spec,active FROM public.manifests WHERE id=$1 AND kind='capacity_policy' FOR SHARE`, parsed).Scan(&policy.Metadata.Namespace, &policy.Metadata.Name, &policy.Version, &policy.Checksum, &policy.Spec, &active)
	if err != nil || !active {
		return policy, p, ErrCapacityConflict
	}
	policy.Metadata.Active = active
	var latest string
	err = tx.QueryRowContext(ctx, `SELECT id::text FROM public.manifests WHERE kind='capacity_policy' AND namespace=$1 AND name=$2 ORDER BY version DESC,id DESC LIMIT 1 FOR SHARE`, policy.Metadata.Namespace, policy.Metadata.Name).Scan(&latest)
	if err != nil || latest != id {
		return policy, p, ErrCapacityConflict
	}
	p, err = parseCapacityPolicy(policy)
	if err != nil || p.Floor != 1 || p.Ceiling != 8 || len(p.Profiles) != 1 || len(p.MutationBindings) != 1 || p.GuestRetirementBinding == nil || p.GuestNotifyReconcileBinding == nil || capacity.ValidateGuestNotifyReconcileBinding(p) != nil || !capacity.GuestBindingAuthorityCurrent(p, *p.GuestRetirementBinding) || !capacity.GuestOriginalProfileEnabled(p, *p.GuestRetirementBinding, p.Profiles[0].Provider) {
		return policy, p, ErrCapacityConflict
	}
	return policy, p, nil
}

func failedServingBusyTx(ctx context.Context, tx *sql.Tx, policy model.Manifest, p model.CapacityPolicySpec, workflow model.Manifest, preID string, now time.Time) error {
	var busy int
	// Disposed historical unknowns intentionally keep ACK NULL and uncertain
	// canary effects. They are not queued/started/unknown/returned-unacked work.
	err := tx.QueryRowContext(ctx, `SELECT
 (SELECT count(*) FROM public.workflow_runs WHERE (workflow_id=$1 OR (workflow_namespace=$2 AND workflow_name=$3)) AND (COALESCE(status,'') NOT IN('succeeded','failed','cancelled') OR finished_at IS NULL))+
 (SELECT count(*) FROM public.capacity_dispatch_jobs WHERE realm=$2 AND environment=$4 AND domain=$5 AND dimension=$6 AND (state IN('queued','started','unknown') OR state='returned' AND finalization_ack_at IS NULL))+
 (SELECT count(*) FROM public.capacity_mutation_grants WHERE ((namespace=$2 AND environment=$4 AND domain=$5 AND dimension=$6) OR (integration_instance_id=$9 AND scope_checksum=$10 AND profile_name=$11)) AND `+capacityGrantUndisposedSQL+` AND state IN('issued','redeemed','settled','compensating'))+
 (SELECT count(*) FROM public.capacity_guest_notify_canary_challenges WHERE preregistration_id=$7 AND original_deadline>$8)+
 (SELECT count(*) FROM public.capacity_vm_retirement_intents WHERE preregistration_id=$7)
`, workflow.ID, policy.Metadata.Namespace, p.Workflow.Name, p.Environment, p.Domain, p.Dimension, preID, now, p.MutationBindings[0].IntegrationInstanceID, p.MutationBindings[0].ScopeChecksum, p.MutationBindings[0].ProfileName).Scan(&busy)
	if err != nil {
		return err
	}
	if busy != 0 {
		return ErrCapacityConflict
	}
	return nil
}

func failedServingSnapshotTx(ctx context.Context, tx *sql.Tx, req model.CapacityFailedServingGuestDisposalRequest, id string) (failedServingSnapshot, error) {
	var out failedServingSnapshot
	// SQL row-to-JSON hashes include timestamptz projections. Use one explicit
	// representation across pooled sessions and the existing ADR-0096 reader.
	if _, err := tx.ExecContext(ctx, `SET LOCAL TIME ZONE 'UTC'`); err != nil {
		return out, err
	}
	policy, p, err := failedServingCurrentPolicyTx(ctx, tx, req.PolicyID)
	if err != nil || policy.Checksum != req.PolicyChecksum {
		return out, ErrCapacityConflict
	}
	if err = lockMutationScope(ctx, tx, policy.Metadata.Namespace, p); err != nil {
		return out, err
	}
	b := p.MutationBindings[0]
	slotContext := ctx
	if id != "" {
		slotContext = context.WithValue(ctx, failedServingReadScopeKey{}, failedServingReadScope{id, req.PreregistrationID})
	}
	if err = lockNativeMutationSlot(slotContext, tx, b, 1); err != nil {
		return out, err
	}
	if err = tx.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&out.now); err != nil {
		return out, err
	}
	if err = tx.QueryRowContext(ctx, `SELECT intent::text FROM public.capacity_intents WHERE namespace=$1 AND environment=$2 AND domain=$3 AND dimension=$4 FOR UPDATE`, policy.Metadata.Namespace, p.Environment, p.Domain, p.Dimension).Scan(&out.intentWire); err != nil {
		return out, err
	}
	if decodeFailedServingIntent(out.intentWire, &out.intent) != nil {
		return out, ErrCapacityConflict
	}
	current := out.intent
	if current.PolicyID != policy.ID || current.PolicyChecksum != policy.Checksum || current.Generation != req.Generation || current.RecoveryOnly || current.FloorDegraded || current.LeaseExpiresAt != nil && current.LeaseExpiresAt.After(out.now) || current.LeaseOwner != "" || current.LeaseExecutorID != "" || current.FailedInstalledDisposal != nil {
		return out, ErrCapacityConflict
	}
	if id == "" {
		if !guestNotifyStableEpoch(current) || current.FailedServingDisposal != nil || current.FencingToken != req.FencingToken || capacity.BusinessCreationSHA256(out.intentWire) != req.IntentSHA256 || current.Decision.Units != 1 || current.Assessment.Snapshot.Units != 1 {
			return out, ErrCapacityConflict
		}
	} else {
		r, e := loadFailedServingTx(ctx, tx, id, "quarantined")
		if e != nil || r.PreregistrationID != req.PreregistrationID || current.Phase != FailedServingGuestQuarantinedPhase || current.FailedServingDisposal == nil || current.FailedServingDisposal.ID != id || current.FailedServingDisposal.Stage != "quarantined" || current.FencingToken != req.FencingToken+1 || current.FailedServingDisposal.OriginalIntentSHA256 != req.IntentSHA256 || capacity.BusinessCreationSHA256(out.intentWire) != r.QuarantineIntentSHA256 {
			return out, ErrCapacityConflict
		}
		out.record = r
	}
	stored, err := loadGuestOriginalTx(ctx, tx, req.PreregistrationID)
	if err != nil || stored.pre.Slot != 1 || stored.pre.Generation <= 0 || stored.pre.Generation > current.Generation || stored.pre.Fence <= 0 || stored.pre.Fence > req.FencingToken || !reflect.DeepEqual(stored.binding, *p.GuestRetirementBinding) {
		return out, ErrCapacityConflict
	}
	if stored.pre.OriginalDeadline.IsZero() || !stored.pre.OriginalDeadline.Before(out.now) || stored.pre.OriginalWorkflowContextDeadline.IsZero() || !stored.pre.OriginalWorkflowContextDeadline.Before(out.now) {
		return out, ErrCapacityConflict
	}
	if err = guestPolicyContinuityTx(ctx, tx, policy, p, stored.pre.PolicyID, stored.pre.PolicyChecksum); err != nil {
		return out, err
	}
	if err = loadGuestWitnessTx(ctx, tx, &stored); err != nil {
		return out, err
	}
	receipt, _, err := loadGuestReceiptTx(ctx, tx, req.PreregistrationID)
	if err != nil {
		return out, err
	}
	if !guestNotifyHistoricalEnrollmentMatches(p, stored, receipt) {
		return out, ErrCapacityConflict
	}
	installed, err := loadGuestInstallationTx(ctx, tx, stored, receipt)
	if err != nil {
		return out, err
	}
	slot, exists, err := loadMutationSlot(ctx, tx, policy.Metadata.Namespace, p, b, 1)
	if err != nil || !exists || slot.Tombstone || slot.ResourceID != stored.witness.Tuple.ResourceID || slot.ResourceCreatedAt != stored.witness.Tuple.CreatedAt {
		return out, ErrCapacityConflict
	}
	if id == "" && slot.FailedServingDisposalID != "" || id != "" && slot.FailedServingDisposalID != id {
		return out, ErrCapacityConflict
	}
	var raw []byte
	var state string
	var grantExpiry time.Time
	err = tx.QueryRowContext(ctx, `SELECT state,grant_record,expires_at FROM public.capacity_mutation_grants WHERE id=$1 FOR SHARE`, stored.pre.OriginalCreateGrantID).Scan(&state, &raw, &grantExpiry)
	var created capacityMutationRecord
	if err != nil || json.Unmarshal(raw, &created) != nil || state != "confirmed" || created.Grant.State != state || created.Settlement == nil || created.Proof == nil || created.Grant.Capability != b.EnsureCapability || !reflect.DeepEqual(created.Binding, b) || created.Grant.GrantID != stored.pre.OriginalCreateGrantID || created.Grant.RequestSHA256 != stored.pre.OriginalCreateRequestSHA256 || created.Settlement.ResourceID != slot.ResourceID || created.Settlement.ResourceCreatedAt != slot.ResourceCreatedAt || created.Settlement.Outcome != "accepted" || !created.Settlement.TransportCompleted || created.Settlement.OriginalProviderCreateReturn == nil || created.Settlement.OriginalProviderCreateReturn.AdapterSourceCommit != b.OriginalProviderSourceCommit {
		return out, ErrCapacityConflict
	}
	if created.PolicyID.String() != stored.pre.PolicyID || created.PolicyChecksum != stored.pre.PolicyChecksum || created.Generation != stored.pre.Generation || created.FencingToken != stored.pre.Fence || created.WorkflowID.String() != stored.pre.WorkflowID {
		return out, ErrCapacityConflict
	}
	if created.Grant.ExpiresAt.IsZero() || !created.Grant.ExpiresAt.Equal(grantExpiry) || !created.Grant.ExpiresAt.Before(out.now) {
		return out, ErrCapacityConflict
	}
	var workflow model.Manifest
	workflow.Kind = "workflow"
	var active bool
	err = tx.QueryRowContext(ctx, `SELECT id,namespace,name,version,checksum,spec,active FROM public.manifests WHERE kind='workflow' AND namespace=$1 AND name=$2 ORDER BY version DESC,id DESC LIMIT 1 FOR SHARE`, p.Workflow.Namespace, p.Workflow.Name).Scan(&workflow.ID, &workflow.Metadata.Namespace, &workflow.Metadata.Name, &workflow.Version, &workflow.Checksum, &workflow.Spec, &active)
	var graph model.WorkflowManifestSpec
	if err != nil || !active || workflow.ID.String() != stored.pre.WorkflowID || workflow.Checksum != stored.pre.WorkflowChecksum || json.Unmarshal(workflow.Spec, &graph) != nil || capacity.ValidateOriginalGuestReconcileGraph(graph, policy, p) != nil {
		return out, ErrCapacityConflict
	}
	workflow.Metadata.Active = active
	if err = checkMutationIntegration(ctx, tx, b); err != nil {
		return out, err
	}
	if err = failedServingBusyTx(ctx, tx, policy, p, workflow, req.PreregistrationID, out.now); err != nil {
		return out, err
	}
	var live int
	err = tx.QueryRowContext(ctx, `SELECT count(*) FROM public.capacity_resource_slots WHERE namespace=$1 AND environment=$2 AND domain=$3 AND dimension=$4 AND resource_id<>'' AND COALESCE(slot_record->>'tombstone','false')='false'`, policy.Metadata.Namespace, p.Environment, p.Domain, p.Dimension).Scan(&live)
	if err != nil || live != 1 {
		return out, ErrCapacityConflict
	}
	var reads, promoted int
	err = tx.QueryRowContext(ctx, `SELECT
 (SELECT count(*) FROM public.capacity_guest_notify_canary_challenges c JOIN public.capacity_guest_notify_canary_returns r ON r.challenge_id=c.id WHERE c.preregistration_id=$1 AND c.phase='read' AND r.outcome='accepted'),
	 (SELECT count(*) FROM public.capacity_intent_events WHERE namespace=$2 AND environment=$3 AND domain=$4 AND dimension=$5 AND generation=$6 AND phase='promoted')`, req.PreregistrationID, policy.Metadata.Namespace, p.Environment, p.Domain, p.Dimension, stored.pre.Generation).Scan(&reads, &promoted)
	if err != nil || reads < 1 || promoted < 1 {
		return out, ErrCapacityConflict
	}
	stable := current
	if id != "" && decodeFailedServingIntent(out.record.OriginalIntentWire, &stable) != nil {
		return out, ErrCapacityConflict
	}
	var stableEventSHA string
	err = tx.QueryRowContext(ctx, `SELECT encode(sha256(convert_to(to_jsonb(e)::text,'UTF8')),'hex') FROM public.capacity_intent_events e WHERE namespace=$1 AND environment=$2 AND domain=$3 AND dimension=$4 AND generation=$5 AND fencing_token=$6 AND phase=$7 ORDER BY id DESC LIMIT 1 FOR SHARE`, policy.Metadata.Namespace, p.Environment, p.Domain, p.Dimension, req.Generation, req.FencingToken, stable.Phase).Scan(&stableEventSHA)
	if err != nil || !guestNotifyStableEpoch(stable) {
		return out, ErrCapacityConflict
	}
	var unknowns, canaries []byte
	err = tx.QueryRowContext(ctx, `SELECT COALESCE(jsonb_agg(jsonb_build_object('id',id,'state',state,'finalization_ack_at',finalization_ack_at,'row_sha_input',row_to_json(j)) ORDER BY j.id) FILTER(WHERE state='unknown_maintenance_disposed'),'[]'::jsonb) FROM public.capacity_dispatch_jobs j WHERE realm=$1 AND environment=$2 AND domain=$3 AND dimension=$4`, policy.Metadata.Namespace, p.Environment, p.Domain, p.Dimension).Scan(&unknowns)
	if err != nil {
		return out, err
	}
	var historical []struct {
		ID uuid.UUID `json:"id"`
	}
	if json.Unmarshal(unknowns, &historical) != nil {
		return out, ErrCapacityConflict
	}
	for _, job := range historical {
		if _, e := readCapacityDispatchUnknownMaintenanceDisposition(ctx, tx, job.ID); e != nil {
			return out, ErrCapacityConflict
		}
	}
	err = tx.QueryRowContext(ctx, `SELECT COALESCE(jsonb_agg(jsonb_build_object('challenge',row_to_json(c),'return',row_to_json(r)) ORDER BY c.id),'[]'::jsonb) FROM public.capacity_guest_notify_canary_challenges c LEFT JOIN public.capacity_guest_notify_canary_returns r ON r.challenge_id=c.id WHERE c.preregistration_id=$1`, req.PreregistrationID).Scan(&canaries)
	if err != nil {
		return out, err
	}
	x := created.Settlement
	candidate := model.CapacityOriginalCreateDispositionCandidate{OriginalPolicy: policy, Binding: b, Preregistration: stored.pre, Receipt: guestMutationReceiptV2(created), Request: model.CapacityOriginalCreateDispositionReadRequest{OriginalAuxiliaryInventoryComplete: x.AuxiliaryInventoryComplete, Profile: b.ProfileName, Slot: 1, GrantID: created.Grant.GrantID, AttemptID: created.AttemptID, RequestSHA256: created.Grant.RequestSHA256, ExpectedResourceID: x.ResourceID, ExpectedResourceCreatedAt: x.ResourceCreatedAt, OriginalAdapterSourceCommit: b.OriginalProviderSourceCommit, AuxiliaryResources: append([]model.CapacityMutationAuxiliaryResource{}, x.AuxiliaryResources...)}, OriginalGrantSHA256: capacity.BusinessCreationSHA256(raw), OriginalPreregistrationSHA256: capacity.GuestRetirementSHA(stored.pre), OriginalBindingSHA256: capacity.GuestRetirementSHA(stored.binding), OriginalSettlementSHA256: capacity.GuestRetirementSHA(x), Generation: current.Generation, FencingToken: req.FencingToken}
	if !x.AuxiliaryInventoryComplete {
		candidate.Request.OriginalCreateActionID = x.ActionID
	}
	if candidate.Request.AuxiliaryResources == nil {
		candidate.Request.AuxiliaryResources = []model.CapacityMutationAuxiliaryResource{}
	}
	if id == "" {
		out.record = FailedServingGuestDisposal{Schema: failedServingSchema, Stage: "quarantined", Namespace: policy.Metadata.Namespace, Environment: p.Environment, Domain: p.Domain, Dimension: p.Dimension, PreregistrationID: req.PreregistrationID, OriginalIntentWire: append([]byte(nil), out.intentWire...), OriginalIntentSHA256: req.IntentSHA256, Candidate: candidate, Workflow: workflow, InstallationSHA256: capacity.GuestRetirementSHA(installed), EnrollmentSHA256: capacity.GuestRetirementSHA(receipt.Enrollment), HistoricalAcceptedReadCount: reads, HistoricalPromotedCount: promoted, HistoricalUnknowns: unknowns, HistoricalCanaries: canaries, OriginalSlotSHA256: capacity.GuestRetirementSHA(slot), BusinessEffectsPreserved: true}
		out.record.CurrentStableEventSHA256 = stableEventSHA
	} else {
		r := out.record
		if r.CurrentStableEventSHA256 != stableEventSHA {
			return out, ErrCapacityConflict
		}
		if capacity.GuestRetirementSHA(candidate) != capacity.GuestRetirementSHA(r.Candidate) || capacity.GuestRetirementSHA(workflow) != capacity.GuestRetirementSHA(r.Workflow) || r.InstallationSHA256 != capacity.GuestRetirementSHA(installed) || r.EnrollmentSHA256 != capacity.GuestRetirementSHA(receipt.Enrollment) || r.QuarantineSlotSHA256 != capacity.GuestRetirementSHA(slot) || r.HistoricalAcceptedReadCount != reads || r.HistoricalPromotedCount != promoted || failedServingJSONSHA(r.HistoricalUnknowns) != failedServingJSONSHA(unknowns) || failedServingJSONSHA(r.HistoricalCanaries) != failedServingJSONSHA(canaries) {
			return out, ErrCapacityConflict
		}
	}
	out.policy, out.spec, out.slot = policy, p, slot
	return out, nil
}

func (s CapacityStore) BeginFailedServingGuestQuarantine(ctx context.Context, req model.CapacityFailedServingGuestDisposalRequest, issuer string) (*FailedServingGuestOwner, error) {
	if s.DB == nil || ctx == nil || ctx.Err() != nil || !failedServingIssuer(issuer) || !failedServingRequestValid(req) {
		return nil, ErrCapacityConflict
	}
	deadline, ok := ctx.Deadline()
	if !ok || !time.Now().Before(deadline) {
		return nil, ErrCapacityConflict
	}
	actualSource := failedServingCurrentSource()
	if !originalDispositionHex(actualSource, 40) {
		return nil, ErrCapacityConflict
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	snap, err := failedServingSnapshotTx(ctx, tx, req, "")
	if err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return &FailedServingGuestOwner{db: s.DB, ctx: ctx, deadline: deadline, started: time.Now().UTC(), mode: "request", issuer: issuer, actualCoreSource: actualSource, request: req, preID: req.PreregistrationID, snapshot: snap, snapshotSHA: failedServingSnapshotSHA(snap)}, nil
}

func failedServingOwnerConsume(ctx context.Context, db *sql.DB, o *FailedServingGuestOwner, mode string) bool {
	return o != nil && o.db == db && ctx == o.ctx && ctx.Err() == nil && time.Now().Before(o.deadline) && o.mode == mode && o.used.CompareAndSwap(false, true)
}

func failedServingInventory(policy model.Manifest, p model.CapacityPolicySpec, inv model.CapacityVMFleetInventory, want int, resourceID, birth string) (model.CapacitySnapshot, error) {
	snapshot, err := capacity.GuestReconcileSnapshot(policy, p, inv, time.Now().UTC())
	if err != nil || snapshot.Units != want || len(inv.MissingSlots) != 8-want {
		return snapshot, ErrCapacityConflict
	}
	seen := map[int]bool{}
	for _, slot := range inv.MissingSlots {
		if slot < 1 || slot > 8 || seen[slot] {
			return snapshot, ErrCapacityConflict
		}
		seen[slot] = true
	}
	if want == 1 {
		if seen[1] || len(inv.Members) != 1 || inv.Members[0].Slot != 1 || inv.Members[0].Server.ID != resourceID || inv.Members[0].Server.CreatedAt != birth {
			return snapshot, ErrCapacityConflict
		}
		seen[1] = true
	}
	if len(seen) != 8 {
		return snapshot, ErrCapacityConflict
	}
	return snapshot, nil
}

// The raw PostgreSQL JSONB text CAS retains every original field. The new
// current record is an operational quarantine, not a rewritten old event.
func persistFailedServingIntentTx(ctx context.Context, tx *sql.Tx, oldWire []byte, next model.CapacityIntent, receipt string) ([]byte, error) {
	raw, err := json.Marshal(next)
	if err != nil {
		return nil, err
	}
	var actual []byte
	err = tx.QueryRowContext(ctx, `UPDATE public.capacity_intents SET intent=$5::jsonb,updated_at=clock_timestamp() WHERE namespace=$1 AND environment=$2 AND domain=$3 AND dimension=$4 AND intent::text=$6 RETURNING intent::text`, next.Namespace, next.Environment, next.Domain, next.Dimension, string(raw), string(oldWire)).Scan(&actual)
	if err != nil {
		return nil, ErrCapacityConflict
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO public.capacity_intent_events(namespace,environment,domain,dimension,generation,fencing_token,phase,receipt_ref) VALUES($1,$2,$3,$4,$5,$6,$7,$8)`, next.Namespace, next.Environment, next.Domain, next.Dimension, next.Generation, next.FencingToken, next.Phase, receipt)
	return actual, err
}

func (s CapacityStore) CompleteFailedServingGuestQuarantine(ctx context.Context, o *FailedServingGuestOwner, inventory model.CapacityVMFleetInventory) (FailedServingGuestDisposal, error) {
	var out FailedServingGuestDisposal
	if !failedServingOwnerConsume(ctx, s.DB, o, "request") {
		return out, ErrCapacityConflict
	}
	returnedAt := time.Now().UTC()
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return out, err
	}
	defer tx.Rollback()
	snap, err := failedServingSnapshotTx(ctx, tx, o.request, "")
	if err != nil || failedServingSnapshotSHA(snap) != o.snapshotSHA {
		return out, ErrCapacityConflict
	}
	if _, err = failedServingInventory(snap.policy, snap.spec, inventory, 1, snap.record.Candidate.Request.ExpectedResourceID, snap.record.Candidate.Request.ExpectedResourceCreatedAt); err != nil {
		return out, err
	}
	out = snap.record
	out.ID = uuid.NewString()
	out.RecordID = out.ID
	out.Issuer = o.issuer
	out.ActualCoreSource = o.actualCoreSource
	out.RecordedAt = snap.now.UTC()
	out.Inventory = &inventory
	out.OriginalReadStartedAt = o.started
	out.OriginalReadReturnedAt = returnedAt
	next := snap.intent
	next.FencingToken++
	next.Phase = FailedServingGuestQuarantinedPhase
	next.Decision.ExecutionPermitted = false
	next.LeaseOwner = ""
	next.LeaseExecutorID = ""
	next.LeaseExpiresAt = nil
	next.UpdatedAt = snap.now.UTC()
	next.FailedServingDisposal = &model.CapacityFailedServingDisposal{ID: out.ID, PreregistrationID: out.PreregistrationID, OriginalIntentSHA256: out.OriginalIntentSHA256, Stage: "quarantined"}
	slot := snap.slot
	slot.FailedServingDisposalID = out.ID
	if err = saveMutationSlot(ctx, tx, out.Namespace, snap.spec, out.Candidate.Binding, 1, slot); err != nil {
		return out, err
	}
	out.QuarantineSlotSHA256 = capacity.GuestRetirementSHA(slot)
	quarantineWire, err := persistFailedServingIntentTx(ctx, tx, snap.intentWire, next, "failed-serving-quarantine:"+out.ID)
	if err != nil {
		return out, err
	}
	out.QuarantineIntentSHA256 = capacity.BusinessCreationSHA256(quarantineWire)
	if err = insertFailedServingTx(ctx, tx, out); err != nil {
		return out, err
	}
	if ctx.Err() != nil || !time.Now().Before(o.deadline) {
		return out, ErrCapacityConflict
	}
	return out, tx.Commit()
}

func (s CapacityStore) BeginFailedServingGuestObservation(ctx context.Context, preID, id, issuer, mode string) (*FailedServingGuestOwner, error) {
	if s.DB == nil || ctx == nil || ctx.Err() != nil || !validCapacityExecutor(preID) || !validCapacityExecutor(id) || !failedServingIssuer(issuer) || mode != "off" && mode != "absence" {
		return nil, ErrCapacityConflict
	}
	deadline, ok := ctx.Deadline()
	if !ok || !time.Now().Before(deadline) {
		return nil, ErrCapacityConflict
	}
	actualSource := failedServingCurrentSource()
	if !originalDispositionHex(actualSource, 40) {
		return nil, ErrCapacityConflict
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	r, err := loadFailedServingTx(ctx, tx, id, "quarantined")
	if err != nil || r.PreregistrationID != preID {
		return nil, ErrCapacityConflict
	}
	var original model.CapacityIntent
	if decodeFailedServingIntent(r.OriginalIntentWire, &original) != nil || capacity.BusinessCreationSHA256(r.OriginalIntentWire) != r.OriginalIntentSHA256 {
		return nil, ErrCapacityConflict
	}
	req := model.CapacityFailedServingGuestDisposalRequest{PreregistrationID: preID, PolicyID: original.PolicyID.String(), PolicyChecksum: original.PolicyChecksum, Generation: original.Generation, FencingToken: original.FencingToken, IntentSHA256: r.OriginalIntentSHA256}
	snap, err := failedServingSnapshotTx(ctx, tx, req, id)
	if err != nil {
		return nil, err
	}
	if mode == "off" {
		if _, existingErr := loadFailedServingTx(ctx, tx, id, "quiescent"); !errors.Is(existingErr, sql.ErrNoRows) {
			return nil, ErrCapacityConflict
		}
	}
	if mode == "absence" {
		if _, err = loadFailedServingTx(ctx, tx, id, "quiescent"); err != nil {
			return nil, ErrCapacityConflict
		}
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return &FailedServingGuestOwner{db: s.DB, ctx: ctx, deadline: deadline, started: time.Now().UTC(), mode: mode, issuer: issuer, actualCoreSource: actualSource, request: req, preID: preID, admissionID: id, snapshot: snap, snapshotSHA: failedServingSnapshotSHA(snap)}, nil
}

func (s CapacityStore) CompleteFailedServingGuestNativeOff(ctx context.Context, o *FailedServingGuestOwner, plan model.CapacityVMFleetPlan) (FailedServingGuestDisposal, error) {
	var out FailedServingGuestDisposal
	if !failedServingOwnerConsume(ctx, s.DB, o, "off") {
		return out, ErrCapacityConflict
	}
	returnedAt := time.Now().UTC()
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return out, err
	}
	defer tx.Rollback()
	snap, err := failedServingSnapshotTx(ctx, tx, o.request, o.admissionID)
	if err != nil || failedServingSnapshotSHA(snap) != o.snapshotSHA {
		return out, ErrCapacityConflict
	}
	if err = capacity.GuestRetirementV2NativeOffPlanContent(snap.spec, snap.record.Candidate.Binding, plan, snap.record.Candidate.Receipt); err != nil {
		return out, err
	}
	out = snap.record
	out.RecordID = uuid.NewString()
	out.Stage = "quiescent"
	out.Issuer = o.issuer
	out.ActualCoreSource = o.actualCoreSource
	out.RecordedAt = snap.now.UTC()
	out.Inventory = nil
	out.NativeOff = &plan
	out.OriginalReadStartedAt = o.started
	out.OriginalReadReturnedAt = returnedAt
	if err = insertFailedServingTx(ctx, tx, out); err != nil {
		return out, err
	}
	if ctx.Err() != nil || !time.Now().Before(o.deadline) {
		return out, ErrCapacityConflict
	}
	return out, tx.Commit()
}

func (s CapacityStore) CompleteFailedServingGuestAbsence(ctx context.Context, o *FailedServingGuestOwner, observed model.CapacityOriginalCreateDispositionObservation, inventory model.CapacityVMFleetInventory) (FailedServingGuestDisposal, error) {
	var out FailedServingGuestDisposal
	if !failedServingOwnerConsume(ctx, s.DB, o, "absence") {
		return out, ErrCapacityConflict
	}
	returnedAt := time.Now().UTC()
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return out, err
	}
	defer tx.Rollback()
	snap, err := failedServingSnapshotTx(ctx, tx, o.request, o.admissionID)
	if err != nil || failedServingSnapshotSHA(snap) != o.snapshotSHA {
		return out, ErrCapacityConflict
	}
	off, err := loadFailedServingTx(ctx, tx, o.admissionID, "quiescent")
	if err != nil {
		return out, ErrCapacityConflict
	}
	if err = validateEnrolledFailedOriginalObservation(snap.record.Candidate, observed, o.started, time.Now().UTC(), 30*time.Second); err != nil {
		return out, err
	}
	snapshot, err := failedServingInventory(snap.policy, snap.spec, inventory, 0, "", "")
	if err != nil {
		return out, err
	}
	out = snap.record
	out.RecordID = uuid.NewString()
	out.Stage = "terminal"
	out.Issuer = o.issuer
	out.ActualCoreSource = o.actualCoreSource
	out.RecordedAt = snap.now.UTC()
	out.Inventory = &inventory
	out.Absence = &observed
	out.OriginalReadStartedAt = o.started
	out.OriginalReadReturnedAt = returnedAt
	out.NativeOffRecordID = off.RecordID
	slot := snap.slot
	slot.ResourceID = ""
	slot.Tombstone = true
	slot.ObservedAt = snap.now.UTC()
	slot.ReceiptRef = "failed-serving-native-absence:" + out.ID + ":" + capacity.GuestRetirementSHA(observed)
	if err = saveMutationSlot(ctx, tx, out.Namespace, snap.spec, out.Candidate.Binding, 1, slot); err != nil {
		return out, err
	}
	next := snap.intent
	marker := *next.FailedServingDisposal
	marker.Stage = "terminal"
	next.FailedServingDisposal = &marker
	next.Phase = FailedServingGuestDisposedPhase
	next.Decision.Action = "hold"
	next.Decision.Reason = "failed_serving_native_absence_observed_floor_deficit"
	next.Decision.Units = 0
	next.Decision.ExecutionPermitted = false
	next.Assessment = model.CapacityAssessment{Snapshot: snapshot}
	next.UpdatedAt = snap.now.UTC()
	next.LeaseOwner = ""
	next.LeaseExecutorID = ""
	next.LeaseExpiresAt = nil
	terminalWire, err := persistFailedServingIntentTx(ctx, tx, snap.intentWire, next, "failed-serving-native-absence:"+out.ID)
	if err != nil {
		return out, err
	}
	out.TerminalIntentSHA256 = capacity.BusinessCreationSHA256(terminalWire)
	if err = insertFailedServingTx(ctx, tx, out); err != nil {
		return out, err
	}
	if ctx.Err() != nil || !time.Now().Before(o.deadline) {
		return out, ErrCapacityConflict
	}
	return out, tx.Commit()
}

func (s CapacityStore) ReadFailedServingGuestDisposals(ctx context.Context, preID string) ([]FailedServingGuestDisposal, error) {
	if s.DB == nil || !validCapacityExecutor(preID) {
		return nil, ErrCapacityConflict
	}
	rows, err := s.DB.QueryContext(ctx, `SELECT original_wire,record_sha256 FROM public.capacity_guest_failed_serving_disposals WHERE preregistration_id=$1 ORDER BY recorded_at,row_id`, preID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []FailedServingGuestDisposal{}
	for rows.Next() {
		var raw []byte
		var sha string
		var r FailedServingGuestDisposal
		if rows.Scan(&raw, &sha) != nil || capacity.BusinessCreationSHA256(raw) != sha || decodeFailedServingDisposal(raw, &r) != nil || r.Schema != failedServingSchema || r.PreregistrationID != preID || !originalDispositionHex(r.ActualCoreSource, 40) || !r.BusinessEffectsPreserved || r.CoreOrGuestNativeWriteSent || r.GuestWriterDrainClaimed {
			return nil, ErrCapacityConflict
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func failedServingQuarantineBlocks(intent *model.CapacityIntent) bool {
	return intent != nil && (intent.Phase == FailedServingGuestQuarantinedPhase || intent.FailedServingDisposal != nil && intent.FailedServingDisposal.Stage != "terminal")
}

func (s CapacityStore) FailedServingGuestDisposalWaiting(ctx context.Context, policy model.Manifest) (FailedServingGuestDisposal, bool, error) {
	var out FailedServingGuestDisposal
	p, err := parseCapacityPolicy(policy)
	if err != nil || s.DB == nil {
		return out, false, ErrCapacityConflict
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return out, false, err
	}
	defer tx.Rollback()
	if err = lockMutationScope(ctx, tx, policy.Metadata.Namespace, p); err != nil {
		return out, false, err
	}
	current, err := loadCapacityIntent(ctx, tx, policy.Metadata.Namespace, p, true)
	if errors.Is(err, sql.ErrNoRows) {
		return out, false, nil
	}
	if err != nil {
		return out, false, err
	}
	if !failedServingQuarantineBlocks(&current) {
		return out, false, nil
	}
	if current.FailedServingDisposal == nil {
		return out, false, ErrCapacityConflict
	}
	out, err = loadFailedServingTx(ctx, tx, current.FailedServingDisposal.ID, "quarantined")
	if err != nil || out.PreregistrationID != current.FailedServingDisposal.PreregistrationID {
		return out, false, ErrCapacityConflict
	}
	return out, true, nil
}
