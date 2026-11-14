package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"reflect"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

// A separate admission for an accepted, witnessed CREATE with an expired
// un-enrolled Guest expansion. It never rewrites the original failed run or ACK.
const WitnessedUnenrolledExpansionCleanupSchema = "witnessed_unenrolled_expansion_cleanup_v1"
const WitnessedUnenrolledExpansionCleanupMode = "witnessed_unenrolled_expansion_cleanup"

type WitnessedUnenrolledExpansionCleanup struct {
	Schema                      string    `json:"schema"`
	ID                          string    `json:"id"`
	GrantID                     string    `json:"grant_id"`
	ChildGrantID                string    `json:"child_grant_id"`
	JobID                       string    `json:"job_id"`
	RunID                       string    `json:"run_id"`
	PreregistrationID           string    `json:"preregistration_id"`
	Issuer                      string    `json:"issuer"`
	Namespace                   string    `json:"namespace"`
	Environment                 string    `json:"environment"`
	Domain                      string    `json:"domain"`
	Dimension                   string    `json:"dimension"`
	PolicyID                    string    `json:"policy_id"`
	PolicyChecksum              string    `json:"policy_checksum"`
	WorkflowID                  string    `json:"workflow_id"`
	WorkflowChecksum            string    `json:"workflow_checksum"`
	BindingName                 string    `json:"binding_name"`
	ProfileName                 string    `json:"profile_name"`
	Slot                        int       `json:"slot"`
	ResourceID                  string    `json:"resource_id"`
	ResourceCreatedAt           string    `json:"resource_created_at"`
	OriginalGrantSHA256         string    `json:"original_grant_sha256"`
	OriginalSDKReturnSHA256     string    `json:"original_SDK_return_sha256"`
	OriginalPreregSHA256        string    `json:"original_preregistration_sha256"`
	OriginalDispatchSHA256      string    `json:"original_dispatch_sha256"`
	OriginalRunSHA256           string    `json:"original_run_sha256"`
	OriginalIntentSHA256        string    `json:"original_intent_sha256"`
	OriginalIntentWire          []byte    `json:"original_intent_wire"`
	OriginalGeneration          int64     `json:"original_generation"`
	OriginalFencingToken        int64     `json:"original_fencing_token"`
	OriginalDeadline            time.Time `json:"original_deadline"`
	OriginalLeaseExpiresAt      time.Time `json:"original_lease_expires_at"`
	OriginalAuxiliaryKnown      bool      `json:"original_auxiliary_inventory_complete"`
	SurvivorRosterWire          []byte    `json:"survivor_roster_wire"`
	SurvivorRosterSHA256        string    `json:"survivor_roster_sha256"`
	SurvivorCount               int       `json:"survivor_count"`
	OriginalWitnessSHA256       string    `json:"original_create_witness_sha256"`
	OriginalWitnessWire         []byte    `json:"original_create_witness_wire"`
	OriginalGrantWire           []byte    `json:"original_grant_wire"`
	OriginalSDKReturnWire       []byte    `json:"original_SDK_return_wire"`
	OriginalPreregistrationWire []byte    `json:"original_preregistration_wire"`
	OriginalDispatchWire        []byte    `json:"original_dispatch_wire"`
	OriginalRunWire             []byte    `json:"original_run_wire"`
	RecordedAt                  time.Time `json:"recorded_at"`
}

type WitnessedUnenrolledExpansionCleanupEvent struct {
	Schema         string          `json:"schema"`
	CleanupID      string          `json:"cleanup_id"`
	Sequence       int64           `json:"sequence"`
	Stage          string          `json:"stage"`
	RunID          string          `json:"run_id,omitempty"`
	Generation     int64           `json:"generation"`
	FencingToken   int64           `json:"fencing_token"`
	LeaseOwner     string          `json:"lease_owner,omitempty"`
	ExecutorID     string          `json:"executor_id,omitempty"`
	LeaseExpiresAt *time.Time      `json:"lease_expires_at,omitempty"`
	ChildGrantID   string          `json:"child_grant_id"`
	Evidence       json.RawMessage `json:"evidence,omitempty"`
	RecordedAt     time.Time       `json:"recorded_at"`
}

type witnessedExpansionSnapshot struct {
	record                                                                        capacityMutationRecord
	witness                                                                       model.CapacityGuestOriginalCreateWitness
	witnessWire                                                                   []byte
	pre                                                                           model.CapacityGuestOriginalProvisioningPreregistration
	policy                                                                        model.Manifest
	spec                                                                          model.CapacityPolicySpec
	intent                                                                        model.CapacityIntent
	grantWire, sdkWire, preregWire, dispatchWire, runWire, rosterWire, intentWire []byte
	job                                                                           CapacityDispatchJob
	now                                                                           time.Time
}

func witnessedCleanupError(detail string) error {
	return fmt.Errorf("%w: witnessed unenrolled expansion %s", ErrCapacityConflict, detail)
}

// HTTP supplies only the two original UUIDs and its authenticated issuer.
// All epochs, identities, original UNKNOWN/no-ACK and native targets come from locked DB records.
// The admission itself performs no provider call. Only the linked new owner may
// obtain one ordinary DELETE grant after fresh native and survivor evidence.
func (s CapacityStore) RequestWitnessedUnenrolledExpansionCleanup(ctx context.Context, grantID, jobID, issuer string) (WitnessedUnenrolledExpansionCleanup, error) {
	var out WitnessedUnenrolledExpansionCleanup
	if s.DB == nil || ctx == nil || ctx.Err() != nil || !validCapacityExecutor(grantID) || !validCapacityExecutor(jobID) || !validCleanupIssuer(issuer) {
		return out, ErrCapacityMutationAuthorization
	}
	tx, err := beginWitnessedExpansionTx(ctx, s.DB)
	if err != nil {
		return out, err
	}
	defer tx.Rollback()
	x, err := s.witnessedExpansionSnapshotTx(ctx, tx, grantID, jobID)
	if err != nil {
		return out, err
	}
	var exists bool
	if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM public.capacity_witnessed_unenrolled_expansion_cleanups WHERE grant_id=$1)`, grantID).Scan(&exists); err != nil || exists {
		return out, witnessedCleanupError("admission already exists; exact GET only")
	}
	sdk := x.sdkWire
	out = WitnessedUnenrolledExpansionCleanup{Schema: WitnessedUnenrolledExpansionCleanupSchema, ID: uuid.NewString(), GrantID: grantID, ChildGrantID: uuid.NewString(), JobID: jobID, RunID: x.job.RunID.String(), PreregistrationID: x.pre.PreregistrationID, Issuer: issuer, Namespace: x.policy.Metadata.Namespace, Environment: x.spec.Environment, Domain: x.spec.Domain, Dimension: x.spec.Dimension, PolicyID: x.policy.ID.String(), PolicyChecksum: x.policy.Checksum, WorkflowID: x.record.WorkflowID.String(), WorkflowChecksum: x.pre.WorkflowChecksum, BindingName: x.record.Binding.Name, ProfileName: x.record.Binding.ProfileName, Slot: x.record.Grant.Slot, ResourceID: x.record.Settlement.ResourceID, ResourceCreatedAt: x.record.Settlement.ResourceCreatedAt, OriginalGrantSHA256: originalDispositionDigest(x.grantWire), OriginalSDKReturnSHA256: originalDispositionDigest(sdk), OriginalPreregSHA256: originalDispositionDigest(x.preregWire), OriginalDispatchSHA256: originalDispositionDigest(x.dispatchWire), OriginalRunSHA256: originalDispositionDigest(x.runWire), OriginalIntentSHA256: originalDispositionDigest(x.intentWire), OriginalIntentWire: append([]byte(nil), x.intentWire...), OriginalGeneration: x.intent.Generation, OriginalFencingToken: x.intent.FencingToken, OriginalDeadline: x.pre.OriginalDeadline, OriginalLeaseExpiresAt: *x.intent.LeaseExpiresAt, OriginalAuxiliaryKnown: x.record.Settlement.AuxiliaryInventoryComplete, SurvivorRosterSHA256: originalDispositionDigest(x.rosterWire), SurvivorRosterWire: append([]byte(nil), x.rosterWire...), SurvivorCount: x.record.Grant.Slot - 1, OriginalWitnessSHA256: originalDispositionDigest(x.witnessWire), OriginalWitnessWire: append([]byte(nil), x.witnessWire...), OriginalGrantWire: append([]byte(nil), x.grantWire...), OriginalSDKReturnWire: append([]byte(nil), x.sdkWire...), OriginalPreregistrationWire: append([]byte(nil), x.preregWire...), OriginalDispatchWire: append([]byte(nil), x.dispatchWire...), OriginalRunWire: append([]byte(nil), x.runWire...), RecordedAt: x.now}
	raw, err := json.Marshal(out)
	if err != nil {
		return out, err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO public.capacity_witnessed_unenrolled_expansion_cleanups(id,grant_id,child_grant_id,job_id,preregistration_id,namespace,environment,domain,dimension,policy_id,policy_checksum,slot,admission_sha256,original_wire,original_record,recorded_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15::jsonb,$16)`, out.ID, out.GrantID, out.ChildGrantID, out.JobID, out.PreregistrationID, out.Namespace, out.Environment, out.Domain, out.Dimension, out.PolicyID, out.PolicyChecksum, out.Slot, originalDispositionDigest(raw), raw, string(raw), out.RecordedAt)
	if err != nil {
		return WitnessedUnenrolledExpansionCleanup{}, err
	}
	e := WitnessedUnenrolledExpansionCleanupEvent{Schema: WitnessedUnenrolledExpansionCleanupSchema, CleanupID: out.ID, Sequence: 1, Stage: "requested", Generation: out.OriginalGeneration, FencingToken: out.OriginalFencingToken, ChildGrantID: out.ChildGrantID, RecordedAt: x.now}
	if err = s.appendWitnessedExpansionEventTx(ctx, tx, e); err != nil {
		return WitnessedUnenrolledExpansionCleanup{}, err
	}
	next := x.intent
	next.WitnessedUnenrolledExpansionCleanupID = out.ID
	next.Decision.Reason = WitnessedUnenrolledExpansionCleanupMode
	next.UpdatedAt = x.now
	if err = persistRetirementForwardIntentTx(ctx, tx, x.intent, next, "witnessed-unenrolled-expansion:"+out.ID+":requested"); err != nil {
		return WitnessedUnenrolledExpansionCleanup{}, err
	}
	if err = tx.Commit(); err != nil {
		return WitnessedUnenrolledExpansionCleanup{}, err
	}
	return out, nil
}

func (s CapacityStore) ReadWitnessedUnenrolledExpansionCleanup(ctx context.Context, grantID string) (WitnessedUnenrolledExpansionCleanup, []WitnessedUnenrolledExpansionCleanupEvent, error) {
	var out WitnessedUnenrolledExpansionCleanup
	if s.DB == nil || !validCapacityExecutor(grantID) {
		return out, nil, ErrCapacityConflict
	}
	var raw []byte
	var digest string
	if err := s.DB.QueryRowContext(ctx, `SELECT original_wire,admission_sha256 FROM public.capacity_witnessed_unenrolled_expansion_cleanups WHERE grant_id=$1`, grantID).Scan(&raw, &digest); err != nil {
		return out, nil, err
	}
	if originalDispositionDigest(raw) != digest || capacity.DecodeGuestLifecycle(raw, &out) != nil || out.GrantID != grantID || out.Schema != WitnessedUnenrolledExpansionCleanupSchema {
		return out, nil, ErrCapacityConflict
	}
	rows, err := s.DB.QueryContext(ctx, `SELECT original_wire,event_sha256 FROM public.capacity_witnessed_unenrolled_expansion_cleanup_events WHERE cleanup_id=$1 ORDER BY sequence`, out.ID)
	if err != nil {
		return out, nil, err
	}
	defer rows.Close()
	var events []WitnessedUnenrolledExpansionCleanupEvent
	for rows.Next() {
		var e WitnessedUnenrolledExpansionCleanupEvent
		if rows.Scan(&raw, &digest) != nil || originalDispositionDigest(raw) != digest || json.Unmarshal(raw, &e) != nil || e.CleanupID != out.ID || e.Sequence != int64(len(events)+1) {
			return out, nil, ErrCapacityConflict
		}
		events = append(events, e)
	}
	if err = rows.Err(); err != nil {
		return out, nil, err
	}
	return out, events, nil
}

func (s CapacityStore) appendWitnessedExpansionEventTx(ctx context.Context, tx *sql.Tx, e WitnessedUnenrolledExpansionCleanupEvent) error {
	raw, err := json.Marshal(e)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO public.capacity_witnessed_unenrolled_expansion_cleanup_events(cleanup_id,sequence,stage,run_id,child_grant_id,event_sha256,original_wire,original_record,recorded_at) VALUES($1,$2,$3,NULLIF($4,'')::uuid,$5,$6,$7,$8::jsonb,$9)`, e.CleanupID, e.Sequence, e.Stage, e.RunID, e.ChildGrantID, originalDispositionDigest(raw), raw, string(raw), e.RecordedAt)
	return err
}

// Admission is deliberately stricter than a failure label. The complete
// SDK/grant/witness/preregistration/scope, actual failed UNKNOWN and single un-enrolled tail are
// joined while holding the same scope and native-slot locks as registration.
func (s CapacityStore) witnessedExpansionSnapshotTx(ctx context.Context, tx *sql.Tx, grantID, jobID string) (witnessedExpansionSnapshot, error) {
	var x witnessedExpansionSnapshot
	var locator []byte
	var ns, env, domain, dimension string
	if err := tx.QueryRowContext(ctx, `SELECT namespace,environment,domain,dimension,grant_record FROM public.capacity_mutation_grants WHERE id=$1`, grantID).Scan(&ns, &env, &domain, &dimension, &locator); err != nil {
		return x, err
	}
	if json.Unmarshal(locator, &x.record) != nil {
		return x, ErrCapacityConflict
	}
	p := model.CapacityPolicySpec{Environment: env, Domain: domain, Dimension: dimension}
	if err := lockMutationScope(ctx, tx, ns, p); err != nil {
		return x, err
	}
	if err := lockNativeMutationSlot(ctx, tx, x.record.Binding, x.record.Grant.Slot); err != nil {
		return x, err
	}
	var state string
	var pointer bool
	if err := tx.QueryRowContext(ctx, `SELECT grant_record,(grant_record#>'{settlement,original_provider_create_return}')::text,state,num_nonnulls(original_disposition_id,failed_original_disposition_id,native_denied_disposition_id,enrolled_failed_disposition_id)>0 FROM public.capacity_mutation_grants WHERE id=$1 FOR UPDATE`, grantID).Scan(&x.grantWire, &x.sdkWire, &state, &pointer); err != nil {
		return x, err
	}
	if pointer || state != "settled" || !reflect.DeepEqual(locator, x.grantWire) || json.Unmarshal(x.grantWire, &x.record) != nil {
		return x, ErrCapacityConflict
	}
	r := x.record
	g, b := r.Grant, r.Binding
	settlement := r.Settlement
	if g.GrantID != grantID || g.State != "settled" || g.CompensationOf != "" || g.Capability != b.EnsureCapability || g.Slot != 2 || settlement == nil || settlement.Outcome != "accepted" || !settlement.TransportCompleted || settlement.OriginalProviderCreateReturn == nil {
		return x, ErrCapacityConflict
	}
	original := settlement.OriginalProviderCreateReturn
	if original.Provider != "hetzner" || original.AdapterSourceCommit != failedOriginalHetznerCreator || original.Schema != "hetzner_original_create_return_v1" || original.ResponseStatus != 201 || !settlement.AuxiliaryInventoryComplete || len(settlement.AuxiliaryResources) < 1 || len(settlement.AuxiliaryResources) > 16 || original.ResourceID != settlement.ResourceID || original.ResourceCreatedAt != settlement.ResourceCreatedAt || original.ActionID != settlement.ActionID || original.GrantID != grantID || original.AttemptID != r.AttemptID || original.RequestSHA256 != g.RequestSHA256 || settlement.GrantID != grantID || settlement.AttemptID != r.AttemptID || settlement.RequestSHA256 != g.RequestSHA256 || b.OriginalProviderSourceCommit != original.AdapterSourceCommit {
		return x, ErrCapacityConflict
	}
	var preID string
	if err := tx.QueryRowContext(ctx, `SELECT id::text,original_wire FROM public.capacity_vm_provisioning_preregistrations WHERE create_grant_id=$1 FOR SHARE`, grantID).Scan(&preID, &x.preregWire); err != nil {
		return x, err
	}
	stored, err := loadGuestOriginalTx(ctx, tx, preID)
	if err != nil {
		return x, err
	}
	x.pre = stored.pre
	if x.pre.BindingName != stored.member.Name || x.pre.OriginalCreateGrantID != grantID || x.pre.Slot != g.Slot || x.pre.PolicyID != r.PolicyID.String() || x.pre.PolicyChecksum != r.PolicyChecksum || x.pre.WorkflowID != r.WorkflowID.String() || x.pre.Generation != r.Generation || x.pre.Fence != r.FencingToken || x.pre.LeaseOwner != r.LeaseOwner || x.pre.ExecutorID != r.ExecutorID || x.pre.OriginalCreateRequestSHA256 != g.RequestSHA256 || stored.binding.MutationBindingName != b.Name {
		return x, ErrCapacityConflict
	}
	x.policy.ID = r.PolicyID
	x.policy.Kind = "capacity_policy"
	var specRaw []byte
	var active bool
	if err = tx.QueryRowContext(ctx, `SELECT namespace,name,checksum,spec,active FROM public.manifests WHERE id=$1 AND kind='capacity_policy' FOR SHARE`, r.PolicyID).Scan(&x.policy.Metadata.Namespace, &x.policy.Metadata.Name, &x.policy.Checksum, &specRaw, &active); err != nil {
		return x, err
	}
	x.policy.Spec = specRaw
	var latestID, latestSHA string
	var latestActive bool
	if err = tx.QueryRowContext(ctx, `SELECT id::text,checksum,active FROM public.manifests WHERE kind='capacity_policy' AND namespace=$1 AND name=$2 ORDER BY version DESC,id DESC LIMIT 1 FOR SHARE`, ns, x.policy.Metadata.Name).Scan(&latestID, &latestSHA, &latestActive); err != nil || !latestActive || latestID != r.PolicyID.String() || latestSHA != r.PolicyChecksum {
		return x, ErrCapacityConflict
	}
	if !active || x.policy.Metadata.Namespace != ns || x.policy.Checksum != r.PolicyChecksum || json.Unmarshal(specRaw, &x.spec) != nil || x.spec.Environment != env || x.spec.Domain != domain || x.spec.Dimension != dimension || x.spec.Floor != 1 || x.spec.GuestRetirementBinding == nil || !reflect.DeepEqual(stored.binding, *x.spec.GuestRetirementBinding) {
		return x, ErrCapacityConflict
	}
	currentBinding, bindingErr := capacity.VMObservationBinding(x.spec, b.Name)
	if bindingErr != nil || !reflect.DeepEqual(currentBinding, b) {
		return x, ErrCapacityConflict
	}
	if err = tx.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&x.now); err != nil {
		return x, err
	}
	x.now = x.now.UTC()
	x.intent, err = loadCapacityIntent(ctx, tx, ns, p, true)
	if err != nil {
		return x, err
	}
	if err = tx.QueryRowContext(ctx, `SELECT intent::text FROM public.capacity_intents WHERE namespace=$1 AND environment=$2 AND domain=$3 AND dimension=$4`, ns, env, domain, dimension).Scan(&x.intentWire); err != nil {
		return x, err
	}
	if x.intent.PolicyID != r.PolicyID || x.intent.PolicyChecksum != r.PolicyChecksum || x.intent.Generation != r.Generation || x.intent.FencingToken != r.FencingToken || x.intent.Phase != "preparing" || x.intent.Decision.Action != "expand" || x.intent.Decision.Units != 2 || x.intent.WitnessedUnenrolledExpansionCleanupID != "" || x.intent.WitnessedExpansionTerminalReconcile != nil || x.intent.FailedUnwitnessedExpansionCleanupID != "" || x.intent.FailedExpansionTerminalReconcile != nil || x.intent.OriginalNotifyWindow != nil || x.intent.InstalledReadinessHandoff != nil || x.intent.RecoveryOnly || x.intent.FloorDegraded || x.intent.RetirementForward != nil || x.intent.FailedInstalledDisposal != nil || x.intent.FailedServingDisposal != nil || x.intent.InstalledGuestReconcile != nil || x.intent.LeaseExpiresAt == nil || !x.now.After(*x.intent.LeaseExpiresAt) || !x.now.After(x.pre.OriginalDeadline) || x.intent.BaselineSnapshot.Units != g.Slot-1 || x.intent.Assessment.Snapshot.Units != g.Slot-1 {
		return x, ErrCapacityConflict
	}
	// The old failed-original validator is a pure read of this exact failed
	// UNKNOWN dispatch/run and predicate29. Its caller's floor0 restriction is
	// not part of this shared validator; the new lane keeps the S1 floor.
	var failed failedOriginalDispositionSnapshot
	if err = loadFailedOriginalDispatch(ctx, tx, jobID, ns, x.spec, r, x.pre, x.now, &failed); err != nil {
		return x, err
	}
	x.job = failed.job
	j := x.job
	if err = tx.QueryRowContext(ctx, `SELECT to_jsonb(j)::text,to_jsonb(w)::text FROM public.capacity_dispatch_jobs j JOIN public.workflow_runs w ON w.id=j.run_id WHERE j.id=$1 AND j.return_status='failed' AND w.status='failed' AND w.finished_at=j.returned_at`, jobID).Scan(&x.dispatchWire, &x.runWire); err != nil {
		return x, err
	}
	if err = loadGuestWitnessTx(ctx, tx, &stored); err != nil {
		return x, err
	}
	x.witness = stored.witness
	if err = tx.QueryRowContext(ctx, `SELECT original_wire FROM public.capacity_guest_original_create_witnesses WHERE preregistration_id=$1 FOR SHARE`, preID).Scan(&x.witnessWire); err != nil {
		return x, err
	}
	w := x.witness
	profileChecksum := ""
	for _, slot := range b.Slots {
		if slot.Slot == g.Slot && slot.DesiredSpec != nil {
			profileChecksum = slot.DesiredSpec.ProfileChecksum
		}
	}
	returned, validationErr := capacity.ValidateOriginalHetznerCreateReturn(b, g, r.AttemptID, *settlement, x.pre.ReservedAt, w.ObservedAt)
	if validationErr != nil || !returned.Equal(w.OriginalCreateReturnedAt) || originalDispositionDigest(x.witnessWire) != capacity.GuestRetirementSHA(w) ||
		w.Schema != capacity.GuestCreateWitnessSchema || w.PreregistrationID != preID || w.BindingName != x.pre.BindingName || w.PreregistrationNonceSHA256 != x.pre.NonceSHA256 ||
		w.OriginalCreateGrantID != grantID || w.OriginalCreateAttemptID != r.AttemptID || w.OriginalCreateRequestSHA256 != g.RequestSHA256 ||
		w.OriginalCreateSettlementSHA256 != capacity.GuestRetirementSHA(*settlement) || w.ProfileManifestSHA256 != x.pre.ProfileManifestSHA256 || w.CoreSourceCommit != x.pre.CoreSourceCommit ||
		!w.OriginalDeadline.Equal(x.pre.OriginalDeadline) || w.Tuple.Provider != "hetzner" || w.Tuple.InstanceID != b.IntegrationInstanceID || w.Tuple.InstanceChecksum != b.IntegrationChecksum ||
		w.Tuple.TypeID != b.IntegrationTypeID || w.Tuple.TypeChecksum != b.IntegrationTypeChecksum || profileChecksum == "" || w.Tuple.ProfileChecksum != profileChecksum || w.Tuple.ScopeChecksum != b.ScopeChecksum || w.Tuple.Profile != b.ProfileName ||
		w.Tuple.Slot != 2 || w.Tuple.ResourceID != settlement.ResourceID || w.Tuple.CreatedAt != settlement.ResourceCreatedAt || w.ObservedAt.Before(w.OriginalCreateReturnedAt) || !w.ObservedAt.Before(x.pre.OriginalDeadline) ||
		capacity.ValidateGuestProviderNativeIdentity(w.ProviderNativeIdentity, w.Tuple, original.AdapterSourceCommit, w.ObservedAt) != nil {
		return x, ErrCapacityConflict
	}
	var blocked bool
	if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM public.capacity_vm_original_enrollments WHERE preregistration_id=$1) OR EXISTS(SELECT 1 FROM public.capacity_guest_original_installations WHERE preregistration_id=$1) OR EXISTS(SELECT 1 FROM public.capacity_vm_retirement_intents WHERE preregistration_id=$1) OR EXISTS(SELECT 1 FROM public.capacity_factory_original_grant_bindings WHERE grant_id=$2) OR EXISTS(SELECT 1 FROM public.capacity_mutation_grants WHERE grant_record#>>'{grant,compensation_of}'=$2::text) OR EXISTS(SELECT 1 FROM public.capacity_resource_slots WHERE integration_instance_id=$3 AND resource_id=$4) OR EXISTS(SELECT 1 FROM public.capacity_dispatch_jobs WHERE realm=$5 AND environment=$6 AND domain=$7 AND dimension=$8 AND id<>$9::uuid AND(state IN('queued','started','unknown') OR state='returned' AND finalization_ack_at IS NULL)) OR EXISTS(SELECT 1 FROM public.workflow_runs WHERE (workflow_id=$10::uuid OR(workflow_id IS NULL AND workflow_namespace=$11 AND workflow_name=$12 AND workflow_version=$13)) AND id<>$14::uuid AND(status NOT IN('succeeded','failed','cancelled') OR finished_at IS NULL))`, preID, grantID, b.IntegrationInstanceID, settlement.ResourceID, ns, env, domain, dimension, jobID, x.pre.WorkflowID, j.Workflow.Namespace, j.Workflow.Name, j.Workflow.Version, j.RunID).Scan(&blocked); err != nil {
		return x, err
	}
	if blocked {
		return x, ErrCapacityConflict
	}
	// Admit only this CREATE authority. Unrelated active scope work or any
	// second authority naming the same physical incarnation remains a barrier.
	if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM public.capacity_mutation_grants g WHERE g.id<>$1::uuid AND ((g.namespace=$2 AND g.environment=$3 AND g.domain=$4 AND g.dimension=$5 AND g.state IN('issued','redeemed','settled','compensating')) OR (g.grant_record#>>'{grant,expected_resource_id}'=$6 AND g.grant_record#>>'{grant,expected_resource_created_at}'=$7) OR (g.grant_record#>>'{settlement,resource_id}'=$6 AND g.grant_record#>>'{settlement,resource_created_at}'=$7)))`, grantID, ns, env, domain, dimension, settlement.ResourceID, settlement.ResourceCreatedAt).Scan(&blocked); err != nil {
		return x, err
	}
	if blocked {
		return x, ErrCapacityConflict
	}
	if x.pre.ReservedAt.Before(*j.StartedAt) || x.pre.ReservedAt.After(*j.ReturnedAt) {
		return x, ErrCapacityConflict
	}
	if _, err = capacity.ValidateOriginalHetznerCreateReturn(b, g, r.AttemptID, *settlement, x.pre.ReservedAt, x.witness.ObservedAt); err != nil {
		return x, err
	}
	if err = s.witnessedExpansionRosterTx(ctx, tx, &x); err != nil {
		return x, err
	}
	return x, nil
}

func (s CapacityStore) witnessedExpansionRosterTx(ctx context.Context, tx *sql.Tx, x *witnessedExpansionSnapshot) error {
	rows, err := tx.QueryContext(ctx, `SELECT slot,resource_id,slot_record::text FROM public.capacity_resource_slots WHERE namespace=$1 AND environment=$2 AND domain=$3 AND dimension=$4 AND resource_id<>'' ORDER BY slot FOR SHARE`, x.policy.Metadata.Namespace, x.spec.Environment, x.spec.Domain, x.spec.Dimension)
	if err != nil {
		return err
	}
	defer rows.Close()
	var wires []json.RawMessage
	expected := 1
	for rows.Next() {
		var slot int
		var id string
		var raw []byte
		var record capacityResourceSlot
		if rows.Scan(&slot, &id, &raw) != nil || json.Unmarshal(raw, &record) != nil || record.BindingName != x.record.Binding.Name || record.ProfileName != x.record.Binding.ProfileName || record.Tombstone || record.ResourceID != id || record.ResourceCreatedAt == "" || slot != expected || slot >= x.record.Grant.Slot || id == x.record.Settlement.ResourceID {
			return ErrCapacityConflict
		}
		wires = append(wires, raw)
		expected++
	}
	if err = rows.Err(); err != nil {
		return err
	}
	if expected != x.record.Grant.Slot {
		return ErrCapacityConflict
	}
	// Hash the exact ordered PostgreSQL JSON text, not a reserialized map.
	_ = wires
	return tx.QueryRowContext(ctx, `SELECT COALESCE(jsonb_agg(slot_record ORDER BY slot),'[]'::jsonb)::text FROM public.capacity_resource_slots WHERE namespace=$1 AND environment=$2 AND domain=$3 AND dimension=$4 AND resource_id<>''`, x.policy.Metadata.Namespace, x.spec.Environment, x.spec.Domain, x.spec.Dimension).Scan(&x.rosterWire)
}

// Whole PostgreSQL JSON frame renderings are pinned in UTC independently of
// the caller session. This changes no clock or deadline.
func beginWitnessedExpansionTx(ctx context.Context, db *sql.DB) (*sql.Tx, error) {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	if _, err = tx.ExecContext(ctx, `SET LOCAL TIME ZONE 'UTC'`); err != nil {
		tx.Rollback()
		return nil, err
	}
	return tx, nil
}
