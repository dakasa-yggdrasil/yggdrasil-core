//go:build recoveryfixture && !nativequalification

package repository

import (
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

// Continue the existing root through the ordinary source APIs. Provider and
// process facts below are independently declared signed fixture operands, not
// an SDK/Guest execution. No original or successful new row is seeded by SQL.
func failedServingCompleteOrdinaryReplacement(t *testing.T, f *failedServingFixture, claimed model.CapacityIntent) {
	t.Helper()
	before := f.preserved(t)
	base := f.store.WithOriginalGuestReconcile(f.workflow, f.steps[0], capacity.CurrentGuestCoreSource(), "provision", "", f.inventory(t, true), model.CapacityMetricRangeObservation{})
	parent := failedServingContext(t)
	deadline, err := base.OriginalGuestReconcileLeaseDeadline(parent, f.policy, claimed.Generation, claimed.FencingToken, claimed.LeaseOwner)
	if err != nil {
		t.Fatal("new original lease deadline", err)
	}
	ctx, stop := context.WithDeadline(parent, deadline)
	defer stop()
	b := f.p.MutationBindings[0]
	member := f.p.GuestRetirementBinding.Members[0]
	provision := base.WithOriginalGuestProvisioning(f.steps[1], capacity.CurrentGuestCoreSource(), capacity.BusinessCreationSHA256([]byte(uuid.NewString())))
	grant, err := provision.IssueMutation(ctx, f.policy, claimed.Generation, claimed.FencingToken, claimed.LeaseOwner, model.CapacityMutationIssue{BindingName: b.Name, DesiredSpec: failedServingWire(t, b.Slots[0].DesiredSpec)})
	if err != nil || grant.GrantID == f.pre.OriginalCreateGrantID || grant.State != "issued" || grant.CompensationOf != "" {
		t.Fatal("ordinary new create grant", err)
	}
	var preWire []byte
	if err = f.db.QueryRowContext(ctx, `SELECT original_wire FROM public.capacity_vm_provisioning_preregistrations WHERE create_grant_id=$1`, grant.GrantID).Scan(&preWire); err != nil {
		t.Fatal(err)
	}
	var pre model.CapacityGuestOriginalProvisioningPreregistration
	if capacity.DecodeGuestLifecycle(preWire, &pre) != nil || pre.PreregistrationID == f.pre.PreregistrationID || pre.NonceSHA256 == f.pre.NonceSHA256 || pre.Generation != claimed.Generation || pre.Fence != claimed.FencingToken || pre.LeaseOwner != claimed.LeaseOwner || pre.ExecutorID != f.store.ExecutorID {
		t.Fatal("new original preregistration was not independently issued")
	}
	nonce := uuid.NewString()
	redemption := mutationRedeem(grant, nonce)
	permit, err := provision.RedeemMutation(ctx, b.AdapterPrincipalID, redemption)
	if err != nil || permit.Mode != "write_once" {
		t.Fatal("new original redemption", permit.Mode, err)
	}
	created := time.Now().UTC().Truncate(time.Microsecond)
	resourceID, action, schema, status := "987654321", "88", "hetzner_original_create_return_v1", 201
	aux := []model.CapacityMutationAuxiliaryResource{{Kind: "ssh_key", ID: "902", RequiresAbsence: true}}
	if f.p.Profiles[0].Provider == "aws" {
		resourceID, action, schema, status = "i-00000000000000456", uuid.NewString(), "aws_original_run_instances_return_v1", 200
		aux = []model.CapacityMutationAuxiliaryResource{{Kind: "aws_ebs_volume", ID: "vol-00000000000000456", RequiresAbsence: true}, {Kind: "aws_network_interface", ID: "eni-00000000000000456", RequiresAbsence: true}}
	}
	at := created.Format(time.RFC3339Nano)
	settle := model.CapacityMutationSettleRequest{GrantID: grant.GrantID, AttemptID: redemption.AttemptID, RequestSHA256: grant.RequestSHA256, Outcome: "accepted", TransportCompleted: true, ResourceID: resourceID, ResourceCreatedAt: at, ActionID: action, NextActionIDs: []string{}, ObservedAt: at, AuxiliaryInventoryComplete: true, AuxiliaryResources: aux}
	if f.p.Profiles[0].Provider == "aws" {
		settle.AuxiliaryInventoryComplete = false
		settle.AuxiliaryResources = []model.CapacityMutationAuxiliaryResource{}
	}
	settle.OriginalProviderCreateReturn = &model.CapacityOriginalProviderCreateReturn{Schema: schema, Provider: f.p.Profiles[0].Provider, AdapterSourceCommit: b.OriginalProviderSourceCommit, GrantID: grant.GrantID, AttemptID: redemption.AttemptID, RequestSHA256: grant.RequestSHA256, ResourceID: resourceID, ResourceCreatedAt: at, ActionID: action, NextActionIDs: []string{}, CalledAt: at, ReturnedAt: at, ContextDeadline: grant.ExpiresAt.UTC().Format(time.RFC3339Nano), ResponseStatus: status, ResponseBodySHA256: capacity.BusinessCreationSHA256([]byte("declared-new-original-native-return")), ResponseBytes: int64(len("declared-new-original-native-return"))}
	if _, err = provision.SettleMutation(ctx, b.AdapterPrincipalID, nonce, settle); err != nil {
		t.Fatal("new owning original settlement", err)
	}
	observed := time.Now().UTC()
	identity := *f.reg.Result.ProductionClock.Authority.CreateWitness.ProviderNativeIdentity
	identity.ResourceID, identity.ResourceCreatedAt, identity.ObservedAt = resourceID, at, observed
	proof := model.CapacityMutationProof{GrantID: grant.GrantID, BindingName: b.Name, Slot: 1, RequestSHA256: grant.RequestSHA256, ResourceID: resourceID, ResourceCreatedAt: at, ObservedCreationGrantID: grant.GrantID, OwnerVerified: true, SpecVerified: true, ReceiptRef: "declared-source-new-original-native-read", ObservedAt: observed, ProviderNativeIdentity: &identity}
	if f.p.Profiles[0].Provider == "aws" {
		proof.AWSInstanceLifecycle = &model.CapacityAWSInstanceLifecycle{Schema: "aws_original_request_and_instance_status_v1", RequestID: action, EC2State: "running", SystemStatus: "ok", InstanceStatus: "ok", ObservedAt: observed}
	} else {
		proof.ActionIDs = []string{action}
		proof.ActionsTerminal = true
		proof.ActionsSuccessful = true
	}
	witness, err := provision.RecordGuestCreateWitness(ctx, pre.PreregistrationID, proof, failedServingKey('c'))
	if err != nil || witness.Tuple.ResourceID != resourceID || witness.Tuple.CreatedAt != at {
		t.Fatal("new source-issued create witness", err)
	}
	boot := uuid.NewString()
	authorityCtx, cancel := context.WithTimeout(ctx, 4*time.Second)
	authority, err := provision.GuestOriginalProfileAuthorityV2(authorityCtx, member.ProvisionerClientPrincipal, pre.PreregistrationID, member.Name, 1, pre.ProfileManifestSHA256, resourceID, boot, capacity.BusinessCreationSHA256([]byte(uuid.NewString())), failedServingKey('c'))
	cancel()
	if err != nil || !reflect.DeepEqual(authority.CreateWitness, witness) || authority.Preregistration.PreregistrationID != pre.PreregistrationID {
		t.Fatal("new source-owned profile authority", err)
	}
	registration := failedServingFreshRegistration(t, f, authority)
	failedServingWaitFixtureInstant(t, registration.EnrollmentStatement.IssuedAt)
	receipt, err := provision.RegisterOriginalGuest(ctx, member.ProvisionerClientPrincipal, registration, failedServingKey('c'), failedServingKey('i'))
	if err != nil || receipt.PreregistrationID == f.receipt.PreregistrationID || capacity.GuestRetirementSHA(receipt.Enrollment) == capacity.GuestRetirementSHA(f.receipt.Enrollment) {
		t.Fatal("new registered enrollment", err)
	}
	if receipt.Enrollment.Statement.Tuple.ResourceID != resourceID || receipt.Enrollment.Statement.Tuple.CreatedAt != at || receipt.Enrollment.Statement.Actor.BootID != boot || receipt.Enrollment.Statement.Runtime.BootID != boot || boot == f.receipt.Enrollment.Statement.Actor.BootID || receipt.Enrollment.Statement.Writers[0].Lifetime.BootID != boot {
		t.Fatal("new enrollment reused an old physical/process lifetime")
	}
	clock := registration.Result.ProductionClock
	installedAt := time.Now().UTC().Add(time.Millisecond)
	confirmation := model.CapacityGuestOriginalInstallationConfirmation{Schema: capacity.GuestInstallationV2Schema, PreregistrationID: pre.PreregistrationID, OriginalReceiptSHA256: capacity.GuestRetirementSHA(receipt), EnrollmentSHA256: capacity.GuestRetirementSHA(receipt.Enrollment), InstalledAt: installedAt.Add(time.Millisecond), AdmittedAt: installedAt.Add(2 * time.Millisecond), ProductionClock: &model.CapacityGuestProductionInstallationClockV2{Schema: capacity.GuestInstallationClockV2Schema, OriginalProvisioningClockSHA256: capacity.GuestRetirementSHA(*clock), OriginalReceiptReadStartedMonotonicNS: int64(111 * time.Second), OriginalReceiptReadReturnedMonotonicNS: int64(112 * time.Second), OriginalReceiptReadReturnedAt: installedAt, InstalledMonotonicNS: int64(113 * time.Second), AdmittedMonotonicNS: int64(114 * time.Second), OriginalConfirmationPreparedMonotonicNS: int64(115 * time.Second)}}
	confirmation.Signature, err = capacity.GuestLifecycleSignature(failedServingKey('p'), confirmation)
	if err != nil {
		t.Fatal(err)
	}
	failedServingWaitFixtureInstant(t, confirmation.AdmittedAt)
	if _, err = provision.RegisterOriginalGuestInstallation(ctx, member.ProvisionerClientPrincipal, confirmation); err != nil {
		t.Fatal("new original installation", err)
	}
	// The terminal marker still protects this tombstone until the NEW confirmed
	// creation replaces it through the ordinary locked native-slot owner.
	var marker string
	if err = f.db.QueryRowContext(ctx, `SELECT slot_record->>'failed_serving_disposal_id' FROM public.capacity_resource_slots WHERE integration_instance_id=$1 AND scope_checksum=$2 AND profile_name=$3 AND slot=1`, b.IntegrationInstanceID, b.ScopeChecksum, b.ProfileName).Scan(&marker); err != nil || marker == "" {
		t.Fatal("terminal custody disappeared before replacement confirmation", err)
	}
	if _, err = provision.ConfirmMutation(ctx, f.policy, claimed.Generation, claimed.FencingToken, claimed.LeaseOwner, proof); err != nil {
		t.Fatal("new original native confirmation", err)
	}
	var slotWire []byte
	if err = f.db.QueryRowContext(ctx, `SELECT slot_record FROM public.capacity_resource_slots WHERE integration_instance_id=$1 AND scope_checksum=$2 AND profile_name=$3 AND slot=1`, b.IntegrationInstanceID, b.ScopeChecksum, b.ProfileName).Scan(&slotWire); err != nil {
		t.Fatal(err)
	}
	var slot capacityResourceSlot
	if json.Unmarshal(slotWire, &slot) != nil || slot.FailedServingDisposalID != "" || slot.ResourceID != resourceID || slot.ResourceCreatedAt != at || slot.Tombstone {
		t.Fatal("ordinary confirmation reused or erased the wrong lifetime")
	}
	inventory := capacity.RecoveryFixtureInventory(t, f.p, registration, time.Now().UTC())
	inventory.Members[0].Server.Status = "running"
	completeStep := failedServingReplacementStep(t, f, "complete-original-provision")
	complete := f.store.WithOriginalGuestReconcile(f.workflow, completeStep, capacity.CurrentGuestCoreSource(), "provision", "", inventory, failedServingReplacementCoverage(f.p, time.Now().UTC())).WithOriginalGuestNotifyCanary(completeStep, capacity.CurrentGuestCoreSource())
	failedServingReplacementCanary(t, ctx, complete, f.policy, f.p, claimed, pre, receipt)
	for _, phase := range []string{"prepared", "canary", "promoted"} {
		inventory = capacity.RecoveryFixtureInventory(t, f.p, registration, time.Now().UTC())
		inventory.Members[0].Server.Status = "running"
		snapshot, e := capacity.GuestReconcileSnapshot(f.policy, f.p, inventory, time.Now().UTC())
		if e != nil {
			t.Fatal(e)
		}
		complete = complete.WithOriginalGuestReconcile(f.workflow, completeStep, capacity.CurrentGuestCoreSource(), "provision", "", inventory, failedServingReplacementCoverage(f.p, time.Now().UTC()))
		claimed, err = complete.AdvanceOriginalGuest(ctx, f.policy, claimed.Generation, claimed.FencingToken, claimed.LeaseOwner, phase, model.CapacityAssessment{Snapshot: snapshot})
		if err != nil || claimed.Phase != phase {
			t.Fatal("ordinary new Guest phase", phase, err)
		}
	}
	if claimed.LeaseOwner != "" || claimed.LeaseExpiresAt != nil || claimed.FailedServingDisposal != nil || claimed.Assessment.Snapshot.Units != 1 || claimed.Generation <= f.pre.Generation || claimed.FencingToken <= f.pre.Fence {
		t.Fatal("new promotion reused the failed original authority")
	}
	if !reflect.DeepEqual(f.preserved(t), before) {
		t.Fatal("ordinary replacement changed any serving/disposal original")
	}
}

// Build an unpersisted NEW provider-specific itinerary from the already typed
// fixture shape. The original declared wall-time intervals and BOOTTIME
// samples, source limits and validators remain unchanged. Actual
// Core preregistration, witness and signed profile authority are used verbatim.
func failedServingFreshRegistration(t *testing.T, f *failedServingFixture, a model.CapacityGuestOriginalProfileAuthorityV2) model.CapacityGuestOriginalProvisioningRegistration {
	t.Helper()
	var shape any
	if json.Unmarshal(failedServingWire(t, f.reg), &shape) != nil {
		t.Fatal("new fixture itinerary")
	}
	old := f.reg.Result.ProductionClock.OriginalReadStartedAt
	start := a.ObservedAt.Add(time.Millisecond)
	invocation := strings.ReplaceAll(uuid.NewString(), "-", "")
	processNonce := capacity.BusinessCreationSHA256([]byte(uuid.NewString()))
	var fresh func(any) any
	fresh = func(v any) any {
		switch x := v.(type) {
		case string:
			if at, err := time.Parse(time.RFC3339Nano, x); err == nil {
				return start.Add(at.Sub(old)).Format(time.RFC3339Nano)
			}
		case []any:
			for i := range x {
				x[i] = fresh(x[i])
			}
		case map[string]any:
			for key, value := range x {
				switch key {
				case "boot_id", "guest_boot_id", "invocation_nonce":
					x[key] = a.GuestBootID
				case "service_invocation_id", "invocation_id":
					x[key] = invocation
				case "process_nonce_sha256":
					x[key] = processNonce
				default:
					x[key] = fresh(value)
				}
			}
		}
		return v
	}
	var reg model.CapacityGuestOriginalProvisioningRegistration
	if json.Unmarshal(failedServingWire(t, fresh(shape)), &reg) != nil {
		t.Fatal("new original shape decode")
	}
	r := &reg.Result
	c := r.ProductionClock
	c.Authority = a
	var err error
	c.AcceptedExpiresMonotonicNS, err = capacity.GuestConservativeProductionExpiry(c.AcquisitionExpiresMonotonicNS, c.OriginalReadStartedMonotonicNS, a.RemainingNS)
	if err != nil {
		t.Fatal(err)
	}
	w := a.CreateWitness
	r.OriginalCreateGrantID, r.OriginalCreateAttemptID, r.OriginalCreateSettlementSHA256 = w.OriginalCreateGrantID, w.OriginalCreateAttemptID, w.OriginalCreateSettlementSHA256
	r.PreregistrationID, r.PreregistrationNonceSHA256, r.Tuple = w.PreregistrationID, w.PreregistrationNonceSHA256, w.Tuple
	r.BootstrapOriginalJournal.Tuple = w.Tuple
	r.BootstrapOriginalObservation.Journal = r.BootstrapOriginalJournal
	r.BootstrapOriginalObservation.JournalSHA256 = capacity.GuestRetirementSHA(r.BootstrapOriginalJournal)
	r.WriterRosterSHA256 = capacity.GuestRetirementSHA(r.Writers)
	for i := range r.WriterPlacements {
		r.WriterPlacements[i].Writer = r.Writers[i]
		r.WriterPlacements[i].Census = r.ProtectedCensus
		r.WriterPlacements[i].RequestSHA256 = capacity.BusinessCreationSHA256([]byte(w.PreregistrationID + ":" + r.Writers[i].ID))
	}
	e := &reg.EnrollmentStatement
	e.Tuple, e.Actor, e.Runtime, e.Writers, e.WriterRosterSHA256 = r.Tuple, r.Actor, r.Runtime, r.Writers, r.WriterRosterSHA256
	e.OriginalNativeResultSHA256, e.OriginalProvisioningClockSHA256 = capacity.GuestRetirementSHA(*r), capacity.GuestRetirementSHA(*c)
	reg.Signature = ""
	reg.Signature, err = capacity.GuestLifecycleSignature(failedServingKey('p'), reg)
	if err != nil {
		t.Fatal(err)
	}
	return reg
}

func failedServingWaitFixtureInstant(t *testing.T, at time.Time) {
	t.Helper()
	if delay := time.Until(at) + time.Millisecond; delay > 0 {
		if delay > 15*time.Second {
			t.Fatal("unbounded declared fixture wall itinerary")
		}
		time.Sleep(delay)
	}
}

func failedServingReplacementCoverage(p model.CapacityPolicySpec, now time.Time) model.CapacityMetricRangeObservation {
	b := p.GuestNotifyReconcileBinding.MemberCoverage
	value := 1.0
	return model.CapacityMetricRangeObservation{Operation: capacity.ObserveMetricRange, Binding: b.BindingName, BindingSHA256: b.BindingSHA256, EvaluatedAt: now, OK: true, Reason: "complete", CapacityEvidence: model.CapacityEvidence{Name: capacity.OriginalGuestMemberCoverageName, SourceIdentity: "production/notify/" + p.Profiles[0].Provider + "/reporting-members", Unit: "members", RequireData: true, Matched: true, DataState: "present", Value: &value, RangeMin: &value, RangeMax: &value, SourceSampledAt: now, WindowStart: now.Add(-30 * time.Second), WindowEnd: now, Samples: 7, CoverageComplete: true, MaxGapSeconds: 5}}
}

func failedServingReplacementStep(t *testing.T, f *failedServingFixture, id string) model.WorkflowStepSpec {
	t.Helper()
	for _, step := range f.steps {
		if step.ID == id {
			return step
		}
	}
	t.Fatal("missing exact source workflow step", id)
	return model.WorkflowStepSpec{}
}

func failedServingReplacementCanary(t *testing.T, ctx context.Context, store CapacityStore, policy model.Manifest, p model.CapacityPolicySpec, intent model.CapacityIntent, pre model.CapacityGuestOriginalProvisioningPreregistration, receipt model.CapacityGuestOriginalProvisioningReceipt) {
	t.Helper()
	probe := func(c model.CapacityGuestNotifyCanaryChallenge, publication *capacity.GuestNotifyPublicationReply) *capacity.GuestNotifyPublicationReply {
		c = capacity.RecoveryFixtureCanaryNonce(t, c, receipt.Enrollment)
		if err := store.FinalizeGuestNotifyCanaryNonce(ctx, policy, intent.Generation, intent.FencingToken, intent.LeaseOwner, c, failedServingHTTP(t, c.GuestNonce, time.Now().UTC())); err != nil {
			t.Fatal("new original canary nonce", err)
		}
		if err := store.ReserveGuestNotifyCanarySend(ctx, policy, intent.Generation, intent.FencingToken, intent.LeaseOwner, c); err != nil {
			t.Fatal("new original canary possible-send", err)
		}
		response, facts := capacity.RecoveryFixtureCanaryResponse(t, p, c, receipt.Enrollment, publication)
		returned := failedServingHTTP(t, response, response.OriginalReadStartedAt.Add(-time.Millisecond))
		failedServingWaitFixtureInstant(t, returned.DriverReturnedAt)
		if _, err := store.RecordGuestNotifyCanaryReturn(ctx, policy, intent.Generation, intent.FencingToken, intent.LeaseOwner, c, returned); err != nil {
			t.Fatal("new original accepted canary", err)
		}
		return facts
	}
	pub, err := store.IssueGuestNotifyCanaryPublication(ctx, policy, intent.Generation, intent.FencingToken, intent.LeaseOwner, pre.PreregistrationID, "initial_useful_membership", failedServingKey('c'))
	if err != nil {
		t.Fatal("new original publication", err)
	}
	facts := probe(pub, nil)
	read, err := store.IssueGuestNotifyCanaryRead(ctx, policy, intent.Generation, intent.FencingToken, intent.LeaseOwner, pre.PreregistrationID, "initial_useful_membership", pub.ChallengeID, failedServingKey('c'))
	if err != nil {
		t.Fatal("new original read", err)
	}
	probe(read, facts)
}
