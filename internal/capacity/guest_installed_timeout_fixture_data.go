//go:build recoveryfixture && !nativequalification

package capacity

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

// RecoveryFixtureInstalledSlotDuring signs declared CI operands inside the
// genuine dispatch window. Existing historical fixture constructors and their
// clocks remain untouched; no committed original is rewritten into eligibility.
func RecoveryFixtureInstalledSlotDuring(t *testing.T, slot int, reservedAt, deadline time.Time) (model.CapacityPolicySpec, model.CapacityGuestRetirementBinding, model.CapacityGuestOriginalProvisioningRegistration, model.CapacityGuestOriginalProvisioningReceipt, model.CapacityGuestOriginalInstallationConfirmation) {
	t.Helper()
	if !strings.HasSuffix(filepath.Base(os.Args[0]), ".test") || os.Getenv("CAPACITY_RECOVERY_FIXTURE_ONLY") != "true" || reservedAt.IsZero() || deadline.Sub(reservedAt) < 25*time.Second || deadline.Sub(reservedAt) > GuestProductionProvisioningLimit {
		t.Fatal("explicit test-only bounded original dispatch window required")
	}
	return installedTimeoutInstalledFixtureSlot(t, slot, reservedAt, deadline)
}

func installedTimeoutClockFixtureSlot(t *testing.T, offset time.Duration, selectedSlot int, reservedAt, deadline time.Time) (model.CapacityPolicySpec, model.CapacityGuestRetirementBinding, model.CapacityGuestProductionProvisioningClockV2, ed25519.PrivateKey, ed25519.PrivateKey) {
	t.Helper()
	var p model.CapacityPolicySpec
	if DecodeNativeCapacity(json.RawMessage(recoveryFixturePolicyRaw), &p) != nil || p.GuestRetirementBinding == nil {
		t.Fatal("source policy fixture")
	}
	b := *p.GuestRetirementBinding
	key := func(ch byte) ed25519.PrivateKey {
		return ed25519.NewKeyFromSeed([]byte(strings.Repeat(string(ch), 32)))
	}
	core, producer, issuer := key('c'), key('p'), key('i')
	public := func(k ed25519.PrivateKey) string {
		return base64.StdEncoding.EncodeToString(k.Public().(ed25519.PublicKey))
	}
	b.ProvisionerPublicKey, b.EnrollmentIssuerPublicKey = public(producer), public(issuer)
	p.GuestRetirementBinding = &b
	// The test recipients and approval map are deliberately synthetic.
	p.GuestNotifyCanaryBinding.RecipientSHA256 = BusinessRecipientSHA256([]string{"77777777-7777-4777-8777-777777777777", "88888888-8888-4888-8888-888888888888"})
	mutation := p.MutationBindings[0]
	if selectedSlot < 1 || selectedSlot > len(b.Members) {
		t.Fatal("fixture slot")
	}
	member := b.Members[selectedSlot-1]
	spec := mutation.Slots[selectedSlot-1].DesiredSpec
	uid := "10000000-0000-4000-8000-000000000001"
	policyID := "10000000-0000-4000-8000-000000000002"
	workflowID := "10000000-0000-4000-8000-000000000003"
	grantID := "10000000-0000-4000-8000-000000000004"
	attemptID := "10000000-0000-4000-8000-000000000005"
	leaseOwner := "10000000-0000-4000-8000-000000000006"
	executorID := "10000000-0000-4000-8000-000000000007"
	if selectedSlot != 1 {
		uid = fmt.Sprintf("10000000-0000-4000-8000-%012d", selectedSlot*100+1)
		grantID = fmt.Sprintf("10000000-0000-4000-8000-%012d", selectedSlot*100+4)
		attemptID = fmt.Sprintf("10000000-0000-4000-8000-%012d", selectedSlot*100+5)
	}
	now := reservedAt.UTC()
	pre := model.CapacityGuestOriginalProvisioningPreregistration{Schema: GuestPreregistrationSchema, PreregistrationID: uid, BindingName: member.Name, OriginalCreateGrantID: grantID, OriginalCreateRequestSHA256: mutation.Slots[selectedSlot-1].DesiredSpecSHA256, NonceSHA256: strings.Repeat("b", 64), ProfileManifestSHA256: b.ProfileManifestSHA256, PolicyID: policyID, PolicyChecksum: strings.Repeat("c", 64), WorkflowID: workflowID, WorkflowChecksum: strings.Repeat("d", 64), OriginalWorkflowStepID: b.ProfileManifest.OriginalProvisioningStepID, OriginalWorkflowStepTimeoutSeconds: 420, OriginalWorkflowContextDeadline: deadline, CoreSourceCommit: b.CoreAuthoritySourceCommit, Generation: 1, Fence: 1, LeaseOwner: leaseOwner, ExecutorID: executorID, Slot: 1, ReservedAt: now, OriginalDeadline: deadline}
	pre.Slot, pre.Generation, pre.Fence = selectedSlot, int64(selectedSlot), int64(selectedSlot)
	if selectedSlot != 1 {
		pre.NonceSHA256 = BusinessCreationSHA256([]byte("fixture-preregistration:" + uid))
		pre.OriginalCreateRequestSHA256 = mutation.Slots[selectedSlot-1].DesiredSpecSHA256
	}
	tuple := model.CapacityGuestNativeTuple{Provider: "hetzner", InstanceID: mutation.IntegrationInstanceID, InstanceChecksum: mutation.IntegrationChecksum, TypeID: mutation.IntegrationTypeID, TypeChecksum: mutation.IntegrationTypeChecksum, ScopeChecksum: mutation.ScopeChecksum, ProfileChecksum: spec.ProfileChecksum, Profile: mutation.ProfileName, Slot: 1, ResourceID: "123", CreatedAt: now.Format(time.RFC3339Nano)}
	tuple.Slot = selectedSlot
	tuple.ResourceID = fmt.Sprint(122 + selectedSlot)
	w := model.CapacityGuestOriginalCreateWitness{Schema: GuestCreateWitnessSchema, BindingName: pre.BindingName, PreregistrationID: uid, PreregistrationNonceSHA256: pre.NonceSHA256, OriginalCreateGrantID: grantID, OriginalCreateAttemptID: attemptID, OriginalCreateRequestSHA256: pre.OriginalCreateRequestSHA256, OriginalCreateSettlementSHA256: GuestRetirementSHA(RecoveryFixtureInstalledTimeoutSettlement(pre, mutation, tuple, attemptID)), ProfileManifestSHA256: b.ProfileManifestSHA256, BootstrapSHA256: GuestProfileBootstrapSHA(b.ProfileManifest, 1), CoreSourceCommit: b.CoreAuthoritySourceCommit, OriginalCreateReturnedAt: now.Add(time.Second), ObservedAt: now.Add(2 * time.Second), OriginalDeadline: pre.OriginalDeadline, Tuple: tuple}
	w.BootstrapSHA256 = GuestProfileBootstrapSHA(b.ProfileManifest, selectedSlot)
	w.ProviderNativeIdentity = &model.CapacityGuestProviderNativeIdentity{Schema: GuestProviderNativeIdentitySchema, Provider: "hetzner", ResourceID: tuple.ResourceID, ResourceCreatedAt: tuple.CreatedAt, Region: "us-east", Location: "ash", TypeID: "22", ImageID: "33", Hostname: "unit-guest", ObservedAt: w.ObservedAt, AdapterSourceCommit: mutation.OriginalProviderSourceCommit}
	w.Signature, _ = GuestLifecycleSignature(core, w)
	a := model.CapacityGuestOriginalProfileAuthorityV2{Schema: GuestProfileAuthorityV2Schema, BindingName: pre.BindingName, Slot: 1, GuestBootID: uid, RequestNonceSHA256: strings.Repeat("f", 64), Profile: b.ProfileManifest, Preregistration: pre, CreateWitness: w, RemainingNS: int64(deadline.Sub(now.Add(3 * time.Second))), ObservedAt: now.Add(3 * time.Second)}
	a.Slot = selectedSlot
	a.Signature, _ = GuestLifecycleSignature(core, a)
	guest := now.Add(offset)
	c := model.CapacityGuestProductionProvisioningClockV2{Schema: GuestProvisioningClockV2Schema, Authority: a, BootstrapOwnerPID: 123, BootstrapOwnerStartTicks: 456, AcquisitionStartedMonotonicNS: int64(100 * time.Second), AcquisitionExpiresMonotonicNS: int64(100*time.Second + deadline.Sub(now)), OriginalReadStartedAt: guest, OriginalReadReturnedAt: guest.Add(time.Second), OriginalReadStartedMonotonicNS: int64(101 * time.Second), OriginalReadReturnedMonotonicNS: int64(102 * time.Second), AcceptedExpiresMonotonicNS: int64(101*time.Second + deadline.Sub(now.Add(3*time.Second))), OriginalResultReturnedMonotonicNS: int64(110 * time.Second)}
	if err := GuestProductionProvisioningClockV2(p, b, member, c, public(core), now.Add(5*time.Second)); err != nil {
		t.Fatal("source-derived fixture clock", err)
	}
	return p, b, c, core, producer
}

func installedTimeoutRegistrationFixtureSlot(t *testing.T, offset time.Duration, slot int, reservedAt, deadline time.Time) (model.CapacityPolicySpec, model.CapacityGuestRetirementBinding, model.CapacityGuestOriginalProvisioningRegistration, ed25519.PrivateKey) {
	t.Helper()
	p, b, c, core, producer := installedTimeoutClockFixtureSlot(t, offset, slot, reservedAt, deadline)
	w, profile := c.Authority.CreateWitness, b.ProfileManifest
	guest := c.OriginalReadReturnedAt
	at := func(n int) time.Time { return guest.Add(time.Duration(n) * time.Second) }
	start, wait, prepared, code := at(2), at(3), at(4), 0
	j := model.CapacityGuestJournal{Schema: GuestBootstrapSchema, AdmissionProtocol: "original_guest_bootstrap_prestarter_v1", InvocationNonce: c.Authority.GuestBootID, State: "returned", BootID: c.Authority.GuestBootID, Tuple: w.Tuple, UserDataSHA256: w.BootstrapSHA256, PayloadSHA256: profile.BootstrapPayloadSHA256, OwnerSourceCommit: profile.BootstrapOwnerSourceCommit, OwnerBinarySHA256: profile.BootstrapOwnerBinarySHA256, OwnerPID: c.BootstrapOwnerPID, OwnerStartTicks: c.BootstrapOwnerStartTicks, ParentAncestry: []int{50}, UnitAtAdmission: model.CapacityGuestUnitObservation{InvocationID: strings.Repeat("1", 32), MainPID: 50, ExecMainPID: 50, StartMonotonic: 1}, PossibleStartAt: at(1), ChildPID: 124, ChildStartTicks: 125, StartedAt: &start, OriginalWaitReturnedAt: &wait, FinalRecordPreparedAt: &prepared, ExitCode: &code}
	o := model.CapacityGuestObservation{Schema: GuestBootstrapSchema, ReaderSourceCommit: profile.BootstrapOwnerSourceCommit, ReaderBinarySHA256: profile.BootstrapReaderBinarySHA256, ReaderPID: 200, ReaderStartTicks: 201, BootID: j.BootID, UserDataSHA256: w.BootstrapSHA256, Journal: j, JournalSHA256: GuestRetirementSHA(j), Unit: model.CapacityGuestUnitObservation{InvocationID: j.UnitAtAdmission.InvocationID, ExecMainPID: 50, ExecMainCode: 1, ExecMainStatus: 0, StartMonotonic: 1, ExitMonotonic: 2, ActiveState: "inactive", SubState: "dead", Result: "success"}, CloudInitStatus: "done", CloudInitFinalFinished: 1, ObservedAt: at(5)}
	life := func(pid int) model.CapacityGuestRetirementLifetime {
		return model.CapacityGuestRetirementLifetime{BootID: j.BootID, ProcessNonceSHA256: strings.Repeat("2", 64), PID: pid, StartTicks: uint64(pid), SourceCommit: profile.OwnerSourceCommit, BinarySHA256: profile.OwnerBinarySHA256, ServiceInvocationID: strings.Repeat("3", 32)}
	}
	actor, runtime, writer := life(300), life(301), model.CapacityGuestRetirementWriter{ID: profile.Writers[0].ID, Lifetime: life(302)}
	actor.SourceCommit, actor.BinarySHA256 = profile.ActorSourceCommit, profile.ActorBinarySHA256
	writer.Lifetime.SourceCommit, writer.Lifetime.BinarySHA256 = profile.Writers[0].SourceCommit, profile.Writers[0].BinarySHA256
	census := model.CapacityGuestRetirementProtectedCensus{Schema: "guest_retirement_protected_cgroup_v1", Scope: "fixed_protected_cgroup_v2", SourceCommit: runtime.SourceCommit, Processes: []model.CapacityGuestRetirementNativeProcess{{PID: writer.Lifetime.PID, StartTicks: writer.Lifetime.StartTicks}}, RawCensusSHA256: strings.Repeat("4", 64), ObservedAt: at(7)}
	op := model.CapacityGuestRetirementOperationReturn{StartedAt: at(6), PID: 400, StartTicks: 401, WaitReturnedAt: at(8), BodyJoined: true, CloseReturned: true, Outcome: "returned"}
	r := model.CapacityGuestOriginalProvisioningResult{Schema: GuestProvisioningV2Schema, BindingName: b.Members[0].Name, SourceClass: b.EvidenceClass, ProvisionerSourceCommit: b.ProvisionerSourceCommit, OriginalCreateGrantID: w.OriginalCreateGrantID, OriginalCreateAttemptID: w.OriginalCreateAttemptID, OriginalCreateSettlementSHA256: w.OriginalCreateSettlementSHA256, PreregistrationID: w.PreregistrationID, PreregistrationNonceSHA256: w.PreregistrationNonceSHA256, Tuple: w.Tuple, ProfileManifestSHA256: b.ProfileManifestSHA256, Actor: actor, Runtime: runtime, Writers: []model.CapacityGuestRetirementWriter{writer}, ProtectedCensus: census, PlacementOperation: op, BootstrapOriginalJournal: j, BootstrapOriginalObservation: o, OriginalReturnedAt: at(9), ProductionClock: &c}
	r.BindingName = b.Members[slot-1].Name
	// Allocate the anonymous wire entry, then explicitly populate every fact.
	if json.Unmarshal([]byte(`[{}]`), &r.WriterPlacements) != nil {
		t.Fatal("fixture allocation")
	}
	x := &r.WriterPlacements[0]
	x.Writer = writer
	x.DefinitionSHA256 = GuestRetirementSHA(profile.Writers[0])
	x.ProtectedCgroup = profile.ProtectedCgroup
	x.RequestSHA256 = strings.Repeat("5", 64)
	x.Operation = op
	x.Census = census
	x.OriginalReturnedAt = at(7)
	r.WriterRosterSHA256 = GuestRetirementSHA(r.Writers)
	obs := ed25519.NewKeyFromSeed([]byte(strings.Repeat("o", 32)))
	e := model.CapacityGuestRetirementEnrollmentStatement{Schema: GuestRetirementSchema, Purpose: GuestRetirementPurpose, BindingName: r.BindingName, SourceClass: r.SourceClass, ProvisionerSourceCommit: r.ProvisionerSourceCommit, OriginalNativeResultSHA256: GuestRetirementSHA(r), Tuple: r.Tuple, Actor: actor, Runtime: runtime, Writers: r.Writers, WriterRosterSHA256: r.WriterRosterSHA256, RuntimeCommandSHA256: profile.RuntimeClientCommandSHA256, PoweroffCommandSHA256: profile.PoweroffCommandSHA256, ObservationPublicKey: base64.StdEncoding.EncodeToString(obs.Public().(ed25519.PublicKey)), CoreIntentPublicKey: base64.StdEncoding.EncodeToString(core.Public().(ed25519.PublicKey)), CoreAuthoritySourceCommit: w.CoreSourceCommit, IssuedAt: at(10), OriginalProvisioningClockSHA256: GuestRetirementSHA(c)}
	reg := model.CapacityGuestOriginalProvisioningRegistration{Result: r, EnrollmentStatement: e}
	reg.Signature, _ = GuestLifecycleSignature(producer, reg)
	return p, b, reg, producer
}

func installedTimeoutInstalledFixtureSlot(t *testing.T, slot int, reservedAt, deadline time.Time) (model.CapacityPolicySpec, model.CapacityGuestRetirementBinding, model.CapacityGuestOriginalProvisioningRegistration, model.CapacityGuestOriginalProvisioningReceipt, model.CapacityGuestOriginalInstallationConfirmation) {
	t.Helper()
	p, b, reg, producer := installedTimeoutRegistrationFixtureSlot(t, 0, slot, reservedAt, deadline)
	clock := reg.Result.ProductionClock
	pre := clock.Authority.Preregistration
	issuer := ed25519.NewKeyFromSeed([]byte(strings.Repeat("i", 32)))
	enrollment := model.CapacityGuestRetirementEnrollment{Statement: reg.EnrollmentStatement}
	enrollment.Signature, _ = GuestLifecycleSignature(issuer, enrollment.Statement)
	receipt := model.CapacityGuestOriginalProvisioningReceipt{PreregistrationID: pre.PreregistrationID, OriginalProvisioningSHA256: GuestRetirementSHA(reg), RecordedAt: clock.Authority.ObservedAt.Add(20 * time.Second), Enrollment: enrollment}
	guest := reg.EnrollmentStatement.IssuedAt.Add(time.Second)
	ownerClock := &model.CapacityGuestProductionInstallationClockV2{Schema: GuestInstallationClockV2Schema, OriginalProvisioningClockSHA256: GuestRetirementSHA(*clock), OriginalReceiptReadStartedMonotonicNS: int64(111 * time.Second), OriginalReceiptReadReturnedMonotonicNS: int64(112 * time.Second), OriginalReceiptReadReturnedAt: guest, InstalledMonotonicNS: int64(113 * time.Second), AdmittedMonotonicNS: int64(114 * time.Second), OriginalConfirmationPreparedMonotonicNS: int64(115 * time.Second)}
	confirmation := model.CapacityGuestOriginalInstallationConfirmation{Schema: GuestInstallationV2Schema, PreregistrationID: pre.PreregistrationID, OriginalReceiptSHA256: GuestRetirementSHA(receipt), EnrollmentSHA256: GuestRetirementSHA(enrollment), InstalledAt: guest.Add(time.Second), AdmittedAt: guest.Add(2 * time.Second), ProductionClock: ownerClock}
	confirmation.Signature, _ = GuestLifecycleSignature(producer, confirmation)
	if err := GuestRetirementEnrollment(p, b, b.Members[slot-1], enrollment, receipt.RecordedAt); err != nil {
		t.Fatal("fixture enrollment", err)
	}
	if err := GuestOriginalRegistration(p, b, b.Members[slot-1], clock.Authority.CreateWitness, reg, receipt.RecordedAt); err != nil {
		t.Fatal("fixture registration", err)
	}
	if err := GuestOriginalInstallationV2(pre, receipt, confirmation, b.ProvisionerPublicKey, *clock, receipt.RecordedAt.Add(time.Second)); err != nil {
		t.Fatal("fixture installation", err)
	}
	return p, b, reg, receipt, confirmation
}

// RecoveryFixtureInstalled is available only in the explicit test build.

// RecoveryFixtureInstalledTimeoutSettlement is the same declared immutable
// provider original hashed by the witness and stored by the repository fixture.
func RecoveryFixtureInstalledTimeoutSettlement(pre model.CapacityGuestOriginalProvisioningPreregistration, binding model.CapacityMutationBinding, tuple model.CapacityGuestNativeTuple, attempt string) model.CapacityMutationSettleRequest {
	returned := pre.ReservedAt.Add(time.Second)
	action := "declared-create-" + pre.OriginalCreateGrantID
	original := &model.CapacityOriginalProviderCreateReturn{Schema: "hetzner_original_create_return_v1", Provider: "hetzner", AdapterSourceCommit: binding.OriginalProviderSourceCommit, GrantID: pre.OriginalCreateGrantID, AttemptID: attempt, RequestSHA256: pre.OriginalCreateRequestSHA256, ResourceID: tuple.ResourceID, ResourceCreatedAt: tuple.CreatedAt, ActionID: action, NextActionIDs: []string{}, CalledAt: pre.ReservedAt.Format(time.RFC3339Nano), ReturnedAt: returned.Format(time.RFC3339Nano), ContextDeadline: pre.OriginalDeadline.Format(time.RFC3339Nano), ResponseStatus: 201, ResponseBodySHA256: strings.Repeat("a", 64), ResponseBytes: 2}
	return model.CapacityMutationSettleRequest{GrantID: pre.OriginalCreateGrantID, AttemptID: attempt, RequestSHA256: pre.OriginalCreateRequestSHA256, Outcome: "accepted", TransportCompleted: true, ResourceID: tuple.ResourceID, ResourceCreatedAt: tuple.CreatedAt, ActionID: action, NextActionIDs: []string{}, ObservedAt: returned.Format(time.RFC3339Nano), AuxiliaryResources: []model.CapacityMutationAuxiliaryResource{{Kind: "ssh_key", ID: "declared-key-" + pre.PreregistrationID, RequiresAbsence: true}}, AuxiliaryInventoryComplete: true, OriginalProviderCreateReturn: original}
}
