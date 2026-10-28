//go:build recoveryfixture && !nativequalification

package capacity

import (
	"crypto/ed25519"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

//go:embed testdata/b509-notify-hetzner-production-contract.json
var recoveryFixturePolicyRaw []byte

// Test-only declared operands; never real provider, runtime or readiness proof.
func recoveryClockFixture(t *testing.T, offset time.Duration) (model.CapacityPolicySpec, model.CapacityGuestRetirementBinding, model.CapacityGuestProductionProvisioningClockV2, ed25519.PrivateKey, ed25519.PrivateKey) {
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
	member := b.Members[0]
	spec := mutation.Slots[0].DesiredSpec
	uid := "10000000-0000-4000-8000-000000000001"
	policyID := "10000000-0000-4000-8000-000000000002"
	workflowID := "10000000-0000-4000-8000-000000000003"
	grantID := "10000000-0000-4000-8000-000000000004"
	attemptID := "10000000-0000-4000-8000-000000000005"
	leaseOwner := "10000000-0000-4000-8000-000000000006"
	executorID := "10000000-0000-4000-8000-000000000007"
	now := time.Now().UTC().Add(-60 * time.Second).Truncate(time.Microsecond)
	pre := model.CapacityGuestOriginalProvisioningPreregistration{Schema: GuestPreregistrationSchema, PreregistrationID: uid, BindingName: member.Name, OriginalCreateGrantID: grantID, OriginalCreateRequestSHA256: strings.Repeat("a", 64), NonceSHA256: strings.Repeat("b", 64), ProfileManifestSHA256: b.ProfileManifestSHA256, PolicyID: policyID, PolicyChecksum: strings.Repeat("c", 64), WorkflowID: workflowID, WorkflowChecksum: strings.Repeat("d", 64), OriginalWorkflowStepID: b.ProfileManifest.OriginalProvisioningStepID, OriginalWorkflowStepTimeoutSeconds: 420, OriginalWorkflowContextDeadline: now.Add(420 * time.Second), CoreSourceCommit: b.CoreAuthoritySourceCommit, Generation: 1, Fence: 1, LeaseOwner: leaseOwner, ExecutorID: executorID, Slot: 1, ReservedAt: now, OriginalDeadline: now.Add(420 * time.Second)}
	tuple := model.CapacityGuestNativeTuple{Provider: "hetzner", InstanceID: mutation.IntegrationInstanceID, InstanceChecksum: mutation.IntegrationChecksum, TypeID: mutation.IntegrationTypeID, TypeChecksum: mutation.IntegrationTypeChecksum, ScopeChecksum: mutation.ScopeChecksum, ProfileChecksum: spec.ProfileChecksum, Profile: mutation.ProfileName, Slot: 1, ResourceID: "123", CreatedAt: now.Format(time.RFC3339Nano)}
	w := model.CapacityGuestOriginalCreateWitness{Schema: GuestCreateWitnessSchema, BindingName: pre.BindingName, PreregistrationID: uid, PreregistrationNonceSHA256: pre.NonceSHA256, OriginalCreateGrantID: grantID, OriginalCreateAttemptID: attemptID, OriginalCreateRequestSHA256: pre.OriginalCreateRequestSHA256, OriginalCreateSettlementSHA256: strings.Repeat("e", 64), ProfileManifestSHA256: b.ProfileManifestSHA256, BootstrapSHA256: GuestProfileBootstrapSHA(b.ProfileManifest, 1), CoreSourceCommit: b.CoreAuthoritySourceCommit, OriginalCreateReturnedAt: now.Add(time.Second), ObservedAt: now.Add(2 * time.Second), OriginalDeadline: pre.OriginalDeadline, Tuple: tuple}
	w.ProviderNativeIdentity = &model.CapacityGuestProviderNativeIdentity{Schema: GuestProviderNativeIdentitySchema, Provider: "hetzner", ResourceID: "123", ResourceCreatedAt: tuple.CreatedAt, Region: "us-east", Location: "ash", TypeID: "22", ImageID: "33", Hostname: "unit-guest", ObservedAt: w.ObservedAt, AdapterSourceCommit: mutation.OriginalProviderSourceCommit}
	w.Signature, _ = GuestLifecycleSignature(core, w)
	a := model.CapacityGuestOriginalProfileAuthorityV2{Schema: GuestProfileAuthorityV2Schema, BindingName: pre.BindingName, Slot: 1, GuestBootID: uid, RequestNonceSHA256: strings.Repeat("f", 64), Profile: b.ProfileManifest, Preregistration: pre, CreateWitness: w, RemainingNS: int64(417 * time.Second), ObservedAt: now.Add(3 * time.Second)}
	a.Signature, _ = GuestLifecycleSignature(core, a)
	guest := now.Add(offset)
	c := model.CapacityGuestProductionProvisioningClockV2{Schema: GuestProvisioningClockV2Schema, Authority: a, BootstrapOwnerPID: 123, BootstrapOwnerStartTicks: 456, AcquisitionStartedMonotonicNS: int64(100 * time.Second), AcquisitionExpiresMonotonicNS: int64(520 * time.Second), OriginalReadStartedAt: guest, OriginalReadReturnedAt: guest.Add(time.Second), OriginalReadStartedMonotonicNS: int64(101 * time.Second), OriginalReadReturnedMonotonicNS: int64(102 * time.Second), AcceptedExpiresMonotonicNS: int64(518 * time.Second), OriginalResultReturnedMonotonicNS: int64(110 * time.Second)}
	if err := GuestProductionProvisioningClockV2(p, b, member, c, public(core), now.Add(5*time.Second)); err != nil {
		t.Fatal("source-derived fixture clock", err)
	}
	return p, b, c, core, producer
}

func recoveryRegistrationFixture(t *testing.T, offset time.Duration) (model.CapacityPolicySpec, model.CapacityGuestRetirementBinding, model.CapacityGuestOriginalProvisioningRegistration, ed25519.PrivateKey) {
	t.Helper()
	p, b, c, core, producer := recoveryClockFixture(t, offset)
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

func recoveryInstalledFixture(t *testing.T) (model.CapacityPolicySpec, model.CapacityGuestRetirementBinding, model.CapacityGuestOriginalProvisioningRegistration, model.CapacityGuestOriginalProvisioningReceipt, model.CapacityGuestOriginalInstallationConfirmation) {
	t.Helper()
	p, b, reg, producer := recoveryRegistrationFixture(t, 0)
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
	if err := GuestRetirementEnrollment(p, b, b.Members[0], enrollment, receipt.RecordedAt); err != nil {
		t.Fatal("fixture enrollment", err)
	}
	if err := GuestOriginalRegistration(p, b, b.Members[0], clock.Authority.CreateWitness, reg, receipt.RecordedAt); err != nil {
		t.Fatal("fixture registration", err)
	}
	if err := GuestOriginalInstallationV2(pre, receipt, confirmation, b.ProvisionerPublicKey, *clock, receipt.RecordedAt.Add(time.Second)); err != nil {
		t.Fatal("fixture installation", err)
	}
	return p, b, reg, receipt, confirmation
}

// RecoveryFixtureInstalled is available only in the explicit test build.
func RecoveryFixtureInstalled(t *testing.T) (model.CapacityPolicySpec, model.CapacityGuestRetirementBinding, model.CapacityGuestOriginalProvisioningRegistration, model.CapacityGuestOriginalProvisioningReceipt, model.CapacityGuestOriginalInstallationConfirmation) {
	if !strings.HasSuffix(filepath.Base(os.Args[0]), ".test") || os.Getenv("CAPACITY_RECOVERY_FIXTURE_ONLY") != "true" {
		t.Fatal("recovery fixture is test-only")
	}
	return recoveryInstalledFixture(t)
}

// RecoveryFixtureInventory is a declared source-test operand, not a provider
// observation or approval. It cannot be compiled in the default build.
func RecoveryFixtureInventory(t *testing.T, p model.CapacityPolicySpec, reg model.CapacityGuestOriginalProvisioningRegistration, now time.Time) model.CapacityVMFleetInventory {
	if !strings.HasSuffix(filepath.Base(os.Args[0]), ".test") || os.Getenv("CAPACITY_RECOVERY_FIXTURE_ONLY") != "true" {
		t.Fatal("recovery fixture is test-only")
	}
	mutation := p.MutationBindings[0]
	slot := mutation.Slots[0]
	inv := model.CapacityVMFleetInventory{IntegrationInstanceID: mutation.IntegrationInstanceID, ScopeChecksum: mutation.ScopeChecksum, ProfileChecksum: slot.DesiredSpec.ProfileChecksum, AdmissionChecksum: slot.DesiredSpec.AdmissionChecksum, ProfileName: mutation.ProfileName, ProtectedSlots: mutation.ProtectedSlots, MaxSlots: mutation.MaxSlots, Complete: true, ObservationStartedAt: now.Add(-time.Second).Format(time.RFC3339Nano), ObservedAt: now.Format(time.RFC3339Nano), MissingSlots: []int{2, 3, 4, 5, 6, 7, 8}}
	server := model.CapacityVMServerObservation{CapacityVMNativeTuple: model.CapacityVMNativeTuple{ID: reg.Result.Tuple.ResourceID, CreatedAt: reg.Result.Tuple.CreatedAt}, Name: slot.DesiredSpec.NativeName, Status: "off", PhysicalSpecVerified: true, ObservedAt: inv.ObservedAt, Labels: map[string]string{"yggdrasil.io/owner": p.Owner, "yggdrasil.io/scope": vmLabelDigest(mutation.ScopeChecksum), "yggdrasil.io/spec": vmLabelDigest(slot.DesiredSpec.ProfileChecksum), "yggdrasil.io/profile": mutation.ProfileName, "yggdrasil.io/slot": "1"}}
	inv.Members = []model.CapacityVMFleetInventoryMember{{Slot: 1, Protected: 1 <= mutation.ProtectedSlots, DesiredSpec: *slot.DesiredSpec, RequestSHA256: slot.DesiredSpecSHA256, Server: server}}
	return inv
}

// RecoveryFixtureCausal creates declared signed operands for a previous
// publication and timeout. These are never provider or real Guest evidence.
func RecoveryFixtureCausal(t *testing.T, p model.CapacityPolicySpec, reg model.CapacityGuestOriginalProvisioningRegistration, receipt model.CapacityGuestOriginalProvisioningReceipt, oldFence uint64, leaseOwner string, at time.Time) (model.CapacityGuestNotifyCanaryChallenge, model.CapacityGuestNotifyCanaryChallenge, model.CapacityGuestNotifyCanaryRead, GuestOriginalHTTPReturn) {
	if !strings.HasSuffix(filepath.Base(os.Args[0]), ".test") || os.Getenv("CAPACITY_RECOVERY_FIXTURE_ONLY") != "true" {
		t.Fatal("recovery fixture is test-only")
	}
	pre := reg.Result.ProductionClock.Authority.Preregistration
	w := reg.Result.ProductionClock.Authority.CreateWitness
	e := receipt.Enrollment
	core := ed25519.NewKeyFromSeed([]byte(strings.Repeat("c", 32)))
	observer := ed25519.NewKeyFromSeed([]byte(strings.Repeat("o", 32)))
	readID := "20000000-0000-4000-8000-000000000001"
	pubID := "20000000-0000-4000-8000-000000000002"
	read := model.CapacityGuestNotifyCanaryChallenge{Schema: GuestNotifyCanaryChallengeSchema, Purpose: GuestNotifyCanaryReadPurpose, ChallengeID: readID, RecordChallengeID: pubID, NonceSHA256: strings.Repeat("a", 64), UsageClass: "initial_useful_membership", BindingName: e.Statement.BindingName, Slot: pre.Slot, PreregistrationID: pre.PreregistrationID, PreregistrationNonceSHA256: pre.NonceSHA256, OriginalRegistrationSHA256: receipt.OriginalProvisioningSHA256, OriginalCreateWitnessSHA256: GuestRetirementSHA(w), EnrollmentSHA256: GuestRetirementSHA(e), ProfileManifestSHA256: pre.ProfileManifestSHA256, Tuple: e.Statement.Tuple, PolicyID: pre.PolicyID, PolicyChecksum: pre.PolicyChecksum, WorkflowID: pre.WorkflowID, WorkflowChecksum: pre.WorkflowChecksum, Generation: uint64(pre.Generation), Fence: oldFence, LeaseOwner: leaseOwner, CoreSourceCommit: e.Statement.CoreAuthoritySourceCommit, IssuedAt: at.Add(500 * time.Millisecond), OriginalDeadline: at.Add(5 * time.Second)}
	publication := read
	publication.Schema = GuestNotifyCanaryPublicationChallengeSchema
	publication.Purpose = GuestNotifyCanaryPublicationPurpose
	publication.ChallengeID = pubID
	publication.NonceSHA256 = strings.Repeat("b", 64)
	publication.IssuedAt = at
	sign := func(c *model.CapacityGuestNotifyCanaryChallenge, phase, nonce string) {
		c.GuestNonce = model.CapacityGuestNotifyCanaryNonce{Schema: "original_notify_canary_guest_nonce_v1", ChallengeID: c.ChallengeID, Phase: phase, PreflightSHA256: GuestNotifyPreflightSHA(*c), EnrollmentSHA256: c.EnrollmentSHA256, Actor: e.Statement.Actor, Runtime: e.Statement.Runtime, Writer: e.Statement.Writers[0], NonceSHA256: nonce, IssuedMonotonicNS: 1000000000, ExpiresMonotonicNS: 1000000000 + int64(c.OriginalDeadline.Sub(c.IssuedAt))}
		c.GuestNonce.Signature, _ = GuestLifecycleSignature(observer, c.GuestNonce)
		c.Signature, _ = GuestLifecycleSignature(core, *c)
	}
	sign(&publication, "publish", strings.Repeat("e", 64))
	sign(&read, "read", strings.Repeat("d", 64))
	if ValidateGuestNotifyCanaryChallenge(publication, e, at.Add(10*time.Millisecond)) != nil || ValidateGuestNotifyCanaryChallenge(read, e, read.IssuedAt.Add(time.Millisecond)) != nil || !GuestNotifyCausalPair(publication, read) {
		t.Fatal("signed fixture causal challenges")
	}
	lifetime := e.Statement.Writers[0].Lifetime
	id := GuestNotifyIdentity{lifetime.SourceCommit, lifetime.BinarySHA256, lifetime.PID, lifetime.StartTicks, lifetime.BootID, lifetime.ServiceInvocationID}
	admit := func(when time.Time) GuestNotifyAdmission {
		return GuestNotifyAdmission{Schema: "notify_original_guest_admission_v1", EnrollmentSHA256: read.EnrollmentSHA256, Identity: id, RootsOpen: true, ObservedAt: when}
	}
	users := []string{"77777777-7777-4777-8777-777777777777", "88888888-8888-4888-8888-888888888888"}
	payload := guestNotifyPayload{UserIDs: users, Title: "Capacity canary", Message: "Original two-recipient creation", Route: "/home", Persistent: true, ExpireIn: 1, DedupeKey: GuestNotifyRecord(pubID)}
	push, inApp := false, true
	payload.Delivery.Push = &push
	payload.Delivery.InApp = &inApp
	body, _ := json.Marshal(payload)
	started, published, committed, finished := at.Add(100*time.Millisecond), at.Add(200*time.Millisecond), at.Add(250*time.Millisecond), at.Add(300*time.Millisecond)
	response := GuestNotifyPublicationReply{Schema: "notify_original_guest_canary_publication_return_v1", Source: p.GuestNotifyCanaryBinding.NotifySourceCommit, EnrollmentSHA256: read.EnrollmentSHA256, ChallengeID: pubID, RecordSHA256: BusinessCreationSHA256([]byte(GuestNotifyRecord(pubID))), BodySHA256: BusinessCreationSHA256(body), QueueSHA256: BusinessCreationSHA256([]byte(GuestNotifyQueue(p.GuestRetirementBinding.ProfileManifest.NotifyCanaryTopology, read.Tuple.Provider, read.Slot))), NativeBody: body, PreparationBefore: admit(at.Add(150 * time.Millisecond)), PreparationAfter: admit(at.Add(275 * time.Millisecond)), StartedAt: started, PublishReturnedAt: &published, CommitReturnedAt: &committed, OutboxXID: "101", BackendPID: 1001, BackendStart: at.Add(-time.Hour)}
	responseWire, _ := json.Marshal(response)
	census := func(when time.Time) model.CapacityGuestRetirementProtectedCensus {
		return model.CapacityGuestRetirementProtectedCensus{Schema: "guest_retirement_protected_cgroup_v1", Scope: "fixed_protected_cgroup_v2", SourceCommit: e.Statement.Runtime.SourceCommit, Processes: []model.CapacityGuestRetirementNativeProcess{{PID: lifetime.PID, StartTicks: lifetime.StartTicks}}, RawCensusSHA256: strings.Repeat("4", 64), ObservedAt: when}
	}
	observed := model.CapacityGuestNotifyCanaryRead{Schema: GuestNotifyCanaryPublicationSchema, Purpose: GuestNotifyCanaryPublicationPurpose, ChallengeID: pubID, ChallengeSHA256: GuestRetirementSHA(publication), PreregistrationID: pre.PreregistrationID, EnrollmentSHA256: read.EnrollmentSHA256, Tuple: read.Tuple, Actor: e.Statement.Actor, Runtime: e.Statement.Runtime, Writers: append([]model.CapacityGuestRetirementWriter(nil), e.Statement.Writers...), WriterRosterSHA256: e.Statement.WriterRosterSHA256, CensusBefore: census(at.Add(80 * time.Millisecond)), CensusAfter: census(at.Add(350 * time.Millisecond)), OriginalReadStartedAt: at.Add(50 * time.Millisecond), OriginalRequestWriteReturnedAt: at.Add(90 * time.Millisecond), OriginalFrameReadReturnedAt: at.Add(340 * time.Millisecond), HoldReasons: []string{}, Reader: e.Statement.Actor, ObservedAt: at.Add(360 * time.Millisecond)}
	frame := GuestNotifyOriginalFrame{Schema: "notify_original_guest_writer_v1", Kind: "creation_canary_publication", NonceSHA256: lifetime.ProcessNonceSHA256, Identity: id, EnrollmentSHA256: read.EnrollmentSHA256, OperationID: pubID, RequestSHA256: GuestRetirementSHA(publication), ReturnedAt: at.Add(320 * time.Millisecond), Roster: append([]string(nil), guestNotifyRoster...), CanaryInstalled: true, Healthy: true, CanaryPublication: responseWire, CanaryPublicationSHA256: BusinessCreationSHA256(responseWire), CanaryPublicationStartedAt: &started, CanaryPublicationReturnedAt: &finished, CanaryPublicationDeadline: &publication.OriginalDeadline, RecordChallengeID: pubID}
	frameWire, _ := json.Marshal(frame)
	observed.NotifyOriginalReturn = append(frameWire, '\n')
	observed.NotifyOriginalReturnSHA256 = BusinessCreationSHA256(observed.NotifyOriginalReturn)
	observed.Signature, _ = GuestLifecycleSignature(observer, observed)
	bodyWire, _ := json.Marshal(observed)
	digest := BusinessCreationSHA256(bodyWire)
	transport := GuestOriginalHTTPReturn{StartedAt: at.Add(20 * time.Millisecond), DoStartedAt: at.Add(30 * time.Millisecond), DoReturnedAt: at.Add(370 * time.Millisecond), ReadReturnedAt: at.Add(380 * time.Millisecond), CloseReturnedAt: at.Add(390 * time.Millisecond), DriverReturnedAt: at.Add(400 * time.Millisecond), Status: 200, Body: bodyWire, ReceivedBodyBytes: len(bodyWire), ResponseSHA256: digest, ResponseBodyScope: GuestOriginalBodyCompleteRead, RetainedPrefixBytes: len(bodyWire), RetainedPrefixSHA256: digest}
	if ValidateGuestNotifyCanaryEnvelope(publication, e, observed, transport.DriverReturnedAt) != nil {
		t.Fatal("fixture publication envelope")
	}
	if _, err := GuestNotifyPublicationFacts(p, publication, e, observed); err != nil {
		t.Fatal("fixture publication facts", err)
	}
	return read, publication, observed, transport
}

// RecoveryFixtureCompensationRegistration is signed synthetic data for an
// existing test-generated preregistration and settlement. It grants no Guest,
// provider or production authority and is unavailable in normal builds.
func RecoveryFixtureCompensationRegistration(t *testing.T, p model.CapacityPolicySpec, b model.CapacityGuestRetirementBinding, pre model.CapacityGuestOriginalProvisioningPreregistration, settle model.CapacityMutationSettleRequest) (model.CapacityGuestOriginalCreateWitness, model.CapacityGuestOriginalProvisioningRegistration, model.CapacityGuestOriginalProvisioningReceipt) {
	t.Helper()
	if !strings.HasSuffix(filepath.Base(os.Args[0]), ".test") || os.Getenv("CAPACITY_RECOVERY_FIXTURE_ONLY") != "true" {
		t.Fatal("test-only fixture")
	}
	if pre.Slot < 1 || pre.Slot > len(b.Members) || settle.OriginalProviderCreateReturn == nil {
		t.Fatal("fixture original operands")
	}
	core := ed25519.NewKeyFromSeed([]byte(strings.Repeat("c", 32)))
	producer := ed25519.NewKeyFromSeed([]byte(strings.Repeat("p", 32)))
	issuer := ed25519.NewKeyFromSeed([]byte(strings.Repeat("i", 32)))
	member := b.Members[pre.Slot-1]
	mutation := p.MutationBindings[0]
	spec := mutation.Slots[pre.Slot-1].DesiredSpec
	returned, err := time.Parse(time.RFC3339Nano, settle.OriginalProviderCreateReturn.ReturnedAt)
	if err != nil {
		t.Fatal(err)
	}
	tuple := model.CapacityGuestNativeTuple{Provider: "hetzner", InstanceID: mutation.IntegrationInstanceID, InstanceChecksum: mutation.IntegrationChecksum, TypeID: mutation.IntegrationTypeID, TypeChecksum: mutation.IntegrationTypeChecksum, ScopeChecksum: mutation.ScopeChecksum, ProfileChecksum: spec.ProfileChecksum, Profile: mutation.ProfileName, Slot: pre.Slot, ResourceID: settle.ResourceID, CreatedAt: settle.ResourceCreatedAt}
	w := model.CapacityGuestOriginalCreateWitness{Schema: GuestCreateWitnessSchema, BindingName: pre.BindingName, PreregistrationID: pre.PreregistrationID, PreregistrationNonceSHA256: pre.NonceSHA256, OriginalCreateGrantID: pre.OriginalCreateGrantID, OriginalCreateAttemptID: settle.AttemptID, OriginalCreateRequestSHA256: pre.OriginalCreateRequestSHA256, OriginalCreateSettlementSHA256: GuestRetirementSHA(settle), ProfileManifestSHA256: b.ProfileManifestSHA256, BootstrapSHA256: GuestProfileBootstrapSHA(b.ProfileManifest, pre.Slot), CoreSourceCommit: b.CoreAuthoritySourceCommit, OriginalCreateReturnedAt: returned, ObservedAt: returned.Add(time.Millisecond), OriginalDeadline: pre.OriginalDeadline, Tuple: tuple}
	w.ProviderNativeIdentity = &model.CapacityGuestProviderNativeIdentity{Schema: GuestProviderNativeIdentitySchema, Provider: "hetzner", ResourceID: tuple.ResourceID, ResourceCreatedAt: tuple.CreatedAt, Region: "us-east", Location: "ash", TypeID: "22", ImageID: "33", Hostname: "unit-guest", ObservedAt: w.ObservedAt, AdapterSourceCommit: mutation.OriginalProviderSourceCommit}
	w.Signature, _ = GuestLifecycleSignature(core, w)
	authorityAt := w.ObservedAt.Add(time.Millisecond)
	a := model.CapacityGuestOriginalProfileAuthorityV2{Schema: GuestProfileAuthorityV2Schema, BindingName: pre.BindingName, Slot: pre.Slot, GuestBootID: "10000000-0000-4000-8000-000000000001", RequestNonceSHA256: strings.Repeat("f", 64), Profile: b.ProfileManifest, Preregistration: pre, CreateWitness: w, RemainingNS: int64(pre.OriginalDeadline.Sub(authorityAt)), ObservedAt: authorityAt}
	a.Signature, _ = GuestLifecycleSignature(core, a)
	expiry, err := GuestConservativeProductionExpiry(int64(520*time.Second), int64(101*time.Second), a.RemainingNS)
	if err != nil {
		t.Fatal(err)
	}
	guest := authorityAt
	c := model.CapacityGuestProductionProvisioningClockV2{Schema: GuestProvisioningClockV2Schema, Authority: a, BootstrapOwnerPID: 123, BootstrapOwnerStartTicks: 456, AcquisitionStartedMonotonicNS: int64(100 * time.Second), AcquisitionExpiresMonotonicNS: int64(520 * time.Second), OriginalReadStartedAt: guest, OriginalReadReturnedAt: guest.Add(time.Millisecond), OriginalReadStartedMonotonicNS: int64(101 * time.Second), OriginalReadReturnedMonotonicNS: int64(102 * time.Second), AcceptedExpiresMonotonicNS: expiry, OriginalResultReturnedMonotonicNS: int64(110 * time.Second)}

	w, profile := c.Authority.CreateWitness, b.ProfileManifest
	guest = c.OriginalReadReturnedAt
	at := func(n int) time.Time { return guest.Add(time.Duration(n) * time.Millisecond) }
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
	r := model.CapacityGuestOriginalProvisioningResult{Schema: GuestProvisioningV2Schema, BindingName: member.Name, SourceClass: b.EvidenceClass, ProvisionerSourceCommit: b.ProvisionerSourceCommit, OriginalCreateGrantID: w.OriginalCreateGrantID, OriginalCreateAttemptID: w.OriginalCreateAttemptID, OriginalCreateSettlementSHA256: w.OriginalCreateSettlementSHA256, PreregistrationID: w.PreregistrationID, PreregistrationNonceSHA256: w.PreregistrationNonceSHA256, Tuple: w.Tuple, ProfileManifestSHA256: b.ProfileManifestSHA256, Actor: actor, Runtime: runtime, Writers: []model.CapacityGuestRetirementWriter{writer}, ProtectedCensus: census, PlacementOperation: op, BootstrapOriginalJournal: j, BootstrapOriginalObservation: o, OriginalReturnedAt: at(9), ProductionClock: &c}
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
	enrollment := model.CapacityGuestRetirementEnrollment{Statement: reg.EnrollmentStatement}
	enrollment.Signature, _ = GuestLifecycleSignature(issuer, enrollment.Statement)
	receipt := model.CapacityGuestOriginalProvisioningReceipt{PreregistrationID: pre.PreregistrationID, OriginalProvisioningSHA256: GuestRetirementSHA(reg), RecordedAt: authorityAt.Add(20 * time.Millisecond), Enrollment: enrollment}
	if err := GuestRetirementEnrollment(p, b, member, enrollment, receipt.RecordedAt); err != nil {
		t.Fatal("signed fixture enrollment", err)
	}
	if err := GuestOriginalRegistration(p, b, member, w, reg, receipt.RecordedAt); err != nil {
		t.Fatal("signed fixture registration", err)
	}
	return w, reg, receipt
}
