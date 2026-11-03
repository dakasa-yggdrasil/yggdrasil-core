package repository

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"strings"
	"testing"
	"time"
)

// Owning capacity pure fixtures copied as DECLARED signed arithmetic input.
// No production registry entry, provider, process, SQL or cleanup authority.
func enrolledRegistryFixture(t *testing.T) (model.CapacityPolicySpec, model.CapacityGuestRetirementBinding, string) {
	t.Helper()
	source, digest := strings.Repeat("a", 40), strings.Repeat("b", 64)
	profile := model.CapacityGuestProtectedProfileManifest{Schema: capacity.GuestProtectedProfileSchema, Profile: "synthetic-production", CoverageClass: "complete_production_roster", ProductionCatalogSHA256: digest, MutationBinding: "synthetic-binding", BootstrapOwnerSourceCommit: source, BootstrapOwnerBinarySHA256: digest, BootstrapReaderBinarySHA256: digest, BootstrapPayloadSHA256: digest, BootstrapSHA256: digest, OriginalProvisioningBudgetSeconds: 420, OriginalProvisioningStepID: "original-create", OwnerSourceCommit: source, OwnerBinarySHA256: digest, OwnerImageDigest: "sha256:" + strings.Repeat("c", 64), ProtectedCgroup: capacity.GuestProtectedCgroup, ActorSourceCommit: source, ActorBinarySHA256: digest, RuntimeClientCommandSHA256: digest, PoweroffCommandSHA256: digest, Writers: []model.CapacityGuestProtectedWriterDefinition{{ID: "synthetic-writer", SourceCommit: source, BinarySHA256: digest, CommandSHA256: strings.Repeat("d", 64), ImageDigest: "sha256:" + strings.Repeat("e", 64), SourceImageReceiptSHA256: strings.Repeat("f", 64), HandleContractSHA256: strings.Repeat("1", 64), CgroupRelativePath: "synthetic-writer"}}}
	mutation := model.CapacityMutationBinding{Name: profile.MutationBinding, ProfileName: profile.Profile, MaxSlots: 1, Slots: []model.CapacityMutationSlotBinding{{Slot: 1, DesiredSpec: &model.CapacityMutationSpecV1{BootstrapSHA256: digest}}}}
	binding := model.CapacityGuestRetirementBinding{Mode: capacity.GuestRetirementSchema, MutationBindingName: mutation.Name, EvidenceClass: "owned_provisioner_original", ProvisionerSourceCommit: source, GuestSourceCommit: source, CoreAuthoritySourceCommit: source, ProvisionerPublicKey: base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32)), EnrollmentIssuerPublicKey: base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{2}, 32)), EnrollmentSigningKeyRef: "secret://synthetic/enrollment#value", IntentSigningKeyRef: "secret://synthetic/intent#value", ProfileManifest: profile, ProfileManifestSHA256: capacity.GuestRetirementSHA(profile), MaxEvidenceAgeSeconds: 30, Members: []model.CapacityGuestRetirementMemberBinding{{Name: "synthetic-member", Slot: 1, Origin: "https://synthetic.invalid", ServerCARef: "secret://synthetic/ca#value", ClientCertificateRef: "secret://synthetic/cert#value", ClientKeyRef: "secret://synthetic/key#value", ActorClientPrincipal: "synthetic-actor", ProvisionerClientPrincipal: "synthetic-provisioner"}}}
	policy := model.CapacityPolicySpec{MaxEvidenceAgeSeconds: 30, Profiles: []model.CapacityProfile{{Name: profile.Profile, Provider: "fixture"}}, MutationBindings: []model.CapacityMutationBinding{mutation}, GuestRetirementBinding: &binding}
	contract := capacity.GuestProductionProfileContractSHA256(policy, binding, "fixture")
	if !capacity.ValidDigest(contract) {
		t.Fatal("synthetic complete contract did not validate")
	}
	return policy, binding, source
}

func enrolledClockFixture(t *testing.T, offset time.Duration) (model.CapacityPolicySpec, model.CapacityGuestRetirementBinding, model.CapacityGuestProductionProvisioningClockV2, ed25519.PrivateKey, ed25519.PrivateKey) {
	t.Helper()
	p, b, source := enrolledRegistryFixture(t)
	key := func(ch byte) ed25519.PrivateKey {
		return ed25519.NewKeyFromSeed([]byte(strings.Repeat(string(ch), 32)))
	}
	core, producer, issuer := key('c'), key('p'), key('i')
	public := func(k ed25519.PrivateKey) string {
		return base64.StdEncoding.EncodeToString(k.Public().(ed25519.PublicKey))
	}
	b.ProvisionerPublicKey, b.EnrollmentIssuerPublicKey = public(producer), public(issuer)
	p.Profiles[0].Provider = "hetzner"
	p.MutationBindings[0].OriginalProviderSourceCommit = source
	p.GuestRetirementBinding = &b
	uid := "10000000-0000-4000-8000-000000000001"
	now := time.Date(2026, 10, 21, 0, 0, 0, 0, time.UTC)
	pre := model.CapacityGuestOriginalProvisioningPreregistration{Schema: capacity.GuestPreregistrationSchema, PreregistrationID: uid, BindingName: b.Members[0].Name, OriginalCreateGrantID: uid, OriginalCreateRequestSHA256: strings.Repeat("a", 64), NonceSHA256: strings.Repeat("b", 64), ProfileManifestSHA256: b.ProfileManifestSHA256, PolicyID: uid, PolicyChecksum: strings.Repeat("c", 64), WorkflowID: uid, WorkflowChecksum: strings.Repeat("d", 64), OriginalWorkflowStepID: b.ProfileManifest.OriginalProvisioningStepID, OriginalWorkflowStepTimeoutSeconds: 420, OriginalWorkflowContextDeadline: now.Add(420 * time.Second), CoreSourceCommit: b.CoreAuthoritySourceCommit, Generation: 1, Fence: 1, LeaseOwner: uid, ExecutorID: uid, Slot: 1, ReservedAt: now, OriginalDeadline: now.Add(420 * time.Second)}
	w := model.CapacityGuestOriginalCreateWitness{Schema: capacity.GuestCreateWitnessSchema, BindingName: pre.BindingName, PreregistrationID: uid, PreregistrationNonceSHA256: pre.NonceSHA256, OriginalCreateGrantID: uid, OriginalCreateAttemptID: uid, OriginalCreateRequestSHA256: pre.OriginalCreateRequestSHA256, OriginalCreateSettlementSHA256: strings.Repeat("e", 64), ProfileManifestSHA256: b.ProfileManifestSHA256, BootstrapSHA256: b.ProfileManifest.BootstrapSHA256, CoreSourceCommit: b.CoreAuthoritySourceCommit, OriginalCreateReturnedAt: now.Add(time.Second), ObservedAt: now.Add(2 * time.Second), OriginalDeadline: pre.OriginalDeadline, Tuple: model.CapacityGuestNativeTuple{Provider: "hetzner", Profile: b.ProfileManifest.Profile, Slot: 1, ResourceID: "123", CreatedAt: now.Format(time.RFC3339Nano)}}
	w.ProviderNativeIdentity = &model.CapacityGuestProviderNativeIdentity{Schema: capacity.GuestProviderNativeIdentitySchema, Provider: "hetzner", ResourceID: "123", ResourceCreatedAt: w.Tuple.CreatedAt, Region: "us-east", Location: "ash", TypeID: "22", ImageID: "33", Hostname: "unit-guest", ObservedAt: w.ObservedAt, AdapterSourceCommit: source}
	w.Signature, _ = capacity.GuestLifecycleSignature(core, w)
	a := model.CapacityGuestOriginalProfileAuthorityV2{Schema: capacity.GuestProfileAuthorityV2Schema, BindingName: pre.BindingName, Slot: 1, GuestBootID: uid, RequestNonceSHA256: strings.Repeat("f", 64), Profile: b.ProfileManifest, Preregistration: pre, CreateWitness: w, RemainingNS: int64(417 * time.Second), ObservedAt: now.Add(3 * time.Second)}
	a.Signature, _ = capacity.GuestLifecycleSignature(core, a)
	guest := now.Add(offset)
	c := model.CapacityGuestProductionProvisioningClockV2{Schema: capacity.GuestProvisioningClockV2Schema, Authority: a, BootstrapOwnerPID: 123, BootstrapOwnerStartTicks: 456, AcquisitionStartedMonotonicNS: int64(100 * time.Second), AcquisitionExpiresMonotonicNS: int64(520 * time.Second), OriginalReadStartedAt: guest, OriginalReadReturnedAt: guest.Add(time.Second), OriginalReadStartedMonotonicNS: int64(101 * time.Second), OriginalReadReturnedMonotonicNS: int64(102 * time.Second), AcceptedExpiresMonotonicNS: int64(518 * time.Second), OriginalResultReturnedMonotonicNS: int64(110 * time.Second)}
	if err := capacity.GuestProductionProvisioningClockV2(p, b, b.Members[0], c, public(core), now.Add(5*time.Second)); err != nil {
		t.Fatal("synthetic clock content invalid", err)
	}
	if capacity.GuestOriginalProfileEnabled(p, b, "hetzner") {
		t.Fatal("fixture must not install a production approval")
	}
	return p, b, c, core, producer
}

func enrolledRegistrationFixture(t *testing.T, offset time.Duration) (model.CapacityPolicySpec, model.CapacityGuestRetirementBinding, model.CapacityGuestOriginalProvisioningRegistration, ed25519.PrivateKey) {
	t.Helper()
	p, b, c, core, producer := enrolledClockFixture(t, offset)
	w, profile := c.Authority.CreateWitness, b.ProfileManifest
	guest := c.OriginalReadReturnedAt
	at := func(n int) time.Time { return guest.Add(time.Duration(n) * time.Second) }
	start, wait, prepared, code := at(2), at(3), at(4), 0
	j := model.CapacityGuestJournal{Schema: capacity.GuestBootstrapSchema, AdmissionProtocol: "original_guest_bootstrap_prestarter_v1", InvocationNonce: c.Authority.GuestBootID, State: "returned", BootID: c.Authority.GuestBootID, Tuple: w.Tuple, UserDataSHA256: w.BootstrapSHA256, PayloadSHA256: profile.BootstrapPayloadSHA256, OwnerSourceCommit: profile.BootstrapOwnerSourceCommit, OwnerBinarySHA256: profile.BootstrapOwnerBinarySHA256, OwnerPID: c.BootstrapOwnerPID, OwnerStartTicks: c.BootstrapOwnerStartTicks, ParentAncestry: []int{50}, UnitAtAdmission: model.CapacityGuestUnitObservation{InvocationID: strings.Repeat("1", 32), MainPID: 50, ExecMainPID: 50, StartMonotonic: 1}, PossibleStartAt: at(1), ChildPID: 124, ChildStartTicks: 125, StartedAt: &start, OriginalWaitReturnedAt: &wait, FinalRecordPreparedAt: &prepared, ExitCode: &code}
	o := model.CapacityGuestObservation{Schema: capacity.GuestBootstrapSchema, ReaderSourceCommit: profile.BootstrapOwnerSourceCommit, ReaderBinarySHA256: profile.BootstrapReaderBinarySHA256, ReaderPID: 200, ReaderStartTicks: 201, BootID: j.BootID, UserDataSHA256: w.BootstrapSHA256, Journal: j, JournalSHA256: capacity.GuestRetirementSHA(j), Unit: model.CapacityGuestUnitObservation{InvocationID: j.UnitAtAdmission.InvocationID, ExecMainPID: 50, ExecMainCode: 1, ExecMainStatus: 0, StartMonotonic: 1, ExitMonotonic: 2, ActiveState: "inactive", SubState: "dead", Result: "success"}, CloudInitStatus: "done", CloudInitFinalFinished: 1, ObservedAt: at(5)}
	life := func(pid int) model.CapacityGuestRetirementLifetime {
		return model.CapacityGuestRetirementLifetime{BootID: j.BootID, ProcessNonceSHA256: strings.Repeat("2", 64), PID: pid, StartTicks: uint64(pid), SourceCommit: profile.OwnerSourceCommit, BinarySHA256: profile.OwnerBinarySHA256, ServiceInvocationID: strings.Repeat("3", 32)}
	}
	actor, runtime, writer := life(300), life(301), model.CapacityGuestRetirementWriter{ID: profile.Writers[0].ID, Lifetime: life(302)}
	actor.SourceCommit, actor.BinarySHA256 = profile.ActorSourceCommit, profile.ActorBinarySHA256
	writer.Lifetime.SourceCommit, writer.Lifetime.BinarySHA256 = profile.Writers[0].SourceCommit, profile.Writers[0].BinarySHA256
	census := model.CapacityGuestRetirementProtectedCensus{Schema: "guest_retirement_protected_cgroup_v1", Scope: "fixed_protected_cgroup_v2", SourceCommit: runtime.SourceCommit, Processes: []model.CapacityGuestRetirementNativeProcess{{PID: writer.Lifetime.PID, StartTicks: writer.Lifetime.StartTicks}}, RawCensusSHA256: strings.Repeat("4", 64), ObservedAt: at(7)}
	op := model.CapacityGuestRetirementOperationReturn{StartedAt: at(6), PID: 400, StartTicks: 401, WaitReturnedAt: at(8), BodyJoined: true, CloseReturned: true, Outcome: "returned"}
	r := model.CapacityGuestOriginalProvisioningResult{Schema: capacity.GuestProvisioningV2Schema, BindingName: b.Members[0].Name, SourceClass: b.EvidenceClass, ProvisionerSourceCommit: b.ProvisionerSourceCommit, OriginalCreateGrantID: w.OriginalCreateGrantID, OriginalCreateAttemptID: w.OriginalCreateAttemptID, OriginalCreateSettlementSHA256: w.OriginalCreateSettlementSHA256, PreregistrationID: w.PreregistrationID, PreregistrationNonceSHA256: w.PreregistrationNonceSHA256, Tuple: w.Tuple, ProfileManifestSHA256: b.ProfileManifestSHA256, Actor: actor, Runtime: runtime, Writers: []model.CapacityGuestRetirementWriter{writer}, ProtectedCensus: census, PlacementOperation: op, BootstrapOriginalJournal: j, BootstrapOriginalObservation: o, OriginalReturnedAt: at(9), ProductionClock: &c}
	// Allocate the anonymous wire entry, then explicitly populate every fact.
	if json.Unmarshal([]byte(`[{}]`), &r.WriterPlacements) != nil {
		t.Fatal("fixture allocation")
	}
	x := &r.WriterPlacements[0]
	x.Writer = writer
	x.DefinitionSHA256 = capacity.GuestRetirementSHA(profile.Writers[0])
	x.ProtectedCgroup = profile.ProtectedCgroup
	x.RequestSHA256 = strings.Repeat("5", 64)
	x.Operation = op
	x.Census = census
	x.OriginalReturnedAt = at(7)
	r.WriterRosterSHA256 = capacity.GuestRetirementSHA(r.Writers)
	obs := ed25519.NewKeyFromSeed([]byte(strings.Repeat("o", 32)))
	e := model.CapacityGuestRetirementEnrollmentStatement{Schema: capacity.GuestRetirementSchema, Purpose: capacity.GuestRetirementPurpose, BindingName: r.BindingName, SourceClass: r.SourceClass, ProvisionerSourceCommit: r.ProvisionerSourceCommit, OriginalNativeResultSHA256: capacity.GuestRetirementSHA(r), Tuple: r.Tuple, Actor: actor, Runtime: runtime, Writers: r.Writers, WriterRosterSHA256: r.WriterRosterSHA256, RuntimeCommandSHA256: profile.RuntimeClientCommandSHA256, PoweroffCommandSHA256: profile.PoweroffCommandSHA256, ObservationPublicKey: base64.StdEncoding.EncodeToString(obs.Public().(ed25519.PublicKey)), CoreIntentPublicKey: base64.StdEncoding.EncodeToString(core.Public().(ed25519.PublicKey)), CoreAuthoritySourceCommit: w.CoreSourceCommit, IssuedAt: at(10), OriginalProvisioningClockSHA256: capacity.GuestRetirementSHA(c)}
	reg := model.CapacityGuestOriginalProvisioningRegistration{Result: r, EnrollmentStatement: e}
	reg.Signature, _ = capacity.GuestLifecycleSignature(producer, reg)
	return p, b, reg, producer
}

func enrolledReceiptFixture(t *testing.T) (guestOriginalStored, model.CapacityPolicySpec, model.CapacityGuestOriginalProvisioningReceipt, model.CapacityGuestOriginalProvisioningRegistration) {
	t.Helper()
	p, b, r, _ := enrolledRegistrationFixture(t, 0)
	c := r.Result.ProductionClock
	pre, w := c.Authority.Preregistration, c.Authority.CreateWitness
	issuer := ed25519.NewKeyFromSeed([]byte(strings.Repeat("i", 32)))
	enrollment := model.CapacityGuestRetirementEnrollment{Statement: r.EnrollmentStatement}
	enrollment.Signature, _ = capacity.GuestLifecycleSignature(issuer, enrollment.Statement)
	receipt := model.CapacityGuestOriginalProvisioningReceipt{PreregistrationID: pre.PreregistrationID, OriginalProvisioningSHA256: capacity.GuestRetirementSHA(r), Enrollment: enrollment, RecordedAt: c.Authority.ObservedAt.Add(20 * time.Second)}
	return guestOriginalStored{pre: pre, binding: b, member: b.Members[0], witness: w}, p, receipt, r
}
func TestEnrolledFailedReceiptAuthenticatesHistoricalOriginals(t *testing.T) {
	for _, name := range []string{"valid_expired_now", "registration_signature", "issuer_signature", "witness_signature", "missing_clock", "profile", "tuple", "nonce", "original_deadline", "wrong_registration_digest", "wrong_receipt_bytes", "wrong_tuple_digest", "receipt_at_deadline", "claim_admission"} {
		t.Run(name, func(t *testing.T) {
			stored, p, receipt, reg := enrolledReceiptFixture(t)
			switch name {
			case "registration_signature":
				reg.Signature = "bad"
			case "issuer_signature":
				receipt.Enrollment.Signature = "bad"
			case "witness_signature":
				stored.witness.Signature = "bad"
			case "missing_clock":
				reg.Result.ProductionClock = nil
			case "profile":
				stored.binding.ProfileManifest.Profile = "foreign"
			case "tuple":
				receipt.Enrollment.Statement.Tuple.ResourceID = "foreign"
			case "nonce":
				reg.Result.PreregistrationNonceSHA256 = strings.Repeat("0", 64)
			case "original_deadline":
				stored.pre.OriginalDeadline = stored.pre.OriginalDeadline.Add(time.Second)
			case "receipt_at_deadline":
				receipt.RecordedAt = stored.pre.OriginalDeadline
			case "claim_admission":
				reg.Result.AdmissionOpened = true
			}
			regWire, _ := json.Marshal(reg)
			receiptWire, _ := json.Marshal(receipt)
			regSHA := capacity.GuestRetirementSHA(reg)
			enrollmentSHA := capacity.GuestRetirementSHA(receipt.Enrollment)
			tupleSHA := capacity.GuestRetirementSHA(stored.witness.Tuple)
			if name == "wrong_registration_digest" {
				regSHA = strings.Repeat("0", 64)
			}
			if name == "wrong_tuple_digest" {
				tupleSHA = strings.Repeat("0", 64)
			}
			if name == "wrong_receipt_bytes" {
				receiptWire = append(receiptWire, '\n')
			}
			err := validateEnrolledFailedReceipt(stored, p, receipt, reg, regWire, receiptWire, enrollmentSHA, regSHA, tupleSHA)
			if (err == nil) != (name == "valid_expired_now") {
				t.Fatalf("original enrollment boundary %s: %v", name, err)
			}
		})
	}
}
func TestEnrolledFailedKnownAuxiliaryNeverInventsMissingInventory(t *testing.T) {
	good := []model.CapacityMutationAuxiliaryResource{{Kind: "aws_ebs_volume", ID: "vol-0123456789abcdef0", RequiresAbsence: true}, {Kind: "aws_network_interface", ID: "eni-0123456789abcdef0", RequiresAbsence: true}}
	if !enrolledFailedKnownAWSAuxiliary(good) {
		t.Fatal("declared exact known pair refused")
	}
	for _, bad := range [][]model.CapacityMutationAuxiliaryResource{nil, {}, good[:1], {good[0], good[0]}, {{Kind: "aws_ebs_volume", ID: "vol-0123456789abcdef0", RequiresAbsence: false}, good[1]}} {
		if enrolledFailedKnownAWSAuxiliary(bad) {
			t.Fatal("incomplete or aliased AUX accepted")
		}
	}
}
