package capacity

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

// All process/Wait/SQL content below is DECLARED arithmetic input, never an
// actual process return, registry approval or native provisioning receipt.
func productionRegistrationFixture(t *testing.T, offset time.Duration) (model.CapacityPolicySpec, model.CapacityGuestRetirementBinding, model.CapacityGuestOriginalProvisioningRegistration, ed25519.PrivateKey) {
	t.Helper()
	p, b, c, core, producer := productionClockFixture(t, offset)
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

func TestGuestProductionClockV2RegistrationKeepsOriginalProofs(t *testing.T) {
	for _, offset := range []time.Duration{-24 * time.Hour, 24 * time.Hour} {
		for _, mode := range []string{"valid", "owner", "boot", "pre_clock", "witness", "profile", "missing_clock", "legacy", "marker", "late_operation", "early_operation", "census_after_wait", "census_missing", "admission_open", "result_signature"} {
			t.Run(offset.String()+"/"+mode, func(t *testing.T) {
				p, b, r, key := productionRegistrationFixture(t, offset)
				w := r.Result.ProductionClock.Authority.CreateWitness
				now := r.Result.ProductionClock.Authority.ObservedAt.Add(20 * time.Second)
				switch mode {
				case "owner":
					r.Result.BootstrapOriginalJournal.OwnerPID++
				case "boot":
					r.Result.Actor.BootID = "10000000-0000-4000-8000-000000000099"
				case "pre_clock":
					r.Result.ProductionClock.Authority.Preregistration.NonceSHA256 = strings.Repeat("9", 64)
				case "witness":
					r.Result.ProductionClock.Authority.CreateWitness.Tuple.ResourceID = "999"
				case "profile":
					r.Result.ProductionClock.Authority.Profile.Profile = "foreign"
				case "missing_clock":
					r.Result.ProductionClock = nil
				case "legacy":
					r.Result.Schema = GuestOriginalProvisioningSchema
					r.Result.ProductionClock = nil
					r.EnrollmentStatement.OriginalProvisioningClockSHA256 = ""
				case "marker":
					r.EnrollmentStatement.OriginalProvisioningClockSHA256 = strings.Repeat("9", 64)
				case "late_operation":
					r.Result.PlacementOperation.WaitReturnedAt = r.Result.OriginalReturnedAt.Add(time.Second)
				case "early_operation":
					r.Result.PlacementOperation.StartedAt = r.Result.ProductionClock.OriginalReadReturnedAt.Add(-time.Second)
				case "census_after_wait":
					r.Result.WriterPlacements[0].Census.ObservedAt = r.Result.WriterPlacements[0].Operation.WaitReturnedAt.Add(time.Second)
				case "census_missing":
					r.Result.ProtectedCensus.Processes = nil
				case "admission_open":
					r.Result.AdmissionOpened = true
				}
				// Re-sign the enclosing callback to exercise semantic joins, not
				// merely detect the first changed byte via its producer signature.
				r.EnrollmentStatement.OriginalNativeResultSHA256 = GuestRetirementSHA(r.Result)
				r.Signature = ""
				r.Signature, _ = GuestLifecycleSignature(key, r)
				if mode == "result_signature" {
					r.Signature = "bad"
				}
				if (GuestOriginalRegistration(p, b, b.Members[0], w, r, now) == nil) != (mode == "valid") {
					t.Fatal("original registration proof changed", mode)
				}
				if mode == "valid" && GuestRetirementSHA(r) == r.EnrollmentStatement.OriginalNativeResultSHA256 {
					t.Fatal("registration/result hashes accidentally conflated")
				}
			})
		}
	}
}

func TestGuestProductionClockV2EnrollmentMarkerIsIssuerSigned(t *testing.T) {
	for _, offset := range []time.Duration{-24 * time.Hour, 24 * time.Hour} {
		for _, mode := range []string{"valid", "missing_clock", "bad_clock", "foreign_provider", "altered_signature"} {
			t.Run(offset.String()+"/"+mode, func(t *testing.T) {
				p, b, r, _ := productionRegistrationFixture(t, offset)
				e := model.CapacityGuestRetirementEnrollment{Statement: r.EnrollmentStatement}
				switch mode {
				case "missing_clock":
					e.Statement.OriginalProvisioningClockSHA256 = ""
				case "bad_clock":
					e.Statement.OriginalProvisioningClockSHA256 = "bad"
				case "foreign_provider":
					e.Statement.Tuple.Provider = "native-qemu"
				}
				issuer := ed25519.NewKeyFromSeed([]byte(strings.Repeat("i", 32)))
				e.Signature, _ = GuestLifecycleSignature(issuer, e.Statement)
				if mode == "altered_signature" {
					e.Statement.OriginalProvisioningClockSHA256 = strings.Repeat("f", 64)
				}
				now := r.Result.ProductionClock.Authority.ObservedAt.Add(20 * time.Second)
				if (GuestRetirementEnrollment(p, b, b.Members[0], e, now) == nil) != (mode == "valid") {
					t.Fatal("marker bypassed enrollment issuer or clock domains")
				}
			})
		}
	}
}
