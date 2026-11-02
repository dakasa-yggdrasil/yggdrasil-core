package capacity

import (
	"fmt"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"math"
	"reflect"
	"time"
)

func guestOriginalBootstrapV2(w model.CapacityGuestOriginalCreateWitness, profile model.CapacityGuestProtectedProfileManifest, journal model.CapacityGuestJournal, observation model.CapacityGuestObservation, now time.Time, clock model.CapacityGuestProductionProvisioningClockV2) error {
	j, o := journal, observation
	if !ValidDigest(w.BootstrapSHA256) || w.BootstrapSHA256 != GuestProfileBootstrapSHA(profile, w.Tuple.Slot) || !reflect.DeepEqual(j, o.Journal) || j.Schema != GuestBootstrapSchema || j.AdmissionProtocol != "original_guest_bootstrap_prestarter_v1" || !guestUUID(j.InvocationNonce) || j.Tuple != w.Tuple || j.UserDataSHA256 != w.BootstrapSHA256 || j.PayloadSHA256 != profile.BootstrapPayloadSHA256 || j.OwnerSourceCommit != profile.BootstrapOwnerSourceCommit || j.OwnerBinarySHA256 != profile.BootstrapOwnerBinarySHA256 || j.OwnerPID < 1 || j.OwnerPID != clock.BootstrapOwnerPID || j.OwnerStartTicks != clock.BootstrapOwnerStartTicks || j.BootID != clock.Authority.GuestBootID || !guestUUID(j.BootID) || j.BootID != o.BootID || j.PossibleStartAt.IsZero() || j.PossibleStartAt.Before(clock.OriginalReadReturnedAt) || j.PossibleStartAt.After(o.ObservedAt) || j.State != "returned" || j.ChildPID < 1 || j.ChildStartTicks == 0 || j.StartedAt == nil || j.OriginalWaitReturnedAt == nil || j.FinalRecordPreparedAt == nil || j.ExitCode == nil || *j.ExitCode != 0 || j.Signal != "" || j.OriginalContextFailed || j.StartedAt.Before(j.PossibleStartAt) || j.OriginalWaitReturnedAt.Before(*j.StartedAt) || j.FinalRecordPreparedAt.Before(*j.OriginalWaitReturnedAt) || j.FinalRecordPreparedAt.After(o.ObservedAt) {
		return fmt.Errorf("original bootstrap owner return does not join")
	}
	a, u := j.UnitAtAdmission, o.Unit
	if !regexpInvocation(a.InvocationID) || a.MainPID < 1 || a.MainPID != a.ExecMainPID || a.StartMonotonic == 0 || a.ExitMonotonic != 0 || !guestAncestry(j.ParentAncestry, a.MainPID) || o.Schema != GuestBootstrapSchema || o.ReaderSourceCommit != profile.BootstrapOwnerSourceCommit || o.ReaderBinarySHA256 != profile.BootstrapReaderBinarySHA256 || o.ReaderPID < 1 || o.ReaderStartTicks == 0 || o.UserDataSHA256 != w.BootstrapSHA256 || o.JournalSHA256 != GuestRetirementSHA(j) || o.ObservedAt.IsZero() || o.ObservedAt.After(now) || now.Sub(o.ObservedAt) > 30*time.Second || u.InvocationID != a.InvocationID || u.ExecMainPID != a.ExecMainPID || u.StartMonotonic != a.StartMonotonic || u.MainPID != 0 || u.ExecMainCode != 1 || u.ExecMainStatus != 0 || u.ExitMonotonic <= u.StartMonotonic || u.Result != "success" || (u.ActiveState != "inactive" && u.ActiveState != "active") || (u.SubState != "dead" && u.SubState != "exited") || o.CloudInitStatus != "done" || o.CloudInitFinalFinished <= 0 || math.IsNaN(o.CloudInitFinalFinished) || math.IsInf(o.CloudInitFinalFinished, 0) || o.CloudInitHasErrors {
		return fmt.Errorf("complete enclosing original bootstrap read required")
	}
	return nil
}

func guestOriginalRegistrationV2(p model.CapacityPolicySpec, binding model.CapacityGuestRetirementBinding, member model.CapacityGuestRetirementMemberBinding, witness model.CapacityGuestOriginalCreateWitness, registration model.CapacityGuestOriginalProvisioningRegistration, now time.Time) error {
	r, e, profile := registration.Result, registration.EnrollmentStatement, binding.ProfileManifest
	clock := r.ProductionClock
	if r.Schema != GuestProvisioningV2Schema || clock == nil || e.OriginalProvisioningClockSHA256 != GuestRetirementSHA(clock) || !GuestProductionClockStoredMatches(clock, clock.Authority.Preregistration, witness, profile) || GuestProductionProvisioningClockV2(p, binding, member, *clock, e.CoreIntentPublicKey, now) != nil || r.Actor.BootID != clock.Authority.GuestBootID || r.OriginalReturnedAt.Before(clock.OriginalReadReturnedAt) {
		return fmt.Errorf("explicit original production clock required")
	}
	if ValidateGuestRetirementBinding(p, &binding) != nil || r.Schema != GuestProvisioningV2Schema || r.BindingName != member.Name || r.BindingName != witness.BindingName || r.SourceClass != binding.EvidenceClass || r.ProvisionerSourceCommit != binding.ProvisionerSourceCommit || r.OriginalCreateGrantID != witness.OriginalCreateGrantID || r.OriginalCreateAttemptID != witness.OriginalCreateAttemptID || r.OriginalCreateSettlementSHA256 != witness.OriginalCreateSettlementSHA256 || r.PreregistrationID != witness.PreregistrationID || r.PreregistrationNonceSHA256 != witness.PreregistrationNonceSHA256 || r.Tuple != witness.Tuple || r.ProfileManifestSHA256 != binding.ProfileManifestSHA256 || !GuestRetirementLifetime(r.Actor) || !GuestRetirementLifetime(r.Runtime) || r.Actor.SourceCommit != profile.ActorSourceCommit || r.Actor.BinarySHA256 != profile.ActorBinarySHA256 || r.Runtime.SourceCommit != profile.OwnerSourceCommit || r.Runtime.BinarySHA256 != profile.OwnerBinarySHA256 || r.Runtime.BootID != r.Actor.BootID || r.Actor.PID == r.Runtime.PID || len(r.Writers) != len(profile.Writers) || len(r.WriterPlacements) != len(r.Writers) || r.WriterRosterSHA256 != GuestRetirementSHA(r.Writers) || r.AdmissionOpened || r.OriginalReturnedAt.IsZero() || r.OriginalReturnedAt.Before(r.BootstrapOriginalObservation.ObservedAt) || guestOriginalBootstrapV2(witness, profile, r.BootstrapOriginalJournal, r.BootstrapOriginalObservation, r.OriginalReturnedAt, *clock) != nil {
		return fmt.Errorf("complete original protected provisioning required")
	}
	full := model.CapacityGuestRetirementEnrollment{Statement: e}
	if !GuestRetirementProtectedCensus(r.ProtectedCensus, full, r.OriginalReturnedAt, true) || r.ProtectedCensus.ObservedAt.Before(r.BootstrapOriginalObservation.ObservedAt) {
		return fmt.Errorf("full original pre-admission writer census required")
	}
	seenPID := map[int]bool{r.Actor.PID: true, r.Runtime.PID: true}
	for n, writer := range r.Writers {
		d, placement := profile.Writers[n], r.WriterPlacements[n]
		prefix := full
		prefix.Statement.Writers = r.Writers[:n+1]
		if writer.ID != d.ID || !GuestRetirementLifetime(writer.Lifetime) || seenPID[writer.Lifetime.PID] || writer.Lifetime.SourceCommit != d.SourceCommit || writer.Lifetime.BinarySHA256 != d.BinarySHA256 || writer.Lifetime.BootID != r.Actor.BootID || placement.Writer != writer || placement.DefinitionSHA256 != GuestRetirementSHA(d) || placement.ProtectedCgroup != profile.ProtectedCgroup || !ValidDigest(placement.RequestSHA256) || !guestPlacementReturned(placement.Operation, clock.OriginalReadReturnedAt, r.OriginalReturnedAt) || placement.OriginalReturnedAt.IsZero() || placement.OriginalReturnedAt.Before(placement.Operation.StartedAt) || placement.OriginalReturnedAt.After(placement.Operation.WaitReturnedAt) || !GuestRetirementProtectedCensus(placement.Census, prefix, placement.Operation.WaitReturnedAt, true) {
			return fmt.Errorf("source-approved original writer placement required")
		}
		seenPID[writer.Lifetime.PID] = true
	}
	if !guestPlacementReturned(r.PlacementOperation, clock.OriginalReadReturnedAt, r.OriginalReturnedAt) || r.PlacementOperation.WaitReturnedAt.Before(r.WriterPlacements[len(r.WriterPlacements)-1].Operation.WaitReturnedAt) || e.Schema != GuestRetirementSchema || e.Purpose != GuestRetirementPurpose || e.BindingName != r.BindingName || e.SourceClass != r.SourceClass || e.ProvisionerSourceCommit != r.ProvisionerSourceCommit || e.OriginalNativeResultSHA256 != GuestRetirementSHA(r) || e.Tuple != r.Tuple || e.Actor != r.Actor || e.Runtime != r.Runtime || !reflect.DeepEqual(e.Writers, r.Writers) || e.WriterRosterSHA256 != r.WriterRosterSHA256 || e.RuntimeCommandSHA256 != profile.RuntimeClientCommandSHA256 || e.PoweroffCommandSHA256 != profile.PoweroffCommandSHA256 || e.CoreAuthoritySourceCommit != witness.CoreSourceCommit || !guestRetirementPublicKey(e.ObservationPublicKey) || !guestRetirementPublicKey(e.CoreIntentPublicKey) || e.ObservationPublicKey == e.CoreIntentPublicKey || e.ObservationPublicKey == binding.ProvisionerPublicKey || e.ObservationPublicKey == binding.EnrollmentIssuerPublicKey || e.CoreIntentPublicKey == binding.ProvisionerPublicKey || e.CoreIntentPublicKey == binding.EnrollmentIssuerPublicKey || e.IssuedAt.Before(r.OriginalReturnedAt) {
		return fmt.Errorf("separate original enrollment statement required")
	}
	signature := registration.Signature
	registration.Signature = ""
	if !guestRetirementVerify(binding.ProvisionerPublicKey, signature, registration) {
		return fmt.Errorf("original provisioning callback signature refused")
	}
	return nil
}
