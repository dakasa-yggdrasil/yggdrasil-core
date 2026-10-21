package capacity

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math"
	"reflect"
	"runtime/debug"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

const GuestPreregistrationSchema = "original_guest_provisioning_preregistration_v1"
const GuestCreateWitnessSchema = "original_guest_create_witness_v1"
const GuestSnapshotSchema = "original_guest_runtime_snapshot_v1"
const GuestSnapshotPurpose = "observe_before_guest_retirement"

// Runtime source identity is native build metadata, never an environment
// value, a workflow input or the expected value copied from an enrollment.
func CurrentGuestCoreSource() string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return ""
	}
	source, modified := "", false
	for _, setting := range info.Settings {
		if setting.Key == "vcs.revision" {
			source = setting.Value
		}
		if setting.Key == "vcs.modified" {
			modified = setting.Value != "false"
		}
	}
	if modified || !businessSource.MatchString(source) {
		return ""
	}
	return source
}

// Closed original bytes are decoded before Output:any, signature verification
// or PostgreSQL JSONB rendering. Missing false-valued facts are not facts.
func DecodeGuestLifecycle(raw []byte, out any) error {
	t := reflect.TypeOf(out)
	if t == nil || t.Kind() != reflect.Pointer || reflect.ValueOf(out).IsNil() || guestClosedJSON(raw, t.Elem(), 0) != nil {
		return fmt.Errorf("closed original Guest lifecycle bytes required")
	}
	return json.Unmarshal(raw, out)
}

func GuestLifecycleSignature(key ed25519.PrivateKey, unsigned any) (string, error) {
	if len(key) != ed25519.PrivateKeySize {
		return "", fmt.Errorf("separate original Guest signing key required")
	}
	raw, err := json.Marshal(unsigned)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(ed25519.Sign(key, raw)), nil
}

func GuestLifecycleKeyMatches(key ed25519.PrivateKey, encoded string) bool {
	return len(key) == ed25519.PrivateKeySize && base64.StdEncoding.EncodeToString(key.Public().(ed25519.PublicKey)) == encoded
}

func GuestOriginalCreateWitness(p model.CapacityPolicySpec, binding model.CapacityGuestRetirementBinding, member model.CapacityGuestRetirementMemberBinding, pre model.CapacityGuestOriginalProvisioningPreregistration, w model.CapacityGuestOriginalCreateWitness, corePublic string, now time.Time) error {
	if ValidateGuestRetirementBinding(p, &binding) != nil || !GuestOriginalProvisioningDeadlineMatches(pre, binding.ProfileManifest) || w.Schema != GuestCreateWitnessSchema || w.BindingName != member.Name || pre.BindingName != member.Name || w.PreregistrationID != pre.PreregistrationID || w.PreregistrationNonceSHA256 != pre.NonceSHA256 || !guestRetirementNativeTuple(p, binding, member, w.Tuple) || w.Tuple.Slot != pre.Slot || w.OriginalCreateGrantID != pre.OriginalCreateGrantID || !guestUUID(w.OriginalCreateAttemptID) || w.OriginalCreateRequestSHA256 != pre.OriginalCreateRequestSHA256 || !ValidDigest(w.OriginalCreateSettlementSHA256) || w.ProfileManifestSHA256 != pre.ProfileManifestSHA256 || w.BootstrapSHA256 != binding.ProfileManifest.BootstrapSHA256 || w.CoreSourceCommit != pre.CoreSourceCommit || w.CoreSourceCommit != binding.CoreAuthoritySourceCommit || !w.OriginalDeadline.Equal(pre.OriginalDeadline) || w.OriginalCreateReturnedAt.IsZero() || w.OriginalCreateReturnedAt.Before(pre.ReservedAt) || w.OriginalCreateReturnedAt.After(w.ObservedAt) || w.ObservedAt.After(now) || !w.ObservedAt.Before(w.OriginalDeadline) {
		return fmt.Errorf("authentic original create witness required")
	}
	if w.SourceObservation != nil && !guestPostlossObservationAllowed(binding, w) {
		return fmt.Errorf("source-only postloss witness refused")
	}
	signature := w.Signature
	w.Signature = ""
	if !guestRetirementVerify(corePublic, signature, w) {
		return fmt.Errorf("original create witness signature refused")
	}
	return nil
}

// This joins the real owner prestarter journal and independent enclosing
// cloud-final read without creating a static Node or bootstrap enrollment.
func GuestOriginalBootstrap(w model.CapacityGuestOriginalCreateWitness, profile model.CapacityGuestProtectedProfileManifest, journal model.CapacityGuestJournal, observation model.CapacityGuestObservation, now time.Time) error {
	j, o := journal, observation
	if !reflect.DeepEqual(j, o.Journal) || j.Schema != GuestBootstrapSchema || j.AdmissionProtocol != "original_guest_bootstrap_prestarter_v1" || !guestUUID(j.InvocationNonce) || j.Tuple != w.Tuple || j.UserDataSHA256 != w.BootstrapSHA256 || j.PayloadSHA256 != profile.BootstrapPayloadSHA256 || j.OwnerSourceCommit != profile.BootstrapOwnerSourceCommit || j.OwnerBinarySHA256 != profile.BootstrapOwnerBinarySHA256 || j.OwnerPID < 1 || j.OwnerStartTicks == 0 || !guestUUID(j.BootID) || j.BootID != o.BootID || j.PossibleStartAt.IsZero() || j.PossibleStartAt.Before(w.OriginalCreateReturnedAt) || j.PossibleStartAt.After(o.ObservedAt) || j.State != "returned" || j.ChildPID < 1 || j.ChildStartTicks == 0 || j.StartedAt == nil || j.OriginalWaitReturnedAt == nil || j.FinalRecordPreparedAt == nil || j.ExitCode == nil || *j.ExitCode != 0 || j.Signal != "" || j.OriginalContextFailed || j.StartedAt.Before(j.PossibleStartAt) || j.OriginalWaitReturnedAt.Before(*j.StartedAt) || j.FinalRecordPreparedAt.Before(*j.OriginalWaitReturnedAt) || j.FinalRecordPreparedAt.After(o.ObservedAt) {
		return fmt.Errorf("original bootstrap owner return does not join")
	}
	a, u := j.UnitAtAdmission, o.Unit
	if !regexpInvocation(a.InvocationID) || a.MainPID < 1 || a.MainPID != a.ExecMainPID || a.StartMonotonic == 0 || a.ExitMonotonic != 0 || !guestAncestry(j.ParentAncestry, a.MainPID) || o.Schema != GuestBootstrapSchema || o.ReaderSourceCommit != profile.BootstrapOwnerSourceCommit || o.ReaderBinarySHA256 != profile.BootstrapReaderBinarySHA256 || o.ReaderPID < 1 || o.ReaderStartTicks == 0 || o.UserDataSHA256 != w.BootstrapSHA256 || o.JournalSHA256 != GuestRetirementSHA(j) || o.ObservedAt.IsZero() || o.ObservedAt.After(now) || now.Sub(o.ObservedAt) > 30*time.Second || !o.ObservedAt.Before(w.OriginalDeadline) || u.InvocationID != a.InvocationID || u.ExecMainPID != a.ExecMainPID || u.StartMonotonic != a.StartMonotonic || u.MainPID != 0 || u.ExecMainCode != 1 || u.ExecMainStatus != 0 || u.ExitMonotonic <= u.StartMonotonic || u.Result != "success" || (u.ActiveState != "inactive" && u.ActiveState != "active") || (u.SubState != "dead" && u.SubState != "exited") || o.CloudInitStatus != "done" || o.CloudInitFinalFinished <= 0 || math.IsNaN(o.CloudInitFinalFinished) || math.IsInf(o.CloudInitFinalFinished, 0) || o.CloudInitHasErrors {
		return fmt.Errorf("complete enclosing original bootstrap read required")
	}
	return nil
}

func GuestOriginalRegistration(p model.CapacityPolicySpec, binding model.CapacityGuestRetirementBinding, member model.CapacityGuestRetirementMemberBinding, witness model.CapacityGuestOriginalCreateWitness, registration model.CapacityGuestOriginalProvisioningRegistration, now time.Time) error {
	r, e, profile := registration.Result, registration.EnrollmentStatement, binding.ProfileManifest
	if ValidateGuestRetirementBinding(p, &binding) != nil || r.Schema != GuestOriginalProvisioningSchema || r.BindingName != member.Name || r.BindingName != witness.BindingName || r.SourceClass != binding.EvidenceClass || r.ProvisionerSourceCommit != binding.ProvisionerSourceCommit || r.OriginalCreateGrantID != witness.OriginalCreateGrantID || r.OriginalCreateAttemptID != witness.OriginalCreateAttemptID || r.OriginalCreateSettlementSHA256 != witness.OriginalCreateSettlementSHA256 || r.PreregistrationID != witness.PreregistrationID || r.PreregistrationNonceSHA256 != witness.PreregistrationNonceSHA256 || r.Tuple != witness.Tuple || r.ProfileManifestSHA256 != binding.ProfileManifestSHA256 || !GuestRetirementLifetime(r.Actor) || !GuestRetirementLifetime(r.Runtime) || r.Actor.SourceCommit != profile.ActorSourceCommit || r.Actor.BinarySHA256 != profile.ActorBinarySHA256 || r.Runtime.SourceCommit != profile.OwnerSourceCommit || r.Runtime.BinarySHA256 != profile.OwnerBinarySHA256 || r.Runtime.BootID != r.Actor.BootID || r.Actor.PID == r.Runtime.PID || len(r.Writers) != len(profile.Writers) || len(r.WriterPlacements) != len(r.Writers) || r.WriterRosterSHA256 != GuestRetirementSHA(r.Writers) || r.AdmissionOpened || r.OriginalReturnedAt.IsZero() || r.OriginalReturnedAt.After(now) || !r.OriginalReturnedAt.Before(witness.OriginalDeadline) || r.OriginalReturnedAt.Before(r.BootstrapOriginalObservation.ObservedAt) || GuestOriginalBootstrap(witness, profile, r.BootstrapOriginalJournal, r.BootstrapOriginalObservation, r.OriginalReturnedAt) != nil {
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
		if writer.ID != d.ID || !GuestRetirementLifetime(writer.Lifetime) || seenPID[writer.Lifetime.PID] || writer.Lifetime.SourceCommit != d.SourceCommit || writer.Lifetime.BinarySHA256 != d.BinarySHA256 || writer.Lifetime.BootID != r.Actor.BootID || placement.Writer != writer || placement.DefinitionSHA256 != GuestRetirementSHA(d) || placement.ProtectedCgroup != profile.ProtectedCgroup || !ValidDigest(placement.RequestSHA256) || !guestPlacementReturned(placement.Operation, witness.OriginalCreateReturnedAt, r.OriginalReturnedAt) || placement.OriginalReturnedAt.IsZero() || placement.OriginalReturnedAt.Before(placement.Operation.StartedAt) || placement.OriginalReturnedAt.After(placement.Operation.WaitReturnedAt) || !GuestRetirementProtectedCensus(placement.Census, prefix, placement.Operation.WaitReturnedAt, true) {
			return fmt.Errorf("source-approved original writer placement required")
		}
		seenPID[writer.Lifetime.PID] = true
	}
	if !guestPlacementReturned(r.PlacementOperation, witness.OriginalCreateReturnedAt, r.OriginalReturnedAt) || r.PlacementOperation.WaitReturnedAt.Before(r.WriterPlacements[len(r.WriterPlacements)-1].Operation.WaitReturnedAt) || e.Schema != GuestRetirementSchema || e.Purpose != GuestRetirementPurpose || e.BindingName != r.BindingName || e.SourceClass != r.SourceClass || e.ProvisionerSourceCommit != r.ProvisionerSourceCommit || e.OriginalNativeResultSHA256 != GuestRetirementSHA(r) || e.Tuple != r.Tuple || e.Actor != r.Actor || e.Runtime != r.Runtime || !reflect.DeepEqual(e.Writers, r.Writers) || e.WriterRosterSHA256 != r.WriterRosterSHA256 || e.RuntimeCommandSHA256 != profile.RuntimeClientCommandSHA256 || e.PoweroffCommandSHA256 != profile.PoweroffCommandSHA256 || e.CoreAuthoritySourceCommit != witness.CoreSourceCommit || !guestRetirementPublicKey(e.ObservationPublicKey) || !guestRetirementPublicKey(e.CoreIntentPublicKey) || e.ObservationPublicKey == e.CoreIntentPublicKey || e.ObservationPublicKey == binding.ProvisionerPublicKey || e.ObservationPublicKey == binding.EnrollmentIssuerPublicKey || e.CoreIntentPublicKey == binding.ProvisionerPublicKey || e.CoreIntentPublicKey == binding.EnrollmentIssuerPublicKey || e.IssuedAt.Before(r.OriginalReturnedAt) || e.IssuedAt.After(now) || !e.IssuedAt.Before(witness.OriginalDeadline) {
		return fmt.Errorf("separate original enrollment statement required")
	}
	signature := registration.Signature
	registration.Signature = ""
	if !guestRetirementVerify(binding.ProvisionerPublicKey, signature, registration) {
		return fmt.Errorf("original provisioning callback signature refused")
	}
	return nil
}

func guestPlacementReturned(operation model.CapacityGuestRetirementOperationReturn, createdReturn, resultReturn time.Time) bool {
	return !operation.StartedAt.IsZero() && !operation.StartedAt.Before(createdReturn) && operation.PID > 0 && operation.StartTicks > 0 && !operation.WaitReturnedAt.Before(operation.StartedAt) && !operation.WaitReturnedAt.After(resultReturn) && operation.ExitCode == 0 && operation.BodyJoined && operation.CloseReturned && !operation.OriginalContextFailed && operation.Outcome == "returned"
}

// The original challenge was stored before GET; the reader is the current
// original ACTOR. Provisioning expiry does not end an admitted daemon lifetime.
func GuestRuntimeSnapshot(c model.CapacityGuestRuntimeSnapshotChallenge, e model.CapacityGuestRetirementEnrollment, i model.CapacityGuestRetirementIntent, snapshot model.CapacityGuestRuntimeSnapshot, now time.Time) error {
	s := snapshot
	if c.Schema != GuestSnapshotSchema || c.Purpose != GuestSnapshotPurpose || !guestUUID(c.ChallengeID) || c.Phase != "before_start" || c.BindingName != e.Statement.BindingName || c.Slot != e.Statement.Tuple.Slot || !guestUUID(c.PreregistrationID) || !ValidDigest(c.PreregistrationNonceSHA256) || !ValidDigest(c.OriginalRegistrationSHA256) || !ValidDigest(c.OriginalCreateWitnessSHA256) || c.EnrollmentSHA256 != GuestRetirementSHA(e) || !ValidDigest(c.ProfileManifestSHA256) || c.Tuple != e.Statement.Tuple || c.RequestID != i.RequestID || c.AttemptID != i.AttemptID || c.IntentSHA256 != GuestRetirementSHA(i) || c.PolicyID != i.PolicyID || c.PolicyChecksum != i.PolicyChecksum || c.WorkflowID != i.WorkflowID || c.WorkflowChecksum != i.WorkflowChecksum || c.Generation != i.Generation || c.Fence != i.Fence || c.LeaseOwner != i.LeaseOwner || c.CoreSourceCommit != e.Statement.CoreAuthoritySourceCommit || c.IssuedAt.IsZero() || c.IssuedAt.After(now) || !c.OriginalDeadline.After(c.IssuedAt) || !now.Before(c.OriginalDeadline) || c.OriginalDeadline.After(i.OriginalDeadline) || c.OriginalDeadline.Sub(c.IssuedAt) > 30*time.Second {
		return fmt.Errorf("scoped original runtime challenge required")
	}
	sig := c.Signature
	c.Signature = ""
	if !guestRetirementVerify(e.Statement.CoreIntentPublicKey, sig, c) {
		return fmt.Errorf("original snapshot challenge signature refused")
	}
	c.Signature = sig
	if s.Schema != GuestSnapshotSchema || s.Purpose != GuestSnapshotPurpose || s.ChallengeID != c.ChallengeID || s.ChallengeSHA256 != GuestRetirementSHA(c) || s.PreregistrationID != c.PreregistrationID || s.OriginalRegistrationSHA256 != c.OriginalRegistrationSHA256 || s.OriginalCreateWitnessSHA256 != c.OriginalCreateWitnessSHA256 || s.ProfileManifestSHA256 != c.ProfileManifestSHA256 || s.EnrollmentSHA256 != c.EnrollmentSHA256 || s.Tuple != c.Tuple || s.Actor != e.Statement.Actor || s.Runtime != e.Statement.Runtime || s.Reader != e.Statement.Actor || !reflect.DeepEqual(s.Writers, e.Statement.Writers) || s.WriterRosterSHA256 != e.Statement.WriterRosterSHA256 || !GuestRetirementProtectedCensus(s.ProtectedCensus, e, s.OriginalReadReturnedAt, true) || s.OriginalReadStartedAt.Before(c.IssuedAt) || s.OriginalReadReturnedAt.Before(s.OriginalReadStartedAt) || !s.OriginalReadReturnedAt.Before(c.OriginalDeadline) || !s.OriginalReadsReturned || !s.OriginalClosesReturned || s.OriginalContextFailed || s.HoldReasons == nil || len(s.HoldReasons) != 0 || s.ObservedAt.Before(s.OriginalReadReturnedAt) || s.ObservedAt.After(now) || now.Sub(s.ObservedAt) > 30*time.Second {
		return fmt.Errorf("current complete original Actor runtime read required")
	}
	sig = s.Signature
	s.Signature = ""
	if !guestRetirementVerify(e.Statement.ObservationPublicKey, sig, s) {
		return fmt.Errorf("original runtime snapshot signature refused")
	}
	return nil
}
