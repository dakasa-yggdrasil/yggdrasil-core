//go:build linux && nativequalification

package capacitynativeqemu

import (
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

type enrollmentConfirmJoinFixture struct {
	realm      *Realm
	grant      model.CapacityMutationGrant
	pre        model.CapacityGuestOriginalProvisioningPreregistration
	enrollment model.CapacityGuestOriginalProvisioningReceipt
	proof      model.CapacityMutationProof
	original   IndependentReturn
	fresh      IndependentReturn
	disk       OriginalDisk
	deadline   time.Time
}

// Synthetic records exercise only pure joins/merging. They are never passed
// to Observe, Publish, a store, or a native-success authority assertion.
func enrollmentConfirmFixture() enrollmentConfirmJoinFixture {
	base := time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC)
	id := "11111111-1111-4111-8111-111111111111"
	f := enrollmentConfirmJoinFixture{realm: &Realm{}}
	f.realm.Profile = model.CapacityGuestProtectedProfileManifest{Profile: capacity.GuestQualificationProfile, MutationBinding: "native-vm", OriginalProvisioningBudgetSeconds: 420, OriginalProvisioningStepID: "original-native-qemu-create"}
	f.realm.Request = SourceRequest{NativeProvider: "native-qemu", SourceCommit: strings.Repeat("a", 40), CreatorSourceSHA256: digest([]byte("creator-source")), OriginalContextDeadline: base.Add(600 * time.Second), Slots: []SlotRequest{{Slot: 1, ResourceID: id}, {Slot: 2}}}
	f.realm.QEMUBinarySHA256 = digest([]byte("qemu-binary"))
	f.grant = model.CapacityMutationGrant{GrantID: id, BindingName: "native-vm", Slot: 1, Capability: "ensure_server", RequestSHA256: digest([]byte("request")), IntegrationInstanceID: id, ScopeChecksum: digest([]byte("scope")), ProfileName: f.realm.Profile.Profile, ExpiresAt: base.Add(60 * time.Second)}
	f.pre = model.CapacityGuestOriginalProvisioningPreregistration{
		Schema: capacity.GuestPreregistrationSchema, PreregistrationID: id, BindingName: "guest-1", OriginalCreateGrantID: id,
		OriginalCreateRequestSHA256: f.grant.RequestSHA256, NonceSHA256: digest([]byte("nonce")), ProfileManifestSHA256: capacity.GuestRetirementSHA(f.realm.Profile),
		PolicyID: id, PolicyChecksum: digest([]byte("policy")), WorkflowID: id, WorkflowChecksum: digest([]byte("workflow")),
		OriginalWorkflowStepID: f.realm.Profile.OriginalProvisioningStepID, OriginalWorkflowStepTimeoutSeconds: 600,
		OriginalWorkflowContextDeadline: f.realm.Request.OriginalContextDeadline, CoreSourceCommit: strings.Repeat("b", 40),
		Generation: 1, Fence: 1, LeaseOwner: id, ExecutorID: id, Slot: 1, OriginalDeadline: base.Add(420 * time.Second), ReservedAt: base,
	}
	f.disk = OriginalDisk{Device: 7, Inode: 9}
	process := Process{PID: 100, PPID: 99, StartTicks: 10, StatSHA256: digest([]byte("stat"))}
	creator := CreatorReturn{Provider: "native-qemu", Slot: 1, ResourceID: id, QEMU: process, OriginalCreateReturnedAt: base.Add(time.Second), OriginalSourceCommit: f.realm.Request.SourceCommit, CreatorSourceSHA256: f.realm.Request.CreatorSourceSHA256}
	f.original = IndependentReturn{Schema: "core_independent_original_qemu_read_v1", Original: creator, OriginalCreatorSHA256: digest([]byte("creator-wire")), Before: process, After: process, QMPPeerPID: 100, ExecutableSHA256: f.realm.QEMUBinarySHA256, CommandLineSHA256: digest([]byte("command-line")), OriginalDisk: f.disk, OriginalDiskFD: 4, UUID: UUIDRead{UUID: id}, Status: StatusRead{Running: true, Status: "running"}, CloseReturnedAt: base.Add(2 * time.Second)}
	f.proof = model.CapacityMutationProof{GrantID: id, BindingName: f.grant.BindingName, Slot: 1, ResourceID: id, ResourceCreatedAt: creator.OriginalCreateReturnedAt.Format(time.RFC3339Nano), RequestSHA256: f.grant.RequestSHA256, ObservedAt: f.original.CloseReturnedAt, ReceiptRef: "original-native-qemu:" + capacity.GuestRetirementSHA(f.original), OwnerVerified: true, SpecVerified: true, ActionIDs: []string{"qemu-original-create:" + capacity.GuestRetirementSHA(creator)}, ActionsTerminal: true, ActionsSuccessful: true, ObservedCreationGrantID: id}
	f.enrollment = model.CapacityGuestOriginalProvisioningReceipt{PreregistrationID: id, OriginalProvisioningSHA256: digest([]byte("registration")), RecordedAt: base.Add(70 * time.Second), Enrollment: model.CapacityGuestRetirementEnrollment{Signature: "pure-join-only", Statement: model.CapacityGuestRetirementEnrollmentStatement{BindingName: f.pre.BindingName, SourceClass: "native_qemu_qualification", ProvisionerSourceCommit: f.realm.Request.SourceCommit, CoreAuthoritySourceCommit: f.pre.CoreSourceCommit, OriginalNativeResultSHA256: digest([]byte("result")), IssuedAt: base.Add(69 * time.Second), Tuple: model.CapacityGuestNativeTuple{Provider: "native-qemu", InstanceID: id, ScopeChecksum: f.grant.ScopeChecksum, Profile: f.grant.ProfileName, Slot: 1, ResourceID: id, CreatedAt: f.proof.ResourceCreatedAt}}}}
	f.fresh = f.original
	f.fresh.StartedAt = base.Add(71 * time.Second)
	f.fresh.OriginalDiskReadReturnedAt = base.Add(72 * time.Second)
	f.fresh.OriginalDiskDirectoryCloseReturnedAt = base.Add(73 * time.Second)
	f.fresh.ReadReturnedAt = base.Add(74 * time.Second)
	f.fresh.CloseReturnedAt = base.Add(75 * time.Second)
	f.deadline = base.Add(76 * time.Second)
	return f
}

func TestEnrollmentConfirmInputsRejectsChangedLineageAndDeadline(t *testing.T) {
	for _, name := range []string{"same-original", "shorter-original-context", "grant", "request", "slot", "provider", "source", "disk", "missing-receipt", "enrollment-signature", "enrollment-source", "enrollment-core-source", "enrollment-id", "enrollment-binding", "enrollment-resource", "enrollment-created", "enrollment-instance", "enrollment-scope", "enrollment-before-create", "enrollment-at-deadline", "action", "action-success", "creation-grant", "proof-time", "extended-context", "rewritten-original-deadline", "extended-workflow-context"} {
		t.Run(name, func(t *testing.T) {
			f := enrollmentConfirmFixture()
			switch name {
			case "shorter-original-context":
				f.pre.OriginalWorkflowContextDeadline = f.pre.ReservedAt.Add(400 * time.Second)
				f.pre.OriginalDeadline = f.pre.OriginalWorkflowContextDeadline
			case "grant":
				f.grant.GrantID = "foreign"
			case "request":
				f.grant.RequestSHA256 = digest([]byte("foreign"))
			case "slot":
				f.grant.Slot = 2
			case "provider":
				f.original.Original.Provider = "foreign"
			case "source":
				f.original.Original.OriginalSourceCommit = strings.Repeat("c", 40)
			case "disk":
				f.disk.Inode++
			case "missing-receipt":
				f.enrollment = model.CapacityGuestOriginalProvisioningReceipt{}
			case "enrollment-signature":
				f.enrollment.Enrollment.Signature = ""
			case "enrollment-source":
				f.enrollment.Enrollment.Statement.ProvisionerSourceCommit = strings.Repeat("c", 40)
			case "enrollment-core-source":
				f.enrollment.Enrollment.Statement.CoreAuthoritySourceCommit = strings.Repeat("c", 40)
			case "enrollment-id":
				f.enrollment.PreregistrationID = "foreign"
			case "enrollment-binding":
				f.enrollment.Enrollment.Statement.BindingName = f.grant.BindingName
			case "enrollment-resource":
				f.enrollment.Enrollment.Statement.Tuple.ResourceID = "foreign"
			case "enrollment-created":
				f.enrollment.Enrollment.Statement.Tuple.CreatedAt = "foreign"
			case "enrollment-instance":
				f.enrollment.Enrollment.Statement.Tuple.InstanceID = "foreign"
			case "enrollment-scope":
				f.enrollment.Enrollment.Statement.Tuple.ScopeChecksum = "foreign"
			case "enrollment-before-create":
				f.enrollment.Enrollment.Statement.IssuedAt = f.original.CloseReturnedAt.Add(-time.Second)
			case "enrollment-at-deadline":
				f.enrollment.RecordedAt = f.deadline
			case "action":
				f.proof.ActionIDs[0] = "foreign"
			case "action-success":
				f.proof.ActionsSuccessful = false
			case "creation-grant":
				f.proof.ObservedCreationGrantID = "foreign"
			case "proof-time":
				f.proof.ObservedAt = f.fresh.CloseReturnedAt
			case "extended-context":
				f.deadline = f.pre.OriginalDeadline.Add(time.Nanosecond)
			case "rewritten-original-deadline":
				f.pre.OriginalDeadline = f.pre.OriginalDeadline.Add(time.Second)
			case "extended-workflow-context":
				f.pre.OriginalWorkflowContextDeadline = f.realm.Request.OriginalContextDeadline.Add(time.Second)
			}
			err := f.realm.enrollmentConfirmInputs(f.deadline, f.grant, f.pre, f.enrollment, f.proof, f.original, f.disk)
			if (err == nil) != (name == "same-original" || name == "shorter-original-context") {
				t.Fatalf("input join %s: %v", name, err)
			}
		})
	}
}

func TestEnrollmentConfirmNativeJoinRejectsForeignAndOldObservations(t *testing.T) {
	for _, name := range []string{"same-original", "creator", "creator-hash", "before-process", "after-process", "peer", "executable", "command", "owned-disk", "source-disk", "uuid", "stopped", "disk-fd", "before-enrollment", "disk-before-start", "disk-close-before-read", "read-before-disk-close", "close-before-read", "at-deadline", "wire"} {
		t.Run(name, func(t *testing.T) {
			f := enrollmentConfirmFixture()
			switch name {
			case "creator":
				f.fresh.Original.ResourceID = "foreign"
			case "creator-hash":
				f.fresh.OriginalCreatorSHA256 = digest([]byte("foreign"))
			case "before-process":
				f.fresh.Before.StartTicks++
			case "after-process":
				f.fresh.After.PPID++
			case "peer":
				f.fresh.QMPPeerPID++
			case "executable":
				f.fresh.ExecutableSHA256 = digest([]byte("foreign"))
			case "command":
				f.fresh.CommandLineSHA256 = digest([]byte("foreign"))
			case "owned-disk":
				f.disk.Inode++
			case "source-disk":
				f.fresh.OriginalDisk.Device++
			case "uuid":
				f.fresh.UUID.UUID = "foreign"
			case "stopped":
				f.fresh.Status.Running = false
			case "disk-fd":
				f.fresh.OriginalDiskFD = -1
			case "before-enrollment":
				f.fresh.StartedAt = f.enrollment.RecordedAt.Add(-time.Nanosecond)
			case "disk-before-start":
				f.fresh.OriginalDiskReadReturnedAt = f.fresh.StartedAt.Add(-time.Nanosecond)
			case "disk-close-before-read":
				f.fresh.OriginalDiskDirectoryCloseReturnedAt = f.fresh.OriginalDiskReadReturnedAt.Add(-time.Nanosecond)
			case "read-before-disk-close":
				f.fresh.ReadReturnedAt = f.fresh.OriginalDiskDirectoryCloseReturnedAt.Add(-time.Nanosecond)
			case "close-before-read":
				f.fresh.CloseReturnedAt = f.fresh.ReadReturnedAt.Add(-time.Nanosecond)
			case "at-deadline":
				f.fresh.CloseReturnedAt = f.deadline
			}
			wire, err := json.Marshal(f.fresh)
			if err != nil {
				t.Fatal(err)
			}
			if name == "wire" {
				wire = append(wire, ' ')
			}
			proof, err := mergeEnrollmentConfirmProof(f.proof, f.original, f.fresh, f.disk, f.enrollment.RecordedAt, f.deadline, wire)
			if (err == nil) != (name == "same-original") {
				t.Fatalf("native join %s: %v", name, err)
			}
			if err != nil && !reflect.DeepEqual(proof, model.CapacityMutationProof{}) {
				t.Fatal("refused join returned a proof")
			}
		})
	}
}

func TestEnrollmentConfirmMergePreservesOriginalActionAndCreationLineage(t *testing.T) {
	f := enrollmentConfirmFixture()
	before, err := json.Marshal(f.proof)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := json.Marshal(f.fresh)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := mergeEnrollmentConfirmProof(f.proof, f.original, f.fresh, f.disk, f.enrollment.RecordedAt, f.deadline, wire)
	if err != nil {
		t.Fatal(err)
	}
	if !proof.ObservedAt.Equal(f.fresh.CloseReturnedAt) || proof.ReceiptRef != "original-native-qemu-enrollment-confirm:"+digest(wire) || !proof.OwnerVerified || !proof.SpecVerified {
		t.Fatal("confirmation is not tied to retained fresh return")
	}
	if capacity.Fresh(f.proof.ObservedAt, f.fresh.CloseReturnedAt, 30) || !capacity.Fresh(proof.ObservedAt, f.fresh.CloseReturnedAt, 30) {
		t.Fatal("original proof must remain stale under the unchanged 30-second freshness rule")
	}
	proof.ObservedAt, proof.ReceiptRef = f.proof.ObservedAt, f.proof.ReceiptRef
	proof.OwnerVerified, proof.SpecVerified = f.proof.OwnerVerified, f.proof.SpecVerified
	if !reflect.DeepEqual(proof, f.proof) {
		t.Fatal("refresh changed action or creation lineage")
	}
	after, err := json.Marshal(f.proof)
	if err != nil || string(before) != string(after) {
		t.Fatal("original proof mutated")
	}
	if f.grant.ExpiresAt.After(f.enrollment.RecordedAt) {
		t.Fatal("fixture must keep grant expiry separate from observation freshness")
	}
}

func TestRefreshEnrollmentProofRejectsUnboundedOrUnownedInput(t *testing.T) {
	for _, name := range []string{"unbounded", "canceled", "unowned"} {
		t.Run(name, func(t *testing.T) {
			f := enrollmentConfirmFixture()
			ctx := context.Background()
			if name != "unbounded" {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, time.Second)
				defer cancel()
				if name == "canceled" {
					cancel()
				}
			}
			proof, err := f.realm.RefreshEnrollmentProof(ctx, f.grant, f.pre, f.enrollment, f.proof)
			if err == nil || !reflect.DeepEqual(proof, model.CapacityMutationProof{}) {
				t.Fatal("unbounded or unowned input reached native authority")
			}
		})
	}
}
