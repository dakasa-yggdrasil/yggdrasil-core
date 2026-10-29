//go:build linux && nativequalification

package capacitynativeqemu

import (
	"context"
	"path/filepath"
	"reflect"
	"strings"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

// EnrollmentConfirmProofLineage retains both typed proofs so custody can join
// the original settlement/witness to confirmation without rewriting either.
type EnrollmentConfirmProofLineage struct {
	Schema                  string                      `json:"schema"`
	CoreSource              string                      `json:"core_source"`
	Slot                    int                         `json:"slot"`
	GrantID                 string                      `json:"grant_id"`
	PreregistrationID       string                      `json:"preregistration_id"`
	EnrollmentReceiptSHA256 string                      `json:"enrollment_receipt_sha256"`
	EnrollmentRecordedAt    time.Time                   `json:"enrollment_recorded_at"`
	OriginalProof           model.CapacityMutationProof `json:"original_proof"`
	OriginalProofSHA256     string                      `json:"original_proof_sha256"`
	ConfirmationProof       model.CapacityMutationProof `json:"confirmation_proof"`
	ConfirmationProofSHA256 string                      `json:"confirmation_proof_sha256"`
	NativeReadSHA256        string                      `json:"native_read_sha256"`
}

func postlossConfirmationRetentionRequired(nativeCase string, slot int) bool {
	return PostlossSourceCase(nativeCase) && slot == SourceFailureSlot(nativeCase)
}

// RefreshEnrollmentProof observes the SAME source-owned native create after
// its enrollment receipt. It preserves the create proof/action lineage and
// original deadline, and does not publish the post-confirm Enrolled stage.
func (r *Realm) RefreshEnrollmentProof(ctx context.Context, grant model.CapacityMutationGrant, pre model.CapacityGuestOriginalProvisioningPreregistration, enrollment model.CapacityGuestOriginalProvisioningReceipt, originalProof model.CapacityMutationProof, retain func(context.Context, model.CapacityMutationProof, []byte) error) (model.CapacityMutationProof, error) {
	var empty model.CapacityMutationProof
	deadline, bounded := ctx.Deadline()
	if r == nil || !bounded || ctx.Err() != nil || grant.Slot < 1 || grant.Slot > 2 || len(r.Request.Slots) != 2 {
		return empty, ErrOriginalUnknown
	}
	r.mu.Lock()
	original, originalOK := r.originals[grant.Slot]
	ownedPre, preOK := r.preregistrations[grant.Slot]
	disk, diskOK := r.disks[grant.Slot]
	r.mu.Unlock()
	if !originalOK || !preOK || !diskOK || ownedPre != pre || pre.CoreSourceCommit != capacity.CurrentGuestCoreSource() || r.enrollmentConfirmInputs(deadline, grant, pre, enrollment, originalProof, original, disk) != nil {
		return empty, ErrOriginalUnknown
	}
	// The actual native read, command verification and immutable publication
	// share this child; none can outlive the caller's original provisioning cap.
	read, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	readDeadline, _ := read.Deadline()
	fresh, err := Observe(read, SlotDirectory(r.PrivateDirectory, grant.Slot), original.Original, r.QEMUBinarySHA256)
	if err != nil || r.verifyFixedCommand(read, grant.Slot, fresh) != nil {
		return empty, ErrOriginalUnknown
	}
	fresh.OriginalCreatorSHA256 = original.OriginalCreatorSHA256
	if joinEnrollmentConfirmNative(original, fresh, disk, enrollment.RecordedAt, readDeadline) != nil {
		return empty, ErrOriginalUnknown
	}
	nativeWire, err := Publish(read, filepath.Join(SlotDirectory(r.PrivateDirectory, grant.Slot), "enrollment-confirm-native-read.json"), fresh)
	if err != nil {
		return empty, err
	}
	proof, err := mergeEnrollmentConfirmProof(originalProof, original, fresh, disk, enrollment.RecordedAt, readDeadline, nativeWire)
	if err != nil {
		return empty, err
	}
	// Only the source owner has the real joined fresh read and exact proof.
	if postlossConfirmationRetentionRequired(r.Request.NativeCase, grant.Slot) {
		if retain == nil || retain(read, proof, nativeWire) != nil {
			return empty, ErrOriginalUnknown
		}
	}
	lineage := EnrollmentConfirmProofLineage{
		Schema: "core_original_enrollment_confirm_proof_lineage_v1", CoreSource: capacity.CurrentGuestCoreSource(),
		Slot: grant.Slot, GrantID: grant.GrantID, PreregistrationID: pre.PreregistrationID,
		EnrollmentReceiptSHA256: capacity.GuestRetirementSHA(enrollment), EnrollmentRecordedAt: enrollment.RecordedAt,
		OriginalProof: originalProof, OriginalProofSHA256: capacity.GuestRetirementSHA(originalProof),
		ConfirmationProof: proof, ConfirmationProofSHA256: capacity.GuestRetirementSHA(proof), NativeReadSHA256: digest(nativeWire),
	}
	if _, err = Publish(read, filepath.Join(SlotDirectory(r.PrivateDirectory, grant.Slot), "enrollment-confirm-proof-lineage.json"), lineage); err != nil {
		return empty, err
	}
	if read.Err() != nil || !time.Now().UTC().Before(readDeadline) {
		return empty, ErrOriginalUnknown
	}
	return proof, nil
}

func (r *Realm) enrollmentConfirmInputs(deadline time.Time, grant model.CapacityMutationGrant, pre model.CapacityGuestOriginalProvisioningPreregistration, enrollment model.CapacityGuestOriginalProvisioningReceipt, proof model.CapacityMutationProof, original IndependentReturn, disk OriginalDisk) error {
	creator := original.Original
	if !capacity.GuestOriginalProvisioningDeadlineMatches(pre, r.Profile) || deadline.After(pre.OriginalDeadline) || pre.OriginalWorkflowContextDeadline.After(r.Request.OriginalContextDeadline) || deadline.After(r.Request.OriginalContextDeadline) || grant.Capability != "ensure_server" || grant.GrantID != pre.OriginalCreateGrantID || grant.RequestSHA256 != pre.OriginalCreateRequestSHA256 || grant.Slot != pre.Slot || grant.BindingName != r.Profile.MutationBinding || grant.ProfileName != r.Profile.Profile {
		return ErrOriginalUnknown
	}
	if creator.Slot != grant.Slot || creator.Provider != "native-qemu" || creator.Provider != r.Request.NativeProvider || creator.ResourceID != r.Request.Slots[grant.Slot-1].ResourceID || creator.OriginalSourceCommit != r.Request.SourceCommit || creator.CreatorSourceSHA256 != r.Request.CreatorSourceSHA256 || original.ExecutableSHA256 != r.QEMUBinarySHA256 || !validSHA(original.OriginalCreatorSHA256) || disk.Device == 0 || disk.Inode == 0 || original.OriginalDisk != disk {
		return ErrOriginalUnknown
	}
	// This is exactly Create's returned proof, not a caller-selected action
	// list or a previous refreshed observation. The original source stays intact.
	expected := model.CapacityMutationProof{
		GrantID: grant.GrantID, BindingName: grant.BindingName, Slot: grant.Slot,
		ResourceID: creator.ResourceID, ResourceCreatedAt: creator.OriginalCreateReturnedAt.UTC().Format(time.RFC3339Nano),
		RequestSHA256: grant.RequestSHA256, ObservedAt: original.CloseReturnedAt,
		ReceiptRef: "original-native-qemu:" + capacity.GuestRetirementSHA(original), OwnerVerified: true, SpecVerified: true,
		ActionIDs: []string{"qemu-original-create:" + capacity.GuestRetirementSHA(creator)}, ActionsTerminal: true,
		ActionsSuccessful: true, ObservedCreationGrantID: grant.GrantID,
	}
	if !reflect.DeepEqual(proof, expected) {
		return ErrOriginalUnknown
	}
	statement, tuple := enrollment.Enrollment.Statement, enrollment.Enrollment.Statement.Tuple
	if enrollment.PreregistrationID != pre.PreregistrationID || !validSHA(enrollment.OriginalProvisioningSHA256) || enrollment.Enrollment.Signature == "" || statement.BindingName != pre.BindingName || statement.SourceClass != "native_qemu_qualification" || statement.ProvisionerSourceCommit != r.Request.SourceCommit || statement.CoreAuthoritySourceCommit != pre.CoreSourceCommit || !validSHA(statement.OriginalNativeResultSHA256) || tuple.Provider != creator.Provider || tuple.InstanceID != grant.IntegrationInstanceID || tuple.ScopeChecksum != grant.ScopeChecksum || tuple.Profile != grant.ProfileName || tuple.Slot != grant.Slot || tuple.ResourceID != proof.ResourceID || tuple.CreatedAt != proof.ResourceCreatedAt {
		return ErrOriginalUnknown
	}
	if statement.IssuedAt.IsZero() || statement.IssuedAt.Before(original.CloseReturnedAt) || enrollment.RecordedAt.Before(statement.IssuedAt) || !enrollment.RecordedAt.Before(deadline) {
		return ErrOriginalUnknown
	}
	return nil
}

// This pure join checks relationships only; only Observe supplies native
// authority. Tests cannot turn synthetic records into a successful native read.
func joinEnrollmentConfirmNative(original, fresh IndependentReturn, disk OriginalDisk, recordedAt, deadline time.Time) error {
	if fresh.Schema != original.Schema || !reflect.DeepEqual(fresh.Original, original.Original) || fresh.OriginalCreatorSHA256 != original.OriginalCreatorSHA256 || !sameProcess(fresh.Before, original.After) || !sameProcess(fresh.After, original.After) || fresh.QMPPeerPID != original.QMPPeerPID || fresh.ExecutableSHA256 != original.ExecutableSHA256 || fresh.CommandLineSHA256 != original.CommandLineSHA256 || fresh.OriginalDisk != disk || fresh.OriginalDisk != original.OriginalDisk || fresh.OriginalDiskFD < 0 || fresh.UUID != original.UUID || strings.ToLower(fresh.UUID.UUID) != original.Original.ResourceID || fresh.Status.SingleStep || !fresh.Status.Running || fresh.Status.Status != "running" {
		return ErrOriginalUnknown
	}
	if recordedAt.IsZero() || deadline.IsZero() || fresh.StartedAt.Before(recordedAt) || fresh.StartedAt.Before(original.CloseReturnedAt) || fresh.OriginalDiskReadReturnedAt.Before(fresh.StartedAt) || fresh.OriginalDiskDirectoryCloseReturnedAt.Before(fresh.OriginalDiskReadReturnedAt) || fresh.ReadReturnedAt.Before(fresh.OriginalDiskDirectoryCloseReturnedAt) || fresh.CloseReturnedAt.Before(fresh.ReadReturnedAt) || !fresh.CloseReturnedAt.Before(deadline) {
		return ErrOriginalUnknown
	}
	return nil
}

func mergeEnrollmentConfirmProof(originalProof model.CapacityMutationProof, original, fresh IndependentReturn, disk OriginalDisk, recordedAt, deadline time.Time, nativeWire []byte) (model.CapacityMutationProof, error) {
	if joinEnrollmentConfirmNative(original, fresh, disk, recordedAt, deadline) != nil || digest(nativeWire) != capacity.GuestRetirementSHA(fresh) {
		return model.CapacityMutationProof{}, ErrOriginalUnknown
	}
	proof := originalProof
	proof.ObservedAt = fresh.CloseReturnedAt
	proof.ReceiptRef = "original-native-qemu-enrollment-confirm:" + digest(nativeWire)
	proof.OwnerVerified, proof.SpecVerified = true, true
	return proof, nil
}
