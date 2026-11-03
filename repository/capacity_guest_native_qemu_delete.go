package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
	"reflect"
	"time"
)

type GuestNativeQEMUOriginalDisk struct {
	Device uint64 `json:"device"`
	Inode  uint64 `json:"inode"`
}
type GuestNativeQEMUOriginalDeleteReturn struct {
	Schema                           string                      `json:"schema"`
	Scope                            string                      `json:"scope"`
	GrantID                          string                      `json:"grant_id"`
	AttemptID                        string                      `json:"attempt_id"`
	ResourceID                       string                      `json:"resource_id"`
	CreatorOriginalSHA256            string                      `json:"creator_original_sha256"`
	OriginalDisk                     GuestNativeQEMUOriginalDisk `json:"original_disk"`
	OriginalUnlinkCalledAt           time.Time                   `json:"original_unlink_called_at"`
	OriginalUnlinkReturnedAt         time.Time                   `json:"original_unlink_returned_at"`
	OriginalDirectorySyncReturnedAt  time.Time                   `json:"original_directory_sync_returned_at"`
	OriginalAbsenceReturnedAt        time.Time                   `json:"original_absence_returned_at"`
	OriginalDirectoryCloseReturnedAt time.Time                   `json:"original_directory_close_returned_at"`
}

// This private readback has no billing, invoice, provider-label or exposure
// fields. It joins only the QEMU original authorized disk action and a new
// independent anchored Fstatat/ENOENT + directory Close return.
type GuestNativeQEMUDeleteReadback struct {
	Schema                           string                              `json:"schema"`
	Scope                            string                              `json:"scope"`
	CoreSourceCommit                 string                              `json:"core_source_commit"`
	GuestSourceCommit                string                              `json:"guest_source_commit"`
	GrantID                          string                              `json:"grant_id"`
	GrantState                       string                              `json:"grant_state"`
	AttemptID                        string                              `json:"attempt_id"`
	ActionID                         string                              `json:"action_id"`
	ResourceID                       string                              `json:"resource_id"`
	ResourceCreatedAt                string                              `json:"resource_created_at"`
	OriginalDelete                   GuestNativeQEMUOriginalDeleteReturn `json:"original_delete"`
	OriginalDeleteSHA256             string                              `json:"original_delete_sha256"`
	OriginalObservationStartedAt     time.Time                           `json:"original_observation_started_at"`
	OriginalAbsenceErrorClass        string                              `json:"original_absence_error_class"`
	OriginalAbsenceReturnedAt        time.Time                           `json:"original_absence_returned_at"`
	OriginalDirectoryCloseReturnedAt time.Time                           `json:"original_directory_close_returned_at"`
}

func GuestNativeQEMUDeleteProof(p model.CapacityPolicySpec, b model.CapacityMutationBinding, r model.CapacityMutationReceipt, observed GuestNativeQEMUDeleteReadback, now time.Time, receiptRef string) (model.CapacityMutationProof, error) {
	var out model.CapacityMutationProof
	g := r.Grant
	d := observed.OriginalDelete
	if p.GuestRetirementBinding == nil || !capacity.GuestOriginalProfileEnabled(p, *p.GuestRetirementBinding, "native-qemu") || p.GuestRetirementBinding.EvidenceClass != "native_qemu_qualification" || g.CompensationOf != "" || g.Capability != b.DestroyCapability || g.BindingName != b.Name || g.ScopeChecksum != b.ScopeChecksum || g.IntegrationInstanceID != b.IntegrationInstanceID || g.ProfileName != b.ProfileName || g.Slot != 2 || g.Slot <= b.ProtectedSlots || (g.State != "settled" && g.State != "confirmed") || r.Outcome != "accepted" || !r.TransportCompleted || !r.AuxiliaryInventoryComplete || len(r.AuxiliaryResources) != 0 || len(r.NextActionIDs) != 0 || r.ActionID == "" || observed.Schema != "core_original_native_qemu_disk_absence_readback_v1" || observed.Scope != "same_original_native_qemu_authorized_disk_only_no_physical_provider_or_billing_claim" || observed.CoreSourceCommit != p.GuestRetirementBinding.CoreAuthoritySourceCommit || observed.GuestSourceCommit != p.GuestRetirementBinding.GuestSourceCommit || observed.GrantID != g.GrantID || observed.GrantState != g.State || observed.AttemptID != r.AttemptID || observed.ActionID != r.ActionID || observed.ResourceID != g.ExpectedResourceID || observed.ResourceCreatedAt != g.ExpectedResourceCreatedAt || r.ResourceID != observed.ResourceID || r.ResourceCreatedAt != observed.ResourceCreatedAt || d.Schema != "core_original_native_qemu_disk_delete_v1" || d.Scope != "original_source_owned_native_qemu_disk_only_not_physical_provider_or_billing" || d.GrantID != g.GrantID || d.AttemptID != r.AttemptID || d.ResourceID != observed.ResourceID || !capacity.ValidDigest(d.CreatorOriginalSHA256) || d.OriginalDisk.Device == 0 || d.OriginalDisk.Inode == 0 || observed.OriginalDeleteSHA256 != capacity.GuestRetirementSHA(d) || observed.ActionID != "qemu-original-disk-unlink:"+observed.OriginalDeleteSHA256 || d.OriginalUnlinkCalledAt.IsZero() || d.OriginalUnlinkReturnedAt.Before(d.OriginalUnlinkCalledAt) || d.OriginalDirectorySyncReturnedAt.Before(d.OriginalUnlinkReturnedAt) || d.OriginalAbsenceReturnedAt.Before(d.OriginalDirectorySyncReturnedAt) || d.OriginalDirectoryCloseReturnedAt.Before(d.OriginalAbsenceReturnedAt) || observed.OriginalObservationStartedAt.Before(d.OriginalDirectoryCloseReturnedAt) || observed.OriginalAbsenceReturnedAt.Before(observed.OriginalObservationStartedAt) || observed.OriginalDirectoryCloseReturnedAt.Before(observed.OriginalAbsenceReturnedAt) || observed.OriginalDirectoryCloseReturnedAt.After(now) || !capacity.Fresh(observed.OriginalDirectoryCloseReturnedAt, now, p.MaxEvidenceAgeSeconds) || observed.OriginalAbsenceErrorClass != "ENOENT" || receiptRef == "" || len(receiptRef) > 2048 {
		return out, ErrCapacityConflict
	}
	created, err := time.Parse(time.RFC3339Nano, observed.ResourceCreatedAt)
	if err != nil || created.UTC().Format(time.RFC3339Nano) != observed.ResourceCreatedAt || d.OriginalUnlinkCalledAt.Before(created) {
		return out, ErrCapacityConflict
	}
	out = model.CapacityMutationProof{GrantID: g.GrantID, BindingName: b.Name, Slot: g.Slot, ResourceID: observed.ResourceID, ResourceCreatedAt: observed.ResourceCreatedAt, RequestSHA256: g.RequestSHA256, ObservedAt: observed.OriginalDirectoryCloseReturnedAt, ReceiptRef: receiptRef, OwnerVerified: true, SpecVerified: true, ResourceAbsent: true, ActionIDs: []string{r.ActionID}, ActionsTerminal: true, ActionsSuccessful: true, AuxiliaryAbsent: []model.CapacityMutationAuxiliaryResource{}}
	return out, nil
}

func (s CapacityStore) RecordGuestNativeQEMUDeleteReadback(ctx context.Context, policy model.Manifest, generation, fence int64, owner string, observed GuestNativeQEMUDeleteReadback) error {
	return s.mutationTransaction(ctx, policy, true, generation, fence, owner, func(tx *sql.Tx, p model.CapacityPolicySpec, _ model.CapacityIntent, now time.Time) error {
		if !capacity.GuestOriginalNativeQEMUProviderEnabled("native-qemu") || observed.CoreSourceCommit != capacity.CurrentGuestCoreSource() {
			return ErrCapacityConflict
		}
		var raw []byte
		if err := tx.QueryRowContext(ctx, `SELECT grant_record FROM public.capacity_mutation_grants WHERE id=$1`, observed.GrantID).Scan(&raw); err != nil {
			return err
		}
		var original capacityMutationRecord
		if json.Unmarshal(raw, &original) != nil || original.Settlement == nil || original.WorkflowID != s.WorkflowID || original.PolicyID != policy.ID || original.PolicyChecksum != policy.Checksum {
			return ErrCapacityConflict
		}
		settlement := original.Settlement
		r := model.CapacityMutationReceipt{Grant: original.Grant, AttemptID: original.AttemptID, Outcome: settlement.Outcome, TransportCompleted: settlement.TransportCompleted, ResourceID: settlement.ResourceID, ResourceCreatedAt: settlement.ResourceCreatedAt, ActionID: settlement.ActionID, NextActionIDs: settlement.NextActionIDs, AuxiliaryResources: settlement.AuxiliaryResources, AuxiliaryInventoryComplete: settlement.AuxiliaryInventoryComplete}
		if _, err := GuestNativeQEMUDeleteProof(p, original.Binding, r, observed, now, "original-native-qemu-disk-readback"); err != nil {
			return err
		}
		wire, err := json.Marshal(observed)
		if err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO public.capacity_vm_retirement_native_readbacks(id,destroy_grant_id,observation_sha256,original_observation_record,recorded_at,original_wire) VALUES($1,$2,$3,$4::jsonb,$5,$6)`, uuid.New(), observed.GrantID, capacity.BusinessCreationSHA256(wire), string(wire), now, wire)
		return err
	})
}

func guestNativeQEMUConfirmedDelete(p model.CapacityPolicySpec, original capacityMutationRecord, stored GuestRetirementOriginal, wire []byte, proof model.CapacityMutationProof, now time.Time) error {
	var observed GuestNativeQEMUDeleteReadback
	if capacity.DecodeGuestLifecycle(wire, &observed) != nil || observed.OriginalDelete.CreatorOriginalSHA256 == "" || !observed.OriginalDelete.OriginalUnlinkCalledAt.Before(stored.Request.Intent.OriginalDeadline) || !observed.OriginalDirectoryCloseReturnedAt.Before(stored.Request.Intent.OriginalDeadline) {
		return ErrCapacityConflict
	}
	r := model.CapacityMutationReceipt{Grant: original.Grant, AttemptID: original.AttemptID, Outcome: original.Settlement.Outcome, TransportCompleted: original.Settlement.TransportCompleted, ResourceID: original.Settlement.ResourceID, ResourceCreatedAt: original.Settlement.ResourceCreatedAt, ActionID: original.Settlement.ActionID, NextActionIDs: original.Settlement.NextActionIDs, AuxiliaryResources: original.Settlement.AuxiliaryResources, AuxiliaryInventoryComplete: original.Settlement.AuxiliaryInventoryComplete}
	expected, err := GuestNativeQEMUDeleteProof(p, original.Binding, r, observed, now, proof.ReceiptRef)
	if err != nil || !reflect.DeepEqual(expected, proof) {
		return ErrCapacityConflict
	}
	return nil
}
