//go:build linux && nativequalification

package repository

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"strings"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

// This projection compares only identities emitted by the already source-owned
// QEMU observer; the raw original and refreshed reads remain immutable.
type postlossConfirmRead struct {
	Schema      string                 `json:"schema"`
	CreatorSHA  string                 `json:"original_creator_sha256"`
	Original    json.RawMessage        `json:"original"`
	Before      GuestNativeQEMUProcess `json:"before"`
	After       GuestNativeQEMUProcess `json:"after"`
	Peer        int32                  `json:"qmp_peer_pid"`
	Executable  string                 `json:"executable_sha256"`
	CommandLine string                 `json:"command_line_sha256"`
	Disk        json.RawMessage        `json:"original_disk"`
	DiskFD      int                    `json:"original_disk_fd"`
	DiskRead    time.Time              `json:"original_disk_read_returned_at"`
	DiskClose   time.Time              `json:"original_disk_directory_close_returned_at"`
	UUID        struct {
		UUID string `json:"UUID"`
	} `json:"uuid"`
	Status struct {
		Running    bool   `json:"running"`
		SingleStep bool   `json:"singlestep"`
		Status     string `json:"status"`
	} `json:"status"`
	Started time.Time `json:"started_at"`
	Read    time.Time `json:"read_returned_at"`
	Closed  time.Time `json:"close_returned_at"`
}

func postlossSameProcess(a, b GuestNativeQEMUProcess) bool {
	return a.PID == b.PID && a.PPID == b.PPID && a.StartTicks == b.StartTicks
}

func postlossConfirmationJoin(originalWire, freshWire []byte, witness model.CapacityGuestOriginalCreateWitness, receipt model.CapacityGuestOriginalProvisioningReceipt, grant model.CapacityMutationGrant, proof model.CapacityMutationProof, now time.Time) bool {
	var original, fresh postlossConfirmRead
	if witness.SourceObservation == nil || originalWire == nil || freshWire == nil {
		return false
	}
	if json.Unmarshal(originalWire, &original) != nil || json.Unmarshal(freshWire, &fresh) != nil || original.CreatorSHA != witness.SourceObservation.OriginalCreatorSHA256 || original.Schema != "core_independent_original_qemu_read_v1" || fresh.Schema != original.Schema || !bytes.Equal(original.Original, fresh.Original) || !capacity.ValidDigest(original.CreatorSHA) || fresh.CreatorSHA != original.CreatorSHA || !postlossSameProcess(fresh.Before, original.After) || !postlossSameProcess(fresh.After, original.After) || fresh.After.PID < 2 || fresh.After.StartTicks == 0 || fresh.Peer != original.Peer || fresh.Executable != original.Executable || fresh.CommandLine != original.CommandLine || !capacity.ValidDigest(fresh.Executable) || !capacity.ValidDigest(fresh.CommandLine) || !bytes.Equal(fresh.Disk, original.Disk) || fresh.DiskFD < 0 || fresh.UUID != original.UUID || strings.ToLower(fresh.UUID.UUID) != witness.Tuple.ResourceID || fresh.Status.SingleStep || !fresh.Status.Running || fresh.Status.Status != "running" {
		return false
	}
	if receipt.RecordedAt.IsZero() || fresh.Started.Before(receipt.RecordedAt) || fresh.Started.Before(original.Closed) || fresh.DiskRead.Before(fresh.Started) || fresh.DiskClose.Before(fresh.DiskRead) || fresh.Read.Before(fresh.DiskClose) || fresh.Closed.Before(fresh.Read) || !fresh.Closed.Before(witness.OriginalDeadline) || fresh.Closed.After(now) || !capacity.Fresh(fresh.Closed, now, 30) {
		return false
	}
	var creator struct {
		ResourceID string    `json:"resource_id"`
		Slot       int       `json:"slot"`
		Created    time.Time `json:"original_create_returned_at"`
	}
	if json.Unmarshal(original.Original, &creator) != nil || creator.ResourceID != witness.Tuple.ResourceID || creator.Slot != witness.Tuple.Slot || creator.Created.UTC().Format(time.RFC3339Nano) != witness.Tuple.CreatedAt {
		return false
	}
	expected := model.CapacityMutationProof{GrantID: grant.GrantID, BindingName: grant.BindingName, Slot: grant.Slot, ResourceID: creator.ResourceID, ResourceCreatedAt: creator.Created.UTC().Format(time.RFC3339Nano), RequestSHA256: grant.RequestSHA256, ObservedAt: fresh.Closed, ReceiptRef: "original-native-qemu-enrollment-confirm:" + capacity.BusinessCreationSHA256(freshWire), OwnerVerified: true, SpecVerified: true, ActionIDs: []string{"qemu-original-create:" + capacity.BusinessCreationSHA256(original.Original)}, ActionsTerminal: true, ActionsSuccessful: true, ObservedCreationGrantID: grant.GrantID}
	a, _ := json.Marshal(expected)
	b, _ := json.Marshal(proof)
	return bytes.Equal(a, b)
}

func postlossWitnessMatchesCustody(ctx context.Context, tx *sql.Tx, stored guestOriginalStored) bool {
	var raw []byte
	if tx.QueryRowContext(ctx, `SELECT witness_wire FROM public.capacity_canonical_postloss_originals WHERE preregistration_id=$1 AND parent_grant_id=$2`, stored.pre.PreregistrationID, stored.pre.OriginalCreateGrantID).Scan(&raw) != nil {
		return false
	}
	expected, err := json.Marshal(stored.witness)
	return err == nil && bytes.Equal(raw, expected)
}

// Only the source Realm calls this after its actual read, joins and close.
// This table exists only in the private postloss qualification schema.
func (s CapacityStore) RecordCanonicalPostlossConfirmation(ctx context.Context, preID string, proof model.CapacityMutationProof, freshWire []byte) error {
	return s.guestStoredTransaction(ctx, preID, func(tx *sql.Tx, stored guestOriginalStored, now time.Time) error {
		_, _, err := s.guestCurrentTx(ctx, tx, stored, now, true)
		if err != nil {
			return err
		}
		if err = loadGuestWitnessTx(ctx, tx, &stored); err != nil {
			return err
		}
		if stored.witness.SourceObservation == nil || !postlossWitnessMatchesCustody(ctx, tx, stored) {
			return ErrCapacityConflict
		}
		var parent capacityMutationRecord
		var parentWire []byte
		if len(freshWire) == 0 || len(freshWire) > capacity.GuestBootstrapLimit || !json.Valid(freshWire) || tx.QueryRowContext(ctx, `SELECT grant_record FROM public.capacity_mutation_grants WHERE id=$1 FOR SHARE`, stored.pre.OriginalCreateGrantID).Scan(&parentWire) != nil || json.Unmarshal(parentWire, &parent) != nil || !s.canonicalPostlossParentTx(ctx, tx, stored, parent, stored.witness.SourceObservation.Case) {
			return ErrCapacityConflict
		}
		receipt, _, err := loadGuestReceiptTx(ctx, tx, preID)
		if err != nil {
			return err
		}
		var originalWire []byte
		if tx.QueryRowContext(ctx, `SELECT original_wire FROM public.capacity_guest_qualification_native_source_returns WHERE preregistration_id=$1 AND native_stage='native_read' AND return_sha256=$2 AND original_record=convert_from(original_wire,'UTF8')::jsonb`, preID, stored.witness.SourceObservation.IndependentNativeReadSHA256).Scan(&originalWire) != nil || capacity.BusinessCreationSHA256(originalWire) != stored.witness.SourceObservation.IndependentNativeReadSHA256 || !postlossConfirmationJoin(originalWire, freshWire, stored.witness, receipt, parent.Grant, proof, now) {
			return ErrCapacityConflict
		}
		proofWire, err := json.Marshal(proof)
		if err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO public.capacity_canonical_postloss_confirmations(preregistration_id,parent_grant_id,native_wire,native_sha256,proof_wire,proof_sha256,recorded_at) VALUES($1,$2,$3,$4,$5,$6,$7)`, preID, parent.Grant.GrantID, freshWire, capacity.BusinessCreationSHA256(freshWire), proofWire, capacity.BusinessCreationSHA256(proofWire), now)
		return err
	})
}

func (s CapacityStore) canonicalPostlossConfirmationTx(ctx context.Context, tx *sql.Tx, policy model.Manifest, p model.CapacityPolicySpec, parent capacityMutationRecord, proof model.CapacityMutationProof, now time.Time) bool {
	var preID string
	if tx.QueryRowContext(ctx, `SELECT id::text FROM public.capacity_vm_provisioning_preregistrations WHERE create_grant_id=$1`, parent.Grant.GrantID).Scan(&preID) != nil {
		return false
	}
	stored, err := loadGuestOriginalTx(ctx, tx, preID)
	if err != nil || loadGuestWitnessTx(ctx, tx, &stored) != nil || stored.witness.SourceObservation == nil || !postlossWitnessMatchesCustody(ctx, tx, stored) || !s.canonicalPostlossParentTx(ctx, tx, stored, parent, stored.witness.SourceObservation.Case) {
		return false
	}
	receipt, _, err := loadGuestReceiptTx(ctx, tx, preID)
	if err != nil {
		return false
	}
	var originalWire, freshWire, proofWire []byte
	var freshSHA, proofSHA string
	if tx.QueryRowContext(ctx, `SELECT original_wire FROM public.capacity_guest_qualification_native_source_returns WHERE preregistration_id=$1 AND native_stage='native_read' AND return_sha256=$2 AND original_record=convert_from(original_wire,'UTF8')::jsonb`, preID, stored.witness.SourceObservation.IndependentNativeReadSHA256).Scan(&originalWire) != nil || capacity.BusinessCreationSHA256(originalWire) != stored.witness.SourceObservation.IndependentNativeReadSHA256 {
		return false
	}
	if tx.QueryRowContext(ctx, `SELECT native_wire,native_sha256,proof_wire,proof_sha256 FROM public.capacity_canonical_postloss_confirmations WHERE preregistration_id=$1 AND parent_grant_id=$2`, preID, parent.Grant.GrantID).Scan(&freshWire, &freshSHA, &proofWire, &proofSHA) != nil {
		return false
	}
	wire, err := json.Marshal(proof)
	return err == nil && bytes.Equal(wire, proofWire) && capacity.BusinessCreationSHA256(freshWire) == freshSHA && capacity.BusinessCreationSHA256(proofWire) == proofSHA && postlossConfirmationJoin(originalWire, freshWire, stored.witness, receipt, parent.Grant, proof, now)
}
