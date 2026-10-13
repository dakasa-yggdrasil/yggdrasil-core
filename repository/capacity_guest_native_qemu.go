package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
	"time"
)

// These private source returns are outside the nine/three/sixteen shared DTOs.
// The QEMU tuple's created instant is the original successful Popen return,
// never a Hetzner timestamp or Linux birth-time assertion.
type GuestNativeQEMUProcess struct {
	PID        int    `json:"pid"`
	PPID       int    `json:"ppid"`
	StartTicks uint64 `json:"start_ticks"`
	StatSHA256 string `json:"stat_sha256"`
}
type GuestNativeQEMUOffReturn struct {
	Schema                        string                 `json:"schema"`
	Stage                         string                 `json:"stage"`
	Slot                          int                    `json:"slot"`
	ResourceID                    string                 `json:"resource_id"`
	SourceCommit                  string                 `json:"source_commit"`
	CreatorOriginalSHA256         string                 `json:"creator_original_sha256"`
	QEMU                          GuestNativeQEMUProcess `json:"qemu"`
	OriginalWaitCode              int                    `json:"original_wait_code"`
	OriginalWaitReturnedAt        time.Time              `json:"original_wait_returned_at"`
	OriginalStderrCloseReturnedAt time.Time              `json:"original_stderr_close_returned_at"`
	OriginalStderrEOF             bool                   `json:"original_stderr_eof"`
	Scope                         string                 `json:"scope"`
}
type GuestNativeQEMUPIDFDReturn struct {
	Schema                  string                 `json:"schema"`
	ResourceID              string                 `json:"resource_id"`
	CreatorOriginalSHA256   string                 `json:"creator_original_sha256"`
	Before                  GuestNativeQEMUProcess `json:"before"`
	After                   GuestNativeQEMUProcess `json:"after"`
	OriginalPinStartedAt    time.Time              `json:"original_pin_started_at"`
	OriginalPinReturnedAt   time.Time              `json:"original_pin_returned_at"`
	OriginalPollReturnedAt  time.Time              `json:"original_poll_returned_at"`
	OriginalPollRevents     int16                  `json:"original_poll_revents"`
	OriginalCloseReturnedAt time.Time              `json:"original_close_returned_at"`
}

func guestNativeQEMUOffJoin(off GuestNativeQEMUOffReturn, join GuestNativeQEMUPIDFDReturn, stored GuestRetirementOriginal, quiescent model.CapacityGuestRetirementObservation, creatorSHA string, now time.Time) bool {
	same := func(a, b GuestNativeQEMUProcess) bool {
		return a.PID == b.PID && a.PPID == b.PPID && a.StartTicks == b.StartTicks
	}
	i := stored.Request.Intent
	return capacity.GuestOriginalNativeQEMUProviderEnabled("native-qemu") && stored.Binding.EvidenceClass == "native_qemu_qualification" && off.Schema == "core_original_guest_native_qemu_fixture_v1" && off.Stage == "native-off-original.json" && off.Scope == "original_burst_native_off" && off.Slot == i.Slot && i.Slot == 2 && off.ResourceID == i.Tuple.ResourceID && off.SourceCommit == stored.Binding.GuestSourceCommit && off.CreatorOriginalSHA256 == creatorSHA && capacity.ValidDigest(creatorSHA) && off.QEMU.PID > 1 && off.QEMU.StartTicks > 0 && off.OriginalWaitCode == 0 && off.OriginalStderrEOF && !off.OriginalWaitReturnedAt.Before(quiescent.Record.PoweroffOperation.WaitReturnedAt) && !off.OriginalStderrCloseReturnedAt.Before(off.OriginalWaitReturnedAt) && !off.OriginalStderrCloseReturnedAt.After(now) && join.Schema == "core_original_same_qemu_pidfd_join_v1" && join.ResourceID == off.ResourceID && join.CreatorOriginalSHA256 == creatorSHA && same(join.Before, off.QEMU) && same(join.Before, join.After) && !join.OriginalPinStartedAt.IsZero() && !join.OriginalPinReturnedAt.Before(join.OriginalPinStartedAt) && !join.OriginalPinReturnedAt.After(i.IssuedAt) && join.OriginalPollRevents == 1 && !join.OriginalPollReturnedAt.Before(off.OriginalWaitReturnedAt) && !join.OriginalCloseReturnedAt.Before(join.OriginalPollReturnedAt) && !join.OriginalCloseReturnedAt.After(now) && join.OriginalCloseReturnedAt.Before(i.OriginalDeadline)
}

type guestNativeQEMUOriginalIdentity struct {
	Schema                string `json:"schema"`
	OriginalCreatorSHA256 string `json:"original_creator_sha256"`
	Original              struct {
		QEMU                     GuestNativeQEMUProcess `json:"qemu"`
		Provider                 string                 `json:"provider"`
		ResourceID               string                 `json:"resource_id"`
		Slot                     int                    `json:"slot"`
		OriginalSourceCommit     string                 `json:"original_source_commit"`
		OriginalCreateStartedAt  time.Time              `json:"original_create_started_at"`
		OriginalCreateReturnedAt time.Time              `json:"original_create_returned_at"`
	} `json:"original"`
	OriginalDisk                         GuestNativeQEMUOriginalDisk `json:"original_disk"`
	OriginalDiskFD                       int                         `json:"original_disk_fd"`
	OriginalDiskReadReturnedAt           time.Time                   `json:"original_disk_read_returned_at"`
	OriginalDiskDirectoryCloseReturnedAt time.Time                   `json:"original_disk_directory_close_returned_at"`
	CloseReturnedAt                      time.Time                   `json:"close_returned_at"`
}

func guestNativeQEMUIdentityTx(ctx context.Context, tx *sql.Tx, preID string) (guestNativeQEMUOriginalIdentity, error) {
	var wire []byte
	var wireSHA string
	var consistent bool
	var original guestNativeQEMUOriginalIdentity
	if err := tx.QueryRowContext(ctx, `SELECT original_wire,return_sha256,original_record=convert_from(original_wire,'UTF8')::jsonb FROM public.capacity_guest_qualification_native_source_returns WHERE preregistration_id=$1 AND native_stage='native_read'`, preID).Scan(&wire, &wireSHA, &consistent); err != nil {
		return original, err
	}
	// This is a projection of the immutable, source-owned native reader row,
	// never a public decoder or a replacement for its original native reads.
	if !consistent || capacity.BusinessCreationSHA256(wire) != wireSHA || json.Unmarshal(wire, &original) != nil || original.Schema != "core_independent_original_qemu_read_v1" || !capacity.ValidDigest(original.OriginalCreatorSHA256) || original.Original.Provider != "native-qemu" || original.Original.ResourceID == "" || original.Original.Slot < 1 || original.Original.OriginalCreateStartedAt.IsZero() || original.Original.OriginalCreateReturnedAt.Before(original.Original.OriginalCreateStartedAt) || original.CloseReturnedAt.Before(original.Original.OriginalCreateReturnedAt) || original.Original.QEMU.PID < 2 || original.Original.QEMU.PPID < 1 || original.Original.QEMU.StartTicks == 0 || !capacity.ValidDigest(original.Original.QEMU.StatSHA256) || original.OriginalDisk.Device == 0 || original.OriginalDisk.Inode == 0 || original.OriginalDiskFD < 0 || original.OriginalDiskReadReturnedAt.IsZero() || original.OriginalDiskDirectoryCloseReturnedAt.Before(original.OriginalDiskReadReturnedAt) {
		return original, ErrCapacityConflict
	}
	return original, nil
}

func guestNativeQEMUCreatorSHA(ctx context.Context, tx *sql.Tx, preID string) (string, error) {
	original, err := guestNativeQEMUIdentityTx(ctx, tx, preID)
	return original.OriginalCreatorSHA256, err
}

func guestNativeQEMUSameCreator(off GuestNativeQEMUOffReturn, original guestNativeQEMUOriginalIdentity) bool {
	return off.CreatorOriginalSHA256 == original.OriginalCreatorSHA256 && off.QEMU == original.Original.QEMU
}

// No public handler accepts supplied native facts. Only the fixed source
// native realm invokes this after its original PIDFD Poll and Close returned.
func (s CapacityStore) RecordGuestNativeQEMUPoweroff(ctx context.Context, id string, wire, joinWire []byte) error {
	var off GuestNativeQEMUOffReturn
	var join GuestNativeQEMUPIDFDReturn
	if capacity.DecodeGuestLifecycle(wire, &off) != nil || capacity.DecodeGuestLifecycle(joinWire, &join) != nil {
		return ErrCapacityConflict
	}
	return s.guestRetirementTransaction(ctx, id, func(tx *sql.Tx, stored GuestRetirementOriginal, now time.Time) error {
		if _, _, _, err := s.guestRetirementCurrentTx(ctx, tx, stored, now, false); err != nil {
			return err
		}
		observed, err := guestQuiescentProofTx(ctx, tx, stored)
		if err != nil {
			return err
		}
		creator, err := guestNativeQEMUIdentityTx(ctx, tx, stored.Preregistration.PreregistrationID)
		if err != nil || !guestNativeQEMUSameCreator(off, creator) || !guestNativeQEMUOffJoin(off, join, stored, observed, creator.OriginalCreatorSHA256, now) {
			return ErrCapacityConflict
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO public.capacity_guest_original_native_poweroff_reads(id,intent_id,observation_sha256,original_wire,original_record,recorded_at,original_native_join_wire) VALUES($1,$2,$3,$4,$5::jsonb,$6,$7)`, uuid.New(), id, capacity.BusinessCreationSHA256(wire), wire, string(wire), now, joinWire)
		return err
	})
}

func guestNativeQEMUStoredOff(ctx context.Context, tx *sql.Tx, stored GuestRetirementOriginal, wire []byte, now time.Time) bool {
	var off GuestNativeQEMUOffReturn
	var joinWire []byte
	var join GuestNativeQEMUPIDFDReturn
	if capacity.DecodeGuestLifecycle(wire, &off) != nil || tx.QueryRowContext(ctx, `SELECT original_native_join_wire FROM public.capacity_guest_original_native_poweroff_reads WHERE intent_id=$1 AND observation_sha256=$2`, stored.Request.Intent.RequestID, capacity.BusinessCreationSHA256(wire)).Scan(&joinWire) != nil || capacity.DecodeGuestLifecycle(joinWire, &join) != nil {
		return false
	}
	quiescent, err := guestQuiescentProofTx(ctx, tx, stored)
	if err != nil {
		return false
	}
	creator, err := guestNativeQEMUIdentityTx(ctx, tx, stored.Preregistration.PreregistrationID)
	return err == nil && guestNativeQEMUSameCreator(off, creator) && guestNativeQEMUOffJoin(off, join, stored, quiescent, creator.OriginalCreatorSHA256, now) && capacity.Fresh(join.OriginalCloseReturnedAt, now, stored.Binding.MaxEvidenceAgeSeconds)
}

// An actual useful baseline proof supplements the unchanged physical floor
// and fence checks. A physical count or a caller supplied census cannot do so.
func guestNativeUsefulFloorTx(ctx context.Context, tx *sql.Tx, stored GuestRetirementOriginal, now time.Time) error {
	if stored.Binding.EvidenceClass != "native_qemu_qualification" {
		return nil
	}
	if !capacity.GuestOriginalNativeQEMUProviderEnabled("native-qemu") {
		return ErrCapacityConflict
	}
	var wire []byte
	if err := tx.QueryRowContext(ctx, `SELECT r.original_wire FROM public.capacity_guest_qualification_native_source_returns r JOIN public.capacity_vm_provisioning_preregistrations p ON p.id=r.preregistration_id WHERE p.preregistration_record->>'policy_id'=$1 AND p.preregistration_record->>'policy_checksum'=$2 AND p.preregistration_record->>'slot'='1' AND r.native_stage='serving_probe' ORDER BY r.recorded_at DESC LIMIT 1`, stored.Request.Intent.PolicyID, stored.Request.Intent.PolicyChecksum).Scan(&wire); err != nil {
		return ErrCapacityConflict
	}
	var header struct {
		EnrollmentSHA256              string    `json:"enrollment_sha256"`
		OriginalNativeAfterReturnedAt time.Time `json:"original_native_after_returned_at"`
	}
	if json.Unmarshal(wire, &header) != nil || !capacity.ValidDigest(header.EnrollmentSHA256) || !capacity.Fresh(header.OriginalNativeAfterReturnedAt, now, 5) || header.OriginalNativeAfterReturnedAt.After(now) {
		return ErrCapacityConflict
	}
	// FinishGuestQualificationProbe stores only its source authenticated exact
	// original challenge/enrollment return. The latest row remains immutable.
	var count int
	if tx.QueryRowContext(ctx, `SELECT count(*) FROM public.capacity_vm_original_enrollments e JOIN public.capacity_vm_provisioning_preregistrations p ON p.id=e.preregistration_id WHERE e.enrollment_sha256=$1 AND p.preregistration_record->>'policy_id'=$2 AND p.preregistration_record->>'slot'='1'`, header.EnrollmentSHA256, stored.Request.Intent.PolicyID).Scan(&count) != nil || count != 1 {
		return ErrCapacityConflict
	}
	return nil
}
