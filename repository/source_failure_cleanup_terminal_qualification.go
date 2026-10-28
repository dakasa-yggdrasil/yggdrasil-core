//go:build linux && nativequalification

package repository

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
	"golang.org/x/sys/unix"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type SourceFailureCleanupBody struct {
	Recovery                     *model.CapacitySourceRecoveryCleanupEpoch `json:"recovery,omitempty"`
	Schema                       string                                    `json:"schema"`
	SourceSlotDirectory          string                                    `json:"source_slot_directory"`
	SourceDirectoryDevice        uint64                                    `json:"source_directory_device"`
	SourceDirectoryInode         uint64                                    `json:"source_directory_inode"`
	OriginalHostBootID           string                                    `json:"original_host_boot_id"`
	Mode                         string                                    `json:"mode"`
	Scope                        string                                    `json:"scope"`
	AuthorityID                  string                                    `json:"authority_id"`
	NativeCase                   string                                    `json:"native_case"`
	CoreSource                   string                                    `json:"core_source"`
	GuestSource                  string                                    `json:"guest_source"`
	CreatorSourceSHA256          string                                    `json:"creator_source_sha256"`
	PreregistrationID            string                                    `json:"preregistration_id"`
	ParentGrantID                string                                    `json:"parent_grant_id"`
	PolicyID                     string                                    `json:"policy_id"`
	PolicyChecksum               string                                    `json:"policy_checksum"`
	OriginalReceiptSHA256        string                                    `json:"original_receipt_sha256"`
	OriginalOutcome              string                                    `json:"original_outcome"`
	FailureSHA256                string                                    `json:"failure_sha256"`
	EnrollmentSHA256             string                                    `json:"enrollment_sha256"`
	CreatorSHA256                string                                    `json:"creator_sha256"`
	NativeReadSHA256             string                                    `json:"native_read_sha256"`
	Slot                         int                                       `json:"slot"`
	ResourceID                   string                                    `json:"resource_id"`
	ResourceCreatedAt            string                                    `json:"resource_created_at"`
	QEMU                         json.RawMessage                           `json:"qemu"`
	OriginalDisk                 json.RawMessage                           `json:"original_disk"`
	IssuedAt                     time.Time                                 `json:"issued_at"`
	OriginalProvisioningDeadline time.Time                                 `json:"original_provisioning_deadline"`
	OriginalContextDeadline      time.Time                                 `json:"original_context_deadline"`
	CleanupDeadline              time.Time                                 `json:"cleanup_deadline"`
	BaselineMembers              int                                       `json:"baseline_members"`
	FailedSlotMembers            int                                       `json:"failed_slot_members"`
	FailedSlotEnsuredEvents      int                                       `json:"failed_slot_ensured_events"`
	ProductionQualified          bool                                      `json:"production_qualified"`
	PositiveQuiescence           bool                                      `json:"positive_quiescence"`
}
type SourceFailureCleanupAuthority struct {
	Body      []byte `json:"body"`
	Signature string `json:"signature"`
}
type SourceFailureCleanupPhysical struct {
	Schema                           string          `json:"schema"`
	Scope                            string          `json:"scope"`
	AuthoritySHA256                  string          `json:"authority_sha256"`
	CoreSource                       string          `json:"core_source"`
	GuestSource                      string          `json:"guest_source"`
	Slot                             int             `json:"slot"`
	ResourceID                       string          `json:"resource_id"`
	QEMU                             json.RawMessage `json:"qemu"`
	OriginalDisk                     json.RawMessage `json:"original_disk"`
	OriginalPinStartedAt             time.Time       `json:"original_pin_started_at"`
	OriginalPinReturnedAt            time.Time       `json:"original_pin_returned_at"`
	OriginalSignalCalledAt           time.Time       `json:"original_signal_called_at"`
	OriginalSignalReturnedAt         time.Time       `json:"original_signal_returned_at"`
	OriginalSignal                   int             `json:"original_signal"`
	OriginalWaitCode                 int             `json:"original_wait_code"`
	OriginalWaitReturnedAt           time.Time       `json:"original_wait_returned_at"`
	OriginalStderrEOF                bool            `json:"original_stderr_eof"`
	OriginalStderrCloseReturnedAt    time.Time       `json:"original_stderr_close_returned_at"`
	OriginalPIDFDOffReturnedAt       time.Time       `json:"original_pidfd_off_returned_at"`
	OriginalPIDFDCloseReturnedAt     time.Time       `json:"original_pidfd_close_returned_at"`
	OriginalUnlinkCalledAt           time.Time       `json:"original_unlink_called_at"`
	OriginalUnlinkReturnedAt         time.Time       `json:"original_unlink_returned_at"`
	OriginalDirectorySyncReturnedAt  time.Time       `json:"original_directory_sync_returned_at"`
	OriginalAbsenceReturnedAt        time.Time       `json:"original_absence_returned_at"`
	OriginalDirectoryCloseReturnedAt time.Time       `json:"original_directory_close_returned_at"`
	AbsenceClass                     string          `json:"absence_class"`
	PositiveQuiescence               bool            `json:"positive_quiescence"`
	ProductionQualified              bool            `json:"production_qualified"`
}

// Source-only terminal accounting does not change any ordinary grant or receipt.
// Production builds have no caller for this explicit nativequalification ABI.
type SourceFailureCleanupTerminal struct {
	Schema                  string    `json:"schema"`
	OriginalGeneration      int64     `json:"original_generation"`
	OriginalFencingToken    int64     `json:"original_fencing_token"`
	OriginalLeaseOwner      string    `json:"original_lease_owner"`
	OriginalExecutorID      string    `json:"original_executor_id"`
	ParentGrantID           string    `json:"parent_grant_id"`
	AuthoritySHA256         string    `json:"authority_sha256"`
	PhysicalSHA256          string    `json:"physical_sha256"`
	OriginalReceiptSHA256   string    `json:"original_receipt_sha256"`
	CoreSource              string    `json:"core_source"`
	GuestSource             string    `json:"guest_source"`
	SourceTerminal          bool      `json:"source_terminal"`
	CanonicalParentTerminal bool      `json:"canonical_parent_terminal"`
	ProductionQualified     bool      `json:"production_qualified"`
	ReturnedAt              time.Time `json:"returned_at"`
	TerminalSHA256          string    `json:"-"`
	FreshReadSHA256         string    `json:"-"`
	FreshReadWire           []byte    `json:"-"`
}

func (s CapacityStore) ValidateSourceFailureCleanupTerminalTx(ctx context.Context, tx *sql.Tx, policy model.Manifest, p model.CapacityPolicySpec, current model.CapacityIntent, parentID string, now time.Time) (SourceFailureCleanupTerminal, error) {
	var out SourceFailureCleanupTerminal
	var aw, pw, tw, raw []byte
	var preID string
	if err := tx.QueryRowContext(ctx, `SELECT a.authority_wire,p.physical_wire,t.terminal_wire FROM public.capacity_source_failure_cleanup_originals a JOIN public.capacity_source_failure_cleanup_physical p USING(parent_grant_id) JOIN public.capacity_source_failure_cleanup_terminals t USING(parent_grant_id) WHERE a.parent_grant_id=$1 AND a.namespace=$2 FOR SHARE OF a,p,t`, parentID, policy.Metadata.Namespace).Scan(&aw, &pw, &tw); err != nil {
		return out, err
	}
	var a SourceFailureCleanupAuthority
	var signedTerminal SourceFailureCleanupAuthority
	var b SourceFailureCleanupBody
	var f SourceFailureCleanupPhysical
	if capacity.DecodeGuestLifecycle(aw, &a) != nil || capacity.DecodeGuestLifecycle(a.Body, &b) != nil || capacity.DecodeGuestLifecycle(pw, &f) != nil || capacity.DecodeGuestLifecycle(tw, &signedTerminal) != nil || capacity.DecodeGuestLifecycle(signedTerminal.Body, &out) != nil {
		return out, ErrCapacityConflict
	}
	switch b.NativeCase {
	case "compensation_unprotected_failed_create", "compensation_protected_failed_create", "compensation_unprotected_lost_create_reply", "compensation_protected_lost_create_reply", "source_live_failed_floor_recovery":
	default:
		return out, ErrCapacityDisabled
	}
	if b.Schema != "original_source_failure_cleanup_authority_v1" || b.Mode != "failure_cleanup_only" || b.Scope != "same_original_host_qemu_cleanup_not_guest_positive_retirement" || b.ParentGrantID != parentID || b.PolicyID != policy.ID.String() || b.PolicyChecksum != policy.Checksum || b.CoreSource != capacity.CurrentGuestCoreSource() || b.Slot != 2 || b.ProductionQualified || b.PositiveQuiescence || b.BaselineMembers != 1 || b.FailedSlotMembers != 0 || b.FailedSlotEnsuredEvents != 0 || !now.Before(b.OriginalContextDeadline) {
		return out, ErrCapacityConflict
	}
	preID = b.PreregistrationID
	stored, err := loadGuestOriginalTx(ctx, tx, preID)
	if err != nil {
		return out, err
	}
	if stored.pre.OriginalCreateGrantID != parentID || stored.pre.CoreSourceCommit != b.CoreSource || stored.pre.PolicyID != b.PolicyID || stored.pre.PolicyChecksum != b.PolicyChecksum || stored.pre.WorkflowID != s.WorkflowID.String() || stored.pre.Slot != 2 || stored.pre.OriginalWorkflowStepTimeoutSeconds != 600 || !stored.pre.OriginalWorkflowContextDeadline.Equal(b.OriginalContextDeadline) || !stored.pre.OriginalDeadline.Equal(b.OriginalProvisioningDeadline) || stored.binding.GuestSourceCommit != b.GuestSource || stored.binding.CoreAuthoritySourceCommit != b.CoreSource || stored.binding.EvidenceClass != "native_qemu_qualification" || stored.binding.ProfileManifest.Profile != "qualification-original-echo-writer-v1" {
		return out, ErrCapacityConflict
	}
	secret, err := ResolveSecretRef(ctx, s.DB, stored.binding.IntentSigningKeyRef)
	if err != nil {
		return out, err
	}
	encoded, ok := secret.(string)
	if !ok {
		return out, ErrCapacityConflict
	}
	key, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil || len(key) != ed25519.PrivateKeySize {
		return out, ErrCapacityConflict
	}
	sig, err := base64.StdEncoding.DecodeString(a.Signature)
	if err != nil || !ed25519.Verify(ed25519.PrivateKey(key).Public().(ed25519.PublicKey), a.Body, sig) {
		return out, ErrCapacityConflict
	}
	terminalSig, err := base64.StdEncoding.DecodeString(signedTerminal.Signature)
	if err != nil || !ed25519.Verify(ed25519.PrivateKey(key).Public().(ed25519.PublicKey), signedTerminal.Body, terminalSig) {
		return out, ErrCapacityConflict
	}
	if err = tx.QueryRowContext(ctx, `SELECT grant_record FROM public.capacity_mutation_grants WHERE id=$1 FOR UPDATE`, parentID).Scan(&raw); err != nil {
		return out, err
	}
	var record capacityMutationRecord
	if capacity.DecodeGuestLifecycle(raw, &record) != nil || record.Grant.State != "settled" || record.WorkflowID != s.WorkflowID || record.PolicyID != policy.ID || record.PolicyChecksum != policy.Checksum {
		return out, ErrCapacityConflict
	}
	if current.Generation < record.Generation || current.FencingToken < record.FencingToken || out.OriginalGeneration != record.Generation || out.OriginalFencingToken != record.FencingToken || out.OriginalLeaseOwner != record.LeaseOwner || out.OriginalExecutorID != record.ExecutorID {
		return out, ErrCapacityConflict
	}
	if current.RecoveryOnly {
		err = s.checkRecoveryLease(policy, &current, current.Generation, current.FencingToken, current.LeaseOwner, now)
	} else {
		err = s.checkLease(p, policy, &current, current.Generation, current.FencingToken, current.LeaseOwner, now)
	}
	if err != nil {
		return out, err
	}
	original := model.CapacityMutationReceipt{Grant: record.Grant, AttemptID: record.AttemptID}
	if record.Settlement == nil {
		return out, ErrCapacityConflict
	}
	settled := record.Settlement
	original.Outcome, original.TransportCompleted, original.ResourceID, original.ResourceCreatedAt, original.ActionID, original.NextActionIDs = settled.Outcome, settled.TransportCompleted, settled.ResourceID, settled.ResourceCreatedAt, settled.ActionID, append([]string(nil), settled.NextActionIDs...)
	original.AuxiliaryResources = append([]model.CapacityMutationAuxiliaryResource(nil), settled.AuxiliaryResources...)
	original.AuxiliaryInventoryComplete = settled.AuxiliaryInventoryComplete
	if capacity.GuestRetirementSHA(original) != b.OriginalReceiptSHA256 || !original.TransportCompleted {
		return out, ErrCapacityConflict
	}
	lost := b.NativeCase == "compensation_unprotected_lost_create_reply" || b.NativeCase == "compensation_protected_lost_create_reply"
	if lost {
		if original.Outcome != "uncertain" || original.ResourceID != "" || original.ResourceCreatedAt != "" || b.EnrollmentSHA256 != "" || b.FailureSHA256 != "" {
			return out, ErrCapacityConflict
		}
	} else {
		if original.Outcome != "accepted" || !capacity.ValidDigest(b.EnrollmentSHA256) || !capacity.ValidDigest(b.FailureSHA256) {
			return out, ErrCapacityConflict
		}
		var matching int
		if err = tx.QueryRowContext(ctx, `SELECT count(*) FROM public.capacity_guest_qualification_native_source_returns WHERE preregistration_id=$1 AND native_stage='source_refusal' AND return_sha256=$2 AND original_record=convert_from(original_wire,'UTF8')::jsonb`, preID, b.FailureSHA256).Scan(&matching); err != nil || matching != 1 {
			return out, ErrCapacityConflict
		}
	}
	if out.Schema != "original_source_failure_cleanup_terminal_v1" || out.ParentGrantID != parentID || !out.SourceTerminal || out.CanonicalParentTerminal || out.ProductionQualified || out.CoreSource != b.CoreSource || out.GuestSource != b.GuestSource || out.AuthoritySHA256 != capacity.GuestRetirementSHA(a) || out.PhysicalSHA256 != capacity.BusinessCreationSHA256(pw) || out.OriginalReceiptSHA256 != b.OriginalReceiptSHA256 || out.ReturnedAt.Before(f.OriginalDirectoryCloseReturnedAt) || !out.ReturnedAt.Before(b.CleanupDeadline) {
		return out, ErrCapacityConflict
	}
	if f.Schema != "original_source_failure_cleanup_physical_v1" || f.Scope != "host_owned_failure_cleanup_only_not_positive_retirement" || f.AuthoritySHA256 != out.AuthoritySHA256 || f.CoreSource != b.CoreSource || f.GuestSource != b.GuestSource || f.Slot != 2 || f.ResourceID != b.ResourceID || !bytes.Equal(f.QEMU, b.QEMU) || !bytes.Equal(f.OriginalDisk, b.OriginalDisk) || f.OriginalSignal != 9 || f.OriginalWaitCode != -9 || !f.OriginalStderrEOF || f.AbsenceClass != "ENOENT" || f.PositiveQuiescence || f.ProductionQualified {
		return out, ErrCapacityConflict
	}
	for _, at := range []time.Time{f.OriginalPinStartedAt, f.OriginalPinReturnedAt, f.OriginalSignalCalledAt, f.OriginalSignalReturnedAt, f.OriginalWaitReturnedAt, f.OriginalStderrCloseReturnedAt, f.OriginalPIDFDOffReturnedAt, f.OriginalPIDFDCloseReturnedAt, f.OriginalUnlinkCalledAt, f.OriginalUnlinkReturnedAt, f.OriginalDirectorySyncReturnedAt, f.OriginalAbsenceReturnedAt, f.OriginalDirectoryCloseReturnedAt} {
		if at.IsZero() || at.Before(b.IssuedAt) || !at.Before(b.CleanupDeadline) {
			return out, ErrCapacityConflict
		}
	}
	var members, failed, events int
	if err = tx.QueryRowContext(ctx, `SELECT count(*) FILTER(WHERE resource_id<>''),count(*) FILTER(WHERE slot=2 AND resource_id<>'') FROM public.capacity_resource_slots WHERE namespace=$1`, policy.Metadata.Namespace).Scan(&members, &failed); err != nil || members != 1 || failed != 0 {
		return out, ErrCapacityConflict
	}
	if err = tx.QueryRowContext(ctx, `SELECT count(*) FROM public.event_log WHERE idempotency_key=$1`, "capacity-mutation/"+parentID).Scan(&events); err != nil || events != 0 {
		return out, ErrCapacityConflict
	}
	out.TerminalSHA256 = capacity.BusinessCreationSHA256(tw)
	fresh, err := sourceFailureCleanupCurrentRead(b, out, current, now)
	if err != nil {
		return out, err
	}
	freshWire, err := json.Marshal(fresh)
	if err != nil {
		return out, err
	}
	freshSHA := capacity.BusinessCreationSHA256(freshWire)
	if _, err = tx.ExecContext(ctx, `INSERT INTO public.capacity_source_failure_cleanup_reads(read_id,parent_grant_id,generation,fencing_token,read_wire,read_sha256) VALUES($1,$2,$3,$4,$5,$6)`, fresh.ReadID, parentID, current.Generation, current.FencingToken, freshWire, freshSHA); err != nil {
		return out, err
	}
	out.TerminalSHA256 = capacity.BusinessCreationSHA256(tw)
	out.FreshReadSHA256 = freshSHA
	out.FreshReadWire = freshWire
	return out, nil
}

// A fresh original lease read is required before the possible effect and after
// physical absence. It does not mint or renew a lease or adopt another executor.
func (s CapacityStore) CheckSourceFailureCleanupLease(ctx context.Context, policy model.Manifest, parentID string) error {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	p, err := parseCapacityPolicy(policy)
	if err != nil {
		return err
	}
	var raw []byte
	var now time.Time
	var active bool
	var checksum string
	if err = tx.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		return err
	}
	if err = tx.QueryRowContext(ctx, `SELECT checksum,active FROM public.manifests WHERE id=$1 AND kind='capacity_policy' FOR SHARE`, policy.ID).Scan(&checksum, &active); err != nil || !active || checksum != policy.Checksum {
		return ErrCapacityConflict
	}
	if err = tx.QueryRowContext(ctx, `SELECT grant_record FROM public.capacity_mutation_grants WHERE id=$1 FOR UPDATE`, parentID).Scan(&raw); err != nil {
		return err
	}
	var record capacityMutationRecord
	if capacity.DecodeGuestLifecycle(raw, &record) != nil || record.WorkflowID != s.WorkflowID || record.PolicyID != policy.ID || record.PolicyChecksum != policy.Checksum || record.Grant.State != "settled" {
		return ErrCapacityConflict
	}
	current, err := loadCapacityIntent(ctx, tx, policy.Metadata.Namespace, p, true)
	if err != nil {
		return err
	}
	owner := s
	owner.ExecutorID = record.ExecutorID
	if err = owner.checkLease(p, policy, &current, record.Generation, record.FencingToken, record.LeaseOwner, now); err != nil {
		return err
	}
	return tx.Commit()
}

// Current negative read is separate from historical Wait/EOF and never repeats
// a signal, unlink or create. The Source-owned PIDFD and disk are already off.
type SourceFailureCleanupCurrentRead struct {
	Generation               int64     `json:"generation"`
	FencingToken             int64     `json:"fencing_token"`
	LeaseOwner               string    `json:"lease_owner"`
	ExecutorID               string    `json:"executor_id"`
	Schema                   string    `json:"schema"`
	ReadID                   string    `json:"read_id"`
	ParentGrantID            string    `json:"parent_grant_id"`
	AuthoritySHA256          string    `json:"authority_sha256"`
	OriginalTerminalSHA256   string    `json:"original_terminal_sha256"`
	CoreSource               string    `json:"core_source"`
	GuestSource              string    `json:"guest_source"`
	HostBootID               string    `json:"host_boot_id"`
	DirectoryDevice          uint64    `json:"directory_device"`
	DirectoryInode           uint64    `json:"directory_inode"`
	OriginalPID              int       `json:"original_pid"`
	PIDFDOpenError           string    `json:"pidfd_open_error"`
	DiskAbsence              string    `json:"disk_absence"`
	StartedAt                time.Time `json:"started_at"`
	PIDReadReturnedAt        time.Time `json:"pid_read_returned_at"`
	DiskReadReturnedAt       time.Time `json:"disk_read_returned_at"`
	DirectoryCloseReturnedAt time.Time `json:"directory_close_returned_at"`
	ReturnedAt               time.Time `json:"returned_at"`
	ProductionQualified      bool      `json:"production_qualified"`
}

func sourceCleanupSlotDirectoryMatches(b SourceFailureCleanupBody) bool {
	slot := canonicalSourceExpectedSlot(b.NativeCase)
	if slot == 0 {
		switch b.NativeCase {
		case "compensation_unprotected_failed_create", "compensation_protected_failed_create", "compensation_unprotected_lost_create_reply", "compensation_protected_lost_create_reply", "source_live_failed_floor_recovery":
			slot = 2
		default:
			return false
		}
	}
	return b.Slot == slot && ((slot == 1 && filepath.Base(b.SourceSlotDirectory) == "slot-1") || (slot == 2 && filepath.Base(b.SourceSlotDirectory) == "slot-2"))
}

func sourceFailureCleanupCurrentRead(b SourceFailureCleanupBody, t SourceFailureCleanupTerminal, current model.CapacityIntent, dbNow time.Time) (SourceFailureCleanupCurrentRead, error) {
	var r SourceFailureCleanupCurrentRead
	if b.CoreSource != capacity.CurrentGuestCoreSource() || b.SourceDirectoryDevice == 0 || b.SourceDirectoryInode == 0 || !sourceCleanupSlotDirectoryMatches(b) || filepath.Clean(b.SourceSlotDirectory) != b.SourceSlotDirectory || !filepath.IsAbs(b.SourceSlotDirectory) || !strings.HasPrefix(filepath.Base(filepath.Dir(b.SourceSlotDirectory)), "guest-provisioning-native-") || !dbNow.Before(b.OriginalContextDeadline) {
		return r, ErrCapacityConflict
	}
	r = SourceFailureCleanupCurrentRead{Generation: current.Generation, FencingToken: current.FencingToken, LeaseOwner: current.LeaseOwner, ExecutorID: current.LeaseExecutorID, Schema: "original_source_failure_cleanup_current_read_v1", ReadID: uuid.NewString(), ParentGrantID: b.ParentGrantID, AuthoritySHA256: t.AuthoritySHA256, OriginalTerminalSHA256: t.TerminalSHA256, CoreSource: b.CoreSource, GuestSource: b.GuestSource, HostBootID: b.OriginalHostBootID, DirectoryDevice: b.SourceDirectoryDevice, DirectoryInode: b.SourceDirectoryInode, StartedAt: time.Now().UTC(), ProductionQualified: false}
	var process struct {
		PID        int    `json:"pid"`
		PPID       int    `json:"ppid"`
		StartTicks uint64 `json:"start_ticks"`
		StatSHA256 string `json:"stat_sha256"`
	}
	if capacity.DecodeGuestLifecycle(b.QEMU, &process) != nil || process.PID < 2 {
		return r, ErrCapacityConflict
	}
	r.OriginalPID = process.PID
	fd, err := unix.PidfdOpen(process.PID, 0)
	r.PIDReadReturnedAt = time.Now().UTC()
	if err != unix.ESRCH {
		if err == nil {
			_ = unix.Close(fd)
		}
		return r, ErrCapacityConflict
	}
	r.PIDFDOpenError = "ESRCH"
	directory, err := unix.Open(b.SourceSlotDirectory, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return r, err
	}
	var d unix.Stat_t
	se := unix.Fstat(directory, &d)
	var disk unix.Stat_t
	de := unix.Fstatat(directory, "original.qcow2", &disk, unix.AT_SYMLINK_NOFOLLOW)
	r.DiskReadReturnedAt = time.Now().UTC()
	ce := unix.Close(directory)
	r.DirectoryCloseReturnedAt = time.Now().UTC()
	if se != nil || ce != nil || uint64(d.Dev) != b.SourceDirectoryDevice || d.Ino != b.SourceDirectoryInode || de != unix.ENOENT {
		return r, ErrCapacityConflict
	}
	r.DiskAbsence = "ENOENT"
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	r.ReturnedAt = time.Now().UTC()
	if err != nil || strings.TrimSpace(string(boot)) != b.OriginalHostBootID || !r.ReturnedAt.Before(b.OriginalContextDeadline) || r.StartedAt.Before(t.ReturnedAt) {
		return r, ErrCapacityConflict
	}
	return r, nil
}
