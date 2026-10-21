//go:build linux && nativequalification

package capacitynativeqemu

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	"github.com/google/uuid"
	"golang.org/x/sys/unix"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type SourceRecoveryCleanupSession struct {
	Store             repository.CapacityStore
	Policy            model.Manifest
	PreregistrationID string
	Epoch             model.CapacitySourceRecoveryCleanupEpoch
}

// Session provenance is the actual resolved Source invocation's store, retained
// in the original Realm. No executor is reconstructed from a JSON statement.
func (r *Realm) OriginalRecoveryCleanupSession(ctx context.Context) (SourceRecoveryCleanupSession, error) {
	r.mu.Lock()
	s := r.recoveryCleanup
	r.mu.Unlock()
	if s == nil || ctx.Err() != nil || !CanonicalSourceCompensationCase(r.Request.NativeCase) {
		return SourceRecoveryCleanupSession{}, ErrOriginalUnknown
	}
	return *s, nil
}

func (r *Realm) PrepareOriginalRecoveryCleanupRead(ctx context.Context, store repository.CapacityStore, policy model.Manifest, pre model.CapacityGuestOriginalProvisioningPreregistration, client *capacity.GuestOriginalHTTPClient) error {
	if !CanonicalSourceCompensationCase(r.Request.NativeCase) || pre.Slot != 2 || pre.WorkflowID != store.WorkflowID.String() || client == nil {
		return ErrOriginalUnknown
	}
	var random [32]byte
	if _, err := rand.Read(random[:]); err != nil {
		return err
	}
	nonce := capacity.BusinessCreationSHA256(random[:])
	epoch, err := store.PrepareSourceRecoveryCleanupChallenge(ctx, policy, pre.OriginalCreateGrantID, nonce)
	if err != nil {
		return err
	}
	request := struct {
		Schema      string `json:"schema"`
		NonceSHA256 string `json:"nonce_sha256"`
	}{"canonical_recovery_fresh_failure_request_v1", nonce}
	raw, err := Publish(ctx, filepath.Join(r.PrivateDirectory, "canonical-recovery-fresh-read-request.json"), request)
	if err != nil {
		return err
	}
	// Both operations are reads of the SAME already-started original, never retry,
	// Prepare, adoption, create, withdraw or positive-quiescence permission.
	_, nativeWire, err := r.freshCanonicalRecoveryNative(ctx)
	if err != nil {
		return err
	}
	read, cancel := context.WithTimeout(ctx, 5*time.Second)
	returned, err := client.Original(read, http.MethodGet, "/v1/qualification-source-refusal", raw)
	cancel()
	if err != nil || returned.Status != 200 || !returned.DriverReturnedAt.Before(pre.OriginalDeadline) {
		return ErrOriginalUnknown
	}
	if _, err = Publish(ctx, filepath.Join(r.PrivateDirectory, "canonical-recovery-fresh-read-host-return.json"), returned); err != nil {
		return err
	}
	if _, err = PublishBytes(ctx, filepath.Join(SlotDirectory(r.PrivateDirectory, 2), "core-recovery-fresh-failure-read.json"), returned.Body); err != nil {
		return err
	}
	epoch, err = store.CompleteSourceRecoveryCleanupRead(ctx, policy, pre.OriginalCreateGrantID, epoch, nativeWire, returned.Body)
	if err != nil {
		return err
	}
	session := SourceRecoveryCleanupSession{Store: store, Policy: policy, PreregistrationID: pre.PreregistrationID, Epoch: epoch}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.recoveryCleanup != nil {
		return ErrOriginalUnknown
	}
	r.recoveryCleanup = &session
	return nil
}
func (r *Realm) freshCanonicalRecoveryNative(ctx context.Context) (IndependentReturn, []byte, error) {
	var fresh IndependentReturn
	if !CanonicalSourceCompensationCase(r.Request.NativeCase) {
		return fresh, nil, ErrOriginalUnknown
	}
	r.mu.Lock()
	original, ok := r.originals[2]
	r.mu.Unlock()
	if !ok {
		return fresh, nil, ErrOriginalUnknown
	}
	read, cancel := context.WithTimeout(ctx, 5*time.Second)
	fresh, err := Observe(read, SlotDirectory(r.PrivateDirectory, 2), original.Original, r.QEMUBinarySHA256)
	cancel()
	if err != nil || r.verifyFixedCommand(ctx, 2, fresh) != nil || !sameProcess(fresh.Before, original.After) || !sameProcess(fresh.After, original.After) || fresh.OriginalDisk != original.OriginalDisk {
		return fresh, nil, ErrOriginalUnknown
	}
	fresh.OriginalCreatorSHA256 = original.OriginalCreatorSHA256
	wire, err := Publish(ctx, filepath.Join(SlotDirectory(r.PrivateDirectory, 2), "core-recovery-fresh-native-read.json"), fresh)
	return fresh, wire, err
}

func (r *Realm) PrepareSourceRecoveryFailureCleanup(ctx context.Context, store repository.CapacityStore, policy model.Manifest, pre model.CapacityGuestOriginalProvisioningPreregistration, failureSHA, enrollmentSHA string, key ed25519.PrivateKey) (SourceFailureCleanupAuthority, SourceFailureCleanupBody, error) {
	var authority SourceFailureCleanupAuthority
	var body SourceFailureCleanupBody
	if !SourceCompensationCase(r.Request.NativeCase) || pre.Slot != 2 || len(key) != ed25519.PrivateKeySize || ctx.Err() != nil || pre.CoreSourceCommit != capacity.CurrentGuestCoreSource() || policy.Metadata.Namespace == "" || pre.WorkflowID != store.WorkflowID.String() {
		return authority, body, ErrOriginalUnknown
	}
	r.mu.Lock()
	native, ok := r.originals[2]
	disk, known := r.disks[2]
	r.mu.Unlock()
	if !ok || !known || native.OriginalDisk != disk {
		return authority, body, ErrOriginalUnknown
	}
	receipt, err := r.OriginalMutationReceipt(ctx, pre.OriginalCreateGrantID)
	if err != nil || receipt.Grant.State != "settled" || !receipt.TransportCompleted {
		return authority, body, ErrOriginalUnknown
	}
	lost := SourceLostCreateCase(r.Request.NativeCase)
	if lost {
		if receipt.Outcome != "uncertain" || receipt.ResourceID != "" || receipt.ResourceCreatedAt != "" || failureSHA != "" || enrollmentSHA != "" {
			return authority, body, ErrOriginalUnknown
		}
	} else if PostlossSourceCase(r.Request.NativeCase) {
		if receipt.Outcome != "uncertain" || receipt.ResourceID != "" || receipt.ResourceCreatedAt != "" || !validSHA(failureSHA) || !validSHA(enrollmentSHA) {
			return authority, body, ErrOriginalUnknown
		}
	} else if receipt.Outcome != "accepted" || !validSHA(failureSHA) || !validSHA(enrollmentSHA) {
		return authority, body, ErrOriginalUnknown
	}
	var members, failed, events int
	if err = store.DB.QueryRowContext(ctx, `SELECT count(*) FILTER (WHERE resource_id<>''),count(*) FILTER (WHERE slot=2 AND resource_id<>'') FROM public.capacity_resource_slots WHERE namespace=$1`, policy.Metadata.Namespace).Scan(&members, &failed); err != nil || members != 1 || failed != 0 {
		return authority, body, ErrOriginalUnknown
	}
	if err = store.DB.QueryRowContext(ctx, `SELECT count(*) FROM public.event_log WHERE idempotency_key=$1`, "capacity-mutation/"+pre.OriginalCreateGrantID).Scan(&events); err != nil || events != 0 {
		return authority, body, ErrOriginalUnknown
	}
	// Read the ACTUAL private current lease, never a cached grant expiry or
	// an invented successor. This creates no lease and renews no clock.
	var policySpec model.CapacityPolicySpec
	if json.Unmarshal(policy.Spec, &policySpec) != nil {
		return authority, body, ErrOriginalUnknown
	}
	actual, err := r.OriginalRecoveryCleanupSession(ctx)
	if err != nil || actual.Store.ExecutorID != store.ExecutorID || actual.Store.WorkflowID != store.WorkflowID || actual.Store.DB != store.DB || actual.PreregistrationID != pre.PreregistrationID {
		return authority, body, ErrOriginalUnknown
	}
	currentLease, err := store.ValidateSourceRecoveryPreparation(ctx, policy, pre.OriginalCreateGrantID, actual.Epoch)
	if err != nil {
		return authority, body, err
	}
	now := time.Now().UTC()
	deadline := now.Add(150 * time.Second)
	parent, ok := ctx.Deadline()
	if !ok {
		return authority, body, ErrOriginalUnknown
	}
	if parent.Before(deadline) {
		deadline = parent
	}
	if r.Request.OriginalContextDeadline.Before(deadline) {
		deadline = r.Request.OriginalContextDeadline
	}
	if currentLease.LeaseExpiresAt.Before(deadline) {
		deadline = *currentLease.LeaseExpiresAt
	}
	if pre.OriginalDeadline.Before(deadline) {
		deadline = pre.OriginalDeadline
	}
	if !now.Before(deadline) {
		return authority, body, ErrOriginalUnknown
	}
	directory, err := unix.Open(SlotDirectory(r.PrivateDirectory, 2), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return authority, body, err
	}
	var directoryStat unix.Stat_t
	se := unix.Fstat(directory, &directoryStat)
	ce := unix.Close(directory)
	if se != nil || ce != nil {
		return authority, body, ErrOriginalUnknown
	}
	hostBoot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil || !validUUID(strings.TrimSpace(string(hostBoot))) {
		return authority, body, ErrOriginalUnknown
	}
	body = SourceFailureCleanupBody{Recovery: &actual.Epoch, Schema: "original_source_recovery_failure_cleanup_authority_v1", SourceSlotDirectory: SlotDirectory(r.PrivateDirectory, 2), SourceDirectoryDevice: uint64(directoryStat.Dev), SourceDirectoryInode: directoryStat.Ino, OriginalHostBootID: strings.TrimSpace(string(hostBoot)), Mode: "recovery_failure_cleanup_only", Scope: "same_original_host_qemu_recovery_owned_cleanup_not_guest_positive_retirement", AuthorityID: uuid.NewString(), NativeCase: r.Request.NativeCase, CoreSource: capacity.CurrentGuestCoreSource(), GuestSource: r.Request.SourceCommit, CreatorSourceSHA256: r.Request.CreatorSourceSHA256, PreregistrationID: pre.PreregistrationID, ParentGrantID: pre.OriginalCreateGrantID, PolicyID: policy.ID.String(), PolicyChecksum: policy.Checksum, OriginalReceiptSHA256: capacity.GuestRetirementSHA(receipt), OriginalOutcome: receipt.Outcome, FailureSHA256: failureSHA, EnrollmentSHA256: enrollmentSHA, CreatorSHA256: native.OriginalCreatorSHA256, NativeReadSHA256: capacity.GuestRetirementSHA(native), Slot: 2, ResourceID: native.Original.ResourceID, ResourceCreatedAt: native.Original.OriginalCreateReturnedAt.UTC().Format(time.RFC3339Nano), QEMU: native.Original.QEMU, OriginalDisk: disk, IssuedAt: now, OriginalProvisioningDeadline: pre.OriginalDeadline, OriginalContextDeadline: r.Request.OriginalContextDeadline, CleanupDeadline: deadline, BaselineMembers: members, FailedSlotMembers: failed, FailedSlotEnsuredEvents: events, ProductionQualified: false, PositiveQuiescence: false}
	authority.Body, err = json.Marshal(body)
	if err != nil {
		return authority, body, err
	}
	authority.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(key, authority.Body))
	return authority, body, nil
}

func (r *Realm) ReadSourceRecoveryFailureCleanup(ctx context.Context, a SourceFailureCleanupAuthority, b SourceFailureCleanupBody, store repository.CapacityStore, policy model.Manifest, session CanonicalCleanupSession) (SourceFailureCleanupPhysical, error) {
	var f SourceFailureCleanupPhysical
	original, cancel := context.WithDeadline(ctx, b.CleanupDeadline)
	defer cancel()
	if b.Recovery == nil || b.Schema != "original_source_recovery_failure_cleanup_authority_v1" || session.Child.CompensationOf != b.ParentGrantID {
		return f, ErrOriginalUnknown
	}
	for _, phase := range []string{"signal", "unlink"} {
		var request model.CapacitySourceRecoveryEffectRequest
		requestWire, err := Await(original, filepath.Join(SlotDirectory(r.PrivateDirectory, 2), "source-recovery-"+phase+"-request.json"), &request)
		if err != nil || request.Phase != phase {
			return f, ErrOriginalUnknown
		}
		// The helper commits and releases all database locks before this publish;
		// neither original owner waits for a stage while holding a SQL transaction.
		permit, err := store.AuthorizeSourceRecoveryEffect(original, policy, session.Child.GrantID, requestWire)
		if err != nil {
			return f, err
		}
		if _, err = Publish(original, filepath.Join(SlotDirectory(r.PrivateDirectory, 2), "source-recovery-"+phase+"-permit.json"), permit); err != nil {
			return f, err
		}
	}
	if _, err := Await(original, filepath.Join(SlotDirectory(r.PrivateDirectory, 2), "source-failure-cleanup-physical.json"), &f); err != nil {
		return f, err
	}
	if f.Schema != "original_source_recovery_failure_cleanup_physical_v1" || f.Scope != "host_owned_recovery_failure_cleanup_only_not_positive_retirement" || f.AuthoritySHA256 != capacity.GuestRetirementSHA(a) || f.CoreSource != b.CoreSource || f.GuestSource != b.GuestSource || f.Slot != 2 || f.ResourceID != b.ResourceID || f.QEMU != b.QEMU || f.OriginalDisk != b.OriginalDisk || f.OriginalSignal != 9 || f.OriginalWaitCode != -9 || !f.OriginalStderrEOF || f.AbsenceClass != "ENOENT" || f.PositiveQuiescence || f.ProductionQualified {
		return f, ErrOriginalUnknown
	}
	for _, at := range []time.Time{f.OriginalPinStartedAt, f.OriginalPinReturnedAt, f.OriginalSignalCalledAt, f.OriginalSignalReturnedAt, f.OriginalWaitReturnedAt, f.OriginalStderrCloseReturnedAt, f.OriginalPIDFDOffReturnedAt, f.OriginalPIDFDCloseReturnedAt, f.OriginalUnlinkCalledAt, f.OriginalUnlinkReturnedAt, f.OriginalDirectorySyncReturnedAt, f.OriginalAbsenceReturnedAt, f.OriginalDirectoryCloseReturnedAt} {
		if at.IsZero() || at.Before(b.IssuedAt) || !at.Before(b.CleanupDeadline) {
			return f, ErrOriginalUnknown
		}
	}
	// Signal syscall return and the original Wait thread are concurrent. Retain
	// both real stamps; never impose a made-up total order on independent owners.
	if f.OriginalPinReturnedAt.Before(f.OriginalPinStartedAt) || f.OriginalSignalCalledAt.Before(f.OriginalPinReturnedAt) || f.OriginalSignalReturnedAt.Before(f.OriginalSignalCalledAt) || f.OriginalWaitReturnedAt.Before(f.OriginalSignalCalledAt) || f.OriginalStderrCloseReturnedAt.Before(f.OriginalWaitReturnedAt) || f.OriginalPIDFDOffReturnedAt.Before(f.OriginalStderrCloseReturnedAt) || f.OriginalPIDFDCloseReturnedAt.Before(f.OriginalPIDFDOffReturnedAt) || f.OriginalUnlinkCalledAt.Before(f.OriginalPIDFDCloseReturnedAt) || f.OriginalUnlinkReturnedAt.Before(f.OriginalUnlinkCalledAt) || f.OriginalDirectorySyncReturnedAt.Before(f.OriginalUnlinkReturnedAt) || f.OriginalAbsenceReturnedAt.Before(f.OriginalDirectorySyncReturnedAt) || f.OriginalDirectoryCloseReturnedAt.Before(f.OriginalAbsenceReturnedAt) {
		return f, ErrOriginalUnknown
	}
	return f, nil
}
