//go:build linux && nativequalification

package capacitynativeqemu

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	"github.com/google/uuid"
	"golang.org/x/sys/unix"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

type OriginalDisk = repository.GuestNativeQEMUOriginalDisk
type OriginalDeleteReturn = repository.GuestNativeQEMUOriginalDeleteReturn

func originalDiskAt(ctx context.Context, path string) (OriginalDisk, error) {
	var stat unix.Stat_t
	if ctx.Err() != nil || unix.Lstat(path, &stat) != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Uid != uint32(os.Getuid()) {
		return OriginalDisk{}, ErrOriginalUnknown
	}
	return OriginalDisk{uint64(stat.Dev), stat.Ino}, nil
}
func (r *Realm) rememberOriginalDisk(ctx context.Context, slot int) error {
	identity, err := originalDiskAt(ctx, filepath.Join(SlotDirectory(r.PrivateDirectory, slot), "original.qcow2"))
	if err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.disks == nil {
		r.disks = map[int]OriginalDisk{}
	}
	if _, exists := r.disks[slot]; exists {
		return ErrOriginalUnknown
	}
	r.disks[slot] = identity
	return nil
}

func (r *Realm) OriginalMutationReceipt(ctx context.Context, id string) (model.CapacityMutationReceipt, error) {
	var receipt model.CapacityMutationReceipt
	if !validUUID(id) {
		return receipt, ErrOriginalUnknown
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, r.CoreOrigin+"/api/v1/capacity/mutations/"+id, nil)
	if err != nil {
		return receipt, err
	}
	request.Header.Set("Authorization", "Bearer "+r.MutationToken)
	response, err := r.Client.Do(request)
	if err != nil {
		return receipt, ErrOriginalUnknown
	}
	body, re := io.ReadAll(io.LimitReader(response.Body, 2<<20))
	ce := response.Body.Close()
	if re != nil || ce != nil || ctx.Err() != nil || len(body) == 2<<20 || response.StatusCode != 200 || closedJSON(body, &receipt) != nil || receipt.Grant.GrantID != id {
		return receipt, ErrOriginalUnknown
	}
	return receipt, nil
}

// The sole native mutation is an authorized unlink of the exact source-owned
// burst disk AFTER original Guest quiescence, QEMU exit, Wait and PIDFD join.
// No physical provider request or paid-resource/billing claim is involved.
func (r *Realm) DestroyOriginal(ctx context.Context, grant model.CapacityMutationGrant) (repository.GuestNativeQEMUDeleteReadback, error) {
	var observed repository.GuestNativeQEMUDeleteReadback
	r.mu.Lock()
	pin := r.retirementPins[2]
	disk, known := r.disks[2]
	native := r.originals[2]
	if r.deleted {
		r.mu.Unlock()
		return observed, ErrOriginalUnknown
	}
	r.mu.Unlock()
	if grant.Slot != 2 || grant.Capability != "destroy_server" || grant.ExpectedResourceID != native.Original.ResourceID || grant.ExpectedResourceCreatedAt != native.Original.OriginalCreateReturnedAt.UTC().Format(time.RFC3339Nano) || pin == nil || !pin.closed || pin.fact.OriginalCloseReturnedAt.IsZero() || !known || !PositiveCase(r.Request.NativeCase) {
		return observed, ErrOriginalUnknown
	}
	var nonceRaw [32]byte
	if _, err := rand.Read(nonceRaw[:]); err != nil {
		return observed, err
	}
	nonce := hex.EncodeToString(nonceRaw[:])
	attempt := uuid.NewString()
	redeem := model.CapacityMutationRedeemRequest{GrantID: grant.GrantID, AttemptID: attempt, SettlementTokenSHA256: capacity.BusinessCreationSHA256([]byte(nonce)), Capability: grant.Capability, IntegrationInstanceID: grant.IntegrationInstanceID, ScopeChecksum: grant.ScopeChecksum, ProfileName: grant.ProfileName, Slot: 2, RequestSHA256: grant.RequestSHA256, ExpectedResourceID: grant.ExpectedResourceID, ExpectedResourceCreatedAt: grant.ExpectedResourceCreatedAt}
	var redeemed model.CapacityMutationRedeemResponse
	if r.api(ctx, "/api/v1/capacity/mutations/redeem", "", redeem, &redeemed) != nil || redeemed.Mode != "write_once" || redeemed.GrantID != grant.GrantID || redeemed.AttemptID != attempt {
		return observed, ErrOriginalUnknown
	}
	dir := SlotDirectory(r.PrivateDirectory, 2)
	fd, err := unix.Open(dir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return observed, ErrOriginalUnknown
	}
	directory := os.NewFile(uintptr(fd), dir)
	closed := false
	defer func() {
		if !closed {
			_ = directory.Close()
		}
	}()
	var anchored unix.Stat_t
	if unix.Fstatat(fd, "original.qcow2", &anchored, unix.AT_SYMLINK_NOFOLLOW) != nil || anchored.Mode&unix.S_IFMT != unix.S_IFREG || uint64(anchored.Dev) != disk.Device || anchored.Ino != disk.Inode || ctx.Err() != nil {
		return observed, ErrOriginalUnknown
	}
	fact := OriginalDeleteReturn{Schema: "core_original_native_qemu_disk_delete_v1", Scope: "original_source_owned_native_qemu_disk_only_not_physical_provider_or_billing", GrantID: grant.GrantID, AttemptID: attempt, ResourceID: grant.ExpectedResourceID, CreatorOriginalSHA256: native.OriginalCreatorSHA256, OriginalDisk: disk, OriginalUnlinkCalledAt: time.Now().UTC()}
	var sourceDirectory unix.Stat_t
	if unix.Fstat(fd,&sourceDirectory)!=nil || sourceDirectory.Mode&unix.S_IFMT!=unix.S_IFDIR || sourceDirectory.Uid!=uint32(os.Getuid()) || sourceDirectory.Mode&0022!=0 {return observed,ErrOriginalUnknown}
	r.mu.Lock()
	r.deleteDirectory=OriginalDisk{Device:uint64(sourceDirectory.Dev),Inode:sourceDirectory.Ino}
	r.deleted = true
	r.mu.Unlock() // possible unlink is never retried
	err = unix.Unlinkat(fd, "original.qcow2", 0)
	fact.OriginalUnlinkReturnedAt = time.Now().UTC()
	if err != nil {
		return observed, ErrOriginalUnknown
	}
	err = directory.Sync()
	fact.OriginalDirectorySyncReturnedAt = time.Now().UTC()
	if err != nil {
		return observed, ErrOriginalUnknown
	}
	absentErr := unix.Fstatat(fd, "original.qcow2", &anchored, unix.AT_SYMLINK_NOFOLLOW)
	fact.OriginalAbsenceReturnedAt = time.Now().UTC()
	closeErr := directory.Close()
	closed = true
	fact.OriginalDirectoryCloseReturnedAt = time.Now().UTC()
	if absentErr != unix.ENOENT || closeErr != nil || ctx.Err() != nil {
		return observed, ErrOriginalUnknown
	}
	raw, err := Publish(ctx, filepath.Join(dir, "core-original-native-disk-delete.json"), fact)
	if err != nil {
		return observed, err
	}
	actionID := "qemu-original-disk-unlink:" + digest(raw)
	settlement := model.CapacityMutationSettleRequest{GrantID: grant.GrantID, AttemptID: attempt, RequestSHA256: grant.RequestSHA256, Outcome: "accepted", TransportCompleted: true, ResourceID: grant.ExpectedResourceID, ResourceCreatedAt: grant.ExpectedResourceCreatedAt, ActionID: actionID, ObservedAt: fact.OriginalDirectoryCloseReturnedAt.UTC().Format(time.RFC3339Nano), AuxiliaryInventoryComplete: true}
	var settled struct {
		GrantID       string `json:"grant_id"`
		AttemptID     string `json:"attempt_id"`
		RequestSHA256 string `json:"request_sha256"`
		Status        string `json:"status"`
	}
	if r.api(ctx, "/api/v1/capacity/mutations/settle", nonce, settlement, &settled) != nil || settled.Status != "settled" || settled.GrantID != grant.GrantID || settled.AttemptID != attempt {
		return observed, ErrOriginalUnknown
	}
	receipt, err := r.OriginalMutationReceipt(ctx, grant.GrantID)
	if err != nil || receipt.Grant.State != "settled" || receipt.Outcome != "accepted" || !receipt.TransportCompleted || receipt.ActionID != actionID || !receipt.AuxiliaryInventoryComplete {
		return observed, ErrOriginalUnknown
	}
	// A new read of the exact anchored directory is GET-only recovery. Action
	// timestamps retain the original unlink; they are never a second DELETE.
	at := time.Now().UTC()
	fd, err = unix.Open(dir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return observed, ErrOriginalUnknown
	}
	absentErr = unix.Fstatat(fd, "original.qcow2", &anchored, unix.AT_SYMLINK_NOFOLLOW)
	serverAt := time.Now().UTC()
	closeErr = unix.Close(fd)
	end := time.Now().UTC()
	if absentErr != unix.ENOENT || closeErr != nil || ctx.Err() != nil {
		return observed, ErrOriginalUnknown
	}
	observed = repository.GuestNativeQEMUDeleteReadback{Schema: "core_original_native_qemu_disk_absence_readback_v1", Scope: "same_original_native_qemu_authorized_disk_only_no_physical_provider_or_billing_claim", CoreSourceCommit: capacity.CurrentGuestCoreSource(), GuestSourceCommit: r.Request.SourceCommit, GrantID: grant.GrantID, GrantState: receipt.Grant.State, AttemptID: attempt, ActionID: actionID, ResourceID: grant.ExpectedResourceID, ResourceCreatedAt: grant.ExpectedResourceCreatedAt, OriginalDelete: fact, OriginalDeleteSHA256: digest(raw), OriginalObservationStartedAt: at, OriginalAbsenceErrorClass: "ENOENT", OriginalAbsenceReturnedAt: serverAt, OriginalDirectoryCloseReturnedAt: end}
	if _, err = Publish(ctx, filepath.Join(dir, "core-original-native-delete-readback.json"), observed); err != nil {
		return observed, err
	}
	return observed, nil
}
