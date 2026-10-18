//go:build linux && nativequalification

package capacitynativeqemu

import (
 "context"
 "crypto/ed25519"
 "encoding/base64"
 "encoding/json"
 "path/filepath"
 "os"
 "strings"
 "golang.org/x/sys/unix"
 "time"

 "github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
 "github.com/dakasa-yggdrasil/yggdrasil-core/model"
 "github.com/dakasa-yggdrasil/yggdrasil-core/repository"
 "github.com/google/uuid"
)

func SourceCompensationCase(s string) bool {
 switch s { case "canonical_compensation_unprotected_failed_create", "canonical_compensation_protected_failed_create", "canonical_failed_floor_recovery", "compensation_unprotected_failed_create","compensation_protected_failed_create","compensation_unprotected_lost_create_reply","compensation_protected_lost_create_reply","source_live_failed_floor_recovery":return true };return false
}
func SourceLostCreateCase(s string) bool { return s=="compensation_unprotected_lost_create_reply" || s=="compensation_protected_lost_create_reply" }
func SourceProtectedCompensationCase(s string) bool { return s=="canonical_compensation_protected_failed_create" || s=="compensation_protected_failed_create" || s=="compensation_protected_lost_create_reply" }

// Host-original source authority, never an enrollment or successful Guest
// retirement. Unenrolled uncertain creations are explicitly cleanup-only.
type SourceFailureCleanupBody struct {
 Schema string `json:"schema"`
 SourceSlotDirectory string `json:"source_slot_directory"`
 SourceDirectoryDevice uint64 `json:"source_directory_device"`
 SourceDirectoryInode uint64 `json:"source_directory_inode"`
 OriginalHostBootID string `json:"original_host_boot_id"`
 Mode string `json:"mode"`
 Scope string `json:"scope"`
 AuthorityID string `json:"authority_id"`
 NativeCase string `json:"native_case"`
 CoreSource string `json:"core_source"`
 GuestSource string `json:"guest_source"`
 CreatorSourceSHA256 string `json:"creator_source_sha256"`
 PreregistrationID string `json:"preregistration_id"`
 ParentGrantID string `json:"parent_grant_id"`
 PolicyID string `json:"policy_id"`
 PolicyChecksum string `json:"policy_checksum"`
 OriginalReceiptSHA256 string `json:"original_receipt_sha256"`
 OriginalOutcome string `json:"original_outcome"`
 FailureSHA256 string `json:"failure_sha256"`
 EnrollmentSHA256 string `json:"enrollment_sha256"`
 CreatorSHA256 string `json:"creator_sha256"`
 NativeReadSHA256 string `json:"native_read_sha256"`
 Slot int `json:"slot"`
 ResourceID string `json:"resource_id"`
 ResourceCreatedAt string `json:"resource_created_at"`
 QEMU Process `json:"qemu"`
 OriginalDisk OriginalDisk `json:"original_disk"`
 IssuedAt time.Time `json:"issued_at"`
 OriginalProvisioningDeadline time.Time `json:"original_provisioning_deadline"`
 OriginalContextDeadline time.Time `json:"original_context_deadline"`
 CleanupDeadline time.Time `json:"cleanup_deadline"`
 BaselineMembers int `json:"baseline_members"`
 FailedSlotMembers int `json:"failed_slot_members"`
 FailedSlotEnsuredEvents int `json:"failed_slot_ensured_events"`
 ProductionQualified bool `json:"production_qualified"`
 PositiveQuiescence bool `json:"positive_quiescence"`
}
type SourceFailureCleanupAuthority struct {
 Body []byte `json:"body"`
 Signature string `json:"signature"`
}
type SourceFailureCleanupPhysical struct {
 Schema string `json:"schema"`
 Scope string `json:"scope"`
 AuthoritySHA256 string `json:"authority_sha256"`
 CoreSource string `json:"core_source"`
 GuestSource string `json:"guest_source"`
 Slot int `json:"slot"`
 ResourceID string `json:"resource_id"`
 QEMU Process `json:"qemu"`
 OriginalDisk OriginalDisk `json:"original_disk"`
 OriginalPinStartedAt time.Time `json:"original_pin_started_at"`
 OriginalPinReturnedAt time.Time `json:"original_pin_returned_at"`
 OriginalSignalCalledAt time.Time `json:"original_signal_called_at"`
 OriginalSignalReturnedAt time.Time `json:"original_signal_returned_at"`
 OriginalSignal int `json:"original_signal"`
 OriginalWaitCode int `json:"original_wait_code"`
 OriginalWaitReturnedAt time.Time `json:"original_wait_returned_at"`
 OriginalStderrEOF bool `json:"original_stderr_eof"`
 OriginalStderrCloseReturnedAt time.Time `json:"original_stderr_close_returned_at"`
 OriginalPIDFDOffReturnedAt time.Time `json:"original_pidfd_off_returned_at"`
 OriginalPIDFDCloseReturnedAt time.Time `json:"original_pidfd_close_returned_at"`
 OriginalUnlinkCalledAt time.Time `json:"original_unlink_called_at"`
 OriginalUnlinkReturnedAt time.Time `json:"original_unlink_returned_at"`
 OriginalDirectorySyncReturnedAt time.Time `json:"original_directory_sync_returned_at"`
 OriginalAbsenceReturnedAt time.Time `json:"original_absence_returned_at"`
 OriginalDirectoryCloseReturnedAt time.Time `json:"original_directory_close_returned_at"`
 AbsenceClass string `json:"absence_class"`
 PositiveQuiescence bool `json:"positive_quiescence"`
 ProductionQualified bool `json:"production_qualified"`
}

func (r *Realm) PrepareSourceFailureCleanup(ctx context.Context,store repository.CapacityStore,policy model.Manifest,pre model.CapacityGuestOriginalProvisioningPreregistration,failureSHA,enrollmentSHA string,key ed25519.PrivateKey) (SourceFailureCleanupAuthority,SourceFailureCleanupBody,error) {
 var authority SourceFailureCleanupAuthority;var body SourceFailureCleanupBody
 if !SourceCompensationCase(r.Request.NativeCase) || pre.Slot!=2 || len(key)!=ed25519.PrivateKeySize || ctx.Err()!=nil || pre.CoreSourceCommit!=capacity.CurrentGuestCoreSource() || policy.Metadata.Namespace=="" || pre.WorkflowID!=store.WorkflowID.String() { return authority,body,ErrOriginalUnknown }
 r.mu.Lock();native,ok:=r.originals[2];disk,known:=r.disks[2];r.mu.Unlock()
 if !ok || !known || native.OriginalDisk!=disk { return authority,body,ErrOriginalUnknown }
 receipt,err:=r.OriginalMutationReceipt(ctx,pre.OriginalCreateGrantID);if err!=nil || receipt.Grant.State!="settled" || !receipt.TransportCompleted { return authority,body,ErrOriginalUnknown }
 lost:=SourceLostCreateCase(r.Request.NativeCase)
 if lost { if receipt.Outcome!="uncertain" || receipt.ResourceID!="" || receipt.ResourceCreatedAt!="" || failureSHA!="" || enrollmentSHA!="" { return authority,body,ErrOriginalUnknown } } else if receipt.Outcome!="accepted" || !validSHA(failureSHA) || !validSHA(enrollmentSHA) { return authority,body,ErrOriginalUnknown }
 var members,failed,events int
 if err=store.DB.QueryRowContext(ctx,`SELECT count(*) FILTER (WHERE resource_id<>''),count(*) FILTER (WHERE slot=2 AND resource_id<>'') FROM public.capacity_resource_slots WHERE namespace=$1`,policy.Metadata.Namespace).Scan(&members,&failed);err!=nil || members!=1 || failed!=0 { return authority,body,ErrOriginalUnknown }
 if err=store.DB.QueryRowContext(ctx,`SELECT count(*) FROM public.event_log WHERE idempotency_key=$1`,"capacity-mutation/"+pre.OriginalCreateGrantID).Scan(&events);err!=nil || events!=0 { return authority,body,ErrOriginalUnknown }
 // Read the ACTUAL private current lease, never a cached grant expiry or
 // an invented successor. This creates no lease and renews no clock.
 var policySpec model.CapacityPolicySpec
 if json.Unmarshal(policy.Spec,&policySpec)!=nil{return authority,body,ErrOriginalUnknown}
 if err=store.CheckSourceFailureCleanupLease(ctx,policy,pre.OriginalCreateGrantID);err!=nil{return authority,body,err}
 currentLease,err:=sourceFencePrivateIntent(ctx,store,policy,policySpec)
 if err!=nil || currentLease.Generation!=pre.Generation || currentLease.FencingToken!=pre.Fence || currentLease.LeaseOwner!=pre.LeaseOwner || currentLease.LeaseExecutorID!=pre.ExecutorID || currentLease.LeaseExpiresAt==nil || currentLease.RecoveryOnly {return authority,body,ErrOriginalUnknown}
 now:=time.Now().UTC();deadline:=now.Add(150*time.Second);parent,ok:=ctx.Deadline();if !ok { return authority,body,ErrOriginalUnknown };if parent.Before(deadline){deadline=parent};if r.Request.OriginalContextDeadline.Before(deadline){deadline=r.Request.OriginalContextDeadline};if currentLease.LeaseExpiresAt.Before(deadline){deadline=*currentLease.LeaseExpiresAt};if !now.Before(deadline){return authority,body,ErrOriginalUnknown}
 directory,err:=unix.Open(SlotDirectory(r.PrivateDirectory,2),unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC,0);if err!=nil{return authority,body,err}
 var directoryStat unix.Stat_t;se:=unix.Fstat(directory,&directoryStat);ce:=unix.Close(directory);if se!=nil || ce!=nil{return authority,body,ErrOriginalUnknown}
 hostBoot,err:=os.ReadFile("/proc/sys/kernel/random/boot_id");if err!=nil || !validUUID(strings.TrimSpace(string(hostBoot))){return authority,body,ErrOriginalUnknown}
 body=SourceFailureCleanupBody{Schema:"original_source_failure_cleanup_authority_v1",SourceSlotDirectory:SlotDirectory(r.PrivateDirectory,2),SourceDirectoryDevice:uint64(directoryStat.Dev),SourceDirectoryInode:directoryStat.Ino,OriginalHostBootID:strings.TrimSpace(string(hostBoot)),Mode:"failure_cleanup_only",Scope:"same_original_host_qemu_cleanup_not_guest_positive_retirement",AuthorityID:uuid.NewString(),NativeCase:r.Request.NativeCase,CoreSource:capacity.CurrentGuestCoreSource(),GuestSource:r.Request.SourceCommit,CreatorSourceSHA256:r.Request.CreatorSourceSHA256,PreregistrationID:pre.PreregistrationID,ParentGrantID:pre.OriginalCreateGrantID,PolicyID:policy.ID.String(),PolicyChecksum:policy.Checksum,OriginalReceiptSHA256:capacity.GuestRetirementSHA(receipt),OriginalOutcome:receipt.Outcome,FailureSHA256:failureSHA,EnrollmentSHA256:enrollmentSHA,CreatorSHA256:native.OriginalCreatorSHA256,NativeReadSHA256:capacity.GuestRetirementSHA(native),Slot:2,ResourceID:native.Original.ResourceID,ResourceCreatedAt:native.Original.OriginalCreateReturnedAt.UTC().Format(time.RFC3339Nano),QEMU:native.Original.QEMU,OriginalDisk:disk,IssuedAt:now,OriginalProvisioningDeadline:pre.OriginalDeadline,OriginalContextDeadline:r.Request.OriginalContextDeadline,CleanupDeadline:deadline,BaselineMembers:members,FailedSlotMembers:failed,FailedSlotEnsuredEvents:events,ProductionQualified:false,PositiveQuiescence:false}
 authority.Body,err=json.Marshal(body);if err!=nil{return authority,body,err};authority.Signature=base64.StdEncoding.EncodeToString(ed25519.Sign(key,authority.Body))
 return authority,body,nil
}

func (r *Realm) ReadSourceFailureCleanup(ctx context.Context,a SourceFailureCleanupAuthority,b SourceFailureCleanupBody) (SourceFailureCleanupPhysical,error) {
 var f SourceFailureCleanupPhysical
 original,cancel:=context.WithDeadline(ctx,b.CleanupDeadline);defer cancel()
 if _,err:=Await(original,filepath.Join(SlotDirectory(r.PrivateDirectory,2),"source-failure-cleanup-physical.json"),&f);err!=nil{return f,err}
 if f.Schema!="original_source_failure_cleanup_physical_v1" || f.Scope!="host_owned_failure_cleanup_only_not_positive_retirement" || f.AuthoritySHA256!=capacity.GuestRetirementSHA(a) || f.CoreSource!=b.CoreSource || f.GuestSource!=b.GuestSource || f.Slot!=2 || f.ResourceID!=b.ResourceID || f.QEMU!=b.QEMU || f.OriginalDisk!=b.OriginalDisk || f.OriginalSignal!=9 || f.OriginalWaitCode!=-9 || !f.OriginalStderrEOF || f.AbsenceClass!="ENOENT" || f.PositiveQuiescence || f.ProductionQualified {return f,ErrOriginalUnknown}
 for _,at:=range []time.Time{f.OriginalPinStartedAt,f.OriginalPinReturnedAt,f.OriginalSignalCalledAt,f.OriginalSignalReturnedAt,f.OriginalWaitReturnedAt,f.OriginalStderrCloseReturnedAt,f.OriginalPIDFDOffReturnedAt,f.OriginalPIDFDCloseReturnedAt,f.OriginalUnlinkCalledAt,f.OriginalUnlinkReturnedAt,f.OriginalDirectorySyncReturnedAt,f.OriginalAbsenceReturnedAt,f.OriginalDirectoryCloseReturnedAt}{if at.IsZero() || at.Before(b.IssuedAt) || !at.Before(b.CleanupDeadline){return f,ErrOriginalUnknown}}
 // Signal syscall return and the original Wait thread are concurrent. Retain
 // both real stamps; never impose a made-up total order on independent owners.
 if f.OriginalPinReturnedAt.Before(f.OriginalPinStartedAt) || f.OriginalSignalCalledAt.Before(f.OriginalPinReturnedAt) || f.OriginalSignalReturnedAt.Before(f.OriginalSignalCalledAt) || f.OriginalWaitReturnedAt.Before(f.OriginalSignalCalledAt) || f.OriginalStderrCloseReturnedAt.Before(f.OriginalWaitReturnedAt) || f.OriginalPIDFDOffReturnedAt.Before(f.OriginalStderrCloseReturnedAt) || f.OriginalPIDFDCloseReturnedAt.Before(f.OriginalPIDFDOffReturnedAt) || f.OriginalUnlinkCalledAt.Before(f.OriginalPIDFDCloseReturnedAt) || f.OriginalUnlinkReturnedAt.Before(f.OriginalUnlinkCalledAt) || f.OriginalDirectorySyncReturnedAt.Before(f.OriginalUnlinkReturnedAt) || f.OriginalAbsenceReturnedAt.Before(f.OriginalDirectorySyncReturnedAt) || f.OriginalDirectoryCloseReturnedAt.Before(f.OriginalAbsenceReturnedAt){return f,ErrOriginalUnknown}
 return f,nil
}

func CanonicalSourceCompensationCase(s string) bool {return s=="canonical_compensation_unprotected_failed_create" || s=="canonical_compensation_protected_failed_create" || s=="canonical_failed_floor_recovery"}
