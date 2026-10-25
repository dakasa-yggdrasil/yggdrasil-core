//go:build linux && nativequalification

package capacitynativeqemu

import (
 "context"
 "os"
 "path/filepath"
 "time"
 "github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
 "github.com/dakasa-yggdrasil/yggdrasil-core/model"
 "golang.org/x/sys/unix"
)

// This is a NEW GET-only observation of the same original source-owned disk
// directory. It is not a provider/billing/auxiliary-IP observation and never
// reruns unlink, poweroff or any Guest command.
type OriginalPostDeleteAbsence struct {
 Schema string `json:"schema"`
 Scope string `json:"scope"`
 CoreSource string `json:"core_source"`
 GuestSource string `json:"guest_source"`
 GrantID string `json:"grant_id"`
 ResourceID string `json:"resource_id"`
 ResourceCreatedAt string `json:"resource_created_at"`
 OriginalDirectory OriginalDisk `json:"original_directory"`
 OriginalDisk OriginalDisk `json:"original_disk"`
 OpenCalledAt time.Time `json:"open_called_at"`
 OpenReturnedAt time.Time `json:"open_returned_at"`
 AbsenceReturnedAt time.Time `json:"absence_returned_at"`
 CloseReturnedAt time.Time `json:"close_returned_at"`
 AbsenceClass string `json:"absence_class"`
 PaidAuxiliaryAuthority bool `json:"paid_auxiliary_authority"`
}

func(r *Realm) ObserveOriginalDeletedDisk(ctx context.Context,grant model.CapacityMutationGrant)(OriginalPostDeleteAbsence,error){
 var result OriginalPostDeleteAbsence
 r.mu.Lock();directory:=r.deleteDirectory;disk:=r.disks[2];native:=r.originals[2];pin:=r.retirementPins[2];deleted:=r.deleted;r.mu.Unlock()
 if !PositiveCase(r.Request.NativeCase) || !deleted || pin==nil || !pin.closed || directory.Device==0 || directory.Inode==0 || disk.Device==0 || disk.Inode==0 || grant.State!="confirmed" || grant.Slot!=2 || grant.Capability!="destroy_server" || grant.ExpectedResourceID!=native.Original.ResourceID || grant.ExpectedResourceCreatedAt!=native.Original.OriginalCreateReturnedAt.UTC().Format(time.RFC3339Nano){return result,ErrOriginalUnknown}
 receipt,err:=r.OriginalMutationReceipt(ctx,grant.GrantID)
 if err!=nil || receipt.Grant.State!="confirmed" || receipt.Grant.GrantID!=grant.GrantID || receipt.Outcome!="accepted" || !receipt.TransportCompleted || !receipt.AuxiliaryInventoryComplete || len(receipt.AuxiliaryResources)!=0{return result,ErrOriginalUnknown}
 result=OriginalPostDeleteAbsence{Schema:"core_original_post_delete_absence_v1",Scope:"same_original_native_qemu_disk_only_not_provider_or_paid_auxiliary",CoreSource:capacity.CurrentGuestCoreSource(),GuestSource:r.Request.SourceCommit,GrantID:grant.GrantID,ResourceID:grant.ExpectedResourceID,ResourceCreatedAt:grant.ExpectedResourceCreatedAt,OriginalDirectory:directory,OriginalDisk:disk,OpenCalledAt:time.Now().UTC(),PaidAuxiliaryAuthority:false}
 if ctx.Err()!=nil{return result,ErrOriginalUnknown}
 fd,err:=unix.Open(SlotDirectory(r.PrivateDirectory,2),unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW,0)
 result.OpenReturnedAt=time.Now().UTC();if err!=nil{return result,ErrOriginalUnknown}
 var before,after,target unix.Stat_t
 beforeErr:=unix.Fstat(fd,&before)
 absentErr:=unix.Fstatat(fd,"original.qcow2",&target,unix.AT_SYMLINK_NOFOLLOW)
 result.AbsenceReturnedAt=time.Now().UTC()
 afterErr:=unix.Fstat(fd,&after);closeErr:=unix.Close(fd);result.CloseReturnedAt=time.Now().UTC()
 if beforeErr!=nil || afterErr!=nil || closeErr!=nil || absentErr!=unix.ENOENT || before.Mode&unix.S_IFMT!=unix.S_IFDIR || before.Uid!=uint32(os.Getuid()) || before.Mode&0022!=0 || uint64(before.Dev)!=directory.Device || before.Ino!=directory.Inode || before.Dev!=after.Dev || before.Ino!=after.Ino || before.Mode!=after.Mode || before.Uid!=after.Uid || before.Gid!=after.Gid || ctx.Err()!=nil{return result,ErrOriginalUnknown}
 result.AbsenceClass="ENOENT"
 if _,err=Publish(ctx,filepath.Join(SlotDirectory(r.PrivateDirectory,2),"delete-readoption-current-absence.json"),result);err!=nil{return result,err}
 return result,nil
}

// SAME original Observe/verify ABI as FreshNativeMember, with the complete
// independent return retained once for the new replay assertion's custody.
func(r *Realm) OriginalReadoptionPresence(ctx context.Context,slot int,b model.CapacityMutationBinding)(model.CapacityMutationProof,error){
 var proof model.CapacityMutationProof
 r.mu.Lock();native,exists:=r.originals[slot];pre:=r.preregistrations[slot];r.mu.Unlock()
 if slot!=2 || !PositiveCase(r.Request.NativeCase) || !exists{return proof,ErrOriginalUnknown}
 original,cancel:=context.WithTimeout(ctx,5*time.Second);defer cancel()
 fresh,err:=Observe(original,SlotDirectory(r.PrivateDirectory,slot),native.Original,r.QEMUBinarySHA256)
 if err!=nil || r.verifyFixedCommand(original,slot,fresh)!=nil{return proof,ErrOriginalUnknown}
 raw,err:=Publish(original,filepath.Join(SlotDirectory(r.PrivateDirectory,slot),"delete-readoption-original-native-read.json"),fresh)
 if err!=nil{return proof,err}
 proof=model.CapacityMutationProof{BindingName:b.Name,Slot:slot,ResourceID:native.Original.ResourceID,ResourceCreatedAt:native.Original.OriginalCreateReturnedAt.UTC().Format(time.RFC3339Nano),RequestSHA256:pre.OriginalCreateRequestSHA256,ObservedAt:fresh.CloseReturnedAt,ReceiptRef:"original-native-qemu-fresh:"+capacity.BusinessCreationSHA256(raw),OwnerVerified:true,SpecVerified:true,ObservedCreationGrantID:pre.OriginalCreateGrantID}
 return proof,nil
}
