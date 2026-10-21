//go:build linux && nativequalification

package message

import (
 "context"
 "encoding/json"
 "errors"
 "path/filepath"
 "time"
 "github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
 q "github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacitynativeqemu"
 "github.com/dakasa-yggdrasil/yggdrasil-core/model"
 "github.com/dakasa-yggdrasil/yggdrasil-core/repository"
)

func sourceNativePostDeleteReadoptionContract(ctx context.Context,store repository.CapacityStore,policy model.Manifest,p model.CapacityPolicySpec,b model.CapacityMutationBinding,input guestOriginalStepInput,absence model.CapacityMutationProof,confirmed model.CapacityMutationGrant)error{
 if originalGuestNativeRealm==nil || !q.PositiveCase(originalGuestNativeRealm.Request.NativeCase) || input.Slot!=2{return errOriginalGuestStep}
 freshAbsence,err:=originalGuestNativeRealm.ObserveOriginalDeletedDisk(ctx,confirmed);if err!=nil{return err}
 var originalPresence model.CapacityMutationProof
 presenceWire,err:=q.ReadPrivate(ctx,filepath.Join(q.SlotDirectory(originalGuestNativeRealm.PrivateDirectory,2),"delete-readoption-original-presence.json"),&originalPresence)
 if err!=nil || originalPresence.Slot!=2 || originalPresence.ResourceAbsent || !originalPresence.OwnerVerified || !originalPresence.SpecVerified || originalPresence.ResourceID!=absence.ResourceID || originalPresence.ResourceCreatedAt!=absence.ResourceCreatedAt || originalPresence.ResourceID!=freshAbsence.ResourceID || originalPresence.ResourceCreatedAt!=freshAbsence.ResourceCreatedAt{return errOriginalGuestStep}
 var desired []byte;for _,slot:=range b.Slots{if slot.Slot==2 && slot.DesiredSpec!=nil{desired,err=json.Marshal(slot.DesiredSpec)}}
 if err!=nil || len(desired)==0 || originalPresence.RequestSHA256!=capacity.BusinessCreationSHA256(desired){return errOriginalGuestStep}
 if err=store.ValidateNativeObservationLease(ctx,policy,input.Generation,input.FencingToken,input.LeaseOwner);err!=nil{return err}
 var prior,after []byte;var beforeAt,afterAt time.Time
 query:=`SELECT slot_record FROM public.capacity_resource_slots WHERE namespace=$1 AND environment=$2 AND domain=$3 AND dimension=$4 AND integration_instance_id=$5 AND scope_checksum=$6 AND profile_name=$7 AND slot=2`
 if err=store.DB.QueryRowContext(ctx,query,policy.Metadata.Namespace,p.Environment,p.Domain,p.Dimension,b.IntegrationInstanceID,b.ScopeChecksum,b.ProfileName).Scan(&prior);err!=nil{return err}
 if _,err=q.PublishBytes(ctx,filepath.Join(q.SlotDirectory(originalGuestNativeRealm.PrivateDirectory,2),"delete-readoption-tombstone-before.json"),prior);err!=nil{return err}
 if err=store.DB.QueryRowContext(ctx,`SELECT clock_timestamp()`).Scan(&beforeAt);err!=nil{return err}
 actualErr:=store.RecordMutationSlot(ctx,policy,input.Generation,input.FencingToken,input.LeaseOwner,model.CapacityMutationIssue{BindingName:b.Name,DesiredSpec:desired},originalPresence)
 if !errors.Is(actualErr,repository.ErrCapacityConflict){return errOriginalGuestStep}
 if err=store.DB.QueryRowContext(ctx,`SELECT clock_timestamp()`).Scan(&afterAt);err!=nil{return err}
 if err=store.DB.QueryRowContext(ctx,query,policy.Metadata.Namespace,p.Environment,p.Domain,p.Dimension,b.IntegrationInstanceID,b.ScopeChecksum,b.ProfileName).Scan(&after);err!=nil || string(prior)!=string(after){return errOriginalGuestStep}
 if _,err=q.PublishBytes(ctx,filepath.Join(q.SlotDirectory(originalGuestNativeRealm.PrivateDirectory,2),"delete-readoption-tombstone-after.json"),after);err!=nil{return err}
 var tombstone struct{Tombstone bool `json:"tombstone"`;ResourceID string `json:"resource_id"`;ResourceCreatedAt string `json:"resource_created_at"`}
 if json.Unmarshal(after,&tombstone)!=nil || !tombstone.Tombstone || tombstone.ResourceID!="" || tombstone.ResourceCreatedAt!=originalPresence.ResourceCreatedAt{return errOriginalGuestStep}
 // Do not re-stamp the original live tuple after deletion. A legitimate
 // stale proof refusal is recorded as stale, never credited to tombstone.
 freshAtAttempt:=capacity.Fresh(originalPresence.ObservedAt,beforeAt,p.MaxEvidenceAgeSeconds) && capacity.Fresh(originalPresence.ObservedAt,afterAt,p.MaxEvidenceAgeSeconds)
 class:="tombstone_or_other_original_guard_with_fresh_original_tuple"
 if !freshAtAttempt{class="stale_original_tuple_no_exclusive_tombstone_credit"}
 contract:=struct{
  Schema string `json:"schema"`;Scope string `json:"scope"`;CoreSource string `json:"core_source"`;GuestSource string `json:"guest_source"`;GrantID string `json:"grant_id"`;ResourceID string `json:"resource_id"`;ResourceCreatedAt string `json:"resource_created_at"`;OriginalPresenceSHA256 string `json:"original_presence_sha256"`;CurrentAbsenceSHA256 string `json:"current_absence_sha256"`;TombstoneBeforeSHA256 string `json:"tombstone_before_sha256"`;TombstoneAfterSHA256 string `json:"tombstone_after_sha256"`;OriginalObservedAt time.Time `json:"original_observed_at"`;AttemptBeforeAt time.Time `json:"attempt_before_at"`;AttemptAfterAt time.Time `json:"attempt_after_at"`;FreshAtAttempt bool `json:"fresh_at_attempt"`;RefusalClass string `json:"refusal_class"`;RecordRefused bool `json:"record_refused"`;TombstoneUnchanged bool `json:"tombstone_unchanged"`;PaidAuxiliaryAuthority bool `json:"paid_auxiliary_authority"`;ExclusiveTombstoneCredit bool `json:"exclusive_tombstone_credit"`
 }{"core_original_post_delete_readoption_v1","NATIVE_QEMU_ORIGINAL_READOPTION_ONLY_NOT_PROVIDER_PAID_AUXILIARY",capacity.CurrentGuestCoreSource(),originalGuestNativeRealm.Request.SourceCommit,confirmed.GrantID,originalPresence.ResourceID,originalPresence.ResourceCreatedAt,capacity.BusinessCreationSHA256(presenceWire),capacity.GuestRetirementSHA(freshAbsence),capacity.BusinessCreationSHA256(prior),capacity.BusinessCreationSHA256(after),originalPresence.ObservedAt,beforeAt,afterAt,freshAtAttempt,class,true,true,false,false}
 _,err=q.Publish(ctx,filepath.Join(q.SlotDirectory(originalGuestNativeRealm.PrivateDirectory,2),"delete-readoption-contract.json"),contract);return err
}
