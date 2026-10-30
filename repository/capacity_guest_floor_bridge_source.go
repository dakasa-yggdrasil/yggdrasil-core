//go:build linux && nativequalification

package repository

import (
 "context"
 "database/sql"
 "encoding/json"
 "bytes"
 "github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
 "github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

// This is not generic policy compatibility. The only permitted source delta
// is floor1 -> floor2 with the sole profile minimum also 1 -> 2, same
// canonical namespace/name and immediate version.
func sourceFloorBridgeTx(ctx context.Context,tx *sql.Tx,policy model.Manifest,p model.CapacityPolicySpec,stored guestOriginalStored) error {
 if !capacity.GuestOriginalNativeQEMUProviderEnabled("native-qemu") || p.Floor!=2 || p.Ceiling!=2 || stored.pre.CoreSourceCommit!=capacity.CurrentGuestCoreSource() || stored.pre.PolicyID==policy.ID.String(){return ErrCapacityConflict}
 var oldID,newID,oldSHA,newSHA,namespace,name,source,guest string
 if err:=tx.QueryRowContext(ctx,`SELECT original_policy_id::text,current_policy_id::text,original_checksum,current_checksum,namespace,policy_name,core_source,guest_source FROM public.capacity_guest_floor_source_bridges WHERE current_policy_id=$1`,policy.ID).Scan(&oldID,&newID,&oldSHA,&newSHA,&namespace,&name,&source,&guest);err!=nil{return err}
 if oldID!=stored.pre.PolicyID || oldSHA!=stored.pre.PolicyChecksum || newID!=policy.ID.String() || newSHA!=policy.Checksum || namespace!=policy.Metadata.Namespace || name!=policy.Metadata.Name || source!=capacity.CurrentGuestCoreSource() || guest!=stored.binding.GuestSourceCommit{return ErrCapacityConflict}
 var oldRaw,newRaw []byte;var oldVersion,newVersion int;var oldActive,newActive bool;var oldKind,newKind,oldNS,newNS,oldName,newName,oldChecksum,newChecksum string
 if err:=tx.QueryRowContext(ctx,`SELECT kind,namespace,name,version,active,checksum,spec FROM public.manifests WHERE id=$1`,oldID).Scan(&oldKind,&oldNS,&oldName,&oldVersion,&oldActive,&oldChecksum,&oldRaw);err!=nil{return err}
 if err:=tx.QueryRowContext(ctx,`SELECT kind,namespace,name,version,active,checksum,spec FROM public.manifests WHERE id=$1`,newID).Scan(&newKind,&newNS,&newName,&newVersion,&newActive,&newChecksum,&newRaw);err!=nil{return err}
 if oldKind!="capacity_policy" || newKind!=oldKind || oldNS!=namespace || newNS!=namespace || oldName!=name || newName!=name || oldActive || !newActive || oldChecksum!=oldSHA || newChecksum!=newSHA || newVersion!=oldVersion+1{return ErrCapacityConflict}
 if !sourceFloorPolicyExactDelta(oldRaw,newRaw){return ErrCapacityConflict}
 var before,after model.CapacityPolicySpec
 if json.Unmarshal(oldRaw,&before)!=nil || json.Unmarshal(newRaw,&after)!=nil || before.Floor!=1 || after.Floor!=2 || before.Ceiling!=2 || after.Ceiling!=2 || len(before.Profiles)!=1 || len(after.Profiles)!=1 || before.Profiles[0].MinUnits!=1 || after.Profiles[0].MinUnits!=2 || capacity.ValidatePolicy(before)!=nil || capacity.ValidatePolicy(after)!=nil{return ErrCapacityConflict}
 // Full typed spec equality after reverting exactly the stronger floor and
 // its required profile minimum.
 // Source producer creates both original specs from this closed model.
 after.Floor=1;after.Profiles[0].MinUnits=1
 if capacity.GuestRetirementSHA(before)!=capacity.GuestRetirementSHA(after) || before.GuestRetirementBinding==nil || capacity.GuestRetirementSHA(*before.GuestRetirementBinding)!=capacity.GuestRetirementSHA(stored.binding){return ErrCapacityConflict}
 return nil
}

// The bridge only admits these two explicit numeric changes in the original
// stored JSON. Any extra key, profile, or changed value remains a refusal.
func sourceFloorPolicyExactDelta(oldRaw,newRaw []byte) bool {
 var oldObject,newObject map[string]any
 oldDecoder:=json.NewDecoder(bytes.NewReader(oldRaw));oldDecoder.UseNumber()
 newDecoder:=json.NewDecoder(bytes.NewReader(newRaw));newDecoder.UseNumber()
 if oldDecoder.Decode(&oldObject)!=nil || newDecoder.Decode(&newObject)!=nil || oldObject["floor"]!=json.Number("1") || newObject["floor"]!=json.Number("2"){return false}
 oldProfiles,ok:=oldObject["profiles"].([]any);if !ok || len(oldProfiles)!=1{return false}
 newProfiles,ok:=newObject["profiles"].([]any);if !ok || len(newProfiles)!=1{return false}
 oldProfile,ok:=oldProfiles[0].(map[string]any);if !ok{return false}
 newProfile,ok:=newProfiles[0].(map[string]any);if !ok || oldProfile["min_units"]!=json.Number("1") || newProfile["min_units"]!=json.Number("2"){return false}
 newObject["floor"]=json.Number("1");newProfile["min_units"]=json.Number("1")
 oldCanonical,e1:=json.Marshal(oldObject);newCanonical,e2:=json.Marshal(newObject)
 return e1==nil && e2==nil && bytes.Equal(oldCanonical,newCanonical)
}
