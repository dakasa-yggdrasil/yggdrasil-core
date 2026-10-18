//go:build linux && nativequalification
package message
import("context";"path/filepath";q "github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacitynativeqemu";"github.com/dakasa-yggdrasil/yggdrasil-core/model";"github.com/dakasa-yggdrasil/yggdrasil-core/repository")
// Called after this SAME resolved source-owned step generated its original
// nonce/context. It never accepts caller-supplied private Source authority.
func guestOriginalCanonicalFloorPermission(ctx context.Context,store repository.CapacityStore,policy model.Manifest,input guestOriginalStepInput,issue model.CapacityMutationIssue)(any,bool,error){
 if originalGuestNativeRealm==nil || originalGuestNativeRealm.Request.NativeCase!="canonical_failed_floor_recovery" || input.Slot!=2{return nil,false,nil}
 handled,err:=store.CanonicalFloorNextPermission(ctx,policy,input.Generation,input.FencingToken,input.LeaseOwner);if !handled || err!=nil{return nil,handled,err}
 grant,err:=store.IssueMutation(ctx,policy,input.Generation,input.FencingToken,input.LeaseOwner,issue);if err!=nil || grant.State!="issued" || grant.CompensationOf!=""{return nil,true,errOriginalGuestStep}
 pre,err:=store.OriginalGuestProvisioning(ctx,grant.GrantID);if err!=nil || pre.OriginalCreateGrantID!=grant.GrantID || pre.Generation!=input.Generation{return nil,true,errOriginalGuestStep}
 // No Redeem/Create/actor/bootstrap command occurs in this branch.
 if _,err=q.Publish(ctx,filepath.Join(originalGuestNativeRealm.PrivateDirectory,"canonical-floor-next-grant.json"),grant);err!=nil{return nil,true,err}
 return map[string]any{"schema":"canonical_original_next_floor_permission_v1","grant_id":grant.GrantID,"preregistration_id":pre.PreregistrationID,"state":"issued","redeemed":false,"physical_create_called":false,"provider_prepare_performed":false},true,nil
}

func guestOriginalCanonicalFloorPreparing(ctx context.Context,store repository.CapacityStore,policy model.Manifest,input guestOriginalStepInput)(bool,error){
 if originalGuestNativeRealm==nil || originalGuestNativeRealm.Request.NativeCase!="canonical_failed_floor_recovery" || input.Slot!=2{return false,nil}
 return store.CanonicalFloorNextPermission(ctx,policy,input.Generation,input.FencingToken,input.LeaseOwner)
}
