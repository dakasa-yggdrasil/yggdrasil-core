//go:build linux && nativequalification
package capacitynativeqemu
import("context";"crypto/rand";"encoding/hex";"path/filepath";"time";"github.com/google/uuid";"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity";"github.com/dakasa-yggdrasil/yggdrasil-core/model")
func(r *Realm) ExpireCanonicalPostlossUnusedChild(ctx context.Context,child model.CapacityMutationGrant)(model.CapacityMutationRedeemResponse,error){
 var response model.CapacityMutationRedeemResponse;var random [32]byte
 if !PostlossSourceCase(r.Request.NativeCase) || child.State!="issued" || child.CompensationOf=="" || child.Slot!=2{return response,ErrOriginalUnknown};if _,err:=rand.Read(random[:]);err!=nil{return response,err}
 request:=model.CapacityMutationRedeemRequest{GrantID:child.GrantID,AttemptID:uuid.NewString(),SettlementTokenSHA256:capacity.BusinessCreationSHA256([]byte(hex.EncodeToString(random[:]))),Capability:child.Capability,IntegrationInstanceID:child.IntegrationInstanceID,ScopeChecksum:child.ScopeChecksum,ProfileName:child.ProfileName,Slot:child.Slot,RequestSHA256:child.RequestSHA256,ExpectedResourceID:child.ExpectedResourceID,ExpectedResourceCreatedAt:child.ExpectedResourceCreatedAt,CompensationOf:child.CompensationOf}
 if err:=r.api(ctx,"/api/v1/capacity/mutations/redeem","",request,&response);err!=nil || response.Mode!="read_only" || response.GrantID!=child.GrantID || response.RequestSHA256!=child.RequestSHA256 || response.AttemptID!=request.AttemptID || response.CompensationOf!=child.CompensationOf{return response,ErrOriginalUnknown}
 return response,nil
}
func(r *Realm) FreshCanonicalPostlossNative(ctx context.Context)(IndependentReturn,[]byte,error){
 var fresh IndependentReturn
 if !PostlossSourceCase(r.Request.NativeCase){return fresh,nil,ErrOriginalUnknown}
 r.mu.Lock();original,ok:=r.originals[2];r.mu.Unlock();if !ok{return fresh,nil,ErrOriginalUnknown}
 read,cancel:=context.WithTimeout(ctx,5*time.Second);fresh,err:=Observe(read,SlotDirectory(r.PrivateDirectory,2),original.Original,r.QEMUBinarySHA256);cancel()
 if err!=nil || r.verifyFixedCommand(ctx,2,fresh)!=nil || !sameProcess(fresh.Before,original.After) || !sameProcess(fresh.After,original.After) || fresh.OriginalDisk!=original.OriginalDisk{return fresh,nil,ErrOriginalUnknown}
 fresh.OriginalCreatorSHA256=original.OriginalCreatorSHA256
 wire,err:=Publish(ctx,filepath.Join(SlotDirectory(r.PrivateDirectory,2),"core-postloss-fresh-native-read.json"),fresh);return fresh,wire,err
}
