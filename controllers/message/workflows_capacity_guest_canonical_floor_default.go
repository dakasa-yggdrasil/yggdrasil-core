//go:build !linux || !nativequalification
package message
import("context";"github.com/dakasa-yggdrasil/yggdrasil-core/model";"github.com/dakasa-yggdrasil/yggdrasil-core/repository")
func guestOriginalCanonicalFloorPermission(context.Context,repository.CapacityStore,model.Manifest,guestOriginalStepInput,model.CapacityMutationIssue)(any,bool,error){return nil,false,nil}

func guestOriginalCanonicalFloorPreparing(context.Context,repository.CapacityStore,model.Manifest,guestOriginalStepInput)(bool,error){return false,nil}
