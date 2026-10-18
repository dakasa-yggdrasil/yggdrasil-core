//go:build !linux || !nativequalification
package capacity
import "github.com/dakasa-yggdrasil/yggdrasil-core/model"
func guestPostlossObservationAllowed(model.CapacityGuestRetirementBinding,model.CapacityGuestOriginalCreateWitness)bool{return false}
