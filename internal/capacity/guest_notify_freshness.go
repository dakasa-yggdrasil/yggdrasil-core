package capacity

import (
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"time"
)

// The source-owned causal join bounds actual creation by the original Core
// five-second window. Add the complete subsequent age measured on Core PG.
// Native PG/Guest/Core wall clocks are never compared or offset-estimated.
func GuestNotifyBusinessStillFresh(b model.CapacityGuestNotifyBusinessObservation, recordedPG, nowPG time.Time, maxAgeSeconds int) bool {
	if maxAgeSeconds < 1 || maxAgeSeconds > 3600 || b.CreationFreshnessClass != GuestNotifyCreationFreshnessClass || b.CreationUpperBoundSeconds != 5 || recordedPG.IsZero() || nowPG.IsZero() {
		return false
	}
	age := nowPG.Sub(recordedPG)
	return age >= 0 && age+5*time.Second <= time.Duration(maxAgeSeconds)*time.Second
}
