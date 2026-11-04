package capacity

import (
	"fmt"
	"regexp"
	"strconv"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

var guestNotifyStableBinding = regexp.MustCompile(`^[a-z][a-z0-9-]{0,47}$`)

func guestNotifyQueueName(binding, provider string, slot int) string {
	if !guestNotifyStableBinding.MatchString(binding) || (provider != "aws" && provider != "hetzner") || slot < 1 || slot > 64 {
		return ""
	}
	return "notify.guest-canary.dakasa-production." + binding + "." + provider + ".s" + strconv.Itoa(slot) + ".q"
}

// A source contract only. Existing declarative broker reconciliation must
// apply quorum/retry/DLX definitions before the original consumer can admit.
func ValidateGuestNotifyCanaryTopology(t *model.CapacityGuestNotifyCanaryTopology) error {
	fail := fmt.Errorf("canonical source-owned Notify canary queue topology required")
	if t == nil || t.Schema != "notify_guest_canary_topology_v1" || t.Namespace != "dakasa-production" || !guestNotifyStableBinding.MatchString(t.Binding) || !ValidDigest(t.DefinitionsSHA256) || len(t.Queues) < 1 || len(t.Queues) > 128 {
		return fail
	}
	previousProvider, previousSlot := "", 0
	for _, q := range t.Queues {
		expected := guestNotifyQueueName(t.Binding, q.Provider, q.Slot)
		if expected == "" || q.Name != expected || q.Provider < previousProvider || q.Provider == previousProvider && q.Slot <= previousSlot {
			return fail
		}
		previousProvider, previousSlot = q.Provider, q.Slot
	}
	return nil
}

func GuestNotifyQueue(t *model.CapacityGuestNotifyCanaryTopology, provider string, slot int) string {
	if ValidateGuestNotifyCanaryTopology(t) != nil {
		return ""
	}
	for _, q := range t.Queues {
		if q.Provider == provider && q.Slot == slot {
			return q.Name
		}
	}
	return ""
}
