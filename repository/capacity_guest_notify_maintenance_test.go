package repository

import (
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

// Only authority shape. No PostgreSQL intent, native enrollment or permission
// is seeded by these operands; the production helper rereads each under lock.
func TestGuestNotifyMaintenanceCannotAdoptMutationLease(t *testing.T) {
	for _, kind := range []string{"stable_promoted", "stable_reconciled", "stable_partial", "preparing", "canary", "draining", "drained", "proposed", "aborted", "failed_floor", "recovery_only", "vm_owner", "vm_executor", "vm_expiry", "zero_generation", "zero_fence"} {
		t.Run(kind, func(t *testing.T) {
			current := model.CapacityIntent{Phase: "promoted", Generation: 1, FencingToken: 2}
			switch kind {
			case "stable_reconciled":
				current.Phase = "reconciled"
			case "stable_partial":
				current.Phase = "reconciled_partial"
			case "recovery_only":
				current.RecoveryOnly = true
			case "vm_owner":
				current.LeaseOwner = "existing-vm-owner"
			case "vm_executor":
				current.LeaseExecutorID = "existing-vm-executor"
			case "vm_expiry":
				at := time.Now().Add(-time.Hour)
				current.LeaseExpiresAt = &at
			case "zero_generation":
				current.Generation = 0
			case "zero_fence":
				current.FencingToken = 0
			case "stable_promoted":
			default:
				current.Phase = kind
			}
			positive := kind == "stable_promoted" || kind == "stable_reconciled" || kind == "stable_partial"
			if guestNotifyStableEpoch(current) != positive {
				t.Fatal("maintenance adopted an active, failed or recovery epoch")
			}
		})
	}
	if GuestNotifyMaintenanceOwner("") != "" || GuestNotifyMaintenanceOwner("11111111-1111-4111-8111-111111111111") == GuestNotifyMaintenanceOwner("22222222-2222-4222-8222-222222222222") || GuestNotifyMaintenanceOwner("11111111-1111-4111-8111-111111111111") == "11111111-1111-4111-8111-111111111111" {
		t.Fatal("canary owner is not a distinct valid invocation scope")
	}
}
