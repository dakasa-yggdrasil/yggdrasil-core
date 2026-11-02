package repository

import (
	"strings"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
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

// guestBootIdentity mirrors the Guest admission rule for a challenge
// lease_owner (integration-guest-bootstrap internal/protocol BootIdentity):
// 36 bytes, dashes at 8/13/18/23 and 32 hex digits. It is a copy for this
// cross-repository contract test only; the Guest source stays authoritative.
func guestBootIdentity(s string) bool {
	if len(s) != 36 || s[8] != '-' || s[13] != '-' || s[18] != '-' || s[23] != '-' {
		return false
	}
	hex := strings.ReplaceAll(s, "-", "")
	if len(hex) != 32 {
		return false
	}
	for _, r := range hex {
		if !(r >= '0' && r <= '9' || r >= 'a' && r <= 'f' || r >= 'A' && r <= 'F') {
			return false
		}
	}
	return true
}

// ADR-0093: the steady-maintenance canary owner is a deterministic,
// domain-separated RFC 4122 UUIDv5 the Guest admits, never the former
// "notify-maintenance:<sha256hex>" string the Guest refused.
func TestGuestNotifyMaintenanceOwnerIsDomainSeparatedUUID(t *testing.T) {
	if guestNotifyMaintenanceOwnerNamespace.String() != "04321c5b-fb9b-5087-9636-068fa7072abd" || guestNotifyMaintenanceOwnerNamespace != uuid.NewSHA1(uuid.NameSpaceURL, []byte(guestNotifyMaintenanceOwnerDomain)) {
		t.Fatal("maintenance owner name-space is not the pinned protocol constant")
	}
	known := map[string]string{
		"11111111-1111-4111-8111-111111111111": "b70152ca-6493-5b62-b930-6245b7caeb93",
		"22222222-2222-4222-8222-222222222222": "853c0681-1863-5930-9cda-48471c530408",
	}
	seen := map[string]string{}
	for executor, want := range known {
		got := GuestNotifyMaintenanceOwner(executor)
		if got != want || GuestNotifyMaintenanceOwner(executor) != got {
			t.Fatalf("maintenance owner is not the deterministic known answer for %s: %s", executor, got)
		}
		if GuestNotifyMaintenanceOwner(strings.ToUpper(executor)) != got {
			t.Fatal("one executor UUID spelled differently produced a different owner")
		}
		parsed, err := uuid.Parse(got)
		if err != nil || parsed.String() != got || parsed.Version() != 5 || parsed.Variant() != uuid.RFC4122 || !guestBootIdentity(got) {
			t.Fatal("maintenance owner is not a canonical RFC 4122 UUIDv5 the Guest admits")
		}
		if strings.HasPrefix(got, "notify-maintenance:") || got == executor {
			t.Fatal("maintenance owner kept the legacy form or reused the executor")
		}
		id := uuid.MustParse(executor)
		for _, other := range []uuid.UUID{uuid.NameSpaceURL, uuid.NameSpaceDNS, uuid.NameSpaceOID, uuid.NameSpaceX500, uuid.Nil} {
			if uuid.NewSHA1(other, id[:]).String() == got || uuid.NewSHA1(other, []byte(executor)).String() == got {
				t.Fatal("maintenance owner is not separated from a generic UUIDv5 domain")
			}
		}
		if previous, ok := seen[got]; ok {
			t.Fatalf("executors %s and %s share one owner", previous, executor)
		}
		seen[got] = executor
	}
	for i := 0; i < 64; i++ {
		executor := uuid.NewString()
		got := GuestNotifyMaintenanceOwner(executor)
		if previous, ok := seen[got]; ok || !guestBootIdentity(got) || uuid.MustParse(got).Version() != 5 {
			t.Fatalf("random executor %s collided with %s or is not Guest-admissible", executor, previous)
		}
		// A VM lease owner is a random UUIDv4; the version nibble keeps the
		// steady usage selection from ever matching one.
		if uuid.MustParse(executor).Version() == uuid.MustParse(got).Version() {
			t.Fatal("maintenance owner shares the VM lease owner UUID version")
		}
		seen[got] = executor
	}
	for _, invalid := range []string{"", "not-a-uuid", uuid.Nil.String(), "notify-maintenance:" + strings.Repeat("a", 64)} {
		if GuestNotifyMaintenanceOwner(invalid) != "" {
			t.Fatalf("invalid executor %q produced an owner", invalid)
		}
	}
	legacy := "notify-maintenance:" + strings.Repeat("a", 64)
	if guestBootIdentity(legacy) {
		t.Fatal("the Guest mirror would admit the legacy owner")
	}
}
