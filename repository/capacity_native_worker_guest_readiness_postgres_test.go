package repository

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
	"github.com/lib/pq"
)

// These tests exercise the real guarded store and full migrations. The scoped
// fixture's fake provider facts are not a qualified System guest or readiness.
func TestNativeGuestReadinessStoredContextUsesExactFreshAttemptAndLaunch(t *testing.T) {
	f, store, _, authority := nativeAttemptFixture(t)
	a, err := store.Reserve(t.Context(), f.policy, authority)
	if err != nil {
		t.Fatal(err)
	}
	first, err := nativeGuestStoredLaunch(t.Context(), f.db, a)
	if err != nil || len(first) == 0 {
		t.Fatal("real stored reservation unavailable", err)
	}
	for _, fault := range []string{"revision", "namespace", "policy", "checksum", "source", "launch", "scope", "pin", "missing"} {
		t.Run(fault, func(t *testing.T) {
			copy := a
			switch fault {
			case "revision":
				copy.Revision++
			case "namespace":
				copy.Namespace += "-foreign"
			case "policy":
				copy.PolicyID = uuid.New()
			case "checksum":
				copy.PolicyChecksum = strings.Repeat("0", 64)
			case "source":
				copy.SourceCommit = strings.Repeat("0", 40)
			case "launch":
				copy.LaunchSHA256 = strings.Repeat("0", 64)
			case "scope":
				copy.Execution.ScopeSHA256 = strings.Repeat("0", 64)
			case "pin":
				copy.Execution.GuestIdentityPolicySHA256 = strings.Repeat("0", 64)
			case "missing":
				copy.ID = uuid.New()
			}
			if wire, err := nativeGuestStoredLaunch(t.Context(), f.db, copy); err == nil || wire != nil {
				t.Fatal("foreign/stale context became private guest selector")
			}
		})
	}
	if _, err := store.Redeem(t.Context(), f.policy, authority, a.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := nativeGuestStoredLaunch(t.Context(), f.db, a); err == nil {
		t.Fatal("previous reservation remained current after real one-send redemption")
	}
	current, err := store.Read(t.Context(), f.policy, a.ID)
	if err != nil {
		t.Fatal(err)
	}
	second, err := nativeGuestStoredLaunch(t.Context(), f.db, current)
	if err != nil || !bytes.Equal(first, second) {
		t.Fatal("actual current state lost immutable original Launch", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := nativeGuestStoredLaunch(ctx, f.db, current); err == nil {
		t.Fatal("cancelled DB read became current")
	}
}

func TestNativeGuestIdentityPolicyPinIsImmutableInRealAttemptHistory(t *testing.T) {
	pin := strings.Repeat("a", 64)
	f, store, _, authority := nativeAttemptFixture(t, func(p *model.CapacityPolicySpec) {
		p.NativeWorkerLifecycleBinding.Profiles[0].GuestIdentityPolicySHA256 = pin
	})
	a, err := store.Reserve(t.Context(), f.policy, authority)
	if err != nil || a.Execution.GuestIdentityPolicySHA256 != pin {
		t.Fatal("durable optional identity pin lost", err)
	}
	_, err = f.db.ExecContext(t.Context(), `UPDATE public.capacity_native_worker_attempts SET attempt=jsonb_set(attempt,'{execution,guest_identity_policy_sha256}',to_jsonb($2::text)) WHERE id=$1`, a.ID, strings.Repeat("b", 64))
	var pg *pq.Error
	if !errors.As(err, &pg) || string(pg.Code) != "P0001" {
		t.Fatal("immutable authority guard did not reject identity replacement", err)
	}
	got, err := store.Read(t.Context(), f.policy, a.ID)
	if err != nil || got.Execution.GuestIdentityPolicySHA256 != pin {
		t.Fatal("rejected edit changed actual identity generation", err)
	}
	proofPort := nativeConcreteGuestReadiness(f.db, f.policy, a.SourceCommit, nil, nil)
	if proof, err := proofPort(t.Context(), a); err == nil || proof != nil {
		t.Fatal("new policy pin alone fabricated physical/Node/path/warmup proof")
	}
	var events int
	if err := f.db.QueryRowContext(t.Context(), `SELECT count(*) FROM public.capacity_native_worker_original_returns WHERE attempt_id=$1`, a.ID).Scan(&events); err != nil || events != 0 {
		t.Fatal("readiness without independent facts created original custody", err)
	}
}
