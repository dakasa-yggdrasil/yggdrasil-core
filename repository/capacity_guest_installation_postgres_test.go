package repository

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

// This is real PostgreSQL and the real scope-locked transaction. Its records
// are storage fixtures, never fabricated native lifecycle evidence. Full native
// policy/registry/lease admission is intentionally not bypassed to make it pass.
func TestGuestInstallationRealPostgres(t *testing.T) {
	if os.Getenv("GUEST_INSTALLATION_PG_TEST") != "isolated" {
		t.Skip("requires dedicated isolated PostgreSQL")
	}
	dsn := os.Getenv("GUEST_INSTALLATION_TEST_DSN")
	if !strings.Contains(dsn, "host=/") || !strings.Contains(dsn, "dbname=guest_installation_") {
		t.Fatal("dedicated Unix-socket database required")
	}
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.SetMaxOpenConns(2)
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	if err = db.PingContext(ctx); err != nil {
		t.Fatal(err)
	}
	// Existing migrations 1..68 must already be applied to this disposable DB.
	migration, err := os.ReadFile(os.Getenv("GUEST_INSTALLATION_MIGRATION"))
	if err != nil {
		t.Fatal(err)
	}
	up := strings.Split(string(migration), "-- +goose Down")[0]
	for i := 0; i < 2; i++ {
		if _, err = db.ExecContext(ctx, up); err != nil {
			t.Fatal("migration69/reapply", err)
		}
	}
	f := guestOriginalStorageRecords(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	f.pre.ReservedAt = now.Add(-time.Second)
	f.pre.OriginalDeadline = f.pre.ReservedAt.Add(50 * time.Second)
	f.pre.OriginalWorkflowContextDeadline = f.pre.OriginalDeadline
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	f.binding.ProvisionerPublicKey = base64.StdEncoding.EncodeToString(pub)
	f.wire, _ = json.Marshal(f.pre)
	f.bindingWire, _ = json.Marshal(f.binding)
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	guestOriginalStorageChain(t, tx, ctx, f)
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
	receipt := model.CapacityGuestOriginalProvisioningReceipt{PreregistrationID: f.pre.PreregistrationID, RecordedAt: f.pre.ReservedAt}
	c := model.CapacityGuestOriginalInstallationConfirmation{Schema: capacity.GuestOriginalInstallationSchema, PreregistrationID: f.pre.PreregistrationID, OriginalReceiptSHA256: capacity.GuestRetirementSHA(receipt), EnrollmentSHA256: capacity.GuestRetirementSHA(receipt.Enrollment), InstalledAt: now.Add(-time.Millisecond * 2), AdmittedAt: now.Add(-time.Millisecond)}
	c.Signature, _ = capacity.GuestLifecycleSignature(key, c)
	s := CapacityStore{DB: db}
	store := func(v model.CapacityGuestOriginalInstallationConfirmation, rollback bool) error {
		return s.guestStoredTransaction(ctx, f.pre.PreregistrationID, func(tx *sql.Tx, stored guestOriginalStored, at time.Time) error {
			_, e := storeGuestInstallationTx(ctx, tx, stored, receipt, v, at)
			if e != nil {
				return e
			}
			if rollback {
				return errors.New("controlled rollback")
			}
			return nil
		})
	}
	count := func() int {
		var n int
		if e := db.QueryRowContext(ctx, `SELECT count(*) FROM public.capacity_guest_original_installations WHERE preregistration_id=$1`, f.pre.PreregistrationID).Scan(&n); e != nil {
			t.Fatal(e)
		}
		return n
	}
	t.Run("pending_read", func(t *testing.T) {
		e := s.guestStoredTransaction(ctx, f.pre.PreregistrationID, func(tx *sql.Tx, stored guestOriginalStored, _ time.Time) error {
			_, e := loadGuestInstallationTx(ctx, tx, stored, receipt)
			return e
		})
		if !errors.Is(e, sql.ErrNoRows) || count() != 0 {
			t.Fatal("pending read invented confirmation", e)
		}
	})
	t.Run("rollback", func(t *testing.T) {
		if store(c, true) == nil || count() != 0 {
			t.Fatal("rollback persisted")
		}
	})
	t.Run("concurrent_exact_duplicates", func(t *testing.T) {
		var wg sync.WaitGroup
		out := make(chan error, 2)
		for i := 0; i < 2; i++ {
			wg.Add(1)
			go func() { defer wg.Done(); out <- store(c, false) }()
		}
		wg.Wait()
		close(out)
		for e := range out {
			if e != nil {
				t.Fatal(e)
			}
		}
		if count() != 1 {
			t.Fatal("not exactly one")
		}
	})
	t.Run("conflicting_signed_duplicate", func(t *testing.T) {
		v := c
		v.AdmittedAt = v.AdmittedAt.Add(time.Microsecond)
		v.Signature = ""
		v.Signature, _ = capacity.GuestLifecycleSignature(key, v)
		if store(v, false) == nil || count() != 1 {
			t.Fatal("conflict adopted")
		}
	})
	t.Run("concurrent_conflicting_duplicate", func(t *testing.T) {
		v := c
		v.AdmittedAt = v.AdmittedAt.Add(time.Microsecond)
		v.Signature = ""
		v.Signature, _ = capacity.GuestLifecycleSignature(key, v)
		start := make(chan struct{})
		good, bad := make(chan error, 1), make(chan error, 1)
		go func() { <-start; good <- store(c, false) }()
		go func() { <-start; bad <- store(v, false) }()
		close(start)
		if e := <-good; e != nil {
			t.Fatal("exact duplicate refused", e)
		}
		if e := <-bad; !errors.Is(e, ErrCapacityConflict) {
			t.Fatal("conflicting concurrent value not refused", e)
		}
		if count() != 1 {
			t.Fatal("concurrent conflict changed count")
		}
	})
	t.Run("observed_scope_lock_contention", func(t *testing.T) {
		holder, e := db.BeginTx(ctx, nil)
		if e != nil {
			t.Fatal(e)
		}
		defer holder.Rollback()
		var ns, env, domain, dimension string
		if e = holder.QueryRowContext(ctx, `SELECT namespace,environment,domain,dimension FROM public.capacity_mutation_grants WHERE id=$1`, f.pre.OriginalCreateGrantID).Scan(&ns, &env, &domain, &dimension); e != nil {
			t.Fatal(e)
		}
		if e = lockMutationScope(ctx, holder, ns, model.CapacityPolicySpec{Environment: env, Domain: domain, Dimension: dimension}); e != nil {
			t.Fatal(e)
		}
		var pid int
		if e = holder.QueryRowContext(ctx, `SELECT pg_backend_pid()`).Scan(&pid); e != nil {
			t.Fatal(e)
		}
		done := make(chan error, 1)
		go func() { done <- store(c, false) }()
		deadline := time.NewTimer(3 * time.Second)
		defer deadline.Stop()
		tick := time.NewTicker(time.Millisecond)
		defer tick.Stop()
		observed := false
		for !observed {
			if e = holder.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND $1=ANY(pg_blocking_pids(pid)))`, pid).Scan(&observed); e != nil {
				t.Fatal(e)
			}
			if observed {
				break
			}
			select {
			case e := <-done:
				t.Fatal("transaction escaped scope lock", e)
			case <-deadline.C:
				t.Fatal("no PostgreSQL lock wait observed")
			case <-tick.C:
			}
		}
		if e = holder.Commit(); e != nil {
			t.Fatal(e)
		}
		select {
		case e := <-done:
			if e != nil {
				t.Fatal("waiter failed after release", e)
			}
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
		if count() != 1 {
			t.Fatal("lock contender duplicated record")
		}
	})
	t.Run("foreign_replay", func(t *testing.T) {
		v := c
		v.PreregistrationID = f.pre.OriginalCreateGrantID
		v.Signature = ""
		v.Signature, _ = capacity.GuestLifecycleSignature(key, v)
		if store(v, false) == nil {
			t.Fatal("foreign accepted")
		}
	})
	t.Run("stale_confirmation", func(t *testing.T) {
		e := s.guestStoredTransaction(ctx, f.pre.PreregistrationID, func(tx *sql.Tx, stored guestOriginalStored, _ time.Time) error {
			_, e := storeGuestInstallationTx(ctx, tx, stored, receipt, c, stored.pre.OriginalDeadline)
			return e
		})
		if e == nil {
			t.Fatal("late accepted")
		}
	})
	t.Run("immutable_update_delete", func(t *testing.T) {
		for _, q := range []string{`UPDATE public.capacity_guest_original_installations SET recorded_at=recorded_at WHERE preregistration_id=$1`, `DELETE FROM public.capacity_guest_original_installations WHERE preregistration_id=$1`} {
			if _, e := db.ExecContext(ctx, q, f.pre.PreregistrationID); e == nil {
				t.Fatal("immutable mutation allowed")
			}
		}
	})
	t.Run("read_authenticates_original", func(t *testing.T) {
		if e := s.guestStoredTransaction(ctx, f.pre.PreregistrationID, func(tx *sql.Tx, stored guestOriginalStored, _ time.Time) error {
			_, e := loadGuestInstallationTx(ctx, tx, stored, receipt)
			return e
		}); e != nil {
			t.Fatal(e)
		}
	})
	t.Run("full_callback_refuses_foreign_principal", func(t *testing.T) {
		_, e := s.RegisterOriginalGuestInstallation(ctx, "foreign", c)
		if !errors.Is(e, ErrCapacityMutationAuthorization) {
			t.Fatal("wrong refusal", e)
		}
	})
	t.Run("storage_fixture_cannot_bypass_policy", func(t *testing.T) {
		_, e := s.RegisterOriginalGuestInstallation(ctx, f.binding.Members[0].ProvisionerClientPrincipal, c)
		if !errors.Is(e, sql.ErrNoRows) {
			t.Fatal("missing live policy returned unexpected result", e)
		}
	})
}
