package repository

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

func nativeReadinessJournalFixture(t *testing.T) (marketRepositoryFixture, model.CapacityNativeWorkerAttempt, *nativeReadinessRunJournal) {
	t.Helper()
	f, a, producer, _ := nativeReadinessComposedFixture(t, nativeReadinessComposedOptions{NoOpen: true})
	return f, a, producer.state.journal
}

func TestNativeReadinessRunPostgresConcurrentOpenAndOneDiagnosticSend(t *testing.T) {
	f, a, s := nativeReadinessJournalFixture(t)
	var generates atomic.Int32
	generate := func(uuid.UUID, time.Time, time.Time) ([]byte, error) {
		generates.Add(1)
		return bytes.Repeat([]byte("private-ci-run-material"), 4), nil
	}
	var wg sync.WaitGroup
	results := make(chan nativeReadinessRun, 4)
	errors := make(chan error, 4)
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r, keys, err := s.open(t.Context(), a, generate)
			if err == nil && !bytes.Equal(keys, bytes.Repeat([]byte("private-ci-run-material"), 4)) {
				t.Error("resume substituted private run material")
			}
			clear(keys)
			results <- r
			errors <- err
		}()
	}
	wg.Wait()
	close(results)
	close(errors)
	for err := range errors {
		if err != nil {
			t.Fatal(err)
		}
	}
	if generates.Load() != 1 {
		t.Fatal("concurrent opens reminted run keys", generates.Load())
	}
	var original nativeReadinessRun
	for r := range results {
		if original.ID == uuid.Nil {
			original = r
		}
		if r.ID != original.ID || r.Identity != original.Identity || !r.NotAfter.Equal(original.NotAfter) || r.Revision != 1 {
			t.Fatal("concurrent open created another run or renewed its lifetime")
		}
	}
	var wins atomic.Int32
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := s.begin(t.Context(), a, original, "candidate_pod", strings.Repeat("4", 64)); err == nil {
				wins.Add(1)
			}
		}()
	}
	wg.Wait()
	if wins.Load() != 1 {
		t.Fatal("diagnostic object dispatch did not have exactly one durable owner", wins.Load())
	}
	current, err := s.read(t.Context(), a.ID)
	if err != nil || len(current.Effects) != 1 || current.Effects[0].State != "requested" {
		t.Fatal("crash-before-RPC was incorrectly marked observed", err)
	}
	if _, err = s.begin(t.Context(), a, current, "candidate_pod", strings.Repeat("4", 64)); err == nil {
		t.Fatal("restart repeated diagnostic creation")
	}
	if _, err = s.finish(t.Context(), current); err == nil {
		t.Fatal("unknown diagnostic creation became cleanup complete")
	}
	if _, err = s.receiveAbsent(t.Context(), current, "candidate_pod", uuid.NewString(), strings.Repeat("5", 64), time.Now().UTC()); err == nil {
		t.Fatal("a GET404 without a known original UID closed an uncertain create")
	}
	var nonce, ciphertext, raw []byte
	if err = f.db.QueryRowContext(t.Context(), `SELECT key_nonce,key_ciphertext,record FROM public.capacity_native_worker_readiness_runs WHERE attempt_id=$1`, a.ID).Scan(&nonce, &ciphertext, &raw); err != nil || bytes.Contains(ciphertext, []byte("private-ci-run-material")) || bytes.Contains(raw, []byte("private-ci-run-material")) || len(nonce) != 12 {
		t.Fatal("private run material was not encrypted outside the event projection", err)
	}
	for _, query := range []string{
		`UPDATE public.capacity_native_worker_readiness_runs SET not_after=not_after+interval '1 second' WHERE attempt_id=$1`,
		`UPDATE public.capacity_native_worker_readiness_runs SET key_ciphertext=decode('00','hex') WHERE attempt_id=$1`,
		`DELETE FROM public.capacity_native_worker_readiness_runs WHERE attempt_id=$1`,
		`DELETE FROM public.capacity_native_worker_readiness_events WHERE attempt_id=$1`,
		`UPDATE public.capacity_native_worker_readiness_events SET record='{}'::jsonb WHERE attempt_id=$1`,
	} {
		if _, err = f.db.ExecContext(t.Context(), query, a.ID); err == nil {
			t.Fatal("database allowed readiness custody/key/lifetime/history replacement")
		}
	}
	s.close()
	if _, _, err = s.open(t.Context(), a, generate); err == nil {
		t.Fatal("closed journal reminted run material")
	}
	if err = f.db.PingContext(t.Context()); err != nil {
		t.Fatal("journal closed its borrowed database", err)
	}
}

func TestNativeReadinessRunPostgresLeaseExpiryAllowsOnlyExactReceivingAndCleanup(t *testing.T) {
	f, a, s := nativeReadinessJournalFixture(t)
	r, keys, err := s.open(t.Context(), a, func(uuid.UUID, time.Time, time.Time) ([]byte, error) { return bytes.Repeat([]byte{9}, 64), nil })
	clear(keys)
	if err != nil {
		t.Fatal(err)
	}
	r, err = s.begin(t.Context(), a, r, "candidate_pod", strings.Repeat("4", 64))
	if err != nil {
		t.Fatal(err)
	}
	var createToken string
	r, createToken, err = s.redeem(t.Context(), a, r, "candidate_pod")
	if err != nil {
		t.Fatal(err)
	}
	var parent model.CapacityIntent
	if err = f.db.QueryRowContext(t.Context(), `SELECT intent FROM public.capacity_intents WHERE namespace=$1`, a.Namespace).Scan((*nativeIntentScan)(&parent)); err != nil {
		t.Fatal(err)
	}
	expired := time.Now().UTC().Add(-time.Second)
	parent.LeaseExpiresAt = &expired
	wire, err := json.Marshal(parent)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.db.ExecContext(t.Context(), `UPDATE public.capacity_intents SET intent=$2 WHERE namespace=$1`, a.Namespace, wire); err != nil {
		t.Fatal(err)
	}
	if _, _, err = s.open(t.Context(), a, func(uuid.UUID, time.Time, time.Time) ([]byte, error) {
		t.Fatal("expired run reminted keys")
		return nil, nil
	}); err == nil {
		t.Fatal("expired parent opened another growth operation")
	}
	if _, err = s.begin(t.Context(), a, r, "floor_pod", strings.Repeat("4", 64)); err == nil {
		t.Fatal("expired parent created another diagnostic resource")
	}
	uid := uuid.NewString()
	// Low-level custody/cleanup fixture only. It does not qualify this synthetic
	// native body as a Kubernetes ACK or manufacture a readiness proof.
	r, err = s.captureOriginal(t.Context(), r, model.NativeWorkerProbeResourceReceive{BindingName: "journal-fixture", RunID: r.ID.String(), Slot: "candidate_pod", SettlementToken: createToken, HTTPStatus: 201, TransportCompleted: true, CompletedAt: time.Now().UTC(), OriginalReturn: []byte(`{"fixture":"private original before interpretation"}`)})
	if err != nil {
		t.Fatal("expired parent prevented original private custody", err)
	}
	r, err = s.receive(t.Context(), r, "candidate_pod", uid, strings.Repeat("4", 64), strings.Repeat("5", 64), time.Now().UTC())
	if err != nil {
		t.Fatal("expired parent prevented late original receiving", err)
	}
	r, err = s.beginDelete(t.Context(), r, "candidate_pod")
	if err != nil {
		t.Fatal("expired parent prevented owned cleanup", err)
	}
	var deleteToken string
	r, deleteToken, err = s.redeem(t.Context(), a, r, "candidate_pod")
	if err != nil {
		t.Fatal("expired parent prevented one owned cleanup redemption", err)
	}
	r, err = s.captureOriginal(t.Context(), r, model.NativeWorkerProbeResourceReceive{BindingName: "journal-fixture", RunID: r.ID.String(), Slot: "candidate_pod", SettlementToken: deleteToken, HTTPStatus: 200, TransportCompleted: true, CompletedAt: time.Now().UTC(), OriginalReturn: []byte(`{"fixture":"private delete original"}`)})
	if err != nil {
		t.Fatal("expired parent prevented original cleanup custody", err)
	}
	if _, err = s.receiveAbsent(t.Context(), r, "candidate_pod", uuid.NewString(), strings.Repeat("6", 64), time.Now().UTC()); err == nil {
		t.Fatal("cleanup accepted another Pod lifetime")
	}
	r, err = s.receiveAbsent(t.Context(), r, "candidate_pod", uid, strings.Repeat("6", 64), time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	r, err = s.finish(t.Context(), r)
	if err != nil || !r.Closed {
		t.Fatal("exact owned cleanup could not close", err)
	}
	current, err := s.read(t.Context(), a.ID)
	if err != nil || current.ID != r.ID || current.Revision != r.Revision || !current.Closed {
		t.Fatal("receiving rewrote the run identity or history", err)
	}
}

func TestNativeReadinessRunPostgresClockIsReadAfterTheContendedRunLock(t *testing.T) {
	for _, mode := range []string{"open-existing-run", "begin-with-shortened-parent"} {
		t.Run(mode, func(t *testing.T) {
			f, a, s := nativeReadinessJournalFixture(t)
			ctx, cancel := context.WithTimeout(t.Context(), 8*time.Second)
			defer cancel()
			var r nativeReadinessRun
			var expires time.Time
			if mode == "open-existing-run" {
				// A synthetic retained row isolates resume/clock semantics. This
				// does not qualify initial creation's required 180-second budget.
				// Real PostgreSQL locks and wall clock cross its near deadline.
				identity, err := s.identity(a)
				if err != nil {
					t.Fatal(err)
				}
				var now time.Time
				if err = f.db.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
					t.Fatal(err)
				}
				r = nativeReadinessRun{Schema: "native_worker_readiness_run_v1", ID: uuid.New(), Identity: identity, CreatedAt: now.UTC(), NotAfter: now.UTC().Add(1500 * time.Millisecond), Revision: 1, Effects: []nativeReadinessEffect{}}
				expires = r.NotAfter
				nonce, sealed, err := s.crypt(r, nil, bytes.Repeat([]byte{7}, 64), true)
				if err != nil {
					t.Fatal(err)
				}
				raw, err := json.Marshal(r)
				if err != nil {
					t.Fatal(err)
				}
				if _, err = f.db.ExecContext(ctx, `INSERT INTO public.capacity_native_worker_readiness_runs(attempt_id,id,revision,record,key_nonce,key_ciphertext,created_at,not_after) VALUES($1,$2,1,$3,$4,$5,$6,$7)`, a.ID, r.ID, raw, nonce, sealed, r.CreatedAt, r.NotAfter); err != nil {
					t.Fatal(err)
				}
			} else {
				var err error
				var keys []byte
				r, keys, err = s.open(ctx, a, func(uuid.UUID, time.Time, time.Time) ([]byte, error) { return bytes.Repeat([]byte{8}, 64), nil })
				clear(keys)
				if err != nil {
					t.Fatal(err)
				}
				var parent model.CapacityIntent
				if err = f.db.QueryRowContext(ctx, `SELECT intent FROM public.capacity_intents WHERE namespace=$1`, a.Namespace).Scan((*nativeIntentScan)(&parent)); err != nil {
					t.Fatal(err)
				}
				var now time.Time
				if err = f.db.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
					t.Fatal(err)
				}
				expires = now.Add(1500 * time.Millisecond)
				parent.LeaseExpiresAt = &expires
				raw, err := json.Marshal(parent)
				if err != nil {
					t.Fatal(err)
				}
				if _, err = f.db.ExecContext(ctx, `UPDATE public.capacity_intents SET intent=$2 WHERE namespace=$1`, a.Namespace, raw); err != nil {
					t.Fatal(err)
				}
			}
			locker, err := f.db.BeginTx(ctx, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer locker.Rollback()
			var locked []byte
			if err = locker.QueryRowContext(ctx, `SELECT record FROM public.capacity_native_worker_readiness_runs WHERE attempt_id=$1 FOR UPDATE`, a.ID).Scan(&locked); err != nil {
				t.Fatal(err)
			}
			returned := make(chan error, 1)
			go func() {
				if mode == "open-existing-run" {
					_, keys, e := s.open(ctx, a, func(uuid.UUID, time.Time, time.Time) ([]byte, error) { return nil, errNativeReadinessRun })
					clear(keys)
					returned <- e
				} else {
					_, e := s.begin(ctx, a, r, "candidate_pod", strings.Repeat("4", 64))
					returned <- e
				}
			}()
			waiting := false
			deadline := time.Now().Add(3 * time.Second)
			for time.Now().Before(deadline) {
				if err = f.db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND state='active' AND wait_event_type='Lock' AND query LIKE $1 AND pid<>pg_backend_pid())`, "%FROM public.capacity_native_worker_readiness_runs%FOR UPDATE%").Scan(&waiting); err != nil {
					t.Fatal(err)
				}
				if waiting {
					break
				}
				time.Sleep(10 * time.Millisecond)
			}
			if !waiting {
				t.Fatal("original operation did not reach the real contended row lock")
			}
			if _, err = f.db.ExecContext(ctx, `SELECT pg_sleep(GREATEST(0, EXTRACT(EPOCH FROM ($1::timestamptz-clock_timestamp())))+0.05)`, expires); err != nil {
				t.Fatal(err)
			}
			if err = locker.Rollback(); err != nil {
				t.Fatal(err)
			}
			select {
			case err = <-returned:
				if err == nil {
					t.Fatal("pre-lock clock authorized an expired run/parent after the wait")
				}
			case <-ctx.Done():
				t.Fatal("operation did not return after its real lock was released")
			}
			current, err := s.read(ctx, a.ID)
			if err != nil || current.Revision != 1 || len(current.Effects) != 0 || current.ID != r.ID {
				t.Fatal("lock wait expired but created an effect or reminted identity", err)
			}
		})
	}
}
