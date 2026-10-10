package repository

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
	_ "github.com/lib/pq"
)

func capacityDispatchPostgresFixture(t *testing.T) (*sql.DB, CapacityDispatchEnvelope) {
	t.Helper()
	dsn := os.Getenv("DB_URL")
	if dsn == "" {
		if os.Getenv("REQUIRE_CAPACITY_POSTGRES") == "true" || os.Getenv("REQUIRE_CAPACITY_DISPATCH_POSTGRES") == "true" {
			t.Fatal("DB_URL required by capacity dispatch PostgreSQL gate")
		}
		t.Skip("PostgreSQL integration runs in CI")
	}
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(12)
	realm := "dispatch-" + uuid.NewString()
	create := func(kind, name string) CapacityDispatchManifestPin {
		m, createErr := CreateManifestVersion(context.Background(), db, model.ManifestDocument{APIVersion: "v1", Kind: kind, Metadata: model.ManifestMetadataInput{Namespace: realm, Name: name}, Spec: []byte(`{}`)}, capacityDispatchSHA([]byte(kind+name)))
		if createErr != nil {
			t.Fatal(createErr)
		}
		return CapacityDispatchManifestPin{ID: m.ID, Namespace: realm, Name: name, Version: m.Version, Checksum: m.Checksum}
	}
	e := CapacityDispatchEnvelope{Protocol: CapacityDispatchProtocol, JobID: uuid.New(), RunID: uuid.New(), Realm: realm, Environment: "ci", Domain: "hpa", Dimension: "reserved_pod_envelope", SourceTick: time.Now().UTC().Truncate(time.Second).Format(time.RFC3339), Policy: create("capacity_policy", "pressure"), Workflow: create("workflow", "pressure"), RBAC: create("rbac", "dispatch"), MachinePrincipalID: "capacity-controller", PrincipalSHA256: capacityDispatchSHA([]byte("canonical-principal")), BindingSHA256: capacityDispatchSHA([]byte("operator-binding"))}
	e.Inputs = map[string]any{"policy": map[string]any{"namespace": realm, "name": e.Policy.Name}}
	e.Metadata = map[string]any{WorkflowRunCreatorMachinePrincipalMetadataKey: e.MachinePrincipalID, "triggered_by": "workflow_scheduler", "manifest_id": e.Workflow.ID.String(), "scheduled_for": e.SourceTick}
	e.InputsSHA256, e.MetadataSHA256, err = CapacityDispatchEnvelopeHashes(e)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		for _, query := range []string{
			`DELETE FROM public.capacity_dispatch_wakes WHERE realm=$1`,
			`DELETE FROM public.capacity_dispatch_jobs WHERE realm=$1`,
			`DELETE FROM public.workflow_runs WHERE workflow_namespace=$1`,
			`DELETE FROM public.workflow_schedule_state WHERE workflow_manifest_id IN (SELECT id FROM public.manifests WHERE namespace=$1)`,
			`DELETE FROM public.manifests WHERE namespace=$1`,
		} {
			if _, cleanupErr := db.ExecContext(context.Background(), query, realm); cleanupErr != nil {
				t.Error(cleanupErr)
			}
		}
		if err := db.Close(); err != nil {
			t.Error(err)
		}
	})
	return db, e
}

func capacityDispatchEnqueueFixture(t *testing.T, db *sql.DB, e CapacityDispatchEnvelope) (CapacityDispatchJob, bool) {
	t.Helper()
	tx, err := db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	job, dedup, err := EnqueueCapacityDispatch(context.Background(), tx, e)
	if err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
	return job, dedup
}

func capacityDispatchNextWake(t *testing.T, e CapacityDispatchEnvelope, tick int) CapacityDispatchEnvelope {
	t.Helper()
	e.JobID, e.RunID = uuid.New(), uuid.New()
	base, err := time.Parse(time.RFC3339, e.SourceTick)
	if err != nil {
		t.Fatal(err)
	}
	e.SourceTick = base.Add(time.Duration(tick) * time.Second).Format(time.RFC3339)
	e.Metadata = map[string]any{WorkflowRunCreatorMachinePrincipalMetadataKey: e.MachinePrincipalID, "triggered_by": "workflow_scheduler", "manifest_id": e.Workflow.ID.String(), "scheduled_for": e.SourceTick}
	e.InputsSHA256, e.MetadataSHA256, err = CapacityDispatchEnvelopeHashes(e)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func capacityDispatchClaimFixture(t *testing.T, db *sql.DB, e CapacityDispatchEnvelope, lease time.Duration) CapacityDispatchJob {
	t.Helper()
	job, err := ClaimCapacityDispatch(context.Background(), db, e.Realm, e.Environment, uuid.New(), lease)
	if err != nil {
		t.Fatal(err)
	}
	return job
}

func capacityDispatchResponse(e CapacityDispatchEnvelope, status string) model.RunWorkflowResponse {
	return model.RunWorkflowResponse{Workflow: model.ManifestReference{ID: e.Workflow.ID, Kind: "workflow", Namespace: e.Workflow.Namespace, Name: e.Workflow.Name, Version: e.Workflow.Version}, Status: status}
}

func TestCapacityDispatchPostgres(t *testing.T) {
	t.Run("same_transaction_rollback_and_commit", func(t *testing.T) {
		db, e := capacityDispatchPostgresFixture(t)
		ctx := context.Background()
		tick, err := time.Parse(time.RFC3339, e.SourceTick)
		if err != nil {
			t.Fatal(err)
		}
		admit := func(commit bool) {
			tx, beginErr := db.BeginTx(ctx, nil)
			if beginErr != nil {
				t.Fatal(beginErr)
			}
			defer tx.Rollback()
			if won, scheduleErr := UpsertWorkflowScheduleState(ctx, tx, e.Workflow.ID.String(), tick, tick.Add(time.Minute)); scheduleErr != nil || !won {
				t.Fatalf("tick admission: %t %v", won, scheduleErr)
			}
			if _, _, enqueueErr := EnqueueCapacityDispatch(ctx, tx, e); enqueueErr != nil {
				t.Fatal(enqueueErr)
			}
			if commit {
				if err := tx.Commit(); err != nil {
					t.Fatal(err)
				}
			}
		}
		admit(false)
		for _, query := range []string{`SELECT count(*) FROM public.workflow_schedule_state WHERE workflow_manifest_id=$1`, `SELECT count(*) FROM public.workflow_runs WHERE workflow_namespace=$1`, `SELECT count(*) FROM public.capacity_dispatch_jobs WHERE realm=$1`, `SELECT count(*) FROM public.capacity_dispatch_wakes WHERE realm=$1`} {
			arg := any(e.Realm)
			if query == `SELECT count(*) FROM public.workflow_schedule_state WHERE workflow_manifest_id=$1` {
				arg = e.Workflow.ID
			}
			var count int
			if err := db.QueryRowContext(ctx, query, arg).Scan(&count); err != nil || count != 0 {
				t.Fatalf("partial rollback: count=%d err=%v", count, err)
			}
		}
		admit(true)
		run, err := GetWorkflowRun(ctx, db, e.RunID)
		if err != nil || run.Status != "pending" || run.StartedAt != nil || run.WorkflowVersion == nil || *run.WorkflowVersion != e.Workflow.Version {
			t.Fatalf("original pending run: %+v %v", run, err)
		}
		job := capacityDispatchClaimFixture(t, db, e, time.Minute)
		if job.RunID != e.RunID || job.JobID != e.JobID || job.Protocol != CapacityDispatchProtocol {
			t.Fatal("original execution identity changed")
		}
	})
	t.Run("exact_tick_dedup_and_bounded_wakes", func(t *testing.T) {
		db, e := capacityDispatchPostgresFixture(t)
		original, dedup := capacityDispatchEnqueueFixture(t, db, e)
		if dedup {
			t.Fatal("first wake deduped")
		}
		retry := e
		retry.JobID, retry.RunID = uuid.New(), uuid.New()
		job, dedup := capacityDispatchEnqueueFixture(t, db, retry)
		if !dedup || job.JobID != original.JobID || job.RunID != original.RunID || job.PendingWakeCount != 1 {
			t.Fatal("duplicate tick created execution")
		}
		for tick := 1; tick < MaxCapacityDispatchPendingWakes; tick++ {
			job, dedup = capacityDispatchEnqueueFixture(t, db, capacityDispatchNextWake(t, e, tick))
			if !dedup || job.JobID != original.JobID || job.SourceTick != e.SourceTick || job.BindingSHA256 != e.BindingSHA256 {
				t.Fatal("pending wake replaced original pins")
			}
		}
		tx, err := db.BeginTx(context.Background(), nil)
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err = EnqueueCapacityDispatch(context.Background(), tx, capacityDispatchNextWake(t, e, MaxCapacityDispatchPendingWakes)); !errors.Is(err, ErrCapacityDispatchSaturated) {
			t.Fatal("wake saturation lost bound", err)
		}
		if err = tx.Rollback(); err != nil {
			t.Fatal(err)
		}
		var runs, wakes int
		if err = db.QueryRow(`SELECT count(*) FROM public.workflow_runs WHERE workflow_namespace=$1`, e.Realm).Scan(&runs); err != nil {
			t.Fatal(err)
		}
		if err = db.QueryRow(`SELECT count(*) FROM public.capacity_dispatch_wakes WHERE realm=$1`, e.Realm).Scan(&wakes); err != nil || runs != 1 || wakes != MaxCapacityDispatchPendingWakes {
			t.Fatalf("unbounded pending storm: runs=%d wakes=%d err=%v", runs, wakes, err)
		}
	})
	t.Run("two_owners_and_original_realm", func(t *testing.T) {
		db, e := capacityDispatchPostgresFixture(t)
		capacityDispatchEnqueueFixture(t, db, e)
		if _, err := ClaimCapacityDispatch(context.Background(), db, "foreign", e.Environment, uuid.New(), time.Minute); !errors.Is(err, ErrCapacityDispatchClaim) {
			t.Fatal("foreign realm claimed job", err)
		}
		if _, err := ClaimCapacityDispatch(context.Background(), db, e.Realm, "foreign", uuid.New(), time.Minute); !errors.Is(err, ErrCapacityDispatchClaim) {
			t.Fatal("foreign environment claimed job", err)
		}
		var won atomic.Int32
		var wg sync.WaitGroup
		for i := 0; i < 8; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				job, err := ClaimCapacityDispatch(context.Background(), db, e.Realm, e.Environment, uuid.New(), time.Minute)
				if err == nil {
					won.Add(1)
					if job.RunID != e.RunID {
						t.Error("claim changed original run")
					}
				} else if !errors.Is(err, ErrCapacityDispatchClaim) {
					t.Error(err)
				}
			}()
		}
		wg.Wait()
		if won.Load() != 1 {
			t.Fatalf("owners=%d", won.Load())
		}
		other := e
		other.JobID, other.RunID, other.Dimension = uuid.New(), uuid.New(), "independent_dimension"
		if _, dedup := capacityDispatchEnqueueFixture(t, db, other); dedup {
			t.Fatal("independent dimension coalesced onto live owner")
		}
		independent := capacityDispatchClaimFixture(t, db, other, time.Minute)
		if independent.JobID != other.JobID {
			t.Fatal("live lease blocked independent dimension")
		}
	})
	t.Run("prestart_expiry_and_fence", func(t *testing.T) {
		db, e := capacityDispatchPostgresFixture(t)
		capacityDispatchEnqueueFixture(t, db, e)
		first := capacityDispatchClaimFixture(t, db, e, time.Second)
		time.Sleep(time.Until(*first.LeaseExpiresAt) + 20*time.Millisecond)
		second := capacityDispatchClaimFixture(t, db, e, time.Minute)
		if second.FencingToken != first.FencingToken+1 || second.LeaseOwner == first.LeaseOwner || second.RunID != first.RunID {
			t.Fatal("prestart reclaim lost original fence")
		}
		if _, err := StartCapacityDispatch(context.Background(), db, first); !errors.Is(err, ErrCapacityDispatchClaim) {
			t.Fatal("stale prestart owner started", err)
		}
		if _, err := StartCapacityDispatch(context.Background(), db, second); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("started_expiry_never_replays_or_releases", func(t *testing.T) {
		db, e := capacityDispatchPostgresFixture(t)
		capacityDispatchEnqueueFixture(t, db, e)
		claimed := capacityDispatchClaimFixture(t, db, e, time.Second)
		started, err := StartCapacityDispatch(context.Background(), db, claimed)
		if err != nil {
			t.Fatal(err)
		}
		// This is remote CI time, following the actual persisted deadline.
		time.Sleep(time.Until(*started.LeaseExpiresAt) + 20*time.Millisecond)
		if _, err := ClaimCapacityDispatch(context.Background(), db, e.Realm, e.Environment, uuid.New(), time.Minute); !errors.Is(err, ErrCapacityDispatchClaim) {
			t.Fatal("started expiry replayed", err)
		}
		wake, dedup := capacityDispatchEnqueueFixture(t, db, capacityDispatchNextWake(t, e, 1))
		if !dedup || wake.JobID != started.JobID || wake.State != "started" {
			t.Fatal("fresh wake released started owner")
		}
		if err := FinishCapacityDispatch(context.Background(), db, started, capacityDispatchResponse(e, "succeeded"), time.Now().UTC(), nil); !errors.Is(err, ErrCapacityDispatchUnknown) {
			t.Fatal("late actual return succeeded", err)
		}
		unknown, err := readCapacityDispatchJob(context.Background(), db, started.JobID, false)
		if err != nil || unknown.State != "unknown" || unknown.ReturnedAt == nil || unknown.StartedAt == nil || !unknown.StartedAt.Equal(*started.StartedAt) {
			t.Fatalf("unknown owner lost: %+v %v", unknown, err)
		}
		if _, err := ClaimCapacityDispatch(context.Background(), db, e.Realm, e.Environment, uuid.New(), time.Minute); !errors.Is(err, ErrCapacityDispatchClaim) {
			t.Fatal("unknown replayed", err)
		}
	})
	t.Run("legacy_ambiguous_rows_excluded", func(t *testing.T) {
		db, e := capacityDispatchPostgresFixture(t)
		version := e.Workflow.Version
		if err := InsertWorkflowRun(context.Background(), db, e.RunID, model.ManifestSelector{Namespace: e.Workflow.Namespace, Name: e.Workflow.Name, Version: &version}, e.Inputs, e.Metadata); err != nil {
			t.Fatal(err)
		}
		// No legacy protocol infers zero invocation from NULL StartedAt.
		if _, err := db.Exec(`INSERT INTO public.capacity_dispatch_jobs (id,run_id,protocol,realm,environment,domain,dimension,source_tick,envelope,envelope_sha256) VALUES ($1,$2,'legacy_ambiguous',$3,$4,$5,$6,$7,'{}',$8)`, e.JobID, e.RunID, e.Realm, e.Environment, e.Domain, e.Dimension, e.SourceTick, capacityDispatchSHA([]byte(`{}`))); err != nil {
			t.Fatal(err)
		}
		if _, err := ClaimCapacityDispatch(context.Background(), db, e.Realm, e.Environment, uuid.New(), time.Minute); !errors.Is(err, ErrCapacityDispatchClaim) {
			t.Fatal("legacy row auto-adopted", err)
		}
		tx, err := db.BeginTx(context.Background(), nil)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback()
		if _, _, err := EnqueueCapacityDispatch(context.Background(), tx, capacityDispatchNextWake(t, e, 1)); !errors.Is(err, ErrCapacityDispatchEnvelope) {
			t.Fatal("new wake replaced ambiguous original owner", err)
		}
	})
	t.Run("actual_return_context_failure_and_typed_status", func(t *testing.T) {
		for _, status := range []string{"succeeded", "failed", "unknown", "cancelled-context", "absolute-deadline-without-err", "opaque-original-error", "independent-go-return-clock"} {
			t.Run(status, func(t *testing.T) {
				db, e := capacityDispatchPostgresFixture(t)
				capacityDispatchEnqueueFixture(t, db, e)
				claimed := capacityDispatchClaimFixture(t, db, e, time.Minute)
				started, err := StartCapacityDispatch(context.Background(), db, claimed)
				if err != nil {
					t.Fatal(err)
				}
				cancelCtx, cancel := context.WithCancel(context.Background())
				var ctx context.Context = cancelCtx
				defer cancel()
				response := capacityDispatchResponse(e, status)
				var runErr error
				if status == "cancelled-context" {
					response.Status = "succeeded"
					runErr = context.Canceled
					cancel()
				}
				if status == "absolute-deadline-without-err" {
					response.Status = "succeeded"
					ctx = capacityDispatchAbsoluteDeadlineContext{Context: context.Background(), deadline: time.Now().Add(-time.Second)}
				}
				if status == "opaque-original-error" {
					response.Status = "failed"
					runErr = errors.New("private provider bearer must not be persisted")
				}
				observedReturn := time.Now().UTC()
				if status == "independent-go-return-clock" {
					response.Status = "succeeded"
					observedReturn = observedReturn.Add(-time.Hour)
				}
				err = FinishCapacityDispatch(ctx, db, started, response, observedReturn, runErr)
				job, readErr := readCapacityDispatchJob(context.Background(), db, e.JobID, false)
				run, runReadErr := GetWorkflowRun(context.Background(), db, e.RunID)
				if readErr != nil || runReadErr != nil || job.ReturnedAt == nil || run.FinishedAt == nil {
					t.Fatalf("actual return missing: %v %v", readErr, runReadErr)
				}
				if status == "unknown" || status == "cancelled-context" || status == "absolute-deadline-without-err" {
					if !errors.Is(err, ErrCapacityDispatchUnknown) || job.State != "unknown" || run.Status != "failed" {
						t.Fatalf("uncertain return claimed success: state=%s run=%s err=%v", job.State, run.Status, err)
					}
				} else if status == "opaque-original-error" {
					if !errors.Is(err, runErr) || job.State != "returned" || run.Status != "failed" || run.Error != "capacity dispatch original workflow returned error" {
						t.Fatalf("original error was leaked or dropped: state=%s run=%s stored=%s err=%v", job.State, run.Status, run.Error, err)
					}
				} else if status == "independent-go-return-clock" {
					if err != nil || job.State != "returned" || run.Status != "succeeded" || !job.ReturnedAt.Truncate(time.Microsecond).Equal(observedReturn.Truncate(time.Microsecond)) {
						t.Fatal("independent Go return clock was treated as PostgreSQL clock", err)
					}
				} else if err != nil || job.State != "returned" || run.Status != status {
					t.Fatalf("typed return changed: state=%s run=%s err=%v", job.State, run.Status, err)
				}
			})
		}
	})
	t.Run("unacknowledged_return_holds_concurrent_tick_and_claim", func(t *testing.T) {
		db, e := capacityDispatchPostgresFixture(t)
		capacityDispatchEnqueueFixture(t, db, e)
		claimed := capacityDispatchClaimFixture(t, db, e, time.Minute)
		started, err := StartCapacityDispatch(context.Background(), db, claimed)
		if err != nil {
			t.Fatal(err)
		}
		// The source-protocol fixture supplies a typed DTO; it does not
		// certify original RunWorkflow/product/SDK return. Its FIRST native
		// Commit really returned and is visible at the owned release hook.
		// Addon/Kind cases separately exercise the actual original function.
		visible, release := make(chan struct{}), make(chan struct{})
		done := make(chan error, 1)
		go func() {
			done <- FinishCapacityDispatch(context.Background(), db, started, capacityDispatchResponse(e, "succeeded"), time.Now().UTC(), nil, func(context.Context) error {
				close(visible)
				<-release
				return nil
			})
		}()
		joined := false
		defer func() {
			if !joined {
				close(release)
				<-done
			}
		}()
		select {
		case <-visible:
		case err := <-done:
			joined = true
			t.Fatal("original finalization failed before release boundary", err)
		case <-time.After(5 * time.Second):
			t.Fatal("original finalization never reached release boundary")
		}
		original, err := readCapacityDispatchJob(context.Background(), db, e.JobID, false)
		if err != nil || original.State != "returned" || original.ReturnedAt == nil || original.FinalizationAckAt != nil {
			t.Fatal("original return/ack boundary changed", err)
		}
		wake, dedup := capacityDispatchEnqueueFixture(t, db, capacityDispatchNextWake(t, e, 1))
		if !dedup || wake.JobID != e.JobID || wake.FinalizationAckAt != nil {
			t.Fatal("visible return without observed ack released dimension")
		}
		if _, err := ClaimCapacityDispatch(context.Background(), db, e.Realm, e.Environment, uuid.New(), time.Minute); !errors.Is(err, ErrCapacityDispatchClaim) {
			t.Fatal("new native dispatch admitted before original acknowledgment", err)
		}
		close(release)
		finishErr := <-done
		joined = true
		if finishErr != nil {
			t.Fatal("actual observed first acknowledgment refused", finishErr)
		}
		original, err = readCapacityDispatchJob(context.Background(), db, e.JobID, false)
		if err != nil || original.FinalizationAckAt == nil {
			t.Fatal("source acknowledgment was not retained", err)
		}
		next, dedup := capacityDispatchEnqueueFixture(t, db, capacityDispatchNextWake(t, e, 2))
		if dedup || next.JobID == e.JobID {
			t.Fatal("observed original acknowledgment did not permit independent next wake")
		}
	})
	t.Run("release_authorization_revoked_after_actual_first_ack_holds", func(t *testing.T) {
		db, e := capacityDispatchPostgresFixture(t)
		capacityDispatchEnqueueFixture(t, db, e)
		started, err := StartCapacityDispatch(t.Context(), db, capacityDispatchClaimFixture(t, db, e, time.Minute))
		if err != nil {
			t.Fatal(err)
		}
		revoked := errors.New("private-current-operator-revocation")
		err = FinishCapacityDispatch(t.Context(), db, started, capacityDispatchResponse(e, "succeeded"), time.Now().UTC(), nil, func(context.Context) error { return revoked })
		if !errors.Is(err, ErrCapacityDispatchUnknown) || !errors.Is(err, revoked) {
			t.Fatal("release gate did not preserve current revocation", err)
		}
		job, err := readCapacityDispatchJob(t.Context(), db, e.JobID, false)
		if err != nil || job.State != "unknown" || job.ReturnedAt == nil || job.FinalizationAckAt != nil {
			t.Fatal("failed release gate published dimension acknowledgment", err)
		}
		wake, dedup := capacityDispatchEnqueueFixture(t, db, capacityDispatchNextWake(t, e, 1))
		if !dedup || wake.JobID != e.JobID || wake.State != "unknown" {
			t.Fatal("failed release gate admitted another original invocation")
		}
	})
	t.Run("late_commit_acknowledgment_retains_actual_return", func(t *testing.T) {
		db, e := capacityDispatchPostgresFixture(t)
		capacityDispatchEnqueueFixture(t, db, e)
		claimed := capacityDispatchClaimFixture(t, db, e, time.Minute)
		started, err := StartCapacityDispatch(context.Background(), db, claimed)
		if err != nil {
			t.Fatal(err)
		}
		lockConn, err := db.Conn(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		defer lockConn.Close()
		key, err := strconv.ParseInt(uuid.NewString()[:8], 16, 64)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := lockConn.ExecContext(context.Background(), `SELECT pg_advisory_lock($1)`, key); err != nil {
			t.Fatal(err)
		}
		defer lockConn.ExecContext(context.Background(), `SELECT pg_advisory_unlock($1)`, key)
		identifier := "dispatch_ack_" + fmt.Sprintf("%x", key)
		function := fmt.Sprintf(`CREATE FUNCTION public.%s() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.id='%s'::uuid AND NEW.state='returned' THEN PERFORM pg_advisory_xact_lock(%d); END IF; RETURN NEW; END; $$`, identifier, e.JobID, key)
		if _, err := db.Exec(function); err != nil {
			t.Fatal(err)
		}
		if _, err := db.Exec(`CREATE CONSTRAINT TRIGGER ` + identifier + ` AFTER UPDATE ON public.capacity_dispatch_jobs DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION public.` + identifier + `()`); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if _, err := db.Exec(`DROP TRIGGER IF EXISTS ` + identifier + ` ON public.capacity_dispatch_jobs`); err != nil {
				t.Error(err)
			}
			if _, err := db.Exec(`DROP FUNCTION IF EXISTS public.` + identifier + `()`); err != nil {
				t.Error(err)
			}
		})
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		actualReturn := time.Now().UTC()
		finished := make(chan error, 1)
		go func() {
			finished <- FinishCapacityDispatch(ctx, db, started, capacityDispatchResponse(e, "succeeded"), actualReturn, nil)
		}()
		waitBy := time.Now().Add(2 * time.Second)
		waiting := false
		for time.Now().Before(waitBy) {
			var blocked int
			if err := db.QueryRow(`SELECT count(*) FROM pg_locks WHERE locktype='advisory' AND classid=0 AND objid::bigint=$1 AND NOT granted`, key).Scan(&blocked); err != nil {
				t.Fatal(err)
			}
			if blocked > 0 {
				waiting = true
				break
			}
			time.Sleep(10 * time.Millisecond)
		}
		if !waiting {
			t.Fatal("actual PostgreSQL Commit did not reach held deferred native trigger")
		}
		<-ctx.Done()
		if _, err := lockConn.ExecContext(context.Background(), `SELECT pg_advisory_unlock($1)`, key); err != nil {
			t.Fatal(err)
		}
		if err := <-finished; !errors.Is(err, ErrCapacityDispatchUnknown) || !errors.Is(err, context.DeadlineExceeded) {
			t.Fatal("late commit acknowledgment published success", err)
		}
		job, err := readCapacityDispatchJob(context.Background(), db, e.JobID, false)
		run, runErr := GetWorkflowRun(context.Background(), db, e.RunID)
		if err != nil || runErr != nil || job.State != "unknown" || job.ReturnedAt == nil || !job.ReturnedAt.Truncate(time.Microsecond).Equal(actualReturn.Truncate(time.Microsecond)) || run.Status != "failed" || run.Result == nil || run.Result.Status != "succeeded" {
			t.Fatalf("late acknowledgment invented a missing original return: state=%s run=%s err=%v %v", job.State, run.Status, err, runErr)
		}
		wake, dedup := capacityDispatchEnqueueFixture(t, db, capacityDispatchNextWake(t, e, 1))
		if !dedup || wake.JobID != e.JobID || wake.State != "unknown" {
			t.Fatal("late acknowledgment released old active owner")
		}
	})
	t.Run("new_binding_wake_preserves_original_pins", func(t *testing.T) {
		db, e := capacityDispatchPostgresFixture(t)
		original, _ := capacityDispatchEnqueueFixture(t, db, e)
		newPolicy, err := CreateManifestVersion(context.Background(), db, model.ManifestDocument{APIVersion: "v1", Kind: "capacity_policy", Metadata: model.ManifestMetadataInput{Namespace: e.Realm, Name: e.Policy.Name}, Spec: []byte(`{}`)}, capacityDispatchSHA([]byte("changed-operator-policy")))
		if err != nil {
			t.Fatal(err)
		}
		newWake := capacityDispatchNextWake(t, e, 1)
		newWake.Policy = CapacityDispatchManifestPin{ID: newPolicy.ID, Namespace: newPolicy.Metadata.Namespace, Name: newPolicy.Metadata.Name, Version: newPolicy.Version, Checksum: newPolicy.Checksum}
		newWake.BindingSHA256 = capacityDispatchSHA([]byte("changed-binding"))
		coalesced, dedup := capacityDispatchEnqueueFixture(t, db, newWake)
		if !dedup || coalesced.Policy != e.Policy || coalesced.BindingSHA256 != e.BindingSHA256 || coalesced.RunID != original.RunID {
			t.Fatal("new wake silently adopted operator revision")
		}
		if _, err := ClaimCapacityDispatch(context.Background(), db, e.Realm, e.Environment, uuid.New(), time.Minute); !errors.Is(err, ErrCapacityDispatchClaim) {
			t.Fatal("old inactive pin inferred zero invocation/adopted new catalog", err)
		}
	})
	t.Run("exact_original_pins_and_no_native_grants", func(t *testing.T) {
		db, e := capacityDispatchPostgresFixture(t)
		capacityDispatchEnqueueFixture(t, db, e)
		claimed := capacityDispatchClaimFixture(t, db, e, time.Minute)
		forged := claimed
		forged.BindingSHA256 = capacityDispatchSHA([]byte("forged"))
		if err := ValidateCapacityDispatchClaim(context.Background(), db, forged, false); !errors.Is(err, ErrCapacityDispatchClaim) {
			t.Fatal("forged original bytes accepted", err)
		}
		if _, err := db.Exec(`UPDATE public.manifests SET active=FALSE WHERE id=$1`, e.RBAC.ID); err != nil {
			t.Fatal(err)
		}
		if _, err := StartCapacityDispatch(context.Background(), db, claimed); !errors.Is(err, ErrCapacityDispatchClaim) {
			t.Fatal("revoked catalog pin started", err)
		}
		for _, table := range []string{"capacity_intents", "capacity_mutation_grants", "capacity_native_commands"} {
			var count int
			if err := db.QueryRow(`SELECT count(*) FROM public.`+table+` WHERE namespace=$1`, e.Realm).Scan(&count); err != nil || count != 0 {
				t.Fatalf("dispatch wrote native authority: table=%s count=%d err=%v", table, count, err)
			}
		}
	})
}

type capacityDispatchAbsoluteDeadlineContext struct {
	context.Context
	deadline time.Time
}

func (c capacityDispatchAbsoluteDeadlineContext) Deadline() (time.Time, bool) {
	return c.deadline, true
}
