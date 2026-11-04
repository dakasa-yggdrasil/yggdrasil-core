package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

// These fixtures exercise the real repository/SQL boundary. The explicit
// callback is a declared authorization test double, never an admission receipt
// or a native capacity grant. HTTP authorization is covered at that boundary.
func dispatchSupersessionFixture(t *testing.T) (*sql.DB, CapacityDispatchEnvelope) {
	t.Helper()
	db, e := capacityDispatchPostgresFixture(t)
	t.Cleanup(func() {
		if _, err := db.Exec(`DELETE FROM public.capacity_dispatch_prestart_rejections WHERE job_id IN (SELECT id FROM public.capacity_dispatch_jobs WHERE realm=$1)`, e.Realm); err != nil {
			t.Error(err)
		}
	})
	e.Policy = dispatchSupersessionPolicy(t, db, e, nil)
	return db, e
}

func dispatchSupersessionPolicy(t *testing.T, db *sql.DB, e CapacityDispatchEnvelope, edit func(*model.CapacityPolicySpec)) CapacityDispatchManifestPin {
	t.Helper()
	p := model.CapacityPolicySpec{
		Environment: e.Environment, Domain: e.Domain, Dimension: e.Dimension,
		TargetIdentity: "declared-test-target", Owner: "declared-test-owner",
		Workflow:          model.ManifestSelector{Namespace: e.Workflow.Namespace, Name: e.Workflow.Name},
		ExecutionEnabled:  true,
		ControllerBinding: &model.CapacityControllerBinding{Mode: "capacity_dispatch_prestart_v1", MachinePrincipalID: e.MachinePrincipalID, DispatchLeaseSeconds: 90},
	}
	if edit != nil {
		edit(&p)
	}
	raw, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	m, err := CreateManifestVersion(context.Background(), db, model.ManifestDocument{APIVersion: "v1", Kind: "capacity_policy", Metadata: model.ManifestMetadataInput{Namespace: e.Policy.Namespace, Name: e.Policy.Name}, Spec: raw}, capacityDispatchSHA(append(raw, []byte(uuid.NewString())...)))
	if err != nil {
		t.Fatal(err)
	}
	return CapacityDispatchManifestPin{ID: m.ID, Namespace: m.Metadata.Namespace, Name: m.Metadata.Name, Version: m.Version, Checksum: m.Checksum}
}

func dispatchSupersessionRequest(job CapacityDispatchJob, next CapacityDispatchEnvelope) CapacityDispatchPrestartRejectionRequest {
	return CapacityDispatchPrestartRejectionRequest{
		JobID: job.JobID, ExpectedRunID: job.RunID, ExpectedEnvelopeSHA256: job.EnvelopeSHA256,
		ExpectedFencingToken: job.FencingToken, ExpectedSupersedingPolicyID: next.Policy.ID,
		ExpectedSupersedingPolicyVersion: next.Policy.Version, ExpectedSupersedingPolicyChecksum: next.Policy.Checksum,
		Issuer: "collaborator:" + uuid.NewString(),
	}
}

func dispatchSupersessionCurrent(t *testing.T, db *sql.DB, e CapacityDispatchEnvelope) CapacityDispatchEnvelope {
	t.Helper()
	next := capacityDispatchNextWake(t, e, 2)
	next.Policy = dispatchSupersessionPolicy(t, db, e, nil)
	return next
}

func dispatchSupersessionAllow(context.Context, CapacityDispatchEnvelope) error { return nil }

func dispatchSupersessionRead(t *testing.T, db *sql.DB, id uuid.UUID) CapacityDispatchJob {
	t.Helper()
	job, err := readCapacityDispatchJob(context.Background(), db, id, false)
	if err != nil {
		t.Fatal(err)
	}
	return job
}

func dispatchSupersessionNoRecord(t *testing.T, db *sql.DB, id uuid.UUID) {
	t.Helper()
	var count int
	if err := db.QueryRow(`SELECT count(*) FROM public.capacity_dispatch_prestart_rejections WHERE job_id=$1`, id).Scan(&count); err != nil || count != 0 {
		t.Fatalf("unexpected administrative record: count=%d err=%v", count, err)
	}
}

func dispatchSupersessionUntouched(t *testing.T, db *sql.DB, before CapacityDispatchJob) {
	t.Helper()
	after := dispatchSupersessionRead(t, db, before.JobID)
	if !reflect.DeepEqual(before, after) {
		t.Fatalf("refusal changed original job: before=%+v after=%+v", before, after)
	}
	dispatchSupersessionNoRecord(t, db, before.JobID)
}

func TestCapacityDispatchSupersessionPostgres(t *testing.T) {
	for _, expiredClaim := range []bool{false, true} {
		name := "unclaimed"
		if expiredClaim {
			name = "expired_original_claim"
		}
		t.Run(name, func(t *testing.T) {
			db, old := dispatchSupersessionFixture(t)
			original, _ := capacityDispatchEnqueueFixture(t, db, old)
			if expiredClaim {
				original = capacityDispatchClaimFixture(t, db, old, time.Second)
				time.Sleep(time.Until(*original.LeaseExpiresAt) + 20*time.Millisecond)
			}
			next := dispatchSupersessionCurrent(t, db, old)
			// A valid new tick alone must not silently dispose the original job.
			blocked, dedup := capacityDispatchEnqueueFixture(t, db, capacityDispatchNextWake(t, next, -1))
			if !dedup || blocked.JobID != old.JobID || blocked.State != "queued" {
				t.Fatal("enqueue silently replaced original stale-policy job")
			}
			original = dispatchSupersessionRead(t, db, old.JobID)
			var rawBefore string
			if err := db.QueryRow(`SELECT envelope FROM public.capacity_dispatch_jobs WHERE id=$1`, old.JobID).Scan(&rawBefore); err != nil {
				t.Fatal(err)
			}
			var callbacks int
			req := dispatchSupersessionRequest(original, next)
			_, err := RejectCapacityDispatchBeforeStart(context.Background(), db, req, next, func(_ context.Context, got CapacityDispatchEnvelope) error {
				callbacks++
				if !reflect.DeepEqual(got, next) {
					return errors.New("authorization did not receive exact current envelope")
				}
				return nil
			})
			if err != nil || callbacks != 2 {
				t.Fatalf("administrative disposition: callbacks=%d err=%v", callbacks, err)
			}
			after := dispatchSupersessionRead(t, db, old.JobID)
			var rawAfter string
			var rejectedAt time.Time
			var reason, issuer string
			if err := db.QueryRow(`SELECT envelope,rejected_at,rejection_reason,rejection_issuer FROM public.capacity_dispatch_jobs WHERE id=$1`, old.JobID).Scan(&rawAfter, &rejectedAt, &reason, &issuer); err != nil {
				t.Fatal(err)
			}
			if rawAfter != rawBefore || after.EnvelopeSHA256 != original.EnvelopeSHA256 || after.LeaseOwner != original.LeaseOwner || after.FencingToken != original.FencingToken || !reflect.DeepEqual(after.LeaseExpiresAt, original.LeaseExpiresAt) || after.PendingWakeCount != original.PendingWakeCount || after.State != "prestart_rejected" || after.StartedAt != nil || after.ReturnedAt != nil || after.FinalizationAckAt != nil || reason != "policy_superseded_before_start" || issuer != req.Issuer {
				t.Fatalf("disposition rewrote original ownership/history: %+v", after)
			}
			run, err := GetWorkflowRun(context.Background(), db, old.RunID)
			if err != nil || run.Status != "cancelled" || run.StartedAt != nil || run.Result != nil || run.FinishedAt == nil || !run.FinishedAt.Equal(rejectedAt) || run.Error != reason || !reflect.DeepEqual(run.Inputs, old.Inputs) || !reflect.DeepEqual(run.Metadata, old.Metadata) {
				t.Fatalf("original workflow did not cancel atomically before start: %+v %v", run, err)
			}
			var retainedWakes int
			if err = db.QueryRow(`SELECT count(*) FROM public.capacity_dispatch_wakes WHERE job_id=$1`, old.JobID).Scan(&retainedWakes); err != nil || retainedWakes != original.PendingWakeCount {
				t.Fatalf("lost original wakes: %d %v", retainedWakes, err)
			}
			receipt, err := ReadCapacityDispatchPrestartRejection(context.Background(), db, old.JobID)
			if err != nil || receipt.JobID != old.JobID || receipt.RunID != old.RunID || receipt.EnvelopeSHA256 != original.EnvelopeSHA256 || receipt.FencingToken != original.FencingToken || receipt.Reason != reason || receipt.Issuer != req.Issuer || !receipt.RecordedAt.Equal(rejectedAt) || receipt.SupersededPolicyID != old.Policy.ID || receipt.SupersededPolicyChecksum != old.Policy.Checksum || receipt.SupersedingPolicyID != next.Policy.ID || receipt.SupersedingPolicyChecksum != next.Policy.Checksum {
				t.Fatal("missing typed administrative readback", err)
			}
			ownerMatches := receipt.LeaseOwner == nil && original.LeaseOwner == uuid.Nil
			if receipt.LeaseOwner != nil {
				ownerMatches = *receipt.LeaseOwner == original.LeaseOwner
			}
			if receipt.State != "prestart_rejected" || receipt.Realm != old.Realm || receipt.Environment != old.Environment || receipt.Domain != old.Domain || receipt.Dimension != old.Dimension || receipt.OriginalPolicy != old.Policy || !ownerMatches || !reflect.DeepEqual(receipt.LeaseExpiresAt, original.LeaseExpiresAt) || receipt.StartedAt != nil || receipt.ReturnedAt != nil || receipt.FinalizationAckAt != nil || receipt.WorkflowRunStatus != "cancelled" || receipt.WorkflowRunStartedAt != nil || receipt.WorkflowRunFinishedAt == nil || !receipt.WorkflowRunFinishedAt.Equal(receipt.RecordedAt) || receipt.WorkflowRunResultPresent || receipt.WorkflowRunError != reason {
				t.Fatalf("typed readback omitted or changed original prestart proof: %+v", receipt)
			}
			receiptJSON, err := json.Marshal(receipt)
			if err != nil {
				t.Fatal(err)
			}
			var projection map[string]any
			if err = json.Unmarshal(receiptJSON, &projection); err != nil {
				t.Fatal(err)
			}
			for _, field := range []string{"started_at", "returned_at", "finalization_ack_at", "workflow_run_started_at"} {
				if value, present := projection[field]; !present || value != nil {
					t.Fatalf("NULL proof absent or rewritten in typed JSON: %s", field)
				}
			}
			for _, query := range []string{
				`UPDATE public.capacity_dispatch_jobs SET state='queued' WHERE id=$1`,
				`UPDATE public.capacity_dispatch_prestart_rejections SET issuer='collaborator:00000000-0000-0000-0000-000000000001' WHERE job_id=$1`,
			} {
				if _, err = db.Exec(query, old.JobID); err == nil {
					t.Fatal("terminal administrative history was mutable")
				}
			}
			if _, err = db.Exec(`UPDATE public.workflow_runs SET status='running',started_at=clock_timestamp() WHERE id=$1`, old.RunID); err == nil {
				t.Fatal("cancelled prestart workflow revived")
			}
			// Exact old ticks remain attached to the retained terminal job.
			if retry, dedup := capacityDispatchEnqueueFixture(t, db, old); !dedup || retry.JobID != old.JobID || retry.State != "prestart_rejected" {
				t.Fatal("old tick was replayed after rejection")
			}
			fresh, dedup := capacityDispatchEnqueueFixture(t, db, next)
			if dedup || fresh.JobID != next.JobID || fresh.RunID != next.RunID || fresh.Policy.ID != next.Policy.ID || fresh.State != "queued" {
				t.Fatal("explicit disposition did not release only new admitted tick")
			}
			if _, err = RejectCapacityDispatchBeforeStart(context.Background(), db, req, next, dispatchSupersessionAllow); err == nil {
				t.Fatal("terminal administrative disposition replayed")
			}
		})
	}

	t.Run("authorization_failure_rolls_back_before_or_after_effect", func(t *testing.T) {
		for _, failureCall := range []int{1, 2} {
			t.Run(string(rune('0'+failureCall)), func(t *testing.T) {
				db, old := dispatchSupersessionFixture(t)
				original, _ := capacityDispatchEnqueueFixture(t, db, old)
				next := dispatchSupersessionCurrent(t, db, old)
				forced := errors.New("declared current admission revoked")
				calls := 0
				_, err := RejectCapacityDispatchBeforeStart(context.Background(), db, dispatchSupersessionRequest(original, next), next, func(context.Context, CapacityDispatchEnvelope) error {
					calls++
					if calls == failureCall {
						return forced
					}
					return nil
				})
				if err == nil || calls != failureCall {
					t.Fatalf("failed admission accepted: calls=%d err=%v", calls, err)
				}
				dispatchSupersessionUntouched(t, db, original)
				run, err := GetWorkflowRun(context.Background(), db, old.RunID)
				if err != nil || run.Status != "pending" || run.StartedAt != nil || run.FinishedAt != nil || run.Result != nil {
					t.Fatal("failed post-effect admission committed workflow cancellation", err)
				}
			})
		}
	})

	t.Run("exact_request_and_scope_required", func(t *testing.T) {
		cases := []struct {
			name string
			edit func(*CapacityDispatchPrestartRejectionRequest, *CapacityDispatchEnvelope)
		}{
			{"foreign_job", func(r *CapacityDispatchPrestartRejectionRequest, _ *CapacityDispatchEnvelope) { r.JobID = uuid.New() }},
			{"foreign_run", func(r *CapacityDispatchPrestartRejectionRequest, _ *CapacityDispatchEnvelope) {
				r.ExpectedRunID = uuid.New()
			}},
			{"envelope_hash", func(r *CapacityDispatchPrestartRejectionRequest, _ *CapacityDispatchEnvelope) {
				r.ExpectedEnvelopeSHA256 = strings.Repeat("0", 64)
			}},
			{"fence", func(r *CapacityDispatchPrestartRejectionRequest, _ *CapacityDispatchEnvelope) {
				r.ExpectedFencingToken++
			}},
			{"successor_id", func(r *CapacityDispatchPrestartRejectionRequest, _ *CapacityDispatchEnvelope) {
				r.ExpectedSupersedingPolicyID = uuid.New()
			}},
			{"successor_version", func(r *CapacityDispatchPrestartRejectionRequest, _ *CapacityDispatchEnvelope) {
				r.ExpectedSupersedingPolicyVersion++
			}},
			{"successor_checksum", func(r *CapacityDispatchPrestartRejectionRequest, _ *CapacityDispatchEnvelope) {
				r.ExpectedSupersedingPolicyChecksum = strings.Repeat("0", 64)
			}},
			{"machine_issuer", func(r *CapacityDispatchPrestartRejectionRequest, _ *CapacityDispatchEnvelope) {
				r.Issuer = "machine:capacity-controller"
			}},
			{"environment", func(_ *CapacityDispatchPrestartRejectionRequest, e *CapacityDispatchEnvelope) {
				e.Environment = "foreign"
			}},
			{"domain", func(_ *CapacityDispatchPrestartRejectionRequest, e *CapacityDispatchEnvelope) { e.Domain = "foreign" }},
			{"dimension", func(_ *CapacityDispatchPrestartRejectionRequest, e *CapacityDispatchEnvelope) {
				e.Dimension = "foreign"
			}},
			{"workflow_pin", func(_ *CapacityDispatchPrestartRejectionRequest, e *CapacityDispatchEnvelope) {
				e.Workflow.Checksum = strings.Repeat("0", 64)
			}},
			{"rbac_pin", func(_ *CapacityDispatchPrestartRejectionRequest, e *CapacityDispatchEnvelope) {
				e.RBAC.Checksum = strings.Repeat("0", 64)
			}},
			{"inputs_hash", func(_ *CapacityDispatchPrestartRejectionRequest, e *CapacityDispatchEnvelope) {
				e.InputsSHA256 = strings.Repeat("0", 64)
			}},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				db, old := dispatchSupersessionFixture(t)
				original, _ := capacityDispatchEnqueueFixture(t, db, old)
				next := dispatchSupersessionCurrent(t, db, old)
				req := dispatchSupersessionRequest(original, next)
				tc.edit(&req, &next)
				if _, err := RejectCapacityDispatchBeforeStart(context.Background(), db, req, next, dispatchSupersessionAllow); err == nil {
					t.Fatal("unmatched administrative request accepted")
				}
				dispatchSupersessionUntouched(t, db, original)
			})
		}
	})

	t.Run("active_old_policy_and_invalid_successor_hold", func(t *testing.T) {
		for _, mode := range []string{"old_still_active", "disabled", "wrong_controller", "wrong_policy_scope", "wrong_workflow", "later_tombstone"} {
			t.Run(mode, func(t *testing.T) {
				db, old := dispatchSupersessionFixture(t)
				original, _ := capacityDispatchEnqueueFixture(t, db, old)
				next := capacityDispatchNextWake(t, old, 1)
				if mode != "old_still_active" {
					next.Policy = dispatchSupersessionPolicy(t, db, old, func(p *model.CapacityPolicySpec) {
						switch mode {
						case "disabled":
							p.ExecutionEnabled = false
						case "wrong_controller":
							p.ControllerBinding.MachinePrincipalID = "foreign-controller"
						case "wrong_policy_scope":
							p.Dimension = "foreign-dimension"
						case "wrong_workflow":
							p.Workflow.Name = "foreign-workflow"
						}
					})
				}
				if mode == "later_tombstone" {
					inactive := false
					if _, err := CreateManifestVersion(context.Background(), db, model.ManifestDocument{APIVersion: "v1", Kind: "capacity_policy", Metadata: model.ManifestMetadataInput{Namespace: old.Realm, Name: old.Policy.Name, Active: &inactive}, Spec: []byte(`{}`)}, capacityDispatchSHA([]byte(uuid.NewString()))); err != nil {
						t.Fatal(err)
					}
				}
				if _, err := RejectCapacityDispatchBeforeStart(context.Background(), db, dispatchSupersessionRequest(original, next), next, dispatchSupersessionAllow); err == nil {
					t.Fatal("invalid replacement or active original accepted")
				}
				dispatchSupersessionUntouched(t, db, original)
			})
		}
	})

	t.Run("started_unknown_returned_and_live_claims_hold", func(t *testing.T) {
		for _, state := range []string{"live_queued", "started", "unknown", "returned_acknowledged"} {
			t.Run(state, func(t *testing.T) {
				db, old := dispatchSupersessionFixture(t)
				capacityDispatchEnqueueFixture(t, db, old)
				job := capacityDispatchClaimFixture(t, db, old, time.Minute)
				if state != "live_queued" {
					var err error
					job, err = StartCapacityDispatch(context.Background(), db, job)
					if err != nil {
						t.Fatal(err)
					}
					if state != "started" {
						status := "succeeded"
						if state == "unknown" {
							status = "unknown"
						}
						err = FinishCapacityDispatch(context.Background(), db, job, capacityDispatchResponse(old, status), time.Now().UTC().Truncate(time.Microsecond), nil)
						if (state == "unknown" && !errors.Is(err, ErrCapacityDispatchUnknown)) || (state != "unknown" && err != nil) {
							t.Fatal("original typed return fixture", err)
						}
					}
				}
				next := dispatchSupersessionCurrent(t, db, old)
				before := dispatchSupersessionRead(t, db, old.JobID)
				if _, err := RejectCapacityDispatchBeforeStart(context.Background(), db, dispatchSupersessionRequest(before, next), next, dispatchSupersessionAllow); err == nil {
					t.Fatal("possible original invocation or live owner was rejected")
				}
				dispatchSupersessionUntouched(t, db, before)
			})
		}
	})

	t.Run("returned_without_finalization_ack_is_not_prestart", func(t *testing.T) {
		db, old := dispatchSupersessionFixture(t)
		capacityDispatchEnqueueFixture(t, db, old)
		claimed := capacityDispatchClaimFixture(t, db, old, time.Minute)
		started, err := StartCapacityDispatch(context.Background(), db, claimed)
		if err != nil {
			t.Fatal(err)
		}
		forced := errors.New("declared release fence fails after original commit")
		err = FinishCapacityDispatch(context.Background(), db, started, capacityDispatchResponse(old, "succeeded"), time.Now().UTC().Truncate(time.Microsecond), nil, func(context.Context) error {
			next := dispatchSupersessionCurrent(t, db, old)
			before := dispatchSupersessionRead(t, db, old.JobID)
			if before.State != "returned" || before.FinalizationAckAt != nil {
				t.Error("fixture did not enter actual unacknowledged-return boundary")
			}
			if _, rejectErr := RejectCapacityDispatchBeforeStart(context.Background(), db, dispatchSupersessionRequest(before, next), next, dispatchSupersessionAllow); rejectErr == nil {
				t.Error("unacknowledged return was treated as prestart")
			}
			dispatchSupersessionUntouched(t, db, before)
			return forced
		})
		if !errors.Is(err, ErrCapacityDispatchUnknown) || !errors.Is(err, forced) {
			t.Fatal("original release failure lost", err)
		}
	})

	t.Run("original_policy_pin_and_workflow_prestart_boundary_required", func(t *testing.T) {
		for _, mode := range []string{"old_policy_checksum", "run_started", "run_finished", "run_result", "run_error", "run_inputs", "run_metadata"} {
			t.Run(mode, func(t *testing.T) {
				db, old := dispatchSupersessionFixture(t)
				original, _ := capacityDispatchEnqueueFixture(t, db, old)
				next := dispatchSupersessionCurrent(t, db, old)
				queries := map[string]string{
					"old_policy_checksum": `UPDATE public.manifests SET checksum=repeat('0',64) WHERE id=$1`,
					"run_started":         `UPDATE public.workflow_runs SET status='running',started_at=clock_timestamp() WHERE id=$1`,
					"run_finished":        `UPDATE public.workflow_runs SET status='failed',finished_at=clock_timestamp() WHERE id=$1`,
					"run_result":          `UPDATE public.workflow_runs SET result='{}'::jsonb WHERE id=$1`,
					"run_error":           `UPDATE public.workflow_runs SET error='original uncertainty retained' WHERE id=$1`,
					"run_inputs":          `UPDATE public.workflow_runs SET inputs='{}'::jsonb WHERE id=$1`,
					"run_metadata":        `UPDATE public.workflow_runs SET metadata='{}'::jsonb WHERE id=$1`,
				}
				id := old.RunID
				if mode == "old_policy_checksum" {
					id = old.Policy.ID
				}
				if _, err := db.Exec(queries[mode], id); err != nil {
					t.Fatal(err)
				}
				if _, err := RejectCapacityDispatchBeforeStart(context.Background(), db, dispatchSupersessionRequest(original, next), next, dispatchSupersessionAllow); err == nil {
					t.Fatal("changed original boundary accepted")
				}
				dispatchSupersessionUntouched(t, db, original)
			})
		}
	})

	t.Run("administrative_commit_serializes_concurrent_start_and_claim", func(t *testing.T) {
		db, old := dispatchSupersessionFixture(t)
		capacityDispatchEnqueueFixture(t, db, old)
		stale := capacityDispatchClaimFixture(t, db, old, time.Second)
		time.Sleep(time.Until(*stale.LeaseExpiresAt) + 20*time.Millisecond)
		next := dispatchSupersessionCurrent(t, db, old)
		req := dispatchSupersessionRequest(stale, next)
		entered, release := make(chan struct{}), make(chan struct{})
		adminDone := make(chan error, 1)
		var calls atomic.Int32
		go func() {
			_, err := RejectCapacityDispatchBeforeStart(context.Background(), db, req, next, func(context.Context, CapacityDispatchEnvelope) error {
				if calls.Add(1) == 2 {
					close(entered)
					<-release
				}
				return nil
			})
			adminDone <- err
		}()
		joined := false
		defer func() {
			if !joined {
				close(release)
				<-adminDone
			}
		}()
		select {
		case <-entered:
		case err := <-adminDone:
			joined = true
			t.Fatal("administration failed before owned transaction boundary", err)
		case <-time.After(5 * time.Second):
			t.Fatal("administrative boundary did not arrive")
		}
		startDone := make(chan error, 1)
		go func() { _, err := StartCapacityDispatch(context.Background(), db, stale); startDone <- err }()
		if _, err := ClaimCapacityDispatch(context.Background(), db, old.Realm, old.Environment, uuid.New(), time.Minute); !errors.Is(err, ErrCapacityDispatchClaim) {
			t.Error("concurrent claim adopted rejected or inactive-policy original", err)
		}
		close(release)
		if err := <-adminDone; err != nil {
			t.Error("administrative commit", err)
		}
		joined = true
		if err := <-startDone; !errors.Is(err, ErrCapacityDispatchClaim) {
			t.Error("stale original owner started across administrative commit", err)
		}
		after := dispatchSupersessionRead(t, db, old.JobID)
		if after.State != "prestart_rejected" || after.StartedAt != nil || after.FencingToken != stale.FencingToken || after.LeaseOwner != stale.LeaseOwner {
			t.Fatal("race rewrote retained original owner", after)
		}
	})
}
