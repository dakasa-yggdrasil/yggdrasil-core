package repository

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

// ADR-0090 finalization durability against the explicitly isolated Unix-socket
// database of the disposition Source workflow (schema84). Each test owns a
// fresh realm; no provider, Guest or workflow execution is exercised.

// Shorter per-attempt bounds so CI can hold a row lock past several attempts.
func withFastCapacityDispatchFinish(t *testing.T, grace time.Duration, minimumAttempts int) {
	t.Helper()
	saved := capacityDispatchFinishTuning
	capacityDispatchFinishTuning.attempt = 3 * time.Second
	capacityDispatchFinishTuning.lockTimeout = 300 * time.Millisecond
	capacityDispatchFinishTuning.statementTimeout = 2 * time.Second
	capacityDispatchFinishTuning.grace = grace
	capacityDispatchFinishTuning.minimumAttempts = minimumAttempts
	capacityDispatchFinishTuning.backoff = []time.Duration{100 * time.Millisecond}
	t.Cleanup(func() { capacityDispatchFinishTuning = saved })
}

// A real enqueued, claimed and started job with active exact catalog pins.
func finalizationDispatchStarted(t *testing.T, db *sql.DB, lease time.Duration) (CapacityDispatchEnvelope, CapacityDispatchJob) {
	t.Helper()
	ctx := context.Background()
	realm := "finalization-" + uuid.NewString()
	create := func(kind, name string) CapacityDispatchManifestPin {
		m, err := CreateManifestVersion(ctx, db, model.ManifestDocument{APIVersion: "v1", Kind: kind, Metadata: model.ManifestMetadataInput{Namespace: realm, Name: name}, Spec: []byte(`{}`)}, capacityDispatchSHA([]byte(realm+kind+name)))
		if err != nil {
			t.Fatal(err)
		}
		return CapacityDispatchManifestPin{ID: m.ID, Namespace: realm, Name: name, Version: m.Version, Checksum: m.Checksum}
	}
	e := CapacityDispatchEnvelope{Protocol: CapacityDispatchProtocol, JobID: uuid.New(), RunID: uuid.New(), Realm: realm, Environment: "ci", Domain: "notify", Dimension: "original_notify_aws_vm_members", SourceTick: time.Now().UTC().Truncate(time.Second).Format(time.RFC3339), Policy: create("capacity_policy", "finalization"), Workflow: create("workflow", "finalization"), RBAC: create("rbac", "finalization"), MachinePrincipalID: "capacity-controller", PrincipalSHA256: capacityDispatchSHA([]byte("principal")), BindingSHA256: capacityDispatchSHA([]byte("binding"))}
	e.Inputs = map[string]any{"policy": map[string]any{"namespace": realm, "name": e.Policy.Name}}
	e.Metadata = map[string]any{WorkflowRunCreatorMachinePrincipalMetadataKey: e.MachinePrincipalID, "triggered_by": "workflow_scheduler", "manifest_id": e.Workflow.ID.String(), "scheduled_for": e.SourceTick}
	var err error
	if e.InputsSHA256, e.MetadataSHA256, err = CapacityDispatchEnvelopeHashes(e); err != nil {
		t.Fatal(err)
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = EnqueueCapacityDispatch(ctx, tx, e); err != nil {
		_ = tx.Rollback()
		t.Fatal(err)
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
	claimed, err := ClaimCapacityDispatch(ctx, db, realm, e.Environment, uuid.New(), lease)
	if err != nil {
		t.Fatal(err)
	}
	started, err := StartCapacityDispatch(ctx, db, claimed)
	if err != nil {
		t.Fatal(err)
	}
	return e, started
}

// holdRunRow keeps the original run row locked (as a slow trigger or another
// writer would) until release is called.
func holdRunRow(t *testing.T, db *sql.DB, runID uuid.UUID) func() {
	t.Helper()
	tx, err := db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	var id uuid.UUID
	if err = tx.QueryRow(`SELECT id FROM public.workflow_runs WHERE id=$1 FOR UPDATE`, runID).Scan(&id); err != nil {
		_ = tx.Rollback()
		t.Fatal(err)
	}
	var once sync.Once
	release := func() { once.Do(func() { _ = tx.Rollback() }) }
	t.Cleanup(release)
	return release
}

type finishCategories struct {
	mu   sync.Mutex
	seen map[string]int
}

func (c *finishCategories) observe(category string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.seen == nil {
		c.seen = map[string]int{}
	}
	c.seen[category]++
}

func (c *finishCategories) count(category string) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.seen[category]
}

func TestCapacityDispatchFinishRetriesTransientFirstCommitPostgres(t *testing.T) {
	db := originalDispositionPG(t)
	withFastCapacityDispatchFinish(t, 2*time.Minute, 3)
	e, started := finalizationDispatchStarted(t, db, time.Minute)
	release := holdRunRow(t, db, e.RunID)
	actual := time.Now().UTC().Truncate(time.Microsecond)
	var categories finishCategories
	done := make(chan error, 1)
	go func() {
		done <- FinishCapacityDispatchObserved(context.Background(), db, started, capacityDispatchResponse(e, "succeeded"), actual, nil, categories.observe, nil)
	}()
	// Let at least one attempt hit the server-side lock_timeout and roll back.
	deadline := time.Now().Add(10 * time.Second)
	for categories.count(CapacityDispatchFinishWriteRetry) == 0 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if categories.count(CapacityDispatchFinishWriteRetry) == 0 {
		release()
		t.Fatal("blocked first commit was never classified as a retryable attempt")
	}
	mid, err := readCapacityDispatchJob(context.Background(), db, e.JobID, false)
	if err != nil || mid.State != "started" || mid.ReturnedAt != nil {
		release()
		t.Fatal("a failed attempt left a partial finalization", mid.State, err)
	}
	release()
	if err := <-done; err != nil {
		t.Fatal("retry did not record the actual return", err)
	}
	job, err := readCapacityDispatchJob(context.Background(), db, e.JobID, false)
	run, runErr := GetWorkflowRun(context.Background(), db, e.RunID)
	if err != nil || runErr != nil || job.State != "returned" || job.ReturnedAt == nil || !job.ReturnedAt.Equal(actual) || job.FinalizationAckAt == nil ||
		run.Status != "succeeded" || run.FinishedAt == nil || !run.FinishedAt.Equal(actual) {
		t.Fatalf("retried finalization changed the observed return: state=%s run=%s %v %v", job.State, run.Status, err, runErr)
	}
	if categories.count(CapacityDispatchFinishWriteExhausted) != 0 || categories.count(CapacityDispatchFinishCommitAckLost) != 0 {
		t.Fatal("a recovered retry reported exhaustion or a lost acknowledgment")
	}
}

func TestCapacityDispatchFinishRetryAfterLeaseRecordsUnknownPostgres(t *testing.T) {
	db := originalDispositionPG(t)
	withFastCapacityDispatchFinish(t, 2*time.Minute, 3)
	e, started := finalizationDispatchStarted(t, db, 2*time.Second)
	release := holdRunRow(t, db, e.RunID)
	// The executor returned while the claim was live; the write only lands late.
	actual := time.Now().UTC().Truncate(time.Microsecond)
	done := make(chan error, 1)
	go func() {
		done <- FinishCapacityDispatch(context.Background(), db, started, capacityDispatchResponse(e, "succeeded"), actual, nil)
	}()
	time.Sleep(time.Until(*started.LeaseExpiresAt) + 300*time.Millisecond)
	release()
	if err := <-done; !errors.Is(err, ErrCapacityDispatchUnknown) {
		t.Fatal("a commit after the lease claimed a successful return", err)
	}
	job, err := readCapacityDispatchJob(context.Background(), db, e.JobID, false)
	run, runErr := GetWorkflowRun(context.Background(), db, e.RunID)
	if err != nil || runErr != nil || job.State != "unknown" || job.ReturnedAt == nil || !job.ReturnedAt.Equal(actual) || job.FinalizationAckAt != nil ||
		run.Status != "failed" || run.Result == nil || run.Result.Status != "succeeded" {
		t.Fatalf("late retry invented or lost the actual return: state=%s run=%s %v %v", job.State, run.Status, err, runErr)
	}
}

func TestCapacityDispatchFinishExhaustedKeepsStartedThenRetriesPostgres(t *testing.T) {
	db := originalDispositionPG(t)
	withFastCapacityDispatchFinish(t, 0, 2)
	e, started := finalizationDispatchStarted(t, db, time.Second)
	time.Sleep(time.Until(*started.LeaseExpiresAt) + 50*time.Millisecond)
	release := holdRunRow(t, db, e.RunID)
	actual := time.Now().UTC().Truncate(time.Microsecond)
	var categories finishCategories
	err := FinishCapacityDispatchObserved(context.Background(), db, started, capacityDispatchResponse(e, "failed"), actual, nil, categories.observe, nil)
	if !errors.Is(err, ErrCapacityDispatchFinalizationPending) || categories.count(CapacityDispatchFinishWriteExhausted) != 1 || categories.count(CapacityDispatchFinishWriteRetry) < 2 {
		t.Fatal("exhausted finalization was not reported as pending", err)
	}
	job, err := readCapacityDispatchJob(context.Background(), db, e.JobID, false)
	run, runErr := GetWorkflowRun(context.Background(), db, e.RunID)
	if err != nil || runErr != nil || job.State != "started" || job.ReturnedAt != nil || run.Status != "running" || run.FinishedAt != nil {
		t.Fatal("exhausted finalization wrote a partial or invented outcome", job.State, run.Status)
	}
	release()
	// The owning process retries the SAME observed return once more.
	if err := RetryCapacityDispatchFinalization(context.Background(), db, started, capacityDispatchResponse(e, "failed"), actual, nil, nil, nil); !errors.Is(err, ErrCapacityDispatchUnknown) {
		t.Fatal("pending retry did not record the late return as unknown", err)
	}
	job, err = readCapacityDispatchJob(context.Background(), db, e.JobID, false)
	if err != nil || job.State != "unknown" || job.ReturnedAt == nil || !job.ReturnedAt.Equal(actual) {
		t.Fatal("pending retry lost the observed return time", err)
	}
	// A second retry of an already recorded return never writes again.
	before, _ := readCapacityDispatchJob(context.Background(), db, e.JobID, false)
	_ = RetryCapacityDispatchFinalization(context.Background(), db, started, capacityDispatchResponse(e, "failed"), actual, nil, nil, nil)
	after, err := readCapacityDispatchJob(context.Background(), db, e.JobID, false)
	if err != nil || after.State != before.State || !after.ReturnedAt.Equal(*before.ReturnedAt) {
		t.Fatal("repeated retry rewrote a recorded return", err)
	}
}

func TestCapacityDispatchFinishLostCommitAckEndsUnknownPostgres(t *testing.T) {
	db := originalDispositionPG(t)
	withFastCapacityDispatchFinish(t, 2*time.Minute, 3)
	var lost atomic.Bool
	capacityDispatchFinishAfterCommit = func() bool { return lost.CompareAndSwap(false, true) }
	t.Cleanup(func() { capacityDispatchFinishAfterCommit = nil })
	e, started := finalizationDispatchStarted(t, db, time.Minute)
	actual := time.Now().UTC().Truncate(time.Microsecond)
	var categories finishCategories
	err := FinishCapacityDispatchObserved(context.Background(), db, started, capacityDispatchResponse(e, "succeeded"), actual, nil, categories.observe, nil)
	if !errors.Is(err, ErrCapacityDispatchUnknown) || categories.count(CapacityDispatchFinishCommitAckLost) != 1 {
		t.Fatal("an unobserved commit acknowledgment was treated as observed", err)
	}
	job, err := readCapacityDispatchJob(context.Background(), db, e.JobID, false)
	var finalizationError sql.NullString
	if scanErr := db.QueryRow(`SELECT finalization_error FROM public.capacity_dispatch_jobs WHERE id=$1`, e.JobID).Scan(&finalizationError); err != nil || scanErr != nil ||
		job.State != "unknown" || job.ReturnedAt == nil || !job.ReturnedAt.Equal(actual) || job.FinalizationAckAt != nil || !finalizationError.Valid {
		t.Fatal("lost commit acknowledgment left a returned row without acknowledgment", job.State, err)
	}
}

func TestCapacityDispatchFinishNeverOverwritesDisposedStartedPostgres(t *testing.T) {
	db := originalDispositionPG(t)
	withFastCapacityDispatchFinish(t, 2*time.Minute, 3)
	f := abandonedDispatchPGFixture(t, db, abandonedDispatchFixtureOptions{})
	original, err := readCapacityDispatchJob(context.Background(), db, f.envelope.JobID, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = DisposeAbandonedStartedDispatch(context.Background(), db, f.request, f.barrier, abandonedAllow); err != nil {
		t.Fatal(err)
	}
	job, run := f.snapshot(t)
	response := capacityDispatchResponse(f.envelope, "succeeded")
	for name, finish := range map[string]func() error{
		"finish": func() error {
			return FinishCapacityDispatch(context.Background(), db, original, response, time.Now().UTC(), nil)
		},
		"pending_retry": func() error {
			return RetryCapacityDispatchFinalization(context.Background(), db, original, response, time.Now().UTC(), nil, nil, nil)
		},
	} {
		if err := finish(); !errors.Is(err, ErrCapacityDispatchClaim) {
			t.Fatal("late return was not refused on a disposed row", name, err)
		}
		if afterJob, afterRun := f.snapshot(t); afterJob != job || afterRun != run {
			t.Fatal("late return overwrote a disposed row", name)
		}
	}
}

// The workflow event-trigger leader lock is a session lock: it must be taken
// and released on one pinned session and never leak on a pooled connection.
func TestWorkflowEventTriggerLeadershipPinnedSessionPostgres(t *testing.T) {
	db := originalDispositionPG(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	held := func() int {
		var n int
		if err := db.QueryRowContext(ctx, `SELECT count(*) FROM pg_locks WHERE locktype='advisory' AND classid=0 AND objid=$1 AND granted`, workflowEventTriggerLeaderLockID).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	for round := 0; round < 3; round++ {
		leader, err := TryAcquireWorkflowEventTriggerLeadership(ctx, db)
		if err != nil || leader == nil {
			t.Fatal("leader lock not acquired", round, err)
		}
		if other, err := TryAcquireWorkflowEventTriggerLeadership(ctx, db); err != nil || other != nil {
			t.Fatal("a second pooled session also became leader", round, err)
		}
		if held() != 1 {
			t.Fatal("leader lock not held by exactly one session", round)
		}
		// A cancelled caller context still releases on the pinned session.
		released, stop := context.WithCancel(ctx)
		stop()
		if err := leader.Release(released); err != nil {
			t.Fatal("pinned release failed", round, err)
		}
		if err := leader.Release(ctx); err != nil {
			t.Fatal("second release was not a no-op", round, err)
		}
		if held() != 0 {
			t.Fatal("leader lock leaked after release", round)
		}
	}
}

func TestFailedInstalledGuestDisposalRequestedRefusesWithoutPlanOwner(t *testing.T) {
	db, err := sql.Open("postgres", "host=/nonexistent dbname=never_opened sslmode=disable")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for _, store := range []CapacityStore{{}, {DB: db}} {
		if requested, err := store.FailedInstalledGuestDisposalRequested(context.Background(), model.Manifest{}); requested || !errors.Is(err, ErrCapacityConflict) {
			t.Fatal("coverage routing gate answered without the original plan owner", requested, err)
		}
	}
	if !strings.Contains(ErrCapacityDispatchFinalizationPending.Error(), "not yet recorded") {
		t.Fatal("pending finalization error must not claim a recorded outcome")
	}
}

// The coverage routing gate runs the Source proof, whose manifest reads take
// FOR SHARE row locks. PostgreSQL refuses those in a read-only transaction
// (25006), which would silently disable the plan-time exception. The gate's
// own transaction must accept them, and a requested marker must route.
func TestFailedInstalledGuestDisposalRequestedGatePostgres(t *testing.T) {
	db := originalDispositionPG(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	realm := "coverage-gate-" + uuid.NewString()
	p := model.CapacityPolicySpec{Environment: "ci", Domain: "notify", Dimension: "original_notify_hetzner_vm_members"}
	m, err := CreateManifestVersion(ctx, db, model.ManifestDocument{APIVersion: "v1", Kind: "workflow", Metadata: model.ManifestMetadataInput{Namespace: realm, Name: "coverage-gate"}, Spec: []byte(`{}`)}, capacityDispatchSHA([]byte(realm)))
	if err != nil {
		t.Fatal(err)
	}
	route := func(intent string) bool {
		t.Helper()
		if intent != "" {
			if _, e := db.ExecContext(ctx, `INSERT INTO public.capacity_intents(namespace,environment,domain,dimension,intent) VALUES($1,$2,$3,$4,$5::jsonb) ON CONFLICT(namespace,environment,domain,dimension) DO UPDATE SET intent=EXCLUDED.intent`, realm, p.Environment, p.Domain, p.Dimension, intent); e != nil {
				t.Fatal(e)
			}
		}
		tx, e := beginFailedInstalledDisposalGateTx(ctx, db, realm, p)
		if e != nil {
			t.Fatal(e)
		}
		defer tx.Rollback()
		var id uuid.UUID
		if e = tx.QueryRowContext(ctx, `SELECT id FROM public.manifests WHERE kind='workflow' AND namespace=$1 AND name=$2 ORDER BY version DESC,id DESC LIMIT 1 FOR SHARE`, realm, "coverage-gate").Scan(&id); e != nil || id != m.ID {
			t.Fatal("gate transaction refused the Source proof's FOR SHARE read", e)
		}
		requested, e := failedInstalledDisposalRequestedTx(ctx, tx, realm, p)
		if e != nil {
			t.Fatal(e)
		}
		return requested
	}
	if route("") {
		t.Fatal("absent intent routed past the coverage gate")
	}
	if route(`{"generation":3,"fencing_token":5,"phase":"promoted","failed_installed_disposal":{"id":"` + uuid.NewString() + `","admission_sha256":"` + strings.Repeat("a", 64) + `","preregistration_id":"` + uuid.NewString() + `","stage":"claimed"}}`) {
		t.Fatal("claimed disposal routed past the coverage gate")
	}
	if !route(`{"generation":3,"fencing_token":5,"phase":"promoted","failed_installed_disposal":{"id":"` + uuid.NewString() + `","admission_sha256":"` + strings.Repeat("a", 64) + `","preregistration_id":"` + uuid.NewString() + `","stage":"requested"}}`) {
		t.Fatal("requested disposal did not route past the coverage gate")
	}
}
