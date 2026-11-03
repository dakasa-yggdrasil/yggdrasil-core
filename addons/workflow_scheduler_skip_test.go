package addons

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"
	_ "time/tzdata"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	"github.com/google/uuid"
	"github.com/robfig/cron/v3"
)

func workflowSkipTime(t *testing.T, value string) time.Time {
	t.Helper()
	at, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		t.Fatal(err)
	}
	return at
}

func workflowSkipCron(t *testing.T, expression string) cron.Schedule {
	t.Helper()
	schedule, err := cron.NewParser(cron.Minute | cron.Hour | cron.Dom | cron.Month | cron.Dow).Parse(expression)
	if err != nil {
		t.Fatal(err)
	}
	return schedule
}

// Expected instants are explicit calendar facts, not derived by walking the
// production selector or copying its search. In particular, the repeated New
// York 01:30 occurs at two different UTC instants on 2026-11-01.
func TestWorkflowScheduleSkipSelectsActualCronTicks(t *testing.T) {
	tests := []struct {
		name, expression, zone, last, now, policy, fire, next string
		due                                                   bool
	}{
		{"aws_multiday_skip", "* * * * *", "UTC", "2026-10-29T09:12:00Z", "2026-11-03T01:57:23.456Z", "skip", "2026-11-03T01:57:00Z", "2026-11-03T01:58:00Z", true},
		{"aws_multiday_default_empty", "* * * * *", "UTC", "2026-10-29T09:12:00Z", "2026-11-03T01:57:23Z", "", "2026-11-03T01:57:00Z", "2026-11-03T01:58:00Z", true},
		{"aws_multiday_normalized_skip", "* * * * *", "UTC", "2026-10-29T09:12:00Z", "2026-11-03T01:57:23Z", " SKIP \t", "2026-11-03T01:57:00Z", "2026-11-03T01:58:00Z", true},
		{"ordinary_current_minute", "* * * * *", "UTC", "2026-11-03T01:56:00Z", "2026-11-03T01:57:23Z", "skip", "2026-11-03T01:57:00Z", "2026-11-03T01:58:00Z", true},
		{"exact_due_boundary", "* * * * *", "UTC", "2026-11-03T01:55:00Z", "2026-11-03T01:57:00Z", "skip", "2026-11-03T01:57:00Z", "2026-11-03T01:58:00Z", true},
		{"subsecond_now", "* * * * *", "UTC", "2026-10-29T09:12:00.999Z", "2026-11-03T01:57:59.999999999Z", "skip", "2026-11-03T01:57:00Z", "2026-11-03T01:58:00Z", true},
		{"explicit_catch_up_preserves_first", "* * * * *", "UTC", "2026-10-29T09:12:00Z", "2026-11-03T01:57:23Z", " CATCH_UP ", "2026-10-29T09:13:00Z", "2026-10-29T09:14:00Z", true},
		{"monthly_not_last_minute_shortcut", "0 0 1 * *", "UTC", "2026-01-02T00:00:00Z", "2026-11-03T01:57:23Z", "skip", "2026-11-01T00:00:00Z", "2026-12-01T00:00:00Z", true},
		{"yearly_rare_gap", "0 0 1 1 *", "UTC", "2024-01-02T00:00:00Z", "2026-11-03T01:57:23Z", "skip", "2026-01-01T00:00:00Z", "2027-01-01T00:00:00Z", true},
		{"leap_day_gap", "0 0 29 2 *", "UTC", "2021-03-01T00:00:00Z", "2026-11-03T01:57:23Z", "skip", "2024-02-29T00:00:00Z", "2028-02-29T00:00:00Z", true},
		{"non_utc_quarter_hour", "*/15 * * * *", "Asia/Kolkata", "2026-10-29T09:12:00Z", "2026-11-03T01:57:23Z", "skip", "2026-11-03T01:45:00Z", "2026-11-03T02:00:00Z", true},
		{"dst_fall_first_occurrence", "30 1 * * *", "America/New_York", "2026-10-31T05:30:00Z", "2026-11-01T05:45:00Z", "skip", "2026-11-01T05:30:00Z", "2026-11-01T06:30:00Z", true},
		{"dst_fall_between_repeated_hours", "30 1 * * *", "America/New_York", "2026-10-31T05:30:00Z", "2026-11-01T06:15:00Z", "skip", "2026-11-01T05:30:00Z", "2026-11-01T06:30:00Z", true},
		{"dst_fall_second_occurrence", "30 1 * * *", "America/New_York", "2026-10-31T05:30:00Z", "2026-11-01T06:45:00Z", "skip", "2026-11-01T06:30:00Z", "2026-11-02T06:30:00Z", true},
		{"dst_spring_missing_hour", "30 2 * * *", "America/New_York", "2026-03-06T07:30:00Z", "2026-03-08T08:00:00Z", "skip", "2026-03-07T07:30:00Z", "2026-03-09T06:30:00Z", true},
		{"future_cursor_no_due", "* * * * *", "UTC", "2026-11-03T02:00:00Z", "2026-11-03T01:57:23Z", "skip", "2026-11-03T02:01:00Z", "", false},
		{"cross_unix_epoch", "0 0 * * *", "UTC", "1969-12-30T01:00:00Z", "1970-01-01T00:00:30Z", "skip", "1970-01-01T00:00:00Z", "1970-01-02T00:00:00Z", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			loc, err := time.LoadLocation(tt.zone)
			if err != nil {
				t.Fatal(err)
			}
			last, now := workflowSkipTime(t, tt.last), workflowSkipTime(t, tt.now)
			fire, next, due, err := selectWorkflowScheduleTick(workflowSkipCron(t, tt.expression), loc, last, now, tt.policy)
			wantNext := time.Time{}
			if tt.next != "" {
				wantNext = workflowSkipTime(t, tt.next)
			}
			if err != nil || due != tt.due || !fire.Equal(workflowSkipTime(t, tt.fire)) || !next.Equal(wantNext) {
				t.Fatalf("actual tick mismatch: fire=%s next=%s due=%v err=%v; want %s / %s / %v", fire, next, due, err, tt.fire, tt.next, tt.due)
			}
			if due && (!fire.After(last) || fire.After(now)) {
				t.Fatal("selected occurrence is not inside the original due interval")
			}
			if due && tt.policy != " CATCH_UP " && !next.After(now) {
				t.Fatal("skip still leaves another historical due tick")
			}
		})
	}
}

type workflowSkipScheduleFunc func(time.Time) time.Time

func (f workflowSkipScheduleFunc) Next(after time.Time) time.Time { return f(after) }

func TestWorkflowScheduleSkipRejectsInvalidSchedules(t *testing.T) {
	last := workflowSkipTime(t, "2026-10-29T09:12:00Z")
	now := workflowSkipTime(t, "2026-11-03T01:57:23Z")
	real := workflowSkipCron(t, "* * * * *")
	for _, name := range []string{"nil_schedule", "nil_location", "zero_cursor", "zero_now", "unknown_policy", "zero_next", "nonadvancing_next", "backward_next", "following_next_zero", "impossible_february_30"} {
		t.Run(name, func(t *testing.T) {
			schedule, loc, cursor, at, policy := real, time.UTC, last, now, "skip"
			switch name {
			case "nil_schedule":
				schedule = nil
			case "nil_location":
				loc = nil
			case "zero_cursor":
				cursor = time.Time{}
			case "zero_now":
				at = time.Time{}
			case "unknown_policy":
				policy = "replay_everything"
			case "zero_next":
				schedule = workflowSkipScheduleFunc(func(time.Time) time.Time { return time.Time{} })
			case "nonadvancing_next":
				schedule = workflowSkipScheduleFunc(func(after time.Time) time.Time { return after })
			case "backward_next":
				schedule = workflowSkipScheduleFunc(func(after time.Time) time.Time { return after.Add(-time.Minute) })
			case "following_next_zero":
				schedule = workflowSkipScheduleFunc(func(after time.Time) time.Time {
					if after.Equal(last) {
						return last.Add(time.Minute)
					}
					return time.Time{}
				})
			case "impossible_february_30":
				// The parser accepts day30/month2 independently. A real cron Next
				// has no actual occurrence, rather than a made-up monthly instant.
				schedule = workflowSkipCron(t, "0 0 30 2 *")
			}
			fire, next, due, err := selectWorkflowScheduleTick(schedule, loc, cursor, at, policy)
			if err == nil || due || !fire.IsZero() || !next.IsZero() {
				t.Fatalf("invalid selection admitted: fire=%s next=%s due=%v err=%v", fire, next, due, err)
			}
		})
	}
}

type workflowSkipCountingSchedule struct {
	schedule cron.Schedule
	calls    int
}

func (s *workflowSkipCountingSchedule) Next(after time.Time) time.Time {
	s.calls++
	return s.schedule.Next(after)
}

func TestWorkflowScheduleSkipSearchIsBounded(t *testing.T) {
	schedule := &workflowSkipCountingSchedule{schedule: workflowSkipCron(t, "* * * * *")}
	fire, next, due, err := selectWorkflowScheduleTick(schedule, time.UTC,
		workflowSkipTime(t, "1970-01-01T00:00:00Z"), workflowSkipTime(t, "2026-11-03T01:57:23Z"), "skip")
	if err != nil || !due || !fire.Equal(workflowSkipTime(t, "2026-11-03T01:57:00Z")) || !next.Equal(workflowSkipTime(t, "2026-11-03T01:58:00Z")) {
		t.Fatalf("long backlog selection: fire=%s next=%s due=%v err=%v", fire, next, due, err)
	}
	// This is an actual cron implementation with millions of missed occurrences.
	// Count calls, not wall-clock timing or a forced planner/clock environment.
	if schedule.calls > 67 {
		t.Fatalf("selection walked the historical tick backlog: Next calls=%d", schedule.calls)
	}
}

func workflowSkipSeedCursor(t *testing.T, f dispatchSchedulerFixture, last time.Time) repository.WorkflowScheduleState {
	t.Helper()
	tx, err := f.db.BeginTx(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	won, err := repository.UpsertWorkflowScheduleState(t.Context(), tx, f.workflow.ID.String(), last, last.Add(time.Minute))
	if err != nil || !won {
		t.Fatal("seed initial disposable-fixture cursor through normal repository API", err)
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
	state, err := repository.GetWorkflowScheduleState(t.Context(), f.db, f.workflow.ID.String())
	if err != nil || !state.LastFiredAt.Equal(last) {
		t.Fatal("original fixture cursor not retained", err)
	}
	return state
}

func workflowSkipAssertState(t *testing.T, f dispatchSchedulerFixture, fire, next time.Time) repository.WorkflowScheduleState {
	t.Helper()
	state, err := repository.GetWorkflowScheduleState(t.Context(), f.db, f.workflow.ID.String())
	if err != nil || !state.LastFiredAt.Equal(fire) || !state.NextFireAt.Equal(next) {
		t.Fatalf("source-owned schedule transition: last=%s next=%s err=%v; want %s / %s", state.LastFiredAt, state.NextFireAt, err, fire, next)
	}
	return state
}

// Uses the existing real PG/broker fixture and actual processScheduledWorkflow.
// It never starts a protected queued run or asserts successful native capacity.
func TestCapacityDispatchSchedulerSkipPostgres(t *testing.T) {
	t.Run("protected_initial_start_at_selects_latest", func(t *testing.T) {
		f := newDispatchSchedulerFixture(t, false)
		if err := f.tick(t, f.now); err != nil {
			t.Fatal(err)
		}
		workflowSkipAssertState(t, f, f.now, f.now.Add(time.Minute))
		workflowSkipAssertProtectedQueuedTick(t, f, f.now)
	})
	t.Run("protected_multiday_default_skip_is_atomic_and_not_replayed", func(t *testing.T) {
		f := newDispatchSchedulerFixture(t, false)
		workflowSkipSeedCursor(t, f, f.now.Add(-5*24*time.Hour))
		start := make(chan struct{})
		results := make(chan error, 2)
		for range 2 {
			go func() {
				<-start
				results <- f.tick(t, f.now)
			}()
		}
		close(start)
		for range 2 {
			if err := <-results; err != nil {
				t.Fatal("simultaneous scheduler attempt refused", err)
			}
		}
		before := workflowSkipAssertState(t, f, f.now, f.now.Add(time.Minute))
		workflowSkipAssertProtectedQueuedTick(t, f, f.now)
		if err := f.tick(t, f.now.Add(10*time.Second)); err != nil {
			t.Fatal("same current minute replay refused unexpectedly", err)
		}
		after := workflowSkipAssertState(t, f, f.now, f.now.Add(time.Minute))
		if !before.UpdatedAt.Equal(after.UpdatedAt) {
			t.Fatal("not-due pass rewrote original schedule state")
		}
		workflowSkipAssertProtectedQueuedTick(t, f, f.now)
	})
	t.Run("protected_refusal_preserves_original_cursor_and_no_obligations", func(t *testing.T) {
		f := newDispatchSchedulerFixture(t, false)
		original := workflowSkipSeedCursor(t, f, f.now.Add(-5*24*time.Hour))
		t.Setenv("YGGDRASIL_CAPACITY_DISPATCH_ENABLED", "false")
		if err := f.tick(t, f.now); err == nil {
			t.Fatal("disabled source owner accepted the selected tick")
		}
		after := workflowSkipAssertState(t, f, original.LastFiredAt, original.NextFireAt)
		if !after.UpdatedAt.Equal(original.UpdatedAt) {
			t.Fatal("refused admission consumed or retimed the original cursor")
		}
		for _, query := range []string{`SELECT count(*) FROM public.capacity_dispatch_jobs WHERE realm=$1`, `SELECT count(*) FROM public.capacity_dispatch_wakes WHERE realm=$1`, `SELECT count(*) FROM public.workflow_runs WHERE workflow_namespace=$1`} {
			var count int
			if err := f.db.QueryRowContext(t.Context(), query, f.workflow.Metadata.Namespace).Scan(&count); err != nil || count != 0 {
				t.Fatal("refusal created an obligation", count, err)
			}
		}
		assertDispatchNoNativeAuthority(t, f.db, f.workflow.Metadata.Namespace)
	})
	t.Run("legacy_multiday_skip_uses_same_selected_tick", func(t *testing.T) {
		f := newDispatchSchedulerFixture(t, true)
		enabled := true
		spec := model.WorkflowManifestSpec{Trigger: model.WorkflowTriggerSpec{Mode: "schedule", Enabled: &enabled, Schedule: f.schedule}, Steps: []model.WorkflowStepSpec{{ID: "ordinary", Use: model.WorkflowStepUseSpec{Kind: "yggdrasil", Operation: "assert"}, With: map[string]any{"equal": []any{map[string]any{"name": "same", "actual": "ordinary", "expected": "ordinary"}}}}}}
		f.workflow = f.create("workflow", "ordinary-skip", spec)
		workflowSkipSeedCursor(t, f, f.now.Add(-5*24*time.Hour))
		if err := f.tick(t, f.now); err != nil {
			t.Fatal("real legacy source refused", err)
		}
		workflowSkipAssertState(t, f, f.now, f.now.Add(time.Minute))
		ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
		defer cancel()
		var runID uuid.UUID
		if err := f.db.QueryRowContext(ctx, `SELECT id FROM public.workflow_runs WHERE workflow_namespace=$1 AND workflow_name='ordinary-skip'`, f.workflow.Metadata.Namespace).Scan(&runID); err != nil {
			t.Fatal("original legacy source did not insert its run", err)
		}
		for {
			run, err := repository.GetWorkflowRun(ctx, f.db, runID)
			if err != nil {
				t.Fatal(err)
			}
			if run.Metadata["scheduled_for"] != f.now.Format(time.RFC3339) || run.Metadata["manifest_id"] != f.workflow.ID.String() {
				t.Fatal("legacy run received a fabricated historical tick", run.Metadata)
			}
			if run.FinishedAt != nil {
				if run.Status != "succeeded" || run.Result == nil || run.Result.Status != "succeeded" || len(run.Result.Steps) != 1 || run.Result.Steps[0].Operation != "assert" {
					t.Fatal("original ordinary assertion did not complete", run.Status)
				}
				break
			}
			select {
			case <-ctx.Done():
				t.Fatal("real legacy execution did not return", ctx.Err())
			case <-time.After(10 * time.Millisecond):
			}
		}
		var jobs int
		if err := f.db.QueryRowContext(ctx, `SELECT count(*) FROM public.capacity_dispatch_jobs WHERE realm=$1`, f.workflow.Metadata.Namespace).Scan(&jobs); err != nil || jobs != 0 {
			t.Fatal("legacy assertion became protected capacity authority", jobs, err)
		}
		assertDispatchNoNativeAuthority(t, f.db, f.workflow.Metadata.Namespace)
	})
}

func workflowSkipAssertProtectedQueuedTick(t *testing.T, f dispatchSchedulerFixture, tick time.Time) {
	t.Helper()
	var jobID uuid.UUID
	if err := f.db.QueryRowContext(t.Context(), `SELECT id FROM public.capacity_dispatch_jobs WHERE realm=$1`, f.workflow.Metadata.Namespace).Scan(&jobID); err != nil {
		t.Fatal(err)
	}
	job, err := repository.ReadCapacityDispatchJob(t.Context(), f.db, jobID)
	if err != nil || job.SourceTick != tick.Format(time.RFC3339Nano) || job.Metadata["scheduled_for"] != job.SourceTick || job.Workflow.ID != f.workflow.ID || job.Workflow.Checksum != f.workflow.Checksum || job.State != "queued" || job.StartedAt != nil || job.ReturnedAt != nil {
		t.Fatal("actual protected envelope changed selected tick, pins or original state", err)
	}
	run, err := repository.GetWorkflowRun(t.Context(), f.db, job.RunID)
	if err != nil || run.Status != "pending" || run.StartedAt != nil || run.FinishedAt != nil || run.Metadata["scheduled_for"] != job.SourceTick {
		t.Fatal("queued source fabricated a started/returned run", err)
	}
	for _, table := range []string{"capacity_dispatch_jobs", "capacity_dispatch_wakes"} {
		var count int
		if err := f.db.QueryRowContext(t.Context(), fmt.Sprintf("SELECT count(*) FROM public.%s WHERE realm=$1", table), f.workflow.Metadata.Namespace).Scan(&count); err != nil || count != 1 {
			t.Fatal("selected original tick did not remain one durable obligation", table, count, err)
		}
	}
	var raw []byte
	if err := f.db.QueryRowContext(t.Context(), `SELECT metadata FROM public.workflow_runs WHERE id=$1`, job.RunID).Scan(&raw); err != nil || !json.Valid(raw) {
		t.Fatal("actual workflow metadata not persisted", err)
	}
	assertDispatchNoNativeAuthority(t, f.db, f.workflow.Metadata.Namespace)
}
