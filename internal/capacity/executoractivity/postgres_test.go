package executoractivity

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
)

func activitySQLStart(t *testing.T) (*sql.DB, sqlmock.Sqlmock) {
	t.Helper()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Error(err)
		}
		db.Close()
	})
	mock.ExpectBegin()
	mock.ExpectExec(`SELECT pg_advisory_xact_lock`).WithArgs("scope").WillReturnResult(sqlmock.NewResult(0, 1))
	return db, mock
}
func activitySQLRows(mock sqlmock.Sqlmock, s ExecutorActivityState) {
	raw, _ := json.Marshal(s)
	mock.ExpectQuery(`SELECT revision, state FROM public.capacity_executor_activity`).WithArgs("scope", strings.Repeat("a", 64)).WillReturnRows(sqlmock.NewRows([]string{"revision", "state"}).AddRow(int64(s.Revision), raw))
}
func activitySQLClock(mock sqlmock.Sqlmock, now time.Time) {
	mock.ExpectQuery(`SELECT clock_timestamp`).WillReturnRows(sqlmock.NewRows([]string{"clock_timestamp"}).AddRow(now))
}
func activitySQLAuthorize(context.Context, *sql.Tx) error { return nil }

func TestExecutorPostgresInitializationAndTaskUseServerClock(t *testing.T) {
	db, mock := activitySQLStart(t)
	now := activityTestNow
	activitySQLClock(mock, now)
	mock.ExpectExec(`INSERT INTO public.capacity_executor_activity`).WithArgs("scope", strings.Repeat("a", 64), sqlmock.AnyArg()).WillReturnResult(sqlmock.NewResult(0, 1))
	activitySQLRows(mock, ExecutorActivityState{Tasks: map[string]ExecutorTaskLease{}, UpdatedAt: now})
	mock.ExpectExec(`UPDATE public.capacity_executor_activity`).WithArgs("scope", strings.Repeat("a", 64), int64(1), sqlmock.AnyArg(), int64(0)).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()
	s, err := RunPostgres(context.Background(), db, "scope", strings.Repeat("a", 64), activityTestPolicy, true, activitySQLAuthorize, func(s *ExecutorActivityState, at time.Time) error {
		return ApplyWorkflowOperation(s, activityTestPolicy, "capacity.record_executor_activity", "workflow-id", WorkflowRequest{Event: ExecutorActivityEvent{TaskID: "run", Sequence: 1}}, at)
	})
	if err != nil || s.Revision != 1 || !s.Tasks["run"].ExpiresAt.Equal(now.Add(activityTestPolicy.LeaseTTL)) || s.Tasks["run"].Owner != "workflow-id" {
		t.Fatal(s, err)
	}
}

func TestExecutorPostgresMissingStateCannotBecomeIdle(t *testing.T) {
	db, mock := activitySQLStart(t)
	activitySQLClock(mock, activityTestNow)
	mock.ExpectQuery(`SELECT revision, state`).WillReturnRows(sqlmock.NewRows([]string{"revision", "state"}))
	mock.ExpectRollback()
	called := false
	_, err := RunPostgres(context.Background(), db, "scope", strings.Repeat("a", 64), activityTestPolicy, false, activitySQLAuthorize, func(*ExecutorActivityState, time.Time) error { called = true; return nil })
	if !errors.Is(err, sql.ErrNoRows) || called {
		t.Fatal("missing row reached reducer", err)
	}
}

func TestExecutorPostgresRevokedAuthorizationRollsBackBeforeClock(t *testing.T) {
	db, mock := activitySQLStart(t)
	mock.ExpectRollback()
	denied := errors.New("current workflow revoked")
	_, err := RunPostgres(context.Background(), db, "scope", strings.Repeat("a", 64), activityTestPolicy, true, func(context.Context, *sql.Tx) error { return denied }, func(*ExecutorActivityState, time.Time) error { t.Fatal("unauthorized reducer"); return nil })
	if !errors.Is(err, denied) {
		t.Fatal(err)
	}
}

func TestExecutorPostgresCASConflictDoesNotReturnSendableState(t *testing.T) {
	db, mock := activitySQLStart(t)
	activitySQLClock(mock, activityTestNow)
	activitySQLRows(mock, ExecutorActivityState{Revision: 4, Tasks: map[string]ExecutorTaskLease{}, UpdatedAt: activityTestNow})
	mock.ExpectExec(`UPDATE public.capacity_executor_activity`).WithArgs("scope", strings.Repeat("a", 64), int64(5), sqlmock.AnyArg(), int64(4)).WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectRollback()
	s, err := RunPostgres(context.Background(), db, "scope", strings.Repeat("a", 64), activityTestPolicy, false, activitySQLAuthorize, func(*ExecutorActivityState, time.Time) error { return nil })
	if !errors.Is(err, ErrExecutorActivityConflict) || s.Revision != 0 {
		t.Fatal(s, err)
	}
}

func TestExecutorPostgresCommitAmbiguityNeverReturnsStopAuthority(t *testing.T) {
	f, now := activityDraining(t)
	db, mock := activitySQLStart(t)
	activitySQLClock(mock, now)
	activitySQLRows(mock, f.s)
	mock.ExpectExec(`UPDATE public.capacity_executor_activity`).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit().WillReturnError(errors.New("lost commit acknowledgement"))
	o := quietObservation(now)
	o.Epoch = f.s.Epoch
	o.AdmissionClosed = true
	s, err := RunPostgres(context.Background(), db, "scope", strings.Repeat("a", 64), activityTestPolicy, false, activitySQLAuthorize, func(s *ExecutorActivityState, at time.Time) error {
		return MarkExecutorStopPossibleSend(s, activityTestPolicy, "stop-1", o, at)
	})
	if err == nil || s.Stop != nil {
		t.Fatal("ambiguous commit yielded send state", s, err)
	}
}

func TestExecutorPostgresRestartQueuesDemandBehindSentStop(t *testing.T) {
	f, now := activityDraining(t)
	o := quietObservation(now)
	o.Epoch = f.s.Epoch
	o.AdmissionClosed = true
	activityUpdate(t, f, now, func(s *ExecutorActivityState) error {
		return MarkExecutorStopPossibleSend(s, activityTestPolicy, "stop-1", o, now)
	})
	db, mock := activitySQLStart(t)
	now = now.Add(time.Second)
	activitySQLClock(mock, now)
	activitySQLRows(mock, f.s)
	mock.ExpectExec(`UPDATE public.capacity_executor_activity`).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()
	s, err := RunPostgres(context.Background(), db, "scope", strings.Repeat("a", 64), activityTestPolicy, false, activitySQLAuthorize, func(s *ExecutorActivityState, at time.Time) error {
		return ApplyExecutorActivity(s, activityTestPolicy, activityEvent("new-run", 1, false), at)
	})
	if err != nil || s.Stop == nil || s.Stop.Stage != "possible_send" || ExecutorActiveTasks(s, now) != 1 || ExecutorDemandPending(s, now) {
		t.Fatal(s, err)
	}
}

func TestExecutorWorkflowRejectsInputAuthorshipAndExpiredHeartbeat(t *testing.T) {
	s := ExecutorActivityState{}
	if err := ApplyWorkflowOperation(&s, activityTestPolicy, "capacity.record_executor_activity", "workflow", WorkflowRequest{Event: activityEvent("run", 1, false)}, activityTestNow); err == nil {
		t.Fatal("caller supplied owner")
	}
	r := WorkflowRequest{Event: ExecutorActivityEvent{TaskID: "run", Sequence: 1}}
	if err := ApplyWorkflowOperation(&s, activityTestPolicy, "capacity.record_executor_activity", "workflow", r, activityTestNow); err != nil {
		t.Fatal(err)
	}
	r.Event.Sequence = 2
	if err := ApplyWorkflowOperation(&s, activityTestPolicy, "capacity.record_executor_activity", "workflow", r, activityTestNow.Add(time.Minute)); err == nil {
		t.Fatal("late heartbeat renewed expired run")
	}
}

func TestExecutorPostgresCorruptStateFailsBeforeChange(t *testing.T) {
	db, mock := activitySQLStart(t)
	activitySQLClock(mock, activityTestNow)
	mock.ExpectQuery(`SELECT revision, state`).WillReturnRows(sqlmock.NewRows([]string{"revision", "state"}).AddRow(0, []byte(`{}`)))
	mock.ExpectRollback()
	_, err := RunPostgres(context.Background(), db, "scope", strings.Repeat("a", 64), activityTestPolicy, false, activitySQLAuthorize, func(*ExecutorActivityState, time.Time) error { t.Fatal("corrupt state reached reducer"); return nil })
	if err == nil {
		t.Fatal("corrupt state accepted")
	}
}

func TestExecutorWorkflowRecoveryDeadlineEscalatesWithoutClearingStop(t *testing.T) {
	f, now := activityDraining(t)
	r := ResultFor(f.s, activityTestPolicy, now.Add(activityTestPolicy.IdleAfter))
	if !r.RecoveryRequired || r.RecoveryDeadline == nil || r.Stop == nil || r.Stop.Stage != "draining" {
		t.Fatal(r)
	}
	if f.s.Stop == nil {
		t.Fatal("escalation cleared uncertainty")
	}
	raw, _ := json.Marshal(r)
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		t.Fatal(err)
	}
	if _, exists := fields["tasks"]; exists || strings.Contains(string(raw), "\"owner\"") {
		t.Fatal("workflow result leaked task roster", string(raw))
	}
}
