package executoractivity

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"
)

const maxActivityStateBytes = 2 << 20
const maxActivityRevision = 9007199254740991

// PostgresStore is transaction-scoped. Binding pins the operator policy and
// workflow revision; policy changes must not silently adopt an unfinished stop.
type PostgresStore struct {
	Tx      *sql.Tx
	Binding string
}

func (s PostgresStore) Load(ctx context.Context, scope string) (ExecutorActivityState, error) {
	var revision uint64
	var raw []byte
	err := s.Tx.QueryRowContext(ctx, `SELECT revision, state FROM public.capacity_executor_activity WHERE scope_key=$1 AND binding_sha256=$2 FOR UPDATE`, scope, s.Binding).Scan(&revision, &raw)
	if err != nil {
		return ExecutorActivityState{}, err
	}
	if len(raw) > maxActivityStateBytes {
		return ExecutorActivityState{}, fmt.Errorf("executor activity state exceeds bound")
	}
	var state ExecutorActivityState
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err = d.Decode(&state); err != nil {
		return state, err
	}
	if d.Decode(new(any)) != io.EOF || state.Revision != revision || revision >= maxActivityRevision || state.UpdatedAt.IsZero() || state.Tasks == nil {
		return ExecutorActivityState{}, fmt.Errorf("executor activity state/revision mismatch")
	}
	return state, nil
}

func (s PostgresStore) CompareAndSwap(ctx context.Context, scope string, revision uint64, next ExecutorActivityState) error {
	if revision >= maxActivityRevision-1 || next.Revision != revision+1 {
		return ErrExecutorActivityConflict
	}
	raw, err := json.Marshal(next)
	if err != nil {
		return err
	}
	if len(raw) > maxActivityStateBytes {
		return fmt.Errorf("executor activity state exceeds bound")
	}
	r, err := s.Tx.ExecContext(ctx, `UPDATE public.capacity_executor_activity SET revision=$3, state=$4::jsonb, updated_at=clock_timestamp() WHERE scope_key=$1 AND binding_sha256=$2 AND revision=$5`, scope, s.Binding, int64(next.Revision), string(raw), int64(revision))
	if err != nil {
		return err
	}
	n, err := r.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return ErrExecutorActivityConflict
	}
	return nil
}

// RunPostgres serializes initialization, current authorization, task ingress and
// stop preparation under the same dimension lock used by CapacityStore. It never
// calls a provider inside a transaction. Initialization must be explicitly selected
// by the already-authorized workflow; missing state is otherwise a hard error.
func RunPostgres(ctx context.Context, db *sql.DB, scope, binding string, p ExecutorActivityPolicy, initialize bool, authorize func(context.Context, *sql.Tx) error, change func(*ExecutorActivityState, time.Time) error) (ExecutorActivityState, error) {
	if db == nil || !activityID(scope) || !activityID(binding) || authorize == nil || change == nil {
		return ExecutorActivityState{}, fmt.Errorf("executor activity transaction binding required")
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return ExecutorActivityState{}, err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, scope); err != nil {
		return ExecutorActivityState{}, err
	}
	if err = authorize(ctx, tx); err != nil {
		return ExecutorActivityState{}, err
	}
	var now time.Time
	if err = tx.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		return ExecutorActivityState{}, err
	}
	if initialize {
		initial := ExecutorActivityState{Epoch: 1, UpdatedAt: now, Tasks: map[string]ExecutorTaskLease{}}
		raw, _ := json.Marshal(initial)
		if _, err = tx.ExecContext(ctx, `INSERT INTO public.capacity_executor_activity (scope_key,binding_sha256,revision,state) VALUES ($1,$2,0,$3::jsonb) ON CONFLICT (scope_key) DO NOTHING`, scope, binding, string(raw)); err != nil {
			return ExecutorActivityState{}, err
		}
	}
	store := PostgresStore{Tx: tx, Binding: binding}
	next, err := UpdateExecutorActivity(ctx, store, scope, p, now, func(s *ExecutorActivityState) error { return change(s, now) })
	if err != nil {
		return ExecutorActivityState{}, err
	}
	if err = tx.Commit(); err != nil {
		// Commit may have succeeded. Never return a sendable state on ambiguity.
		return ExecutorActivityState{}, errors.Join(fmt.Errorf("executor activity commit outcome unknown"), err)
	}
	return next, nil
}

// WorkflowRequest is only accepted inside the policy's current protected workflow.
// It supplies observations/demand, never an executor identity or provider action.
type WorkflowRequest struct {
	JobID         string                      `json:"job_id,omitempty"`
	Event         ExecutorActivityEvent       `json:"event"`
	Observation   ExecutorActivityObservation `json:"observation"`
	ReservationID string                      `json:"reservation_id"`
}

func ApplyWorkflowOperation(s *ExecutorActivityState, p ExecutorActivityPolicy, operation, owner string, request WorkflowRequest, now time.Time) error {
	switch operation {
	case "capacity.initialize_executor_activity":
		return nil
	case "capacity.record_executor_activity":
		if request.Event.Owner != "" {
			return fmt.Errorf("executor task owner is workflow-authored")
		}
		e := request.Event
		e.Owner = owner
		if request.JobID != "" && e.Release {
			return fmt.Errorf("release cannot enqueue a job")
		}
		if err := ApplyExecutorActivity(s, p, e, now); err != nil {
			return err
		}
		if request.JobID != "" {
			return QueueJob(s, p, e.TaskID, request.JobID, owner, now)
		}
		return nil
	case "capacity.observe_executor_activity":
		return ObserveExecutorQuiet(s, p, request.Observation, now)
	case "capacity.reserve_executor_stop":
		return ReserveExecutorStop(s, p, request.ReservationID, request.Observation, now)
	case "capacity.prepare_executor_stop":
		return MarkExecutorStopPossibleSend(s, p, request.ReservationID, request.Observation, now)
	default:
		return fmt.Errorf("unsupported executor activity workflow operation")
	}
}
