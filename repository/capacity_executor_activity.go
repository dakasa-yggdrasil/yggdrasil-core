package repository

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity/executoractivity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

// ExecutorActivity is called only by the existing protected workflow handler.
func (s CapacityStore) ExecutorActivity(ctx context.Context, policy model.Manifest, operation string, request executoractivity.WorkflowRequest) (executoractivity.WorkflowResult, error) {
	if operation == "capacity.record_executor_activity" && s.ExecutorActivityPrincipal == "" {
		return executoractivity.WorkflowResult{}, ErrCapacityDisabled
	}
	var config executoractivity.ExecutorActivityPolicy
	state, err := s.changeExecutorActivity(ctx, policy, operation == "capacity.initialize_executor_activity", func(state *executoractivity.ExecutorActivityState, p executoractivity.ExecutorActivityPolicy, now time.Time) error {
		config = p
		return executoractivity.ApplyWorkflowOperation(state, p, operation, s.ExecutorActivityPrincipal, request, now)
	})
	if err != nil {
		return executoractivity.WorkflowResult{}, err
	}
	return executoractivity.ResultFor(state, config, state.UpdatedAt), nil
}

// ExecutorActivityTransactions supplies the same pinned authorization and lock to
// an externally hosted reconcile pass. It neither installs a controller nor grants
// access to a provider. Every Change rechecks the current workflow/policy gates.
func (s CapacityStore) ExecutorActivityTransactions(policy model.Manifest) executoractivity.Transactions {
	return executorActivityTransactions{s, policy}
}

type executorActivityTransactions struct {
	store  CapacityStore
	policy model.Manifest
}

func (t executorActivityTransactions) Change(ctx context.Context, change func(*executoractivity.ExecutorActivityState, time.Time) error) (executoractivity.ExecutorActivityState, error) {
	return t.store.changeExecutorActivity(ctx, t.policy, false, func(state *executoractivity.ExecutorActivityState, _ executoractivity.ExecutorActivityPolicy, now time.Time) error {
		return change(state, now)
	})
}
func (s CapacityStore) changeExecutorActivity(ctx context.Context, policy model.Manifest, initialize bool, change func(*executoractivity.ExecutorActivityState, executoractivity.ExecutorActivityPolicy, time.Time) error) (executoractivity.ExecutorActivityState, error) {
	p, err := parseCapacityPolicy(policy)
	if err != nil {
		return executoractivity.ExecutorActivityState{}, err
	}
	b := p.ExecutorActivityBinding
	if !s.ExecutionEnabled || !p.ExecutionEnabled || s.WorkflowID == uuid.Nil || s.ExecutorID == "" || b == nil || s.AdmissionOnly {
		return executoractivity.ExecutorActivityState{}, ErrCapacityDisabled
	}
	key, _ := json.Marshal([]string{policy.Metadata.Namespace, p.Environment, p.Domain, p.Dimension})
	pin, _ := json.Marshal([]string{policy.ID.String(), policy.Checksum, s.WorkflowID.String()})
	binding := fmt.Sprintf("%x", sha256.Sum256(pin))
	config := executoractivity.ExecutorActivityPolicy{LeaseTTL: time.Duration(b.LeaseTTLSeconds) * time.Second, IdleAfter: time.Duration(b.IdleAfterSeconds) * time.Second, MaxObservationAge: time.Duration(b.MaxObservationAgeSeconds) * time.Second, MaxTasks: b.MaxTasks}
	authorize := func(ctx context.Context, tx *sql.Tx) error {
		var checksum string
		var active bool
		if err := tx.QueryRowContext(ctx, `SELECT checksum, active FROM public.manifests WHERE id=$1 AND kind='capacity_policy' AND namespace=$2 AND name=$3 FOR SHARE`, policy.ID, policy.Metadata.Namespace, policy.Metadata.Name).Scan(&checksum, &active); err != nil {
			return err
		}
		if !active || checksum != policy.Checksum {
			return ErrCapacityConflict
		}
		if err := tx.QueryRowContext(ctx, `SELECT active FROM public.manifests WHERE id=$1 AND kind='workflow' AND namespace=$2 AND name=$3 FOR SHARE`, s.WorkflowID, p.Workflow.Namespace, p.Workflow.Name).Scan(&active); err != nil {
			return err
		}
		if !active {
			return ErrCapacityConflict
		}
		return nil
	}
	state, err := executoractivity.RunPostgres(ctx, s.DB, string(key), binding, config, initialize, authorize, func(state *executoractivity.ExecutorActivityState, now time.Time) error {
		return change(state, config, now)
	})
	if err != nil {
		return executoractivity.ExecutorActivityState{}, err
	}
	return state, nil
}
