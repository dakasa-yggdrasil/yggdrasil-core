package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

// CloseUnredeemed releases only a server-proven unsent reservation after its
// immutable original command deadline. It never interprets a transport timeout
// or an expired lease as evidence that a possible provider send had no effect.
// The same mutation/Attempt locks arbitrate against the original Redeem.
func (s CapacityNativeWorkerCommandStore) CloseUnredeemed(ctx context.Context, policy model.Manifest, id uuid.UUID) (model.CapacityNativeWorkerAttempt, error) {
	var out model.CapacityNativeWorkerAttempt
	if !s.Workers.Enabled || !s.Workers.Capacity.ExecutionEnabled || s.Workers.Capacity.DB == nil {
		return out, ErrCapacityDisabled
	}
	err := s.Workers.tx(ctx, policy, func(tx *sql.Tx, _ model.CapacityPolicySpec, now time.Time) error {
		a, _, err := nativeAttemptLoadTx(ctx, tx, policy, id)
		if err != nil {
			return err
		}
		var raw []byte
		if err = tx.QueryRowContext(ctx, `SELECT record FROM public.capacity_native_worker_command_contexts WHERE attempt_id=$1`, id).Scan(&raw); err != nil {
			return err
		}
		var command nativeWorkerCommandContext
		if json.Unmarshal(raw, &command) != nil || command.AttemptID != a.ID || command.PolicyID != policy.ID ||
			command.PolicyChecksum != policy.Checksum || command.Namespace != policy.Metadata.Namespace ||
			command.Generation != a.Generation || command.FencingToken != a.FencingToken ||
			!capacity.NativeWorkerSameExecution(command.Execution, a.Execution) || command.ExpiresAt.IsZero() || command.ExpiresAt.After(now) {
			return ErrCapacityConflict
		}
		if a.State == "absent" {
			var matches bool
			if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM public.capacity_native_worker_unsent_closures WHERE attempt_id=$1 AND command_context=$2::jsonb AND from_revision=$3)`, id, raw, a.Revision-1).Scan(&matches); err != nil || !matches {
				return ErrCapacityConflict
			}
			out = a
			return nil
		}
		if a.State != "reserved" || a.Revision != 1 || a.Physical != nil || a.BirthSHA256 != "" || a.NodeUID != "" {
			return ErrCapacityConflict
		}
		var captured bool
		if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM public.capacity_native_worker_original_returns WHERE attempt_id=$1)`, id).Scan(&captured); err != nil || captured {
			return ErrCapacityConflict
		}
		// The immutable closure is committed in the same transaction as state and
		// event history. Its SQL guard independently rechecks the unsent facts.
		if _, err = tx.ExecContext(ctx, `INSERT INTO public.capacity_native_worker_unsent_closures(attempt_id,policy_id,namespace,from_revision,command_context,closed_at) VALUES($1,$2,$3,$4,$5,$6)`, id, policy.ID, policy.Metadata.Namespace, a.Revision, raw, now); err != nil {
			return err
		}
		a.State, a.Revision, a.UpdatedAt = "absent", a.Revision+1, now
		if err = nativeAttemptWriteTx(ctx, tx, a, nil, false, nil); err != nil {
			return err
		}
		out = a
		return nil
	})
	if err != nil {
		return model.CapacityNativeWorkerAttempt{}, err
	}
	return out, nil
}
