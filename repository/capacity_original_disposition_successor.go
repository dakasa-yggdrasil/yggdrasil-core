package repository

import (
	"context"
	"database/sql"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

// Disposition closes only its historical permission. No old decision, fence or
// integration revision may use it to repeat a create. Logical scope and slot
// remain stable across an observer/adapter metadata version upgrade.
func requireOriginalDispositionSuccessorTx(ctx context.Context, tx *sql.Tx, namespace string, p model.CapacityPolicySpec, b model.CapacityMutationBinding, slot int, generation, fence int64) error {
	var previousGeneration, previousFence int64
	err := tx.QueryRowContext(ctx, `SELECT COALESCE(max(d.closed_generation),0),COALESCE(max(d.closed_fencing_token),0) FROM public.capacity_original_create_dispositions d JOIN public.capacity_mutation_grants g ON g.id=d.grant_id AND g.original_disposition_id=d.id WHERE g.namespace=$1 AND g.environment=$2 AND g.domain=$3 AND g.dimension=$4 AND g.profile_name=$5 AND g.slot=$6`, namespace, p.Environment, p.Domain, p.Dimension, b.ProfileName, slot).Scan(&previousGeneration, &previousFence)
	if err != nil {
		return err
	}
	if generation <= previousGeneration || fence <= previousFence {
		return ErrCapacityConflict
	}
	return nil
}
