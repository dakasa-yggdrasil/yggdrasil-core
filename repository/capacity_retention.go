package repository

import (
	"context"
	"database/sql"
	"fmt"
)

// PruneCapacityEvents removes only expired historical observations. Intent
// state, lease epochs, current and immediately previous generations are never
// deleted. Orphans without an authoritative current intent remain retained.
// Concurrent replicas claim disjoint event rows; one call performs one batch.
func PruneCapacityEvents(ctx context.Context, db *sql.DB, days, batch int) (int64, error) {
	if db == nil || days < 30 || days > 3650 || batch < 1 || batch > 1000 {
		return 0, fmt.Errorf("capacity retention requires a database and bounded days/batch")
	}
	result, err := db.ExecContext(ctx, `
		WITH expired AS MATERIALIZED (
			SELECT e.id
			FROM public.capacity_intent_events e
			JOIN public.capacity_intents i
			  ON i.namespace=e.namespace AND i.environment=e.environment
			 AND i.domain=e.domain AND i.dimension=e.dimension
			WHERE e.recorded_at < clock_timestamp() - ($1::integer * INTERVAL '1 day')
			  AND e.generation < (i.intent->>'generation')::bigint - 1
			ORDER BY e.recorded_at, e.id
			LIMIT $2
			FOR UPDATE OF e SKIP LOCKED
		)
		DELETE FROM public.capacity_intent_events e USING expired x WHERE e.id=x.id`, days, batch)
	if err != nil {
		return 0, fmt.Errorf("capacity event retention: %w", err)
	}
	return result.RowsAffected()
}
