package teamreconcile

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/google/uuid"
)

// UnprovisionedPair represents (team, integration_instance) pairs that
// have no entry in team_provisioning_log despite both being active and
// the integration_type declaring an `on team.created` reactor.
type UnprovisionedPair struct {
	TeamID                uuid.UUID
	IntegrationInstanceID uuid.UUID
}

// ListUnprovisionedPairs walks every active team across every active
// integration_instance whose integration_type declares a reactor on
// team.created, and returns those without a matching team_provisioning_log
// row. This is the "gap" set the reconcile cron will re-emit team.created
// for.
//
// Anti-join via LEFT JOIN + WHERE log.id IS NULL. Same shape as the SQL
// in internal/manifestsync.
//
// Note: teams table uses status='active' for active teams (no deleted_at column).
func ListUnprovisionedPairs(ctx context.Context, db *sql.DB) ([]UnprovisionedPair, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT t.id AS team_id, ii.id AS instance_id
		FROM teams t
		CROSS JOIN manifests ii
		JOIN manifests it
		  ON it.kind = 'integration_type'
		  AND it.namespace = (ii.spec->'type_ref'->>'namespace')
		  AND it.name = (ii.spec->'type_ref'->>'name')
		  AND it.active = true
		LEFT JOIN team_provisioning_log tpl
		  ON tpl.team_id = t.id
		  AND tpl.integration_instance_id = ii.id
		LEFT JOIN public.integration_reactor_dispatch_policies p
		  ON p.namespace = ii.namespace AND p.name = ii.name
		WHERE t.status = 'active'
		  AND ii.kind = 'integration_instance'
		  AND ii.active = true
		  AND NOT ('team.created' = ANY(COALESCE(p.paused_event_types, ARRAY[]::text[])))
		  AND EXISTS (
		    SELECT 1 FROM jsonb_array_elements(COALESCE(it.spec->'reactors','[]'::jsonb)) r
		    WHERE r->>'event_type' = 'team.created'
		  )
		  AND tpl.id IS NULL
		  AND NOT EXISTS (
		    SELECT 1
		    FROM public.event_log e
		    JOIN public.integration_event_reactions reaction ON reaction.event_id = e.event_id
		    JOIN public.manifests reaction_ii ON reaction_ii.id = reaction.integration_instance_id
		    WHERE e.type = 'team.created'
		      AND e.aggregate_type = 'team' AND e.aggregate_id = t.id::text
		      AND reaction.event_type = 'team.created'
		      AND reaction.status IN ('pending', 'failed', 'in_progress')
		      AND reaction_ii.kind = 'integration_instance'
		      AND reaction_ii.namespace = ii.namespace AND reaction_ii.name = ii.name
		  )
	`)
	if err != nil {
		return nil, fmt.Errorf("list unprovisioned pairs: %w", err)
	}
	defer rows.Close()

	var out []UnprovisionedPair
	for rows.Next() {
		var p UnprovisionedPair
		if err := rows.Scan(&p.TeamID, &p.IntegrationInstanceID); err != nil {
			return nil, fmt.Errorf("scan: %w", err)
		}
		out = append(out, p)
	}
	return out, rows.Err()
}
