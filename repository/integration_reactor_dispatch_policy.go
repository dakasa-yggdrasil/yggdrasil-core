package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
)

var ErrIntegrationReactorPolicyInstanceNotFound = errors.New("active integration instance not found")
var ErrIntegrationReactorPolicyRevisionConflict = errors.New("reactor dispatch policy revision conflict")

// IntegrationReactorDispatchPolicy is operator-owned control state for one
// logical integration instance. It is intentionally independent of manifest
// versions and the adapter's integration_type action catalog.
type IntegrationReactorDispatchPolicy struct {
	Namespace        string     `json:"namespace"`
	Name             string     `json:"name"`
	PausedEventTypes []string   `json:"paused_event_types"`
	Revision         int64      `json:"revision"`
	UpdatedAt        *time.Time `json:"updated_at,omitempty"`
}

// GetIntegrationReactorDispatchPolicy returns an empty pause set when an active
// instance exists but no operator policy has been written.
func GetIntegrationReactorDispatchPolicy(ctx context.Context, db *sql.DB, namespace, name string) (IntegrationReactorDispatchPolicy, error) {
	var p IntegrationReactorDispatchPolicy
	var updatedAt sql.NullTime
	err := db.QueryRowContext(ctx, `
		SELECT ii.namespace, ii.name,
		       COALESCE(p.paused_event_types, ARRAY[]::text[]),
		       COALESCE(p.revision, 0), p.updated_at
		FROM public.manifests ii
		LEFT JOIN public.integration_reactor_dispatch_policies p
		  ON p.namespace = ii.namespace AND p.name = ii.name
		WHERE ii.kind = 'integration_instance' AND ii.active = TRUE
		  AND ii.namespace = $1 AND ii.name = $2
	`, namespace, name).Scan(&p.Namespace, &p.Name, pq.Array(&p.PausedEventTypes), &p.Revision, &updatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return IntegrationReactorDispatchPolicy{}, ErrIntegrationReactorPolicyInstanceNotFound
	}
	if err != nil {
		return IntegrationReactorDispatchPolicy{}, fmt.Errorf("get reactor dispatch policy: %w", err)
	}
	if p.PausedEventTypes == nil {
		p.PausedEventTypes = []string{}
	}
	if updatedAt.Valid {
		p.UpdatedAt = &updatedAt.Time
	}
	return p, nil
}

// ReplaceIntegrationReactorDispatchPolicy atomically replaces the exact pause
// set. The active manifest row is locked so a concurrent logical delete cannot
// leave a newly written policy on an already deleted instance.
func ReplaceIntegrationReactorDispatchPolicy(ctx context.Context, db *sql.DB, namespace, name string, paused []string, expectedRevision int64, actorID uuid.UUID) (IntegrationReactorDispatchPolicy, error) {
	if actorID == uuid.Nil {
		return IntegrationReactorDispatchPolicy{}, fmt.Errorf("verified operator identity is required")
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return IntegrationReactorDispatchPolicy{}, fmt.Errorf("begin reactor policy: %w", err)
	}
	defer tx.Rollback()

	var activeID uuid.UUID
	if err := tx.QueryRowContext(ctx, `
		SELECT id FROM public.manifests
		WHERE kind = 'integration_instance' AND active = TRUE
		  AND namespace = $1 AND name = $2
		FOR UPDATE
	`, namespace, name).Scan(&activeID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return IntegrationReactorDispatchPolicy{}, ErrIntegrationReactorPolicyInstanceNotFound
		}
		return IntegrationReactorDispatchPolicy{}, fmt.Errorf("resolve reactor policy instance: %w", err)
	}
	var currentRevision int64
	err = tx.QueryRowContext(ctx, `
		SELECT revision FROM public.integration_reactor_dispatch_policies
		WHERE namespace = $1 AND name = $2
	`, namespace, name).Scan(&currentRevision)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return IntegrationReactorDispatchPolicy{}, fmt.Errorf("load reactor policy revision: %w", err)
	}
	if currentRevision != expectedRevision {
		return IntegrationReactorDispatchPolicy{}, ErrIntegrationReactorPolicyRevisionConflict
	}

	var p IntegrationReactorDispatchPolicy
	var updatedAt time.Time
	if currentRevision == 0 {
		err = tx.QueryRowContext(ctx, `
			INSERT INTO public.integration_reactor_dispatch_policies
			  (namespace, name, paused_event_types, revision)
			VALUES ($1, $2, $3, 1)
			RETURNING namespace, name, paused_event_types, revision, updated_at
		`, namespace, name, pq.Array(paused)).Scan(&p.Namespace, &p.Name, pq.Array(&p.PausedEventTypes), &p.Revision, &updatedAt)
	} else {
		err = tx.QueryRowContext(ctx, `
			UPDATE public.integration_reactor_dispatch_policies
			SET paused_event_types = $3, revision = revision + 1
			WHERE namespace = $1 AND name = $2 AND revision = $4
			RETURNING namespace, name, paused_event_types, revision, updated_at
		`, namespace, name, pq.Array(paused), expectedRevision).Scan(&p.Namespace, &p.Name, pq.Array(&p.PausedEventTypes), &p.Revision, &updatedAt)
	}
	if errors.Is(err, sql.ErrNoRows) {
		return IntegrationReactorDispatchPolicy{}, ErrIntegrationReactorPolicyRevisionConflict
	}
	if err != nil {
		return IntegrationReactorDispatchPolicy{}, fmt.Errorf("replace reactor policy: %w", err)
	}
	p.UpdatedAt = &updatedAt
	auditMetadata, err := json.Marshal(map[string]any{
		"expected_revision":  expectedRevision,
		"revision":           p.Revision,
		"paused_event_types": p.PausedEventTypes,
	})
	if err != nil {
		return IntegrationReactorDispatchPolicy{}, fmt.Errorf("marshal reactor policy audit: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO public.audit_events
		  (actor, actor_collaborator_id, action, resource_kind, resource_id,
		   outcome, result_status, metadata)
		VALUES ($1, $2, 'integration_instance.reactor_dispatch.replace',
		        'integration_instance', $3, 'success', 'success', $4::jsonb)
	`, "user:"+actorID.String(), actorID, namespace+"/"+name, auditMetadata); err != nil {
		return IntegrationReactorDispatchPolicy{}, fmt.Errorf("audit reactor policy replacement: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return IntegrationReactorDispatchPolicy{}, fmt.Errorf("commit reactor policy: %w", err)
	}
	if p.PausedEventTypes == nil {
		p.PausedEventTypes = []string{}
	}
	return p, nil
}

// ReactionDispatchAllowed rechecks a claimed reaction immediately before the
// adapter RPC. A missing active instance fails closed. DB errors are returned
// so callers do not mistake an unavailable policy store for an empty policy.
func ReactionDispatchAllowed(ctx context.Context, db *sql.DB, reactionID uuid.UUID, attempt int) (uuid.UUID, bool, error) {
	var activeID uuid.UUID
	var allowed bool
	err := db.QueryRowContext(ctx, `
		SELECT active_ii.id,
		       NOT (r.event_type = ANY(COALESCE(p.paused_event_types, ARRAY[]::text[])))
		FROM public.integration_event_reactions r
		JOIN public.manifests old_ii
		  ON old_ii.id = r.integration_instance_id
		 AND old_ii.kind = 'integration_instance'
		JOIN public.manifests active_ii
		  ON active_ii.kind = old_ii.kind
		 AND active_ii.namespace = old_ii.namespace
		 AND active_ii.name = old_ii.name
		 AND active_ii.active = TRUE
		LEFT JOIN public.integration_reactor_dispatch_policies p
		  ON p.namespace = active_ii.namespace AND p.name = active_ii.name
		WHERE r.id = $1 AND r.status = 'in_progress' AND r.attempt = $2
	`, reactionID, attempt).Scan(&activeID, &allowed)
	if errors.Is(err, sql.ErrNoRows) {
		return uuid.Nil, false, nil
	}
	if err != nil {
		return uuid.Nil, false, fmt.Errorf("recheck reaction dispatch policy: %w", err)
	}
	return activeID, allowed, nil
}
