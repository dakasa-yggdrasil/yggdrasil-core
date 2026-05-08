package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

// ErrProviderStateNotFound is returned when a (collaborator, provider)
// pair has no row in collaborator_provider_state.
var ErrProviderStateNotFound = errors.New("collaborator_provider_state not found")

// UpsertCollaboratorProviderState creates or updates the desired/observed
// state for a (collaborator, provider) pair. error_count is preserved
// across upserts (only MarkProviderStateError increments it; only
// MarkProviderStateReconciled resets it).
func UpsertCollaboratorProviderState(ctx context.Context, db *sql.DB, req model.UpsertProviderStateRequest) (model.CollaboratorProviderState, error) {
	if req.CollaboratorID == uuid.Nil {
		return model.CollaboratorProviderState{}, fmt.Errorf("collaborator_id is required")
	}
	if strings.TrimSpace(req.Provider) == "" {
		return model.CollaboratorProviderState{}, fmt.Errorf("provider is required")
	}

	desired, err := json.Marshal(req.DesiredState)
	if err != nil {
		return model.CollaboratorProviderState{}, fmt.Errorf("marshal desired_state: %w", err)
	}
	if len(req.DesiredState) == 0 {
		desired = []byte(`{}`)
	}

	var observedJSON any = nil
	if req.ObservedState != nil {
		bs, err := json.Marshal(*req.ObservedState)
		if err != nil {
			return model.CollaboratorProviderState{}, fmt.Errorf("marshal observed_state: %w", err)
		}
		observedJSON = bs
	}

	pendingAction := sql.NullString{}
	if pa := strings.TrimSpace(req.PendingAction); pa != "" {
		pendingAction = sql.NullString{String: pa, Valid: true}
	}

	row := db.QueryRowContext(ctx, `
		INSERT INTO public.collaborator_provider_state (
			collaborator_id, provider, external_id, desired_state, observed_state, pending_action
		) VALUES ($1, $2, NULLIF($3, ''), $4, $5, $6)
		ON CONFLICT (collaborator_id, provider) DO UPDATE SET
			external_id     = COALESCE(EXCLUDED.external_id, public.collaborator_provider_state.external_id),
			desired_state   = EXCLUDED.desired_state,
			observed_state  = COALESCE(EXCLUDED.observed_state, public.collaborator_provider_state.observed_state),
			pending_action  = EXCLUDED.pending_action,
			updated_at      = NOW()
		RETURNING collaborator_id, provider, external_id, desired_state, observed_state,
		         last_reconciled_at, last_drift_detected_at, pending_action,
		         error_count, last_error, created_at, updated_at
	`, req.CollaboratorID, req.Provider, req.ExternalID, desired, observedJSON, pendingAction)

	return scanProviderState(row)
}

// ListProviderStateByCollaborator returns every provider state row
// for one collaborator, ordered by provider asc.
func ListProviderStateByCollaborator(ctx context.Context, db *sql.DB, collaboratorID uuid.UUID) ([]model.CollaboratorProviderState, error) {
	if collaboratorID == uuid.Nil {
		return nil, fmt.Errorf("collaborator_id is required")
	}
	rows, err := db.QueryContext(ctx, `
		SELECT collaborator_id, provider, external_id, desired_state, observed_state,
		       last_reconciled_at, last_drift_detected_at, pending_action,
		       error_count, last_error, created_at, updated_at
		FROM public.collaborator_provider_state
		WHERE collaborator_id = $1
		ORDER BY provider ASC
	`, collaboratorID)
	if err != nil {
		return nil, fmt.Errorf("query collaborator_provider_state: %w", err)
	}
	defer func() { _ = rows.Close() }()

	out := make([]model.CollaboratorProviderState, 0)
	for rows.Next() {
		state, err := scanProviderState(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, state)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate collaborator_provider_state: %w", err)
	}
	return out, nil
}

// MarkProviderStateError increments error_count and records the
// last_error message. Used when reconcile or apply step fails for
// this (collaborator, provider) pair.
func MarkProviderStateError(ctx context.Context, db *sql.DB, collaboratorID uuid.UUID, provider, errorMsg string) error {
	res, err := db.ExecContext(ctx, `
		UPDATE public.collaborator_provider_state
		SET error_count = error_count + 1,
		    last_error  = $3,
		    updated_at  = NOW()
		WHERE collaborator_id = $1 AND provider = $2
	`, collaboratorID, provider, errorMsg)
	if err != nil {
		return fmt.Errorf("mark provider state error: %w", err)
	}
	rows, _ := res.RowsAffected()
	if rows == 0 {
		return ErrProviderStateNotFound
	}
	return nil
}

// MarkProviderStateReconciled records a successful reconcile pass:
// resets error_count, records last_reconciled_at, and clears
// pending_action. driftDetected toggles last_drift_detected_at when a
// diff was actually applied.
func MarkProviderStateReconciled(ctx context.Context, db *sql.DB, collaboratorID uuid.UUID, provider string, driftDetected bool) error {
	q := `
		UPDATE public.collaborator_provider_state
		SET last_reconciled_at = NOW(),
		    error_count        = 0,
		    last_error         = NULL,
		    pending_action     = NULL,
		    updated_at         = NOW()`
	if driftDetected {
		q += `, last_drift_detected_at = NOW()`
	}
	q += ` WHERE collaborator_id = $1 AND provider = $2`

	res, err := db.ExecContext(ctx, q, collaboratorID, provider)
	if err != nil {
		return fmt.Errorf("mark provider state reconciled: %w", err)
	}
	rows, _ := res.RowsAffected()
	if rows == 0 {
		return ErrProviderStateNotFound
	}
	return nil
}

type providerStateScanner interface {
	Scan(dest ...any) error
}

func scanProviderState(s providerStateScanner) (model.CollaboratorProviderState, error) {
	var state model.CollaboratorProviderState
	var (
		externalID    sql.NullString
		desired       []byte
		observed      []byte
		lastRecon     sql.NullTime
		lastDrift     sql.NullTime
		pendingAction sql.NullString
		lastError     sql.NullString
	)
	if err := s.Scan(
		&state.CollaboratorID,
		&state.Provider,
		&externalID,
		&desired,
		&observed,
		&lastRecon,
		&lastDrift,
		&pendingAction,
		&state.ErrorCount,
		&lastError,
		&state.CreatedAt,
		&state.UpdatedAt,
	); err != nil {
		return model.CollaboratorProviderState{}, fmt.Errorf("scan collaborator_provider_state: %w", err)
	}
	if externalID.Valid {
		state.ExternalID = externalID.String
	}
	if len(desired) > 0 {
		_ = json.Unmarshal(desired, &state.DesiredState)
	} else {
		state.DesiredState = map[string]any{}
	}
	if len(observed) > 0 {
		_ = json.Unmarshal(observed, &state.ObservedState)
	}
	if lastRecon.Valid {
		state.LastReconciledAt = &lastRecon.Time
	}
	if lastDrift.Valid {
		state.LastDriftDetectedAt = &lastDrift.Time
	}
	if pendingAction.Valid {
		state.PendingAction = pendingAction.String
	}
	if lastError.Valid {
		state.LastError = lastError.String
	}
	return state, nil
}
