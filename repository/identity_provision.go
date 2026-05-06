package repository

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

// CreateCollaboratorTx is the transaction-aware variant of CreateCollaborator.
// It is used by auto-provision flows that need to atomically insert one
// collaborator and one team membership in the same transaction.
//
// Behavior matches CreateCollaborator: same validation, same INSERT, same
// scan path. The only difference is the receiver (*sql.Tx vs *sql.DB).
func CreateCollaboratorTx(ctx context.Context, tx *sql.Tx, req model.CreateCollaboratorRequest) (model.Collaborator, error) {
	slug := normalizeSlug(req.Slug)
	if slug == "" {
		return model.Collaborator{}, fmt.Errorf("collaborator slug is required")
	}

	displayName := strings.TrimSpace(req.DisplayName)
	if displayName == "" {
		return model.Collaborator{}, fmt.Errorf("collaborator display_name is required")
	}

	personalData, err := marshalJSONObject(req.PersonalData)
	if err != nil {
		return model.Collaborator{}, err
	}
	employmentData, err := marshalJSONObject(req.EmploymentData)
	if err != nil {
		return model.Collaborator{}, err
	}
	thirdPartyIdentities, err := marshalJSONObject(req.ThirdPartyIdentities)
	if err != nil {
		return model.Collaborator{}, err
	}
	traits, err := marshalJSONObject(req.Traits)
	if err != nil {
		return model.Collaborator{}, err
	}
	metadata, err := marshalJSONObject(req.Metadata)
	if err != nil {
		return model.Collaborator{}, err
	}

	row := tx.QueryRowContext(
		ctx,
		`
			INSERT INTO public.collaborators (
				slug,
				status,
				display_name,
				primary_email,
				personal_data,
				employment_data,
				third_party_identities,
				traits,
				metadata
			) VALUES (
				$1,
				$2,
				$3,
				$4,
				$5::jsonb,
				$6::jsonb,
				$7::jsonb,
				$8::jsonb,
				$9::jsonb
			)
			RETURNING
				id,
				slug,
				status,
				display_name,
				primary_email,
				manager_id,
				primary_team_id,
				personal_data,
				employment_data,
				third_party_identities,
				traits,
				metadata,
				created_at,
				updated_at
		`,
		slug,
		normalizeStatus(req.Status),
		displayName,
		strings.TrimSpace(req.PrimaryEmail),
		personalData,
		employmentData,
		thirdPartyIdentities,
		traits,
		metadata,
	)

	return scanCollaborator(row)
}

// AddCollaboratorToTeamBySlugTx inserts a team_memberships row linking the
// given collaborator to the team identified by slug. Source records the
// reason for the membership (e.g. "auto_provision"). Returns ErrTeamNotFound
// when the team slug does not resolve.
//
// Idempotent: ON CONFLICT (team_id, collaborator_id) DO NOTHING.
func AddCollaboratorToTeamBySlugTx(ctx context.Context, tx *sql.Tx, collaboratorID uuid.UUID, teamSlug, source string) error {
	teamSlug = normalizeSlug(teamSlug)
	if teamSlug == "" {
		return fmt.Errorf("team slug is required")
	}
	if collaboratorID == uuid.Nil {
		return fmt.Errorf("collaborator id is required")
	}

	var teamID uuid.UUID
	err := tx.QueryRowContext(ctx,
		`SELECT id FROM public.teams WHERE slug = $1`, teamSlug,
	).Scan(&teamID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrTeamNotFound
		}
		return fmt.Errorf("lookup team %q: %w", teamSlug, err)
	}

	_, err = tx.ExecContext(ctx,
		`
			INSERT INTO public.team_memberships (
				team_id,
				collaborator_id,
				role,
				active,
				source
			) VALUES ($1, $2, $3, $4, $5)
			ON CONFLICT (team_id, collaborator_id) DO NOTHING
		`,
		teamID,
		collaboratorID,
		normalizeMembershipRole(""),
		true,
		normalizeMembershipSource(source),
	)
	if err != nil {
		return fmt.Errorf("insert team_memberships: %w", err)
	}
	return nil
}
