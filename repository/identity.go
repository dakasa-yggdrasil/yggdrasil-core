package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/collaboratorstate"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
	"github.com/lib/pq"
)

var (
	ErrCollaboratorNotFound                = errors.New("collaborator not found")
	ErrTeamNotFound                        = errors.New("team not found")
	ErrInvalidCollaboratorStatusTransition = errors.New("invalid collaborator status transition")
	// ErrConcurrentUpdate is returned by UpdateCollaborator when the row's
	// version column changed between the initial load and the UPDATE — i.e.,
	// another writer (HTTP PATCH, status_clock worker, lifecycle endpoint)
	// won the race. Callers should re-fetch and retry, or surface a 409.
	ErrConcurrentUpdate = errors.New("concurrent update detected; re-fetch and retry")
)

// CreateCollaborator stores one collaborator record and, in the same
// transaction, inserts a matching auth_identities row so that
// /auth/passwords/setup can always UPDATE an existing row (the silent-zero-rows
// bug is avoided).
//
// Username for auth_identities is LOWER(TRIM(primary_email)); falls back to
// slug when primary_email is empty. If two collaborators share the same email
// address the INSERT will hit the UNIQUE constraint on auth_identities.username
// (CITEXT) and return an error — callers must ensure emails are unique.
func CreateCollaborator(ctx context.Context, db *sql.DB, req model.CreateCollaboratorRequest) (model.Collaborator, error) {
	slug := normalizeSlug(req.Slug)
	if slug == "" {
		return model.Collaborator{}, fmt.Errorf("collaborator slug is required")
	}

	displayName := strings.TrimSpace(req.DisplayName)
	if displayName == "" {
		return model.Collaborator{}, fmt.Errorf("collaborator display_name is required")
	}

	managerID, err := resolveOptionalCollaboratorID(ctx, db, req.ManagerID)
	if err != nil {
		return model.Collaborator{}, err
	}

	primaryTeamID, err := resolveOptionalTeamID(ctx, db, req.PrimaryTeamID)
	if err != nil {
		return model.Collaborator{}, err
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

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return model.Collaborator{}, fmt.Errorf("begin create_collaborator tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	row := tx.QueryRowContext(
		ctx,
		`
			INSERT INTO public.collaborators (
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
				metadata
			) VALUES (
				$1,
				$2,
				$3,
				$4,
				$5,
				$6,
				$7::jsonb,
				$8::jsonb,
				$9::jsonb,
				$10::jsonb,
				$11::jsonb
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
				version,
				created_at,
				updated_at
		`,
		slug,
		normalizeStatus(req.Status),
		displayName,
		strings.TrimSpace(req.PrimaryEmail),
		managerID,
		primaryTeamID,
		personalData,
		employmentData,
		thirdPartyIdentities,
		traits,
		metadata,
	)

	created, err := scanCollaborator(row)
	if err != nil {
		return model.Collaborator{}, err
	}

	// Derive the auth_identities username from the primary email; fall back to
	// slug when the email is absent.
	username := strings.ToLower(strings.TrimSpace(created.PrimaryEmail))
	if username == "" {
		username = created.Slug
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO public.auth_identities (collaborator_id, username)
		VALUES ($1, $2)
		ON CONFLICT (collaborator_id) DO NOTHING
	`, created.ID, username); err != nil {
		return model.Collaborator{}, fmt.Errorf("create auth_identity: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return model.Collaborator{}, fmt.Errorf("commit create_collaborator tx: %w", err)
	}

	return created, nil
}

// UpdateCollaborator updates one collaborator record with patch semantics.
func UpdateCollaborator(ctx context.Context, db *sql.DB, req model.UpdateCollaboratorRequest) (model.Collaborator, error) {
	current, err := GetCollaborator(ctx, db, req.ID)
	if err != nil {
		return model.Collaborator{}, err
	}

	slug := current.Slug
	if req.Slug != nil {
		slug = normalizeSlug(*req.Slug)
		if slug == "" {
			return model.Collaborator{}, fmt.Errorf("collaborator slug is required")
		}
	}

	status := current.Status
	if req.Status != nil {
		status = normalizeStatus(*req.Status)
		if status != current.Status {
			from := collaboratorstate.Status(strings.TrimSpace(current.Status))
			to := collaboratorstate.Status(strings.TrimSpace(status))
			if err := collaboratorstate.ValidateTransition(from, to); err != nil {
				return model.Collaborator{}, fmt.Errorf("%w: %s", ErrInvalidCollaboratorStatusTransition, err.Error())
			}
		}
	}

	displayName := current.DisplayName
	if req.DisplayName != nil {
		displayName = strings.TrimSpace(*req.DisplayName)
		if displayName == "" {
			return model.Collaborator{}, fmt.Errorf("collaborator display_name is required")
		}
	}

	primaryEmail := current.PrimaryEmail
	if req.PrimaryEmail != nil {
		primaryEmail = strings.TrimSpace(*req.PrimaryEmail)
	}

	managerID := current.ManagerID
	if req.ManagerID != nil {
		resolvedManagerID, err := resolveOptionalCollaboratorID(ctx, db, *req.ManagerID)
		if err != nil {
			return model.Collaborator{}, err
		}
		managerID = resolvedUUIDPointer(resolvedManagerID)
		if managerID != nil && *managerID == current.ID {
			return model.Collaborator{}, fmt.Errorf("collaborator manager_id cannot reference itself")
		}
	}

	primaryTeamID := current.PrimaryTeamID
	if req.PrimaryTeamID != nil {
		resolvedPrimaryTeamID, err := resolveOptionalTeamID(ctx, db, *req.PrimaryTeamID)
		if err != nil {
			return model.Collaborator{}, err
		}
		primaryTeamID = resolvedUUIDPointer(resolvedPrimaryTeamID)
	}

	personalData := current.PersonalData
	if req.PersonalData != nil {
		personalData = cloneJSONObject(*req.PersonalData)
	}
	employmentData := current.EmploymentData
	if req.EmploymentData != nil {
		employmentData = cloneJSONObject(*req.EmploymentData)
	}
	thirdPartyIdentities := current.ThirdPartyIdentities
	if req.ThirdPartyIdentities != nil {
		thirdPartyIdentities = cloneJSONObject(*req.ThirdPartyIdentities)
	}
	traits := current.Traits
	if req.Traits != nil {
		traits = cloneJSONObject(*req.Traits)
	}
	metadata := current.Metadata
	if req.Metadata != nil {
		metadata = cloneJSONObject(*req.Metadata)
	}

	personalDataRaw, err := marshalJSONObject(personalData)
	if err != nil {
		return model.Collaborator{}, err
	}
	employmentDataRaw, err := marshalJSONObject(employmentData)
	if err != nil {
		return model.Collaborator{}, err
	}
	thirdPartyIdentitiesRaw, err := marshalJSONObject(thirdPartyIdentities)
	if err != nil {
		return model.Collaborator{}, err
	}
	traitsRaw, err := marshalJSONObject(traits)
	if err != nil {
		return model.Collaborator{}, err
	}
	metadataRaw, err := marshalJSONObject(metadata)
	if err != nil {
		return model.Collaborator{}, err
	}

	// Optimistic locking: only update if the row is still on the version we
	// expect. When req.ExpectedVersion is non-nil the caller is asserting they
	// already loaded the row in a prior transaction (or HTTP request) and
	// don't want a concurrent writer's bump to be silently overwritten — we
	// match against that value and return ErrConcurrentUpdate on miss.
	// Otherwise we use the version loaded by GetCollaborator above; the race
	// window collapses to the time between SELECT and UPDATE in this call.
	expectedVersion := current.Version
	if req.ExpectedVersion != nil {
		expectedVersion = *req.ExpectedVersion
	}

	row := db.QueryRowContext(
		ctx,
		`
			UPDATE public.collaborators
			SET
				slug = $2,
				status = $3,
				display_name = $4,
				primary_email = $5,
				manager_id = $6,
				primary_team_id = $7,
				personal_data = $8::jsonb,
				employment_data = $9::jsonb,
				third_party_identities = $10::jsonb,
				traits = $11::jsonb,
				metadata = $12::jsonb,
				version = version + 1
			WHERE id = $1 AND version = $13
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
				version,
				created_at,
				updated_at
		`,
		current.ID,
		slug,
		status,
		displayName,
		primaryEmail,
		managerID,
		primaryTeamID,
		personalDataRaw,
		employmentDataRaw,
		thirdPartyIdentitiesRaw,
		traitsRaw,
		metadataRaw,
		expectedVersion,
	)

	updated, err := scanCollaborator(row)
	if errors.Is(err, sql.ErrNoRows) {
		return model.Collaborator{}, ErrConcurrentUpdate
	}
	return updated, err
}

// DeleteCollaborator removes one collaborator by UUID or slug.
func DeleteCollaborator(ctx context.Context, db *sql.DB, identity string) (model.Collaborator, error) {
	collaborator, err := GetCollaborator(ctx, db, identity)
	if err != nil {
		return model.Collaborator{}, err
	}

	if _, err := db.ExecContext(ctx, `DELETE FROM public.collaborators WHERE id = $1`, collaborator.ID); err != nil {
		return model.Collaborator{}, err
	}

	return collaborator, nil
}

// GetCollaborator returns one collaborator by UUID or slug.
func GetCollaborator(ctx context.Context, db *sql.DB, identity string) (model.Collaborator, error) {
	collaborator, err := scanCollaborator(db.QueryRowContext(ctx, collaboratorLookupQuery(identity), collaboratorLookupArg(identity)))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return model.Collaborator{}, ErrCollaboratorNotFound
		}
		return model.Collaborator{}, err
	}
	return collaborator, nil
}

// GetCollaboratorByThirdPartyLogin returns one collaborator by third-party provider login.
func GetCollaboratorByThirdPartyLogin(ctx context.Context, db *sql.DB, provider, login string) (model.Collaborator, error) {
	provider = normalizeSlug(provider)
	login = strings.TrimSpace(login)
	if provider == "" {
		return model.Collaborator{}, fmt.Errorf("collaborator third-party provider is required")
	}
	if login == "" {
		return model.Collaborator{}, fmt.Errorf("collaborator third-party login is required")
	}

	row := db.QueryRowContext(
		ctx,
		`
			SELECT
				c.id,
				c.slug,
				c.status,
				c.display_name,
				c.primary_email,
				c.manager_id,
				c.primary_team_id,
				c.personal_data,
				c.employment_data,
				c.third_party_identities,
				c.traits,
				c.metadata,
				c.version,
				c.created_at,
				c.updated_at
			FROM public.collaborator_third_party_identities tpi
			JOIN public.collaborators c ON c.id = tpi.collaborator_id
			WHERE tpi.provider = $1
				AND tpi.login = $2
			ORDER BY tpi.created_at ASC
			LIMIT 1
		`,
		provider,
		login,
	)

	collaborator, err := scanCollaborator(row)
	if err == nil {
		return collaborator, nil
	}
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return model.Collaborator{}, err
	}

	row = db.QueryRowContext(
		ctx,
		`
			SELECT
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
				version,
				created_at,
				updated_at
			FROM public.collaborators
			WHERE third_party_identities -> $1 ->> 'login' = $2
			ORDER BY created_at ASC
			LIMIT 1
		`,
		provider,
		login,
	)

	collaborator, err = scanCollaborator(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return model.Collaborator{}, ErrCollaboratorNotFound
		}
		return model.Collaborator{}, err
	}

	return collaborator, nil
}

// ListCollaborators returns collaborators matching the requested status.
// ListCollaborators returns all collaborators matching the filters without
// pagination. For RPC-facing lists, prefer ListCollaboratorsPaginated.
func ListCollaborators(ctx context.Context, db *sql.DB, req model.ListCollaboratorsRequest) ([]model.Collaborator, error) {
	q, args := buildListCollaboratorsQuery(req)
	q += " ORDER BY display_name, slug"

	rows, err := db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var collaborators []model.Collaborator
	for rows.Next() {
		collaborator, err := scanCollaborator(rows)
		if err != nil {
			return nil, err
		}
		collaborators = append(collaborators, collaborator)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return collaborators, nil
}

// ListCollaboratorsPaginated returns a single page of collaborators using
// cursor-based pagination. Default sort is (slug ASC, id ASC).
func ListCollaboratorsPaginated(
	ctx context.Context,
	db *sql.DB,
	req model.ListCollaboratorsRequest,
	pagination model.PaginationRequest,
) ([]model.Collaborator, model.PaginationResponse, error) {
	pagination = NormalizePagination(pagination)
	cursor, err := DecodeCursor(pagination.Cursor)
	if err != nil {
		return nil, model.PaginationResponse{}, fmt.Errorf("invalid cursor: %w", err)
	}

	q, args := buildListCollaboratorsQuery(req)

	// Cursor clause: (slug, id) > (cursor.last_sort_value, cursor.last_id)
	if cursor.LastID != "" && cursor.LastSortValue != nil {
		hasWhere := strings.Contains(q, " WHERE ")
		clause := fmt.Sprintf("(slug, id) > ($%d, $%d)", len(args)+1, len(args)+2)
		if hasWhere {
			q += " AND " + clause
		} else {
			q += " WHERE " + clause
		}
		args = append(args, cursor.LastSortValue, cursor.LastID)
	}
	q += " ORDER BY slug ASC, id ASC"
	args = append(args, pagination.Limit+1)
	q += fmt.Sprintf(" LIMIT $%d", len(args))

	rows, err := db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, model.PaginationResponse{}, err
	}
	defer rows.Close()

	collaborators := make([]model.Collaborator, 0, pagination.Limit)
	for rows.Next() {
		c, err := scanCollaborator(rows)
		if err != nil {
			return nil, model.PaginationResponse{}, err
		}
		collaborators = append(collaborators, c)
	}
	if err := rows.Err(); err != nil {
		return nil, model.PaginationResponse{}, err
	}

	hasMore := len(collaborators) > pagination.Limit
	if hasMore {
		collaborators = collaborators[:pagination.Limit]
	}

	nextCursor := ""
	if len(collaborators) > 0 {
		last := collaborators[len(collaborators)-1]
		nextCursor = EncodeCursor(Cursor{
			LastID:        last.ID.String(),
			LastSortValue: last.Slug,
			SortKey:       "slug_asc",
		})
	}

	return collaborators, model.PaginationResponse{
		NextCursor: nextCursor,
		HasMore:    hasMore,
	}, nil
}

func buildListCollaboratorsQuery(req model.ListCollaboratorsRequest) (string, []any) {
	q := `
		SELECT
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
			version,
			created_at,
			updated_at
		FROM public.collaborators
	`

	var (
		args    []any
		clauses []string
	)

	if status := strings.TrimSpace(req.Status); status != "" {
		args = append(args, strings.ToLower(status))
		clauses = append(clauses, fmt.Sprintf("status = $%d", len(args)))
	}

	if len(clauses) > 0 {
		q += " WHERE " + strings.Join(clauses, " AND ")
	}
	return q, args
}

// CreateTeam stores one team record.
func CreateTeam(ctx context.Context, db *sql.DB, req model.CreateTeamRequest) (model.Team, error) {
	slug := normalizeSlug(req.Slug)
	if slug == "" {
		return model.Team{}, fmt.Errorf("team slug is required")
	}

	name := strings.TrimSpace(req.Name)
	if name == "" {
		return model.Team{}, fmt.Errorf("team name is required")
	}

	parentTeamID, err := resolveOptionalTeamID(ctx, db, req.ParentTeamID)
	if err != nil {
		return model.Team{}, err
	}

	owners, err := marshalJSONArray(normalizeStringList(req.Owners))
	if err != nil {
		return model.Team{}, err
	}
	traits, err := marshalJSONObject(req.Traits)
	if err != nil {
		return model.Team{}, err
	}
	metadata, err := marshalJSONObject(req.Metadata)
	if err != nil {
		return model.Team{}, err
	}

	row := db.QueryRowContext(
		ctx,
		`
			INSERT INTO public.teams (
				slug,
				name,
				type,
				status,
				parent_team_id,
				owners,
				traits,
				metadata
			) VALUES (
				$1,
				$2,
				$3,
				$4,
				$5,
				$6::jsonb,
				$7::jsonb,
				$8::jsonb
			)
			RETURNING
				id,
				slug,
				name,
				type,
				status,
				parent_team_id,
				owners,
				traits,
				metadata,
				created_at,
				updated_at
		`,
		slug,
		name,
		normalizeTeamType(req.Type),
		normalizeStatus(req.Status),
		parentTeamID,
		owners,
		traits,
		metadata,
	)

	return scanTeam(row)
}

// GetTeam returns one team by UUID or slug.
func GetTeam(ctx context.Context, db *sql.DB, identity string) (model.Team, error) {
	team, err := scanTeam(db.QueryRowContext(ctx, teamLookupQuery(identity), teamLookupArg(identity)))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return model.Team{}, ErrTeamNotFound
		}
		return model.Team{}, err
	}
	return team, nil
}

// ListTeams returns teams matching the provided status/type filters.
// ListTeams returns all teams matching the filters without pagination.
// For RPC-facing lists, prefer ListTeamsPaginated.
func ListTeams(ctx context.Context, db *sql.DB, req model.ListTeamsRequest) ([]model.Team, error) {
	q, args := buildListTeamsQuery(req)
	q += " ORDER BY name, slug"

	rows, err := db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var teams []model.Team
	for rows.Next() {
		team, err := scanTeam(rows)
		if err != nil {
			return nil, err
		}
		teams = append(teams, team)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return teams, nil
}

// ListTeamsPaginated returns a single page of teams using cursor-based
// pagination. Default sort is (slug ASC, id ASC).
func ListTeamsPaginated(
	ctx context.Context,
	db *sql.DB,
	req model.ListTeamsRequest,
	pagination model.PaginationRequest,
) ([]model.Team, model.PaginationResponse, error) {
	pagination = NormalizePagination(pagination)
	cursor, err := DecodeCursor(pagination.Cursor)
	if err != nil {
		return nil, model.PaginationResponse{}, fmt.Errorf("invalid cursor: %w", err)
	}

	q, args := buildListTeamsQuery(req)

	if cursor.LastID != "" && cursor.LastSortValue != nil {
		hasWhere := strings.Contains(q, " WHERE ")
		clause := fmt.Sprintf("(slug, id) > ($%d, $%d)", len(args)+1, len(args)+2)
		if hasWhere {
			q += " AND " + clause
		} else {
			q += " WHERE " + clause
		}
		args = append(args, cursor.LastSortValue, cursor.LastID)
	}
	q += " ORDER BY slug ASC, id ASC"
	args = append(args, pagination.Limit+1)
	q += fmt.Sprintf(" LIMIT $%d", len(args))

	rows, err := db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, model.PaginationResponse{}, err
	}
	defer rows.Close()

	teams := make([]model.Team, 0, pagination.Limit)
	for rows.Next() {
		team, err := scanTeam(rows)
		if err != nil {
			return nil, model.PaginationResponse{}, err
		}
		teams = append(teams, team)
	}
	if err := rows.Err(); err != nil {
		return nil, model.PaginationResponse{}, err
	}

	hasMore := len(teams) > pagination.Limit
	if hasMore {
		teams = teams[:pagination.Limit]
	}

	nextCursor := ""
	if len(teams) > 0 {
		last := teams[len(teams)-1]
		nextCursor = EncodeCursor(Cursor{
			LastID:        last.ID.String(),
			LastSortValue: last.Slug,
			SortKey:       "slug_asc",
		})
	}

	return teams, model.PaginationResponse{
		NextCursor: nextCursor,
		HasMore:    hasMore,
	}, nil
}

func buildListTeamsQuery(req model.ListTeamsRequest) (string, []any) {
	q := `
		SELECT
			id,
			slug,
			name,
			type,
			status,
			parent_team_id,
			owners,
			traits,
			metadata,
			created_at,
			updated_at
		FROM public.teams
	`

	var (
		args    []any
		clauses []string
	)

	if status := strings.TrimSpace(req.Status); status != "" {
		args = append(args, strings.ToLower(status))
		clauses = append(clauses, fmt.Sprintf("status = $%d", len(args)))
	}
	if teamType := strings.TrimSpace(req.Type); teamType != "" {
		args = append(args, strings.ToLower(teamType))
		clauses = append(clauses, fmt.Sprintf("type = $%d", len(args)))
	}

	if len(clauses) > 0 {
		q += " WHERE " + strings.Join(clauses, " AND ")
	}
	return q, args
}

// UpdateTeam updates one team record with patch semantics.
func UpdateTeam(ctx context.Context, db *sql.DB, req model.UpdateTeamRequest) (model.Team, error) {
	current, err := GetTeam(ctx, db, req.ID)
	if err != nil {
		return model.Team{}, err
	}

	protected := isTeamRootAdmin(current)

	slug := current.Slug
	if req.Slug != nil {
		slug = normalizeSlug(*req.Slug)
		if slug == "" {
			return model.Team{}, fmt.Errorf("team slug is required")
		}
		if protected && slug != current.Slug {
			return model.Team{}, fmt.Errorf("team %q is protected (traits.is_root_admin=true); slug cannot be changed", current.Slug)
		}
	}

	name := current.Name
	if req.Name != nil {
		name = strings.TrimSpace(*req.Name)
		if name == "" {
			return model.Team{}, fmt.Errorf("team name is required")
		}
	}

	teamType := current.Type
	if req.Type != nil {
		teamType = normalizeTeamType(*req.Type)
	}

	status := current.Status
	if req.Status != nil {
		status = normalizeStatus(*req.Status)
		if protected && status != "active" {
			return model.Team{}, fmt.Errorf("team %q is protected (traits.is_root_admin=true); status must remain 'active'", current.Slug)
		}
	}

	parentTeamID := current.ParentTeamID
	if req.ParentTeamID != nil {
		resolvedParentTeamID, err := resolveOptionalTeamID(ctx, db, *req.ParentTeamID)
		if err != nil {
			return model.Team{}, err
		}
		parentTeamID = resolvedUUIDPointer(resolvedParentTeamID)
		if parentTeamID != nil && *parentTeamID == current.ID {
			return model.Team{}, fmt.Errorf("team parent_team_id cannot reference itself")
		}
		if protected && !samePointer(current.ParentTeamID, parentTeamID) {
			return model.Team{}, fmt.Errorf("team %q is protected (traits.is_root_admin=true); parent_team_id cannot be changed", current.Slug)
		}
	}

	owners := current.Owners
	if req.Owners != nil {
		owners = normalizeStringList(*req.Owners)
	}
	traits := current.Traits
	if req.Traits != nil {
		traits = cloneJSONObject(*req.Traits)
		if protected {
			// Don't allow unsetting the flag — root-admin protection is self-defending.
			traits["is_root_admin"] = true
		}
	}
	metadata := current.Metadata
	if req.Metadata != nil {
		metadata = cloneJSONObject(*req.Metadata)
	}

	ownersRaw, err := marshalJSONArray(owners)
	if err != nil {
		return model.Team{}, err
	}
	traitsRaw, err := marshalJSONObject(traits)
	if err != nil {
		return model.Team{}, err
	}
	metadataRaw, err := marshalJSONObject(metadata)
	if err != nil {
		return model.Team{}, err
	}

	row := db.QueryRowContext(
		ctx,
		`
			UPDATE public.teams
			SET
				slug = $2,
				name = $3,
				type = $4,
				status = $5,
				parent_team_id = $6,
				owners = $7::jsonb,
				traits = $8::jsonb,
				metadata = $9::jsonb
			WHERE id = $1
			RETURNING
				id,
				slug,
				name,
				type,
				status,
				parent_team_id,
				owners,
				traits,
				metadata,
				created_at,
				updated_at
		`,
		current.ID,
		slug,
		name,
		teamType,
		status,
		parentTeamID,
		ownersRaw,
		traitsRaw,
		metadataRaw,
	)

	return scanTeam(row)
}

// DeleteTeam removes one team by UUID or slug.
func DeleteTeam(ctx context.Context, db *sql.DB, identity string) (model.Team, error) {
	team, err := GetTeam(ctx, db, identity)
	if err != nil {
		return model.Team{}, err
	}

	if isTeamRootAdmin(team) {
		return model.Team{}, fmt.Errorf("team %q is protected (traits.is_root_admin=true) and cannot be deleted", team.Slug)
	}

	if _, err := db.ExecContext(ctx, `DELETE FROM public.teams WHERE id = $1`, team.ID); err != nil {
		return model.Team{}, err
	}

	return team, nil
}

// samePointer returns true if both uuid pointers reference the same value
// (or are both nil). Compares by content, not address.
func samePointer(a, b *uuid.UUID) bool {
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil {
		return false
	}
	return *a == *b
}

// isTeamRootAdmin reads team.traits.is_root_admin defensively.
func isTeamRootAdmin(team model.Team) bool {
	if team.Traits == nil {
		return false
	}
	v, ok := team.Traits["is_root_admin"]
	if !ok {
		return false
	}
	if b, ok := v.(bool); ok {
		return b
	}
	return false
}

// UpsertTeamMembership creates or updates one membership link.
func UpsertTeamMembership(ctx context.Context, db *sql.DB, req model.UpsertTeamMembershipRequest) (model.TeamMembership, error) {
	teamID, err := resolveTeamIdentityID(ctx, db, req.TeamID)
	if err != nil {
		return model.TeamMembership{}, err
	}

	collaboratorID, err := resolveCollaboratorIdentityID(ctx, db, req.CollaboratorID)
	if err != nil {
		return model.TeamMembership{}, err
	}

	metadata, err := marshalJSONObject(req.Metadata)
	if err != nil {
		return model.TeamMembership{}, err
	}

	active := true
	if req.Active != nil {
		active = *req.Active
	}

	row := db.QueryRowContext(
		ctx,
		`
			WITH upserted AS (
				INSERT INTO public.team_memberships (
					team_id,
					collaborator_id,
					role,
					active,
					source,
					starts_at,
					ends_at,
					metadata
				) VALUES (
					$1,
					$2,
					$3,
					$4,
					$5,
					$6,
					$7,
					$8::jsonb
				)
				ON CONFLICT (team_id, collaborator_id)
				DO UPDATE SET
					role = EXCLUDED.role,
					active = EXCLUDED.active,
					source = EXCLUDED.source,
					starts_at = EXCLUDED.starts_at,
					ends_at = EXCLUDED.ends_at,
					metadata = EXCLUDED.metadata,
					updated_at = NOW()
				RETURNING
					id,
					team_id,
					collaborator_id,
					role,
					active,
					source,
					starts_at,
					ends_at,
					metadata,
					created_at,
					updated_at
			)
			SELECT
				u.id,
				u.team_id,
				t.slug,
				u.collaborator_id,
				c.slug,
				u.role,
				u.active,
				u.source,
				u.starts_at,
				u.ends_at,
				u.metadata,
				u.created_at,
				u.updated_at
			FROM upserted u
			JOIN public.teams t ON t.id = u.team_id
			JOIN public.collaborators c ON c.id = u.collaborator_id
		`,
		teamID,
		collaboratorID,
		normalizeMembershipRole(req.Role),
		active,
		normalizeMembershipSource(req.Source),
		req.StartsAt,
		req.EndsAt,
		metadata,
	)

	return scanTeamMembership(row)
}

// ListTeamMemberships returns memberships filtered by team/collaborator.
func ListTeamMemberships(ctx context.Context, db *sql.DB, req model.ListTeamMembershipsRequest) ([]model.TeamMembership, error) {
	q := `
		SELECT
			tm.id,
			tm.team_id,
			t.slug,
			tm.collaborator_id,
			c.slug,
			tm.role,
			tm.active,
			tm.source,
			tm.starts_at,
			tm.ends_at,
			tm.metadata,
			tm.created_at,
			tm.updated_at
		FROM public.team_memberships tm
		JOIN public.teams t ON t.id = tm.team_id
		JOIN public.collaborators c ON c.id = tm.collaborator_id
	`

	var (
		args    []any
		clauses []string
	)

	if value := strings.TrimSpace(req.TeamID); value != "" {
		teamID, err := resolveTeamIdentityID(ctx, db, value)
		if err != nil {
			return nil, err
		}
		args = append(args, teamID)
		clauses = append(clauses, fmt.Sprintf("tm.team_id = $%d", len(args)))
	}

	if value := strings.TrimSpace(req.CollaboratorID); value != "" {
		collaboratorID, err := resolveCollaboratorIdentityID(ctx, db, value)
		if err != nil {
			return nil, err
		}
		args = append(args, collaboratorID)
		clauses = append(clauses, fmt.Sprintf("tm.collaborator_id = $%d", len(args)))
	}

	if req.ActiveOnly {
		clauses = append(clauses, "tm.active = TRUE")
	}

	if len(clauses) > 0 {
		q += " WHERE " + strings.Join(clauses, " AND ")
	}
	q += " ORDER BY t.slug, c.slug"

	rows, err := db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var memberships []model.TeamMembership
	for rows.Next() {
		membership, err := scanTeamMembership(rows)
		if err != nil {
			return nil, err
		}
		memberships = append(memberships, membership)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return memberships, nil
}

// ResolveAuthorizationSubjects expands one collaborator into the effective RBAC subjects and active teams.
func ResolveAuthorizationSubjects(ctx context.Context, db *sql.DB, collaboratorIdentity string) (model.Collaborator, []model.Team, []model.RBACSubject, error) {
	collaborator, err := GetCollaborator(ctx, db, collaboratorIdentity)
	if err != nil {
		return model.Collaborator{}, nil, nil, err
	}

	directTeams, err := listDirectAuthorizationTeams(ctx, db, collaborator.ID)
	if err != nil {
		return model.Collaborator{}, nil, nil, err
	}

	teams, err := expandAncestorTeams(directTeams, func(parentTeamID uuid.UUID) (model.Team, error) {
		team, err := GetTeam(ctx, db, parentTeamID.String())
		if err != nil {
			return model.Team{}, err
		}
		if team.Status != "active" {
			return model.Team{}, ErrTeamNotFound
		}
		return team, nil
	})
	if err != nil {
		return model.Collaborator{}, nil, nil, err
	}

	subjects := []model.RBACSubject{
		{Type: "collaborator", ID: collaborator.Slug},
	}
	for _, team := range teams {
		subjects = append(subjects, model.RBACSubject{Type: "team", ID: team.Slug})
	}

	return collaborator, teams, subjects, nil
}

func listDirectAuthorizationTeams(ctx context.Context, db *sql.DB, collaboratorID uuid.UUID) ([]model.Team, error) {
	rows, err := db.QueryContext(
		ctx,
		`
			SELECT
				t.id,
				t.slug,
				t.name,
				t.type,
				t.status,
				t.parent_team_id,
				t.owners,
				t.traits,
				t.metadata,
				t.created_at,
				t.updated_at
			FROM public.team_memberships tm
			JOIN public.teams t ON t.id = tm.team_id
			WHERE
				tm.collaborator_id = $1
				AND tm.active = TRUE
				AND t.status = 'active'
				AND (tm.starts_at IS NULL OR tm.starts_at <= NOW())
				AND (tm.ends_at IS NULL OR tm.ends_at >= NOW())
			ORDER BY t.name, t.slug
		`,
		collaboratorID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var teams []model.Team
	for rows.Next() {
		team, err := scanTeam(rows)
		if err != nil {
			return nil, err
		}
		teams = append(teams, team)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	return teams, nil
}

func expandAncestorTeams(seed []model.Team, resolve func(parentTeamID uuid.UUID) (model.Team, error)) ([]model.Team, error) {
	if len(seed) == 0 {
		return nil, nil
	}

	expanded := make([]model.Team, 0, len(seed))
	seen := map[uuid.UUID]struct{}{}
	queue := append([]model.Team(nil), seed...)

	for len(queue) > 0 {
		team := queue[0]
		queue = queue[1:]

		if _, exists := seen[team.ID]; exists {
			continue
		}
		seen[team.ID] = struct{}{}
		expanded = append(expanded, team)

		if team.ParentTeamID == nil || *team.ParentTeamID == uuid.Nil {
			continue
		}

		parentTeam, err := resolve(*team.ParentTeamID)
		if err != nil {
			if errors.Is(err, ErrTeamNotFound) {
				continue
			}
			return nil, err
		}

		queue = append(queue, parentTeam)
	}

	return expanded, nil
}

func collaboratorLookupQuery(identity string) string {
	q := `
		SELECT
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
			version,
			created_at,
			updated_at
		FROM public.collaborators
	`

	if parsedID, err := uuid.Parse(strings.TrimSpace(identity)); err == nil && parsedID != uuid.Nil {
		return q + " WHERE id = $1"
	}
	return q + " WHERE slug = $1"
}

func collaboratorLookupArg(identity string) any {
	if parsedID, err := uuid.Parse(strings.TrimSpace(identity)); err == nil && parsedID != uuid.Nil {
		return parsedID
	}
	return normalizeSlug(identity)
}

func teamLookupQuery(identity string) string {
	q := `
		SELECT
			id,
			slug,
			name,
			type,
			status,
			parent_team_id,
			owners,
			traits,
			metadata,
			created_at,
			updated_at
		FROM public.teams
	`

	if parsedID, err := uuid.Parse(strings.TrimSpace(identity)); err == nil && parsedID != uuid.Nil {
		return q + " WHERE id = $1"
	}
	return q + " WHERE slug = $1"
}

func teamLookupArg(identity string) any {
	if parsedID, err := uuid.Parse(strings.TrimSpace(identity)); err == nil && parsedID != uuid.Nil {
		return parsedID
	}
	return normalizeSlug(identity)
}

func resolveOptionalCollaboratorID(ctx context.Context, db *sql.DB, identity string) (any, error) {
	if strings.TrimSpace(identity) == "" {
		return nil, nil
	}

	resolvedID, err := resolveCollaboratorIdentityID(ctx, db, identity)
	if err != nil {
		return nil, err
	}
	return resolvedID, nil
}

func resolveOptionalTeamID(ctx context.Context, db *sql.DB, identity string) (any, error) {
	if strings.TrimSpace(identity) == "" {
		return nil, nil
	}

	resolvedID, err := resolveTeamIdentityID(ctx, db, identity)
	if err != nil {
		return nil, err
	}
	return resolvedID, nil
}

func resolveCollaboratorIdentityID(ctx context.Context, db *sql.DB, identity string) (uuid.UUID, error) {
	collaborator, err := GetCollaborator(ctx, db, identity)
	if err != nil {
		return uuid.Nil, err
	}
	return collaborator.ID, nil
}

func resolveTeamIdentityID(ctx context.Context, db *sql.DB, identity string) (uuid.UUID, error) {
	team, err := GetTeam(ctx, db, identity)
	if err != nil {
		return uuid.Nil, err
	}
	return team.ID, nil
}

func scanCollaborator(row scanner) (model.Collaborator, error) {
	var (
		collaborator         model.Collaborator
		managerID            sql.NullString
		primaryTeamID        sql.NullString
		personalData         []byte
		employmentData       []byte
		thirdPartyIdentities []byte
		traits               []byte
		metadata             []byte
	)

	err := row.Scan(
		&collaborator.ID,
		&collaborator.Slug,
		&collaborator.Status,
		&collaborator.DisplayName,
		&collaborator.PrimaryEmail,
		&managerID,
		&primaryTeamID,
		&personalData,
		&employmentData,
		&thirdPartyIdentities,
		&traits,
		&metadata,
		&collaborator.Version,
		&collaborator.CreatedAt,
		&collaborator.UpdatedAt,
	)
	if err != nil {
		return model.Collaborator{}, err
	}

	collaborator.ManagerID, err = parseNullableUUID(managerID)
	if err != nil {
		return model.Collaborator{}, err
	}
	collaborator.PrimaryTeamID, err = parseNullableUUID(primaryTeamID)
	if err != nil {
		return model.Collaborator{}, err
	}
	if collaborator.PersonalData, err = unmarshalJSONObject(personalData); err != nil {
		return model.Collaborator{}, err
	}
	if collaborator.EmploymentData, err = unmarshalJSONObject(employmentData); err != nil {
		return model.Collaborator{}, err
	}
	if collaborator.ThirdPartyIdentities, err = unmarshalJSONObject(thirdPartyIdentities); err != nil {
		return model.Collaborator{}, err
	}
	if collaborator.Traits, err = unmarshalJSONObject(traits); err != nil {
		return model.Collaborator{}, err
	}
	if collaborator.Metadata, err = unmarshalJSONObject(metadata); err != nil {
		return model.Collaborator{}, err
	}

	return collaborator, nil
}

func scanTeam(row scanner) (model.Team, error) {
	var (
		team         model.Team
		parentTeamID sql.NullString
		owners       []byte
		traits       []byte
		metadata     []byte
		err          error
	)

	err = row.Scan(
		&team.ID,
		&team.Slug,
		&team.Name,
		&team.Type,
		&team.Status,
		&parentTeamID,
		&owners,
		&traits,
		&metadata,
		&team.CreatedAt,
		&team.UpdatedAt,
	)
	if err != nil {
		return model.Team{}, err
	}

	team.ParentTeamID, err = parseNullableUUID(parentTeamID)
	if err != nil {
		return model.Team{}, err
	}
	if team.Owners, err = unmarshalStringArray(owners); err != nil {
		return model.Team{}, err
	}
	if team.Traits, err = unmarshalJSONObject(traits); err != nil {
		return model.Team{}, err
	}
	if team.Metadata, err = unmarshalJSONObject(metadata); err != nil {
		return model.Team{}, err
	}

	return team, nil
}

func scanTeamMembership(row scanner) (model.TeamMembership, error) {
	var (
		membership model.TeamMembership
		startsAt   sql.NullTime
		endsAt     sql.NullTime
		metadata   []byte
		err        error
	)

	err = row.Scan(
		&membership.ID,
		&membership.TeamID,
		&membership.TeamSlug,
		&membership.CollaboratorID,
		&membership.CollaboratorSlug,
		&membership.Role,
		&membership.Active,
		&membership.Source,
		&startsAt,
		&endsAt,
		&metadata,
		&membership.CreatedAt,
		&membership.UpdatedAt,
	)
	if err != nil {
		return model.TeamMembership{}, err
	}

	if startsAt.Valid {
		value := startsAt.Time
		membership.StartsAt = &value
	}
	if endsAt.Valid {
		value := endsAt.Time
		membership.EndsAt = &value
	}
	if membership.Metadata, err = unmarshalJSONObject(metadata); err != nil {
		return model.TeamMembership{}, err
	}

	return membership, nil
}

func normalizeSlug(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

func normalizeStatus(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return "active"
	}
	return value
}

func normalizeTeamType(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return "team"
	}
	return value
}

func normalizeMembershipRole(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return "member"
	}
	return value
}

func normalizeMembershipSource(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return "manual"
	}
	return value
}

func normalizeStringList(values []string) []string {
	seen := map[string]struct{}{}
	normalized := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		normalized = append(normalized, value)
	}
	return normalized
}

func cloneJSONObject(value map[string]any) map[string]any {
	if value == nil {
		return map[string]any{}
	}

	cloned := make(map[string]any, len(value))
	for key, item := range value {
		cloned[key] = item
	}
	return cloned
}

func marshalJSONObject(value map[string]any) ([]byte, error) {
	if value == nil {
		return []byte("{}"), nil
	}
	return json.Marshal(value)
}

func marshalJSONArray(value []string) ([]byte, error) {
	if value == nil {
		return []byte("[]"), nil
	}
	return json.Marshal(value)
}

func unmarshalJSONObject(raw []byte) (map[string]any, error) {
	if len(raw) == 0 {
		return map[string]any{}, nil
	}

	var result map[string]any
	if err := json.Unmarshal(raw, &result); err != nil {
		return nil, err
	}
	if result == nil {
		return map[string]any{}, nil
	}
	return result, nil
}

func unmarshalStringArray(raw []byte) ([]string, error) {
	if len(raw) == 0 {
		return []string{}, nil
	}

	var result []string
	if err := json.Unmarshal(raw, &result); err != nil {
		return nil, err
	}
	if result == nil {
		return []string{}, nil
	}
	return result, nil
}

func parseNullableUUID(value sql.NullString) (*uuid.UUID, error) {
	if !value.Valid || strings.TrimSpace(value.String) == "" {
		return nil, nil
	}

	parsedID, err := uuid.Parse(strings.TrimSpace(value.String))
	if err != nil {
		return nil, err
	}
	return &parsedID, nil
}

func resolvedUUIDPointer(value any) *uuid.UUID {
	if value == nil {
		return nil
	}

	switch typed := value.(type) {
	case uuid.UUID:
		if typed == uuid.Nil {
			return nil
		}
		result := typed
		return &result
	case *uuid.UUID:
		return typed
	default:
		return nil
	}
}

// === TEAM GRANTS ===

// ListTeamGrants returns grants of one team.
func ListTeamGrants(ctx context.Context, db *sql.DB, req model.ListTeamGrantsRequest) ([]model.TeamGrant, error) {
	teamID, err := resolveTeamID(ctx, db, req.TeamID)
	if err != nil {
		return nil, err
	}

	rows, err := db.QueryContext(ctx, `
		SELECT id, team_id, integration_instance_namespace, integration_instance_name,
			action_name, scope, granted_at, granted_by
		FROM public.team_grants
		WHERE team_id = $1
		ORDER BY integration_instance_namespace, integration_instance_name, action_name
	`, teamID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	grants := []model.TeamGrant{}
	for rows.Next() {
		var g model.TeamGrant
		var scope []byte
		var grantedBy sql.NullString
		if err := rows.Scan(&g.ID, &g.TeamID, &g.IntegrationInstanceNamespace,
			&g.IntegrationInstanceName, &g.ActionName, &scope, &g.GrantedAt, &grantedBy); err != nil {
			return nil, err
		}
		obj, err := unmarshalJSONObject(scope)
		if err != nil {
			return nil, err
		}
		g.Scope = obj
		if grantedBy.Valid {
			val := grantedBy.String
			g.GrantedBy = &val
		}
		grants = append(grants, g)
	}
	return grants, rows.Err()
}

// GrantTeamAction inserts (or updates) one grant.
func GrantTeamAction(ctx context.Context, db *sql.DB, req model.GrantTeamActionRequest) (model.TeamGrant, error) {
	teamID, err := resolveTeamID(ctx, db, req.TeamID)
	if err != nil {
		return model.TeamGrant{}, err
	}

	namespace := strings.TrimSpace(req.IntegrationInstanceNamespace)
	name := strings.TrimSpace(req.IntegrationInstanceName)
	action := strings.TrimSpace(req.ActionName)
	if namespace == "" || name == "" {
		return model.TeamGrant{}, fmt.Errorf("integration_instance namespace and name are required")
	}
	if action == "" {
		action = "*"
	}

	scopeRaw, err := marshalJSONObject(req.Scope)
	if err != nil {
		return model.TeamGrant{}, err
	}

	grantedBy, err := parseOptionalUUIDGrants(req.GrantedBy)
	if err != nil {
		return model.TeamGrant{}, err
	}

	var g model.TeamGrant
	var scope []byte
	var grantedByDB sql.NullString
	err = db.QueryRowContext(ctx, `
		INSERT INTO public.team_grants (team_id, integration_instance_namespace,
			integration_instance_name, action_name, scope, granted_by)
		VALUES ($1, $2, $3, $4, $5::jsonb, $6)
		ON CONFLICT (team_id, integration_instance_namespace, integration_instance_name, action_name)
			DO UPDATE SET scope = EXCLUDED.scope, granted_by = EXCLUDED.granted_by, granted_at = NOW()
		RETURNING id, team_id, integration_instance_namespace, integration_instance_name,
			action_name, scope, granted_at, granted_by
	`, teamID, namespace, name, action, scopeRaw, grantedBy).Scan(
		&g.ID, &g.TeamID, &g.IntegrationInstanceNamespace, &g.IntegrationInstanceName,
		&g.ActionName, &scope, &g.GrantedAt, &grantedByDB,
	)
	if err != nil {
		return model.TeamGrant{}, err
	}
	obj, err := unmarshalJSONObject(scope)
	if err != nil {
		return model.TeamGrant{}, err
	}
	g.Scope = obj
	if grantedByDB.Valid {
		val := grantedByDB.String
		g.GrantedBy = &val
	}
	return g, nil
}

// RevokeTeamGrant deletes one grant by id.
func RevokeTeamGrant(ctx context.Context, db *sql.DB, grantID string) error {
	id, err := uuid.Parse(strings.TrimSpace(grantID))
	if err != nil {
		return fmt.Errorf("invalid grant_id")
	}

	// Last-grant-of-power check: refuse to revoke if it would leave the cluster
	// without any active grant that can manage team grants.
	var ns, name, action string
	err = db.QueryRowContext(ctx, `
		SELECT integration_instance_namespace, integration_instance_name, action_name
		FROM public.team_grants WHERE id = $1
	`, id).Scan(&ns, &name, &action)
	if err == sql.ErrNoRows {
		return fmt.Errorf("grant not found")
	}
	if err != nil {
		return err
	}
	if isYggdrasilSelfManageGrant(name, action) {
		var siblingCount int
		err = db.QueryRowContext(ctx, `
			SELECT COUNT(*)
			FROM public.team_grants
			WHERE id <> $1
				AND integration_instance_name LIKE 'yggdrasil-self%'
				AND action_name IN ('*', 'manage_team_sources', 'manage_team_permissions')
		`, id).Scan(&siblingCount)
		if err != nil {
			return err
		}
		if siblingCount == 0 {
			return fmt.Errorf("refusing to revoke last grant that controls yggdrasil-self management; cluster would have no admin")
		}
	}

	res, err := db.ExecContext(ctx, `DELETE FROM public.team_grants WHERE id = $1`, id)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return fmt.Errorf("grant not found")
	}
	return nil
}

// isYggdrasilSelfManageGrant detects grants that confer admin power over the
// team_grants system itself: any grant on a yggdrasil-self instance whose
// action is wildcard or one of the meta-actions declared in the type catalog.
func isYggdrasilSelfManageGrant(integrationInstanceName, action string) bool {
	if !strings.HasPrefix(integrationInstanceName, "yggdrasil-self") {
		return false
	}
	switch action {
	case "*", "manage_team_sources", "manage_team_permissions":
		return true
	}
	return false
}

func resolveTeamID(ctx context.Context, db *sql.DB, identity string) (string, error) {
	team, err := GetTeam(ctx, db, identity)
	if err != nil {
		return "", err
	}
	return team.ID.String(), nil
}

func parseOptionalUUIDGrants(value string) (*uuid.UUID, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil, nil
	}
	id, err := uuid.Parse(value)
	if err != nil {
		return nil, err
	}
	return &id, nil
}

// ListAvailableSourcesForTeam returns the pool of integration_instance sources
// that the given team can pick from when configuring its own grants. Pool =
// union of (own grants ∪ ancestor grants) deduped by (namespace, name).
// Ancestor walk stops on inactive teams (same rule as ResolveAuthorizationSubjects).
func ListAvailableSourcesForTeam(ctx context.Context, db *sql.DB, teamIdentity string) ([]model.TeamGrantSource, error) {
	startTeam, err := GetTeam(ctx, db, teamIdentity)
	if err != nil {
		return nil, err
	}

	// Walk up the parent chain, collecting team IDs whose grants count.
	teamIDs := []uuid.UUID{startTeam.ID}
	seen := map[uuid.UUID]struct{}{startTeam.ID: {}}
	cursor := startTeam.ParentTeamID
	for cursor != nil && *cursor != uuid.Nil {
		if _, dup := seen[*cursor]; dup {
			break // defensive: cycle
		}
		parent, err := GetTeam(ctx, db, cursor.String())
		if err != nil {
			if errors.Is(err, ErrTeamNotFound) {
				break
			}
			return nil, err
		}
		if parent.Status != "active" {
			break
		}
		teamIDs = append(teamIDs, parent.ID)
		seen[parent.ID] = struct{}{}
		cursor = parent.ParentTeamID
	}

	// Query unique sources across all those teams.
	rows, err := db.QueryContext(ctx, `
		SELECT DISTINCT integration_instance_namespace, integration_instance_name
		FROM public.team_grants
		WHERE team_id = ANY($1)
		ORDER BY integration_instance_namespace, integration_instance_name
	`, pq.Array(teamIDs))
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	sources := []model.TeamGrantSource{}
	for rows.Next() {
		var s model.TeamGrantSource
		if err := rows.Scan(&s.Namespace, &s.Name); err != nil {
			return nil, err
		}
		sources = append(sources, s)
	}
	return sources, rows.Err()
}
