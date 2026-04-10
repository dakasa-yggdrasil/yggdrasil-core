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

var ErrIntegrationRuntimeStateNotFound = errors.New("integration runtime state not found")

// UpsertIntegrationRuntimeState stores one observed runtime check result for an integration instance.
func UpsertIntegrationRuntimeState(
	ctx context.Context,
	db *sql.DB,
	instanceManifest model.Manifest,
	typeManifest model.Manifest,
	checkKind string,
	status string,
	message string,
	details map[string]any,
) (model.IntegrationRuntimeState, error) {
	checkKind = strings.ToLower(strings.TrimSpace(checkKind))
	if checkKind == "" {
		return model.IntegrationRuntimeState{}, fmt.Errorf("integration runtime state check_kind is required")
	}

	status = strings.ToLower(strings.TrimSpace(status))
	if status == "" {
		return model.IntegrationRuntimeState{}, fmt.Errorf("integration runtime state status is required")
	}

	if instanceManifest.Kind != "integration_instance" {
		return model.IntegrationRuntimeState{}, fmt.Errorf("manifest %s is not an integration_instance", instanceManifest.ID)
	}
	if typeManifest.Kind != "integration_type" {
		return model.IntegrationRuntimeState{}, fmt.Errorf("manifest %s is not an integration_type", typeManifest.ID)
	}

	detailsRaw, err := marshalJSONObject(details)
	if err != nil {
		return model.IntegrationRuntimeState{}, err
	}

	row := db.QueryRowContext(
		ctx,
		`
			INSERT INTO public.integration_instance_runtime_states (
				integration_instance_manifest_id,
				integration_type_manifest_id,
				check_kind,
				status,
				message,
				details,
				last_checked_at,
				last_success_at,
				last_failure_at,
				created_at,
				updated_at
			) VALUES (
				$1,
				$2,
				$3,
				$4,
				$5,
				$6::jsonb,
				NOW(),
				CASE WHEN $4 = 'healthy' THEN NOW() ELSE NULL END,
				CASE WHEN $4 <> 'healthy' THEN NOW() ELSE NULL END,
				NOW(),
				NOW()
			)
			ON CONFLICT (integration_instance_manifest_id, check_kind)
			DO UPDATE SET
				integration_type_manifest_id = EXCLUDED.integration_type_manifest_id,
				status = EXCLUDED.status,
				message = EXCLUDED.message,
				details = EXCLUDED.details,
				last_checked_at = EXCLUDED.last_checked_at,
				last_success_at = CASE
					WHEN EXCLUDED.status = 'healthy' THEN EXCLUDED.last_checked_at
					ELSE public.integration_instance_runtime_states.last_success_at
				END,
				last_failure_at = CASE
					WHEN EXCLUDED.status <> 'healthy' THEN EXCLUDED.last_checked_at
					ELSE public.integration_instance_runtime_states.last_failure_at
				END,
				updated_at = NOW()
			RETURNING
				check_kind,
				status,
				message,
				details,
				last_checked_at,
				last_success_at,
				last_failure_at,
				created_at,
				updated_at
		`,
		instanceManifest.ID,
		typeManifest.ID,
		checkKind,
		status,
		strings.TrimSpace(message),
		detailsRaw,
	)

	return scanIntegrationRuntimeState(instanceManifest, typeManifest, row)
}

// GetIntegrationRuntimeState fetches one runtime state by integration instance and check kind.
func GetIntegrationRuntimeState(
	ctx context.Context,
	db *sql.DB,
	selector model.ManifestSelector,
	checkKind string,
) (model.IntegrationRuntimeState, error) {
	instanceManifest, err := resolveIntegrationInstanceManifest(ctx, db, selector)
	if err != nil {
		return model.IntegrationRuntimeState{}, err
	}

	checkKind = strings.ToLower(strings.TrimSpace(checkKind))
	if checkKind == "" {
		checkKind = model.IntegrationRuntimeCheckKindDescribeHandshake
	}

	row := db.QueryRowContext(
		ctx,
		`
			SELECT
				mt.id,
				mt.kind,
				mt.namespace,
				mt.name,
				mt.version,
				s.check_kind,
				s.status,
				s.message,
				s.details,
				s.last_checked_at,
				s.last_success_at,
				s.last_failure_at,
				s.created_at,
				s.updated_at
			FROM public.integration_instance_runtime_states s
			INNER JOIN public.manifests mt ON mt.id = s.integration_type_manifest_id
			WHERE s.integration_instance_manifest_id = $1
				AND s.check_kind = $2
		`,
		instanceManifest.ID,
		checkKind,
	)

	state, err := scanIntegrationRuntimeStateWithType(instanceManifest, row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return model.IntegrationRuntimeState{}, ErrIntegrationRuntimeStateNotFound
		}
		return model.IntegrationRuntimeState{}, err
	}

	return state, nil
}

// ListIntegrationRuntimeStates returns observed runtime checks matching the provided filters.
func ListIntegrationRuntimeStates(
	ctx context.Context,
	db *sql.DB,
	req model.ListIntegrationRuntimeStatesRequest,
) ([]model.IntegrationRuntimeState, error) {
	query := `
		SELECT
			mi.id,
			mi.kind,
			mi.namespace,
			mi.name,
			mi.version,
			mt.id,
			mt.kind,
			mt.namespace,
			mt.name,
			mt.version,
			s.check_kind,
			s.status,
			s.message,
			s.details,
			s.last_checked_at,
			s.last_success_at,
			s.last_failure_at,
			s.created_at,
			s.updated_at
		FROM public.integration_instance_runtime_states s
		INNER JOIN public.manifests mi ON mi.id = s.integration_instance_manifest_id
		INNER JOIN public.manifests mt ON mt.id = s.integration_type_manifest_id
		WHERE mi.kind = 'integration_instance'
			AND mt.kind = 'integration_type'
	`

	var (
		clauses []string
		args    []any
	)

	if namespace := strings.ToLower(strings.TrimSpace(req.Namespace)); namespace != "" {
		args = append(args, namespace)
		clauses = append(clauses, fmt.Sprintf("mi.namespace = $%d", len(args)))
	}
	if name := strings.ToLower(strings.TrimSpace(req.Name)); name != "" {
		args = append(args, name)
		clauses = append(clauses, fmt.Sprintf("mi.name = $%d", len(args)))
	}
	if status := strings.ToLower(strings.TrimSpace(req.Status)); status != "" {
		args = append(args, status)
		clauses = append(clauses, fmt.Sprintf("s.status = $%d", len(args)))
	}
	if checkKind := strings.ToLower(strings.TrimSpace(req.CheckKind)); checkKind != "" {
		args = append(args, checkKind)
		clauses = append(clauses, fmt.Sprintf("s.check_kind = $%d", len(args)))
	}

	if len(clauses) > 0 {
		query += " AND " + strings.Join(clauses, " AND ")
	}

	query += " ORDER BY mi.namespace, mi.name, s.check_kind"

	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	states := make([]model.IntegrationRuntimeState, 0)
	for rows.Next() {
		state, err := scanIntegrationRuntimeStateWithManifests(rows)
		if err != nil {
			return nil, err
		}
		states = append(states, state)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	return states, nil
}

func resolveIntegrationInstanceManifest(ctx context.Context, db *sql.DB, selector model.ManifestSelector) (model.Manifest, error) {
	if manifestID := strings.TrimSpace(selector.ManifestID); manifestID != "" {
		parsedID, err := uuid.Parse(manifestID)
		if err != nil {
			return model.Manifest{}, fmt.Errorf("invalid manifest id")
		}
		manifest, err := GetManifestByID(ctx, db, parsedID)
		if err != nil {
			return model.Manifest{}, err
		}
		if manifest.Kind != "integration_instance" {
			return model.Manifest{}, fmt.Errorf("manifest %s is not an integration_instance", parsedID)
		}
		return manifest, nil
	}

	name := strings.TrimSpace(selector.Name)
	if name == "" {
		return model.Manifest{}, fmt.Errorf("integration instance name is required when manifest_id is not provided")
	}

	namespace := strings.TrimSpace(selector.Namespace)
	if namespace == "" {
		namespace = "global"
	}

	return ResolveManifest(ctx, db, "integration_instance", namespace, name, selector.Version, true)
}

func scanIntegrationRuntimeStateWithManifests(row scanner) (model.IntegrationRuntimeState, error) {
	var (
		state            model.IntegrationRuntimeState
		instanceManifest model.Manifest
		typeManifest     model.Manifest
		instanceNS       string
		instanceName     string
		typeNS           string
		typeName         string
		details          []byte
		lastSuccessAt    sql.NullTime
		lastFailureAt    sql.NullTime
	)

	err := row.Scan(
		&instanceManifest.ID,
		&instanceManifest.Kind,
		&instanceNS,
		&instanceName,
		&instanceManifest.Version,
		&typeManifest.ID,
		&typeManifest.Kind,
		&typeNS,
		&typeName,
		&typeManifest.Version,
		&state.CheckKind,
		&state.Status,
		&state.Message,
		&details,
		&state.LastCheckedAt,
		&lastSuccessAt,
		&lastFailureAt,
		&state.CreatedAt,
		&state.UpdatedAt,
	)
	if err != nil {
		return model.IntegrationRuntimeState{}, err
	}

	state.IntegrationInstance = model.ManifestReference{
		ID:        instanceManifest.ID,
		Kind:      instanceManifest.Kind,
		Namespace: instanceNS,
		Name:      instanceName,
		Version:   instanceManifest.Version,
	}
	state.IntegrationType = model.ManifestReference{
		ID:        typeManifest.ID,
		Kind:      typeManifest.Kind,
		Namespace: typeNS,
		Name:      typeName,
		Version:   typeManifest.Version,
	}
	if state.Details, err = unmarshalJSONObject(details); err != nil {
		return model.IntegrationRuntimeState{}, err
	}
	if lastSuccessAt.Valid {
		value := lastSuccessAt.Time
		state.LastSuccessAt = &value
	}
	if lastFailureAt.Valid {
		value := lastFailureAt.Time
		state.LastFailureAt = &value
	}

	return state, nil
}

func scanIntegrationRuntimeStateWithType(instanceManifest model.Manifest, row scanner) (model.IntegrationRuntimeState, error) {
	var (
		state         model.IntegrationRuntimeState
		typeManifest  model.Manifest
		typeNamespace string
		typeName      string
		details       []byte
		lastSuccessAt sql.NullTime
		lastFailureAt sql.NullTime
	)

	err := row.Scan(
		&typeManifest.ID,
		&typeManifest.Kind,
		&typeNamespace,
		&typeName,
		&typeManifest.Version,
		&state.CheckKind,
		&state.Status,
		&state.Message,
		&details,
		&state.LastCheckedAt,
		&lastSuccessAt,
		&lastFailureAt,
		&state.CreatedAt,
		&state.UpdatedAt,
	)
	if err != nil {
		return model.IntegrationRuntimeState{}, err
	}

	state.IntegrationInstance = model.ManifestReference{
		ID:        instanceManifest.ID,
		Kind:      instanceManifest.Kind,
		Namespace: instanceManifest.Metadata.Namespace,
		Name:      instanceManifest.Metadata.Name,
		Version:   instanceManifest.Version,
	}
	state.IntegrationType = model.ManifestReference{
		ID:        typeManifest.ID,
		Kind:      typeManifest.Kind,
		Namespace: typeNamespace,
		Name:      typeName,
		Version:   typeManifest.Version,
	}

	if state.Details, err = unmarshalJSONObject(details); err != nil {
		return model.IntegrationRuntimeState{}, err
	}
	if lastSuccessAt.Valid {
		value := lastSuccessAt.Time
		state.LastSuccessAt = &value
	}
	if lastFailureAt.Valid {
		value := lastFailureAt.Time
		state.LastFailureAt = &value
	}

	return state, nil
}

func scanIntegrationRuntimeState(instanceManifest model.Manifest, typeManifest model.Manifest, row scanner) (model.IntegrationRuntimeState, error) {
	var (
		state         model.IntegrationRuntimeState
		details       []byte
		lastSuccessAt sql.NullTime
		lastFailureAt sql.NullTime
	)

	err := row.Scan(
		&state.CheckKind,
		&state.Status,
		&state.Message,
		&details,
		&state.LastCheckedAt,
		&lastSuccessAt,
		&lastFailureAt,
		&state.CreatedAt,
		&state.UpdatedAt,
	)
	if err != nil {
		return model.IntegrationRuntimeState{}, err
	}

	state.IntegrationInstance = model.ManifestReference{
		ID:        instanceManifest.ID,
		Kind:      instanceManifest.Kind,
		Namespace: instanceManifest.Metadata.Namespace,
		Name:      instanceManifest.Metadata.Name,
		Version:   instanceManifest.Version,
	}
	state.IntegrationType = model.ManifestReference{
		ID:        typeManifest.ID,
		Kind:      typeManifest.Kind,
		Namespace: typeManifest.Metadata.Namespace,
		Name:      typeManifest.Metadata.Name,
		Version:   typeManifest.Version,
	}

	if state.Details, err = unmarshalJSONObject(details); err != nil {
		return model.IntegrationRuntimeState{}, err
	}
	if lastSuccessAt.Valid {
		value := lastSuccessAt.Time
		state.LastSuccessAt = &value
	}
	if lastFailureAt.Valid {
		value := lastFailureAt.Time
		state.LastFailureAt = &value
	}

	return state, nil
}
