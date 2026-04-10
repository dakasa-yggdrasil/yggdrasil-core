package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

var ErrManagedSecretNotFound = errors.New("managed secret not found")

// UpsertManagedSecret creates or updates one namespaced secret in the core.
func UpsertManagedSecret(ctx context.Context, db *sql.DB, req model.UpsertManagedSecretRequest) (model.ManagedSecret, error) {
	namespace := normalizeManagedSecretNamespace(req.Namespace)
	name := normalizeManagedSecretName(req.Name)
	if name == "" {
		return model.ManagedSecret{}, fmt.Errorf("secret name is required")
	}

	status := normalizeManagedSecretStatus(req.Status)
	if status == "" {
		status = "active"
	}
	switch status {
	case "active", "disabled", "revoked":
	default:
		return model.ManagedSecret{}, fmt.Errorf("secret status %q is unsupported", req.Status)
	}
	if err := validateManagedSecretRotation(req.Rotation); err != nil {
		return model.ManagedSecret{}, err
	}
	if req.ExpiresAt != nil && req.ExpiresAt.UTC().IsZero() {
		return model.ManagedSecret{}, fmt.Errorf("secret expires_at must be a valid timestamp")
	}

	dataRaw, err := marshalStringMap(req.Data)
	if err != nil {
		return model.ManagedSecret{}, err
	}
	metadataRaw, err := marshalJSONObject(req.Metadata)
	if err != nil {
		return model.ManagedSecret{}, err
	}
	rotationRaw, err := marshalSecretRotationPolicy(req.Rotation)
	if err != nil {
		return model.ManagedSecret{}, err
	}

	row := db.QueryRowContext(
		ctx,
		`
			INSERT INTO public.managed_secrets (
				namespace,
				name,
				status,
				data,
				metadata,
				rotation,
				expires_at
			) VALUES (
				$1,
				$2,
				$3,
				$4::jsonb,
				$5::jsonb,
				$6::jsonb,
				$7
			)
			ON CONFLICT (namespace, name)
			DO UPDATE SET
				status = EXCLUDED.status,
				data = EXCLUDED.data,
				metadata = EXCLUDED.metadata,
				rotation = EXCLUDED.rotation,
				expires_at = EXCLUDED.expires_at,
				version = CASE
					WHEN public.managed_secrets.data IS DISTINCT FROM EXCLUDED.data
						THEN public.managed_secrets.version + 1
					ELSE public.managed_secrets.version
				END,
				last_rotated_at = CASE
					WHEN public.managed_secrets.data IS DISTINCT FROM EXCLUDED.data
						THEN NOW()
					ELSE public.managed_secrets.last_rotated_at
				END,
				updated_at = NOW()
			RETURNING
				id,
				namespace,
				name,
				status,
				version,
				data,
				metadata,
				rotation,
				last_rotated_at,
				expires_at,
				created_at,
				updated_at
		`,
		namespace,
		name,
		status,
		dataRaw,
		metadataRaw,
		rotationRaw,
		req.ExpiresAt,
	)

	return scanManagedSecret(row)
}

// RotateManagedSecret replaces the secret payload of one existing secret and reactivates it.
func RotateManagedSecret(ctx context.Context, db *sql.DB, req model.RotateManagedSecretRequest) (model.ManagedSecret, error) {
	current, err := GetManagedSecret(ctx, db, model.GetManagedSecretRequest{
		Namespace: req.Namespace,
		Name:      req.Name,
	})
	if err != nil {
		return model.ManagedSecret{}, err
	}

	expiresAt := req.ExpiresAt
	if expiresAt == nil {
		expiresAt = current.ExpiresAt
	}

	return UpsertManagedSecret(ctx, db, model.UpsertManagedSecretRequest{
		Namespace: current.Namespace,
		Name:      current.Name,
		Status:    "active",
		Data:      req.Data,
		Metadata:  mergeJSONObject(current.Metadata, req.Metadata),
		Rotation:  normalizeManagedSecretRotation(req.Rotation, current.Rotation),
		ExpiresAt: expiresAt,
	})
}

// DisableManagedSecret marks one secret as disabled while preserving the stored material.
func DisableManagedSecret(ctx context.Context, db *sql.DB, req model.DisableManagedSecretRequest) (model.ManagedSecret, error) {
	return updateManagedSecretStatus(ctx, db, req.Namespace, req.Name, "disabled", nil, req.Metadata)
}

// RevokeManagedSecret marks one secret as revoked and clears the stored material.
func RevokeManagedSecret(ctx context.Context, db *sql.DB, req model.RevokeManagedSecretRequest) (model.ManagedSecret, error) {
	return updateManagedSecretStatus(ctx, db, req.Namespace, req.Name, "revoked", map[string]string{}, req.Metadata)
}

// GetManagedSecret fetches one secret by namespace and name.
func GetManagedSecret(ctx context.Context, db *sql.DB, req model.GetManagedSecretRequest) (model.ManagedSecret, error) {
	namespace := normalizeManagedSecretNamespace(req.Namespace)
	name := normalizeManagedSecretName(req.Name)
	if name == "" {
		return model.ManagedSecret{}, fmt.Errorf("secret name is required")
	}

	row := db.QueryRowContext(
		ctx,
		`
			SELECT
				id,
				namespace,
				name,
				status,
				version,
				data,
				metadata,
				rotation,
				last_rotated_at,
				expires_at,
				created_at,
				updated_at
			FROM public.managed_secrets
			WHERE namespace = $1
				AND name = $2
		`,
		namespace,
		name,
	)

	secret, err := scanManagedSecret(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return model.ManagedSecret{}, ErrManagedSecretNotFound
		}
		return model.ManagedSecret{}, err
	}
	return secret, nil
}

// ListManagedSecrets returns secrets matching the provided filters.
func ListManagedSecrets(ctx context.Context, db *sql.DB, req model.ListManagedSecretsRequest) ([]model.ManagedSecret, error) {
	query := `
		SELECT
			id,
			namespace,
			name,
			status,
			version,
			data,
			metadata,
			rotation,
			last_rotated_at,
			expires_at,
			created_at,
			updated_at
		FROM public.managed_secrets
	`

	var (
		clauses []string
		args    []any
	)

	if namespace := normalizeManagedSecretNamespace(req.Namespace); namespace != "global" || strings.TrimSpace(req.Namespace) != "" {
		args = append(args, namespace)
		clauses = append(clauses, fmt.Sprintf("namespace = $%d", len(args)))
	}
	if status := normalizeManagedSecretStatus(req.Status); status != "" {
		args = append(args, status)
		clauses = append(clauses, fmt.Sprintf("status = $%d", len(args)))
	}
	if len(clauses) > 0 {
		query += " WHERE " + strings.Join(clauses, " AND ")
	}
	query += " ORDER BY namespace, name"

	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	items := make([]model.ManagedSecret, 0)
	for rows.Next() {
		item, err := scanManagedSecret(rows)
		if err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return items, nil
}

func updateManagedSecretStatus(
	ctx context.Context,
	db *sql.DB,
	namespaceRaw string,
	nameRaw string,
	status string,
	data map[string]string,
	metadata map[string]any,
) (model.ManagedSecret, error) {
	current, err := GetManagedSecret(ctx, db, model.GetManagedSecretRequest{
		Namespace: namespaceRaw,
		Name:      nameRaw,
	})
	if err != nil {
		return model.ManagedSecret{}, err
	}

	status = normalizeManagedSecretStatus(status)
	if status == "" {
		return model.ManagedSecret{}, fmt.Errorf("secret status is required")
	}

	var (
		dataRaw     []byte
		metadataRaw []byte
	)
	if data == nil {
		data = current.Data
	}
	dataRaw, err = marshalStringMap(data)
	if err != nil {
		return model.ManagedSecret{}, err
	}
	metadataRaw, err = marshalJSONObject(mergeJSONObject(current.Metadata, metadata))
	if err != nil {
		return model.ManagedSecret{}, err
	}

	row := db.QueryRowContext(
		ctx,
		`
			UPDATE public.managed_secrets
			SET
				status = $3,
				data = $4::jsonb,
				metadata = $5::jsonb,
				version = CASE
					WHEN public.managed_secrets.data IS DISTINCT FROM $4::jsonb
						THEN public.managed_secrets.version + 1
					ELSE public.managed_secrets.version
				END,
				last_rotated_at = CASE
					WHEN public.managed_secrets.data IS DISTINCT FROM $4::jsonb
						THEN NOW()
					ELSE public.managed_secrets.last_rotated_at
				END,
				updated_at = NOW()
			WHERE namespace = $1
				AND name = $2
			RETURNING
				id,
				namespace,
				name,
				status,
				version,
				data,
				metadata,
				rotation,
				last_rotated_at,
				expires_at,
				created_at,
				updated_at
		`,
		current.Namespace,
		current.Name,
		status,
		dataRaw,
		metadataRaw,
	)

	secret, err := scanManagedSecret(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return model.ManagedSecret{}, ErrManagedSecretNotFound
		}
		return model.ManagedSecret{}, err
	}
	return secret, nil
}

// ResolveSecretRef resolves one secret:// reference into its stored value.
func ResolveSecretRef(ctx context.Context, db *sql.DB, ref string) (any, error) {
	namespace, name, key, err := parseSecretRef(ref)
	if err != nil {
		return nil, err
	}

	secret, err := GetManagedSecret(ctx, db, model.GetManagedSecretRequest{
		Namespace: namespace,
		Name:      name,
	})
	if err != nil {
		return nil, err
	}
	if strings.ToLower(strings.TrimSpace(secret.Status)) != "active" {
		return nil, fmt.Errorf("secret %s/%s is not active", secret.Namespace, secret.Name)
	}
	if secret.IsExpired(time.Now().UTC()) {
		return nil, fmt.Errorf("secret %s/%s is expired", secret.Namespace, secret.Name)
	}

	if key != "" {
		value, ok := secret.Data[key]
		if !ok {
			return nil, fmt.Errorf("secret %s/%s does not define key %q", secret.Namespace, secret.Name, key)
		}
		return value, nil
	}
	if len(secret.Data) == 1 {
		for _, value := range secret.Data {
			return value, nil
		}
	}

	output := make(map[string]any, len(secret.Data))
	for name, value := range secret.Data {
		output[name] = value
	}
	return output, nil
}

// ResolveSecretObjectRef resolves one secret:// reference into an object map.
// Unlike ResolveSecretRef, this never collapses single-key secrets into a
// scalar when the reference targets the whole secret.
func ResolveSecretObjectRef(ctx context.Context, db *sql.DB, ref string) (map[string]any, error) {
	namespace, name, key, err := parseSecretRef(ref)
	if err != nil {
		return nil, err
	}
	if key != "" {
		return nil, fmt.Errorf("secret object ref %q must not target an individual key", ref)
	}

	secret, err := GetManagedSecret(ctx, db, model.GetManagedSecretRequest{
		Namespace: namespace,
		Name:      name,
	})
	if err != nil {
		return nil, err
	}
	if strings.ToLower(strings.TrimSpace(secret.Status)) != "active" {
		return nil, fmt.Errorf("secret %s/%s is not active", secret.Namespace, secret.Name)
	}
	if secret.IsExpired(time.Now().UTC()) {
		return nil, fmt.Errorf("secret %s/%s is expired", secret.Namespace, secret.Name)
	}

	output := make(map[string]any, len(secret.Data))
	for itemKey, value := range secret.Data {
		output[itemKey] = value
	}
	return output, nil
}

// ResolveSecretRefs recursively resolves secret:// references from arbitrary input.
func ResolveSecretRefs(ctx context.Context, db *sql.DB, input any) (any, error) {
	switch value := input.(type) {
	case nil:
		return nil, nil
	case string:
		if !strings.HasPrefix(strings.TrimSpace(value), "secret://") {
			return value, nil
		}
		return ResolveSecretRef(ctx, db, value)
	case []any:
		resolved := make([]any, 0, len(value))
		for _, item := range value {
			next, err := ResolveSecretRefs(ctx, db, item)
			if err != nil {
				return nil, err
			}
			resolved = append(resolved, next)
		}
		return resolved, nil
	case map[string]any:
		resolved := make(map[string]any, len(value))
		keys := make([]string, 0, len(value))
		for key := range value {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			item := value[key]
			next, err := ResolveSecretRefs(ctx, db, item)
			if err != nil {
				return nil, err
			}
			resolved[key] = next
		}
		return resolved, nil
	default:
		return value, nil
	}
}

func parseSecretRef(ref string) (namespace string, name string, key string, err error) {
	ref = strings.TrimSpace(ref)
	if !strings.HasPrefix(ref, "secret://") {
		return "", "", "", fmt.Errorf("secret ref %q must use secret://", ref)
	}

	target := strings.TrimPrefix(ref, "secret://")
	parts := strings.SplitN(target, "#", 2)
	pathPart := strings.Trim(parts[0], "/")
	if len(parts) == 2 {
		key = strings.TrimSpace(parts[1])
	}

	pathSegments := strings.Split(pathPart, "/")
	if len(pathSegments) < 2 {
		return "", "", "", fmt.Errorf("secret ref %q must use secret://<namespace>/<name>[#key]", ref)
	}

	namespace = strings.ToLower(strings.TrimSpace(pathSegments[0]))
	name = strings.ToLower(strings.TrimSpace(strings.Join(pathSegments[1:], "/")))
	if namespace == "" || name == "" {
		return "", "", "", fmt.Errorf("secret ref %q must use secret://<namespace>/<name>[#key]", ref)
	}

	return namespace, name, key, nil
}

func scanManagedSecret(row scanner) (model.ManagedSecret, error) {
	var (
		secret       model.ManagedSecret
		dataRaw      []byte
		metadataRaw  []byte
		rotationRaw  []byte
		expiresAtRaw sql.NullTime
	)

	if err := row.Scan(
		&secret.ID,
		&secret.Namespace,
		&secret.Name,
		&secret.Status,
		&secret.Version,
		&dataRaw,
		&metadataRaw,
		&rotationRaw,
		&secret.LastRotatedAt,
		&expiresAtRaw,
		&secret.CreatedAt,
		&secret.UpdatedAt,
	); err != nil {
		return model.ManagedSecret{}, err
	}

	data, err := unmarshalStringMap(dataRaw)
	if err != nil {
		return model.ManagedSecret{}, err
	}
	metadata, err := unmarshalJSONObject(metadataRaw)
	if err != nil {
		return model.ManagedSecret{}, err
	}
	rotation, err := unmarshalSecretRotationPolicy(rotationRaw)
	if err != nil {
		return model.ManagedSecret{}, err
	}

	secret.Data = data
	secret.Metadata = metadata
	secret.Rotation = rotation
	if expiresAtRaw.Valid {
		expiresAt := expiresAtRaw.Time.UTC()
		secret.ExpiresAt = &expiresAt
	}
	return secret, nil
}

func marshalStringMap(value map[string]string) ([]byte, error) {
	if value == nil {
		return []byte("{}"), nil
	}
	for key := range value {
		if strings.TrimSpace(key) == "" {
			return nil, fmt.Errorf("object keys cannot be empty")
		}
	}
	return jsonMarshal(value)
}

func unmarshalStringMap(raw []byte) (map[string]string, error) {
	if len(raw) == 0 {
		return map[string]string{}, nil
	}
	output := map[string]string{}
	if err := jsonUnmarshal(raw, &output); err != nil {
		return nil, err
	}
	return output, nil
}

func marshalSecretRotationPolicy(value model.ManagedSecretRotationPolicy) ([]byte, error) {
	return jsonMarshal(value)
}

func unmarshalSecretRotationPolicy(raw []byte) (model.ManagedSecretRotationPolicy, error) {
	if len(raw) == 0 {
		return model.ManagedSecretRotationPolicy{}, nil
	}
	var output model.ManagedSecretRotationPolicy
	if err := jsonUnmarshal(raw, &output); err != nil {
		return model.ManagedSecretRotationPolicy{}, err
	}
	return output, nil
}

func validateManagedSecretRotation(rotation model.ManagedSecretRotationPolicy) error {
	mode := strings.ToLower(strings.TrimSpace(rotation.Mode))
	switch mode {
	case "", "manual", "scheduled":
	default:
		return fmt.Errorf("secret rotation mode %q is unsupported", rotation.Mode)
	}
	if rotation.RotateAfterDays < 0 {
		return fmt.Errorf("secret rotation rotate_after_days cannot be negative")
	}
	if mode == "scheduled" && rotation.RotateAfterDays <= 0 {
		return fmt.Errorf("secret rotation mode %q requires rotate_after_days", rotation.Mode)
	}
	return nil
}

func normalizeManagedSecretNamespace(namespace string) string {
	namespace = strings.ToLower(strings.TrimSpace(namespace))
	if namespace == "" {
		return "global"
	}
	return namespace
}

func normalizeManagedSecretName(name string) string {
	return strings.ToLower(strings.TrimSpace(name))
}

func normalizeManagedSecretStatus(status string) string {
	return strings.ToLower(strings.TrimSpace(status))
}

func normalizeManagedSecretRotation(
	next model.ManagedSecretRotationPolicy,
	current model.ManagedSecretRotationPolicy,
) model.ManagedSecretRotationPolicy {
	if strings.TrimSpace(next.Mode) == "" && next.RotateAfterDays == 0 {
		return current
	}
	return next
}

func mergeJSONObject(base map[string]any, extra map[string]any) map[string]any {
	if len(base) == 0 && len(extra) == 0 {
		return nil
	}
	out := make(map[string]any, len(base)+len(extra))
	for key, value := range base {
		out[key] = value
	}
	for key, value := range extra {
		out[key] = value
	}
	return out
}

func jsonMarshal(value any) ([]byte, error) {
	return json.Marshal(value)
}

func jsonUnmarshal(raw []byte, dst any) error {
	return json.Unmarshal(raw, dst)
}
