package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/lib/pq"
)

// ErrPermissionNotFound is returned when a permission name is not in
// the catalog.
var ErrPermissionNotFound = errors.New("permission not found in catalog")

// RegisterPermission upserts one entry in permissions_catalog. Idempotent
// on (name) — a second call with the same name updates description,
// registered_by, and metadata.
func RegisterPermission(ctx context.Context, db *sql.DB, req model.RegisterPermissionRequest) (model.Permission, error) {
	name := strings.TrimSpace(req.Name)
	if name == "" {
		return model.Permission{}, fmt.Errorf("permission name is required")
	}
	registeredBy := strings.TrimSpace(req.RegisteredBy)
	if registeredBy == "" {
		return model.Permission{}, fmt.Errorf("permission registered_by is required")
	}

	metadata, err := json.Marshal(req.Metadata)
	if err != nil {
		return model.Permission{}, fmt.Errorf("marshal metadata: %w", err)
	}
	if len(req.Metadata) == 0 {
		metadata = []byte(`{}`)
	}

	row := db.QueryRowContext(ctx, `
		INSERT INTO public.permissions_catalog (name, description, registered_by, metadata)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (name) DO UPDATE SET
			description   = EXCLUDED.description,
			registered_by = EXCLUDED.registered_by,
			metadata      = EXCLUDED.metadata,
			updated_at    = NOW()
		RETURNING id, name, description, registered_by, metadata, created_at, updated_at
	`, name, req.Description, registeredBy, metadata)

	return scanPermission(row)
}

// BindRoleToPermission upserts one row in role_permission_bindings.
// Idempotent on (role, permission_name).
func BindRoleToPermission(ctx context.Context, db *sql.DB, req model.BindRoleToPermissionRequest) (model.RoleBinding, error) {
	role := strings.TrimSpace(req.Role)
	if role == "" {
		return model.RoleBinding{}, fmt.Errorf("role is required")
	}
	permName := strings.TrimSpace(req.PermissionName)
	if permName == "" {
		return model.RoleBinding{}, fmt.Errorf("permission_name is required")
	}

	metadata, err := json.Marshal(req.Metadata)
	if err != nil {
		return model.RoleBinding{}, fmt.Errorf("marshal metadata: %w", err)
	}
	if len(req.Metadata) == 0 {
		metadata = []byte(`{}`)
	}

	row := db.QueryRowContext(ctx, `
		INSERT INTO public.role_permission_bindings (role, permission_name, bound_by, metadata)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (role, permission_name) DO UPDATE SET
			bound_by = EXCLUDED.bound_by,
			metadata = EXCLUDED.metadata
		RETURNING id, role, permission_name, bound_by, metadata, created_at
	`, role, permName, req.BoundBy, metadata)

	return scanRoleBinding(row)
}

// EvaluatePermission returns whether the subject's role grants the
// requested permission. Phase 1 evaluates against role only;
// team-based bindings are a future extension (the API accepts
// SubjectTeams but ignores them for now — handler can fan-out as
// teams binding lands).
func EvaluatePermission(ctx context.Context, db *sql.DB, req model.EvaluatePermissionRequest) (model.EvaluatePermissionResponse, error) {
	role := strings.TrimSpace(req.SubjectRole)
	permName := strings.TrimSpace(req.Permission)
	if role == "" || permName == "" {
		return model.EvaluatePermissionResponse{}, fmt.Errorf("subject_role and permission are required")
	}

	subjectRoles := permissionSubjectRoles(role, req.SubjectTeams)
	rows, err := db.QueryContext(ctx, `
		SELECT id::text, role, permission_name FROM public.role_permission_bindings
		WHERE role = ANY($1)
	`, pq.Array(subjectRoles))
	if err != nil {
		return model.EvaluatePermissionResponse{}, fmt.Errorf("evaluate permission: %w", err)
	}
	defer rows.Close()

	matches := []string{}
	matchedRole := ""
	for rows.Next() {
		var bindingID, bindingRole, bindingPermission string
		if err := rows.Scan(&bindingID, &bindingRole, &bindingPermission); err != nil {
			return model.EvaluatePermissionResponse{}, fmt.Errorf("scan role binding: %w", err)
		}
		if permissionMatchesBinding(permName, bindingPermission) {
			matches = append(matches, bindingID)
			if matchedRole == "" {
				matchedRole = bindingRole
			}
		}
	}
	if err := rows.Err(); err != nil {
		return model.EvaluatePermissionResponse{}, fmt.Errorf("evaluate permission rows: %w", err)
	}
	if len(matches) == 0 {
		return model.EvaluatePermissionResponse{Allowed: false}, nil
	}
	return model.EvaluatePermissionResponse{
		Allowed:         true,
		MatchedRole:     matchedRole,
		MatchedBindings: matches,
	}, nil
}

func permissionSubjectRoles(role string, teams []string) []string {
	seen := map[string]bool{}
	out := []string{}
	add := func(value string) {
		value = strings.TrimSpace(value)
		if value == "" || seen[value] {
			return
		}
		seen[value] = true
		out = append(out, value)
	}
	add(role)
	for _, team := range teams {
		team = strings.TrimSpace(team)
		add("team:" + team)
	}
	return out
}

func permissionMatchesBinding(requested, binding string) bool {
	requested = strings.TrimSpace(requested)
	binding = strings.TrimSpace(binding)
	if requested == "" || binding == "" {
		return false
	}
	if binding == "*" || binding == requested {
		return true
	}
	if strings.HasSuffix(binding, "*") {
		return strings.HasPrefix(requested, strings.TrimSuffix(binding, "*"))
	}
	return false
}

// ListPermissions returns the permissions catalog filtered optionally
// by registered_by and/or name prefix. Ordered by name asc.
func ListPermissions(ctx context.Context, db *sql.DB, req model.ListPermissionsRequest) ([]model.Permission, error) {
	args := []any{}
	q := `SELECT id, name, description, registered_by, metadata, created_at, updated_at
		FROM public.permissions_catalog WHERE 1=1`
	if rb := strings.TrimSpace(req.RegisteredBy); rb != "" {
		args = append(args, rb)
		q += fmt.Sprintf(" AND registered_by = $%d", len(args))
	}
	if np := strings.TrimSpace(req.NamePrefix); np != "" {
		args = append(args, np+"%")
		q += fmt.Sprintf(" AND name LIKE $%d", len(args))
	}
	q += " ORDER BY name ASC"

	rows, err := db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("list permissions: %w", err)
	}
	defer func() { _ = rows.Close() }()

	out := make([]model.Permission, 0)
	for rows.Next() {
		p, err := scanPermission(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// ListBindings returns role_permission_bindings filtered by role
// and/or permission_name. Ordered by (role, permission_name).
func ListBindings(ctx context.Context, db *sql.DB, req model.ListBindingsRequest) ([]model.RoleBinding, error) {
	args := []any{}
	q := `SELECT id, role, permission_name, bound_by, metadata, created_at
		FROM public.role_permission_bindings WHERE 1=1`
	if r := strings.TrimSpace(req.Role); r != "" {
		args = append(args, r)
		q += fmt.Sprintf(" AND role = $%d", len(args))
	}
	if pn := strings.TrimSpace(req.PermissionName); pn != "" {
		args = append(args, pn)
		q += fmt.Sprintf(" AND permission_name = $%d", len(args))
	}
	q += " ORDER BY role ASC, permission_name ASC"

	rows, err := db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("list bindings: %w", err)
	}
	defer func() { _ = rows.Close() }()

	out := make([]model.RoleBinding, 0)
	for rows.Next() {
		b, err := scanRoleBinding(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, rows.Err()
}

type permissionScanner interface {
	Scan(dest ...any) error
}

func scanPermission(s permissionScanner) (model.Permission, error) {
	var p model.Permission
	var metadata []byte
	if err := s.Scan(&p.ID, &p.Name, &p.Description, &p.RegisteredBy, &metadata, &p.CreatedAt, &p.UpdatedAt); err != nil {
		return model.Permission{}, fmt.Errorf("scan permission: %w", err)
	}
	if len(metadata) > 0 {
		_ = json.Unmarshal(metadata, &p.Metadata)
	} else {
		p.Metadata = map[string]any{}
	}
	return p, nil
}

func scanRoleBinding(s permissionScanner) (model.RoleBinding, error) {
	var b model.RoleBinding
	var metadata []byte
	if err := s.Scan(&b.ID, &b.Role, &b.PermissionName, &b.BoundBy, &metadata, &b.CreatedAt); err != nil {
		return model.RoleBinding{}, fmt.Errorf("scan role_binding: %w", err)
	}
	if len(metadata) > 0 {
		_ = json.Unmarshal(metadata, &b.Metadata)
	} else {
		b.Metadata = map[string]any{}
	}
	return b, nil
}
