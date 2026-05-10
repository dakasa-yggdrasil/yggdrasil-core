package repository

import (
	"context"
	"database/sql"
	"os"
	"testing"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	_ "github.com/lib/pq"
)

func dbForPermissionsTest(t *testing.T) *sql.DB {
	t.Helper()
	dsn := os.Getenv("DB_URL")
	if dsn == "" {
		t.Skip("DB_URL not set; skipping permissions_catalog integration test")
	}
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	if err := db.Ping(); err != nil {
		t.Fatalf("ping db: %v", err)
	}
	return db
}

func cleanPermissions(t *testing.T, db *sql.DB) {
	t.Helper()
	if _, err := db.Exec(`DELETE FROM public.role_permission_bindings`); err != nil {
		t.Fatalf("clean bindings: %v", err)
	}
	if _, err := db.Exec(`DELETE FROM public.permissions_catalog`); err != nil {
		t.Fatalf("clean catalog: %v", err)
	}
}

func TestRegisterPermission_Idempotent(t *testing.T) {
	db := dbForPermissionsTest(t)
	defer func() { _ = db.Close() }()
	cleanPermissions(t, db)

	ctx := context.Background()
	first, err := RegisterPermission(ctx, db, model.RegisterPermissionRequest{
		Name:         "clt:vacation:request-own",
		Description:  "Request own vacation",
		RegisteredBy: "integration-employment-clt",
	})
	if err != nil {
		t.Fatalf("RegisterPermission first: %v", err)
	}

	second, err := RegisterPermission(ctx, db, model.RegisterPermissionRequest{
		Name:         "clt:vacation:request-own",
		Description:  "Request own vacation (updated)",
		RegisteredBy: "integration-employment-clt",
	})
	if err != nil {
		t.Fatalf("RegisterPermission second: %v", err)
	}
	if first.ID != second.ID {
		t.Fatalf("expected same ID on second call, got %v != %v", first.ID, second.ID)
	}
	if second.Description != "Request own vacation (updated)" {
		t.Fatalf("expected description updated, got %q", second.Description)
	}
}

func TestBindRoleToPermission_AndEvaluate(t *testing.T) {
	db := dbForPermissionsTest(t)
	defer func() { _ = db.Close() }()
	cleanPermissions(t, db)

	ctx := context.Background()
	if _, err := RegisterPermission(ctx, db, model.RegisterPermissionRequest{
		Name:         "clt:vacation:request-own",
		RegisteredBy: "integration-employment-clt",
	}); err != nil {
		t.Fatalf("seed permission: %v", err)
	}
	if _, err := BindRoleToPermission(ctx, db, model.BindRoleToPermissionRequest{
		Role:           "engineer",
		PermissionName: "clt:vacation:request-own",
		BoundBy:        "tenant-config",
	}); err != nil {
		t.Fatalf("BindRoleToPermission: %v", err)
	}

	resp, err := EvaluatePermission(ctx, db, model.EvaluatePermissionRequest{
		SubjectRole: "engineer",
		Permission:  "clt:vacation:request-own",
	})
	if err != nil {
		t.Fatalf("EvaluatePermission: %v", err)
	}
	if !resp.Allowed {
		t.Fatalf("expected allowed=true, got false")
	}
	if resp.MatchedRole != "engineer" {
		t.Fatalf("expected matched_role=engineer, got %q", resp.MatchedRole)
	}
}

func TestEvaluatePermission_DeniesUnboundRole(t *testing.T) {
	db := dbForPermissionsTest(t)
	defer func() { _ = db.Close() }()
	cleanPermissions(t, db)

	ctx := context.Background()
	if _, err := RegisterPermission(ctx, db, model.RegisterPermissionRequest{
		Name:         "core:collaborators:offboard",
		RegisteredBy: "yggdrasil-core",
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}

	resp, err := EvaluatePermission(ctx, db, model.EvaluatePermissionRequest{
		SubjectRole: "engineer",
		Permission:  "core:collaborators:offboard",
	})
	if err != nil {
		t.Fatalf("EvaluatePermission: %v", err)
	}
	if resp.Allowed {
		t.Fatalf("expected allowed=false for unbound role, got true")
	}
}

func TestEvaluatePermission_AllowsWildcardBindings(t *testing.T) {
	db := dbForPermissionsTest(t)
	defer func() { _ = db.Close() }()
	cleanPermissions(t, db)

	ctx := context.Background()
	for _, name := range []string{"google_workspace.*", "google_workspace.users.write"} {
		if _, err := RegisterPermission(ctx, db, model.RegisterPermissionRequest{
			Name:         name,
			RegisteredBy: "yggdrasil-core",
		}); err != nil {
			t.Fatalf("seed %s: %v", name, err)
		}
	}
	if _, err := BindRoleToPermission(ctx, db, model.BindRoleToPermissionRequest{
		Role:           "ceo",
		PermissionName: "google_workspace.*",
	}); err != nil {
		t.Fatalf("bind wildcard: %v", err)
	}

	resp, err := EvaluatePermission(ctx, db, model.EvaluatePermissionRequest{
		SubjectRole: "ceo",
		Permission:  "google_workspace.users.write",
	})
	if err != nil {
		t.Fatalf("EvaluatePermission: %v", err)
	}
	if !resp.Allowed {
		t.Fatalf("expected wildcard binding to allow permission")
	}
}

func TestEvaluatePermission_AllowsTeamRoleBindings(t *testing.T) {
	db := dbForPermissionsTest(t)
	defer func() { _ = db.Close() }()
	cleanPermissions(t, db)

	ctx := context.Background()
	for _, name := range []string{"tartaro:*", "tartaro:admin:create"} {
		if _, err := RegisterPermission(ctx, db, model.RegisterPermissionRequest{
			Name:         name,
			RegisteredBy: "integration-tartaro",
		}); err != nil {
			t.Fatalf("seed %s: %v", name, err)
		}
	}
	if _, err := BindRoleToPermission(ctx, db, model.BindRoleToPermissionRequest{
		Role:           "team:admin-tartaro",
		PermissionName: "tartaro:*",
	}); err != nil {
		t.Fatalf("bind team wildcard: %v", err)
	}

	resp, err := EvaluatePermission(ctx, db, model.EvaluatePermissionRequest{
		SubjectRole:  "cmo",
		SubjectTeams: []string{"admin-tartaro"},
		Permission:   "tartaro:admin:create",
	})
	if err != nil {
		t.Fatalf("EvaluatePermission: %v", err)
	}
	if !resp.Allowed || resp.MatchedRole != "team:admin-tartaro" {
		t.Fatalf("expected team binding, got %+v", resp)
	}
}

func TestBindRoleToPermission_IdempotentOnDuplicate(t *testing.T) {
	db := dbForPermissionsTest(t)
	defer func() { _ = db.Close() }()
	cleanPermissions(t, db)

	ctx := context.Background()
	if _, err := RegisterPermission(ctx, db, model.RegisterPermissionRequest{
		Name:         "core:teams:manage",
		RegisteredBy: "yggdrasil-core",
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	first, err := BindRoleToPermission(ctx, db, model.BindRoleToPermissionRequest{
		Role:           "admin",
		PermissionName: "core:teams:manage",
	})
	if err != nil {
		t.Fatalf("first bind: %v", err)
	}
	second, err := BindRoleToPermission(ctx, db, model.BindRoleToPermissionRequest{
		Role:           "admin",
		PermissionName: "core:teams:manage",
	})
	if err != nil {
		t.Fatalf("second bind: %v", err)
	}
	if first.ID != second.ID {
		t.Fatalf("expected idempotent (same ID), got %v != %v", first.ID, second.ID)
	}
}

func TestListPermissions_FiltersByRegisteredBy(t *testing.T) {
	db := dbForPermissionsTest(t)
	defer func() { _ = db.Close() }()
	cleanPermissions(t, db)

	ctx := context.Background()
	for _, p := range []model.RegisterPermissionRequest{
		{Name: "clt:vacation:request-own", RegisteredBy: "integration-employment-clt"},
		{Name: "clt:paystub:view-own", RegisteredBy: "integration-employment-clt"},
		{Name: "core:collaborators:read", RegisteredBy: "yggdrasil-core"},
	} {
		if _, err := RegisterPermission(ctx, db, p); err != nil {
			t.Fatalf("seed %s: %v", p.Name, err)
		}
	}

	cltPerms, err := ListPermissions(ctx, db, model.ListPermissionsRequest{
		RegisteredBy: "integration-employment-clt",
	})
	if err != nil {
		t.Fatalf("ListPermissions: %v", err)
	}
	if len(cltPerms) != 2 {
		t.Fatalf("expected 2 clt permissions, got %d", len(cltPerms))
	}
}
