package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

func TestUpsertSurfaceManifest(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	m := model.SurfaceManifestRow{
		SurfaceID:       "heimdall",
		SurfaceVersion:  "1.0.0",
		SchemaVersion:   1,
		DisplayName:     "Heimdall",
		Icon:            "shield-check",
		Description:     "test",
		PageCount:       1,
		WidgetCount:     0,
		PermissionCount: 1,
		Raw:             json.RawMessage(`{"surface":"heimdall"}`),
		Health:          "ok",
		FetchedAt:       time.Now(),
	}

	mock.ExpectExec("INSERT INTO public.surface_manifests").
		WithArgs(
			m.SurfaceID, m.SurfaceVersion, m.SchemaVersion, m.DisplayName,
			m.Icon, m.Description, m.PageCount, m.WidgetCount, m.PermissionCount,
			[]byte(m.Raw), m.Health, sqlmock.AnyArg(),
		).
		WillReturnResult(sqlmock.NewResult(1, 1))

	if err := UpsertSurfaceManifest(context.Background(), db, m); err != nil {
		t.Fatalf("UpsertSurfaceManifest: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestListSurfaceManifests(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	rows := sqlmock.NewRows([]string{
		"surface_id", "surface_version", "schema_version", "display_name",
		"icon", "description", "page_count", "widget_count", "permission_count",
		"health", "fetched_at",
	}).
		AddRow("heimdall", "1.0.0", 1, "Heimdall", "shield-check", "ops", 4, 1, 4, "ok", time.Now()).
		AddRow("aws", "1.0.0", 1, "AWS", "cloud", "FinOps", 3, 1, 5, "ok", time.Now())

	mock.ExpectQuery("SELECT .* FROM public.surface_manifests").
		WillReturnRows(rows)

	got, err := ListSurfaceManifests(context.Background(), db)
	if err != nil {
		t.Fatalf("ListSurfaceManifests: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("len: %d", len(got))
	}
	if got[0].SurfaceID != "heimdall" {
		t.Errorf("first: %+v", got[0])
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestGetSurfaceManifest_NotFound(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	mock.ExpectQuery("SELECT .* FROM public.surface_manifests").
		WithArgs("missing").
		WillReturnRows(sqlmock.NewRows([]string{"surface_id"}))

	_, err = GetSurfaceManifest(context.Background(), db, "missing")
	if err != ErrSurfaceManifestNotFound {
		t.Errorf("err: got %v want ErrSurfaceManifestNotFound", err)
	}
}

func TestUpsertSurfaceRuntimeTarget(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	now := time.Now()
	rows := sqlmock.NewRows([]string{
		"surface_id", "base_url", "enabled", "description", "created_at", "updated_at",
	}).AddRow("github", "http://integration-github:8080", true, "GitHub Enterprise", now, now)

	mock.ExpectQuery("INSERT INTO public.surface_runtime_targets").
		WithArgs("github", "http://integration-github:8080", true, "GitHub Enterprise").
		WillReturnRows(rows)

	got, err := UpsertSurfaceRuntimeTarget(context.Background(), db, model.UpsertSurfaceRuntimeTargetRequest{
		SurfaceID:   " GitHub ",
		BaseURL:     "http://integration-github:8080/",
		Enabled:     true,
		Description: " GitHub Enterprise ",
	})
	if err != nil {
		t.Fatalf("UpsertSurfaceRuntimeTarget: %v", err)
	}
	if got.SurfaceID != "github" || got.BaseURL != "http://integration-github:8080" {
		t.Fatalf("target: %+v", got)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestListSurfaceRuntimeTargets(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	now := time.Now()
	rows := sqlmock.NewRows([]string{
		"surface_id", "base_url", "enabled", "description", "created_at", "updated_at",
	}).AddRow("github", "http://integration-github:8080", true, "GitHub Enterprise", now, now)

	mock.ExpectQuery("SELECT .* FROM public.surface_runtime_targets").
		WithArgs(false).
		WillReturnRows(rows)

	got, err := ListSurfaceRuntimeTargets(context.Background(), db, false)
	if err != nil {
		t.Fatalf("ListSurfaceRuntimeTargets: %v", err)
	}
	if len(got) != 1 || got[0].SurfaceID != "github" {
		t.Fatalf("targets: %+v", got)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestGetSurfaceRuntimeTarget_NotFound(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	mock.ExpectQuery("SELECT .* FROM public.surface_runtime_targets").
		WithArgs("missing").
		WillReturnError(sql.ErrNoRows)

	_, err = GetSurfaceRuntimeTarget(context.Background(), db, "missing")
	if err != ErrSurfaceRuntimeTargetNotFound {
		t.Errorf("err: got %v want ErrSurfaceRuntimeTargetNotFound", err)
	}
}

func TestDeleteSurfaceRuntimeTarget_NotFound(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	mock.ExpectExec("DELETE FROM public.surface_runtime_targets").
		WithArgs("missing").
		WillReturnResult(sqlmock.NewResult(0, 0))

	err = DeleteSurfaceRuntimeTarget(context.Background(), db, "missing")
	if err != ErrSurfaceRuntimeTargetNotFound {
		t.Errorf("err: got %v want ErrSurfaceRuntimeTargetNotFound", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}
