package repository

import (
	"context"
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
