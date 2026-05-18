package integrationsurfaces_test

import (
	"context"
	"database/sql"
	"os"
	"testing"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/integrationsurfaces"
	_ "github.com/lib/pq"
)

func openTestDB(t *testing.T) *sql.DB {
	t.Helper()
	dsn := os.Getenv("DB_URL")
	if dsn == "" {
		t.Skip("DB_URL not set; skipping integrationsurfaces integration test")
	}
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := db.Ping(); err != nil {
		t.Fatalf("ping: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func cleanup(t *testing.T, db *sql.DB, name string) {
	t.Helper()
	_, _ = db.Exec("DELETE FROM integration_surfaces WHERE name = $1", name)
}

func TestRepository_UpsertGetSoftDeleteByName(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)
	repo := integrationsurfaces.NewRepository(db)
	cleanup(t, db, "surface-test-a")
	t.Cleanup(func() { cleanup(t, db, "surface-test-a") })

	intType := "slack"
	m := integrationsurfaces.Manifest{
		Name:            "surface-test-a",
		IntegrationType: &intType,
		Category:        integrationsurfaces.CategoryIntegration,
		Spec: integrationsurfaces.ManifestSpec{
			Category: integrationsurfaces.CategoryIntegration,
			Runtime:  integrationsurfaces.Runtime{Kind: "spa", BasePath: "/s/test-a"},
			Display:  integrationsurfaces.Display{Title: "Test A", AppearsOn: []string{"ops-integrations"}},
		},
		Active: true,
	}
	if err := repo.Upsert(ctx, &m); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	if m.ID == "" {
		t.Fatal("expected ID populated after upsert")
	}

	got, err := repo.GetByName(ctx, "surface-test-a")
	if err != nil {
		t.Fatalf("GetByName: %v", err)
	}
	if got.Spec.Display.Title != "Test A" {
		t.Errorf("title = %q", got.Spec.Display.Title)
	}

	if err := repo.Deactivate(ctx, "surface-test-a"); err != nil {
		t.Fatalf("Deactivate: %v", err)
	}
	got, _ = repo.GetByName(ctx, "surface-test-a")
	if got.Active {
		t.Error("expected active=false after Deactivate")
	}
}

func TestRepository_List_FilterByAppearsOn(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)
	repo := integrationsurfaces.NewRepository(db)
	cleanup(t, db, "surface-test-b")
	cleanup(t, db, "surface-test-c")
	t.Cleanup(func() { cleanup(t, db, "surface-test-b"); cleanup(t, db, "surface-test-c") })

	mk := func(name string, slots []string) integrationsurfaces.Manifest {
		return integrationsurfaces.Manifest{
			Name:     name,
			Category: integrationsurfaces.CategoryIntegration,
			Spec: integrationsurfaces.ManifestSpec{
				Category: integrationsurfaces.CategoryIntegration,
				Display:  integrationsurfaces.Display{Title: name, AppearsOn: slots},
			},
			Active: true,
		}
	}
	a := mk("surface-test-b", []string{"ops-integrations", "console-home"})
	b := mk("surface-test-c", []string{"me"})
	_ = repo.Upsert(ctx, &a)
	_ = repo.Upsert(ctx, &b)

	items, err := repo.List(ctx, integrationsurfaces.ListFilter{AppearsOn: "ops-integrations"})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, m := range items {
		if m.Name == "surface-test-b" {
			found = true
		}
		if m.Name == "surface-test-c" {
			t.Errorf("surface-test-c should not match appears_on=ops-integrations")
		}
	}
	if !found {
		t.Error("surface-test-b not in results")
	}
}
