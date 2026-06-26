package surface

import (
	"context"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
)

func TestReconcile_InsertsPermissions(t *testing.T) {
	db, mock, _ := sqlmock.New()
	defer db.Close()

	mock.ExpectBegin()
	mock.ExpectExec("DELETE FROM public.permissions_catalog").
		WithArgs("heimdall").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec("INSERT INTO public.permissions_catalog").
		WithArgs("heimdall.pulses.read", "Ver pulses", "heimdall").
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectExec("INSERT INTO public.permissions_catalog").
		WithArgs("heimdall.pulses.trigger", "Disparar pulse manualmente", "heimdall").
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectCommit()

	r := NewPermissionsReconciler(db, nil)
	err := r.Reconcile(context.Background(), "heimdall", []SurfacePerm{
		{ID: "heimdall.pulses.read", Label: "Ver pulses"},
		{ID: "heimdall.pulses.trigger", Label: "Disparar pulse manualmente"},
	})
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

// TestReconcile_UpsertsOnNameConflict pins the idempotency fix: the INSERT must
// be an ON CONFLICT (name) DO UPDATE upsert so that a permission name already
// present in the catalog (registered by another surface / a bootstrap path) does
// not blow up the whole reconcile with a unique-constraint violation (23505) on
// every tick. Without the upsert clause this expectation's regex would not match
// the emitted query and the test fails.
func TestReconcile_UpsertsOnNameConflict(t *testing.T) {
	db, mock, _ := sqlmock.New()
	defer db.Close()

	mock.ExpectBegin()
	mock.ExpectExec("DELETE FROM public.permissions_catalog").
		WithArgs("github").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec(`ON CONFLICT \(name\) DO UPDATE`).
		WithArgs("github.teams.write", "Write teams", "github").
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectCommit()

	r := NewPermissionsReconciler(db, nil)
	err := r.Reconcile(context.Background(), "github", []SurfacePerm{
		{ID: "github.teams.write", Label: "Write teams"},
	})
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestReconcile_NoPermissionsClears(t *testing.T) {
	db, mock, _ := sqlmock.New()
	defer db.Close()

	mock.ExpectBegin()
	mock.ExpectExec("DELETE FROM public.permissions_catalog").
		WithArgs("ghost").
		WillReturnResult(sqlmock.NewResult(0, 3))
	mock.ExpectCommit()

	r := NewPermissionsReconciler(db, nil)
	if err := r.Reconcile(context.Background(), "ghost", nil); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}
