package surface

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
)

func TestDiscovery_UpsertsHealthyAdapter(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{
			"surface":"heimdall","surface_version":"1.0.0","schema_version":1,
			"display_name":"Heimdall","icon":"shield-check",
			"pages":[{"id":"pulses","path":"/pulses","title":"Pulses","view":{"kind":"table"}}],
			"permissions":[{"id":"heimdall.pulses.read","label":"Ver pulses"}]
		}`))
	}))
	defer srv.Close()

	db, mock, _ := sqlmock.New()
	defer db.Close()

	mock.ExpectExec("INSERT INTO public.surface_manifests").
		WithArgs(
			"heimdall", "1.0.0", 1, "Heimdall",
			"shield-check", "", 1, 0, 1,
			sqlmock.AnyArg(), "ok", sqlmock.AnyArg(),
		).
		WillReturnResult(sqlmock.NewResult(1, 1))

	d := NewDiscovery(db, NewClient(srv.Client()), nil)
	if err := d.RefreshOne(context.Background(), AdapterTarget{ID: "heimdall", BaseURL: srv.URL}); err != nil {
		t.Fatalf("RefreshOne: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestDiscovery_404Ignored(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "not found", http.StatusNotFound)
	}))
	defer srv.Close()

	db, _, _ := sqlmock.New()
	defer db.Close()

	d := NewDiscovery(db, NewClient(srv.Client()), nil)
	if err := d.RefreshOne(context.Background(), AdapterTarget{ID: "x", BaseURL: srv.URL}); err != nil {
		t.Fatalf("RefreshOne: %v", err)
	}
}

func TestDiscovery_RecordsCounts(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{
			"surface":"aws","surface_version":"1.0.0","schema_version":1,
			"display_name":"AWS","icon":"cloud",
			"pages":[
				{"id":"finops","path":"/finops","title":"FinOps","view":{"kind":"table"}},
				{"id":"audits","path":"/audits","title":"Audits","view":{"kind":"table"}}
			],
			"widgets":[{"id":"savings","target":"ops_home","view":{"kind":"stat-card"}}],
			"permissions":[{"id":"aws.finops.read","label":"Ver"}]
		}`))
	}))
	defer srv.Close()

	db, mock, _ := sqlmock.New()
	defer db.Close()
	mock.ExpectExec("INSERT INTO public.surface_manifests").
		WithArgs(
			"aws", "1.0.0", 1, "AWS",
			"cloud", "", 2, 1, 1,
			sqlmock.AnyArg(), "ok", sqlmock.AnyArg(),
		).
		WillReturnResult(sqlmock.NewResult(1, 1))

	d := NewDiscovery(db, NewClient(srv.Client()), nil)
	_ = d.RefreshOne(context.Background(), AdapterTarget{ID: "aws", BaseURL: srv.URL})
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}
