package repository

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"
)

var permissionCatalogColumns = []string{"type_ref", "candidates"}

func newPermissionCatalogMock(t *testing.T) (sqlmock.Sqlmock, func() ([]string, error)) {
	t.Helper()
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherEqual))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return mock, func() ([]string, error) {
		return ListIntegrationInstancePermissionActions(context.Background(), db, "dakasa", "tartaro-dakasa-validation")
	}
}

func catalogCandidate(id uuid.UUID, namespace, name string, version int, catalog string) string {
	return fmt.Sprintf(`{"id":"%s","namespace":"%s","name":"%s","version":%d,"action_catalog":%s}`, id, namespace, name, version, catalog)
}

func catalogRows(typeRef string, candidates ...string) *sqlmock.Rows {
	return sqlmock.NewRows(permissionCatalogColumns).
		AddRow([]byte(typeRef), []byte("["+strings.Join(candidates, ",")+"]"))
}

func TestListIntegrationInstancePermissionActionsReturnsSortedPermissionNames(t *testing.T) {
	mock, list := newPermissionCatalogMock(t)
	catalog := `[
		{"name":"tartaro:suspend_user","category":"permission"},
		{"name":"tartaro:read_user","category":"permission","idempotent":true},
		{"name":" tartaro:read_user ","category":"permission"},
		{"name":"*","category":"permission"},
		{"name":"  ","category":"permission"},
		{"name":"tartaro:uppercase_category","category":"Permission"},
		{"name":"on_collaborator_session_terminated","category":"reactor"},
		{"name":"observe_collaborator","category":"capability"},
		{"name":"observe_collaborators"}
	]`
	mock.ExpectQuery(integrationInstancePermissionCatalogQuery).WithArgs("dakasa", "tartaro-dakasa-validation").
		WillReturnRows(catalogRows(`{"namespace":"dakasa","name":"tartaro-dakasa"}`,
			catalogCandidate(uuid.New(), "dakasa", "tartaro-dakasa", 7, catalog)))

	actions, err := list()
	if err != nil {
		t.Fatal(err)
	}
	if got := fmt.Sprint(actions); got != "[tartaro:read_user tartaro:suspend_user]" {
		t.Fatalf("actions=%s, want only the distinct exact permission names", got)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestListIntegrationInstancePermissionActionsSelectsTheTypeLikeTheIdentityResolver(t *testing.T) {
	typeID := uuid.New()
	for _, test := range []struct {
		name       string
		typeRef    string
		candidates []string
	}{
		{
			name:    "namespace defaults to global and the name is normalized",
			typeRef: `{"name":" Tartaro-Dakasa "}`,
			candidates: []string{
				catalogCandidate(uuid.New(), "dakasa", "tartaro-dakasa", 1, `[{"name":"wrong","category":"permission"}]`),
				catalogCandidate(uuid.New(), "global", "tartaro-dakasa", 2, `[{"name":"right","category":"permission"}]`),
			},
		},
		{
			name:    "pinned version",
			typeRef: `{"namespace":"dakasa","name":"tartaro-dakasa","version":4}`,
			candidates: []string{
				catalogCandidate(uuid.New(), "dakasa", "tartaro-dakasa", 3, `[{"name":"wrong","category":"permission"}]`),
				catalogCandidate(uuid.New(), "dakasa", "tartaro-dakasa", 4, `[{"name":"right","category":"permission"}]`),
			},
		},
		{
			name:    "manifest id wins over a name",
			typeRef: `{"manifest_id":"` + typeID.String() + `","name":"tartaro-dakasa"}`,
			candidates: []string{
				catalogCandidate(uuid.New(), "global", "tartaro-dakasa", 1, `[{"name":"wrong","category":"permission"}]`),
				catalogCandidate(typeID, "dakasa", "renamed-type", 9, `[{"name":"right","category":"permission"}]`),
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			mock, list := newPermissionCatalogMock(t)
			mock.ExpectQuery(integrationInstancePermissionCatalogQuery).WithArgs("dakasa", "tartaro-dakasa-validation").
				WillReturnRows(catalogRows(test.typeRef, test.candidates...))
			actions, err := list()
			if err != nil || fmt.Sprint(actions) != "[right]" {
				t.Fatalf("actions=%v err=%v", actions, err)
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestListIntegrationInstancePermissionActionsEmptyCatalogIsNotAnError(t *testing.T) {
	mock, list := newPermissionCatalogMock(t)
	mock.ExpectQuery(integrationInstancePermissionCatalogQuery).WithArgs("dakasa", "tartaro-dakasa-validation").
		WillReturnRows(catalogRows(`{"namespace":"dakasa","name":"tartaro-dakasa"}`,
			catalogCandidate(uuid.New(), "dakasa", "tartaro-dakasa", 1, `[]`)))
	actions, err := list()
	if err != nil || actions == nil || len(actions) != 0 {
		t.Fatalf("actions=%v err=%v, want an empty non-nil list", actions, err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestListIntegrationInstancePermissionActionsNotResolvableCases(t *testing.T) {
	for _, test := range []struct {
		name string
		rows *sqlmock.Rows
	}{
		{name: "no active instance version", rows: sqlmock.NewRows(permissionCatalogColumns)},
		{name: "missing type_ref", rows: sqlmock.NewRows(permissionCatalogColumns).AddRow(nil, []byte(`[]`))},
		{name: "unreadable type_ref", rows: catalogRows(`"tartaro-dakasa"`)},
		{name: "no active type candidate", rows: catalogRows(`{"namespace":"dakasa","name":"tartaro-dakasa"}`)},
		{name: "candidate of another namespace", rows: catalogRows(`{"namespace":"dakasa","name":"tartaro-dakasa"}`,
			catalogCandidate(uuid.New(), "global", "tartaro-dakasa", 1, `[{"name":"tartaro:read_user","category":"permission"}]`))},
		{name: "pinned version that is not active", rows: catalogRows(`{"namespace":"dakasa","name":"tartaro-dakasa","version":2}`,
			catalogCandidate(uuid.New(), "dakasa", "tartaro-dakasa", 3, `[{"name":"tartaro:read_user","category":"permission"}]`))},
		{name: "malformed manifest id", rows: catalogRows(`{"manifest_id":"not-a-uuid","name":"tartaro-dakasa"}`,
			catalogCandidate(uuid.New(), "global", "tartaro-dakasa", 1, `[{"name":"tartaro:read_user","category":"permission"}]`))},
	} {
		t.Run(test.name, func(t *testing.T) {
			mock, list := newPermissionCatalogMock(t)
			mock.ExpectQuery(integrationInstancePermissionCatalogQuery).WithArgs("dakasa", "tartaro-dakasa-validation").WillReturnRows(test.rows)
			actions, err := list()
			if !errors.Is(err, ErrIntegrationInstanceNotResolvable) || actions != nil {
				t.Fatalf("actions=%v err=%v, want ErrIntegrationInstanceNotResolvable", actions, err)
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestListIntegrationInstancePermissionActionsSurfacesReadAndDecodeFailures(t *testing.T) {
	t.Run("database", func(t *testing.T) {
		mock, list := newPermissionCatalogMock(t)
		driverErr := errors.New("pq: connection refused")
		mock.ExpectQuery(integrationInstancePermissionCatalogQuery).WithArgs("dakasa", "tartaro-dakasa-validation").WillReturnError(driverErr)
		if _, err := list(); !errors.Is(err, driverErr) {
			t.Fatalf("err=%v, want the driver error", err)
		}
	})
	t.Run("catalog that is not a list", func(t *testing.T) {
		mock, list := newPermissionCatalogMock(t)
		mock.ExpectQuery(integrationInstancePermissionCatalogQuery).WithArgs("dakasa", "tartaro-dakasa-validation").
			WillReturnRows(catalogRows(`{"namespace":"dakasa","name":"tartaro-dakasa"}`,
				catalogCandidate(uuid.New(), "dakasa", "tartaro-dakasa", 1, `{"name":"tartaro:read_user"}`)))
		if _, err := list(); err == nil || errors.Is(err, ErrIntegrationInstanceNotResolvable) {
			t.Fatalf("err=%v, want a decoding error", err)
		}
	})
}

// The catalog resolver must select its type with the same candidate predicate
// as the ADR-0021 identity resolver, stay one read-only statement, and read
// only the active instance version.
func TestIntegrationInstancePermissionCatalogQueryPinsItsPredicates(t *testing.T) {
	query := integrationInstancePermissionCatalogQuery
	for _, fragment := range []string{
		"LEFT JOIN LATERAL",
		"ty.kind = 'integration_type'",
		"AND ty.active = TRUE",
		"ty.id::text = lower(btrim(a.spec -> 'type_ref' ->> 'manifest_id'))",
		"OR ty.name = lower(btrim(a.spec -> 'type_ref' ->> 'name'))",
		"COALESCE(t.candidates, '[]'::jsonb)",
		"'action_catalog', COALESCE(ty.spec -> 'action_catalog', '[]'::jsonb)",
		"a.kind = 'integration_instance'",
		"AND a.namespace = $1",
		"AND a.name = $2",
		"AND a.active = TRUE",
	} {
		if !strings.Contains(query, fragment) {
			t.Fatalf("query lost %q:\n%s", fragment, query)
		}
	}
	upper := strings.ToUpper(query)
	for _, write := range []string{"INSERT", "UPDATE", "DELETE"} {
		if strings.Contains(upper, write) {
			t.Fatalf("catalog resolution must be read-only:\n%s", query)
		}
	}
	if strings.Count(query, "SELECT") != 2 {
		t.Fatalf("catalog resolution must stay one statement with one type subquery:\n%s", query)
	}
}
