package repository

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"
)

func newIdentityMock(t *testing.T) (sqlmock.Sqlmock, func() (IntegrationInstanceIdentity, error), uuid.UUID) {
	t.Helper()
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherEqual))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	wire := uuid.New()
	return mock, func() (IntegrationInstanceIdentity, error) {
		return ResolveIntegrationInstanceByManifestID(context.Background(), db, wire)
	}, wire
}

func instanceRows(activeID uuid.UUID, typeRef string) *sqlmock.Rows {
	return sqlmock.NewRows([]string{"id", "namespace", "name", "version", "type_ref"}).
		AddRow(activeID, "dakasa", "kubernetes-dakasa-production", 51, []byte(typeRef))
}

func TestResolveIntegrationInstanceByManifestIDReturnsTheActiveVersionAndTypeProvider(t *testing.T) {
	mock, resolve, wire := newIdentityMock(t)
	activeID := uuid.New()
	mock.ExpectQuery(resolveIntegrationInstanceByManifestIDQuery).WithArgs(wire).
		WillReturnRows(instanceRows(activeID, `{"namespace":"global","name":"kubernetes"}`))
	mock.ExpectQuery(resolveIntegrationTypeProviderByNameQuery).WithArgs("global", "kubernetes").
		WillReturnRows(sqlmock.NewRows([]string{"provider"}).AddRow("kubernetes"))

	identity, err := resolve()
	if err != nil {
		t.Fatal(err)
	}
	want := IntegrationInstanceIdentity{Namespace: "dakasa", Name: "kubernetes-dakasa-production", ActiveManifestID: activeID, ActiveVersion: 51, TypeProvider: "kubernetes"}
	if identity != want {
		t.Fatalf("identity=%+v, want %+v", identity, want)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestResolveIntegrationInstanceTypeRefFormsMirrorExecution(t *testing.T) {
	typeID := uuid.New()
	for _, test := range []struct {
		name    string
		typeRef string
		expect  func(sqlmock.Sqlmock)
	}{
		{
			name:    "namespace defaults to global and is normalized",
			typeRef: `{"name":" Kubernetes "}`,
			expect: func(mock sqlmock.Sqlmock) {
				mock.ExpectQuery(resolveIntegrationTypeProviderByNameQuery).WithArgs("global", "kubernetes").
					WillReturnRows(sqlmock.NewRows([]string{"provider"}).AddRow("kubernetes"))
			},
		},
		{
			name:    "pinned version",
			typeRef: `{"namespace":"global","name":"kubernetes","version":7}`,
			expect: func(mock sqlmock.Sqlmock) {
				mock.ExpectQuery(resolveIntegrationTypeProviderByNameVersionQuery).WithArgs("global", "kubernetes", 7).
					WillReturnRows(sqlmock.NewRows([]string{"provider"}).AddRow("kubernetes"))
			},
		},
		{
			name:    "manifest id",
			typeRef: `{"manifest_id":"` + typeID.String() + `"}`,
			expect: func(mock sqlmock.Sqlmock) {
				mock.ExpectQuery(resolveIntegrationTypeProviderByIDQuery).WithArgs(typeID).
					WillReturnRows(sqlmock.NewRows([]string{"provider"}).AddRow("kubernetes"))
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			mock, resolve, wire := newIdentityMock(t)
			mock.ExpectQuery(resolveIntegrationInstanceByManifestIDQuery).WithArgs(wire).
				WillReturnRows(instanceRows(uuid.New(), test.typeRef))
			test.expect(mock)
			if identity, err := resolve(); err != nil || identity.TypeProvider != "kubernetes" {
				t.Fatalf("identity=%+v err=%v", identity, err)
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestResolveIntegrationInstanceNotResolvableCases(t *testing.T) {
	for _, test := range []struct {
		name   string
		expect func(sqlmock.Sqlmock, uuid.UUID)
	}{
		{
			// No row: absent, purged, not an integration_instance, or no active version.
			name: "no active instance",
			expect: func(mock sqlmock.Sqlmock, wire uuid.UUID) {
				mock.ExpectQuery(resolveIntegrationInstanceByManifestIDQuery).WithArgs(wire).
					WillReturnRows(sqlmock.NewRows([]string{"id", "namespace", "name", "version", "type_ref"}))
			},
		},
		{
			name: "no active integration_type",
			expect: func(mock sqlmock.Sqlmock, wire uuid.UUID) {
				mock.ExpectQuery(resolveIntegrationInstanceByManifestIDQuery).WithArgs(wire).
					WillReturnRows(instanceRows(uuid.New(), `{"namespace":"global","name":"kubernetes"}`))
				mock.ExpectQuery(resolveIntegrationTypeProviderByNameQuery).WithArgs("global", "kubernetes").
					WillReturnRows(sqlmock.NewRows([]string{"provider"}))
			},
		},
		{
			name: "type without provider",
			expect: func(mock sqlmock.Sqlmock, wire uuid.UUID) {
				mock.ExpectQuery(resolveIntegrationInstanceByManifestIDQuery).WithArgs(wire).
					WillReturnRows(instanceRows(uuid.New(), `{"namespace":"global","name":"kubernetes"}`))
				mock.ExpectQuery(resolveIntegrationTypeProviderByNameQuery).WithArgs("global", "kubernetes").
					WillReturnRows(sqlmock.NewRows([]string{"provider"}).AddRow(""))
			},
		},
		{
			name: "missing type_ref never queries a type",
			expect: func(mock sqlmock.Sqlmock, wire uuid.UUID) {
				mock.ExpectQuery(resolveIntegrationInstanceByManifestIDQuery).WithArgs(wire).
					WillReturnRows(instanceRows(uuid.New(), `null`))
			},
		},
		{
			name: "malformed type_ref manifest_id never queries a type",
			expect: func(mock sqlmock.Sqlmock, wire uuid.UUID) {
				mock.ExpectQuery(resolveIntegrationInstanceByManifestIDQuery).WithArgs(wire).
					WillReturnRows(instanceRows(uuid.New(), `{"manifest_id":"not-a-uuid"}`))
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			mock, resolve, wire := newIdentityMock(t)
			test.expect(mock, wire)
			if _, err := resolve(); !errors.Is(err, ErrIntegrationInstanceNotResolvable) {
				t.Fatalf("err=%v, want ErrIntegrationInstanceNotResolvable", err)
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestResolveIntegrationInstanceSurfacesDatabaseFailures(t *testing.T) {
	mock, resolve, wire := newIdentityMock(t)
	mock.ExpectQuery(resolveIntegrationInstanceByManifestIDQuery).WithArgs(wire).
		WillReturnError(errors.New("pq: the database system is shutting down"))
	_, err := resolve()
	if err == nil || errors.Is(err, ErrIntegrationInstanceNotResolvable) {
		t.Fatalf("err=%v, a database failure must not read as not-found", err)
	}
}

func TestResolveIntegrationInstanceByNameUsesTheActiveVersion(t *testing.T) {
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherEqual))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	mock.ExpectQuery(resolveIntegrationInstanceByNameQuery).WithArgs("dakasa", "kubernetes-dakasa-production").
		WillReturnRows(instanceRows(uuid.New(), `{"namespace":"global","name":"kubernetes"}`))
	mock.ExpectQuery(resolveIntegrationTypeProviderByNameQuery).WithArgs("global", "kubernetes").
		WillReturnRows(sqlmock.NewRows([]string{"provider"}).AddRow("kubernetes"))
	if _, err := ResolveIntegrationInstanceByName(context.Background(), db, "dakasa", "kubernetes-dakasa-production"); err != nil {
		t.Fatal(err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestResolveIntegrationInstanceByNameNotResolvable(t *testing.T) {
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherEqual))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	mock.ExpectQuery(resolveIntegrationInstanceByNameQuery).WithArgs("dakasa", "kubernetes-dakasa-production").
		WillReturnRows(sqlmock.NewRows([]string{"id", "namespace", "name", "version", "type_ref"}))
	if _, err := ResolveIntegrationInstanceByName(context.Background(), db, "dakasa", "kubernetes-dakasa-production"); !errors.Is(err, ErrIntegrationInstanceNotResolvable) {
		t.Fatalf("err=%v, want ErrIntegrationInstanceNotResolvable", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

// sqlmock matches the query text but cannot execute it, so the predicates
// that carry the ADR-0021 semantics are pinned here as text. A real
// PostgreSQL run is still the only proof of the self-join behavior.
func TestIntegrationInstanceResolutionQueriesPinTheirPredicates(t *testing.T) {
	for _, test := range []struct {
		name  string
		query string
		want  []string
	}{
		{
			name:  "any version id resolves to the active version of the same logical instance",
			query: resolveIntegrationInstanceByManifestIDQuery,
			want: []string{
				"WHERE v.id = $1",
				"AND v.kind = 'integration_instance'",
				"ON a.kind = v.kind",
				"AND a.namespace = v.namespace",
				"AND a.name = v.name",
				"AND a.active = TRUE",
			},
		},
		{
			name:  "a literal namespace/name resolves only to its active version",
			query: resolveIntegrationInstanceByNameQuery,
			want:  []string{"a.kind = 'integration_instance'", "AND a.namespace = $1", "AND a.name = $2", "AND a.active = TRUE"},
		},
		{
			name:  "type by id must be the active integration_type",
			query: resolveIntegrationTypeProviderByIDQuery,
			want:  []string{"WHERE id = $1", "AND kind = 'integration_type'", "AND active = TRUE"},
		},
		{
			name:  "type by name must be the active integration_type",
			query: resolveIntegrationTypeProviderByNameQuery,
			want:  []string{"kind = 'integration_type'", "AND namespace = $1", "AND name = $2", "AND active = TRUE"},
		},
		{
			name:  "type by pinned version must still be the active integration_type",
			query: resolveIntegrationTypeProviderByNameVersionQuery,
			want:  []string{"kind = 'integration_type'", "AND namespace = $1", "AND name = $2", "AND version = $3", "AND active = TRUE"},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			for _, fragment := range test.want {
				if !strings.Contains(test.query, fragment) {
					t.Fatalf("query lost %q:\n%s", fragment, test.query)
				}
			}
			if strings.Contains(strings.ToUpper(test.query), "INSERT") || strings.Contains(strings.ToUpper(test.query), "UPDATE") {
				t.Fatalf("resolution must be read-only:\n%s", test.query)
			}
		})
	}
}
