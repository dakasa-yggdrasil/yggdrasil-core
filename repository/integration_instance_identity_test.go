package repository

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"
)

var instanceIdentityColumns = []string{"id", "namespace", "name", "version", "type_ref", "candidates"}

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

func typeCandidates(t *testing.T, candidates ...integrationTypeCandidate) []byte {
	t.Helper()
	if candidates == nil {
		candidates = []integrationTypeCandidate{}
	}
	raw, err := json.Marshal(candidates)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func kubernetesType(id uuid.UUID, namespace string, version int, provider string) integrationTypeCandidate {
	return integrationTypeCandidate{ID: id, Namespace: namespace, Name: "kubernetes", Version: version, Provider: provider}
}

func instanceRows(activeID uuid.UUID, typeRef string, candidates []byte) *sqlmock.Rows {
	return sqlmock.NewRows(instanceIdentityColumns).
		AddRow(activeID, "dakasa", "kubernetes-dakasa-production", 51, []byte(typeRef), candidates)
}

func TestResolveIntegrationInstanceByManifestIDReturnsTheActiveVersionAndTypeProvider(t *testing.T) {
	mock, resolve, wire := newIdentityMock(t)
	activeID := uuid.New()
	mock.ExpectQuery(resolveIntegrationInstanceByManifestIDQuery).WithArgs(wire).
		WillReturnRows(instanceRows(activeID, `{"namespace":"global","name":"kubernetes"}`,
			typeCandidates(t, kubernetesType(uuid.New(), "global", 3, "kubernetes"))))

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
		name       string
		typeRef    string
		candidates []integrationTypeCandidate
	}{
		{
			name:    "namespace defaults to global and is normalized",
			typeRef: `{"name":" Kubernetes "}`,
			candidates: []integrationTypeCandidate{
				kubernetesType(uuid.New(), "platform", 1, "helm"),
				kubernetesType(uuid.New(), "global", 4, "kubernetes"),
			},
		},
		{
			name:       "pinned version that is the active one",
			typeRef:    `{"namespace":"global","name":"kubernetes","version":7}`,
			candidates: []integrationTypeCandidate{kubernetesType(uuid.New(), "global", 7, "kubernetes")},
		},
		{
			name:    "manifest id wins over a name",
			typeRef: `{"manifest_id":"` + typeID.String() + `","name":"other"}`,
			candidates: []integrationTypeCandidate{
				{ID: uuid.New(), Namespace: "global", Name: "other", Version: 1, Provider: "helm"},
				kubernetesType(typeID, "global", 2, "kubernetes"),
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			mock, resolve, wire := newIdentityMock(t)
			mock.ExpectQuery(resolveIntegrationInstanceByManifestIDQuery).WithArgs(wire).
				WillReturnRows(instanceRows(uuid.New(), test.typeRef, typeCandidates(t, test.candidates...)))
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
	typeID := uuid.New()
	for _, test := range []struct {
		name string
		rows func(t *testing.T) *sqlmock.Rows
	}{
		{
			// No row: absent, purged, not an integration_instance, or no active version.
			name: "no active instance",
			rows: func(*testing.T) *sqlmock.Rows { return sqlmock.NewRows(instanceIdentityColumns) },
		},
		{
			name: "no active integration_type",
			rows: func(t *testing.T) *sqlmock.Rows {
				return instanceRows(uuid.New(), `{"namespace":"global","name":"kubernetes"}`, typeCandidates(t))
			},
		},
		{
			name: "type only in another namespace",
			rows: func(t *testing.T) *sqlmock.Rows {
				return instanceRows(uuid.New(), `{"name":"kubernetes"}`, typeCandidates(t, kubernetesType(uuid.New(), "platform", 1, "kubernetes")))
			},
		},
		{
			// Only the active type version is a candidate, so a pin to any
			// other version cannot match.
			name: "pinned version is not the active one",
			rows: func(t *testing.T) *sqlmock.Rows {
				return instanceRows(uuid.New(), `{"namespace":"global","name":"kubernetes","version":1}`, typeCandidates(t, kubernetesType(uuid.New(), "global", 2, "kubernetes")))
			},
		},
		{
			name: "manifest id of no active type",
			rows: func(t *testing.T) *sqlmock.Rows {
				return instanceRows(uuid.New(), `{"manifest_id":"`+typeID.String()+`"}`, typeCandidates(t, kubernetesType(uuid.New(), "global", 2, "kubernetes")))
			},
		},
		{
			name: "type without provider",
			rows: func(t *testing.T) *sqlmock.Rows {
				return instanceRows(uuid.New(), `{"namespace":"global","name":"kubernetes"}`, typeCandidates(t, kubernetesType(uuid.New(), "global", 2, " ")))
			},
		},
		{
			name: "missing type_ref",
			rows: func(t *testing.T) *sqlmock.Rows {
				return sqlmock.NewRows(instanceIdentityColumns).AddRow(uuid.New(), "dakasa", "kubernetes-dakasa-production", 51, nil, typeCandidates(t))
			},
		},
		{
			name: "null type_ref",
			rows: func(t *testing.T) *sqlmock.Rows { return instanceRows(uuid.New(), `null`, typeCandidates(t)) },
		},
		{
			name: "malformed type_ref manifest_id",
			rows: func(t *testing.T) *sqlmock.Rows {
				return instanceRows(uuid.New(), `{"manifest_id":"not-a-uuid"}`, typeCandidates(t, kubernetesType(uuid.New(), "global", 2, "kubernetes")))
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			mock, resolve, wire := newIdentityMock(t)
			mock.ExpectQuery(resolveIntegrationInstanceByManifestIDQuery).WithArgs(wire).WillReturnRows(test.rows(t))
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
		WillReturnRows(instanceRows(uuid.New(), `{"namespace":"global","name":"kubernetes"}`,
			typeCandidates(t, kubernetesType(uuid.New(), "global", 3, "kubernetes"))))
	if identity, err := ResolveIntegrationInstanceByName(context.Background(), db, "dakasa", "kubernetes-dakasa-production"); err != nil || identity.TypeProvider != "kubernetes" {
		t.Fatalf("identity=%+v err=%v", identity, err)
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
		WillReturnRows(sqlmock.NewRows(instanceIdentityColumns))
	if _, err := ResolveIntegrationInstanceByName(context.Background(), db, "dakasa", "kubernetes-dakasa-production"); !errors.Is(err, ErrIntegrationInstanceNotResolvable) {
		t.Fatalf("err=%v, want ErrIntegrationInstanceNotResolvable", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

// sqlmock matches the query text but cannot execute it, so the predicates
// that carry the ADR-0021 semantics are pinned here as text. The DB_URL-gated
// integration_instance_identity_pg_test.go runs the same statements against
// PostgreSQL with every production migration applied.
func TestIntegrationInstanceResolutionQueriesPinTheirPredicates(t *testing.T) {
	typeCandidatePredicates := []string{
		"LEFT JOIN LATERAL",
		"ty.kind = 'integration_type'",
		"AND ty.active = TRUE",
		"ty.id::text = lower(btrim(a.spec -> 'type_ref' ->> 'manifest_id'))",
		"OR ty.name = lower(btrim(a.spec -> 'type_ref' ->> 'name'))",
		"COALESCE(t.candidates, '[]'::jsonb)",
	}
	for _, test := range []struct {
		name  string
		query string
		want  []string
	}{
		{
			name:  "any version id resolves to the active version of the same logical instance, type included",
			query: resolveIntegrationInstanceByManifestIDQuery,
			want: append([]string{
				"WHERE v.id = $1",
				"AND v.kind = 'integration_instance'",
				"ON a.kind = v.kind",
				"AND a.namespace = v.namespace",
				"AND a.name = v.name",
				"AND a.active = TRUE",
			}, typeCandidatePredicates...),
		},
		{
			name:  "a literal namespace/name resolves only to its active version, type included",
			query: resolveIntegrationInstanceByNameQuery,
			want: append([]string{
				"a.kind = 'integration_instance'",
				"AND a.namespace = $1",
				"AND a.name = $2",
				"AND a.active = TRUE",
			}, typeCandidatePredicates...),
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			for _, fragment := range test.want {
				if !strings.Contains(test.query, fragment) {
					t.Fatalf("query lost %q:\n%s", fragment, test.query)
				}
			}
			upper := strings.ToUpper(test.query)
			for _, write := range []string{"INSERT", "UPDATE", "DELETE"} {
				if strings.Contains(upper, write) {
					t.Fatalf("resolution must be read-only:\n%s", test.query)
				}
			}
			if strings.Count(test.query, "SELECT") != 2 {
				t.Fatalf("resolution must stay one statement with one type subquery:\n%s", test.query)
			}
		})
	}
}
