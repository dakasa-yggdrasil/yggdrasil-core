package httpapi

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
)

// teamGrantsByTeamIDsQuery matches the one batched grant read of the grant
// walk for count membership teams. A walk that reads grants team by team
// (team lookup plus grant read per membership) does not match.
func teamGrantsByTeamIDsQuery(count int) string {
	placeholders := make([]string, 0, count)
	for index := 1; index <= count; index++ {
		placeholders = append(placeholders, fmt.Sprintf(`\$%d`, index))
	}
	return `FROM public\.team_grants\s+WHERE team_id IN \(` + strings.Join(placeholders, ", ") + `\)`
}

// tartaroPermissionCatalogQuery matches the catalog read that resolves a "*"
// grant on the configured Tartaro instance.
const tartaroPermissionCatalogQuery = `'action_catalog', COALESCE\(ty\.spec -> 'action_catalog', '\[\]'::jsonb\)[\s\S]+WHERE a\.kind = 'integration_instance'\s+AND a\.namespace = \$1\s+AND a\.name = \$2\s+AND a\.active = TRUE`

const tartaroTestTypeRef = `{"namespace":"dakasa","name":"tartaro-dakasa"}`

// tartaroTestCatalog mixes permission entries (one duplicated, one literal
// "*"), a reactor, an explicit capability and an uncategorized capability.
// Only the two distinct permission names may come out of a wildcard.
const tartaroTestCatalog = `[
	{"name":"tartaro:read_user","category":"permission"},
	{"name":"tartaro:moderate_post","category":"permission"},
	{"name":"tartaro:read_user","category":"permission"},
	{"name":"*","category":"permission"},
	{"name":"on_collaborator_session_terminated","category":"reactor"},
	{"name":"observe_collaborator","category":"capability"},
	{"name":"observe_collaborators"}
]`

func tartaroCatalogColumns() []string {
	return []string{"type_ref", "candidates"}
}

func tartaroTypeCandidates(typeName, catalog string) []byte {
	return []byte(`[{"id":"` + uuid.New().String() + `","namespace":"dakasa","name":"` + typeName + `","version":3,"action_catalog":` + catalog + `}]`)
}

func tartaroCollaboratorRow(rows *sqlmock.Rows, id uuid.UUID, status, traits string) *sqlmock.Rows {
	return rows.AddRow(
		id.String(), "ana-souza", status, "Ana Souza", testLookupEmail, "", "",
		[]byte(`{}`), []byte(`{}`), []byte(`{}`),
		[]byte(traits), []byte(`{}`), 3,
		time.Now(), time.Now(),
	)
}

func tartaroMembershipRow(rows *sqlmock.Rows, collaboratorID, teamID uuid.UUID, teamSlug string) *sqlmock.Rows {
	return rows.AddRow(uuid.New().String(), teamID.String(), teamSlug, collaboratorID.String(), "ana-souza",
		"member", true, "manual", nil, nil, []byte("{}"), time.Now(), time.Now(), false)
}

func tartaroGrantRow(rows *sqlmock.Rows, teamID uuid.UUID, namespace, name, action string) *sqlmock.Rows {
	return rows.AddRow(uuid.New().String(), teamID.String(), namespace, name, action, []byte("{}"), time.Now(), nil)
}

func newTartaroActionsMock(t *testing.T) (*sql.DB, sqlmock.Sqlmock) {
	t.Helper()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db, mock
}

func serveConsoleEffectiveTartaroActions(server *Server, id string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "/api/v1/collaborators/"+id+"/effective-tartaro-actions", nil)
	req.SetPathValue("id", id)
	recorder := httptest.NewRecorder()
	server.handleEffectiveTartaroActions(recorder, req)
	return recorder
}

func TestTartaroGodModeReadsTheAdminTraitOfActiveCollaborators(t *testing.T) {
	cases := []struct {
		name   string
		status string
		traits map[string]any
		want   bool
	}{
		{name: "bool true", status: "active", traits: map[string]any{"yggdrasil_admin": true}, want: true},
		{name: "string true", status: "active", traits: map[string]any{"yggdrasil_admin": "true"}, want: true},
		{name: "string 1", status: "active", traits: map[string]any{"yggdrasil_admin": "1"}, want: true},
		{name: "bool false", status: "active", traits: map[string]any{"yggdrasil_admin": false}},
		{name: "string false", status: "active", traits: map[string]any{"yggdrasil_admin": "false"}},
		{name: "string 0", status: "active", traits: map[string]any{"yggdrasil_admin": "0"}},
		{name: "uppercase string", status: "active", traits: map[string]any{"yggdrasil_admin": "TRUE"}},
		{name: "padded string", status: "active", traits: map[string]any{"yggdrasil_admin": " true"}},
		{name: "empty string", status: "active", traits: map[string]any{"yggdrasil_admin": ""}},
		{name: "json number one", status: "active", traits: map[string]any{"yggdrasil_admin": float64(1)}},
		{name: "list", status: "active", traits: map[string]any{"yggdrasil_admin": []any{true}}},
		{name: "object", status: "active", traits: map[string]any{"yggdrasil_admin": map[string]any{"value": true}}},
		{name: "null", status: "active", traits: map[string]any{"yggdrasil_admin": nil}},
		{name: "missing", status: "active", traits: map[string]any{"tartaro_actions": []any{"*"}}},
		{name: "nil traits", status: "active"},
		{name: "suspended admin", status: "suspended", traits: map[string]any{"yggdrasil_admin": true}},
		{name: "offboarded admin", status: "offboarded", traits: map[string]any{"yggdrasil_admin": "true"}},
		{name: "uppercase active status", status: "Active", traits: map[string]any{"yggdrasil_admin": true}},
		{name: "empty status", status: "", traits: map[string]any{"yggdrasil_admin": "1"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := tartaroGodMode(model.Collaborator{ID: uuid.New(), Status: tc.status, Traits: tc.traits})
			if got != tc.want {
				t.Fatalf("tartaroGodMode(status=%q, traits=%v)=%v, want %v", tc.status, tc.traits, got, tc.want)
			}
		})
	}
}

func TestConsoleEffectiveActionsUseTheAuthorizationPredicateAndAnswerGodMode(t *testing.T) {
	// The console variant applies the same membership predicate as the
	// directory variant (authorizationMembershipsQuery only matches a query
	// that carries membership active, team active and the window), reads the
	// grants of every team in one statement, keeps only the configured
	// instance and answers god_mode. The retired trait comparison is gone.
	db, mock := newTartaroActionsMock(t)
	id := uuid.New()
	alpha := uuid.New()
	beta := uuid.New()
	mock.ExpectQuery(`FROM public\.collaborators\s+WHERE id = \$1`).WithArgs(id).
		WillReturnRows(tartaroCollaboratorRow(sqlmock.NewRows(collaboratorColumns()), id, "active",
			`{"yggdrasil_admin":true,"tartaro_actions":["tartaro:stale_trait_action"]}`))
	memberships := sqlmock.NewRows(authorizationMembershipColumns())
	tartaroMembershipRow(memberships, id, alpha, "alpha")
	tartaroMembershipRow(memberships, id, beta, "beta")
	mock.ExpectQuery(authorizationMembershipsQuery).WithArgs(id).WillReturnRows(memberships)
	grants := sqlmock.NewRows(teamGrantColumns())
	tartaroGrantRow(grants, alpha, "dakasa", "tartaro-dakasa-validation", "tartaro:read_user")
	tartaroGrantRow(grants, alpha, "dakasa", "other-instance", "tartaro:delete_everything")
	tartaroGrantRow(grants, beta, "dakasa", "tartaro-dakasa-validation", "tartaro:read_user")
	tartaroGrantRow(grants, beta, "dakasa", "tartaro-dakasa-validation", "tartaro:moderate_post")
	mock.ExpectQuery(teamGrantsByTeamIDsQuery(2)).WithArgs(alpha, beta).WillReturnRows(grants)

	recorder := serveConsoleEffectiveTartaroActions(&Server{db: db, logger: zap.NewNop()}, id.String())

	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	body := decodeDirectoryBody(t, recorder)
	if got := strings.Join(sortedKeys(body), ","); got != "collaborator_id,computed_tartaro_actions,effective_via_teams,god_mode" {
		t.Fatalf("console keys=%s", got)
	}
	if body["collaborator_id"] != id.String() || body["god_mode"] != true {
		t.Fatalf("body=%s", recorder.Body.String())
	}
	if got := fmt.Sprint(body["computed_tartaro_actions"]); got != "[tartaro:moderate_post tartaro:read_user]" {
		t.Fatalf("computed_tartaro_actions=%s", got)
	}
	teams, _ := body["effective_via_teams"].([]any)
	if len(teams) != 2 {
		t.Fatalf("effective_via_teams=%v", body["effective_via_teams"])
	}
	first, _ := teams[0].(map[string]any)
	second, _ := teams[1].(map[string]any)
	if first["team_id"] != alpha.String() || first["team_slug"] != "alpha" || fmt.Sprint(first["actions"]) != "[tartaro:read_user]" {
		t.Fatalf("alpha=%v", first)
	}
	if second["team_id"] != beta.String() || second["team_slug"] != "beta" || fmt.Sprint(second["actions"]) != "[tartaro:moderate_post tartaro:read_user]" {
		t.Fatalf("beta=%v", second)
	}
	for _, forbidden := range []string{"trait_tartaro_actions", "drift", "stale_trait_action", "delete_everything"} {
		if strings.Contains(recorder.Body.String(), forbidden) {
			t.Fatalf("console response carries %q: %s", forbidden, recorder.Body.String())
		}
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("the console variant did not use the authorization predicate and one grant read: %v", err)
	}
}

func TestConsoleEffectiveActionsAnswerNoGodModeForAnInactiveAdmin(t *testing.T) {
	db, mock := newTartaroActionsMock(t)
	id := uuid.New()
	mock.ExpectQuery(`FROM public\.collaborators\s+WHERE id = \$1`).WithArgs(id).
		WillReturnRows(tartaroCollaboratorRow(sqlmock.NewRows(collaboratorColumns()), id, "suspended", `{"yggdrasil_admin":true}`))

	recorder := serveConsoleEffectiveTartaroActions(&Server{db: db, logger: zap.NewNop()}, id.String())

	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	want := `{"collaborator_id":"` + id.String() + `","effective_via_teams":[],"computed_tartaro_actions":[],"god_mode":false}`
	if got := strings.TrimSpace(recorder.Body.String()); got != want {
		t.Fatalf("body=%s, want %s", got, want)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestConsoleEffectiveActionsAnswerNoActionForACollaboratorWhoIsNotActive(t *testing.T) {
	// The console variant is the live authorization source of the Tartaro
	// panel services, called with the human's own token, which outlives a
	// status change. A collaborator who is not active must get no action from
	// it, exactly like the directory variant, which reads them as absent.
	// Only the collaborator is read: the mock carries no membership, grant or
	// catalog expectation, so a walk would hit an unexpected query, fail the
	// read with a non-200 status and leave the body without the empty sets.
	for _, status := range []string{"pending_start", "on_leave", "suspended", "offboarded", "Active", ""} {
		t.Run("status "+status, func(t *testing.T) {
			db, mock := newTartaroActionsMock(t)
			id := uuid.New()
			mock.ExpectQuery(`FROM public\.collaborators\s+WHERE id = \$1`).WithArgs(id).
				WillReturnRows(tartaroCollaboratorRow(sqlmock.NewRows(collaboratorColumns()), id, status,
					`{"department":"finance","tartaro_actions":["tartaro:write_financeiro"]}`))

			recorder := serveConsoleEffectiveTartaroActions(&Server{db: db, logger: zap.NewNop()}, id.String())

			if recorder.Code != http.StatusOK {
				t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
			}
			want := `{"collaborator_id":"` + id.String() + `","effective_via_teams":[],"computed_tartaro_actions":[],"god_mode":false}`
			if got := strings.TrimSpace(recorder.Body.String()); got != want {
				t.Fatalf("body=%s, want %s", got, want)
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestEffectiveActionsVariantsGiveNoActionToASuspendedCollaboratorWithGrants(t *testing.T) {
	// Parity for a suspended non-admin whose team still grants Tartaro
	// actions: the console variant answers empty sets and no god mode, and the
	// directory variant answers 404 without reading memberships. Neither
	// variant walks the grants of a collaborator who is not active.
	id := uuid.New()

	consoleDB, consoleMock := newTartaroActionsMock(t)
	consoleMock.ExpectQuery(`FROM public\.collaborators\s+WHERE id = \$1`).WithArgs(id).
		WillReturnRows(tartaroCollaboratorRow(sqlmock.NewRows(collaboratorColumns()), id, "suspended", `{}`))
	console := serveConsoleEffectiveTartaroActions(&Server{db: consoleDB, logger: zap.NewNop()}, id.String())
	if console.Code != http.StatusOK {
		t.Fatalf("console status=%d body=%s", console.Code, console.Body.String())
	}
	body := decodeDirectoryBody(t, console)
	if got := fmt.Sprint(body["computed_tartaro_actions"]); got != "[]" {
		t.Fatalf("console computed_tartaro_actions=%s", got)
	}
	if got := fmt.Sprint(body["effective_via_teams"]); got != "[]" {
		t.Fatalf("console effective_via_teams=%s", got)
	}
	if body["god_mode"] != false {
		t.Fatalf("console god_mode=%v", body["god_mode"])
	}
	if err := consoleMock.ExpectationsWereMet(); err != nil {
		t.Fatalf("console variant: %v", err)
	}

	directoryDB, directoryMock := newTartaroActionsMock(t)
	directoryMock.ExpectQuery(`FROM public\.collaborators\s+WHERE id = \$1`).WithArgs(id).
		WillReturnRows(tartaroCollaboratorRow(sqlmock.NewRows(collaboratorColumns()), id, "suspended", `{}`))
	if _, reason, err := (&Server{db: directoryDB, logger: zap.NewNop()}).loadActiveDirectoryCollaborator(context.Background(), id.String()); reason != "inactive" || err == nil {
		t.Fatalf("directory variant loaded a suspended collaborator: reason=%q err=%v", reason, err)
	}
	if err := directoryMock.ExpectationsWereMet(); err != nil {
		t.Fatalf("directory variant: %v", err)
	}
}

func TestConsoleEffectiveActionsRejectAnInvalidIDWithoutTheDatabase(t *testing.T) {
	db, mock := newTartaroActionsMock(t)
	recorder := serveConsoleEffectiveTartaroActions(&Server{db: db, logger: zap.NewNop()}, "not-a-uuid")
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestConsoleEffectiveActionsAnswer404ForAnUnknownCollaborator(t *testing.T) {
	db, mock := newTartaroActionsMock(t)
	id := uuid.New()
	mock.ExpectQuery(`FROM public\.collaborators\s+WHERE id = \$1`).WithArgs(id).
		WillReturnRows(sqlmock.NewRows(collaboratorColumns()))

	recorder := serveConsoleEffectiveTartaroActions(&Server{db: db, logger: zap.NewNop()}, id.String())

	if recorder.Code != http.StatusNotFound {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestTartaroWildcardGrantExpandsToThePermissionCatalog(t *testing.T) {
	// A "*" grant on the configured instance means every permission action
	// of that instance's active integration_type. The catalog is read once
	// even when two teams hold the wildcard, the expansion is deduplicated
	// with explicit grants and sorted, and "*" never appears literally.
	db, mock := newTartaroActionsMock(t)
	id := uuid.New()
	alpha := uuid.New()
	beta := uuid.New()
	grants := sqlmock.NewRows(teamGrantColumns())
	tartaroGrantRow(grants, alpha, "dakasa", "tartaro-dakasa-validation", "*")
	tartaroGrantRow(grants, alpha, "dakasa", "tartaro-dakasa-validation", "tartaro:read_user")
	tartaroGrantRow(grants, alpha, "dakasa", "tartaro-dakasa-validation", "tartaro:legacy_extra")
	tartaroGrantRow(grants, beta, "dakasa", "tartaro-dakasa-validation", "*")
	mock.ExpectQuery(teamGrantsByTeamIDsQuery(2)).WithArgs(alpha, beta).WillReturnRows(grants)
	mock.ExpectQuery(tartaroPermissionCatalogQuery).WithArgs("dakasa", "tartaro-dakasa-validation").
		WillReturnRows(sqlmock.NewRows(tartaroCatalogColumns()).
			AddRow([]byte(tartaroTestTypeRef), tartaroTypeCandidates("tartaro-dakasa", tartaroTestCatalog)))

	core, logs := observer.New(zapcore.DebugLevel)
	server := &Server{db: db, logger: zap.New(core)}
	memberships := []model.TeamMembership{
		{TeamID: alpha, TeamSlug: "alpha", CollaboratorID: id},
		{TeamID: beta, TeamSlug: "beta", CollaboratorID: id},
	}
	result, err := server.tartaroActionsFromMemberships(context.Background(), memberships)
	if err != nil {
		t.Fatal(err)
	}
	if got := fmt.Sprint(result.Computed); got != "[tartaro:legacy_extra tartaro:moderate_post tartaro:read_user]" {
		t.Fatalf("computed=%s", got)
	}
	if len(result.PerTeam) != 2 ||
		fmt.Sprint(result.PerTeam[0].Actions) != "[tartaro:legacy_extra tartaro:moderate_post tartaro:read_user]" ||
		fmt.Sprint(result.PerTeam[1].Actions) != "[tartaro:moderate_post tartaro:read_user]" {
		t.Fatalf("per team=%+v", result.PerTeam)
	}
	for _, team := range result.PerTeam {
		for _, action := range team.Actions {
			if action == tartaroWildcardAction {
				t.Fatalf("wildcard leaked literally: %+v", result.PerTeam)
			}
		}
	}
	if logs.Len() != 0 {
		t.Fatalf("a resolvable catalog must not log: %v", logs.All())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestTartaroWildcardOnAnotherInstanceIsIgnoredWithoutReadingACatalog(t *testing.T) {
	// A "*" grant on any other instance (another name, or the configured
	// name under another namespace) is not a Tartaro grant: it contributes
	// nothing and no catalog is read. An unexpected catalog query would fail
	// against sqlmock and be logged, so an empty log proves none was issued.
	db, mock := newTartaroActionsMock(t)
	id := uuid.New()
	team := uuid.New()
	grants := sqlmock.NewRows(teamGrantColumns())
	tartaroGrantRow(grants, team, "dakasa", "yggdrasil-self", "*")
	tartaroGrantRow(grants, team, "other-namespace", "tartaro-dakasa-validation", "*")
	tartaroGrantRow(grants, team, "dakasa", "tartaro-dakasa-validation", "tartaro:read_user")
	mock.ExpectQuery(teamGrantsByTeamIDsQuery(1)).WithArgs(team).WillReturnRows(grants)

	core, logs := observer.New(zapcore.DebugLevel)
	server := &Server{db: db, logger: zap.New(core)}
	result, err := server.tartaroActionsFromMemberships(context.Background(), []model.TeamMembership{{TeamID: team, TeamSlug: "social", CollaboratorID: id}})
	if err != nil {
		t.Fatal(err)
	}
	if got := fmt.Sprint(result.Computed); got != "[tartaro:read_user]" {
		t.Fatalf("computed=%s", got)
	}
	if logs.Len() != 0 {
		t.Fatalf("no catalog may be read for a foreign wildcard: %v", logs.All())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestTartaroWildcardContributesNothingWhenTheCatalogIsNotResolvable(t *testing.T) {
	// Fail closed for the wildcard only: explicit grants still count, the
	// computation does not error, and the failure is logged once.
	cases := []struct {
		name   string
		expect func(sqlmock.Sqlmock)
	}{
		{name: "instance without an active version", expect: func(mock sqlmock.Sqlmock) {
			mock.ExpectQuery(tartaroPermissionCatalogQuery).WithArgs("dakasa", "tartaro-dakasa-validation").
				WillReturnRows(sqlmock.NewRows(tartaroCatalogColumns()))
		}},
		{name: "type_ref selects no active type", expect: func(mock sqlmock.Sqlmock) {
			mock.ExpectQuery(tartaroPermissionCatalogQuery).WithArgs("dakasa", "tartaro-dakasa-validation").
				WillReturnRows(sqlmock.NewRows(tartaroCatalogColumns()).
					AddRow([]byte(tartaroTestTypeRef), tartaroTypeCandidates("another-type", tartaroTestCatalog)))
		}},
		{name: "unreadable type_ref", expect: func(mock sqlmock.Sqlmock) {
			mock.ExpectQuery(tartaroPermissionCatalogQuery).WithArgs("dakasa", "tartaro-dakasa-validation").
				WillReturnRows(sqlmock.NewRows(tartaroCatalogColumns()).
					AddRow([]byte(`"not an object"`), tartaroTypeCandidates("tartaro-dakasa", tartaroTestCatalog)))
		}},
		{name: "malformed catalog", expect: func(mock sqlmock.Sqlmock) {
			mock.ExpectQuery(tartaroPermissionCatalogQuery).WithArgs("dakasa", "tartaro-dakasa-validation").
				WillReturnRows(sqlmock.NewRows(tartaroCatalogColumns()).
					AddRow([]byte(tartaroTestTypeRef), tartaroTypeCandidates("tartaro-dakasa", `{"name":"not a list"}`)))
		}},
		{name: "database failure", expect: func(mock sqlmock.Sqlmock) {
			mock.ExpectQuery(tartaroPermissionCatalogQuery).WithArgs("dakasa", "tartaro-dakasa-validation").
				WillReturnError(errors.New("pq: canceling statement due to statement timeout"))
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			db, mock := newTartaroActionsMock(t)
			id := uuid.New()
			team := uuid.New()
			grants := sqlmock.NewRows(teamGrantColumns())
			tartaroGrantRow(grants, team, "dakasa", "tartaro-dakasa-validation", "*")
			tartaroGrantRow(grants, team, "dakasa", "tartaro-dakasa-validation", "tartaro:read_user")
			mock.ExpectQuery(teamGrantsByTeamIDsQuery(1)).WithArgs(team).WillReturnRows(grants)
			tc.expect(mock)

			core, logs := observer.New(zapcore.DebugLevel)
			server := &Server{db: db, logger: zap.New(core)}
			result, err := server.tartaroActionsFromMemberships(context.Background(), []model.TeamMembership{{TeamID: team, TeamSlug: "social", CollaboratorID: id}})
			if err != nil {
				t.Fatalf("an unresolvable catalog must not fail the computation: %v", err)
			}
			if got := fmt.Sprint(result.Computed); got != "[tartaro:read_user]" {
				t.Fatalf("computed=%s, want only the explicit grant", got)
			}
			if len(result.PerTeam) != 1 || fmt.Sprint(result.PerTeam[0].Actions) != "[tartaro:read_user]" {
				t.Fatalf("per team=%+v", result.PerTeam)
			}
			if logs.FilterLevelExact(zapcore.WarnLevel).Len() != 1 {
				t.Fatalf("the unresolvable catalog must be logged once at warn level: %v", logs.All())
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestTartaroWildcardOnlyTeamDropsOutWhenTheCatalogIsNotResolvable(t *testing.T) {
	db, mock := newTartaroActionsMock(t)
	id := uuid.New()
	team := uuid.New()
	mock.ExpectQuery(teamGrantsByTeamIDsQuery(1)).WithArgs(team).
		WillReturnRows(tartaroGrantRow(sqlmock.NewRows(teamGrantColumns()), team, "dakasa", "tartaro-dakasa-validation", "*"))
	mock.ExpectQuery(tartaroPermissionCatalogQuery).WithArgs("dakasa", "tartaro-dakasa-validation").
		WillReturnRows(sqlmock.NewRows(tartaroCatalogColumns()))

	server := &Server{db: db, logger: zap.NewNop()}
	result, err := server.tartaroActionsFromMemberships(context.Background(), []model.TeamMembership{{TeamID: team, TeamSlug: "social", CollaboratorID: id}})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Computed) != 0 || len(result.PerTeam) != 0 || result.Computed == nil || result.PerTeam == nil {
		t.Fatalf("result=%+v, want empty non-nil sets", result)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestTartaroGrantWalkWithoutMembershipsReadsNoGrants(t *testing.T) {
	db, mock := newTartaroActionsMock(t)
	server := &Server{db: db, logger: zap.NewNop()}
	result, err := server.tartaroActionsFromMemberships(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if result.Computed == nil || result.PerTeam == nil || len(result.Computed) != 0 || len(result.PerTeam) != 0 {
		t.Fatalf("result=%+v, want empty non-nil sets", result)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestTartaroGrantWalkSurfacesAGrantReadFailure(t *testing.T) {
	db, mock := newTartaroActionsMock(t)
	team := uuid.New()
	mock.ExpectQuery(teamGrantsByTeamIDsQuery(1)).WithArgs(team).WillReturnError(errors.New("pq: connection reset"))
	server := &Server{db: db, logger: zap.NewNop()}
	if _, err := server.tartaroActionsFromMemberships(context.Background(), []model.TeamMembership{{TeamID: team, TeamSlug: "social"}}); err == nil {
		t.Fatal("a failed grant read must fail the computation")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}
