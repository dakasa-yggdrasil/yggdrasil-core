package httpapi

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

// actionHolderCandidatesQuery matches the one set-based roster statement
// (repository.ListIntegrationInstanceActionHolderCandidates).
const actionHolderCandidatesQuery = `WITH instance_grants AS[\s\S]+FROM public\.team_grants g[\s\S]+FROM \(SELECT 1\) AS anchor\s+LEFT JOIN candidates ON TRUE`

func actionHolderCandidateColumns() []string {
	return []string{"instance_has_wildcard_grant", "id", "status", "admin_trait", "exact_grant", "wildcard_grant"}
}

// actionHolderCandidate adds one candidate row. adminTrait is the raw JSON of
// traits.yggdrasil_admin, or "" when the key is absent (SQL NULL).
func actionHolderCandidate(rows *sqlmock.Rows, hasWildcard bool, id uuid.UUID, status, adminTrait string, exact, wildcard bool) *sqlmock.Rows {
	var trait any
	if adminTrait != "" {
		trait = []byte(adminTrait)
	}
	return rows.AddRow(hasWildcard, id.String(), status, trait, exact, wildcard)
}

// actionHolderAnchor adds the anchor row of an empty candidate set.
func actionHolderAnchor(rows *sqlmock.Rows, hasWildcard bool) *sqlmock.Rows {
	return rows.AddRow(hasWildcard, nil, nil, nil, nil, nil)
}

func serveTartaroActionHolders(server *Server, rawQuery string) *httptest.ResponseRecorder {
	target := tartaroActionHoldersPath
	if rawQuery != "" {
		target += "?" + rawQuery
	}
	req := httptest.NewRequest(http.MethodGet, target, nil)
	caller := uuid.NewString()
	req = req.WithContext(contextWithClaims(req.Context(), map[string]any{"collaborator_id": caller, "sub": caller}))
	recorder := httptest.NewRecorder()
	server.handleTartaroActionHolders(recorder, req)
	return recorder
}

func decodeTartaroActionHolders(t *testing.T, recorder *httptest.ResponseRecorder) tartaroActionHoldersResponse {
	t.Helper()
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var body tartaroActionHoldersResponse
	decoder := json.NewDecoder(strings.NewReader(recorder.Body.String()))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&body); err != nil {
		t.Fatalf("decode %s: %v", recorder.Body.String(), err)
	}
	requireTartaroActionHoldersInvariants(t, body)
	return body
}

// requireTartaroActionHoldersInvariants checks what every 200 answer
// promises: total == len(holders), holders sorted by collaborator_id and
// unique, every sources list a non-empty sorted subset of
// ["god_mode", "team_grant"].
func requireTartaroActionHoldersInvariants(t *testing.T, body tartaroActionHoldersResponse) {
	t.Helper()
	if body.Holders == nil {
		t.Fatal("holders is null")
	}
	if body.Total != len(body.Holders) {
		t.Fatalf("total=%d len(holders)=%d", body.Total, len(body.Holders))
	}
	for index, holder := range body.Holders {
		if _, err := uuid.Parse(holder.CollaboratorID); err != nil || strings.ToLower(holder.CollaboratorID) != holder.CollaboratorID {
			t.Fatalf("holder %d id %q is not a canonical lowercase uuid", index, holder.CollaboratorID)
		}
		if index > 0 && body.Holders[index-1].CollaboratorID >= holder.CollaboratorID {
			t.Fatalf("holders not strictly ascending at %d: %v", index, body.Holders)
		}
		if len(holder.Sources) == 0 || !sort.StringsAreSorted(holder.Sources) {
			t.Fatalf("holder %s sources=%v", holder.CollaboratorID, holder.Sources)
		}
		seen := map[string]bool{}
		for _, source := range holder.Sources {
			if (source != tartaroActionHolderSourceGodMode && source != tartaroActionHolderSourceTeamGrant) || seen[source] {
				t.Fatalf("holder %s sources=%v", holder.CollaboratorID, holder.Sources)
			}
			seen[source] = true
		}
	}
}

func requireErrorBody(t *testing.T, recorder *httptest.ResponseRecorder, status int) {
	t.Helper()
	if recorder.Code != status {
		t.Fatalf("status=%d, want %d, body=%s", recorder.Code, status, recorder.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatalf("error body is not JSON: %s", recorder.Body.String())
	}
	if message, _ := body["error"].(string); strings.TrimSpace(message) == "" {
		t.Fatalf("error body has no error message: %s", recorder.Body.String())
	}
}

// requireNoRoster fails when an error response carries a roster. It checks
// the decoded JSON keys, never the raw text: the error messages themselves
// legitimately say "holders" ("tartaro action holders unavailable: ...").
func requireNoRoster(t *testing.T, recorder *httptest.ResponseRecorder, why string) {
	t.Helper()
	var body map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatalf("error body is not a JSON object: %s", recorder.Body.String())
	}
	for _, key := range []string{"holders", "total"} {
		if _, present := body[key]; present {
			t.Fatalf("%s: body carries %q: %s", why, key, recorder.Body.String())
		}
	}
}

func TestTartaroActionHoldersRejectsMalformedQueriesBeforeAnyRead(t *testing.T) {
	long := "tartaro:" + strings.Repeat("a", tartaroActionHoldersMaxActionLength)
	for name, rawQuery := range map[string]string{
		"missing":             "",
		"empty":               "action=",
		"blank":               "action=%20%20",
		"leading space":       "action=%20tartaro:suspend_user",
		"trailing space":      "action=tartaro:suspend_user%20",
		"trailing tab":        "action=tartaro:suspend_user%09",
		"wildcard":            "action=*",
		"encoded wildcard":    "action=%2A",
		"repeated":            "action=tartaro:suspend_user&action=tartaro:suspend_user",
		"repeated empty":      "action=tartaro:suspend_user&action=",
		"too long":            "action=" + long,
		"unknown parameter":   "action=tartaro:suspend_user&role=risk",
		"only unknown":        "role=risk",
		"semicolon separator": "action=tartaro:suspend_user;role=risk",
		"bad escape":          "action=%zz",
	} {
		t.Run(name, func(t *testing.T) {
			db, mock := newTartaroActionsMock(t)
			recorder := serveTartaroActionHolders(&Server{db: db, logger: zap.NewNop()}, rawQuery)
			requireErrorBody(t, recorder, http.StatusBadRequest)
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestTartaroActionHoldersQueryAcceptsTheLongestAction(t *testing.T) {
	action := strings.Repeat("a", tartaroActionHoldersMaxActionLength)
	got, err := parseTartaroActionHoldersQuery("action=" + action)
	if err != nil || got != action {
		t.Fatalf("got=%q err=%v", got, err)
	}
	if _, err := parseTartaroActionHoldersQuery("action=" + action + "a"); err == nil {
		t.Fatal("129-byte action accepted")
	}
	if got, err := parseTartaroActionHoldersQuery("action=tartaro%3Asuspend_user"); err != nil || got != "tartaro:suspend_user" {
		t.Fatalf("encoded colon: got=%q err=%v", got, err)
	}
}

func TestTartaroActionHoldersRefusesAnonymousCallers(t *testing.T) {
	t.Run("console gate", func(t *testing.T) {
		s := &Server{}
		handler := s.requireAuthenticatedConsoleAPIs(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
			t.Fatal("the roster handler must not run without an authenticated caller")
		}))
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, tartaroActionHoldersPath+"?action=tartaro:suspend_user", nil))
		requireErrorBody(t, recorder, http.StatusUnauthorized)
	})
	t.Run("handler without claims", func(t *testing.T) {
		db, mock := newTartaroActionsMock(t)
		recorder := httptest.NewRecorder()
		(&Server{db: db, logger: zap.NewNop()}).handleTartaroActionHolders(recorder,
			httptest.NewRequest(http.MethodGet, tartaroActionHoldersPath+"?action=tartaro:suspend_user", nil))
		requireErrorBody(t, recorder, http.StatusUnauthorized)
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Fatal(err)
		}
	})
}

func TestTartaroActionHoldersAnswersTheContractShape(t *testing.T) {
	db, mock := newTartaroActionsMock(t)
	action := "tartaro:suspend_user"
	ids := []uuid.UUID{uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()}
	sort.Slice(ids, func(i, j int) bool { return ids[i].String() < ids[j].String() })
	grantOnly, godAndGrant, godOnly, upperAdmin, numberAdmin, suspendedRow := ids[0], ids[1], ids[2], ids[3], ids[4], ids[5]

	rows := sqlmock.NewRows(actionHolderCandidateColumns())
	actionHolderCandidate(rows, false, grantOnly, "active", "", true, false)
	actionHolderCandidate(rows, false, godAndGrant, "active", `"true"`, true, false)
	actionHolderCandidate(rows, false, godOnly, "active", `true`, false, false)
	actionHolderCandidate(rows, false, upperAdmin, "active", `"TRUE"`, false, false)
	actionHolderCandidate(rows, false, numberAdmin, "active", `1`, false, false)
	// The statement filters on active; a row that is not active anyway is
	// dropped by the same active-record rule as the effective-actions read.
	actionHolderCandidate(rows, false, suspendedRow, "suspended", `true`, true, false)
	mock.ExpectQuery(actionHolderCandidatesQuery).
		WithArgs(tartaroInstanceNamespace, tartaroInstanceName, action).
		WillReturnRows(rows)

	recorder := serveTartaroActionHolders(&Server{db: db, logger: zap.NewNop()}, "action=tartaro%3Asuspend_user")
	body := decodeTartaroActionHolders(t, recorder)

	want := tartaroActionHoldersResponse{
		Action:              action,
		IntegrationInstance: tartaroIntegrationInstanceID{Namespace: tartaroInstanceNamespace, Name: tartaroInstanceName},
		Total:               3,
		Holders: []tartaroActionHolder{
			{CollaboratorID: grantOnly.String(), Sources: []string{"team_grant"}},
			{CollaboratorID: godAndGrant.String(), Sources: []string{"god_mode", "team_grant"}},
			{CollaboratorID: godOnly.String(), Sources: []string{"god_mode"}},
		},
	}
	if !reflect.DeepEqual(body, want) {
		t.Fatalf("body=%+v\nwant=%+v", body, want)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("the roster must be one statement and read no catalog without a wildcard grant: %v", err)
	}
}

func TestTartaroActionHoldersAnswersAnEmptyRoster(t *testing.T) {
	db, mock := newTartaroActionsMock(t)
	mock.ExpectQuery(actionHolderCandidatesQuery).
		WithArgs(tartaroInstanceNamespace, tartaroInstanceName, "tartaro:suspend_user").
		WillReturnRows(actionHolderAnchor(sqlmock.NewRows(actionHolderCandidateColumns()), false))

	recorder := serveTartaroActionHolders(&Server{db: db, logger: zap.NewNop()}, "action=tartaro:suspend_user")

	wantBody := `{"action":"tartaro:suspend_user","integration_instance":{"namespace":"` + tartaroInstanceNamespace +
		`","name":"` + tartaroInstanceName + `"},"total":0,"holders":[]}`
	if recorder.Code != http.StatusOK || strings.TrimSpace(recorder.Body.String()) != wantBody {
		t.Fatalf("status=%d body=%s, want %s", recorder.Code, recorder.Body.String(), wantBody)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestTartaroActionHoldersCountAWildcardGrantOnlyForACatalogAction(t *testing.T) {
	// tartaroTestCatalog lists tartaro:read_user and tartaro:moderate_post as
	// permissions, never tartaro:suspend_user.
	for _, tc := range []struct {
		action  string
		counted bool
	}{
		{action: "tartaro:read_user", counted: true},
		{action: "tartaro:suspend_user", counted: false},
	} {
		t.Run(tc.action, func(t *testing.T) {
			db, mock := newTartaroActionsMock(t)
			wildcardOnly := uuid.New()
			rows := sqlmock.NewRows(actionHolderCandidateColumns())
			actionHolderCandidate(rows, true, wildcardOnly, "active", "", false, true)
			mock.ExpectQuery(actionHolderCandidatesQuery).
				WithArgs(tartaroInstanceNamespace, tartaroInstanceName, tc.action).
				WillReturnRows(rows)
			mock.ExpectQuery(tartaroPermissionCatalogQuery).
				WithArgs(tartaroInstanceNamespace, tartaroInstanceName).
				WillReturnRows(sqlmock.NewRows(tartaroCatalogColumns()).
					AddRow([]byte(tartaroTestTypeRef), tartaroTypeCandidates("tartaro-dakasa", tartaroTestCatalog)))

			body := decodeTartaroActionHolders(t, serveTartaroActionHolders(&Server{db: db, logger: zap.NewNop()}, "action="+tc.action))

			if tc.counted {
				if body.Total != 1 || body.Holders[0].CollaboratorID != wildcardOnly.String() ||
					!reflect.DeepEqual(body.Holders[0].Sources, []string{"team_grant"}) {
					t.Fatalf("wildcard holder not counted: %+v", body)
				}
			} else if body.Total != 0 {
				t.Fatalf("wildcard counted for an action outside the catalog: %+v", body)
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestTartaroActionHoldersRefuseToCountWhenAWildcardCatalogIsUnresolvable(t *testing.T) {
	for name, catalog := range map[string]func(*sqlmock.ExpectedQuery){
		"instance not resolvable": func(q *sqlmock.ExpectedQuery) {
			q.WillReturnRows(sqlmock.NewRows(tartaroCatalogColumns()))
		},
		"type_ref unreadable": func(q *sqlmock.ExpectedQuery) {
			q.WillReturnRows(sqlmock.NewRows(tartaroCatalogColumns()).AddRow(nil, []byte(`[]`)))
		},
		"catalog read failure": func(q *sqlmock.ExpectedQuery) {
			q.WillReturnError(errors.New("connection reset"))
		},
	} {
		t.Run(name, func(t *testing.T) {
			db, mock := newTartaroActionsMock(t)
			rows := sqlmock.NewRows(actionHolderCandidateColumns())
			// Even an exact holder and a god are not answered: a roster
			// that silently dropped the wildcard holders would count lower.
			actionHolderCandidate(rows, true, uuid.New(), "active", "", true, false)
			actionHolderCandidate(rows, true, uuid.New(), "active", "true", false, false)
			mock.ExpectQuery(actionHolderCandidatesQuery).
				WithArgs(tartaroInstanceNamespace, tartaroInstanceName, "tartaro:suspend_user").
				WillReturnRows(rows)
			catalog(mock.ExpectQuery(tartaroPermissionCatalogQuery).WithArgs(tartaroInstanceNamespace, tartaroInstanceName))

			recorder := serveTartaroActionHolders(&Server{db: db, logger: zap.NewNop()}, "action=tartaro:suspend_user")

			requireErrorBody(t, recorder, http.StatusServiceUnavailable)
			requireNoRoster(t, recorder, "a refused count leaked a partial roster")
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestTartaroActionHoldersMapARosterReadFailureToAServerError(t *testing.T) {
	db, mock := newTartaroActionsMock(t)
	mock.ExpectQuery(actionHolderCandidatesQuery).
		WithArgs(tartaroInstanceNamespace, tartaroInstanceName, "tartaro:suspend_user").
		WillReturnError(errors.New("connection reset"))

	recorder := serveTartaroActionHolders(&Server{db: db, logger: zap.NewNop()}, "action=tartaro:suspend_user")

	if recorder.Code < 500 {
		t.Fatalf("status=%d body=%s, want 5xx", recorder.Code, recorder.Body.String())
	}
	requireNoRoster(t, recorder, "a failed read answered a roster")
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

// TestTartaroActionHoldersWireFieldNamesAreTheContract pins the exact JSON
// field names that dakasa-tartaro-api decodes strictly (and the tartaro-fe
// stub reproduces), in the Go wire type and in the published OpenAPI schema.
// Renaming a field breaks the Tartaro ban quorum, which then fails closed.
func TestTartaroActionHoldersWireFieldNamesAreTheContract(t *testing.T) {
	raw, err := json.Marshal(tartaroActionHoldersResponse{
		Action:              "tartaro:suspend_user",
		IntegrationInstance: tartaroIntegrationInstanceID{Namespace: "dakasa", Name: "tartaro-dakasa-validation"},
		Total:               1,
		Holders:             []tartaroActionHolder{{CollaboratorID: uuid.NewString(), Sources: []string{"god_mode", "team_grant"}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	var top map[string]json.RawMessage
	if err := json.Unmarshal(raw, &top); err != nil {
		t.Fatal(err)
	}
	keys := func(object map[string]json.RawMessage) string {
		out := make([]string, 0, len(object))
		for key := range object {
			out = append(out, key)
		}
		sort.Strings(out)
		return strings.Join(out, ",")
	}
	if got := keys(top); got != "action,holders,integration_instance,total" {
		t.Fatalf("top-level keys=%s", got)
	}
	var instance map[string]json.RawMessage
	if err := json.Unmarshal(top["integration_instance"], &instance); err != nil || keys(instance) != "name,namespace" {
		t.Fatalf("integration_instance keys=%s err=%v", keys(instance), err)
	}
	var holders []map[string]json.RawMessage
	if err := json.Unmarshal(top["holders"], &holders); err != nil || len(holders) != 1 || keys(holders[0]) != "collaborator_id,sources" {
		t.Fatalf("holder keys=%v err=%v", holders, err)
	}
	if tartaroActionHolderSourceGodMode != "god_mode" || tartaroActionHolderSourceTeamGrant != "team_grant" {
		t.Fatal("holder source names changed")
	}
	if tartaroActionHoldersPath != "/api/v1/tartaro/action-holders" {
		t.Fatal("roster path changed")
	}

	empty, err := json.Marshal(tartaroActionHoldersResponse{Holders: []tartaroActionHolder{}})
	if err != nil || !strings.Contains(string(empty), `"holders":[]`) || !strings.Contains(string(empty), `"total":0`) {
		t.Fatalf("empty roster wire=%s err=%v", empty, err)
	}

	// The published OpenAPI schemas name exactly the same fields, all required.
	var spec struct {
		Paths      map[string]map[string]json.RawMessage `json:"paths"`
		Components struct {
			Schemas map[string]struct {
				Required   []string                   `json:"required"`
				Properties map[string]json.RawMessage `json:"properties"`
			} `json:"schemas"`
		} `json:"components"`
	}
	if err := json.Unmarshal(openapiBundle, &spec); err != nil {
		t.Fatalf("bundled OpenAPI unavailable: %v", err)
	}
	if spec.Paths[tartaroActionHoldersPath]["get"] == nil {
		t.Fatal("OpenAPI does not document GET " + tartaroActionHoldersPath)
	}
	for schema, want := range map[string]string{
		"TartaroActionHolders":                    "action,holders,integration_instance,total",
		"TartaroActionHoldersIntegrationInstance": "name,namespace",
		"TartaroActionHolder":                     "collaborator_id,sources",
	} {
		got, ok := spec.Components.Schemas[schema]
		if !ok {
			t.Fatalf("OpenAPI schema %s missing", schema)
		}
		required := append([]string(nil), got.Required...)
		sort.Strings(required)
		if keys(got.Properties) != want || strings.Join(required, ",") != want {
			t.Fatalf("OpenAPI schema %s properties=%s required=%v, want %s", schema, keys(got.Properties), required, want)
		}
	}
}
