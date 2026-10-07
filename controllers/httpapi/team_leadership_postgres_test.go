package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/contactphone"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	"github.com/google/uuid"
)

func TestTeamLeadershipHTTPPostgres(t *testing.T) {
	db := directoryHTTPPostgres(t)
	ctx := context.Background()
	t.Setenv(contactphone.EnrollmentPolicyEnv, "false")
	actor := directoryHTTPPerson(t, db, false)
	traits := map[string]any{"yggdrasil_admin": true}
	if _, err := repository.UpdateCollaborator(ctx, db, model.UpdateCollaboratorRequest{ID: actor.ID.String(), Traits: &traits}); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE auth_identities SET mfa_enrolled_at=NOW() WHERE collaborator_id=$1`, actor.ID); err != nil {
		t.Fatal(err)
	}
	session, token, err := repository.CreateAuthSession(ctx, db, actor.ID, nil, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	team, err := repository.CreateTeam(ctx, db, model.CreateTeamRequest{Slug: "lead-http-" + uuid.NewString(), Name: "Leadership HTTP"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = db.Exec(`DELETE FROM teams WHERE id=$1`, team.ID) })
	h := directoryHTTPHandler(t, db)
	request := func(method, path string, body any) *httptest.ResponseRecorder {
		raw, _ := json.Marshal(body)
		r := httptest.NewRequest(method, path, strings.NewReader(string(raw)))
		r.AddCookie(&http.Cookie{Name: authSessionCookieName(), Value: token})
		r.Header.Set("X-CSRF-Token", computeCSRFToken(session.ID))
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	path := "/api/v1/console/teams/" + team.ID.String()
	for _, tc := range []struct {
		body   map[string]any
		status int
		code   string
	}{
		{map[string]any{"name": "Cached rename", "owners": []string{actor.ID.String()}}, 422, "team.leadership_assertion_required"},
		{map[string]any{"name": "Stale rename", "owners": []string{actor.ID.String()}, "assert_leadership": true, "expected_updated_at": team.UpdatedAt.Add(-time.Hour)}, 409, "team.leadership_conflict"},
		{map[string]any{"name": "Null rename", "owners": nil}, 400, ""},
	} {
		w := request(http.MethodPatch, path, tc.body)
		if w.Code != tc.status || tc.code != "" && !strings.Contains(w.Body.String(), tc.code) {
			t.Fatalf("status=%d expected=%d", w.Code, tc.status)
		}
		current, e := repository.GetTeam(ctx, db, team.ID.String())
		if e != nil || current.Name != team.Name || !current.UpdatedAt.Equal(team.UpdatedAt) {
			t.Fatal("refusal partially committed team")
		}
	}
	w := request(http.MethodPatch, path, map[string]any{"owners": []string{actor.ID.String()}, "assert_leadership": true, "expected_updated_at": team.UpdatedAt})
	if w.Code != 200 {
		t.Fatalf("explicit assertion status=%d", w.Code)
	}
	members, err := repository.ListTeamMemberships(ctx, db, model.ListTeamMembershipsRequest{TeamID: team.ID.String()})
	if err != nil || len(members) != 1 || !members[0].IsLead {
		t.Fatal("HTTP assertion did not commit typed leadership")
	}

	future := time.Now().UTC().Add(time.Hour).Truncate(time.Microsecond)
	if _, err := db.Exec(`UPDATE team_memberships SET active=FALSE,starts_at=$2 WHERE id=$1`, members[0].ID, future); err != nil {
		t.Fatal(err)
	}
	w = request(http.MethodGet, path+"/edit-context", nil)
	var edit consoleTeamEditContext
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &edit) != nil || len(edit.ActiveMemberships) != 0 || len(edit.LeadershipMemberships) != 1 || !edit.LeadershipMemberships[0].IsLead {
		t.Fatal("editor lost a formal inactive/future assignment")
	}
	second := directoryHTTPPerson(t, db, false)
	w = request(http.MethodPatch, path, map[string]any{"owners": []string{actor.ID.String(), second.ID.String()}, "assert_leadership": true, "expected_updated_at": edit.Team.UpdatedAt})
	if w.Code != 200 {
		t.Fatalf("replacement status=%d", w.Code)
	}
	members, err = repository.ListTeamMemberships(ctx, db, model.ListTeamMembershipsRequest{TeamID: team.ID.String()})
	if err != nil || len(members) != 2 {
		t.Fatal("replacement lost a formal assignment")
	}
	for _, m := range members {
		if m.CollaboratorID == actor.ID && (!m.IsLead || m.Active || m.StartsAt == nil || !m.StartsAt.Equal(future)) {
			t.Fatal("editing another leader reactivated or changed the old assignment window")
		}
	}
	w = request(http.MethodPatch, path, map[string]any{"name": "Basic rename"})
	if w.Code != 200 {
		t.Fatal("omitted owners patch became incompatible")
	}
	w = request(http.MethodPatch, "/api/v1/console/teams/"+uuid.NewString(), map[string]any{"name": "Missing"})
	if w.Code != 404 {
		t.Fatal("missing team no longer maps to404")
	}
	// Creation requires intent but no invented previous version.
	slug := "lead-http-create-" + uuid.NewString()
	w = request(http.MethodPost, "/api/v1/console/teams", map[string]any{"slug": slug, "name": "Creation", "owners": []string{actor.ID.String()}})
	if w.Code != 422 {
		t.Fatal("HTTP creation inferred owner intent")
	}
	w = request(http.MethodPost, "/api/v1/console/teams", map[string]any{"slug": slug, "name": "Creation", "owners": []string{actor.ID.String()}, "assert_leadership": true})
	if w.Code != 201 {
		t.Fatalf("explicit creation status=%d", w.Code)
	}
	t.Cleanup(func() { _, _ = db.Exec(`DELETE FROM teams WHERE slug=$1`, slug) })
}
