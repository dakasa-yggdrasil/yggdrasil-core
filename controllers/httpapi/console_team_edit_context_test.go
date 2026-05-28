package httpapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

// Phase 6 — handleConsoleTeamEditContext tests.
//
// The aggregate replaces 3 dataset-wide queries from TeamEditPage. The
// tests below lock the field-name contract, the "member_of_this_team"
// flag, and the parent-options descendant filtering.
//
// We mock at the query level: GetTeam → ListTeams → ListCollaborators →
// ListTeamMemberships (scoped to this team) → per-member ListTeamMemberships
// (only if there are members). Test isolates handler behaviour from the
// repository layer.

// teamEditContextRowsForGetTeam returns sqlmock rows shaped like scanTeam.
func teamEditContextRowsForGetTeam(id uuid.UUID, slug, name string, parentID *uuid.UUID) *sqlmock.Rows {
	parent := ""
	if parentID != nil {
		parent = parentID.String()
	}
	return sqlmock.NewRows([]string{
		"id", "slug", "name", "type", "status", "email", "parent_team_id",
		"owners", "traits", "metadata", "created_at", "updated_at",
	}).AddRow(
		id.String(), slug, name, "guild", "active", "", parent,
		[]byte("[]"), []byte("{}"), []byte("{}"),
		time.Now(), time.Now(),
	)
}

func teamEditContextRowsForListCollaborators(c uuid.UUID, slug, display, email string) *sqlmock.Rows {
	return sqlmock.NewRows([]string{
		"id", "slug", "status", "display_name", "primary_email", "manager_id", "primary_team_id",
		"personal_data", "employment_data", "third_party_identities", "traits", "metadata", "version",
		"created_at", "updated_at",
	}).AddRow(
		c.String(), slug, "active", display, email, "", "",
		[]byte("{}"), []byte("{}"), []byte("{}"), []byte("{}"), []byte("{}"), 1,
		time.Now(), time.Now(),
	)
}

func teamEditContextRowsForListMemberships(teamID, collabID uuid.UUID) *sqlmock.Rows {
	return sqlmock.NewRows([]string{
		"id", "team_id", "team_slug", "collaborator_id", "collaborator_slug",
		"role", "active", "source", "starts_at", "ends_at", "metadata",
		"created_at", "updated_at",
	}).AddRow(
		uuid.New().String(), teamID.String(), "engineering", collabID.String(), "alice",
		"member", true, "manual", nil, nil, []byte("{}"),
		time.Now(), time.Now(),
	)
}

// TestHandleConsoleTeamEditContext_HappyPath — the canonical shape:
// returns team + parent options + owner candidates with member flag +
// active memberships scoped to this team.
//
// The query plan inside the handler ends up calling 7 SQL queries (not
// 4 like the comment suggests), because ListTeamMemberships internally
// re-resolves the team UUID via GetTeam, and the per-member walk
// re-resolves each collaborator UUID via GetCollaborator. The test
// sets those expectations explicitly so sqlmock can match in
// declaration order.
func TestHandleConsoleTeamEditContext_HappyPath(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer func() { _ = db.Close() }()

	teamID := uuid.New()
	collabID := uuid.New()
	otherID := uuid.New()

	// 1. GetTeam("engineering") — slug variant.
	mock.ExpectQuery(`FROM\s+public\.teams\s+WHERE\s+slug = \$1`).
		WillReturnRows(teamEditContextRowsForGetTeam(teamID, "engineering", "Engineering", nil))

	// 2. ListTeams — ORDER BY name.
	mock.ExpectQuery(`FROM\s+public\.teams\s*ORDER BY`).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "slug", "name", "type", "status", "email", "parent_team_id",
			"owners", "traits", "metadata", "created_at", "updated_at",
		}).
			AddRow(teamID.String(), "engineering", "Engineering", "guild", "active", "", "", []byte("[]"), []byte("{}"), []byte("{}"), time.Now(), time.Now()).
			AddRow(otherID.String(), "design", "Design", "guild", "active", "", "", []byte("[]"), []byte("{}"), []byte("{}"), time.Now(), time.Now()),
		)

	// 3. ListCollaborators — ORDER BY display_name.
	mock.ExpectQuery(`FROM\s+public\.collaborators\s*ORDER BY`).
		WillReturnRows(teamEditContextRowsForListCollaborators(collabID, "alice", "Alice Allen", "alice@example.com"))

	// 4. resolveTeamIdentityID(uuid) — internal GetTeam by id.
	mock.ExpectQuery(`FROM\s+public\.teams\s+WHERE\s+id = \$1`).
		WillReturnRows(teamEditContextRowsForGetTeam(teamID, "engineering", "Engineering", nil))

	// 5. The real team_memberships query.
	mock.ExpectQuery(`FROM\s+public\.team_memberships`).
		WillReturnRows(teamEditContextRowsForListMemberships(teamID, collabID))

	// 6. resolveCollaboratorIdentityID(uuid) — internal GetCollaborator by id.
	mock.ExpectQuery(`FROM\s+public\.collaborators\s+WHERE\s+id = \$1`).
		WillReturnRows(teamEditContextRowsForListCollaborators(collabID, "alice", "Alice Allen", "alice@example.com"))

	// 7. Per-member: team_memberships scoped to collabID.
	mock.ExpectQuery(`FROM\s+public\.team_memberships`).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "team_id", "team_slug", "collaborator_id", "collaborator_slug",
			"role", "active", "source", "starts_at", "ends_at", "metadata",
			"created_at", "updated_at",
		}).AddRow(
			uuid.New().String(), otherID.String(), "design", collabID.String(), "alice",
			"member", true, "manual", nil, nil, []byte("{}"),
			time.Now(), time.Now(),
		))

	s := &Server{db: db, logger: zap.NewNop()}
	r := httptest.NewRequest(http.MethodGet, "/api/v1/console/teams/engineering/edit-context", nil)
	r.SetPathValue("id", "engineering")
	w := httptest.NewRecorder()
	s.handleConsoleTeamEditContext(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status: expected 200, got %d body=%s", w.Code, w.Body.String())
	}

	var got consoleTeamEditContext
	if err := json.NewDecoder(w.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}

	if got.Team.Slug != "engineering" {
		t.Errorf("team.slug: got %q want engineering", got.Team.Slug)
	}
	// parent_options excludes the team itself, so we should have ONE entry
	// (the other team). The current team is a "descendant" of itself.
	if len(got.ParentOptions) != 1 {
		t.Errorf("parent_options: got %d want 1", len(got.ParentOptions))
	}
	if len(got.OwnerCandidates) != 1 {
		t.Errorf("owner_candidates: got %d want 1", len(got.OwnerCandidates))
	}
	if !got.OwnerCandidates[0].MemberOfThisTeam {
		t.Errorf("owner_candidates[0].member_of_this_team: expected true (alice is a member of engineering)")
	}
	if len(got.ActiveMemberships) != 1 {
		t.Errorf("active_memberships: got %d want 1", len(got.ActiveMemberships))
	}
	if rows := got.OtherMembershipsByCollaborator[collabID.String()]; len(rows) != 1 || rows[0].TeamSlug != "design" {
		t.Errorf("other_memberships_by_collaborator[%s]: got %+v want [{TeamSlug:design}]", collabID, rows)
	}
}

// TestHandleConsoleTeamEditContext_EmptyMembersDoesNotRunPerMemberQuery —
// optimisation contract: when the team has no members we skip the
// per-member dataset query entirely.
func TestHandleConsoleTeamEditContext_EmptyMembersDoesNotRunPerMemberQuery(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer func() { _ = db.Close() }()

	teamID := uuid.New()
	mock.ExpectQuery(`FROM\s+public\.teams\s+WHERE\s+slug = \$1`).
		WillReturnRows(teamEditContextRowsForGetTeam(teamID, "skeleton", "Skeleton", nil))
	mock.ExpectQuery(`FROM\s+public\.teams\s*ORDER BY`).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "slug", "name", "type", "status", "email", "parent_team_id",
			"owners", "traits", "metadata", "created_at", "updated_at",
		}))
	mock.ExpectQuery(`FROM\s+public\.collaborators\s*ORDER BY`).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "slug", "status", "display_name", "primary_email", "manager_id", "primary_team_id",
			"personal_data", "employment_data", "third_party_identities", "traits", "metadata", "version",
			"created_at", "updated_at",
		}))
	// resolveTeamIdentityID inside ListTeamMemberships — internal GetTeam by id.
	mock.ExpectQuery(`FROM\s+public\.teams\s+WHERE\s+id = \$1`).
		WillReturnRows(teamEditContextRowsForGetTeam(teamID, "skeleton", "Skeleton", nil))
	mock.ExpectQuery(`FROM\s+public\.team_memberships`).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "team_id", "team_slug", "collaborator_id", "collaborator_slug",
			"role", "active", "source", "starts_at", "ends_at", "metadata",
			"created_at", "updated_at",
		}))
	// NO per-member query expected because there are no memberships.

	s := &Server{db: db, logger: zap.NewNop()}
	r := httptest.NewRequest(http.MethodGet, "/api/v1/console/teams/skeleton/edit-context", nil)
	r.SetPathValue("id", "skeleton")
	w := httptest.NewRecorder()
	s.handleConsoleTeamEditContext(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status: expected 200, got %d body=%s", w.Code, w.Body.String())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unexpected query pattern: %v", err)
	}
}

// TestHandleConsoleTeamEditContext_MissingTeamIDReturns400 — defensive
// 400 instead of a SQL error from GetTeam with empty arg.
func TestHandleConsoleTeamEditContext_MissingTeamIDReturns400(t *testing.T) {
	db, _, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer func() { _ = db.Close() }()
	s := &Server{db: db, logger: zap.NewNop()}

	r := httptest.NewRequest(http.MethodGet, "/api/v1/console/teams//edit-context", nil)
	r.SetPathValue("id", "")
	w := httptest.NewRecorder()
	s.handleConsoleTeamEditContext(w, r)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status: expected 400, got %d body=%s", w.Code, w.Body.String())
	}
}

// TestHandleConsoleTeamEditContext_FieldNames locks the contract for
// the surface refactor. If any of these JSON keys vanish the TS side
// breaks; this test catches it before the refactor diverges.
func TestHandleConsoleTeamEditContext_FieldNames(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer func() { _ = db.Close() }()

	teamID := uuid.New()
	collabID := uuid.New()
	mock.ExpectQuery(`FROM\s+public\.teams\s+WHERE\s+slug = \$1`).
		WillReturnRows(teamEditContextRowsForGetTeam(teamID, "x", "X", nil))
	mock.ExpectQuery(`FROM\s+public\.teams\s*ORDER BY`).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "slug", "name", "type", "status", "email", "parent_team_id",
			"owners", "traits", "metadata", "created_at", "updated_at",
		}))
	// Non-empty collaborator listing so the owner_candidates array has at
	// least one row — the member_of_this_team flag JSON key only appears
	// when at least one row serializes.
	mock.ExpectQuery(`FROM\s+public\.collaborators\s*ORDER BY`).
		WillReturnRows(teamEditContextRowsForListCollaborators(collabID, "alice", "Alice", "a@x.com"))
	// Inner GetTeam(uuid) before the membership SELECT
	mock.ExpectQuery(`FROM\s+public\.teams\s+WHERE\s+id = \$1`).
		WillReturnRows(teamEditContextRowsForGetTeam(teamID, "x", "X", nil))
	mock.ExpectQuery(`FROM\s+public\.team_memberships`).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "team_id", "team_slug", "collaborator_id", "collaborator_slug",
			"role", "active", "source", "starts_at", "ends_at", "metadata",
			"created_at", "updated_at",
		}))

	s := &Server{db: db, logger: zap.NewNop()}
	r := httptest.NewRequest(http.MethodGet, "/api/v1/console/teams/x/edit-context", nil)
	r.SetPathValue("id", "x")
	w := httptest.NewRecorder()
	s.handleConsoleTeamEditContext(w, r)

	body := w.Body.String()
	for _, key := range []string{
		`"team"`, `"parent_options"`, `"owner_candidates"`,
		`"active_memberships"`, `"other_memberships_by_collaborator"`,
		`"member_of_this_team"`,
	} {
		if !strings.Contains(body, key) {
			t.Errorf("missing canonical key %s in body=%s", key, body)
		}
	}
}
