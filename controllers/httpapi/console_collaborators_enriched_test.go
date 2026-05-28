package httpapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

// Phase 6 — enriched collaborators tests (audit 2026-05-27 §2.3).

// TestResolveCanonicalRole_FallbackChain verifies the 6-step fallback
// from §1.2. Each priority level wins over the next when populated.
func TestResolveCanonicalRole_FallbackChain(t *testing.T) {
	tests := []struct {
		name string
		c    model.Collaborator
		want string
	}{
		{
			name: "traits.tartaro_roles wins",
			c: model.Collaborator{Traits: map[string]any{
				"tartaro_roles":   []any{"admin", "viewer"},
				"roles":           []any{"member"},
				"role":            "engineer",
				"employment_data": map[string]any{"role": "intern"},
			}},
			want: "admin",
		},
		{
			name: "traits.roles[0] when no tartaro_roles",
			c: model.Collaborator{Traits: map[string]any{
				"roles": []any{"engineer", "lead"},
			}},
			want: "engineer",
		},
		{
			name: "traits.role when no arrays",
			c: model.Collaborator{Traits: map[string]any{
				"role": "platform-lead",
			}},
			want: "platform-lead",
		},
		{
			name: "employment_data.role",
			c: model.Collaborator{EmploymentData: map[string]any{
				"role": "manager",
			}},
			want: "manager",
		},
		{
			name: "metadata.roles[0]",
			c: model.Collaborator{Metadata: map[string]any{
				"roles": []any{"ops"},
			}},
			want: "ops",
		},
		{
			name: "metadata.role",
			c: model.Collaborator{Metadata: map[string]any{
				"role": "intern",
			}},
			want: "intern",
		},
		{
			name: "nothing → empty",
			c:    model.Collaborator{},
			want: "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := resolveCanonicalRole(tc.c)
			if got != tc.want {
				t.Errorf("got %q want %q", got, tc.want)
			}
		})
	}
}

// TestEnrichCollaborators_AddsTeamNamesAndMFAFlags verifies the join
// produces the expected denormalized fields on each collaborator.
func TestEnrichCollaborators_AddsTeamNamesAndMFAFlags(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer func() { _ = db.Close() }()

	id1 := uuid.New()
	id2 := uuid.New()
	collabs := []model.Collaborator{
		{ID: id1, Slug: "alice", DisplayName: "Alice"},
		{ID: id2, Slug: "bob", DisplayName: "Bob"},
	}

	// 1. team_names query
	mock.ExpectQuery(`(?i)FROM\s+public\.team_memberships\s+tm\s+JOIN\s+public\.teams`).
		WithArgs(id1, id2).
		WillReturnRows(sqlmock.NewRows([]string{"collaborator_id", "name"}).
			AddRow(id1.String(), "Engineering").
			AddRow(id1.String(), "Design").
			AddRow(id2.String(), "Engineering"))

	// 2. auth_identities query
	mfaTime := time.Now().Add(-24 * time.Hour)
	mock.ExpectQuery(`(?i)FROM\s+public\.auth_identities`).
		WithArgs(id1, id2).
		WillReturnRows(sqlmock.NewRows([]string{"collaborator_id", "last_login_at", "mfa_enrolled_at"}).
			AddRow(id1.String(), time.Now(), mfaTime).
			AddRow(id2.String(), nil, nil))

	rows, err := enrichCollaborators(t.Context(), db, collabs)
	if err != nil {
		t.Fatalf("enrichCollaborators: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("rows: got %d want 2", len(rows))
	}

	if got := rows[0].TeamNames; len(got) != 2 || got[0] != "Engineering" || got[1] != "Design" {
		t.Errorf("rows[0].team_names: got %v want [Engineering Design]", got)
	}
	if !rows[0].MFAEnrolled {
		t.Errorf("rows[0].mfa_enrolled: expected true")
	}
	if rows[0].LastLoginAt == nil {
		t.Errorf("rows[0].last_login_at: expected non-nil")
	}
	if rows[1].MFAEnrolled {
		t.Errorf("rows[1].mfa_enrolled: expected false (no auth identity)")
	}
	if len(rows[1].TeamNames) != 1 || rows[1].TeamNames[0] != "Engineering" {
		t.Errorf("rows[1].team_names: got %v want [Engineering]", rows[1].TeamNames)
	}
}

// TestEnrichCollaborators_EmptyInputReturnsEmptyOutput — defensive
// short-circuit so we never hit the DB with empty IN ().
func TestEnrichCollaborators_EmptyInputReturnsEmptyOutput(t *testing.T) {
	db, _, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer func() { _ = db.Close() }()

	rows, err := enrichCollaborators(t.Context(), db, nil)
	if err != nil {
		t.Fatalf("enrichCollaborators: %v", err)
	}
	if len(rows) != 0 {
		t.Errorf("rows: got %d want 0", len(rows))
	}
}

// TestHandleCollaboratorList_EnrichedFlagAddsDenormalizedFields verifies
// that ?enriched=true triggers the enrichment path and the response
// envelope includes team_names + primary_role + mfa_enrolled keys.
func TestHandleCollaboratorList_EnrichedFlagAddsDenormalizedFields(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer func() { _ = db.Close() }()

	id := uuid.New()
	// ListCollaborators returns one row.
	mock.ExpectQuery(`(?i)FROM\s+public\.collaborators`).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "slug", "status", "display_name", "primary_email", "manager_id", "primary_team_id",
			"personal_data", "employment_data", "third_party_identities", "traits", "metadata", "version",
			"created_at", "updated_at",
		}).AddRow(
			id.String(), "alice", "active", "Alice Allen", "alice@example.com", "", "",
			[]byte("{}"), []byte(`{"role":"engineer"}`), []byte("{}"), []byte("{}"), []byte("{}"), 1,
			time.Now(), time.Now(),
		))

	// Enrichment queries.
	mock.ExpectQuery(`(?i)FROM\s+public\.team_memberships`).
		WillReturnRows(sqlmock.NewRows([]string{"collaborator_id", "name"}).
			AddRow(id.String(), "Engineering"))
	mock.ExpectQuery(`(?i)FROM\s+public\.auth_identities`).
		WillReturnRows(sqlmock.NewRows([]string{"collaborator_id", "last_login_at", "mfa_enrolled_at"}).
			AddRow(id.String(), time.Now(), time.Now()))

	s := &Server{db: db, logger: zap.NewNop()}
	r := httptest.NewRequest(http.MethodGet, "/api/v1/console/collaborators?enriched=true", nil)
	w := httptest.NewRecorder()
	s.handleCollaboratorList(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status: expected 200, got %d body=%s", w.Code, w.Body.String())
	}
	body := w.Body.String()
	for _, key := range []string{`"team_names"`, `"primary_role"`, `"mfa_enrolled"`, `"last_login_at"`} {
		if !strings.Contains(body, key) {
			t.Errorf("missing enriched key %s in body=%s", key, body)
		}
	}
	if !strings.Contains(body, `"primary_role":"engineer"`) {
		t.Errorf("expected primary_role=engineer (resolved from employment_data.role), got %s", body)
	}
}

// TestHandleCollaboratorList_NoEnrichedFlagReturnsLegacyShape — the
// existing CLI/ops callers must not break. The enriched fields are
// gated behind ?enriched=true; without it the response stays the same
// shape it has always been.
func TestHandleCollaboratorList_NoEnrichedFlagReturnsLegacyShape(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer func() { _ = db.Close() }()

	mock.ExpectQuery(`(?i)FROM\s+public\.collaborators`).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "slug", "status", "display_name", "primary_email", "manager_id", "primary_team_id",
			"personal_data", "employment_data", "third_party_identities", "traits", "metadata", "version",
			"created_at", "updated_at",
		}).AddRow(
			uuid.New().String(), "alice", "active", "Alice Allen", "alice@example.com", "", "",
			[]byte("{}"), []byte("{}"), []byte("{}"), []byte("{}"), []byte("{}"), 1,
			time.Now(), time.Now(),
		))

	s := &Server{db: db, logger: zap.NewNop()}
	r := httptest.NewRequest(http.MethodGet, "/api/v1/console/collaborators", nil)
	w := httptest.NewRecorder()
	s.handleCollaboratorList(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status: expected 200, got %d body=%s", w.Code, w.Body.String())
	}
	body := w.Body.String()
	if strings.Contains(body, `"team_names"`) {
		t.Errorf("legacy shape should NOT include team_names, got %s", body)
	}
	var resp collaboratorsResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Errorf("legacy response should decode to collaboratorsResponse: %v", err)
	}
}

// TestEnrichedResponseEnvelopeShape locks down the JSON envelope field
// name so the FE refactor can rely on it.
func TestEnrichedResponseEnvelopeShape(t *testing.T) {
	r := collaboratorEnrichedResponse{
		Collaborators: []CollaboratorEnriched{
			{
				Collaborator: model.Collaborator{ID: uuid.New(), Slug: "alice"},
				TeamNames:    []string{"engineering"},
				PrimaryRole:  "engineer",
				MFAEnrolled:  true,
			},
		},
	}
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	body := string(b)
	if !strings.Contains(body, `"collaborators"`) {
		t.Errorf("envelope should have collaborators key, got %s", body)
	}
	if !strings.Contains(body, `"team_names":["engineering"]`) {
		t.Errorf("team_names should serialize as array, got %s", body)
	}
}
