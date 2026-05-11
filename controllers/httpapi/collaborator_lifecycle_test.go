package httpapi

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	"github.com/google/uuid"
	_ "github.com/lib/pq"
	"go.uber.org/zap"
)

func dbForLifecycleHandlerTest(t *testing.T) *sql.DB {
	t.Helper()
	dsn := os.Getenv("DB_URL")
	if dsn == "" {
		t.Skip("DB_URL not set; skipping lifecycle handler integration test")
	}
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	if err := db.Ping(); err != nil {
		t.Fatalf("ping db: %v", err)
	}
	return db
}

func cleanLifecycleFixtures(t *testing.T, db *sql.DB) {
	t.Helper()
	if _, err := db.Exec(`DELETE FROM public.lifecycle_events WHERE collaborator_id IN (SELECT id FROM public.collaborators WHERE slug LIKE 'lh-test-%')`); err != nil {
		t.Fatalf("delete lifecycle_events: %v", err)
	}
	if _, err := db.Exec(`DELETE FROM public.team_memberships WHERE collaborator_id IN (SELECT id FROM public.collaborators WHERE slug LIKE 'lh-test-%')`); err != nil {
		t.Fatalf("delete team_memberships: %v", err)
	}
	// Clean event_log rows for test collaborators so assertions are stable across runs.
	if _, err := db.Exec(`DELETE FROM public.event_log WHERE aggregate_type = 'collaborator' AND aggregate_id IN (SELECT id::text FROM public.collaborators WHERE slug LIKE 'lh-test-%')`); err != nil {
		t.Fatalf("delete event_log: %v", err)
	}
	if _, err := db.Exec(`DELETE FROM public.collaborators WHERE slug LIKE 'lh-test-%'`); err != nil {
		t.Fatalf("delete collaborators: %v", err)
	}
	if _, err := db.Exec(`DELETE FROM public.teams WHERE slug LIKE 'lh-test-team-%'`); err != nil {
		t.Fatalf("delete teams: %v", err)
	}
}

func newLifecycleTestServer(t *testing.T, db *sql.DB) http.Handler {
	t.Helper()
	logger, _ := zap.NewDevelopment()
	srv, err := New("test-yggdrasil-core", db, nil, logger)
	if err != nil {
		t.Fatalf("New server: %v", err)
	}
	return srv
}

func seedActiveCollaborator(t *testing.T, db *sql.DB, slug string) uuid.UUID {
	t.Helper()
	collab, err := repository.CreateCollaborator(context.Background(), db, model.CreateCollaboratorRequest{
		Slug:         "lh-test-" + slug,
		DisplayName:  "Lifecycle " + slug,
		PrimaryEmail: "lh-" + slug + "@dakasa.test",
		Status:       "active",
	})
	if err != nil {
		t.Fatalf("seed collaborator: %v", err)
	}
	return collab.ID
}

func postJSON(t *testing.T, srv http.Handler, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	buf, _ := json.Marshal(body)
	req := httptest.NewRequest("POST", path, bytes.NewReader(buf))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Actor", "test-suite")
	rr := httptest.NewRecorder()
	srv.ServeHTTP(rr, req)
	return rr
}

func TestOffboardCollaborator_Success(t *testing.T) {
	db := dbForLifecycleHandlerTest(t)
	defer func() { _ = db.Close() }()
	cleanLifecycleFixtures(t, db)

	collabID := seedActiveCollaborator(t, db, "off")
	srv := newLifecycleTestServer(t, db)

	rr := postJSON(t, srv, "/api/v1/collaborators/"+collabID.String()+"/offboard", map[string]any{
		"reason":   "voluntary",
		"end_date": "2026-06-01",
	})
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d body=%s", rr.Code, rr.Body.String())
	}
	collab, err := repository.GetCollaborator(context.Background(), db, collabID.String())
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if collab.Status != "offboarded" {
		t.Fatalf("expected status=offboarded, got %q", collab.Status)
	}
	events, err := repository.ListLifecycleEventsByCollaborator(context.Background(), db, model.ListLifecycleEventsRequest{
		CollaboratorID: collabID,
	})
	if err != nil {
		t.Fatalf("list events: %v", err)
	}
	var found bool
	for _, e := range events {
		if e.EventType == model.LifecycleEventOffboarded && e.Payload["reason"] == "voluntary" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected offboarded event with reason=voluntary, got %+v", events)
	}
}

func TestOffboardCollaborator_RejectsInvalidReason(t *testing.T) {
	db := dbForLifecycleHandlerTest(t)
	defer func() { _ = db.Close() }()
	cleanLifecycleFixtures(t, db)

	collabID := seedActiveCollaborator(t, db, "off-bad")
	srv := newLifecycleTestServer(t, db)

	rr := postJSON(t, srv, "/api/v1/collaborators/"+collabID.String()+"/offboard", map[string]any{"reason": "alien-abduction"})
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d body=%s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "reason") {
		t.Fatalf("expected error mention of reason, got %s", rr.Body.String())
	}
}

func TestSuspendUnsuspend_RoundTrip(t *testing.T) {
	db := dbForLifecycleHandlerTest(t)
	defer func() { _ = db.Close() }()
	cleanLifecycleFixtures(t, db)

	collabID := seedActiveCollaborator(t, db, "sus")
	srv := newLifecycleTestServer(t, db)

	if rr := postJSON(t, srv, "/api/v1/collaborators/"+collabID.String()+"/suspend", map[string]any{"reason": "investigation"}); rr.Code != http.StatusOK {
		t.Fatalf("suspend: expected 200, got %d body=%s", rr.Code, rr.Body.String())
	}
	if rr := postJSON(t, srv, "/api/v1/collaborators/"+collabID.String()+"/unsuspend", map[string]any{"reason": "cleared"}); rr.Code != http.StatusOK {
		t.Fatalf("unsuspend: expected 200, got %d body=%s", rr.Code, rr.Body.String())
	}
	collab, err := repository.GetCollaborator(context.Background(), db, collabID.String())
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if collab.Status != "active" {
		t.Fatalf("expected active after unsuspend, got %q", collab.Status)
	}
}

func TestReOnboard_FromOffboarded(t *testing.T) {
	db := dbForLifecycleHandlerTest(t)
	defer func() { _ = db.Close() }()
	cleanLifecycleFixtures(t, db)

	collab, err := repository.CreateCollaborator(context.Background(), db, model.CreateCollaboratorRequest{
		Slug:        "lh-test-reonboard",
		DisplayName: "Re-onboard",
		Status:      "offboarded",
	})
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	srv := newLifecycleTestServer(t, db)

	rr := postJSON(t, srv, "/api/v1/collaborators/"+collab.ID.String()+"/re-onboard", map[string]any{
		"new_start_date": "2026-08-01",
		"role":           "engineer",
	})
	if rr.Code != http.StatusOK {
		t.Fatalf("re-onboard: expected 200, got %d body=%s", rr.Code, rr.Body.String())
	}
	got, err := repository.GetCollaborator(context.Background(), db, collab.ID.String())
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Status != "pending_start" {
		t.Fatalf("expected pending_start, got %q", got.Status)
	}
}

func TestRoleChange_AppendsEvent(t *testing.T) {
	db := dbForLifecycleHandlerTest(t)
	defer func() { _ = db.Close() }()
	cleanLifecycleFixtures(t, db)

	collabID := seedActiveCollaborator(t, db, "role")
	srv := newLifecycleTestServer(t, db)

	rr := postJSON(t, srv, "/api/v1/collaborators/"+collabID.String()+"/role-change", map[string]any{"new_role": "senior-engineer"})
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rr.Code, rr.Body.String())
	}
	got, err := repository.GetCollaborator(context.Background(), db, collabID.String())
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if v, _ := got.EmploymentData["role"].(string); v != "senior-engineer" {
		t.Fatalf("expected employment_data.role=senior-engineer, got %v", got.EmploymentData)
	}
}

func TestAttributeSet_AppendsToTraits(t *testing.T) {
	db := dbForLifecycleHandlerTest(t)
	defer func() { _ = db.Close() }()
	cleanLifecycleFixtures(t, db)

	collabID := seedActiveCollaborator(t, db, "attr")
	srv := newLifecycleTestServer(t, db)

	rr := postJSON(t, srv, "/api/v1/collaborators/"+collabID.String()+"/attribute-set", map[string]any{
		"key":   "level",
		"value": "senior",
	})
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rr.Code, rr.Body.String())
	}
	got, err := repository.GetCollaborator(context.Background(), db, collabID.String())
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Traits["level"] != "senior" {
		t.Fatalf("expected traits.level=senior, got %v", got.Traits)
	}
}

func TestAbsenceStart_LongLeaveTransitionsToOnLeave(t *testing.T) {
	db := dbForLifecycleHandlerTest(t)
	defer func() { _ = db.Close() }()
	cleanLifecycleFixtures(t, db)

	collabID := seedActiveCollaborator(t, db, "abs")
	srv := newLifecycleTestServer(t, db)

	rr := postJSON(t, srv, "/api/v1/collaborators/"+collabID.String()+"/absence/start", map[string]any{
		"type":          "leave-medical",
		"from":          "2026-06-01",
		"to":            "2026-09-01",
		"duration_days": 92,
	})
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rr.Code, rr.Body.String())
	}
	got, err := repository.GetCollaborator(context.Background(), db, collabID.String())
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Status != "on_leave" {
		t.Fatalf("expected on_leave, got %q", got.Status)
	}

	rr2 := postJSON(t, srv, "/api/v1/collaborators/"+collabID.String()+"/absence/end", map[string]any{
		"actual_end": "2026-08-15",
	})
	if rr2.Code != http.StatusOK {
		t.Fatalf("absence/end expected 200, got %d body=%s", rr2.Code, rr2.Body.String())
	}
	got2, err := repository.GetCollaborator(context.Background(), db, collabID.String())
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got2.Status != "active" {
		t.Fatalf("expected active after absence end, got %q", got2.Status)
	}
}

func TestGetLifecycleEvents_ReturnsAppendedEntries(t *testing.T) {
	db := dbForLifecycleHandlerTest(t)
	defer func() { _ = db.Close() }()
	cleanLifecycleFixtures(t, db)

	collabID := seedActiveCollaborator(t, db, "audit")
	srv := newLifecycleTestServer(t, db)

	if rr := postJSON(t, srv, "/api/v1/collaborators/"+collabID.String()+"/suspend", map[string]any{"reason": "audit"}); rr.Code != http.StatusOK {
		t.Fatalf("seed suspend: %d", rr.Code)
	}
	req := httptest.NewRequest("GET", "/api/v1/collaborators/"+collabID.String()+"/lifecycle-events", nil)
	rr := httptest.NewRecorder()
	srv.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rr.Code, rr.Body.String())
	}
	var resp struct {
		Events []model.LifecycleEvent `json:"events"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(resp.Events) == 0 {
		t.Fatalf("expected at least one event")
	}
}

func TestCreateCollaborator_EmitsHiredEvent(t *testing.T) {
	db := dbForLifecycleHandlerTest(t)
	defer func() { _ = db.Close() }()
	cleanLifecycleFixtures(t, db)
	srv := newLifecycleTestServer(t, db)

	body, _ := json.Marshal(map[string]any{
		"slug":          "lh-test-hired",
		"display_name":  "Hired Event",
		"primary_email": "hired@dakasa.test",
		"status":        "pending_start",
		"employment_data": map[string]any{
			"start_date": "2026-08-01",
			"role":       "engineer",
		},
	})
	req := httptest.NewRequest("POST", "/api/v1/collaborators", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	srv.ServeHTTP(rr, req)
	if rr.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d body=%s", rr.Code, rr.Body.String())
	}
	var resp struct {
		Collaborator model.Collaborator `json:"collaborator"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	events, err := repository.ListLifecycleEventsByCollaborator(context.Background(), db, model.ListLifecycleEventsRequest{
		CollaboratorID: resp.Collaborator.ID,
		EventType:      model.LifecycleEventHired,
	})
	if err != nil {
		t.Fatalf("list events: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 hired event, got %d", len(events))
	}
	if events[0].Payload["start_date"] != "2026-08-01" {
		t.Fatalf("expected start_date=2026-08-01 in payload, got %v", events[0].Payload)
	}
}

func TestGetProviderState_EmptyByDefault(t *testing.T) {
	db := dbForLifecycleHandlerTest(t)
	defer func() { _ = db.Close() }()
	cleanLifecycleFixtures(t, db)

	collabID := seedActiveCollaborator(t, db, "ps")
	srv := newLifecycleTestServer(t, db)

	req := httptest.NewRequest("GET", "/api/v1/collaborators/"+collabID.String()+"/provider-state", nil)
	rr := httptest.NewRecorder()
	srv.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rr.Code, rr.Body.String())
	}
	var resp struct {
		ProviderState []model.CollaboratorProviderState `json:"provider_state"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.ProviderState == nil {
		t.Fatal("expected non-nil provider_state slice")
	}
	if len(resp.ProviderState) != 0 {
		t.Fatalf("expected empty provider_state, got %d rows", len(resp.ProviderState))
	}
}

func TestGetProviderState_ReturnsRows(t *testing.T) {
	db := dbForLifecycleHandlerTest(t)
	defer func() { _ = db.Close() }()
	cleanLifecycleFixtures(t, db)

	collabID := seedActiveCollaborator(t, db, "ps-rows")
	srv := newLifecycleTestServer(t, db)

	// Seed a provider state row directly via the repository.
	if _, err := repository.UpsertCollaboratorProviderState(context.Background(), db, model.UpsertProviderStateRequest{
		CollaboratorID: collabID,
		Provider:       "github",
		ExternalID:     "gh-123",
		DesiredState:   map[string]any{"active": true},
	}); err != nil {
		t.Fatalf("seed provider state: %v", err)
	}

	req := httptest.NewRequest("GET", "/api/v1/collaborators/"+collabID.String()+"/provider-state", nil)
	rr := httptest.NewRecorder()
	srv.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rr.Code, rr.Body.String())
	}
	var resp struct {
		ProviderState []model.CollaboratorProviderState `json:"provider_state"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(resp.ProviderState) != 1 {
		t.Fatalf("expected 1 provider_state row, got %d", len(resp.ProviderState))
	}
	if resp.ProviderState[0].Provider != "github" {
		t.Fatalf("expected provider=github, got %q", resp.ProviderState[0].Provider)
	}
	if resp.ProviderState[0].ExternalID != "gh-123" {
		t.Fatalf("expected external_id=gh-123, got %q", resp.ProviderState[0].ExternalID)
	}
}

func TestGetProviderState_UnknownCollaborator_Returns404(t *testing.T) {
	db := dbForLifecycleHandlerTest(t)
	defer func() { _ = db.Close() }()
	cleanLifecycleFixtures(t, db)

	srv := newLifecycleTestServer(t, db)

	// A well-formed UUID that has no corresponding collaborator row returns 404
	// (the handler resolves by UUID, finds no row, maps ErrCollaboratorNotFound → 404).
	nonExistentID := uuid.New()
	req := httptest.NewRequest("GET", "/api/v1/collaborators/"+nonExistentID.String()+"/provider-state", nil)
	rr := httptest.NewRecorder()
	srv.ServeHTTP(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for unknown collaborator, got %d body=%s", rr.Code, rr.Body.String())
	}
}

func TestGetConsoleProviderState_RouteRegistered(t *testing.T) {
	db := dbForLifecycleHandlerTest(t)
	defer func() { _ = db.Close() }()
	cleanLifecycleFixtures(t, db)

	collabID := seedActiveCollaborator(t, db, "ps-console")
	srv := newLifecycleTestServer(t, db)

	// Verify the /console/ path alias resolves the same handler.
	req := httptest.NewRequest("GET", "/api/v1/console/collaborators/"+collabID.String()+"/provider-state", nil)
	rr := httptest.NewRecorder()
	srv.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 on console route, got %d body=%s", rr.Code, rr.Body.String())
	}
	var resp struct {
		ProviderState []model.CollaboratorProviderState `json:"provider_state"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
}

// TestCreateCollaborator_EmitsCollaboratorCreatedEvent verifies that creating a
// collaborator via the HTTP handler causes a collaborator.created event to appear
// in event_log with the correct type, aggregate_id, and payload fields.
func TestCreateCollaborator_EmitsCollaboratorCreatedEvent(t *testing.T) {
	db := dbForLifecycleHandlerTest(t)
	defer func() { _ = db.Close() }()
	cleanLifecycleFixtures(t, db)
	srv := newLifecycleTestServer(t, db)

	body, _ := json.Marshal(map[string]any{
		"slug":          "lh-test-ev-created",
		"display_name":  "Event Created",
		"primary_email": "ev-created@dakasa.test",
		"status":        "active",
	})
	req := httptest.NewRequest("POST", "/api/v1/collaborators", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	srv.ServeHTTP(rr, req)
	if rr.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d body=%s", rr.Code, rr.Body.String())
	}
	var createResp struct {
		Collaborator model.Collaborator `json:"collaborator"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &createResp); err != nil {
		t.Fatalf("decode create response: %v", err)
	}
	collabID := createResp.Collaborator.ID

	// Pull events from event_log filtered to this collaborator.
	evResp, err := repository.PullEvents(context.Background(), db, model.PullEventsRequest{
		Limit: 10,
		Filters: model.PullEventsFilters{
			Types:         []string{"collaborator.created"},
			AggregateType: "collaborator",
			AggregateID:   collabID.String(),
		},
	})
	if err != nil {
		t.Fatalf("PullEvents: %v", err)
	}
	if len(evResp.Events) != 1 {
		t.Fatalf("expected 1 collaborator.created event in event_log, got %d", len(evResp.Events))
	}

	ev := evResp.Events[0]
	if ev.Type != "collaborator.created" {
		t.Errorf("event type: got %q, want collaborator.created", ev.Type)
	}
	if ev.AggregateID != collabID.String() {
		t.Errorf("aggregate_id: got %q, want %q", ev.AggregateID, collabID.String())
	}
	var payload map[string]any
	if err := json.Unmarshal(ev.Payload, &payload); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	if payload["collaborator_id"] != collabID.String() {
		t.Errorf("payload.collaborator_id: got %v, want %s", payload["collaborator_id"], collabID.String())
	}
	if payload["primary_email"] != "ev-created@dakasa.test" {
		t.Errorf("payload.primary_email: got %v, want ev-created@dakasa.test", payload["primary_email"])
	}
}

// TestOffboardCollaborator_EmitsCollaboratorOffboardedEvent verifies that
// offboarding a collaborator via the HTTP handler causes a
// collaborator.offboarded event to appear in event_log with the correct
// type, aggregate_id, and payload fields (including reason).
func TestOffboardCollaborator_EmitsCollaboratorOffboardedEvent(t *testing.T) {
	db := dbForLifecycleHandlerTest(t)
	defer func() { _ = db.Close() }()
	cleanLifecycleFixtures(t, db)

	collabID := seedActiveCollaborator(t, db, "ev-offboarded")
	srv := newLifecycleTestServer(t, db)

	rr := postJSON(t, srv, "/api/v1/collaborators/"+collabID.String()+"/offboard", map[string]any{
		"reason":   "involuntary",
		"end_date": "2026-07-01",
	})
	if rr.Code != http.StatusOK {
		t.Fatalf("offboard: expected 200, got %d body=%s", rr.Code, rr.Body.String())
	}

	evResp, err := repository.PullEvents(context.Background(), db, model.PullEventsRequest{
		Limit: 10,
		Filters: model.PullEventsFilters{
			Types:         []string{"collaborator.offboarded"},
			AggregateType: "collaborator",
			AggregateID:   collabID.String(),
		},
	})
	if err != nil {
		t.Fatalf("PullEvents: %v", err)
	}
	if len(evResp.Events) != 1 {
		t.Fatalf("expected 1 collaborator.offboarded event in event_log, got %d", len(evResp.Events))
	}

	ev := evResp.Events[0]
	if ev.Type != "collaborator.offboarded" {
		t.Errorf("event type: got %q, want collaborator.offboarded", ev.Type)
	}
	if ev.AggregateID != collabID.String() {
		t.Errorf("aggregate_id: got %q, want %q", ev.AggregateID, collabID.String())
	}
	var payload map[string]any
	if err := json.Unmarshal(ev.Payload, &payload); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	if payload["reason"] != "involuntary" {
		t.Errorf("payload.reason: got %v, want involuntary", payload["reason"])
	}
	if payload["end_date"] != "2026-07-01" {
		t.Errorf("payload.end_date: got %v, want 2026-07-01", payload["end_date"])
	}
}
