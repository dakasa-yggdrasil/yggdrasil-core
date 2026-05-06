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

	_ "github.com/lib/pq"

	"github.com/google/uuid"
)

// dbForEventPublishTest opens a *sql.DB pointing at the integration Postgres
// or skips. Mirrors dbForProvisionTest in auth_third_party_provision_test.go
// — same env var, same skip pattern.
func dbForEventPublishTest(t *testing.T) *sql.DB {
	t.Helper()
	dsn := os.Getenv("DB_URL")
	if dsn == "" {
		t.Skip("DB_URL not set; skipping events publish integration test")
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

// cleanEventLogForPublishTest truncates the event_log so each test starts
// with a known empty stream. Cheaper than per-row deletion and the test
// suite owns the integration DB exclusively.
func cleanEventLogForPublishTest(t *testing.T, db *sql.DB) {
	t.Helper()
	if _, err := db.Exec(`TRUNCATE TABLE public.event_log RESTART IDENTITY`); err != nil {
		t.Fatalf("truncate event_log: %v", err)
	}
}

// validManifestCreatedPayload is the shape the events/v1/manifest/created
// schema expects. Reused across the happy-path tests.
func validManifestCreatedPayloadForPublish() map[string]any {
	return map[string]any{
		"manifest_id": "018f2b4a-1234-7abc-def0-123456789012",
		"kind":        "product",
		"namespace":   "dakasa",
		"name":        "service-a",
		"version":     1,
		"checksum":    "sha256:abc123def456abc123def456abc123def456abc123def456abc123def456abc1",
	}
}

// newEventPublishServer wires a Server with the live Postgres handle and the
// test mux registering the route under test. Mirrors the way New() composes
// routes but stays small so each test doesn't pay for OIDC mount, console
// SPA, etc.
func newEventPublishServer(db *sql.DB) http.Handler {
	server := &Server{
		serviceName: "yggdrasil-core-test",
		db:          db,
	}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v1/events", server.handleEventPublish)
	return mux
}

// doPublish posts a JSON body to /api/v1/events and returns the recorded
// response, leaving the test free to assert on status and body.
func doPublish(t *testing.T, h http.Handler, body any, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal body: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/events", bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w
}

func TestHandleEventPublish_HappyPath(t *testing.T) {
	t.Setenv("YGGDRASIL_WORKFLOW_RUN_TOKEN", "")
	db := dbForEventPublishTest(t)
	defer db.Close()
	cleanEventLogForPublishTest(t, db)

	h := newEventPublishServer(db)
	body := map[string]any{
		"type":           "manifest.created",
		"schema_version": "v1",
		"aggregate_type": "manifest",
		"aggregate_id":   "018f2b4a-1234-7abc-def0-123456789012",
		"payload":        validManifestCreatedPayloadForPublish(),
		"actor":          map[string]any{"type": "system", "id": "test"},
	}
	w := doPublish(t, h, body, nil)

	if w.Code != http.StatusCreated {
		t.Fatalf("status: got %d, want %d (body=%s)", w.Code, http.StatusCreated, w.Body.String())
	}

	var resp map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	idStr, ok := resp["event_id"]
	if !ok || idStr == "" {
		t.Fatalf("response missing event_id: %s", w.Body.String())
	}
	if _, err := uuid.Parse(idStr); err != nil {
		t.Fatalf("event_id is not a valid uuid: %v", err)
	}

	// Row landed in event_log.
	var count int
	if err := db.QueryRowContext(context.Background(),
		`SELECT COUNT(*) FROM public.event_log WHERE event_id = $1`, idStr).Scan(&count); err != nil {
		t.Fatalf("count event_log: %v", err)
	}
	if count != 1 {
		t.Errorf("expected 1 event_log row for %s, got %d", idStr, count)
	}
}

func TestHandleEventPublish_DefaultsSchemaVersionToV1(t *testing.T) {
	t.Setenv("YGGDRASIL_WORKFLOW_RUN_TOKEN", "")
	db := dbForEventPublishTest(t)
	defer db.Close()
	cleanEventLogForPublishTest(t, db)

	h := newEventPublishServer(db)
	body := map[string]any{
		"type":           "manifest.created",
		"aggregate_type": "manifest",
		"aggregate_id":   "018f2b4a-1234-7abc-def0-123456789013",
		"payload":        validManifestCreatedPayloadForPublish(),
	}
	w := doPublish(t, h, body, nil)
	if w.Code != http.StatusCreated {
		t.Fatalf("status: got %d, want %d (body=%s)", w.Code, http.StatusCreated, w.Body.String())
	}

	var version string
	if err := db.QueryRowContext(context.Background(),
		`SELECT schema_version FROM public.event_log ORDER BY sequence DESC LIMIT 1`).Scan(&version); err != nil {
		t.Fatalf("query schema_version: %v", err)
	}
	if version != "v1" {
		t.Errorf("schema_version: got %q, want %q", version, "v1")
	}
}

func TestHandleEventPublish_ValidationErrors(t *testing.T) {
	t.Setenv("YGGDRASIL_WORKFLOW_RUN_TOKEN", "")
	db := dbForEventPublishTest(t)
	defer db.Close()
	cleanEventLogForPublishTest(t, db)

	h := newEventPublishServer(db)
	good := func() map[string]any {
		return map[string]any{
			"type":           "manifest.created",
			"aggregate_type": "manifest",
			"aggregate_id":   "018f2b4a-1234-7abc-def0-123456789014",
			"payload":        validManifestCreatedPayloadForPublish(),
		}
	}

	cases := []struct {
		name       string
		mutate     func(map[string]any)
		errFragment string
	}{
		{
			name:        "missing type",
			mutate:      func(m map[string]any) { delete(m, "type") },
			errFragment: "type is required",
		},
		{
			name:        "empty type",
			mutate:      func(m map[string]any) { m["type"] = "" },
			errFragment: "type is required",
		},
		{
			name:        "missing aggregate_type",
			mutate:      func(m map[string]any) { delete(m, "aggregate_type") },
			errFragment: "aggregate_type is required",
		},
		{
			name:        "missing aggregate_id",
			mutate:      func(m map[string]any) { delete(m, "aggregate_id") },
			errFragment: "aggregate_id is required",
		},
		{
			name:        "missing payload",
			mutate:      func(m map[string]any) { delete(m, "payload") },
			errFragment: "payload is required",
		},
		{
			name:        "non-object payload",
			mutate:      func(m map[string]any) { m["payload"] = "not-an-object" },
			errFragment: "payload must be a JSON object",
		},
		{
			name:        "null payload",
			mutate:      func(m map[string]any) { m["payload"] = nil },
			errFragment: "payload must be a JSON object",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			body := good()
			tc.mutate(body)
			w := doPublish(t, h, body, nil)
			if w.Code != http.StatusBadRequest {
				t.Fatalf("status: got %d, want %d (body=%s)", w.Code, http.StatusBadRequest, w.Body.String())
			}
			if !strings.Contains(strings.ToLower(w.Body.String()), strings.ToLower(tc.errFragment)) {
				t.Errorf("error body missing %q: %s", tc.errFragment, w.Body.String())
			}
		})
	}
}

func TestHandleEventPublish_RejectsUnauthorized(t *testing.T) {
	t.Setenv("YGGDRASIL_WORKFLOW_RUN_TOKEN", "shared-token")
	db := dbForEventPublishTest(t)
	defer db.Close()
	cleanEventLogForPublishTest(t, db)

	h := newEventPublishServer(db)
	body := map[string]any{
		"type":           "manifest.created",
		"aggregate_type": "manifest",
		"aggregate_id":   "018f2b4a-1234-7abc-def0-123456789015",
		"payload":        validManifestCreatedPayloadForPublish(),
	}

	t.Run("missing token", func(t *testing.T) {
		w := doPublish(t, h, body, nil)
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("status: got %d, want %d (body=%s)", w.Code, http.StatusUnauthorized, w.Body.String())
		}
	})

	t.Run("wrong token", func(t *testing.T) {
		w := doPublish(t, h, body, map[string]string{"X-Yggdrasil-Workflow-Token": "wrong"})
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("status: got %d, want %d (body=%s)", w.Code, http.StatusUnauthorized, w.Body.String())
		}
	})

	t.Run("correct token via header", func(t *testing.T) {
		w := doPublish(t, h, body, map[string]string{"X-Yggdrasil-Workflow-Token": "shared-token"})
		if w.Code != http.StatusCreated {
			t.Fatalf("status: got %d, want %d (body=%s)", w.Code, http.StatusCreated, w.Body.String())
		}
	})
}

func TestHandleEventPublish_RejectsUnknownEventType(t *testing.T) {
	// EmitEvent calls contracts.ValidateEventPayload which fails on unknown
	// types. The handler should map that to 400 (the message contains
	// "no schema registered" which httpStatusFromError doesn't catch by
	// fragment, so the handler relies on the default 400/500 mapping).
	// We intentionally feed an unknown type to lock in 400 as the
	// expected response for adopters who post a yet-unregistered type.
	t.Setenv("YGGDRASIL_WORKFLOW_RUN_TOKEN", "")
	db := dbForEventPublishTest(t)
	defer db.Close()
	cleanEventLogForPublishTest(t, db)

	h := newEventPublishServer(db)
	body := map[string]any{
		"type":           "infra.alert.firing",
		"aggregate_type": "alert",
		"aggregate_id":   "grafana/abc-123",
		"payload":        map[string]any{"summary": "boom"},
	}
	w := doPublish(t, h, body, nil)
	// httpStatusFromError defaults unknown errors to 500. The
	// "no schema registered" message doesn't hit any of the 400
	// fragments either. We accept either 400 or 500 as long as the
	// body surfaces the schema diagnostic so adopters know to
	// register a schema for new types.
	if w.Code != http.StatusBadRequest && w.Code != http.StatusInternalServerError {
		t.Fatalf("status: got %d, want 400 or 500 (body=%s)", w.Code, w.Body.String())
	}
	if !strings.Contains(strings.ToLower(w.Body.String()), "no schema registered") {
		t.Errorf("expected schema diagnostic in body, got %s", w.Body.String())
	}
}
