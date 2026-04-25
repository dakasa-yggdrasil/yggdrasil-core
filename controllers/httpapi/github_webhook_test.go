package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"sync"
	"testing"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"go.uber.org/zap"
)

const findBindingQuery = `SELECT namespace, name, COALESCE(description, ''), spec`

func newWebhookTestServer(t *testing.T) (*Server, sqlmock.Sqlmock, func()) {
	t.Helper()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New error: %v", err)
	}
	server := &Server{
		serviceName: "test",
		db:          db,
		logger:      zap.NewNop(),
	}
	server.dispatchWorkflow = func(ctx context.Context, ref model.ManifestSelector, inputs map[string]any) error {
		return nil
	}
	return server, mock, func() { _ = db.Close() }
}

func bindingRows(spec string) *sqlmock.Rows {
	return sqlmock.NewRows([]string{"namespace", "name", "description", "spec"}).
		AddRow("dakasa", "test-binding", "", []byte(spec))
}

func performPushRequest(t *testing.T, server *Server, body []byte) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest("POST", "/api/v1/github/webhook", strings.NewReader(string(body)))
	w := httptest.NewRecorder()
	server.handlePushEvent(w, r, body)
	return w
}

func pushPayload(repo string, ref string) []byte {
	body := map[string]any{
		"ref": ref,
		"repository": map[string]any{
			"full_name": repo,
			"clone_url": "https://github.com/" + repo + ".git",
		},
		"head_commit": map[string]any{
			"id":       "deadbeef0123456789",
			"message":  "test commit",
			"modified": []string{"deploy/overlay.yaml"},
		},
		"pusher": map[string]string{"name": "alice"},
	}
	out, _ := json.Marshal(body)
	return out
}

func TestPushEventInvalidJSONReturns400(t *testing.T) {
	server, _, cleanup := newWebhookTestServer(t)
	defer cleanup()
	w := performPushRequest(t, server, []byte("{not-json"))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status: got %d want 400", w.Code)
	}
}

func TestPushEventNoBindingReturns200Skip(t *testing.T) {
	server, mock, cleanup := newWebhookTestServer(t)
	defer cleanup()

	mock.ExpectQuery(regexp.QuoteMeta(findBindingQuery)).
		WithArgs("acme/widget").
		WillReturnRows(sqlmock.NewRows([]string{"namespace", "name", "description", "spec"}))

	w := performPushRequest(t, server, pushPayload("acme/widget", "refs/heads/main"))
	if w.Code != http.StatusOK {
		t.Fatalf("status: got %d want 200", w.Code)
	}
	if !strings.Contains(w.Body.String(), "no repository_binding") {
		t.Fatalf("body: %s", w.Body.String())
	}
}

func TestPushEventBindingWithoutDeployReturns200Skip(t *testing.T) {
	server, mock, cleanup := newWebhookTestServer(t)
	defer cleanup()

	spec := `{"component_kind":"product","component_name":"x","repository":"acme/widget","automation":{"observe":true}}`
	mock.ExpectQuery(regexp.QuoteMeta(findBindingQuery)).
		WithArgs("acme/widget").
		WillReturnRows(bindingRows(spec))

	w := performPushRequest(t, server, pushPayload("acme/widget", "refs/heads/main"))
	if w.Code != http.StatusOK {
		t.Fatalf("status: got %d want 200", w.Code)
	}
	if !strings.Contains(w.Body.String(), "binding has no deploy spec") {
		t.Fatalf("body: %s", w.Body.String())
	}
}

func TestPushEventBranchFilterMismatchReturns200Skip(t *testing.T) {
	server, mock, cleanup := newWebhookTestServer(t)
	defer cleanup()

	spec := `{
		"component_kind":"product","component_name":"x","repository":"acme/widget",
		"deploy":{
			"workflow_kind":"yggdrasil",
			"workflow_ref":{"namespace":"acme","name":"deploy"},
			"branch_filter":["main"]
		}
	}`
	mock.ExpectQuery(regexp.QuoteMeta(findBindingQuery)).
		WithArgs("acme/widget").
		WillReturnRows(bindingRows(spec))

	w := performPushRequest(t, server, pushPayload("acme/widget", "refs/heads/develop"))
	if w.Code != http.StatusOK {
		t.Fatalf("status: got %d want 200", w.Code)
	}
	if !strings.Contains(w.Body.String(), "outside branch_filter") {
		t.Fatalf("body: %s", w.Body.String())
	}
}

func TestPushEventPathFilterMismatchReturns200Skip(t *testing.T) {
	server, mock, cleanup := newWebhookTestServer(t)
	defer cleanup()

	spec := `{
		"component_kind":"product","component_name":"x","repository":"acme/widget",
		"deploy":{
			"workflow_kind":"yggdrasil",
			"workflow_ref":{"namespace":"acme","name":"deploy"},
			"branch_filter":["main"],
			"path_filter":["src/*"]
		}
	}`
	mock.ExpectQuery(regexp.QuoteMeta(findBindingQuery)).
		WithArgs("acme/widget").
		WillReturnRows(bindingRows(spec))

	// pushPayload modified is ["deploy/overlay.yaml"] which won't match src/*
	w := performPushRequest(t, server, pushPayload("acme/widget", "refs/heads/main"))
	if w.Code != http.StatusOK {
		t.Fatalf("status: got %d want 200", w.Code)
	}
	if !strings.Contains(w.Body.String(), "path_filter") {
		t.Fatalf("body: %s", w.Body.String())
	}
}

func TestPushEventDispatchesYggdrasilWorkflow(t *testing.T) {
	server, mock, cleanup := newWebhookTestServer(t)
	defer cleanup()

	spec := `{
		"component_kind":"product","component_name":"x","repository":"acme/widget",
		"deploy":{
			"workflow_kind":"yggdrasil",
			"workflow_ref":{"namespace":"acme","name":"deploy-via-kustomize-source"},
			"default_inputs":{
				"git_url":"{{ push.repository.clone_url }}",
				"revision":"{{ push.head_commit.id }}",
				"namespace":"acme"
			},
			"branch_filter":["main"]
		}
	}`
	mock.ExpectQuery(regexp.QuoteMeta(findBindingQuery)).
		WithArgs("acme/widget").
		WillReturnRows(bindingRows(spec))

	var (
		wg          sync.WaitGroup
		gotRef      model.ManifestSelector
		gotInputs   map[string]any
		gotCalled   bool
		dispatchMu  sync.Mutex
	)
	wg.Add(1)
	server.dispatchWorkflow = func(ctx context.Context, ref model.ManifestSelector, inputs map[string]any) error {
		dispatchMu.Lock()
		gotRef = ref
		gotInputs = inputs
		gotCalled = true
		dispatchMu.Unlock()
		wg.Done()
		return nil
	}

	w := performPushRequest(t, server, pushPayload("acme/widget", "refs/heads/main"))
	if w.Code != http.StatusAccepted {
		t.Fatalf("status: got %d want 202", w.Code)
	}
	wg.Wait()

	dispatchMu.Lock()
	defer dispatchMu.Unlock()
	if !gotCalled {
		t.Fatal("dispatcher was not called")
	}
	if gotRef.Namespace != "acme" || gotRef.Name != "deploy-via-kustomize-source" {
		t.Fatalf("ref: got %+v", gotRef)
	}
	if gotInputs["git_url"] != "https://github.com/acme/widget.git" {
		t.Fatalf("templated git_url: got %v", gotInputs["git_url"])
	}
	if gotInputs["revision"] != "deadbeef0123456789" {
		t.Fatalf("templated revision: got %v", gotInputs["revision"])
	}
	if gotInputs["namespace"] != "acme" {
		t.Fatalf("namespace: got %v", gotInputs["namespace"])
	}
}

func TestPushEventGithubActionsKindReturns501(t *testing.T) {
	server, mock, cleanup := newWebhookTestServer(t)
	defer cleanup()

	spec := `{
		"component_kind":"product","component_name":"x","repository":"acme/widget",
		"deploy":{
			"workflow_kind":"github_actions",
			"branch_filter":["main"]
		}
	}`
	mock.ExpectQuery(regexp.QuoteMeta(findBindingQuery)).
		WithArgs("acme/widget").
		WillReturnRows(bindingRows(spec))

	w := performPushRequest(t, server, pushPayload("acme/widget", "refs/heads/main"))
	if w.Code != http.StatusNotImplemented {
		t.Fatalf("status: got %d want 501", w.Code)
	}
}

func TestPushEventDispatchErrorReturns202StillButLogsError(t *testing.T) {
	// Dispatch is fire-and-forget: the handler returns 202 immediately
	// regardless of dispatch outcome. Error path is logged, not surfaced.
	// This test verifies that contract.
	server, mock, cleanup := newWebhookTestServer(t)
	defer cleanup()

	spec := `{
		"component_kind":"product","component_name":"x","repository":"acme/widget",
		"deploy":{
			"workflow_kind":"yggdrasil",
			"workflow_ref":{"namespace":"acme","name":"wf"},
			"branch_filter":["main"]
		}
	}`
	mock.ExpectQuery(regexp.QuoteMeta(findBindingQuery)).
		WithArgs("acme/widget").
		WillReturnRows(bindingRows(spec))

	var wg sync.WaitGroup
	wg.Add(1)
	server.dispatchWorkflow = func(ctx context.Context, ref model.ManifestSelector, inputs map[string]any) error {
		defer wg.Done()
		return errStub
	}

	w := performPushRequest(t, server, pushPayload("acme/widget", "refs/heads/main"))
	if w.Code != http.StatusAccepted {
		t.Fatalf("status: got %d want 202", w.Code)
	}
	wg.Wait()
}

var errStub = stubError("boom")

type stubError string

func (e stubError) Error() string { return string(e) }
