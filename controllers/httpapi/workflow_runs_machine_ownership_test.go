package httpapi

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
	amqp "github.com/rabbitmq/amqp091-go"
)

func TestHandleWorkflowRunGetReturnsNotFoundForForeignMachineRun(t *testing.T) {
	t.Setenv("YGGDRASIL_WORKFLOW_RUN_TOKEN", "")
	t.Setenv(legacyScopedWorkflowTokensEnv, "")
	t.Setenv(workflowMachinePrincipalsEnv, testWorkflowMachinePrincipalsJSON(t, "ci-a-token", "ci-a",
		machineWorkflowRef{Namespace: "dakasa", Name: "deploy"}))

	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	runID := uuid.New()
	mock.ExpectQuery(`metadata ->> 'yggdrasil\.io/creator_machine_principal_id' = \$2`).
		WithArgs(runID, "ci-a").
		WillReturnRows(emptyWorkflowRunRows())

	server := &Server{db: db}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/workflow-runs/{run_id}", server.handleWorkflowRunGet)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/workflow-runs/"+runID.String(), nil)
	req.Header.Set("Authorization", "Bearer ci-a-token")
	recorder := httptest.NewRecorder()
	mux.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusNotFound {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestHandleWorkflowRunGetReturnsOwnedMachineRun(t *testing.T) {
	t.Setenv("YGGDRASIL_WORKFLOW_RUN_TOKEN", "")
	t.Setenv(legacyScopedWorkflowTokensEnv, "")
	t.Setenv(workflowMachinePrincipalsEnv, testWorkflowMachinePrincipalsJSON(t, "ci-a-token", "ci-a",
		machineWorkflowRef{Namespace: "dakasa", Name: "deploy"}))

	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	runID := uuid.New()
	now := time.Now().UTC()
	mock.ExpectQuery(`metadata ->> 'yggdrasil\.io/creator_machine_principal_id' = \$2`).
		WithArgs(runID, "ci-a").
		WillReturnRows(emptyWorkflowRunRows().AddRow(
			runID, "dakasa", "deploy", nil, "pending", []byte(`{}`),
			[]byte(`{"yggdrasil.io/creator_machine_principal_id":"ci-a"}`), nil, nil, nil, nil, now, now,
		))

	server := &Server{db: db}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/workflow-runs/{run_id}", server.handleWorkflowRunGet)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/workflow-runs/"+runID.String(), nil)
	req.Header.Set("Authorization", "Bearer ci-a-token")
	recorder := httptest.NewRecorder()
	mux.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), runID.String()) {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestAsyncIdempotencyRetryNeverReturnsForeignMachineRunID(t *testing.T) {
	t.Setenv("BROKER_URL", "amqp://unit-test")
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	expectWorkflowAuthorizationManifest(mock, "workflow", "deploy", `{
		"steps":[{
			"id":"observe",
			"use":{"kind":"integration","instance_ref":{"namespace":"dakasa","name":"example"},"operation":"observe_state"}
		}]
	}`)

	principalID := "ci-a"
	clientKey := "stable-request-key"
	persistedKey := scopedMachineWorkflowIdempotencyKey(principalID, clientKey)
	existingRunID := uuid.New()
	mock.ExpectQuery(`INSERT INTO public\.workflow_runs`).
		WithArgs(sqlmock.AnyArg(), "dakasa", "deploy", nil, `null`,
			`{"idempotency_key":"`+persistedKey+`","yggdrasil.io/creator_machine_principal_id":"ci-a"}`).
		WillReturnRows(sqlmock.NewRows([]string{"id"}))
	mock.ExpectQuery(`SELECT id, workflow_namespace, workflow_name`).
		WithArgs(persistedKey).
		WillReturnRows(sqlmock.NewRows([]string{"id", "workflow_namespace", "workflow_name"}).
			AddRow(existingRunID, "dakasa", "deploy"))
	mock.ExpectQuery(`SELECT EXISTS`).
		WithArgs(existingRunID, principalID).
		WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(false))

	server := &Server{db: db, rabbitmq: &amqp.Connection{}}
	recorder := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/workflow-runs?async=true", nil)
	server.dispatchAsyncWorkflowRun(recorder, req, model.RunWorkflowRequest{
		Workflow: model.ManifestSelector{Namespace: "dakasa", Name: "deploy"},
		Metadata: map[string]any{
			"idempotency_key": clientKey,
			// Must be overwritten by the authenticated actor before INSERT.
			"yggdrasil.io/creator_machine_principal_id": "spoofed-other-principal",
		},
	}, workflowRunActor{MachinePrincipalID: principalID})

	if recorder.Code != http.StatusNotFound {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if strings.Contains(recorder.Body.String(), existingRunID.String()) {
		t.Fatalf("foreign run id leaked in response: %s", recorder.Body.String())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestDispatchAsyncWorkflowRunUsesPanicSafeLauncher(t *testing.T) {
	t.Setenv("BROKER_URL", "amqp://unit-test")
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	expectWorkflowAuthorizationManifest(mock, "workflow", "deploy", `{
		"steps":[{
			"id":"observe",
			"use":{"kind":"integration","instance_ref":{"namespace":"dakasa","name":"example"},"operation":"observe_state"}
		}]
	}`)

	principalID := "ci-a"
	clientKey := "stable-request-key"
	persistedKey := scopedMachineWorkflowIdempotencyKey(principalID, clientKey)
	runID := uuid.New()
	mock.ExpectQuery(`INSERT INTO public\.workflow_runs`).
		WithArgs(sqlmock.AnyArg(), "dakasa", "deploy", nil, `null`,
			`{"idempotency_key":"`+persistedKey+`","yggdrasil.io/creator_machine_principal_id":"ci-a"}`).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(runID))

	originalLauncher := launchAsyncWorkflowRun
	var launchedName string
	var launchedFn func()
	launchAsyncWorkflowRun = func(name string, fn func()) {
		launchedName = name
		launchedFn = fn
	}
	t.Cleanup(func() { launchAsyncWorkflowRun = originalLauncher })

	server := &Server{db: db, rabbitmq: &amqp.Connection{}}
	recorder := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/workflow-runs?async=true", nil)
	server.dispatchAsyncWorkflowRun(recorder, req, model.RunWorkflowRequest{
		Workflow: model.ManifestSelector{Namespace: "dakasa", Name: "deploy"},
		Metadata: map[string]any{"idempotency_key": clientKey},
	}, workflowRunActor{MachinePrincipalID: principalID})

	if recorder.Code != http.StatusAccepted {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if launchedName != "workflow_run_async" || launchedFn == nil {
		t.Fatalf("async launcher = (%q, %v), want stable SafeGo wiring", launchedName, launchedFn != nil)
	}
	// Do not execute launchedFn: this test owns only the launch boundary, while
	// the panic-finalization behavior is exercised synchronously below.
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestMarkAsyncWorkflowRunFailedOnPanicPersistsGenericFailureAndRepanics(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	runID := uuid.New()
	mock.ExpectExec(`UPDATE public\.workflow_runs`).
		WithArgs(runID, "failed", "", asyncWorkflowRunPanicError, sqlmock.AnyArg()).
		WillReturnResult(sqlmock.NewResult(0, 1))

	panicValue := &struct{ secret string }{secret: "must-not-reach-durable-result"}
	var repanicked any
	func() {
		defer func() { repanicked = recover() }()
		defer markAsyncWorkflowRunFailedOnPanic(db, runID)
		panic(panicValue)
	}()

	if repanicked != panicValue {
		t.Fatalf("panic was not preserved for SafeGo recovery: %#v", repanicked)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestMarkAsyncWorkflowRunFailedOnPanicPreservesPanicWithoutDatabase(t *testing.T) {
	panicValue := errors.New("original panic")
	var repanicked any
	func() {
		defer func() { repanicked = recover() }()
		defer markAsyncWorkflowRunFailedOnPanic(nil, uuid.New())
		panic(panicValue)
	}()
	if repanicked != panicValue {
		t.Fatalf("nil database replaced original panic: %#v", repanicked)
	}
}

func emptyWorkflowRunRows() *sqlmock.Rows {
	return sqlmock.NewRows([]string{
		"id", "workflow_namespace", "workflow_name", "workflow_version", "status",
		"inputs", "metadata", "result", "error", "started_at", "finished_at", "created_at", "updated_at",
	})
}
