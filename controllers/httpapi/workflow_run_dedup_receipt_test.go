package httpapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
	amqp "github.com/rabbitmq/amqp091-go"
)

func TestAsyncIdempotentRetryReportsPersistedVersionAfterRollout(t *testing.T) {
	t.Setenv("BROKER_URL", "amqp://unit-test")
	t.Setenv("YGGDRASIL_ENV", "dev")
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	newManifestID := uuid.New()
	const spec = `{"steps":[{"id":"observe","condition":"false","use":{"kind":"yggdrasil","operation":"oidc_client.verify_bootstrap_file"}}]}`
	now := time.Now().UTC()
	mock.ExpectQuery(`FROM public\.manifests\s+WHERE id = \$1`).WithArgs(newManifestID).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "api_version", "kind", "namespace", "name", "version", "active",
			"description", "labels", "spec", "checksum", "created_at", "updated_at",
		}).AddRow(newManifestID, "yggdrasil.io/v1alpha1", "workflow", "dakasa", "deploy", 2, true,
			"", []byte(`{}`), []byte(spec), "sha256:test", now, now))

	principalID := "ci-a"
	persistedKey := scopedMachineWorkflowIdempotencyKey(principalID, "same-action")
	oldRunID := uuid.New()
	mock.ExpectQuery(`INSERT INTO public\.workflow_runs`).
		WithArgs(sqlmock.AnyArg(), "dakasa", "deploy", 2, sqlmock.AnyArg(), sqlmock.AnyArg()).
		WillReturnRows(sqlmock.NewRows([]string{"id"}))
	mock.ExpectQuery(`SELECT id, workflow_namespace, workflow_name`).WithArgs(persistedKey).
		WillReturnRows(sqlmock.NewRows([]string{"id", "workflow_namespace", "workflow_name"}).
			AddRow(oldRunID, "dakasa", "deploy"))
	mock.ExpectQuery(`SELECT EXISTS`).WithArgs(oldRunID, principalID).
		WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(true))
	mock.ExpectQuery(`SELECT workflow_namespace, workflow_name, workflow_version`).WithArgs(oldRunID).
		WillReturnRows(sqlmock.NewRows([]string{
			"workflow_namespace", "workflow_name", "workflow_version",
		}).AddRow("dakasa", "deploy", 1))

	currentVersion := 2
	recorder := httptest.NewRecorder()
	(&Server{db: db, rabbitmq: &amqp.Connection{}}).dispatchAsyncWorkflowRun(
		recorder,
		httptest.NewRequest(http.MethodPost, "/api/v1/workflow-runs?async=true", nil),
		model.RunWorkflowRequest{
			Workflow: model.ManifestSelector{
				ManifestID: newManifestID.String(), Namespace: "dakasa", Name: "deploy", Version: &currentVersion,
			},
			Metadata: map[string]any{"idempotency_key": "same-action"},
		},
		workflowRunActor{MachinePrincipalID: principalID},
	)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var receipt struct {
		RunID    string                 `json:"run_id"`
		Status   string                 `json:"status"`
		Workflow model.ManifestSelector `json:"workflow"`
		Deduped  bool                   `json:"deduped"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &receipt); err != nil {
		t.Fatal(err)
	}
	if receipt.RunID != oldRunID.String() || receipt.Status != "accepted" || !receipt.Deduped ||
		receipt.Workflow.ManifestID != "" || receipt.Workflow.Namespace != "dakasa" ||
		receipt.Workflow.Name != "deploy" || receipt.Workflow.Version == nil || *receipt.Workflow.Version != 1 {
		t.Fatalf("retry receipt describes new request rather than original run: %#v", receipt)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}
