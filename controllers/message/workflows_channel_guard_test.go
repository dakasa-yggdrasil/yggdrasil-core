package message

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/workflowdispatchlock"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-sdk-go/rpc"
	"github.com/google/uuid"
)

const actorlessLegacyWorkflowSpec = `{
	"trigger":{"mode":"manual"},
	"steps":[{
		"id":"assert-same",
		"use":{"kind":"yggdrasil","operation":"assert"},
		"with":{"equal":[{"name":"same","actual":"ok","expected":"ok"}]}
	}]
}`

const actorlessProtectedWorkflowSpec = `{
	"trigger":{"mode":"manual"},
	"authorization":{"rbac":{"namespace":"dakasa","name":"operators"}},
	"steps":[{
		"id":"assert-same",
		"use":{"kind":"yggdrasil","operation":"assert"},
		"with":{"equal":[{"name":"same","actual":"ok","expected":"ok"}]}
	}]
}`

func TestWorkflowRunAMQPRejectsProtectedWorkflow(t *testing.T) {
	t.Setenv(workflowdispatchlock.EnvName, `{"mode":"off","allowed_workflows":[]}`)
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })

	expectActorlessChannelWorkflow(mock, actorlessProtectedWorkflowSpec)
	body, err := json.Marshal(model.RunWorkflowRequest{
		Workflow: model.ManifestSelector{Namespace: "dakasa", Name: "lifecycle"},
	})
	if err != nil {
		t.Fatal(err)
	}

	var response rpcResponse
	delivery := rpc.Delivery{
		Body:    body,
		ReplyTo: "test-reply",
		ReplyFn: func(_ context.Context, reply []byte, _ string) error {
			return json.Unmarshal(reply, &response)
		},
	}
	if err := workflowRunHandler(nil, db, nil)(context.Background(), delivery); err != nil {
		t.Fatal(err)
	}
	if response.Error == nil || response.Error.Code != "workflow_authenticated_actor_required" {
		t.Fatalf("response error = %#v, want workflow_authenticated_actor_required", response.Error)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("protected AMQP workflow crossed the execution boundary: %v", err)
	}
}

func TestUnauthenticatedChannelKeepsLegacyWorkflowRunnable(t *testing.T) {
	t.Setenv(workflowdispatchlock.EnvName, `{"mode":"off","allowed_workflows":[]}`)
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })

	expectActorlessChannelWorkflow(mock, actorlessLegacyWorkflowSpec)
	response, err := RunWorkflowFromUnauthenticatedChannel(context.Background(), nil, db, model.RunWorkflowRequest{
		Workflow: model.ManifestSelector{Namespace: "dakasa", Name: "lifecycle"},
	})
	if err != nil {
		t.Fatalf("legacy workflow refused: %v", err)
	}
	if response.Status != "succeeded" {
		t.Fatalf("legacy workflow status = %q, want succeeded", response.Status)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("legacy workflow was resolved more than once: %v", err)
	}
}

func TestRepositoryBindingRunRejectsProtectedWorkflowBeforePersistence(t *testing.T) {
	t.Setenv(workflowdispatchlock.EnvName, `{"mode":"off","allowed_workflows":[]}`)
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })

	expectActorlessChannelWorkflow(mock, actorlessProtectedWorkflowSpec)
	_, err = PrepareInsertAndRunWorkflowFromUnauthenticatedChannel(
		context.Background(),
		nil,
		db,
		uuid.New(),
		model.RunWorkflowRequest{Workflow: model.ManifestSelector{Namespace: "dakasa", Name: "lifecycle"}},
	)
	if !errors.Is(err, ErrWorkflowAuthenticatedActorRequired) {
		t.Fatalf("error = %v, want ErrWorkflowAuthenticatedActorRequired", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("protected repository-binding workflow was persisted: %v", err)
	}
}

func TestRepositoryBindingRunExecutesTheCheckedLegacySpec(t *testing.T) {
	t.Setenv(workflowdispatchlock.EnvName, `{"mode":"off","allowed_workflows":[]}`)
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })

	expectActorlessChannelWorkflow(mock, actorlessLegacyWorkflowSpec)
	runID := uuid.New()
	mock.ExpectExec(`INSERT INTO public\.workflow_runs`).
		WithArgs(runID, "dakasa", "lifecycle", nil, `null`, `{}`).
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectExec(`UPDATE public\.workflow_runs\s+SET status = 'running'`).
		WithArgs(runID, sqlmock.AnyArg()).
		WillReturnResult(sqlmock.NewResult(0, 1))

	response, err := PrepareInsertAndRunWorkflowFromUnauthenticatedChannel(
		context.Background(),
		nil,
		db,
		runID,
		model.RunWorkflowRequest{Workflow: model.ManifestSelector{Namespace: "dakasa", Name: "lifecycle"}},
	)
	if err != nil {
		t.Fatalf("legacy repository-binding workflow refused: %v", err)
	}
	if response.Status != "succeeded" {
		t.Fatalf("legacy repository-binding status = %q, want succeeded", response.Status)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("repository-binding execution did not reuse the checked spec: %v", err)
	}
}

func expectActorlessChannelWorkflow(mock sqlmock.Sqlmock, spec string) {
	now := time.Now().UTC()
	rows := sqlmock.NewRows(workflowManifestColumns()).AddRow(
		uuid.New(),
		"yggdrasil.io/v1alpha1",
		"workflow",
		"dakasa",
		"lifecycle",
		1,
		true,
		"",
		[]byte(`{}`),
		[]byte(spec),
		"sha256:test",
		now,
		now,
	)
	mock.ExpectQuery(`(?s)FROM public\.manifests\s+WHERE kind = \$1 AND namespace = \$2 AND name = \$3\s+AND active = TRUE`).
		WithArgs("workflow", "dakasa", "lifecycle").
		WillReturnRows(rows)
}
