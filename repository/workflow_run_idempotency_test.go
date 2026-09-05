package repository

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

func TestInsertWorkflowRunIdempotentCreatesOnce(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	id := uuid.New()
	mock.ExpectQuery(`INSERT INTO public\.workflow_runs`).
		WithArgs(id, "dakasa", "remediate", nil, `{"x":1}`, `{"idempotency_key":"guardian:approval-1"}`).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(id))

	got, deduped, err := InsertWorkflowRunIdempotent(context.Background(), db, id,
		model.ManifestSelector{Name: "remediate", Namespace: "dakasa"},
		map[string]any{"x": 1}, map[string]any{"idempotency_key": "guardian:approval-1"})
	if err != nil || deduped || got != id {
		t.Fatalf("got id=%s deduped=%v err=%v", got, deduped, err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestInsertWorkflowRunIdempotentReturnsExistingRunOnRetry(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	requested := uuid.New()
	existing := uuid.New()
	mock.ExpectQuery(`INSERT INTO public\.workflow_runs`).
		WillReturnRows(sqlmock.NewRows([]string{"id"}))
	mock.ExpectQuery(`SELECT id, workflow_namespace, workflow_name`).
		WithArgs("guardian:approval-1").
		WillReturnRows(sqlmock.NewRows([]string{"id", "workflow_namespace", "workflow_name"}).
			AddRow(existing, "dakasa", "remediate"))

	got, deduped, err := InsertWorkflowRunIdempotent(context.Background(), db, requested,
		model.ManifestSelector{Name: "remediate", Namespace: "dakasa"}, nil,
		map[string]any{"idempotency_key": "guardian:approval-1"})
	if err != nil || !deduped || got != existing {
		t.Fatalf("got id=%s deduped=%v err=%v", got, deduped, err)
	}
}

func TestInsertWorkflowRunIdempotentRejectsKeyReuseForDifferentWorkflow(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	mock.ExpectQuery(`INSERT INTO public\.workflow_runs`).
		WillReturnRows(sqlmock.NewRows([]string{"id"}))
	mock.ExpectQuery(`SELECT id, workflow_namespace, workflow_name`).
		WillReturnRows(sqlmock.NewRows([]string{"id", "workflow_namespace", "workflow_name"}).
			AddRow(uuid.New(), "dakasa", "some-other-action"))

	_, _, err = InsertWorkflowRunIdempotent(context.Background(), db, uuid.New(),
		model.ManifestSelector{Name: "remediate", Namespace: "dakasa"}, nil,
		map[string]any{"idempotency_key": "guardian:approval-1"})
	if !errors.Is(err, ErrWorkflowRunIdempotencyConflict) {
		t.Fatalf("err=%v, want ErrWorkflowRunIdempotencyConflict", err)
	}
}

func TestGetWorkflowRunForMachinePrincipalReturnsOnlyOwnedRun(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	id := uuid.New()
	now := time.Now().UTC()
	rows := sqlmock.NewRows([]string{
		"id", "workflow_namespace", "workflow_name", "workflow_version", "status",
		"inputs", "metadata", "result", "error", "started_at", "finished_at", "created_at", "updated_at",
	}).AddRow(id, "dakasa", "deploy", nil, "pending", []byte(`{}`),
		[]byte(`{"yggdrasil.io/creator_machine_principal_id":"ci-a"}`), nil, nil, nil, nil, now, now)
	mock.ExpectQuery(`metadata ->> 'yggdrasil\.io/creator_machine_principal_id' = \$2`).
		WithArgs(id, "ci-a").
		WillReturnRows(rows)

	record, err := GetWorkflowRunForMachinePrincipal(context.Background(), db, id, "ci-a")
	if err != nil {
		t.Fatal(err)
	}
	if record.ID != id {
		t.Fatalf("record id=%s, want %s", record.ID, id)
	}

	foreignID := uuid.New()
	mock.ExpectQuery(`metadata ->> 'yggdrasil\.io/creator_machine_principal_id' = \$2`).
		WithArgs(foreignID, "ci-b").
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "workflow_namespace", "workflow_name", "workflow_version", "status",
			"inputs", "metadata", "result", "error", "started_at", "finished_at", "created_at", "updated_at",
		}))
	if _, err := GetWorkflowRunForMachinePrincipal(context.Background(), db, foreignID, "ci-b"); !errors.Is(err, ErrWorkflowRunNotFound) {
		t.Fatalf("foreign run err=%v, want ErrWorkflowRunNotFound", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestWorkflowRunOwnedByMachinePrincipal(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	id := uuid.New()
	mock.ExpectQuery(`SELECT EXISTS`).WithArgs(id, "ci-a").WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(true))
	owned, err := WorkflowRunOwnedByMachinePrincipal(context.Background(), db, id, "ci-a")
	if err != nil || !owned {
		t.Fatalf("owned=%v err=%v", owned, err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}
