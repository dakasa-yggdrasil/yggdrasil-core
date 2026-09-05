package message

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	manifestengine "github.com/dakasa-yggdrasil/yggdrasil-core/manifest"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

func TestRedactSensitiveWorkflowInputsKeepsExecutionCopyIntact(t *testing.T) {
	spec := model.WorkflowManifestSpec{
		InputSchema: model.WorkflowInputSchemaSpec{
			Properties: map[string]model.IntegrationSchemaProperty{
				"api_key": {Type: "string", Secret: true},
				"pin":     {Type: "string", Sensitive: true},
				"config":  {Type: "object"},
			},
		},
	}
	executionInputs := map[string]any{
		"api_key": "raw-api-key",
		"pin":     "1234",
		"config":  map[string]any{"region": "sa-east-1"},
	}

	persistedInputs := redactSensitiveWorkflowInputs(spec, executionInputs)
	if got := persistedInputs["api_key"]; got != redactedWorkflowInputValue {
		t.Fatalf("persisted api_key = %#v, want redaction marker", got)
	}
	if got := persistedInputs["pin"]; got != redactedWorkflowInputValue {
		t.Fatalf("persisted pin = %#v, want redaction marker", got)
	}
	if got := executionInputs["api_key"]; got != "raw-api-key" {
		t.Fatalf("execution api_key was mutated: %#v", got)
	}
	if got := executionInputs["pin"]; got != "1234" {
		t.Fatalf("execution pin was mutated: %#v", got)
	}

	persistedInputs["config"].(map[string]any)["region"] = "changed"
	if got := executionInputs["config"].(map[string]any)["region"]; got != "sa-east-1" {
		t.Fatalf("nested execution input was aliased to persistence copy: %#v", got)
	}
}

func TestPrepareAndInsertWorkflowRunPersistsRedactedInputsAndKeepsExecutionValues(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })

	expectPreparedWorkflowManifest(mock, `{
		"trigger":{"mode":"manual"},
		"input_schema":{
			"additionalProperties":false,
			"required":["api_key","pin","region"],
			"properties":{
				"api_key":{"type":"string","secret":true},
				"pin":{"type":"string","sensitive":true},
				"region":{"type":"string"}
			}
		},
		"defaults":{"region":"sa-east-1"},
		"steps":[{
			"id":"observe",
			"use":{"kind":"integration","instance_ref":{"namespace":"dakasa","name":"example"},"operation":"observe_state"}
		}]
	}`)

	runID := uuid.New()
	mock.ExpectExec(`INSERT INTO public\.workflow_runs`).
		WithArgs(runID, "dakasa", "rotate", nil,
			`{"api_key":"[REDACTED]","pin":"[REDACTED]"}`, `{}`).
		WillReturnResult(sqlmock.NewResult(1, 1))
	prepared, err := PrepareAndInsertWorkflowRun(context.Background(), db, runID, model.RunWorkflowRequest{
		Workflow: model.ManifestSelector{Namespace: "dakasa", Name: "rotate"},
		Inputs: map[string]any{
			"api_key": "raw-api-key",
			"pin":     "1234",
		},
	})
	if err != nil {
		t.Fatalf("PrepareAndInsertWorkflowRun error: %v", err)
	}
	if got := prepared.Inputs["api_key"]; got != "raw-api-key" {
		t.Fatalf("execution api_key = %#v, want raw value for templates", got)
	}
	if got := prepared.Inputs["pin"]; got != "1234" {
		t.Fatalf("execution pin = %#v, want raw value for templates", got)
	}
	if got := prepared.Inputs["region"]; got != "sa-east-1" {
		t.Fatalf("execution default region = %#v", got)
	}
	rendered, err := manifestengine.RenderWorkflowInput("{{ inputs.api_key }}", manifestengine.WorkflowExecutionContext{Inputs: prepared.Inputs})
	if err != nil {
		t.Fatalf("render execution api_key: %v", err)
	}
	if rendered != "raw-api-key" {
		t.Fatalf("rendered execution api_key = %#v, want raw value", rendered)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestPrepareAndInsertWorkflowRunIdempotentPersistsRedactedInputs(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })

	expectPreparedWorkflowManifest(mock, `{
		"trigger":{"mode":"manual"},
		"input_schema":{
			"properties":{"api_key":{"type":"string","secret":true}}
		},
		"steps":[{
			"id":"observe",
			"use":{"kind":"integration","instance_ref":{"namespace":"dakasa","name":"example"},"operation":"observe_state"}
		}]
	}`)

	runID := uuid.New()
	mock.ExpectQuery(`INSERT INTO public\.workflow_runs`).
		WithArgs(runID, "dakasa", "rotate", nil,
			`{"api_key":"[REDACTED]"}`, `{"idempotency_key":"test:rotate:1"}`).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(runID))
	prepared, persistedID, deduped, err := PrepareAndInsertWorkflowRunIdempotent(context.Background(), db, runID, model.RunWorkflowRequest{
		Workflow: model.ManifestSelector{Namespace: "dakasa", Name: "rotate"},
		Inputs:   map[string]any{"api_key": "raw-api-key"},
		Metadata: map[string]any{"idempotency_key": "test:rotate:1"},
	})
	if err != nil {
		t.Fatalf("PrepareAndInsertWorkflowRunIdempotent error: %v", err)
	}
	if deduped {
		t.Fatal("new idempotent run unexpectedly deduped")
	}
	if persistedID != runID {
		t.Fatalf("persisted id = %s, want %s", persistedID, runID)
	}
	if got := prepared.Inputs["api_key"]; got != "raw-api-key" {
		t.Fatalf("execution api_key = %#v, want raw value", got)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestPrepareAndInsertWorkflowRunRejectsUndeclaredBeforeInsert(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })

	expectPreparedWorkflowManifest(mock, `{
		"trigger":{"mode":"manual"},
		"input_schema":{
			"additionalProperties":false,
			"properties":{"declared":{"type":"string"}}
		},
		"steps":[{
			"id":"observe",
			"use":{"kind":"integration","instance_ref":{"namespace":"dakasa","name":"example"},"operation":"observe_state"}
		}]
	}`)

	_, err = PrepareAndInsertWorkflowRun(context.Background(), db, uuid.New(), model.RunWorkflowRequest{
		Workflow: model.ManifestSelector{Namespace: "dakasa", Name: "rotate"},
		Inputs: map[string]any{
			"declared":   "ok",
			"undeclared": "must-not-persist",
		},
	})
	if err == nil {
		t.Fatal("expected undeclared input to fail before insert")
	}
	if !strings.Contains(err.Error(), "must be declared") {
		t.Fatalf("error = %q", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func expectPreparedWorkflowManifest(mock sqlmock.Sqlmock, spec string) {
	now := time.Now().UTC()
	rows := sqlmock.NewRows([]string{
		"id", "api_version", "kind", "namespace", "name", "version", "active",
		"description", "labels", "spec", "checksum", "created_at", "updated_at",
	}).AddRow(uuid.New(), "yggdrasil.io/v1alpha1", "workflow", "dakasa", "rotate", 1, true,
		"", []byte(`{}`), []byte(spec), "sha256:test", now, now)
	mock.ExpectQuery(`FROM public\.manifests`).
		WithArgs("workflow", "dakasa", "rotate").
		WillReturnRows(rows)
}
