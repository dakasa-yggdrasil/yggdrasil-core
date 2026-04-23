package message

import (
	"context"
	"database/sql"
	"encoding/json"
	"os"
	"testing"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
	_ "github.com/lib/pq"
)

// TestManifestDocumentFromStepInput_AcceptsObject verifies the JSON
// round-trip keeps every field the workflow step author wrote in YAML,
// including the nested spec which lands as json.RawMessage on the output
// document (the downstream validator decides how to parse it).
func TestManifestDocumentFromStepInput_AcceptsObject(t *testing.T) {
	input := map[string]any{
		"manifest": map[string]any{
			"apiVersion": "yggdrasil.io/v1alpha1",
			"kind":       "integration_instance",
			"metadata": map[string]any{
				"name":      "schema-migrations-goose-postgres",
				"namespace": "global",
			},
			"spec": map[string]any{
				"type_ref": map[string]any{
					"namespace": "dakasa",
					"name":      "schema-migrations-goose-postgres",
				},
				"config": map[string]any{
					"default_track_table": "goose_db_version",
				},
			},
		},
	}

	doc, err := manifestDocumentFromStepInput(input)
	if err != nil {
		t.Fatalf("manifestDocumentFromStepInput error: %v", err)
	}
	if doc.APIVersion != "yggdrasil.io/v1alpha1" {
		t.Errorf("apiVersion = %q", doc.APIVersion)
	}
	if doc.Kind != "integration_instance" {
		t.Errorf("kind = %q", doc.Kind)
	}
	if doc.Metadata.Name != "schema-migrations-goose-postgres" {
		t.Errorf("metadata.name = %q", doc.Metadata.Name)
	}
	if doc.Metadata.Namespace != "global" {
		t.Errorf("metadata.namespace = %q", doc.Metadata.Namespace)
	}
	if len(doc.Spec) == 0 {
		t.Fatal("spec was lost in the round trip")
	}
	// Spec arrives as json.RawMessage — sanity-check it parses back to
	// something that contains the type_ref path the compiler wrote.
	var specRoundtrip map[string]any
	if err := json.Unmarshal(doc.Spec, &specRoundtrip); err != nil {
		t.Fatalf("spec unmarshal: %v", err)
	}
	typeRef, ok := specRoundtrip["type_ref"].(map[string]any)
	if !ok {
		t.Fatalf("type_ref lost: %#v", specRoundtrip)
	}
	if typeRef["name"] != "schema-migrations-goose-postgres" {
		t.Errorf("type_ref.name = %#v", typeRef["name"])
	}
}

func TestManifestDocumentFromStepInput_RejectsMissingManifest(t *testing.T) {
	_, err := manifestDocumentFromStepInput(map[string]any{"other": "value"})
	if err == nil {
		t.Fatal("expected error when with.manifest is absent")
	}
}

func TestManifestDocumentFromStepInput_RejectsNonObjectManifest(t *testing.T) {
	_, err := manifestDocumentFromStepInput(map[string]any{"manifest": "a string"})
	if err == nil {
		t.Fatal("expected error when with.manifest is not an object")
	}
}

func TestManifestDocumentFromStepInput_RejectsEmptyManifest(t *testing.T) {
	_, err := manifestDocumentFromStepInput(map[string]any{"manifest": map[string]any{}})
	if err == nil {
		t.Fatal("expected error when with.manifest is an empty object")
	}
}

// TestExecuteYggdrasilWorkflowStep_UnsupportedOperationFails guards the
// contract that the only in-process yggdrasil operation today is
// apply_manifest. New operations require matching dispatcher wiring.
func TestExecuteYggdrasilWorkflowStep_UnsupportedOperationFails(t *testing.T) {
	step := model.WorkflowStepSpec{
		ID: "mystery",
		Use: model.WorkflowStepUseSpec{
			Kind:      "yggdrasil",
			Operation: "delete_manifest",
		},
		With: map[string]any{"manifest": map[string]any{}},
	}
	result := model.WorkflowRunStepResult{ID: "mystery", Kind: "yggdrasil", Operation: "delete_manifest", Status: "failed"}

	got := executeYggdrasilWorkflowStep(context.Background(), nil, step, result, step.With)
	if got.Status != "failed" {
		t.Fatalf("status = %q, want failed", got.Status)
	}
	if got.Error == "" {
		t.Fatal("expected non-empty error describing unsupported operation")
	}
}

// TestExecuteYggdrasilWorkflowStep_BadManifestFails guards that a step
// with a malformed with.manifest (object missing, wrong type) fails at
// input shaping — before any DB interaction. This gives us a DB-free
// test of the error path while the happy path stays in the integration
// test below.
func TestExecuteYggdrasilWorkflowStep_BadManifestFails(t *testing.T) {
	step := model.WorkflowStepSpec{
		ID: "register-instance",
		Use: model.WorkflowStepUseSpec{
			Kind:      "yggdrasil",
			Operation: "apply_manifest",
		},
		With: map[string]any{"manifest": "not an object"},
	}
	result := model.WorkflowRunStepResult{ID: "register-instance", Kind: "yggdrasil", Operation: "apply_manifest", Status: "failed"}

	got := executeYggdrasilWorkflowStep(context.Background(), nil, step, result, step.With)
	if got.Status != "failed" {
		t.Fatalf("status = %q, want failed", got.Status)
	}
	if got.Error == "" {
		t.Fatal("expected non-empty error describing bad manifest shape")
	}
}

// dbForYggdrasilStepTest is the same gated-DB helper used by other
// integration tests in the repo: skip the test gracefully when DB_URL
// is not set, fail fast when it is set but unreachable.
func dbForYggdrasilStepTest(t *testing.T) *sql.DB {
	t.Helper()
	dsn := os.Getenv("DB_URL")
	if dsn == "" {
		t.Skip("DB_URL not set; skipping yggdrasil step integration test")
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

// TestRunWorkflow_YggdrasilApplyManifestPersistsDocument runs one workflow
// whose single step is kind=yggdrasil, operation=apply_manifest and asserts
// that (a) the step succeeds, (b) the returned metadata contains the
// manifest coordinates persistManifestVersion emits, and (c) the record
// actually lands in the DB.
//
// Needs DB_URL pointing at a schema-migrated yggdrasil database. We create
// an integration_instance that references a type_ref with a made-up name
// — integration_instance validation only shape-checks the ref, it does
// not dereference the target, so the test is self-contained.
func TestRunWorkflow_YggdrasilApplyManifestPersistsDocument(t *testing.T) {
	db := dbForYggdrasilStepTest(t)
	defer func() { _ = db.Close() }()

	instanceName := "ygg-step-test-" + uuid.NewString()[:8]

	workflowManifest := model.Manifest{
		ID:   uuid.New(),
		Kind: "workflow",
		Metadata: model.ManifestMetadata{
			Name:      "yggdrasil-step-smoke",
			Namespace: "test",
		},
	}

	spec := model.WorkflowManifestSpec{
		Trigger: model.WorkflowTriggerSpec{Mode: "manual"},
		Steps: []model.WorkflowStepSpec{
			{
				ID: "register-instance",
				Use: model.WorkflowStepUseSpec{
					Kind:      "yggdrasil",
					Operation: "apply_manifest",
				},
				With: map[string]any{
					"manifest": map[string]any{
						"apiVersion": "yggdrasil.io/v1alpha1",
						"kind":       "integration_instance",
						"metadata": map[string]any{
							"name":      instanceName,
							"namespace": "test",
						},
						"spec": map[string]any{
							"type_ref": map[string]any{
								"namespace": "dakasa",
								"name":      "yggdrasil-step-probe",
							},
						},
					},
				},
			},
		},
	}

	req := model.RunWorkflowRequest{
		Workflow: model.ManifestSelector{Name: "yggdrasil-step-smoke", Namespace: "test"},
	}

	resp, err := runWorkflow(context.Background(), nil, db, workflowManifest, spec, req)
	if err != nil {
		t.Fatalf("runWorkflow error: %v", err)
	}

	if resp.Status != "succeeded" {
		t.Fatalf("workflow status = %q (step error=%q), want succeeded", resp.Status, firstStepError(resp.Steps))
	}
	if len(resp.Steps) != 1 {
		t.Fatalf("step count = %d, want 1", len(resp.Steps))
	}
	step := resp.Steps[0]
	if step.Status != "succeeded" {
		t.Fatalf("step status = %q (error=%q), want succeeded", step.Status, step.Error)
	}

	for _, key := range []string{"manifest_id", "kind", "namespace", "name", "version", "checksum"} {
		if _, ok := step.Metadata[key]; !ok {
			t.Errorf("step metadata missing key %q (got %v)", key, step.Metadata)
		}
	}
	if got, _ := step.Metadata["kind"].(string); got != "integration_instance" {
		t.Errorf("metadata.kind = %q, want integration_instance", got)
	}
	if got, _ := step.Metadata["name"].(string); got != instanceName {
		t.Errorf("metadata.name = %q, want %q", got, instanceName)
	}

	// Verify the record is actually in the DB.
	var dbKind, dbName, dbNamespace string
	err = db.QueryRowContext(context.Background(), `
		SELECT kind, name, namespace FROM manifest WHERE id = $1
	`, step.Metadata["manifest_id"]).Scan(&dbKind, &dbName, &dbNamespace)
	if err != nil {
		t.Fatalf("select persisted manifest: %v", err)
	}
	if dbKind != "integration_instance" || dbName != instanceName || dbNamespace != "test" {
		t.Errorf("persisted record = (%q, %q, %q), want (integration_instance, %q, test)", dbKind, dbName, dbNamespace, instanceName)
	}
}

func firstStepError(steps []model.WorkflowRunStepResult) string {
	for _, s := range steps {
		if s.Error != "" {
			return s.Error
		}
	}
	return ""
}
