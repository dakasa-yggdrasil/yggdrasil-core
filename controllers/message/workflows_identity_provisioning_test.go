package message

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

func provisioningTestManifest() model.Manifest {
	return model.Manifest{
		ID:   uuid.New(),
		Kind: "workflow",
		Metadata: model.ManifestMetadata{
			Namespace: "dakasa",
			Name:      "reconcile-identity-providers",
			Active:    true,
		},
	}
}

func provisioningTestSpec() model.WorkflowManifestSpec {
	return model.WorkflowManifestSpec{
		Trigger: model.WorkflowTriggerSpec{Mode: "manual"},
		Steps: []model.WorkflowStepSpec{
			{
				ID:  "list-collaborators",
				Use: model.WorkflowStepUseSpec{Kind: "yggdrasil", Operation: "collaborator.provisioning_snapshot"},
			},
			{
				ID:        "probe",
				DependsOn: []string{"list-collaborators"},
				ForEach:   &model.WorkflowForEachSpec{Items: identityProvisioningSource, As: "collaborator"},
				Condition: "false",
				Use: model.WorkflowStepUseSpec{
					Kind:        "integration",
					Operation:   "ensure_user",
					Capability:  "ensure_user",
					InstanceRef: &model.ManifestSelector{Namespace: "dakasa", Name: "never-resolved"},
				},
				With: map[string]any{"email": "{{ each.collaborator.provider_desired.primary_email }}"},
			},
		},
	}
}

func TestIdentityProvisioningSnapshotKeepsPeopleOutOfWorkflowResult(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	workflow := provisioningTestManifest()
	t.Setenv(identityProvisioningManifestIDEnv, workflow.ID.String())
	personID := uuid.New()
	email := "private-person@example.invalid"
	mock.ExpectQuery(`SELECT id, status, display_name, primary_email`).
		WithArgs(identityProvisioningMaxPeople + 1).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "status", "display_name", "primary_email", "given_name", "family_name",
		}).AddRow(personID.String(), "on_leave", "Private Person", email, "Private", "Person"))

	response, err := runWorkflow(context.Background(), nil, db, workflow, provisioningTestSpec(), model.RunWorkflowRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if response.Status != "succeeded" || len(response.Steps) != 2 {
		t.Fatalf("unexpected workflow result: status=%s steps=%d", response.Status, len(response.Steps))
	}
	if response.Steps[0].Metadata["total_count"] != 1 || response.Steps[1].Status != "skipped" || response.Steps[1].Metadata != nil {
		t.Fatalf("public result contains unexpected fields: %#v", response.Steps)
	}
	encoded, err := json.Marshal(response)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{email, "Private Person", personID.String(), "on_leave"} {
		if strings.Contains(string(encoded), secret) {
			t.Fatalf("workflow result contains collaborator data %q", secret)
		}
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestIdentityProvisioningSnapshotRequiresExactActiveManifestBeforeRead(t *testing.T) {
	workflow := provisioningTestManifest()
	spec := provisioningTestSpec()
	t.Setenv(identityProvisioningManifestIDEnv, uuid.NewString())
	if _, err := runWorkflow(context.Background(), nil, nil, workflow, spec, model.RunWorkflowRequest{}); err != errIdentityProvisioningUnavailable {
		t.Fatalf("wrong manifest grant: %v", err)
	}
	t.Setenv(identityProvisioningManifestIDEnv, workflow.ID.String())
	workflow.Metadata.Active = false
	if _, err := runWorkflow(context.Background(), nil, nil, workflow, spec, model.RunWorkflowRequest{}); err != errIdentityProvisioningUnavailable {
		t.Fatalf("inactive manifest grant: %v", err)
	}
	workflow.Metadata.Active = true
	if _, err := runWorkflow(context.Background(), nil, nil, workflow, spec, model.RunWorkflowRequest{
		Metadata: map[string]any{"caller_note": "private-person@example.invalid"},
	}); err != errIdentityProvisioningUnavailable {
		t.Fatalf("caller metadata grant: %v", err)
	}
	if _, err := runWorkflow(context.Background(), nil, nil, workflow, spec, model.RunWorkflowRequest{
		Inputs: map[string]any{"email": "private-person@example.invalid"},
	}); err != errIdentityProvisioningUnavailable {
		t.Fatalf("caller input grant: %v", err)
	}
}

func TestIdentityProvisioningIterationRedactsProviderEcho(t *testing.T) {
	now := time.Now().UTC()
	raw := model.WorkflowRunStepResult{
		ID: "probe[0]", Kind: "integration", Operation: "ensure_user", Capability: "ensure_user",
		Status: "failed", Attempts: 2, Error: "private-person@example.invalid",
		Metadata:  map[string]any{"output": map[string]any{"email": "private-person@example.invalid"}},
		StartedAt: now, FinishedAt: now,
	}
	safe := redactIdentityProvisioningIteration(raw)
	encoded, err := json.Marshal(safe)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "private-person@example.invalid") || safe.Metadata != nil || safe.Status != "failed" || safe.Attempts != 2 {
		t.Fatalf("private iteration result is unsafe: %s", encoded)
	}
}

func TestIdentityProvisioningSnapshotPreservesCanonicalStatusWithoutProviderActive(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	workflow := provisioningTestManifest()
	t.Setenv(identityProvisioningManifestIDEnv, workflow.ID.String())
	personID := uuid.New()
	mock.ExpectQuery(`SELECT id, status, display_name, primary_email`).
		WithArgs(identityProvisioningMaxPeople + 1).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "status", "display_name", "primary_email", "given_name", "family_name",
		}).AddRow(personID.String(), "on_leave", "Private Person", "private-person@example.invalid", "Private", "Person"))
	state := &identityProvisioningPrivateState{}
	result := executeIdentityProvisioningSnapshot(context.Background(), db, workflow, model.WorkflowRunStepResult{
		ID: "list-collaborators", Kind: "yggdrasil", Operation: "collaborator.provisioning_snapshot", Status: "failed",
	}, state)
	if result.Status != "succeeded" || result.Metadata["total_count"] != 1 {
		t.Fatalf("unexpected public snapshot result: %#v", result)
	}
	item := state.collaborators[0].(map[string]any)
	if item["status"] != "on_leave" {
		t.Fatalf("status was changed: %#v", item)
	}
	desired := item["provider_desired"].(map[string]any)
	if _, exists := desired["active"]; exists {
		t.Fatal("Core must not infer provider active from canonical status")
	}
	if _, exists := desired["groups"]; exists {
		t.Fatal("group authority is outside the read-only projection")
	}
	state.clear()
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}
