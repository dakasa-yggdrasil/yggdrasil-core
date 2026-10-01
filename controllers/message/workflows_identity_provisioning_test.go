package message

import (
	"context"
	"database/sql/driver"
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
	disabled := false
	return model.WorkflowManifestSpec{
		Trigger: model.WorkflowTriggerSpec{Mode: "manual", Enabled: &disabled},
		Authorization: &model.WorkflowAuthorizationSpec{
			RBAC: model.ManifestSelector{Namespace: "dakasa", Name: "identity-provisioning-manual"},
		},
		Steps: []model.WorkflowStepSpec{{
			ID:  "list-collaborators",
			Use: model.WorkflowStepUseSpec{Kind: "yggdrasil", Operation: "collaborator.provisioning_snapshot"},
		}},
	}
}

func expectProvisioningRead(mock sqlmock.Sqlmock, workflowID uuid.UUID, rows *sqlmock.Rows) {
	mock.ExpectBegin()
	mock.ExpectQuery(`SELECT id FROM public.manifests`).
		WithArgs(workflowID).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(workflowID.String()))
	mock.ExpectQuery(`SELECT id, status, primary_email`).
		WithArgs(identityProvisioningMaxPeople + 1).
		WillReturnRows(rows)
	mock.ExpectCommit()
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
	rows := sqlmock.NewRows([]string{
		"id", "status", "primary_email",
	}).AddRow(personID.String(), "on_leave", email)
	expectProvisioningRead(mock, workflow.ID, rows)

	response, err := runWorkflow(context.Background(), nil, db, workflow, provisioningTestSpec(), model.RunWorkflowRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if response.Status != "succeeded" || len(response.Steps) != 1 || response.Steps[0].Metadata["total_count"] != 1 {
		t.Fatalf("unexpected public workflow result: %#v", response)
	}
	encoded, err := json.Marshal(response)
	if err != nil {
		t.Fatal(err)
	}
	for _, personal := range []string{email, personID.String(), "on_leave"} {
		if strings.Contains(string(encoded), personal) {
			t.Fatalf("workflow result contains collaborator data %q", personal)
		}
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestIdentityProvisioningSnapshotRequiresExactActiveAuthorizedManualManifest(t *testing.T) {
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
	noAuthorization := provisioningTestSpec()
	noAuthorization.Authorization = nil
	if _, err := runWorkflow(context.Background(), nil, nil, workflow, noAuthorization, model.RunWorkflowRequest{}); err != errIdentityProvisioningUnavailable {
		t.Fatalf("actorless manifest grant: %v", err)
	}
	scheduled := provisioningTestSpec()
	scheduled.Trigger.Mode = "schedule"
	if _, err := runWorkflow(context.Background(), nil, nil, workflow, scheduled, model.RunWorkflowRequest{}); err != errIdentityProvisioningUnavailable {
		t.Fatalf("scheduled manifest grant: %v", err)
	}
	enabled := true
	unexpectedTrigger := provisioningTestSpec()
	unexpectedTrigger.Trigger.Enabled = &enabled
	if _, err := runWorkflow(context.Background(), nil, nil, workflow, unexpectedTrigger, model.RunWorkflowRequest{}); err != errIdentityProvisioningUnavailable {
		t.Fatalf("enabled trigger grant: %v", err)
	}
	unexpectedTrigger.Trigger.Enabled = nil
	if _, err := runWorkflow(context.Background(), nil, nil, workflow, unexpectedTrigger, model.RunWorkflowRequest{}); err != errIdentityProvisioningUnavailable {
		t.Fatalf("default trigger grant: %v", err)
	}
	withWrite := provisioningTestSpec()
	withWrite.Steps = append(withWrite.Steps, model.WorkflowStepSpec{
		ID: "provider-write",
		Use: model.WorkflowStepUseSpec{
			Kind: "integration", Operation: "ensure_user",
			InstanceRef: &model.ManifestSelector{Namespace: "dakasa", Name: "provider"},
		},
	})
	if _, err := runWorkflow(context.Background(), nil, nil, workflow, withWrite, model.RunWorkflowRequest{}); err != errIdentityProvisioningUnavailable {
		t.Fatalf("provider write manifest grant: %v", err)
	}
	for _, req := range []model.RunWorkflowRequest{
		{Metadata: map[string]any{"caller_note": "private-person@example.invalid"}},
		{Inputs: map[string]any{"email": "private-person@example.invalid"}},
	} {
		if _, err := runWorkflow(context.Background(), nil, nil, workflow, spec, req); err != errIdentityProvisioningUnavailable {
			t.Fatalf("caller data grant: %v", err)
		}
	}
}

func TestIdentityProvisioningPinDeniedBeforeAsyncPersistence(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	workflow := provisioningTestManifest()
	t.Setenv(identityProvisioningManifestIDEnv, uuid.NewString())
	specJSON, err := json.Marshal(provisioningTestSpec())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	mock.ExpectQuery(`FROM public\.manifests`).
		WithArgs("workflow", "dakasa", "reconcile-identity-providers").
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "api_version", "kind", "namespace", "name", "version", "active",
			"description", "labels", "spec", "checksum", "created_at", "updated_at",
		}).AddRow(workflow.ID.String(), "yggdrasil.io/v1alpha1", "workflow", "dakasa",
			"reconcile-identity-providers", 1, true, "", []byte(`{}`), specJSON, "sha256:test", now, now))
	_, err = PrepareAndInsertWorkflowRun(context.Background(), db, uuid.New(), model.RunWorkflowRequest{
		Workflow: model.ManifestSelector{Namespace: "dakasa", Name: "reconcile-identity-providers"},
	})
	if err != errIdentityProvisioningUnavailable {
		t.Fatalf("unconfigured pin reached persistence: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestIdentityProvisioningSnapshotFailsClosedOnRevokedManifest(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	workflow := provisioningTestManifest()
	t.Setenv(identityProvisioningManifestIDEnv, workflow.ID.String())
	mock.ExpectBegin()
	mock.ExpectQuery(`SELECT id FROM public.manifests`).WithArgs(workflow.ID).
		WillReturnRows(sqlmock.NewRows([]string{"id"}))
	mock.ExpectRollback()
	result := executeIdentityProvisioningSnapshot(context.Background(), db, workflow, model.WorkflowRunStepResult{
		ID: "list-collaborators", Status: "failed",
	})
	if result.Status != "failed" || result.Error != errIdentityProvisioningUnavailable.Error() || result.Metadata != nil {
		t.Fatalf("revoked manifest read leaked data: %#v", result)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestIdentityProvisioningSnapshotRefusesMissingDuplicateUnknownOrNullIdentity(t *testing.T) {
	tests := []struct {
		name string
		rows [][]driver.Value
	}{
		{"missing email", [][]driver.Value{{uuid.NewString(), "active", ""}}},
		{"duplicate normalized email", [][]driver.Value{
			{uuid.NewString(), "active", " Person@Example.invalid "},
			{uuid.NewString(), "active", "person@example.invalid"},
		}},
		{"unknown status", [][]driver.Value{{uuid.NewString(), "unmapped", "person@example.invalid"}}},
		{"null source column", [][]driver.Value{{uuid.NewString(), "active", nil}}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			workflow := provisioningTestManifest()
			t.Setenv(identityProvisioningManifestIDEnv, workflow.ID.String())
			rows := sqlmock.NewRows([]string{
				"id", "status", "primary_email",
			})
			for _, row := range test.rows {
				rows.AddRow(row...)
			}
			mock.ExpectBegin()
			mock.ExpectQuery(`SELECT id FROM public.manifests`).WithArgs(workflow.ID).
				WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(workflow.ID.String()))
			mock.ExpectQuery(`SELECT id, status, primary_email`).
				WithArgs(identityProvisioningMaxPeople + 1).WillReturnRows(rows)
			if test.name == "null source column" {
				mock.ExpectRollback()
			} else {
				mock.ExpectCommit()
			}
			result := executeIdentityProvisioningSnapshot(context.Background(), db, workflow, model.WorkflowRunStepResult{
				ID: "list-collaborators", Status: "failed",
			})
			if result.Status != "failed" || result.Error != errIdentityProvisioningUnavailable.Error() || result.Metadata != nil {
				t.Fatalf("unsafe failure result: %#v", result)
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatal(err)
			}
		})
	}
}
