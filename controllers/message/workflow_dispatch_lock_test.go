package message

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/workflowdispatchlock"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-sdk-go/rpc"
	"github.com/google/uuid"
)

func TestDispatchLockControlsMutationConsumerRegistration(t *testing.T) {
	tests := []struct {
		name                     string
		config                   string
		wantWorkflowConsumers    int
		wantManifestConsumers    int
		wantIntegrationConsumers int
		wantProductConsumers     int
	}{
		{
			name:                     "off",
			config:                   `{"mode":"off","allowed_workflows":[]}`,
			wantWorkflowConsumers:    2,
			wantManifestConsumers:    8,
			wantIntegrationConsumers: 8,
			wantProductConsumers:     6,
		},
		{
			name:                     "enforce",
			config:                   `{"mode":"enforce","allowed_workflows":[{"namespace":"dakasa","name":"fixed-unlock"}]}`,
			wantWorkflowConsumers:    0,
			wantManifestConsumers:    7,
			wantIntegrationConsumers: 6,
			wantProductConsumers:     1,
		},
		{
			name:                     "invalid",
			config:                   `{`,
			wantWorkflowConsumers:    0,
			wantManifestConsumers:    7,
			wantIntegrationConsumers: 6,
			wantProductConsumers:     1,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Setenv(workflowdispatchlock.EnvName, test.config)

			workflow := workflowConsumers(nil, nil, nil)
			if len(workflow) != test.wantWorkflowConsumers {
				t.Fatalf("workflow consumers = %d, want %d", len(workflow), test.wantWorkflowConsumers)
			}

			manifest := manifestConsumers(nil, nil, nil)
			if len(manifest) != test.wantManifestConsumers {
				t.Fatalf("manifest consumers = %d, want %d", len(manifest), test.wantManifestConsumers)
			}
			if (findConsumer(manifest, queueManifestCreate) != nil) != (test.name == "off") {
				t.Fatalf("manifest.create registration does not match policy %s", test.name)
			}

			integration := integrationConsumers(nil, nil, nil)
			if len(integration) != test.wantIntegrationConsumers {
				t.Fatalf("integration consumers = %d, want %d", len(integration), test.wantIntegrationConsumers)
			}
			if (findConsumer(integration, queueIntegrationExecute) != nil) != (test.name == "off") {
				t.Fatalf("integration.execute registration does not match policy %s", test.name)
			}
			if (findConsumer(integration, queueCatalogDiscover) != nil) != (test.name == "off") {
				t.Fatalf("catalog.discover registration does not match policy %s", test.name)
			}

			product := productConsumers(nil, nil, nil)
			if len(product) != test.wantProductConsumers {
				t.Fatalf("product consumers = %d, want %d", len(product), test.wantProductConsumers)
			}
			if findConsumer(product, queueProductInstallationStateDiscover) == nil {
				t.Fatal("read-only product state discovery consumer is missing")
			}
			for _, queue := range []string{
				queueProductMaterialize,
				queueProductInstallationReconcile,
				queueProductInstallationApply,
				queueProductInstallationObserve,
				queueProductInstallationUninstall,
			} {
				if (findConsumer(product, queue) != nil) != (test.name == "off") {
					t.Fatalf("product queue %s registration does not match policy %s", queue, test.name)
				}
			}
		})
	}
}

func findConsumer(consumers []ConsumerConfig, queue string) *ConsumerConfig {
	for index := range consumers {
		if consumers[index].Queue == queue {
			return &consumers[index]
		}
	}
	return nil
}

func TestPrepareAndInsertWorkflowRunChecksEmergencyLockBeforePersistence(t *testing.T) {
	t.Setenv(workflowdispatchlock.EnvName, `{"mode":"enforce","allowed_workflows":[{"namespace":"dakasa","name":"fixed-unlock"}]}`)
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })

	manifestID := uuid.New()
	mock.ExpectQuery(`(?s)FROM public\.manifests\s+WHERE kind = \$1 AND namespace = \$2 AND name = \$3\s+AND active = TRUE`).
		WithArgs("workflow", "dakasa", "lifecycle").
		WillReturnRows(workflowManifestRows(manifestID, 4, true))

	_, err = PrepareAndInsertWorkflowRun(context.Background(), db, uuid.New(), model.RunWorkflowRequest{
		Workflow: model.ManifestSelector{Namespace: "dakasa", Name: "lifecycle"},
	})
	if !errors.Is(err, workflowdispatchlock.ErrLocked) {
		t.Fatalf("error = %v, want ErrLocked", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestExportedIntegrationExecutionChecksEmergencyLockBeforeRequestValidation(t *testing.T) {
	t.Setenv(workflowdispatchlock.EnvName, `{"mode":"enforce","allowed_workflows":[{"namespace":"dakasa","name":"fixed-unlock"}]}`)

	_, err := ExecuteIntegration(context.Background(), nil, nil, model.ExecuteIntegrationRequest{})
	if !errors.Is(err, workflowdispatchlock.ErrLocked) {
		t.Fatalf("error = %v, want ErrLocked", err)
	}
}

func TestCatalogDiscoverHandlerChecksEmergencyLockBeforeRequestValidation(t *testing.T) {
	t.Setenv(workflowdispatchlock.EnvName, `{"mode":"enforce","allowed_workflows":[{"namespace":"dakasa","name":"fixed-unlock"}]}`)

	var response rpcResponse
	delivery := rpc.Delivery{
		Body:    []byte(`{`),
		ReplyTo: "test-reply",
		ReplyFn: func(_ context.Context, body []byte, _ string) error {
			return json.Unmarshal(body, &response)
		},
	}

	if err := catalogDiscoverHandler(nil, nil, nil)(context.Background(), delivery); err != nil {
		t.Fatal(err)
	}
	if response.Error == nil || response.Error.Code != "workflow_dispatch_locked" {
		t.Fatalf("response error = %#v, want workflow_dispatch_locked", response.Error)
	}
}

func TestPrepareWorkflowRunAllowsExactEmergencyWorkflow(t *testing.T) {
	t.Setenv(workflowdispatchlock.EnvName, `{"mode":"enforce","allowed_workflows":[{"namespace":"dakasa","name":"lifecycle"}]}`)
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })

	manifestID := uuid.New()
	mock.ExpectQuery(`(?s)FROM public\.manifests\s+WHERE kind = \$1 AND namespace = \$2 AND name = \$3\s+AND active = TRUE`).
		WithArgs("workflow", "dakasa", "lifecycle").
		WillReturnRows(workflowManifestRows(manifestID, 4, true))

	manifestRecord, _, _, err := prepareWorkflowRun(context.Background(), db, model.RunWorkflowRequest{
		Workflow: model.ManifestSelector{Namespace: "dakasa", Name: "lifecycle"},
	})
	if err != nil {
		t.Fatalf("exact emergency workflow refused: %v", err)
	}
	if manifestRecord.ID != manifestID {
		t.Fatalf("manifest id = %s, want %s", manifestRecord.ID, manifestID)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestPrepareWorkflowRunChecksResolvedIdentityForManifestID(t *testing.T) {
	t.Setenv(workflowdispatchlock.EnvName, `{"mode":"enforce","allowed_workflows":[{"namespace":"dakasa","name":"fixed-unlock"}]}`)
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })

	manifestID := uuid.New()
	mock.ExpectQuery(`(?s)FROM public\.manifests\s+WHERE id = \$1`).
		WithArgs(manifestID).
		WillReturnRows(workflowManifestRows(manifestID, 4, true))

	_, _, _, err = prepareWorkflowRun(context.Background(), db, model.RunWorkflowRequest{
		Workflow: model.ManifestSelector{ManifestID: manifestID.String()},
	})
	if !errors.Is(err, workflowdispatchlock.ErrLocked) {
		t.Fatalf("error = %v, want resolved manifest to be locked", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}
