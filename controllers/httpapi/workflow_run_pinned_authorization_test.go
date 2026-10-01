package httpapi

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	amqp "github.com/rabbitmq/amqp091-go"
)

// The first lookup is authorized by logical name. Both dispatch paths must
// resolve that exact row by UUID afterwards, even if another active version
// appears before execution or async insertion.
func TestWorkflowRunBindsAuthorizedManifestForSyncAndAsync(t *testing.T) {
	for _, test := range []struct {
		name       string
		query      string
		wantStatus int
	}{
		{name: "sync", query: "?async=false", wantStatus: http.StatusCreated},
		{name: "async", query: "?async=true", wantStatus: http.StatusAccepted},
	} {
		t.Run(test.name, func(t *testing.T) {
			clearWorkflowRunAuthEnv(t)
			t.Setenv("YGGDRASIL_ENV", "dev")
			t.Setenv("BROKER_URL", "amqp://unit-test")
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			const spec = `{"trigger":{"mode":"manual"},"steps":[{"id":"skip","condition":"false","use":{"kind":"yggdrasil","operation":"oidc_client.verify_bootstrap_file"}}]}`
			authorizedID := expectWorkflowAuthorizationManifest(mock, "workflow", "safe-read", spec)
			expectWorkflowAuthorizationManifestByID(mock, authorizedID, "workflow", "safe-read", spec)
			if test.name == "async" {
				mock.ExpectExec(`INSERT INTO public\.workflow_runs`).
					WithArgs(sqlmock.AnyArg(), "dakasa", "safe-read", 1, sqlmock.AnyArg(), sqlmock.AnyArg()).
					WillReturnResult(sqlmock.NewResult(0, 1))
				originalLauncher := launchAsyncWorkflowRun
				launchAsyncWorkflowRun = func(string, func()) {}
				t.Cleanup(func() { launchAsyncWorkflowRun = originalLauncher })
			} else {
				mock.ExpectBegin().WillReturnError(errors.New("completion event unavailable"))
			}

			server := &Server{db: db, rabbitmq: &amqp.Connection{}}
			req := httptest.NewRequest(http.MethodPost, "/api/v1/workflow-runs"+test.query,
				strings.NewReader(`{"workflow":{"namespace":"dakasa","name":"safe-read"}}`))
			recorder := httptest.NewRecorder()
			server.handleWorkflowRun(recorder, req)
			if recorder.Code != test.wantStatus {
				t.Fatalf("status=%d, want %d; body=%s", recorder.Code, test.wantStatus, recorder.Body.String())
			}
			if test.name == "async" && !strings.Contains(recorder.Body.String(), authorizedID.String()) {
				t.Fatalf("async response did not pin authorized manifest %s: %s", authorizedID, recorder.Body.String())
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestProtectedWorkflowAuthorizationReturnsTheEvaluatedManifestID(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	const protectedSpec = `{"authorization":{"rbac":{"namespace":"dakasa","name":"snapshot-rbac"}},"steps":[]}`
	const rbacSpec = `{"roles":[{"name":"reader","rules":[{"effect":"allow","resources":["workflow:dakasa:safe-read"],"actions":["run"]}]}],"bindings":[{"name":"bound-reader","subjects":[{"type":"service","id":"reviewed-reader"}],"roles":["reader"]}]}`
	wantID := expectWorkflowAuthorizationManifest(mock, "workflow", "safe-read", protectedSpec)
	expectWorkflowAuthorizationManifest(mock, "rbac", "snapshot-rbac", rbacSpec)
	mock.ExpectBegin().WillReturnError(errors.New("audit unavailable"))
	workflow, err := (&Server{db: db}).authorizeWorkflowDispatchManifest(context.Background(), model.RunWorkflowRequest{
		Workflow: model.ManifestSelector{Namespace: "dakasa", Name: "safe-read"},
	}, workflowRunActor{Subject: model.RBACSubject{Type: "service", ID: "reviewed-reader"}})
	if err != nil || workflow.ID != wantID {
		t.Fatalf("authorized manifest = %s, want %s; err=%v", workflow.ID, wantID, err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}
