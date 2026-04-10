package httpapi

import (
	"net/http/httptest"
	"testing"
)

func TestAuthorizeWorkflowRunRequestAllowsMissingTokenWhenUnset(t *testing.T) {
	t.Setenv("YGGDRASIL_WORKFLOW_RUN_TOKEN", "")

	req := httptest.NewRequest("POST", "http://yggdrasil-core:9080/api/v1/workflow-runs", nil)
	if err := authorizeWorkflowRunRequest(req); err != nil {
		t.Fatalf("expected request to be allowed without configured token, got %v", err)
	}
}

func TestAuthorizeWorkflowRunRequestAcceptsSharedHeader(t *testing.T) {
	t.Setenv("YGGDRASIL_WORKFLOW_RUN_TOKEN", "shared-token")

	req := httptest.NewRequest("POST", "http://yggdrasil-core:9080/api/v1/workflow-runs", nil)
	req.Header.Set("X-Yggdrasil-Workflow-Token", "shared-token")
	if err := authorizeWorkflowRunRequest(req); err != nil {
		t.Fatalf("expected request to be authorized by explicit header, got %v", err)
	}
}

func TestAuthorizeWorkflowRunRequestAcceptsBearerToken(t *testing.T) {
	t.Setenv("YGGDRASIL_WORKFLOW_RUN_TOKEN", "shared-token")

	req := httptest.NewRequest("POST", "http://yggdrasil-core:9080/api/v1/workflow-runs", nil)
	req.Header.Set("Authorization", "Bearer shared-token")
	if err := authorizeWorkflowRunRequest(req); err != nil {
		t.Fatalf("expected request to be authorized by bearer token, got %v", err)
	}
}

func TestAuthorizeWorkflowRunRequestRejectsInvalidToken(t *testing.T) {
	t.Setenv("YGGDRASIL_WORKFLOW_RUN_TOKEN", "shared-token")

	req := httptest.NewRequest("POST", "http://yggdrasil-core:9080/api/v1/workflow-runs", nil)
	req.Header.Set("X-Yggdrasil-Workflow-Token", "wrong-token")
	if err := authorizeWorkflowRunRequest(req); err == nil {
		t.Fatalf("expected invalid token to be rejected")
	}
}
