package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestParseRepoRefSimple(t *testing.T) {
	got, err := parseRepoRef("dakasa-yggdrasil/integration-secrets-management")
	if err != nil {
		t.Fatalf("parseRepoRef error: %v", err)
	}
	if got.Owner != "dakasa-yggdrasil" || got.Repo != "integration-secrets-management" {
		t.Fatalf("unexpected owner/repo: %+v", got)
	}
	if got.Ref != "main" {
		t.Fatalf("expected default ref=main, got %q", got.Ref)
	}
	if got.Path != defaultQuickstartPath {
		t.Fatalf("expected default path, got %q", got.Path)
	}
}

func TestParseRepoRefWithRefAndPath(t *testing.T) {
	got, err := parseRepoRef("foo/bar@v1.2.3:custom/path/qs.yaml")
	if err != nil {
		t.Fatalf("parseRepoRef error: %v", err)
	}
	if got.Owner != "foo" || got.Repo != "bar" || got.Ref != "v1.2.3" || got.Path != "custom/path/qs.yaml" {
		t.Fatalf("unexpected parse: %+v", got)
	}
}

func TestParseRepoRefRejectsEmpty(t *testing.T) {
	if _, err := parseRepoRef(""); err == nil {
		t.Fatal("expected empty repo_ref to fail")
	}
}

func TestParseRepoRefRejectsMalformed(t *testing.T) {
	if _, err := parseRepoRef("missingslash"); err == nil {
		t.Fatal("expected single-segment repo_ref to fail")
	}
}

func TestDecodeQuickstartDocumentJSON(t *testing.T) {
	raw := []byte(`{"apiVersion":"yggdrasil.io/v1alpha1","kind":"integration_quickstart","metadata":{"name":"x","namespace":"global"},"spec":{}}`)
	doc, err := decodeQuickstartDocument(raw)
	if err != nil {
		t.Fatalf("decodeQuickstartDocument JSON error: %v", err)
	}
	if doc.Kind != "integration_quickstart" {
		t.Fatalf("expected kind integration_quickstart, got %q", doc.Kind)
	}
}

func TestDecodeQuickstartDocumentYAML(t *testing.T) {
	raw := []byte(`apiVersion: yggdrasil.io/v1alpha1
kind: integration_quickstart
metadata:
  name: x
  namespace: global
spec: {}
`)
	doc, err := decodeQuickstartDocument(raw)
	if err != nil {
		t.Fatalf("decodeQuickstartDocument YAML error: %v", err)
	}
	if doc.Metadata.Name != "x" {
		t.Fatalf("expected metadata.name=x, got %q", doc.Metadata.Name)
	}
}

func TestHandleInstallIntegrationDryRun(t *testing.T) {
	manifestYAML := []byte(`apiVersion: yggdrasil.io/v1alpha1
kind: integration_quickstart
metadata:
  name: secrets-management
  namespace: global
spec:
  display_name: Secrets Management
  providers:
    - id: aws-secrets-manager
      display_name: AWS
      inputs:
        - id: region
          label: Region
          type: string
          required: true
      steps:
        - id: register
          uses:
            kind: integration
            family: secrets-management
            operation: upsert_secret
          with:
            secret_id: probe
      smoke_test:
        uses:
          kind: integration
          family: secrets-management
          operation: describe_secret
        with:
          secret_id: probe
      post_install_hints:
        - "now run yggdrasil secrets ..."
`)

	prevFetcher := quickstartFetcher
	defer func() { quickstartFetcher = prevFetcher }()
	quickstartFetcher = func(_ context.Context, ref repoRefSpec) ([]byte, error) {
		if ref.Owner != "foo" || ref.Repo != "bar" {
			t.Fatalf("unexpected fetch ref: %+v", ref)
		}
		return manifestYAML, nil
	}

	server := &Server{}
	body := strings.NewReader(`{"repo_ref":"foo/bar","provider_id":"aws-secrets-manager","inputs":{"region":"us-east-1"},"dry_run":true}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/integrations/install", body)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	server.handleInstallIntegration(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d (body=%s)", rr.Code, rr.Body.String())
	}

	var resp struct {
		ProviderID       string         `json:"provider_id"`
		CompiledWorkflow map[string]any `json:"compiled_workflow"`
		Hints            []string       `json:"hints"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v (body=%s)", err, rr.Body.String())
	}
	if resp.ProviderID != "aws-secrets-manager" {
		t.Fatalf("expected provider_id aws-secrets-manager, got %q", resp.ProviderID)
	}
	if resp.CompiledWorkflow == nil {
		t.Fatal("expected compiled_workflow in DryRun response")
	}
	if len(resp.Hints) != 1 || resp.Hints[0] != "now run yggdrasil secrets ..." {
		t.Fatalf("unexpected hints: %v", resp.Hints)
	}
}

func TestHandleInstallIntegrationRejectsMissingRequiredInput(t *testing.T) {
	manifestYAML := []byte(`apiVersion: yggdrasil.io/v1alpha1
kind: integration_quickstart
metadata:
  name: secrets-management
spec:
  providers:
    - id: aws-secrets-manager
      inputs:
        - id: region
          label: Region
          type: string
          required: true
      steps:
        - id: noop
          uses:
            kind: integration
            family: f
            operation: op
`)
	prevFetcher := quickstartFetcher
	defer func() { quickstartFetcher = prevFetcher }()
	quickstartFetcher = func(_ context.Context, _ repoRefSpec) ([]byte, error) {
		return manifestYAML, nil
	}

	server := &Server{}
	body := strings.NewReader(`{"repo_ref":"foo/bar","provider_id":"aws-secrets-manager","dry_run":true}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/integrations/install", body)
	rr := httptest.NewRecorder()

	server.handleInstallIntegration(rr, req)

	if rr.Code == http.StatusOK {
		t.Fatalf("expected non-200 for missing required input, got 200 (body=%s)", rr.Body.String())
	}
}
