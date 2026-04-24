// Package operator runs a Yggdrasil-native reconciler that watches
// control_plane manifests via the core's HTTP API and dispatches the
// yggdrasil-deploy-control-plane workflow whenever a new version
// lands. It is the event-driven counterpart to `yggdrasil deploy
// control-plane`: same workflow, same shape, continuous.
//
// This is deliberately NOT a Kubernetes Operator watching CRDs. The
// control_plane manifest already lives in the core's catalog; a CRD
// would duplicate the authoritative definition. GitOps adopters
// keep their flow (git file → `yggdrasil apply -f`) — the operator
// picks up from there.
package operator

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Client is the minimal HTTP client the operator needs against a
// yggdrasil-core. It implements only the three endpoints reconcile
// uses (list manifests, run workflow, readyz), so it stays
// dependency-free — no `internal/corecli` import, no `sdk-go` dep.
type Client struct {
	baseURL string
	token   string
	http    *http.Client
}

// NewClient constructs a Client. tokenSource is a string that may
// either be a bearer token (the usual case) or empty when the core
// has auth disabled (dev).
func NewClient(baseURL, token string) *Client {
	return &Client{
		baseURL: strings.TrimRight(baseURL, "/"),
		token:   token,
		http: &http.Client{
			Timeout: 60 * time.Second,
		},
	}
}

// ManifestRecord is the subset of fields the reconciler needs.
// Kept minimal so the shape survives additive API changes — the
// core returns more, we decode only what we read.
type ManifestRecord struct {
	ID       string         `json:"id"`
	Kind     string         `json:"kind"`
	Metadata RecordMetadata `json:"metadata"`
	Version  int            `json:"version"`
	Active   bool           `json:"active"`
}

// RecordMetadata mirrors the core's ManifestMetadata, trimmed.
type RecordMetadata struct {
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
}

// WorkflowRunStep is one step in a workflow run response.
type WorkflowRunStep struct {
	ID      string `json:"id"`
	Kind    string `json:"kind"`
	Status  string `json:"status"`
	Error   string `json:"error,omitempty"`
}

// WorkflowRunResult is the subset of RunWorkflowResponse we care
// about.
type WorkflowRunResult struct {
	Status string            `json:"status"`
	Steps  []WorkflowRunStep `json:"steps"`
}

// ListControlPlanes fetches every active control_plane manifest the
// core knows about. Ordered by the core's default (version DESC) but
// the reconciler treats the list as a set — order does not matter.
func (c *Client) ListControlPlanes(ctx context.Context) ([]ManifestRecord, error) {
	q := url.Values{}
	q.Set("kind", "control_plane")
	q.Set("active_only", "true")

	var body struct {
		Manifests []ManifestRecord `json:"manifests"`
	}
	if err := c.do(ctx, http.MethodGet, "/api/v1/manifests?"+q.Encode(), nil, &body); err != nil {
		return nil, err
	}
	return body.Manifests, nil
}

// RunDeployWorkflow dispatches yggdrasil-deploy-control-plane for the
// named control_plane manifest. Inputs match what the CLI's
// `deploy control-plane` subcommand sends so both paths exercise the
// same workflow shape.
func (c *Client) RunDeployWorkflow(ctx context.Context, cp ManifestRecord, opts DispatchOptions) (WorkflowRunResult, error) {
	payload := map[string]any{
		"workflow": map[string]any{
			"namespace": "global",
			"name":      "yggdrasil-deploy-control-plane",
		},
		"inputs": map[string]any{
			"control_plane": map[string]any{
				"namespace": cp.Metadata.Namespace,
				"name":      cp.Metadata.Name,
				"version":   cp.Version,
			},
			"kubernetes_instance": map[string]any{
				"namespace": opts.InstanceNamespace,
				"name":      opts.KubernetesInstance,
			},
			"schema_migrations_instance": map[string]any{
				"namespace": opts.InstanceNamespace,
				"name":      opts.SchemaMigrationsInstance,
			},
		},
		"metadata": map[string]any{
			"source": "yggdrasil-operator",
		},
	}
	var result WorkflowRunResult
	if err := c.do(ctx, http.MethodPost, "/api/v1/workflow-runs", payload, &result); err != nil {
		return WorkflowRunResult{}, err
	}
	return result, nil
}

// Readyz polls /readyz. The operator's own /readyz gates on this
// returning 200 — if the core is down, the operator is not ready
// either.
func (c *Client) Readyz(ctx context.Context) error {
	return c.do(ctx, http.MethodGet, "/readyz", nil, nil)
}

// do is the lowest-level HTTP call. Marshals body, dispatches, and
// decodes the response into out when non-nil. A non-2xx response is
// surfaced as an error with status code + truncated body so logs
// carry a diagnostic without dumping arbitrary HTML.
func (c *Client) do(ctx context.Context, method, path string, body any, out any) error {
	var reader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("marshal request body: %w", err)
		}
		reader = bytes.NewReader(encoded)
	}

	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, reader)
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("%s %s: %w", method, path, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return fmt.Errorf("%s %s: %s: %s", method, path, resp.Status, strings.TrimSpace(string(snippet)))
	}
	if out == nil {
		return nil
	}
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}
	return nil
}

// DispatchOptions carries per-run overrides the reconciler passes
// along. Zero values fall back to the defaults that match the
// compose topology seeded by `yggdrasil init`.
type DispatchOptions struct {
	KubernetesInstance       string
	SchemaMigrationsInstance string
	InstanceNamespace        string
}

// WithDefaults fills in the compose-topology defaults.
func (o DispatchOptions) WithDefaults() DispatchOptions {
	if o.KubernetesInstance == "" {
		o.KubernetesInstance = "yggdrasil-core-kubernetes"
	}
	if o.SchemaMigrationsInstance == "" {
		o.SchemaMigrationsInstance = "yggdrasil-core-schema-migrations"
	}
	if o.InstanceNamespace == "" {
		o.InstanceNamespace = "global"
	}
	return o
}
