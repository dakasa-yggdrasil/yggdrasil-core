package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	messagecontroller "github.com/dakasa-yggdrasil/yggdrasil-core/controllers/message"
	manifestengine "github.com/dakasa-yggdrasil/yggdrasil-core/manifest"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"sigs.k8s.io/yaml"
)

// defaultQuickstartPath is the conventional location of the quickstart
// manifest inside an integration repository. It can be overridden via
// repo_ref using the "owner/repo:path/to/file" syntax.
const defaultQuickstartPath = "yggdrasil-quickstart.yaml"

// quickstartFetcher is overridable in tests to avoid hitting GitHub.
var quickstartFetcher = fetchQuickstartManifest

// handleInstallIntegration accepts a quickstart install request, fetches the
// manifest, validates+compiles it into a workflow, optionally persists and
// dispatches the workflow run. DryRun=true short-circuits before persistence
// so the adopter can preview the compiled workflow.
//
//	POST /api/v1/integrations/install
//	{
//	  "repo_ref":     "owner/repo[@ref][:path]",
//	  "provider_id":  "aws-secrets-manager",
//	  "inputs":       {...},
//	  "dry_run":      false
//	}
func (s *Server) handleInstallIntegration(w http.ResponseWriter, r *http.Request) {
	if err := authorizeWorkflowRunRequest(r); err != nil {
		writeMappedError(w, err)
		return
	}

	var req model.InstallIntegrationRequest
	if err := decodeJSON(r, &req); err != nil {
		writeMappedError(w, err)
		return
	}

	repoRef, err := parseRepoRef(req.RepoRef)
	if err != nil {
		writeMappedError(w, err)
		return
	}

	rawManifest, err := quickstartFetcher(r.Context(), repoRef)
	if err != nil {
		writeMappedError(w, fmt.Errorf("fetch quickstart manifest: %w", err))
		return
	}

	doc, err := decodeQuickstartDocument(rawManifest)
	if err != nil {
		writeMappedError(w, err)
		return
	}

	if err := manifestengine.ValidateDocument(doc); err != nil {
		writeMappedError(w, err)
		return
	}

	spec, err := manifestengine.ParseIntegrationQuickstartSpec(doc.Spec)
	if err != nil {
		writeMappedError(w, err)
		return
	}

	workflow, provider, err := manifestengine.CompileQuickstartToWorkflow(spec, req.ProviderID, req.Inputs)
	if err != nil {
		writeMappedError(w, err)
		return
	}

	resp := model.InstallIntegrationResponse{
		ProviderID: provider.ID,
		Hints:      provider.PostInstallHints,
	}

	if req.DryRun {
		resp.CompiledWorkflow = &workflow
		writeJSON(w, http.StatusOK, resp)
		return
	}

	wfManifest, err := persistCompiledWorkflow(r.Context(), s, doc.Metadata.Name, provider.ID, workflow)
	if err != nil {
		writeMappedError(w, fmt.Errorf("persist compiled workflow: %w", err))
		return
	}

	runResp, err := messagecontroller.RunWorkflow(r.Context(), s.rabbitmq, s.db, model.RunWorkflowRequest{
		Workflow: model.ManifestSelector{
			Namespace: wfManifest.Metadata.Namespace,
			Name:      wfManifest.Metadata.Name,
		},
		Inputs: req.Inputs,
	})
	if err != nil {
		writeMappedError(w, fmt.Errorf("dispatch workflow run: %w", err))
		return
	}

	resp.RunID = runResp.Workflow.ID.String()
	writeJSON(w, http.StatusCreated, resp)
}

// repoRefSpec is the parsed form of "owner/repo[@ref][:path]".
type repoRefSpec struct {
	Owner string
	Repo  string
	Ref   string // git ref; empty means "main"
	Path  string // path inside the repo; empty means defaultQuickstartPath
}

func parseRepoRef(raw string) (repoRefSpec, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return repoRefSpec{}, errors.New("repo_ref is required")
	}

	rest := raw
	var path string
	if i := strings.Index(rest, ":"); i >= 0 {
		path = strings.TrimSpace(rest[i+1:])
		rest = rest[:i]
	}

	var ref string
	if i := strings.Index(rest, "@"); i >= 0 {
		ref = strings.TrimSpace(rest[i+1:])
		rest = rest[:i]
	}

	parts := strings.SplitN(rest, "/", 2)
	if len(parts) != 2 || strings.TrimSpace(parts[0]) == "" || strings.TrimSpace(parts[1]) == "" {
		return repoRefSpec{}, fmt.Errorf("repo_ref %q must look like owner/repo[@ref][:path]", raw)
	}

	if ref == "" {
		ref = "main"
	}
	if path == "" {
		path = defaultQuickstartPath
	}
	return repoRefSpec{
		Owner: strings.TrimSpace(parts[0]),
		Repo:  strings.TrimSpace(parts[1]),
		Ref:   ref,
		Path:  path,
	}, nil
}

// fetchQuickstartManifest downloads the manifest via raw.githubusercontent.com.
// Public repos work out of the box; private repos require a GitHub-side
// integration that proxies the read — out of scope for the POC, which the
// adopter can layer on by replacing quickstartFetcher.
func fetchQuickstartManifest(ctx context.Context, ref repoRefSpec) ([]byte, error) {
	url := fmt.Sprintf("https://raw.githubusercontent.com/%s/%s/%s/%s", ref.Owner, ref.Repo, ref.Ref, ref.Path)
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	httpReq.Header.Set("User-Agent", "yggdrasil-core/integrations-install")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("download %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("download %s: HTTP %d", url, resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}
	return body, nil
}

// decodeQuickstartDocument accepts either YAML or JSON, normalizing to a
// ManifestDocument. We detect format heuristically: a leading `{` means JSON,
// anything else gets YAML→JSON conversion via sigs.k8s.io/yaml (which honors
// JSON struct tags).
func decodeQuickstartDocument(raw []byte) (model.ManifestDocument, error) {
	trimmed := bytesTrimSpace(raw)
	var jsonBytes []byte
	if len(trimmed) > 0 && trimmed[0] == '{' {
		jsonBytes = raw
	} else {
		converted, err := yaml.YAMLToJSON(raw)
		if err != nil {
			return model.ManifestDocument{}, fmt.Errorf("convert YAML to JSON: %w", err)
		}
		jsonBytes = converted
	}

	var doc model.ManifestDocument
	if err := json.Unmarshal(jsonBytes, &doc); err != nil {
		return model.ManifestDocument{}, fmt.Errorf("decode manifest envelope: %w", err)
	}
	return doc, nil
}

// persistCompiledWorkflow writes the compiled workflow into the manifest
// store under a deterministic name tied to the source quickstart + provider
// + timestamp. It is labeled so future cleanup jobs can find them.
func persistCompiledWorkflow(
	ctx context.Context,
	s *Server,
	quickstartName string,
	providerID string,
	workflow model.WorkflowManifestSpec,
) (model.Manifest, error) {
	specBytes, err := json.Marshal(workflow)
	if err != nil {
		return model.Manifest{}, fmt.Errorf("marshal workflow: %w", err)
	}

	timestamp := time.Now().UTC().Format("20060102150405")
	name := fmt.Sprintf("quickstart-%s-%s-%s", quickstartName, providerID, timestamp)

	doc := model.ManifestDocument{
		APIVersion: "yggdrasil.io/v1alpha1",
		Kind:       "workflow",
		Metadata: model.ManifestMetadataInput{
			Name:      name,
			Namespace: "global",
			Labels: map[string]string{
				"dakasa.io/managed_by": "quickstart",
				"dakasa.io/source":     quickstartName,
				"dakasa.io/provider":   providerID,
			},
			Description: fmt.Sprintf("Auto-generated by integration_quickstart for %s/%s", quickstartName, providerID),
		},
		Spec: specBytes,
	}

	manifest, err := createManifestVersion(ctx, s.db, doc)
	if err != nil {
		return model.Manifest{}, err
	}
	s.materializeAfterManifestWrite(manifest)
	return manifest, nil
}
