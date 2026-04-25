package httpapi

import (
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"

	manifestengine "github.com/dakasa-yggdrasil/yggdrasil-core/manifest"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
)

// templateInstantiateRequest is the body for POST /api/v1/workflow-templates/{ns}/{name}/instantiate.
type templateInstantiateRequest struct {
	// Name is the name to assign to the resulting workflow manifest.
	Name string `json:"name"`
	// Namespace where the resulting workflow is created. Defaults to template's namespace.
	Namespace string `json:"namespace,omitempty"`
	// Params satisfy the template's params declarations. Required params must be present.
	Params map[string]any `json:"params"`
	// Apply, when true, posts the rendered workflow manifest server-side. Default false:
	// returns the rendered shape without persisting, so callers can preview.
	Apply bool `json:"apply,omitempty"`
}

// templateParamPattern matches {{ params.<name> }} placeholders in the template body.
var templateParamPattern = regexp.MustCompile(`\{\{\s*params\.([a-zA-Z0-9_]+)\s*\}\}`)

// handleWorkflowTemplateInstantiate substitutes `{{ params.* }}` placeholders
// in a workflow_template's body with caller-supplied values, validates the
// resulting workflow shape, and either returns it (`apply=false`) or persists
// it (`apply=true`).
//
//	POST /api/v1/workflow-templates/{namespace}/{name}/instantiate
func (s *Server) handleWorkflowTemplateInstantiate(w http.ResponseWriter, r *http.Request) {
	templateNS := r.PathValue("namespace")
	templateName := r.PathValue("name")
	if strings.TrimSpace(templateNS) == "" || strings.TrimSpace(templateName) == "" {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: "namespace and name are required"})
		return
	}

	var req templateInstantiateRequest
	if err := decodeJSON(r, &req); err != nil {
		writeMappedError(w, err)
		return
	}
	if strings.TrimSpace(req.Name) == "" {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: "name is required (the workflow name to assign)"})
		return
	}
	targetNS := strings.TrimSpace(req.Namespace)
	if targetNS == "" {
		targetNS = templateNS
	}

	templates, err := repository.ListManifests(r.Context(), s.db, model.ListManifestFilters{
		Kind:       "workflow_template",
		Namespace:  templateNS,
		Name:       templateName,
		ActiveOnly: true,
	})
	if err != nil {
		writeMappedError(w, err)
		return
	}
	if len(templates) == 0 {
		writeJSON(w, http.StatusNotFound, errorResponse{
			Error: fmt.Sprintf("workflow_template %s/%s not found", templateNS, templateName),
		})
		return
	}

	tmplSpec, err := manifestengine.ParseWorkflowTemplateSpec(templates[0].Spec)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errorResponse{Error: "decode template: " + err.Error()})
		return
	}

	if err := validateRequiredParams(tmplSpec, req.Params); err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: err.Error()})
		return
	}

	rendered, err := substituteParams(tmplSpec.Body, mergeParams(tmplSpec, req.Params))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: "param substitution: " + err.Error()})
		return
	}

	// Validate result is a coherent workflow_spec.
	wfSpec, err := manifestengine.ParseWorkflowSpec(rendered)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: "rendered workflow invalid: " + err.Error()})
		return
	}
	if err := manifestengine.ValidateWorkflowSpec(wfSpec); err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: "rendered workflow validation failed: " + err.Error()})
		return
	}

	resp := map[string]any{
		"template": map[string]string{"namespace": templateNS, "name": templateName, "version": tmplSpec.Version},
		"workflow": map[string]any{
			"apiVersion": "yggdrasil.io/v1alpha1",
			"kind":       "workflow",
			"metadata":   map[string]string{"namespace": targetNS, "name": req.Name},
			"spec":       json.RawMessage(rendered),
		},
		"applied": false,
	}

	if req.Apply {
		doc := model.ManifestDocument{
			APIVersion: "yggdrasil.io/v1alpha1",
			Kind:       "workflow",
			Metadata:   model.ManifestMetadataInput{Name: req.Name, Namespace: targetNS},
			Spec:       rendered,
		}
		if err := manifestengine.ValidateDocument(doc); err != nil {
			writeJSON(w, http.StatusBadRequest, errorResponse{Error: "validate: " + err.Error()})
			return
		}
		checksum, err := manifestengine.Checksum(doc)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, errorResponse{Error: "checksum: " + err.Error()})
			return
		}
		manifest, err := repository.CreateManifestVersion(r.Context(), s.db, doc, checksum)
		if err != nil {
			writeMappedError(w, err)
			return
		}
		s.recordAudit(r, "workflow_template.instantiate", "workflow_template",
			fmt.Sprintf("%s/%s", templateNS, templateName), "success",
			map[string]any{"target_workflow": fmt.Sprintf("%s/%s", targetNS, req.Name), "applied": true})
		resp["workflow"] = manifest
		resp["applied"] = true
		writeJSON(w, http.StatusCreated, resp)
		return
	}

	s.recordAudit(r, "workflow_template.instantiate", "workflow_template",
		fmt.Sprintf("%s/%s", templateNS, templateName), "success",
		map[string]any{"target_workflow": fmt.Sprintf("%s/%s", targetNS, req.Name), "applied": false})
	writeJSON(w, http.StatusOK, resp)
}

// validateRequiredParams checks every required param is present.
func validateRequiredParams(spec model.WorkflowTemplateManifestSpec, supplied map[string]any) error {
	for name, p := range spec.Params {
		if !p.Required {
			continue
		}
		if _, ok := supplied[name]; !ok {
			return fmt.Errorf("required param %q is missing", name)
		}
	}
	return nil
}

// mergeParams overlays supplied params on top of param defaults.
func mergeParams(spec model.WorkflowTemplateManifestSpec, supplied map[string]any) map[string]any {
	out := make(map[string]any, len(spec.Params))
	for name, p := range spec.Params {
		if p.Default != nil {
			out[name] = p.Default
		}
	}
	for k, v := range supplied {
		out[k] = v
	}
	return out
}

// substituteParams walks the JSON body and replaces every `{{ params.<name> }}`
// placeholder with the corresponding value from `params`. Unknown placeholders
// return error. Non-string values pass through.
func substituteParams(body json.RawMessage, params map[string]any) (json.RawMessage, error) {
	str := string(body)
	var firstErr error
	replaced := templateParamPattern.ReplaceAllStringFunc(str, func(match string) string {
		sub := templateParamPattern.FindStringSubmatch(match)
		if len(sub) != 2 {
			return match
		}
		name := sub[1]
		val, ok := params[name]
		if !ok {
			if firstErr == nil {
				firstErr = fmt.Errorf("unknown placeholder {{ params.%s }} (not declared in template)", name)
			}
			return match
		}
		raw, err := json.Marshal(val)
		if err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("marshal param %q: %w", name, err)
			}
			return match
		}
		// Strip surrounding quotes when we're replacing inside a JSON string literal.
		// e.g. "name": "{{ params.foo }}" with foo="bar" becomes "name": "bar".
		// The placeholder match always lives inside quotes when emitted by template authors;
		// we let json.Marshal produce "..." and trim if the surrounding context has quotes.
		s := string(raw)
		// If the raw is a JSON string ("...") and is surrounded by quotes in the body,
		// strip the JSON quotes so the result is a plain string substitution.
		if strings.HasPrefix(s, `"`) && strings.HasSuffix(s, `"`) {
			return strings.Trim(s, `"`)
		}
		return s
	})
	if firstErr != nil {
		return nil, firstErr
	}
	return json.RawMessage(replaced), nil
}
