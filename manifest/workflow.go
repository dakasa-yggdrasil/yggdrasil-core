package manifest

import (
	"encoding/json"
	"fmt"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/robfig/cron/v3"
)

var (
	supportedWorkflowTriggerModes  = []string{"manual", "event", "schedule"}
	supportedWorkflowDispatchModes = []string{"sync", "async"}
	supportedWorkflowStepKinds     = []string{"integration", "product", "yggdrasil"}
	supportedProductStepOperations = []string{
		"materialize",
		"installation.reconcile",
		"installation.apply",
		"installation.observe",
		"installation.uninstall",
		"installation_state.discover",
	}
	// yggdrasil step operations run in-process against the core's own
	// manifest store or pure-render helpers rather than dispatching to
	// an adapter. New entries here require a matching handler in
	// controllers/message/workflows_yggdrasil.go.
	supportedYggdrasilStepOperations = []string{
		"apply_manifest",
		"control_plane.render",
		"collaborator.reconcile_provider_state",
		"oidc_client.verify_bootstrap_file",
	}
	workflowTemplatePattern = regexp.MustCompile(`{{\s*([^{}]+?)\s*}}`)
)

// WorkflowExecutionContext carries the runtime values available while rendering one workflow step.
//
// The `Each` field is populated only inside a for_each iteration: the engine
// fans the parent step out into N iterations, each setting `Each[as]=item`
// so that templates like `{{ each.sub }}` render the per-iteration value.
// Outside a for_each iteration, `Each` is nil and `each.<x>` template paths
// fail to render fail-loud.
type WorkflowExecutionContext struct {
	Inputs   map[string]any
	Metadata map[string]any
	Auth     model.WorkflowDispatchAuth
	Workflow model.ManifestReference
	Steps    map[string]model.WorkflowRunStepResult
	Each     map[string]any
}

// ParseWorkflowSpec parses the raw spec payload into the typed workflow manifest.
func ParseWorkflowSpec(raw json.RawMessage) (model.WorkflowManifestSpec, error) {
	var spec model.WorkflowManifestSpec
	if err := json.Unmarshal(raw, &spec); err != nil {
		return model.WorkflowManifestSpec{}, fmt.Errorf("parse workflow spec: %w", err)
	}
	return spec, nil
}

// ValidateWorkflowSpec validates one workflow manifest.
func ValidateWorkflowSpec(spec model.WorkflowManifestSpec) error {
	triggerMode := strings.ToLower(strings.TrimSpace(spec.Trigger.Mode))
	if triggerMode == "" {
		triggerMode = "manual"
	}
	if !slices.Contains(supportedWorkflowTriggerModes, triggerMode) {
		return fmt.Errorf("workflow trigger mode %q is unsupported", spec.Trigger.Mode)
	}

	if err := validateWorkflowTriggerDetails(triggerMode, spec.Trigger); err != nil {
		return err
	}

	// dispatch_mode controls the default for POST /api/v1/workflow-runs when
	// the request does not opt into a mode explicitly. Empty is treated as
	// "sync" so the historical default for unmigrated workflows is unchanged.
	dispatchMode := strings.ToLower(strings.TrimSpace(spec.DispatchMode))
	if dispatchMode != "" && !slices.Contains(supportedWorkflowDispatchModes, dispatchMode) {
		return fmt.Errorf("workflow dispatch_mode %q is unsupported (allowed: %v)", spec.DispatchMode, supportedWorkflowDispatchModes)
	}
	if spec.Authorization != nil {
		if err := validateManifestSelector("workflow authorization rbac", spec.Authorization.RBAC); err != nil {
			return err
		}
		if spec.Authorization.Policy != nil {
			if err := validateManifestSelector("workflow authorization policy", *spec.Authorization.Policy); err != nil {
				return err
			}
		}
	}

	if err := validateWorkflowInputSchema(spec.InputSchema); err != nil {
		return err
	}
	if err := validateLooseObject("workflow defaults", spec.Defaults); err != nil {
		return err
	}
	if len(spec.Steps) == 0 {
		return fmt.Errorf("workflow steps require at least one value")
	}

	stepNames := map[string]struct{}{}
	for _, step := range spec.Steps {
		id := normalizeIntegrationName(step.ID)
		if id == "" {
			return fmt.Errorf("workflow step id is required")
		}
		if !integrationNamePattern.MatchString(id) {
			return fmt.Errorf("workflow step id %q is invalid", step.ID)
		}
		if _, exists := stepNames[id]; exists {
			return fmt.Errorf("workflow step %q is duplicated", id)
		}
		stepNames[id] = struct{}{}

		if err := validateWorkflowStep(step); err != nil {
			return fmt.Errorf("workflow step %q: %w", id, err)
		}
	}

	for _, step := range spec.Steps {
		id := normalizeIntegrationName(step.ID)
		if err := validateNamedStringList("workflow step depends_on", step.DependsOn); err != nil {
			return fmt.Errorf("workflow step %q: %w", id, err)
		}
		for _, dependency := range step.DependsOn {
			dependency = normalizeIntegrationName(dependency)
			if _, exists := stepNames[dependency]; !exists {
				return fmt.Errorf("workflow step %q depends_on unknown step %q", id, dependency)
			}
			if dependency == id {
				return fmt.Errorf("workflow step %q cannot depend on itself", id)
			}
		}
	}

	if _, err := WorkflowExecutionOrder(spec); err != nil {
		return err
	}

	return nil
}

// ValidateWorkflowInputs validates runtime inputs against the workflow input schema.
func ValidateWorkflowInputs(spec model.WorkflowManifestSpec, inputs map[string]any) error {
	inputs = MergeWorkflowInputs(spec, inputs)
	if inputs == nil {
		inputs = map[string]any{}
	}
	if spec.InputSchema.AdditionalProperties != nil && !*spec.InputSchema.AdditionalProperties {
		undeclared := make([]string, 0)
		for name := range inputs {
			if _, declared := spec.InputSchema.Properties[name]; !declared {
				undeclared = append(undeclared, name)
			}
		}
		if len(undeclared) > 0 {
			sort.Strings(undeclared)
			return fmt.Errorf("workflow inputs %q must be declared in input_schema.properties", undeclared)
		}
	}

	required := map[string]struct{}{}
	for _, name := range spec.InputSchema.Required {
		name = normalizeIntegrationName(name)
		required[name] = struct{}{}
		if _, exists := inputs[name]; !exists {
			return fmt.Errorf("workflow input %q is required", name)
		}
	}

	for name, property := range spec.InputSchema.Properties {
		value, exists := inputs[name]
		if !exists {
			continue
		}
		if err := validateWorkflowInputValue(name, property, value); err != nil {
			return err
		}
	}

	return nil
}

// MergeWorkflowInputs merges manifest defaults with runtime inputs.
// Runtime values override defaults recursively for nested objects.
func MergeWorkflowInputs(spec model.WorkflowManifestSpec, inputs map[string]any) map[string]any {
	base := cloneWorkflowMap(spec.Defaults)
	if len(base) == 0 {
		return cloneWorkflowMap(inputs)
	}
	return mergeWorkflowMaps(base, inputs)
}

// WorkflowExecutionOrder returns the workflow steps in dependency-safe order.
func WorkflowExecutionOrder(spec model.WorkflowManifestSpec) ([]model.WorkflowStepSpec, error) {
	stepByID := make(map[string]model.WorkflowStepSpec, len(spec.Steps))
	remaining := make(map[string]int, len(spec.Steps))
	dependents := make(map[string][]string, len(spec.Steps))

	for _, step := range spec.Steps {
		id := normalizeIntegrationName(step.ID)
		stepByID[id] = step
		remaining[id] = len(step.DependsOn)
		for _, dependency := range step.DependsOn {
			dependency = normalizeIntegrationName(dependency)
			dependents[dependency] = append(dependents[dependency], id)
		}
	}

	queue := make([]string, 0, len(spec.Steps))
	for _, step := range spec.Steps {
		id := normalizeIntegrationName(step.ID)
		if remaining[id] == 0 {
			queue = append(queue, id)
		}
	}

	ordered := make([]model.WorkflowStepSpec, 0, len(spec.Steps))
	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]

		ordered = append(ordered, stepByID[current])
		for _, dependent := range dependents[current] {
			remaining[dependent]--
			if remaining[dependent] == 0 {
				queue = append(queue, dependent)
			}
		}
	}

	if len(ordered) != len(spec.Steps) {
		return nil, fmt.Errorf("workflow steps contain a dependency cycle")
	}

	return ordered, nil
}

// RenderWorkflowInput recursively resolves workflow templates against runtime inputs.
// Both map values AND map keys are rendered — so a step spec like
// `target_overrides: {"{{ inputs.component_name }}": {...}}` resolves the
// key against runtime inputs, enabling generic templates over per-component
// keys without downstream parsers needing to handle unrendered placeholders.
func RenderWorkflowInput(value any, ctx WorkflowExecutionContext) (any, error) {
	switch typed := value.(type) {
	case map[string]any:
		rendered := make(map[string]any, len(typed))
		for key, item := range typed {
			renderedKey, err := renderWorkflowString(key, ctx)
			if err != nil {
				return nil, fmt.Errorf("render map key %q: %w", key, err)
			}
			keyStr, ok := renderedKey.(string)
			if !ok {
				keyStr = fmt.Sprint(renderedKey)
			}
			next, err := RenderWorkflowInput(item, ctx)
			if err != nil {
				return nil, err
			}
			rendered[keyStr] = next
		}
		return rendered, nil
	case []any:
		rendered := make([]any, 0, len(typed))
		for _, item := range typed {
			next, err := RenderWorkflowInput(item, ctx)
			if err != nil {
				return nil, err
			}
			rendered = append(rendered, next)
		}
		return rendered, nil
	case string:
		return renderWorkflowString(typed, ctx)
	default:
		return value, nil
	}
}

func mergeWorkflowMaps(base map[string]any, override map[string]any) map[string]any {
	if len(base) == 0 && len(override) == 0 {
		return map[string]any{}
	}

	merged := cloneWorkflowMap(base)
	for key, value := range override {
		existing, exists := merged[key]
		if !exists {
			merged[key] = cloneWorkflowValue(value)
			continue
		}

		existingMap, existingOK := existing.(map[string]any)
		overrideMap, overrideOK := value.(map[string]any)
		if existingOK && overrideOK {
			merged[key] = mergeWorkflowMaps(existingMap, overrideMap)
			continue
		}

		merged[key] = cloneWorkflowValue(value)
	}

	return merged
}

func cloneWorkflowMap(input map[string]any) map[string]any {
	if len(input) == 0 {
		return map[string]any{}
	}

	cloned := make(map[string]any, len(input))
	for key, value := range input {
		cloned[key] = cloneWorkflowValue(value)
	}
	return cloned
}

func cloneWorkflowValue(value any) any {
	switch typed := value.(type) {
	case map[string]any:
		return cloneWorkflowMap(typed)
	case []any:
		output := make([]any, 0, len(typed))
		for _, item := range typed {
			output = append(output, cloneWorkflowValue(item))
		}
		return output
	default:
		return value
	}
}

func validateWorkflowStep(step model.WorkflowStepSpec) error {
	kind := strings.ToLower(strings.TrimSpace(step.Use.Kind))
	if !slices.Contains(supportedWorkflowStepKinds, kind) {
		return fmt.Errorf("use.kind %q is unsupported", step.Use.Kind)
	}

	switch kind {
	case "integration":
		family := strings.TrimSpace(step.Use.Family)
		if step.Use.InstanceRef == nil && family == "" {
			return fmt.Errorf("integration step requires instance_ref or family")
		}
		if step.Use.InstanceRef != nil && family != "" {
			return fmt.Errorf("integration step cannot combine instance_ref with family; use one resolution mode")
		}
		if step.Use.InstanceRef != nil {
			if err := validateManifestSelector("workflow step instance_ref", *step.Use.InstanceRef); err != nil {
				return err
			}
			if step.Use.ProviderRef != nil {
				return fmt.Errorf("integration step cannot set provider_ref when instance_ref is used")
			}
		} else {
			if !integrationNamePattern.MatchString(family) {
				return fmt.Errorf("integration step family %q is invalid", step.Use.Family)
			}
			if strings.TrimSpace(step.Use.Operation) == "" {
				return fmt.Errorf("integration step with family requires operation")
			}
			if step.Use.ProviderRef != nil {
				if err := validateManifestSelector("workflow step provider_ref", *step.Use.ProviderRef); err != nil {
					return err
				}
			}
		}
		if NormalizeWorkflowStepOperation(step) == "" {
			return fmt.Errorf("integration step requires capability or operation")
		}
		if capability := NormalizeWorkflowStepCapability(step); capability != "" && !integrationNamePattern.MatchString(capability) {
			return fmt.Errorf("integration step capability %q is invalid", step.Use.Capability)
		}
	case "product":
		// Product steps dispatch product operations from inside a workflow.
		// They require an operation name and a product_ref in `with`. The
		// product_ref target is validated at runtime by the product handlers
		// (same code path as the direct product RPC calls).
		operation := strings.ToLower(strings.TrimSpace(step.Use.Operation))
		if operation == "" {
			return fmt.Errorf("product step requires use.operation")
		}
		if !slices.Contains(supportedProductStepOperations, operation) {
			return fmt.Errorf("product step operation %q is unsupported (allowed: %v)", operation, supportedProductStepOperations)
		}
		if step.With == nil {
			return fmt.Errorf("product step requires with.product_ref")
		}
		if _, hasProductRef := step.With["product_ref"]; !hasProductRef {
			return fmt.Errorf("product step requires with.product_ref")
		}
		// instance_ref is not used for product steps
		if step.Use.InstanceRef != nil {
			return fmt.Errorf("product step must not set use.instance_ref (use with.product_ref instead)")
		}
	case "yggdrasil":
		// Yggdrasil steps run in-process against the core's own manifest
		// store: they persist a manifest document carried in with.manifest
		// through the same normalize/validate/persist pipeline that the
		// HTTP and AMQP manifest handlers use. They are resolution-free —
		// there is no integration instance to select and no provider to
		// pin — so instance_ref/family/provider_ref must all be empty.
		operation := strings.ToLower(strings.TrimSpace(step.Use.Operation))
		if operation == "" {
			return fmt.Errorf("yggdrasil step requires use.operation")
		}
		if !slices.Contains(supportedYggdrasilStepOperations, operation) {
			return fmt.Errorf("yggdrasil step operation %q is unsupported (allowed: %v)", operation, supportedYggdrasilStepOperations)
		}
		if step.Use.InstanceRef != nil {
			return fmt.Errorf("yggdrasil step must not set use.instance_ref")
		}
		if strings.TrimSpace(step.Use.Family) != "" {
			return fmt.Errorf("yggdrasil step must not set use.family")
		}
		if step.Use.ProviderRef != nil {
			return fmt.Errorf("yggdrasil step must not set use.provider_ref")
		}
		switch operation {
		case "apply_manifest":
			if step.With == nil {
				return fmt.Errorf("yggdrasil step requires with.manifest")
			}
			if _, hasManifest := step.With["manifest"]; !hasManifest {
				return fmt.Errorf("yggdrasil step requires with.manifest")
			}
		case "control_plane.render":
			if step.With == nil {
				return fmt.Errorf("yggdrasil step control_plane.render requires with.control_plane_ref")
			}
			if _, hasRef := step.With["control_plane_ref"]; !hasRef {
				return fmt.Errorf("yggdrasil step control_plane.render requires with.control_plane_ref")
			}
		case "collaborator.reconcile_provider_state":
			if step.With == nil {
				return fmt.Errorf("yggdrasil step collaborator.reconcile_provider_state requires with.provider")
			}
			if _, hasProvider := step.With["provider"]; !hasProvider {
				return fmt.Errorf("yggdrasil step collaborator.reconcile_provider_state requires with.provider")
			}
		case "oidc_client.verify_bootstrap_file":
			if len(step.With) != 0 {
				return fmt.Errorf("yggdrasil step oidc_client.verify_bootstrap_file accepts no with input")
			}
		}
	}

	if step.TimeoutSeconds < 0 {
		return fmt.Errorf("timeout_seconds cannot be negative")
	}
	if step.Retry.MaxAttempts < 0 {
		return fmt.Errorf("retry.max_attempts cannot be negative")
	}
	if step.Retry.BackoffSeconds < 0 {
		return fmt.Errorf("retry.backoff_seconds cannot be negative")
	}
	if err := validateLooseObject("workflow step with", step.With); err != nil {
		return err
	}

	return nil
}

func validateWorkflowInputSchema(schema model.WorkflowInputSchemaSpec) error {
	requiredSeen := map[string]struct{}{}
	for _, field := range schema.Required {
		field = normalizeIntegrationName(field)
		if field == "" {
			return fmt.Errorf("workflow input_schema required cannot contain empty values")
		}
		if _, exists := requiredSeen[field]; exists {
			return fmt.Errorf("workflow input_schema required field %q is duplicated", field)
		}
		requiredSeen[field] = struct{}{}
	}

	for name, property := range schema.Properties {
		normalizedName := normalizeIntegrationName(name)
		if normalizedName == "" {
			return fmt.Errorf("workflow input_schema property name is required")
		}
		propertyType := strings.ToLower(strings.TrimSpace(property.Type))
		if !slices.Contains(supportedIntegrationSchemaTypes, propertyType) {
			return fmt.Errorf("workflow input_schema property %q has unsupported type %q", name, property.Type)
		}
	}

	if len(schema.Properties) > 0 {
		for field := range requiredSeen {
			if _, exists := schema.Properties[field]; !exists {
				return fmt.Errorf("workflow input_schema required field %q must exist in properties", field)
			}
		}
	}

	return nil
}

func validateWorkflowInputValue(name string, property model.IntegrationSchemaProperty, value any) error {
	switch strings.ToLower(strings.TrimSpace(property.Type)) {
	case "", "string":
		stringValue, ok := value.(string)
		if !ok {
			return fmt.Errorf("workflow input %q must be a string", name)
		}
		// minLength is a string-only constraint and is the second gate after
		// presence (`required`). Empty payloads slip past `required` because
		// the key IS in the map; minLength is what stops `image_repo: ""`
		// from expanding into a no-op image_overrides `{"":":"}`. Whitespace
		// is trimmed so " " is treated as empty — operators paste-fumbling a
		// blank should not silently masquerade as a deploy.
		if property.MinLength != nil {
			minLen := *property.MinLength
			if len(strings.TrimSpace(stringValue)) < minLen {
				return fmt.Errorf("workflow input %q must have minLength %d", name, minLen)
			}
		}
	case "boolean":
		if _, ok := value.(bool); !ok {
			return fmt.Errorf("workflow input %q must be a boolean", name)
		}
	case "integer":
		switch value.(type) {
		case int, int8, int16, int32, int64, float64, float32, json.Number:
			return nil
		default:
			return fmt.Errorf("workflow input %q must be an integer", name)
		}
	case "number":
		switch value.(type) {
		case int, int8, int16, int32, int64, float64, float32, json.Number:
			return nil
		default:
			return fmt.Errorf("workflow input %q must be a number", name)
		}
	case "object":
		if _, ok := value.(map[string]any); !ok {
			return fmt.Errorf("workflow input %q must be an object", name)
		}
	case "array":
		if _, ok := value.([]any); !ok {
			return fmt.Errorf("workflow input %q must be an array", name)
		}
	}
	return nil
}

func renderWorkflowString(value string, ctx WorkflowExecutionContext) (any, error) {
	matches := workflowTemplatePattern.FindAllStringSubmatchIndex(value, -1)
	if len(matches) == 0 {
		return value, nil
	}

	if len(matches) == 1 && matches[0][0] == 0 && matches[0][1] == len(value) {
		resolved, ok := workflowTemplateValue(value[matches[0][2]:matches[0][3]], ctx)
		if !ok {
			return nil, fmt.Errorf("workflow template %q could not be resolved", value)
		}
		return resolved, nil
	}

	var builder strings.Builder
	last := 0
	for _, match := range matches {
		builder.WriteString(value[last:match[0]])
		resolved, ok := workflowTemplateValue(value[match[2]:match[3]], ctx)
		if !ok {
			return nil, fmt.Errorf("workflow template %q could not be resolved", value[match[0]:match[1]])
		}
		switch typed := resolved.(type) {
		case string:
			builder.WriteString(typed)
		case fmt.Stringer:
			builder.WriteString(typed.String())
		default:
			fmt.Fprint(&builder, typed)
		}
		last = match[1]
	}
	builder.WriteString(value[last:])
	return builder.String(), nil
}

// workflowTemplateRoots is the set of context roots a Yggdrasil template path
// may begin with. workflowTemplateValue treats a token whose leading segment is
// absent from this set as a downstream renderer's template (Grafana / Prometheus
// / Alertmanager) and ships it back untouched.
var workflowTemplateRoots = map[string]bool{
	"inputs":   true,
	"metadata": true,
	"auth":     true,
	"workflow": true,
	"steps":    true,
	"each":     true,
}

// workflowTemplateLeadingSegment returns the first path segment of a trimmed
// template body: the text before the first path separator (`.`), index (`[`),
// pipe (`|`), or whitespace. For "inputs.image_tag" it is "inputs"; for
// "service", "$value", ".GroupKey", or "" it is a value absent from
// workflowTemplateRoots, which routes those to the pass-through.
func workflowTemplateLeadingSegment(trimmed string) string {
	for i, r := range trimmed {
		if r == '.' || r == '[' || r == '|' || r == ' ' || r == '\t' {
			return trimmed[:i]
		}
	}
	return trimmed
}

func workflowTemplateValue(path string, ctx WorkflowExecutionContext) (any, bool) {
	trimmed := strings.TrimSpace(path)

	// Pass-through for non-Yggdrasil templates. A Yggdrasil path always
	// begins with a context root key (`inputs`, `steps`, `metadata`,
	// `auth`, `workflow`, `each`). Anything whose leading segment is not
	// one of those is a downstream renderer's token that only shares the
	// `{{ }}` delimiter, and must survive the Yggdrasil pre-render untouched
	// so it reaches its own engine verbatim. Real cases that ship inside a
	// declarative_apply ConfigMap blob:
	//   - Grafana dashboard legends: {{service}}, {{status}}, {{queue}}
	//   - Grafana contact point / Alertmanager: {{ .GroupKey }}, {{ . | toJson }}
	//   - Prometheus / Alertmanager rule annotations: {{ $value }}, {{ $labels.db }}
	// Without this carve-out a Grafana dashboard or a Prometheus rules file
	// fails declarative_apply with "could not be resolved" before the objects
	// ever reach Kubernetes. The `.`-prefixed form was the original, narrower
	// version of this rule; the leading-segment test generalises it so a bare
	// `{{service}}` legend (no dot) and a `{{ $value }}` annotation pass too.
	if leading := workflowTemplateLeadingSegment(trimmed); !workflowTemplateRoots[leading] {
		return "{{ " + trimmed + " }}", true
	}

	root := map[string]any{
		"inputs":   ctx.Inputs,
		"metadata": ctx.Metadata,
		"auth":     map[string]any{"token": ctx.Auth.Token},
		"workflow": map[string]any{"name": ctx.Workflow.Name, "namespace": ctx.Workflow.Namespace, "version": ctx.Workflow.Version},
		"steps":    workflowStepResultsContext(ctx.Steps),
	}
	if ctx.Each != nil {
		root["each"] = ctx.Each
	}
	return lookupWorkflowPath(root, trimmed)
}

func workflowStepResultsContext(results map[string]model.WorkflowRunStepResult) map[string]any {
	output := make(map[string]any, len(results))
	for name, result := range results {
		output[name] = map[string]any{
			"id":         result.ID,
			"kind":       result.Kind,
			"status":     result.Status,
			"operation":  result.Operation,
			"capability": result.Capability,
			"attempts":   result.Attempts,
			"error":      result.Error,
			"metadata":   result.Metadata,
		}
	}
	return output
}

func lookupWorkflowPath(root map[string]any, path string) (any, bool) {
	if path == "" {
		return nil, false
	}

	current := any(root)
	for _, part := range strings.Split(path, ".") {
		part = strings.TrimSpace(part)
		if part == "" {
			return nil, false
		}

		switch typed := current.(type) {
		case map[string]any:
			next, ok := typed[part]
			if !ok {
				return nil, false
			}
			current = next
		case []any:
			// Numeric index into a slice — needed so workflow templates
			// can navigate JSON-shaped event payloads, e.g. an alertmanager
			// webhook's `alerts.0.labels.alertname`.
			idx, err := strconv.Atoi(part)
			if err != nil || idx < 0 || idx >= len(typed) {
				return nil, false
			}
			current = typed[idx]
		default:
			return nil, false
		}
	}

	return current, true
}

// WorkflowDispatchModeAsync is the manifest value that flips the default
// behaviour of POST /api/v1/workflow-runs from sync (HTTP 201 + full
// RunWorkflowResponse, blocking) to async (HTTP 202 + run_id, polled via
// GET /api/v1/workflow-runs/{id}).
const WorkflowDispatchModeAsync = "async"

// NormalizeWorkflowDispatchMode returns the lower-cased dispatch_mode value
// declared in a workflow spec, defaulting to "sync" when empty so callers
// can compare against a stable canonical form. Unknown / invalid values
// fall through unchanged (validation is the job of ValidateWorkflowSpec).
func NormalizeWorkflowDispatchMode(spec model.WorkflowManifestSpec) string {
	mode := strings.ToLower(strings.TrimSpace(spec.DispatchMode))
	if mode == "" {
		return "sync"
	}
	return mode
}

// NormalizeWorkflowStepOperation returns the normalized step operation, defaulting to the capability.
func NormalizeWorkflowStepOperation(step model.WorkflowStepSpec) string {
	operation := normalizeIntegrationName(step.Use.Operation)
	if operation != "" {
		return operation
	}
	return normalizeIntegrationName(step.Use.Capability)
}

// NormalizeWorkflowStepCapability returns the normalized step capability, defaulting to the operation.
func NormalizeWorkflowStepCapability(step model.WorkflowStepSpec) string {
	capability := normalizeIntegrationName(step.Use.Capability)
	if capability != "" {
		return capability
	}
	return NormalizeWorkflowStepOperation(step)
}

// validateWorkflowTriggerDetails checks trigger mode-specific configuration.
// Manual mode accepts any empty sub-objects. Schedule mode requires a valid
// cron expression and optional catchup policy. Event mode requires at least
// one event type pattern.
func validateWorkflowTriggerDetails(mode string, trigger model.WorkflowTriggerSpec) error {
	switch mode {
	case "", "manual":
		return nil

	case "schedule":
		if trigger.Schedule == nil {
			return fmt.Errorf("workflow trigger mode=schedule requires schedule object")
		}
		if strings.TrimSpace(trigger.Schedule.CronExpression) == "" {
			return fmt.Errorf("workflow trigger schedule.cron_expression is required")
		}
		parser := cron.NewParser(cron.Minute | cron.Hour | cron.Dom | cron.Month | cron.Dow)
		if _, err := parser.Parse(trigger.Schedule.CronExpression); err != nil {
			return fmt.Errorf("workflow trigger schedule.cron_expression is invalid: %w", err)
		}
		if tz := strings.TrimSpace(trigger.Schedule.Timezone); tz != "" {
			if _, err := time.LoadLocation(tz); err != nil {
				return fmt.Errorf("workflow trigger schedule.timezone %q is invalid: %w", tz, err)
			}
		}
		catchup := strings.ToLower(strings.TrimSpace(trigger.Schedule.CatchupPolicy))
		if catchup != "" && catchup != "skip" && catchup != "catch_up" {
			return fmt.Errorf("workflow trigger schedule.catchup_policy %q is invalid (allowed: skip, catch_up)", trigger.Schedule.CatchupPolicy)
		}

	case "event":
		if trigger.Event == nil {
			return fmt.Errorf("workflow trigger mode=event requires event object")
		}
		if len(trigger.Event.Types) == 0 {
			return fmt.Errorf("workflow trigger event.types requires at least one type pattern")
		}
		for _, t := range trigger.Event.Types {
			if strings.TrimSpace(t) == "" {
				return fmt.Errorf("workflow trigger event.types cannot contain empty values")
			}
		}
		for i, filter := range trigger.Event.PayloadFilters {
			if strings.TrimSpace(filter.Path) == "" {
				return fmt.Errorf("workflow trigger event.payload_filters[%d].path is required", i)
			}
			op := strings.ToLower(strings.TrimSpace(filter.Operator))
			allowedOps := []string{"eq", "neq", "in", "not_in", "contains", "matches"}
			if !slices.Contains(allowedOps, op) {
				return fmt.Errorf("workflow trigger event.payload_filters[%d].operator %q is invalid (allowed: %v)", i, filter.Operator, allowedOps)
			}
		}
		if trigger.Event.DebounceSeconds < 0 {
			return fmt.Errorf("workflow trigger event.debounce_seconds cannot be negative")
		}
	}

	return nil
}

// EvaluateWorkflowStepCondition decides whether a step should run based on
// its Condition expression. Empty conditions always return true. The
// expression supports:
//
//  1. Unary truthiness — "{{ inputs.flag }}" or a literal like "true".
//     The rendered value is coerced to bool via isConditionTruthy.
//  2. Binary equality — "{{ inputs.env }} == production". The left and
//     right sides are rendered independently then compared as strings.
//     Both `==` and `!=` are supported. Operators must be surrounded by
//     single spaces on both sides.
//
// Rendering failures (unresolvable templates) return an error — the caller
// is expected to fail the step loudly rather than silently skip. Operators
// without spaces are treated as literal characters, so "x==y" with no
// spaces is a single unary expression.
func EvaluateWorkflowStepCondition(condition string, ctx WorkflowExecutionContext) (bool, error) {
	trimmed := strings.TrimSpace(condition)
	if trimmed == "" {
		return true, nil
	}

	// Compound conjunctions / disjunctions are evaluated short-circuit.
	// `&&` binds tighter than `||`, matching the precedence operators
	// have in Go and almost every templated workflow language. Recursion
	// re-enters this same function so each conjunct/disjunct receives
	// the same string-quote / equality treatment as a standalone clause.
	if left, right, found := splitOnTopLevelOperator(trimmed, " || "); found {
		leftBool, err := EvaluateWorkflowStepCondition(left, ctx)
		if err != nil {
			return false, err
		}
		if leftBool {
			return true, nil
		}
		return EvaluateWorkflowStepCondition(right, ctx)
	}
	if left, right, found := splitOnTopLevelOperator(trimmed, " && "); found {
		leftBool, err := EvaluateWorkflowStepCondition(left, ctx)
		if err != nil {
			return false, err
		}
		if !leftBool {
			return false, nil
		}
		return EvaluateWorkflowStepCondition(right, ctx)
	}

	if op, left, right, found := splitWorkflowStepConditionBinary(trimmed); found {
		leftVal, err := RenderWorkflowInput(left, ctx)
		if err != nil {
			return false, fmt.Errorf("condition left side: %w", err)
		}
		rightVal, err := RenderWorkflowInput(right, ctx)
		if err != nil {
			return false, fmt.Errorf("condition right side: %w", err)
		}
		leftStr := stripSurroundingQuotes(fmt.Sprintf("%v", leftVal))
		rightStr := stripSurroundingQuotes(fmt.Sprintf("%v", rightVal))
		switch op {
		case "==":
			return leftStr == rightStr, nil
		case "!=":
			return leftStr != rightStr, nil
		}
	}

	value, err := RenderWorkflowInput(trimmed, ctx)
	if err != nil {
		return false, fmt.Errorf("condition: %w", err)
	}
	return isConditionTruthy(value), nil
}

// splitOnTopLevelOperator looks for a separator that lives outside of any
// {{ }} template span — so an inner `&&` inside a Grafana template literal
// like `{{ printf "%v && %v" .a .b }}` does not split the expression in
// the wrong place. The first top-level occurrence wins.
func splitOnTopLevelOperator(expr, sep string) (left, right string, found bool) {
	depth := 0
	for i := 0; i+len(sep) <= len(expr); i++ {
		if i+1 < len(expr) && expr[i] == '{' && expr[i+1] == '{' {
			depth++
			i++
			continue
		}
		if i+1 < len(expr) && expr[i] == '}' && expr[i+1] == '}' {
			if depth > 0 {
				depth--
			}
			i++
			continue
		}
		if depth == 0 && expr[i:i+len(sep)] == sep {
			return strings.TrimSpace(expr[:i]), strings.TrimSpace(expr[i+len(sep):]), true
		}
	}
	return "", "", false
}

// splitWorkflowStepConditionBinary looks for " == " or " != " (surrounded
// by a single space on each side) inside the expression. The first match
// wins. Returns the operator, left side, right side and a found flag.
// Compound `&&` / `||` are handled before this in EvaluateWorkflowStepCondition.
func splitWorkflowStepConditionBinary(expr string) (op, left, right string, found bool) {
	if idx := strings.Index(expr, " == "); idx >= 0 {
		return "==", strings.TrimSpace(expr[:idx]), strings.TrimSpace(expr[idx+4:]), true
	}
	if idx := strings.Index(expr, " != "); idx >= 0 {
		return "!=", strings.TrimSpace(expr[:idx]), strings.TrimSpace(expr[idx+4:]), true
	}
	return "", "", "", false
}

// stripSurroundingQuotes removes a single matching pair of leading +
// trailing double-quotes (or single-quotes) so condition expressions
// can write `== "succeeded"` and have it compare against the unquoted
// string the left side renders to. Without this fix
// `{{ steps.X.status }} == "succeeded"` always evaluates false because
// the literal `"succeeded"` (quotes included) never equals `succeeded`.
func stripSurroundingQuotes(value string) string {
	if len(value) >= 2 {
		first := value[0]
		last := value[len(value)-1]
		if (first == '"' && last == '"') || (first == '\'' && last == '\'') {
			return value[1 : len(value)-1]
		}
	}
	return value
}

// isConditionTruthy coerces a rendered value to a boolean for the unary
// truthiness check. The rules are deliberately permissive so templates
// that resolve to natural boolean-ish values (strings "true"/"false",
// numbers, slices, maps) behave as users expect.
func isConditionTruthy(value any) bool {
	if value == nil {
		return false
	}
	switch typed := value.(type) {
	case bool:
		return typed
	case string:
		normalized := strings.ToLower(strings.TrimSpace(typed))
		switch normalized {
		case "", "false", "0", "null", "nil":
			return false
		}
		return true
	case int:
		return typed != 0
	case int8:
		return typed != 0
	case int16:
		return typed != 0
	case int32:
		return typed != 0
	case int64:
		return typed != 0
	case uint:
		return typed != 0
	case uint8:
		return typed != 0
	case uint16:
		return typed != 0
	case uint32:
		return typed != 0
	case uint64:
		return typed != 0
	case float32:
		return typed != 0
	case float64:
		return typed != 0
	case []any:
		return len(typed) > 0
	case map[string]any:
		return len(typed) > 0
	default:
		return true
	}
}
