package manifest

import (
	"encoding/json"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/robfig/cron/v3"
)

var (
	supportedWorkflowTriggerModes  = []string{"manual", "event", "schedule"}
	supportedWorkflowStepKinds     = []string{"integration", "product"}
	supportedProductStepOperations = []string{
		"materialize",
		"installation.reconcile",
		"installation.apply",
		"installation.observe",
		"installation_state.discover",
	}
	workflowTemplatePattern = regexp.MustCompile(`{{\s*([^{}]+?)\s*}}`)
)

// WorkflowExecutionContext carries the runtime values available while rendering one workflow step.
type WorkflowExecutionContext struct {
	Inputs   map[string]any
	Metadata map[string]any
	Auth     model.WorkflowDispatchAuth
	Workflow model.ManifestReference
	Steps    map[string]model.WorkflowRunStepResult
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
func RenderWorkflowInput(value any, ctx WorkflowExecutionContext) (any, error) {
	switch typed := value.(type) {
	case map[string]any:
		rendered := make(map[string]any, len(typed))
		for key, item := range typed {
			next, err := RenderWorkflowInput(item, ctx)
			if err != nil {
				return nil, err
			}
			rendered[key] = next
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
		if step.Use.InstanceRef == nil {
			return fmt.Errorf("integration step requires instance_ref")
		}
		if err := validateManifestSelector("workflow step instance_ref", *step.Use.InstanceRef); err != nil {
			return err
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
		if _, ok := value.(string); !ok {
			return fmt.Errorf("workflow input %q must be a string", name)
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
			builder.WriteString(fmt.Sprint(typed))
		}
		last = match[1]
	}
	builder.WriteString(value[last:])
	return builder.String(), nil
}

func workflowTemplateValue(path string, ctx WorkflowExecutionContext) (any, bool) {
	root := map[string]any{
		"inputs":   ctx.Inputs,
		"metadata": ctx.Metadata,
		"auth":     map[string]any{"token": ctx.Auth.Token},
		"workflow": map[string]any{"name": ctx.Workflow.Name, "namespace": ctx.Workflow.Namespace, "version": ctx.Workflow.Version},
		"steps":    workflowStepResultsContext(ctx.Steps),
	}
	return lookupWorkflowPath(root, strings.TrimSpace(path))
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
		default:
			return nil, false
		}
	}

	return current, true
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

	if op, left, right, found := splitWorkflowStepConditionBinary(trimmed); found {
		leftVal, err := RenderWorkflowInput(left, ctx)
		if err != nil {
			return false, fmt.Errorf("condition left side: %w", err)
		}
		rightVal, err := RenderWorkflowInput(right, ctx)
		if err != nil {
			return false, fmt.Errorf("condition right side: %w", err)
		}
		leftStr := fmt.Sprintf("%v", leftVal)
		rightStr := fmt.Sprintf("%v", rightVal)
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

// splitWorkflowStepConditionBinary looks for " == " or " != " (surrounded
// by a single space on each side) inside the expression. The first match
// wins. Returns the operator, left side, right side and a found flag.
func splitWorkflowStepConditionBinary(expr string) (op, left, right string, found bool) {
	if idx := strings.Index(expr, " == "); idx >= 0 {
		return "==", strings.TrimSpace(expr[:idx]), strings.TrimSpace(expr[idx+4:]), true
	}
	if idx := strings.Index(expr, " != "); idx >= 0 {
		return "!=", strings.TrimSpace(expr[:idx]), strings.TrimSpace(expr[idx+4:]), true
	}
	return "", "", "", false
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
