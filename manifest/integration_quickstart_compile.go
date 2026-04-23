package manifest

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

// CompileQuickstartToWorkflow turns a validated IntegrationQuickstartManifestSpec
// into a runnable WorkflowManifestSpec.
//
// Responsibilities:
//   - pick the provider (by id, or the only one if there is just one);
//   - validate user-supplied inputs against the provider's input schema
//     (required / type / regex / choices / min / max);
//   - copy the provider's steps as workflow steps, converting Uses (map)
//     into WorkflowStepUseSpec (struct), and inferring linear depends_on
//     when none is declared;
//   - append the smoke_test as the last step (depends_on the last real step).
//
// Templates ({{ inputs.X }}, {{ steps.Y.outputs.Z }}) are NOT rendered here.
// The workflow engine has a mature resolver — we leave the strings intact so
// (a) the rendering is centralized and (b) DryRun output stays expressive.
func CompileQuickstartToWorkflow(
	spec model.IntegrationQuickstartManifestSpec,
	providerID string,
	userInputs map[string]any,
) (model.WorkflowManifestSpec, model.ProviderQuickstart, error) {
	provider, err := selectProvider(spec, providerID)
	if err != nil {
		return model.WorkflowManifestSpec{}, model.ProviderQuickstart{}, err
	}

	resolved, err := validateAndDefaultInputs(provider.Inputs, userInputs)
	if err != nil {
		return model.WorkflowManifestSpec{}, provider, err
	}

	steps, err := compileSteps(provider.Steps, provider.SmokeTest)
	if err != nil {
		return model.WorkflowManifestSpec{}, provider, err
	}

	wf := model.WorkflowManifestSpec{
		Trigger:     model.WorkflowTriggerSpec{Mode: "manual"},
		InputSchema: buildInputSchema(provider.Inputs),
		Defaults:    resolved,
		Steps:       steps,
	}
	return wf, provider, nil
}

func selectProvider(spec model.IntegrationQuickstartManifestSpec, providerID string) (model.ProviderQuickstart, error) {
	if providerID == "" {
		if len(spec.Providers) == 1 {
			return spec.Providers[0], nil
		}
		ids := make([]string, 0, len(spec.Providers))
		for _, p := range spec.Providers {
			ids = append(ids, p.ID)
		}
		return model.ProviderQuickstart{}, fmt.Errorf("provider_id is required (manifest declares %d providers: %s)", len(spec.Providers), strings.Join(ids, ", "))
	}
	for _, p := range spec.Providers {
		if p.ID == providerID {
			return p, nil
		}
	}
	return model.ProviderQuickstart{}, fmt.Errorf("provider %q not found in manifest", providerID)
}

func validateAndDefaultInputs(declared []model.QuickstartInput, supplied map[string]any) (map[string]any, error) {
	if supplied == nil {
		supplied = map[string]any{}
	}
	resolved := map[string]any{}

	declaredIDs := map[string]struct{}{}
	for _, in := range declared {
		declaredIDs[in.ID] = struct{}{}
		typ := normalizeInputType(in.Type)

		raw, present := supplied[in.ID]
		if !present {
			if in.Required {
				return nil, fmt.Errorf("input %q is required but not provided", in.ID)
			}
			if in.Default != nil {
				resolved[in.ID] = in.Default
			}
			continue
		}

		coerced, err := coerceInputValue(in.ID, typ, raw)
		if err != nil {
			return nil, err
		}
		if err := enforceInputConstraints(in, typ, coerced); err != nil {
			return nil, err
		}
		resolved[in.ID] = coerced
	}

	for k := range supplied {
		if _, ok := declaredIDs[k]; !ok {
			return nil, fmt.Errorf("unknown input %q (not declared by provider)", k)
		}
	}
	return resolved, nil
}

func normalizeInputType(t string) string {
	t = strings.ToLower(strings.TrimSpace(t))
	if t == "" {
		return "string"
	}
	return t
}

func coerceInputValue(id, typ string, raw any) (any, error) {
	switch typ {
	case "string", "select":
		s, ok := raw.(string)
		if !ok {
			return nil, fmt.Errorf("input %q must be a string", id)
		}
		return s, nil
	case "integer":
		switch v := raw.(type) {
		case int:
			return v, nil
		case int64:
			return int(v), nil
		case float64:
			if v != float64(int(v)) {
				return nil, fmt.Errorf("input %q must be an integer (got fractional %v)", id, v)
			}
			return int(v), nil
		case string:
			n, err := strconv.Atoi(v)
			if err != nil {
				return nil, fmt.Errorf("input %q must be an integer (got %q)", id, v)
			}
			return n, nil
		default:
			return nil, fmt.Errorf("input %q must be an integer (got %T)", id, raw)
		}
	case "boolean":
		switch v := raw.(type) {
		case bool:
			return v, nil
		case string:
			b, err := strconv.ParseBool(v)
			if err != nil {
				return nil, fmt.Errorf("input %q must be a boolean (got %q)", id, v)
			}
			return b, nil
		default:
			return nil, fmt.Errorf("input %q must be a boolean (got %T)", id, raw)
		}
	default:
		return raw, nil
	}
}

func enforceInputConstraints(in model.QuickstartInput, typ string, value any) error {
	if typ == "select" {
		s := value.(string)
		for _, c := range in.Choices {
			if c.Value == s {
				return nil
			}
		}
		return fmt.Errorf("input %q value %q is not one of the allowed choices", in.ID, s)
	}

	if in.Validate == nil {
		return nil
	}

	if in.Validate.Regex != "" {
		s, ok := value.(string)
		if !ok {
			return fmt.Errorf("input %q has a regex validator but value is not a string", in.ID)
		}
		re, err := regexp.Compile(in.Validate.Regex)
		if err != nil {
			return fmt.Errorf("input %q validate.regex is invalid: %w", in.ID, err)
		}
		if !re.MatchString(s) {
			if in.Validate.Message != "" {
				return fmt.Errorf("input %q: %s", in.ID, in.Validate.Message)
			}
			return fmt.Errorf("input %q does not match required pattern", in.ID)
		}
	}

	if typ == "integer" {
		n := value.(int)
		if in.Validate.Min != nil && n < *in.Validate.Min {
			return fmt.Errorf("input %q must be >= %d", in.ID, *in.Validate.Min)
		}
		if in.Validate.Max != nil && n > *in.Validate.Max {
			return fmt.Errorf("input %q must be <= %d", in.ID, *in.Validate.Max)
		}
	}
	return nil
}

func buildInputSchema(inputs []model.QuickstartInput) model.WorkflowInputSchemaSpec {
	if len(inputs) == 0 {
		return model.WorkflowInputSchemaSpec{}
	}
	schema := model.WorkflowInputSchemaSpec{
		Properties: map[string]model.IntegrationSchemaProperty{},
	}
	for _, in := range inputs {
		typ := normalizeInputType(in.Type)
		jsonType := typ
		if jsonType == "select" {
			jsonType = "string"
		}
		schema.Properties[in.ID] = model.IntegrationSchemaProperty{
			Type:        jsonType,
			Description: strings.TrimSpace(in.Description),
			Secret:      in.Sensitive,
		}
		if in.Required {
			schema.Required = append(schema.Required, in.ID)
		}
	}
	return schema
}

func compileSteps(qSteps []model.QuickstartStep, smoke *model.QuickstartSmokeTest) ([]model.WorkflowStepSpec, error) {
	steps := make([]model.WorkflowStepSpec, 0, len(qSteps)+1)
	var prevID string
	for i, qs := range qSteps {
		use, err := decodeUses(qs.Uses)
		if err != nil {
			return nil, fmt.Errorf("steps[%d] (%s): %w", i, qs.ID, err)
		}
		ws := model.WorkflowStepSpec{
			ID:             qs.ID,
			Description:    qs.Description,
			Condition:      qs.Condition,
			Use:            use,
			With:           qs.With,
			TimeoutSeconds: qs.TimeoutSeconds,
		}
		if qs.Retry != nil {
			ws.Retry = *qs.Retry
		}
		if prevID != "" {
			ws.DependsOn = []string{prevID}
		}
		steps = append(steps, ws)
		prevID = qs.ID
	}

	if smoke != nil {
		use, err := decodeUses(smoke.Uses)
		if err != nil {
			return nil, fmt.Errorf("smoke_test: %w", err)
		}
		smokeStep := model.WorkflowStepSpec{
			ID:             "smoke-test",
			Description:    smoke.Description,
			Use:            use,
			With:           smoke.With,
			TimeoutSeconds: smoke.TimeoutSeconds,
		}
		if prevID != "" {
			smokeStep.DependsOn = []string{prevID}
		}
		steps = append(steps, smokeStep)
	}
	return steps, nil
}

func decodeUses(raw map[string]any) (model.WorkflowStepUseSpec, error) {
	if len(raw) == 0 {
		return model.WorkflowStepUseSpec{}, fmt.Errorf("uses is required")
	}
	data, err := json.Marshal(raw)
	if err != nil {
		return model.WorkflowStepUseSpec{}, fmt.Errorf("encode uses: %w", err)
	}
	var use model.WorkflowStepUseSpec
	if err := json.Unmarshal(data, &use); err != nil {
		return model.WorkflowStepUseSpec{}, fmt.Errorf("decode uses: %w", err)
	}
	if use.Kind == "" {
		return model.WorkflowStepUseSpec{}, fmt.Errorf("uses.kind is required")
	}
	return use, nil
}
