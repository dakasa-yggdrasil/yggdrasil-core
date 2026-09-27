package manifest

import "fmt"

// WorkflowAssertInput is the closed input contract for the in-process
// yggdrasil assert operation. Values stay opaque here so the workflow renderer
// can resolve complete templates to their native JSON-compatible types before
// execution.
type WorkflowAssertInput struct {
	Equal    []WorkflowAssertEqualCheck
	Nonempty []WorkflowAssertNonemptyCheck
}

// WorkflowAssertEqualCheck compares two rendered values without coercion.
type WorkflowAssertEqualCheck struct {
	Name     string
	Actual   any
	Expected any
}

// WorkflowAssertNonemptyCheck requires one rendered string, collection, or map
// to contain at least one item.
type WorkflowAssertNonemptyCheck struct {
	Name  string
	Value any
}

// ParseWorkflowAssertInput validates and decodes the closed assert input
// shape. Error messages deliberately identify only fields, positions, and
// check names. Assertion values may contain credentials or response headers
// and must never cross into errors or workflow metadata.
func ParseWorkflowAssertInput(input map[string]any) (WorkflowAssertInput, error) {
	for key := range input {
		if key != "equal" && key != "nonempty" {
			return WorkflowAssertInput{}, fmt.Errorf("assert input contains unsupported fields")
		}
	}

	parsed := WorkflowAssertInput{}
	seenNames := map[string]struct{}{}

	if raw, exists := input["equal"]; exists {
		checks, ok := raw.([]any)
		if !ok {
			return WorkflowAssertInput{}, fmt.Errorf("assert with.equal must be an array")
		}
		parsed.Equal = make([]WorkflowAssertEqualCheck, 0, len(checks))
		for index, rawCheck := range checks {
			check, ok := rawCheck.(map[string]any)
			if !ok || !hasExactWorkflowAssertFields(check, "name", "actual", "expected") {
				return WorkflowAssertInput{}, fmt.Errorf("assert equal check %d must contain exactly name, actual, and expected", index+1)
			}
			name, ok := check["name"].(string)
			if !ok || name == "" {
				return WorkflowAssertInput{}, fmt.Errorf("assert equal check %d requires a non-empty string name", index+1)
			}
			if _, duplicate := seenNames[name]; duplicate {
				return WorkflowAssertInput{}, fmt.Errorf("assert check name %q is duplicated", name)
			}
			seenNames[name] = struct{}{}
			parsed.Equal = append(parsed.Equal, WorkflowAssertEqualCheck{
				Name:     name,
				Actual:   check["actual"],
				Expected: check["expected"],
			})
		}
	}

	if raw, exists := input["nonempty"]; exists {
		checks, ok := raw.([]any)
		if !ok {
			return WorkflowAssertInput{}, fmt.Errorf("assert with.nonempty must be an array")
		}
		parsed.Nonempty = make([]WorkflowAssertNonemptyCheck, 0, len(checks))
		for index, rawCheck := range checks {
			check, ok := rawCheck.(map[string]any)
			if !ok || !hasExactWorkflowAssertFields(check, "name", "value") {
				return WorkflowAssertInput{}, fmt.Errorf("assert nonempty check %d must contain exactly name and value", index+1)
			}
			name, ok := check["name"].(string)
			if !ok || name == "" {
				return WorkflowAssertInput{}, fmt.Errorf("assert nonempty check %d requires a non-empty string name", index+1)
			}
			if _, duplicate := seenNames[name]; duplicate {
				return WorkflowAssertInput{}, fmt.Errorf("assert check name %q is duplicated", name)
			}
			seenNames[name] = struct{}{}
			parsed.Nonempty = append(parsed.Nonempty, WorkflowAssertNonemptyCheck{
				Name:  name,
				Value: check["value"],
			})
		}
	}

	if len(parsed.Equal)+len(parsed.Nonempty) == 0 {
		return WorkflowAssertInput{}, fmt.Errorf("assert requires at least one equal or nonempty check")
	}

	return parsed, nil
}

func hasExactWorkflowAssertFields(input map[string]any, fields ...string) bool {
	if len(input) != len(fields) {
		return false
	}
	for _, field := range fields {
		if _, exists := input[field]; !exists {
			return false
		}
	}
	return true
}
