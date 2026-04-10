package manifest

import (
	"encoding/json"
	"fmt"
	"path"
	"reflect"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

var supportedPolicyOperators = []string{
	"eq",
	"neq",
	"gt",
	"gte",
	"lt",
	"lte",
	"in",
	"not_in",
	"contains",
	"exists",
	"matches",
}

// ParsePolicySpec parses the raw spec payload into the typed policy manifest.
func ParsePolicySpec(raw json.RawMessage) (model.PolicyManifestSpec, error) {
	var spec model.PolicyManifestSpec
	if err := json.Unmarshal(raw, &spec); err != nil {
		return model.PolicyManifestSpec{}, fmt.Errorf("parse policy spec: %w", err)
	}
	return spec, nil
}

// ValidatePolicySpec validates the policy manifest semantics.
func ValidatePolicySpec(spec model.PolicyManifestSpec) error {
	if len(spec.Rules) == 0 {
		return fmt.Errorf("policy spec requires at least one rule")
	}

	ruleNames := map[string]struct{}{}
	for _, rule := range spec.Rules {
		name := strings.TrimSpace(rule.Name)
		if name == "" {
			return fmt.Errorf("policy rule name is required")
		}
		if _, exists := ruleNames[name]; exists {
			return fmt.Errorf("policy rule %q is duplicated", name)
		}
		ruleNames[name] = struct{}{}

		effect := normalizeEffect(rule.Effect)
		if effect != "allow" && effect != "deny" {
			return fmt.Errorf("policy rule %q has invalid effect %q", name, rule.Effect)
		}
		if len(rule.Resources) == 0 {
			return fmt.Errorf("policy rule %q requires at least one resource pattern", name)
		}
		if len(rule.Actions) == 0 {
			return fmt.Errorf("policy rule %q requires at least one action pattern", name)
		}

		for _, resource := range rule.Resources {
			if strings.TrimSpace(resource) == "" {
				return fmt.Errorf("policy rule %q contains an empty resource pattern", name)
			}
		}
		for _, action := range rule.Actions {
			if strings.TrimSpace(action) == "" {
				return fmt.Errorf("policy rule %q contains an empty action pattern", name)
			}
		}

		for _, condition := range rule.Conditions {
			if err := validatePolicyCondition(condition); err != nil {
				return fmt.Errorf("policy rule %q: %w", name, err)
			}
		}
	}

	return nil
}

// EvaluatePolicy calculates whether a policy manifest allows, denies, or does not apply.
func EvaluatePolicy(spec model.PolicyManifestSpec, resource, action string, input map[string]any) (bool, string, []model.PolicyRuleMatch, error) {
	if err := ValidatePolicySpec(spec); err != nil {
		return false, "", nil, err
	}

	resource = strings.TrimSpace(resource)
	action = strings.TrimSpace(action)
	if resource == "" || action == "" {
		return false, "", nil, fmt.Errorf("resource and action are required")
	}
	if input == nil {
		input = map[string]any{}
	}

	var (
		matchedRules []model.PolicyRuleMatch
		allowMatch   bool
		denyMatch    bool
	)

	for _, rule := range spec.Rules {
		if !anyPatternMatch(rule.Resources, resource) || !anyPatternMatch(rule.Actions, action) {
			continue
		}

		matchedConditions, matched, err := evaluatePolicyConditions(rule.Conditions, input)
		if err != nil {
			return false, "", nil, fmt.Errorf("policy rule %q: %w", rule.Name, err)
		}
		if !matched {
			continue
		}

		effect := normalizeEffect(rule.Effect)
		matchedRules = append(matchedRules, model.PolicyRuleMatch{
			Name:        strings.TrimSpace(rule.Name),
			Effect:      effect,
			Description: strings.TrimSpace(rule.Description),
			Resources:   append([]string(nil), rule.Resources...),
			Actions:     append([]string(nil), rule.Actions...),
			Conditions:  matchedConditions,
		})

		if effect == "deny" {
			denyMatch = true
		}
		if effect == "allow" {
			allowMatch = true
		}
	}

	if denyMatch {
		return false, "deny", matchedRules, nil
	}
	if allowMatch {
		return true, "allow", matchedRules, nil
	}

	return false, "not_applicable", matchedRules, nil
}

func validatePolicyCondition(condition model.PolicyCondition) error {
	if strings.TrimSpace(condition.Key) == "" {
		return fmt.Errorf("condition key is required")
	}

	operator := strings.ToLower(strings.TrimSpace(condition.Operator))
	if !slices.Contains(supportedPolicyOperators, operator) {
		return fmt.Errorf("unsupported operator %q", condition.Operator)
	}

	if operator != "exists" && condition.Value == nil {
		return fmt.Errorf("condition %q requires value", condition.Key)
	}

	return nil
}

func evaluatePolicyConditions(conditions []model.PolicyCondition, input map[string]any) ([]model.PolicyConditionMatch, bool, error) {
	if len(conditions) == 0 {
		return nil, true, nil
	}

	matches := make([]model.PolicyConditionMatch, 0, len(conditions))
	for _, condition := range conditions {
		actual, exists := lookupPath(input, condition.Key)
		expected := resolvePolicyValue(input, condition.Value)
		ok, err := policyConditionMatches(strings.ToLower(strings.TrimSpace(condition.Operator)), actual, exists, expected)
		if err != nil {
			return nil, false, err
		}
		if !ok {
			return nil, false, nil
		}

		matches = append(matches, model.PolicyConditionMatch{
			Key:      strings.TrimSpace(condition.Key),
			Operator: strings.ToLower(strings.TrimSpace(condition.Operator)),
			Expected: expected,
			Actual:   actual,
		})
	}

	return matches, true, nil
}

func policyConditionMatches(operator string, actual any, exists bool, expected any) (bool, error) {
	switch operator {
	case "exists":
		want := true
		if expected != nil {
			value, ok := expected.(bool)
			if !ok {
				return false, fmt.Errorf("exists operator expects boolean value")
			}
			want = value
		}
		return exists == want, nil
	case "eq":
		return compareEqual(actual, expected), nil
	case "neq":
		return !compareEqual(actual, expected), nil
	case "gt", "gte", "lt", "lte":
		actualNumber, ok := toFloat(actual)
		if !ok {
			return false, nil
		}
		expectedNumber, ok := toFloat(expected)
		if !ok {
			return false, fmt.Errorf("%s operator expects numeric value", operator)
		}

		switch operator {
		case "gt":
			return actualNumber > expectedNumber, nil
		case "gte":
			return actualNumber >= expectedNumber, nil
		case "lt":
			return actualNumber < expectedNumber, nil
		case "lte":
			return actualNumber <= expectedNumber, nil
		}
	case "in", "not_in":
		items, ok := expected.([]any)
		if !ok {
			return false, fmt.Errorf("%s operator expects array value", operator)
		}

		found := false
		for _, item := range items {
			if compareEqual(actual, item) {
				found = true
				break
			}
		}

		if operator == "in" {
			return found, nil
		}
		return !found, nil
	case "contains":
		return containsValue(actual, expected), nil
	case "matches":
		actualString, ok := actual.(string)
		if !ok {
			return false, nil
		}
		expectedString, ok := expected.(string)
		if !ok {
			return false, fmt.Errorf("matches operator expects string value")
		}

		if matched, err := path.Match(expectedString, actualString); err == nil {
			return matched, nil
		}

		return regexp.MatchString(expectedString, actualString)
	}

	return false, fmt.Errorf("unsupported operator %q", operator)
}

func lookupPath(input map[string]any, dotted string) (any, bool) {
	current := any(input)
	for _, segment := range strings.Split(strings.TrimSpace(dotted), ".") {
		if segment == "" {
			return nil, false
		}

		switch typed := current.(type) {
		case map[string]any:
			value, ok := typed[segment]
			if !ok {
				return nil, false
			}
			current = value
		case []any:
			index, err := strconv.Atoi(segment)
			if err != nil || index < 0 || index >= len(typed) {
				return nil, false
			}
			current = typed[index]
		default:
			return nil, false
		}
	}

	return current, true
}

func resolvePolicyValue(input map[string]any, value any) any {
	ref, ok := value.(map[string]any)
	if !ok {
		return value
	}

	rawRef, ok := ref["$ref"]
	if !ok {
		return value
	}

	refPath, ok := rawRef.(string)
	if !ok {
		return value
	}

	resolved, found := lookupPath(input, refPath)
	if !found {
		return nil
	}
	return resolved
}

func compareEqual(left, right any) bool {
	if leftNumber, ok := toFloat(left); ok {
		if rightNumber, ok := toFloat(right); ok {
			return leftNumber == rightNumber
		}
	}

	return reflect.DeepEqual(left, right)
}

func containsValue(actual, expected any) bool {
	switch typed := actual.(type) {
	case string:
		expectedString, ok := expected.(string)
		if !ok {
			return false
		}
		return strings.Contains(typed, expectedString)
	case []any:
		for _, item := range typed {
			if compareEqual(item, expected) {
				return true
			}
		}
	}

	return false
}

func toFloat(value any) (float64, bool) {
	switch typed := value.(type) {
	case float64:
		return typed, true
	case float32:
		return float64(typed), true
	case int:
		return float64(typed), true
	case int64:
		return float64(typed), true
	case int32:
		return float64(typed), true
	case int16:
		return float64(typed), true
	case int8:
		return float64(typed), true
	case uint:
		return float64(typed), true
	case uint64:
		return float64(typed), true
	case uint32:
		return float64(typed), true
	case uint16:
		return float64(typed), true
	case uint8:
		return float64(typed), true
	case json.Number:
		number, err := typed.Float64()
		if err != nil {
			return 0, false
		}
		return number, true
	default:
		return 0, false
	}
}
