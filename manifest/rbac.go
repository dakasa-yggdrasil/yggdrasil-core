package manifest

import (
	"encoding/json"
	"fmt"
	"path"
	"slices"
	"strings"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

// ParseRBACSpec parses the raw spec payload into the typed RBAC manifest.
func ParseRBACSpec(raw json.RawMessage) (model.RBACManifestSpec, error) {
	var spec model.RBACManifestSpec
	if err := json.Unmarshal(raw, &spec); err != nil {
		return model.RBACManifestSpec{}, fmt.Errorf("parse rbac spec: %w", err)
	}
	return spec, nil
}

// ValidateRBACSpec validates the RBAC manifest semantics.
func ValidateRBACSpec(spec model.RBACManifestSpec) error {
	if len(spec.Roles) == 0 {
		return fmt.Errorf("rbac spec requires at least one role")
	}

	roleNames := map[string]struct{}{}
	for _, role := range spec.Roles {
		name := strings.TrimSpace(role.Name)
		if name == "" {
			return fmt.Errorf("rbac role name is required")
		}
		if _, exists := roleNames[name]; exists {
			return fmt.Errorf("rbac role %q is duplicated", name)
		}
		roleNames[name] = struct{}{}

		if len(role.Rules) == 0 {
			return fmt.Errorf("rbac role %q requires at least one rule", name)
		}

		for _, rule := range role.Rules {
			if err := validateRBACRule(rule); err != nil {
				return fmt.Errorf("rbac role %q: %w", name, err)
			}
		}
	}

	for _, binding := range spec.Bindings {
		if strings.TrimSpace(binding.Name) == "" {
			return fmt.Errorf("rbac binding name is required")
		}
		if len(binding.Subjects) == 0 {
			return fmt.Errorf("rbac binding %q requires at least one subject", binding.Name)
		}
		if len(binding.Roles) == 0 {
			return fmt.Errorf("rbac binding %q requires at least one role", binding.Name)
		}

		for _, subject := range binding.Subjects {
			if strings.TrimSpace(subject.Type) == "" || strings.TrimSpace(subject.ID) == "" {
				return fmt.Errorf("rbac binding %q contains an invalid subject", binding.Name)
			}
		}

		for _, roleName := range binding.Roles {
			if _, exists := roleNames[strings.TrimSpace(roleName)]; !exists {
				return fmt.Errorf("rbac binding %q references unknown role %q", binding.Name, roleName)
			}
		}
	}

	return nil
}

// EvaluateRBAC calculates whether a subject can execute an action on a resource.
func EvaluateRBAC(spec model.RBACManifestSpec, subject model.RBACSubject, resource, action string) (bool, []string, []model.RBACRuleMatch, error) {
	return EvaluateRBACSubjects(spec, []model.RBACSubject{subject}, resource, action)
}

// EvaluateRBACSubjects calculates whether any effective subject can execute an action on a resource.
func EvaluateRBACSubjects(spec model.RBACManifestSpec, subjects []model.RBACSubject, resource, action string) (bool, []string, []model.RBACRuleMatch, error) {
	if err := ValidateRBACSpec(spec); err != nil {
		return false, nil, nil, err
	}

	resource = strings.TrimSpace(resource)
	action = strings.TrimSpace(action)
	if resource == "" || action == "" {
		return false, nil, nil, fmt.Errorf("resource and action are required")
	}

	normalizedSubjects := make([]model.RBACSubject, 0, len(subjects))
	for _, subject := range subjects {
		subject = normalizeSubject(subject)
		if subject.Type == "" || subject.ID == "" {
			continue
		}
		if slices.Contains(normalizedSubjects, subject) {
			continue
		}
		normalizedSubjects = append(normalizedSubjects, subject)
	}
	if len(normalizedSubjects) == 0 {
		return false, nil, nil, fmt.Errorf("at least one valid subject is required")
	}

	roleIndex := map[string]model.RBACRole{}
	for _, role := range spec.Roles {
		roleIndex[strings.TrimSpace(role.Name)] = role
	}

	var (
		matchedRoles []string
		matchedRules []model.RBACRuleMatch
		allowMatch   bool
		denyMatch    bool
	)

	ruleMatchSet := map[string]struct{}{}

	for _, subject := range normalizedSubjects {
		for _, binding := range spec.Bindings {
			if !bindingMatchesSubject(binding, subject) {
				continue
			}

			for _, roleName := range binding.Roles {
				roleName = strings.TrimSpace(roleName)
				role := roleIndex[roleName]
				if !slices.Contains(matchedRoles, roleName) {
					matchedRoles = append(matchedRoles, roleName)
				}

				for _, rule := range role.Rules {
					if !ruleMatches(rule, resource, action) {
						continue
					}

					effect := normalizeEffect(rule.Effect)
					match := model.RBACRuleMatch{
						Role:        roleName,
						Effect:      effect,
						Description: strings.TrimSpace(rule.Description),
						Resources:   append([]string(nil), rule.Resources...),
						Actions:     append([]string(nil), rule.Actions...),
					}
					matchKey := rbacRuleMatchKey(match)
					if _, exists := ruleMatchSet[matchKey]; !exists {
						matchedRules = append(matchedRules, match)
						ruleMatchSet[matchKey] = struct{}{}
					}

					if effect == "deny" {
						denyMatch = true
					}
					if effect == "allow" {
						allowMatch = true
					}
				}
			}
		}
	}

	if denyMatch {
		return false, matchedRoles, matchedRules, nil
	}
	if allowMatch {
		return true, matchedRoles, matchedRules, nil
	}

	return false, matchedRoles, matchedRules, nil
}

func validateRBACRule(rule model.RBACRule) error {
	effect := normalizeEffect(rule.Effect)
	if effect != "allow" && effect != "deny" {
		return fmt.Errorf("invalid effect %q", rule.Effect)
	}
	if len(rule.Resources) == 0 {
		return fmt.Errorf("rule requires at least one resource pattern")
	}
	if len(rule.Actions) == 0 {
		return fmt.Errorf("rule requires at least one action pattern")
	}

	for _, resource := range rule.Resources {
		if strings.TrimSpace(resource) == "" {
			return fmt.Errorf("rule contains an empty resource pattern")
		}
	}
	for _, action := range rule.Actions {
		if strings.TrimSpace(action) == "" {
			return fmt.Errorf("rule contains an empty action pattern")
		}
	}

	return nil
}

func bindingMatchesSubject(binding model.RBACBinding, subject model.RBACSubject) bool {
	for _, candidate := range binding.Subjects {
		candidate = normalizeSubject(candidate)
		if subjectPatternMatches(candidate.Type, subject.Type) && subjectPatternMatches(candidate.ID, subject.ID) {
			return true
		}
	}
	return false
}

func ruleMatches(rule model.RBACRule, resource, action string) bool {
	return anyPatternMatch(rule.Resources, resource) && anyPatternMatch(rule.Actions, action)
}

func anyPatternMatch(patterns []string, value string) bool {
	for _, pattern := range patterns {
		pattern = strings.TrimSpace(pattern)
		if pattern == "" {
			continue
		}

		matched, err := path.Match(pattern, value)
		if err == nil && matched {
			return true
		}

		if strings.EqualFold(pattern, value) {
			return true
		}
	}
	return false
}

func subjectPatternMatches(pattern, value string) bool {
	if pattern == "*" {
		return true
	}
	return anyPatternMatch([]string{pattern}, value)
}

func normalizeEffect(effect string) string {
	effect = strings.ToLower(strings.TrimSpace(effect))
	if effect == "" {
		return "allow"
	}
	return effect
}

func normalizeSubject(subject model.RBACSubject) model.RBACSubject {
	subject.Type = strings.ToLower(strings.TrimSpace(subject.Type))
	subject.ID = strings.TrimSpace(subject.ID)
	return subject
}

func rbacRuleMatchKey(match model.RBACRuleMatch) string {
	return strings.Join([]string{
		match.Role,
		match.Effect,
		match.Description,
		strings.Join(match.Resources, ","),
		strings.Join(match.Actions, ","),
	}, "|")
}
