package manifest

import (
	"fmt"
	"strings"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

// EvaluateAuthorization evaluates RBAC first, then refines the decision with an optional policy manifest.
func EvaluateAuthorization(
	rbacSpec model.RBACManifestSpec,
	policySpec *model.PolicyManifestSpec,
	subject model.RBACSubject,
	resource, action string,
	input map[string]any,
) (model.EvaluateAuthorizationResponse, error) {
	return EvaluateAuthorizationSubjects(rbacSpec, policySpec, []model.RBACSubject{subject}, resource, action, input)
}

// EvaluateAuthorizationSubjects evaluates RBAC against all effective subjects before applying optional policy conditions.
func EvaluateAuthorizationSubjects(
	rbacSpec model.RBACManifestSpec,
	policySpec *model.PolicyManifestSpec,
	subjects []model.RBACSubject,
	resource, action string,
	input map[string]any,
) (model.EvaluateAuthorizationResponse, error) {
	rbacAllowed, roles, rbacMatches, err := EvaluateRBACSubjects(rbacSpec, subjects, resource, action)
	if err != nil {
		return model.EvaluateAuthorizationResponse{}, err
	}

	response := model.EvaluateAuthorizationResponse{
		Decision:         "deny",
		ResolvedSubjects: normalizeAuthorizationSubjects(subjects),
		RBAC: model.EvaluateRBACResponse{
			Allowed:      rbacAllowed,
			Decision:     authorizationRBACDecision(rbacAllowed),
			MatchedRoles: roles,
			MatchedRules: rbacMatches,
		},
	}

	if !rbacAllowed {
		return response, nil
	}

	response.Allowed = true
	response.Decision = "allow"

	if policySpec == nil {
		return response, nil
	}

	policyAllowed, policyDecision, policyMatches, err := EvaluatePolicy(
		*policySpec,
		resource,
		action,
		authorizationPolicyInput(response.ResolvedSubjects, input),
	)
	if err != nil {
		return model.EvaluateAuthorizationResponse{}, err
	}

	response.Policy = &model.EvaluatePolicyResponse{
		Allowed:      policyAllowed,
		Decision:     policyDecision,
		MatchedRules: policyMatches,
	}

	switch policyDecision {
	case "allow", "not_applicable":
		return response, nil
	case "deny":
		response.Allowed = false
		response.Decision = "deny"
		return response, nil
	default:
		return model.EvaluateAuthorizationResponse{}, fmt.Errorf("unsupported policy decision %q", policyDecision)
	}
}

func authorizationRBACDecision(allowed bool) string {
	if allowed {
		return "allow"
	}
	return "deny"
}

func authorizationPolicyInput(subjects []model.RBACSubject, input map[string]any) map[string]any {
	if input == nil {
		input = map[string]any{}
	}

	normalized := make(map[string]any, len(input)+2)
	rawInput := make(map[string]any, len(input))
	for key, value := range input {
		normalized[key] = value
		rawInput[key] = value
	}
	// Policy manifests describe runtime values under input.*. Preserve the
	// historical flat keys while also exposing that canonical namespace.
	if _, exists := normalized["input"]; !exists {
		normalized["input"] = rawInput
	}

	var subjectData map[string]any
	if len(subjects) > 0 {
		subjectData = map[string]any{
			"type": strings.TrimSpace(subjects[0].Type),
			"id":   strings.TrimSpace(subjects[0].ID),
		}
	}

	if _, exists := normalized["subjects"]; !exists {
		normalized["subjects"] = authorizationSubjectsToInput(subjects)
	}

	existing, exists := normalized["subject"]
	if subjectData == nil {
		return normalized
	}
	if !exists || existing == nil {
		normalized["subject"] = subjectData
		return normalized
	}

	subjectMap, ok := existing.(map[string]any)
	if !ok {
		return normalized
	}

	if _, hasType := subjectMap["type"]; !hasType && subjectData["type"] != "" {
		subjectMap["type"] = subjectData["type"]
	}
	if _, hasID := subjectMap["id"]; !hasID && subjectData["id"] != "" {
		subjectMap["id"] = subjectData["id"]
	}

	return normalized
}

func normalizeAuthorizationSubjects(subjects []model.RBACSubject) []model.RBACSubject {
	normalized := make([]model.RBACSubject, 0, len(subjects))
	for _, subject := range subjects {
		subject.Type = strings.ToLower(strings.TrimSpace(subject.Type))
		subject.ID = strings.TrimSpace(subject.ID)
		if subject.Type == "" || subject.ID == "" {
			continue
		}
		if containsAuthorizationSubject(normalized, subject) {
			continue
		}
		normalized = append(normalized, subject)
	}
	return normalized
}

func authorizationSubjectsToInput(subjects []model.RBACSubject) []map[string]any {
	items := make([]map[string]any, 0, len(subjects))
	for _, subject := range subjects {
		items = append(items, map[string]any{
			"type": subject.Type,
			"id":   subject.ID,
		})
	}
	return items
}

func containsAuthorizationSubject(subjects []model.RBACSubject, candidate model.RBACSubject) bool {
	for _, subject := range subjects {
		if subject.Type == candidate.Type && subject.ID == candidate.ID {
			return true
		}
	}
	return false
}
