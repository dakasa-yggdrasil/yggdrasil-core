package scim

import (
	"strings"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

// MapCollaboratorToSCIMUser projects a Collaborator + AuthIdentity into the
// SCIM 2.0 User schema (with the enterprise extension). The version field is
// derived from updated_at to give downstream SPs a monotonic etag-like value.
func MapCollaboratorToSCIMUser(c model.Collaborator, ai *model.AuthIdentity, primaryTeam *model.Team, manager *model.Collaborator) model.SCIMUser {
	displayName := collaboratorDisplayName(c)
	name := collaboratorSCIMName(c, displayName)
	title := firstMapString(c.EmploymentData, "title", "role")

	user := model.SCIMUser{
		Schemas: []string{
			"urn:ietf:params:scim:schemas:core:2.0:User",
			"urn:ietf:params:scim:schemas:extension:enterprise:2.0:User",
		},
		ID:          c.ID.String(),
		ExternalID:  c.Slug,
		UserName:    primaryUserName(c, ai),
		Name:        name,
		DisplayName: displayName,
		Title:       title,
		UserType:    stringFromMap(c.EmploymentData, "role"),
		Active:      strings.EqualFold(c.Status, "active") || strings.EqualFold(c.Status, "on_leave"),
		Emails: []model.SCIMEmail{{
			Value:   c.PrimaryEmail,
			Type:    "work",
			Primary: true,
		}},
		Photos: scimPhotos(c),
		Meta: model.SCIMResourceMeta{
			ResourceType: "User",
			Created:      c.CreatedAt,
			LastModified: maxTime(c.UpdatedAt, identityUpdatedAt(ai)),
			Version:      `W/"` + c.UpdatedAt.UTC().Format(time.RFC3339Nano) + `"`,
			Location:     "/scim/v2/Users/" + c.ID.String(),
		},
		Enterprise: &model.SCIMEnterprise{
			EmployeeNumber: firstMapString(c.EmploymentData, "employee_number", "employee_id", "directory_id", "id"),
			Department:     firstNonEmptyMapString(c.EmploymentData, teamSlug(primaryTeam), "department"),
			Manager:        managerRef(manager),
			CostCenter:     stringFromMap(c.EmploymentData, "cost_center"),
			Organization:   stringFromMap(c.EmploymentData, "organization"),
			Division:       stringFromMap(c.EmploymentData, "division"),
		},
	}
	if user.Enterprise.EmployeeNumber == "" {
		user.Enterprise.EmployeeNumber = c.Slug
	}
	return user
}

func primaryUserName(c model.Collaborator, ai *model.AuthIdentity) string {
	if ai != nil && ai.Username != "" {
		return ai.Username
	}
	if c.PrimaryEmail != "" {
		return strings.ToLower(c.PrimaryEmail)
	}
	return c.Slug
}

func collaboratorDisplayName(c model.Collaborator) string {
	if preferred := strings.TrimSpace(stringFromMap(c.PersonalData, "preferred_name")); preferred != "" {
		return preferred
	}
	profile := nestedMap(c.PersonalData, "profile")
	if preferred := strings.TrimSpace(stringFromMap(profile, "preferred_name")); preferred != "" {
		return preferred
	}
	if full := strings.TrimSpace(stringFromMap(profile, "full_name")); full != "" {
		return full
	}
	if displayName := strings.TrimSpace(c.DisplayName); displayName != "" {
		return displayName
	}
	return strings.TrimSpace(strings.Join([]string{
		firstMapString(c.PersonalData, "given_name", "first_name"),
		firstMapString(c.PersonalData, "family_name", "last_name"),
	}, " "))
}

func collaboratorSCIMName(c model.Collaborator, displayName string) model.SCIMName {
	profile := nestedMap(c.PersonalData, "profile")
	givenName := firstNonEmpty(
		firstMapString(profile, "given_name", "first_name"),
		firstMapString(c.PersonalData, "given_name", "first_name"),
	)
	familyName := firstNonEmpty(
		firstMapString(profile, "family_name", "last_name"),
		firstMapString(c.PersonalData, "family_name", "last_name"),
	)
	name := splitDisplayName(displayName)
	if name.GivenName == "" {
		name.GivenName = givenName
	}
	if name.FamilyName == "" {
		name.FamilyName = familyName
	}
	if name.Formatted == "" {
		name.Formatted = strings.TrimSpace(strings.Join([]string{name.GivenName, name.FamilyName}, " "))
	}
	return name
}

func splitDisplayName(displayName string) model.SCIMName {
	parts := strings.Fields(strings.TrimSpace(displayName))
	out := model.SCIMName{Formatted: strings.TrimSpace(displayName)}
	if len(parts) == 0 {
		return out
	}
	out.GivenName = parts[0]
	if len(parts) > 1 {
		out.FamilyName = strings.Join(parts[1:], " ")
	}
	return out
}

func teamSlug(t *model.Team) string {
	if t == nil {
		return ""
	}
	return t.Slug
}

func managerRef(m *model.Collaborator) *model.SCIMRef {
	if m == nil {
		return nil
	}
	return &model.SCIMRef{
		Value:       m.ID.String(),
		Ref:         "/scim/v2/Users/" + m.ID.String(),
		DisplayName: m.DisplayName,
	}
}

func stringFromMap(m map[string]any, key string) string {
	if m == nil {
		return ""
	}
	if v, ok := m[key].(string); ok {
		return strings.TrimSpace(v)
	}
	return ""
}

func nestedMap(m map[string]any, key string) map[string]any {
	if m == nil {
		return nil
	}
	if v, ok := m[key].(map[string]any); ok {
		return v
	}
	return nil
}

func firstMapString(m map[string]any, keys ...string) string {
	for _, key := range keys {
		if value := stringFromMap(m, key); value != "" {
			return value
		}
	}
	return ""
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
}

func firstNonEmptyMapString(m map[string]any, fallback string, keys ...string) string {
	if value := firstMapString(m, keys...); value != "" {
		return value
	}
	return strings.TrimSpace(fallback)
}

func scimPhotos(c model.Collaborator) []model.SCIMPhoto {
	profile := nestedMap(c.PersonalData, "profile")
	value := firstNonEmpty(
		stringFromMap(profile, "avatar_url"),
		stringFromMap(c.PersonalData, "avatar_url"),
		stringFromMap(profile, "avatar_data_url"),
		stringFromMap(c.PersonalData, "avatar_data_url"),
	)
	if value == "" {
		return nil
	}
	return []model.SCIMPhoto{{Value: value, Type: "photo", Primary: true}}
}

func identityUpdatedAt(ai *model.AuthIdentity) time.Time {
	if ai == nil {
		return time.Time{}
	}
	return ai.UpdatedAt
}

func maxTime(a, b time.Time) time.Time {
	if b.After(a) {
		return b
	}
	return a
}
