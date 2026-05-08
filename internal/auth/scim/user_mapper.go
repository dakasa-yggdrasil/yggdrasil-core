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
	name := splitDisplayName(c.DisplayName)

	user := model.SCIMUser{
		Schemas: []string{
			"urn:ietf:params:scim:schemas:core:2.0:User",
			"urn:ietf:params:scim:schemas:extension:enterprise:2.0:User",
		},
		ID:         c.ID.String(),
		ExternalID: c.Slug,
		UserName:   primaryUserName(c, ai),
		Name:       name,
		Active:     strings.EqualFold(c.Status, "active") || strings.EqualFold(c.Status, "on_leave"),
		Emails: []model.SCIMEmail{{
			Value:   c.PrimaryEmail,
			Type:    "work",
			Primary: true,
		}},
		Meta: model.SCIMResourceMeta{
			ResourceType: "User",
			Created:      c.CreatedAt,
			LastModified: maxTime(c.UpdatedAt, identityUpdatedAt(ai)),
			Version:      `W/"` + c.UpdatedAt.UTC().Format(time.RFC3339Nano) + `"`,
			Location:     "/scim/v2/Users/" + c.ID.String(),
		},
		Enterprise: &model.SCIMEnterprise{
			EmployeeNumber: c.Slug,
			Department:     teamSlug(primaryTeam),
			Manager:        managerRef(manager),
			CostCenter:     stringFromMap(c.EmploymentData, "cost_center"),
		},
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

func splitDisplayName(displayName string) model.SCIMName {
	parts := strings.Fields(strings.TrimSpace(displayName))
	out := model.SCIMName{Formatted: displayName}
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
		return v
	}
	return ""
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
