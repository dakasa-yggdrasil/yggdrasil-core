package scim

import (
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

// MapTeamToSCIMGroup projects a Team + member list into a SCIM 2.0 Group.
func MapTeamToSCIMGroup(t model.Team, members []model.Collaborator) model.SCIMGroup {
	g := model.SCIMGroup{
		Schemas:     []string{"urn:ietf:params:scim:schemas:core:2.0:Group"},
		ID:          t.ID.String(),
		ExternalID:  "team:" + t.Slug,
		DisplayName: t.Name,
		Members:     make([]model.SCIMGroupMember, 0, len(members)),
		Meta: model.SCIMResourceMeta{
			ResourceType: "Group",
			Created:      t.CreatedAt,
			LastModified: t.UpdatedAt,
			Version:      `W/"` + t.UpdatedAt.UTC().Format(time.RFC3339Nano) + `"`,
			Location:     "/scim/v2/Groups/" + t.ID.String(),
		},
	}
	for _, m := range members {
		g.Members = append(g.Members, model.SCIMGroupMember{
			Value:   m.ID.String(),
			Display: m.DisplayName,
			Type:    "User",
			Ref:     "/scim/v2/Users/" + m.ID.String(),
		})
	}
	return g
}

// SyntheticRoleGroup builds a `role:<role>` virtual group from collaborators
// sharing the same primary role. ID is a stable v5 UUID equivalent (we hex-encode
// the role name) so downstream SPs can keep stable references.
func SyntheticRoleGroup(roleName string, members []model.Collaborator, modified time.Time) model.SCIMGroup {
	id := "role-" + roleName
	g := model.SCIMGroup{
		Schemas:     []string{"urn:ietf:params:scim:schemas:core:2.0:Group"},
		ID:          id,
		ExternalID:  "role:" + roleName,
		DisplayName: "Role: " + roleName,
		Members:     make([]model.SCIMGroupMember, 0, len(members)),
		Meta: model.SCIMResourceMeta{
			ResourceType: "Group",
			LastModified: modified,
			Version:      `W/"` + modified.UTC().Format(time.RFC3339Nano) + `"`,
			Location:     "/scim/v2/Groups/" + id,
		},
	}
	for _, m := range members {
		g.Members = append(g.Members, model.SCIMGroupMember{
			Value:   m.ID.String(),
			Display: m.DisplayName,
			Type:    "User",
			Ref:     "/scim/v2/Users/" + m.ID.String(),
		})
	}
	return g
}
