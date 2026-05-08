package scim

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
)

// teamMembers resolves a team's collaborator records via team_memberships.
// Errors are swallowed to keep the SCIM list response best-effort consistent.
func teamMembers(ctx context.Context, db *sql.DB, teamID string) []model.Collaborator {
	memberships, err := repository.ListTeamMemberships(ctx, db, model.ListTeamMembershipsRequest{TeamID: teamID, ActiveOnly: true})
	if err != nil {
		return nil
	}
	out := make([]model.Collaborator, 0, len(memberships))
	for _, m := range memberships {
		c, err := repository.GetCollaborator(ctx, db, m.CollaboratorID.String())
		if err == nil {
			out = append(out, c)
		}
	}
	return out
}

// Server hosts the read-only SCIM 2.0 endpoints. Mount at `/scim/v2/` after
// wrapping with BearerAuth + ReadOnlyGuard. The server only implements GET
// because Yggdrasil is source of truth.
type Server struct {
	DB *sql.DB
}

// NewServer returns a Server configured against the given DB.
func NewServer(db *sql.DB) *Server { return &Server{DB: db} }

// RegisterRoutes mounts /scim/v2/Users, /scim/v2/Groups, and metadata endpoints.
func (s *Server) RegisterRoutes(mux *http.ServeMux) {
	mux.Handle("GET /scim/v2/Users", http.HandlerFunc(s.handleListUsers))
	mux.Handle("GET /scim/v2/Users/{id}", http.HandlerFunc(s.handleGetUser))
	mux.Handle("GET /scim/v2/Groups", http.HandlerFunc(s.handleListGroups))
	mux.Handle("GET /scim/v2/Groups/{id}", http.HandlerFunc(s.handleGetGroup))
	mux.Handle("GET /scim/v2/Schemas", http.HandlerFunc(s.handleSchemas))
	mux.Handle("GET /scim/v2/ServiceProviderConfig", http.HandlerFunc(s.handleServiceProviderConfig))
	mux.Handle("GET /scim/v2/ResourceTypes", http.HandlerFunc(s.handleResourceTypes))
}

func (s *Server) handleListUsers(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	filter, err := ParseFilter(q.Get("filter"))
	if err != nil {
		writeSCIMError(w, http.StatusBadRequest, "invalidFilter", err.Error())
		return
	}
	startIndex := parsePagination(q.Get("startIndex"), 1)
	count := parsePagination(q.Get("count"), 100)
	if count > 200 {
		count = 200
	}

	collabs, err := repository.ListCollaborators(r.Context(), s.DB, model.ListCollaboratorsRequest{})
	if err != nil {
		writeSCIMError(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	matched := filterCollaborators(collabs, filter)

	// Pagination after filtering
	total := len(matched)
	from := startIndex - 1
	if from < 0 {
		from = 0
	}
	if from > total {
		from = total
	}
	to := from + count
	if to > total {
		to = total
	}

	resources := make([]any, 0, to-from)
	for _, c := range matched[from:to] {
		ai, _ := repository.GetAuthIdentityByCollaboratorID(r.Context(), s.DB, c.ID)
		resources = append(resources, MapCollaboratorToSCIMUser(c, &ai, nil, nil))
	}

	writeSCIMJSON(w, http.StatusOK, model.SCIMListResponse{
		Schemas:      []string{"urn:ietf:params:scim:api:messages:2.0:ListResponse"},
		TotalResults: total,
		StartIndex:   startIndex,
		ItemsPerPage: len(resources),
		Resources:    resources,
	})
}

func (s *Server) handleGetUser(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	c, err := repository.GetCollaborator(r.Context(), s.DB, id)
	if err != nil {
		writeSCIMError(w, http.StatusNotFound, "notFound", "user "+id+" not found")
		return
	}
	ai, _ := repository.GetAuthIdentityByCollaboratorID(r.Context(), s.DB, c.ID)
	writeSCIMJSON(w, http.StatusOK, MapCollaboratorToSCIMUser(c, &ai, nil, nil))
}

func (s *Server) handleListGroups(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	filter, err := ParseFilter(q.Get("filter"))
	if err != nil {
		writeSCIMError(w, http.StatusBadRequest, "invalidFilter", err.Error())
		return
	}

	teams, err := repository.ListTeams(r.Context(), s.DB, model.ListTeamsRequest{})
	if err != nil {
		writeSCIMError(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}

	resources := make([]any, 0, len(teams))
	for _, t := range teams {
		if !matchGroup(t, filter) {
			continue
		}
		members := teamMembers(r.Context(), s.DB, t.ID.String())
		resources = append(resources, MapTeamToSCIMGroup(t, members))
	}
	writeSCIMJSON(w, http.StatusOK, model.SCIMListResponse{
		Schemas:      []string{"urn:ietf:params:scim:api:messages:2.0:ListResponse"},
		TotalResults: len(resources),
		StartIndex:   1,
		ItemsPerPage: len(resources),
		Resources:    resources,
	})
}

func (s *Server) handleGetGroup(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	t, err := repository.GetTeam(r.Context(), s.DB, id)
	if err != nil {
		writeSCIMError(w, http.StatusNotFound, "notFound", "group "+id+" not found")
		return
	}
	members := teamMembers(r.Context(), s.DB, t.ID.String())
	writeSCIMJSON(w, http.StatusOK, MapTeamToSCIMGroup(t, members))
}

func (s *Server) handleSchemas(w http.ResponseWriter, r *http.Request) {
	writeSCIMJSON(w, http.StatusOK, map[string]any{
		"schemas": []string{"urn:ietf:params:scim:api:messages:2.0:ListResponse"},
		"totalResults": 3,
		"Resources": []map[string]any{
			{"id": "urn:ietf:params:scim:schemas:core:2.0:User", "name": "User"},
			{"id": "urn:ietf:params:scim:schemas:core:2.0:Group", "name": "Group"},
			{"id": "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User", "name": "EnterpriseUser"},
		},
	})
}

func (s *Server) handleServiceProviderConfig(w http.ResponseWriter, r *http.Request) {
	writeSCIMJSON(w, http.StatusOK, map[string]any{
		"schemas":          []string{"urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"},
		"documentationUri": "https://docs.dakasa.me/yggdrasil/auth/scim",
		"patch":            map[string]bool{"supported": false},
		"bulk":             map[string]any{"supported": false, "maxOperations": 0, "maxPayloadSize": 0},
		"filter":           map[string]any{"supported": true, "maxResults": 200},
		"changePassword":   map[string]bool{"supported": false},
		"sort":             map[string]bool{"supported": false},
		"etag":             map[string]bool{"supported": true},
		"authenticationSchemes": []map[string]any{
			{"type": "oauthbearertoken", "name": "OAuth Bearer Token", "primary": true},
		},
	})
}

func (s *Server) handleResourceTypes(w http.ResponseWriter, r *http.Request) {
	writeSCIMJSON(w, http.StatusOK, map[string]any{
		"schemas":      []string{"urn:ietf:params:scim:api:messages:2.0:ListResponse"},
		"totalResults": 2,
		"Resources": []map[string]any{
			{"id": "User", "name": "User", "endpoint": "/Users", "schema": "urn:ietf:params:scim:schemas:core:2.0:User"},
			{"id": "Group", "name": "Group", "endpoint": "/Groups", "schema": "urn:ietf:params:scim:schemas:core:2.0:Group"},
		},
	})
}

func writeSCIMJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/scim+json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func writeSCIMError(w http.ResponseWriter, status int, scimType, detail string) {
	writeSCIMJSON(w, status, map[string]any{
		"schemas":  []string{"urn:ietf:params:scim:api:messages:2.0:Error"},
		"status":   strconv.Itoa(status),
		"scimType": scimType,
		"detail":   detail,
	})
}

func parsePagination(raw string, def int) int {
	if raw == "" {
		return def
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n <= 0 {
		return def
	}
	return n
}

func filterCollaborators(in []model.Collaborator, f *Filter) []model.Collaborator {
	if f == nil {
		return in
	}
	out := make([]model.Collaborator, 0, len(in))
	for _, c := range in {
		if matchUser(c, f) {
			out = append(out, c)
		}
	}
	return out
}

func matchUser(c model.Collaborator, f *Filter) bool {
	if f == nil {
		return true
	}
	leftMatch := matchOne(getCollaboratorAttr(c, f.Attribute), f)
	if !leftMatch {
		return false
	}
	if f.And == nil {
		return true
	}
	return matchOne(getCollaboratorAttr(c, f.And.Attribute), f.And)
}

func matchGroup(t model.Team, f *Filter) bool {
	if f == nil {
		return true
	}
	switch f.Attribute {
	case "displayname":
		return matchOne(t.Name, f)
	case "externalid":
		return matchOne("team:"+t.Slug, f)
	default:
		return false
	}
}

func getCollaboratorAttr(c model.Collaborator, name string) string {
	switch name {
	case "username":
		if c.PrimaryEmail != "" {
			return strings.ToLower(c.PrimaryEmail)
		}
		return c.Slug
	case "externalid":
		return c.Slug
	case "emails":
		return c.PrimaryEmail
	case "displayname":
		return c.DisplayName
	case "active":
		if strings.EqualFold(c.Status, "active") || strings.EqualFold(c.Status, "on_leave") {
			return "true"
		}
		return "false"
	}
	return ""
}

func matchOne(haystack string, f *Filter) bool {
	switch f.Operator {
	case "eq":
		return strings.EqualFold(haystack, f.Value)
	case "ne":
		return !strings.EqualFold(haystack, f.Value)
	case "co":
		return strings.Contains(strings.ToLower(haystack), strings.ToLower(f.Value))
	case "sw":
		return strings.HasPrefix(strings.ToLower(haystack), strings.ToLower(f.Value))
	case "ew":
		return strings.HasSuffix(strings.ToLower(haystack), strings.ToLower(f.Value))
	case "pr":
		return strings.TrimSpace(haystack) != ""
	}
	return false
}
