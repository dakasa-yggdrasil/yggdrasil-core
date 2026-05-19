# Tartaro Team Permissions Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace per-user `traits.tartaro_roles` RBAC with team-scoped action-level grants materialized into `traits.tartaro_actions` via the team reactor framework.

**Architecture:** New canon events `team_grant.added/revoked` (yggdrasil-core) flow through the existing reactor machinery to integration-tartaro-dakasa, which recomputes the UNION of grants from all the user's active teams and PUTs `traits.tartaro_actions`. Tartaro-api's `authz.Evaluate` reads that trait directly. Big-bang migration creates `tartaro-legacy-<role>` teams + grants per existing role.

**Tech Stack:** Go 1.25 (yggdrasil-core, integration-tartaro-dakasa, dakasa-tartaro-api), PostgreSQL goose migrations, AMQP RPC, vendored `dakasa-commons` (security helpers shared across tartaro services).

**Spec:** `docs/superpowers/specs/2026-05-18-tartaro-team-permissions-design.md`

**Conventions:**
- Push direct to main per DaKasa convention
- Cluster mutations via Yggdrasil workflows (memory: `feedback_yggdrasil_only`)
- Image deploy via `update_container_image` capability bump workflow (item #2 playbook)
- Each phase commits as it goes; per-phase push at end of phase, NOT per task

---

## File inventory

### yggdrasil-core
- `repository/event_types_lifecycle.go` — add 2 constants + set entries
- `repository/event_types_lifecycle_test.go` — assertions
- `controllers/httpapi/server.go` — modify team_grant handlers to emit events + register 2 new routes
- `controllers/httpapi/tartaro_actions.go` — new file (2 endpoints) + `_test.go`
- `scripts/migrate_tartaro_roles_to_actions/main.go` — new
- `scripts/migrate_tartaro_roles_to_actions/main_test.go` — new

### integration-tartaro-dakasa
- `internal/yggdrasilclient/client.go` — 3 new methods
- `internal/capabilities/effective_actions.go` — new (Recompute*)
- `internal/capabilities/effective_actions_test.go` — new
- `internal/capabilities/dispatch.go` — 4 new cases
- `internal/config/instance.go` — expose namespace+name (or whatever holds tartaroInstanceRef today)
- `integration.yaml` — 4 new reactors + 4 capability descs + deprecate 2 old
- `example.json` — 4 new examples

### dakasa-commons (`dakasa-system/dakasa-commons`)
- `security/yggdrasil.go` — add `YggdrasilHasAction(collab, action)` alongside existing `YggdrasilHasRole`
- `security/yggdrasil_test.go` — unit test

### dakasa-tartaro-api
- `backend/dakasa-tartaro-api/internal/authz/client.go` — Evaluate rewrite
- `backend/dakasa-tartaro-api/internal/authz/client_test.go` — covers new reads
- `backend/dakasa-tartaro-api/`, `tartaro-{review,legal,operations}/` — sweep call sites (grep-driven; magnitude in plan)
- `backend/tartaro-operations/internal/handlers/role_actions.go` — new (+ test)
- `backend/tartaro-operations/cmd/server/main.go` (or wherever routes register) — wire endpoint
- Re-vendor `dakasa-commons` after `security/yggdrasil.go` change

---

## Phase 0: Foundation (tartaro-operations endpoint + dakasa-commons helper)

### Task 1: `tartaro-operations` role catalog → actions endpoint

**Repo**: `/Users/dakasa/projects/dakasa/dakasa-tartaro-fe/backend/tartaro-operations`

**Files:**
- Create: `internal/handlers/role_actions.go`
- Create: `internal/handlers/role_actions_test.go`
- Modify: route registration file (find via grep `RouterGroup\|engine.GET.*roles`)

> First locate the role catalog source: `grep -rn "roleCatalog\|role_catalog\|listRoles\|ActionsForRole" internal/`. Tartaro-operations already serves `GET /internal/admin/roles` returning the canonical list — find where the `roles` slice is defined.

- [ ] **Step 1: Locate role catalog source**

```bash
cd /Users/dakasa/projects/dakasa/dakasa-tartaro-fe/backend/tartaro-operations
grep -rn "listRoles\|ListRoles\|/internal/admin/roles" --include="*.go" | head -5
```

Expected: at least one handler that serves the GET and one source of role data (config map, DB query, or constants).

- [ ] **Step 2: Read the existing handler to confirm the role data shape**

Look at how role slugs map to action sets today. There may be a `roles.yaml` config, a `rolePermissions` map in Go, or it may be implicit (only slugs known, actions resolved elsewhere).

If actions-per-role isn't stored locally, the role catalog is purely a slug list. In that case, **action mapping lives elsewhere** (likely tartaro-api's authz definitions). Update the plan: this task adds the mapping in tartaro-operations as the authoritative source. Document the role→action mapping inline (in code) for V1.

- [ ] **Step 3: Write the failing test**

```go
// internal/handlers/role_actions_test.go
package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestGetRoleActionsReturnsActionsForKnownRole(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h := &Handler{ /* whatever deps Handler needs — match existing handler init */ }

	r := gin.New()
	r.GET("/internal/admin/roles/:slug/actions", h.GetRoleActions)

	req := httptest.NewRequest(http.MethodGet, "/internal/admin/roles/moderator/actions", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d (body=%s)", w.Code, w.Body.String())
	}
	var resp struct {
		Role    string   `json:"role"`
		Actions []string `json:"actions"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Role != "moderator" {
		t.Fatalf("role mismatch: %s", resp.Role)
	}
	if len(resp.Actions) == 0 {
		t.Fatal("expected non-empty action list for moderator")
	}
}

func TestGetRoleActionsReturns404ForUnknownRole(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h := &Handler{}

	r := gin.New()
	r.GET("/internal/admin/roles/:slug/actions", h.GetRoleActions)

	req := httptest.NewRequest(http.MethodGet, "/internal/admin/roles/does-not-exist/actions", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", w.Code)
	}
}
```

- [ ] **Step 4: Run to verify FAIL**

```bash
go test ./internal/handlers/ -run TestGetRoleActions -v -count=1
```

Expected: FAIL with `undefined: GetRoleActions` or build error.

- [ ] **Step 5: Write the handler**

```go
// internal/handlers/role_actions.go
package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// roleActions is the inline V1 mapping from role slug to canonical tartaro
// action set. Each action follows the convention "tartaro:<verb>_<resource>".
// Source of truth for the migration script; surface-console will read this
// via GET /internal/admin/roles/{slug}/actions.
//
// Keep this in sync with internal/authz definitions on the tartaro-api side
// until V2 unifies the catalog under a single source.
var roleActions = map[string][]string{
	"admin": {
		"tartaro:moderate_post", "tartaro:decide_report", "tartaro:manage_access_requests",
		"tartaro:manage_tickets", "tartaro:read_collaborator", "tartaro:manage_roles",
	},
	"moderator": {"tartaro:moderate_post", "tartaro:decide_report"},
	"support":   {"tartaro:manage_tickets", "tartaro:manage_access_requests"},
	"reviewer":  {"tartaro:read_collaborator"},
}

// GetRoleActions returns the canonical action set for one role slug.
// Returns 404 when the slug is not in the catalog.
func (h *Handler) GetRoleActions(c *gin.Context) {
	slug := c.Param("slug")
	actions, ok := roleActions[slug]
	if !ok {
		c.JSON(http.StatusNotFound, gin.H{"error": "role not found", "slug": slug})
		return
	}
	c.JSON(http.StatusOK, gin.H{"role": slug, "actions": actions})
}
```

> If `Handler` struct fields needed for this method differ from the test's init, copy them. If the catalog already lives elsewhere (DB, config file), replace `roleActions` with a lookup against that source. The 6 actions listed above are placeholders — replace with the real mapping discovered in Step 2.

- [ ] **Step 6: Register the route**

In the route registration file (the one identified in Step 1):

```go
adminGroup.GET("/roles/:slug/actions", h.GetRoleActions)
```

> Match the existing routing convention. The list route is `GET /internal/admin/roles` — keep `/internal/admin/roles/:slug/actions` consistent.

- [ ] **Step 7: Tests pass**

```bash
go test ./internal/handlers/ -run TestGetRoleActions -v -count=1
```

Expected: PASS (both subtests).

- [ ] **Step 8: Build**

```bash
go build ./...
```

Expected: exit 0.

- [ ] **Step 9: Commit (don't push yet — Phase 0 pushes together)**

```bash
git add internal/handlers/role_actions.go internal/handlers/role_actions_test.go <route file>
git commit -m "$(cat <<'EOF'
✨ feat(roles): GET /internal/admin/roles/:slug/actions

Returns canonical action set for a tartaro role slug. Powers the
yggdrasil migration script that maps tartaro_roles → team_grants.

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

---

### Task 2: `dakasa-commons` adds `YggdrasilHasAction` helper

**Repo**: `/Users/dakasa/projects/dakasa/dakasa-system/dakasa-commons`

**Files:**
- Modify: `security/yggdrasil.go`
- Modify: `security/yggdrasil_test.go`

- [ ] **Step 1: Write the failing test**

Add to `security/yggdrasil_test.go`:

```go
func TestYggdrasilHasAction(t *testing.T) {
	cases := []struct {
		name   string
		traits map[string]any
		action string
		want   bool
	}{
		{
			name:   "empty trait → false",
			traits: map[string]any{},
			action: "tartaro:moderate_post",
			want:   false,
		},
		{
			name:   "matching action → true",
			traits: map[string]any{"tartaro_actions": []any{"tartaro:moderate_post", "tartaro:decide_report"}},
			action: "tartaro:moderate_post",
			want:   true,
		},
		{
			name:   "non-matching action → false",
			traits: map[string]any{"tartaro_actions": []any{"tartaro:moderate_post"}},
			action: "tartaro:decide_report",
			want:   false,
		},
		{
			name:   "nil collaborator → false (handled by caller)",
			traits: nil,
			action: "tartaro:moderate_post",
			want:   false,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var collab *YggdrasilCollaborator
			if c.traits != nil {
				collab = &YggdrasilCollaborator{Traits: c.traits}
			}
			if got := YggdrasilHasAction(collab, c.action); got != c.want {
				t.Errorf("YggdrasilHasAction(%v, %q) = %v, want %v", c.traits, c.action, got, c.want)
			}
		})
	}
}
```

- [ ] **Step 2: Verify FAIL**

```bash
cd /Users/dakasa/projects/dakasa/dakasa-system/dakasa-commons
go test ./security/ -run TestYggdrasilHasAction -v
```

Expected: FAIL with `undefined: YggdrasilHasAction`.

- [ ] **Step 3: Add the helper**

In `security/yggdrasil.go`, right after `YggdrasilHasRole`:

```go
// YggdrasilHasAction checks if the collaborator has a specific action in their
// tartaro_actions trait. Replaces YggdrasilHasRole for V1+ team-scoped RBAC.
// YggdrasilHasRole is retained during the transition (some legacy code paths
// still derive role labels for UI), but new authorization checks should call
// this function.
func YggdrasilHasAction(collaborator *YggdrasilCollaborator, action string) bool {
	if collaborator == nil {
		return false
	}
	actions, ok := collaborator.Traits["tartaro_actions"]
	if !ok {
		return false
	}
	slice, ok := actions.([]any)
	if !ok {
		return false
	}
	for _, a := range slice {
		if fmt.Sprint(a) == action {
			return true
		}
	}
	return false
}
```

- [ ] **Step 4: Tests pass**

```bash
go test ./security/ -count=1
```

Expected: all tests PASS (including existing).

- [ ] **Step 5: Commit**

```bash
git add security/yggdrasil.go security/yggdrasil_test.go
git commit -m "$(cat <<'EOF'
✨ feat(security): add YggdrasilHasAction helper

Action-level auth helper alongside existing YggdrasilHasRole.
Reads collaborator.Traits["tartaro_actions"]. Populated by the
team reactor when team_grants change.

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

---

### Task 3: Re-vendor `dakasa-commons` in tartaro services + push Phase 0

**Repos**: all three vendoring tartaro services (`tartaro-legal`, `tartaro-operations`, `tartaro-review`) plus tartaro-api if it also vendors.

- [ ] **Step 1: Identify vendoring services**

```bash
cd /Users/dakasa/projects/dakasa/dakasa-tartaro-fe/backend
for d in */; do
  if [ -d "$d/vendor/github.com/dakasa-co/dakasa-commons/security" ]; then
    echo "$d"
  fi
done
```

Expected: list of services that vendor dakasa-commons.

- [ ] **Step 2: Re-vendor for each**

> The repo root has `task vendor:update` or equivalent. If not, use `go mod vendor` per service. Confirm with the dakasa-system root taskfile.

```bash
cd /Users/dakasa/projects/dakasa/dakasa-system
task vendor:update  # or equivalent
```

If task fails, fallback per-service:

```bash
for svc in tartaro-legal tartaro-operations tartaro-review dakasa-tartaro-api; do
  cd /Users/dakasa/projects/dakasa/dakasa-tartaro-fe/backend/$svc
  go mod vendor
done
```

- [ ] **Step 3: Verify `YggdrasilHasAction` is in each vendored file**

```bash
for svc in tartaro-legal tartaro-operations tartaro-review dakasa-tartaro-api; do
  echo -n "$svc: "
  grep -c "YggdrasilHasAction" /Users/dakasa/projects/dakasa/dakasa-tartaro-fe/backend/$svc/vendor/github.com/dakasa-co/dakasa-commons/security/yggdrasil.go 2>/dev/null || echo 0
done
```

Expected: 1 (or more) per service.

- [ ] **Step 4: Build each**

```bash
for svc in tartaro-legal tartaro-operations tartaro-review dakasa-tartaro-api; do
  echo "=== $svc ==="
  (cd /Users/dakasa/projects/dakasa/dakasa-tartaro-fe/backend/$svc && go build ./...)
done
```

Expected: clean.

- [ ] **Step 5: Commit re-vendor changes**

```bash
cd /Users/dakasa/projects/dakasa/dakasa-tartaro-fe
git add backend/*/vendor/github.com/dakasa-co/dakasa-commons/
git commit -m "$(cat <<'EOF'
♻️ chore(vendor): pull YggdrasilHasAction into tartaro services

Re-vendor dakasa-commons after security/yggdrasil.go added the new
action-level helper.

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

- [ ] **Step 6: Push Phase 0 to all 3 affected repos**

Order matters: dakasa-commons → tartaro-operations (uses commons) → other tartaro services (use commons).

```bash
# dakasa-commons (source)
cd /Users/dakasa/projects/dakasa/dakasa-system/dakasa-commons
git push origin main

# tartaro-operations (has role_actions handler + re-vendored commons)
cd /Users/dakasa/projects/dakasa/dakasa-tartaro-fe
git push origin main
```

> If dakasa-commons is a submodule, `git push` from inside its directory pushes the submodule; the parent (dakasa-system) needs a separate commit pointing at the new submodule SHA. Verify by running `git status` in dakasa-system root after the inner push.

- [ ] **Step 7: Wait for builds, bump tartaro-operations deployment**

After GH Actions release succeeds for tartaro-operations (~5-10 min), follow item #2's playbook to bump the kube deployment image tag. The pattern is in `project_team_reactor_shipped_2026_05_18`:

```bash
# Construct bump workflow (see item #2 memory for full template)
# POST /api/v1/manifests?kind=workflow + POST /api/v1/workflow-runs
```

Wait until `kubectl get deploy tartaro-operations` shows the new SHA, then verify the endpoint:

```bash
curl -sS -H "Authorization: $YGGDRASIL_ADMIN_TOKEN" \
  "https://tartaro-operations.dakasa.me/internal/admin/roles/moderator/actions"
```

Expected: HTTP 200 with non-empty `actions` array.

---

## Phase 1: integration-tartaro-dakasa adapter changes

### Task 4: yggdrasilclient extensions (3 new methods)

**Repo**: `/Users/dakasa/projects/dakasa/integration-tartaro-dakasa`

**Files:**
- Modify: `internal/yggdrasilclient/client.go`
- Modify: `internal/yggdrasilclient/client_test.go`

- [ ] **Step 1: Read existing client structure**

```bash
cd /Users/dakasa/projects/dakasa/integration-tartaro-dakasa
grep -n "func (c \*Client)" internal/yggdrasilclient/client.go | head -10
```

Expected: see existing methods like `GetCollaborator`, `UpdateCollaboratorRoles`, etc. Match their style.

- [ ] **Step 2: Write the failing tests**

Add to `internal/yggdrasilclient/client_test.go`:

```go
func TestListTeamMembershipsByCollaborator(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/team-memberships" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		if r.URL.Query().Get("collaborator_id") != "collab-1" || r.URL.Query().Get("active") != "true" {
			t.Fatalf("unexpected query: %s", r.URL.RawQuery)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"memberships":[{"id":"m1","collaborator_id":"collab-1","team_id":"team-a","active":true},{"id":"m2","collaborator_id":"collab-1","team_id":"team-b","active":true}]}`))
	}))
	defer srv.Close()
	c := NewClient(srv.URL, "test-token")
	ms, err := c.ListTeamMemberships(context.Background(), "collab-1", true)
	if err != nil {
		t.Fatalf("ListTeamMemberships: %v", err)
	}
	if len(ms) != 2 {
		t.Fatalf("expected 2 memberships, got %d", len(ms))
	}
}

func TestListTeamGrants(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/teams/team-a/grants" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"grants":[{"id":"g1","team_id":"team-a","integration_instance_namespace":"dakasa","integration_instance_name":"integration-tartaro-dakasa","action_name":"tartaro:moderate_post"}]}`))
	}))
	defer srv.Close()
	c := NewClient(srv.URL, "test-token")
	gs, err := c.ListTeamGrants(context.Background(), "team-a")
	if err != nil {
		t.Fatalf("ListTeamGrants: %v", err)
	}
	if len(gs) != 1 || gs[0].ActionName != "tartaro:moderate_post" {
		t.Fatalf("unexpected grants: %+v", gs)
	}
}

func TestUpdateCollaboratorTraits(t *testing.T) {
	called := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		if r.Method != http.MethodPatch {
			t.Fatalf("expected PATCH, got %s", r.Method)
		}
		if r.URL.Path != "/api/v1/collaborators/collab-1/traits" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		body, _ := io.ReadAll(r.Body)
		if !strings.Contains(string(body), `"tartaro_actions"`) {
			t.Fatalf("body missing tartaro_actions: %s", string(body))
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"updated":true}`))
	}))
	defer srv.Close()
	c := NewClient(srv.URL, "test-token")
	if err := c.UpdateCollaboratorTraits(context.Background(), "collab-1", map[string]any{
		"tartaro_actions": []string{"tartaro:moderate_post"},
	}); err != nil {
		t.Fatalf("UpdateCollaboratorTraits: %v", err)
	}
	if !called {
		t.Fatal("server never called")
	}
}
```

> Adapt imports + helper names (`NewClient`, types like `TeamMembership`, `TeamGrant`) to whatever exists in the file today.

- [ ] **Step 3: FAIL**

```bash
go test ./internal/yggdrasilclient/ -count=1
```

Expected: FAIL with undefined methods.

- [ ] **Step 4: Implement the methods**

In `internal/yggdrasilclient/client.go`, append (or insert near related GET methods):

```go
// TeamMembership represents a row from /api/v1/team-memberships.
type TeamMembership struct {
	ID             string `json:"id"`
	CollaboratorID string `json:"collaborator_id"`
	TeamID         string `json:"team_id"`
	TeamSlug       string `json:"team_slug,omitempty"`
	Active         bool   `json:"active"`
}

// TeamGrant represents a (team, integration_instance, action) link.
type TeamGrant struct {
	ID                           string         `json:"id"`
	TeamID                       string         `json:"team_id"`
	IntegrationInstanceNamespace string         `json:"integration_instance_namespace"`
	IntegrationInstanceName      string         `json:"integration_instance_name"`
	ActionName                   string         `json:"action_name"`
	Scope                        map[string]any `json:"scope,omitempty"`
}

// ListTeamMemberships returns the collaborator's team memberships. When
// activeOnly is true, only active memberships are returned.
func (c *Client) ListTeamMemberships(ctx context.Context, collaboratorID string, activeOnly bool) ([]TeamMembership, error) {
	q := url.Values{}
	q.Set("collaborator_id", collaboratorID)
	if activeOnly {
		q.Set("active", "true")
	}
	body, err := c.get(ctx, "/api/v1/team-memberships?"+q.Encode())
	if err != nil {
		return nil, fmt.Errorf("list team memberships: %w", err)
	}
	var resp struct{ Memberships []TeamMembership `json:"memberships"` }
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("decode memberships: %w", err)
	}
	return resp.Memberships, nil
}

// ListTeamMembershipsByTeam returns memberships of one team.
func (c *Client) ListTeamMembershipsByTeam(ctx context.Context, teamID string, activeOnly bool) ([]TeamMembership, error) {
	q := url.Values{}
	q.Set("team_id", teamID)
	if activeOnly {
		q.Set("active", "true")
	}
	body, err := c.get(ctx, "/api/v1/team-memberships?"+q.Encode())
	if err != nil {
		return nil, fmt.Errorf("list team memberships by team: %w", err)
	}
	var resp struct{ Memberships []TeamMembership `json:"memberships"` }
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("decode memberships: %w", err)
	}
	return resp.Memberships, nil
}

// ListTeamGrants returns all grants of a team.
func (c *Client) ListTeamGrants(ctx context.Context, teamID string) ([]TeamGrant, error) {
	body, err := c.get(ctx, "/api/v1/teams/"+url.PathEscape(teamID)+"/grants")
	if err != nil {
		return nil, fmt.Errorf("list team grants: %w", err)
	}
	var resp struct{ Grants []TeamGrant `json:"grants"` }
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("decode grants: %w", err)
	}
	return resp.Grants, nil
}

// UpdateCollaboratorTraits PATCHes the collaborator's traits.
func (c *Client) UpdateCollaboratorTraits(ctx context.Context, collaboratorID string, traits map[string]any) error {
	buf, err := json.Marshal(map[string]any{"traits": traits})
	if err != nil {
		return fmt.Errorf("marshal traits: %w", err)
	}
	_, err = c.do(ctx, http.MethodPatch, "/api/v1/collaborators/"+url.PathEscape(collaboratorID)+"/traits", buf)
	if err != nil {
		return fmt.Errorf("update traits: %w", err)
	}
	return nil
}
```

> If `c.get` / `c.do` don't exist (different naming), adapt. The pattern is "build request, sign, send, return body bytes".

- [ ] **Step 5: Tests pass**

```bash
go test ./internal/yggdrasilclient/ -count=1
```

Expected: PASS.

- [ ] **Step 6: Build**

```bash
go build ./...
```

Expected: clean.

- [ ] **Step 7: Commit (don't push yet — Phase 1 batches)**

```bash
git add internal/yggdrasilclient/
git commit -m "$(cat <<'EOF'
✨ feat(yggdrasilclient): add ListTeamMemberships, ListTeamGrants, UpdateCollaboratorTraits

Three methods the upcoming team-permissions reactor needs:
- ListTeamMemberships(collabID, activeOnly) → user's active teams
- ListTeamMembershipsByTeam(teamID, activeOnly) → team's members
- ListTeamGrants(teamID) → all grants of a team
- UpdateCollaboratorTraits(collabID, traits) → PATCH .traits.tartaro_actions

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

---

### Task 5: `RecomputeUserTartaroActions` + `RecomputeTeamMembers` helpers

**Files:**
- Create: `internal/capabilities/effective_actions.go`
- Create: `internal/capabilities/effective_actions_test.go`

- [ ] **Step 1: Confirm the instance ref source**

```bash
grep -rn "Namespace\|Name" internal/config/ | head -10
```

Find how the adapter knows its own (namespace, name). Usually env vars (`INTEGRATION_INSTANCE_NAMESPACE`, `INTEGRATION_INSTANCE_NAME`) or a config struct.

- [ ] **Step 2: Write failing tests**

```go
// internal/capabilities/effective_actions_test.go
package capabilities

import (
	"context"
	"testing"

	"github.com/dakasa-co/integration-tartaro-dakasa/internal/yggdrasilclient"
)

type fakeYgg struct {
	memberships func(collabID string) []yggdrasilclient.TeamMembership
	grants      func(teamID string) []yggdrasilclient.TeamGrant
	traitsPUT   map[string][]string // last PUT per collab
}

func (f *fakeYgg) ListTeamMemberships(_ context.Context, c string, _ bool) ([]yggdrasilclient.TeamMembership, error) {
	return f.memberships(c), nil
}
func (f *fakeYgg) ListTeamMembershipsByTeam(_ context.Context, t string, _ bool) ([]yggdrasilclient.TeamMembership, error) {
	// reverse map by team
	out := []yggdrasilclient.TeamMembership{}
	for collabID, _ := range map[string]struct{}{"u1": {}, "u2": {}, "u3": {}} {
		for _, m := range f.memberships(collabID) {
			if m.TeamID == t {
				out = append(out, m)
			}
		}
	}
	return out, nil
}
func (f *fakeYgg) ListTeamGrants(_ context.Context, t string) ([]yggdrasilclient.TeamGrant, error) {
	return f.grants(t), nil
}
func (f *fakeYgg) UpdateCollaboratorTraits(_ context.Context, c string, traits map[string]any) error {
	if f.traitsPUT == nil {
		f.traitsPUT = map[string][]string{}
	}
	actions, _ := traits["tartaro_actions"].([]string)
	f.traitsPUT[c] = actions
	return nil
}

func TestRecomputeUserTartaroActions_UnionOfGrantsFromActiveTeams(t *testing.T) {
	ygg := &fakeYgg{
		memberships: func(c string) []yggdrasilclient.TeamMembership {
			if c == "u1" {
				return []yggdrasilclient.TeamMembership{{TeamID: "team-a", Active: true}, {TeamID: "team-b", Active: true}}
			}
			return nil
		},
		grants: func(t string) []yggdrasilclient.TeamGrant {
			ours := func(n string) yggdrasilclient.TeamGrant {
				return yggdrasilclient.TeamGrant{
					IntegrationInstanceNamespace: "dakasa",
					IntegrationInstanceName:      "integration-tartaro-dakasa",
					ActionName:                   n,
				}
			}
			switch t {
			case "team-a":
				return []yggdrasilclient.TeamGrant{ours("tartaro:moderate_post"), ours("tartaro:decide_report")}
			case "team-b":
				return []yggdrasilclient.TeamGrant{ours("tartaro:decide_report"), ours("tartaro:read_collaborator")}
			}
			return nil
		},
	}
	actions, err := RecomputeUserTartaroActions(context.Background(), ygg, "u1", "dakasa", "integration-tartaro-dakasa")
	if err != nil {
		t.Fatalf("Recompute: %v", err)
	}
	want := []string{"tartaro:decide_report", "tartaro:moderate_post", "tartaro:read_collaborator"}
	if !equalStrSlice(actions, want) {
		t.Fatalf("expected sorted union %v, got %v", want, actions)
	}
	if !equalStrSlice(ygg.traitsPUT["u1"], want) {
		t.Fatalf("expected trait PUT %v, got %v", want, ygg.traitsPUT["u1"])
	}
}

func TestRecomputeUserTartaroActions_IgnoresWildcardAndOtherInstances(t *testing.T) {
	ygg := &fakeYgg{
		memberships: func(c string) []yggdrasilclient.TeamMembership {
			return []yggdrasilclient.TeamMembership{{TeamID: "team-a", Active: true}}
		},
		grants: func(t string) []yggdrasilclient.TeamGrant {
			return []yggdrasilclient.TeamGrant{
				{IntegrationInstanceNamespace: "dakasa", IntegrationInstanceName: "integration-tartaro-dakasa", ActionName: "tartaro:moderate_post"},
				{IntegrationInstanceNamespace: "dakasa", IntegrationInstanceName: "integration-tartaro-dakasa", ActionName: "*"},
				{IntegrationInstanceNamespace: "dakasa", IntegrationInstanceName: "integration-slack-dakasa", ActionName: "slack:invite_user"},
			}
		},
	}
	actions, _ := RecomputeUserTartaroActions(context.Background(), ygg, "u1", "dakasa", "integration-tartaro-dakasa")
	want := []string{"tartaro:moderate_post"}
	if !equalStrSlice(actions, want) {
		t.Fatalf("expected %v, got %v", want, actions)
	}
}

func equalStrSlice(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
```

- [ ] **Step 3: FAIL**

```bash
go test ./internal/capabilities/ -run TestRecompute -v -count=1
```

Expected: FAIL — `RecomputeUserTartaroActions` undefined + `YggdrasilLike` interface or signature mismatch.

- [ ] **Step 4: Implement**

```go
// internal/capabilities/effective_actions.go
package capabilities

import (
	"context"
	"fmt"
	"sort"

	"github.com/dakasa-co/integration-tartaro-dakasa/internal/yggdrasilclient"
)

// YggdrasilLike is the subset of yggdrasilclient.Client the recompute
// helpers depend on. Test fakes implement this directly.
type YggdrasilLike interface {
	ListTeamMemberships(ctx context.Context, collaboratorID string, activeOnly bool) ([]yggdrasilclient.TeamMembership, error)
	ListTeamMembershipsByTeam(ctx context.Context, teamID string, activeOnly bool) ([]yggdrasilclient.TeamMembership, error)
	ListTeamGrants(ctx context.Context, teamID string) ([]yggdrasilclient.TeamGrant, error)
	UpdateCollaboratorTraits(ctx context.Context, collaboratorID string, traits map[string]any) error
}

// RecomputeUserTartaroActions rebuilds the user's tartaro_actions trait
// from the UNION of grants across all their active team memberships,
// scoped to one integration_instance. Idempotent: safe to retry on
// reactor backoff. Wildcards ("*") are V1-skipped.
func RecomputeUserTartaroActions(
	ctx context.Context, ygg YggdrasilLike, collaboratorID, instanceNamespace, instanceName string,
) ([]string, error) {
	memberships, err := ygg.ListTeamMemberships(ctx, collaboratorID, true)
	if err != nil {
		return nil, fmt.Errorf("list memberships: %w", err)
	}

	seen := map[string]struct{}{}
	for _, m := range memberships {
		grants, err := ygg.ListTeamGrants(ctx, m.TeamID)
		if err != nil {
			return nil, fmt.Errorf("list grants team %s: %w", m.TeamID, err)
		}
		for _, g := range grants {
			if g.IntegrationInstanceNamespace != instanceNamespace || g.IntegrationInstanceName != instanceName {
				continue
			}
			if g.ActionName == "*" {
				continue
			}
			seen[g.ActionName] = struct{}{}
		}
	}

	actions := make([]string, 0, len(seen))
	for a := range seen {
		actions = append(actions, a)
	}
	sort.Strings(actions)

	if err := ygg.UpdateCollaboratorTraits(ctx, collaboratorID, map[string]any{
		"tartaro_actions": actions,
	}); err != nil {
		return nil, fmt.Errorf("update traits: %w", err)
	}
	return actions, nil
}

// RecomputeTeamMembers recomputes tartaro_actions for every active
// member of one team. Used when a team_grant changes — affects all
// current members at once.
func RecomputeTeamMembers(
	ctx context.Context, ygg YggdrasilLike, teamID, instanceNamespace, instanceName string,
) ([]string, error) {
	members, err := ygg.ListTeamMembershipsByTeam(ctx, teamID, true)
	if err != nil {
		return nil, fmt.Errorf("list team members: %w", err)
	}
	var done []string
	for _, m := range members {
		if _, err := RecomputeUserTartaroActions(ctx, ygg, m.CollaboratorID, instanceNamespace, instanceName); err != nil {
			// Single-user failure shouldn't block the rest — caller logs.
			continue
		}
		done = append(done, m.CollaboratorID)
	}
	return done, nil
}
```

- [ ] **Step 5: Tests pass**

```bash
go test ./internal/capabilities/ -run TestRecompute -v -count=1
```

Expected: PASS (both subtests).

- [ ] **Step 6: Commit**

```bash
git add internal/capabilities/effective_actions.go internal/capabilities/effective_actions_test.go
git commit -m "$(cat <<'EOF'
✨ feat(capabilities): add RecomputeUserTartaroActions + RecomputeTeamMembers

UNION of action_names from grants on the user's active teams (scoped
to this integration_instance). Wildcards skipped in V1. Sorted output
so repeated calls produce identical traits PUT bodies.

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

---

### Task 6: 4 new dispatcher cases + reactor declarations

**Files:**
- Modify: `internal/capabilities/dispatch.go`
- Modify: `internal/capabilities/dispatch_test.go`
- Modify: `integration.yaml`
- Modify: `example.json`

- [ ] **Step 1: Find the instance namespace/name source**

The dispatch handler needs (namespace, name). Look at config:

```bash
grep -rn "InstanceNamespace\|InstanceName\|INTEGRATION_INSTANCE" internal/config/
```

Adapt the imports / accessors below to what exists.

- [ ] **Step 2: Add 4 dispatcher cases**

In `internal/capabilities/dispatch.go`, add to the switch in `Dispatch` (or whatever the entry function is called):

```go
case "tartaro:on_team_membership_added", "tartaro:on_team_membership_removed":
    var p struct { CollaboratorID string `json:"collaborator_id"` }
    if err := json.Unmarshal(payload, &p); err != nil {
        return Result{}, fmt.Errorf("decode payload: %w", err)
    }
    actions, err := RecomputeUserTartaroActions(ctx, ygg, p.CollaboratorID, cfg.InstanceNamespace, cfg.InstanceName)
    if err != nil {
        return Result{}, err
    }
    return Result{OK: true, Data: map[string]any{
        "collaborator_id": p.CollaboratorID,
        "tartaro_actions": actions,
    }}, nil

case "tartaro:on_team_grant_added", "tartaro:on_team_grant_revoked":
    var p struct {
        TeamID                       string `json:"team_id"`
        IntegrationInstanceNamespace string `json:"integration_instance_namespace"`
        IntegrationInstanceName      string `json:"integration_instance_name"`
    }
    if err := json.Unmarshal(payload, &p); err != nil {
        return Result{}, fmt.Errorf("decode payload: %w", err)
    }
    if p.IntegrationInstanceNamespace != cfg.InstanceNamespace || p.IntegrationInstanceName != cfg.InstanceName {
        return Result{OK: true, Data: map[string]any{"skipped": "different integration_instance"}}, nil
    }
    affected, err := RecomputeTeamMembers(ctx, ygg, p.TeamID, cfg.InstanceNamespace, cfg.InstanceName)
    if err != nil {
        return Result{}, err
    }
    return Result{OK: true, Data: map[string]any{
        "team_id":          p.TeamID,
        "users_recomputed": len(affected),
    }}, nil
```

> Pass `cfg` (or your equivalent that holds InstanceNamespace + InstanceName) into the dispatcher signature if not already there. Match existing case patterns.

- [ ] **Step 3: Add dispatcher tests**

Append to `internal/capabilities/dispatch_test.go`:

```go
func TestDispatch_OnTeamMembershipAdded_Recomputes(t *testing.T) {
	ygg := &fakeYgg{
		memberships: func(c string) []yggdrasilclient.TeamMembership {
			return []yggdrasilclient.TeamMembership{{TeamID: "team-a", Active: true}}
		},
		grants: func(_ string) []yggdrasilclient.TeamGrant {
			return []yggdrasilclient.TeamGrant{{IntegrationInstanceNamespace: "dakasa", IntegrationInstanceName: "integration-tartaro-dakasa", ActionName: "tartaro:moderate_post"}}
		},
	}
	cfg := Config{InstanceNamespace: "dakasa", InstanceName: "integration-tartaro-dakasa"}
	payload := []byte(`{"collaborator_id":"u1"}`)
	out, err := Dispatch(context.Background(), "tartaro:on_team_membership_added", payload, ygg, nil, cfg)
	if err != nil {
		t.Fatalf("Dispatch: %v", err)
	}
	if !out.OK {
		t.Fatal("expected OK")
	}
	if len(ygg.traitsPUT["u1"]) != 1 || ygg.traitsPUT["u1"][0] != "tartaro:moderate_post" {
		t.Fatalf("trait not PUT: %v", ygg.traitsPUT)
	}
}

func TestDispatch_OnTeamGrantAdded_DifferentInstance_Skipped(t *testing.T) {
	ygg := &fakeYgg{}
	cfg := Config{InstanceNamespace: "dakasa", InstanceName: "integration-tartaro-dakasa"}
	payload := []byte(`{"team_id":"team-a","integration_instance_namespace":"dakasa","integration_instance_name":"integration-slack-dakasa"}`)
	out, err := Dispatch(context.Background(), "tartaro:on_team_grant_added", payload, ygg, nil, cfg)
	if err != nil {
		t.Fatalf("Dispatch: %v", err)
	}
	if out.Data["skipped"] != "different integration_instance" {
		t.Fatalf("expected skipped marker, got %v", out.Data)
	}
}
```

- [ ] **Step 4: Update `integration.yaml` reactors + capabilities**

Replace the `reactors:` block (or add if absent) with:

```yaml
reactors:
  - event_type: team_membership.added
    capability: tartaro:on_team_membership_added
    description: Recompute traits.tartaro_actions for the user joining
  - event_type: team_membership.removed
    capability: tartaro:on_team_membership_removed
    description: Recompute traits.tartaro_actions for the user leaving
  - event_type: team_grant.added
    capability: tartaro:on_team_grant_added
    description: Recompute every active member of the granted team
  - event_type: team_grant.revoked
    capability: tartaro:on_team_grant_revoked
    description: Same on revoke side
```

And ADD the 4 capabilities to the `capabilities:` list:

```yaml
- name: tartaro:on_team_membership_added
  description: Recompute traits.tartaro_actions for one user
- name: tartaro:on_team_membership_removed
  description: Same as above for user leaving
- name: tartaro:on_team_grant_added
  description: Recompute traits.tartaro_actions for every member of a team
- name: tartaro:on_team_grant_revoked
  description: Same on revoke
```

And mark old role capabilities deprecated (keep entries, prepend `[deprecated V1]` to description):

```yaml
- name: tartaro:assign_rbac_role
  description: "[deprecated V1] Use team_grant via Yggdrasil teams; no-ops with warning."
- name: tartaro:revoke_rbac_role
  description: "[deprecated V1] Use team_grant via Yggdrasil teams; no-ops with warning."
```

- [ ] **Step 5: Update `example.json` with 4 new examples**

```json
"tartaro:on_team_membership_added": {
  "capability": "tartaro:on_team_membership_added",
  "payload": {"collaborator_id": "abc-123"}
},
"tartaro:on_team_membership_removed": {
  "capability": "tartaro:on_team_membership_removed",
  "payload": {"collaborator_id": "abc-123"}
},
"tartaro:on_team_grant_added": {
  "capability": "tartaro:on_team_grant_added",
  "payload": {"team_id": "team-a", "integration_instance_namespace": "dakasa", "integration_instance_name": "integration-tartaro-dakasa"}
},
"tartaro:on_team_grant_revoked": {
  "capability": "tartaro:on_team_grant_revoked",
  "payload": {"team_id": "team-a", "integration_instance_namespace": "dakasa", "integration_instance_name": "integration-tartaro-dakasa"}
}
```

Validate JSON:

```bash
python3 -c 'import json; json.load(open("example.json"))' && echo OK
```

- [ ] **Step 6: Deprecate old role caps (runtime)**

In `internal/capabilities/dispatch.go`, replace the bodies of `tartaro:assign_rbac_role` / `tartaro:revoke_rbac_role` cases with a no-op + warn log:

```go
case "tartaro:assign_rbac_role", "tartaro:revoke_rbac_role":
    // V1: these capabilities are deprecated. Team-scoped grants replaced
    // per-user role assignment. We keep the cases to preserve the
    // adapter contract; callers should migrate to POST /teams/{id}/grants.
    if logger != nil {
        logger.Warn("deprecated capability called",
            zap.String("capability", name),
            zap.String("hint", "use team_grant via Yggdrasil teams instead"))
    }
    return Result{OK: true, Data: map[string]any{
        "deprecated": true,
        "capability": name,
        "hint":       "Use POST /api/v1/teams/{id}/grants instead",
    }}, nil
```

- [ ] **Step 7: All tests + build**

```bash
go test ./... -count=1
go build ./...
```

Expected: clean.

- [ ] **Step 8: Commit + push Phase 1**

```bash
git add internal/capabilities/dispatch.go internal/capabilities/dispatch_test.go internal/capabilities/effective_actions.go internal/capabilities/effective_actions_test.go internal/yggdrasilclient/ integration.yaml example.json
git commit -m "$(cat <<'EOF'
✨ feat(team-perms): add 4 reactor capabilities + deprecate role caps

Adds dispatcher cases for team_membership.added/removed and
team_grant.added/revoked. Recomputes traits.tartaro_actions via the
union of grants across the user's active teams (scoped to this
integration_instance). Wildcards skipped.

Deprecates tartaro:assign_rbac_role / revoke_rbac_role — they no-op
with a warning. Operators migrate to POST /teams/{id}/grants.

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"

git push origin main
```

- [ ] **Step 9: Wait for release, bump kube deployment**

Per item #2 playbook: build the `bump-integration-tartaro-dakasa-sha-<short>` workflow, apply, wait for rollout, confirm SHA.

---

## Phase 2: yggdrasil-core (canon events + endpoints)

### Task 7: 2 new canon events

**Repo**: `/Users/dakasa/projects/yggdrasil/yggdrasil-core`

**Files:**
- Modify: `repository/event_types_lifecycle.go`
- Modify: `repository/event_types_lifecycle_test.go`

- [ ] **Step 1: Add constants**

In `repository/event_types_lifecycle.go`, in the constants block:

```go
EventTypeTeamGrantAdded   = "team_grant.added"
EventTypeTeamGrantRevoked = "team_grant.revoked"
```

And add both to `CanonLifecycleEventTypes`:

```go
EventTypeTeamGrantAdded:   {},
EventTypeTeamGrantRevoked: {},
```

- [ ] **Step 2: Update tests**

In `repository/event_types_lifecycle_test.go`, if any test enumerates the canon set or asserts a count, update to include the 2 new entries.

```bash
go test ./repository/ -run TestCanonLifecycleEvent -v -count=1
```

Expected: PASS (with new entries asserted).

- [ ] **Step 3: Commit**

```bash
git add repository/event_types_lifecycle.go repository/event_types_lifecycle_test.go
git commit -m "$(cat <<'EOF'
✨ feat(events): add team_grant.added/revoked canon events

Powers the tartaro adapter's recompute reactor — when a grant is added
or revoked on a team, the adapter materializes traits.tartaro_actions
for every active member.

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

---

### Task 8: Emit `team_grant.added/revoked` in CRUD handlers

**Files:**
- Modify: `controllers/httpapi/server.go` (handleTeamGrantCreate + handleTeamGrantRevoke)

- [ ] **Step 1: Find the handlers**

```bash
grep -n "func .*handleTeamGrant\|handleGrantTeamAction\|POST /api/v1/teams/{id}/grants" controllers/httpapi/server.go
```

- [ ] **Step 2: Modify handleTeamGrantCreate to emit canon event**

After the grant is inserted in the transaction, before commit, add:

```go
payload := map[string]any{
    "id":                              grant.ID,
    "team_id":                         grant.TeamID,
    "integration_instance_namespace":  grant.IntegrationInstanceNamespace,
    "integration_instance_name":       grant.IntegrationInstanceName,
    "action_name":                     grant.ActionName,
}
if grant.Scope != nil {
    payload["scope"] = grant.Scope
}
if grant.GrantedBy != nil {
    payload["granted_by"] = *grant.GrantedBy
}
if _, err := repository.EmitEvent(r.Context(), tx, model.EmitEventRequest{
    Type:          repository.EventTypeTeamGrantAdded,
    SchemaVersion: "v1",
    AggregateType: "team_grant",
    AggregateID:   grant.ID,
    Payload:       payload,
    Actor: &model.EventActor{
        Type: model.ActorTypeAPI,
        ID:   actorIDFromRequest(r),
    },
}); err != nil {
    writeMappedError(w, fmt.Errorf("emit team_grant.added: %w", err))
    return
}
```

- [ ] **Step 3: Same for handleTeamGrantRevoke**

After delete:

```go
if _, err := repository.EmitEvent(r.Context(), tx, model.EmitEventRequest{
    Type:          repository.EventTypeTeamGrantRevoked,
    SchemaVersion: "v1",
    AggregateType: "team_grant",
    AggregateID:   grant.ID,
    Payload: map[string]any{
        "id":          grant.ID,
        "team_id":     grant.TeamID,
        "action_name": grant.ActionName,
    },
    Actor: &model.EventActor{
        Type: model.ActorTypeAPI,
        ID:   actorIDFromRequest(r),
    },
}); err != nil {
    writeMappedError(w, fmt.Errorf("emit team_grant.revoked: %w", err))
    return
}
```

- [ ] **Step 4: Write HTTP-level test (or extend existing)**

Find the existing team_grant test file:

```bash
grep -rln "handleTeamGrant\|TestTeamGrant" controllers/httpapi/*_test.go
```

Add a test that posts a grant, then queries event_log:

```go
func TestTeamGrantCreateEmitsCanonEvent(t *testing.T) {
    srv, db := newTestServer(t)
    t.Cleanup(func() { _ = db.Close() })

    teamID := seedActiveTeam(t, db)
    instance := seedIntegrationInstanceForGrants(t, db) // matches existing helper pattern

    body := strings.NewReader(fmt.Sprintf(`{
        "integration_instance_namespace": "dakasa",
        "integration_instance_name": "%s",
        "action_name": "tartaro:moderate_post"
    }`, instance))
    req := httptest.NewRequest(http.MethodPost, "/api/v1/teams/"+teamID.String()+"/grants", body)
    rr := httptest.NewRecorder()
    srv.ServeHTTP(rr, req)
    if rr.Code != http.StatusCreated && rr.Code != http.StatusOK {
        t.Fatalf("expected 201/200, got %d (body=%s)", rr.Code, rr.Body.String())
    }
    var count int
    if err := db.QueryRow(`SELECT COUNT(*) FROM event_log WHERE type = 'team_grant.added' AND aggregate_type = 'team_grant'`).Scan(&count); err != nil {
        t.Fatalf("query event_log: %v", err)
    }
    if count == 0 {
        t.Fatal("expected event_log row for team_grant.added")
    }
}
```

- [ ] **Step 5: Build + tests**

```bash
go build ./...
go test ./controllers/httpapi/ -run TestTeamGrant -count=1
```

Expected: clean + PASS.

- [ ] **Step 6: Commit**

```bash
git add controllers/httpapi/server.go controllers/httpapi/*_test.go
git commit -m "$(cat <<'EOF'
✨ feat(team_grants): emit team_grant.added/revoked canon events

Same TX as the grant mutation. MaterializeReactions then fans out to
integration-tartaro-dakasa (and any future adapter declaring a reactor
for these events).

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

---

### Task 9: `/effective-tartaro-actions` + `/sync-tartaro-actions` endpoints

**Files:**
- Create: `controllers/httpapi/tartaro_actions.go`
- Create: `controllers/httpapi/tartaro_actions_test.go`
- Modify: `controllers/httpapi/server.go` (route registration)

- [ ] **Step 1: Tests FIRST**

Create `controllers/httpapi/tartaro_actions_test.go`:

```go
package httpapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestEffectiveTartaroActions(t *testing.T) {
	srv, db := newTestServer(t)
	t.Cleanup(func() { _ = db.Close() })

	collabID := seedActiveCollaborator(t, db)
	teamID := seedActiveTeam(t, db)
	addToTeam(t, db, collabID, teamID)
	addGrant(t, db, teamID, "dakasa", "integration-tartaro-dakasa", "tartaro:moderate_post")
	// Trait left empty on purpose — endpoint should compute and report drift=true

	req := httptest.NewRequest(http.MethodGet, "/api/v1/collaborators/"+collabID.String()+"/effective-tartaro-actions", nil)
	rr := httptest.NewRecorder()
	srv.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d (body=%s)", rr.Code, rr.Body.String())
	}
	var resp struct {
		TraitTartaroActions []string `json:"trait_tartaro_actions"`
		EffectiveViaTeams   []struct {
			TeamID  string   `json:"team_id"`
			Actions []string `json:"actions"`
		} `json:"effective_via_teams"`
		Drift bool `json:"drift"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !resp.Drift {
		t.Fatal("expected drift=true since trait is empty")
	}
	if len(resp.EffectiveViaTeams) != 1 || len(resp.EffectiveViaTeams[0].Actions) != 1 {
		t.Fatalf("expected 1 team with 1 action, got %+v", resp.EffectiveViaTeams)
	}
}

func TestSyncTartaroActionsEmitsSyntheticEvent(t *testing.T) {
	srv, db := newTestServer(t)
	t.Cleanup(func() { _ = db.Close() })

	collabID := seedActiveCollaborator(t, db)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/collaborators/"+collabID.String()+"/sync-tartaro-actions", strings.NewReader(""))
	rr := httptest.NewRecorder()
	srv.ServeHTTP(rr, req)
	if rr.Code != http.StatusAccepted {
		t.Fatalf("expected 202, got %d", rr.Code)
	}
	var count int
	_ = db.QueryRow(`SELECT COUNT(*) FROM event_log WHERE aggregate_id = $1 AND type LIKE 'team_membership.%'`, collabID.String()).Scan(&count)
	// A synthetic team_membership.added (or similar) event should land
	if count == 0 {
		t.Fatal("expected synthetic event in event_log")
	}
}
```

- [ ] **Step 2: Implement the handlers**

```go
// controllers/httpapi/tartaro_actions.go
package httpapi

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	"github.com/google/uuid"
)

const (
	tartaroInstanceNamespace = "dakasa"
	tartaroInstanceName      = "integration-tartaro-dakasa"
)

type effectivePerTeam struct {
	TeamID   string   `json:"team_id"`
	TeamSlug string   `json:"team_slug,omitempty"`
	Actions  []string `json:"actions"`
}

// handleEffectiveTartaroActions returns the trait set vs the ground-
// truth computation. drift=true signals the reactor lagged or failed.
func (s *Server) handleEffectiveTartaroActions(w http.ResponseWriter, r *http.Request) {
	collabID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid collaborator id"})
		return
	}

	collab, err := repository.GetCollaborator(r.Context(), s.db, collabID)
	if err != nil {
		writeMappedError(w, err)
		return
	}

	memberships, err := repository.ListTeamMemberships(r.Context(), s.db, model.ListTeamMembershipsRequest{
		CollaboratorID: collabID.String(),
		ActiveOnly:     true,
	})
	if err != nil {
		writeMappedError(w, err)
		return
	}

	perTeam := make([]effectivePerTeam, 0, len(memberships))
	union := map[string]struct{}{}
	for _, m := range memberships {
		grants, err := repository.ListTeamGrants(r.Context(), s.db, model.ListTeamGrantsRequest{TeamID: m.TeamID.String()})
		if err != nil {
			writeMappedError(w, err)
			return
		}
		var actions []string
		for _, g := range grants {
			if g.IntegrationInstanceNamespace != tartaroInstanceNamespace || g.IntegrationInstanceName != tartaroInstanceName {
				continue
			}
			if g.ActionName == "*" {
				continue
			}
			union[g.ActionName] = struct{}{}
			actions = append(actions, g.ActionName)
		}
		sort.Strings(actions)
		if len(actions) > 0 {
			perTeam = append(perTeam, effectivePerTeam{
				TeamID:   m.TeamID.String(),
				TeamSlug: m.TeamSlug,
				Actions:  actions,
			})
		}
	}

	computed := make([]string, 0, len(union))
	for a := range union {
		computed = append(computed, a)
	}
	sort.Strings(computed)

	// Compare to trait
	traitActions := parseTraitActions(collab.Traits)
	drift := !equalSortedStrings(traitActions, computed)

	writeJSON(w, http.StatusOK, map[string]any{
		"collaborator_id":        collabID,
		"trait_tartaro_actions":  traitActions,
		"effective_via_teams":    perTeam,
		"computed_tartaro_actions": computed,
		"drift":                  drift,
	})
}

// handleSyncTartaroActions emits a synthetic team_membership event so the
// reactor framework reprocesses this user. Returns 202 Accepted.
func (s *Server) handleSyncTartaroActions(w http.ResponseWriter, r *http.Request) {
	collabID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid collaborator id"})
		return
	}

	if _, err := repository.GetCollaborator(r.Context(), s.db, collabID); err != nil {
		writeMappedError(w, err)
		return
	}

	tx, err := s.db.BeginTx(r.Context(), nil)
	if err != nil {
		writeMappedError(w, fmt.Errorf("begin tx: %w", err))
		return
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := repository.EmitEvent(r.Context(), tx, model.EmitEventRequest{
		Type:          repository.EventTypeTeamMembershipAdded, // reuse — reactor recomputes regardless of trigger
		SchemaVersion: "v1",
		AggregateType: "team_membership",
		AggregateID:   collabID.String(), // synthetic — no real membership row
		Payload: map[string]any{
			"collaborator_id": collabID.String(),
			"synthetic":       true,
			"trigger":         "sync-tartaro-actions",
		},
		Actor: &model.EventActor{Type: model.ActorTypeAPI, ID: actorIDFromRequest(r)},
	}); err != nil {
		writeMappedError(w, fmt.Errorf("emit synthetic event: %w", err))
		return
	}
	if err := tx.Commit(); err != nil {
		writeMappedError(w, fmt.Errorf("commit: %w", err))
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]any{
		"collaborator_id": collabID,
		"events_emitted":  1,
		"event_type":      "team_membership.added",
		"note":            "synthetic — reactor recomputes user trait",
	})
}

func parseTraitActions(traits map[string]any) []string {
	raw, _ := traits["tartaro_actions"].([]any)
	out := make([]string, 0, len(raw))
	for _, v := range raw {
		if s, ok := v.(string); ok {
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}

func equalSortedStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
```

> `repository.GetCollaborator`, `ListTeamMemberships`, `ListTeamGrants` are the existing helpers — verify exact names with `grep`. Adapt if different.

- [ ] **Step 3: Register routes**

In `controllers/httpapi/server.go`:

```go
mux.HandleFunc("GET /api/v1/collaborators/{id}/effective-tartaro-actions", server.handleEffectiveTartaroActions)
mux.HandleFunc("POST /api/v1/collaborators/{id}/sync-tartaro-actions", server.handleSyncTartaroActions)
```

- [ ] **Step 4: Build + tests**

```bash
go build ./...
go test ./controllers/httpapi/ -run "TestEffectiveTartaroActions|TestSyncTartaroActions" -count=1
```

Expected: clean + PASS.

- [ ] **Step 5: Commit + push Phase 2**

```bash
git add repository/event_types_lifecycle.go repository/event_types_lifecycle_test.go controllers/httpapi/server.go controllers/httpapi/tartaro_actions.go controllers/httpapi/tartaro_actions_test.go controllers/httpapi/*_grant*_test.go
git commit -m "$(cat <<'EOF'
✨ feat(tartaro-perms): canon events + debug endpoints

Adds team_grant.added/revoked canon events emitted by team_grants
CRUD handlers. Plus two debug endpoints:
- GET /collaborators/{id}/effective-tartaro-actions (drift detection)
- POST /collaborators/{id}/sync-tartaro-actions (operator escape hatch)

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"

git push origin main
```

- [ ] **Step 6: Wait for yggdrasil-core release, bump deployment**

Per item #2 playbook.

---

## Phase 3: Migration script

### Task 10: Migration script — `--dry-run` + connect

**Repo**: yggdrasil-core (script lives in scripts/)

**Files:**
- Create: `scripts/migrate_tartaro_roles_to_actions/main.go`
- Create: `scripts/migrate_tartaro_roles_to_actions/main_test.go`

- [ ] **Step 1: Script skeleton with flags**

```go
// scripts/migrate_tartaro_roles_to_actions/main.go
package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"strings"

	_ "github.com/lib/pq"
)

type config struct {
	dbURL              string
	tartaroOpsBaseURL  string
	tartaroOpsToken    string
	instanceNamespace  string
	instanceName       string
	mode               string // "dry-run" | "validate" | "apply"
	logger             *log.Logger
}

func parseFlags() config {
	var c config
	flag.StringVar(&c.dbURL, "db-url", os.Getenv("YGGDRASIL_DB_URL"), "PostgreSQL DSN")
	flag.StringVar(&c.tartaroOpsBaseURL, "tartaro-ops-url", os.Getenv("TARTARO_OPS_URL"), "tartaro-operations base URL")
	flag.StringVar(&c.tartaroOpsToken, "tartaro-ops-token", os.Getenv("TARTARO_OPS_TOKEN"), "Bearer token for tartaro-operations")
	flag.StringVar(&c.instanceNamespace, "instance-namespace", "dakasa", "Tartaro integration instance namespace")
	flag.StringVar(&c.instanceName, "instance-name", "integration-tartaro-dakasa", "Tartaro integration instance name")
	flag.StringVar(&c.mode, "mode", "dry-run", "Mode: dry-run | validate | apply")
	flag.Parse()
	c.logger = log.New(os.Stdout, "[migrate-tartaro] ", log.LstdFlags)
	return c
}

func main() {
	cfg := parseFlags()
	if cfg.dbURL == "" || cfg.tartaroOpsBaseURL == "" {
		fmt.Fprintln(os.Stderr, "db-url and tartaro-ops-url are required")
		os.Exit(2)
	}
	db, err := sql.Open("postgres", cfg.dbURL)
	if err != nil {
		fmt.Fprintln(os.Stderr, "open db:", err)
		os.Exit(2)
	}
	defer db.Close()
	if err := db.Ping(); err != nil {
		fmt.Fprintln(os.Stderr, "ping db:", err)
		os.Exit(2)
	}

	ctx := context.Background()
	switch cfg.mode {
	case "dry-run", "apply":
		if err := runMigration(ctx, cfg, db, cfg.mode == "apply"); err != nil {
			cfg.logger.Println("FAILED:", err)
			os.Exit(1)
		}
	case "validate":
		if err := runValidate(ctx, cfg, db); err != nil {
			cfg.logger.Println("DRIFT:", err)
			os.Exit(1)
		}
	default:
		fmt.Fprintln(os.Stderr, "unknown mode:", cfg.mode)
		os.Exit(2)
	}
}
```

Add `log` to imports.

- [ ] **Step 2: HTTP client for tartaro-ops + role-actions fetcher**

```go
func fetchRoleActions(ctx context.Context, cfg config, slug string) ([]string, error) {
	u := strings.TrimRight(cfg.tartaroOpsBaseURL, "/") + "/internal/admin/roles/" + slug + "/actions"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	if cfg.tartaroOpsToken != "" {
		req.Header.Set("Authorization", "Bearer "+cfg.tartaroOpsToken)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, errors.New("role not in tartaro-ops catalog")
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("tartaro-ops %s: status %d", u, resp.StatusCode)
	}
	var out struct {
		Actions []string `json:"actions"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	return out.Actions, nil
}
```

- [ ] **Step 3: Skeleton stubs for runMigration / runValidate**

```go
func runMigration(ctx context.Context, cfg config, db *sql.DB, apply bool) error {
	cfg.logger.Printf("starting migration mode=%s", map[bool]string{true: "apply", false: "dry-run"}[apply])
	// next task fills the body
	return nil
}

func runValidate(ctx context.Context, cfg config, db *sql.DB) error {
	cfg.logger.Println("starting validate (no-op for now — next task implements)")
	return nil
}
```

- [ ] **Step 4: Compile**

```bash
cd /Users/dakasa/projects/yggdrasil/yggdrasil-core
go build ./scripts/migrate_tartaro_roles_to_actions/
```

Expected: clean.

- [ ] **Step 5: Commit (don't push — Phase 3 isn't deployed via CD anyway, but commit for tracking)**

```bash
git add scripts/migrate_tartaro_roles_to_actions/
git commit -m "✨ feat(migrate-tartaro): script skeleton + flags + role-actions fetcher

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>"
```

---

### Task 11: Migration script — `runMigration` (find-or-create teams, grants, memberships)

- [ ] **Step 1: Implement `runMigration` body**

```go
func runMigration(ctx context.Context, cfg config, db *sql.DB, apply bool) error {
	// 1. SELECT collaborators with non-empty tartaro_roles
	rows, err := db.QueryContext(ctx, `
		SELECT id, slug, COALESCE(traits->'tartaro_roles', '[]'::jsonb)::text AS roles_json
		FROM collaborators
		WHERE jsonb_array_length(COALESCE(traits->'tartaro_roles','[]'::jsonb)) > 0
	`)
	if err != nil {
		return fmt.Errorf("select collaborators: %w", err)
	}
	defer rows.Close()

	roleSets := map[string][]string{} // collab_id → roles
	collabSlugs := map[string]string{}
	for rows.Next() {
		var id, slug, rolesJSON string
		if err := rows.Scan(&id, &slug, &rolesJSON); err != nil {
			return err
		}
		var roles []string
		_ = json.Unmarshal([]byte(rolesJSON), &roles)
		roleSets[id] = roles
		collabSlugs[id] = slug
	}
	cfg.logger.Printf("found %d collaborators with tartaro_roles", len(roleSets))

	// 2. Resolve action sets per distinct role
	distinctRoles := map[string]struct{}{}
	for _, rs := range roleSets {
		for _, r := range rs {
			distinctRoles[r] = struct{}{}
		}
	}
	actionsForRole := map[string][]string{}
	for role := range distinctRoles {
		actions, err := fetchRoleActions(ctx, cfg, role)
		if err != nil {
			cfg.logger.Printf("WARN role=%s skipped: %v", role, err)
			continue
		}
		actionsForRole[role] = actions
		cfg.logger.Printf("resolved role=%s actions=%d", role, len(actions))
	}

	// 3. For each (role), find-or-create team + grants
	teamForRole := map[string]string{} // role → team_id
	for role := range actionsForRole {
		teamSlug := "tartaro-legacy-" + role
		var teamID string
		err := db.QueryRowContext(ctx, `SELECT id::text FROM teams WHERE slug = $1`, teamSlug).Scan(&teamID)
		if errors.Is(err, sql.ErrNoRows) {
			if !apply {
				cfg.logger.Printf("DRY-RUN: would create team %s", teamSlug)
				teamForRole[role] = "<dry-run>"
				continue
			}
			err = db.QueryRowContext(ctx, `
				INSERT INTO teams (slug, name, type, status)
				VALUES ($1, $2, 'role', 'active')
				RETURNING id::text
			`, teamSlug, "Tartaro Legacy: "+role).Scan(&teamID)
			if err != nil {
				return fmt.Errorf("create team %s: %w", teamSlug, err)
			}
		} else if err != nil {
			return err
		}
		teamForRole[role] = teamID

		// Grants
		for _, action := range actionsForRole[role] {
			var existsID string
			err := db.QueryRowContext(ctx, `
				SELECT id::text FROM team_grants
				WHERE team_id = $1::uuid
				  AND integration_instance_namespace = $2
				  AND integration_instance_name = $3
				  AND action_name = $4
			`, teamID, cfg.instanceNamespace, cfg.instanceName, action).Scan(&existsID)
			if errors.Is(err, sql.ErrNoRows) {
				if !apply {
					cfg.logger.Printf("DRY-RUN: would grant team=%s action=%s", teamSlug, action)
					continue
				}
				if _, err := db.ExecContext(ctx, `
					INSERT INTO team_grants (team_id, integration_instance_namespace, integration_instance_name, action_name)
					VALUES ($1::uuid, $2, $3, $4)
				`, teamID, cfg.instanceNamespace, cfg.instanceName, action); err != nil {
					return fmt.Errorf("grant team=%s action=%s: %w", teamSlug, action, err)
				}
			} else if err != nil {
				return err
			}
		}
	}

	// 4. For each (collab, role), find-or-create active membership
	for collabID, roles := range roleSets {
		for _, role := range roles {
			teamID, ok := teamForRole[role]
			if !ok {
				continue
			}
			var existsID string
			err := db.QueryRowContext(ctx, `
				SELECT id::text FROM team_memberships
				WHERE collaborator_id = $1::uuid AND team_id = $2::uuid AND active = true
			`, collabID, teamID).Scan(&existsID)
			if errors.Is(err, sql.ErrNoRows) {
				if !apply {
					cfg.logger.Printf("DRY-RUN: would add %s to team %s", collabSlugs[collabID], "tartaro-legacy-"+role)
					continue
				}
				if _, err := db.ExecContext(ctx, `
					INSERT INTO team_memberships (collaborator_id, team_id, role, active, source)
					VALUES ($1::uuid, $2::uuid, 'base-employee', true, 'tartaro-roles-migration')
				`, collabID, teamID); err != nil {
					return fmt.Errorf("add membership %s→%s: %w", collabSlugs[collabID], teamID, err)
				}
			} else if err != nil {
				return err
			}
		}
	}

	cfg.logger.Printf("DONE: users=%d roles=%d apply=%v", len(roleSets), len(actionsForRole), apply)
	return nil
}
```

> Adjust SQL column names if the actual teams/team_grants/team_memberships schema differs. Check with `\d teams; \d team_grants; \d team_memberships` if unsure.

- [ ] **Step 2: Build + unit test**

Add a basic test (mock the SQL where possible, or use real DB if available):

```go
// scripts/migrate_tartaro_roles_to_actions/main_test.go
package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestFetchRoleActions_OK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/internal/admin/roles/moderator/actions" {
			t.Fatalf("path: %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"role":"moderator","actions":["tartaro:moderate_post","tartaro:decide_report"]}`))
	}))
	defer srv.Close()
	cfg := config{tartaroOpsBaseURL: srv.URL}
	actions, err := fetchRoleActions(context.Background(), cfg, "moderator")
	if err != nil {
		t.Fatal(err)
	}
	if len(actions) != 2 {
		t.Fatalf("got %v", actions)
	}
}
```

```bash
go test ./scripts/migrate_tartaro_roles_to_actions/ -count=1
```

Expected: PASS.

- [ ] **Step 3: Commit**

```bash
git add scripts/migrate_tartaro_roles_to_actions/
git commit -m "✨ feat(migrate-tartaro): runMigration find-or-create teams/grants/memberships

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>"
```

---

### Task 12: Migration script — `runValidate`

- [ ] **Step 1: Implement runValidate**

```go
func runValidate(ctx context.Context, cfg config, db *sql.DB) error {
	rows, err := db.QueryContext(ctx, `
		SELECT id, slug, COALESCE(traits->'tartaro_roles', '[]'::jsonb)::text,
		       COALESCE(traits->'tartaro_actions','[]'::jsonb)::text
		FROM collaborators
	`)
	if err != nil {
		return err
	}
	defer rows.Close()

	driftCount := 0
	checked := 0
	roleActionsCache := map[string][]string{}
	for rows.Next() {
		var id, slug, rolesJSON, actionsJSON string
		if err := rows.Scan(&id, &slug, &rolesJSON, &actionsJSON); err != nil {
			return err
		}
		var roles, actualActions []string
		_ = json.Unmarshal([]byte(rolesJSON), &roles)
		_ = json.Unmarshal([]byte(actionsJSON), &actualActions)

		// Compute expected = UNION(roleActions(role) for role in roles)
		expected := map[string]struct{}{}
		for _, r := range roles {
			as, ok := roleActionsCache[r]
			if !ok {
				as, err = fetchRoleActions(ctx, cfg, r)
				if err != nil {
					cfg.logger.Printf("WARN role=%s skip: %v", r, err)
					continue
				}
				roleActionsCache[r] = as
			}
			for _, a := range as {
				expected[a] = struct{}{}
			}
		}
		expSlice := make([]string, 0, len(expected))
		for a := range expected {
			expSlice = append(expSlice, a)
		}

		if !sameStringSet(actualActions, expSlice) {
			driftCount++
			cfg.logger.Printf("DRIFT collab=%s slug=%s expected=%v actual=%v", id, slug, expSlice, actualActions)
		}
		checked++
	}
	cfg.logger.Printf("validate: checked=%d drift=%d", checked, driftCount)
	if driftCount > 0 {
		return fmt.Errorf("%d users have drift between tartaro_roles and tartaro_actions", driftCount)
	}
	return nil
}

func sameStringSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	m := map[string]struct{}{}
	for _, s := range a {
		m[s] = struct{}{}
	}
	for _, s := range b {
		if _, ok := m[s]; !ok {
			return false
		}
	}
	return true
}
```

- [ ] **Step 2: Build + push Phase 3 (script lives in repo, deployed via CD will it ever build? no — it's a manual `go run`)**

```bash
go build ./scripts/migrate_tartaro_roles_to_actions/
```

Expected: clean.

```bash
git add scripts/migrate_tartaro_roles_to_actions/
git commit -m "✨ feat(migrate-tartaro): runValidate compares expected vs actual

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>"
git push origin main
```

---

## Phase 4: Tartaro-api refactor + cutover

### Task 13: `authz.Evaluate` rewrite (tartaro-api)

**Repo**: `/Users/dakasa/projects/dakasa/dakasa-tartaro-fe/backend/dakasa-tartaro-api`

**Files:**
- Modify: `internal/authz/client.go`
- Modify: `internal/authz/client_test.go`

- [ ] **Step 1: Read existing Evaluate**

```bash
grep -n "func .*Evaluate" internal/authz/*.go
```

- [ ] **Step 2: Write failing test**

```go
// internal/authz/client_test.go (append or new file)
func TestEvaluate_AllowWhenActionInTrait(t *testing.T) {
	ygg := &fakeYgg{
		collab: &security.YggdrasilCollaborator{
			Traits: map[string]any{"tartaro_actions": []any{"tartaro:moderate_post"}},
		},
	}
	c := &Client{yggdrasil: ygg, logger: zap.NewNop()}
	allowed, err := c.Evaluate(context.Background(), "u1", "tartaro:moderate_post", nil)
	if err != nil { t.Fatal(err) }
	if !allowed { t.Fatal("expected allow") }
}

func TestEvaluate_DenyWhenActionMissing(t *testing.T) {
	ygg := &fakeYgg{collab: &security.YggdrasilCollaborator{Traits: map[string]any{"tartaro_actions": []any{"tartaro:other"}}}}
	c := &Client{yggdrasil: ygg, logger: zap.NewNop()}
	allowed, _ := c.Evaluate(context.Background(), "u1", "tartaro:moderate_post", nil)
	if allowed { t.Fatal("expected deny") }
}

func TestEvaluate_DenyWhenTraitAbsent(t *testing.T) {
	ygg := &fakeYgg{collab: &security.YggdrasilCollaborator{Traits: map[string]any{}}}
	c := &Client{yggdrasil: ygg, logger: zap.NewNop()}
	allowed, _ := c.Evaluate(context.Background(), "u1", "tartaro:moderate_post", nil)
	if allowed { t.Fatal("expected deny when trait absent") }
}
```

> Adapt `fakeYgg`, `Client` constructor, and `security` import to existing patterns.

- [ ] **Step 3: Rewrite Evaluate**

```go
func (c *Client) Evaluate(ctx context.Context, collabID, action string, scope map[string]any) (bool, error) {
	collab, err := c.yggdrasil.GetCollaborator(ctx, collabID)
	if err != nil {
		c.logger.Warn("authz.Evaluate fetch collaborator failed",
			zap.Error(err), zap.String("collab", collabID))
		return false, err
	}
	if collab == nil {
		return false, nil
	}
	actions, _ := collab.Traits["tartaro_actions"].([]any)
	if len(actions) == 0 {
		c.logger.Info("evaluate: tartaro_actions empty or absent",
			zap.String("collab", collabID), zap.String("action", action))
		return false, nil
	}
	for _, a := range actions {
		if s, ok := a.(string); ok && s == action {
			return true, nil
		}
	}
	return false, nil
}
```

- [ ] **Step 4: Tests pass**

```bash
go test ./internal/authz/ -count=1
```

Expected: PASS.

- [ ] **Step 5: Commit (don't push — Phase 4 batches with the sweep)**

```bash
git add internal/authz/client.go internal/authz/client_test.go
git commit -m "♻️ refactor(authz): Evaluate reads traits.tartaro_actions

Replaces role-based check with action-level. tartaro_roles trait is
no longer consulted by Evaluate. The reactor maintains tartaro_actions
as the union of grants across the user's active teams.

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>"
```

---

### Task 14: Sweep `tartaro_roles` call sites across tartaro services

**Repos**: `dakasa-tartaro-fe/backend/{dakasa-tartaro-api,tartaro-review,tartaro-legal,tartaro-operations,tartaro-notify}`

- [ ] **Step 1: Inventory call sites**

```bash
cd /Users/dakasa/projects/dakasa/dakasa-tartaro-fe
grep -rn 'YggdrasilHasRole\|tartaro_roles\|Traits\["tartaro_roles"\]\|tartaroRoles' \
  backend/ --include="*.go" \
  | grep -v "/vendor/" \
  > /tmp/tartaro-roles-sweep.txt
cat /tmp/tartaro-roles-sweep.txt
```

Expected: list of N call sites. Annotate each with whether it's a permission check (replace) or a UI-label derivation (keep for now, separate concern).

- [ ] **Step 2: Migrate permission-check sites**

For each line that does `YggdrasilHasRole(collab, "moderator")`, replace with the corresponding action check:

```go
// Before
if !security.YggdrasilHasRole(collab, "moderator") {
    c.AbortWithStatus(http.StatusForbidden)
    return
}

// After
if !security.YggdrasilHasAction(collab, "tartaro:moderate_post") {
    c.AbortWithStatus(http.StatusForbidden)
    return
}
```

Use the role→action mapping from `tartaro-operations` (task 1's `roleActions` map). If a role gates multiple actions in the same handler, choose the most-specific or check ALL with `&&`.

For UI-label derivations (`if hasRole == "admin" { showAdminMenu }`), leave for V2 — adding a comment `// TODO V2: replace role label with action capability check`.

- [ ] **Step 3: Update existing tests**

Each test that mocked `tartaro_roles` now mocks `tartaro_actions`:

```go
// Before
traits := map[string]any{"tartaro_roles": []any{"moderator"}}

// After
traits := map[string]any{"tartaro_actions": []any{"tartaro:moderate_post", "tartaro:decide_report"}}
```

- [ ] **Step 4: Build all services**

```bash
for svc in dakasa-tartaro-api tartaro-review tartaro-legal tartaro-operations tartaro-notify; do
  echo "=== $svc ==="
  (cd backend/$svc && go build ./... && go test ./... -count=1 -short) || exit 1
done
```

Expected: all services clean.

- [ ] **Step 5: Commit + push Phase 4 to all repos**

```bash
git add backend/
git commit -m "♻️ refactor(tartaro): migrate permission checks to YggdrasilHasAction

Sweep of $(grep -c '' /tmp/tartaro-roles-sweep.txt) call sites across 5 tartaro services. UI-label
derivations preserved with V2 TODO. Each handler that gated on a role
now gates on the corresponding tartaro:* action.

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>"

git push origin main
```

- [ ] **Step 6: Wait for builds, bump all tartaro service deployments**

Per item #2 playbook, build the bump workflows for tartaro-api + tartaro-review + tartaro-legal + tartaro-operations + tartaro-notify (5 services). Apply, wait for rollouts. **Skip step 5 (tartaro-api bump) until step 7 (migration validate) passes.**

---

### Task 15: Run migration `--validate` then `--apply`

- [ ] **Step 1: Set up environment**

```bash
export YGGDRASIL_DB_URL='postgres://...'
export TARTARO_OPS_URL='https://tartaro-operations.dakasa.me'
export TARTARO_OPS_TOKEN='<bearer-token-from-yggdrasil-secrets>'
```

For DaKasa staging, pull DB URL from `yggdrasil-secrets`:

```bash
YGGDRASIL_DB_URL=$(kubectl get secret -n dakasa yggdrasil-secrets \
  -o jsonpath='{.data.DATABASE_URL}' | base64 -d)
```

- [ ] **Step 2: Run dry-run first**

```bash
cd /Users/dakasa/projects/yggdrasil/yggdrasil-core
go run ./scripts/migrate_tartaro_roles_to_actions/ -mode dry-run
```

Expected: list of would-create teams + grants + memberships. Eyeball for sanity.

- [ ] **Step 3: Run apply**

```bash
go run ./scripts/migrate_tartaro_roles_to_actions/ -mode apply
```

Expected: `DONE: users=N roles=M apply=true` with no errors.

- [ ] **Step 4: Wait for reactor catch-up (5 min cron + materialize)**

The migration creates team_grant + team_membership rows, which emit canon events. Adapter processes them, recomputes traits.

```bash
# Watch reactor activity
kubectl logs -n dakasa deploy/integration-tartaro-dakasa --since=10m | grep recomputed | wc -l
# Should approximately equal #migrated users
```

- [ ] **Step 5: Validate**

```bash
go run ./scripts/migrate_tartaro_roles_to_actions/ -mode validate
```

Expected: `validate: checked=N drift=0` and exit 0.

If drift > 0:
- Identify users with drift
- For each, POST `/api/v1/collaborators/{id}/sync-tartaro-actions` to re-emit
- Wait 30s, re-run validate

Block deploy of tartaro-api Evaluate refactor until validate is clean.

---

### Task 16: Ship tartaro-api with new Evaluate

- [ ] **Step 1: Bump tartaro-api deployment**

Per item #2 playbook, build bump workflow for `dakasa-tartaro-api` deployment with the SHA from Phase 4 Task 14 commit.

- [ ] **Step 2: Wait for rollout, sanity check**

```bash
kubectl get pods -n dakasa -l app=dakasa-tartaro-api
# all running on new SHA
```

```bash
# tartaro health endpoint
curl -sS https://tartaro-operations.dakasa.me/health
```

Probe Evaluate via an existing endpoint that gates on `tartaro:moderate_post`. With a valid session for a user known to have moderator action:

```bash
curl -sS -H "Authorization: Bearer <session>" \
  https://api.tartaro.dakasa.me/tartaro/moderation/posts?status=pending
```

Expected: 200 (or empty list) — not 403.

---

## Phase 5: Manual E2E + cleanup

### Task 17: Manual E2E runbook (operator-driven)

7 staging scenarios:

- [ ] **1. Post-migration sanity**: `curl GET /api/v1/collaborators/<known-user>/effective-tartaro-actions` — `drift=false`; trait actions match role→action expected mapping.

- [ ] **2. Grant action to team**: 
  ```bash
  curl -sS -X POST -H "Authorization: $YGGDRASIL_ADMIN_TOKEN" \
    "https://yggdrasil.dakasa.me/api/v1/teams/<team-id>/grants" \
    -d '{"integration_instance_namespace":"dakasa","integration_instance_name":"integration-tartaro-dakasa","action_name":"tartaro:moderate_post"}'
  ```
  Within 30s, all team members' `effective-tartaro-actions` include the action.

- [ ] **3. Add user to team**: POST `/team-memberships` — within 30s user's trait gains team's actions.

- [ ] **4. Remove user from team**: DELETE / PATCH membership.active=false — trait shrinks (preserves overlaps from other teams).

- [ ] **5. Revoke action from team**: DELETE `/api/v1/team-grants/{id}` — all members' traits shrink.

- [ ] **6. tartaro-api Evaluate probes**: known-allow + known-deny actions via curl to gated endpoints (moderation/posts, reports, etc) — match trait.

- [ ] **7. Force-sync outlier**: pick a user, manually mutate their trait to wrong state (PATCH `/collaborators/{id}/traits` with bogus actions), then `POST /sync-tartaro-actions` → `effective-tartaro-actions` shows `drift=false`.

---

## Self-review checklist (before merging)

- [ ] All 5 phases pushed to their respective `main` branches
- [ ] All affected deployments running new SHA in staging
- [ ] Migration `--validate` returned drift=0
- [ ] Manual E2E 7/7 scenarios pass
- [ ] No `tartaro_roles` reads outside the deprecated capabilities (verify with `grep` post-deploy)
- [ ] No dead_lettered reactions for `team_grant.*` or `team_membership.*` events

If any unchecked: file issue + stop. Don't move on to V2 work (UI for grants, wildcard expansion, role catalog cleanup) until V1 is stable for 24h+.
