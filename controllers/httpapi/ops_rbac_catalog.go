package httpapi

// Phase 5 RBAC wiring — audit 2026-05-27 §3.1.
//
// This file maps every /api/v1/console/* route to the canonical
// yggdrasil:* permission that gates it. Permission names match
// surface-console's PERMS catalog (lib/auth/permissions.ts) one-for-one,
// which in turn matches the integration-yggdrasil-self action_catalog
// (internal/adapter/spec.go).
//
// Drift-prevention strategy: when a new console route is added, the
// reviewer MUST add the corresponding entry here. Routes that lack a
// permission entry default to wide-open (anonymous IF
// requireAuthenticatedConsoleAPIs lets them through, but in production
// that gate always requires a session), exactly the pre-Phase-5 state.
// To catch drift, a TestConsoleRoutesAreFullyMapped test scans
// server.go and fails when a /api/v1/console/* registration lacks a
// permission wrapper.
//
// Permission catalog (19 entries — canonical, single source):
//   - ViewPeople            yggdrasil:view_people
//   - CreateCollaborator    yggdrasil:create_collaborator
//   - EditCollaborator      yggdrasil:edit_collaborator
//   - OffboardCollaborator  yggdrasil:offboard_collaborator
//   - IssueSetupToken       yggdrasil:issue_setup_token
//   - ViewTeams             yggdrasil:view_teams
//   - CreateTeam            yggdrasil:create_team
//   - EditTeam              yggdrasil:edit_team
//   - ManageTeamPermissions yggdrasil:manage_team_permissions
//   - ViewIntegrations      yggdrasil:view_integrations
//   - ManageIntegrations    yggdrasil:manage_integrations
//   - ManageSecrets         yggdrasil:manage_secrets       ← Phase 5B split
//   - ViewAudit             yggdrasil:view_audit
//   - ManageAuthProviders   yggdrasil:manage_auth_providers
//   - ViewOps               yggdrasil:view_ops
//   - ManageWorkflows       yggdrasil:manage_workflows
//   - ManageOrganization    yggdrasil:manage_organization
//   - ViewOverview          yggdrasil:view_overview        ← Phase 6 aggregator
//   - (god mode)            yggdrasil:*  ← handled inside the middleware
//
// Mapping principles:
//   - GET → view:<area>
//   - POST/PATCH/DELETE → manage:<area> (the "edit_" naming in the catalog)
//   - operations on lifecycle (suspend/offboard/role-change/…) → the most
//     specific permission available (e.g. offboard_collaborator)
//   - secrets read/rotate/disable/revoke/materialize → manage_secrets
//     (HIGH-risk: distinct from manage_integrations because read/rotate
//     cluster secrets has a different blast radius than provisioning
//     integration instances — Phase 5B split.)
//   - repository_bindings / provision / bootstrap → manage_integrations
//     (these are integration-adjacent infrastructure but NOT secret
//     custody)
//   - guardian/remediation → manage_workflows (they ARE workflow primitives)
//   - reconciler → view_ops (read-only)
//   - permissions endpoints → manage_team_permissions
//   - oidc-clients endpoints → manage_auth_providers
//   - audit / audit list → view_audit
//   - ops/* mirrors console/* equivalents (Phase 5B): surfaces = view/manage
//     integrations; workflow runs = view_ops / manage_workflows; approvals,
//     drift, catalog, system/health, audit → most-specific perm.

// Permission constants — keep aligned with surface-console PERMS.
const (
	permViewPeople            = "yggdrasil:view_people"
	permCreateCollaborator    = "yggdrasil:create_collaborator"
	permEditCollaborator      = "yggdrasil:edit_collaborator"
	permOffboardCollaborator  = "yggdrasil:offboard_collaborator"
	permIssueSetupToken       = "yggdrasil:issue_setup_token"
	permViewTeams             = "yggdrasil:view_teams"
	permCreateTeam            = "yggdrasil:create_team"
	permEditTeam              = "yggdrasil:edit_team"
	permManageTeamPermissions = "yggdrasil:manage_team_permissions"
	permViewIntegrations      = "yggdrasil:view_integrations"
	permManageIntegrations    = "yggdrasil:manage_integrations"
	permManageSecrets         = "yggdrasil:manage_secrets"
	permViewAudit             = "yggdrasil:view_audit"
	permManageAuthProviders   = "yggdrasil:manage_auth_providers"
	permViewOps               = "yggdrasil:view_ops"
	permManageWorkflows       = "yggdrasil:manage_workflows"
	permManageOrganization    = "yggdrasil:manage_organization"
	// Phase 6 aggregator (audit 2026-05-27 §2.1): the OverviewPage aggregate
	// reaches into 6 separate subsystems (people, teams, identity providers,
	// system health, recent audit) and would otherwise require every viewer
	// to own all six view_* permissions. The single view_overview keeps
	// the "I'm allowed to see the homepage" decision in one place; the
	// aggregate handler still respects the visibility of individual
	// sections by data-shaping (sections omitted when their owning
	// permission is missing — see console_overview_summary.go).
	permViewOverview          = "yggdrasil:view_overview"
)
