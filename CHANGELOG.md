# Changelog

All notable changes to yggdrasil-core are documented here.

## [2.18.0] - 2026-05-28

### Changed
- **§14 RFC 7807 Problem+JSON migration: closed for auth/MFA/password handlers.** Phase 2B-core (commit `e202e3d`) migrated the universal `writeMappedError` / `writeJSONError` writers; Phase 2B-close lands the remaining 25 hand-rolled `writeJSON(w, status, map[string]any{...,"code":...})` sites in `auth.go`, `mfa.go`, `credentials.go`, and `middleware_credentials.go`. Every error response (4xx/5xx) on these handlers now emits `Content-Type: application/problem+json` with a stable dotted `code` field. Sites migrated:
  - `auth.go`: password-strength validation (handleAuthPasswordUpsert), MFA factor unavailable (login), TOTP-unavailable + invalid TOTP + recovery-code paths, MFA-required dotted-code on the 202 challenge envelope.
  - `mfa.go`: `requireEnvelope` (KEK missing → `auth.kek_not_configured`), `writeMFAEnrollRequired` (now Problem+JSON with enroll_url/expires_at/collaborator as extensions), `handleMFAEnrollRequest` missing email, `handleMFATOTPFinish` invalid TOTP, `handleMFAWebAuthnFinish` 501 stub.
  - `credentials.go`: setup-token invalid UUID, setup-commit token/password required + unknown_fields + password_too_weak (×2) + setup_token_invalid; password-change unauthenticated (×2) + invalid_current_password + mfa_not_enrolled + invalid_mfa + webauthn_not_implemented + password_too_weak + password_unchanged; password-reset reset_token_invalid + mfa_not_enrolled + webauthn_not_implemented + invalid_mfa + password_too_weak.
  - `middleware_credentials.go`: unauthenticated (×2) + mfa_enrollment_required + password_change_required.

### Added
- **11 new error codes** in `internal/httperr/problem.go` + `docs/error_codes.md` (`auth.mfa_invalid`, `auth.mfa_factor_unavailable`, `auth.webauthn_not_implemented`, `auth.password_too_weak`, `auth.password_unchanged`, `auth.password_change_required`, `auth.invalid_current_password`, `auth.setup_token_invalid`, `auth.reset_token_invalid`, `auth.kek_not_configured`, `input.unknown_fields`).
- **Typed-error mapping** in `codeFromError` for `mfa.ErrInvalidRecoveryCode` (→ `auth.mfa_invalid`) and `repository.ErrMFAEnrollTokenAlreadyConsumed` / `ErrMFAEnrollTokenExpired` (→ `auth.setup_token_invalid`).
- **Lint script** `scripts/lint-no-legacy-error-envelopes.sh` that hard-fails on regression in the §14-closed file set (auth/mfa/credentials/middleware_credentials) and warns on the pending file set (invites, saml, scim_admin, integration_webhook, workflow_runs, external_identities, team_sync, tartaro_actions, integration_type_sync). Wire into CI to lock the closure.
- **Phase 14 test suite** `controllers/httpapi/phase14_auth_problem_test.go` — 9 focused unit tests asserting the Problem+JSON wire shape on each migrated branch.

### Notes
- The MFA-required 202 response (handleAuthLogin mid-flow challenge) is intentionally NOT migrated to Problem+JSON because 202 Accepted is a success-class status; the `code` field on that body is now updated to use the canonical `auth.mfa_required` dotted form so surface-console's i18n table resolves it the same way it resolves errors.
- Surface-console i18n table (`src/lib/errors/i18n.ts`) extended with pt-BR + en-US translations for every new code; vitest now covers all 31 codes (up from 20) and the catalog drift-prevention assertion is updated accordingly.
- INTEGRATION_CONTRACT.md §14 updated with the migration status table and the regression guard snippet.

## [2.17.0] - 2026-05-28

### Added
- **§2.1 Phase 6: aggregate endpoints to kill the round-trip explosion**. The 2026-05-27 co-design audit identified four hotspots where surface-console fired 3-6 separate requests per page mount to merge data the BE could trivially denormalize. Phase 6 ships four aggregates:
  - `GET /api/v1/console/overview-summary` (gate: `yggdrasil:view_overview`, NEW) — replaces 6 queries on OverviewPage (collaborators + teams + saml SPs + scim clients + system health + audit). Single round-trip returns people/teams/identity counts, db+migration health, and the last 10 audit events. The 30s polling that previously fanned to health+audit collapses to one refetch.
  - `GET /api/v1/console/teams/{id}/edit-context` (gate: `view_teams`) — replaces 3 dataset-wide queries on TeamEditPage (fetchTeams + fetchCollaborators + fetchTeamMemberships). Returns team + parent_options (descendant filter applied server-side) + owner_candidates (capped at 500, with `member_of_this_team` pre-flagged) + active_memberships scoped to THIS team + per-member other_memberships for the DangerZone preview. The FE drops collectDescendants(), member-merge logic, and the helper maps.
  - `GET /api/v1/console/collaborators?enriched=true` (gate: `view_people`, existing handler extended) — replaces 3 queries on CollaboratorListPage (collaborators + teams + memberships). Each record carries denormalized `team_names[]`, `primary_role`, `last_login_at`, `mfa_enrolled`. The `?enriched=true` flag keeps the legacy shape default for CLI/ops callers; the FE refactor opts in.
  - `GET /api/v1/ops/surfaces/{id}/configure-context` (gate: `view_integrations`) — replaces 3 sequential dependent queries on the OpsIntegrationsPage configure modal (surface manifest + catalog list + catalog entry detail). Server-side catalog walker matches the surface id by plugin_name exact / entry exact / plugin_name substring. Returns surface + matched catalog entry + integration_type manifest + current instance in one envelope.
  - **NEW permission `yggdrasil:view_overview`** added to `ops_rbac_catalog.go`, `surface-console/lib/auth/permissions.ts`, AND `integration-yggdrasil-self/internal/adapter/spec.go` `action_catalog` (the source of truth for grantable permissions in TeamPermissionsBox). Drift-prevention test `TestConsoleRoutesUseCanonicalPermissions` now includes it.

### Notes
- Section-level visibility inside the overview aggregate is honoured by the existing `PermissionGate` wrappers on the FE; the BE returns the same counters regardless of section-specific permissions (the gate decides whether to render). If finer-grained section omission becomes desirable, the next cycle can shape the response per caller permission set.
- The `?enriched=true` flag is the opt-in for the new shape. Legacy callers without the flag keep the existing `{collaborators: [...]}` envelope unchanged.
- All four routes pass through `requireOpsPermissionFunc(perm, ...)` (the Phase 5 wrapper) and the existing `TestConsoleRoutesAreFullyMapped` / `TestOpsRoutesAreFullyMapped` drift-prevention assertions cover them.
- Surface-console refactor lands in the same cycle: OverviewPage, TeamEditPage, CollaboratorListPage, and the OpsIntegrationsPage configure modal each now do ONE request per page mount instead of the 3-6 they did before. Vitest fixtures updated accordingly (mocks added for the new aggregate URLs).

## [2.16.0] - 2026-05-28

### Added
- **§3.1 / §12 Phase 5B: backend RBAC enforcement extended to `/api/v1/ops/*` (22 routes, warn-only)**. The older console-style `/api/v1/ops/*` namespace — referenced by surface-console's `lib/ops/api.ts` for surfaces, workflow-runs, approvals, drift, catalog, system health, audit, and missing-MFA probes — was OUT of scope for Phase 5 and shipped with zero backend RBAC. Phase 5B wires every ops route through `server.requireOpsPermissionFunc(perm, handler)` using the same middleware as Phase 5. The single `YGGDRASIL_CONSOLE_RBAC_ENFORCE` env switch governs both namespaces, so the existing observation window covers both. Mapping mirrors `/api/v1/console/*`: surfaces and surface-targets gate on `view_integrations` / `manage_integrations`, workflow runs on `view_ops` / `manage_workflows`, approvals and drift on `view_ops` / `manage_workflows`, catalog on `view_integrations`, system/health on `view_ops`, audit on `view_audit`, missing-MFA on `view_people`. New drift-prevention test `TestOpsRoutesAreFullyMapped` mirrors `TestConsoleRoutesAreFullyMapped` so the regex-scanner safety net covers both namespaces.
- **Dedicated `yggdrasil:manage_secrets` permission (Phase 5B split)**. Secret read/rotate/disable/revoke/materialize routes (`/api/v1/console/secrets/*`) were previously gated by `manage_integrations`, coupling secret custody to integration provisioning. The Phase 5B split separates them because the blast radius differs: an integration admin can register a stripe instance with a `credentials_ref` URI WITHOUT inheriting the right to read the underlying cluster secret. Operators who need full custody now receive BOTH permissions; the default integration-admin role does not. The new constant lands in `controllers/httpapi/ops_rbac_catalog.go` (Go), `surface-console/src/lib/auth/permissions.ts` (TS), and `integration-yggdrasil-self/internal/adapter/spec.go` `action_catalog` (the source of truth for grantable permissions in TeamPermissionsBox). New `TestManageSecretsIsDistinctFromManageIntegrations` locks the split.

### Notes
- This cycle continues warn-only mode (`YGGDRASIL_CONSOLE_RBAC_ENFORCE` unset = `warn`). Same flip semantics as Phase 5 — observe `yggdrasil_console_rbac_denied_total{permission,mode="warn"}` for legit users, then flip to `enforce`. Runbook in `~/.claude/projects/-Users-dakasa-projects/memory/reference_phase5_rbac_enforce_runbook.md` applies unchanged.
- Existing god-mode (`yggdrasil:*`) and traits.yggdrasil_admin bypasses match any yggdrasil:* permission, so cluster admins are unaffected by the split.
- Secret-custody operators with only `manage_integrations` who relied on the old coupling MUST be granted the new `manage_secrets` permission before the enforce flip (warn-mode period exists precisely so this drift surfaces in metrics before it becomes a 403 storm).

## [2.15.0] - 2026-05-28

### Added
- **§3.1 / §12: backend RBAC enforcement on `/api/v1/console/*` (warn-only)**. The `requireOpsPermission` middleware existed as dead code (`//nolint:unused`) until this cycle — surface-console's `usePermission()` was the ONLY gating layer, which the 2026-05-27 co-design audit ranked as the #1 critical co-design finding. INTEGRATION_CONTRACT §12 (backend is authorization authority) is now enforced server-side. All 89 `/api/v1/console/*` routes are wrapped with `server.requireOpsPermissionFunc(perm, handler)`. Permission resolution reuses `repository.ResolveYggdrasilPermissions` so the BE check is byte-for-byte consistent with what `/api/v1/auth/session` returns to the SPA. Mode gated by `YGGDRASIL_CONSOLE_RBAC_ENFORCE`:
  - `warn` (default): missing permission → log + bump counter + set `X-RBAC-Warn: <permission>` response header + ALLOW through. Lets ops compare surface-console's `usePermission()` catalog against backend enforcement for 24-48h before flipping.
  - `enforce`: missing permission → HTTP 403 + Problem+JSON `code: permission.denied` + denial audit row. Same A7 CSRF rollout pattern.

  God-mode (`yggdrasil:*`) short-circuits the check. New metric family `yggdrasil_console_rbac_denied_total{permission,mode}` lets ops chart `rate(...{mode="warn"}[5m])` during observation. Drift-prevention test (`TestConsoleRoutesAreFullyMapped`) scans `server.go` and fails when a new console route lands without a permission wrapper.

### Notes
- This cycle ships in warn-only mode. After the 24-48h observation window converges (no false-positive warn bumps from legit users on stable workflows), flip `YGGDRASIL_CONSOLE_RBAC_ENFORCE=enforce` on the Deployment env to start returning 403 on missing permissions. Runbook: `~/.claude/projects/-Users-dakasa-projects/memory/reference_phase5_rbac_enforce_runbook.md`.
- Scope: 89 `/api/v1/console/*` routes. The 25 `/api/v1/ops/*` routes (older console-style namespace, also referenced by surface-console) are NOT yet wired — they're tracked as Phase 5B follow-up. Pre-Phase 5 audit posture had ZERO BE enforcement on either namespace; the console namespace was the primary FE entry point (humans), so it ships first.
- The `requireOpsPermission` middleware was previously documented as querying `role_permission_bindings`. That was a stub never wired to production; this cycle rewrites it to use `team_grants` via `ResolveYggdrasilPermissions` (the only production permission path).

## [2.14.0] - 2026-05-28

### Added
- **A6: SameSite=Strict default for the session cookie.** `writeAuthCookie` and `clearAuthCookie` now emit `SameSite=Strict` by default (was `Lax`). For an admin IDP this kills the broadest CSRF surface — the cookie won't ride any cross-site request, top-level navigations included. Operators can override via `AUTH_SESSION_COOKIE_SAMESITE` (Strict/Lax/None, case-insensitive); the third-party OAuth state cookie keeps Lax intentionally because the IdP callback is a cross-site navigation.
- **A7: Per-session CSRF token defense (warn-only enforce).** Per-session token derived as `base64url(HMAC-SHA256(YGGDRASIL_CSRF_HMAC_SECRET, session.id))` — stateless, deterministic, no migration. Surfaced via a non-HttpOnly `yggdrasil_csrf_token` cookie AND the `csrf_token` field on `GET /auth/session`. New `csrfMiddleware` (wired between session resolution and route dispatch) recomputes the HMAC and rejects mismatched/missing `X-CSRF-Token` headers on POST/PUT/DELETE/PATCH. Mode gated by `YGGDRASIL_CSRF_ENFORCE` (default `warn` so the surface-console rollout can ship its matching client without 403-storming production). New metric family `yggdrasil_csrf_rejected_total{outcome,mode}`.
- **A10: Per-client OIDC AccessTokenLifetime override.** Migration 00048 adds nullable `oidc_clients.access_token_lifetime_seconds` (CHECK bounded to [60, 86400]). NULL = use the global 15-minute default; positive int = use that lifetime in seconds. Admin endpoint `PATCH /api/v1/admin/oidc-clients/{id}` (admin-token auth) lets operators set/clear the override per client; high-trust clients can opt down to 60–300s so a leaked JWT is short-lived. The override flows through `clientView.AccessTokenLifetime()` and is read fresh per request — no clientView caching.

### Fixed
- **A9: hardened OIDC redirect_uri exact-match guarantee.** Pinned the existing protection (zitadel/oidc/v3's `slices.Contains` validator + our clientView NOT implementing `op.HasRedirectGlobs`) with a 7-test suite covering attacker URI families (prefix attacks, host suffix attacks, scheme downgrades, double-slash hijacks, protocol-relative URIs, `javascript:` pseudo-schemes, path/query/fragment append fuzz) plus a sentinel that breaks if a future refactor adds glob support to clientView. Also documented the security rules in `storage.go::RedirectURIs`. No production code change — the protection was already correct; this commit prevents regression.

### Notes
- A7 ships in warn-only mode. The matching `X-CSRF-Token` emission lands in surface-console (separate cycle); after that rolls, flip `YGGDRASIL_CSRF_ENFORCE=enforce` on the Deployment env to start returning 403 + Problem+JSON on missing/invalid tokens.
- A10 admin endpoint is PATCH-only — full OIDC client lifecycle (create/delete) stays out of scope for the audit. Clients are still bootstrapped via manifests / direct `UpsertOIDCClient` calls.

## [2.9.2] - 2026-05-27

### Added
- **Adapter-declared reactors** (`AdapterDescribeResponse.Reactors`). Adapters can now declare their canonical reactor subscriptions in `Describe()` instead of operators having to POST `spec.reactors[]` to the manifest catalog after registration. `integrationTypeSpecFromDescribeResponse` carries `response.Reactors` through to the live spec, and `manifestsync.MergeSpec` adopts them when the current spec has no operator-managed reactors. Operator overrides still win when explicitly set — initial registration / fresh sync seeds from the adapter, post-override the operator's value is preserved verbatim.

### Notes
- Backwards-compatible: adapters that don't emit `reactors[]` continue to work; only adapters that opt in to the new field get auto-seeded reactor subscriptions on registration.

## [2.9.1] - 2026-05-27

### Fixed
- **Workflow status normalization accepts `executed`** (Phase 2C follow-up). The bootstrap workflow `oidc-client-set-backchannel-logout-uri` (database-admin-postgres `execute_sql`) returned cosmetic `failed` even though the SQL UPDATE succeeded (`rows_affected: 1`). `executed` now collapses to the success bucket alongside `committed`/`applied`/`created` in `controllers/message/workflows.go::normalizeWorkflowIntegrationStatus`. Same semantics — the state change landed.

## [2.9.0] - 2026-04-25

### Added
- **Audit trail** (`/api/v1/audit`). New table `audit_events` with fields actor, action, resource_kind, resource_id, outcome, tenant_slug, metadata, trace_id, span_id, created_at. `GET /api/v1/audit?actor=&action=&resource_kind=&resource_id=&tenant=&since=&until=&limit=` queries with AND-combined filters; default limit 100, capped 1000. `manifest.create` now emits an audit event on every POST `/api/v1/manifests` (success and error).
- **Workflow template instantiation** (`POST /api/v1/workflow-templates/{namespace}/{name}/instantiate`). Substitutes `{{ params.<name> }}` placeholders in the template body with caller-supplied `params` (validates required params, applies defaults, rejects unknown placeholders). When `apply=true`, the rendered workflow manifest is created server-side and returned as a manifest record; when `apply=false` (default), the rendered shape is returned without persistence so callers can preview.
- **`yggdrasil_manifest_applies_total` counter** now bumps on every successful manifest create (was wired in v2.4.0 but not actually called).
- **Migration `00017_audit_events`** with btree indexes for the common query patterns (recent first, by actor, by resource, by tenant).

### Notes
- Audit insertion is fire-and-forget in a goroutine; failures are logged via the server logger but never gate the user's request. Audit is observability, not business logic.
- Tracecontext propagation through adapter calls (W3C `traceparent` header forwarding into AdapterExecuteIntegrationRequest) is still v2.9.x — webhook handler and audit table already record the inbound `traceparent` when present.
- TTL reaper goroutine for `ephemeral_environment` and Postgres advisory-lock leader election ship in v2.9.x patches; the data shapes are stable as of v2.2.0 / v2.3.0 respectively.

## [2.8.1] - 2026-04-25

### Fixed
- **Renderer no longer overwrites `Namespace.metadata.labels.app.kubernetes.io/part-of`** (D2). Yggdrasil's renderer used to emit the namespace with `app.kubernetes.io/part-of=yggdrasil`, but the higher-level platform managing the namespace may classify it differently (e.g. `=dakasa` for a DaKasa-style ecosystem). When the platform also installs a NetworkPolicy keyed on its own `part-of` value, the renderer's label silently broke the egress rule on every reconcile. The renderer now emits only `app.kubernetes.io/managed-by=yggdrasil-core` on the Namespace; cluster admins or higher-level platforms own the rest of the namespace's labels.
- **Dockerfile cross-compile support** (D1). Renamed/replaced the build with `BUILDPLATFORM` + `TARGETARCH` ARGs so Go cross-compiles natively on the build host instead of running through qemu. Fixes `go: error obtaining buildID for go tool compile: signal: segmentation fault (core dumped)` when building on Apple Silicon for `linux/amd64`.

### Notes
- D3 (Postgres healthcheck noise: `database "superuser" does not exist`) was a `pg_isready` probe missing `-d postgres` in the StatefulSet pod template. Fixed in the prod cluster's StatefulSet manifest, not in core (Postgres is a cluster-side concern, not Yggdrasil renderer-managed). The renderer-emitted bundled-Postgres profile already passes `-d postgres`; the bug existed only in the legacy hand-rolled StatefulSet predating Phase 14.

## [2.8.0] - 2026-04-25

### Added
- HA roadmap published. Adopter documentation describes the path to multi-replica yggdrasil-core with leader election, idempotent workflow_run creation, and zero-downtime rolling upgrades.

### Notes
- Implementation lands in v2.8.x patches: (1) Postgres advisory-lock-based leader election for the workflow scheduler ticker; (2) idempotency_key honoured on `POST /api/v1/workflow-runs`; (3) k8s deploymentmanifests configurable for replicas≥3 + PDB; (4) benchmark suite for p50/p95/p99 latency on manifest apply, workflow dispatch, webhook → run start.
- v2.8.0 is the **last v2 minor**. v3.0 introduces RBAC enforcement default-on (current opt-in via `YGGDRASIL_TENANCY_ENFORCED`) and OpenAPI generation from handler annotations.

## [2.7.0] - 2026-04-25

### Added
- Console UI roadmap published. The `surface-console` repo gains its first deploy with this minor; the bundled UI surfaces dashboard, manifests browser, workflow run viewer, audit log (when v2.4.x audit ships), ephemeral envs list, and repository_bindings.

### Notes
- The UI itself ships from the **`surface-console` companion repo** with its own release cycle (v0.x.0). The core in v2.7.0 is unchanged from v2.6.0; this version bump signals that the console is officially supported.
- Auth uses the same OIDC flow exposed at `/api/v1/auth/third-party/*`. Multi-tenant aware (filters listings by caller's authorised tenants when `YGGDRASIL_TENANCY_ENFORCED=true`).
- Live updates use SSE in v2.7.0 (WebSocket support is a v3 enhancement).

## [2.6.0] - 2026-04-25

### Added
- New manifest kind `workflow_template`. Declares a parameterised workflow with `display_name`, `description`, `category`, `tags`, `authors`, `params` (typed input declarations: string/integer/number/boolean/array/object), `body` (workflow shape with `{{ params.<name> }}` placeholders), and `version`.
- Validation: display_name + body required; param types must be one of the supported six; a param cannot be both required and have a default (contradictory).
- Normalisation: trims whitespace; defaults `version` to `v0.1.0`.
- Adopters POST templates via the generic `POST /api/v1/manifests?kind=workflow_template`. The companion CLI/console will add discovery and instantiation in v2.6.x.

### Notes
- Template instantiation (substituting `{{ params.* }}` and posting the resulting workflow) is currently adopter-side. v2.6.x adds a server endpoint `POST /api/v1/workflow-templates/{ns}/{name}/instantiate`. The data shape is stable in v2.6.0.

## [2.5.0] - 2026-04-25

### Added
- (none in core) — see companion `yggdrasil/yggdrasil` repo for the v2.5 CLI release. The CLI ships on its own cadence; this version bump in the core simply syncs the major.minor with the v2.x roadmap.

### Notes
- v2.5.0 of the **CLI** ships these adopter-visible changes (handled in the companion repo, not here):
  - Shell completion (`yggdrasil completion bash|zsh|fish`).
  - Friendly error messages on empty results (`yggdrasil get integration-instance` returns "no integration-instance manifests found in namespace X" instead of an empty stdout).
  - `--output yaml|json|table` consistency across all `get` subcommands.
  - `yggdrasil whoami` to show the current auth context.
  - Verb-noun structure cleanup; dropped flags renamed with deprecation aliases for one minor.

### Compatibility
- The HTTP API surface in v2.5.0 of the core is **identical** to v2.4.0. Existing CLI binaries continue to work.

## [2.4.0] - 2026-04-25

### Added
- `GET /metrics` endpoint serving Prometheus text exposition format (no auth, no external deps).
- Counters: `yggdrasil_workflow_runs_total{status}`, `yggdrasil_webhook_events_total{outcome}`, `yggdrasil_manifest_applies_total`, `yggdrasil_secret_lookups_total`.
- Gauges: `yggdrasil_uptime_seconds`, `yggdrasil_goroutines`, `yggdrasil_memory_bytes`.
- Webhook handler instrumented to increment `yggdrasil_webhook_events_total` on every branch (skipped / failed / accepted).

### Notes
- Audit trail (`/api/v1/audit`) and W3C tracecontext propagation across core+adapters land in v2.4.x patches. The data shape and metric names in v2.4.0 are stable; later patches expand instrumentation coverage without changing the public surface.
- v3 will switch to `prometheus/client_golang` (histograms with `le` buckets, native scrape negotiation). The current text-format implementation is dependency-free for adopters who do not run Prometheus.

## [2.3.0] - 2026-04-25

### Added
- New manifest kind `tenant`. Declares a top-level tenancy scope with slug, display_name, owners, billing_ref, quotas, and metadata. Slug validates against `^[a-z0-9][a-z0-9-]{0,61}[a-z0-9]$` (2-63 chars, lowercase alphanumeric + hyphens). Owners must be `user:<id>`, `team:<name>` or `service:<name>`. Quotas must be non-negative (0 = no cap).
- Other manifests can carry `metadata.tenant: <slug>` informationally in v2.3.0; v3.0 makes enforcement default-on.
- `YGGDRASIL_TENANCY_ENFORCED=true` env var opts into RBAC enforcement: list endpoints filter by caller's tenants, write endpoints reject mismatched tenants, quota ceilings produce 429. Default (unset/`false`) preserves v2.2 behaviour.
- `docs/tutorials/05-multi-tenancy.md` — adoption walkthrough.

### Notes
- This phase ships the **data shape** and **opt-in flag**. Quota counters and write-time enforcement land in v2.3.x patches as adopter feedback comes in. v3.0 flips `YGGDRASIL_TENANCY_ENFORCED` default to `true`.

## [2.2.0] - 2026-04-25

### Added
- New manifest kind `ephemeral_environment`. Declares a time-bounded environment with `create_workflow`, `destroy_workflow`, `ttl_seconds`, `auto_destroy`, optional `cost_projection`, and free-form `metadata`. Adopters POST one per PR / nightly env / demo env; the create_workflow runs at apply time and destroy_workflow at TTL expiry.
- Validation: TTL must be 0 (no expiry) or ≥ 60 seconds; `auto_destroy` requires `destroy_workflow`; cost values must be non-negative.
- Normalisation: `workflow_ref.namespace` defaults to `global`; `cost_projection.currency` defaults to `USD`.
- `docs/tutorials/04-ephemeral-envs.md` — end-to-end tutorial.

### Notes
- TTL reaper goroutine ships in v2.2.x (next patch). Until then, schedule the destroy workflow externally on TTL expiry. The data shape and validation are stable in v2.2.0.

## [2.1.0] - 2026-04-25

### Added
- `GET /openapi.json` — serves the bundled OpenAPI 3 spec describing the public REST surface (no auth). External tools can fetch and discover the API contract.
- `docs/quickstart.md` — 12-step walkthrough from clean k3s to a working webhook → workflow → deploy pipeline. Target: 60 minutes for a competent platform engineer who has never seen Yggdrasil.
- `docs/api-reference/openapi.json` — hand-curated OpenAPI 3 spec (~12 endpoints across health, manifests, integrations, workflows, webhooks, secrets, products).
- `docs/api-reference/openapi.md` — narrative companion explaining manifest envelope, workflow templating language (`{{ inputs.* }}`, `{{ steps.* }}`, `{{ push.* }}`), webhook signature verification, skip semantics, error envelope, auth model, idempotency, and compatibility commitments.
- `docs/api-reference/README.md` — endpoint index for quick lookup.
- `docs/tutorials/01-webhook-cd.md` — wire a real service repository to declarative CD via `repository_binding`.
- `docs/tutorials/02-custom-adapter.md` — build and deploy a custom integration adapter (Datadog event poster as worked example).
- `docs/tutorials/03-secret-store.md` — migrate inline credentials to the managed secret store with rotation.
- `docs/tutorials/README.md` — tutorial catalogue.

## [2.0.0] - 2026-04-25

### BREAKING
- `POST /api/v1/products/{namespace}/{name}/deploy`, `POST /api/v1/products/deploy-all`, `POST /api/v1/bootstrap`, and the `/api/v1/console/products/...` mirrors now return `410 Gone`. CD goes through `kind: repository_binding` manifests with a `spec.deploy` block; the GitHub webhook handler dispatches the declared workflow.
- Package `provisioner/` removed (`KustomizeDeployer` deleted). The `deploy-via-kustomize-source` workflow (using `integration-kustomize` + `integration-kubernetes`) is the supported deploy primitive.
- `addons/deployer.go` removed. The `deployer` resource and `httpapi.WithDeployer` option are gone.
- `REPO_BASE_PATH` environment variable is no longer read; remove from your deployment configuration.
- Webhook handler no longer falls back to a hardcoded `repoProductMap`. Pushes from repositories without a `repository_binding` return `200` with `status=skipped`.

### Added
- `repository_binding.spec.deploy` field with `workflow_kind`, `workflow_ref`, `default_inputs`, `branch_filter`, `path_filter`. The GitHub webhook handler consults this field to dispatch Yggdrasil workflows on push events.
- Push event templating in `default_inputs`: `{{ push.repository.full_name }}`, `{{ push.repository.clone_url }}`, `{{ push.ref }}`, `{{ push.head_commit.id }}`, `{{ push.head_commit.message }}`, `{{ push.pusher.name }}`. Non-string values pass through unchanged; unknown placeholders return error; non-`push.*` placeholders pass through verbatim.
- Database indexes `manifests_repository_binding_lookup` (lookup) and `manifests_repository_binding_unique_repo` (one binding per repo).
- `repository.FindBindingByRepository` Go function for binding lookup by repository slug.
- `branch_filter` and `path_filter` on `repository_binding.spec.deploy` (glob via `path/filepath.Match`; `*` accepts any branch).
- `workflow_kind: github_actions` is reserved (returns `501 Not Implemented` in 2.0.0; future expansion).

### Removed
- `provisioner/kustomize.go` (entire `KustomizeDeployer`, `locatorMap`, `LocatorToLocalPath`).
- `addons/deployer.go` (constructor wiring).
- `controllers/httpapi/github_webhook.go` `repoProductMap` and `repoToProduct`.
- `controllers/httpapi/server.go` `deployer` field and `WithDeployer` option.

### Migration
See `dakasa-system/docs/runbooks/yggdrasil-v2-cutover.md` for the operator playbook. Apply 17 deploy bindings + 3 observe-only bindings before flipping the control_plane image to v2.0.0; no behavioural change at cutover beyond the granularity of "push to repo X deploys repo X" replacing "push to any repo in product P deploys all of P".

## [Unreleased]

### Changed
- Integration type seeds refreshed to reflect live HTTP-transport state (github, kubernetes, aws, manifest-sources-kustomize). Greenfield deployments now bootstrap with the correct schemas — no contract_mismatch on first run after the adapters connect.

### Added
- `control_plane.spec.name` — override default resource names (`yggdrasil-core`) so in-place updates of legacy deployments are possible.
- `control_plane.spec.image_pull_secrets` — list of Kubernetes Secret names mounted as `podSpec.imagePullSecrets`.
- `control_plane.spec.pull_policy` — enum `Always|IfNotPresent|Never`, propagated to `container.imagePullPolicy`.
- `control_plane.spec.extra_env_from` — array of `{secret_ref|config_map_ref}` entries added to the core container's `envFrom`.
- `control_plane.spec.annotations` — map merged into `Deployment.spec.template.metadata.annotations`.
- `control_plane.spec.labels` — map merged into `Deployment.spec.template.metadata.labels` alongside `baseLabels`.
- `control_plane.spec.postgres.mode=inherit` — skip Postgres infra rendering when credentials are supplied via `extra_env_from`.

### Changed
- `Render` now returns an error when `spec.Postgres.Mode == "external"` and `password_ref` is missing or not a `secret://` reference (previously silently emitted an incomplete envFrom).

### Fixed
- Validator now emits distinct errors for empty-pointer vs fully-absent `extra_env_from` entries, and rejects blank names on either `secret_ref` or `config_map_ref`.
- `spec.name` regex now enforces the DNS-1123 label 63-char limit.
