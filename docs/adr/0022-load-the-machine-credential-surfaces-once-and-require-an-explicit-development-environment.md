# ADR-0022: Load the machine credential surfaces once and require an explicit development environment

- **Status:** Accepted
- **Date:** 2026-09-24
- **Deciders:** DaKasa Platform
- **Scope:** yggdrasil-core / workflow-run, event and directory machine authentication (`/api/v1/workflow-runs`, `/api/v1/events`, manifest writes, directory reads)
- **Supersedes:** none
- **Superseded by:** none

## Context

ADR-0017 introduced hashed workflow machine principals
(`YGGDRASIL_WORKFLOW_MACHINE_PRINCIPALS_JSON`) next to a plaintext, expiring
migration bridge (`YGGDRASIL_WORKFLOW_RUN_TOKEN` with
`YGGDRASIL_WORKFLOW_RUN_LEGACY_ENABLED` and
`YGGDRASIL_WORKFLOW_RUN_LEGACY_EXPIRES_AT`). ADR-0021 loaded the event
publisher surface once at start and refused a set-but-blank event inventory.
The workflow surface was left behind, and dakasa-system ADR-0286, which
retires the workflow bridge, depends on closing the gaps below first.

1. **Per-request parsing, silent refusals.** The workflow inventory and the
   bridge settings were parsed from the environment on every request. A
   malformed inventory produced no log line: the outer gate discarded the
   parse error and every machine caller got a plain `401`.
2. **A blank inventory meant "no principals".** An ExternalSecret key that
   resolved to an empty string read as "unconfigured".
3. **The anonymous posture followed from that.** Outside
   `YGGDRASIL_ENV=production|prod`, a Core with no workflow credential
   configured accepted anonymous workflow dispatch of any workflow without
   `spec.authorization`, unscoped polling and anonymous manifest writes. The
   event surface had the same rule. DaKasa production runs with
   `YGGDRASIL_ENV` unset: setting `production` would fail boot, because the
   CSRF and OAuth-state secrets `validateBootSecrets` requires are not
   configured there. Only the configured bridge and principals kept that
   posture closed. Once the bridge is retired, a blank or missing inventory
   would open anonymous dispatch on the production control plane.
4. **Refused bridge settings locked principals out.** A bridge error (for
   example the token still present after `LEGACY_ENABLED` was deleted)
   returned before principal matching, so a half-applied retirement answered
   `401` to every machine caller. The event path already kept these apart.
5. **Cross-scope collisions were checked only in production boot.** With
   `YGGDRASIL_ENV` unset nothing compared workflow, event and directory
   digests with each other or with the plaintext credentials. The directory
   gate runs before every other credential family and claims any bearer whose
   digest matches a directory principal.
6. **Bridge use left no trace.** No log line, metric or audit row recorded a
   request the bridge authenticated, so nobody could prove the bridge was
   unused before deleting its key.

## Decision

Core loads the machine credential surfaces once, refuses what it cannot
trust, keeps each refusal to its own surface, and grants the credential-free
posture only to an explicitly named development environment.

1. **Refuse a blank workflow inventory.** `workflowMachinePrincipalsFromEnv`
   refuses `YGGDRASIL_WORKFLOW_MACHINE_PRINCIPALS_JSON` when it is present but
   blank, as the event loader does. Only a truly unset variable means "no
   principals". `null` and `[]` stay refused.
2. **Load once.** The workflow surface (`workflowRunAuthConfig`: principals,
   a refusal `err`, the bridge settings and a separate bridge refusal
   `legacyErr`) is parsed once. `New` fills it eagerly. A `Server` built as a
   literal (tests only) fills it once, on first use, from the environment of
   that moment, and a literal that already carries one keeps it. The gate, the
   dispatch and poll handlers and the manifest-write check share that copy.
   Only the bridge expiry is evaluated per request.
3. **Cross-scope collisions refuse the colliding surface, in every
   environment.**
   - A workflow digest equal to a directory digest, an event digest, or the
     SHA-256 of the trimmed `YGGDRASIL_WORKFLOW_RUN_TOKEN`,
     `YGGDRASIL_EVENT_PUBLISH_TOKEN`, `YGGDRASIL_DEPLOY_TOKEN` or
     `YGGDRASIL_AUTH_ADMIN_TOKEN` refuses the workflow surface: every machine
     request to the workflow-run routes answers `401`.
   - A directory digest equal to an event digest or to one of those
     plaintexts refuses the directory surface without stopping boot. `New`
     serves an empty directory inventory, so the bearer reaches its own scope
     instead of the directory branch's `403`, and directory reads answer
     `401` until the inventory is fixed. A malformed directory inventory still
     stops boot (ADR-0019).
   - Production boot validation keeps refusing every collision, as before.
4. **Boot lines.** `New` logs one error line per refusal (workflow inventory,
   bridge settings, directory collision) and always one info line,
   `workflow run credential surface loaded`, with `principals`, `usable`,
   `principal_ids`, `earliest_expiry`, `workflow_refused`,
   `legacy_configured`, `legacy_active`, `legacy_expires_at`,
   `legacy_refused`, `anonymous_allowed` and `directory_refused`. No line
   carries a credential or a digest.
5. **Order of checks.** Refused bridge settings never lock a principal out,
   and a refused inventory never falls into the anonymous posture:

   ```mermaid
   flowchart TD
     A[request to a workflow-run route] --> B{console claims?}
     B -- yes --> H[collaborator actor]
     B -- no --> C{workflow surface refused?}
     C -- yes --> U[401]
     C -- no --> D{bearer matches an active, unexpired principal?}
     D -- yes --> P[service principal actor]
     D -- no --> E{bridge settings refused?}
     E -- yes --> U
     E -- no --> F{bridge active and bearer matches it?}
     F -- yes --> L[legacy actor: logged, counted, audited]
     F -- no --> G{nothing configured, no credential presented, explicit development YGGDRASIL_ENV?}
     G -- yes --> N[anonymous development actor]
     G -- no --> U
   ```

6. **The credential-free posture needs an explicit development
   environment.** Anonymous workflow dispatch and polling, anonymous manifest
   writes (which go through the same check) and anonymous event publishing
   require `YGGDRASIL_ENV`, trimmed and lowercased, to be one of `dev`,
   `development`, `local` or `test`, on top of an unconfigured surface. An
   unset or any other value keeps them closed. `devEnvAllowsFallback` is
   unchanged, so the CSRF, OAuth-state and deploy-token development fallbacks
   are out of scope here.
7. **Bridge use is observable and durable.** Every request the bridge
   authenticates, counted in the dispatch and poll handlers only (never twice
   through the gate), leaves:
   - a warning line `legacy workflow-run bridge accepted` with `route`
     (`dispatch` or `poll`), the workflow (`namespace/name` or the manifest
     id) or the run id, the subject, `user_agent` (at most 128 bytes) and
     `remote_ip`;
   - one bump of `yggdrasil_workflow_run_legacy_bridge_requests_total{route}`;
   - an `audit_events` row: actor the bridge subject
     (`service:legacy-workflow-run-token` unless renamed), action
     `workflow_run.legacy_bridge`, resource kind `workflow` or
     `workflow_run`, resource id the workflow or the run id, outcome
     `accepted`, metadata `{route, user_agent, remote_ip}`. Dispatches are
     always audited; polls are logged and audited once per run id per
     process, in a set bounded at 4096 ids and cleared when full. The write is
     synchronous with a 2 second bound and best effort: a failure bumps
     `yggdrasil_workflow_run_legacy_bridge_audit_failures_total`, is logged,
     and the request is still served;
   - on an asynchronous dispatch, the reserved run metadata
     `yggdrasil.io/creator_legacy_workflow_bridge=true`. The server always
     drops a client value for that key. Synchronous runs are not persisted in
     `workflow_runs`, so for them the audit row is the record.
8. **Local and test postures.** The package tests set `YGGDRASIL_ENV=test`
   in `TestMain` when the runner left it unset; tests that assert the closed
   posture set or unset it themselves. The repository compose files set
   `YGGDRASIL_ENV` to `development` (overridable where the file reads `.env`).
   The `yggdrasil init` compose asset, in the `yggdrasil` repository, must do
   the same before the next Core release tag moves `latest`.

## Consequences

- **Breaking:** a Core without an explicit development `YGGDRASIL_ENV` no
  longer accepts anonymous workflow dispatch, manifest writes or event
  publishes. Every deployment that relied on credential-free access (local
  compose, `yggdrasil init`, validation, ephemeral and e2e environments) must
  set `YGGDRASIL_ENV` before it runs a build carrying this decision.
- On a Core that already has its bridge and principals configured, nothing a
  caller can observe changes. What changes is the boot summary, the error
  lines, the legacy metrics and the `workflow_run.legacy_bridge` rows.
- A workflow inventory changed in the environment of a running process takes
  effect only at the next restart. Kubernetes already fixes a container's
  environment at start, so this states what was true in production.
- A half-applied bridge retirement no longer takes the principals down with
  the bridge; it switches off only the bridge and the anonymous posture.
- The durable non-use proof is the absence of `workflow_run.legacy_bridge`
  rows over a soak window. Poll rows are a lower bound (once per run id per
  process, again after a restart); dispatch rows are exact except for writes
  that failed, and those are counted. A legacy request pays at most the
  2 second audit bound.
- A directory digest shared with an event principal or a plaintext credential
  now switches the directory reads off outside production, where it used to
  go unnoticed; production boot still refuses it.
- The deploy-token development fallback and the CSRF and OAuth-state
  fallbacks still follow `devEnvAllowsFallback` and need their own decision.

## Related

- ADR-0017 (refines: the workflow principals and the bridge now load once, and bridge refusals no longer block principals)
- ADR-0019 (refines: a directory digest collision refuses the directory surface at load)
- ADR-0021 (extends: the same load-once and set-but-blank rules, now for the workflow surface; the event anonymous posture now needs an explicit development environment)
- dakasa-system ADR-0286 (motivates: retiring the legacy workflow-run bridge needs this refusal, the explicit environment and the durable non-use proof)
