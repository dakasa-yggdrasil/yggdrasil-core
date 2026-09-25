# OpenAPI Companion

This page explains the cross-cutting concepts that the OpenAPI spec assumes but does not fully spell out. Read it once; refer back when an endpoint behaves unexpectedly.

## Manifest envelope

Every manifest persisted by Yggdrasil shares the same outer shape:

```json
{
  "apiVersion": "yggdrasil.io/v1alpha1",
  "kind": "<kind>",
  "metadata": {
    "namespace": "<ns>",
    "name": "<name>",
    "description": "<optional>",
    "labels": {"<key>": "<value>"},
    "active": true
  },
  "spec": { /* kind-specific */ }
}
```

`POST /api/v1/manifests` accepts a flatter request body for ergonomics (the `apiVersion`/`kind` come from the `?kind=` query parameter):

```json
{
  "name": "...",
  "namespace": "...",
  "description": "...",
  "labels": {...},
  "spec": {...}
}
```

The server validates `spec` against the kind-specific validator, attaches a UUID, and stores a new version. Existing versions of the same `(kind, namespace, name)` tuple are deactivated unless the new request explicitly sets `active: false`.

An `integration_instance` write also resolves its referenced
`integration_type` before persistence. The generic manifests endpoint
and the typed integration-instances endpoint both enforce the type's
credential policy, hydrate secret references in memory for validation,
and validate credentials and config against the type schemas. Resolved
secret values are not persisted in the manifest.

## Manifest selectors

Several endpoints accept a `ManifestSelector` to identify a target manifest. You can use any one of:

```json
{"manifest_id": "<uuid>"}                       // by id
{"namespace": "<ns>", "name": "<name>"}         // by name (active version)
{"namespace": "<ns>", "name": "<name>", "version": 3}  // by name + version
```

Invalid selectors return `400` with a descriptive error.

## Workflow templating

Workflows can interpolate values into step inputs using `{{ ... }}` syntax. Three namespaces are recognised:

| Namespace | Source | Example |
|---|---|---|
| `inputs.*` | The `inputs` map passed to `POST /api/v1/workflow-runs` (or templated by webhook from a push event) | `{{ inputs.git_url }}` |
| `steps.<id>.metadata.<field>` | Metadata returned by a previous step's adapter response | `{{ steps.render.metadata.objects }}` |
| `push.*` | Available **only** in `default_inputs` of a `repository_binding.spec.deploy` block; substituted by the webhook handler | `{{ push.repository.clone_url }}`, `{{ push.head_commit.id }}` |

`push.*` placeholders supported by v2.0.0+:

- `push.repository.full_name`
- `push.repository.clone_url`
- `push.ref`
- `push.head_commit.id`
- `push.head_commit.message`
- `push.pusher.name`

Unknown `push.*` placeholders return `500`. Any other `{{ ... }}` whose leading segment is not a recognised namespace (`inputs`, `steps`, `metadata`, `auth`, `workflow`, `each`) is treated as a downstream renderer's own token and passed through unchanged. That is what lets a `declarative_apply` step carry opaque ConfigMap blobs to Kubernetes verbatim: Grafana dashboard legends (`{{service}}`, `{{status}}`), Prometheus and Alertmanager rule annotations (`{{ $value }}`, `{{ $labels.db }}`), and Grafana contact point templates (`{{ .GroupKey }}`). A path *under* a recognised namespace that does not resolve (a typo such as `{{ inputs.tyop }}`) still fails loudly with `could not be resolved`.

## Webhook signature verification

`POST /api/v1/github/webhook` validates the `X-Hub-Signature-256` header against the body using HMAC-SHA256 with the `GITHUB_WEBHOOK_SECRET` env var. Signatures are formatted `sha256=<hex>`. If `GITHUB_WEBHOOK_SECRET` is unset (development only), signature validation is skipped — never run a public-facing instance with the secret unset.

Forge a signature:

```bash
SIG=$(printf '%s' "$BODY" | openssl dgst -sha256 -hmac "$WEBHOOK_SECRET" | awk '{print "sha256="$2}')
```

## Skip semantics

The webhook returns `200` with a `status: skipped` body in three cases that are *not* errors:

1. **`X-GitHub-Event` is not `push` or `ping`** — we ignore other events (e.g. `pull_request`); GitHub gets a 200 so it does not retry.
2. **No `repository_binding` matches the pushed repository** — installing the webhook on a repo Yggdrasil does not know about should be harmless.
3. **`branch_filter` or `path_filter` excludes the push** — explicit policy.

Adopters who want loud failures on misconfigured bindings should monitor `workflow_runs` cardinality, not webhook responses.

## Error envelope

All non-2xx responses share:

```json
{
  "error": "<human-readable reason>",
  "deprecation": "<version that removed this behaviour>"   // present only on 410 Gone
}
```

## Auth

Non-human routes use environment-backed, route-scoped credentials. Machine
principal inventories store only SHA-256 digests; raw bearers remain in caller
secret stores. Endpoints requiring auth and the configuration that gates them:

| Endpoint | Env var | Header(s) accepted |
|---|---|---|
| `POST /api/v1/workflow-runs`, `GET /api/v1/workflow-runs/{run_id}` | `YGGDRASIL_WORKFLOW_MACHINE_PRINCIPALS_JSON`; explicit time-bounded `YGGDRASIL_WORKFLOW_RUN_TOKEN` migration bridge | `X-Yggdrasil-Workflow-Token: <bearer>` or `Authorization: Bearer <bearer>` |
| `POST /api/v1/events` | `YGGDRASIL_EVENT_PUBLISHER_PRINCIPALS_JSON`; explicit time-bounded `YGGDRASIL_EVENT_PUBLISH_TOKEN` migration bridge | `X-Yggdrasil-Event-Token: <bearer>` or `Authorization: Bearer <bearer>` |
| Manifest reads/writes, `/console`, `/ops`, secrets | Console session; permission middleware applies where registered | Session cookie or console bearer |
| Provider, SCIM, and SAML auth-administration mutations | `YGGDRASIL_AUTH_ADMIN_TOKEN` or an authorized console session | `X-Yggdrasil-Auth-Admin-Token: <token>`, matching bearer, or console session |
| Direct deploy, deploy-all, bootstrap, integration-install API routes | `YGGDRASIL_DEPLOY_TOKEN` | `X-Deploy-Token: <token>` or `Authorization: Bearer <token>` |
| Equivalent `/api/v1/console/*` deploy routes | Authorized console session after RBAC | Session cookie or console bearer |

Core loads the workflow, event and directory inventories once at start
(ADR-0021, ADR-0022). A request with no credential reaches the workflow-run
routes, the event route or the deploy-family routes (direct
and console deploy, deploy-all, bootstrap and integration install) only when
nothing is configured for that surface (for the deploy-family routes, no
`YGGDRASIL_DEPLOY_TOKEN`) and `YGGDRASIL_ENV` is explicitly `dev`,
`development`, `local` or `test`; otherwise it answers `401`. A workflow inventory that is
malformed, set but blank, or shares a digest with another credential scope
refuses the workflow surface: every machine dispatch and poll answers `401`.
Refused workflow bridge settings switch off only the bridge; hashed
principals keep working.

Production requires an active, unexpired workflow principal and an independent
event principal (or the corresponding explicit legacy bridge). The core
rejects malformed, wildcarded, duplicate, expired-only, and credential-reusing
configuration at boot, without printing credentials or digests. Hashed event
principals may not reuse the plaintext event bridge bearer, because principal
expiry or revocation must not downgrade that bearer to bridge authority.

Every workflow machine principal has a mandatory exact namespace/name
allowlist. Machine dispatch is denied when the workflow has no authorization
block; `spec.authorization.rbac` and optional `spec.authorization.policy` are
additional mandatory restrictions. Machine selectors use logical
namespace/name resolution (including the normal default namespace) and only
the current active workflow; `manifest_id` and explicit `version` are rejected.
Async creation records the authenticated
principal server-side; all hashed machine dispatch is therefore forced async,
even when `async=false` or a `sync` header is supplied. Machine polling returns
only owned runs and hides foreign ids as 404. `metadata.idempotency_key` is also
principal-scoped before persistence.

Every hashed event publisher has a non-empty `allowed_events` list of
`{provider,instance_id,event_type}` mutation grants. It cannot publish the
generic event shape or another publisher's scope; actor identity and every
`yggdrasil.io/publisher_*` metadata key are server-authored. Console sessions
are not accepted on this machine route. The plaintext bridge is mutation-only
and its actor is replaced with the reserved `legacy-event-publish-bridge`
service identity.

A grant is exact or logical (ADR-0021):

| Grant `instance_id` | Matches | Database |
|---|---|---|
| No `/` (version UUID or bare name) | The event's `instance_id` as an opaque string | Never |
| `<namespace>/<name>` | After Core resolves the event's `instance_id` (any not-yet-purged version UUID in canonical lowercase form, or a literal `<namespace>/<name>`; never a bare name) to an `integration_instance` with an active version whose active `integration_type` provider equals the event `provider` | One read-only statement (one round trip), only after the bearer matched and only when the principal holds a logical grant for that provider and event type |

`POST /api/v1/events` answers `403 event.authorization_denied` with one
identical body when the instance is not found, not granted, or of another
provider (also when the wire value carries a control character, which never
reaches the database), and `503 event.authorization_unavailable` with a fixed
detail when the lookup fails. Core loads the inventory once at start; a
malformed grant or a set-but-blank variable refuses the whole inventory, and
then every event publish answers `401` until a restart with a valid one (with
`YGGDRASIL_ENV=production` Core refuses to boot instead). Refused legacy
bridge settings switch off only the bridge and the anonymous development
posture.

The legacy workflow bridge requires
`YGGDRASIL_WORKFLOW_RUN_LEGACY_ENABLED=true` and a future RFC3339
`YGGDRASIL_WORKFLOW_RUN_LEGACY_EXPIRES_AT`. Every request it authenticates is
logged, counted in `yggdrasil_workflow_run_legacy_bridge_requests_total` and
audited as `workflow_run.legacy_bridge`, and its asynchronous runs carry
`yggdrasil.io/creator_legacy_workflow_bridge=true` (ADR-0022). The event bridge likewise requires
`YGGDRASIL_EVENT_PUBLISH_LEGACY_ENABLED=true` and a future RFC3339
`YGGDRASIL_EVENT_PUBLISH_LEGACY_EXPIRES_AT`. The former raw-token
`YGGDRASIL_WORKFLOW_RUN_SCOPED_TOKENS_JSON` configuration is rejected.

## Pagination

Endpoints that can return many items (`/api/v1/manifests`, `/api/v1/workflow-runs`, `/api/v1/audit`) accept `?limit=<n>` and return arrays without a server-side cursor in v2.x. v3 will add cursors.

## Idempotency

Manifest creation (`POST /api/v1/manifests`) is idempotent on `(kind, namespace, name)` — re-posting the same `spec` produces a new version with identical `checksum`; clients deduplicate by checksum.

Human and migration workflow runs preserve the historical always-create
behavior unless the caller opts into both durable async dispatch
(`?async=true`) and a stable `metadata.idempotency_key`. Hashed machine
principals are always routed through durable async dispatch. The first request
returns `202` and persists the run; retries return `200` with the same `run_id`
and `deduped:true` without starting another provider execution. Reusing a key
for a different workflow returns `409 workflow_run_idempotency_conflict`.

For machine principals, the persisted key is a server-derived digest scoped to
the authenticated principal. A retry cannot return another principal's run id.

## Compatibility commitments

- **Manifest shapes**: `apiVersion: yggdrasil.io/v1alpha1` is preserved across minor versions. v3 will introduce `v1` (no alpha) and provide a one-version migration window.
- **Endpoint shapes**: documented endpoints in `openapi.json` are stable across minor versions.
- **410 Gone**: endpoints listed as deprecated will keep returning 410 (not 404) for at least one major version after deprecation.
- **Workflow templating language**: `{{ }}` syntax is stable; new namespaces are additive.

For full semver and migration guidance, see [`upgrade.md`](../upgrade.md).
