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

Unknown `push.*` placeholders return `500`. Unmatched `{{ ... }}` patterns from other namespaces (e.g. `{{ env.HOME }}`) are passed through unchanged for forward compatibility.

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

v2.x relies on environment-backed static credentials, including route-scoped
tokens where a caller needs only one write surface. Endpoints requiring auth
and the env var that gates them:

| Endpoint | Env var | Header(s) accepted |
|---|---|---|
| `POST /api/v1/workflow-runs` | `YGGDRASIL_WORKFLOW_RUN_TOKEN` (legacy, optional in local dev) or `YGGDRASIL_WORKFLOW_RUN_SCOPED_TOKENS_JSON` | `X-Yggdrasil-Workflow-Token: <token>` or `Authorization: Bearer <token>` |
| `POST /api/v1/events` | `YGGDRASIL_EVENT_PUBLISH_TOKEN` (preferred) or `YGGDRASIL_WORKFLOW_RUN_TOKEN` (legacy fallback) | `X-Yggdrasil-Event-Token: <token>`, `X-Yggdrasil-Workflow-Token: <token>`, or `Authorization: Bearer <token>` |

Production requires at least one event-publish credential during the legacy
compatibility window. A configured dedicated event token must differ from all
workflow, deploy, and auth-admin static tokens; the core rejects collisions at
boot so the event credential cannot be replayed on a broader route.

Workflows may opt into manifest-backed dispatch authorization with
`spec.authorization.rbac` and optional `spec.authorization.policy`. The legacy
token evaluates as `service/legacy-workflow-run-token` (overridable with
`YGGDRASIL_WORKFLOW_RUN_LEGACY_SUBJECT_TYPE` and `_ID`). Scoped-token entries
carry an explicit subject and are accepted only on workflow-run URLs; store the
JSON in a Secret because it contains raw credentials.
| `POST /api/v1/products/.../deploy` (returns 410 anyway) | `YGGDRASIL_DEPLOY_TOKEN` | `Authorization: Bearer <token>` |

`POST /api/v1/manifests` is **not** gated in v2.x — adopters expose the API behind their own ingress policy. RBAC enforcement (Phase 3) will add per-user/per-tenant gating server-side.

## Pagination

Endpoints that can return many items (`/api/v1/manifests`, `/api/v1/workflow-runs`, `/api/v1/audit`) accept `?limit=<n>` and return arrays without a server-side cursor in v2.x. v3 will add cursors.

## Idempotency

Manifest creation (`POST /api/v1/manifests`) is idempotent on `(kind, namespace, name)` — re-posting the same `spec` produces a new version with identical `checksum`; clients deduplicate by checksum.

Workflow runs preserve the historical always-create behavior unless the caller
opts into both durable async dispatch (`?async=true`) and a stable
`metadata.idempotency_key`. In that mode the first request returns `202` and
persists the run; retries return `200` with the same `run_id` and `deduped:true`
without starting another provider execution. Reusing a key for a different
workflow returns `409 workflow_run_idempotency_conflict`.

## Compatibility commitments

- **Manifest shapes**: `apiVersion: yggdrasil.io/v1alpha1` is preserved across minor versions. v3 will introduce `v1` (no alpha) and provide a one-version migration window.
- **Endpoint shapes**: documented endpoints in `openapi.json` are stable across minor versions.
- **410 Gone**: endpoints listed as deprecated will keep returning 410 (not 404) for at least one major version after deprecation.
- **Workflow templating language**: `{{ }}` syntax is stable; new namespaces are additive.

For full semver and migration guidance, see [`upgrade.md`](../upgrade.md).
