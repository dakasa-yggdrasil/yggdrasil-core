# Tutorial 3 — Use Yggdrasil as Your Secret Store

**Time:** ~30 minutes.
**Outcome:** an integration_instance previously configured with cleartext credentials is reconfigured to use a `secret://` reference. The actual values live in Yggdrasil's managed secret store and are materialised into Kubernetes Secrets on demand.

## Why this matters

In v1.x most adopters set credentials directly in `integration_instance.spec.credentials` — JSON literal in a manifest committed to git. Even with private repos, that pattern leaks: branch contents, manifests in error logs, tokens in `kubectl describe`. Yggdrasil ships a managed secret store so tokens never appear in manifests.

## Step 1 — Identify a secret to migrate

Pick an integration_instance that has cleartext credentials. Example: a GitHub PAT for `integration-github-acme`:

```bash
curl -sf "$YGG_URL/api/v1/integration-instances" | jq '.integration_instances[] | select(.metadata.name == "integration-github-acme") | .spec.credentials'
# → {"github_token": "ghp_AbcDef..."}
```

You will:

1. Create a managed secret holding `github_token`.
2. Replace the inline `credentials` with `credentials_ref: secret://...`.
3. Re-apply the integration_instance manifest.
4. Verify the runtime state stays `healthy`.

## Step 2 — Create the managed secret

```bash
curl -sf -X POST -H "Content-Type: application/json" \
  "$YGG_URL/api/v1/secrets" \
  -d '{
    "namespace": "default",
    "name": "integration-github-acme-credentials",
    "data": {"github_token": "ghp_AbcDef..."},
    "rotation": {"interval_days": 90, "policy": "manual"},
    "metadata": {"owner": "team:platform", "purpose": "GitHub PAT for acme integration"}
  }' | jq '{namespace, name, status, version}'
```

Expected:

```json
{"namespace":"default","name":"integration-github-acme-credentials","status":"active","version":1}
```

`POST /api/v1/secrets` does not return the secret values — only metadata. The values are stored encrypted-at-rest server-side.

## Step 3 — Update the integration_instance

Replace the cleartext `credentials` map with a reference:

```bash
curl -sf -X POST -H "Content-Type: application/json" \
  "$YGG_URL/api/v1/integration-instances" \
  -d '{
    "name": "integration-github-acme",
    "namespace": "default",
    "type_ref": {"namespace": "global", "name": "github"},
    "status": "active",
    "credentials_ref": "secret://yggdrasil/default/integration-github-acme-credentials",
    "config": {"base_url": "http://integration-github-adapter.yggdrasil.svc.cluster.local:8081"}
  }' | jq '.metadata.name, .spec.credentials_ref'
```

The `secret://yggdrasil/...` URI tells the core to dereference the managed secret at adapter-call time. Other supported schemes:

- `secret://aws/secretsmanager/<secret-id>` — when an AWS Secrets Manager mirror is configured
- `secret://gcp/secretmanager/<resource>` — for GCP-mirrored adopters

## Step 4 — Materialise into a Kubernetes Secret (optional)

If your adapter expects to read the value from a Kubernetes Secret rather than via the core API, materialise:

```bash
curl -sf -X POST \
  "$YGG_URL/api/v1/secrets/default/integration-github-acme-credentials/materialize" \
  | jq '{kubernetes_secret, namespace}'
```

This creates a Kubernetes `Secret/integration-github-acme-credentials` in the configured namespace, with the same `data` map. The Secret is owned by Yggdrasil's reconciler — manual edits will be overwritten on next materialise.

## Step 5 — Verify the integration still works

```bash
curl -sf "$YGG_URL/api/v1/integration-runtime-states?namespace=default&name=integration-github-acme" \
  | jq '.runtime_states[] | {check_kind, status}'
```

Both checks (`describe_handshake`, `transport_connectivity`) should remain `healthy`. If `unauthorized`, the secret was not deferred correctly — `kubectl logs deploy/yggdrasil` will show the dereferencing error.

## Step 6 — Rotate the secret

```bash
curl -sf -X POST -H "Content-Type: application/json" \
  "$YGG_URL/api/v1/secrets/default/integration-github-acme-credentials/rotate" \
  -d '{"data": {"github_token": "ghp_NewValue..."}}' \
  | jq '{version, status, rotated_at}'
```

The new version is active immediately. If the secret was materialised, the next reconciler tick (60s) updates the Kubernetes Secret. Adapters reading via the API see the new value on the next dereferencing call (no restart needed).

## Step 7 — Audit

```bash
curl -sf "$YGG_URL/api/v1/secrets/default/integration-github-acme-credentials" | jq '{name, version, rotation, status}'
```

The version counter increments on each rotate. Disable / revoke flows:

```bash
# Mark disabled (runtime state turns unauthorized; adapter calls fail loudly)
curl -sf -X POST "$YGG_URL/api/v1/secrets/default/integration-github-acme-credentials/disable"

# Mark revoked (irrecoverable; subsequent rotates rejected)
curl -sf -X POST "$YGG_URL/api/v1/secrets/default/integration-github-acme-credentials/revoke"
```

## What you accomplished

- One token stored once, referenced everywhere via `secret://`.
- Rotation is one POST; no editing of integration_instance manifests.
- The token never appears in any committed manifest, runtime state response, or workflow_run record.

## Next

- Migrate the rest of your inline `credentials` maps. Do it incrementally — each integration_instance is independent.
- Adopters with policy requirements around at-rest encryption: see [features/secrets.md](../features/secrets.md) for KMS configuration.
- Adopters with multi-tenancy: secrets are namespaced; per-tenant boundaries arrive in v2.3 (Phase 3).
