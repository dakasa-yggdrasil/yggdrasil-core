# Secrets

Yggdrasil's managed-secret feature gives every credential a versioned,
auditable, rotatable home. Manifests reference secrets by URI
(`secret://namespace/name`); the core resolves them at use time and
never echoes the value back through the read APIs.

## What it is

Three concrete moving parts:

1. **`managed_secret` table.** Holds versioned secret values
   (encrypted at rest). One row per (namespace, name, version);
   `active` pointer indicates which version reads receive.
2. **The `secret://` reference scheme.** Manifests embed
   `credentials_ref: "secret://aws-prod/access-keys"`; the core
   substitutes the resolved value when handing the manifest to an
   integration adapter.
3. **Pluggable upstream backends via integrations.** The
   `integration-secrets-management` family wraps AWS Secrets Manager
   and GCP Secret Manager — your `managed_secret` rows can mirror
   from there, or be the source of truth and push to there. See
   [integration-secrets-management](https://github.com/dakasa-yggdrasil/integration-secrets-management).

## Lifecycle

```mermaid
flowchart LR
    Create[POST /api/v1/secrets] --> Active[active version]
    Active --> Rotate[POST /api/v1/secrets/.../rotate]
    Rotate --> NewVersion[new active version]
    NewVersion --> Disable[POST /api/v1/secrets/.../disable]
    Disable --> Revoke[POST /api/v1/secrets/.../revoke]
```

| Operation | What it does |
|---|---|
| Create | Write a new (namespace, name) with version 1, active. |
| Rotate | Generate (or accept) a new version, set as active, the previous becomes inactive but readable until revoked. |
| Disable | Mark the secret read-blocked; consumers receive an error. |
| Revoke | Hard-delete the value (the metadata stays for audit). |

The lifecycle is auditable end-to-end via
`secret.created`, `secret.rotated`, `secret.disabled`,
`secret.revoked` events.

## Wire shape

### Create a secret

```http
POST /api/v1/secrets
{
  "namespace": "aws-prod",
  "name": "access-keys",
  "value": { "access_key_id": "...", "secret_access_key": "..." },
  "metadata": { "created_by": "platform-bot" }
}
```

Response carries the metadata only. The `value` is never returned
once the row is written.

### Reference from a manifest

```yaml
apiVersion: yggdrasil.io/v1alpha1
kind: integration_instance
metadata:
  name: aws-prod
spec:
  type_ref: { name: aws, namespace: global }
  credentials_ref: "secret://aws-prod/access-keys"
```

When the core dispatches an `integration.execute` for this instance,
it resolves the `secret://` URI internally and includes the resolved
value in the AMQP message to the adapter — never echoes it via the
HTTP read endpoints, never logs it.

### Per-key reference

For composite secrets, reference a single key:

```yaml
credentials_ref: "secret://aws-prod/access-keys#secret_access_key"
```

The core returns just the named field.

### Rotate

```http
POST /api/v1/secrets/aws-prod/access-keys/rotate
{
  "value": { "access_key_id": "...", "secret_access_key": "..." }
}
```

Or, when paired with `integration-secrets-management`, the rotation
workflow can fetch a fresh value from the upstream backend and call
`/rotate` automatically.

## Backends

Three backend modes today:

| Backend | Trade-off |
|---|---|
| **Core-only** (default) | Values live in `managed_secret`. Encrypted at rest with the core's key. Simplest. |
| **Upstream-mirrored** | The core mirrors values from AWS Secrets Manager / GCP Secret Manager via `integration-secrets-management`. Useful when those are already your audited source of truth. |
| **Reference-only** | The core stores only a pointer (e.g. AWS Secrets Manager ARN); reads through the integration at use time. Higher latency, no in-Yggdrasil cache, but no plaintext-in-Postgres concern. |

Pick one per (namespace, name); don't mix modes for the same secret.

## Operate it

**Monitor:**

- `secret.rotated` event rate. Should match your rotation policy.
  Long gaps mean rotation automation is broken.
- `secret.disabled` / `.revoked` events with no preceding `created`
  in the same workflow — orphan reads.
- Failed secret resolutions. Surface adapter errors that mention
  "secret not found" — common cause of integration outages.

**Tune:**

- Encryption key rotation. The core encrypts secret values with a
  master key configured via env. Document its rotation procedure as
  part of your DR runbook.

**Back up:**

`managed_secret` is part of the standard Postgres backup. The
encryption key is *not* — back it up separately, in your secrets
manager (the cycle is intentional: backups don't decrypt without the
key).

## Pitfalls

- **Logging values.** Adapters that log the resolved credential
  defeat the whole point. Standard practice: `zap.SkipField` or
  equivalent for any field touched by `credentials.*`.
- **Inline credentials in `instance.config` instead of `credentials_ref`.**
  Config is read-back-able through the API; credentials are not.
  Anything sensitive goes via `credentials_ref` even if it feels
  like overkill for a single value.
- **Sharing one secret across environments.** A single
  `secret://global/aws-keys` shared between dev and prod is the most
  common path to a prod-affecting incident. Per-environment
  namespaces (`aws-dev`, `aws-prod`) cost nothing.
- **Forgetting the encryption key in DR.** If your backup includes
  Postgres but not the master encryption key, your restore is
  Postgres-shaped useless data.
