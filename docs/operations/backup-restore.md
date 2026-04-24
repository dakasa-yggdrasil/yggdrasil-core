# Backup and restore

Yggdrasil state lives in two places: Postgres (everything durable)
and an encryption key (outside Postgres, for managed secrets). Back
up both; drill the restore.

## What's in Postgres

Every piece of platform state you care about:

- `manifest` + `manifest_version` — the catalog.
- `auth_session`, `password_credential`, `third_party_identity`,
  `third_party_auth_provider` — identity + auth.
- `collaborator`, `team`, `team_membership` — subjects.
- `managed_secret` — encrypted secret values.
- `workflow_run`, `workflow_run_step` — run history.
- `event_log` — the audit stream.
- `integration_instance_runtime_state` — adapter health.
- `product_materializations` — product apply snapshots.
- `topology_node`, `topology_edge`, `topology_document` — topology
  storage (if you use it).

A `pg_dump` of the Yggdrasil database covers all of it.

## What's NOT in Postgres

- **The encryption key** for managed secrets. Must be backed up
  separately (your cloud KMS, HashiCorp Vault, a 1Password-style
  vault). The key lives in an env var on the core pods; the backup
  procedure is "wherever your other infra keys live, put this one
  there too".
- **Bootstrap seed files** (`docs/bootstrap/seeds/`). Shipped in
  the container image; no backup needed as long as you keep the
  image tag in your registry.
- **Transport state.** HTTP adapters are stateless — nothing to back
  up. AMQP adapters (when `transport: rabbitmq` is used) re-declare
  their queues on reconnect; no persistent queue content worth
  backing up.

## Strategies

### Managed Postgres (recommended)

If you use RDS / Cloud SQL / Aiven / Neon, use their native backups:

- **Automated snapshots** (daily, 30-day retention).
- **Point-in-time recovery** (PITR) for finer granularity.
- **Cross-region replication** if your DR plan needs it.

Test-restore monthly. Treat the test-restore as a drill, not a
ceremony.

### Self-hosted Postgres

```sh
# Nightly, to shared storage
pg_dump \
  --dbname "$DB_URL" \
  --format=custom \
  --file "/backups/yggdrasil-$(date -Iseconds).dump" \
  --exclude-table=topology_event  # if you don't care about topology audit

# Retention: keep 30 days.
find /backups -name 'yggdrasil-*.dump' -mtime +30 -delete
```

Ship `/backups` off-site (S3 / GCS / your backup appliance). If the
server is your only backup location, you have no backup.

### The bundled bitnami Postgres

If you're running the Helm chart with the bundled Postgres subchart,
the subchart supports snapshot-based backup via Velero or persistent-
volume snapshots. Document and automate whichever your cluster
infrastructure supports.

## RPO / RTO targets

| Deployment tier | RPO (data loss window) | RTO (recovery window) |
|---|---|---|
| Trial / dev | 24h | 4h |
| Team prod | 1h | 1h |
| Department prod | 5 min (via PITR) | 30 min |
| Org-wide prod | < 1 min (synchronous replica) | 5 min (automated failover) |

Scale the backup strategy to the tier. Nightly pg_dump is not enough
at department-prod scale.

## Restore procedure

### 1. Stop the write path

```sh
# Scale the core down so nobody writes during restore.
kubectl scale --replicas=0 deployment/yggdrasil-core -n yggdrasil
```

### 2. Restore Postgres

```sh
# Managed: use the provider's restore UI / API.
# Self-hosted:
pg_restore \
  --dbname "$DB_URL" \
  --clean --if-exists \
  --format=custom \
  /backups/yggdrasil-<timestamp>.dump
```

### 3. Verify the encryption key

The key must be in the env of the new core pods. Without it, secret
reads fail — adapters suddenly can't authenticate to anything.

### 4. Run migrations (should be a no-op if the backup is recent)

```sh
kubectl exec -it deploy/yggdrasil-core -- /app/goose up
```

### 5. Restart the core

```sh
kubectl scale --replicas=2 deployment/yggdrasil-core -n yggdrasil
kubectl rollout status deployment/yggdrasil-core -n yggdrasil
```

### 6. Smoke-test

```sh
yggdrasil status
yggdrasil get integration_family | wc -l    # expected > 0
yggdrasil get workflow | head -3             # known workflow visible?
```

If these three pass, the control plane is back.

### 7. Integration adapters recover autonomously

Adapters reconnect to their transport and (for AMQP) re-declare their queues.
`integration_instance_runtime_state` starts reporting `healthy`
within one monitor interval (default 60s). No manual work needed.

## Restoring specific manifests (not a full restore)

Because manifests are versioned, "restore a single manifest" is just
re-applying an earlier version:

```sh
# Fetch version N of a manifest from a backup export:
yggdrasil describe workflow deploy-service -o yaml > /tmp/v5.yaml
# (or extract from the pg_dump via a table-level restore to a scratch DB)

# Re-apply:
yggdrasil apply -f /tmp/v5.yaml
```

The re-apply writes a new version with the old content — the audit
trail shows the restore explicitly.

## Restore drills

Run a restore against a scratch environment **every month**. Don't
let the first time you restore be an incident. Minimum drill:

1. Spin up a scratch Postgres.
2. Restore last night's backup.
3. Point a `yggdrasil-core` replica at the scratch DB.
4. `yggdrasil status`, `yggdrasil get workflow`, pick one random
   workflow, dispatch it against the scratch environment, see it
   succeed.
5. Tear down.

Takes ~30 minutes once automated. Catches the 3 AM surprises (wrong
backup retention, missing encryption key, schema version drift).

## Automate the whole thing

Ideal end state: a Yggdrasil workflow that owns the backup flow,
running on a schedule, using
[integration-database-admin](https://github.com/dakasa-yggdrasil/integration-database-admin)
+ [integration-aws](https://github.com/dakasa-yggdrasil/integration-aws)
(for S3 upload).

```yaml
apiVersion: yggdrasil.io/v1alpha1
kind: workflow
metadata:
  name: yggdrasil-postgres-backup
spec:
  trigger: { mode: schedule, schedule: "0 3 * * *" }   # 03:00 UTC daily
  steps:
    - id: dump
      use: { kind: integration, family: database-admin, operation: pg_dump }
      with: { instance_name: yggdrasil-primary, output_format: custom }
    - id: upload
      depends_on: [dump]
      use: { kind: integration, family: aws, operation: s3_put_object }
      with:
        bucket: yggdrasil-backups
        key: "yggdrasil-{{ steps.dump.metadata.timestamp }}.dump"
        source: "{{ steps.dump.metadata.local_path }}"
    - id: prune
      depends_on: [upload]
      use: { kind: integration, family: aws, operation: s3_lifecycle }
      with: { bucket: yggdrasil-backups, retention_days: 30 }
```

Backup-of-platform running on the platform itself. Dogfood the
runbook.
