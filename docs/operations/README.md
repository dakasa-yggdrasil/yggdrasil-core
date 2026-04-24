# Operations

Running Yggdrasil healthily and at scale. This directory is the
runbook for operators — what to monitor, what to tune, how to recover,
how to grow.

## Index

| Topic | Page | When to read it |
|---|---|---|
| **Scaling** | [scaling.md](./scaling.md) | When request rate, manifest count, or workflow run count grows past comfortable single-replica numbers. |
| **Observability** | [observability.md](./observability.md) | Day one. Always have logs, metrics, traces wired up before traffic. |
| **Backup & restore** | [backup-restore.md](./backup-restore.md) | Day one. Restore drills monthly. |
| **Disaster recovery** | [disaster-recovery.md](./disaster-recovery.md) | Before your first prod outage. RPO/RTO planning. |
| **Performance tuning** | [performance-tuning.md](./performance-tuning.md) | When p95 / p99 latency drifts past SLO. |
| **Multi-environment** | [multi-environment.md](./multi-environment.md) | When you need dev / staging / prod separation. |
| **Incident response** | [incident-response.md](./incident-response.md) | When something is on fire. Read it before, not during. |
| **Security hardening** | [security-hardening.md](./security-hardening.md) | After the first install, before the first non-platform user. |

## A healthy production deployment

The minimum viable production setup, in checklist form:

- [ ] **HA core**: ≥ 2 replicas behind a service. See
  [scaling.md](./scaling.md).
- [ ] **Managed Postgres** (RDS, Cloud SQL, Neon). The bundled
  Postgres in `docker-compose.standalone.yml` is fine for demos and
  small footprints; a managed instance removes operational toil at
  any scale that matters. Control-plane manifests declare their
  Postgres target via `spec.postgres.external`.
- [ ] **Message broker only if needed** — required only if any
  integration uses `transport: rabbitmq`. Pure HTTP
  (`transport: http_json`) deployments can skip the broker entirely.
  If you do use AMQP: managed RabbitMQ OR a hardened self-hosted
  cluster with queue HA + persistent storage. See
  [features/transports.md](../features/transports.md).
- [ ] **TLS termination** at an ingress (nginx / Traefik / cloud LB).
  Cookie marked `Secure`; `AUTH_SESSION_COOKIE_DOMAIN` set per your
  apex.
- [ ] **OAuth/OIDC** configured (don't run prod on password-only).
  See [features/sessions.md](../features/sessions.md).
- [ ] **Logs shipped** to your log store. JSON to stdout — your
  infra picks them up.
- [ ] **Metrics scraped** (Prometheus exposition planned roadmap;
  for now, derive from event_log + access logs).
- [ ] **Backup automation**: nightly `pg_dump` or managed snapshots,
  retained ≥ 30 days, restore-tested monthly.
- [ ] **Encryption key in a secrets store**, separately backed up.
  See [security-hardening.md](./security-hardening.md).
- [ ] **Runbook** (this directory) reviewed by every on-call.

## A healthy growth path

| Stage | Concrete signal | Next step |
|---|---|---|
| **Tire kicker** | One operator, < 100 manifests, < 100 workflow runs/day | `yggdrasil init` on a VM |
| **Team adoption** | < 10 daily ops, < 10k manifests | Helm + bundled deps on a small cluster |
| **Department-wide** | < 100 daily ops, < 100k manifests, < 10k runs/day | Helm + managed Postgres + managed RMQ + 3-replica core |
| **Org-wide** | > 100 daily ops, > 100k manifests, > 100k runs/day | Sharded by namespace, dedicated Postgres + RMQ pools, surface-per-team |
| **Multi-tenant** | Multiple teams with isolation needs | Multiple cores, federated catalog, per-tenant adapters |

The transitions are read-only — no data migration costs along this
path. Move when the need arises, not preemptively.

## Anti-patterns

These show up in deployments that grew faster than the operator
expected. Reading them once might save a postmortem.

- **Treating `event_log` as queryable forever.** Archive after 90
  days. See [scaling.md](./scaling.md#event_log-archival).
- **Sharing the compose-bundled Postgres into prod.** It's fine for
  a trial; in prod, declare `spec.postgres.external` in your
  control_plane manifest and point at a managed DB.
- **Ignoring adapter health.** A degraded adapter manifests as
  workflow timeouts that look like Yggdrasil bugs. Monitor adapter
  describe handshakes via `integration_instance_runtime_state`.
- **Running everything in `global` namespace.** Two real namespaces
  cost nothing and let you scope RBAC + filter views.
- **Logging credentials.** Adapters or workflows that emit
  `credentials.*` payloads in logs defeat managed secrets entirely.
  See [features/secrets.md](../features/secrets.md#pitfalls).
