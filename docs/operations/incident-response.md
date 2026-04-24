# Incident response

Things go wrong. Have a plan before the pager fires. This page has
the triage matrix, the common incident shapes, and the postmortem
template.

## Triage in 60 seconds

When the pager fires:

1. **`yggdrasil status`** — is the control plane even reachable?
2. **Read the alert** — which component is the symptom?
3. **Check `event_log`** for the last 15 minutes of activity.
4. **Declare the blast radius** — control-plane outage, one
   integration degraded, specific workflow failing?
5. **Communicate** — drop a note in the incident channel, even if
   it's "investigating, no impact yet".

Don't spend 10 minutes debugging before step 5.

## The triage matrix

| Symptom | Most likely cause | First action |
|---|---|---|
| `yggdrasil status` returns non-2xx | Core or LB down | Check pod status + ingress logs |
| Status OK, workflows failing with "no instance" | RBAC / catalog issue | `yggdrasil get integration_instance` + check RBAC allow for caller |
| Status OK, workflows failing with "timeout" | Adapter or broker | Check queue depth + adapter pod logs |
| Everything slow | Postgres | Slow query log + connection count |
| Denials spiking | Policy change | `event_log` for `authorization.evaluated` with deny + recent policy changes |
| Secret resolution failing | Encryption key or managed secret | Check core pod env has key; `yggdrasil get managed_secret <name>` exists |
| Surface 500 | Surface itself, not the core | Surface pod logs |

Match symptom → cause → action. Move fast, but verify each step.

## Common incident shapes

### 1. Postgres hits connection limit

**Symptom:** HTTP 500 on all core endpoints, logs show
`too many connections for role`. All workflows hanging.

**Immediate action:**

```sh
# Scale the core down to free connections.
kubectl scale --replicas=1 deploy/yggdrasil-core -n yggdrasil
# Or kill half the pods, same effect.
```

**Why it happens:**

- Autoscaled the core without bumping Postgres connection limit.
- pgBouncer not in the path; every core pod holds 15 direct
  connections.

**Fix:**

- Put pgBouncer in transaction-pooling mode. Cores share a pool.
- Or bump `max_connections` on Postgres; verify RAM supports it.

### 2. Adapter handshake drift

**Symptom:** All workflow steps for one family failing with
"contract mismatch".

**Immediate action:**

```sh
# Find which adapter is drifting.
yggdrasil get integration_type -o yaml | grep -E "adapter:|version:"

# Check the live adapter's describe response (via `yggdrasil
# integration describe` if available, or via a temporary AMQP call).
```

**Why it happens:**

- Adapter image was rebuilt with a contract change, but the
  `integration_type.spec.adapter.version` wasn't bumped.

**Fix:**

- Revert the adapter image to the previous tag, or bump the
  `integration_type.spec.adapter.version` and re-apply.
- Keep the describe check; don't disable it to "unstuck"
  production. That drift check is the only thing catching the
  real bug.

### 3. Workflow runs accumulating as "running"

**Symptom:** `workflow_run` table has many rows with
`status: running` and no movement. `yggdrasil logs <run-id>`
returns stale.

**Immediate action:**

- Is the transport up? For AMQP-using integrations, check RabbitMQ —
  a dead broker fails dispatch silently. For HTTP-using integrations,
  check that adapter pods reach 200 on `/healthz`.
- Is the engine up? Log: `workflow engine heartbeat`.
- Check `workflow.dispatch` queue depth (when AMQP is in use) or
  adapter HTTP error rates.

**Why it happens:**

- Broker outage where the dispatch succeeded but the reply was lost.
- Adapter crashed mid-execute.

**Fix:**

- Run a cleanup workflow that marks orphans as `failed` with
  `error: "engine recovery"` — audit-preserving.
- Re-dispatch the real work if it's idempotent.

### 4. Mass manifest deletion

See the [disaster-recovery playbook](./disaster-recovery.md#ransomware--mass-deletion).
Short version: freeze writes, use `manifest_version` to restore,
rotate the compromised subject's token.

### 5. Encryption key lost

**Symptom:** All adapter calls requiring credentials fail.

**Immediate action:**

- Is the env var still set on core pods? Most common cause is a
  misconfigured ConfigMap / Secret.
- Did the key rotate without re-encrypting `managed_secret`?

**Fix:**

- Restore the key from your KMS backup.
- If truly lost, you're in a DR scenario — see
  [disaster-recovery.md](./disaster-recovery.md#encryption-key-compromise).

## Severity levels

Suggested scheme; adapt to your org.

| Severity | Criteria | Response |
|---|---|---|
| **SEV1** | Control plane down OR data loss risk | Page immediately, incident commander assigned, update customers |
| **SEV2** | Key workflow family broken, degraded for >30 min | Page primary oncall, work through triage matrix |
| **SEV3** | Elevated error rate or one integration degraded | Ticket, fix in business hours |
| **SEV4** | Cosmetic or single-user | Ticket, prioritized normally |

SEV1 and SEV2 get incident channels and postmortems. SEV3/SEV4 get
tickets.

## Postmortem template

Copy this structure into your incident ticket at the end:

```markdown
# Incident: <one-line summary>

- **Start:** <timestamp>
- **End:** <timestamp>
- **Severity:** SEV<N>
- **Detected by:** <alert | user report | routine check>

## Impact

- Which workflows / users / systems were affected?
- Quantified: <X> failed workflow runs, <Y> users saw errors.

## Timeline

- T+00:00 — alert fires
- T+00:05 — IC takes over, triage begins
- T+...   — ...

## Root cause

A few paragraphs. Describe *the mechanism*, not just the symptom.
"RMQ queue depth grew because the kubernetes adapter replica
count was reduced to 1 for a cost-saving change that didn't
account for peak load."

## Contributing factors

- Lack of alert on queue depth.
- Cost-saving PR merged without review from platform team.

## What worked

- RBAC contained the blast radius.
- Event log made timeline reconstruction trivial.

## What didn't

- Page didn't fire for 10 minutes because alert threshold was
  too high.

## Action items

- [ ] Add alert on queue depth > 1000 for 5 min.
- [ ] Update integration-kubernetes replicas floor to 3.
- [ ] Add cost-vs-capacity trade-off to the PR checklist.

## Related

- Incident ticket: #...
- Related postmortems: #...
```

Postmortems are blameless. "Why did this happen?" not "who did this?"

## Keep handy

A single dashboard with these four graphs solves 80% of triage:

1. Core HTTP error rate, by endpoint family.
2. Adapter `execute` reply p95 and error rate, by family.
3. Postgres: connections in use, slow query count.
4. Transport health: RabbitMQ queue depth per `yggdrasil.adapter.*.execute`
   (when AMQP is in use), adapter HTTP latency and 5xx rate (when HTTP
   is in use).

When the page fires, that dashboard is your first tab.
