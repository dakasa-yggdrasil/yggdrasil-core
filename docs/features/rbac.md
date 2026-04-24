# RBAC

Role-based access control in Yggdrasil. Subjects (collaborators or
teams) get bindings into roles; roles carry rules of the form
"effect (allow / deny) over (resources, actions)". The evaluator runs
before any state-changing operation.

## What it is

```yaml
apiVersion: yggdrasil.io/v1alpha1
kind: rbac
metadata:
  name: global-rbac
  namespace: global
spec:
  roles:
    - name: platform-admin
      rules:
        - effect: allow
          resources: ["manifest.*"]
          actions:   ["*"]
    - name: workflow-runner
      rules:
        - effect: allow
          resources: ["workflow.run.*"]
          actions:   ["dispatch", "read"]

  bindings:
    - name: platform-team-admins
      subjects:
        - { type: team, id: platform }
      roles: [platform-admin]
    - name: ci-bot
      subjects:
        - { type: collaborator, id: github-actions-bot }
      roles: [workflow-runner]
```

## How it works

1. **Subject expansion.** A request comes in with `collaborator_id`.
   The evaluator looks up active team memberships and expands
   recursively through `parent_team_id`. The result is the set of
   "effective subjects" for this request — `collaborator:<slug>` plus
   every team and ancestor team.
2. **Rule matching.** For each effective subject, find every binding
   that lists it, and every rule of every role in those bindings.
3. **Wildcards.** `*` matches any single resource segment.
   `manifest.*` matches `manifest.create`, `manifest.read`, etc.
   `*.*` matches everything.
4. **Deny precedence.** A single matching `deny` rule wins over any
   number of `allow` rules.
5. **Result.** Allowed, denied, or `not_applicable` (no rule matched
   at all — treated as deny by the upstream pipeline).

The evaluator response is structured so audits show *why*:

```json
{
  "allowed": true,
  "decision": "allow",
  "manifest": { "kind": "rbac", "namespace": "global", "name": "global-rbac", "version": 1 },
  "matched_roles": ["platform-admin"]
}
```

## Two-phase pipeline (RBAC + policy)

RBAC runs first. If it denies, the request is rejected immediately.
If it allows, the optional `policy` phase runs next with runtime
input (amount, region, time-of-day, etc.). Policy can refine RBAC's
allow into a deny; it cannot upgrade a deny to allow.

See [policy.md](./policy.md) for the second phase.

## Wire shape

### POST /api/v1/authorization/evaluate

```json
{
  "rbac":   { "namespace": "global", "name": "global-rbac" },
  "policy": { "namespace": "global", "name": "payment-policy" },
  "collaborator_id": "ana",
  "resource": "payment.invoice",
  "action":   "approve",
  "input": {
    "subject": { "department": "finance" },
    "context": { "amount": 9500 }
  }
}
```

Response carries the full trace: resolved subjects, RBAC trace,
policy trace, final decision. Auditable end-to-end.

## Operate it

**Monitor:**

- `authorization.evaluated` event rate by decision. A spike in `deny`
  for a bot subject usually means a credential rotation or a binding
  drift.
- p95 evaluator latency. RBAC is in-memory after the manifest load,
  so it should stay sub-millisecond. If it spikes, suspect Postgres
  health or a degenerate role (thousands of rules).

**Back up:**

RBAC manifests are normal manifests. Backed up with Postgres.

**Tune:**

- Role granularity. 5–20 well-named roles outperforms 200 fine-grained
  ones — both for evaluation cost and for human comprehension at
  audit time.
- Binding count per subject. A subject in 100 bindings makes every
  rule lookup linear-in-bindings; flatten the hierarchy or merge
  redundant bindings.

## Pitfalls

- **Catch-all admin role.** A role with `resources: ["*"], actions:
  ["*"], effect: allow` bound to `team:engineering` is convenient on
  day one and a fire on day 365. Start with named, scoped roles and
  resist the temptation.
- **No `deny`.** If you only use `allow`, you can never reverse a
  decision without removing a binding entirely. A `deny` for
  `payment.invoice / approve` outside business hours is more
  maintainable than removing the role from people's bindings every
  evening.
- **Forgetting team hierarchy.** A subject in `team:eng-platform`
  inherits roles bound to `team:eng` and `team:engineering` (any
  ancestor). When you bind a sensitive role to `team:engineering`
  thinking only the top level gets it, you've actually given it to
  every descendant.
- **Subject naming drift.** Bindings reference subjects by `id`. When
  a collaborator's slug changes (rare, but possible), bindings
  silently miss. Use stable slugs from day one and treat them as
  permanent identifiers.
