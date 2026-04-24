# Policy

Runtime conditional access on top of RBAC. Where RBAC answers "is
this subject permitted to act on this resource?", policy answers
"under the conditions present right now, should we still allow it?"

## What it is

```yaml
apiVersion: yggdrasil.io/v1alpha1
kind: policy
metadata:
  name: payment-policy
  namespace: global
spec:
  rules:
    - name: finance-small-approvals
      effect: allow
      resources: ["payment.invoice"]
      actions:   ["approve"]
      conditions:
        - { key: subject.department, operator: eq,  value: finance }
        - { key: context.amount,     operator: lte, value: 10000 }

    - name: deny-after-hours
      effect: deny
      resources: ["payment.invoice"]
      actions:   ["approve"]
      conditions:
        - { key: context.hour, operator: gte, value: 18 }
        - { key: context.hour, operator: lt,  value: 6 }
```

## How it works

Policy runs **after** RBAC allows. If RBAC says deny, policy never
runs. If RBAC says allow, policy can:

- Allow (the request proceeds).
- Deny (the request is rejected with a structured error pointing at
  the policy rule).
- Be `not_applicable` — no rule matched, treated as allow (RBAC's
  decision stands).

A request reaches policy with three concrete data sources:

1. **Subject** — the resolved collaborator + teams from RBAC.
2. **Context** — the request input (amount, region, hour, anything
   the caller passed).
3. **Resource + action** — same as RBAC.

Conditions reference these via dotted keys: `subject.department`,
`context.amount`, `subject.email`, etc.

## Operators

Implemented:

| Operator | Meaning |
|---|---|
| `eq` / `neq` | Equal / not equal (typed; string vs string, number vs number). |
| `gt` / `gte` / `lt` / `lte` | Numeric ordering. |
| `in` | Value is in a provided list. |
| `contains` | String contains substring, list contains element. |
| `exists` | Key is present (any value). |
| `matches` | Regex match (Go regex flavor). |

Conditions in a rule are AND-joined. Multiple rules are evaluated
independently; **deny precedence** still applies — any matching
deny wins.

## Wire shape

Same endpoint as RBAC: `POST /api/v1/authorization/evaluate`. The
response carries both the RBAC and policy traces:

```json
{
  "allowed": false,
  "decision": "deny",
  "rbac":   { "decision": "allow", "matched_roles": ["finance-approver"] },
  "policy": {
    "decision": "deny",
    "matched_rule": "deny-after-hours",
    "manifest": { "kind": "policy", "namespace": "global", "name": "payment-policy", "version": 3 }
  }
}
```

The structured trace is what makes audits actionable — "denied because
of policy/payment-policy/deny-after-hours" beats "403 forbidden" by a
mile.

## When to use policy vs RBAC

| You want | Use |
|---|---|
| "Only the platform team can deploy" | RBAC |
| "Only the platform team can deploy, AND deploys to prod outside business hours need approval" | RBAC + policy |
| "Anyone can rotate dev secrets, only admins can rotate prod secrets" | Two RBAC bindings, no policy needed |
| "Anyone can rotate secrets, but rotations of `aws.iam.user.*` require an open guardian approval" | RBAC allows, policy denies unless `context.approval_id` matches an open `guardian_approval` manifest |

The heuristic: if the answer depends on **who**, it's RBAC. If it
depends on **what's true at the moment of the request**, it's policy.

## Operate it

**Monitor:**

- `authorization.evaluated` events with `policy.decision: deny` and
  matched rule. Sudden spikes usually mean a behavior change in the
  caller (a bot started passing a different `context` shape) or a
  policy authoring mistake.
- Evaluator latency. Policy adds work; if your policies have hundreds
  of rules with regex conditions, p99 latency creeps up.

**Back up:**

Policy manifests are normal manifests. Standard backup applies.

**Tune:**

- Number of rules per policy. Aim for ~10–30. Combine with multiple
  named policies and reference whichever is right per request.
- Regex usage. Compiled at evaluation time; cache them in your
  policy authoring tool by reusing the same exact string.

## Pitfalls

- **Missing `context` keys.** A condition like `context.hour eq 14`
  silently doesn't match if the caller didn't send `hour`. Use
  `exists` first when a condition's absence should be a deny:
  `[{ key: context.hour, operator: exists, value: true }, ...]`.
- **Deny everything by accident.** A deny rule with broad
  `resources: ["*"]` and a typo in conditions becomes a global
  outage. Test every new policy with `yggdrasil get authorization
  evaluate` (or the CLI of choice) on representative requests
  before applying.
- **Stale policies.** Policies are versioned; old runs still hit
  their version-frozen logic for replay. A policy you "fixed" 5
  minutes ago is not retroactively applied to in-flight runs that
  loaded the old version. This is intentional; it makes replay
  deterministic, but means rollouts are non-instant.
- **Policy as auth.** Policy is a refinement of RBAC. You cannot
  make a request "allow if subject is X" via policy alone — without
  an RBAC allow, policy never runs. Allowing a subject through
  policy without an RBAC binding is the most common bug in custom
  policies.
