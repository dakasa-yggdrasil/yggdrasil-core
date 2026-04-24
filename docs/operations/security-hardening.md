# Security hardening

A practical checklist for taking Yggdrasil from "it runs" to "it can
hold the crown jewels". Complements
[docs/security.md](../security.md), which is the threat model
overview.

## Day-one checklist

Before the first non-platform user touches the system:

- [ ] **TLS everywhere.** Cookie marked `Secure`.
  `AUTH_SESSION_COOKIE_SECURE=true`. Ingress terminates TLS;
  inter-pod traffic in a mesh or over a VPC.
- [ ] **Default admin password rotated.** If you used
  `yggdrasil init` with a generated password, or via Helm with
  the auto-generated secret — log in, change it, re-issue tokens
  for anyone who received the bootstrap one.
- [ ] **No password-only auth in prod.** Configure OAuth/OIDC via
  `yggdrasil auth provider apply`.
- [ ] **RBAC scoped, not `*:*`.** See RBAC pitfalls in
  [features/rbac.md](../features/rbac.md#pitfalls).
- [ ] **Policy for destructive actions.** At minimum, a rule that
  denies bulk deletes without approval context.
- [ ] **Managed secrets for every credential.** Nothing inline in
  `integration_instance.credentials` that isn't fully public.
- [ ] **Encryption key in a secrets store** (cloud KMS, Vault) and
  backed up separately.
- [ ] **Bootstrap env vars removed** from running pods after first
  install (or left on, documented, and understood as idempotent).
- [ ] **Responsible disclosure process published.**
  `security@<your-domain>` ready.

## Day-one checklist continued (deployment)

- [ ] **Container image signed** (cosign or similar). Image-policy
  admission in your cluster verifies signatures.
- [ ] **Pod security context** enforced via overlays on the
  `control_plane` manifest — `runAsNonRoot: true`,
  `readOnlyRootFilesystem: false` (Go writes temp files),
  `allowPrivilegeEscalation: false`, dropped all capabilities.
- [ ] **Network policy** restricting core pods to Postgres, RMQ, and
  ingress only.
- [ ] **Postgres in a private subnet.** No public IP.
- [ ] **RMQ management UI disabled** (`RABBITMQ_MANAGEMENT_PLUGIN_
  ENABLED=false` in prod) OR restricted to ops network.
- [ ] **Ingress with rate limits.** Prevents auth endpoints from
  being brute-forced.
- [ ] **Log shipping configured, sensitive fields redacted at
  source.** Zap's structured format makes this easy — a log
  processor can strip any field matching `credentials.*`,
  `password`, `token`, `secret`.

## Ongoing hygiene

- [ ] **Rotate session signing secret** annually
  (`AUTH_SESSION_SIGNING_SECRET`). Rotation invalidates all active
  sessions — plan the communication.
- [ ] **Rotate third-party state secret** semi-annually
  (`AUTH_THIRD_PARTY_STATE_SECRET`). In-flight OAuth callbacks fail
  during rotation; it's fast (< 1 min), so just coordinate.
- [ ] **Rotate encryption key** annually or after any suspected
  compromise. See the DR playbook.
- [ ] **Review `event_log` for `authorization.evaluated` denies**
  quarterly. Spot access drift.
- [ ] **Audit bindings + collaborators** quarterly. Remove
  departed teammates, remove unused bots.
- [ ] **Review the rendered bundle before applying a new control_plane
  version.** Inspect the `steps.render.metadata.infra_objects` and
  `core_objects` in a dispatched run's output (or via the console's
  run detail view) so drift is caught before the workflow moves past
  the render step.
- [ ] **Penetration test** annually, or before a major release.

## Secrets and credentials

Beyond the features page:

- **Per-environment managed secrets.** `secret://aws-prod/access-keys`
  vs `secret://aws-staging/access-keys`. Don't share. See
  [features/secrets.md](../features/secrets.md).
- **Short-lived tokens where possible.** For automation, prefer
  short-lived tokens (STS, GitHub App tokens rotated automatically)
  over long-lived API keys stored as managed secrets.
- **Per-collaborator automation accounts.** When a CI job needs to
  call Yggdrasil, give it its own collaborator with scoped RBAC, not
  a human's token.

## Adapter security

Adapters run in your cluster with the credentials you give them.
They're as trusted as their credential.

- **Minimum-privilege credentials.** Don't give the
  `integration-aws` adapter `AdministratorAccess`; give it an IAM
  role scoped to the specific services it touches.
- **Image source.** Ship adapters from a registry you control. For
  first-party adapters pulled from `ghcr.io/dakasa-yggdrasil`,
  verify the signature.
- **Sandbox per instance where possible.** If two teams both use
  `integration-kubernetes` for different clusters, consider two
  adapter deployments, one per team — reduces blast radius if one
  credential leaks.

## RBAC + policy patterns worth stealing

### Break-glass admin

Bind the super-admin role to a subject gated by policy:

```yaml
# RBAC
roles:
  - name: break-glass-admin
    rules:
      - { effect: allow, resources: ["*"], actions: ["*"] }
bindings:
  - name: on-call-admin
    subjects: [{ type: team, id: on-call }]
    roles: [break-glass-admin]

# Policy
rules:
  - name: deny-break-glass-without-context
    effect: deny
    resources: ["*"]
    actions: ["*"]
    conditions:
      - { key: context.break_glass_ticket, operator: exists, value: false }
```

The role is powerful; policy requires a ticket id in every
request. An op without the ticket is denied.

### Production write window

```yaml
rules:
  - name: prod-writes-business-hours-only
    effect: deny
    resources: ["manifest.prod.*"]
    actions: ["create", "update", "delete"]
    conditions:
      - { key: context.hour, operator: gte, value: 18 }
      - { key: context.hour, operator: lt,  value: 6 }
```

Denies prod writes between 6 PM and 6 AM. Break-glass pattern above
still works because it runs with a ticket.

### Approved-by-human gate

Deny the write unless the caller's request context includes an
approval id that matches an open `guardian_approval` manifest.
Requires a helper (Heimdall or custom) that injects the approval
id into the request context.

## What NOT to do

- Don't disable the describe handshake check to "unstuck" a stuck
  integration. It's your contract drift detector.
- Don't put secrets in `labels`. Labels are metadata, visible in
  every list response.
- Don't accept unauthenticated writes on any endpoint. The only
  intentionally-unauthenticated endpoints are `/healthz` and
  `/readyz` — never widen that list.
- Don't share session tokens between services. Each automation gets
  its own collaborator + token.
- Don't run on a trial password-only setup with real customer data.
  OIDC + TLS + rotation are day-one concerns, not "we'll do it
  later".

## When you're unsure

The default-safe pose is:

- Deny > allow.
- Short-lived > long-lived.
- Managed secret > inline.
- Per-env > shared.
- Scoped RBAC > global admin.

Tightness has a cost — rotations, onboarding friction, occasional
"oh right, I don't have access to that". The cost of looseness is
incident severity; pay the tightness cost cheerfully.
