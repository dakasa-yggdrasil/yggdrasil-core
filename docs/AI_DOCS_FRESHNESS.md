# AI docs freshness stamp

Records the commit an AI (or agent-assisted human) last reconciled these docs at.
The docs-freshness CI reads it: a PR that bumps it is trusted and the AI is skipped
(economy path). See the "Docs freshness" rule in AGENTS.md / CLAUDE.md.

Before a PR: update stale docs, set verified_at_commit to your branch tip.
On arrival: if this is behind the code you touch, reconcile the docs FIRST.

verified_at_commit: f9315076cb78bd477fad7c7463010fa9424a5da7
verified_diff_sha256: 341b83fc9ae1a8709086283be7756bb379cac9785c0b57e0533dcb0ee6b8557b
reconciler_schema: 1
verified_at: 2026-09-24
by: Claude
note: Reconciled ADR-0022 (workflow-run credential surface loaded once, set-but-blank workflow inventory refused, per-surface refusal of cross-scope digest collisions, bridge refusals kept apart from principals, explicit development YGGDRASIL_ENV for the credential-free workflow, manifest-write and event posture, boot summary, durable legacy bridge audit, metrics and run stamp) with the code. security.md, features/workflows.md, features/events.md, api-reference openapi.md and both openapi.json copies, operations/observability.md (two new families), quickstart.md, deployment.md, README, CHANGELOG (breaking), the CLAUDE.md auth bullets and the ADR index match. Generated AI context refreshed. No production rollout is claimed.
