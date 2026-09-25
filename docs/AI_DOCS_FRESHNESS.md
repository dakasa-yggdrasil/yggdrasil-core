# AI docs freshness stamp

Records the commit an AI (or agent-assisted human) last reconciled these docs at.
The docs-freshness CI reads it: a PR that bumps it is trusted and the AI is skipped
(economy path). See the "Docs freshness" rule in AGENTS.md / CLAUDE.md.

Before a PR: update stale docs, set verified_at_commit to your branch tip.
On arrival: if this is behind the code you touch, reconcile the docs FIRST.

verified_at_commit: 7622a8b6c5102d68e6bc1008f6c418097ec6ee46
verified_diff_sha256: be78486cf584f528661725bd1d3fe53b9f5f75634abc52fcaa35a4b029c12b00
reconciler_schema: 1
verified_at: 2026-09-25
by: Claude
note: Reconciled ADR-0022 (workflow-run credential surface loaded once, set-but-blank workflow inventory refused, per-surface refusal of cross-scope digest collisions, bridge refusals kept apart from principals, explicit development YGGDRASIL_ENV for the credential-free workflow, manifest-write, event and deploy-family (integration install, bootstrap, product deploy) posture, boot summary, durable legacy bridge audit, metrics and run stamp) with the code. security.md, features/workflows.md, features/events.md (generic local-compatibility paragraph included), features/integrations.md (install auth), api-reference openapi.md and both openapi.json copies, operations/observability.md (two new families), quickstart.md, deployment.md, cli.md, README, CHANGELOG (breaking), the CLAUDE.md auth bullets, the handler and gate doc-comments and the ADR index match. Generated AI context refreshed. No production rollout is claimed.
