# AI docs freshness stamp

Records the commit an AI (or agent-assisted human) last reconciled these docs at.
The docs-freshness CI reads it: a PR that bumps it is trusted and the AI is skipped
(economy path). See the "Docs freshness" rule in AGENTS.md / CLAUDE.md.

Before a PR: update stale docs, set verified_at_commit to your branch tip.
On arrival: if this is behind the code you touch, reconcile the docs FIRST.

verified_at_commit: 649c278fcedafe4c7ec7bb0cf63209070d7026b7
verified_diff_sha256: d0bcc40e6e755538c0d09f19adc83fba7d030da2cc0688db06ca0d1907d53dae
reconciler_schema: 1
verified_at: 2026-09-24
by: Claude
note: Reconciled ADR-0021 (logical event publisher grants) with the code after the adversarial review: one resolution statement per logical event, control characters, set-but-blank inventory refusal, separate legacy bridge refusal, cancellation logging, case-insensitive metadata stripping and the PostgreSQL proof in the native-oidc-postgres job. features/events.md, security.md, api-reference openapi.md and both openapi.json copies, error_codes.md, CHANGELOG, the CLAUDE.md event writers bullet and the ADR index match. Generated AI context refreshed. No production rollout is claimed.
