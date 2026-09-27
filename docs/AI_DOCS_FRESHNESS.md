# AI docs freshness stamp

Records the commit an AI (or agent-assisted human) last reconciled these docs at.
The docs-freshness CI reads it: a PR that bumps it is trusted and the AI is skipped
(economy path). See the "Docs freshness" rule in AGENTS.md / CLAUDE.md.

Before a PR: update stale docs, set verified_at_commit to your branch tip.
On arrival: if this is behind the code you touch, reconcile the docs FIRST.

verified_at_commit: 322cfe32786d96c410b2a4982d7c39be5e46e617
verified_diff_sha256: 75edea0acb156a9ccfdd0d5d7fa1341305cc88539058fd8c9824981514c8ff91
reconciler_schema: 1
verified_at: 2026-09-27
by: Codex
note: Reconciled the non-persisting event publisher authorization readback. ADR-0026, the API references, the ADR index, and generated AI context now describe the exact functional source commit. No production rollout is claimed.
