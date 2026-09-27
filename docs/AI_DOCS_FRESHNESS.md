# AI docs freshness stamp

Records the commit an AI (or agent-assisted human) last reconciled these docs at.
The docs-freshness CI reads it: a PR that bumps it is trusted and the AI is skipped
(economy path). See the "Docs freshness" rule in AGENTS.md / CLAUDE.md.

Before a PR: update stale docs, set verified_at_commit to your branch tip.
On arrival: if this is behind the code you touch, reconcile the docs FIRST.

verified_at_commit: 845701d1b6af4034b08a996831115bba43cdd597
verified_diff_sha256: 56dd8639174aae64b74795ea350ee7ce5f601b1323bbd91ec92f9e8f161b49ab
reconciler_schema: 1
verified_at: 2026-09-27
by: Codex
note: Reconciled the actor-channel guard for authorized workflows. ADR-0027, the workflow and security references, both OpenAPI copies, and generated AI context now describe the exact functional source commit. No production rollout is claimed.
