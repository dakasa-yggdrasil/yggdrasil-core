# AI docs freshness stamp

Records the commit an AI (or agent-assisted human) last reconciled these docs at.
The docs-freshness CI reads it: a PR that bumps it is trusted and the AI is skipped
(economy path). See the "Docs freshness" rule in AGENTS.md / CLAUDE.md.

Before a PR: update stale docs, set verified_at_commit to your branch tip.
On arrival: if this is behind the code you touch, reconcile the docs FIRST.

verified_at_commit: bbfd318cd4a65c63fa0588c2c0515ed1adc92658
verified_diff_sha256: 347f7b68f556f8c0597ab55e253cfa93074afefd4d7c817b194bede7fa8ceaf7
reconciler_schema: 1
verified_at: 2026-10-01
by: Codex
note: Reconciled ADR-0028, workflow feature docs, and API idempotency guidance with the human-session-only, exact-manifest, count-only identity snapshot and persisted-selector retry receipt. This is source and CI work; no workflow or provider activation is claimed.
