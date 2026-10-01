# AI docs freshness stamp

Records the commit an AI (or agent-assisted human) last reconciled these docs at.
The docs-freshness CI reads it: a PR that bumps it is trusted and the AI is skipped
(economy path). See the "Docs freshness" rule in AGENTS.md / CLAUDE.md.

Before a PR: update stale docs, set verified_at_commit to your branch tip.
On arrival: if this is behind the code you touch, reconcile the docs FIRST.

verified_at_commit: 8a2d82ab1ddb90618bd7ac7c5720231690b80a49
verified_diff_sha256: 41bbb4efc0b6bb5a599fc71d25222f70eaecc697ecd3e7692daf23bb82065a5f
reconciler_schema: 1
verified_at: 2026-10-01
by: Codex
note: Reconciled ADR-0028, workflow feature docs, and API idempotency guidance with the exact-manifest, count-only identity snapshot and persisted-selector retry receipt. This is source and CI work; no workflow or provider activation is claimed.
