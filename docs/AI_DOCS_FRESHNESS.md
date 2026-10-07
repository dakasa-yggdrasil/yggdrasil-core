# AI docs freshness stamp

Records the commit an AI (or agent-assisted human) last reconciled these docs at.
The docs-freshness CI reads it: a PR that bumps it is trusted and the AI is skipped
(economy path). See the "Docs freshness" rule in AGENTS.md / CLAUDE.md.

Before a PR: update stale docs, set verified_at_commit to your branch tip.
On arrival: if this is behind the code you touch, reconcile the docs FIRST.

verified_at_commit: 84bf95028dbc58512ae3be6a4609319e50931343
verified_diff_sha256: 555bd1f004a3453db76fd9643061e9ac9e58c2299f1de21ffd843aecc1a88d73
reconciler_schema: 1
verified_at: 2026-10-07
by: Codex
note: Reviewed committed typed leadership, explicit intent and team-row CAS, complete formal editor state, frozen snapshot time, conditional operator contact declarations, ADRs0032/0033 and mirrored OpenAPI. Required PostgreSQL coverage now demands15 authority roots with no skips. Static review and formatting only; final remote CI remains required. No live contact/owner/grant mutation or deployment is claimed.
