# AI docs freshness stamp

Records the commit an AI (or agent-assisted human) last reconciled these docs at.
The docs-freshness CI reads it: a PR that bumps it is trusted and the AI is skipped
(economy path). See the "Docs freshness" rule in AGENTS.md / CLAUDE.md.

Before a PR: update stale docs, set verified_at_commit to your branch tip.
On arrival: if this is behind the code you touch, reconcile the docs FIRST.

verified_at_commit: 13a6eccb00b0da33371bbd4c528ba208f61270e2
verified_diff_sha256: 6d1b1cad6a52859f76ca0dfe5cc6235fbf82384a8286d86a71d3f41bf278c946
reconciler_schema: 1
verified_at: 2026-09-20
by: Claude
note: Reconciled the directory machine principal contract (ADR-0019): third hashed inventory with exact capabilities and Tartaro instance allowlist, the three exact collaborator read routes with minimal projections, fail-closed 401/403/400 behavior, audit shape, and boot validation. No change to human console routes.
