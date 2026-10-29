# AI docs freshness stamp

Records the commit an AI (or agent-assisted human) last reconciled these docs at.
The docs-freshness CI reads it: a PR that bumps it is trusted and the AI is skipped
(economy path). See the "Docs freshness" rule in AGENTS.md / CLAUDE.md.

Before a PR: update stale docs, set verified_at_commit to your branch tip.
On arrival: if this is behind the code you touch, reconcile the docs FIRST.

verified_at_commit: 155231473b8b74a5965ea8e9370ce5dd10de0d7f
verified_diff_sha256: d529a928dd95af0ff0f6fc0e896dadacd81eb42cb8905581d02d2fcebc180404
reconciler_schema: 1
verified_at: 2026-10-29
by: Giomaster
note: Reconciled the live Tartaro effective actions change. ADR-0085 retires the materialized tartaro_actions trait (sync route, console trait and drift fields, migration script and committed binary) and supersedes ADR-0009; ADR-0086 records the shared authorization predicate for the console and directory variants, the god_mode verdict, the permission-catalog wildcard expansion that fails closed, and the god_mode key added to the minimal directory projection. docs/security.md, CLAUDE.md, CHANGELOG and the ADR index match the code. Static checks only (gofmt, go build, go vet); tests run in CI. No deployment or production change.
