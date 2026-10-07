# AI docs freshness stamp

Records the commit an AI (or agent-assisted human) last reconciled these docs at.
The docs-freshness CI reads it: a PR that bumps it is trusted and the AI is skipped
(economy path). See the "Docs freshness" rule in AGENTS.md / CLAUDE.md.

Before a PR: update stale docs, set verified_at_commit to your branch tip.
On arrival: if this is behind the code you touch, reconcile the docs FIRST.

verified_at_commit: b9cec1904d71584f583d049f5b57cef5391c4899
verified_diff_sha256: 569e48f9449604588e9c0e55d94f37916f0fccb7b7df2073e9325970b4acbf94
reconciler_schema: 1
verified_at: 2026-10-07
by: Codex
note: Reviewed the authenticated operator-provenance fix after the actual HTTP PostgreSQL regression exposed the legacy header lookup. X-Actor cannot attribute contact declarations; typed leadership, CAS/MFA/grants, independent phone completion and all mirrored contracts remain unchanged. Independent delta review approved; exact-head remote CI15 roots/no skips remains required. No live mutation or deployment is claimed.
