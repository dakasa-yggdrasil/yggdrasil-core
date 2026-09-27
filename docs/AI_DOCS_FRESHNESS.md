# AI docs freshness stamp

Records the commit an AI (or agent-assisted human) last reconciled these docs at.
The docs-freshness CI reads it: a PR that bumps it is trusted and the AI is skipped
(economy path). See the "Docs freshness" rule in AGENTS.md / CLAUDE.md.

Before a PR: update stale docs, set verified_at_commit to your branch tip.
On arrival: if this is behind the code you touch, reconcile the docs FIRST.

verified_at_commit: d7f2c6d4fb40bdc3977afed30c85c7d005620d1c
verified_diff_sha256: 6587871cb9f4ff21152b066c64826ca76874d0a49b7589308889c24c0d322291
reconciler_schema: 1
verified_at: 2026-09-27
by: Codex
note: Reconciled the fail-loud read-only workflow assertion contract. ADR-0024 and the workflow guide define its closed equal and nonempty schema, exact comparison, failure behavior, and value-redaction boundary. Generated AI context was refreshed from the exact functional source commit. No production rollout is claimed.
