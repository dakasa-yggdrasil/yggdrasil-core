# AI docs freshness stamp

Records the commit an AI (or agent-assisted human) last reconciled these docs at.
The docs-freshness CI reads it: a PR that bumps it is trusted and the AI is skipped
(economy path). See the "Docs freshness" rule in AGENTS.md / CLAUDE.md.

Before a PR: update stale docs, set verified_at_commit to your branch tip.
On arrival: if this is behind the code you touch, reconcile the docs FIRST.

verified_at_commit: 1685e6b7e9df8336b6f37c9416f563d7c130c117
verified_diff_sha256: 7caa2131f4787d19e7e10158201896c54fc51fa0866ad886db9edf897b3aea4b
reconciler_schema: 1
verified_at: 2026-10-06
by: Codex
note: Reviewed declared contact provenance, server-side provisional access and recovery, exact sensitive grants, capability-bound consistent snapshots, migration53 private projection and synchronized OpenAPI. Contract and cutover docs reflect committed source; no deployment or contact/grant mutation is claimed.
