# AI docs freshness stamp

Records the commit an AI (or agent-assisted human) last reconciled these docs at.
The docs-freshness CI reads it: a PR that bumps it is trusted and the AI is skipped
(economy path). See the "Docs freshness" rule in AGENTS.md / CLAUDE.md.

Before a PR: update stale docs, set verified_at_commit to your branch tip.
On arrival: if this is behind the code you touch, reconcile the docs FIRST.

verified_at_commit: db67358053327108baa695343eae96f55d2d7dbc
verified_diff_sha256: 6f9dbc25cdf2f817888346a080c89c42accbca16bf7e006dcfe62338c7c08844
reconciler_schema: 1
verified_at: 2026-09-26
by: Codex
note: Reconciled the inactive workflow dispatch guard with the code after independent review. features/workflows.md documents that manifest_id and version pins are accepted only while the selected workflow record is active; the shared resolver additionally requires a case-insensitive workflow kind match, and its doc-comment matches the HTTP and message execution paths. No production rollout is claimed.
