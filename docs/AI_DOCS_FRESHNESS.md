# AI docs freshness stamp

Records the commit an AI (or agent-assisted human) last reconciled these docs at.
The docs-freshness CI reads it: a PR that bumps it is trusted and the AI is skipped
(economy path). See the "Docs freshness" rule in AGENTS.md / CLAUDE.md.

Before a PR: update stale docs, set verified_at_commit to your branch tip.
On arrival: if this is behind the code you touch, reconcile the docs FIRST.

verified_at_commit: 76af0769c85ce851a8252086c7eba2363679466a
verified_diff_sha256: f9e5c2ac8e5587d6822ad5d71ad56b09841f0cd6379ed78d6630c6dda2753d51
reconciler_schema: 1
verified_at: 2026-09-26
by: Codex
note: Reconciled the inactive workflow dispatch guard with the code. features/workflows.md now documents that manifest_id and version pins are accepted only while the selected workflow record is active, and the shared resolver doc-comment matches the HTTP and message execution paths. No production rollout is claimed.
