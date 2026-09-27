# AI docs freshness stamp

Records the commit an AI (or agent-assisted human) last reconciled these docs at.
The docs-freshness CI reads it: a PR that bumps it is trusted and the AI is skipped
(economy path). See the "Docs freshness" rule in AGENTS.md / CLAUDE.md.

Before a PR: update stale docs, set verified_at_commit to your branch tip.
On arrival: if this is behind the code you touch, reconcile the docs FIRST.

verified_at_commit: 83d8f424f0eaf5379d398886bd40bf9b0245f54f
verified_diff_sha256: a890d125a63bee3daff92a73b7a46d2f0d5f3f760e5c0cc5bb30bd33b464a669
reconciler_schema: 1
verified_at: 2026-09-27
by: Codex
note: Reconciled the emergency lock contract after closing repository-binding webhook dispatch. ADR-0025, the workflow guide, security guidance, API references, deployment guidance, and observability guidance now document the pre-lookup refusal and pre-persistence recheck. Generated AI context was refreshed from the exact functional source commit. No production rollout is claimed.
