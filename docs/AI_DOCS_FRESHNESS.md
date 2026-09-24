# AI docs freshness stamp

Records the commit an AI (or agent-assisted human) last reconciled these docs at.
The docs-freshness CI reads it: a PR that bumps it is trusted and the AI is skipped
(economy path). See the "Docs freshness" rule in AGENTS.md / CLAUDE.md.

Before a PR: update stale docs, set verified_at_commit to your branch tip.
On arrival: if this is behind the code you touch, reconcile the docs FIRST.

verified_at_commit: a27d7e08716a003e000781958fc9357e38f8c259
verified_diff_sha256: 1ef3f27b2bb3b06b980117b7fc962cfa20a7d93114ee76e4d89924f86c402c42
reconciler_schema: 1
verified_at: 2026-09-24
by: Claude
note: Reconciled ADR-0021 (logical event publisher grants) with the code: features/events.md (exact and logical grants, 403/503, reserved metadata, load-once), security.md event writers, api-reference openapi.md and both openapi.json copies (new 403 wording, 503, EventPublishProblem), error_codes.md (event.authorization_denied, event.authorization_unavailable), CHANGELOG, the CLAUDE.md event writers bullet and the ADR index. Generated AI context refreshed. No production rollout is claimed.
