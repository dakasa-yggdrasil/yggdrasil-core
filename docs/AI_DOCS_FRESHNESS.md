# AI docs freshness stamp

Records the commit an AI (or agent-assisted human) last reconciled these docs at.
The docs-freshness CI reads it: a PR that bumps it is trusted and the AI is skipped
(economy path). See the "Docs freshness" rule in AGENTS.md / CLAUDE.md.

Before a PR: update stale docs, set verified_at_commit to your branch tip.
On arrival: if this is behind the code you touch, reconcile the docs FIRST.

verified_at_commit: def2a6b0892e4b2107bd07bfb77218873994473f
verified_diff_sha256: e49d84c987845a594203a714b3480d9f795b4a88126afcdf3e5c29074f216c31
reconciler_schema: 1
verified_at: 2026-09-27
by: Codex
note: Reconciled the actor-channel guard for authorized workflows. ADR-0027, the workflow and security references, both OpenAPI copies, and generated AI context now describe the exact functional source commit. No production rollout is claimed.
