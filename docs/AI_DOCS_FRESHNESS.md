# AI docs freshness stamp

Records the commit an AI (or agent-assisted human) last reconciled these docs at.
The docs-freshness CI reads it: a PR that bumps it is trusted and the AI is skipped
(economy path). See the "Docs freshness" rule in AGENTS.md / CLAUDE.md.

Before a PR: update stale docs, set verified_at_commit to your branch tip.
On arrival: if this is behind the code you touch, reconcile the docs FIRST.

verified_at_commit: 75e84f754a6114c90013672a9e0860ab8a7b5769
verified_diff_sha256: b20aaa6107f790f9eb356fa7cf8ba13c1c4ed89f05be1f1b3d158723739753b3
reconciler_schema: 1
verified_at: 2026-10-06
by: Codex
note: Independent review covered the Core snapshot/profile/encryption/audit and paired Console seams. Fixed effective-credential continuity and no-store contact responses, preserving DTO/authority and prior strict gate results. Updated contract/OpenAPI mirror; final exact-head CI remains required. No live contact/grant/provider mutation or deployment is claimed.
