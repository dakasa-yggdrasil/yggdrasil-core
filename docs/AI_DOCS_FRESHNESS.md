# AI docs freshness stamp

Records the commit an AI (or agent-assisted human) last reconciled these docs at.
The docs-freshness CI reads it: a PR that bumps it is trusted and the AI is skipped
(economy path). See the "Docs freshness" rule in AGENTS.md / CLAUDE.md.

Before a PR: update stale docs, set verified_at_commit to your branch tip.
On arrival: if this is behind the code you touch, reconcile the docs FIRST.

verified_at_commit: 9b395025ba138c36a642ca24bb9cbdad1a920acf
verified_diff_sha256: bd55ddba1871aeeb4547c76b0c2efa1a06909cfca7d3700c7b984a8808695fcf
reconciler_schema: 1
verified_at: 2026-10-06
by: Codex
note: Reviewed the safe authority buffer allocation after the CodeQL finding; effective-credential MAC binding, no-store contact responses and paired contracts remain unchanged. Functional, lint and all required PostgreSQL gates passed the prior head; final security/CI verdict remains required. No live contact/grant/provider mutation or deployment is claimed.
