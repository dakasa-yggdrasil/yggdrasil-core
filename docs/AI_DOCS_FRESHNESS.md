# AI docs freshness stamp

Records the commit an AI (or agent-assisted human) last reconciled these docs at.
The docs-freshness CI reads it: a PR that bumps it is trusted and the AI is skipped
(economy path). See the "Docs freshness" rule in AGENTS.md / CLAUDE.md.

Before a PR: update stale docs, set verified_at_commit to your branch tip.
On arrival: if this is behind the code you touch, reconcile the docs FIRST.

verified_at_commit: f9a20b3d3aae45c5158b61e9559e9bf0b4200f99
verified_diff_sha256: 51e8f75061f9aaea5215ec65facb700909b5f0378dd8ded89721e4bbef14d77f
reconciler_schema: 1
verified_at: 2026-09-21
by: Claude
note: Reconciled the directory machine principal contract (ADR-0019) including the non-canonical path rule: a doubled-slash or dot-segment spelling that escapes the gate prefixes is refused by the directory branch (401/403, audited) before the mux can answer its cleaned-path redirect; anonymous, session, console JWT, and unknown-bearer callers keep the redirect. Regenerated .ai/ai_context.json and docs/REPO_SUMMARY.generated.md. No change to human console routes.
