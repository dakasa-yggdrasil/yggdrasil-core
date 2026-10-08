# AI docs freshness stamp

Records the commit an AI (or agent-assisted human) last reconciled these docs at.
The docs-freshness CI reads it: a PR that bumps it is trusted and the AI is skipped
(economy path). See the "Docs freshness" rule in AGENTS.md / CLAUDE.md.

Before a PR: update stale docs, set verified_at_commit to your branch tip.
On arrival: if this is behind the code you touch, reconcile the docs FIRST.

verified_at_commit: 8b92e677deb3fc3d7752a2c319b7eb0d4ca602c6
verified_diff_sha256: 0903f49dbb729eb9905037ef32403cf4ee612982684fcee1ece21412cd0a6505
reconciler_schema: 1
verified_at: 2026-10-08
by: Codex
note: Contact OTP uses random credential epochs and current-time expiration. The verifier API is named for its returned identity and version; SARIF traced a false password classification from its previous name into public collaborator UUID fingerprints. Real passwords remain Argon2/legacy-verified, CodeQL stays enabled, and final CI gates must pass.
