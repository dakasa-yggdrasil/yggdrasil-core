# AI docs freshness stamp

Records the commit an AI (or agent-assisted human) last reconciled these docs at.
The docs-freshness CI reads it: a PR that bumps it is trusted and the AI is skipped
(economy path). See the "Docs freshness" rule in AGENTS.md / CLAUDE.md.

Before a PR: update stale docs, set verified_at_commit to your branch tip.
On arrival: if this is behind the code you touch, reconcile the docs FIRST.

verified_at_commit: 4c83bc758ad2ae94d40dd691125a0c88191fc774
verified_diff_sha256: 4a3a77e13b29fed0cd7a65c7fd1e0e328212a85b7fdf99cca795b5029f9944c1
reconciler_schema: 1
verified_at: 2026-10-29
by: Giomaster
note: Reconciled the removal of the body-asserted third-party identity exchange. ADR-0088 records that POST /api/v1/auth/third-party/login, which took provider, subject, e-mail and auto_link_by_email from the request body and opened a session for any active collaborator with MFA enrolled, is removed (404 from the mux), that the browser start and callback flow is the only third-party login and is unchanged, that AuthenticateWithThirdPartyIdentity and LoginWithThirdPartyIdentityRequest stay with the callback as their only caller, that the production ingress refuses the path until a Core without it is live, and the follow-up audit of third-party sessions. ADR-0087 is not edited. The ADR index, the CHANGELOG (Security and Removed, breaking), docs/security.md, docs/features/sessions.md, docs/api-reference/README.md, the session counter note in docs/operations/observability.md and the CLAUDE.md auth bullet match the code; AGENTS.md does not describe third-party login and needs no change. Static checks only (gofmt, go build, go vet); tests run in CI, including a new PostgreSQL step in the native OIDC integration workflow. No deployment or production change.
