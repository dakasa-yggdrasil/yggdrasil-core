# ADR-0003: Yggdrasil-core becomes DaKasa's own OIDC Provider, mediating Google Workspace SSO

- **Status:** Accepted
- **Date:** 2026-05-05
- **Deciders:** unknown
- **Scope:** yggdrasil-core, dakasa-commons (oidcclient), Tartaro (dakasa-tartaro-api/dakasa-tartaro-fe, first consumer), Yggdrasil console (Phase 1: internal SSO)

## Context

Tartaro and the Yggdrasil console needed centralized authentication against the `dakasa.me` Google Workspace, with downstream services able to verify a single trusted identity token rather than each maintaining its own password-based login or its own direct Google OAuth integration — password-based login in `dakasa-tartaro-api` was the prior state. yggdrasil-core already had a generic third-party-auth framework (`/auth/providers`, `/auth/third-party/*`) for operator console login, but nothing let it act as a central identity authority issuing verifiable tokens that other DaKasa surfaces (Tartaro, the Yggdrasil console, future surfaces) could consume without each reimplementing auth.

## Decision

Make **yggdrasil-core itself an OIDC Provider** (Phase 1, internal-only scope) — not just an OIDC *client* to Google — using `github.com/zitadel/oidc/v3` (`op.Storage`), with Google Workspace `dakasa.me` registered as the upstream third-party IdP:

- **Storage**: `op.Storage` is implemented on top of Postgres tables — `oidc_clients`, `oidc_auth_requests`/`oidc_auth_codes` (short TTL, single-use), `oidc_refresh_tokens` (only the refresh token is persisted; access/ID tokens are stateless JWTs), `oidc_signing_keys` (current + previous, RS256), `oidc_provider_settings` (singleton row: allowed email domains, auto-provision toggle), `oidc_audit_events` — rather than delegating state to Redis or an external IdP-as-a-service.
- **Endpoints**: standard OIDC surface under `/oidc/*` — discovery, JWKS, `/authorize`, `/token`, `/userinfo`, `/end_session` — additive, coexisting with the existing `/auth/login` and `/auth/third-party/*` endpoints (not a replacement). `/oidc/authorize` delegates to the existing `/auth/third-party/start/google` flow when there's no local session cookie.
- **Domain gating + auto-provision**: `oidc_provider_settings.allowed_email_domains` (default `['dakasa.me']`) gates who can auto-provision on first Google login; a callback hook on the third-party-provider auth flow performs domain-check + auto-provision into a default team (`dakasa-internal`) for any verified `@dakasa.me` email — admins promote to higher-privilege teams (`yggdrasil-admin`, `tartaro-mod`) after the fact via console or a `bootstrap-admin` CLI.
- **Signing keys**: RSA-2048 keypairs are generated and persisted in `oidc_signing_keys` (not mounted from a K8s secret), loaded-or-created idempotently at startup (`EnsureSigningKey`, using `SELECT ... FOR UPDATE` on the settings row to serialize bootstrap races across multiple pods) — the private key never leaves the database/binary boundary via config. JWKS rotation runs on a cron (every 3 months) with a 7-day dual-serve grace window. `private_pem` is stored as plain text in Phase 1, not as a managed secret — an explicitly accepted interim risk, with managed-secret storage deferred to Phase 2.
- **Token policy**: 15-minute access/ID tokens; 7-day **sliding, rotating** refresh tokens with replay detection per BCP-225. Refresh tokens are single-use — rotating token A→B links B.`rotated_from = A`. If an already-rotated (revoked) token is replayed, the entire rotation chain from that root is revoked (`RevokeOIDCRefreshChainByRoot`, recursive CTE) — a stolen/duplicated refresh token invalidates the whole session lineage, not just the reused token. PKCE is mandatory on all clients; logout is local (not federated) in Phase 1.
- **Console embedding**: the Yggdrasil console SPA is embedded directly into the yggdrasil-core Go binary via `//go:embed` (multi-stage Dockerfile: Vite build → copy `dist/` into the Go build), rather than being served from a separate deployment, and authenticates via the same OIDC flow.
- **Downstream verification**: a shared library `dakasa-commons/oidcclient` (~150 LOC, JWKS-cache-backed `Verifier`, `AuthorizeURL`/`ExchangeCode`/`Refresh`, cache refreshed on `kid not found`) is the sanctioned way for any DaKasa service to verify Yggdrasil-issued JWTs. **Tartaro cuts over directly**: its password middleware is replaced by this verifier as the first consumer, with the password-login code removed outright (no feature flag) — rollback path is redeploying the previous Tartaro binary.
- **RBAC claims are `teams`-only**: Yggdrasil deliberately does not emit `roles` or `permissions` in the JWT — each surface decides authorization locally from team membership; Yggdrasil's OIDC responsibility never extends to "does this JWT have permission X."
- **Rate limiting**: OIDC endpoints use `unified-redis` for rate-limit counters (not per-pod in-memory).
- **Scope boundary**: multi-tenant/B2B SSO (customer-facing "enterprise tier" orgs with per-org IdP config), additional IdPs (Apple, Microsoft, Facebook), and federated logout (SLO) are explicitly deferred to a later, separately-designed phase — this decision covers internal `@dakasa.me` SSO only.

## Consequences

- Yggdrasil-core is now a security-critical, stateful OIDC authority for the whole platform — its Postgres availability and signing-key integrity/rotation become a hard dependency for every consumer that adopts `oidcclient`, not just Tartaro; a key-rotation bug is now an authentication-outage risk across every OIDC-backed surface simultaneously.
- Any future service wanting SSO must integrate via `dakasa-commons/oidcclient` against Yggdrasil's issuer rather than talking to Google directly — Google becomes an implementation detail behind Yggdrasil, not a per-service integration. There is no password-login fallback path for `@dakasa.me` staff after the Tartaro cutover.
- Refresh-token replay detection is chain-wide by design: legitimate concurrent-device use must each get its own token, since replaying a rotated-out token intentionally kills every descendant token derived from it.
- `teams`-only claims push all authorization/permission modeling into each surface individually — a deliberate, permanent scope boundary on Yggdrasil's OIDC responsibility.
- `private_pem` (the RSA signing key) is stored as plain text in Phase 1 — an explicitly accepted interim risk pending Phase 2 managed-secret storage.
- Adding a new allowed email domain, or a new default team for auto-provisioned users, is a data change (`oidc_provider_settings`/`teams` seed rows), not a code change — but changing `allowed_email_domains` directly controls who can self-provision an account. A domain misconfiguration is a silent-provisioning risk, mitigated only by an audit event (`collaborator.auto_provisioned`) and API-only visibility (no Phase-1 UI for it).
- The console being embedded in the core binary means a console-only change now requires a full yggdrasil-core rebuild/redeploy (multi-stage Docker build), coupling console release cadence to the core service's.
- Logout is local-only in Phase 1 — a user's underlying Google session survives an "end_session" call against Yggdrasil; anyone assuming logout is federated will be wrong until Phase 2 SLO ships.

## Related
- scratch: `docs/superpowers/plans/2026-05-05-yggdrasil-oidc-provider.md`
- scratch: `/Users/dakasa/projects/dakasa/yggdrasil/yggdrasil-core/docs/superpowers/specs/2026-05-05-yggdrasil-oidc-provider-design.md`
