# ADR-0005: Unify password credential lifecycle into `auth_identities`; argon2id as the hashing scheme; deprecate `yggdrasil-identities`

- **Status:** Accepted
- **Date:** 2026-05-15
- **Deciders:** unknown
- **Scope:** yggdrasil-core (auth/identity)
- **Supersedes:** `collaborator_password_credentials` table; the standalone `yggdrasil-identities` service (JWT-only, no MFA/sessions) — marked deprecated, not physically removed in this change
- **Superseded by:** —

## Context

yggdrasil-core had password+MFA login, sessions, and third-party (OIDC) auth, but password data lived in a separate `collaborator_password_credentials` table split from `auth_identities` (which already owns WebAuthn/TOTP/recovery-code/MFA state), forcing a join for every security decision and making it awkward to gate on both password and MFA state together. There was no credential lifecycle at all: no setup-link onboarding, no authenticated change flow, no forgot-password recovery, and no rotation — new collaborators could only enter via SSO/IdP, local passwords never expired, and password loss required manual DB intervention.

Two of the project's abiding principles apply here: (1) only yggdrasil-core imports structurally — surfaces/integrations are opt-in and the core API must be self-sufficient without them; (2) zero dependency on integrations — the admin-assisted path (an operator issues a setup/reset link) must work on a bare Yggdrasil install, with integration-driven notification (e.g. a Slack DM) as a pure opt-in enhancement via the outbox.

## Decision

Consolidate all local-auth credential state into `auth_identities` as the single source of truth and build the full credential lifecycle around it:

- Migration 00027 adds `password_hash`, `password_scheme`, `password_updated_at`, `password_expires_at`, `password_must_change`, `password_metadata` to `auth_identities`, backfills from `collaborator_password_credentials`, and drops that table in the same migration/transaction.
- Migration 00028 adds `auth_credential_tokens` (`purpose IN ('setup','reset')`, `UNIQUE(token_hash)`) for single-use, hash-stored, TTL-bound setup/reset tokens, redeemed via an atomic `UPDATE ... WHERE consumed_at IS NULL RETURNING`.
- `argon2id` (RFC 9106, params env-tunable) is the hashing scheme for all new/changed passwords; the legacy `pbkdf2_sha256` scheme is retained **verify-only** (a `Scheme` string persisted alongside the hash selects the verifier, so existing hashes keep working without a forced reset) and is transparently re-hashed to argon2id on successful login.
- 5 endpoints under `/api/v1/auth/passwords/*`: `setup-tokens` (admin-issued invite), `setup` (public, token-gated, opens a session with `mfa_enrollment_required`), `change` (authenticated, MFA inline), `forgot` (public, always-202 anti-enumeration regardless of whether the identifier exists), `reset` (public, token + mandatory MFA gate).
- Middleware enforces, on all authenticated `/api/v1/*` routes except the escape-hatch endpoints themselves: `mfa_enrollment_required` blocks until a factor is enrolled; `password_change_required` blocks when `password_must_change` or the password is past `password_expires_at`. The login response also carries both flags so surfaces can redirect proactively (middleware is belt-and-suspenders).
- A rotation runner (ticker-based, batched, idempotent) periodically flips `password_must_change=true` for collaborators whose `password_expires_at` has elapsed (default period 90d, configurable), scoped to `status IN ('active','on_leave')`.
- 5 new canon event types (`credential.setup_token_issued`, `credential.password_setup_completed`, `credential.password_changed`, `credential.reset_token_issued`, `credential.password_rotation_required`) are emitted for audit/opt-in consumers; payloads never carry the raw token or setup URL (retrieving those requires a separately-protected render endpoint / admin API).
- `yggdrasil-identities` (the legacy standalone service) is marked `DEPRECATED` in its README; physical removal is an explicit follow-up, not part of this change.

## Consequences

- All password-credential reads/writes must target `auth_identities`; any code still joining the old table breaks after migration (2 known call sites in `repository/auth.go` needed refactoring).
- Every authenticated endpoint now implicitly depends on the `mfa_enrollment_required` / `password_change_required` middleware ordering; new routes must be added to the exemption list deliberately if they need to be reachable before enrollment/rotation completes.
- Password strength policy (`ValidateStrength`: substring vs. Levenshtein identity matching, Unicode normalization) and rotation eligibility (`on_leave` inclusion) and reset-URL construction are explicitly left as tunable, human-authored decision points rather than hard-coded or guessed.
- No password-history/reuse-prevention is implemented — deliberately out of scope per NIST 800-63B (2017+) guidance, which does not require it.
- `yggdrasil-identities` keeps running (marked deprecated, not removed) until a separate removal issue lands; consumers must not assume it is gone.
- Recovery for a user with no MFA enrolled is intentionally **not** self-service (`reset` requires an MFA gate) — the only path is a fresh admin-issued setup token, a deliberate security trade-off over convenience.

## Related
- scratch: `/Users/dakasa/projects/dakasa/yggdrasil/yggdrasil-core/docs/superpowers/plans/2026-05-15-credential-lifecycle.md`
- scratch: `/Users/dakasa/projects/dakasa/yggdrasil/yggdrasil-core/docs/superpowers/specs/2026-05-15-credential-lifecycle-design.md`
