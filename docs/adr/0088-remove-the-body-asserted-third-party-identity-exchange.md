# ADR-0088: Remove the body-asserted third-party identity exchange

- **Status:** Accepted
- **Date:** 2026-10-29
- **Deciders:** DaKasa Platform
- **Scope:** yggdrasil-core / third-party authentication (`/api/v1/auth/third-party/*`)
- **Supersedes:** none (closes the `POST /api/v1/auth/third-party/login` follow-up recorded in ADR-0087)
- **Superseded by:** none

## Context

Core had two kinds of third-party login:

- The browser flow. `GET /api/v1/auth/third-party/start/{provider}` signs a
  state cookie and redirects to the provider. `GET
  /api/v1/auth/third-party/callback/{provider}` verifies that state, exchanges
  the provider's authorization code with the provider's token endpoint, reads
  the provider's userinfo, and only then calls
  `repository.AuthenticateWithThirdPartyIdentity` with the provider, subject
  and email the provider returned.
- `POST /api/v1/auth/third-party/login`. Its handler decoded
  `model.LoginWithThirdPartyIdentityRequest` from the request body (provider,
  subject, email, `auto_link_by_email`, claims, session metadata) and passed
  it straight to `repository.AuthenticateWithThirdPartyIdentity`, which treats
  its input as an identity a provider already verified.

The route was public. `/api/v1/auth/*` is outside the console gate
(`requiresAuthenticatedConsoleAPI`), the `/api/v1/auth/third-party/` prefix is
exempt from CSRF, the route had no rate limit, and `TestNoUngatedMutatingRoutes`
listed it as an intended pre-session route. Any anonymous caller could:

- send `auto_link_by_email: true` with the e-mail of any active collaborator
  and any subject: Core linked a new third-party identity for that subject to
  the collaborator and opened a session;
- send the provider and subject of an identity that was already linked: Core
  opened a session for its collaborator.

`createThirdPartyAuthSession` checks only that MFA is enrolled
(`mfa_enrolled_at`); it never asks for a factor, because in the browser flow
the provider is the authentication. So every collaborator who could sign in
with MFA enrolled was exposed, and the session carried their full authority:
the console, and SSO session reuse on third-party start, which completes OIDC
logins for relying parties. A collaborator without MFA got the
enroll-required answer instead of a session.

On 2026-10-29 production answered `400 third-party provider is required` to
an empty body, so the handler was reachable. A read-only check found two
third-party identities in production, both Google, created on 2026-05-15 and
2026-06-10, with the numeric subjects Google issues. Nothing shows the
auto-link path was used to link an identity. That check covers new links
only; it does not by itself exclude sessions opened for the two existing
identities through the subject path.

No first-party client needs the route. The console never offers it. The
known callers are the `surface-auth` reverse proxy, which listed it among the
paths it forwards, and a smoke script in the `yggdrasil` CLI repository that
used exactly the auto-link shape. ADR-0087 recorded the route as an open
follow-up.

## Decision

1. Remove `POST /api/v1/auth/third-party/login` and its handler. Core has no
   route that opens a session from a provider, subject or e-mail the caller
   supplies. Third-party login is only the browser flow: `GET
   /api/v1/auth/third-party/start/{provider}` and `GET
   /api/v1/auth/third-party/callback/{provider}`, both unchanged. Every method
   and spelling of the removed path now falls through to the mux, which
   answers 404 without reading the database or setting a cookie.
2. Keep `repository.AuthenticateWithThirdPartyIdentity` and
   `model.LoginWithThirdPartyIdentityRequest`. The browser callback is their
   only caller and builds the request from the provider's own token exchange
   and userinfo. A future caller must do the same: take the identity from a
   provider exchange Core performed itself, never from the request.
3. Skip the one-release deprecation window of the API stability contract.
   The route is a security exposure, not a contract to migrate, and its known
   callers (a proxy path list and a smoke step) change in their own
   repositories.
4. Until a Core without the route runs in production, the production ingress
   refuses it: a rule in front of production Core answers 403 to every
   spelling of the path (letter case, repeated slashes, an encoded slash, a
   trailing slash) before the request reaches Core, and every other route
   keeps working. The rule is removed once the live production Core image is
   a build that contains this change, checked against the revision label of
   the running image, not against a catalog pin.
5. Guard against a return. The route leaves the `TestNoUngatedMutatingRoutes`
   allowlist, so registering it again without a gate fails CI. A unit test
   drives the real router and requires 404 or 405, no cookie and no database
   access for the removed path, and that start and callback still reach their
   handlers. A PostgreSQL gate in the native OIDC integration workflow proves
   against the migrated schema that the removed path links and signs in
   nobody, and that the browser flow still links an active collaborator by
   e-mail, signs the linked identity in again and refuses a forged state.

## Consequences

- Breaking for any client that still calls the route: it gets 404. The
  `surface-auth` proxy drops the path, and the CLI smoke drops the step; the
  browser flow needs a real provider and is not a headless smoke.
- Production Core keeps the handler until the next production Core
  candidate, which must include this change. The ingress rule is the control
  in the meantime; removing it before that image is live reopens the
  exposure.
- The CSRF exemption for the `/api/v1/auth/third-party/` prefix now covers
  only GET routes, which the CSRF middleware does not check. It is left as
  is.
- Follow-up, outside this decision: audit the third-party sessions opened
  while the route was public. Sessions opened by the callback carry
  `auth_flow: browser_callback` in their metadata; the removed route copied
  caller-supplied session metadata, so a caller could have set the same
  value, and the audit also needs the recorded source addresses and the
  identities' `last_authenticated_at`.

## Related

- ADR-0087 (records this route as a follow-up of the session lifecycle; this decision closes it)
- ADR-0003 (Core as DaKasa's OIDC provider, mediating third-party login)
