# ADR-0011: Bootstrap internal public OIDC clients declaratively

- **Status:** Accepted
- **Date:** 2026-08-25
- **Deciders:** Giovanni Rios Martins
- **Scope:** yggdrasil-core / internal OIDC client lifecycle
- **Supersedes:** —
- **Superseded by:** —

## Context

Internal native tools such as the common DaKasa CLI need collaborator SSO without embedding a client secret. Registering those clients manually after every environment bootstrap creates configuration drift, while treating a native CLI as a confidential client would distribute a shared secret to developer machines. The registration path must preserve the existing security boundary: exact redirect matching, mandatory PKCE, restricted grant types, and no accidental conversion of an existing confidential client.

## Decision

Bootstrap reviewed internal public OIDC clients from the strict `YGGDRASIL_OIDC_PUBLIC_CLIENTS_JSON` startup configuration.

- Every entry is a public client and therefore has no client secret.
- Authorization Code with PKCE S256 is mandatory. Only `authorization_code` and `refresh_token` grants may be declared.
- Redirect URIs are exact. HTTPS is required except for HTTP callbacks whose host is `localhost` or a loopback IP.
- Client identifiers, scopes, token lifetimes, entry count, and JSON fields are validated before any write. Invalid configuration fails startup without partially applying the list.
- Reconciliation is idempotent. It may update a previously bootstrapped public client, but it must fail closed when the same identifier already belongs to a confidential client.
- This startup contract is for reviewed first-party clients. Runtime or third-party client administration remains a separate privileged lifecycle.

## Consequences

- A new internal native client requires a reviewed deployment configuration change and a Yggdrasil restart; it cannot silently self-register.
- Native tools can use the system browser and loopback callback without storing a client secret.
- An invalid entry or a public/confidential identifier collision intentionally makes the deployment unready instead of weakening an existing client.
- Operators must keep the declarative client list synchronized across environments that are expected to support the same internal tools.

## Related

- ADR-0003 (refines the internal OIDC provider and mandatory-PKCE decision)
