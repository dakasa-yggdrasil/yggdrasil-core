# ADR-0062: Preserve primary HTTP with same-owner secondary TLS

- **Status:** Accepted
- **Date:** 2026-10-21
- **Deciders:** Integration owner under the operator-authorized architecture migration
- **Scope:** Core HTTP transport and mixed-process rollout
- **Supersedes:** —
- **Superseded by:** —

## Context

Private ephemeral authority belongs to the original Core process and requires an actual TLS connection. Enabling TLS on the existing HTTP port changes transport for every caller at once. Mixed old/new processes behind the current HTTP service need a way to retain that service while exposing direct TLS to the same handler and authority owner.

## Decision

Add an explicit optional `HTTP_TLS_SECONDARY_ADDR` using the existing mounted certificate/key identity. Preserve primary HTTP and serve TLS on the additional socket through the exact same API handler and private authorization registry. Without this variable, retain the existing HTTP or primary-TLS behavior. Load and validate identity and secondary address before HTTP database/OIDC bootstrap. Refuse blank, noncanonical, hostname-based, zoned, zero-port and same-port addresses. Bind all sockets before starting any server; close already bound sockets on failure. Shut down both servers under the caller's same context without renewing its deadline.

## Consequences

This enables a transport-compatible mixed rollout without creating a second authority owner or trusting forwarding headers. It does not configure DNS, certificates, proxy routes or network access, nor make a load-balanced endpoint target the process that owns an ephemeral token. Deployment must provide verified certificate identity, direct TLS reachability and correct original-process routing. A failed listener bind does not undo earlier addon or database/OIDC initialization. Certificate rotation continues to require process restart.

## Related

- ADR-0027 (authenticated actor channels)
- ADR-0061 (source-owned service contract)
