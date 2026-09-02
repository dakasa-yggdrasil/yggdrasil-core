# ADR-0014: Bootstrap confidential OIDC clients from read-only Secret files

- **Status:** Accepted
- **Date:** 2026-09-02
- **Deciders:** Giovanni Rios Martins
- **Scope:** yggdrasil-core / confidential OIDC client lifecycle
- **Supersedes:** —
- **Superseded by:** —

## Context

Server-side applications need confidential OIDC clients whose plaintext secret must remain in the relying application's secret boundary. Registering those clients through a workflow input, an integration RPC, a generic SQL adapter, or an administrative HTTP token would move secret material or its reusable bcrypt verifier through audit and orchestration surfaces that do not own it. Manual database registration also leaves callback, logout, grant, scope, authentication-method, and PKCE drift undetected.

The Core already owns the `oidc_clients` schema and OIDC protocol behavior. Kubernetes can project one property from an external secret as a read-only file without exposing it in a manifest or process environment.

## Decision

Make yggdrasil-core the only component that reconciles environment-managed confidential OIDC clients.

- Read a strict, versioned document from `YGGDRASIL_OIDC_CLIENTS_FILE`. The file must be a regular, non-writable file and is intended to be mounted from a Kubernetes Secret populated by External Secrets Operator.
- Store only a bcrypt verifier with cost 12 or greater in that file. Plaintext client secrets are forbidden by the schema and remain solely in each relying application's secret boundary.
- Require the explicit confidential-client contract: `client_secret_basic`, exact HTTPS callback and post-logout URIs, restricted scopes and grants, and PKCE S256.
- Validate the full document before writing. Reconcile every declared client and read it back inside one database transaction; any validation, write, or readback mismatch rolls the whole set back and fails startup.
- Permit an input-free, in-process `oidc_client.verify_bootstrap_file` workflow operation to compare the same mounted file to persisted state after startup or a Secret rotation. The operation accepts no `with` input, performs no mutation, and exposes only public client identifiers and a count.
- Enforce `pkce_required` while creating every authorization request, including confidential clients. The upstream OIDC library already verifies every supplied S256 challenge during code exchange; requiring and validating the challenge before persistence closes the confidential-client bypass.

## Consequences

- A missing, writable, malformed, weak-hash, or semantically invalid configured file prevents the OIDC server from starting when the file path is configured.
- Rotating a confidential client requires updating the external bcrypt verifier and the relying application's plaintext secret coherently, restarting Core to reconcile it, and dispatching the input-free verification operation before a credential-boundary probe.
- The bcrypt verifier is still sensitive because it enables offline guessing. It exists only in the external secret, the projected file, process memory, and the `oidc_clients` table; it never enters workflow inputs, integration RPC, results, events, or logs.
- Deployments that do not configure `YGGDRASIL_OIDC_CLIENTS_FILE` retain their existing behavior. Public native clients continue to use `YGGDRASIL_OIDC_PUBLIC_CLIENTS_JSON` under ADR-0011.

## Related

- ADR-0003 (implements its mandatory-PKCE decision for confidential clients)
- ADR-0011 (parallel lifecycle for public native clients)
- ADR-0012 (preserves the workflow sensitive-output boundary)
