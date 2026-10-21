# ADR-0061: Verify the public Core service contract explicitly

- **Status:** Accepted
- **Date:** 2026-10-21
- **Deciders:** Integration owner under the operator-authorized architecture migration
- **Scope:** Public Core service architecture and source contract verification
- **Supersedes:** —
- **Superseded by:** —

## Context

The public Core service descriptor selects a checker designed for private DaKasa service scaffolds. The released checker requires another repository namespace, Air, vendoring and a central development workflow that this repository does not use. Correcting its identity must not erase its missing architectural contract or turn a LAB exception into production acceptance. Dynamic adapter/provider/surface endpoints and build-tagged native qualification also prevent a truthful fixed empty dependency graph.

## Decision

Select `public-go-module-v1` explicitly in the service-owned descriptor or doctor flag. Missing selectors retain legacy behavior, including cross-service duplicate checks; unknown selectors fail. Verify the exact public module/repository identity, source-owned layout and a closed versioned contract with nonempty graph sections, hash-bound evidence and a complete current non-test runtime source census. Fail if evidence or sources change, if source coverage is incomplete, or if review remains candidate/unresolved.

Record actual route registrations, dedicated pre-mux dispatch branches, authentication owners, transactional event emitters and schema mappings, logical RPC consumers, HTTP/SDK destinations and build constraints. Express deployment-selected destinations as parameterized families with their actual configuration/authority owners. Do not invent a fixed deployed endpoint list, a production workload roster, a human approval, or authority from a schema fixture. A source census is not a production readback.

Keep actual deployment topology, immutable Core/Guest images and provenance, native provider/workload qualification, current identities/leases, schema/restore compatibility, SLO/canary utility and rollout/rollback as independent operational gates. Acceptance of the source graph cannot satisfy those gates by itself. Full integrated CLI command/catalog tests and independent source review are required before the candidate contract is accepted.

## Consequences

A new runtime source or changed byte invalidates the source census until it is regenerated and reviewed. The public repository no longer needs an unrelated private scaffold to demonstrate its own real contract. The existing `svc-doctor` required-check name remains; the command consumes the descriptor selector, so reconciliation does not omit or rename the gate. No runtime endpoint, network grant or provider permission changes merely by adding the contract/checker.

## Acceptance evidence

The integration owner independently reviewed the source graph and the actual compiled owning CLI, including its clean publication identity. `docs/service-contract/REVIEW.json` records the exact evidence and scope. This accepts the source-checking architecture; it does not assert human signoff, native execution, live deployment bindings or production rollout success.
