# ADR-0031: Export restricted consistent directory snapshots

- **Status:** Superseded by 0032
- **Date:** 2026-10-06
- **Deciders:** DaKasa Platform
- **Scope:** yggdrasil-core / directory machine reads
- **Supersedes:** 0019
- **Superseded by:** 0032

## Context

The existing directory credential resolves one active collaborator by email or UUID and asks an authorization oracle. It cannot export the lifecycle, formal leadership, membership windows and hierarchical relationships needed by a directory consumer. Reusing a console credential would disclose extensible personal and employment data. Independent pages can otherwise combine revisions or cause a consumer to retire people after an incomplete read.

## Decision

Add a separate directory snapshot capability and exact read route. Return only typed canonical collaborators, teams, memberships and explicitly allowlisted external identity links. Resolve team owners to canonical UUIDs; manager and team-parent graphs must have valid references and no cycles. Job titles and membership roles do not confer leadership.

Retain ADR-0019's credential lifecycle, isolated machine branch, exact legacy routes, capability checks, minimal legacy projections and synchronous audit. Extend its closed capability list only with `directory.snapshot` and `directory.contacts.phone` and its route list only with `GET /api/v1/directory/snapshot`. External identity links require an exact canonical integration-instance UUID allowlist. Old capabilities do not authorize the new route.

Require a second phone-contact capability for declared phone disclosure. Bind deterministic pagination to one opaque principal/projection revision, refusing drift rather than returning a mixed dataset. Enforce resource bounds without silent truncation. Audit attributable results synchronously before response and never log contacts, cursors, credentials or arbitrary metadata.

Fix `observed_at` to the first page's UTC transaction time and bind it in the authenticated cursor. Membership boundaries are inclusive at that time. Bind the revision to effective principal capabilities and allowlists as well as projected data. Expose `phone_profile_required` directly as a typed collaborator state; it is neither a lifecycle status nor an inference from a missing contact.

Consumers may replace their projection only after collecting every page of one revision and validating completeness. This API grants directory observation, not messaging consent, provider mutation, organizational business decisions or unrestricted console access.

## Consequences

The old directory routes and capabilities retain their narrow meaning. New consumers need a reviewed capability inventory, an external identity instance allowlist and an explicit snapshot integrity secret. Directory errors retain the last complete projection; an incomplete result is never an authoritative deletion list.

## Related

- ADR-0019: restricted directory machine principals
- ADR-0030: declared phone contact authority
