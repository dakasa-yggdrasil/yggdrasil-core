# ADR-0104: Separate the retirement observer from historical mutation authority

**Status:** Proposed

Date: 2026-11-04

Scope: Existing dedicated AWS read-only service and Core ordinary and partial-forward retirement absence qualification.

## Context

A settled historical destroy receipt binds its original supplier Source, complete
configuration and request digest. Correcting a current provider read must not retag
that historical authority or rewrite a grant. Successful empty provider responses
also require strict raw-response interpretation by the provider adapter.

## Decision

Extend the existing dedicated accepted-failed read-only service with one closed
retirement-absence operation. Authenticate its actual current Source/version through
its fixed Describe/execute origin, independently of the historical normal supplier.
Core supplies the exact protected canonical receipt and its genuine owning read identity;
the observer receives no grant callback bearer and exposes no mutation dispatch.
Preserve the historical supplier type, instance, config, request digest, grants,
settlements and original provider creator identity.

Retain the current observer Source and exact closed public return bytes as optional
paired provenance on each existing append-only ordinary or forward read return. Fresh historical AWS
absence success and pending continuation require the complete pair and all existing
receipt/tuple/lease/deadline/auxiliary joins. Historical unextended records retain
their old bytes and validation. Failed calls retain actual failure clocks and flags
even when no valid wrapper exists; they cannot qualify absence. One original
five-second challenge covers resolution, receipt capture, Describe and execute.

Ordinary reads hash their actual `GuestNativePoweroffReadV2` challenge; they do
not invent a forward admission. Their existing1MiB stored-record cap remains;
forward reads retain their existing2MiB cap. Both preserve the original60s finish
invocation, each five-second read and separate five-second failure custody.

Use the existing API, workflow store, service, authentication and schema. Keep SDK
and XML semantics in the provider adapter. Preserve the existing accepted-failed
operation and all four disposal consumers when binding the new real publication.

## Consequences

A qualified new adapter publication and qualified compatible Core build are needed;
old Source pins cannot claim this protocol. An unbound new route refuses. This
change creates no new retirement admission, destroy attempt, Guest replay, budget,
lease, principal, database schema or deployment authority. Source/CI fixtures and
production qualification remain distinct.
