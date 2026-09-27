# ADR-0026: Expose a non-persisting event grant readback

- **Status:** Accepted
- **Date:** 2026-09-27
- **Deciders:** Giovanni Martins
- **Scope:** yggdrasil-core / event publisher authorization
- **Supersedes:** —
- **Superseded by:** —

## Context

An adapter can prove that its event bearer exists only by publishing a mutation
event. Reading Kubernetes Secret metadata proves projection ordering, not that
the bearer loaded by the adapter matches the principal inventory or that the
effective grant covers the event it will emit. Production reconciliation needs
that proof before the provider mutation, when no audit event should yet exist.

Returning the raw principal inventory would expose credential digests and more
authorization detail than the adapter needs. Treating a caller attestation or a
Secret resource version as grant content would leave the original gap open.

## Decision

Accept active hashed event-publisher credentials on the exact read-only route
`POST /api/v1/events/authorization`. Reject console, workflow, anonymous and
legacy migration credentials. Apply the same exact/logical grant decision used
by `POST /api/v1/events`, but never insert or materialize an event.

On success, return the authenticated principal id, queried tuple, matched grant
form, principal expiry, total grant count and a SHA-256 of the complete grant
set. Never return the bearer or configured credential digest. The grant-set
hash preimage is a JSON array of `{provider,instance_id,event_type}` objects,
sorted lexicographically by those three fields; logical grants render
`instance_id` as `<namespace>/<name>`.

Denied and unavailable logical lookups keep the publish route's indistinguishable
403 and fixed 503 behavior.

## Consequences

Adapters can bind a live bearer to a reviewed source inventory before making a
provider mutation, and compare count plus hash without reading Secret data.
The event credential now authorizes two exact Core routes: publishing and this
non-persisting authorization readback. It still cannot read manifests, dispatch
workflows or access console/admin APIs.

The hash proves equality only against a separately reviewed expected preimage;
it does not make an unreviewed grant set trustworthy. Grant rotations that keep
the same authorization set leave the hash stable. Grant changes require the
consumer's reviewed expected hash to change.

## Related

- ADR-0017 (route-scoped machine principals)
- ADR-0021 (exact and logical event publisher grants)
- ADR-0022 (load machine credential surfaces once)
