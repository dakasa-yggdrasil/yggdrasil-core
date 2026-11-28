# ADR-0141: Qualify HCloud births with explicit project and action witnesses

- **Status:** Proposed
- **Date:** 2026-11-27
- **Deciders:** Giomaster
- **Scope:** Core / Native HCloud physical creation qualification
- **Supersedes:** None
- **Superseded by:** None

## Context

The first physical qualifier supports AWS. HCloud has a real creation action ID,
optional HTTP request IDs, a reviewed logical project rather than an account
introspection API, and distinct location and network-zone names. Filling its
empty account or missing HTTP IDs with invented values would misrepresent the
original return. The exact System provider is `hetzner` with `hcloud://` IDs.

## Decision

Extend the protected physical qualifier with a separate HCloud decoder and safe
typed witness. Keep the AWS decoder, independent-read DTO, evidence order and
absent optional wire byte-for-byte compatible. An internal non-wire carrier
selects the provider-specific read; a profile's name does not select a provider.

Require `hcloud_scope` only on a literal `hetzner` read binding, and reject it
for AWS. Pin the actual reviewed project name and token/network-anchor proof
kind, anchor ID, creation time and owner label. Match these with the independently
observed facts and exact adapter tuple, compiled Source and whole-inventory
digest. A token digest is not presented as a provider account ID.

After private original custody commits, decode the bounded original HTTP 201
and native JSON with duplicate, case-alias and trailing-data refusal. Join the
actual create action, labels and server lifetime to the separate server/network,
firewall and Primary IP read bracket. Retain optional original NIC fields only
when the asynchronous reply actually contains them. Require complete independent
current facts. Missing or failed reads prove neither acceptance nor absence.

Use the current API's `server.location`, not removed datacenter fields.
Map actual location to the Core market region and System zone, and map actual
`network_zone` to System's native provider region. Keep System's empty HCloud
account, ID limits, protected floor, disjoint networks and exact Binding order.
The actual native subnet and provider facts, together with the archived canonical
Launch, determine the physical Binding digest; labels cannot supply that digest.

Bind the full safe acceptance, reader pin and independent observation in a
provider-specific witness. Preserve that witness through Attempt and immutable
Birth JSONB and include it in the public safe birth digest. Generic lifecycle
and abort guards allow an empty account or optional HTTP IDs only with this
complete matching witness. Original bytes, passwords and raw-original digests
remain private. No fresh quote, profile alias or caller observation can replace
the recorded original.

Extend the existing immutable Attempt guard with Goose118. Only the first
`send_started` or `unknown` to `acknowledged` transition for literal
`hetzner` may introduce the witness, with complete original custody, exact
identity and co-present physical/birth fields. A deferred constraint requires
the matching immutable Attempt/event/Birth writes in the same transaction.
Reject witnesses at INSERT, on other providers and on later alteration or
removal. Rollback refuses any current or archived witness marker, then restores
the exact schema116 guard when history has no witness. Existing transitions,
abort/unsent fences and schema117 network guards remain intact.

A sealed birth's witness remains historical. `ReobserveACK` validates fresh
current facts, preserves the real state, original IDs and birth, and returns only
the same physical tuple. Later registry/admission observations carry the stored
witness and its original optional IDs; they do not recreate an acceptance from
the latest GET. This qualifier grants no readiness, warmup, admission, useful
capacity, deletion or billing closure.

## Consequences

Provider-specific evidence remains explicit instead of weakening the AWS account
and two-request-ID checks. The witness is larger but bounded and contains only
the allowlisted safe DTO. Existing JSONB tables retain their shape; migration118
extends their immutable guard and atomically requires the typed birth event.
Existing HCloud SDK GET response-close handling must refuse incomplete transport
before activation; a truthful Core validator cannot recover an error omitted by
a producer. Source delivery and CI fakes do not qualify provider connectivity,
install runtime ports or purchase a machine.

## Related

- [ADR-0137](0137-qualify-native-births-with-an-independent-physical-reader.md).
- [ADR-0134](0134-fence-preadmission-worker-cleanup-separately-from-admission.md).
- [Native worker lifecycle](../features/native-worker-lifecycle.md).
- [Hetzner API changelog: locations replace datacenters](https://docs.hetzner.cloud/changelog#2025-12-16-phasing-out-datacenters).
- [Hetzner API reference](https://docs.hetzner.cloud/reference/cloud).
