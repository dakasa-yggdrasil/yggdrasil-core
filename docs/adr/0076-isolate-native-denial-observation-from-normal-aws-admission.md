# ADR-0076: Isolate native-denial observation from normal AWS admission

- **Status:** Proposed
- **Date:** 2026-10-24
- **Deciders:** DaKasa platform maintainers
- **Scope:** Core capacity native-denied accounting and protected adapter transport
- **Supersedes:** —
- **Superseded by:** —

## Context

A native-denied disposition must re-read a historical failed request using the
original integration identity, configuration and creator source. Its three
timestamp fields use the standard JSON representation of `time.Time`. A shared
reflection-based decoder that requires objects for every struct rejects those
valid timestamp strings before the provider's read-only observation starts.

Repairing this administrative reader does not require changing the normal AWS
supplier, current profiles, IAM scope or Guest inventories. Replacing those
inputs merely to reach a corrected decoder would enlarge the admission change
and obscure the distinction between historical creator and current observer.

## Decision

Route native-denied observation through a separately published HTTP-only reader.
Keep the normal historical-to-current AWS catalog comparison, original IID
resolution, secret hydration and validation intact. Revalidate those identities
after observation. The dedicated reader has its own closed Describe contract,
provider role, version, actual compiler source and compiled private service
origin; it is not registered or represented as the normal integration type.

Require its exact Describe before and after execution. Compare all raw fields,
including explicit false and zero values for normal operations, AMQP and native
mutations. Bound both Describe calls and the single execute call within the
existing original Core deadline, with the existing complete HTTP read/close,
response limit, redirect refusal and detail-free errors.

After authenticating the complete raw historical/current catalogs, project the
historical execution type into the exact AWS protocol DTO. Only the protocol's
declared type, schema-property, endpoint and action fields cross this boundary.
Core-only credential policy, guardian/UI metadata and action input schemas
remain in the authenticated full catalog and are not silently accepted by a
permissive dedicated decoder. The original instance identity, hydrated
credentials, creator config and eleven-field request retain their values.

The reader accepts only the native-denial discriminator and the original
read-only operation. Its local decoder closes all eleven scalar fields and
parses the three timestamps explicitly. The shared decoder and normal AWS
operations retain their existing contracts. Core pins the actual separately
published observer source before any accounting mutation.

## Consequences

The existing native-denied Begin/Complete transaction and ledger remain the sole
accounting authority. This routing change adds no migration, grant, provider
mutation, new normal IID, profile or inventory. Accepted and uncertain historical
records, failed workflow results, original ACKs and failed attempts remain
unchanged. A failed POST is not reclassified or replayed through an old marker.

The dedicated deployment needs a selector and service distinct from the normal
AWS adapter, actual image/source admission and verified private reachability.
It registers no normal handler or AMQP queue. Owned WireGuard rules do not become
evidence for unobserved Kubernetes network policy. Deployment, a new Core
runtime window and an administrative invocation require their own original
results; Source tests alone establish none of them.

## Related

- [ADR-0074](0074-record-native-authorization-denied-originals-separately.md)
- [ADR-0075](0075-preserve-returned-failed-workflow-acks-in-denied-dispositions.md)
