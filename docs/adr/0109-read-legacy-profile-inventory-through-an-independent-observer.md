# ADR-0109: Read legacy profile inventory through an independent observer

- **Status:** Proposed
- **Date:** 2026-11-10
- **Deciders:** Giovanni Martins
- **Scope:** Core / original Guest retirement forward inventory
- **Supersedes:** —
- **Superseded by:** —

## Context

The original settled-retirement continuation refreshes the exact surviving native
membership before preparing its own absence read. Its complete five-second
context already includes immutable supplier resolution, native reads and the
PostgreSQL refresh. An observed finish returned unsuccessfully after 5.078 seconds,
before its own absence read. The corresponding CloudTrail request audit retained
29 successful SDK calls and showed serial progress through the occupied slots.
This is the baseline failure; parallelism is not evidence of a measured production
improvement until the independently published reader is qualified and observed.

The historical producer is the normal AWS 1.65.5 publication
`c34e330d8b266bb88e29ae7cf7b01df6f9fd96ce`. Its immutable instance configuration,
whole-configuration admission checksum, desired requests, policy and original
create/destroy receipts bind that producer. A new binary has a different native
build source. Replacing the normal adapter with an inventory-only source bridge
would reject legitimate future mutations, while treating the new build as c34
would falsify provenance. Changing the old configuration would change the sealed
checksums and disconnect the retained retirement from its original authority.

## Decision

Read the exact AWS/c34 forward-retirement inventory through a separately published,
independently described read-only sibling. Keep the original normal supplier
resolution, immutable manifest checks and pre/post lease guards. The sibling has
its own fixed service origin, provider, version and closed Describe/request/return
protocol. Its compiled actual source is admitted separately from the immutable
profile producer source. An unbound publication source fails closed.

Copy the original hydrated execution context through the existing historical AWS
wire projection and remove the callback `grant_bearer`. Preserve the producer
configuration and all request/admission identities. The sibling registers no
normal adapter operation, grant callback, mutation dispatcher or AMQP handler.
It performs only the complete original native inventory reads, including every
existing physical proof, collision census, pagination bound, body completion and
Close requirement, with bounded parallel slot pipelines and no SDK retries.

Transmit the exact deadline from the already-created Core five-second context.
The sibling clamps its handler context to that deadline and echoes it with the
unique read ID, request digest, actual observer source and profile producer source.
Core validates those joins and the closed response before the unchanged native
inventory proof and repository membership refresh. Describe is checked before
and after the read. Failure produces no normal-adapter fallback or partial result.

Keep the c34 normal adapter and the independently pinned retirement-absence
observer unchanged. Future ensure/observe/destroy operations retain their original
source, destination, grants and original-return validators. The new route exists
only for the exact AWS/c34 forward inventory branch.

## Consequences

- Core pins the actual committed sibling source for CI. Deployment qualification
  additionally requires its successful CI, immutable image publication and actual
  reader acceptance. A metadata annotation or caller-selected hash cannot enable it.
- The normal mutation source and historical profile producer are never aliases
  of the observer's actual build source.
- The existing five-second deadline, original Guest history, failed caller/ACK,
  continuation owner/fence, destroy receipt, absence observer and repository
  freshness/membership guards remain authoritative. No SQL schema change is needed.
- A sibling deployment and exact source admission are maintained independently.
  Extending this route to another operation or producer requires its own reviewed
  contract change.
- CI must exercise the closed HTTP protocol, source and deadline mismatches,
  callback removal, before/after guards, bounded adapter concurrency and the
  PostgreSQL settled-destroy survivor refresh. Declared fixtures do not qualify
  actual provider execution or production performance.

## Related

- [ADR-0104](0104-separate-retirement-observer-from-historical-mutation-authority.md)
  separates observer and historical mutation authority.
- [ADR-0108](0108-resume-a-failed-settled-continuation-before-its-first-read.md)
  preserves failed pre-read continuation history and fresh ownership.
- scratch: `docs/superpowers/elastic-codex-20261102/new-native-pending-continuation-source-20261104/R6-CORE6-CAS16-ACTUAL-DATA-INERT-PREP/ROOT-ACTUAL-d16515e6-bfd6-470d-a9b3-0630ed5267cb/EXISTING-CLOUDTRAIL-FINISH57/SDK-REQUEST-PARAMETERS.PUBLIC.json`

