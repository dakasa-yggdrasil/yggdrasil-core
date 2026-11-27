# ADR-0135: Shard the complete source census through a pinned dual reader

- **Status:** Proposed
- **Date:** 2026-11-27
- **Deciders:** Giovanni Martins
- **Scope:** Core / complete source interface inventory
- **Supersedes:** —
- **Superseded by:** —

## Context

The complete runtime/library/command source census approaches the published
checker limit of128KiB per evidence file. Native worker additions must remain
fully inspected. Dropping files, weakening coverage or enlarging an unbounded
read would change the evidence rather than solve its packaging limit.

## Decision

Pin the reviewed Commons dual reader by exact published commit and complete
tracked-tree SHA256. Keep its original v1 decoder and source selection intact.
Before consuming current v2 evidence, CI runs that actual new checker against
the fixed reviewed published Core v1 source. This compatibility input remains
independent of later growth that can no longer fit a v1 document.

Emit an explicit `core_source_interface_census_index_v2` at the existing
`docs/service-contract/source/sources.json` path. It references sequential
`source/shards/sources-NNNN.json` leaves by exact path, SHA256, byte count and
record count. Keep every source path, digest, size and exact build constraint;
v2 writes the empty default explicitly. The union is the same unchanged
complete production source selection.

Preserve128KiB for every index/leaf,2MiB including the index,16 leaves and4096
unique facts. Missing, aliased, duplicate, indirect or corrupt evidence fails
closed in the owning reader. The producer refuses over-bound output before
publishing any new evidence and removes only its canonical stale generated
leaves. Other source fact envelopes and their v1 schemas are unchanged.

```mermaid
flowchart LR
  Pin[Pinned reviewed checker] --> Legacy[Actual published complete v1 Core]
  Legacy --> Current[Current index and exact hashed leaves]
  Current --> Union[Every selected source fact preserved]
  Union --> Walk[Same complete actual source-tree walk]
```

## Consequences

New source files no longer require artificial file co-location to fit one
evidence document. The census remains finite and complete. CI verifies old
format compatibility before current-format coverage, exact leaf identities and
the full union. This metadata change does not activate a capacity owner,
provider sender, private factory, cloud resource or production switch.

