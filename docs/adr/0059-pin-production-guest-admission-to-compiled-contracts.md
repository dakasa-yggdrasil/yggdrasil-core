# ADR-0059: Pin production Guest admission to compiled contracts

- **Status:** Proposed
- **Date:** 2026-10-21
- **Deciders:** Core architecture maintainers
- **Scope:** Core original Guest production profile admission
- **Supersedes:** —
- **Superseded by:** —

## Context

The existing default source registry refuses every production profile. Its native qualification realm admits a fixed echo writer. A syntactically complete roster, operator-supplied digest or signed callback cannot approve production sources, images, writer handles or private transport identities. Production needs a reviewable source entry without copying a future Core commit into its own source.

## Decision

Admit a production Guest profile only when its actual provider, profile name, actual production catalog digest and complete contract digest match exactly one compiled source approval. Hash the full protected Guest binding and selected mutation binding, including writer definitions, source and image pins, keys, secret-reference names, member principals, transport origins, slot specs and limits. Exclude only `core_authority_source_commit` from that digest and independently require it to match native clean-build VCS metadata at admission. Computing a digest does not install approval. Registry entries are source code, with no environment, manifest or runtime registration path.

Keep the default registry empty until an independently reviewed real production catalog and original provider implementation supply the entry. Keep the native qualification registry separate. Its synthetic unit fixtures, source-only tables and echo results supply no production entry. The registry check does not replace active policy/workflow, lease, original provisioning, installation, settlement, retirement, current native reads or rollout gates. The selected `CapacityProfile` name and provider must match. Its region, minimum/maximum units, costs, quote validity and validation timestamps remain policy/assessment inputs under their existing active-manifest and intent checks; they do not enter this protected-workload source digest. The mutation binding's static slot limits and exact desired specs do enter it.

## Consequences

Any change to the protected sources, images, complete writer roster, public identities, private reference names or native slot contract needs a new reviewed compiled entry. A clean Core release can retain an unchanged entry while still binding every current operation to that release's actual VCS identity. Duplicate matching approvals refuse. A registry matcher alone does not install a provider or close production qualification.

## Related

- ADR-0050 (refines compiled production profile approval)
- ADR-0057 (retains authenticated installation requirement)
