# ADR-0060: Own the original Guest provider per workflow invocation

- **Status:** Proposed
- **Date:** 2026-10-21
- **Deciders:** Core maintainers
- **Scope:** Core / protected Guest provisioning
- **Supersedes:** —
- **Superseded by:** —

## Context

The original Guest workflow requires a source-owned provider. A package-global
provider pointer conflates independent workflow lifetimes and cannot bind a
native create call to one executor, selected slot and original deadline. Native
qualification has a separately compiled realm and must retain that distinction.

## Decision

Construct the production provider in the original workflow invocation after the
compiled profile gate, current policy/workflow/lease checks and exact adapter
catalog checks. Carry the existing transport through a private context key. Do
not register providers from manifests, environment values or workflow inputs.

Freeze the selected slot, binding, member, policy and workflow checksums, step,
executor, epoch and provisioning budget. Require the same unextended original
context and preregistration. Consume creation ownership before the one original
supplier call. An error, cancellation or panic never reopens creation; fresh
readback can confirm only an original create whose caller already returned
successfully. Do not create a background retry or detached lifetime.

Keep the production approval registry empty until the complete real production
catalog, application handle ownership and original provider witness protocol
are implemented and independently verified. The production constructor selects
only the existing fixed Hetzner broker catalog; AWS's legacy name-adopting ensure
and unreviewed HTTP transports do not satisfy this contract.

Check the repository's separately compiled original-witness provider support
before catalog hydration, reservation or native send. Profile approval cannot
activate a provider whose authentic original return source is still absent.

Pin the Hetzner adapter's own clean build source in the mutation binding and
the checksummed FleetConfig admission contract, independently of Guest and Core
sources. The worker checks its actual build identity before network operations.
Only its actual successful native POST/Read/Close produces the closed original
return DTO. Include that DTO in the existing authenticated one-use settlement;
bind its grant, attempt, request, native tuple, actions, body hash and original
times to that same settlement. Preserve the shorter grant/context deadline.

Validate this original inside the authenticated settlement transaction and
retain it immutably in the existing settlement JSON. The repository's Hetzner
witness joins that original with the same preregistration, current authority and
independent native proof. A GET or uncertain create cannot supply a missing
original. Keep native QEMU's existing separate original source path intact.

## Consequences

Invocation ownership is testable without giving unit doubles native or SQL
authority. The actual supplier still uses the existing durable grant,
redemption/settlement and independent native read protocols. It grants no
business readiness or production capacity. Qualification continues using its
own compiled realm, source tables and scope.

Old generic adapter bindings remain compatible when their new optional source
pin is absent; they gain no original Guest witness. Source-pinned accepted
creates require the new original DTO. Failed and uncertain transport outcomes
remain separate immutable facts and cannot receive original-success authority.
The production registry remains empty. Registry population, publication, owning
CI, real provider execution and product qualification remain separate work.

## Related

- ADR-0050 (original provisioning, admission and native retirement)
- ADR-0053 (separate Source recovery authority)
- ADR-0059 (compiled production profile approvals)
