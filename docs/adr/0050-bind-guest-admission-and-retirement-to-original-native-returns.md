# ADR-0050: Bind Guest admission and retirement to original native returns

- **Status:** Proposed
- **Date:** 2026-10-13
- **Deciders:** Giovanni Martins
- **Scope:** Core capacity workflow, Guest provisioning and retirement protocol
- **Supersedes:** —
- **Superseded by:** —

## Context

A settled provider resource is not proof that its original bootstrap completed,
that its protected writers were admitted, or that they quiesced before deletion.
Missing enrollment and uncertain transport are especially unsafe cleanup inputs.
An authenticated callback also needs the original resource, source, attempt,
native placement and enclosing bootstrap returns that it names.

The source qualification fixture has two real QEMU originals and one useful echo
writer per Guest. It does not provide the approved production workload registry,
Hetzner metadata ownership or provider billing observations. Earlier mandatory
capacity tests contain synthetic accepted mutation fixtures that this admission
boundary now refuses. Their names, requirements and failures must be retained.

## Decision

Reserve original provisioning authority before the sole create send, then bind
its authenticated callback and enrollment to the accepted original native tuple,
bootstrap journal, placement, immutable profile and actual source epoch. Persist
canonical original bytes separately from PostgreSQL's JSON and time projections.
Keep provisioning, actor observation, intent and enrollment credentials separate.

Before retirement, persist each scoped challenge before its single original GET.
Both before-start reads require independent current native snapshots. The four
immutable retirement records, current actor, lease, fence, policy, floor and
actual caller Do/Read/Close returns must join before issuing a delete permission.
Recheck the current authority at issue and first redemption. Uncertain returns
remain durable facts; recovery reads do not create a replacement write attempt.

Keep production approval in a compiled source registry. Its current production
registry is empty and refuses new creation before a provider send. A claimed
catalog hash, image digest, complete roster or signed callback cannot approve it.
The separately compiled native qualification registry admits only its fixed echo
profile and `native-qemu` realm. Its poweroff/disk readback schema qualifies only
the same QEMU process and authorized disk, with no provider billing claim.

Publish reviewed experimental Core source independently of the later joint
native qualification. Source/PG/build qualification is explicitly
`FULL_CORE_NATIVE_PENDING`. The isolated Guest fixture may pin that literal Core
CODE after the source gates. Full qualification still requires the genuine joint
receipts and migration of every inherited owning claim; no gate is removed or
silently replaced by a generic admission refusal.

## Consequences

Production activation, merge and deployment remain separate decisions. The
two-slot fixture cannot qualify the production workload or larger floor/recovery
geometries. Those require their own reviewed finite resource profile and actual
original ownership evidence before execution.

There is currently no truthful terminal never-started producer. Missing journal,
enrollment, callback or resource lookup leaves cleanup in HOLD. A future proof
must durably seal the same original creator/source/attempt/process before any
possible writer start and independently prove that a later start is impossible.

The shared sixteen retirement DTOs retain their literal ABI. Provisioning and
runtime snapshot contracts are coordinated with Guest. Native diagnostic and
public artifact projections are distinct private/source protocols and confer no
capacity or billing authority.

## Related

- [ADR-0036](0036-redeem-provider-mutations-once-under-durable-capacity-authority.md): original mutation redemption.
- [ADR-0037](0037-produce-native-vm-proofs-through-fixed-protected-observers.md): independent native readback.
- [ADR-0045](0045-join-original-guest-bootstrap-under-fixed-vm-membership.md): original Guest bootstrap observation.
- [Original Guest lifecycle](../capacity-guest-original-lifecycle.md): source boundaries, gates and artifact contracts.
