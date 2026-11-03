# ADR-0095: Dispose the single failed installed tail of a Guest expansion

- **Status:** Accepted
- **Date:** 2026-11-02
- **Deciders:** Giovanni Martins
- **Scope:** yggdrasil-core / original Notify Guest failed-installed disposal
- **Supersedes:** —
- **Superseded by:** —

## Context

ADR-0079 admits only the failed installed first member of a dimension with no
useful capacity. A subsequent one-member expansion can also install a Guest
without ever accepting its useful read. Its confirmed native still costs money,
but the first-member restriction prevents the operator from requesting its
original retirement and native-absence cleanup.

Replacing constants is insufficient. The original exception skips every floor
canary, and its terminal sets the whole dimension to zero. Applying those rules
to an expansion would discard the accounting and protection of its surviving
members. The scheduler's plan and the refused-V2 cleanup join also select slot 1.

## Decision

Extend the existing immutable disposal ledger to the single newly installed tail
member of a one-member expansion from N−1 to N, for N greater than one. Retain
the existing administrative IDs-only request, original failed-run and ACK joins,
expired lease, confirmed create, installed enrollment and exact native lifetime.

Derive N from the original intent's desired units and require the selected
preregistration's slot to equal it. Require the original action to be `expand`,
the original baseline to contain exactly N−1 units, N to be within the ceiling,
and the current reported units to be either N−1 or N. The scheduled claim must
observe all N installed native members and their complete enrolled prefix.
Guest548 and its historical V1 recovery lanes remain first-member-only.

The failed member must never have an accepted useful read. The failed generation
must never have reached a useful terminal phase. Every other live slot must be
in the exact prefix 1 through N−1 and have an accepted read bound to its same
integration instance, scope, profile, slot, resource ID and creation time.
Outstanding dispatches, target canaries and unresolved mutation grants retain
their existing hold behavior. `useful_capacity_before=0` remains the zero credit
of the member being disposed; no fleet-wide zero-capacity assertion is imported
into a later-slot admission.

The scheduled claim retains the same generation and increments the fence once,
as before. Its observed baseline contains N units, its drain target contains
N−1 units, and the server-authored workflow plan selects that tail slot.
The claimed immutable record, original preregistration and current intent must
agree on the same slot at every subsequent authorization join.

Only the failed first member keeps the original protected-floor exception.
For a later member, reuse the ordinary physical and useful retirement floor
checks. The unchanged original retirement protocol issues fresh canaries for
the surviving members before retirement and after the acknowledged withdrawal.
The failed member receives no new canary. A disposal allows canary issuance
only for its survivors, only for the two existing retirement-floor usages,
and only after revalidating the complete active disposal claim under its lease.

Retain V2 retirement, writer drain, native OFF, explicit operator cleanup and
the exact-lifetime native and auxiliary absence proof. Generalize the
ADR-0092 refused-V2 join to that same admitted tail slot; do not relax any
refusal or original-return predicate. Tombstone only the failed slot. Its
terminal reports N−1 surviving physical members, keeps the generation
unpromoted, and preserves every original failure, ACK, canary and marker.

Keep all replacement-build barriers from ADR-0079, ADR-0084 and ADR-0091.
Disposal does not automatically authorize another instance of the failed build
or resume the dimension as useful. A subsequent normal assessment still needs
the existing corrected-build or explicit qualified replacement admission.

## Consequences

- There is no new caller-selected slot, floor, policy, provider mutation or
  assertion that an earlier publication had no business effect.
- The wire schema and SQL ledger schema remain unchanged. Historical records
  retain their hashes and their first-member interpretation.
- A failed expansion can be cleaned up without tombstoning or zeroing the
  surviving native slots. A lost survivor, sparse membership, changed lifetime,
  useful failed member or previously promoted failed generation remains held.
- This lane is recovery, not partial promotion. Surviving members remain
  physically present; the dimension remains unpromoted until the existing
  replacement gate and ordinary reconciliation complete.
- Source CI exercises the new admission boundaries and PostgreSQL accounting
  query, with explicit storage-only synthetic rows. Those rows claim no signed
  Guest, production retirement or native absence qualification. Production
  execution still requires the full original chain.

## Related

- ADR-0079 (extends: first-member failed-installed disposal)
- ADR-0091 (depends-on: explicit external-cause replacement admission)
- ADR-0092 (extends: refused-V2 native OFF join for the admitted tail slot)
- ADR-0094 (depends-on: survivor continuity across identical Guest contracts)
