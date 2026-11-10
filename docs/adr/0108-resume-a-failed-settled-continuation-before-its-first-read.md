# ADR-0108: Resume a failed settled continuation before its first read

**Status:** Proposed

Date: 2026-11-10

Scope: Original Guest retirement / automatic read-only continuation provenance

Extends ADR-0105 without changing its classic Pending owner contract.

## Context

An admitted read-only settled-absence continuation can fail during its original
inventory or survivor-floor invocation before it prepares any absence read.
Its predecessor's authenticated Pending remains historical custody. Requiring a
new read from the failed owner leaves this state without an automatic successor;
reusing that owner or its deadline would violate fencing and original clocks.

## Decision

Keep the existing `settled_absence_continuation` mode and all its no-OFF,
no-issue, no-redemption and no-DELETE restrictions. A separate closed ten-field
proof schema, `original_settled_absence_pre_read_continuation_v1`, distinguishes
this case from the unchanged classic proof. Only an admitted continuation with
zero read rows of any kind or stage may use it. Its exact failed workflow,
returned dispatch and finalization ACK, naturally expired lease, unchanged active
policy/source, accepted SETTLED owning destroy, global quiet and new actual
scheduler requester remain mandatory.

The last global returned read must still be the exact Pending inherited by the
failed parent's immutable continuation proof. Any own prepared or returned read,
unfinished challenge, newer malformed/failed return or changed SDK refuses this
branch. Exactly one real classic requested frame authenticates the anchor's
root, parent, prefix, tuple, full raw wires, failed owner/ACK, eligibility and
settled receipt. Revalidation substitutes only the current requester in a
validation value so quiet belongs to the new invocation; stored records and all
historical clocks remain exact. The classic schema forces one bounded validation
call, including after repeated pre-read failures.

The ordinary claim obtains a new fence, owner, run and finite lease, bound to
the actual Core process executor. Ordinary ticks do not require a Core restart.
Fresh inventory, the existing survivor canaries, a new bounded absence read and
normal confirmation/completion remain required. No old Pending becomes absence,
no inventory/floor guard is skipped, no deadline is extended, and no mutation or
nonce is replayed. The underlying cause of an inventory/floor failure must still
be corrected within its existing budgets.

## Consequences

Migration96 replaces only the closed continuation-proof CHECK and its validator;
prior migrations and every original record remain unchanged. The old proof's
Go admission/timeline branch and SQL validation body retain their original
meaning. An unused migration can restore the exact prior function and CHECK.
After typed96 custody exists, downgrade refuses rather than deleting or
relabelling append-only evidence. The existing PostgreSQL16/17 owning workflow
adds a separate declared fixture census; this grants no Native or cycle credit.
