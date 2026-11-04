# ADR-0069: Record expired unadmitted create dispositions separately

- **Status:** Proposed
- **Date:** 2026-10-22
- **Deciders:** Core maintainers and production operator
- **Scope:** Original Guest create authority and protected floor recovery
- **Supersedes:** —
- **Superseded by:** —

## Context

An original provider create can be accepted while the owning workflow fails
before recording a signed create witness or installing a Guest. The provider
resource may exist, or may already have terminated. The accepted grant and
settlement must remain truthful. Expiry, a failed workflow, missing enrollment,
a server 404, and a later read do not retroactively turn that create into a
rejected call or reopen its send permission. Unresolved originals currently
reserve their native slot permanently.

The protected Guest startup contract requires a source-signed create witness
and live original provisioning authority before starting its protected runtime.
Writer processes may start before enrollment; enrollment absence alone is
therefore insufficient to establish that a protected runtime never started.

## Decision

Record an independently authenticated, append-only disposition of an expired
accepted original that never acquired protected Guest admission. Keep its grant
state, grant JSON, settlement, preregistration, original deadlines and source
identities unchanged. A disposition is neither an original create witness nor
an enrollment, successful workflow, business readiness or savings assertion.

The administrative API accepts only the original grant identity. Core obtains
its native observation itself through a reviewed authenticated adapter read,
using the retained original provider identity, birth, grant, attempt, request
hash and complete owned auxiliary inventory, or its separately typed and
source-closed complementary basis. A current observer source is
recorded separately from the historical creator source. The adapter capability
performs only bounded native reads, and returns complete retained read receipts.
A terminated instance alone is insufficient when owned billable auxiliaries
remain; shared networks, firewall rules and SSH keys are not cleanup targets.

Unknown auxiliary inventory stays unknown in the original settlement. For the
reviewed AWS original source, a separate authenticated inventory basis may close
it by reading the exact original RunInstances event and request ID, its instance
birth, account, AMI and owning interface, the immutable AMI root snapshot, and a
complete empty all-state volume inventory for that snapshot plus exact interface
absence. Record this as absence of snapshot descendants, never absence of the
snapshot or a fabricated original volume ID. The complete native bodies belong
to the new disposition. Operator-supplied receipts, tag-filtered omissions and
an empty CloudTrail search cannot establish this basis.

Serialize admission and final recording under the existing capacity-scope and
native-slot advisory locks, followed by the original grant, preregistration and
intent row locks. Recheck the original deadline against PostgreSQL time, the
immutable absence of a signed witness, enrollment and installation, the exact
original source profile and bootstrap contract, and absence of an active
owning provisioning invocation. Recheck the original records after the native
read. No request-supplied health or absence boolean is accepted.

For the first implementation, accept only protected floor recovery from an
unchanged zero-member baseline with no serving slots. Preserve every other
unresolved original. Atomically append the disposition, attach its one-way
foreign-key pointer to the original grant, and close the old decision as failed
floor recovery without a business or healthy-capacity claim. The open-slot
unique index excludes only a valid linked disposition. Existing pending and
issuance paths use the same projection. A new resource still requires a new
assessment, decision generation, fence and single-use grant; it cannot replay
the disposed original or reuse its deadlines.

## Consequences

- Installing the schema does not grant provider mutation or useful capacity.
- Original accepted results remain auditable even after their reservation is
  separately closed by physical terminal absence.
- A lost administrative response is reconciled by reading the immutable
  disposition; it never repeats a provider mutation or creates another record.
- Missing native/auxiliary inventory, changed ownership or policy identity,
  witness/enrollment races, active original invocations and nonzero serving
  baselines remain unresolved.
- Broader recovery of installed Guests still requires its existing drain,
  quiescence, retirement and complete membership contracts.

## Related

- ADR-0065: Original provisioning clock domains and signed current authority
- ADR-0066: Original Guest reconciliation through the protected workflow
- ADR-0068: Protected floor and complete membership
