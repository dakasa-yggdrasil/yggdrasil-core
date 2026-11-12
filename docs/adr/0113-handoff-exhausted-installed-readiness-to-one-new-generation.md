# ADR-0113: Hand off exhausted installed readiness to one new generation

- **Status:** Proposed
- **Date:** 2026-11-12
- **Deciders:** DaKasa
- **Scope:** Core / installed readiness, immutable exhausted-generation provenance and scheduler admission
- **Supersedes:** —
- **Superseded by:** —

## Context

Installed readiness permits at most three fenced attempts. A failure to persist
the first completion phase can consume all three attempts after the actual
Guest publications and reads have returned. Correcting the writer does not
make an expired third lease live or admit a fourth attempt. The old generation
is still pending, so ordinary assessment and stable-policy continuity cannot
adopt its installed members. Their accepted useful reads also make the separate
zero-useful-capacity disposal inappropriate.

The retained origin, failed results, real final acknowledgements and finite
attempt limit remain authoritative. A later build needs a distinct operation
that proves ownership of the complete installed roster without relabelling the
old generation as successful or replaying its requests.

## Decision

Add the separate `installed_readiness_exhausted_handoff_v1` contract. Admit it
only from the real scheduler plan, under the existing scope and row locks,
after natural expiry of the third installed-readiness lease. Authenticate the
typed installed-provision-timeout origin, the exact exhausted intent, all three
original failed dispatch/run pairs and their real final acknowledgements,
recorded issuer identities and previous-run chain. Require completion to have
failed at `advance_prepared`, closed original canary windows, no competing or
unresolved authority, and a fresh complete inventory of the same confirmed,
enrolled and installed member tuples. The current actual Core source must
differ from the issuers of those exhausted attempts.

Archive the complete original facts in the immutable
`capacity_installed_readiness_exhausted_handoffs` ledger. Its unique origin
constraint permits one handoff for an installed-timeout disposition, forever.
Record the archive and its exact successor intent atomically. The successor
uses generation and fence each incremented by one, the same policy and full
roster, a distinct actual scheduler run and executor, and one nonrenewable
lease of at most ninety seconds. Its typed marker links the archive and actual
source; the old attempt counter remains three in the archived intent.

This successor has readiness authority only. It cannot issue or redeem a
provider mutation grant, provision or retire a member, enter ordinary installed
resumption, renew its lease, or produce another handoff. Its private completion
path must collect fresh publication and read canaries for every current member
and satisfy the existing assessment, membership and phase guards through
`prepared`, `canary` and `promoted`. Only that new generation can earn current
readiness. Failure of its single execution remains a hold.

Migration 100 adds independent SQL validation, immutable records and deferred
links for the exact before and successor facts. The installed-timeout origin
guard admits only this authenticated transition to the distinct marker; all
other v1 retained-origin, attempt and stable-state rules remain unchanged.
Missing schema is ineligible. Rollback refuses retained handoff provenance.

## Consequences

The operation preserves the original failures, acknowledgements, provider and
Guest records, attempt counters and observer clocks. It claims neither old
success nor quiescence, absence or zero business effects. Fresh readiness does
not count as an elasticity cycle or extend an exhausted observation window.

There is no new public endpoint or provider operation. The scheduler uses its
existing refresh branch while the repository binds the distinct private
readiness context. The permanent unique origin and descendant refusal bound
the additional execution; changing a policy or source cannot mint another
handoff for the same origin.

## Related

- ADR-0094 (installed membership and stable policy continuity)
- ADR-0095 (separate failed-installed disposal)
- ADR-0111 (typed installed-provision-timeout origin and three-attempt readiness)
- ADR-0112 (preserved pre-action failed-plan disposition)
