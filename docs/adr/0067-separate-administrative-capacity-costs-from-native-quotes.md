# ADR-0067: Separate administrative capacity costs from native quotes

- **Status:** Proposed
- **Date:** 2026-10-21
- **Scope:** Original Guest capacity planning costs and native billing diagnostics

## Context

A short-lived native Hetzner quote expires before a continuously scheduled
controller's next work. AWS preparation does not return a market quote. Extending
either into a future quote date would misrepresent the source. Planning assumptions must not relabel the native currency of an exact selected
provider profile or native quote/billing evidence.

## Decision

Permit an explicit `reviewed_administrative_cost_assumption` only inside the
original Guest reconcile binding. Pin the operator's review reference and SHA,
expiry and exact provider's native billing currency. The policy currency and
per-unit monthly amount are administrative planning assumptions. Require the
old profile quote and validation dates to remain zero in this mode. Use only
the actual administrative review expiry for the planner/lease/phase planning
gate. Retain the historical dated-declaration algorithm when the object is
absent; an absent native date cannot silently select the new mode.

Keep native quotes and billing diagnostics in their exact provider currency:
USD for both exact selected AWS and Hetzner profiles. The current Hetzner
profile and native pricing evidence are USD; this does not assert a universal
provider currency. No conversion or claim that a planning assumption caps an
actual invoice is made. Existing actual Hetzner quote collection,
freshness and pre-create price/stock checks remain mandatory; AWS preparation
continues to make no native market-price or stock assertion. All source, native
identity, grant, enrollment, useful-membership and retirement gates remain.

Use strict upper/lower demand comparisons only for the distinct original Guest
mode. Equality at its upper or lower threshold does not scale. Historical HPA
comparison boundaries, hysteresis and cooldown semantics remain unchanged.
For this Guest mode, distinguish the scheduled evaluation interval (bounded by
policy evidence age) from gaps inside each actual metric range. Demand covers
300seconds/61samples, while the separate membership-quality range covers
30seconds/5samples. Retain full real range/hysteresis checks; a wake never
advances a clock on missing or partial evidence.

## Consequences

The controller can continue between native quotes under a finite reviewed
administrative budget without inventing future market evidence or rewriting a
policy for every quote. Expired administrative review closes new planning
authority; it does not extend itself. Existing native observations can still
describe their original provider-currency exposure without becoming invoices.

The optional outer object does not change protected ProfileManifest or complete
production approval hashes. This decision does not install any profile, budget,
policy or quote, and it adds no provider calls or financial ledger.

## Related

- ADR-0066: exact original Guest reconciliation through protected workflows
