# ADR-0112: Close a recorded failed plan without committed authority

- **Status:** Proposed
- **Date:** 2026-11-11
- **Deciders:** DaKasa
- **Scope:** Core / automatic pre-action dispatch disposition
- **Supersedes:** —
- **Superseded by:** —

## Context

A distinct readiness dispatch can fail its first plan after an installed
provision-timeout disposition has released the earlier unknown owner. Its
original result can contain one failed attempted plan and six workflow-abort
skips, while finalization retains the completed failed return as unknown with
no ACK. Expiry does not acknowledge that return. A refusal stage alone does
not prove that the plan committed no authority: its disposal, installed-resume,
terminal-reconcile or ordinary claim may have committed before a later refusal.

Maintenance dispositions require a completed refresh plan, finalization-lost
dispositions require a missing recorded return, and the installed provision
timeout disposition describes an actual successful provision followed by a
completion failure. Preserve those different meanings and their original guards.

## Decision

Add the immutable `unknown_preaction_failed_plan_disposition_v1` receipt and
the separate `preaction_plan_disposed` dispatch terminal. Admission occurs
only in the existing enqueue transaction, after natural expiry and before
wake saturation. There is no administrative reset or replay endpoint.

The initial supported anchor is an independently valid immutable migration98
installed provision-timeout receipt. Authenticate its complete original intent,
paid CREATE chains and signed installed members. Require the current complete
intent to equal that original anchor semantically, including policy, generation,
fence, phase, lease and every marker. Current physical membership must still
match every anchored tuple and confirmed create grant. Observation-only slot
refreshes are permitted only by the existing row-proved migration84 predicate.

Authenticate the whole original dispatch and workflow run, exact scheduler
envelope and inputs/metadata, the source-owned seven-step graph and genuine
ordered timestamps. The plan alone must be failed/attempt1 with its producer's
closed refusal metadata. All six following steps must be unattempted workflow
abort skips. A conditional skip, later action or partial result is ineligible.
No particular error message or refusal-stage label authorizes the disposition.

Retain every original error independently. The first finalization's database
clock may replace only the dispatch return error when its lease expires.
A later finalization-unknown transaction may replace the run error and append
a finalization error while retaining the original return error. Equality of
those different fields is not a general producer invariant. Their complete
stored wires, failed statuses and causal identities remain exact.

Before insertion, independently derive the complete effect scan from Core
tables. No current intent event, claim marker, authority issue, provider grant,
disposal, retirement/forward, canary or other busy actor may be hidden by the
failed plan. Reuse the enumerated migration83/84 ledgers and fixed thirty-second
clock-skew window; preserve canonical undisposed-grant checks, including settled
history whose disposition pointers close it. No provider or Guest mutation,
provider quiescence or global historical debt elimination is inferred.

Serialize admission with the existing compact-JSON dimension advisory lock,
then the active job, pinned manifests, current intent/run, slots and grants in
the established row-lock order. The actual plan claim writers, ordinary
assessment/mutation transactions, and Guest canary transactions take that same
scope lock before writes. Claims commit their intent, event and authority issue
atomically. With the old original returned/failed and expired, no subsequent
context may impersonate its live owner. These writer and lease rules, current
anchor equality and the independent ledger scan close the absence proof;
caller-supplied booleans do not substitute for them.

The receipt stores explicit distinct successor job/run IDs and whole original
job/run/intent/member/evidence bytes. Only the old job's state and updated_at
change. Deferred same-transaction checks require exactly those new queued
scheduler records and their wake with unchanged authority. The old run, return,
missing ACK, failure, pending-wake history and every old receipt remain intact.
A fresh owner may subsequently attempt existing readiness; it receives no
provider authority from this terminal receipt.

Historical receipt reads authenticate saved immutable originals. They do not
rerun current intent/effect eligibility after the legitimate successor advances.
Missing or ambiguous custody refuses admission. Later failed plans may reuse
the same valid unchanged anchor; unanchored workloads are unsupported.

Add migration99 for this ledger, SQL guards and rollback refusal. Preserve the
migration98 dispatch guard body behind only one new terminal-state branch.
Down refuses while any new receipt or terminal remains. Do not delete evidence
to make rollback possible.

Add a nonunique partial Btree access path for the unchanged 641-byte historical
failed-installed lookup: JSON workflow identity followed by returned_at, for
returned failed jobs with a recorded return and ACK. This changes no eligible
history or query predicate. Build it transactionally within existing Goose
limits. No performance improvement is claimed without the actual measured
workload and plan; existing old/new timing observations remain their facts.

## Consequences

The scheduler can distinguish a closed pre-action failure without converting
unknown into an ACK or replaying its run. The following readiness attempt can
still refuse, and all provider/Guest gates, deadlines, fences and protected
floor rules remain unchanged. A committed claim or any uncertain effect holds.

PostgreSQL16/17 tests must exercise actual writers, natural expiry, complete
original wires, independent SQL rejection, concurrent wakes, immutable/deferred
links and historical readback after successor progress. Existing migration98
cases and qualification jobs remain intact. The regular index build keeps
existing lock and execution budgets; failure rolls back rather than raising
a cap or repairing an unexpected same-name index automatically.

This source decision does not approve a migration, image, runtime pair,
restoration or clean elasticity-cycle result. Root owns qualification and
production adoption separately.
