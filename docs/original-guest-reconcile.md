# Original Guest Notify reconciliation

The optional `capacity_policy.spec.guest_notify_reconcile_binding` selects the
closed `original_guest_notify_reconcile_v1` protocol. Its `signals` are existing
`CapacityMetricSignalBinding` objects: signal name, fixed adapter instance/type
UUID and checksums, binding name and the actual owning adapter binding digest.
The separate mandatory `member_coverage` uses the same binding type, with name
`original-guest-member-coverage`, source identity
`production/notify/<provider>/reporting-members` and unit `members`. Its fresh
complete window's value, minimum and maximum must all equal the actual native
inventory count. It is a quality gate outside scale signals: no threshold can
turn partial reporter coverage into low demand. Null/missing coverage is allowed
only when the independently complete native inventory proves zero members.
After an already-confirmed creation/removal, completion may wait for this real
window using GET observations only, inside the same original 90-second step and
captured lease. Identity/configuration errors fail immediately. This wait never
repeats a provider operation or canary publication and never extends a deadline.
Schedule input contains only the logical `policy` namespace/name. A caller
cannot provide an assessment, URL, query, profile, lease or native tuple.

The owning `OriginalGuestReconcileGraph` constructs the seven source steps.
The workflow must be scheduled, enabled, asynchronous and authorized, with only
the required object input `policy`, no defaults/additional inputs, one total
attempt per step and no `for_each`. The protected provisioning step keeps the
exact ID in the compiled ProfileManifest, currently `provision-original-notify`.
An operator cannot substitute aliases or add hidden mutation steps.

Each provider has its own policy, native slot ledger, workflow, dimension and
lease: `original_notify_aws_vm_members` or
`original_notify_hetzner_vm_members`. Namespace is `dakasa-production`, domain
is `notify`, environment is `production`; fixed binding/profile names are
`notify-aws-elastic` and `notify-hetzner-elastic`. Each roster has exactly eight
slots, floor 1, ceiling 8 and a one-member change. Provider floors cannot be
added together to justify removing another provider's last member.

The dispatcher retains exact current catalog/principal/RBAC/policy checks,
durable possible-start and the original dispatch lock. Its Guest claim is at
most 300 seconds and is clipped by the configured dispatch budget. The original
capacity lease is at most the existing 300-second policy bound. The source
captures its remaining interval once after subtracting the whole original PG
transaction round trip; subsequent steps share that private deadline. The
600-second provisioning step and its 420-second original cap are upper bounds,
not permission to outlive the original lease. Nothing here renews an original.

`plan_original_guest` observes metrics and native inventory through exact
resolved adapters. It refuses a foreign or incomplete inventory, unknown native
member, mismatched original tuple or unresolved grant. It selects at most one
missing slot for creation, or one already-enrolled unprotected slot for
retirement. A complete native count below floor can use the existing explicit
floor repair decision with missing demand. Missing metric values remain missing.
After creation, promotion requires complete real metric coverage and every
member's original useful Notify proof. If those are unavailable, authority is
retained in HOLD; scheduling does not replay the creation.

`complete_original_guest` reads source-owned originals. Initial completion joins
actual fresh publication/consumer canaries for all native members, then advances
through prepared/canary/promoted using the existing SQL phase gates. Retirement
completion joins the full original V2 quiescence chain, actual caller HTTP
acknowledgement, exact confirmed destroy grant, native absence and fresh
surviving useful floor. A stable unchanged epoch refreshes useful membership
through the existing maintenance challenge/send ledger, with no provider grant.
Pending originals permit observation/HOLD only, including after lease expiry.

The current compiled production profile registry must independently approve
the complete exact bindings. This module does not populate it. The new outer
binding is omitted when absent and is outside ProfileManifest/approval contract
hashing. Existing HPA and qualification paths keep their source contracts.

The owning PostgreSQL workflow includes a required 25-root no-skip Source gate.
It exercises pure graph/clock/source guards and a real PG negative that preserves
an existing intent, lease, event count and grant count. This is a refusal test;
it does not manufacture positive production enrollment, native inventory or
useful membership. Full provider/Guest/Notify end-to-end qualification remains
required against the actual compiled production approvals and source receipts.

For the explicit new mode, an optional `administrative_cost_assumption` object
contains `mode: reviewed_administrative_cost_assumption`, `review_reference`,
`review_sha256`, `expires_at` and `native_billing_currency`. It is an operator
planning assumption in the policy's USD currency, using the existing profile
`unit_monthly_cost_minor`. Require the existing quote/validation dates to be zero
in this mode, and retain the actual source validation reference. This does not
assert a future native quote or readiness period. The finite administrative
review expiry owns the planning validity gate and never renews automatically.

Native billing currency is pinned separately to USD for both exact selected
AWS and Hetzner profiles, matching their native source/profile evidence. The
Hetzner supplier still obtains and checks its actual fresh quote before original
creation; existing native admission ceilings and all original SDK gates remain.
An administrative estimate never relabels or converts native quote/billing
diagnostics, and does not cap an actual invoice. Without the optional object, both legacy date fields and their
expiry behavior are unchanged.

Demand thresholds in this Guest mode are strict: a value equal to the upper
threshold does not expand, and a range maximum equal to the lower threshold does
not reduce. Legacy HPA thresholds remain inclusive. Hysteresis, complete range
coverage and cooldown still apply independently.


The original Guest controller uses two separate metric quality contracts. Demand
covers a real complete300-second range (5-second step, at least61samples) for the
60-second upper and300-second lower hysteresis. MemberCoverage covers a separate
complete30-second range with at least5samples; it never borrows Demand's61sample
minimum. Both sources retain their pinned15-second source age and10-second range
gap. The source collector's60-second cadence uses the policy's120-second evidence
age for continuity between controller evaluations, while the actual intra-range
gap stays10seconds. Missing or partial data cannot advance either hysteresis;
a short30-second range cannot prove300-second surplus. Legacy HPA retains its
original inter-observation clock and inclusive threshold behavior.
