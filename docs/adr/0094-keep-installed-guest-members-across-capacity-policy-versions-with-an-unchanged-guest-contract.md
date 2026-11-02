# ADR-0094: Keep installed Guest members across capacity_policy versions with an unchanged Guest contract

- **Status:** Proposed
- **Date:** 2026-11-02
- **Deciders:** Giovanni Martins
- **Scope:** yggdrasil-core / original Guest reconcile (installed member lookup, Notify canary and maintenance admission, retirement V2 issue, stable-epoch carry-over) and the Core PostgreSQL pool default
- **Supersedes:** —
- **Superseded by:** —

## Context

Every `POST /api/v1/manifests?kind=capacity_policy` creates a new manifest row
with a new id and checksum. An installed original Guest member is keyed by its
preregistration record, which carries the `policy_id` and `policy_checksum` of
the version that provisioned it. Core then looked that member up only under the
exact current revision:

- `guestNotifyMemberReceiptTx` selected the enrollment with
  `preregistration_record->>'policy_id' = current id AND ->>'policy_checksum' =
  current checksum`. Its callers are the plan step's installed-member stage
  (`guestReconcileMembersTx`), the retirement floor discovery
  (`GuestNotifyFloorMembers`) and the useful-membership count
  (`guestNotifyUsefulMembersTx`).
- `guestNotifyStoredTx`, which admits every Notify canary issue, nonce, return,
  maintenance epoch discovery, enrollment read (`GuestNotifyCanaryEnrollment`)
  and the V2 drained/finish steps, required `stored.pre.PolicyID/Checksum` to be
  the current revision.
- `IssueGuestRetirementV2` required the same.
- `AssessOriginalGuest` kept a stable useful epoch (`promoted`, `reconciled`,
  `reconciled_partial`) on a HOLD decision only when the intent's policy id and
  checksum were the current ones; otherwise it wrote `phase=hold`, which ends
  the maintenance epoch (`guestNotifyStableEpoch`).

So publishing ANY new version stranded the live slot-1 member: the plan step
failed at the installed-members stage with `sql.ErrNoRows` or a conflict on
every tick, and maintenance canaries stopped. The only cross-version
re-adoption code is behind the `nativequalification` build tag. Production
(2026-11-02) needs exactly such publishes: both Notify elastic policies
(`notify-aws-elastic-capacity` v8, `notify-hetzner-elastic-capacity` v9) carry
`min_samples=61`, which the Prometheus adapter can never reach (at most 60
in-window source stamps for a 300 s window at 5 s), so every tick holds on
`signal_evidence_unavailable`. Fixing that changes `min_samples`,
`signals[0].binding_sha256` and the adapter instance id/checksum; later
scale proofs change signal thresholds. None of that touches the Guest.

Separately, the single Core pod kept only 2 idle PostgreSQL connections
(`DefaultMinOpenConns`, applied as `SetMaxIdleConns`). Its steady reconcile,
canary and HTTP concurrency then opened about 110 new connections per minute,
each a ~220 ms SCRAM handshake on a CPU-starved 2-vCPU Brain.

## Decision

1. **Continuity digest.** `capacity.GuestPolicyContinuitySHA256(p)` hashes
   `GuestProductionProfileContractSHA256` (complete Guest retirement binding,
   the mutation binding with its slots, desired specs and bootstrap digests,
   and the Notify canary binding) together with the protocol authority source
   commit (which that contract blanks), the provider, profile name and region
   of the single matching profile, and the environment, domain, dimension and
   workflow selector. It is empty for anything that is not a complete
   production Guest contract. `GuestPolicyContinuous(prior, current)`
   additionally requires byte-identical (`reflect.DeepEqual`) Guest retirement
   and Notify canary bindings. Signals, thresholds, hysteresis, `min_samples`,
   observation adapters, quotes, floor and `max_sample_gap_seconds` are outside
   it on purpose: they decide when Core scales, not which Guest it may manage.
   The policy's `max_evidence_age_seconds` is outside the digest but bounded by
   validation: the Guest binding requires its own evidence age (30 s in
   production) to be at most `min(30, policy max_evidence_age_seconds)`, and the
   Notify canary requires its minimum publication interval to be at most the
   policy bound. Lowering the policy bound below either makes the contract
   invalid (empty digest), so it breaks continuity and strands the member.
2. **Admission.** `guestPolicyContinuityTx` admits a member preregistered under
   (priorID, priorChecksum) for the current active policy when the pair is the
   current revision, or when the prior row is an OLDER version of the SAME
   kind/namespace/name with exactly that stored checksum, the current row is
   active with the caller's checksum, and the prior row and every still-stored
   version after it up to the current one are continuous with the current spec.
   A newer version, another name or namespace, a changed contract (also in an
   intermediate version), an inactive current row or an unstored checksum all
   refuse with `ErrCapacityConflict`.
3. **Where.** The member lookup (`guestMemberPreregistrationTx`, used by
   `guestNotifyMemberReceiptTx`) now selects enrollments of the slot tuple whose
   preregistration policy is a stored row of the same policy name, requires
   exactly one (two is a conflict, none keeps `sql.ErrNoRows`) and applies the
   continuity check; `guestNotifyMemberReceiptTx` re-checks it on the loaded
   original. `guestNotifyStoredTx` and `IssueGuestRetirementV2` replace their
   exact-revision comparison with the same check. Every other check is
   unchanged: signatures, enrollment schema, the stored binding equal to the
   current one, compiled approval, workflow id and checksum, slot tuple,
   witness, installation, native slot row and pending destroy grants.
   The actual-issuer proof (`verifyGuestAuthorityIssuerTx`) takes the policy
   the issue was RECORDED under separately from the preregistration: the
   retirement intent's `policy_id/policy_checksum` (V1 and V2 loaders) or the
   canary challenge's (installed unknown-read reconcile, failed-installed Core
   replacement). After a republish that is the newer version B while the
   preregistration stays under A, so the `capacity_guest_authority_issues` row
   is looked up and the compatibility map checked under B, and B must be a
   continuous successor of A (same namespace/name, older A, identical
   contract in every stored version between them). This lineage check does not
   require B to still be active: the issue is historical provenance, and each
   caller that acts now rechecks the current policy under its own lock.
4. **Stable epoch.** `AssessOriginalGuest` keeps the stable useful phase on a
   HOLD when the intent's revision is the current one OR the prior revision that
   (2) admits, with the same resource identity, units and profile. The intent is
   re-stamped with the new policy id/checksum and keeps its generation and
   fence, so maintenance canaries continue under the new version. The
   continuity read happens before the locking transaction (manifest spec and
   checksum rows are immutable); the transaction still rechecks the current
   policy is active. Hysteresis clocks still restart on a new checksum, and
   `LastActionAt` (cooldown) still carries over.
5. **Pool.** `DefaultMinOpenConns` becomes 10, `DefaultMaxOpenConns` stays 25,
   and the `YGGDRASIL_PG_*` overrides are unchanged. It is applied as
   `SetMaxIdleConns`, an idle cap and not a floor: database/sql keeps up to ten
   returned connections for reuse, never pre-opens them, and still closes each
   after the 5 m idle time and every connection after the 30 m lifetime. When
   `YGGDRASIL_PG_MAX_CONNS` is below 10 database/sql lowers the idle cap to
   it; the startup `pg_pool` line logs that effective `max_idle`.

## Consequences

- After this build is live, a publish that changes only scheduling fields keeps
  the live slot-1 members (AWS preregistration `2a23af4b…`, Hetzner `115358ec…`)
  managed: the plan step lists them, the promoted epoch survives, and
  maintenance canaries are issued under the new policy id (older challenges
  under the prior id are simply not reused; freshness needs new ones anyway).
- Leased intents are NOT carried across versions. `checkLease`, `Claim`,
  `Assess` and every mutation transaction still pin the intent to the exact
  policy id and checksum, and `AssessOriginalGuest` still returns a pending
  non-proposed intent unchanged. Publishing while the intent is claimed,
  preparing, canary, draining or retiring therefore still fails those steps
  until the lease expires and recovery-only fencing applies. Publish only while
  the intent is unleased (promoted/reconciled/hold). A `proposed` intent is
  re-planned under the new version with a new generation, as before.
- A member provisioned under version A and retired under version B (the planned
  scale-up/scale-down proof) is retirable, because V2 issue, the drained step,
  the floor canary and the useful-membership count all use the continuity check.
- Not extended: failed-installed disposal admission
  (`requestFailedInstalledGuestDisposal` and its active checks) still requires
  the preregistration's own policy row to be active, and in-flight provisioning
  admission (`guestCurrentTx`) still requires the exact provisioning revision.
  A slot-1 member that fails after a republish cannot be disposed by that
  operator path without a further decision.
- A version whose Guest contract differs (a new Guest build, key, origin,
  bootstrap digest, mutation slot or canary binding) still strands the existing
  members by design; that is a Guest succession, not a configuration change.
- `manifest_purge` could in principle delete an old inactive policy row that no
  FK still references; a member whose provisioning row is gone is refused (its
  historical installation validation already needs that row). Today canary
  challenge rows reference each version's id, which blocks the purge.
- Keeping up to ten returned connections removes the per-request reconnect
  churn under steady concurrency; the pool can still grow to 25 under load.
  It still reconnects in bursts as connections reach the 30 m lifetime and
  after any quiet period longer than the 5 m idle time.

## Related

- ADR-0059 (relates-to: production Guest admission pinned to compiled contracts)
- ADR-0093 (relates-to: steady Notify canary maintenance owner)
