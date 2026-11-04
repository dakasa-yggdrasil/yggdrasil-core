# ADR-0054: Bind failed-owner compensation to its original redeemed cleanup child

- **Status:** Proposed
- **Date:** 2026-10-18
- **Deciders:** Pending owning review
- **Scope:** yggdrasil-core nativequalification and exact Guest source fixture
- **Supersedes:** —
- **Superseded by:** —

## Context

An original native start can succeed while its same enrolled payload subsequently exits 1. The accepted create receipt must remain intact; its successful native action must not be relabeled as failed. A signed complete payload Wait/EOF/Close and identity chain may instead establish that the aggregate provisioning operation failed. Existing positive Guest quiescence requires successful owner returns and cannot authorize this failure path.

The earlier Source-only cleanup protocol intentionally leaves the ordinary parent SETTLED. Physical absence alone does not prove canonical compensation. A child created after that cleanup would only observe past effects and must not claim to have caused them.

## Decision

For the three closed nativequalification cases only, retain signed real native-start and enrolled payload action identities as immutable aggregate history. Validate the exact current Source pair, preregistration, enrollment, tuple, session nonce, complete failed Wait/EOF/Close and census. Keep SpecVerified true when justified; never derive failure from the native successful action or an uncertain transport alone.

Prepare immutable eligibility before any physical effect. Issue and redeem the actual generic compensation child through the existing API. Sign a separate closed child authority binding that redeemed attempt, eligibility and exact original Source cleanup authority. Publish it before the existing frontend ready file. The sole original frontend performs its existing owned PIDFD signal/Wait/EOF/Close, disk unlink/sync/anchored absence only after verifying this child authority. Bound every effect by the earliest actual child expiry, original current lease, cleanup150, provisioning420 and outer600; never renew any clock. Persist the original physical returns, then fresh absence, then Settle and generic Confirm. The child action is the actual cleanup operation, not a retrospective readback action.

The failed-floor case uses the existing genuine baseline1 and exact stronger Floor1→2 policy bridge. After actual generic compensation, wait the original lease expiry, recover under a new actual lease, obtain the signed original baseline probe and native membership plus a separate current absence read. Use ordinary Reconcile unchanged, exercising its invalid-proof/partial/abort negatives. Next Assess/Claim/Issue run through the same original resolved workflow step, which mints its own fresh preregistration nonce. A closed nativequalification hook validates the real prior ordinary terminal, next generation, current lease and compensated parent/confirmed child before skipping physical provider Prepare/Create for this permission-only call. It creates a fresh logical permission only; do not redeem or start a third VM. This does not claim that a new physical provider preparation or next physical creation is qualified. No Source-only outstanding-grant exception is used in this canonical case.

Production builds have not-handled hooks, empty production registry and no new activation. The positive quiescence path and ordinary Reconcile remain unchanged. A proposed contract is implementation material, not approval for transfer, runtime, release or production.

## Consequences

The old accepted settlement, native-start success, original failed payload returns and historical cleanup clocks remain separately auditable. Private signed originals and lease-bearing intents stay private; public exports use closed typed projections, full-original hashes and read custody. Real compilation, regression execution and owning static/runtime review remain required.

Lost replies without an enrolled failed payload remain a legitimate negative: the current source producer deliberately suppresses the accepted response before enrollment and supplies no failed payload action. Implementing a separate authenticated post-loss readback of actual failed enrollment would be a different explicit producer case; it cannot be inferred from the current uncertain transport. Paid-IP, expired-child reissue and foreign-lock concurrency assertions remain ordinary repository gates and are not claimed as physically covered by this fixed two-QEMU Source fixture.

## Related

- ADR-0053 (existing Source-only cleanup and floor accounting; preserved)
