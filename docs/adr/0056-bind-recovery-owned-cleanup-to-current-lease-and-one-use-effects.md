# ADR-0056: Bind recovery-owned cleanup to current lease and one-use effects

- **Status:** Proposed
- **Date:** 2026-10-19
- **Deciders:** Pending repository review
- **Scope:** Qualification-only original Guest failed-owner cleanup
- **Supersedes:** —
- **Superseded by:** —

## Context

The original cleanup authority expires no later than its original lease. Recover is permitted only after that lease expires. Reusing the original authority after Recover is therefore invalid. The immutable failed payload return is historical, and its timestamp must not be refreshed to satisfy current evidence freshness. A Source-only terminal reader is not physical effect authority.

## Decision

Introduce a distinct recovery cleanup authority only for the five existing canonical failed-owner qualification cases. Preserve the entire original provisioning tuple, accepted or uncertain receipt, native start success, enrolled payload exit failure, and historical failure timestamps. Bind a separate current recovery tuple obtained by the original protected workflow's real Recover step and actual resolved executor store. No executor is granted from JSON.

Persist a fresh random challenge before independent reads of the same original QEMU and signed Guest failure census. Store the unchanged historical failure hash separately from new observation times. Emit authority only while the actual locked recovery lease is current. Its cutoff is the minimum of the current lease, original absolute provisioning deadline, original context deadline, current context, and 150 seconds from issuance. Cleanup child expiry remains 60 seconds; no deadline or original lease is renewed.

Extend the existing stage-file channel with two closed phase requests and signed permits for signal and unlink. Each permit is recorded once in an append-only table after checking the same actual child, current recovery owner, native identity and deadlines in a transaction. Commit before publishing; never hold SQL locks over Guest waits. The original frontend verifies and consumes the permit before its original signal or unlink, rechecks OS identity and freshness, and retains actual physical returns. The second permit requires the first permit's durable record. Existing physical ownership, Wait/EOF and absence checks remain necessary.

Use the genuine ordinary compensation APIs for Issue, Redeem, Settle and Confirm. Before cleanup, genuine Reconcile calls must refuse unresolved parent and child; after confirmed cleanup, known cases must reject no-mutation certification and reach the ordinary partial terminal. The below-floor case retains its ordinary failed-floor reconciliation and permission-only next grant. These Source assertions do not confer production authority or prove a subsequent create.

Keep v1 discriminator and nil-omitted serialization unchanged. New repository and provider authority methods are available only under linux and nativequalification. DTOs are inert in default builds. Add only a new empty migration, never rewrite an applied migration. Production registry, profiles and operational defaults remain disabled.

## Consequences

This is an extended Source protocol, not an assertion that the old protocol was byte-identical. The same original workflow, HTTP endpoint, native owner, stage files and signing key are reused. No new controller, transport, provider, credential, VM, retry or mutation route is introduced. Empty tables grant no authority. Loss of current lease, foreign tuples, unknown schemas, stale/replayed nonces, missing signed reads or missing permits fail closed. A later runtime attempt must independently demonstrate fit inside the unchanged 600/420/150/60 bounds; static authoring does not prove fit, compilation, Native qualification or production acceptance.

## Related

- ADR-0053: Source-only recovery boundaries.
- ADR-0054: Redeemed child owns actual cleanup effects.
- ADR-0055: Uncertain original create observation and unused child reissue.
