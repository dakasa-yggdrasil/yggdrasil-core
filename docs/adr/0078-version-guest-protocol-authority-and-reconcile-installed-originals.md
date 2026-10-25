# ADR-0078: Version Guest protocol authority independently of issuer builds

- **Status:** Accepted
- **Date:** 2026-10-25
- **Deciders:** Production architecture owner
- **Scope:** Protected original Notify Guest provisioning, readiness and retirement
- **Supersedes:** —
- **Superseded by:** —

## Context

Guest-v1 enrollments are immutable signed descriptions of an actual native
lifetime, complete protected profile and authority key. Equating their authority
revision with every subsequent Core implementation build prevents compatible
releases from observing or maintaining the same installed Guest. A failed
readiness step also leaves an installed original in `preparing`; neither another
create nor pretending its failed workflow succeeded is an acceptable recovery.

## Decision

Separate the stable signed protocol authority from the actual implementation
issuer. `CurrentGuestCoreSource()` continues to derive the actual clean Git build
from Go build information. It has no environment override. The existing Guest-v1
`CoreSourceCommit` and enrollment `CoreAuthoritySourceCommit` fields identify the
signed protocol/authority revision. A published compatibility map explicitly
supports revision `48888f21acdddaf411094ec525004297c229863f` only for the two complete
canonical AWS and Hetzner Notify profiles already approved by their exact
catalog, contract, keys, endpoint references and slot checksums. It also supports
the current build's own authority under those same complete approvals. A release
must publish its actual build/image and the compatibility-map fingerprint.

Keep private execution origins bound to the actual current issuer. Resolve the
wire authority from the approved binding independently; never substitute a
historical revision into build information, actual native creator identity or
private origin ownership. Original signed records remain byte exact. Guest-v1
needs no additional wire fields or changed keys. New issue records atomically
bind actual issuer, authority revision, compatibility map, profile, policy,
workflow, executor and issued-wire digest. Failure of that insert aborts the
issue. Best-effort ops logging is insufficient. The ledger rejects missing,
unknown or inconsistent identity fields and is immutable. Installed-reconcile
issues also retain the exact marker bytes in this same immutable ledger, with a
database-verified decoded SHA-256. Later intent updates or retries cannot erase
the body needed to rederive an earlier admission; other issue kinds cannot
supply this marker payload.

The source-owned scheduler may establish up to three fresh installed-readiness epochs
without creating another VM. It requires the same pending generation and old
fence, expired original leases, the original provisioning success and failed
completion, a returned dispatch with its genuine finalization acknowledgment,
confirmed create grant, authenticated installation, unchanged enrolled native
membership, current policy/workflow and no outstanding provider mutation. A
scope-locked CAS advances the fence once and binds a bounded new lease to the
actual new scheduler run/executor. A durable marker and event link the old run
and canaries to this distinct readiness epoch.

Use the existing graph's refresh branch so provisioning and retirement are
skipped. Only the verified private installed-resume scope may use an initial
useful-membership canary in this new epoch. It issues a distinct new publish/read
pair, observes actual current business usefulness, rereads source/native
assessment and advances `prepared`, `canary`, `promoted`. Ordinary maintenance
still requires an unleased stable epoch; an expired non-null VM lease does not
become maintenance authority.

A previous held publication may already have had an effect. Preserve its held
or unknown outcome and complete returned transport where available. The new
fixed-recipient, rate-bounded canary is an independent current test. Never resend
an old POST, reuse its identifiers, assert old quiescence or no effect, or turn
the failed original workflow into success. Existing runtime mutex, pending-work
ownership and nonce expiration continue to serialize actual operations.

Cap the serialized canary deadline by both its conservative remaining duration
and its original parent wall deadline. Realtime and monotonic samples can differ
between `time.Now` reads; dropping monotonic state can otherwise project an equal
duration slightly beyond its parent and fail before HTTP. Keep the strict
preflight guard and subtract the whole PostgreSQL sampling round trip.

Expose only closed reconciliation/probe phase labels in future public workflow
failures. Private error text and credentials remain hidden for every formatter.

## Consequences

Compatible Core releases can maintain installed Guests and create new canonical
Guest-v1 instances without rewriting historical enrollments or mislabeling the
actual issuer. Protocol compatibility is explicit governance, not attestation
that an old binary emitted a new request. Consumers independently qualify the
actual Core build and its atomic issuer ledger, then the approved wire authority.

Installed reconciliation yields an original successful provisioning fact plus a
new successful readiness reconciliation. Consumers must preserve that distinction
from an original seven-step workflow that completed successfully. A crash after
reservation is not permission to replay that epoch. Only after an acknowledged
failed refresh and expiry may a distinct next run advance the fence again. Each
marker preserves the original and preceding failed attempt; after three attempts
the scope remains on HOLD. An incompatible profile, key, schema or protocol still
requires a new explicit contract and release review. Local unit or PostgreSQL
storage checks do not establish native deployment or business success.
