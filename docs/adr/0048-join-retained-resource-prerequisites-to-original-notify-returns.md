# ADR-0048: Join retained resource prerequisites to original Notify returns

- **Status:** Proposed
- **Date:** 2026-10-11
- **Deciders:** DaKasa platform owners
- **Scope:** yggdrasil-core / sealed private resource prerequisites
- **Supersedes:** —
- **Superseded by:** —

## Context

A ready Pod and an observed business return do not establish that its original
database session remained available through that work. Static source, image,
Pod and lease declarations in a resource configuration cannot prove those
identities. Measuring one available resource must not erase other dependencies
from the selected actors' resource roster.

## Decision

Bind an optional, closed `required_resources` roster to the existing immutable
capacity policy. Require sorted, unique actor/kind/name entries and coverage of
every selected participant. Preserve the existing WindowScope encoder and its
digest; its original policy checksum already binds these requirements.

Join the original publisher and every selected consumer's private
`native_pool_prerequisites` to their independently observed current native
identity, original window, message and live intent lease before completion.
For `postgres_retained_session_v1`, require two original observations from the
same once-acquired keeper/session and process, actual acquisition/ping/Rows.Close
returns, the expected configuration and native database identity, unchanged
backend birth, and fresh observations within the original window. Retain static
declarations only as `declared_unverified`; never use them as live lease or native
Pod authority.

Retain Redis, AMQP and resident-model entries in the declared full roster.
Their missing original producers refuse before possible-start or arm. Never
shrink the roster to the main PostgreSQL prerequisite. An absent optional roster
preserves the legacy contract; a present null or empty roster is invalid.

## Consequences

This seam proves one retained session prerequisite. It does not certify a whole
SQL pool, cache/model residency, full warm resources, physical capacity, provider
retirement or all-service throughput. Native producer and joint original Core
evidence remain mandatory before enabling the binding. Protocol fixtures alone
cannot qualify that integration.

The original owner closes its borrowed keeper before its own DB.Close. A known
borrowed-connection return does not establish that the native backend or TCP
connection disappeared. Cancellation, uncertain Close or a replaced session
retain HOLD and never grant another acquisition or effect replay. No new
infrastructure operation, SQL migration, grant, account, public proof endpoint,
business message or production activation is introduced.

## Related

- [ADR-0047](0047-observe-original-live-lease-before-private-notify-canary.md)
- [ADR-0040](0040-separate-native-process-lifetimes-from-reservation-decisions.md)
