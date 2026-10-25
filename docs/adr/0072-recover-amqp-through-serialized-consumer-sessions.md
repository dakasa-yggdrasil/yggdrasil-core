# ADR-0072: Recover AMQP through serialized consumer sessions

- **Status:** Proposed
- **Date:** 2026-10-23
- **Deciders:** Core maintainers
- **Scope:** yggdrasil-core / AMQP connection and consumer lifecycle
- **Supersedes:** —
- **Superseded by:** —

## Context

A broker can close an established AMQP connection during a restart or network
failure. Logging that close leaves the Core process running with an unusable
connection. HTTP controllers, background dispatchers and registered RPC handlers
can retain that original pointer, so replacing only an application resource or
only an SDK transport does not recover all callers.

Consumers and the integration runtime monitor capture the connection for their
lifetime. Starting replacements before their predecessors finish can overlap
handlers or probes. The pinned SDK also settles a handler error with a negative
acknowledgement, so cancelling a handler while its socket is still live can
discard an unsettled delivery during shutdown.

## Decision

Own AMQP recovery as one serialized session lifecycle. A session contains its
connection, transport, registered consumers and integration runtime monitor.
Expose it to new operations only after every consumer has registered. Resolve
the current connection at each HTTP operation and background pass.

On disconnect or shutdown, withdraw the session first. Close the delivery gate
and the socket before cancelling handler and monitor contexts. Join handlers and
the monitor before initializing another session. Report a drain deadline error
when cleanup is slow and remain unavailable until cleanup actually finishes.
Bound connection setup and retry it with cancellable backoff capped at thirty
seconds. Preserve boot degradation when the broker is initially unreachable.

Keep reconnection independent of message retries. Do not store or resend a
Request or Publish payload during session replacement. An operation that loses
its reply or publish result keeps that ambiguous result; another operation needs
its own existing application authorization and identity.

## Consequences

Broker readiness is degraded throughout registration, drain and recovery.
Shutdown can report its caller's deadline when an old handler or probe refuses
to terminate; a replacement session cannot bypass that drain.

Each consumer generation binds one connection. Long-lived infrastructure must
use the current-session provider rather than cache a connection across passes.
An operation already using a retired connection can fail and is not restarted
by the transport supervisor.

The existing delivery acknowledgement, broker redelivery and application
deduplication rules remain in force. Session recovery adds no exactly-once
claim and no authority to repeat a mutation whose outcome is unknown.

## Related

- ADR-0044 (relates-to: durable pre-start capacity dispatch ownership)
- ADR-0060 (relates-to: original provider invocation lifetime)
- scratch: `docs/superpowers/2026-10-23-AMQP-reconnect-handoff.md`
