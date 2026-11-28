# ADR-0148: Install Native runtime under one private main-process owner

- **Status:** Proposed
- **Date:** 2026-11-28
- **Deciders:** Giomaster
- **Scope:** Core / default-off private Worker, Guest, Network and Abort installation
- **Supersedes:** —
- **Superseded by:** —

## Context

The concrete Worker/Guest, Network and Abort runtime constructors and protected
HTTP options exist, but ordinary process startup does not construct them.
Selecting a workflow flag cannot safely supply private files, TLS identities,
artifact credentials, policy authority or a runtime owner. RabbitMQ consumers
start before HTTP installation and their supervised connection can change.
Capturing a missing owner or an old connection at consumer registration would
make later installation or recovery unreliable.

## Decision

Install all three runtimes from one optional private regular file named by
`YGGDRASIL_NATIVE_WORKER_RUNTIME_FILE`. Only the control authority accepts it.
An absent variable preserves existing startup; an empty, unreadable, unsafe or
invalid configured file fails startup with an opaque error. Require mode 0600,
one link, protected ownership, no final symlink, complete bounded reads and
stable file identity/metadata. Parse literal closed JSON with duplicate and
unknown-member refusal. Do not accept this configuration through workflows,
HTTP requests, public plans or integration credentials.

Pin the original active policy ID, namespace/name, version and checksum and
require its lifecycle Source to equal clean compiled Core metadata. Derive
execution profiles, adapter tuples, bindings, Sources, scopes and capabilities
from that exact policy. Configuration supplies private material references,
artifact/CLI pins and fixed TLS origins. The existing pool binding has no scope
field, so a separate private pool-reader whole-file scope pin is mandatory.
It remains coupled to the policy's adapter, binding name and compiled SDK Source.

Resolve artifact signing credentials through the existing managed-secret
repository on every Retrieve, without a cache or ambient AWS chain. Pin its
private UUID/namespace/name and a safe typed artifact-read scope: Core Source,
policy/profile, bucket/key/version, owner, region and action. Require exact
closed metadata, active status, a future expiry and precisely three nonempty
temporary credential fields including the session token. Rotation or revocation
is observed by the next operation. The metadata does not establish actual IAM
permissions; bucket/object-version/owner and read-only policy qualification
remain operational prerequisites. The credential refresher is not installed
by this change.

Construct with rollback ownership, transferring each handle only after its
real constructor succeeds. Borrow the process database and current broker.
Publish the owner only after all components and listeners are built. Register
the existing Worker/bootstrap/phase, Network and Abort HTTP options together.
Seal new borrowed scopes without waiting; final Close joins existing scopes
and closes Abort, Network, Worker and remaining owned handles in reverse order.
Never close the shared DB, broker or global secret registry.

Join Native borrowers with the same callback HTTP listeners still available.
Use a counter and completion channel so `Join(ctx)` can return the original
deadline/cancellation without a detached waiter or a forged completion. On an
unjoined original, return the opt-in `ErrDependencyShutdownHeld` ownership
barrier; the process close chain must stop before runtime/broker/DB dependencies.
Ordinary legacy closer errors keep their existing continuation behavior.

Inject a typed protected resolver into authority HTTP and RabbitMQ contexts.
It finds the current owner per operation, matches the exact DB and original
policy including JSONB bytes, and holds the borrow fence through the synchronous
callback. Maps are copied. Missing, replaced, sealed or closed ownership yields
HOLD. Recursive resolution refuses before another read lock. Callbacks must not
retain handles or start detached work. Original controller/command authority
is restored separately from its durable ledger, never from this accessor.
Protected callbacks acquire a current broker snapshot for each operation and
do not retry or switch snapshots inside it.

## Consequences

Installation does not enable provider execution, the Native market dispatcher,
any process gate or an old allocator. It does not install SDKs or modify floor,
network, persistent data, business Deployments or live credentials. The optional
independent `NativeWorkerGuestWitnessProofFunc` stays nil at main installation;
guest self-observation cannot become end-to-end MTU or warmup authority.
Readiness remains HOLD until its separately reviewed producer is composed.

Before activation, the operator must qualify the mounted material, exact
published CLI/SDK artifacts, temporary-credential renewal and independent
readiness evidence. A single allocator handoff must also quiesce the old
HCloud autoscaler and retain every outstanding/unknown provider producer and
its quota/cost. Core advisory locks and common scheduling labels do not fence
that separate controller. Keep the existing floor and HCCM lifecycle fences.
Legacy workers are not adopted as Native births from labels or absence.
The main process may still exit with a shutdown error. Withholding dependency
Close is not a claim that the process or original caller survives that exit;
durable unknown/receiving state must remain held for reconciliation.

CI exercises configuration closure and file boundaries, per-operation secret
rotation/expiry/scope refusal, owner borrowing/draining/closing and startup
refusal. Existing real factory, PostgreSQL, mTLS and kernel qualification gates
remain separate and unchanged. No test or build runs on the owner's machine.

## Related

- ADR-0139 and ADR-0145: concrete Worker and Network composition ownership.
- ADR-0146: per-Attempt guest identity and independent readiness proof.
- ADR-0147: independent Abort inventory and immutable original custody.
