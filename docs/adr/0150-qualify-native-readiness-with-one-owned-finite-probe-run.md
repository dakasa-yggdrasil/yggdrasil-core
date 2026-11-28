# ADR-0150: Qualify Native readiness with one owned finite probe run

- **Status:** Proposed; activation gated
- **Date:** 2026-11-28
- **Deciders:** Giomaster
- **Scope:** Core Native independent network and API worker warmup proof
- **Supersedes:** —
- **Superseded by:** —

## Context

A guest's authenticated interface witness establishes local facts, including
WireGuard MTU1380, its overlay address and floor TLS. It deliberately does not
qualify the workload Pod path, Service path, process startup or useful capacity.
Node Ready, a provider ACK, an image hash and a diagnostic echo alone cannot
close those gaps. Process admission must also be separate from useful Node
admission: waiting for useful admission before process warmup would be circular.

Diagnostic resources and callbacks can remain uncertain across cancellation,
expiry or a Core restart. Recreating resources or sending another packet batch
would hide that uncertainty and expand the original finite run. Closing a
callback listener while its producer or borrowed factories are still active
would also destroy original receiving authority before its actual join.

## Decision

Install the existing protected GuestWitnessProofFunc only through an optional
Source-bound readiness producer owned by the Native main-process installation.
Keep the nil behavior as HOLD. Require the exact policy, whole private file SHA,
compiled Core Source, independently received normal Core/probe publication
receipts, curated worker template and dedicated Kubernetes reader/writer
bindings. No workflow supplies a resource object, image, endpoint, key or proof.

Own one durable run per Attempt. Migration121 retains its immutable identity,
start/end, encrypted run keys and append-only revisions. Cap the original run
by the original parent command/lease, physical qualification and five minutes;
require at least three minutes before creating a new run. The original quote,
bootstrap and lease must leave that much time; this does not renew or extend
any authority. Read the database clock after contended
locks. A restart keeps the same run, keys, effect barriers and deadlines.

Use exactly two bare Pods, two UDP9446 ClusterIP Services, three Secrets and one
NetworkPolicy. Pin the original protected floor and the candidate's actual
Node/birth/registry. The floor runs only the probe; the candidate runs the
Source-qualified Core API worker beside the probe, without a business Service.
Preserve the normal curated secret/config references, readonly CA volume and
image-pull references. Admit ingress only for the run's UDP exchanges and the
same-namespace controller's authenticated control traffic; business9080 remains
loopback. The protected dependency egress plan remains explicit.

Require complete independent Kubernetes reads to join Namespace/Node/Pod/
Service/EndpointSlice UIDs, exact images and qualified runtime child digests,
container IDs, starts and zero restarts. Neither an opaque resourceVersion
comparison nor an input identity is an independent observation. The probe's
Core Source configuration is an expected pin, not a Source header observed on
loopback9080; actual image provenance and container lifetime provide that join.

Send only the probe's fixed initial and final batches: twelve DF UDP requests
and twelve authenticated echoes globally, IPv4 MTU1330/payload1302, at most
31920 IP bytes and thirty seconds per batch. A retained start barrier forbids
another POST after uncertainty. Validate both signed directions, fixed peer
Pod/Service identities, raw packet metadata and report order. Obtain actual
API worker waiting_projection/process nonce/roster, patch its exact original
Pod with the matching startup challenge, and require the same process's
roots_open plus real readyz. That process handshake grants no useful Node
admission and receives no production jobs or business traffic.

Service DNAT can translate a request's source port. Accept that observed
nonzero port only for the canonical signed Service request from the exact peer
Pod IP. An emitted echo must preserve that original request's signed bytes and
return to its exact observed address. Pod-path requests and received echoes
retain port9446; no caller selects a reply destination or gains another packet.

Before the first initial POST, obtain fresh authenticated idle reports from
both normal probe processes. Configuration is projected after real Pod
identities exist, so a Secret creation ACK is not a listening control server.
Poll with GET only and a short voluntary yield while the original dispatch
context still has time to capture and acknowledge its return. A later eligible
invocation resumes the same live run and keys; it never retries a consumed POST.
Keep the existing 65-second proof-call and 90-second Native-step limits. An
expired or unacknowledged dispatch remains held. Normal Kubernetes Secret
remount uses periodic sync; annotation PodUPDATE requests a remount directly.
Neither is a delivery SLA, and the finite run is not a worst-case IO guarantee.

The SDK obtains one resource permit through a separate private mTLS listener
and four fixed read/bootstrap/redeem/receive routes. Verify CA, client URI/leaf,
bearer hash, compiled SDK Source and whole writer scope before reading a body.
Keep original request/bootstrap and raw native returns private and encrypted;
commit original custody before parsing. A callback204 proves custody only.
An observed create/patch and its canonical ensured event commit together.
A DELETE ACK remains private audit and never emits destroyed by itself.

Seal one PendingProof from the actual final reports, startup/process brackets,
resource reads and a fresh independently authenticated Guest witness before
cleanup. Preserve the oldest final observation time and smallest existing
validity boundary. Cleanup, admission, quarantine release and later Record
consume those same hashes and times; they never send new packets, restart the
worker or remint an expired proof.

Clean up only the eight original diagnostic resources. A fresh exact-name
independent404 closes a known original qualified UID, including external
deletion or an uncertain DELETE, with encrypted absence custody and the
canonical destroyed event in one transaction. Kubernetes cannot recreate the
same UID. An unknown create without a qualified original UID stays HOLD.
Neither404 alone nor a timer fabricates deletion, a successful send or proof.
Cleanup has its separate finite one-send delete context and never renews it on
GET. Recovery owns cleanup only; it cannot open a run or perform more warmup.

Keep the private closed journal bounded at48MiB: at most seventeen native
originals (eight creates, eight deletes, one patch), each original at most1MiB,
plus private requests and control reads. Bound the SQL value before Go
materialization. Public SDK decoders and HTTP limits stay unchanged. Permit
only a bounded five-second database-only original-custody tail after caller
cancellation; it grants no new WAN authority or retry.

Join readiness cleanup and callback receiving before Workers-owned factories
and phase clients. Keep listener lifetime independent of producer-start
cancellation. Forced/unjoined closure returns the existing dependency-held
barrier, retains the opaque owner and lower borrowed handles, and remains held
on later Close calls. Constructor and HTTP startup rollback retain the same
barrier so ServiceApp cannot close the borrowed broker/database underneath it.

## Consequences

The producer adds no provider allocation, live installation, throughput test,
admitted-worker retirement or general Kubernetes CRUD authority. Callback,
resource and image qualification remain default-off until their exact Source,
private inventories, normal artifacts and independent runtime ports are
installed and qualified together. Missing, expired or ambiguous facts hold.

CI accounts for every authored unit, original mTLS ownership and isolated
PostgreSQL16/17 root, with race/count1, original JSON and no skipped cases.
The composed PostgreSQL fixtures label synthetic provider/Kubernetes projections
and retained diagnostic effects explicitly; they do not claim a single live
end-to-end network/warmup qualification. Real Service reverse-SNAT, API worker
startup and actual provider/guest joins require their corresponding independent
integration evidence before activation. No local tests or cloud load qualify
this Source decision.

## Related

- ADR-0140 / ADR-0145: original floor network authority and owned ports
- ADR-0146: protected Guest identity and local witness boundary
- ADR-0148 / ADR-0149: private installation lifetime and real phase receiving
- Integration contract sections6.5,11 and12: paired resources, events and entry authentication
