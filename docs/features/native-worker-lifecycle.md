# Native worker child attempts

The optional `native_worker_lifecycle_binding` is separate from legacy mutation
bindings and Guest slots. It defaults off, as does the process gate. Each
profile pins its execution adapter/catalog revision, credential scope digest,
binding reference, Source, bootstrap Source/template, and a server-owned overlay
CIDR with explicit exclusions. The pricing integration instance cannot double
as its execution instance. No existing allocator is enabled or replaced.

```mermaid
flowchart LR
  Parent[Fresh market Claim and reservation] --> Child[Server UUID and overlay IP]
  Child --> Reserved[Durable reserved child]
  Reserved --> Started[One committed send_started permit]
  Started --> Private[Original return in private DB custody]
  Private --> Join[Independent bound SDK and Launch join]
  Join --> Birth[Safe typed birth]
  Birth --> Registry[Separate actual Node and registry CAS]
  Registry --> Admit[Separate network warmup and admission]
  Admit --> Drain[Normal owned drain]
  Drain --> Absent[Exact provider and network absence]
  Private --> Unknown[Unknown retains finite cost and quota]
```

## Protected APIs

`CapacityNativeWorkerStore` composes the existing capacity store with an
installed `NativeWorkerRuntime`. The callback is Source-owned Go composition,
not decoded from a workflow/RPC DTO. `Prepare` is pure and runs under the
transaction; it performs no WAN operation, secret resolution or external write.
`ObserveAuthority`, original-return capture and GET-only `Qualify` run outside
transaction locks.

| Method | Boundary |
| --- | --- |
| `Reserve` | Requires a current claimed generation/fence/executor, exact catalog and fresh protected pool authority. Allocates a UUID and unique nonexcluded IP under the existing global-before-logical lock order, bounded by the actual parent reservation. |
| `Redeem` | Commits `send_started` before returning the one private CREATE permit. A retry, uncertain commit or expired original offer never returns another permit. |
| `Record` | Commits the original private return before independent SDK qualification. Late ACK/unknown truth remains receivable after lease expiry; registry/admission progress still requires current authority. |
| `Read` | Returns only a scope-bound public child projection, never original return bytes, their digest or a send permission. |
| `Renew` | Extends the same dedicated progress lease under current authority, retaining the original offer expiry. It does not weaken legacy renew or mint another send. |

Fresh pool authority binds the actual Source, adapter, realm, pool, registry UID,
epoch and owner. It is retained only in a per-call private copy and rechecked at
database time. A Lease GET does not make a Node mutation and Lease update
cross-resource atomic. Initial cycles require one stable owner. A later epoch
rotation must fence Node resourceVersions and all in-flight permits before
ownership changes.

This authority check validates the real header independently of useful-member
counting and does not fabricate a roster. The installed observer still needs a
separately qualified extension to report truthful mixed-profile overlap before
live switching; header acceptance does not remove that requirement.

## Original custody and public birth

Provider create responses may contain secrets. Original bytes and their raw
SHA remain only in the private Core DB return table. A still-running original
is reported as pending and never sealed as a fabricated empty response.
Completed malformed, partial or failed returns remain archived; an oversized
return retains a bounded prefix with incomplete custody explicitly recorded.
It cannot produce an accepted birth.

The public birth digest comes from a typed safe projection: exact attempt,
policy/generation/fence, pool/epoch, execution adapter/scope, physical lifetime,
account/type/image/network/IP/MAC, request IDs, LaunchSHA and independently
reconstructed physical System BindingSHA. It never hashes or publishes the raw
private response. The registry's `registration_binding_sha256` remains the
static qualified profile/template digest; it is not the per-machine BindingSHA.

Exact identity, launch and independent current SDK facts must agree before ACK
qualification. Actual Node UID/provider ID and registry CAS receiving precede
registration. Bound network, warmup and unexpired qualification receipts precede
admission. Protected floor identities remain refused.

## Registry and quarantine permissions

An optional `registry_writer` pins a separate exact integration instance,
principal, binding, compiled Source and credential scope. It cannot reuse the
read-only pool or pricing instance. `CapacityNativeWorkerPhaseStore` prepares
from installed independent read callbacks and issues one short-lived permission
for exactly one `register`, `admit_registry`, or `release_quarantine` CAS.
The registry precondition hashes the exact original annotation bytes; a hash of
the whole observer response or reconstructed JSON is not a substitute.

The protected callbacks are `GET /internal/capacity/native-workers/phase-permits/read`
and `POST` at the same prefix with `redeem` or `receive`. Read/redeem inputs contain
only the binding and permit UUID. The authenticated machine principal determines
the private issuance and its policy; callers do not select another namespace,
workflow, adapter version or proof. TLS and exact compiled Core Source are
mandatory. API workers refuse these authority routes. A human session cannot
authorize them. Protected process composition must install both runtime ports;
the lifecycle process gate defaults off.

Read grants no mutation and exposes no settlement token. A fresh authority read
and locked current parent, attempt, birth, Node identity and qualification check
precede the single atomic redemption. The admission deadline is clipped to the
qualification deadline. Only a successful original commit returns a private
one-send token; retries and unknown commits return no token. Private storage
retains only its digest. A second permission for the same attempt/action is
blocked while its predecessor is issued, redeemed, received, unknown or observed.

The adapter receives original PATCH bytes into private Core custody before
parsing an ACK. A complete native `Status/v1` failure `409/Conflict` or
`422/Invalid` proves the atomic PATCH was rejected and permits a newly assessed
successor. Ambiguous, duplicate, partial or non-native responses remain unknown.
An expired issuance that was never redeemed may also be closed under the same
lock before a successor: no PATCH permission was returned. Expiry never frees a
redeemed or uncertain send. Raw bodies are bounded to 2 MiB and the authenticated
base64 receive envelope to 4 MiB. An overflow is explicitly incomplete and cannot
qualify an ACK or definitive rejection.

Independent GET-only reconciliation can record the actual applied state after
expiry without fabricating the original ACK or allowing another PATCH. A late
original response is still archived after this observation. Registration and
admission are separate from usefulness: the owned quarantine taint is removed
only after received registry admission, real network/warmup/qualification evidence
and a fresh native read. Kubernetes cannot atomically test a Lease while patching
a Node. Owner/epoch or admission revocation must fence outstanding Node release
permissions before handoff, including unknown returns; this source alone does
not implement that cross-resource handoff.

## Charges and release

There is no fixed 128-slot child array. Source bounds on collection/addresses
are operational limits, not a permanent nine-worker fleet ceiling. A parent
reservation bounds how many attempts can be issued; even an absent child does
not authorize another send under that original parent.

An active parent's reservation covers its group once. After parent completion,
each nonabsent child retains a finite unit reservation plus the group's fixed
charge once. Unknown children do not become an unknown whole-account quantity,
and timeout/lease expiry does not free an address, cost or quota. Current quote
DTOs do not prove per-resource inventory coverage, so the child ledger
conservatively retains its extra reservation until qualified absence rather
than assuming a provider usage count included that child.

Legacy birth joins and historical slot/grant records are unchanged. Only the
new explicit mode consumes typed child births through its separately bound
execution adapter. It never forges a legacy mutation proof.

## Independent phase facts and runtime composition

The optional `phase_observer` pins a separate read-only adapter instance,
compiled Source and exact complete binding-file digest. It cannot reuse a
pricing, execution or registry-writing instance. Its header-only mode retains
the actual complete registry while asserting neither a zero-worker snapshot
nor useful capacity. A selected candidate must join its complete provider ID,
Node UID and canonical allocated internal IPv4 to the stored physical birth.
Optional label claims remain claims: absent claims are not invented, and a
conflicting present claim refuses preparation.

`NativeWorkerPhaseReader` consumes the real source-bound observation through
the catalog/version-pinned RPC reader. It verifies raw annotation hash, realm,
registry UID/RV, owner, epoch, heartbeat, allocatable resources and quarantine.
The read of authority occurs outside transaction locks and is checked again at
database time. It is a distinct authority-header DTO, never a fabricated
empty useful-pool observation during a mixed or quarantined transition.

`WithProtectedNativeWorkerPhaseReader` composes this reader with a separately
qualified worker runtime. A private independent network/warmup callback must
return fresh evidence bound to the exact attempt, physical lifetime, birth,
Node and allocated address before admission or quarantine release. Merely
installing the phase reader does not install that witness or a provider sender.
Missing readiness fails closed. The normal process defaults remain disabled.
Historical GET-only reconciliation can retain actual applied state after a
permit expires without issuing another mutation.

## Qualification limit

CI runs the normal Goose schema on isolated PostgreSQL 16/17, including UUID/IP
uniqueness beyond 128 children, concurrent single redemption, changed epoch,
pending original returns, SDK read failure, late ACK custody, privacy and
immutable-history checks. No local test/build, cloud call, provision, or Hetzner
load test runs in this change.

This child ledger and phase permission source do not install a cloud sender, establish actual
WireGuard/Pod networking, close/promote a Native parent intent, or orchestrate a
mixed-provider overlap and drain. The independently published registry writer
must qualify its native CAS receiving with installed protected runtime ports. Parent completion,
useful-versus-charged capacity, replacement and the full execution cycle remain
requirements before live automatic switching. Persistent data/floor relocation
is outside this worker protocol.
