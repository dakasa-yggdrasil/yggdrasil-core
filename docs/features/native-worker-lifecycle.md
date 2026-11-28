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

### Provider RPC authentication

`capacity.NewNativeWorkerRPCClient` loads fixed protected client certificate/key
and server CA material. Its Source-owned configuration pins the exact adapter
tuple, profile, binding, scope, compiled SDK Source, HTTPS origin, server leaf
and separate public health URL. Observer and creator roles cannot share the
same allowed-capability set. No public manifest or request selects those files.

`message.WithNativeWorkerRPCClient` carries that opaque client through the
original resolver, health, Describe and execution. Original row/type checksums
and origin are checked before secret hydration. A fresh execution policy cannot
erase the separate private context. Protected Describe requires the actual TLS
server return rather than a generic cached handshake. The independent observer
can be composed with `NewProtectedNativeWorkerPhysicalReadFunc`.

The server chain, hostname, exact leaf and single actual compiled Source response
header must agree before SDK decoding. Original requests disable replay,
redirects and environment proxies. Read and Close both have to complete within
the original bounded context. A separate unauthenticated fixed health GET carries
no private client certificate or header and remains diagnostic only. All copies
of a client share one Close fence and opaque value/pointer/JSON representations.
See [ADR-0138](../adr/0138-bind-native-provider-rpc-to-protected-mutual-tls-clients.md).

This composition does not install the provider process, runtime/controller or
network, and it grants no CREATE or DELETE without its separate original Core
permit. Existing callers with no protected client context keep their contracts.
### Expired commands that never granted a send

`CapacityNativeWorkerCommandStore.CloseUnredeemed` closes only an expired
original command whose Attempt remains revision-one `reserved`, with no birth,
Node identity or original return. It uses the same mutation/Attempt locks as
Redeem and retains an immutable private no-send proof before atomically writing
the normal `absent` state and event. Concurrent calls reuse that proof.

An expired lease, missing ACK or unknown provider response cannot qualify this
operation after a send was granted. The closed command cannot receive later
provider custody, replenish the generation's create budget or authorize a
retry. This protected operation adds no HTTP route or provider action and
requires the Native and global execution gates. See [ADR-0136](../adr/0136-close-expired-unredeemed-native-reservations-with-retained-no-send-proof.md).

### Pre-admission failure recovery

The optional `pre_admission_abort` lifecycle binding names one Source-selected
recovery workflow and a finite permit duration. `CapacityNativeWorkerAbortStore`
defaults off. Its `Begin`, `Read`, `Redeem`, `Receive` and `Reconcile` methods do
not create or destroy any provider resource themselves.

The policy's normal `execution_enabled` growth flag is independent of this
explicit cleanup authority. A disabled growth policy grants nothing by itself:
the cleanup binding, Native store gate, process capacity execution gate, exact
active recovery workflow and fresh scoped ownership must all permit redemption.
Disabling the process capacity execution gate also disables cleanup sends.

`Begin` locks the same mutation scope and Attempt row used by admission and
retains the explicit `aborting` state. A provider-accepted worker need not be
falsely admitted or drained to become eligible for cleanup. Exposed or unknown
phase mutations block cleanup; never-redeemed issued phases can be closed
atomically without inventing an external API refusal. Old creator/bootstrap
readers cannot re-open a child in this new state.

The protected `ObserveAbort` callback performs fixed reads outside database
locks. It must distinguish complete absence from unknown/ambiguous Node data.
An exact empty, cordoned, quarantined Node or a complete no-Node observation
can qualify a send; missing readiness alone cannot. Complete independent
provider, Node, registry, peer/IPAM and ancillary charge closure is required
before releasing quota, money or the overlay address. Expired price or warmup
evidence does not manufacture cleanup authority or block truthful late reads.

Only a successfully committed `Redeem` returns a private one-send token. `Read`
does not return that token or a launch. Original opaque returns remain private,
and late custody preserves an already observed result. Unknown sends do not
expire into retry permission. The target birth generation/fence and original
creation count remain immutable throughout cleanup.

The machine-only callback prefix is
`/internal/capacity/native-workers/abort-permits/`: `GET read` takes exactly
`binding_name` and a canonical `permit_id`; `POST redeem`, `receive` and
`reconcile` share that prefix. Read, redeem and reconcile selectors contain only
those two fields. Receive accepts the private original return, one-use settlement
token, capture-completeness flag and closed error class. Every callback requires
TLS, one active exact machine bearer and one canonical compiled SDK Source
header. The authenticated instance and effective destroy capability must match
an existing private issuance before any request body is read. API workers and
human sessions cannot reach these routes.

Resolution restores the original private recovery workflow and executor; a
callback cannot supply either identity or another policy. The abort process gate
`YGGDRASIL_NATIVE_WORKER_ABORT_ENABLED=true` is additionally required to expose
a new send. Original-return custody remains receivable after gates close or the
runtime becomes unavailable. Installing `WithNativeWorkerAbortRuntime` requires
protected Go process composition; neither the header nor a process flag creates
an observer. These callbacks do not install a controller or a cleanup actor.

This Source slice requires a known sealed physical birth and provides no live
transport or external cleanup writers. Unknown creation-ACK discovery,
provider destruction, Node cordon/deletion, registry retirement, network cleanup
and useful-versus-charged overlap qualification remain explicit prerequisites
for a complete live lifecycle. See [ADR-0134](../adr/0134-fence-preadmission-worker-cleanup-separately-from-admission.md).

### Creation and physical receiving

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

### HCloud physical witness

Literal provider `hetzner` uses a separate HCloud read DTO and required
`physical_observers[].hcloud_scope`. The pin names the reviewed logical project,
token/network-anchor proof kind, anchor ID/creation time and owner label.
It is compared with actual independent facts, compiled SDK Source, exact catalog
tuple and the complete reviewed reader inventory digest. It is forbidden on AWS.
HCloud's `account_id` stays empty; its real create action ID and optional actual
HTTP request IDs are recorded separately.

The original HTTP 201, canonical base32 launch labels, server lifetime and
independent server/network/firewall/Primary IP reads must join the immutable
Launch. The market region is the actual location; System's native provider
region is the distinct network zone. Complete safe evidence is preserved as
`hcloud_witness` through the Attempt and immutable Birth. It never includes a
password, raw original or raw-original hash. A coherent foreign project or
reader pin still fails the current immutable policy check.

`ReobserveACK` returns only the current physical tuple after a fresh complete
read. It does not issue a second birth or lifecycle transition. A later protected
registry/admission observation retains the stored witness and its actual
original optional HTTP IDs. Generic lifecycle and pre-admission abort guards
require that witness before accepting HCloud's empty account/IDs. Node, network,
warmup, admission and all-component absence remain separate proof requirements.
The provider runtime remains separately gated; SDK complete-read/Close handling
must be qualified before activation. See
[ADR-0141](../adr/0141-qualify-hcloud-births-with-explicit-project-and-action-witnesses.md).

## Registry and quarantine permissions

An optional `registry_writer` pins a separate exact integration instance,
principal, binding, compiled Source and credential scope. It cannot reuse the
read-only pool or pricing instance. `CapacityNativeWorkerPhaseStore` prepares
from installed independent read callbacks and issues one short-lived permission
for exactly one `register`, `admit_registry`, or `release_quarantine` CAS.
The registry precondition hashes the exact original annotation bytes; a hash of
the whole observer response or reconstructed JSON is not a substitute.

The permit's `writer_scope_sha256` is the policy pin of the complete reviewed
writer inventory file bytes. The writer must compare its actual loaded file
hash with that value before redemption and with the original returned grant.
Matching pool, realm or registry identities alone does not authorize changed
writer configuration, including a changed quarantine taint key. Core requires
this pin to agree with its private writer record at issuance, persistence,
resolution and redemption.

The protected callbacks are `GET /internal/capacity/native-workers/phase-permits/read`
and `POST` at the same prefix with `redeem` or `receive`. Read/redeem inputs contain
only the binding and permit UUID. The authenticated machine principal determines
the private issuance and its policy; callers do not select another namespace,
workflow, adapter version or proof. TLS and exact compiled Core Source are
mandatory. API workers refuse these authority routes. A human session cannot
authorize them. Protected process composition must install both runtime ports;
the lifecycle process gate defaults off.

Every callback requires exactly one canonical 40-character lowercase
`X-Yggdrasil-Adapter-Source-Commit` header before its body is read. After resolving
the authenticated issuance identity, Core requires that header to equal the
separately pinned writer Source. The current unadopted writer needs the matching
new callback protocol; this addition makes no older-runtime compatibility claim.

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

## Private creator command protocol

An execution profile pins `sdk_source_commit` independently of Core lifecycle
Source and bootstrap Source. The immutable private command context is committed
with Reserve, retaining the original controller executor/workflow without adding
them to public Attempt JSON. The protected SDK actor uses exactly these paths:

| Path suffix under `/internal/capacity/native-workers/attempts/` | Contract |
| --- | --- |
| `read` | GET with only `binding_name` and `attempt_id`; no launch or mutation grant |
| `redeem` | POST with those two fields; one committed original send permit |
| `receive` | POST with those fields plus `original_return`, `capture_complete`, `error_class`; private custody only |

Each request carries one `X-Yggdrasil-Adapter-Source-Commit` equal to the actor's
compiled revision. Each response carries Core's compiled
`X-Yggdrasil-Source-Commit`. TLS, the active hashed exact execution credential and
Source-written context are required before a body is read. The actual attempt,
binding, policy and machine scope are rejoined privately after closed decoding.
The original response is at most 1MiB; the base64 envelope is at most 2MiB.
Oversized transport data must be truncated by the actor with completeness=false
and `ORIGINAL_CAPTURE_BOUND_EXCEEDED`; uncertain transport uses
`ORIGINAL_TRANSPORT_UNCERTAIN`. Neither flag is an ACK or admission assertion.

The private permit includes only the public Launch, fixed execution bindings,
original expiry and `execution_scope_sha256`. The SDK must compare that scope to
its actual complete protected binding-file bytes before any provider API call.
A retry or uncertain redemption cannot return another launch grant. Original
custody is durable before independent qualification; closed/expired parent
leases do not erase it. The creator receive path can settle historical ACK or
unknown truth, and cannot register/admit a Node. Production sender/network
composition and remote execution evidence are still required before activation.

## Private bootstrap preflight

The fixed `GET /internal/capacity/native-workers/attempts/bootstrap` accepts only
`binding_name` and the canonical `attempt_id`. It shares the creator machine's
exact Source/instance/capability, TLS and private immutable-context guards.
`WithNativeWorkerPrivateBootstrapFactory` is an explicit protected installation
port; the default is nil. Flags, policies and request bodies cannot install a
factory or supply private scripts.

```mermaid
sequenceDiagram
  participant A as Dedicated provider actor
  participant C as Core private bootstrap
  participant F as Protected System factory
  A->>C: Read exact reserved attempt
  C->>C: Check original parent, budget, epoch and deadline
  C->>F: Render outside all SQL locks
  F-->>C: Bounded private cloud-init
  C->>C: Recheck authority and exact stored launch
  C-->>A: Private bootstrap; no send right
  A->>C: Redeem original one-send grant
```

The private response schema is `native_worker_private_bootstrap_v1`. It binds the
attempt/binding, compiled SDK Source, execution scope, original Launch digest,
original command expiry and exact public Launch bytes. `cloud_init_base64`,
`cloud_init_sha256` and `cloud_init_bytes` stay private. Raw user-data is at most
16384bytes and must be complete cloud-config. Ordinary JSON serialization and
formatting of the Core response object refuse exposure; only the fixed private
HTTP writer can emit it. Temporary buffers are cleared on success and refusal.

Rendering performs no provider mutation or command redemption. It holds no SQL
connection while protected file reads, capability signing or process waiting
occur. Concurrent redemption, closed policy, cancellation or expired authority
refuses the response. A valid preflight leaves the attempt reserved and the
later grant must retain its exact Launch bytes. Repeated preflights never renew
the immutable command deadline or authorize another create.

The concrete factory remains separately installed through protected composition.
Neither this endpoint nor a rendered configuration proves private routing,
guest health, admission or useful capacity.

### Concrete private factory

`NewNativeWorkerPrivateFactory` binds one exact execution profile to protected
canonical System launch-template bytes, a node-role agent token, certificate-only
floor CA and dedicated WireGuard master. Its explicit credentials provider has
no ambient fallback. A pinned executable descriptor must match the reviewed
System Source, complete binary hash/size and clean Linux/amd64 Go build metadata.
Missing or unqualified material refuses construction.

`Prepare` derives the per-attempt key deterministically from the loaded master
with domain, binding, scope, namespace, pool and attempt separation. It performs
no I/O, credential retrieval, clock read or randomness inside a reservation
transaction. HCloud market location and native region remain distinct template
operands. Rendering accepts only the exact stored canonical public Launch.

Outside SQL locks, rendering signs a fixed versioned S3 operator GET in us-east-1
with expected owner 153828470928 and a lifetime bounded by credentials, the
original command deadline and 900 seconds. The real System `render-private` parent
receives private JSON on stdin and returns at most 16 KiB through FD3. No secret appears in
arguments, environment, ordinary diagnostics or public hashes. FD4 pins the
actual executable; bounded process-group cleanup precedes reaping the owned
parent. Value and pointer representations are opaque, and copied handles share
one Close fence that erases owned material.

CI retains the complete default test census and separately exercises the actual
published System CLI from exact versioned release asset IDs and byte hashes.
It does not rebuild System or use a fake renderer as executable qualification.
This Source delivery installs no material, factory, network peer or provider
sender in production. Actual boot/package/download timing must fit the immutable
command and capability lifetime before live qualification.


## Independent physical creation qualification

Optional lifecycle `physical_observers` select exact protected read-only adapter
instances per profile, separate from execution and pricing. Core supplies only
`binding_name`, `attempt_id`, `resource_id` and `launch_sha256` from stored state
and the already archived original acceptance. Exact compiled source, whole-file
configuration scope and instance/type revision/checksums are mandatory.

`NativeWorkerACKQualifier.QualifyACK` takes the original private custody and the
canonical stored Launch through protected process ports. Its AWS-only first
slice requires an unambiguous complete RunInstances acceptance plus a fresh
independent AWS58 physical read. Ancillary root/ENI IDs may be absent from a
pending original but must match if present; complete current root/interface
identity is always mandatory and absent original IDs are never fabricated. It reconstructs the canonical public System
Binding instead of trusting a supplied digest. Partial/error/missing acceptance
remains unqualified and charged. Raw XML and its digest never become public
workflow evidence. The resulting state is only `acknowledged`; no Node, network,
registry, scheduling or useful-capacity right is implied.

This Source slice adds no public route, controller, process activation, provider
send, cluster mutation or HCloud ACK qualifier. HCloud's declared-project and
action evidence require their own later typed contract; no AWS account or
request identity is fabricated. See [ADR-0137](../adr/0137-qualify-native-births-with-an-independent-physical-reader.md).

For an already sealed acknowledged/registered/admitted/draining birth, the
separate `ReobserveACK` entrypoint preserves its real state and returns only the
unchanged physical tuple. A known Physical and Birth digest, the same original
acceptance and all current SDK joins are required. It neither repeats creation
nor emits an ACK transition or scheduling authority. Missing/terminal states
and substituted or changed physical identity remain refused.

The optional `transport_endpoint_ipv4` field follows Physical in the AWS60 wire.
Its empty omission preserves AWS58 bytes and safe-evidence hashing. A present
value must be a canonical public IPv4 received from the Source-paired independent
reader; native private addresses are not Internet endpoints. This fact does not
qualify reachability or authorize a floor peer. ReobserveACK still returns only
the sealed physical tuple; the protected raw reader port retains endpoint facts.

## Concrete private runtime composition

`message.NewProtectedNativeWorkerConcreteRuntime` builds the existing catalog/RPC
readers around Source-owned mTLS handles. The repository runtime binds a copied
stored policy, its database, real per-profile private factory handles and independent
physical/phase readers. `WithConcreteNativeWorkerRuntime` installs worker, private-bootstrap and phase
ports together on the same database, clearing all three before any refused
replacement; it does not enable
process gates or install a controller, sender, network writer or readiness
callback. A missing or unconstructed handle stays disabled.

The public constructor reads Core Source from native build metadata. Preparation
is a pure delegation to the exact selected factory. Bootstrap rendering uses its
existing descriptor-pinned System executable and immutable launch checks. After
successful construction the runtime owns supplied factory/client handles; failed
construction closes none of the caller's handles. Copies share the Close fence,
and the database remains caller-owned.

Original capture is an archive read only. Missing rows and read failures return
the existing pending sentinel, including a concurrent Close; they never invoke
an actor or convert an absent return into empty completed custody. Before a
physical GET, qualification rechecks exact archived bytes/private digest, current
Attempt and immutable launch. AWS acknowledgement qualification is separate from
sealed reobservation; the latter returns only current physical identity and
preserves lifecycle state. The closed provider set is `aws` and `hetzner`, each matching its copied
profile and market region. `hcloud` and other aliases remain refused. HCloud
qualification uses its separately typed original201, action and independent
project/network witness; empty account and absent HTTP request IDs cannot be
filled with invented values. The same strict qualifier owns sealed reobservation.

The same real phase reader forwards preparation and GET-only receiving under the
copied policy, pool epoch, writer inventory scope and shared Close fence. Missing
independent readiness still refuses admission and quarantine release; expired
permits can receive original GET truth without reopening a mutation.
The real phase reader supplies a complete authority header. It cannot be cast
into a fabricated zero-member useful-worker pool. With no independent network
and warmup evidence this composition grants no admission/readiness substitute.
The five mTLS capability groups remain separate: provider mutation, provider
read, Kubernetes writer, pool read and phase read. Kubernetes phase client
`Profile` and `BindingName` both name the exact protected phase binding; this is
an identity key rather than a workload-capacity claim.

GitHub CI exercises immutable archive/pending/Close behavior on PostgreSQL 16/17,
actual local-to-runner mTLS role isolation and real factory-handle composition
using the existing published System CLI artifact. These are Source tests, not
provider provisioning, production adoption, network qualification or load proof.
See ADR0139.


The paired HCloud runtime keeps factory preparation before CREATE independent of
physical witness creation. Its market location (`hel1`) remains distinct from
the canonical System network region (`eu-central`), and the System account stays
empty. A real factory handle bound to the immutable published System executable
qualifies pure deterministic preparation and transferred ownership only. Missing
HCloud reader project/anchor scope is refused at construction. Actual provider
acceptance still requires committed original bytes, immutable launch and the
complete independent typed witness; preparation cannot supply that proof.

CI adds exact closed-provider/profile refusal cases, real PostgreSQL original
custody and sealed-witness reobservation, plus a third mandatory factory artifact
root. Both existing factory roots and their watchdog/no-skip/race verdict stay
unchanged. No controller, network writer, readiness/admission callback, process
activation or provider resource is installed by this Source.
