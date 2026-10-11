# Fixed native HPA reservation and lifetime execution

`capacity.execute_bound` and `capacity.admit_bound` accept only the logical policy
namespace/name through their distinct exact active protected workflows. Sources,
adapter revisions, capabilities, requests, current native identities, generations
and one-use permissions are constructed privately. No caller supplies a Pod,
receipt, pressure sample, readiness flag, lease, key or provider URL.

The new `native_hpa_lifetime_v2` binding requires an exact adapter principal,
Deployment owner identity, immutable image, complete local lane roster, projection
path and `process_v2` admission with one fixed Pod proxy port. Native pressure
execution defaults off. Candidate bootstrap has its own default-off
`YGGDRASIL_CAPACITY_ADMISSION_ENABLED` gate and distinct `admission_workflow`.
The pressure gate remains `YGGDRASIL_CAPACITY_EXECUTION_ENABLED`; bootstrap cannot
issue an HPA envelope or Pod DELETE. An enabled policy is still required.

Bootstrap observes the complete bounded native candidate LIST and explicitly
unqualified old baseline lifetimes. It can acknowledge one actual schema-two candidate
while schema-one baseline remains frozen and unqualified. The producer supplies its
own current process nonce, exact dynamic projection acknowledgement and source
startup acknowledgement. This does not require every old Pod or every function
to expose schema two before a new candidate can start. It creates no useful or
warm stock receipt. Never invent a schema two nonce for an existing schema-one process.

A controlled rollout must preserve the old protected baseline until its separate
qualified schema one lifetime evidence or controlled migration resolves it.
Old image or incompatible retained origins refuse full pressure execution.
Bootstrap success is not migration completion, and admission metadata never
certifies complete baseline qualification. Source, native scheduling and all22
production-shaped adopter qualification remain separate gates.

PostgreSQL serializes the logical dimension and native UID ownership. An actual
Pod/container/start/restart/process lifetime has one immutable origin independent
of reservation generations. The ledger retains the original policy and binding,
original challenge bytes and digest, full current projection/startup readbacks,
current native successful termination witness and durable acknowledgement.
Original challenge bytes are separate from its semantic JSON object because
PostgreSQL JSONB may reformat that object. A changed process or same-name
replacement never inherits an origin or revives an archived UID.

Every current baseline lifetime must be protected and actually admitted before
an HPA reservation CAS. The native Deployment/HPA controller chooses retirement
victims. The fixed executor issues no Pod DELETE, so a second selected deletion
cannot retire an additional baseline Pod. New Pod birth protection/readiness
preserves concurrent candidates; unknown or missing origins refuse a reduction.
Alive protection is an outstanding lifetime obligation, never a completed join.

One-use commands bind current private invocation lease/fence, exact active
policy/workflow/adapter revision and complete canonical request. A permission can
be revoked only under the same dimension/row locks as redemption, with no attempt
or actor. Each phase has at most four such permissions. A redeemed or uncertain
outcome permits native GET reconciliation only. Global unresolved sends fence
new native writes across generations. No WAN call runs under row locks.

The reservation phase `envelope_applied` confirms only native min/max reservation
bounds and tracking. It leaves live lifetimes in the independent ledger. Hold
invocations still reconcile actual controller retirements. Current native
Terminated exit zero, complete canonical successful lane receipt, exact origin,
nonce/image/identity and native timestamp interval must be durably acknowledged
before a separate one-use permission removes only the capacity finalizer.
Previous termination, timeout, cancellation, Close and missing metrics are not
completion. Native second precision is used only for the exact represented
second; precise native timestamps retain exact comparisons.

The hot ledger bounds active lifetimes to64, retained rows to512 and commands to
8192. Storage compaction has no age or TTL completion predicate. Only complete
terminal bundles with a durable full native witness and confirmed one-use release
move to an immutable archive. Full records, digests and permanent UID/command/
authority-token identity fences remain. Historical completed HPA commands require
an `envelope_applied` event and retain their reservation receipt separately.
Unknown, alive, pending and partial records stay hot. Normal repeated rollouts do
not permanently exhaust the hot quota by accumulating resolved records.

Reserved minimum, actual replicas, warm resources, useful capacity, domain durable
uncertainty, provider mutations and fleet/platform quiescence remain distinct.
Source and ledger tests do not certify native controller scheduling; the actual
SDK/Kubernetes/Core combined KinD adversary and each service's actual startup
joins are mandatory qualification. This change introduces no deployment, purchase,
production activation or VM floor mutation.

A released exact native UID can remain in LIST while an independently owned finalizer retains its already witnessed current termination. The executor re-reads the strict native removal target before excluding that UID from live root admission; Running, restarted or reprotected lifetimes never revive a released origin. While the released UID remains listed, only an unchanged HOLD can complete. New reservation and admission mutations remain refused. The native KinD controller adversary retains a foreign finalizer, requires removal of only the capacity finalizer and replays HOLD before the fixture removes its own finalizer. None of these observations establishes released VM capacity or provider quiescence.

If the terminal origin has already moved to immutable archive, a readonly lookup is limited to UIDs returned by the current native LIST. It validates the full bundle/origin digests, successful native witness and confirmed release against its permanent command identity. It never restores the hot lifetime or grants another command. An archived terminal object still needs the same fresh native removal-target check and HOLD-only restriction.

Enabled `native_hpa_lifetime_v2` policies additionally pin `birth_guard_binding` and `birth_guard_sha256` for the current installed guard in the exact adapter instance. Core reads that graph internally at the native reservation boundary; the adapter independently repeats it before one-use redemption and before HPA CAS. Immutable webhook/config/service/Deployment pins, Fail CREATE/UPDATE/DELETE semantics, the selected namespace label, current source image/container and complete backend routing must all match. A LIST census alone is insufficient. These native reads are not atomic with HPA writes, and they do not self-attest runtime configuration, useful stock or provider continuity. Concurrent operator changes after the final read remain a bounded cross-resource gap.

The private `POST /api/v1/capacity/mutations/native/redeem` route takes exactly
`authority_token`, `integration_instance_id`, `integration_type_id`, `capability`
and `request_sha256` under the independent adapter bearer. Its 200 response has
`schema_version: 1`, `command_id`, `attempt_id`, `capability`, `request_sha256`
and `expires_at`; it contains no authority token. Invalid closed bodies return
400, invalid bearer 401, denied exact scope 403, stale/used authority 409 and
unavailable durable storage 503. Native permission replay is refused. Recovery
reads do not reissue a command whose send or provider outcome is uncertain.

The remote native Core gate imports the exact private guard source, installs its
actual admission-plan objects on KinD and reads a binding from current API
objects through the actual Kubernetes adapter. Its ephemeral ServiceAccount is
restricted to the isolated namespace and exact read-only cluster resources.
Guard drift before authority issuance and during native redemption must refuse
HPA reduction. This fixture qualifies the connected source contract; it does not
prove provider continuity, all product functions, or atomic webhook/HPA updates.

Operator object hashes must use the exact adapter revision's typed JSON projection.
A consumer's newer Kubernetes SDK can change encoding without native resource
changes (for example zero template `creationTimestamp`: omitted vs explicit null).
The remote installed-guard fixture compiles a projection producer inside the
pinned adapter source and hashes the actual native Deployment through that same
code. It preserves the digest equality check; this projection helper is CI-only
and grants neither adoption nor write authority.

## Sensor demand on the original private dispatcher

An optional operator `controller_binding.demand_source` selects exactly one
scheduled sensor workflow by ID, namespace, name, version and checksum, using
`core_workflow_completion_v1` and a finite freshness limit within the policy's
existing evidence-age budget. It cannot select itself or a capacity graph. An
absent source keeps the original cron JSON and behavior. No event or caller can
provide a workflow, principal, token, URL, SQL, capacity or health verdict.

The source event must be the original `workflow.run.completed/v1` row whose
`aggregate_id` and **SQL** `idempotency_key` equal the original scheduled run ID.
The current scheduled emitter is the only application path that writes this
combination. Generic HTTP publication does not copy its wire idempotency into
that column, mutation events use a closed different verb grammar, manual
completion has no key, and the AMQP event stream is pull-only. ActorNULL and a
similar payload are insufficient. The reader joins the terminal scheduled run,
original response and exact current source catalog. This is application-source
lineage under trusted Core database ownership, not a signature against a DBA.
The event is emitted best-effort in another transaction after finalization;
absence is unresolved and never fabricated. The independent cron still exists.

The same one-second private worker checks at most64 independently fixed policies
under one original10-second read/admission context. For each dimension it selects
one latest fresh original completion that is absent from permanent existing wake
keys `(realm,environment,domain,dimension,event:<original UUID>)`; at most64
candidates are read, below the100-candidate cap. A global event sequence is never
an exclusion watermark: BIGSERIAL allocation can precede a later COMMIT. A fresh
lower-sequence event that becomes visible late remains eligible. Proven expired
events do not admit work, change health or consume a wake.

The existing cursor table retains an informational fixed row per dimension. That
cursor and the original wake admission commit together; its value can decrease
when a lower-sequence original event commits late. Only permanent wake keys
provide deduplication. Saturation, inactive/source/authorization/SQL uncertainty
hold that dimension and retain its cause opaquely, while other independently
valid dimensions continue. Parent cancellation or the original absolute deadline
stops the owned pass with the original cause, never success. No second timer,
query replay, global table lock or emitter serialization is introduced. The
maximum32 wake journal and original possible-start/unknown retention are literal.
Protected event graphs refuse before the legacy match marker/dispatcher.

Only existing RunOne may start work, using the same loaded principal, current
RBAC/policy/emergency lock, original claim/fence and finite 5–90 second budget.
Source pin/lineage changes refuse. Started, unknown or unacknowledged returns
never replay or release the dimension. Metrics, HPA, actual canary/lifetimes and
drain are independently reread; the source event supplies no measurement.
20 extreme-scale and two internal-baseline functions keep their existing
availability and recovery obligations. This seam grants no provider bootstrap,
routing, stock, useful-capacity, quiescence or physical-release certificate.

Remote CI retains every prior capacity gate and all twelve original demand
obligations. It additionally requires native independent-dimension HOLD recovery,
actual scheduled-emitter N1-uncommitted/N2-committed/N1-late-COMMIT ordering,
and loss of only an original wake+informational-cursor admission Commit reply.
The reply-loss fixture recognizes those two original native SQL statements in
the same driver TX, retains authorization audit Commits and loses one reply only
after the original pq Commit returns nil; GET-only recovery preserves IDs.

The informational cursor ID is the complete lowercase SHA256 of the JSON array
containing protocol version, realm, environment, domain and dimension, so it fits
the original `VARCHAR(64)` without a schema change. The reply-loss fixture checks
that exact fixed ID. The original scheduler persists a logical selector with
`workflow_version=NULL`; the reader instead binds the positive version in its
original stored response to the original metadata `manifest_id`, event payload
and source catalog. A present SQL version must equal that executed version.
Mandatory CI cases traverse the real scheduler, execution, Finalize and separate
emitter transaction before demand admission, and refuse explicit SQL/response/
metadata/payload drift. The scheduler case uses an ordinary assertion to prove
its persistence route; the other demand cases retain the compiled metric source.
Terminal SQL/event readback does not expose a join handle for the old scheduler
goroutine and is not a claim of its actual return or useful capacity.

The five historical reactive tests had not been selected by this gate. They now
require actual CI Rabbit connections and valid ordinary fixture graphs, scoped
namespace cleanup/window/counters that preserve foreign rows, and the same
original pending-run/inputs/dedup assertions. Their callbacks are recording-only;
they prove source dispatch admission, not product/business execution. Additional
ordinary reactive and protected normalized/capability/unbound/tombstoned cases
cover the original generic dispatch guard before its marker. All run on real
PostgreSQL, the selected compiled metric producer, original Core workflow
return/emitter and actual broker. Their finite fixture
data exercises source protocol and transport, not physical production capacity.
No local test or native execution is required or permitted. Installing bindings,
metric evidence queries, principals/RBAC, source images or operator grants is a
separate held runtime action; the retired Heimdall alert dispatcher stays retired.
