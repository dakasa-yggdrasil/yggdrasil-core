# Executor activity leases: PostgreSQL and protected workflow integration, disabled

This change adds an opt-in component in `internal/capacity/executoractivity`, a
PostgreSQL store and five operations in the existing protected capacity handler.
It adds protected power callback subroutes to the existing mutation ingress,
but starts no loop, issues no AWS request and activates no manifest. It is **not a working automatic AWS laboratory yet**. The migrations
are prepared but NOT applied. The existing authenticated workflow ingress now
carries machine identity privately; real worker and power authority bridges and
external scheduling still remain prerequisites. Tests use fakes/sqlmock;
no live database is contacted.

## Ownership and existing paths

Keep `CapacityDispatchService.RunPass`, its durable dispatch jobs, exact operator
workflow binding and mutation authority as the control path. Do not add a cron
script that directly calls EC2. `capacity_dispatch_demand.go` currently admits
fresh events from a pinned scheduled sensor workflow; it is not a generic task
heartbeat endpoint. Task events must first be authenticated and durably recorded,
then feed the existing protected dispatch path without turning event bodies into
principals or mutation permission.

`CapacityStore.ExecutorActivity` now reuses the exact dimension advisory-lock key
and active policy/workflow row locks, and reads PostgreSQL `clock_timestamp()`.
Both process execution and policy execution gates, a nonnil workflow ID, private
invocation identity and the optional `executor_activity_binding` are mandatory.
The workflow handler retains its existing current-revision and authorization
checks. HTTP transports the authenticated hashed machine principal through a
private context key after existing route/workflow authorization, including the
durable async path. Owner is `machine:<principal ID>`; inputs/metadata cannot set
it. Legacy, anonymous and collaborator dispatch do not become an AI machine owner.
No new authentication endpoint, token, grant or credential inventory is added.

| Operation | Effect, within existing protected handler |
|---|---|
| `capacity.initialize_executor_activity` | Explicitly initialize once; repeated initialization cannot erase existing state |
| `capacity.record_executor_activity` | Acquire/heartbeat/release a run; owner is authenticated-ingress-authored |
| `capacity.observe_executor_activity` | Record independent complete/unknown job inventory and quiet hysteresis |
| `capacity.reserve_executor_stop` | Persist an admission-drain reservation only |
| `capacity.prepare_executor_stop` | Persist possible-send uncertainty; **does not grant or send EC2 stop** |

Step input retains the existing `policy` selector and adds `executor_activity`.
Example demand body: `{"event":{"task_id":"unique-run-id","sequence":1,"release":false}}`.
Add optional `"job_id":"unique-job-id"` alongside `event` to durably queue one job
owned by that current task. A release cannot enqueue work; another principal cannot
heartbeat the task. Jobs survive task/session expiry and finish only through the
trusted worker inventory, never a caller-supplied AI release.
Unknown input members remain rejected by the existing closed workflow decoder.
Optional binding mode is `executor_activity_v1`, with fields `lease_ttl_seconds`,
`idle_after_seconds`, `max_observation_age_seconds` and `max_tasks`. Unknown, null,
case-aliased or duplicate binding members are rejected. No binding means legacy
behavior; the existing protected floor still applies.

`CapacityPolicySpec.Floor` currently requires at least one. Do not set it to zero,
weaken `Assess`, or classify a stopped executor as deleted capacity. Stopping an
opt-in laboratory executor is a separate power lifecycle under the same protected
workflow authority. Production capacity, admission, retirement and Guest gates
keep their current meaning. A Guest retirement receipt does not authorize EC2 stop.

The existing AWS adapter has `start_ec2_instance` and `stop_ec2_instance`, with
`instance_id`, `region`, and optional wait flags. It does not perform this task
lease check, and its current plain AWS call has no provider-side fencing. Do not
connect the new reducer directly to those commands. The eventual fixed executor
binding must identify account, region, instance, ownership, EBS volumes, approved
instance profile and budget; task events cannot choose those values. Stop must
use `StopInstances`, never terminate/destroy. Preserve EBS and cache deliberately.

Current capacity mutation bindings require canonical `ensure_`/`destroy_`
capabilities; legacy `start_ec2_instance`/`stop_ec2_instance` are not a qualified
power-lifecycle grant contract. Adding an alias alone would not supply fencing,
original-result custody or no-stale-sender recovery. That adapter/Core contract
must be implemented and qualified before wiring any real power call.

## State transitions

1. The external control plane authenticates the task/run request and calls the
   existing protected workflow, which uses the PostgreSQL-backed CAS store. A new ID starts at
   sequence 1. TTL uses trusted server time. Heartbeats increase sequence; retries
   do not renew. Expired/released IDs are tombstones and cannot be resurrected.
2. `ExecutorDemandPending` means demand can wake the existing dispatcher; it is
   **not permission to admit work, start EC2, or claim readiness**. If the fixed
   executor is running and independently ready, reuse it. If stopped, the protected
   workflow must issue the existing start action, observe running/ready, then admit.
   Starting/stopping/unknown states require reconciliation, not another blind call.
3. Independent complete inventory covers queued/dispatched work and every running
   build, test, job and child process. All job admission must use the same epoch
   gate. Agent disconnect/expired heartbeat cannot prove subprocess quiescence.
4. `ObserveExecutorQuiet` requires no active task leases and no jobs. Missing,
   stale, future, negative or incomplete inventory resets quiet hysteresis. A gap
   between quiet observations resets it too; ordinary state writes cannot bridge
   an unobserved interval.
5. After `IdleAfter`, `ReserveExecutorStop` creates a new monotonic admission epoch
   and a `draining` ticket. This only requests closure. The worker must ACK that
   exact epoch and fresh zero-job complete inventory after reservation.
6. Fresh task demand before send cancels the draining ticket by CAS. A stale
   sender loses CAS. The dispatcher must reopen admission at the current epoch
   and verify readiness before admitting pending jobs.
7. `MarkExecutorStopPossibleSend` atomically marks the one possible send only after
   exact-epoch admission closure and zero demand/jobs. The caller may proceed only
   if `UpdateExecutorActivity` successfully committed. It must still redeem the
   existing protected mutation authority. A returned mutated copy is not a grant.
8. Demand after possible-send is retained but cannot open admission. Restart reloads
   the same ticket; timeout, agent disconnect or lease expiry never clears it.
   The bounded controller only settles a command when its protected power port
   joins the original invocation/return, matches command/action/exact resource and
   independently observes the corresponding terminal power state. A proven joined
   no-effect result is retained separately. No actual producer of these protected
   receipts is installed; a boolean from an agent or raw EC2 poll is not a substitute.
   A crash after CAS but before sending may therefore require explicit recovery.
   This conservative HOLD is preferable to stopping a newly restarted busy machine.

Migration `00066_capacity_executor_activity.sql` stores one bounded JSONB state
and revision per canonical dimension key. Binding hashes pin policy ID/checksum
and workflow ID; a different policy/workflow cannot adopt the row. Initialization
uses INSERT ON CONFLICT DO NOTHING, never replacement. Load uses FOR UPDATE;
updates check the expected revision and binding, and a commit error returns no
sendable result even if the commit may have succeeded. Missing or corrupt rows
are errors. The down migration deliberately retains activity/tombstones and
uncertain sends. Automatic cleanup is inappropriate while a send is unresolved.

The real worker admission implementation and provider mutation redemption still
need the same durable serialization boundary. SQL mocks do not prove PostgreSQL
locking semantics or that every job uses that admission gate. Do not place state
on the executor or add an in-memory production fallback. State is bounded to 2MiB;
the row/revision ceiling is 9007199254740990. Large rosters can hit the byte bound
before MaxTasks and fail closed. Composite dimension keys are bounded to 256 bytes.

Only a bounded summary reaches workflow metadata: revision, epoch, active count,
demand pending, stop reservation and recovery status. It does not expose the full
task roster. A ticket older than IdleAfter sets `recovery_required` and an explicit
`recovery_deadline`; that escalation never clears uncertainty or authorizes a send.

## Bounded controller and unresolved bridges

`Controller.Reconcile` is one bounded pass, with no ticker or server registration.
`CapacityStore.ExecutorActivityTransactions` supplies its protected PostgreSQL
transaction path. It can be hosted separately from the executor and ultimately
called by the existing dispatcher; nothing schedules or instantiates it at boot
in this change. Its operator activity policy and exact resource binding are pinned
in the durable ledger. A different controller policy or resource cannot adopt it.

`PowerBinding` defaults off. It requires the exact account, region, instance ID
and an independent ownership binding ID, plus exactly `start` and `stop` actions.
There is no terminate/delete action, tag-derived authority or credential fallback.
PowerPort has a default-off ledger-backed repository implementation, a fake,
and a legacy diagnostic read bridge through the real Core SDK adapter client. The latter returns diagnostic EC2 facts, refuses to manufacture account,
ownership, boot or timestamp evidence, and rejects Execute/Settlement. A write implementation must
redeem the existing Core authority, retain original call custody and verify that
ownership record; the configured string is a declaration, not an attestation.

`WorkerPort` separates complete source-owned inventory, ready/boot identity,
epoch-fenced admission and idempotent job execution. Unknown inventory blocks stop.
Durable queued/admitting/running jobs independently block stop even without an AI.
Cancellation of unsent drain increments epoch; an old close response must lose at
the worker. Restart cannot infer missing jobs finished. The real SDK native-read
bridge uses `observe_capacity_pod_admission`, pins the Pod/container lifetime and
omits metadata/challenge/receipt from its diagnostic projection. It returns unknown
job coverage and refuses Open/Close/Admit. Only the fake provides a complete job
producer today; no public worker RPC or SDK lifetime proof is fabricated.

Consulted Guest/Core original lifecycle and native admission code and the SDK RPC
transport. Those native process/Pod/Guest contracts do not establish a qualified
generic EC2 job inventory bridge. The Arch Elastic source/native gates remain open.
The minimal recommended continuation is a lab job worker inside the planned
isolated kind Pod, adapting the existing source-owned SDK admission/lifetime and
retained job census, and an explicit power-lifecycle variant of the existing Core
mutation ledger plus AWS adapter. Do not build a parallel grant service or relabel
legacy start/stop calls as qualified mutations. This structural bridge must be
reviewed/qualified before implementation is connected to real resources.

The inspected ledger currently accepts `capacity_vm_slot_v1` acquisition /
destruction projections, exact ensure/destroy capability pairs and corresponding
preparing/drained intent phases. Creation additionally needs original Guest scope;
destruction binds immutable resource identity and absence/retirement proof. Power
stop preserves that resource, so those proofs cannot be reused. The existing AWS
start/stop helper uses `context.Background()` and an optional 180s waiter, not the
Core original mutation custody protocol. Typed `ErrPowerLifecycleUnqualified`
explicitly refuses those legacy capabilities in the VM ledger without changing
accepted VM projections. Write support requires an explicit power-state contract
inside that ledger/adapter, not an alias or a second grant service.

## Proposed configuration, not installed environment variables

| Field | Pilot proposal | Enforced bounds |
|---|---|---|
| LeaseTTL | 90 seconds | 5 seconds–5 minutes |
| Agent heartbeat cadence | 20 seconds | Caller responsibility; must remain below TTL |
| IdleAfter | 10 minutes | 1 second–24 hours |
| MaxObservationAge | 30 seconds | 1 second–LeaseTTL |
| Inventory cadence | 10 seconds | Caller responsibility; no gaps above MaxObservationAge |
| MaxTasks | 10,000 IDs per initialized scope | 1–100,000 including tombstones |

Tombstones are not silently removed. Reaching MaxTasks refuses new acquisition;
production needs bounded archival/epoch rotation with replay protection before
long-lived use. Configuration changes and identity binding must be operator owned.
The clock is trusted control-plane time; rollback refuses state changes until
reconciled. Leases and active jobs are separate: build activity may outlive an AI.

## Cost and independent wake controller

The controller, PostgreSQL and AWS adapter must run **outside** the executor being
stopped, on an independently available approved host. An instance cannot receive
its own wake request while stopped. Existing Brain/validation machines were found,
but neither is approved as this lab's controller or available spare capacity.
No new IAM permission, secret, public endpoint, firewall or pairing is configured.
The desktop SSH connection does not demonstrate that this assistant can work with
the Mac off; that control/assistant enrollment remains unproven.

Reference us-east-1 Linux On-Demand rates checked separately: C7i.2xlarge 8/16GiB
US$0.357/h, M7i.2xlarge 8/32GiB US$0.4032/h, public IPv4 US$0.005/h,
160GB baseline gp3 US$12.80/month even while stopped. 80 running hours with that
disk retained are approximately US$41.76 or US$45.46 respectively, before tax,
traffic and optional services. Both exact types advertised nested virtualization;
KVM still needs explicit enablement and Linux `/dev/kvm` qualification. No purchase
or performance assertion follows from the quote.

Idle shutdown is not a budget cap: active/unknown jobs can correctly prevent it.
Before activation require an approved monthly limit, running-hour accounting and
an alert/admission policy for budget exhaustion; do not forcibly kill builds to
meet an inferred budget. No budget enforcement is claimed by this source slice.

Unknown inventory must trigger bounded retries and escalation in the independent
controller, not perpetual silent polling. Before activation, install an external
cost alarm and a controller alarm for missing inventory/expired recovery deadline.
An operator-approved recovery runbook must first close admission, inspect the
original send and independently census surviving jobs; then either cancel a
proven-unsent reservation or settle the original stop with no stale sender left.
Fresh demand queued during possible-send must wait for that settlement, followed
by a separately authorized start/readiness observation. No timeout by itself may
clear the ticket or force poweroff. Until that controller and recovery mechanism
are implemented and qualified, automatic provider actions must remain disabled.

## Verification and remaining work

The focused tests use fake durable CAS, sqlmock and fixed time. They cover SQL
transaction boundaries, current workflow authorization, commit uncertainty,
lease retry/release/expiry, multiple tasks, disconnected AI with
live build, inventory uncertainty, idle gaps, rollback, cancellation before send,
CAS races, restart after possible-send and bounded tombstones. They are not the
whole Core, PostgreSQL, live AWS, kind, QEMU/KVM or Mac-off qualification.

On macOS, the complete `controllers/message` test package has pre-existing native
fixtures using Linux-only `syscall.Openat`/`Renameat`. The focused handler test may
select the package's normal macOS production GoFiles plus only
`workflows_capacity_executor_activity_test.go`; it then exercises the real handler,
manifest resolution and repository transaction against sqlmock. This is a bounded
ordinary-path check, not a pass of the complete native/Linux test gate. Do not edit
those native fixtures or weaken their gate to manufacture a macOS suite pass.

`TestExecutorRealPostgresConcurrentIngressAndRestart` is a prepared Linux-only
fixture, not executed locally. It requires `EXECUTOR_ACTIVITY_LINUX_PG_TEST=isolated`
and `EXECUTOR_ACTIVITY_TEST_DB_URL` naming a separately prepared loopback database
`executor_lab_*`, with no URI host overrides. It never falls back to DB_URL and
applies no migration. After separate approval/application to that isolated database,
it checks real serialized ingress and durability across a new connection pool.
A default SKIP is not PostgreSQL evidence.

Next implementation must qualify the migration/locks remotely and full HTTP route
compilation in Linux/CI, approve the concrete source-owned worker/power bridges,
connect this bounded pass to the existing independent dispatcher, and
qualify wake/stop/recovery with fake provider then remote integration tests. Preserve
the existing Arch Elastic pending source/native gates throughout; do not adopt its
paused WIPs or mark sectors complete from these unit tests.


## Explicit operator adoption and power ledger (option A)

`executor_power_binding` is absent by default and uses a closed canonical schema.
It requires the activity binding, a distinct adoption workflow, fixed operator
collaborator IDs, separate controller and adapter principals, exact integration
instance/type IDs and checksums, exact AWS account/region/EC2 instance and sorted
retained EBS IDs. A policy cannot combine this mode with VM mutation bindings.
Process flags `YGGDRASIL_CAPACITY_EXECUTION_ENABLED` and
`YGGDRASIL_EXECUTOR_POWER_ENABLED`, policy execution and binding enablement must
all explicitly permit new authority. This patch changes none of their values.

The protected workflow supports `capacity.adopt_executor_power` (no provider facts
or operator ID in its input), `capacity.grant_executor_power` (persisted command
ID only), and `capacity.confirm_executor_power` (grant ID only). Existing HTTP
human/machine authentication populates separate private context keys. Adoption
requires the exact separate authenticated workflow and allowlisted human. Grant
issuance requires the fixed machine principal, current controller workflow and
current durable command/admission epoch. All current policy/type/workflow pins are
rechecked under existing scope locks. A global physical-resource lock and database
indexes prevent cross-policy duplicate adoption and unresolved power overlap.

The immutable adoption uses the existing resource-slot ledger, with a distinct
JSON `authority_kind=ec2_operator_adoption_v1`. It is an operator origin, never a
Guest provisioning or retirement receipt. EC2's account/region/instance identity
plus the Core adoption UUID identify this origin; LaunchTime is deliberately not
used because it is not an immutable creation receipt across lifecycle changes.
Any disk mismatch, duplicate adoption or attempted replacement fails closed.
An unresolved legacy VM claim for this instance also blocks adoption. A redeemed
creation whose native identity is still unknown conservatively blocks adoption
until its original outcome is resolved, even across policy/integration boundaries.
Legacy compensation and late destructive redemption independently reject adopted
EC2 identity; the instance advisory lock serializes the latter with adoption.
The migration conservatively rejects overlapping legacy EC2 IDs, even when legacy
records lack account/region. It applies no data cleanup or silent adoption.

Power grants use the existing mutation ledger with `authority_kind=ec2_power_v1`,
one command ever per grant and one unresolved grant per adoption. Start and stop
have distinct actions and exact declared catalog capabilities
`ensure_ec2_instance_running` / `ensure_ec2_instance_stopped`. They cannot grant
creation, destruction or termination. Legacy decoders reject the new kinds;
legacy bulk expiry and VM capacity counts exclude them. The capacity floor stays
unchanged, and stopping an adopted executor does not reduce a VM capacity unit.

New TLS callback subroutes `/api/v1/capacity/mutations/power/redeem` and `/power/settle`
reuse the existing hashed adapter inventory, expiry, exact instance and capability
allowlist. No new auth inventory or credential is introduced. Redemption commits
possible-send custody before `execute_once`; all later claims, including the same
attempt, are read-only. Changed demand/epoch, revoked pins or expiry before claim
prevent sending. Redeemed or uncertain commands do not expire into another send.
Original settlement binds adapter, attempt, request hash and original settlement
token. Late original settlement remains available when execution is switched off.
An accepted AWS service acknowledgement and original return must precede fresh
exact-resource/disk readback; a ready matching worker boot is also required for
start. A readback alone never resolves an unknown request.

`ExecutorPowerPort` links the existing controller to these ledger methods through
a fixed `ExecutorPowerDispatch`; `executorpower.Adapter` exercises a context-bound
single-invocation EC2 interface with mocks. Neither is constructed at boot. This
is **not an implemented/qualified native AWS SDK transport**: integration-aws has
not been changed, the new capabilities are not published, and its legacy
Background-context helpers are never called by this path. A source-owned SDK shim
must disable SDK mutation retries, independently bind STS account/region and exact
instance/EBS observation, retain AWS request/return custody, and use the protected
callbacks. Observation must compose provider identity with qualified worker boot
readiness; existing EC2 diagnostics cannot supply those facts. The source-owned
worker must additionally prove complete child/job census and admission closure.
No workflow body or fabricated receipt can replace these producers.

Accordingly, the workflow handler installs **no observer or dispatch factory**;
adoption/confirmation fail closed and the controller cannot become operational
through a manifest flag alone. Real PostgreSQL concurrency/index qualification,
full Linux HTTP/native checks, the AWS SDK and worker producers and external
controller wiring remain mandatory before any separate activation approval.
