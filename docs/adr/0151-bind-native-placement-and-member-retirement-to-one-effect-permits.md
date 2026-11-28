# ADR-0151: Bind Native placement and member retirement to one-effect permits

**Status:** Proposed

**Date:** 2026-11-28

**Scope:** Core private placement arbiter and Native member retirement

## Context

Workload authority already binds actual Pod/ReplicaSet/Deployment lifetimes and
protects startup readiness and termination. It does not authorize Kubernetes
Binding or serialize its original in-flight effects with Native admission and
retirement. Cordon alone does not stop direct placement, DaemonSets or independent
allocators. Pre-admission Abort v1 deliberately refuses admitted members.

## Decision

Use the upstream kube-scheduler with a dedicated Native profile/instance and a
non-ignorable authenticated Bind extender. Preserve scheduling filters; do not
write a scheduling engine. Permanent Native reservation taint and static
fail-closed admission separate Native placement from the default scheduler.
The existing workload authority remains the application lineage/process guard.

Core owns per-subject append-only permits under the same Attempt arbiter as
admission, release and probe creation. Each permit exposes at most one native
effect, retains the original privately before classification, and never reopens
by timeout or UNKNOWN. A Bind parent is its authenticated stock-scheduler request,
current policy/Source/epoch/registry, admitted member and real PodUID/contract
facts; it never borrows or renews the completed grow command. Its original
per-effect expiry is the minimum of thirty seconds and every authorizing fact.
Recovery uses the existing protected recovery workflow identity, whose active
status is checked independently; no fictional workflow expiry is claimed. Each
new distinct effect has a new immutable permit; exposed or UNKNOWN rights block
all successors for that same subject. Bind uniqueness covers a PodUID across all
Nodes, Attempts, pools and epochs within its realm.

Member and Pod placement capabilities remain closed
resource contracts; SDK inputs contain only binding and permit selectors. The
opt-in `capacity.recover` workflow input contains only the active logical policy
selector and uses the exact protected recovery workflow. Stock Bind uses the
official PascalCase `PodName`, `PodNamespace`, `PodUID`, `Node` body and `Error`
response; a distinct TLS role supplies its identity, without SDK headers/bearer.

A separate read-only allocator-fence context precedes paid creation and contains
no invented birth, physical resource or Node. VAP parameters are Source literals:
Kubernetes collects dynamic params before CEL selection, so a global paramRef
with NotFoundDeny could deny floor operations during cache misses. Use a static
Source guard and an immutable ConfigMap audit mirror. Independently read/pin its
actual UID/RV/body together with VAP/Binding identities/spec and retained canary
Source-scope evidence; no cache claim or mutable admitted phase bit is accepted.

Guard installation and legacy
quiescence have their own journal. After birth, independent Node/configz facts
and a separate Guest configured-process readback are joined without changing the
existing NetworkWitness ABI. Configz originals and hashes remain private; safe
projections carry an opaque custody reference only. Core issues ReadID before
the fixed configz GET; reader receive-read grants custody only, never write
authority. It preserves the original Read+Close timestamp. Guest actual k3s
process argv/proctitle is distinct from configured kubelet args. Only
flags_disabled_v1 is permitted; effective static values require authenticated
configz. The reserved taint is permanent; release removes only unadmitted. New Native
workload Pod and Deployment names use `nw-`; existing probe names retain `nwp-`.
A protected PriorityClass `dakasa-native-placement-workloads`, value zero,
non-default, preemption Never is required; merely putting Never in a Pod is
not a substitute for the admitted PriorityClass.
After proved physical absence, Node/registry cleanup consumes sealed bootstrap
facts and fresh independent absence without GET to the dead guest or time remint.

Never-admitted cleanup fences growth/admission/release, drains only eligible
PodUIDs, then reuses Abort v1 after complete zero-Pod observation. The roster
contains ALL Node-bound Pods, including terminal, deleting and DaemonSet Pods;
its total length cannot be replaced by the old nonterminal count. Unowned probe
resources use their existing private cleanup ports, not an invented workload
contract based on labels. A preparing seed only selects protected reads; after
real facts, a NEW UUID/context is created instead of modifying a read context. The private `read_preflight` plan selects
only read-only admission facts, even though its compatibility selector names
cordon. SQL forbids token, dispatch, original mutation, or promotion to issued;
completed read snapshots close no_effect/cancelled and confer no cordon right.

Provider
absence precedes exact Node deletion and registry retirement; canonical destroyed
is emitted only with composed closure. Provider and network RPC dispatch
barriers commit before calling the original writers and are never replayed.
Provider originals must be complete and privately bound; independent absence
does not repair failed original custody. The existing Abort settled predicate
is unchanged. In the Members opt-in only, its final Attempt/IPAM transition is
deferred to the same transaction as the member plan and canonical destroyed
event. Original admission history is immutable.
Admitted provider retirement remains disabled until real useful-capacity,
workload drain and provider counterparts are installed and qualified.

Shutdown seals authority atomically before finite local joins. Cancellation of
a local SDK request is not proof that the remote private original tail has
returned. A separate finite database-only custody check retains receiving, keys
and lower dependencies on missing, partial or uncertain originals or read failure.
Late original receiving remains allowed after sealing; no history or lifetime is
removed to release the dependency barrier. Cleanup inventory ReadIDs are durable
without claiming a configz original that was never requested.

The installed lifecycle-only HCCM needs a Native Node mutation admission fence,
not a fork. Its actual GET cloud hooks are not compute allocation or destruction.
Scope/image/controller drift must be observed and refused before authority.

The installer proof/read counterpart is an explicit dependency. A protected
Authority declaration, Source marker or literal canary alone does not qualify
its coverage or current API-server enforcement. Its missing runtime port returns
incomplete/HOLD. This Source does not install a Node-less cleanup path, admitted
retirement or profile handoff; missing identity or counterpart remains HOLD.

## Consequences

- Existing growth, Abort, probe and NetworkWitness wires remain unchanged.
- Kubernetes/cloud mutations and read-only evidence custody have separate roles.
- Pending Bind/probe effects block retirement; TTL does not settle exposure.
- Static sources are disabled through qualified effective flags/configz, not a
  witness inferred from a pre-CLI file or a mirror Pod.
- Validation is CI-only, including PG16/17 races, real TLS and scoped Kubernetes
  effects. Missing counterparts or facts keep the optional composition disabled.
- No installation, paid resource or production activation follows from Source.
