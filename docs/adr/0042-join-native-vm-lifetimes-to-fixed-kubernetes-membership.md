# ADR-0042: Join native VM lifetimes to fixed Kubernetes membership

- **Status:** Proposed
- **Date:** 2026-10-10
- **Deciders:** Giomaster
- **Scope:** yggdrasil-core / protected native VM-to-Node observation
- **Supersedes:** —
- **Superseded by:** —

## Context

A provider create/action receipt and a registered immutable VM slot do not show
that the VM joined the intended Kubernetes realm. Generic Node lists omit the
complete, fixed ownership and lifetime checks needed for that join. Node Ready
and a Lease heartbeat also do not show completed bootstrap, warmed resources or
useful business capacity.

## Decision

Add opt-in `vm_node_membership_binding` to a capacity policy and the protected,
GET-only `capacity.observe_vm_node_membership` operation. The workflow input can
select only the exact policy namespace/name and existing mutation binding name.
The policy fixes both adapter/type checksums and the Node observer target:
realm namespace UID, owner, profile, provider-ID prefix, ordered slot/Node names
and maximum Lease age. Both immutable active catalogs are checked before private
credential hydration and live adapter requests.

Use registered native VM identity/configuration and original settled/confirmed
creation action history where it exists. A physical baseline without a creation
grant may be linked, but `creation_action_history_known` remains false. Read VM
inventory and Node membership twice, preserving the original VM ID/creation/spec
and Node UID/creation/providerID/boot/Ready transition/Lease owner across the join.
The fixed Kubernetes observer performs a complete unfiltered Node census,
original realm readback and fresh Node-owned Lease checks. It rejects ambiguous
JSON identities, partial/null lists, replacements, stale/expired Leases and
foreign scope; it verifies the actual response origin before reading a body.

Keep the original Core 90-second operation and 65-second SDK bounds. Kubernetes
has a 60-second total owner, five seconds per original HTTP read, at most 64
approved slots/native Nodes, two MiB per body and four MiB projected receipt.
Actual Read and Close must return; private read/Close/context causes remain
unwrap-able behind an opaque refusal. Context errors and absolute deadlines are
checked after return/decode and before acceptance. A new request never refreshes
the original total deadline. Node objects remain open to native extension fields;
label/annotation keys retain Kubernetes case-sensitive semantics.

Return `native_join_observed` diagnostics, never `CapacityTransitionProof`.
Atomic snapshot, bootstrap completion, warm resources, useful capacity, routing
withdrawal, business drain and physical release stay explicitly unknown/false.
An opt-in policy cannot use scalar caller health/inflight to advance prepared,
canary, drained or promoted phases. Existing unbound policies retain their
contract. This observer creates no intent, grant, provider mutation, route or
retirement write and never retries an uncertain mutation.

## Consequences

The source adds a membership prerequisite, not a full elasticity lifecycle.
Domain-owned bootstrap completion, warmup, useful canary, route admission/drain,
business inflight, original SDK/process retirement and provider quiescence still
need their own fixed native sources and reviewed reconciliation. Configuration,
installed catalogs, workflow authorization, images, real ephemeral/provider
readbacks and billable settlement remain separate operator/evidence holds.

CI-only verified-TLS fixtures exercise real transport return/Close and opaque
causes with synthetic Kubernetes identities. The PostgreSQL dispatcher corpus
exercises the actual durable slot ledger with synthetic VM/Node projections;
it is not native cloud bootstrap or production Node/Lease evidence. Existing
native provider, PostgreSQL, Kind, protocol and quality gates remain mandatory.
No local test, provider activation or production capacity qualification follows
from this Proposed source decision.

## Related

- [ADR-0037](0037-produce-native-vm-proofs-through-fixed-protected-observers.md)
- [ADR-0040](0040-separate-native-process-lifetimes-from-reservation-decisions.md)
- [ADR-0041](0041-reobserve-installed-birth-guards-before-native-hpa-authority.md)
