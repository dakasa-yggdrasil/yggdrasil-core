# Native VM observations

Four `yggdrasil` workflow operations connect the closed `capacity_vm_slot_v1`
protocol to durable membership and mutation confirmation. All require the exact
active authenticated workflow named by a `capacity_policy`. Execution remains
disabled by default. Read operations work without enabling provider mutations;
record/confirm reuse the existing private invocation and lease authority.

| Operation | Input additions | Effect |
|---|---|---|
| `capacity.observe_vm_inventory` | optional `parent_grant_id` + `slot` pair | Fresh complete profile inventory and physical membership proofs; no ledger write |
| `capacity.observe_failed_vm_creation` | `parent_grant_id` + `slot` | Exact settled failed parent, partial owned lifetime and complete failed action history; no grant or cleanup |
| `capacity.record_vm_inventory` | generation, fencing_token, lease_owner; optional failed-parent pair | Register/refresh only verified physical members through existing guarded store; compare native and registered tuples |
| `capacity.confirm_native_mutation` | grant_id, generation, fencing_token, lease_owner | Internally read exact native target/action/auxiliary facts, then confirm an ordinary settled grant once |

Every input also contains `policy: {namespace,name}` and `binding_name`. Only
record/confirm may select an explicit historical policy version, subject to the
existing recovery lease restrictions. No operation accepts an assessment,
provider selector, URL, capability override, caller proof or readiness/drain
boolean. Unknown fields are refused.

The binding fixes instance/type manifest-version UUIDs and checksums, profile,
scope and canonical approved slot projections. A new manifest UUID is a new
scope, never automatic adoption. Core first checks active identities, then uses
the normal instance resolver, secret hydration, runtime health and live Describe
handshake. The chosen `observe_*` action must exist in the actual ActionCatalog
as a dispatched capability and in the relevant ResourceTypes default actions.
Top-level transport capabilities remain the normal `describe`/`execute` contract.

The response decoder rejects unknown schema fields and bodies over 2 MiB. Source
times must be canonical and fresh under policy, with a bounded inventory window.
Every configured slot occurs exactly once as an existing member or missing slot.
Existing native states include powered-off and initializing machines: neither
`native_members` nor `registered` means ready business capacity. The receipt
always states `useful_capacity_known: false` and never supplies a capacity
assessment, provider fencing or atomic snapshot claim.

An optional failed parent is read from the exact policy realm/workflow/binding,
not supplied as a caller receipt. Original transport tuples and actions remain
immutable. Stored native readback pins any discovered lifetime. The actual
adapter verifies creation-failure attribution and complete lifetime history;
Core independently matches the tuple, original grant label, approved projection,
known actions and closed partial-identity discriminator. A failed member stays
in inventory as `unresolved: true`, with `physical_spec_verified: false` and
`compensation_identity_verified: true`. It is never registered as serving/native
physical membership and its reservation is not freed.

Record uses one existing guarded transaction per slot. A later refusal can leave
earlier factual records committed; retry refreshes the same immutable tuples.
The final independent DB comparison rejects stale extra membership or missing
registration. It does not delete missing members, infer provider quiescence or
claim an atomic provider/SQL transaction. Empty record and confirmed replay still
validate the current invocation's lease. Observation does not expose a lease,
executor identity or settlement nonce/hash.

Ordinary confirmation requires a settled owning transport, exact native target,
original create-grant label for ensure, terminal successful owning action IDs and
fresh auxiliary absence for destroy. Lost create action IDs can use complete
bound live native history. Unknown delete action IDs after native absence remain
pending. For absent destroy, `spec_verified` refers to the approved historical
tuple and closed slot projection, not a current physical server. An already
confirmed readback does not rewrite its original proof or re-emit an applied
event. Compensation children remain on the separate existing authority path.

The PostgreSQL CI gate compiles a read fixture inside an exact private reviewed
adapter checkout, invokes its actual Execute/native decoder/private receipt
validation against simulated APIs and runs the protected Core operations with
production migrations. Every required case must pass without skips. This is
integration evidence; live provider bootstrap, useful capacity, warm/readiness,
canary, drain, floor qualification and cost certification remain separate gates.

See [ADR-0037](../adr/0037-produce-native-vm-proofs-through-fixed-protected-observers.md)
and [mutation authority](capacity-mutations.md).
