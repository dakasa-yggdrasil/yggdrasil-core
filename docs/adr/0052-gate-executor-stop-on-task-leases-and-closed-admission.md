# ADR-0052: Gate executor stop on task leases and closed admission

- **Status:** Proposed
- **Date:** 2026-10-16
- **Deciders:** Giovanni Martins
- **Scope:** yggdrasil-core / opt-in remote laboratory executor power lifecycle
- **Supersedes:** None
- **Superseded by:** None

## Context

An AI can disconnect while its build continues. A new task can race an idle stop,
and EC2 does not offer the Core's native fencing semantics. Storing all control on
the stopped executor also makes wake impossible. Existing capacity floors protect
running services and must not be weakened to implement a disposable laboratory.

## Decision

Represent per-run activity as bounded, owner-scoped, expiring leases in an external
durable CAS ledger. Treat them as demand to the existing protected workflow, never
provider authority. Require independently complete zero-job inventory and sustained
quiet, then close admission at a monotonic epoch before recording one possible
stop send. New demand cancels an unsent reservation; after possible send it queues
until original mutation settlement. Preserve ambiguous tickets through restart.

Carry the existing authenticated HTTP machine principal in a private execution
context, never task inputs. Retain jobs independently of agent leases. Run one
bounded reconcile pass through protected transactions; pin its operator policy
and exact resource identity. Keep source-owned worker/provider ports without installed production factories
until the SDK evidence and mutation bridges are qualified. Do not introduce a
second credential/grant system.

For this laboratory, accept explicit authenticated operator adoption of an external
EC2 as a distinct ownership origin (option A), independent of original Guest
creation. Store the immutable adoption in `capacity_resource_slots` and distinct
`ec2_power_v1` grants in `capacity_mutation_grants`. Pin account, region, EC2 ID,
retained sorted EBS IDs and an immutable adoption UUID. Do not use a policy tag,
workflow boolean or EC2 LaunchTime as original ownership. Operator adoption uses
a separate exact protected workflow and allowlisted authenticated collaborator;
controller issuance uses a distinct private machine actor. Provider identity must
come from the fixed independently qualified observer, never workflow input.

Separate `ensure_ec2_instance_running` and `ensure_ec2_instance_stopped` from the
legacy VM ensure/destroy pair. Both must be declared by the exact checksum-pinned
AWS integration type. Bind one grant to one persisted command/epoch and original
deadline. The existing adapter machine inventory controls redemption and original
settlement; no credential is generated or configured. Persist `redeemed` before
returning `execute_once`. Even the same attempt receives only read access on a
retry. Loss of a claim reply, provider result or commit acknowledgement preserves
uncertainty and blocks another invocation. Accept independent readback only after
an authenticated original service acknowledgement has returned; readback alone
cannot clear unknown send custody. Start additionally requires the matching ready
worker boot. A provably unredeemed rejection may reconcile as no effect.

Legacy VM consumers reject explicit foreign authority records, and legacy expiry
and capacity accounting exclude power records. Retained adoption records do not
become capacity units or Guest creation receipts. Database indexes prevent
parallel grants/adoptions and conservative overlap with legacy EC2 instance IDs;
existing ambiguous duplicate IDs must fail migration for operator review.

Use PostgreSQL row locks/CAS under the existing dimension advisory lock and the
current protected policy/workflow authorization. Keep provider execution inactive
until persistence is qualified remotely, authenticated agent ingress, the shared
worker admission/authority boundary and original EC2 result recovery are ready.
Do not introduce another autoscaler, change the protected floor,
terminate cache volumes, or make a budget/availability claim from heartbeat alone.

## Consequences

The reducer, PostgreSQL store and protected workflow integration can be reviewed
with fakes/SQL mocks without provisioning or applying a migration.
Storage outage, unknown jobs, unresolved send and exhausted replay ledger hold
automatic shutdown/admission. Persistent EBS and the independent controller cost
money even when the executor is stopped. Activation and security changes need
separate explicit authorization; this ADR does not grant them.

## Related

- ADR-0046: bounded capacity intents under protected workflows.
- ADR-0049: preserve original mutation uncertainty and recovery authority.
- [Executor activity implementation boundary](../features/executor-activity-leases.md).
