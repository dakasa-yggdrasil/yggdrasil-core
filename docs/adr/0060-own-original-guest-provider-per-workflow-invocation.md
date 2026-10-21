# ADR-0060: Own the original Guest provider per workflow invocation

- **Status:** Proposed
- **Date:** 2026-10-21
- **Deciders:** Core maintainers
- **Scope:** Core / protected Guest provisioning
- **Supersedes:** —
- **Superseded by:** —

## Context

The original Guest workflow requires a source-owned provider. A package-global
provider pointer conflates independent workflow lifetimes and cannot bind a
native create call to one executor, selected slot and original deadline. Native
qualification has a separately compiled realm and must retain that distinction.

## Decision

Construct the production provider in the original workflow invocation after the
compiled profile gate, current policy/workflow/lease checks and exact adapter
catalog checks. Carry the existing transport through a private context key. Do
not register providers from manifests, environment values or workflow inputs.

Freeze the selected slot, binding, member, policy and workflow checksums, step,
executor, epoch and provisioning budget. Require the same unextended original
context and preregistration. Consume creation ownership before the one original
supplier call. An error, cancellation or panic never reopens creation; fresh
readback can confirm only an original create whose caller already returned
successfully. Do not create a background retry or detached lifetime.

Keep the production approval registry empty until the complete real production
catalog, application handle ownership and original provider witness protocol
are implemented and independently verified. The production constructor selects
the fixed Hetzner broker catalog or the explicit source-pinned AWS HTTP original
capacity contract. AWS's existing generic name-adopting ensure remains separate;
its legacy catalog cannot activate original provisioning.

Check the repository's separately compiled original-witness provider support
before catalog hydration, reservation or native send. Profile approval cannot
activate a provider whose authentic original return source is still absent.

Pin each adapter's own clean build source in the mutation binding and its
checksummed operator configuration, independently of Guest and Core sources.
The worker checks its actual build identity before network operations.
Only its actual successful native POST/Read/Close produces the closed original
return DTO. Include that DTO in the existing authenticated one-use settlement;
bind its grant, attempt, request, native tuple, actions, body hash and original
times to that same settlement. Preserve the shorter grant/context deadline.

Validate this original inside the authenticated settlement transaction and
retain it immutably in the existing settlement JSON. The repository's Hetzner
witness joins that original with the same preregistration, current authority and
independent native proof. A GET or uncertain create cannot supply a missing
original. Keep native QEMU's existing separate original source path intact.

AWS preserves the deployed adapter's capability names and existing credentials.
Its opt-in configuration freezes account, region, image and image owner, subnet,
security groups, instance profile, bootstrap hash and slot. Actual STS and EC2
reads validate the native realm before grant redemption. The original single
`RunInstances` uses a grant-bound client token, `aws.NopRetryer` and the configured
HTTP transport with all redirects refused. Original HTTP Do, complete Read/EOF,
Close and the actual SDK decoder/metadata return must agree before settlement.
Missing source stamping, name adoption, transport uncertainty or a replay cannot
produce the AWS original DTO.

EC2 exposes an original requestId, instance ID and LaunchTime; it does not expose
a RunInstances job/action observation API. The wire's historical `action_id`
field carries that actual requestId only as original request lineage. The native
proof uses the explicit `AWSInstanceLifecycle` schema and independently fresh
`DescribeInstances` plus `DescribeInstanceStatus` instance/system checks. Its
generic ActionIDs and Actions flags remain empty/false. The repository accepts
this provider-specific creation evidence only with the same authenticated
original DTO, scope and native tuple. It cannot confer application readiness,
cancel a late writer, certify retirement or populate the production registry.

Use the existing AWS pair `ensure_ec2_instance`/`terminate_ec2_instance`; do not
invent a destroy alias. Original capacity start/stop/terminate stay refused in
the adapter until their own source-owned retirement contract exists.

## Consequences

Invocation ownership is testable without giving unit doubles native or SQL
authority. The actual supplier still uses the existing durable grant,
redemption/settlement and independent native read protocols. It grants no
business readiness or production capacity. Qualification continues using its
own compiled realm, source tables and scope.

Old generic adapter bindings remain compatible when their new optional source
pin is absent; they gain no original Guest witness. Source-pinned accepted
creates require the new original DTO. Failed and uncertain transport outcomes
remain separate immutable facts and cannot receive original-success authority.
The production registry remains empty. Registry population, publication, owning
CI, real provider execution and product qualification remain separate work.

## Related

- ADR-0050 (original provisioning, admission and native retirement)
- ADR-0053 (separate Source recovery authority)
- ADR-0059 (compiled production profile approvals)
