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
invent a destroy alias. Original capacity start/stop remain refused. Adapter 1.62.0 supplies a distinct
source-owned original terminate receipt and independently complete native
instance/root-EBS/primary-ENI absence. Core production retirement orchestration
must still join original Guest drain and protected useful-floor evidence before
permitting the write; provider absence cannot stand in for either.

Production profiles may use an exact sorted per-member `slot_bootstraps` list
instead of one shared user-data hash. The legacy hash must be empty in that mode;
legacy profiles omit the optional list and keep their byte-exact contract. Every
member and provider mutation slot must pin its own actual user-data hash. Original
create witness and bootstrap journal joins select the actual native slot's hash,
never another slot or a fallback. The source profile digest covers the whole list.
The original setup executable is shared and retains its real common payload hash;
per-slot certificates and WireGuard keys are materialized only in that slot's
private user-data before setup starts. Provider selection independently checks its
source-owned per-slot secret template and hash before the original grant/send.
No VM receives another slot's private template.

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


### Signed provider identity for Guest startup

AWS and Hetzner production witnesses require the optional closed
`provider_native_identity` extension, schema `guest_provider_native_identity_v1`.
It is populated only by the source-owned independent native read after the
original accepted settlement. Core joins the exact tuple, binding source pin,
fresh observation and original creation return before including it in the
existing signature. The field stays absent for native QEMU qualification.
No migration, seeded grant, caller environment or unsigned manifest supplies
this evidence. Guest separately reads native metadata and kernel boot/process
lifetimes; EC2 LaunchTime/pendingTime identifies creation rather than a new boot.

The fields distinguish provider region, location and availability zone. AWS
uses actual regional account/instance/AZ/image/type/private-hostname data.
Hetzner uses native server location and `location.network_zone`; metadata region
is the latter. The current Hetzner API removed server `datacenter` on 1 July
2026 and removed datacenter endpoints on 1 October 2026, so signed zone is empty
and metadata availability-zone is diagnostic only. No obsolete API field or
inferred location-to-datacenter mapping becomes authority.
Sources: [Hetzner metadata/reference](https://docs.hetzner.cloud/reference/cloud),
[Hetzner API changelog](https://docs.hetzner.cloud/changelog).


### AWS original retirement lifecycle

The existing AWS destroy capability requires a distinct
`original_provider_destroy_return`, closed schema
`aws_original_terminate_instances_return_v1`, inside the existing authenticated
principal/attempt/nonce settlement transaction. Its old creation timestamp is
not restamped to the destroy call. Its actual request ID does not describe an
EC2 job. The original pre-write root EBS volume and primary ENI IDs, each marked
requires_absence, are retained immutably with that settlement.

A source-pinned AWS binding consumes the separate
`aws_original_terminate_and_native_absence_v1` lifecycle. Exact native instance
terminated/NotFound and separately complete volume/ENI NotFound must all be
freshly observed; generic action flags remain false and action IDs empty.
Unknown receipts, retained auxiliaries, incomplete Close/error bodies, reuse of
a creation receipt, generic delete_server actions, invoice/quiescence claims
or compensation without a separate owned contract refuse completion. Legacy
bindings without the optional source pin preserve their prior generic behavior.
No schema migration or source test fabricates durable provider authority.

### Independent original profile read

Per-slot user-data cannot contain a profile that itself hashes those user-data
bytes. The opt-in Guest configuration therefore carries fixed Core origin,
member/slot/provider and independent public/transport identities, with an empty
local profile. It reads the complete public profile over the same fixed Core
mTLS/bearer channel at `bindings/<member>/slots/<slot>/original-profile`.
The principal already pins its exact profile digest; no caller URL or new hash
selects a profile. Exactly one accepted original create witness must already
exist for the native metadata ID. Core rechecks current policy, workflow, lease,
clean source and compiled approval before returning the canonical typed profile.
The read neither creates nor renews preregistration. Guest still verifies the
original signed witness's profile hash and independently verifies the actual
provider-native identity before bootstrap payload or writer admission. Legacy
local profiles and the separate native qualification realm remain unchanged.


### Read-only wait for the owning create

Native boot can reach ConfigV2 before the original provider operation finishes
its independent health observations and records the immutable create witness.
The fixed profile endpoint may return only the canonical non-authoritative 425
`{"schema":"original_guest_profile_pending_v1","code":"original_create_pending"}`
after finding exactly one scoped, unexpired original preregistration and open
create grant. Under the existing scope lock it rechecks current policy,
workflow, lease, source, compiled approval and exact original grant content;
failed/foreign/expired state and SQL errors never become pending. No native ID
proves authority in this branch. A witness that commits concurrently is read
again once within the same HTTP budget, preserving the exact immutable selector.

Guest owns one parent-clipped monotonic wait of at most 420 seconds, beginning
before one native selector read. It repeats only the fixed profile GET on that
exact 425 body. Every Do/read/EOF/Close exchange has a child budget of at most
five seconds; unknown bodies, authentication errors, late returns and Close
failures hold. The wait neither renews the original create/lease nor retries a
mutation. Ready responses still require the full accepted create witness and
independent native health, and bootstrap still verifies the signed witness.
The original five-second canary, thirty-second retirement and HTTP timeouts
remain separate. Source tests do not claim a positive native PostgreSQL witness.
