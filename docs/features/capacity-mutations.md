# Durable provider mutation authority

This optional protocol composes with [capacity intents](capacity-intents.md).
Absent `mutation_bindings` and adapter principals authorize no provider writes.
It adds no privileged scheduler or production configuration. Core owns grants
and logical membership; provider adapters own fixed SDK payloads and native reads.

## Approved plans and membership

Each binding names its instance UUID/checksum, type UUID/checksum, adapter
principal, stable native scope checksum, profile, ensure/destroy capability pair,
protected/max slots and every slot's closed `desired_spec` plus canonical
ensure-spec `desired_spec_sha256`. Core validates the approved projection and
its digest together; digest-only slots authorize nothing. These are
operator declarations, not caller-generated admission facts. Instance/type rows
must remain exact and active when issuing or redeeming. Dynamic prices and query
times must not change logical scope; current physical/admission revisions belong
in the non-secret desired spec and its digest.

The closed `capacity_vm_slot_v1` projection has only `schema_version`,
`capability`, `integration_instance_id`, `scope_checksum`, `profile_checksum`,
`admission_checksum`, `profile_name`, integer `slot`, `native_name`,
`bootstrap_sha256` and optional expected destroy identity. Native names are
lowercase DNS labels up to63 characters. Unknown fields are
refused before hashing. Core never hashes arbitrary credential-bearing JSON.
Canonical JSON sorts object keys and preserves integer numbers. The requested
typed fields must match the immutable operator-approved projection exactly;
only that approved projection supplies bytes for the authority digest.
For destruction, Core loads the immutable resource tuple from its locked slot
ledger, checks the caller tuple for equality, then hashes the approved projection
with that registered tuple and destroy capability. The runtime workflow
metadata never supplies hashed authority bytes. A dry run cannot approve
its own changed spec. Provider-specific identity/payload construction stays in
the adapter.

Control-plane `__GENERATE__:<label>` values are rendering instructions, never
generated passwords. The closed slot projection rejects those markers, secret
fields and unapproved values before fingerprinting. Its SHA-256 is an integrity
fingerprint of public infrastructure identity; it is not a password verifier.
Control-plane deployment must materialize actual secrets separately before
applying a rendered Secret object.

`capacity.record_slot` records an existing exact immutable native ID/creation
time from fresh owned/spec-verified adapter reads. Complete registered live
membership must match the immutable intent baseline before the first mutation.
Every live slot must retain fresh readback before further permission is issued.
An open grant, replacement, foreign dimension or tombstone cannot be adopted.
Existing same-identity slots can refresh their read receipt. Native slot identity
includes the profile. A global native-slot lock plus an ownership-checked upsert
prevents two policy realms from racing to overwrite an absent slot. Protected
slot counts are per profile and may be zero for stateless burst profiles; the
aggregate policy floor remains protected across all live and pending removals.
The slot revision
is a Core ledger version, not an invented provider resource version.

## Protected workflow operations

The existing active workflow, authenticated actor channel, RBAC, policy and
private invocation lease requirements apply to all three operations.

| Operation | Additional input | Effect |
|---|---|---|
| `capacity.record_slot` | `mutation:{binding_name,desired_spec}`, `mutation_proof` | Register/refresh owned exact native membership |
| `capacity.grant_mutation` | `mutation:{binding_name,desired_spec}` | Return non-secret durable grant projection |
| `capacity.confirm_mutation` | `mutation_proof` | Record settled transport plus complete native action/resource outcome |

All use `policy`, `generation`, `fencing_token` and private `lease_owner`.
Confirmation can use the original policy revision and a recovery-only lease
after global execution pause. It never issues another write. A normal ensure
requires preparing expansion and a current eligible profile. A destroy requires
the already admitted `drained` phase, exact current ID/creation time, an
unprotected slot, and remaining live count after pending deletes at/above the
target and protected floor. Pending creates count against target and ceiling.
Automatic physical profile migration is not inferred from a profile decision.
It requires a separately implemented overlap, routing and retirement contract.

## Exact private callback surface

`YGGDRASIL_CAPACITY_MUTATION_PRINCIPALS_JSON` is unset by default. If configured,
it is a non-empty array of hashed machine principals with `principal_id`,
`status`, `expires_at`, `rotation_id`, optional `rotated_at`, `token_sha256`,
one exact `integration_instance_id` and exact `capabilities`. Malformed, blank,
duplicate, wildcard or cross-family shared credentials fail initialization.
No human cookie, workflow, directory, event or deploy token is accepted.
Every matching expired/revoked adapter credential is refused before other
credential fallbacks, even on public routes. Callback timeout is five seconds;
one exact JSON object is bounded to32KiB and unknown fields are rejected.

- `POST /api/v1/capacity/mutations/redeem`: Bearer adapter credential; the
  adapter-generated `attempt_id` and `settlement_token_sha256` accompany the
  exact grant's instance/scope/profile/slot/capability/request digest and optional
  destroy tuple. Response echoes grant/attempt/digest/expiry and either
  `write_once` or `read_only`. Every replay, including the original attempt,
  is read-only. A missing/unknown reply never permits a provider send.
- `POST /api/v1/capacity/mutations/settle`: same independent Bearer scope plus
  private `X-Capacity-Mutation-Settlement` nonce. Request has grant/attempt/digest,
  `outcome`, `transport_completed:true`, immutable resource tuple, primary and
  next action IDs where known, observation time and sanitized provider error.
  An accepted outcome requires identity and action evidence.
  For deletion it also requires `auxiliary_inventory_complete:true` and every
  identified paid auxiliary in `auxiliary_resources:[{kind,id,requires_absence}]`.
  Exact settlement retries are idempotent; changed receipts are conflicts. After commit response
  is `{grant_id,attempt_id,request_sha256,status:"settled"}`.
- `GET /api/v1/capacity/mutations/{grant_id}`: same scoped adapter credential,
  no write permission. Returns `{grant,attempt_id,outcome,transport_completed,
  resource_id,resource_created_at,action_id,next_action_ids,auxiliary_resources,
  auxiliary_inventory_complete}` where available.
  This preserves native deletion identity after a server disappears. No lease
  owner/executor, nonce/hash, credential or desired secret content is returned.

Settlement outcomes are `accepted`, `uncertain`, `rejected_before_send` and
optional `provider_rejected`. A request that was sent cannot be labeled
`rejected_before_send`. `provider_rejected` additionally requires an exact
`provider_status_code`/`provider_error_code` pair from binding
`definitive_rejections:[{status_code,error_code,documentation_ref}]`, with a
reviewed primary HTTPS no-acceptance contract. The default is empty; ordinary
4xx responses, timeout, conflict and GET absence are not inferred no-effect.
408/409/425/429/5xx cannot be allowlisted. Unknown/lost callback settlement keeps
the reservation. Credential rotation may preserve the exact principal identity
and scope so a late owning attempt can submit its nonce proof.

## Recovery and truthful guarantees

An owning adapter can settle after lease expiry, policy replacement or execution
pause. Accepted transport does not establish native action completion. A fresh
protected confirmation requires owned/spec-verified exact resource identity,
all recorded primary/next action IDs present in a complete terminal successful
action proof, and prior owning transport settlement. Native resource IDs are
bounded to128 characters, matching the canonical event aggregate boundary.
Creation confirmation requires `observed_creation_grant_id` equal to the exact grant and creation time
within its bounded chronology. Lost create responses may
recover only from complete native reads bound to the exact creation grant label;
empty/partial action lists or a reused name are insufficient. Delete confirmation
also requires exact native absence, after its recorded delete action completes,
and fresh `auxiliary_absent:[{kind,id}]` proof for every required auxiliary.
Provider-specific discovery and cleanup of paid IP/volume/LB resources stays
with the adapter; a vanished server alone does not prove billing stopped.

Confirmation also emits the canonical `<provider>.<resource>.ensured` or
`.destroyed` event in the same PostgreSQL transaction as membership and grant
confirmation. Routing derives from the exact registered type and canonical
capability pair captured when issuing. Event payloads expose immutable resource,
instance and native receipt facts, with a stable grant idempotency key; private
lease, executor and settlement credentials are absent. Accepted/uncertain SDK
responses emit no applied event. Exact confirmation retries return the stored
confirmation without producing another event or materialized reaction.

Every outstanding `issued`, `redeemed` or `settled` grant blocks intent promotion,
reconciliation and abort. Only never-redeemed expired grants can retire without
remote proof. Confirmed mutations cannot support `no_mutation_verified` abort.
Grant/slot history remains authoritative; history retention does not prune it.
`mutation_authority_kind:"core_mutation_grants"` requires approved bindings,
`provider_fencing_token:0` and the actual DB terminal-grant check. It never
claims native provider CAS, cancellation, absence of external writers, bootstrap,
application warmth, business drain, capacity or canary readiness.

Interrupted partial changes can finish as `reconciled_partial` only after every
grant has resolved and the fixed observer supplies complete native membership.
The store independently checks the live slot count, profile and freshness against
the observed units. Recovery can refresh exact existing tuples with
`capacity.record_slot`, including under an inactive original policy revision;
first registration, replacement and provider writes remain forbidden. The actual
units must lie inside the original same-profile change and protected envelope.
This closes an observed ledger result, allowing a new assessed generation rather
than leaving a successful partial expansion permanently stuck.

CI exercises real production migrations and PostgreSQL16/race: concurrent
issuance/redemption, same-attempt lost replies, private nonce/scope, pause and
historical recovery, pending-create/delete budgets, exact membership, floor,
drain, tombstone, instance/type/executor drift and terminal-intent blocking.
An actual callback pipeline runs request/reply/redemption/settlement/readback
against PostgreSQL, with no local test or provider activation.
