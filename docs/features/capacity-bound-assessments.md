# Bound source assessments

`capacity.observe_bound_assessment` and `capacity.assess_bound` are fixed
`yggdrasil` operations inside the exact active authenticated workflow named by
the policy. Their closed input is only `{policy:{namespace,name}}`. An explicit
version, manifest UUID, caller assessment, provider selector, query or source
boolean is refused.

A policy optionally declares `assessment_binding` with a snapshot binding and
one signal binding per rule. Both sides pin `integration_instance_id`,
`instance_checksum`, `integration_type_id` and `type_checksum`. Signal bindings
also declare the exact rule `name`, provider `binding_name` and `binding_sha256`.
The adapter source fingerprint includes the fixed provider URL and normalized
operator metric declaration; changes require explicit policy reapproval.

The snapshot mode `native_hpa_minimum_v1` has unit and policy dimension
`reserved_pod_envelope`. It fixes namespace, HPA name/UID, Deployment name/UID,
owner, profile, protected floor and maximum replicas. Owner/floor/maximum/profile
must match the policy. One profile and zero VM `mutation_bindings` are required.
`snapshot.units` is HPA `minReplicas`; current/desired replicas, provider VM count,
node membership and ready business capacity remain separate. UID/RV, ownership,
tracking, bounds and source timestamp must all be present and valid. Generated
controller-owned HPAs and unowned/drifted targets are refused.

A policy without an HPA execution binding remains shadow-only. Its fixed
assessor persists observations and decisions without actuator permission. An
optional `native_hpa_lifetime_v2` binding and separate default-off process
switches enable only the source-fixed protected `capacity.admit_bound` and
`capacity.execute_bound` workflows. Neither operation accepts caller Pods,
readiness flags, assessments, URLs or command selection. Old generic
assess/claim/advance/recover/reconcile and provider mutation operations cannot
actuate this bound dimension. Useful capacity and warm resources remain unknown.

Each source is resolved from its exact active revision before private hydration
and Describe, using the existing integration machinery. The dispatched
`observe_metric_range_evidence` or `observe_capacity_envelope` must exist in its
real ActionCatalog and ResourceTypes. Explicit operation/capability/status and
closed output schemas are checked. Reads have a bounded overall context and safe
errors; no secret or private instance spec becomes assessment output.

Signal name, source identity, unit, required data and fingerprint must match.
Quality state is preserved, including null missing/non-finite values. Complete
coverage still requires Core's own fresh source/window, distinct sample count,
maximum gap and numeric range checks at assessment time. Missing/stale/
cardinality/non-finite observations hold; identity/configuration/schema mismatch
refuses the source. There is no zero-fill or implicit maximum/aggregation.

The operator remains responsible for honest value/source-timestamp query
semantics, labels, expected roster/count and availability guards. A range query
cannot prove that all contributors exist. HPA diagnostics cannot prove models
are warm, a path is healthy or jobs drained. The fixed executor binds
private one-send commands to exact HPA/Deployment UID and resource versions,
current native Pod/container identities and immutable process origins.

Admission projects every candidate's immutable SDK2 challenge before waiting
for actual projected-file and business-startup acknowledgements. The existing
90-second protected invocation context bounds these reads. Expiry leaves the
lifetime unknown; a delay or missing frame never grants readiness. The separate
admission workflow can admit a new SDK2 candidate while an older schema one
baseline remains explicitly unqualified, native-running and frozen against
pressure execution. It never invents a process nonce for an already booted SDK1
process.

Every current baseline lifetime must be protected, admitted and reobserved
before an HPA reservation CAS. The executor issues no Pod DELETE. Native
controllers select retirement victims; exact current `State.Terminated`, the
complete successful SDK2 roster and the immutable nonce/challenge are required
before a durable Core ACK and one-use removal of this executor's finalizer.
Alive origins remain retained across reservation generations and hold decisions.
`envelope_applied` confirms only the reserved minimum, never joined lifetimes,
released physical capacity, VM stock or useful/warm fleet capacity.

The mandatory KinD gate uses the actual adapter main and actual Core protected
HTTP/RBAC, production PostgreSQL migrations and immutable independently
qualified SDK fixture images. It exercises full-baseline protection, a real
ReplicaSet controller victim outside the former selected UID subset, a held
worker before native termination, durable receipt ACK before release, and a
mixed schema one/two candidate bootstrap with pressure refusal. The deliberate
native Deployment scale request in this test is a controller-selection
adversary; an HPA minimum change alone does not assert a replica decrement. Birth
protection is fixture source configuration here; the separately qualified
platform admission webhook and useful all-function N-1 proofs remain distinct.

The selected collector source must separately qualify its actual request return,
body Close and original context/absolute deadline before the existing integration
fixtures are compiled. Both capacity workflows run one source-fixed Go lifecycle
gate: its actual process Start/PID, Wait and stdout/stderr drain, strict root and
ten-case GoJSON roster, and one package PASS are all required. A nominal PASS
transcript cannot replace the original zero exit and live deadline. The helper
owns only a fresh Linux process group, with an independent context owner armed
until the single actual Wait and every pipe copy return, even after its leader
exits while a descendant holds the pipes. Cancellation still requires the actual
owner and Wait joins; no forced pipe close or signal can publish success. It
retains at most 4 MiB combined raw output on every outcome; overflow is retained
as incomplete and refused.

Raw files and the observation report are never sufficient on their own. Actual
write/Close returns and the final original context/absolute deadline are checked
before the public gate exit. A late final report stays pre-publication observation
data, with a nonzero exit and a fixed failure category; it is not rewritten into
success. The two existing jobs keep their original 15/40-minute bounds, PG's
5-minute command and Kind's 24-minute command and four scenarios.

This is collector lifecycle qualification plus the existing successful-source
integration. The exported metric fixture still fails its child test on source
error; this increment adds no end-to-end Core late-Close error corpus and does
not persist a successful HOLD from a failed observation. Transport failure is
neither missing quality data nor zero nor provider/capacity authority.

The strict PostgreSQL CI gate compiles reviewed metric/HPA source checkouts and
executes actual native source functions and decoders through protected Core
transport. It checks reserved-minimum semantics, diagnostic holds, caller-path
refusal, foreign/missing UID/RV/hash, paused revisions and prohibited VM/migration/
execution combinations. No missing-producer or required-case skip is accepted.
This is source integration evidence, not production capacity certification.
