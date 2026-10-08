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

The policy is initially shadow-only: `execution_enabled:true` is rejected, even
when the process switch is enabled. Old generic assess/claim/advance/recover/
reconcile and mutation operations cannot operate on this bound policy; existing
`capacity.observe` can read its intent. The fixed assessor persists observations
and decisions, never calls an actuator or acquires a provider write permission.
Its receipt always reports `execution_enabled:false`, `atomic_snapshot:false`
and `useful_capacity_known:false`.

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
are warm, a path is healthy or jobs drained. The future fixed executor must bind
the private intent, HPA/Deployment UID+RV, canonical owner and generation to the
native CAS API, with separate real producer evidence for later transitions.

The strict PostgreSQL CI gate compiles reviewed metric/HPA source checkouts and
executes actual native source functions and decoders through protected Core
transport. It checks reserved-minimum semantics, diagnostic holds, caller-path
refusal, foreign/missing UID/RV/hash, paused revisions and prohibited VM/migration/
execution combinations. No missing-producer or required-case skip is accepted.
This is source integration evidence, not production capacity certification.
