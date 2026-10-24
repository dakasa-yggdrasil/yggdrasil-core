# Architecture Decision Records — yggdrasil-yggdrasil-core

Curated, immutable record of durable architectural decisions — one decision per file.
Working scratch (brainstorming, plans, handoffs) lives in `docs/superpowers/` and is **not
tracked** (see `AGENTS.md` § Spec-driven docs). The domain-wide model is defined in the
monorepo root `docs/adr/0001-adopt-adr-plus-scratch-model.md`. To change a decision, write a
NEW ADR that supersedes the old one; never edit an Accepted ADR's Decision.

**68 decisions.**

| ADR | Title | Status | Date | Scope |
|-----|-------|--------|------|-------|
| [0001](0001-foundational-event-stream-transactional-emission-postgresql.md) | Foundational event stream — transactional emission, PostgreSQL-backed cursor pull, JSON Schema contracts | Accepted | 2026-04-10 | yggdrasil-core |
| [0002](0002-yggdrasil-core-materializes-managed-secrets-as-native-kubern.md) | yggdrasil-core materializes managed secrets as native Kubernetes Secrets via a built-in reconciler (no External Secrets Operator) | Accepted | 2026-04-12 | yggdrasil-core (reconciler engine, cluster-facing) |
| [0003](0003-yggdrasil-core-becomes-dakasa-s-own-oidc-provider-mediating.md) | Yggdrasil-core becomes DaKasa's own OIDC Provider, mediating Google Workspace SSO | Accepted | 2026-05-05 | yggdrasil-core, dakasa-commons (oidcclient), Tartaro (dakasa-tartaro-api/dakasa-tartaro-fe, first consumer), Yggdrasil console (Phase 1: internal SSO) |
| [0004](0004-declarative-lifecycle-reactor-framework-replaces-temporal-ba.md) | Declarative lifecycle reactor framework replaces Temporal-based onboarding/offboarding workflows | Accepted | 2026-05-15 | yggdrasil-core (event/reactor pipeline, core lifecycle propagation architecture), dakasa-system (workflow removal), integration adapters |
| [0005](0005-unify-password-credential-lifecycle-into-auth-identities-arg.md) | Unify password credential lifecycle into `auth_identities`; argon2id as the hashing scheme; deprecate `yggdrasil-identities` | Accepted | 2026-05-15 | yggdrasil-core (auth/identity) |
| [0006](0006-auto-heal-integration-type-manifest-drift-from-the-adapter-s.md) | Auto-heal `integration_type` manifest drift from the adapter's live `describe` response, preserving only the operator-owned `reactors` field | Accepted | 2026-05-16 | yggdrasil-core (`integration_type` manifest lifecycle) |
| [0007](0007-provider-neutral-collaborator-external-identity-mapping-popu.md) | Provider-neutral collaborator↔external-identity mapping, populated via reactor envelope + webhook receiver | Accepted | 2026-05-16 | yggdrasil-core (`internal/externalidentity/`), integration-slack, integration-google-workspace, integration-github (opt-in adapters) |
| [0008](0008-integration-surfaces-federated-per-adapter-admin-spas-discov.md) | Integration Surfaces — federated per-adapter admin SPAs discovered by manifest and slot | Accepted | 2026-05-17 | yggdrasil-core, surface-console, surface-template, per-`integration-<name>` adapter repos |
| [0009](0009-replace-per-user-tartaro-rbac-roles-with-team-scoped-action.md) | Replace per-user Tartaro RBAC roles with team-scoped action grants materialized via the reactor framework | Accepted | 2026-05-18 | yggdrasil-core (canon events + team_grant endpoints), integration-tartaro-dakasa, dakasa-tartaro-fe (tartaro-operations, tartaro-api and sibling services), dakasa-commons |
| [0010](0010-team-mirroring-reactors-ack-via-a-reserved-envelope-into-a-p.md) | Team-mirroring reactors ack via a reserved envelope into a provisioning log, self-healed by an anti-join reconcile sweep | Accepted | 2026-05-18 | yggdrasil-core (reactor dispatcher extension), integration-slack, integration-github, integration-google-workspace |
| [0011](0011-bootstrap-internal-public-oidc-clients-declaratively.md) | Bootstrap internal public OIDC clients declaratively | Accepted | 2026-08-25 | yggdrasil-core / internal OIDC client lifecycle |
| [0012](0012-keep-sensitive-integration-outputs-transient-between-workflow-steps.md) | Keep sensitive integration outputs transient between workflow steps | Superseded | 2026-09-01 | yggdrasil-core / workflow execution and integration adapter contract |
| [0013](0013-scope-adapter-mutation-event-credentials-to-event-publishing.md) | Scope adapter mutation-event credentials to event publishing | Superseded | 2026-09-01 | yggdrasil-core / adapter authentication |
| [0014](0014-bootstrap-confidential-oidc-clients-from-read-only-secret-files.md) | Bootstrap confidential OIDC clients from read-only Secret files | Accepted | 2026-09-02 | yggdrasil-core / confidential OIDC client lifecycle |
| [0015](0015-validate-and-redact-workflow-inputs-before-async-persistence.md) | Validate and redact workflow inputs before async persistence | Accepted | 2026-09-04 | yggdrasil-core / workflow dispatch and durable run evidence |
| [0016](0016-constrain-provider-generated-secrets-to-one-step-private-leases.md) | Constrain provider-generated secrets to one-step private leases | Accepted | 2026-09-05 | yggdrasil-core / workflow execution and integration adapter transport |
| [0017](0017-scope-machine-principals-by-route-workflow-and-run-ownership.md) | Scope machine principals by route, workflow, and run ownership | Accepted | 2026-09-05 | yggdrasil-core / non-human HTTP authentication and workflow dispatch |
| [0018](0018-enforce-workflow-string-pattern-and-maximum-length-at-ingress.md) | Enforce workflow string pattern and maximum length at ingress | Accepted | 2026-09-05 | yggdrasil-core / workflow input validation |
| [0019](0019-scope-directory-machine-principals-to-exact-collaborator-read-routes.md) | Scope directory machine principals to exact collaborator read routes | Superseded by 0031 | 2026-09-20 | yggdrasil-core / non-human directory read authentication |
| [0020](0020-accept-audit-trace-references-only-from-a-well-formed-traceparent.md) | Accept audit trace references only from a well-formed traceparent | Accepted | 2026-09-21 | yggdrasil-core / audit_events writers |
| [0021](0021-key-event-publisher-grants-by-the-logical-integration-instance.md) | Key event publisher grants by the logical integration instance | Accepted | 2026-09-24 | yggdrasil-core / event publisher authorization (`POST /api/v1/events`) |
| [0022](0022-load-the-machine-credential-surfaces-once-and-require-an-explicit-development-environment.md) | Load the machine credential surfaces once and require an explicit development environment | Accepted | 2026-09-24 | yggdrasil-core / workflow-run, event and directory machine authentication; deploy-family anonymous posture |
| [0023](0023-gate-emergency-workflow-dispatch-with-an-exact-process-wide-allowlist.md) | Gate emergency workflow dispatch with an exact process-wide allowlist | Superseded by 0025 | 2026-09-26 | yggdrasil-core / workflow dispatch, manifest mutation, integration execution, reactors, and AMQP queues |
| [0024](0024-fail-workflows-loudly-on-final-state-assertion-drift.md) | Fail workflows loudly on final-state assertion drift | Accepted | 2026-09-27 | yggdrasil-core / workflow manifest validation and in-process workflow execution |
| [0025](0025-block-repository-binding-webhook-dispatch-during-emergency-lock.md) | Block repository-binding webhook dispatch during the emergency lock | Accepted | 2026-09-27 | yggdrasil-core / GitHub webhook repository bindings and emergency workflow dispatch |
| [0026](0026-expose-a-non-persisting-event-grant-readback.md) | Expose a non-persisting event grant readback | Accepted | 2026-09-27 | yggdrasil-core / event publisher authorization |
| [0027](0027-require-authenticated-actor-channels-for-authorized-workflows.md) | Require authenticated actor channels for authorized workflows | Accepted | 2026-09-27 | yggdrasil-core / workflow dispatch channel authorization |
| [0030](0030-own-declared-phone-contacts-and-new-human-profile-completion.md) | Own declared phone contacts and new human profile completion | Accepted | 2026-10-06 | yggdrasil-core / collaborator contact and enrollment |
| [0031](0031-export-restricted-consistent-directory-snapshots.md) | Export restricted consistent directory snapshots | Superseded by 0032 | 2026-10-06 | yggdrasil-core / directory machine reads |
| [0032](0032-materialize-explicit-typed-team-leadership.md) | Materialize explicit typed team leadership | Accepted | 2026-10-07 | yggdrasil-core / team writers and directory leadership |
| [0033](0033-preserve-current-declarations-during-conditional-contact-writes.md) | Preserve current declarations during conditional contact writes | Accepted | 2026-10-07 | yggdrasil-core / operator contact declaration |
| [0034](0034-bind-delivered-mfa-codes-to-canonical-contact-possession.md) | Use saved profile contacts automatically for OTP MFA | Proposed | 2026-10-08 | yggdrasil-core / collaborator authentication |
| [0035](0035-prune-expired-capacity-history-without-changing-intent-authority.md) | Prune expired capacity history without changing intent authority | Proposed | 2026-10-08 | yggdrasil-core / capacity event maintenance |
| [0036](0036-redeem-provider-mutations-once-under-durable-capacity-authority.md) | Redeem provider mutations once under durable capacity authority | Proposed | 2026-10-08 | yggdrasil-core / provider-neutral capacity mutations |
| [0037](0037-produce-native-vm-proofs-through-fixed-protected-observers.md) | Produce native VM proofs through fixed protected observers | Proposed | 2026-10-08 | yggdrasil-core / native VM observation and mutation readback |
| [0038](0038-bind-shadow-pod-assessments-to-fixed-native-and-metric-sources.md) | Bind shadow pod assessments to fixed native and metric sources | Proposed | 2026-10-08 | yggdrasil-core / fixed reserved pod source assessment |
| [0039](0039-bind-native-hpa-commands-to-retained-local-lifetime-witnesses.md) | Bind native HPA commands to retained local lifetime witnesses | Superseded by 0040 | 2026-10-08 | Fixed native HPA executor and protected current Pod termination receipts |
| [0040](0040-separate-native-process-lifetimes-from-reservation-decisions.md) | Separate native process lifetimes from reservation decisions | Proposed | 2026-10-08 | Process nonce admission, independent lifetime ledger and authoritative terminal archive |
| [0041](0041-reobserve-installed-birth-guards-before-native-hpa-authority.md) | Reobserve installed birth guards before native HPA authority | Proposed | 2026-10-09 | yggdrasil-core / native HPA lifetime executor |
| [0042](0042-join-native-vm-lifetimes-to-fixed-kubernetes-membership.md) | Join native VM lifetimes to fixed Kubernetes membership | Proposed | 2026-10-10 | yggdrasil-core / protected native VM-to-Node observation |
| [0043](0043-observe-original-business-creation-canaries.md) | Observe original business creation canaries through fixed readers | Proposed | 2026-10-10 | yggdrasil-core / original business canary observations |
| [0044](0044-durable-pre-start-capacity-dispatch.md) | Admit capacity schedules through durable pre-start ownership | Proposed | 2026-10-10 | yggdrasil-core / protected reserved Pod capacity dispatch |
| [0045](0045-join-original-guest-bootstrap-under-fixed-vm-membership.md) | Join original Guest bootstrap under fixed VM membership | Proposed | 2026-10-11 | yggdrasil-core / protected original Guest observations |
| [0046](0046-persist-bounded-capacity-intents-under-protected-workflows.md) | Persist bounded capacity intents under protected workflows | Proposed | 2026-10-08 | yggdrasil-core / capacity protocol |
| [0047](0047-observe-original-live-lease-before-private-notify-canary.md) | Observe the original live lease before a private Notify canary | Proposed | 2026-10-11 | Original finite private machine useful prerequisite |
| [0048](0048-join-retained-resource-prerequisites-to-original-notify-returns.md) | Join retained resource prerequisites to original Notify returns | Proposed | 2026-10-11 | Sealed private resource prerequisites |
| [0049](0049-create-release-recovery-authority-after-original-dual-returns.md) | Create release recovery authority after both original returns | Proposed | 2026-10-11 | Fixed native finalizer result and release-only subdecision |
| [0050](0050-bind-guest-admission-and-retirement-to-original-native-returns.md) | Bind Guest admission and retirement to original native returns | Proposed | 2026-10-13 | Core original provisioning, Guest admission and protected retirement |
| [0051](0051-keep-original-creator-admission-source-owned-and-durably-sealed.md) | Keep original creator admission source-owned and durably sealed | Proposed | 2026-10-13 | Core original creator lifecycle and persistent exclusions |
| [0052](0052-gate-executor-stop-on-task-leases-and-closed-admission.md) | Gate executor stop on task leases and closed admission | Proposed | 2026-10-16 | Opt-in laboratory activity and power lifecycle |
| [0053](0053-isolate-original-source-recovery-probes-from-production-phase-authority.md) | Isolate original Source recovery probes from production phase authority | Proposed | 2026-10-18 | Original Guest native qualification recovery |

| [0054](0054-bind-failed-owner-compensation-to-redeemed-child.md) | Bind failed-owner compensation to its original redeemed cleanup child | Proposed | 2026-10-18 | nativequalification Source fixture |

| [0055](0055-observe-uncertain-original-create-and-reissue-unused-cleanup-child.md) | Observe uncertain original create and reissue unused cleanup child | Proposed | 2026-10-18 | Qualification-only actual lost reply and fresh reissue |

| [0056](0056-bind-recovery-owned-cleanup-to-current-lease-and-one-use-effects.md) | Bind recovery-owned cleanup to current lease and one-use effects | Proposed | 2026-10-19 | Qualification-only original failed-owner cleanup |

| [0057](0057-require-original-local-installation-before-qualification.md) | Require original local installation before qualification | Proposed | 2026-10-21 | Core/Guest original provisioning |

| [0058](0058-anchor-qualification-freshness-in-original-monotonic-owners.md) | Anchor qualification freshness in original monotonic owners | Proposed | 2026-10-21 | Original qualification nonce protocol |

| [0059](0059-pin-production-guest-admission-to-compiled-contracts.md) | Pin production Guest admission to compiled contracts | Proposed | 2026-10-21 | Core original Guest production profile admission |

| [0060](0060-own-original-guest-provider-per-workflow-invocation.md) | Own the original Guest provider per workflow invocation | Proposed | 2026-10-21 | Original source provider lifetime and single-call ownership |

| [0061](0061-verify-public-core-service-contract-explicitly.md) | Verify public Core service contract explicitly | Accepted | 2026-10-21 | Exact source-owned public Core doctor profile |

| [0062](0062-preserve-primary-http-with-same-owner-secondary-tls.md) | Preserve primary HTTP with same-owner secondary TLS | Accepted | 2026-10-21 | Core transport and mixed-process rollout |

| [0063](0063-own-fresh-notify-canaries-in-original-guest-sessions.md) | Own fresh Notify canaries in original Guest sessions | Proposed | 2026-10-21 | One-use original publication, native transaction read and separate clock owners |

| [0064](0064-separate-production-retirement-clock-owners.md) | Separate production retirement clock owners | Proposed | 2026-10-21 | Original production retirement and causal native destroy readback |

| [0065](0065-transfer-original-provisioning-time-between-clock-domains.md) | Transfer original provisioning time between clock domains | Proposed | 2026-10-21 | Signed current PG authority and original Guest boot-clock provisioning/installation |

| [0066](0066-reconcile-original-notify-guests-through-the-protected-workflow.md) | Reconcile original Notify Guests through the protected workflow | Proposed | 2026-10-21 | Exact scheduled original Guest graph, useful membership and unchanged original deadlines |

| [0067](0067-separate-administrative-capacity-costs-from-native-quotes.md) | Separate administrative capacity costs from native quotes | Proposed | 2026-10-21 | Finite reviewed planning assumptions, unchanged native quote/billing currency and legacy dates |

| [0068](0068-promote-the-original-protected-floor-with-complete-membership.md) | Promote the original protected floor with complete membership | Proposed | 2026-10-21 | Original zero-to-one floor, complete Coverage30 and unchanged raw useful-member gates |

| [0069](0069-record-expired-unadmitted-create-dispositions-separately.md) | Record expired unadmitted create dispositions separately | Proposed | 2026-10-22 | Immutable accepted creates, authenticated terminal absence and fenced floor recovery |

| [0070](0070-validate-explicit-empty-ec2-instance-responses.md) | Validate explicit empty EC2 instance responses | Proposed | 2026-10-23 | Retained native HTTP 200, complete empty XML and unchanged six-read inventory basis |
| [0071](0071-reject-superseded-dispatch-before-start.md) | Reject superseded dispatch before start | Proposed | 2026-10-23 | Explicit administrative capacity dispatch rejection with retained original ownership |
| [0072](0072-recover-amqp-through-serialized-consumer-sessions.md) | Recover AMQP through serialized consumer sessions | Proposed | 2026-10-23 | AMQP session readiness, consumer drain and recovery without ambiguous-operation replay |

| [0073](0073-record-terminal-failed-witnessed-original-lifetimes.md) | Record terminal failed witnessed original lifetimes | Proposed | 2026-10-23 | Preserved accepted create/witness and unknown ACK with separate native-absence terminal ledger |

| [0074](0074-record-native-authorization-denied-originals-separately.md) | Record native authorization-denied originals separately | Proposed | 2026-10-23 | Preserved uncertain originals and unknown ACK with authenticated denial decision and separate fenced terminal ledger |

| [0075](0075-preserve-returned-failed-workflow-acks-in-denied-dispositions.md) | Preserve returned failed-workflow ACKs in denied dispositions | Proposed | 2026-10-23 | Explicit returned/failed/known-ACK lane, immutable original acknowledgment and unchanged native-denial evidence |
