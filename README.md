# yggdrasil-core

`yggdrasil-core` is the central control plane for Yggdrasil. It owns the core database, serves the synchronous HTTP API used by reference surfaces, stores manifests, and evaluates the rules that drive internal and third-party authorization. The first supported manifest kinds are `rbac`, `policy`, `integration_type`, `integration_instance`, `resource`, `surface`, `repository_binding`, `guardian_policy`, `guardian_approval`, `guardian_memory`, `remediation_contract`, `product`, and `workflow`.

The current service foundation includes:

- PostgreSQL for persistence
- HTTP as the synchronous ingress path for consoles and custom surfaces
- RabbitMQ as the current optional async transport backend for integrations and workers
- pluggable adapter transport contracts, with `rabbitmq` and `http_json` support for outbound integration calls
- Goose for SQL migrations
- core identity storage for collaborators, teams, and memberships
- core-owned password credentials and session storage
- operational topology storage for nodes, edges, documents, infra-map, and build scopes
- versioned manifest storage
- generic manifest validation
- RBAC manifest parsing and evaluation
- policy manifest parsing and evaluation
- integration_type manifest parsing and validation
- integration_instance manifest parsing and validation
- resource manifest parsing and validation
- surface manifest parsing and validation
- repository_binding manifest parsing and validation
- guardian_policy manifest parsing and validation
- guardian_approval manifest parsing and validation
- guardian_memory manifest parsing and validation
- remediation_contract manifest parsing and validation
- product manifest parsing and validation
- workflow manifest parsing, rendering, and execution
- generic integration execution through configured integration instances
- closed-loop Heimdall guardian sweeps backed by repository bindings, guardian policies, and remediation contracts
- integration-owned `guardian_support` contracts for plug-and-play lightweight Heimdall signals
- optional Heimdall LLM fallback constrained by guardian autonomy policy
- composed authorization evaluation across RBAC and policy
- structured logging for worker execution
- direct auth/session HTTP endpoints under `/api/v1/auth/...`
- direct domain HTTP endpoints under `/api/v1/...`
- direct console-oriented HTTP endpoints under `/api/v1/console/...`
- managed secrets stored in the core, versioned with rotation metadata, redacted by default in HTTP responses, and referenceable through `secret://namespace/name[#key]`

## Public contracts

Public wire contracts for integrations live in
[/Users/dakasa/projects/yggdrasil-core/docs/contracts](/Users/dakasa/projects/yggdrasil-core/docs/contracts).

Those schemas are the canonical protocol surface for plugin authors. Plugins
should implement local types that match those contracts instead of importing
`yggdrasil-core/model` as if it were an SDK. The core validates plugin request
and response payloads against those versioned schemas at runtime.

## Manifest model

Each stored manifest has:

- `apiVersion`
- `kind`
- `metadata.name`
- `metadata.namespace`
- `metadata.description`
- `metadata.labels`
- `version`
- `active`
- `checksum`
- `spec`

The first supported kinds are:

- `rbac`
- `policy`
- `integration_type`
- `integration_instance`
- `resource`
- `surface`
- `repository_binding`
- `guardian_policy`
- `guardian_approval`
- `guardian_memory`
- `remediation_contract`
- `product`
- `workflow`

`rbac` has:

- `roles`
- `bindings`
- `rules` with `allow` or `deny`
- subject matching by `type` and `id`
- wildcard matching for `resources` and `actions`

`policy` has:

- `rules`
- conditional operators such as `eq`, `neq`, `gt`, `gte`, `lt`, `lte`, `in`, `contains`, `exists`, `matches`
- runtime `input` inspection through dotted keys like `subject.department` or `context.amount`
- deny precedence over allow
- `not_applicable` when no rule matches

`integration_type` has:

- adapter transport, version, queues, and timeout contract
- declared capabilities such as `describe`, `discover`, `read`, `execute`, `sync`, `health`
- credential and instance schema contracts
- resource type and action catalog declarations
- discovery, normalization, execution, and extension settings
- active runtime `describe` handshake verification against the live plugin before integration execution
- optional `guardian_support` describing canonical signals Heimdall can consume in lightweight mode
- support for custom/open-source adapters without hardcoding providers in the core
- a naming and responsibility convention:
  - substrate-specific installers should be explicit, such as `rabbitmq-kubernetes`
  - domain/runtime operators should keep the pure domain name, such as `rabbitmq` or `grafana`

`integration_instance` has:

- reference to one `integration_type`
- concrete credentials and instance config
- optional `credentials_ref` pointing at core-managed secrets
- console/API creation paths materialize inline credentials into managed secrets and persist `credentials_ref`
- owners and lifecycle status
- discovery scheduling/enablement
- runtime execution overrides such as batch size and default dry-run

`guardian_memory` has:

- one persisted record per Heimdall action attempt
- execution details such as `attempted_at`, `completed_at`, and `error`
- later observed outcome after the sweep loop inspects the component again
- a reusable operational memory surface so the guardian can avoid repeating the same failed action blindly

`resource` has:

- canonical Yggdrasil resource identity
- normalized resource type and action set
- source lineage, including `integration_instance_ref` and `external_id`
- normalized attributes and optional raw provider payload
- ownership metadata for RBAC, policy, and future workflows

`surface` has:

- replaceable edge-runtime metadata such as `api`, `auth`, `console`, or `bff`
- runtime shape for HTTP/UI/worker entrypoints
- declared core contracts consumed by the surface
- explicit `integration_binding = core_only` to keep integrations owned by the core
- user-facing capabilities such as endpoints, auth flows, and UI areas
- `auth` as a first-class core contract when a surface fronts login/session behavior

`repository_binding` has:

- one ecosystem component to repository association
- deploy workflow and default branch hints for bounded automation
- explicit repository automation permissions such as workflow dispatch vs pull request automation
- optional metadata used by guardians and future repo-aware workflows

`guardian_policy` has:

- one guardian instance selector
- auto-heal severity threshold, cooldown, and max-action limits
- explicit allow/deny gates for workflow dispatch, secret rotation, and right-sizing
- repository automation and cost-optimization boundaries

`remediation_contract` has:

- one component selector by `component_kind`, `component_namespace`, and `component_name`
- one or more named bounded remediation actions such as `rightsize_component`
- an explicit execution mode, currently `workflow_dispatch`
- an `auto_execute` flag per action so guardians only run opt-in playbooks
- optional workflow defaults and remediation-specific inputs forwarded to the repo workflow

`product` has:

- category and class metadata for platform product taxonomy
- owners and lifecycle metadata
- one or more components with explicit `source`, `renderer`, `target`, and `reconcile` contracts
- `requires` for external preconditions such as products, resources, and integration instances
- `integration` as an optional source kind for installation components generated by ecosystem plugins in a governed way
- `raw_k8s` as the primary delivery mode for internal products
- `kustomize` as the preferred Git-native composition mode for internal services
- `helm` only as an optional compatibility mode for upstream/vendor or OCI-hosted artifacts
- inline object bundles for importing legacy rendered manifests directly into the core
- no dedicated `chart` kind; Helm is intentionally modeled through `source + renderer`

`workflow` has:

- trigger metadata and typed runtime input schema
- manifest-level `defaults` merged with runtime inputs before validation and rendering
- ordered `steps` with `depends_on`, `retry`, and per-step timeout support
- integration-backed execution with template rendering from `inputs`, `metadata`, `auth`, and previous `steps`
- generic step execution through integration `operation + capability`, not only provider-specific dispatch wrappers
- fail-fast orchestration semantics with step-level audit results
- a transitional bootstrap wrapper for GitHub workflow dispatch so edge services can move to `workflow.run` without rewriting topology first

## Product delivery guidance

For internal Yggdrasil services, the preferred order is:

1. `git + raw_k8s`
2. `git + kustomize`
3. `git/oci + helm` only when compatibility with an existing chart ecosystem is actually needed

This keeps delivery ownership close to the service repository and avoids a centralized chart repository becoming a second source of truth.

## Core identities

`collaborator` and `team` are core entities, not manifest kinds.

The worker now stores:

- `collaborators`
- `teams`
- `team_memberships`
- `collaborator_password_credentials`
- `collaborator_third_party_identities`
- `auth_sessions`

The direct core auth endpoints are:

- `POST /api/v1/auth/passwords`
- `POST /api/v1/auth/login`
- `POST /api/v1/auth/third-party/login`
- `GET /api/v1/auth/third-party/start/{provider}`
- `GET /api/v1/auth/third-party/callback/{provider}`
- `GET /api/v1/auth/third-party-identities`
- `POST /api/v1/auth/third-party-identities`
- `DELETE /api/v1/auth/third-party-identities/{provider}/{subject}`
- `GET /api/v1/auth/providers`
- `POST /api/v1/auth/providers`
- `GET /api/v1/auth/providers/{provider}`
- `DELETE /api/v1/auth/providers/{provider}`
- `GET /api/v1/auth/session`
- `POST /api/v1/auth/logout`
- `GET /healthz`
- `GET /readyz`

Additional direct core endpoints now include:

- `/api/v1/collaborators`
- `/api/v1/teams`
- `/api/v1/team-memberships`
- `/api/v1/integration-catalog`
- `/api/v1/catalog/discovery`
- `/api/v1/catalog/discovery/register`
- `/api/v1/integration-instances`
- `/api/v1/secrets`
- `/api/v1/secrets/{namespace}/{name}/rotate`
- `/api/v1/secrets/{namespace}/{name}/disable`
- `/api/v1/secrets/{namespace}/{name}/revoke`
- `/api/v1/products`
- `/api/v1/repository-bindings`
- `/api/v1/guardian-policies`
- `/api/v1/surfaces`
- `/api/v1/workflows`
- `/api/v1/workflow-runs`

`POST /api/v1/workflow-runs` is the synchronous dog-food entrypoint for CI and
repository automation. It executes one stored workflow manifest directly over
HTTP instead of RabbitMQ.

When `YGGDRASIL_WORKFLOW_RUN_TOKEN` is configured on the core, callers must
send either:

- `X-Yggdrasil-Workflow-Token: <token>`
- `Authorization: Bearer <token>`

When RabbitMQ is enabled, the core also starts the periodic Heimdall guardian
loop. The interval is controlled by:

- `HEIMDALL_GUARDIAN_LOOP_INTERVAL_SECONDS`

Heimdall autonomy is controlled by `guardian_policy.spec.autonomy`:

- `policy_bound`: bounded actions execute directly inside policy limits
- `approval_required`: actions are persisted as `guardian_approval` manifests and wait for human approval
- `bypass_hotfix`: critical auto-remediation can bypass approval, while lower-risk actions still require approval

When approval is granted through the HTTP API or console path, the core now
executes the stored action and records the approval as `executed`.

The core also stores `guardian_memory` entries for Heimdall actions. Those
entries let later sweeps compare "what we tried" with "what the ecosystem looked
like afterward", which is the basis for learned remediation behavior.

The intended split is:

- `yggdrasil-core` owns credential verification and session persistence
- `yggdrasil-core` owns third-party identity links and external session issuance
- `yggdrasil-core` owns third-party auth provider configuration and browser OAuth/OIDC flow
- `yggdrasil-auth-surface` stays a thin collaborator-facing edge that proxies login/session/logout

The intended authorization flow is:

1. an edge service sends `collaborator_id` to the core
2. the core loads the collaborator and active team memberships
3. the core expands the effective subjects, including recursive `parent_team_id` inheritance
4. RBAC evaluates the expanded subject set
5. policy refines the authorized request with runtime input

Canonical effective subjects:

- `collaborator:<slug>`
- `team:<slug>`

## Topology authorization

`yggdrasil-core.topology.access.evaluate` no longer reads the legacy `permissions` model.
It now resolves authorization through:

1. collaborator identity from `collaborators.third_party_identities`
2. recursive collaborator/team subject expansion
3. a topology document of kind `authorization`
4. the normal `rbac + optional policy` pipeline

The `authorization` document is resolved from the requested node upward through the topology
parent chain, so projects can define one auth contract and child nodes can inherit it.

Recommended authorization document body:

```json
{
  "rbac": {
    "namespace": "global",
    "name": "topology-access"
  },
  "policy": {
    "namespace": "global",
    "name": "topology-access-conditions"
  },
  "resource": "core.topology.node.3d60f9c0-2d72-4d1d-b99f-767d6dd0a6b5",
  "input": {
    "context": {
      "surface": "yggdrasil-auth-surface"
    }
  }
}
```

When `resource` is omitted, the default resource is:

- `core.topology.node.<node-id>`

The evaluator checks the actions in this order:

1. `manage`
2. `write`
3. `read`

The first allowed action becomes the returned authority:

- `manage` -> `2`
- `write` -> `1`
- `read` -> `0`

## RabbitMQ RPC queues

- `yggdrasil-core.manifest.validate`
- `yggdrasil-core.manifest.create`
- `yggdrasil-core.manifest.list`
- `yggdrasil-core.manifest.get`
- `yggdrasil-core.manifest.rbac.evaluate`
- `yggdrasil-core.manifest.policy.evaluate`
- `yggdrasil-core.authorization.evaluate`
- `yggdrasil-core.integration.execute`
- `yggdrasil-core.integration.status.get`
- `yggdrasil-core.integration.status.list`
- `yggdrasil-core.integration.instance_health.get`
- `yggdrasil-core.integration.instance_health.list`
- `surface` manifests are stored through the generic manifest queues above
- `yggdrasil-core.product.materialize`
- `yggdrasil-core.product.installation.reconcile`
- `yggdrasil-core.product.installation.apply`
- `yggdrasil-core.product.installation.observe`
- `yggdrasil-core.product.installation_state.discover`
- `yggdrasil-core.workflow.dispatch`
- `yggdrasil-core.workflow.run`
- `yggdrasil-core.collaborator.create`
- `yggdrasil-core.collaborator.update`
- `yggdrasil-core.collaborator.delete`
- `yggdrasil-core.collaborator.get`
- `yggdrasil-core.collaborator.list`
- `yggdrasil-core.topology.node.upsert`
- `yggdrasil-core.topology.node.get`
- `yggdrasil-core.topology.node.children`
- `yggdrasil-core.topology.edge.upsert`
- `yggdrasil-core.topology.edge.list`
- `yggdrasil-core.topology.document.upsert`
- `yggdrasil-core.topology.document.get`
- `yggdrasil-core.topology.document.list`
- `yggdrasil-core.topology.document.value`
- `yggdrasil-core.topology.access.evaluate`
- `yggdrasil-core.topology.build_project.create`
- `yggdrasil-core.topology.build_project.get`
- `yggdrasil-core.topology.build_project.list`
- `yggdrasil-core.topology.build_project.delete`
- `yggdrasil-core.team.create`
- `yggdrasil-core.team.update`
- `yggdrasil-core.team.delete`
- `yggdrasil-core.team.get`
- `yggdrasil-core.team.list`
- `yggdrasil-core.team.membership.upsert`
- `yggdrasil-core.team.membership.list`

Each queue expects an RPC-style message:

- JSON body with the request payload
- `reply_to` set to the response queue
- `correlation_id` set by the caller
- JSON response with `{ "ok": true|false, "data": ..., "error": ... }`

## Adapter handshake

`integration_type` is the contract the core stores. The adapter itself runs outside the core and implements the queue names declared in the manifest.

## Plugin catalog convention

Yggdrasil now treats integrations as catalog entries grouped by domain. The catalog shape is:

1. domain
2. section
3. entry

The canonical metadata labels for `integration_type` are:

- `yggdrasil.io/catalog-domain`
- `yggdrasil.io/catalog-section`
- `yggdrasil.io/catalog-entry`

The practical rule is:

- the repository name and `integration_type.metadata.name` stay explicit and honest
- the catalog groups those explicit plugins under one domain for discovery and UX

Example:

- domain `rabbitmq`
- section `installations`
- entry `kubernetes`
- concrete plugin `rabbitmq-kubernetes`

Later, the same catalog domain can also contain:

- domain `rabbitmq`
- section `operations`
- entry `api`
- concrete plugin `rabbitmq`

This gives Yggdrasil a stable catalog for open-source distribution without hiding implementation
truth. Consumers browse one domain such as `rabbitmq`, then choose only the section and entry they
want to run.

Integrations are associated directly with the core, not with any surface. A surface can ask the
core to execute workflows, products, or generic integration operations, but it does not own the
plugin lifecycle or adapter contract.

The current section convention is:

1. `installations`
2. `operations`

`installations` is for substrate-specific placement of a system:

- `rabbitmq-kubernetes`
- `grafana-kubernetes`
- future `*-on-vm`, `*-on-nomad`, `*-on-ecs`

`operations` is for runtime and governance after the system exists:

- `rabbitmq` for `vhost`, `user`, `permission`, `queue`, `exchange`
- `grafana` for `dashboard`, `datasource`, `folder`, `alert`
- `github` for repositories, workflows, teams, environments, secrets
- `aws` for S3, ECR, and Secrets Manager governance
- `gcp` for build runtimes plus Artifact Registry, Storage, and Secret Manager governance
- `kubernetes` for cluster object apply and observation

The important rule is that installation and operation are allowed to start together in one plugin
only when the domain is still small. Once the operational surface becomes meaningful, Yggdrasil
prefers to split them:

- `domain-on-substrate` handles installation and substrate-specific concerns
- plain domain name handles runtime and governance concerns

This keeps plugins honest, keeps `describe` contracts smaller, and avoids turning one adapter into
a hidden monolith.

The catalog itself is derived from manifest metadata. Today that means `manifest.list` with label
filters is enough to build catalog views without provider-specific logic.

The core also exposes an explicit catalog API so consumers do not need to know label conventions:

- `yggdrasil-core.integration.catalog.list`
- `yggdrasil-core.integration.catalog.get`
- `yggdrasil-core.catalog.discover`

`integration.catalog.list` returns the catalog already grouped as:

- domain
- section
- entry

Each entry includes the concrete `integration_type`, adapter metadata, a representative runtime
state derived from configured instances, and `integration_instance` summaries with their own
observed health when available.

`integration.catalog.get` resolves one concrete catalog entry by:

- `domain`
- `section`
- `entry`

`catalog.discover` is the optional discovery surface. It does not replace the
explicit catalog persisted in the core. Instead, it asks one or more
discovery-capable integration instances for candidates and enriches them with
registration state:

- `registered`
- `unregistered`

That keeps the architecture clean:

- `registered` comes from manifests stored in the core
- `discovered` comes from optional scanners such as GitHub, GitLab, filesystem, or future registries
- surfaces never scan providers directly; they only consume the core response
- production traffic should prefer `GET /readyz`, which verifies database reachability and transport availability

The minimum recommended adapter RPC surface is:

- `describe`
- `discover`
- `read`
- `execute`
- `sync`
- `health`

`describe` is mandatory in the current validation model because it is how the core can introspect custom/open-source adapters without provider-specific logic.

The current operational guidance is:

- `describe` must reflect the real adapter surface
- `integration_type` is the stored declared contract
- the core compares stored contract vs live adapter contract before execution
- the core persists handshake state and can fast-fail unhealthy integrations
- plugin naming should communicate whether the adapter is about installation/substrate or runtime/operation

Recommended `describe` request:

```json
{
  "provider": "github",
  "expected_version": "1.0.0"
}
```

Recommended `describe` response:

```json
{
  "provider": "github",
  "adapter": {
    "transport": "rabbitmq",
    "version": "1.0.0",
    "queues": {
      "describe": "yggdrasil.adapter.github.describe",
      "discover": "yggdrasil.adapter.github.discover",
      "read": "yggdrasil.adapter.github.read",
      "execute": "yggdrasil.adapter.github.execute",
      "sync": "yggdrasil.adapter.github.sync",
      "health": "yggdrasil.adapter.github.health"
    },
    "timeout_seconds": 30
  },
  "capabilities": ["describe", "discover", "read", "execute", "sync", "health"]
}
```

Recommended `discover` request:

```json
{
  "instance_ref": {
    "name": "github-dakasa-prod",
    "namespace": "global"
  },
  "cursor": "cursor-v1",
  "limit": 100
}
```

Recommended `discover` response:

```json
{
  "next_cursor": "cursor-v2",
  "resources": [
    {
      "external_id": "R_kgDOExample",
      "type": "repository",
      "name": "api",
      "owner": "dakasa",
      "canonical_resource": "thirdparty.github.org.dakasa.repo.api",
      "actions": ["read", "update", "grant", "revoke"],
      "attributes": {
        "visibility": "private"
      },
      "raw": {
        "provider": "github"
      }
    }
  ]
}
```

## Authorization pipeline

`yggdrasil-core.authorization.evaluate` is the unified authorization entrypoint.

The pipeline works like this:

1. load the referenced RBAC manifest
2. resolve the collaborator and active team memberships when `collaborator_id` is provided
3. expand the effective subjects for RBAC, including ancestor teams through `parent_team_id`
4. stop with `deny` when RBAC does not allow the request
5. optionally load the referenced policy manifest
6. evaluate the policy against `resource + action + input`
7. return the final decision with RBAC and policy traces

Decision semantics:

- RBAC `deny` or no RBAC match => final `deny`
- RBAC `allow` + no policy manifest => final `allow`
- RBAC `allow` + policy `allow` => final `allow`
- RBAC `allow` + policy `not_applicable` => final `allow`
- RBAC `allow` + policy `deny` => final `deny`

The authorization evaluator also injects:

- `subject` with the primary effective subject when it is missing
- `subjects` with all effective subjects when it is missing
- `collaborator` when the request is driven by `collaborator_id`
- `teams` when the request is driven by `collaborator_id`

## Example authorization evaluate payload

```json
{
  "rbac": {
    "name": "global-rbac",
    "namespace": "global"
  },
  "policy": {
    "name": "payment-policy",
    "namespace": "global"
  },
  "collaborator_id": "col:ana",
  "resource": "payment.invoice",
  "action": "approve",
  "input": {
    "subject": {
      "department": "finance"
    },
    "context": {
      "amount": 9500
    }
  }
}
```

## Example authorization response

```json
{
  "ok": true,
  "data": {
    "allowed": true,
    "decision": "allow",
    "resolved_subjects": [
      { "type": "collaborator", "id": "col:ana" },
      { "type": "team", "id": "team:finance" }
    ],
    "collaborator": {
      "slug": "col:ana",
      "status": "active"
    },
    "teams": [
      {
        "slug": "team:finance",
        "name": "Finance",
        "type": "team"
      }
    ],
    "rbac": {
      "allowed": true,
      "decision": "allow",
      "manifest": {
        "kind": "rbac",
        "namespace": "global",
        "name": "global-rbac",
        "version": 1
      },
      "matched_roles": ["payment-approver"]
    },
    "policy": {
      "allowed": true,
      "decision": "allow",
      "manifest": {
        "kind": "policy",
        "namespace": "global",
        "name": "payment-policy",
        "version": 1
      }
    }
  }
}
```

## Manifest feature summary

- manifests are versioned and only one active version exists per `kind + namespace + name`
- `rbac` defines roles, bindings, and coarse-grained access by subject, resource, and action
- `policy` refines access with runtime conditions over arbitrary input
- `integration_type` declares how external adapters describe, discover, and operate provider resources
- `integration_instance` describes one installed adapter configuration in a versioned way
- `resource` stores the canonical resource catalog produced by core systems and integrations
- `surface` stores the replaceable edge runtimes that talk to the core
- `product` replaces the legacy product bundle repository through versioned `source + renderer + target` components
- `workflow` replaces rigid provider-specific orchestration with manifest-driven, integration-backed execution
- `requires` lets one component declare infrastructure and operator preconditions in a typed way
- integrations can generate governed installation components through `source.kind = integration`
- integrations can also reconcile and inspect installation state through adapter operations without moving source of truth out of the core
- `workflow.run` is the canonical orchestration entrypoint, while `workflow.dispatch` remains available as a low-level direct-dispatch queue
- internal delivery is intentionally Git-first; Helm is supported, but it is not the platform default
- collaborators and teams are operational core entities that feed the authorization context
- team hierarchy is inherited recursively during authorization subject expansion
- HTTP is the synchronous ingress path for surfaces, while RabbitMQ remains the current optional async transport for integrations
- every authorization response is audit-friendly because it returns resolved subjects, manifest references, and matched rules

## Workflow catalog convention

For build/deploy workflows consumed by edge runtimes, the recommended convention is:

- `kind: workflow`
- namespace: `global` unless there is a clear tenant boundary
- labels:
  - `workflow_type=deployment`
  - `workflow_build_name=<build-name>`
  - `workflow_env_type=<env-type>`
  - `workflow_component_id=<component-uuid>` when the workflow targets one component

The manifest should store stable dispatch defaults in `spec.defaults`, for example:

- `repository`
- `workflow`
- `ref`
- `inputs`

Runtime callers then send only contextual overrides such as `ref`, `build_name`, `env_type`, and `component_id`.

The bootstrap workflow
[`ecosystem-repository-commit.json`](/Users/dakasa/projects/yggdrasil/services/yggdrasil-core/docs/bootstrap/manifests/workflows/ecosystem-repository-commit.json)
is the reference dog-food template for this flow. Repository GitHub Actions can
POST one commit event into `/api/v1/workflow-runs`, and the core will dispatch
that repository's `deploy.yml` through the configured global GitHub
integration.

## Example RBAC manifest payload

```json
{
  "apiVersion": "yggdrasil.io/v1alpha1",
  "kind": "rbac",
  "metadata": {
    "name": "global-rbac",
    "namespace": "global",
    "description": "Core authorization rules"
  },
  "spec": {
    "roles": [
      {
        "name": "core-admin",
        "rules": [
          {
            "effect": "allow",
            "resources": ["manifest.*"],
            "actions": ["*"]
          }
        ]
      }
    ],
    "bindings": [
      {
        "name": "platform-admins",
        "subjects": [
          { "type": "team", "id": "platform" }
        ],
        "roles": ["core-admin"]
      }
    ]
  }
}
```

## Example policy manifest payload

```json
{
  "apiVersion": "yggdrasil.io/v1alpha1",
  "kind": "policy",
  "metadata": {
    "name": "payment-policy",
    "namespace": "global",
    "description": "Conditional approval limits"
  },
  "spec": {
    "rules": [
      {
        "name": "finance-small-approvals",
        "effect": "allow",
        "resources": ["payment.invoice"],
        "actions": ["approve"],
        "conditions": [
          { "key": "subject.department", "operator": "eq", "value": "finance" },
          { "key": "context.amount", "operator": "lte", "value": 10000 }
        ]
      },
      {
        "name": "deny-over-limit",
        "effect": "deny",
        "resources": ["payment.invoice"],
        "actions": ["approve"],
        "conditions": [
          { "key": "context.amount", "operator": "gt", "value": 10000 }
        ]
      }
    ]
  }
}
```

## Example integration_type manifest payload

```json
{
  "apiVersion": "yggdrasil.io/v1alpha1",
  "kind": "integration_type",
  "metadata": {
    "name": "github",
    "namespace": "global",
    "description": "GitHub adapter contract"
  },
  "spec": {
    "provider": "github",
    "adapter": {
      "transport": "rabbitmq",
      "version": "1.0.0",
      "queues": {
        "describe": "yggdrasil.adapter.github.describe",
        "discover": "yggdrasil.adapter.github.discover",
        "read": "yggdrasil.adapter.github.read",
        "execute": "yggdrasil.adapter.github.execute",
        "sync": "yggdrasil.adapter.github.sync",
        "health": "yggdrasil.adapter.github.health"
      },
      "timeout_seconds": 30
    },
    "capabilities": ["describe", "discover", "read", "execute", "sync", "health"],
    "credential_schema": {
      "mode": "secret_ref",
      "required": ["app_id", "installation_id", "private_key_ref"],
      "properties": {
        "app_id": { "type": "string" },
        "installation_id": { "type": "string" },
        "private_key_ref": { "type": "string", "secret": true }
      }
    },
    "instance_schema": {
      "mode": "inline",
      "required": ["organization"],
      "properties": {
        "organization": { "type": "string" }
      }
    },
    "resource_types": [
      {
        "name": "repository",
        "canonical_prefix": "thirdparty.github.org",
        "identity_template": "repo.{organization}.{name}",
        "discoverable": true,
        "default_actions": ["read", "create", "update", "delete", "grant", "revoke"]
      }
    ],
    "action_catalog": [
      {
        "name": "grant",
        "resource_types": ["repository"],
        "idempotent": true
      },
      {
        "name": "revoke",
        "resource_types": ["repository"],
        "idempotent": true
      }
    ],
    "discovery": {
      "mode": "hybrid",
      "cursor": "incremental",
      "supports_webhooks": true
    },
    "normalization": {
      "external_id_path": "node_id",
      "name_path": "name",
      "owner_path": "organization.login",
      "fallback_resource_prefix": "thirdparty.github.custom"
    },
    "execution": {
      "supports_dry_run": true,
      "idempotent_actions": ["grant", "revoke", "sync"]
    },
    "extensions": {
      "allow_custom_resource_types": true,
      "allow_custom_actions": true,
      "preserve_raw_payload": true
    }
  }
}
```

## Example integration_instance manifest payload

```json
{
  "apiVersion": "yggdrasil.io/v1alpha1",
  "kind": "integration_instance",
  "metadata": {
    "name": "github-dakasa-prod",
    "namespace": "global",
    "description": "Dakasa production GitHub installation"
  },
  "spec": {
    "type_ref": {
      "name": "github",
      "namespace": "global"
    },
    "status": "active",
    "owners": ["team:platform"],
    "credentials": {
      "private_key_ref": "secret://github/private-key",
      "app_id": "123456"
    },
    "config": {
      "organization": "dakasa"
    },
    "discovery": {
      "enabled": true,
      "mode": "hybrid",
      "sync_interval_seconds": 300
    },
    "execution": {
      "default_dry_run": false,
      "max_batch_size": 100
    }
  }
}
```

## Example resource manifest payload

```json
{
  "apiVersion": "yggdrasil.io/v1alpha1",
  "kind": "resource",
  "metadata": {
    "name": "github-dakasa-api-repo",
    "namespace": "global",
    "description": "Canonical catalog entry for dakasa/api"
  },
  "spec": {
    "resource": "thirdparty.github.org.dakasa.repo.api",
    "type": "repository",
    "display_name": "dakasa/api",
    "actions": ["read", "update", "grant", "revoke"],
    "owners": ["team:platform"],
    "source": {
      "kind": "integration",
      "integration_type_ref": {
        "name": "github",
        "namespace": "global"
      },
      "integration_instance_ref": {
        "name": "github-dakasa-prod",
        "namespace": "global"
      },
      "external_id": "R_kgDOExample",
      "external_type": "repository"
    },
    "attributes": {
      "visibility": "private",
      "archived": false
    },
    "raw": {
      "provider": "github"
    }
  }
}
```

## Example surface manifest payload

```json
{
  "apiVersion": "yggdrasil.io/v1alpha1",
  "kind": "surface",
  "metadata": {
    "name": "yggdrasil-auth-surface",
    "namespace": "global",
    "description": "Reference collaborator-facing auth surface"
  },
  "spec": {
    "category": "auth",
    "owners": ["team:platform"],
    "replaces": ["auth", "identities"],
    "integration_binding": "core_only",
    "runtime": {
      "kind": "http_api",
      "exposure": "collaborator",
      "port": 9090,
      "base_path": "/",
      "health_path": "/healthz"
    },
    "core_contracts": ["auth", "authorization", "collaborator", "surface"],
    "capabilities": [
      {
        "name": "collaborator-auth",
        "kind": "auth_flow",
        "audience": "collaborator"
      },
      {
        "name": "login",
        "kind": "endpoint",
        "audience": "collaborator",
        "path": "/api/v1/auth/login",
        "methods": ["POST"]
      },
      {
        "name": "session",
        "kind": "endpoint",
        "audience": "collaborator",
        "path": "/api/v1/auth/session",
        "methods": ["GET"]
      },
      {
        "name": "logout",
        "kind": "endpoint",
        "audience": "collaborator",
        "path": "/api/v1/auth/logout",
        "methods": ["POST"]
      }
    ]
  }
}
```

## Example product manifest payload

```json
{
  "apiVersion": "yggdrasil.io/v1alpha1",
  "kind": "product",
  "metadata": {
    "name": "cert-manager",
    "namespace": "global",
    "description": "Platform product replacing the legacy rendered bundle repository"
  },
  "spec": {
    "category": "certificate",
    "class": "platform",
    "owners": ["team:platform"],
    "lifecycle": {
      "tier": "critical",
      "stage": "production"
    },
    "components": [
      {
        "name": "cert-manager-bundle",
        "source": {
          "kind": "inline",
          "objects": [
            {
              "apiVersion": "v1",
              "kind": "Namespace",
              "metadata": {
                "name": "cert-manager"
              }
            }
          ]
        },
        "renderer": {
          "kind": "raw_k8s"
        },
        "target": {
          "kind": "kubernetes",
          "integration_instance_ref": {
            "name": "kubernetes-platform-prod",
            "namespace": "global"
          },
          "namespace": "cert-manager"
        },
        "reconcile": {
          "strategy": "apply",
          "prune": true
        }
      },
      {
        "name": "identities-api",
        "source": {
          "kind": "git",
          "integration_instance_ref": {
            "name": "github-dakasa-prod",
            "namespace": "global"
          },
          "locator": "github.com/dakasa-co/identity-service",
          "revision": "main"
        },
        "renderer": {
          "kind": "kustomize",
          "path": "deploy/overlays/prod"
        },
        "target": {
          "kind": "kubernetes",
          "integration_instance_ref": {
            "name": "gke-apps-prod",
            "namespace": "global"
          },
          "namespace": "identities"
        },
        "reconcile": {
          "strategy": "sync",
          "prune": true,
          "wait": true
        }
      }
    ]
  }
}
```

## Example product Helm compatibility payload

```json
{
  "apiVersion": "yggdrasil.io/v1alpha1",
  "kind": "product",
  "metadata": {
    "name": "external-vendor-app",
    "namespace": "global",
    "description": "Product using Helm only because the upstream artifact already exists that way"
  },
  "spec": {
    "category": "vendor",
    "class": "platform",
    "owners": ["team:platform"],
    "components": [
      {
        "name": "vendor-chart",
        "source": {
          "kind": "oci",
          "integration_instance_ref": {
            "name": "artifact-registry-prod",
            "namespace": "global"
          },
          "locator": "oci://us-central1-docker.pkg.dev/dakasa/charts/component-api",
          "version": "1.2.3"
        },
        "renderer": {
          "kind": "helm",
          "values": {
            "namespace": "identities"
          }
        },
        "target": {
          "kind": "kubernetes",
          "integration_instance_ref": {
            "name": "gke-apps-prod",
            "namespace": "global"
          },
          "namespace": "identities"
        },
        "reconcile": {
          "strategy": "sync",
          "prune": true,
          "wait": true
        }
      }
    ]
  }
}
```

## Example integration-generated product payload

```json
{
  "apiVersion": "yggdrasil.io/v1alpha1",
  "kind": "product",
  "metadata": {
    "name": "rabbitmq-kubernetes-platform",
    "namespace": "global",
    "description": "Product component generated by a RabbitMQ integration blueprint"
  },
  "spec": {
    "category": "messaging",
    "class": "platform",
    "owners": ["team:platform"],
    "components": [
      {
        "name": "rabbitmq-foundation",
        "source": {
          "kind": "integration",
          "integration_instance_ref": {
            "name": "rabbitmq-kubernetes-platform-prod",
            "namespace": "global"
          },
          "operation": "generate_installation",
          "input": {
            "blueprint": "shared-broker",
            "environment": "prod",
            "namespace": "rabbitmq-system"
          }
        },
        "renderer": {
          "kind": "raw_k8s"
        },
        "target": {
          "kind": "kubernetes",
          "integration_instance_ref": {
            "name": "kubernetes-platform-prod",
            "namespace": "global"
          },
          "namespace": "rabbitmq-system"
        },
        "reconcile": {
          "strategy": "apply",
          "prune": true,
          "wait": true
        }
      }
    ]
  }
}
```

`source.kind = integration` is intentionally narrow in this first version:

- the integration request is declared through `integration_instance_ref + operation + optional capability + input`
- the initial supported renderer is `raw_k8s`
- the goal is to let plugins generate governed installations without turning product delivery into opaque runtime-only behavior

Component-level `requires` adds a typed precondition layer on top of `depends_on`:

- `depends_on` orders components inside the same product
- `requires` points to external prerequisites such as `product`, `integration_instance`, or `resource`
- `policy = install_if_missing` can now also pull dependent product applies/observations forward when target execution runs

`yggdrasil-core.product.materialize` resolves a stored product, rewrites `source.kind = integration`
components into inline object bundles, and stores an immutable audit snapshot in
`product_materializations`.

When the core materializes an integration-backed component, it calls the integration
`execute` queue with an installation-oriented `operation` such as `generate_installation` and passes:

- the resolved product reference and component context
- the resolved `integration_instance` manifest reference and spec
- the resolved `integration_type` manifest reference and spec
- the declared `operation`
- the optional plugin-defined `capability`
- the user-declared `input`

The adapter returns raw Kubernetes objects, and the core persists the resulting materialized
product spec together with component-level trace metadata.

The core persists observed adapter runtime state for each `integration_instance` under explicit
checks such as:

- `transport_connectivity`
- `describe_handshake`

The current statuses are:

- `healthy`
- `contract_mismatch`
- `invalid_response`
- `unreachable`

These states are queryable through:

- `yggdrasil-core.integration.status.get`
- `yggdrasil-core.integration.status.list`

The core also derives a higher-level health view per `integration_instance`. For active instances,
the default `overall` view combines both `transport_connectivity` and `describe_handshake`,
fast-failing when either recent check is unhealthy. If one of those checks is still missing and the
known checks are healthy, the overall status remains `unknown`. Non-active instances still return
their declared manifest status such as `draft` or `disabled`.

These views are queryable through:

- `yggdrasil-core.integration.instance_health.get`
- `yggdrasil-core.integration.instance_health.list`

In addition, the worker now runs a periodic background sweep that rechecks active
`integration_instance` transport connectivity and describe handshakes. The interval defaults to
`60s` and can be overridden with `INTEGRATION_RUNTIME_MONITOR_INTERVAL_SECONDS`.

After generation, the core also exposes two explicit installation RPC flows:

- `yggdrasil-core.product.installation.reconcile`
- `yggdrasil-core.product.installation.apply`
- `yggdrasil-core.product.installation.observe`
- `yggdrasil-core.product.installation_state.discover`

`reconcile` asks the plugin to return an installation execution plan for each integration-backed component.
In the current RabbitMQ adapter this comes back as `mode = declarative_apply` plus the desired objects, which keeps the flow honest until a Kubernetes target integration performs the actual apply.

`apply` uses that reconciliation plan and forwards the desired objects to the declared target integration.
In the current model this means the source integration describes the installation and the Kubernetes target integration performs the actual server-side apply.

`observe` uses the same desired object set and asks the target integration for live object state.
This is the first target-side runtime loop, and it is how installation plugins stop being blind after generation.

`discover` asks the plugin for the currently known installation state of each integration-backed component.
In the current RabbitMQ adapter this is blueprint-derived state, not a live cluster read, and the response marks that distinction through `observed = false`.

## Local development

Run the worker:

```bash
task run
```

Run migrations:

```bash
task migrate:up
```

Run tests:

```bash
go test ./...
```

## Bootstrap assets

Bootstrap product manifests live in `docs/bootstrap/manifests/products`.

Bootstrap manifests can be imported into PostgreSQL with:

```bash
task postgres:ensure-db
task migrate:up
task bootstrap:dry-run
task bootstrap:import
```

## Next steps

- add manifest dependency resolution and composition
- add signature/audit flows for promoted manifests
