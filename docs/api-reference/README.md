# Yggdrasil REST API

The synchronous HTTP surface of `yggdrasil-core`. All endpoints are JSON; default port is 9080.

## Where to start

| Document | Use when |
|---|---|
| [openapi.json](./openapi.json) | Feeding Postman, Swagger UI, or generating client SDKs |
| [openapi.md](./openapi.md) | Reading prose explanations of the API model (auth, manifests, templating, signing) |
| The endpoints below | Looking up a single endpoint quickly |

The OpenAPI spec is also served by the running instance at `GET /openapi.json` (no auth) so external tools can fetch the live contract.

## Endpoint index

### Health

| Method | Path | Purpose |
|---|---|---|
| GET | `/` | Banner |
| GET | `/healthz` | Liveness (text/plain `ok`) |
| GET | `/readyz` | Readiness (checks Postgres) |
| GET | `/openapi.json` | The bundled OpenAPI 3 spec |

### Manifests

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/v1/manifests?kind=<kind>` | List manifests (filterable by `namespace`, `name`) |
| POST | `/api/v1/manifests?kind=<kind>` | Create a new version of one manifest |

Supported `kind` values: `integration_family`, `integration_type`, `integration_instance`, `workflow`, `surface`, `repository_binding`, `secret_intent`, `product`, `control_plane`, `rbac`, `policy`, `guardian_*`, `remediation_*`.

### Integration runtime

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/v1/integration-instances` | List integration_instance manifests |
| POST | `/api/v1/integration-instances` | Create one (typed shortcut for `POST /api/v1/manifests?kind=integration_instance`) |
| GET | `/api/v1/integration-runtime-states` | Diagnose adapter handshake / connectivity |

### Workflows

| Method | Path | Purpose |
|---|---|---|
| POST | `/api/v1/workflow-runs` | Run a workflow synchronously |

### Webhooks

| Method | Path | Purpose |
|---|---|---|
| POST | `/api/v1/github/webhook` | GitHub push events; routes via `repository_binding` lookup |

### Secrets (managed store)

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/v1/secrets` | List metadata (no values) |
| GET | `/api/v1/secrets/{namespace}/{name}` | Get one (metadata) |
| POST | `/api/v1/secrets` | Create |
| POST | `/api/v1/secrets/{namespace}/{name}/rotate` | Rotate (re-generate value) |
| POST | `/api/v1/secrets/{namespace}/{name}/disable` | Mark disabled |
| POST | `/api/v1/secrets/{namespace}/{name}/revoke` | Mark revoked |
| POST | `/api/v1/secrets/{namespace}/{name}/materialize` | Push to a managed Kubernetes Secret |
| POST | `/api/v1/secrets/materialize-all` | Push all active managed secrets |

### Products (informational since v2.0.0)

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/v1/products` | List product manifests |
| POST | `/api/v1/products` | Create one |
| POST | `/api/v1/products/{ns}/{name}/deploy` | **410 Gone** — use `repository_binding` instead |
| POST | `/api/v1/products/deploy-all` | **410 Gone** |

### Auth

| Method | Path | Purpose |
|---|---|---|
| POST | `/api/v1/auth/login` | Username/password, then `totp_code` when `mfa_required` is returned |
| POST | `/api/v1/auth/third-party/login` | Third-party identity exchange |
| GET | `/api/v1/auth/third-party/start/{provider}` | OIDC start |
| GET | `/api/v1/auth/third-party/callback/{provider}` | OIDC callback |

(See `docs/features/sessions.md` for the auth flow narrative.)

## See also

- [Quickstart](../quickstart.md) — build muscle memory
- [Tutorials](../tutorials/) — end-to-end stories
- [Features](../features/) — internal reference / deep dives
