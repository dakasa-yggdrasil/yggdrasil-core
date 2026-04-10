# Addons

`yggdrasil-core` keeps the base service intentionally small. Infrastructure-heavy pieces are generated on demand through `go run ./scripts/addons`.

## Available addons

### `auth`

Generates:

- `addons/auth.go`
- `controllers/auth.go`
- `securities/headers.go`
- `scripts/auth/main.go`

Use it when the service must protect routes with JWT and should gracefully accept both `X-JWT` and `Authorization: Bearer`.

### `postgres`

Generates:

- `psql/config.go`
- `psql/sql.go`
- `addons/postgres.go`
- `scripts/postgres/main.go`

Use it when the service needs PostgreSQL access.

### `goose`

Generates:

- `db/migrations/00001_initial.sql`
- `scripts/goose/main.go`

This addon depends on `postgres` and will generate it automatically when needed.

### `redis`

Generates:

- `store/redis.go`
- `addons/redis.go`
- `scripts/redis/main.go`

Use it when the service needs Redis-backed caching, locks, or lightweight coordination.

### `rabbitmq`

Generates:

- `controllers/message/consume.go`
- `controllers/message/register.go`
- `addons/rabbitmq.go`
- `scripts/rabbitmq/main.go`

Use it when the service needs asynchronous messaging.

### `observability`

Generates:

- `addons/observability.go`
- `scripts/observability/main.go`

Use it when the service should adopt the standard DaKasa observability stack with zap logging, panic recovery, and Prometheus HTTP middleware.

### `outbox`

Generates:

- `addons/outbox.go`
- `auxiliary/outbox.go`
- `store/outbox_redis.go`
- `db/migrations/00002_outbox_critical.sql`
- `scripts/outbox/main.go`

This addon depends on `postgres`, `redis`, and `rabbitmq`. Use it when the service publishes domain events and should follow the DaKasa fast/critical outbox pattern.

### `temporal`

Generates:

- `addons/temporal.go`
- `controllers/temporal.go`
- `temporal/client.go`
- `temporal/example.go`
- `scripts/temporal/main.go`

Use it when the service owns workflows or activities and needs a first-class Temporal bootstrap.

### `websocket`

Generates:

- `addons/websocket.go`
- `controllers/websocket.go`
- `realtime/hub.go`
- `scripts/websocket/main.go`

Use it when the service needs lightweight realtime push endpoints without introducing a separate dedicated RTA service yet.

## Typical flows

### Production-style API baseline

```bash
go run ./scripts/addons add --name observability
go run ./scripts/addons add --name auth
```

### HTTP + PostgreSQL + Goose

```bash
go run ./scripts/addons add --name postgres
go run ./scripts/addons add --name goose
```

### HTTP + RabbitMQ + Redis

```bash
go run ./scripts/addons add --name redis
go run ./scripts/addons add --name rabbitmq
```

### Full common DaKasa stack

```bash
go run ./scripts/addons add --name postgres
go run ./scripts/addons add --name goose
go run ./scripts/addons add --name redis
go run ./scripts/addons add --name rabbitmq
go run ./scripts/addons add --name observability
go run ./scripts/addons add --name auth
go run ./scripts/addons add --name outbox
```

### Workflow-heavy service

```bash
go run ./scripts/addons add --name observability
go run ./scripts/addons add --name temporal
```

### HTTP + lightweight realtime

```bash
go run ./scripts/addons add --name observability
go run ./scripts/addons add --name websocket
```
