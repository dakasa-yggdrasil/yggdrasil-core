# RPC transport migration — handler refactor plan

This directory ships the generic `rpc.Transport` contract and two
implementations (`rpc/amqp`, `rpc/http`). The AMQP addon already
exposes the transport via `addons.RPCTransport(app)`. The dual-backend
end-to-end test in `rpc/http/http_test.go` proves the abstraction
does not leak AMQP specifics.

**What's left**: the 18 handler files in `controllers/message/*.go`
still accept `amqp.Delivery` directly and resolve outbound calls via
`*amqp.Connection`. They need to migrate to `rpc.Delivery` +
`rpc.Transport`. This is mechanical but extensive (~8700 LOC).

## Migration order (per-file commits recommended)

Ordered by size so small wins come first and big refactors get
their own PR:

| # | File | LOC | Notes |
|---|---|---|---|
| 1 | `register.go` | 36 | Accept `rpc.Transport`, iterate consumer configs, call `transport.Consume`. |
| 2 | `rpc_client.go` | 91 | `callRabbitRPC` → `callRPC(ctx, transport, endpoint, req, resp)`. |
| 3 | `manifest_persist.go` | 92 | Already helper-only; mostly typing changes. |
| 4 | `workflows_yggdrasil.go` | 112 | Single handler; straightforward. |
| 5 | `integration_monitor.go` | 162 | Background loop that consumes transport; swap `conn` → `transport`. |
| 6 | `adapter_transport.go` | 217 | Retire the embedded `*amqp.Connection`; use `rpc.Transport` for the rabbitmq-transport path. |
| 7 | `identities.go` | 321 | Standard handler batch. |
| 8 | `integration_family_resolver.go` | 250 | Internal resolver; uses `conn` for outbound. |
| 9 | `topology.go` | 361 | Handler batch. |
| 10 | `integrations.go` | 357 | Handler batch + outbound calls. |
| 11 | `integration_health.go` | 372 | Health checks; outbound-heavy. |
| 12 | `manifests.go` | 651 | Includes the `replySuccess/Failure/JSON` helpers that every handler uses — migrate those first, then the handlers at the top of the file. |
| 13 | `integration_catalog.go` | 453 | Handler batch. |
| 14 | `catalog_discovery.go` | 484 | Handler batch. |
| 15 | `integration_describe.go` | 707 | The adapter describe flow; outbound-heavy. |
| 16 | `workflows.go` | 978 | The workflow engine; outbound RPC to adapters. |
| 17 | `products.go` | 1652 | Product materialization; largest non-heimdall file. |
| 18 | `consume.go` | 37 | Delete once every handler has moved to `rpc.Handler`. |

## The mechanical diff per handler file

For each file:

1. Remove `amqp "github.com/rabbitmq/amqp091-go"` import.
2. Add `"github.com/dakasa-yggdrasil/yggdrasil-core/internal/rpc"`.
3. Change handler signatures:
   - `func(ctx context.Context, d amqp.Delivery) error`
   - → `func(ctx context.Context, d rpc.Delivery) error`
4. Update field access:
   - `d.Body` → stays (struct field, same name)
   - `d.ReplyTo` → stays
   - `d.CorrelationId` → `d.CorrelationID` (Go-convention rename)
   - `d.Headers` → stays
   - `d.ContentType` → stays
5. Update methods:
   - `d.Ack(false)` → `d.Ack()`
   - `d.Nack(false, false)` → `d.Nack(false)`
   - `d.Nack(false, true)` → `d.Nack(true)`
6. Replace outbound calls:
   - `ch, err := conn.Channel(); ch.PublishWithContext(...)` → `transport.Publish(ctx, rpc.Request{...})`
   - `callRabbitRPC(ctx, conn, queue, req, resp)` → `callRPC(ctx, transport, endpoint, req, resp)`
7. Replace `conn *amqp.Connection` parameters with `transport rpc.Transport`.

## The `replySuccess/Failure/JSON` triangle

These three helpers in `manifests.go` are called from 181 sites. Their
signature currently takes `conn *amqp.Connection`. After migration
they take nothing extra — reply goes through `d.Reply(ctx, body,
contentType)` which the transport already populated.

**Before**:
```go
func replySuccess(ctx context.Context, conn *amqp.Connection, d amqp.Delivery, data any, logger *zap.Logger) error {
    // ... build body ...
    ch, _ := conn.Channel()
    ch.PublishWithContext(ctx, "", d.ReplyTo, false, false, amqp.Publishing{ ... })
}
```

**After**:
```go
func replySuccess(ctx context.Context, d rpc.Delivery, data any, logger *zap.Logger) error {
    body, _ := json.Marshal(rpcResponse{OK: true, Data: data})
    return d.Reply(ctx, body, "application/json")
}
```

All 181 callers drop the `conn` argument. This is the single most
impactful step — every handler file has at least one call to these.

## Completion criterion

- `go test ./...` stays green throughout (each handler file is its
  own commit; build stays green after each merge).
- `grep -rln "amqp091" controllers/message/` returns zero after the
  last handler migrates.
- `addons/rabbitmq.go` constructs `rpc.Transport` and hands it to
  `message.RegisterAllConsumers(transport, db, logger)`. The raw
  `*amqp.Connection` is no longer passed around.
- A future `YGGDRASIL_RPC_TRANSPORT=http` env var swaps in the HTTP
  transport without any handler touching its implementation.

## References

- `transport.go` — public interface + types.
- `amqp/amqp.go` — AMQP 0-9-1 implementation.
- `http/http.go` — HTTP implementation + `http/http_test.go` for the
  end-to-end proof.
- `addons/rabbitmq.go` — transport bootstrap (currently AMQP-only;
  will dispatch on env var once migration completes).
