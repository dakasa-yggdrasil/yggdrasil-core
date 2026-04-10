# Yggdrasil Event Contracts v1

Language-agnostic contracts for events emitted by `yggdrasil-core` over its
state change event stream. Consumers in any language parse events as JSON
and validate against these schemas.

## Structure

- `schema.json` — Base event schema (common fields for all events)
- `manifest/` — Events about manifest mutations (created, updated, deactivated)
- `product/` — Events about product lifecycle (materialized, applied, observed)
- `workflow/` — Events about workflow execution (dispatched, started, completed)
- `authorization/` — Events about authorization decisions
- `buildproject/` — Events about BuildProject lifecycle (future, see Gap 4 spec)
- `topology/` — Events about topology mutations (future)
- `integration/` — Events about integration runtime (future)

## How to Consume Events

Events are consumed via the RPC `yggdrasil-core.event_stream.pull`:

1. Initialize cursor to `""` (empty string) or omit.
2. Call `event_stream.pull` with the cursor, optional filters, and a limit.
3. Process returned events.
4. Save `next_cursor` for your next call.
5. Repeat. If `has_more` is `false`, the stream is caught up — wait briefly
   before polling again.

### Filters

- `types` — array of event type patterns; wildcards allowed (e.g. `manifest.*`)
- `aggregate_type` — single aggregate type filter
- `aggregate_id` — single aggregate id filter
- `supported_schema_versions` — array of schema versions your consumer handles
- `emitted_after` — RFC 3339 timestamp; only events after this time

### Example (Python)

```python
import requests

cursor = ""
while True:
    response = call_rpc("event_stream.pull", {
        "cursor": cursor,
        "limit": 100,
        "filters": {
            "types": ["manifest.*", "product.installation.applied"],
            "supported_schema_versions": ["v1"]
        }
    })

    for event in response["events"]:
        process(event)

    cursor = response["next_cursor"]
    if not response["has_more"]:
        time.sleep(5)
```

### Example (Go)

```go
var cursor string
for {
    resp, err := client.PullEvents(ctx, model.PullEventsRequest{
        Cursor: cursor,
        Limit:  100,
        Filters: model.PullEventsFilters{
            Types:                   []string{"manifest.*"},
            SupportedSchemaVersions: []string{"v1"},
        },
    })
    if err != nil {
        log.Warn("pull failed", err)
        time.Sleep(5 * time.Second)
        continue
    }

    for _, event := range resp.Events {
        process(event)
    }
    cursor = resp.NextCursor

    if !resp.HasMore {
        time.Sleep(5 * time.Second)
    }
}
```

## Schema Versioning Policy

- `v1` is **forever non-breaking**. New fields may be added; existing fields
  will never be removed, renamed, or type-changed.
- Breaking changes create `v2` and coexist with `v1`.
- Events emit `schema_version` so consumers can filter by supported versions.

## Cursor Semantics

- Cursors are **opaque strings** to consumers. Do not parse or construct them.
- Cursors guarantee per-aggregate ordering.
- Cross-aggregate ordering is monotonic by `sequence` but not strictly causal.
- After a server restart, consumers resume from their last saved cursor
  (no backfill, no gaps for cross-aggregate).

## Sensitive Data

Events never contain secret values in clear. Only `secret_ref` pointers.
Do not expect credentials, API keys, or passwords in event payloads.
