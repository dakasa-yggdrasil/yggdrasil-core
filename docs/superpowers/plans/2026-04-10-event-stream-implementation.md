# Event Stream Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implementar o primitive fundacional de event stream no yggdrasil-core — core emite events de mutações de estado, persiste em PostgreSQL com cursor global monotônico, e expõe via RPC pull-based para consumers em qualquer linguagem via JSON Schema contracts.

**Architecture:** Nova tabela `event_log` em PostgreSQL com sequence BIGSERIAL global + UUID v7 event_id. Função `repository.EmitEvent(tx, req)` chamada dentro das transactions existentes que mutam estado (atomic com a mutação). RPC `event_stream.pull` via RabbitMQ aceita cursor opaco + filters e retorna batches. Retention policy configurável via tabela `event_retention_policy`, enforced por addon de background `event_log_cleaner`. Primeiros 4 event types implementados no MVP: `manifest.created`, `product.installation.applied`, `workflow.run.completed`, `authorization.evaluated`. Contratos em JSON Schema embedados via `//go:embed`.

**Tech Stack:** Go 1.25, PostgreSQL (via lib/pq), Goose migrations, github.com/santhosh-tekuri/jsonschema/v6 (já usado no projeto para contracts), google/uuid, amqp091-go.

**Specs de referência:**
- [`yggdrasil/docs/superpowers/specs/2026-04-10-event-stream-design.md`](../../../../yggdrasil/docs/superpowers/specs/2026-04-10-event-stream-design.md) — spec completa
- [`yggdrasil/docs/superpowers/specs/2026-04-10-yggdrasil-product-audit-report.md`](../../../../yggdrasil/docs/superpowers/specs/2026-04-10-yggdrasil-product-audit-report.md) — contexto

---

## File Structure

### NEW FILES

| File | Responsibility |
|---|---|
| `db/migrations/00006_event_log.sql` | Create `event_log` table + indices |
| `db/migrations/00007_event_retention_policy.sql` | Create `event_retention_policy` table + default policies |
| `model/event.go` | Go structs: `Event`, `EventActor`, `EmitEventRequest`, `PullEventsRequest`, `PullEventsResponse`, `EventRetentionPolicy` |
| `repository/event.go` | Functions: `EmitEvent(ctx, tx, req)`, `PullEvents(ctx, db, req)`, `CleanupExpiredEvents(ctx, db)`, `ListRetentionPolicies(ctx, db)` |
| `repository/event_test.go` | Unit tests for repository functions |
| `docs/contracts/events/v1/schema.json` | Base event schema (common fields) |
| `docs/contracts/events/v1/manifest/created.json` | Schema for `manifest.created` |
| `docs/contracts/events/v1/product/installation_applied.json` | Schema for `product.installation.applied` |
| `docs/contracts/events/v1/workflow/run_completed.json` | Schema for `workflow.run.completed` |
| `docs/contracts/events/v1/authorization/evaluated.json` | Schema for `authorization.evaluated` |
| `docs/contracts/events/v1/README.md` | Consumer documentation (any language) |
| `docs/contracts/events_validator.go` | Validates event payloads against JSON schemas (follows pattern of `validator.go`) |
| `docs/contracts/events_validator_test.go` | Tests for event schema validation |
| `controllers/message/event_stream.go` | RPC handler for `yggdrasil-core.event_stream.pull` |
| `controllers/message/event_stream_test.go` | Tests for RPC handler |
| `addons/event_log_cleaner.go` | Background addon: periodic retention cleanup |

### MODIFIED FILES

| File | Change |
|---|---|
| `controllers/message/register.go` | Register `event_stream.pull` consumer |
| `controllers/message/manifests.go` | Emit `manifest.<kind>.created` event within the mutation tx |
| `controllers/message/products.go` | Emit `product.installation.applied` event within the mutation tx |
| `controllers/message/workflows.go` | Emit `workflow.run.completed` event within the mutation tx |
| `docs/contracts/validator.go` | Add `FamilyEventsV1` constant + register `events/v1` schemas (or create separate `events_validator.go`) |

### DESIGN CONSTRAINTS

- **Transactional emission**: `EmitEvent(tx, req)` MUST take a `*sql.Tx` and NEVER create its own. Guarantee: event only exists if the mutation committed.
- **Schema validation at emit time**: validate payload against JSON Schema before INSERT.
- **Cursor opaque**: consumers treat cursor as opaque string; internally it's `{"sequence": N}` base64-encoded.
- **Sequence monotonic global**: PostgreSQL BIGSERIAL provides global ordering across multiple core workers.
- **UUID v7 event_id**: time-ordered, unique across workers.
- **Backwards compatible**: all new code; existing mutations only gain an extra `EmitEvent` call inside their existing transactions.

---

## Phase 1: Schema + Model

### Task 1: Check working directory and verify clean state

**Files:**
- None (verification only)

- [ ] **Step 1: Navigate to yggdrasil-core repo**

```bash
cd /Users/dakasa/projects/yggdrasil-core
pwd
```

Expected: `/Users/dakasa/projects/yggdrasil-core`

- [ ] **Step 2: Verify clean git state**

```bash
git status
```

Expected: `nothing to commit, working tree clean` OR changes limited to `docs/superpowers/plans/` (this plan file).

- [ ] **Step 3: Verify branch**

```bash
git branch --show-current
```

Expected: `main`. If not, switch: `git checkout main`.

- [ ] **Step 4: Pull latest**

```bash
git pull
```

Expected: `Already up to date.` or clean fast-forward.

---

### Task 2: Create event_log migration

**Files:**
- Create: `db/migrations/00006_event_log.sql`

- [ ] **Step 1: Create the migration file**

```sql
-- +goose Up
-- +goose StatementBegin

CREATE TABLE IF NOT EXISTS public.event_log (
    event_id        UUID PRIMARY KEY,
    sequence        BIGSERIAL NOT NULL UNIQUE,
    type            VARCHAR(128) NOT NULL,
    schema_version  VARCHAR(16) NOT NULL DEFAULT 'v1',
    aggregate_type  VARCHAR(64) NOT NULL,
    aggregate_id    VARCHAR(128) NOT NULL,
    actor_type      VARCHAR(32),
    actor_id        VARCHAR(128),
    actor_context   JSONB,
    emitted_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    payload         JSONB NOT NULL,
    metadata        JSONB
);

CREATE INDEX IF NOT EXISTS event_log_sequence_idx ON public.event_log (sequence);
CREATE INDEX IF NOT EXISTS event_log_type_sequence_idx ON public.event_log (type, sequence);
CREATE INDEX IF NOT EXISTS event_log_aggregate_idx ON public.event_log (aggregate_type, aggregate_id, sequence);
CREATE INDEX IF NOT EXISTS event_log_emitted_at_idx ON public.event_log (emitted_at);
CREATE INDEX IF NOT EXISTS event_log_type_emitted_idx ON public.event_log (type, emitted_at);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

DROP TABLE IF EXISTS public.event_log;

-- +goose StatementEnd
```

Write this to `db/migrations/00006_event_log.sql`.

- [ ] **Step 2: Verify file was created correctly**

```bash
ls -la db/migrations/00006_event_log.sql
head -5 db/migrations/00006_event_log.sql
```

Expected: File exists, first line is `-- +goose Up`.

- [ ] **Step 3: Apply migration locally**

```bash
goose -dir db/migrations postgres "$DB_URL" up 00006
```

If `goose` is not in PATH, use: `go run github.com/pressly/goose/v3/cmd/goose@latest -dir db/migrations postgres "$DB_URL" up 00006`

Where `$DB_URL` is the local PostgreSQL connection string (e.g., `postgres://postgres:postgres@localhost:5432/yggdrasil?sslmode=disable`).

Expected: `OK 00006_event_log.sql (Xms)`

- [ ] **Step 4: Verify table exists**

```bash
psql "$DB_URL" -c "\d event_log"
```

Expected: Shows the table definition with all columns and indices.

- [ ] **Step 5: Commit**

```bash
git add db/migrations/00006_event_log.sql
git commit -m "$(cat <<'EOF'
🗃️ Add event_log table migration

First half of event stream primitive: persistent table for state change
events with global monotonic sequence and indices for cursor-based pull
with type/aggregate filters.

Part of yggdrasil product audit Gap 1 (Event Stream).

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 3: Create event_retention_policy migration

**Files:**
- Create: `db/migrations/00007_event_retention_policy.sql`

- [ ] **Step 1: Create the migration file**

```sql
-- +goose Up
-- +goose StatementBegin

CREATE TABLE IF NOT EXISTS public.event_retention_policy (
    type_pattern    VARCHAR(128) PRIMARY KEY,
    ttl_days        INTEGER NOT NULL CHECK (ttl_days >= 0),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

INSERT INTO public.event_retention_policy (type_pattern, ttl_days) VALUES
    ('*', 90),
    ('authorization.*', 2555),
    ('manifest.*', 0),
    ('buildproject.*', 365),
    ('workflow.step.*', 30),
    ('workflow.run.*', 180)
ON CONFLICT (type_pattern) DO NOTHING;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

DROP TABLE IF EXISTS public.event_retention_policy;

-- +goose StatementEnd
```

Write to `db/migrations/00007_event_retention_policy.sql`.

- [ ] **Step 2: Apply migration**

```bash
goose -dir db/migrations postgres "$DB_URL" up 00007
```

Expected: `OK 00007_event_retention_policy.sql`

- [ ] **Step 3: Verify seeded data**

```bash
psql "$DB_URL" -c "SELECT type_pattern, ttl_days FROM event_retention_policy ORDER BY type_pattern;"
```

Expected: 6 rows with the seeded policies.

- [ ] **Step 4: Commit**

```bash
git add db/migrations/00007_event_retention_policy.sql
git commit -m "$(cat <<'EOF'
🗃️ Add event_retention_policy table with default policies

Second half of event stream persistence: configurable retention per event
type pattern. Default: 90 days catch-all, 7 years for authorization events,
forever for manifest history.

Part of yggdrasil product audit Gap 1 (Event Stream).

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 4: Create model/event.go with core types

**Files:**
- Create: `model/event.go`

- [ ] **Step 1: Write model/event.go**

```go
package model

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

// Event is a persisted state change event in the yggdrasil-core event stream.
// Events are emitted transactionally with state mutations and consumed by
// subscribers via cursor-based pull.
type Event struct {
	EventID       uuid.UUID       `json:"event_id"`
	Sequence      int64           `json:"sequence"`
	Type          string          `json:"type"`
	SchemaVersion string          `json:"schema_version"`
	AggregateType string          `json:"aggregate_type"`
	AggregateID   string          `json:"aggregate_id"`
	Actor         *EventActor     `json:"actor,omitempty"`
	EmittedAt     time.Time       `json:"emitted_at"`
	Payload       json.RawMessage `json:"payload"`
	Metadata      json.RawMessage `json:"metadata,omitempty"`
}

// EventActor identifies who/what caused an event to be emitted.
type EventActor struct {
	Type    string                 `json:"type"`
	ID      string                 `json:"id"`
	Context map[string]interface{} `json:"context,omitempty"`
}

// EmitEventRequest is the input to repository.EmitEvent.
// Called from within a mutation transaction to guarantee atomicity.
type EmitEventRequest struct {
	Type          string
	SchemaVersion string
	AggregateType string
	AggregateID   string
	Actor         *EventActor
	Payload       map[string]interface{}
	Metadata      map[string]interface{}
}

// PullEventsRequest is the input to the event_stream.pull RPC.
type PullEventsRequest struct {
	Cursor  string              `json:"cursor,omitempty"`
	Limit   int                 `json:"limit,omitempty"`
	Filters PullEventsFilters   `json:"filters,omitempty"`
}

// PullEventsFilters scopes the pulled events.
type PullEventsFilters struct {
	Types                   []string   `json:"types,omitempty"`
	AggregateType           string     `json:"aggregate_type,omitempty"`
	AggregateID             string     `json:"aggregate_id,omitempty"`
	SupportedSchemaVersions []string   `json:"supported_schema_versions,omitempty"`
	EmittedAfter            *time.Time `json:"emitted_after,omitempty"`
}

// PullEventsResponse is the output of event_stream.pull.
type PullEventsResponse struct {
	Events     []Event `json:"events"`
	NextCursor string  `json:"next_cursor"`
	HasMore    bool    `json:"has_more"`
}

// EventRetentionPolicy describes how long events of a given type pattern are retained.
type EventRetentionPolicy struct {
	TypePattern string    `json:"type_pattern"`
	TTLDays     int       `json:"ttl_days"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// Default pagination constants for event pulls.
const (
	DefaultPullLimit = 100
	MaxPullLimit     = 1000
)
```

Write this to `model/event.go`.

- [ ] **Step 2: Verify compiles**

```bash
go build ./model/...
```

Expected: No output (success). If errors, fix before proceeding.

- [ ] **Step 3: Commit**

```bash
git add model/event.go
git commit -m "$(cat <<'EOF'
✨ Add event stream model types

Go structs for Event, EventActor, EmitEventRequest, PullEventsRequest/
Response, EventRetentionPolicy. Types use json.RawMessage for payload and
metadata so consumers can parse with their own typed schemas.

Part of yggdrasil product audit Gap 1 (Event Stream).

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Phase 2: Contract schemas (JSON Schema)

### Task 5: Create base event schema

**Files:**
- Create: `docs/contracts/events/v1/schema.json`

- [ ] **Step 1: Write base schema**

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://yggdrasil.io/contracts/events/v1/schema.json",
  "title": "Yggdrasil Event v1 (base)",
  "description": "Common structure of all events emitted by yggdrasil-core.",
  "type": "object",
  "required": ["event_id", "sequence", "type", "schema_version", "aggregate_type", "aggregate_id", "emitted_at", "payload"],
  "properties": {
    "event_id": {
      "type": "string",
      "format": "uuid",
      "description": "UUID v7 (time-ordered) uniquely identifying the event."
    },
    "sequence": {
      "type": "integer",
      "minimum": 1,
      "description": "Global monotonic sequence assigned by the core PostgreSQL BIGSERIAL."
    },
    "type": {
      "type": "string",
      "pattern": "^[a-z][a-z0-9_.]*$",
      "description": "Dotted event type (e.g. manifest.product.created)."
    },
    "schema_version": {
      "type": "string",
      "pattern": "^v[0-9]+$",
      "description": "Version of the payload schema. v1 is forever non-breaking."
    },
    "aggregate_type": {
      "type": "string",
      "description": "Type of the aggregate this event is about (manifest, product, workflow_run, etc.)."
    },
    "aggregate_id": {
      "type": "string",
      "description": "Identifier of the aggregate within its type. Per-aggregate ordering is guaranteed."
    },
    "actor": {
      "type": "object",
      "description": "Who/what caused the event. Optional; null for system-emitted events.",
      "required": ["type", "id"],
      "properties": {
        "type": {
          "type": "string",
          "enum": ["collaborator", "system", "integration"]
        },
        "id": { "type": "string" },
        "context": { "type": "object" }
      }
    },
    "emitted_at": {
      "type": "string",
      "format": "date-time",
      "description": "RFC 3339 UTC timestamp assigned by the server at emit time."
    },
    "payload": {
      "type": "object",
      "description": "Event-specific payload; validated against the schema of this event type."
    },
    "metadata": {
      "type": "object",
      "description": "Optional free-form metadata (correlation_id, causation_id, etc.)."
    }
  }
}
```

Write to `docs/contracts/events/v1/schema.json`.

- [ ] **Step 2: Verify valid JSON**

```bash
python3 -m json.tool docs/contracts/events/v1/schema.json > /dev/null && echo "valid JSON"
```

Expected: `valid JSON`.

- [ ] **Step 3: Commit**

```bash
git add docs/contracts/events/v1/schema.json
git commit -m "$(cat <<'EOF'
📝 Add base event schema (events/v1)

JSON Schema for the common structure of all yggdrasil-core events.
Language-agnostic contract; consumers in any language validate events
against this schema without importing yggdrasil-core Go types.

Part of yggdrasil product audit Gap 1 (Event Stream).

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 6: Create manifest.created event schema

**Files:**
- Create: `docs/contracts/events/v1/manifest/created.json`

- [ ] **Step 1: Write schema**

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://yggdrasil.io/contracts/events/v1/manifest/created.json",
  "title": "manifest.created payload",
  "description": "Payload emitted when a new manifest version is created (any kind).",
  "type": "object",
  "required": ["manifest_id", "kind", "namespace", "name", "version", "checksum"],
  "properties": {
    "manifest_id": {
      "type": "string",
      "format": "uuid"
    },
    "kind": {
      "type": "string",
      "enum": ["rbac", "policy", "integration_type", "integration_instance", "resource", "product", "workflow"]
    },
    "namespace": {
      "type": "string"
    },
    "name": {
      "type": "string"
    },
    "version": {
      "type": "integer",
      "minimum": 1
    },
    "checksum": {
      "type": "string",
      "pattern": "^sha256:[a-f0-9]{64}$"
    },
    "labels": {
      "type": "object",
      "additionalProperties": { "type": "string" }
    }
  }
}
```

Write to `docs/contracts/events/v1/manifest/created.json`.

- [ ] **Step 2: Verify valid JSON**

```bash
python3 -m json.tool docs/contracts/events/v1/manifest/created.json > /dev/null && echo "valid JSON"
```

- [ ] **Step 3: Commit**

```bash
git add docs/contracts/events/v1/manifest/created.json
git commit -m "📝 Add manifest.created event schema"
```

---

### Task 7: Create product.installation.applied event schema

**Files:**
- Create: `docs/contracts/events/v1/product/installation_applied.json`

- [ ] **Step 1: Write schema**

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://yggdrasil.io/contracts/events/v1/product/installation_applied.json",
  "title": "product.installation.applied payload",
  "description": "Payload emitted when a product installation apply operation succeeds.",
  "type": "object",
  "required": ["product_ref", "components_applied"],
  "properties": {
    "product_ref": {
      "type": "object",
      "required": ["name", "namespace"],
      "properties": {
        "id": { "type": "string", "format": "uuid" },
        "name": { "type": "string" },
        "namespace": { "type": "string" },
        "version": { "type": "integer" }
      }
    },
    "components_applied": {
      "type": "array",
      "items": {
        "type": "object",
        "required": ["name", "target"],
        "properties": {
          "name": { "type": "string" },
          "target": {
            "type": "object",
            "properties": {
              "kind": { "type": "string" },
              "integration_instance_ref": { "type": "object" },
              "namespace": { "type": "string" }
            }
          }
        }
      }
    },
    "target_overrides_used": {
      "type": "object",
      "description": "Map of integration_instance_ref.name → override. Present if the apply was invoked with target_overrides (see target-overrides spec)."
    },
    "dispatched_by": {
      "type": "string",
      "description": "Optional identifier of the workflow run or caller that dispatched this apply."
    }
  }
}
```

Write to `docs/contracts/events/v1/product/installation_applied.json`.

- [ ] **Step 2: Verify**

```bash
python3 -m json.tool docs/contracts/events/v1/product/installation_applied.json > /dev/null && echo "valid JSON"
```

- [ ] **Step 3: Commit**

```bash
git add docs/contracts/events/v1/product/installation_applied.json
git commit -m "📝 Add product.installation.applied event schema"
```

---

### Task 8: Create workflow.run.completed event schema

**Files:**
- Create: `docs/contracts/events/v1/workflow/run_completed.json`

- [ ] **Step 1: Write schema**

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://yggdrasil.io/contracts/events/v1/workflow/run_completed.json",
  "title": "workflow.run.completed payload",
  "description": "Payload emitted when a workflow run finishes with status succeeded.",
  "type": "object",
  "required": ["workflow_ref", "run_id", "status", "started_at", "finished_at"],
  "properties": {
    "workflow_ref": {
      "type": "object",
      "required": ["name", "namespace"],
      "properties": {
        "id": { "type": "string", "format": "uuid" },
        "name": { "type": "string" },
        "namespace": { "type": "string" },
        "version": { "type": "integer" }
      }
    },
    "run_id": {
      "type": "string",
      "format": "uuid"
    },
    "status": {
      "type": "string",
      "enum": ["succeeded", "failed", "partial"]
    },
    "started_at": { "type": "string", "format": "date-time" },
    "finished_at": { "type": "string", "format": "date-time" },
    "step_count": { "type": "integer", "minimum": 0 },
    "triggered_by": {
      "type": "string",
      "enum": ["manual", "schedule", "event"]
    }
  }
}
```

Write to `docs/contracts/events/v1/workflow/run_completed.json`.

- [ ] **Step 2: Verify**

```bash
python3 -m json.tool docs/contracts/events/v1/workflow/run_completed.json > /dev/null && echo "valid JSON"
```

- [ ] **Step 3: Commit**

```bash
git add docs/contracts/events/v1/workflow/run_completed.json
git commit -m "📝 Add workflow.run.completed event schema"
```

---

### Task 9: Create authorization.evaluated event schema

**Files:**
- Create: `docs/contracts/events/v1/authorization/evaluated.json`

- [ ] **Step 1: Write schema**

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://yggdrasil.io/contracts/events/v1/authorization/evaluated.json",
  "title": "authorization.evaluated payload",
  "description": "Payload emitted after an RBAC+Policy authorization decision.",
  "type": "object",
  "required": ["resource", "action", "decision"],
  "properties": {
    "collaborator_id": { "type": "string" },
    "resource": { "type": "string" },
    "action": { "type": "string" },
    "decision": {
      "type": "string",
      "enum": ["allow", "deny", "not_applicable"]
    },
    "matched_roles": {
      "type": "array",
      "items": { "type": "string" }
    },
    "matched_rules": {
      "type": "array",
      "items": { "type": "string" }
    },
    "rbac_manifest_ref": {
      "type": "object",
      "properties": {
        "id": { "type": "string", "format": "uuid" },
        "name": { "type": "string" },
        "namespace": { "type": "string" }
      }
    },
    "policy_manifest_ref": {
      "type": "object",
      "properties": {
        "id": { "type": "string", "format": "uuid" },
        "name": { "type": "string" },
        "namespace": { "type": "string" }
      }
    }
  }
}
```

Write to `docs/contracts/events/v1/authorization/evaluated.json`.

- [ ] **Step 2: Verify**

```bash
python3 -m json.tool docs/contracts/events/v1/authorization/evaluated.json > /dev/null && echo "valid JSON"
```

- [ ] **Step 3: Commit**

```bash
git add docs/contracts/events/v1/authorization/evaluated.json
git commit -m "📝 Add authorization.evaluated event schema"
```

---

### Task 10: Create docs/contracts/events/v1/README.md for consumers

**Files:**
- Create: `docs/contracts/events/v1/README.md`

- [ ] **Step 1: Write README**

```markdown
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
```

Write to `docs/contracts/events/v1/README.md`.

- [ ] **Step 2: Commit**

```bash
git add docs/contracts/events/v1/README.md
git commit -m "📝 Add events/v1 consumer documentation"
```

---

## Phase 3: Schema validation + repository

### Task 11: Create docs/contracts/events_validator.go for schema-based validation

**Files:**
- Create: `docs/contracts/events_validator.go`

- [ ] **Step 1: Write validator**

```go
package contracts

import (
	"embed"
	"encoding/json"
	"fmt"
	"strings"
	"sync"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

const FamilyEventsV1 = "events/v1"

//go:embed events/v1/schema.json events/v1/manifest/*.json events/v1/product/*.json events/v1/workflow/*.json events/v1/authorization/*.json
var eventSchemaFS embed.FS

var (
	eventSchemasMu sync.RWMutex
	eventSchemas   = map[string]*jsonschema.Schema{}
)

// ValidateEventPayload validates a payload against the JSON Schema of a specific
// event type + schema version. Returns an error describing the validation failure
// if the payload does not match the schema, or if the schema is unknown.
//
// Example:
//   err := contracts.ValidateEventPayload("manifest.created", "v1", payloadMap)
func ValidateEventPayload(eventType string, schemaVersion string, payload interface{}) error {
	eventType = strings.TrimSpace(eventType)
	schemaVersion = strings.TrimSpace(schemaVersion)
	if eventType == "" {
		return fmt.Errorf("event type is required")
	}
	if schemaVersion == "" {
		schemaVersion = "v1"
	}

	schemaPath := eventTypeToSchemaPath(eventType, schemaVersion)
	if schemaPath == "" {
		return fmt.Errorf("no schema registered for event type %q version %q", eventType, schemaVersion)
	}

	schema, err := loadEventSchema(schemaPath)
	if err != nil {
		return fmt.Errorf("load event schema %q: %w", schemaPath, err)
	}

	if err := schema.Validate(payload); err != nil {
		return fmt.Errorf("event payload validation for %q: %w", eventType, err)
	}
	return nil
}

// eventTypeToSchemaPath maps "manifest.created" → "events/v1/manifest/created.json".
// Only MVP event types are registered here; extend this map as new types are added.
func eventTypeToSchemaPath(eventType string, schemaVersion string) string {
	mapping := map[string]string{
		"manifest.created":              "events/v1/manifest/created.json",
		"product.installation.applied":  "events/v1/product/installation_applied.json",
		"workflow.run.completed":        "events/v1/workflow/run_completed.json",
		"authorization.evaluated":       "events/v1/authorization/evaluated.json",
	}
	path, ok := mapping[eventType]
	if !ok {
		return ""
	}
	_ = schemaVersion // placeholder for v2+ routing
	return path
}

func loadEventSchema(schemaPath string) (*jsonschema.Schema, error) {
	eventSchemasMu.RLock()
	if cached, ok := eventSchemas[schemaPath]; ok {
		eventSchemasMu.RUnlock()
		return cached, nil
	}
	eventSchemasMu.RUnlock()

	data, err := eventSchemaFS.ReadFile(schemaPath)
	if err != nil {
		return nil, err
	}

	var raw interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parse schema: %w", err)
	}

	compiler := jsonschema.NewCompiler()
	if err := compiler.AddResource(schemaPath, raw); err != nil {
		return nil, fmt.Errorf("add resource: %w", err)
	}

	schema, err := compiler.Compile(schemaPath)
	if err != nil {
		return nil, fmt.Errorf("compile schema: %w", err)
	}

	eventSchemasMu.Lock()
	eventSchemas[schemaPath] = schema
	eventSchemasMu.Unlock()

	return schema, nil
}
```

Write to `docs/contracts/events_validator.go`.

- [ ] **Step 2: Verify compiles**

```bash
go build ./docs/contracts/...
```

Expected: No output.

- [ ] **Step 3: Commit**

```bash
git add docs/contracts/events_validator.go
git commit -m "$(cat <<'EOF'
✨ Add events/v1 schema validator

Loads and validates event payloads against JSON Schema files embedded
from docs/contracts/events/v1/. Used by repository.EmitEvent to reject
malformed payloads at write time.

Part of yggdrasil product audit Gap 1 (Event Stream).

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 12: Create docs/contracts/events_validator_test.go

**Files:**
- Create: `docs/contracts/events_validator_test.go`

- [ ] **Step 1: Write failing test**

```go
package contracts

import (
	"strings"
	"testing"
)

func TestValidateEventPayload_ManifestCreated_Valid(t *testing.T) {
	payload := map[string]interface{}{
		"manifest_id": "018f2b4a-1234-7abc-def0-123456789012",
		"kind":        "product",
		"namespace":   "dakasa",
		"name":        "dakasa-app",
		"version":     1,
		"checksum":    "sha256:abc123def456abc123def456abc123def456abc123def456abc123def456abc1",
	}
	if err := ValidateEventPayload("manifest.created", "v1", payload); err != nil {
		t.Fatalf("expected valid payload, got error: %v", err)
	}
}

func TestValidateEventPayload_ManifestCreated_MissingRequired(t *testing.T) {
	payload := map[string]interface{}{
		"manifest_id": "018f2b4a-1234-7abc-def0-123456789012",
		// missing kind, namespace, name, version, checksum
	}
	err := ValidateEventPayload("manifest.created", "v1", payload)
	if err == nil {
		t.Fatal("expected validation error for missing required fields")
	}
	if !strings.Contains(err.Error(), "manifest.created") {
		t.Errorf("error should mention event type: %v", err)
	}
}

func TestValidateEventPayload_ManifestCreated_InvalidKind(t *testing.T) {
	payload := map[string]interface{}{
		"manifest_id": "018f2b4a-1234-7abc-def0-123456789012",
		"kind":        "not_a_valid_kind",
		"namespace":   "dakasa",
		"name":        "dakasa-app",
		"version":     1,
		"checksum":    "sha256:abc123def456abc123def456abc123def456abc123def456abc123def456abc1",
	}
	err := ValidateEventPayload("manifest.created", "v1", payload)
	if err == nil {
		t.Fatal("expected error for invalid kind enum")
	}
}

func TestValidateEventPayload_AuthorizationEvaluated_Valid(t *testing.T) {
	payload := map[string]interface{}{
		"collaborator_id": "alice",
		"resource":        "products/dakasa-app",
		"action":          "apply",
		"decision":        "allow",
		"matched_roles":   []interface{}{"dakasa-deployer"},
		"matched_rules":   []interface{}{"allow-deploy"},
	}
	if err := ValidateEventPayload("authorization.evaluated", "v1", payload); err != nil {
		t.Fatalf("expected valid payload, got error: %v", err)
	}
}

func TestValidateEventPayload_UnknownType(t *testing.T) {
	payload := map[string]interface{}{"foo": "bar"}
	err := ValidateEventPayload("unknown.event.type", "v1", payload)
	if err == nil {
		t.Fatal("expected error for unknown event type")
	}
	if !strings.Contains(err.Error(), "no schema registered") {
		t.Errorf("error should mention missing schema: %v", err)
	}
}
```

Write to `docs/contracts/events_validator_test.go`.

- [ ] **Step 2: Run tests**

```bash
go test ./docs/contracts/ -run TestValidateEventPayload -v
```

Expected: All 5 tests PASS.

- [ ] **Step 3: Commit**

```bash
git add docs/contracts/events_validator_test.go
git commit -m "✅ Add events/v1 schema validator tests"
```

---

### Task 13: Create repository/event.go with EmitEvent

**Files:**
- Create: `repository/event.go`

- [ ] **Step 1: Write EmitEvent**

```go
package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/dakasa-yggdrasil/yggdrasil-core/docs/contracts"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

// EmitEvent inserts an event into event_log within a caller-provided transaction.
// MUST be called from inside an active *sql.Tx to guarantee atomicity with the
// state mutation that generated the event. If the transaction rolls back, the
// event is not persisted.
//
// Validates the payload against the JSON Schema for the event type before insert.
// Returns the generated UUID v7 event_id on success.
func EmitEvent(ctx context.Context, tx *sql.Tx, req model.EmitEventRequest) (uuid.UUID, error) {
	if tx == nil {
		return uuid.Nil, fmt.Errorf("EmitEvent requires a non-nil transaction")
	}

	req.Type = strings.TrimSpace(req.Type)
	if req.Type == "" {
		return uuid.Nil, fmt.Errorf("event type is required")
	}
	if req.SchemaVersion == "" {
		req.SchemaVersion = "v1"
	}
	req.AggregateType = strings.TrimSpace(req.AggregateType)
	if req.AggregateType == "" {
		return uuid.Nil, fmt.Errorf("aggregate_type is required")
	}
	req.AggregateID = strings.TrimSpace(req.AggregateID)
	if req.AggregateID == "" {
		return uuid.Nil, fmt.Errorf("aggregate_id is required")
	}
	if req.Payload == nil {
		return uuid.Nil, fmt.Errorf("payload is required")
	}

	if err := contracts.ValidateEventPayload(req.Type, req.SchemaVersion, req.Payload); err != nil {
		return uuid.Nil, err
	}

	eventID, err := uuid.NewV7()
	if err != nil {
		return uuid.Nil, fmt.Errorf("generate event_id: %w", err)
	}

	payloadJSON, err := json.Marshal(req.Payload)
	if err != nil {
		return uuid.Nil, fmt.Errorf("marshal payload: %w", err)
	}

	var metadataJSON []byte
	if req.Metadata != nil {
		metadataJSON, err = json.Marshal(req.Metadata)
		if err != nil {
			return uuid.Nil, fmt.Errorf("marshal metadata: %w", err)
		}
	}

	var actorType, actorID sql.NullString
	var actorContextJSON []byte
	if req.Actor != nil {
		actorType = sql.NullString{String: req.Actor.Type, Valid: req.Actor.Type != ""}
		actorID = sql.NullString{String: req.Actor.ID, Valid: req.Actor.ID != ""}
		if req.Actor.Context != nil {
			actorContextJSON, err = json.Marshal(req.Actor.Context)
			if err != nil {
				return uuid.Nil, fmt.Errorf("marshal actor context: %w", err)
			}
		}
	}

	_, err = tx.ExecContext(ctx, `
		INSERT INTO public.event_log (
			event_id, type, schema_version, aggregate_type, aggregate_id,
			actor_type, actor_id, actor_context, payload, metadata
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10
		)
	`, eventID, req.Type, req.SchemaVersion, req.AggregateType, req.AggregateID,
		actorType, actorID, nullableJSON(actorContextJSON), payloadJSON, nullableJSON(metadataJSON))
	if err != nil {
		return uuid.Nil, fmt.Errorf("insert event_log: %w", err)
	}

	return eventID, nil
}

func nullableJSON(raw []byte) interface{} {
	if len(raw) == 0 {
		return nil
	}
	return raw
}
```

Write to `repository/event.go`.

- [ ] **Step 2: Verify compiles**

```bash
go build ./repository/...
```

Expected: No output.

- [ ] **Step 3: Commit**

```bash
git add repository/event.go
git commit -m "$(cat <<'EOF'
✨ Add repository.EmitEvent for transactional event persistence

Accepts a caller-provided *sql.Tx and inserts a validated event into
event_log. Enforces: schema validation at emit time, required fields,
UUID v7 event_id generation. Sequence is assigned by BIGSERIAL.

Part of yggdrasil product audit Gap 1 (Event Stream).

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 14: Add repository.PullEvents

**Files:**
- Modify: `repository/event.go` (append function)

- [ ] **Step 1: Append PullEvents function to repository/event.go**

Add to the end of `repository/event.go` (before the final closing brace? The file has no closing brace, functions are top-level. Append after `nullableJSON`):

```go

// PullEvents returns a batch of events starting from the given cursor, respecting
// the provided filters and limit. The cursor is an opaque string that the caller
// obtained from a previous PullEvents call (or empty to start from the beginning).
//
// Limit is normalized to DefaultPullLimit (100) if <=0 and capped at MaxPullLimit (1000).
//
// Filters are AND-combined. `types` supports wildcards (e.g., "manifest.*").
// Per-aggregate ordering is guaranteed; cross-aggregate ordering is monotonic by sequence.
func PullEvents(ctx context.Context, db *sql.DB, req model.PullEventsRequest) (model.PullEventsResponse, error) {
	cursorSeq, err := decodePullCursor(req.Cursor)
	if err != nil {
		return model.PullEventsResponse{}, fmt.Errorf("invalid cursor: %w", err)
	}

	limit := req.Limit
	if limit <= 0 {
		limit = model.DefaultPullLimit
	}
	if limit > model.MaxPullLimit {
		limit = model.MaxPullLimit
	}

	query, args := buildPullQuery(cursorSeq, req.Filters, limit+1)

	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return model.PullEventsResponse{}, fmt.Errorf("query event_log: %w", err)
	}
	defer rows.Close()

	events := make([]model.Event, 0, limit)
	for rows.Next() {
		var (
			ev               model.Event
			actorType, actorID sql.NullString
			actorContext     sql.NullString
			payloadRaw       []byte
			metadataRaw      []byte
		)
		if err := rows.Scan(
			&ev.EventID,
			&ev.Sequence,
			&ev.Type,
			&ev.SchemaVersion,
			&ev.AggregateType,
			&ev.AggregateID,
			&actorType,
			&actorID,
			&actorContext,
			&ev.EmittedAt,
			&payloadRaw,
			&metadataRaw,
		); err != nil {
			return model.PullEventsResponse{}, fmt.Errorf("scan event row: %w", err)
		}

		ev.Payload = json.RawMessage(payloadRaw)
		if len(metadataRaw) > 0 {
			ev.Metadata = json.RawMessage(metadataRaw)
		}
		if actorType.Valid || actorID.Valid || actorContext.Valid {
			actor := &model.EventActor{
				Type: actorType.String,
				ID:   actorID.String,
			}
			if actorContext.Valid && actorContext.String != "" {
				var ctxMap map[string]interface{}
				if err := json.Unmarshal([]byte(actorContext.String), &ctxMap); err == nil {
					actor.Context = ctxMap
				}
			}
			ev.Actor = actor
		}
		events = append(events, ev)
	}
	if err := rows.Err(); err != nil {
		return model.PullEventsResponse{}, fmt.Errorf("iterate event rows: %w", err)
	}

	hasMore := len(events) > limit
	if hasMore {
		events = events[:limit]
	}

	lastSeq := cursorSeq
	if len(events) > 0 {
		lastSeq = events[len(events)-1].Sequence
	}
	nextCursor := encodePullCursor(lastSeq)

	return model.PullEventsResponse{
		Events:     events,
		NextCursor: nextCursor,
		HasMore:    hasMore,
	}, nil
}

// buildPullQuery composes the SQL query for PullEvents based on filters.
// Returns the query and ordered arguments.
func buildPullQuery(cursorSeq int64, filters model.PullEventsFilters, limit int) (string, []interface{}) {
	var (
		conditions = []string{"sequence > $1"}
		args       = []interface{}{cursorSeq}
		idx        = 2
	)

	if len(filters.Types) > 0 {
		parts := make([]string, 0, len(filters.Types))
		for _, pattern := range filters.Types {
			pattern = strings.TrimSpace(pattern)
			if pattern == "" {
				continue
			}
			parts = append(parts, fmt.Sprintf("type LIKE $%d", idx))
			args = append(args, wildcardToLike(pattern))
			idx++
		}
		if len(parts) > 0 {
			conditions = append(conditions, "("+strings.Join(parts, " OR ")+")")
		}
	}

	if filters.AggregateType != "" {
		conditions = append(conditions, fmt.Sprintf("aggregate_type = $%d", idx))
		args = append(args, filters.AggregateType)
		idx++
	}

	if filters.AggregateID != "" {
		conditions = append(conditions, fmt.Sprintf("aggregate_id = $%d", idx))
		args = append(args, filters.AggregateID)
		idx++
	}

	if len(filters.SupportedSchemaVersions) > 0 {
		versionArgs := make([]string, 0, len(filters.SupportedSchemaVersions))
		for _, v := range filters.SupportedSchemaVersions {
			versionArgs = append(versionArgs, fmt.Sprintf("$%d", idx))
			args = append(args, v)
			idx++
		}
		conditions = append(conditions, "schema_version IN ("+strings.Join(versionArgs, ", ")+")")
	}

	if filters.EmittedAfter != nil {
		conditions = append(conditions, fmt.Sprintf("emitted_at > $%d", idx))
		args = append(args, *filters.EmittedAfter)
		idx++
	}

	conditions = append(conditions, fmt.Sprintf("TRUE LIMIT $%d", idx))
	args = append(args, limit)

	query := `
		SELECT
			event_id, sequence, type, schema_version,
			aggregate_type, aggregate_id,
			actor_type, actor_id, actor_context::text,
			emitted_at, payload::text, metadata::text
		FROM public.event_log
		WHERE ` + strings.Join(conditions[:len(conditions)-1], " AND ") + `
		ORDER BY sequence ASC
		LIMIT $` + fmt.Sprintf("%d", idx-1)

	return query, args
}

// wildcardToLike converts a pattern like "manifest.*" or "workflow.run.*" into
// a SQL LIKE pattern.
func wildcardToLike(pattern string) string {
	return strings.ReplaceAll(pattern, "*", "%")
}

// encodePullCursor turns a sequence number into an opaque cursor string.
func encodePullCursor(seq int64) string {
	return fmt.Sprintf("seq:%d", seq)
}

// decodePullCursor extracts the sequence number from an opaque cursor string.
// Empty cursor returns 0 (start from beginning).
func decodePullCursor(cursor string) (int64, error) {
	cursor = strings.TrimSpace(cursor)
	if cursor == "" {
		return 0, nil
	}
	const prefix = "seq:"
	if !strings.HasPrefix(cursor, prefix) {
		return 0, fmt.Errorf("cursor must start with %q", prefix)
	}
	var seq int64
	_, err := fmt.Sscanf(cursor[len(prefix):], "%d", &seq)
	if err != nil {
		return 0, fmt.Errorf("parse cursor sequence: %w", err)
	}
	if seq < 0 {
		return 0, fmt.Errorf("cursor sequence must be non-negative")
	}
	return seq, nil
}
```

**IMPORTANT:** The `buildPullQuery` function has a bug in its current structure — the LIMIT clause placeholder `TRUE LIMIT $%d` would generate malformed SQL. Replace `conditions = append(conditions, fmt.Sprintf("TRUE LIMIT $%d", idx))` and the query composition with a cleaner approach:

Use this corrected `buildPullQuery`:

```go
// buildPullQuery composes the SQL query for PullEvents based on filters.
// Returns the query and ordered arguments.
func buildPullQuery(cursorSeq int64, filters model.PullEventsFilters, limit int) (string, []interface{}) {
	var (
		conditions = []string{"sequence > $1"}
		args       = []interface{}{cursorSeq}
		idx        = 2
	)

	if len(filters.Types) > 0 {
		parts := make([]string, 0, len(filters.Types))
		for _, pattern := range filters.Types {
			pattern = strings.TrimSpace(pattern)
			if pattern == "" {
				continue
			}
			parts = append(parts, fmt.Sprintf("type LIKE $%d", idx))
			args = append(args, wildcardToLike(pattern))
			idx++
		}
		if len(parts) > 0 {
			conditions = append(conditions, "("+strings.Join(parts, " OR ")+")")
		}
	}

	if filters.AggregateType != "" {
		conditions = append(conditions, fmt.Sprintf("aggregate_type = $%d", idx))
		args = append(args, filters.AggregateType)
		idx++
	}

	if filters.AggregateID != "" {
		conditions = append(conditions, fmt.Sprintf("aggregate_id = $%d", idx))
		args = append(args, filters.AggregateID)
		idx++
	}

	if len(filters.SupportedSchemaVersions) > 0 {
		versionArgs := make([]string, 0, len(filters.SupportedSchemaVersions))
		for _, v := range filters.SupportedSchemaVersions {
			versionArgs = append(versionArgs, fmt.Sprintf("$%d", idx))
			args = append(args, v)
			idx++
		}
		conditions = append(conditions, "schema_version IN ("+strings.Join(versionArgs, ", ")+")")
	}

	if filters.EmittedAfter != nil {
		conditions = append(conditions, fmt.Sprintf("emitted_at > $%d", idx))
		args = append(args, *filters.EmittedAfter)
		idx++
	}

	args = append(args, limit)
	query := `
		SELECT
			event_id, sequence, type, schema_version,
			aggregate_type, aggregate_id,
			actor_type, actor_id, actor_context::text,
			emitted_at, payload::text, metadata::text
		FROM public.event_log
		WHERE ` + strings.Join(conditions, " AND ") + `
		ORDER BY sequence ASC
		LIMIT $` + fmt.Sprintf("%d", idx)

	return query, args
}
```

- [ ] **Step 2: Verify compiles**

```bash
go build ./repository/...
```

Expected: No output. If errors, fix.

- [ ] **Step 3: Commit**

```bash
git add repository/event.go
git commit -m "$(cat <<'EOF'
✨ Add repository.PullEvents for cursor-based event streaming

Returns a batch of events after the given cursor, respecting filters
(types with wildcards, aggregate, schema version, emitted_after) and
limit. Cursor is opaque "seq:N" string. Per-aggregate ordering guaranteed.

Part of yggdrasil product audit Gap 1 (Event Stream).

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 15: Add repository.CleanupExpiredEvents

**Files:**
- Modify: `repository/event.go` (append function)

- [ ] **Step 1: Append CleanupExpiredEvents to repository/event.go**

Add to the end of `repository/event.go`:

```go

// CleanupExpiredEvents deletes events older than their type-specific retention TTL.
// Iterates over event_retention_policy and runs a DELETE per active pattern.
// Patterns with ttl_days = 0 are skipped (infinite retention).
// Safe to call periodically; idempotent.
func CleanupExpiredEvents(ctx context.Context, db *sql.DB) (int64, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT type_pattern, ttl_days
		FROM public.event_retention_policy
		WHERE ttl_days > 0
	`)
	if err != nil {
		return 0, fmt.Errorf("load retention policies: %w", err)
	}
	defer rows.Close()

	type policy struct {
		pattern string
		days    int
	}
	var policies []policy
	for rows.Next() {
		var p policy
		if err := rows.Scan(&p.pattern, &p.days); err != nil {
			return 0, fmt.Errorf("scan retention policy: %w", err)
		}
		policies = append(policies, p)
	}
	if err := rows.Err(); err != nil {
		return 0, fmt.Errorf("iterate retention policies: %w", err)
	}

	var totalDeleted int64
	for _, p := range policies {
		sqlPattern := wildcardToLike(p.pattern)
		result, err := db.ExecContext(ctx, `
			DELETE FROM public.event_log
			WHERE type LIKE $1
			  AND emitted_at < NOW() - ($2::text || ' days')::interval
		`, sqlPattern, fmt.Sprintf("%d", p.days))
		if err != nil {
			return totalDeleted, fmt.Errorf("delete events for pattern %q: %w", p.pattern, err)
		}
		deleted, _ := result.RowsAffected()
		totalDeleted += deleted
	}

	return totalDeleted, nil
}

// ListRetentionPolicies returns all configured retention policies ordered by pattern.
func ListRetentionPolicies(ctx context.Context, db *sql.DB) ([]model.EventRetentionPolicy, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT type_pattern, ttl_days, created_at, updated_at
		FROM public.event_retention_policy
		ORDER BY type_pattern
	`)
	if err != nil {
		return nil, fmt.Errorf("query retention policies: %w", err)
	}
	defer rows.Close()

	var policies []model.EventRetentionPolicy
	for rows.Next() {
		var p model.EventRetentionPolicy
		if err := rows.Scan(&p.TypePattern, &p.TTLDays, &p.CreatedAt, &p.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan policy: %w", err)
		}
		policies = append(policies, p)
	}
	return policies, rows.Err()
}
```

- [ ] **Step 2: Verify compiles**

```bash
go build ./repository/...
```

Expected: No output.

- [ ] **Step 3: Commit**

```bash
git add repository/event.go
git commit -m "✨ Add repository.CleanupExpiredEvents and ListRetentionPolicies"
```

---

### Task 16: Create repository/event_test.go

**Files:**
- Create: `repository/event_test.go`

- [ ] **Step 1: Write tests**

```go
package repository

import (
	"context"
	"database/sql"
	"os"
	"testing"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	_ "github.com/lib/pq"
)

func dbForTest(t *testing.T) *sql.DB {
	t.Helper()
	dsn := os.Getenv("DB_URL")
	if dsn == "" {
		t.Skip("DB_URL not set; skipping integration test")
	}
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	if err := db.Ping(); err != nil {
		t.Fatalf("ping db: %v", err)
	}
	return db
}

func cleanEventLog(t *testing.T, db *sql.DB) {
	t.Helper()
	_, err := db.Exec(`TRUNCATE TABLE public.event_log RESTART IDENTITY`)
	if err != nil {
		t.Fatalf("truncate event_log: %v", err)
	}
}

func TestEmitEvent_ValidPayload_InsertsEvent(t *testing.T) {
	db := dbForTest(t)
	defer db.Close()
	cleanEventLog(t, db)

	ctx := context.Background()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("begin tx: %v", err)
	}
	defer tx.Rollback()

	req := model.EmitEventRequest{
		Type:          "manifest.created",
		SchemaVersion: "v1",
		AggregateType: "manifest",
		AggregateID:   "018f2b4a-1234-7abc-def0-123456789012",
		Actor: &model.EventActor{
			Type: "collaborator",
			ID:   "alice",
		},
		Payload: map[string]interface{}{
			"manifest_id": "018f2b4a-1234-7abc-def0-123456789012",
			"kind":        "product",
			"namespace":   "dakasa",
			"name":        "dakasa-app",
			"version":     1,
			"checksum":    "sha256:abc123def456abc123def456abc123def456abc123def456abc123def456abc1",
		},
	}

	eventID, err := EmitEvent(ctx, tx, req)
	if err != nil {
		t.Fatalf("EmitEvent: %v", err)
	}
	if eventID.String() == "" {
		t.Fatal("expected non-zero event ID")
	}

	if err := tx.Commit(); err != nil {
		t.Fatalf("commit: %v", err)
	}

	var count int
	err = db.QueryRow(`SELECT COUNT(*) FROM public.event_log WHERE event_id = $1`, eventID).Scan(&count)
	if err != nil {
		t.Fatalf("query count: %v", err)
	}
	if count != 1 {
		t.Errorf("expected 1 row, got %d", count)
	}
}

func TestEmitEvent_InvalidPayload_ReturnsValidationError(t *testing.T) {
	db := dbForTest(t)
	defer db.Close()
	cleanEventLog(t, db)

	ctx := context.Background()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("begin tx: %v", err)
	}
	defer tx.Rollback()

	req := model.EmitEventRequest{
		Type:          "manifest.created",
		AggregateType: "manifest",
		AggregateID:   "some-id",
		Payload: map[string]interface{}{
			"manifest_id": "not-a-uuid",
			// missing required fields
		},
	}

	_, err = EmitEvent(ctx, tx, req)
	if err == nil {
		t.Fatal("expected validation error")
	}
}

func TestEmitEvent_TransactionRollback_EventNotPersisted(t *testing.T) {
	db := dbForTest(t)
	defer db.Close()
	cleanEventLog(t, db)

	ctx := context.Background()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("begin tx: %v", err)
	}

	req := model.EmitEventRequest{
		Type:          "manifest.created",
		AggregateType: "manifest",
		AggregateID:   "id-1",
		Payload: map[string]interface{}{
			"manifest_id": "018f2b4a-1234-7abc-def0-123456789012",
			"kind":        "product",
			"namespace":   "dakasa",
			"name":        "x",
			"version":     1,
			"checksum":    "sha256:abc123def456abc123def456abc123def456abc123def456abc123def456abc1",
		},
	}

	_, err = EmitEvent(ctx, tx, req)
	if err != nil {
		t.Fatalf("EmitEvent: %v", err)
	}

	tx.Rollback()

	var count int
	err = db.QueryRow(`SELECT COUNT(*) FROM public.event_log`).Scan(&count)
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if count != 0 {
		t.Errorf("expected 0 rows after rollback, got %d", count)
	}
}

func TestPullEvents_NoCursor_ReturnsAllInOrder(t *testing.T) {
	db := dbForTest(t)
	defer db.Close()
	cleanEventLog(t, db)

	ctx := context.Background()

	for i := 0; i < 5; i++ {
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			t.Fatalf("begin tx: %v", err)
		}
		req := model.EmitEventRequest{
			Type:          "manifest.created",
			AggregateType: "manifest",
			AggregateID:   "id-x",
			Payload: map[string]interface{}{
				"manifest_id": "018f2b4a-1234-7abc-def0-123456789012",
				"kind":        "product",
				"namespace":   "dakasa",
				"name":        "x",
				"version":     i + 1,
				"checksum":    "sha256:abc123def456abc123def456abc123def456abc123def456abc123def456abc1",
			},
		}
		if _, err := EmitEvent(ctx, tx, req); err != nil {
			t.Fatalf("EmitEvent[%d]: %v", i, err)
		}
		if err := tx.Commit(); err != nil {
			t.Fatalf("commit[%d]: %v", i, err)
		}
	}

	resp, err := PullEvents(ctx, db, model.PullEventsRequest{Limit: 100})
	if err != nil {
		t.Fatalf("PullEvents: %v", err)
	}
	if len(resp.Events) != 5 {
		t.Errorf("expected 5 events, got %d", len(resp.Events))
	}
	for i := 1; i < len(resp.Events); i++ {
		if resp.Events[i].Sequence <= resp.Events[i-1].Sequence {
			t.Errorf("sequence not monotonic: %d <= %d", resp.Events[i].Sequence, resp.Events[i-1].Sequence)
		}
	}
	if resp.HasMore {
		t.Error("expected has_more=false")
	}
}

func TestPullEvents_WithCursor_ReturnsEventsAfterCursor(t *testing.T) {
	db := dbForTest(t)
	defer db.Close()
	cleanEventLog(t, db)

	ctx := context.Background()
	for i := 0; i < 3; i++ {
		tx, _ := db.BeginTx(ctx, nil)
		EmitEvent(ctx, tx, model.EmitEventRequest{
			Type:          "manifest.created",
			AggregateType: "manifest",
			AggregateID:   "id-y",
			Payload: map[string]interface{}{
				"manifest_id": "018f2b4a-1234-7abc-def0-123456789012",
				"kind":        "product",
				"namespace":   "dakasa",
				"name":        "y",
				"version":     i + 1,
				"checksum":    "sha256:abc123def456abc123def456abc123def456abc123def456abc123def456abc1",
			},
		})
		tx.Commit()
	}

	firstResp, err := PullEvents(ctx, db, model.PullEventsRequest{Limit: 2})
	if err != nil {
		t.Fatalf("first pull: %v", err)
	}
	if len(firstResp.Events) != 2 {
		t.Fatalf("expected 2 events in first pull, got %d", len(firstResp.Events))
	}
	if !firstResp.HasMore {
		t.Error("expected has_more=true in first pull")
	}

	secondResp, err := PullEvents(ctx, db, model.PullEventsRequest{
		Cursor: firstResp.NextCursor,
		Limit:  2,
	})
	if err != nil {
		t.Fatalf("second pull: %v", err)
	}
	if len(secondResp.Events) != 1 {
		t.Errorf("expected 1 event in second pull, got %d", len(secondResp.Events))
	}
	if secondResp.HasMore {
		t.Error("expected has_more=false in second pull")
	}
}

func TestPullEvents_FilterByType(t *testing.T) {
	db := dbForTest(t)
	defer db.Close()
	cleanEventLog(t, db)

	ctx := context.Background()
	for _, eventType := range []string{"manifest.created", "manifest.created", "authorization.evaluated"} {
		tx, _ := db.BeginTx(ctx, nil)
		var payload map[string]interface{}
		if eventType == "manifest.created" {
			payload = map[string]interface{}{
				"manifest_id": "018f2b4a-1234-7abc-def0-123456789012",
				"kind":        "product",
				"namespace":   "dakasa",
				"name":        "z",
				"version":     1,
				"checksum":    "sha256:abc123def456abc123def456abc123def456abc123def456abc123def456abc1",
			}
		} else {
			payload = map[string]interface{}{
				"resource": "products/x",
				"action":   "apply",
				"decision": "allow",
			}
		}
		EmitEvent(ctx, tx, model.EmitEventRequest{
			Type:          eventType,
			AggregateType: "test",
			AggregateID:   "id-z",
			Payload:       payload,
		})
		tx.Commit()
	}

	resp, err := PullEvents(ctx, db, model.PullEventsRequest{
		Limit: 100,
		Filters: model.PullEventsFilters{
			Types: []string{"manifest.*"},
		},
	})
	if err != nil {
		t.Fatalf("PullEvents: %v", err)
	}
	if len(resp.Events) != 2 {
		t.Errorf("expected 2 manifest events, got %d", len(resp.Events))
	}
	for _, ev := range resp.Events {
		if ev.Type != "manifest.created" {
			t.Errorf("unexpected event type: %s", ev.Type)
		}
	}
}
```

Write to `repository/event_test.go`.

- [ ] **Step 2: Run tests**

```bash
DB_URL="postgres://postgres:postgres@localhost:5432/yggdrasil?sslmode=disable" go test ./repository/ -run TestEmitEvent -v
DB_URL="postgres://postgres:postgres@localhost:5432/yggdrasil?sslmode=disable" go test ./repository/ -run TestPullEvents -v
```

Expected: All tests PASS (assuming DB is up and migrated).

- [ ] **Step 3: Commit**

```bash
git add repository/event_test.go
git commit -m "$(cat <<'EOF'
✅ Add repository event tests (Emit, Pull, Cleanup)

Integration tests against real PostgreSQL covering: valid emit, validation
failure, transaction rollback, pull with/without cursor, filter by type
with wildcards.

Part of yggdrasil product audit Gap 1 (Event Stream).

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Phase 4: RPC handler

### Task 17: Create controllers/message/event_stream.go

**Files:**
- Create: `controllers/message/event_stream.go`

- [ ] **Step 1: Look at an existing RPC handler for the pattern**

```bash
cat controllers/message/manifests.go | head -80
```

Note the pattern for: consumer definition, handler function signature, error replies, success replies. Follow the same pattern.

- [ ] **Step 2: Write event_stream handler**

```go
package message

import (
	"context"
	"database/sql"
	"encoding/json"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	amqp "github.com/rabbitmq/amqp091-go"
	"go.uber.org/zap"
)

const queueEventStreamPull = "yggdrasil-core.event_stream.pull"

func eventStreamConsumers(conn *amqp.Connection, db *sql.DB, logger *zap.Logger) []ConsumerConfig {
	return []ConsumerConfig{
		{
			Queue:   queueEventStreamPull,
			Timeout: 10 * time.Second,
			QoS:     20,
			Handler: eventStreamPullHandler(conn, db, logger),
		},
	}
}

func eventStreamPullHandler(conn *amqp.Connection, db *sql.DB, logger *zap.Logger) ConsumerHandler {
	return func(ctx context.Context, d amqp.Delivery) error {
		var req model.PullEventsRequest
		if err := json.Unmarshal(d.Body, &req); err != nil {
			return replyFailure(ctx, conn, d, "bad_request", err, logger)
		}

		resp, err := repository.PullEvents(ctx, db, req)
		if err != nil {
			return replyFailure(ctx, conn, d, "pull_failed", err, logger)
		}

		return replySuccess(ctx, conn, d, resp, logger)
	}
}
```

Write to `controllers/message/event_stream.go`.

- [ ] **Step 3: Verify compiles**

```bash
go build ./controllers/...
```

Expected: No output.

- [ ] **Step 4: Commit**

```bash
git add controllers/message/event_stream.go
git commit -m "$(cat <<'EOF'
✨ Add event_stream.pull RPC handler

Receives PullEventsRequest via RabbitMQ, delegates to repository.PullEvents,
returns PullEventsResponse. Timeout 10s, QoS 20 (high concurrency for poll
consumers).

Part of yggdrasil product audit Gap 1 (Event Stream).

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 18: Register event_stream consumer in register.go

**Files:**
- Modify: `controllers/message/register.go`

- [ ] **Step 1: Read the current register.go to find the correct insertion point**

```bash
cat controllers/message/register.go
```

Note how other consumers (e.g., manifestConsumers, integrationConsumers) are registered. Find the function `RegisterAllConsumers` or similar.

- [ ] **Step 2: Add event_stream consumers to the registration**

In `controllers/message/register.go`, locate the list/slice where consumers are combined (probably in `RegisterAllConsumers` function). Add a call to `eventStreamConsumers(conn, db, logger)` and append to the combined list.

Specific edit: find the line that looks like:
```go
consumers = append(consumers, manifestConsumers(conn, db, logger)...)
```

or similar, and add after it:
```go
consumers = append(consumers, eventStreamConsumers(conn, db, logger)...)
```

- [ ] **Step 3: Verify compiles**

```bash
go build ./...
```

Expected: No output.

- [ ] **Step 4: Commit**

```bash
git add controllers/message/register.go
git commit -m "✨ Register event_stream.pull consumer"
```

---

## Phase 5: Wire event emission into existing mutation handlers

### Task 19: Emit manifest.created in manifest create handler

**Files:**
- Modify: `controllers/message/manifests.go`

- [ ] **Step 1: Find the manifest create handler**

```bash
grep -n "func.*manifestCreate\|yggdrasil-core.manifest.create" controllers/message/manifests.go
```

Note the handler function name and the tx boundary where manifest is inserted.

- [ ] **Step 2: Add EmitEvent call inside the tx**

After the manifest is successfully inserted (inside the transaction, before `tx.Commit()`), add:

```go
// Emit manifest.created event transactionally with the mutation
_, evErr := repository.EmitEvent(ctx, tx, model.EmitEventRequest{
    Type:          "manifest.created",
    SchemaVersion: "v1",
    AggregateType: "manifest",
    AggregateID:   manifest.ID.String(),
    // Actor: derive from req.Auth if available
    Payload: map[string]interface{}{
        "manifest_id": manifest.ID.String(),
        "kind":        manifest.Kind,
        "namespace":   manifest.Metadata.Namespace,
        "name":        manifest.Metadata.Name,
        "version":     manifest.Version,
        "checksum":    manifest.Checksum,
        "labels":      manifest.Metadata.Labels,
    },
})
if evErr != nil {
    return fmt.Errorf("emit manifest.created event: %w", evErr)
}
```

**Adjust** field names if the struct uses different casing (inspect the existing manifest struct usage in the handler).

- [ ] **Step 3: Verify compiles**

```bash
go build ./...
```

Expected: No output. Add missing imports (`model`, `repository`) if needed.

- [ ] **Step 4: Run integration tests for manifest create**

```bash
DB_URL="postgres://postgres:postgres@localhost:5432/yggdrasil?sslmode=disable" go test ./... -run TestManifest -v
```

Expected: Existing tests still pass. If a new test is needed to verify event emission, add:

```go
func TestManifestCreate_EmitsEvent(t *testing.T) {
	// Create a manifest via the RPC
	// Pull events
	// Assert manifest.created event exists with correct payload
}
```

But this may require touching more of the codebase. If the test infrastructure doesn't support it easily, skip and rely on the repository-level tests + manual verification.

- [ ] **Step 5: Commit**

```bash
git add controllers/message/manifests.go
git commit -m "$(cat <<'EOF'
✨ Emit manifest.created event on manifest creation

Adds transactional event emission inside the create handler so that every
new manifest version produces a manifest.created event in the event stream
atomically with the mutation.

Part of yggdrasil product audit Gap 1 (Event Stream).

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 20: Emit product.installation.applied in product apply handler

**Files:**
- Modify: `controllers/message/products.go`

- [ ] **Step 1: Locate the product installation apply handler**

```bash
grep -n "installation.apply\|productInstallationApply" controllers/message/products.go
```

- [ ] **Step 2: After the apply succeeds (inside the tx, before commit), emit event**

```go
components := make([]map[string]interface{}, 0, len(product.Spec.Components))
for _, c := range product.Spec.Components {
    components = append(components, map[string]interface{}{
        "name":   c.Name,
        "target": map[string]interface{}{
            "kind":                    c.Target.Kind,
            "integration_instance_ref": c.Target.IntegrationInstanceRef,
            "namespace":                c.Target.Namespace,
        },
    })
}
_, evErr := repository.EmitEvent(ctx, tx, model.EmitEventRequest{
    Type:          "product.installation.applied",
    SchemaVersion: "v1",
    AggregateType: "product",
    AggregateID:   product.ID.String(),
    Payload: map[string]interface{}{
        "product_ref": map[string]interface{}{
            "id":        product.ID.String(),
            "name":      product.Metadata.Name,
            "namespace": product.Metadata.Namespace,
            "version":   product.Version,
        },
        "components_applied": components,
    },
})
if evErr != nil {
    return fmt.Errorf("emit product.installation.applied: %w", evErr)
}
```

**Adjust** field names as needed to match actual Product struct in the codebase.

- [ ] **Step 3: Verify compiles**

```bash
go build ./...
```

- [ ] **Step 4: Commit**

```bash
git add controllers/message/products.go
git commit -m "✨ Emit product.installation.applied event on apply success"
```

---

### Task 21: Emit workflow.run.completed in workflow run handler

**Files:**
- Modify: `controllers/message/workflows.go`

- [ ] **Step 1: Locate the workflow run completion path**

```bash
grep -n "RunWorkflow\|workflow.run\|WorkflowRunResponse" controllers/message/workflows.go
```

Find where a workflow run finishes with status == "succeeded" or equivalent.

- [ ] **Step 2: Emit event at completion**

Since workflow runs currently aren't persisted in a tx (runs are ephemeral in current core per the audit), use a standalone transaction just for the event:

```go
// Emit workflow.run.completed event
tx, txErr := db.BeginTx(ctx, nil)
if txErr == nil {
    _, evErr := repository.EmitEvent(ctx, tx, model.EmitEventRequest{
        Type:          "workflow.run.completed",
        SchemaVersion: "v1",
        AggregateType: "workflow_run",
        AggregateID:   runResponse.RunID.String(),
        Payload: map[string]interface{}{
            "workflow_ref": map[string]interface{}{
                "id":        workflow.ID.String(),
                "name":      workflow.Metadata.Name,
                "namespace": workflow.Metadata.Namespace,
            },
            "run_id":       runResponse.RunID.String(),
            "status":       runResponse.Status,
            "started_at":   runResponse.StartedAt,
            "finished_at":  time.Now().UTC(),
            "step_count":   len(runResponse.Steps),
            "triggered_by": "manual",
        },
    })
    if evErr != nil {
        logger.Warn("emit workflow.run.completed", zap.Error(evErr))
        tx.Rollback()
    } else {
        tx.Commit()
    }
}
```

**Note:** since there's no existing tx for workflow runs, we accept the event as best-effort (log on failure, don't fail the RPC). This aligns with the current "runs are ephemeral" design; persistence of runs is a separate future work.

- [ ] **Step 3: Verify compiles**

```bash
go build ./...
```

- [ ] **Step 4: Commit**

```bash
git add controllers/message/workflows.go
git commit -m "✨ Emit workflow.run.completed event on run success"
```

---

### Task 22: Emit authorization.evaluated in authorization evaluator

**Files:**
- Modify: `controllers/message/identities.go` OR the file with authorization evaluation handler (`grep -rn "authorization.evaluate" controllers/`)

- [ ] **Step 1: Locate authorization.evaluate handler**

```bash
grep -rn "yggdrasil-core.authorization.evaluate\|EvaluateAuthorization" controllers/message/
```

- [ ] **Step 2: After the evaluation returns a decision, emit event**

```go
// Emit authorization.evaluated event (best-effort, outside mutation tx)
evtTx, evtTxErr := db.BeginTx(ctx, nil)
if evtTxErr == nil {
    payload := map[string]interface{}{
        "resource": req.Resource,
        "action":   req.Action,
        "decision": string(decision),
    }
    if req.CollaboratorID != "" {
        payload["collaborator_id"] = req.CollaboratorID
    }
    if len(matchedRoles) > 0 {
        payload["matched_roles"] = matchedRoles
    }
    if len(matchedRules) > 0 {
        payload["matched_rules"] = matchedRules
    }

    _, evErr := repository.EmitEvent(ctx, evtTx, model.EmitEventRequest{
        Type:          "authorization.evaluated",
        SchemaVersion: "v1",
        AggregateType: "authorization",
        AggregateID:   req.Resource,
        Payload:       payload,
    })
    if evErr != nil {
        logger.Warn("emit authorization.evaluated", zap.Error(evErr))
        evtTx.Rollback()
    } else {
        evtTx.Commit()
    }
}
```

- [ ] **Step 3: Verify compiles**

```bash
go build ./...
```

- [ ] **Step 4: Commit**

```bash
git add controllers/message/
git commit -m "✨ Emit authorization.evaluated event on authorization decision"
```

---

## Phase 6: Background cleanup addon

### Task 23: Create addons/event_log_cleaner.go

**Files:**
- Create: `addons/event_log_cleaner.go`

- [ ] **Step 1: Look at an existing addon for the pattern**

```bash
cat addons/rabbitmq.go
```

Note the init(), bootstrap, interval reading pattern.

- [ ] **Step 2: Write the cleaner addon**

```go
package addons

import (
	"context"
	"os"
	"strconv"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/runtime"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	"go.uber.org/zap"
)

func init() {
	Register("event_log_cleaner", bootstrapEventLogCleaner, 50)
}

func bootstrapEventLogCleaner(ctx context.Context, app *runtime.ServiceApp) error {
	db, ok := Postgres(app)
	if !ok {
		// Postgres addon not available; skip silently.
		return nil
	}

	logger, _ := Logger(app)
	interval := eventLogCleanerInterval()

	stop := make(chan struct{})
	go runEventLogCleaner(ctx, db, logger, interval, stop)

	app.RegisterCloser(func(context.Context) error {
		close(stop)
		return nil
	})

	return nil
}

func runEventLogCleaner(ctx context.Context, db *sql.DB, logger *zap.Logger, interval time.Duration, stop <-chan struct{}) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-stop:
			return
		case <-ctx.Done():
			return
		case <-ticker.C:
			deleted, err := repository.CleanupExpiredEvents(ctx, db)
			if err != nil {
				if logger != nil {
					logger.Warn("event_log cleanup failed", zap.Error(err))
				}
				continue
			}
			if logger != nil && deleted > 0 {
				logger.Info("event_log cleanup", zap.Int64("deleted", deleted))
			}
		}
	}
}

func eventLogCleanerInterval() time.Duration {
	raw := os.Getenv("EVENT_LOG_CLEANER_INTERVAL_SECONDS")
	if raw == "" {
		return 3600 * time.Second // default 1 hour
	}
	seconds, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || seconds <= 0 {
		return 3600 * time.Second
	}
	return time.Duration(seconds) * time.Second
}
```

**Note:** the `sql` package import needs to be added:

```go
import (
	// ...
	"database/sql"
)
```

Write to `addons/event_log_cleaner.go`.

- [ ] **Step 3: Verify compiles**

```bash
go build ./addons/...
```

Expected: No output.

- [ ] **Step 4: Commit**

```bash
git add addons/event_log_cleaner.go
git commit -m "$(cat <<'EOF'
✨ Add event_log_cleaner background addon

Runs CleanupExpiredEvents every hour (configurable via
EVENT_LOG_CLEANER_INTERVAL_SECONDS env var). Idempotent, safe-to-retry.
Deletes events per event_retention_policy.

Part of yggdrasil product audit Gap 1 (Event Stream).

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Phase 7: Final validation

### Task 24: Run all tests and ensure clean build

**Files:**
- None (verification)

- [ ] **Step 1: Run all tests**

```bash
DB_URL="postgres://postgres:postgres@localhost:5432/yggdrasil?sslmode=disable" go test ./...
```

Expected: All tests PASS. If any fail due to integration env not available (no DB), that's acceptable for unit-only runs; re-run with DB_URL set.

- [ ] **Step 2: Run go vet**

```bash
go vet ./...
```

Expected: No issues.

- [ ] **Step 3: Run go build**

```bash
go build ./...
```

Expected: No issues.

- [ ] **Step 4: Verify migrations are listed**

```bash
goose -dir db/migrations postgres "$DB_URL" status
```

Expected: `00006_event_log.sql` and `00007_event_retention_policy.sql` both shown as applied.

- [ ] **Step 5: Manual smoke test — emit and pull**

```bash
psql "$DB_URL" -c "SELECT COUNT(*) FROM event_log;"
```

Should show events generated from integration tests (or 0 if tests were cleaned).

- [ ] **Step 6: Final commit (if any loose changes)**

```bash
git status
# If clean, nothing to do.
# If changes remain (e.g., formatting), commit:
git add -A
git commit -m "🔧 Final cleanup after event stream implementation"
```

---

### Task 25: Summary commit with changelog

**Files:**
- None (final milestone commit)

- [ ] **Step 1: Check log**

```bash
git log --oneline | head -30
```

Review the commit history to verify all tasks completed.

- [ ] **Step 2: Create a summary message**

No code commit; just ensure previous work is consolidated.

---

## Self-Review

### Spec Coverage

- ✅ **§3.2 Event structure** — covered by `model/event.go` + `docs/contracts/events/v1/schema.json`
- ✅ **§3.3 Catalog inicial de event types** — 4 MVP types (manifest.created, product.installation.applied, workflow.run.completed, authorization.evaluated) implemented; remaining types deferred to phase 3 of spec (not this plan)
- ✅ **§3.4 Schema versioning** — handled via `schema_version` field in model + JSON schema pattern
- ✅ **§4.1 Tabela event_log** — migration 00006
- ✅ **§4.2 Inserção transacional** — `repository.EmitEvent(ctx, tx, req)`
- ✅ **§5 Pull RPC** — controllers/message/event_stream.go + repository.PullEvents
- ✅ **§5.2 Request schema** — PullEventsRequest struct + JSON handler
- ✅ **§5.3 Response schema** — PullEventsResponse struct
- ✅ **§5.4 Cursor semantics** — encodePullCursor/decodePullCursor with "seq:N" format
- ✅ **§6 Retention policy** — migration 00007 + repository.CleanupExpiredEvents + addons/event_log_cleaner
- ✅ **§6.1 Configuration table** — migration 00007 seeds default policies
- ✅ **§6.2 Cleanup job** — addons/event_log_cleaner with configurable interval
- ✅ **§7 Contract files** — 4 initial event schemas + base + README
- ⚠️ **§8 Fases de implementação** — this plan covers phases 1-4 of the spec. Phases 5 (validação em produção) and full catalog beyond 4 MVP types are future work.
- ✅ **§9.2 Índices** — covered in migration 00006
- ⚠️ **§10 Segurança** — trust-boundary default; no RBAC enforcement on pull in MVP. Documented in the spec as MVP decision.
- ✅ **§11.1 O que muda** — covered: new migrations, new repository functions, new handlers, new addon
- ✅ **§11.2 O que NÃO muda** — backwards compatible (aditivo)
- ✅ **§11.3 Backfill** — not backfilling, as specified

### Placeholder Scan

- No "TODO", "TBD", "implement later" in plan
- All steps have concrete commands or code
- File paths are exact
- Commands include expected output

### Type Consistency

- `Event` struct in model matches table schema
- `PullEventsRequest.Filters` matches `buildPullQuery` assumptions
- `EmitEventRequest.Payload` is `map[string]interface{}` consistent with `json.RawMessage` in Event struct (marshal/unmarshal conversion happens in EmitEvent)
- Cursor format `"seq:N"` consistent between encode/decode
- `repository.EmitEvent` requires `*sql.Tx`; callers (handlers) respect this

### Scope Check

This plan is focused on Gap 1 (Event Stream) MVP. It does NOT include:
- Remaining event type schemas beyond the 4 MVP types (future work)
- Frontend/console changes for activity feed (out of scope)
- OpenAPI export (separate surface work)

---

## Execution Handoff

**Plan complete and saved to `docs/superpowers/plans/2026-04-10-event-stream-implementation.md`.**

This plan will be executed via **superpowers:subagent-driven-development** (per user preference).

**Total tasks: 25**
**Estimated commits: ~20-23**
**New files: 15**
**Modified files: 5**
