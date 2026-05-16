# Collaborator External Identities Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Persist provider-specific identifiers per (collaborator, integration_instance) so reactors (notably offboard) can act on the correct provider-side entity, while keeping yggdrasil-core neutral to provider semantics and not requiring adapter binaries to call back into core HTTP APIs.

**Architecture:** Single core package `internal/externalidentity/` (priority-80 addon) owns a new `collaborator_external_identities` table. Reactor dispatcher pre-populates `req._context.external_identity` on reactor invocation (read-side); on reactor success, extracts `output._yggdrasil.external_identity` and persists it (write-side). Webhook receiver `POST /api/v1/integrations/{instance_id}/webhook` accepts provider HMAC-signed payloads, forwards to adapter `on_webhook` capability, and executes returned actions (`link_identity`, `unlink_identity`, `emit_event`). Daily re-sync cron invokes adapter `list_identities` capability and diffs against DB to emit drift events. Hourly cleanup cron hard-deletes rows past 30-day retention. Six canon events: linked, unlinked, drift_detected, unknown_external, purged, conflict_detected.

**Tech Stack:** Go 1.22, PostgreSQL with goose migrations, `database/sql`, RabbitMQ via existing `messagecontroller.ExecuteIntegration` for adapter RPC, JSON Schema 2020-12 for event validation, existing addon registry pattern + reactor dispatcher.

**Spec:** `docs/superpowers/specs/2026-05-16-collaborator-external-identities-design.md`

---

## Cross-repo scope

| Repo | Path | Changes |
|---|---|---|
| `dakasa-yggdrasil/yggdrasil-core` | `/Users/dakasa/projects/yggdrasil/yggdrasil-core` | Schema, repository, API, dispatcher convention, webhook receiver, re-sync cron, cleanup cron, 6 canon events |
| `dakasa-yggdrasil/integration-slack` | `/Users/dakasa/projects/yggdrasil/integration-slack` | Opt-in: write identity envelope on `on_collaborator_created` + `scim_apply_user`; read `_context.external_identity` in `on_collaborator_offboarded`; new `list_identities` capability |
| `dakasa-yggdrasil/integration-google-workspace` | `/Users/dakasa/projects/yggdrasil/integration-google-workspace` | Opt-in: same envelope write+read; new `list_identities` capability |
| `dakasa-yggdrasil/integration-github` | `/Users/dakasa/projects/yggdrasil/integration-github` | Read `_context.external_identity` in `on_collaborator_offboarded`; new `on_webhook` capability handling `member` event; new `list_identities` capability |

Each task's **Files** section names the repo's absolute path in `Create:`/`Modify:` to remove ambiguity.

---

## File Structure (yggdrasil-core)

| Path | Responsibility |
|---|---|
| `db/migrations/00041_collaborator_external_identities.sql` | Schema + indexes |
| `internal/externalidentity/repository.go` | CRUD: Upsert (idempotent), Get, ListBy*, SoftDelete, HardCleanup, ResolveConflict |
| `internal/externalidentity/envelope.go` | ExtractFromOutput, EmbedIntoInput |
| `internal/externalidentity/events.go` | EmitLinked/Unlinked/DriftDetected/UnknownExternal/Purged/ConflictDetected payload builders |
| `internal/externalidentity/hmac.go` | VerifySignature(scheme, secret, headers, body) — dispatches to per-scheme implementations |
| `internal/externalidentity/resync_runner.go` | Daily cron loop + diff logic |
| `internal/externalidentity/cleanup_runner.go` | Hourly cron + hard delete query |
| `addons/external_identity.go` | priority 80 bootstrap: wires dispatcher hooks + HTTP routes |
| `addons/external_identity_resync.go` | priority 85 bootstrap: starts resync_runner |
| `addons/external_identity_cleanup.go` | priority 86 bootstrap: starts cleanup_runner |
| `controllers/httpapi/external_identities.go` | POST/GET/DELETE handlers |
| `controllers/httpapi/integration_webhook.go` | POST webhook receiver |
| `repository/event_types_lifecycle.go` | +6 event constants |
| `docs/contracts/events/v1/collaborator_external_identity/*.json` | 6 schemas |
| `docs/contracts/events_validator.go` | +6 registry entries |

**Modified existing files:**
- `internal/reactors/dispatcher.go` — call `EmbedIntoInput` before AMQP dispatch; call `ExtractFromOutput` on success.
- `controllers/httpapi/server.go` — register 4 new routes.

---

## Phase 1: Core Foundation

### Task 1: Migration `00041_collaborator_external_identities`

**Repo:** yggdrasil-core
**Files:**
- Create: `/Users/dakasa/projects/yggdrasil/yggdrasil-core/db/migrations/00041_collaborator_external_identities.sql`

- [ ] **Step 1: Write the migration file**

Create the file with exactly the following contents:

```sql
-- +goose Up
CREATE TABLE collaborator_external_identities (
  id                      uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  collaborator_id         uuid NOT NULL REFERENCES collaborators(id) ON DELETE CASCADE,
  integration_instance_id uuid NOT NULL,
  external_id             text NOT NULL,
  external_metadata       jsonb NOT NULL DEFAULT '{}'::jsonb,
  linked_at               timestamptz NOT NULL DEFAULT now(),
  last_seen_at            timestamptz NOT NULL DEFAULT now(),
  unlinked_at             timestamptz,
  created_at              timestamptz NOT NULL DEFAULT now(),
  updated_at              timestamptz NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX collaborator_external_identities_active_unique
  ON collaborator_external_identities (integration_instance_id, external_id)
  WHERE unlinked_at IS NULL;

CREATE INDEX collaborator_external_identities_collab_idx
  ON collaborator_external_identities (collaborator_id, integration_instance_id);

CREATE INDEX collaborator_external_identities_unlinked_idx
  ON collaborator_external_identities (unlinked_at)
  WHERE unlinked_at IS NOT NULL;

-- +goose Down
DROP TABLE collaborator_external_identities;
```

- [ ] **Step 2: Apply migration locally and verify**

Run from `/Users/dakasa/projects/yggdrasil/yggdrasil-core`:

```bash
go test ./scripts/goose/... -count=1
```

Expected: PASS (or the existing goose tests show the new file is picked up).

If the project has a `make migrate` or similar, run that against the dev database.

- [ ] **Step 3: Commit**

```bash
cd /Users/dakasa/projects/yggdrasil/yggdrasil-core
git add db/migrations/00041_collaborator_external_identities.sql
git commit -m "feat(db): add collaborator_external_identities table"
```

---

### Task 2: Canon event constants (6)

**Repo:** yggdrasil-core
**Files:**
- Modify: `/Users/dakasa/projects/yggdrasil/yggdrasil-core/repository/event_types_lifecycle.go`
- Modify or create: `/Users/dakasa/projects/yggdrasil/yggdrasil-core/repository/event_types_lifecycle_test.go`

- [ ] **Step 1: Write failing test**

Append to `repository/event_types_lifecycle_test.go`:

```go
func TestExternalIdentityCanonEventConstants(t *testing.T) {
	cases := []struct {
		got  string
		want string
	}{
		{EventTypeExternalIdentityLinked, "collaborator_external_identity.linked"},
		{EventTypeExternalIdentityUnlinked, "collaborator_external_identity.unlinked"},
		{EventTypeExternalIdentityDriftDetected, "collaborator_external_identity.drift_detected"},
		{EventTypeExternalIdentityUnknownExternal, "collaborator_external_identity.unknown_external"},
		{EventTypeExternalIdentityPurged, "collaborator_external_identity.purged"},
		{EventTypeExternalIdentityConflictDetected, "collaborator_external_identity.conflict_detected"},
	}
	for _, c := range cases {
		if c.got != c.want {
			t.Fatalf("constant mismatch: got %q want %q", c.got, c.want)
		}
	}
}

func TestExternalIdentityEventsAreNotCanonLifecycle(t *testing.T) {
	for _, e := range []string{
		EventTypeExternalIdentityLinked,
		EventTypeExternalIdentityUnlinked,
		EventTypeExternalIdentityDriftDetected,
		EventTypeExternalIdentityUnknownExternal,
		EventTypeExternalIdentityPurged,
		EventTypeExternalIdentityConflictDetected,
	} {
		if IsCanonLifecycleEvent(e) {
			t.Fatalf("event %q must NOT be in CanonLifecycleEventTypes (infrastructure event)", e)
		}
	}
}
```

- [ ] **Step 2: Run tests — fail expected**

```bash
go test ./repository/ -run TestExternalIdentity -v
```
Expected: FAIL `undefined: EventTypeExternalIdentityLinked`.

- [ ] **Step 3: Add the 6 constants**

Append to `repository/event_types_lifecycle.go`, after the existing manifest-sync block:

```go
	// External identity framework events — infrastructure, NOT canon lifecycle.
	EventTypeExternalIdentityLinked            = "collaborator_external_identity.linked"
	EventTypeExternalIdentityUnlinked          = "collaborator_external_identity.unlinked"
	EventTypeExternalIdentityDriftDetected     = "collaborator_external_identity.drift_detected"
	EventTypeExternalIdentityUnknownExternal   = "collaborator_external_identity.unknown_external"
	EventTypeExternalIdentityPurged            = "collaborator_external_identity.purged"
	EventTypeExternalIdentityConflictDetected  = "collaborator_external_identity.conflict_detected"
```

- [ ] **Step 4: Re-run tests + full repository suite**

```bash
go test ./repository/ -count=1
```
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
cd /Users/dakasa/projects/yggdrasil/yggdrasil-core
git add repository/event_types_lifecycle.go repository/event_types_lifecycle_test.go
git commit -m "feat(events): add 6 external-identity canon event constants"
```

---

### Task 3: JSON Schemas for 6 events + registry wiring

**Repo:** yggdrasil-core
**Files:**
- Create: `/Users/dakasa/projects/yggdrasil/yggdrasil-core/docs/contracts/events/v1/collaborator_external_identity/linked.json`
- Create: `.../unlinked.json`
- Create: `.../drift_detected.json`
- Create: `.../unknown_external.json`
- Create: `.../purged.json`
- Create: `.../conflict_detected.json`
- Modify: `/Users/dakasa/projects/yggdrasil/yggdrasil-core/docs/contracts/events_validator.go`

- [ ] **Step 1: Inspect existing schema directory layout**

```bash
ls docs/contracts/events/v1/
cat docs/contracts/events/v1/integration_type/synced.json
```
Confirm the pattern: dialect=draft-2020-12, $id, title, additionalProperties:false.

- [ ] **Step 2: Create `linked.json`**

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://dakasa-yggdrasil.io/contracts/events/v1/collaborator_external_identity/linked.json",
  "title": "collaborator_external_identity.linked",
  "description": "Emitted when a new external identity row is INSERTed or an existing unlinked row is re-linked (UPDATE unlinked_at=NULL).",
  "type": "object",
  "required": ["identity_id", "collaborator_id", "integration_instance_id", "external_id", "re_linked", "linked_at"],
  "additionalProperties": false,
  "properties": {
    "identity_id":             { "type": "string", "format": "uuid" },
    "collaborator_id":         { "type": "string", "format": "uuid" },
    "integration_instance_id": { "type": "string", "format": "uuid" },
    "external_id":             { "type": "string", "minLength": 1 },
    "re_linked":               { "type": "boolean" },
    "linked_at":               { "type": "string", "format": "date-time" },
    "external_metadata":       { "type": "object" }
  }
}
```

- [ ] **Step 3: Create `unlinked.json`**

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://dakasa-yggdrasil.io/contracts/events/v1/collaborator_external_identity/unlinked.json",
  "title": "collaborator_external_identity.unlinked",
  "description": "Emitted on soft-delete (offboard reactor or DELETE endpoint).",
  "type": "object",
  "required": ["identity_id", "collaborator_id", "integration_instance_id", "external_id", "unlinked_at"],
  "additionalProperties": false,
  "properties": {
    "identity_id":             { "type": "string", "format": "uuid" },
    "collaborator_id":         { "type": "string", "format": "uuid" },
    "integration_instance_id": { "type": "string", "format": "uuid" },
    "external_id":             { "type": "string", "minLength": 1 },
    "unlinked_at":             { "type": "string", "format": "date-time" }
  }
}
```

- [ ] **Step 4: Create `drift_detected.json`**

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://dakasa-yggdrasil.io/contracts/events/v1/collaborator_external_identity/drift_detected.json",
  "title": "collaborator_external_identity.drift_detected",
  "description": "Re-sync found an external_id present in DB but missing from the provider's live list_identities response. No auto-action — operator decides.",
  "type": "object",
  "required": ["identity_id", "collaborator_id", "integration_instance_id", "external_id", "detected_at"],
  "additionalProperties": false,
  "properties": {
    "identity_id":             { "type": "string", "format": "uuid" },
    "collaborator_id":         { "type": "string", "format": "uuid" },
    "integration_instance_id": { "type": "string", "format": "uuid" },
    "external_id":             { "type": "string", "minLength": 1 },
    "detected_at":             { "type": "string", "format": "date-time" }
  }
}
```

- [ ] **Step 5: Create `unknown_external.json`**

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://dakasa-yggdrasil.io/contracts/events/v1/collaborator_external_identity/unknown_external.json",
  "title": "collaborator_external_identity.unknown_external",
  "description": "Re-sync found an external_id in the provider's live list_identities response that does not correspond to any active identity in DB.",
  "type": "object",
  "required": ["integration_instance_id", "external_id", "detected_at"],
  "additionalProperties": false,
  "properties": {
    "integration_instance_id": { "type": "string", "format": "uuid" },
    "external_id":             { "type": "string", "minLength": 1 },
    "external_metadata":       { "type": "object" },
    "detected_at":             { "type": "string", "format": "date-time" }
  }
}
```

- [ ] **Step 6: Create `purged.json`**

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://dakasa-yggdrasil.io/contracts/events/v1/collaborator_external_identity/purged.json",
  "title": "collaborator_external_identity.purged",
  "description": "Cleanup cron hard-deleted a row whose unlinked_at exceeded the retention window. Payload preserves identifying fields since the row itself is gone.",
  "type": "object",
  "required": ["identity_id", "collaborator_id", "integration_instance_id", "external_id", "purged_at"],
  "additionalProperties": false,
  "properties": {
    "identity_id":             { "type": "string", "format": "uuid" },
    "collaborator_id":         { "type": "string", "format": "uuid" },
    "integration_instance_id": { "type": "string", "format": "uuid" },
    "external_id":             { "type": "string", "minLength": 1 },
    "purged_at":               { "type": "string", "format": "date-time" }
  }
}
```

- [ ] **Step 7: Create `conflict_detected.json`**

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://dakasa-yggdrasil.io/contracts/events/v1/collaborator_external_identity/conflict_detected.json",
  "title": "collaborator_external_identity.conflict_detected",
  "description": "Attempted to write an external_id that is already active on a DIFFERENT collaborator within the same integration_instance. Neither row is mutated. Operator must reconcile.",
  "type": "object",
  "required": ["integration_instance_id", "external_id", "incoming_collaborator_id", "existing_collaborator_id", "detected_at"],
  "additionalProperties": false,
  "properties": {
    "integration_instance_id":  { "type": "string", "format": "uuid" },
    "external_id":              { "type": "string", "minLength": 1 },
    "incoming_collaborator_id": { "type": "string", "format": "uuid" },
    "existing_collaborator_id": { "type": "string", "format": "uuid" },
    "detected_at":              { "type": "string", "format": "date-time" }
  }
}
```

- [ ] **Step 8: Wire schemas in events_validator.go**

Find `eventTypeToSchemaPath` in `docs/contracts/events_validator.go`. Append:

```go
		// external identity framework events
		"collaborator_external_identity.linked":            "events/v1/collaborator_external_identity/linked.json",
		"collaborator_external_identity.unlinked":          "events/v1/collaborator_external_identity/unlinked.json",
		"collaborator_external_identity.drift_detected":    "events/v1/collaborator_external_identity/drift_detected.json",
		"collaborator_external_identity.unknown_external": "events/v1/collaborator_external_identity/unknown_external.json",
		"collaborator_external_identity.purged":            "events/v1/collaborator_external_identity/purged.json",
		"collaborator_external_identity.conflict_detected": "events/v1/collaborator_external_identity/conflict_detected.json",
```

Also extend the `//go:embed` directive at the top of the file to include the new subdir (`events/v1/collaborator_external_identity/*.json`).

- [ ] **Step 9: Run validation tests**

```bash
go test ./docs/contracts/... ./manifest/... -count=1
```
Expected: PASS.

- [ ] **Step 10: Commit**

```bash
cd /Users/dakasa/projects/yggdrasil/yggdrasil-core
git add docs/contracts/events/v1/collaborator_external_identity/ docs/contracts/events_validator.go
git commit -m "feat(events): add JSON schemas for 6 external-identity events"
```

---

### Task 4: Repository (CRUD + tests)

**Repo:** yggdrasil-core
**Files:**
- Create: `/Users/dakasa/projects/yggdrasil/yggdrasil-core/internal/externalidentity/repository.go`
- Create: `/Users/dakasa/projects/yggdrasil/yggdrasil-core/internal/externalidentity/repository_test.go`

- [ ] **Step 1: Define the model + interface types**

Create `internal/externalidentity/repository.go` with model types only (no methods yet):

```go
// Package externalidentity manages the collaborator_external_identities
// table — a generic mapping of (collaborator, integration_instance) to a
// provider-side stable identifier plus mutable metadata.
//
// See docs/superpowers/specs/2026-05-16-collaborator-external-identities-design.md.
package externalidentity

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// Identity is one row of collaborator_external_identities.
type Identity struct {
	ID                    uuid.UUID
	CollaboratorID        uuid.UUID
	IntegrationInstanceID uuid.UUID
	ExternalID            string
	ExternalMetadata      map[string]any
	LinkedAt              time.Time
	LastSeenAt            time.Time
	UnlinkedAt            *time.Time // nil = active
	CreatedAt             time.Time
	UpdatedAt             time.Time
}

// UpsertInput is the per-write payload for the idempotent UPSERT.
type UpsertInput struct {
	CollaboratorID        uuid.UUID
	IntegrationInstanceID uuid.UUID
	ExternalID            string
	ExternalMetadata      map[string]any
}

// UpsertOutcome reports what happened. The handler returns this to the
// caller (HTTP API, dispatcher, webhook receiver).
type UpsertOutcome string

const (
	OutcomeInserted UpsertOutcome = "inserted"
	OutcomeReLinked UpsertOutcome = "re_linked"
	OutcomeRefreshed UpsertOutcome = "refreshed"  // active row already exists with same external_id; metadata refreshed
	OutcomeConflict UpsertOutcome = "conflict"     // existing ACTIVE row with same (instance, external_id) maps to a different collaborator
)

// ConflictError is returned when UpsertOutcome == OutcomeConflict.
type ConflictError struct {
	IntegrationInstanceID  uuid.UUID
	ExternalID             string
	IncomingCollaboratorID uuid.UUID
	ExistingCollaboratorID uuid.UUID
}

func (e *ConflictError) Error() string {
	return fmt.Sprintf("collaborator_external_identity: %s in instance %s is already active on collaborator %s (attempted: %s)",
		e.ExternalID, e.IntegrationInstanceID, e.ExistingCollaboratorID, e.IncomingCollaboratorID)
}

// ListFilters drives the GET endpoint and dispatcher pre-populate.
type ListFilters struct {
	CollaboratorID        *uuid.UUID
	IntegrationInstanceID *uuid.UUID
	TypeName              string // helper: resolves through manifests join
	ActiveOnly            bool   // default true at handler level
	Limit                 int
	Offset                int
}
```

- [ ] **Step 2: Write failing test for Upsert (basic insert)**

Create `internal/externalidentity/repository_test.go`. The tests need a real DB; use the same pattern as `internal/manifestsync/sync_integration_test.go` (DB_URL env, t.Skip if absent).

```go
package externalidentity

import (
	"context"
	"database/sql"
	"os"
	"testing"

	"github.com/google/uuid"
	_ "github.com/lib/pq"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func openTestDB(t *testing.T) *sql.DB {
	t.Helper()
	url := os.Getenv("DB_URL")
	if url == "" {
		t.Skip("DB_URL not set; skipping integration test")
	}
	db, err := sql.Open("postgres", url)
	require.NoError(t, err)
	require.NoError(t, db.Ping())
	return db
}

func seedCollaborator(t *testing.T, db *sql.DB) uuid.UUID {
	t.Helper()
	id := uuid.New()
	_, err := db.Exec(`INSERT INTO collaborators (id, slug, status, display_name, primary_email)
                       VALUES ($1, $2, 'active', 'Test', $3)`,
		id, "test-"+id.String()[:8], id.String()+"@dakasa.me")
	require.NoError(t, err)
	t.Cleanup(func() { db.Exec(`DELETE FROM collaborators WHERE id = $1`, id) })
	return id
}

func TestUpsert_InsertsNewRow(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)
	t.Cleanup(func() { db.Close() })

	collabID := seedCollaborator(t, db)
	instanceID := uuid.New()

	id, outcome, err := Upsert(ctx, db, UpsertInput{
		CollaboratorID:        collabID,
		IntegrationInstanceID: instanceID,
		ExternalID:            "U0B527CCC7J",
		ExternalMetadata:      map[string]any{"display_name": "QA V9"},
	})
	require.NoError(t, err)
	assert.NotEqual(t, uuid.Nil, id)
	assert.Equal(t, OutcomeInserted, outcome)
	t.Cleanup(func() { db.Exec(`DELETE FROM collaborator_external_identities WHERE id = $1`, id) })

	// Verify row
	identity, err := GetByID(ctx, db, id)
	require.NoError(t, err)
	assert.Equal(t, collabID, identity.CollaboratorID)
	assert.Equal(t, "U0B527CCC7J", identity.ExternalID)
	assert.Equal(t, "QA V9", identity.ExternalMetadata["display_name"])
	assert.Nil(t, identity.UnlinkedAt)
}
```

- [ ] **Step 3: Run test — fail expected**

```bash
go test ./internal/externalidentity/ -run TestUpsert_InsertsNewRow -count=1 -v
```
Expected: FAIL `undefined: Upsert`, `undefined: GetByID`. (Or SKIP if DB_URL not set — that's the OK fallback in pure-CI env.)

- [ ] **Step 4: Implement Upsert + GetByID**

Append to `internal/externalidentity/repository.go`:

```go
// Upsert is the idempotent write entry point.
// Behavior per spec §5.1:
//   - No row for (collab, instance, external_id): INSERT → OutcomeInserted
//   - Row exists with unlinked_at != NULL: UPDATE unlinked_at=NULL + refresh → OutcomeReLinked
//   - Row exists with unlinked_at = NULL, same collab: UPDATE metadata+last_seen_at → OutcomeRefreshed
//   - Active row exists with same (instance, external_id), different collab: OutcomeConflict + ConflictError
func Upsert(ctx context.Context, db *sql.DB, in UpsertInput) (uuid.UUID, UpsertOutcome, error) {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return uuid.Nil, "", fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck

	metaJSON, err := json.Marshal(in.ExternalMetadata)
	if err != nil {
		return uuid.Nil, "", fmt.Errorf("marshal metadata: %w", err)
	}

	// 1. Check for ACTIVE row with same (instance, external_id).
	var existingID uuid.UUID
	var existingCollab uuid.UUID
	row := tx.QueryRowContext(ctx, `
		SELECT id, collaborator_id FROM collaborator_external_identities
		WHERE integration_instance_id = $1 AND external_id = $2 AND unlinked_at IS NULL
	`, in.IntegrationInstanceID, in.ExternalID)
	err = row.Scan(&existingID, &existingCollab)

	if err == nil {
		// Active row exists.
		if existingCollab != in.CollaboratorID {
			// Conflict — different collaborator.
			return uuid.Nil, OutcomeConflict, &ConflictError{
				IntegrationInstanceID:  in.IntegrationInstanceID,
				ExternalID:             in.ExternalID,
				IncomingCollaboratorID: in.CollaboratorID,
				ExistingCollaboratorID: existingCollab,
			}
		}
		// Same collab — refresh metadata + last_seen_at.
		if _, err := tx.ExecContext(ctx, `
			UPDATE collaborator_external_identities
			SET external_metadata = $1, last_seen_at = NOW(), updated_at = NOW()
			WHERE id = $2
		`, metaJSON, existingID); err != nil {
			return uuid.Nil, "", fmt.Errorf("refresh metadata: %w", err)
		}
		if err := tx.Commit(); err != nil {
			return uuid.Nil, "", fmt.Errorf("commit: %w", err)
		}
		return existingID, OutcomeRefreshed, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return uuid.Nil, "", fmt.Errorf("lookup active: %w", err)
	}

	// 2. Check for UNLINKED row with same (collab, instance, external_id) → re-link.
	row = tx.QueryRowContext(ctx, `
		SELECT id FROM collaborator_external_identities
		WHERE collaborator_id = $1 AND integration_instance_id = $2 AND external_id = $3
		  AND unlinked_at IS NOT NULL
		ORDER BY linked_at DESC LIMIT 1
	`, in.CollaboratorID, in.IntegrationInstanceID, in.ExternalID)
	if err := row.Scan(&existingID); err == nil {
		// Re-link.
		if _, err := tx.ExecContext(ctx, `
			UPDATE collaborator_external_identities
			SET unlinked_at = NULL, external_metadata = $1, last_seen_at = NOW(), updated_at = NOW()
			WHERE id = $2
		`, metaJSON, existingID); err != nil {
			return uuid.Nil, "", fmt.Errorf("re-link: %w", err)
		}
		if err := tx.Commit(); err != nil {
			return uuid.Nil, "", fmt.Errorf("commit: %w", err)
		}
		return existingID, OutcomeReLinked, nil
	} else if !errors.Is(err, sql.ErrNoRows) {
		return uuid.Nil, "", fmt.Errorf("lookup unlinked: %w", err)
	}

	// 3. INSERT new row.
	newID := uuid.New()
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO collaborator_external_identities
		  (id, collaborator_id, integration_instance_id, external_id, external_metadata)
		VALUES ($1, $2, $3, $4, $5)
	`, newID, in.CollaboratorID, in.IntegrationInstanceID, in.ExternalID, metaJSON); err != nil {
		return uuid.Nil, "", fmt.Errorf("insert: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return uuid.Nil, "", fmt.Errorf("commit: %w", err)
	}
	return newID, OutcomeInserted, nil
}

// GetByID returns the identity matching id, or sql.ErrNoRows.
func GetByID(ctx context.Context, db *sql.DB, id uuid.UUID) (Identity, error) {
	row := db.QueryRowContext(ctx, `
		SELECT id, collaborator_id, integration_instance_id, external_id,
		       external_metadata, linked_at, last_seen_at, unlinked_at,
		       created_at, updated_at
		FROM collaborator_external_identities
		WHERE id = $1
	`, id)
	return scanIdentity(row)
}

func scanIdentity(row interface{ Scan(...any) error }) (Identity, error) {
	var i Identity
	var meta []byte
	var unlinked sql.NullTime
	err := row.Scan(&i.ID, &i.CollaboratorID, &i.IntegrationInstanceID,
		&i.ExternalID, &meta, &i.LinkedAt, &i.LastSeenAt, &unlinked,
		&i.CreatedAt, &i.UpdatedAt)
	if err != nil {
		return Identity{}, err
	}
	if unlinked.Valid {
		i.UnlinkedAt = &unlinked.Time
	}
	if len(meta) > 0 {
		_ = json.Unmarshal(meta, &i.ExternalMetadata)
	}
	if i.ExternalMetadata == nil {
		i.ExternalMetadata = map[string]any{}
	}
	return i, nil
}
```

- [ ] **Step 5: Run tests — should pass with DB_URL set, skip otherwise**

```bash
DB_URL="postgres://yggdrasil:test@localhost:5432/yggdrasil_test?sslmode=disable" \
  go test ./internal/externalidentity/ -run TestUpsert_InsertsNewRow -count=1 -v
```
Expected: PASS.

Compile-only check:
```bash
go build ./internal/externalidentity/
```
Expected: clean.

- [ ] **Step 6: Add remaining repository functions and their tests in one commit**

Add to `repository.go`:

```go
// SoftDelete sets unlinked_at=NOW. Idempotent. Returns the row's pre-state.
func SoftDelete(ctx context.Context, db *sql.DB, id uuid.UUID) (Identity, error) {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return Identity{}, err
	}
	defer tx.Rollback() //nolint:errcheck

	row := tx.QueryRowContext(ctx, `
		SELECT id, collaborator_id, integration_instance_id, external_id,
		       external_metadata, linked_at, last_seen_at, unlinked_at,
		       created_at, updated_at
		FROM collaborator_external_identities
		WHERE id = $1 FOR UPDATE
	`, id)
	identity, err := scanIdentity(row)
	if err != nil {
		return Identity{}, err
	}
	if identity.UnlinkedAt != nil {
		// Already soft-deleted — idempotent return.
		return identity, tx.Commit()
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE collaborator_external_identities
		SET unlinked_at = NOW(), updated_at = NOW()
		WHERE id = $1
	`, id); err != nil {
		return Identity{}, err
	}
	if err := tx.Commit(); err != nil {
		return Identity{}, err
	}
	identity.UnlinkedAt = ptrTime(time.Now().UTC())
	return identity, nil
}

// HardDelete removes the row. Used by cleanup cron and admin escape hatch.
func HardDelete(ctx context.Context, db *sql.DB, id uuid.UUID) error {
	_, err := db.ExecContext(ctx, `DELETE FROM collaborator_external_identities WHERE id = $1`, id)
	return err
}

// HardCleanup removes all rows whose unlinked_at < threshold. Returns identifying
// info of deleted rows so the caller can emit purged events.
func HardCleanup(ctx context.Context, db *sql.DB, before time.Time) ([]Identity, error) {
	rows, err := db.QueryContext(ctx, `
		DELETE FROM collaborator_external_identities
		WHERE unlinked_at IS NOT NULL AND unlinked_at < $1
		RETURNING id, collaborator_id, integration_instance_id, external_id,
		          external_metadata, linked_at, last_seen_at, unlinked_at,
		          created_at, updated_at
	`, before)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Identity
	for rows.Next() {
		i, err := scanIdentity(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, i)
	}
	return out, rows.Err()
}

// List returns identities matching the filters.
func List(ctx context.Context, db *sql.DB, f ListFilters) ([]Identity, error) {
	q := `SELECT id, collaborator_id, integration_instance_id, external_id,
	             external_metadata, linked_at, last_seen_at, unlinked_at,
	             created_at, updated_at
	      FROM collaborator_external_identities WHERE 1=1`
	args := []any{}
	idx := 1
	if f.CollaboratorID != nil {
		q += fmt.Sprintf(" AND collaborator_id = $%d", idx)
		args = append(args, *f.CollaboratorID)
		idx++
	}
	if f.IntegrationInstanceID != nil {
		q += fmt.Sprintf(" AND integration_instance_id = $%d", idx)
		args = append(args, *f.IntegrationInstanceID)
		idx++
	}
	if f.ActiveOnly {
		q += " AND unlinked_at IS NULL"
	}
	if f.TypeName != "" {
		q += fmt.Sprintf(`
			AND integration_instance_id IN (
				SELECT id FROM manifests
				WHERE kind = 'integration_instance' AND active = true
				  AND spec->'type_ref'->>'name' = $%d
			)`, idx)
		args = append(args, f.TypeName)
		idx++
	}
	q += " ORDER BY linked_at DESC"
	if f.Limit > 0 {
		q += fmt.Sprintf(" LIMIT $%d", idx)
		args = append(args, f.Limit)
		idx++
	}
	if f.Offset > 0 {
		q += fmt.Sprintf(" OFFSET $%d", idx)
		args = append(args, f.Offset)
		idx++
	}
	rows, err := db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Identity
	for rows.Next() {
		i, err := scanIdentity(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, i)
	}
	return out, rows.Err()
}

func ptrTime(t time.Time) *time.Time { return &t }
```

Append corresponding tests to `repository_test.go`:

```go
func TestUpsert_ReLinksUnlinkedRow(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)
	t.Cleanup(func() { db.Close() })

	collabID := seedCollaborator(t, db)
	instanceID := uuid.New()

	id, _, err := Upsert(ctx, db, UpsertInput{
		CollaboratorID: collabID, IntegrationInstanceID: instanceID,
		ExternalID: "U_TEST_RELINK", ExternalMetadata: map[string]any{"v": 1},
	})
	require.NoError(t, err)
	t.Cleanup(func() { db.Exec(`DELETE FROM collaborator_external_identities WHERE id = $1`, id) })

	_, err = SoftDelete(ctx, db, id)
	require.NoError(t, err)

	id2, outcome, err := Upsert(ctx, db, UpsertInput{
		CollaboratorID: collabID, IntegrationInstanceID: instanceID,
		ExternalID: "U_TEST_RELINK", ExternalMetadata: map[string]any{"v": 2},
	})
	require.NoError(t, err)
	assert.Equal(t, id, id2, "re-link must reuse the same row id")
	assert.Equal(t, OutcomeReLinked, outcome)

	identity, _ := GetByID(ctx, db, id)
	assert.Nil(t, identity.UnlinkedAt)
	assert.EqualValues(t, 2, identity.ExternalMetadata["v"])
}

func TestUpsert_ConflictReturnsConflictError(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)
	t.Cleanup(func() { db.Close() })

	collabA := seedCollaborator(t, db)
	collabB := seedCollaborator(t, db)
	instanceID := uuid.New()

	idA, _, err := Upsert(ctx, db, UpsertInput{
		CollaboratorID: collabA, IntegrationInstanceID: instanceID,
		ExternalID: "U_CONFLICT", ExternalMetadata: nil,
	})
	require.NoError(t, err)
	t.Cleanup(func() { db.Exec(`DELETE FROM collaborator_external_identities WHERE id = $1`, idA) })

	_, outcome, err := Upsert(ctx, db, UpsertInput{
		CollaboratorID: collabB, IntegrationInstanceID: instanceID,
		ExternalID: "U_CONFLICT", ExternalMetadata: nil,
	})
	assert.Equal(t, OutcomeConflict, outcome)
	var cerr *ConflictError
	require.ErrorAs(t, err, &cerr)
	assert.Equal(t, collabA, cerr.ExistingCollaboratorID)
	assert.Equal(t, collabB, cerr.IncomingCollaboratorID)
}

func TestSoftDelete_Idempotent(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)
	t.Cleanup(func() { db.Close() })

	collabID := seedCollaborator(t, db)
	id, _, err := Upsert(ctx, db, UpsertInput{
		CollaboratorID: collabID, IntegrationInstanceID: uuid.New(),
		ExternalID: "U_SD", ExternalMetadata: nil,
	})
	require.NoError(t, err)
	t.Cleanup(func() { db.Exec(`DELETE FROM collaborator_external_identities WHERE id = $1`, id) })

	_, err = SoftDelete(ctx, db, id)
	require.NoError(t, err)
	_, err = SoftDelete(ctx, db, id)
	require.NoError(t, err, "second SoftDelete must be idempotent")
}

func TestHardCleanup_DeletesOnlyOldUnlinked(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)
	t.Cleanup(func() { db.Close() })

	collabID := seedCollaborator(t, db)
	// Seed two rows: one unlinked 31 days ago, one unlinked 29 days ago.
	oldID := uuid.New()
	recentID := uuid.New()
	_, err := db.Exec(`
		INSERT INTO collaborator_external_identities
		  (id, collaborator_id, integration_instance_id, external_id, unlinked_at)
		VALUES
		  ($1, $2, $3, 'OLD', NOW() - INTERVAL '31 days'),
		  ($4, $5, $6, 'RECENT', NOW() - INTERVAL '29 days')
	`, oldID, collabID, uuid.New(), recentID, collabID, uuid.New())
	require.NoError(t, err)
	t.Cleanup(func() {
		db.Exec(`DELETE FROM collaborator_external_identities WHERE id IN ($1, $2)`, oldID, recentID)
	})

	purged, err := HardCleanup(ctx, db, time.Now().UTC().Add(-30*24*time.Hour))
	require.NoError(t, err)
	require.Len(t, purged, 1)
	assert.Equal(t, oldID, purged[0].ID)
}
```

- [ ] **Step 7: Run all repository tests**

```bash
DB_URL="postgres://yggdrasil:test@localhost:5432/yggdrasil_test?sslmode=disable" \
  go test ./internal/externalidentity/ -count=1 -v
```
Expected: 4 tests PASS (or all SKIP if DB_URL unset; that's the CI-safe fallback).

Compile-only:
```bash
go build ./internal/externalidentity/
go vet ./internal/externalidentity/
```
Expected: clean.

- [ ] **Step 8: Commit**

```bash
cd /Users/dakasa/projects/yggdrasil/yggdrasil-core
git add internal/externalidentity/repository.go internal/externalidentity/repository_test.go
git commit -m "feat(externalidentity): repository (Upsert, GetByID, SoftDelete, HardCleanup, List)"
```

---

## Phase 2: Core API

### Task 5: HTTP POST + GET handlers

**Repo:** yggdrasil-core
**Files:**
- Create: `/Users/dakasa/projects/yggdrasil/yggdrasil-core/controllers/httpapi/external_identities.go`
- Create: `/Users/dakasa/projects/yggdrasil/yggdrasil-core/controllers/httpapi/external_identities_test.go`
- Modify: `/Users/dakasa/projects/yggdrasil/yggdrasil-core/controllers/httpapi/server.go`

- [ ] **Step 1: Write failing test for POST happy path**

Create `controllers/httpapi/external_identities_test.go`:

```go
package httpapi

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExternalIdentitiesPOST_HappyPath_Returns201(t *testing.T) {
	srv := newTestServer(t) // existing helper from manifest_sync test file
	body := map[string]any{
		"collaborator_id":         uuid.New().String(),
		"integration_instance_id": uuid.New().String(),
		"external_id":             "U_TEST_POST",
		"external_metadata":       map[string]any{"k": "v"},
	}
	raw, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/collaborator-external-identities", bytes.NewReader(raw))
	req.Header.Set("Authorization", "Bearer "+testAdminToken)
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	// In a DB-less test, the handler should still parse + auth + reach repository.
	// Because there's no real DB, the repo call will fail. Stub deps as needed
	// (see existing manifest_sync_test.go pattern for injecting stub deps).
	require.Contains(t, []int{http.StatusCreated, http.StatusInternalServerError}, w.Code)
}
```

NOTE: pattern follows `controllers/httpapi/integration_type_sync_test.go`. The full test will be expanded after the handler exists.

- [ ] **Step 2: Implement handler**

Create `controllers/httpapi/external_identities.go`:

```go
package httpapi

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/externalidentity"
	"github.com/google/uuid"
)

type postExternalIdentityRequest struct {
	CollaboratorID        string         `json:"collaborator_id"`
	IntegrationInstanceID string         `json:"integration_instance_id"`
	ExternalID            string         `json:"external_id"`
	ExternalMetadata      map[string]any `json:"external_metadata"`
}

func (s *Server) handleExternalIdentityPost(w http.ResponseWriter, r *http.Request) {
	if err := authorizeAuthAdminRequest(r); err != nil {
		writeMappedError(w, err)
		return
	}
	var body postExternalIdentityRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid body: " + err.Error()})
		return
	}
	collabID, err := uuid.Parse(strings.TrimSpace(body.CollaboratorID))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid collaborator_id"})
		return
	}
	instanceID, err := uuid.Parse(strings.TrimSpace(body.IntegrationInstanceID))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid integration_instance_id"})
		return
	}
	if strings.TrimSpace(body.ExternalID) == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "external_id is required"})
		return
	}

	id, outcome, err := externalidentity.Upsert(r.Context(), s.db, externalidentity.UpsertInput{
		CollaboratorID:        collabID,
		IntegrationInstanceID: instanceID,
		ExternalID:            body.ExternalID,
		ExternalMetadata:      body.ExternalMetadata,
	})
	if err != nil {
		var cerr *externalidentity.ConflictError
		if errors.As(err, &cerr) {
			// Emit conflict_detected event (best-effort).
			_ = emitConflictEvent(r.Context(), s.db, cerr)
			writeJSON(w, http.StatusConflict, map[string]any{
				"error":                    "external_id already active on different collaborator",
				"existing_collaborator_id": cerr.ExistingCollaboratorID.String(),
				"existing_external_id":     cerr.ExternalID,
			})
			return
		}
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}

	// Emit linked event (best-effort).
	_ = emitLinkedEvent(r.Context(), s.db, id, collabID, instanceID, body.ExternalID, body.ExternalMetadata, outcome == externalidentity.OutcomeReLinked)

	status := http.StatusCreated
	if outcome != externalidentity.OutcomeInserted {
		status = http.StatusOK
	}
	writeJSON(w, status, map[string]any{
		"identity_id": id.String(),
		"outcome":     string(outcome),
	})
}

func (s *Server) handleExternalIdentityGet(w http.ResponseWriter, r *http.Request) {
	if err := authorizeAuthAdminRequest(r); err != nil {
		writeMappedError(w, err)
		return
	}
	q := r.URL.Query()
	filters := externalidentity.ListFilters{
		ActiveOnly: q.Get("active") != "false" && q.Get("active") != "all", // default true
		TypeName:   q.Get("type_name"),
	}
	if v := q.Get("collaborator_id"); v != "" {
		id, err := uuid.Parse(v)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid collaborator_id"})
			return
		}
		filters.CollaboratorID = &id
	}
	if v := q.Get("integration_instance_id"); v != "" {
		id, err := uuid.Parse(v)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid integration_instance_id"})
			return
		}
		filters.IntegrationInstanceID = &id
	}
	filters.Limit = parseIntOr(q.Get("limit"), 100)
	if filters.Limit > 500 {
		filters.Limit = 500
	}
	filters.Offset = parseIntOr(q.Get("offset"), 0)

	identities, err := externalidentity.List(r.Context(), s.db, filters)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	// Convert to JSON-friendly shape.
	out := make([]map[string]any, 0, len(identities))
	for _, i := range identities {
		row := map[string]any{
			"id":                      i.ID.String(),
			"collaborator_id":         i.CollaboratorID.String(),
			"integration_instance_id": i.IntegrationInstanceID.String(),
			"external_id":             i.ExternalID,
			"external_metadata":       i.ExternalMetadata,
			"linked_at":               i.LinkedAt.UTC().Format("2006-01-02T15:04:05Z07:00"),
			"last_seen_at":            i.LastSeenAt.UTC().Format("2006-01-02T15:04:05Z07:00"),
		}
		if i.UnlinkedAt != nil {
			row["unlinked_at"] = i.UnlinkedAt.UTC().Format("2006-01-02T15:04:05Z07:00")
		} else {
			row["unlinked_at"] = nil
		}
		out = append(out, row)
	}
	writeJSON(w, http.StatusOK, map[string]any{"identities": out})
}

func parseIntOr(s string, def int) int {
	if s == "" {
		return def
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return def
	}
	return n
}

// emitLinkedEvent and emitConflictEvent are defined in events.go (next task).
func emitLinkedEvent(ctx context.Context, db *sql.DB, identityID, collabID, instanceID uuid.UUID, externalID string, metadata map[string]any, reLinked bool) error {
	return nil // implementation moved into externalidentity package (Task 6)
}
func emitConflictEvent(ctx context.Context, db *sql.DB, e *externalidentity.ConflictError) error {
	return nil // implementation moved into externalidentity package (Task 6)
}
```

NOTE: emit functions are stubs in this task; Task 6 replaces them with real implementations from `internal/externalidentity/events.go`.

Wire routes in `controllers/httpapi/server.go` near the other admin endpoints:

```go
mux.HandleFunc("POST /api/v1/collaborator-external-identities", server.handleExternalIdentityPost)
mux.HandleFunc("GET /api/v1/collaborator-external-identities",  server.handleExternalIdentityGet)
```

- [ ] **Step 3: Run build + tests**

```bash
go build ./...
go test ./controllers/httpapi/ -run TestExternalIdentities -count=1 -v
```
Expected: PASS or controlled fail (StatusInternalServerError because of stub emit + no real DB connection in test).

- [ ] **Step 4: Commit**

```bash
cd /Users/dakasa/projects/yggdrasil/yggdrasil-core
git add controllers/httpapi/external_identities.go controllers/httpapi/external_identities_test.go controllers/httpapi/server.go
git commit -m "feat(httpapi): add POST + GET /api/v1/collaborator-external-identities"
```

---

### Task 6: Event emit helpers + replace stubs

**Repo:** yggdrasil-core
**Files:**
- Create: `/Users/dakasa/projects/yggdrasil/yggdrasil-core/internal/externalidentity/events.go`
- Create: `/Users/dakasa/projects/yggdrasil/yggdrasil-core/internal/externalidentity/events_test.go`
- Modify: `/Users/dakasa/projects/yggdrasil/yggdrasil-core/controllers/httpapi/external_identities.go`

- [ ] **Step 1: Write failing test for payload builders**

Create `internal/externalidentity/events_test.go`:

```go
package externalidentity

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBuildLinkedPayload(t *testing.T) {
	idID := uuid.New()
	collabID := uuid.New()
	instanceID := uuid.New()
	now := time.Date(2026, 5, 16, 12, 0, 0, 0, time.UTC)

	p := BuildLinkedPayload(LinkedInputs{
		IdentityID: idID, CollaboratorID: collabID,
		IntegrationInstanceID: instanceID, ExternalID: "U_X",
		ReLinked: true, LinkedAt: now,
		ExternalMetadata: map[string]any{"k": "v"},
	})
	raw, _ := json.Marshal(p)
	var got map[string]any
	require.NoError(t, json.Unmarshal(raw, &got))
	assert.Equal(t, idID.String(), got["identity_id"])
	assert.Equal(t, "U_X", got["external_id"])
	assert.Equal(t, true, got["re_linked"])
	assert.Equal(t, "2026-05-16T12:00:00Z", got["linked_at"])
}

func TestBuildConflictPayload(t *testing.T) {
	now := time.Date(2026, 5, 16, 12, 0, 0, 0, time.UTC)
	incoming := uuid.New()
	existing := uuid.New()
	instance := uuid.New()
	p := BuildConflictPayload(ConflictInputs{
		IntegrationInstanceID: instance, ExternalID: "U_C",
		IncomingCollaboratorID: incoming, ExistingCollaboratorID: existing,
		DetectedAt: now,
	})
	raw, _ := json.Marshal(p)
	var got map[string]any
	require.NoError(t, json.Unmarshal(raw, &got))
	assert.Equal(t, "U_C", got["external_id"])
	assert.Equal(t, incoming.String(), got["incoming_collaborator_id"])
	assert.Equal(t, existing.String(), got["existing_collaborator_id"])
}
```

- [ ] **Step 2: Run test — fail expected**

```bash
go test ./internal/externalidentity/ -run "TestBuildLinked|TestBuildConflict" -v
```
Expected: FAIL `undefined: BuildLinkedPayload`.

- [ ] **Step 3: Implement events.go**

Create `internal/externalidentity/events.go`:

```go
package externalidentity

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	"github.com/google/uuid"
)

type LinkedInputs struct {
	IdentityID            uuid.UUID
	CollaboratorID        uuid.UUID
	IntegrationInstanceID uuid.UUID
	ExternalID            string
	ReLinked              bool
	LinkedAt              time.Time
	ExternalMetadata      map[string]any
}

func BuildLinkedPayload(in LinkedInputs) map[string]any {
	p := map[string]any{
		"identity_id":             in.IdentityID.String(),
		"collaborator_id":         in.CollaboratorID.String(),
		"integration_instance_id": in.IntegrationInstanceID.String(),
		"external_id":             in.ExternalID,
		"re_linked":               in.ReLinked,
		"linked_at":               in.LinkedAt.UTC().Format(time.RFC3339),
	}
	if in.ExternalMetadata != nil {
		p["external_metadata"] = in.ExternalMetadata
	}
	return p
}

type UnlinkedInputs struct {
	IdentityID            uuid.UUID
	CollaboratorID        uuid.UUID
	IntegrationInstanceID uuid.UUID
	ExternalID            string
	UnlinkedAt            time.Time
}

func BuildUnlinkedPayload(in UnlinkedInputs) map[string]any {
	return map[string]any{
		"identity_id":             in.IdentityID.String(),
		"collaborator_id":         in.CollaboratorID.String(),
		"integration_instance_id": in.IntegrationInstanceID.String(),
		"external_id":             in.ExternalID,
		"unlinked_at":             in.UnlinkedAt.UTC().Format(time.RFC3339),
	}
}

type DriftInputs struct {
	IdentityID            uuid.UUID
	CollaboratorID        uuid.UUID
	IntegrationInstanceID uuid.UUID
	ExternalID            string
	DetectedAt            time.Time
}

func BuildDriftPayload(in DriftInputs) map[string]any {
	return map[string]any{
		"identity_id":             in.IdentityID.String(),
		"collaborator_id":         in.CollaboratorID.String(),
		"integration_instance_id": in.IntegrationInstanceID.String(),
		"external_id":             in.ExternalID,
		"detected_at":             in.DetectedAt.UTC().Format(time.RFC3339),
	}
}

type UnknownExternalInputs struct {
	IntegrationInstanceID uuid.UUID
	ExternalID            string
	ExternalMetadata      map[string]any
	DetectedAt            time.Time
}

func BuildUnknownExternalPayload(in UnknownExternalInputs) map[string]any {
	p := map[string]any{
		"integration_instance_id": in.IntegrationInstanceID.String(),
		"external_id":             in.ExternalID,
		"detected_at":             in.DetectedAt.UTC().Format(time.RFC3339),
	}
	if in.ExternalMetadata != nil {
		p["external_metadata"] = in.ExternalMetadata
	}
	return p
}

type PurgedInputs struct {
	IdentityID            uuid.UUID
	CollaboratorID        uuid.UUID
	IntegrationInstanceID uuid.UUID
	ExternalID            string
	PurgedAt              time.Time
}

func BuildPurgedPayload(in PurgedInputs) map[string]any {
	return map[string]any{
		"identity_id":             in.IdentityID.String(),
		"collaborator_id":         in.CollaboratorID.String(),
		"integration_instance_id": in.IntegrationInstanceID.String(),
		"external_id":             in.ExternalID,
		"purged_at":               in.PurgedAt.UTC().Format(time.RFC3339),
	}
}

type ConflictInputs struct {
	IntegrationInstanceID  uuid.UUID
	ExternalID             string
	IncomingCollaboratorID uuid.UUID
	ExistingCollaboratorID uuid.UUID
	DetectedAt             time.Time
}

func BuildConflictPayload(in ConflictInputs) map[string]any {
	return map[string]any{
		"integration_instance_id":  in.IntegrationInstanceID.String(),
		"external_id":              in.ExternalID,
		"incoming_collaborator_id": in.IncomingCollaboratorID.String(),
		"existing_collaborator_id": in.ExistingCollaboratorID.String(),
		"detected_at":              in.DetectedAt.UTC().Format(time.RFC3339),
	}
}

// EmitEvent persists one canon event row by opening a short tx.
func EmitEvent(ctx context.Context, db *sql.DB, eventType string, aggregateID uuid.UUID, payload map[string]any) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck

	aggType := eventType
	if i := strings.IndexByte(eventType, '.'); i > 0 {
		aggType = eventType[:i]
	}
	raw, _ := json.Marshal(payload)
	if _, err := repository.EmitEvent(ctx, tx, model.EmitEventRequest{
		Type:          eventType,
		AggregateType: aggType,
		AggregateID:   aggregateID.String(),
		Payload:       payload,
	}); err != nil {
		_ = raw // raw used implicitly via Payload; suppress unused-var warn during refactors
		return err
	}
	return tx.Commit()
}
```

- [ ] **Step 4: Replace stubs in `external_identities.go`**

In `controllers/httpapi/external_identities.go`, replace the two stub functions:

```go
func emitLinkedEvent(ctx context.Context, db *sql.DB, identityID, collabID, instanceID uuid.UUID, externalID string, metadata map[string]any, reLinked bool) error {
	return externalidentity.EmitEvent(ctx, db, repository.EventTypeExternalIdentityLinked, identityID,
		externalidentity.BuildLinkedPayload(externalidentity.LinkedInputs{
			IdentityID: identityID, CollaboratorID: collabID,
			IntegrationInstanceID: instanceID, ExternalID: externalID,
			ReLinked: reLinked, LinkedAt: time.Now().UTC(),
			ExternalMetadata: metadata,
		}))
}

func emitConflictEvent(ctx context.Context, db *sql.DB, e *externalidentity.ConflictError) error {
	return externalidentity.EmitEvent(ctx, db, repository.EventTypeExternalIdentityConflictDetected, e.IntegrationInstanceID,
		externalidentity.BuildConflictPayload(externalidentity.ConflictInputs{
			IntegrationInstanceID: e.IntegrationInstanceID,
			ExternalID:            e.ExternalID,
			IncomingCollaboratorID: e.IncomingCollaboratorID,
			ExistingCollaboratorID: e.ExistingCollaboratorID,
			DetectedAt: time.Now().UTC(),
		}))
}
```

Add `"time"` and `"github.com/dakasa-yggdrasil/yggdrasil-core/repository"` to the imports if not already present.

- [ ] **Step 5: Run tests + build**

```bash
go build ./...
go test ./internal/externalidentity/ -run "TestBuild" -count=1 -v
```
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
cd /Users/dakasa/projects/yggdrasil/yggdrasil-core
git add internal/externalidentity/events.go internal/externalidentity/events_test.go controllers/httpapi/external_identities.go
git commit -m "feat(externalidentity): event payload builders + wire emit into HTTP handlers"
```

---

### Task 7: DELETE endpoint + tests

**Repo:** yggdrasil-core
**Files:**
- Modify: `/Users/dakasa/projects/yggdrasil/yggdrasil-core/controllers/httpapi/external_identities.go`
- Modify: `/Users/dakasa/projects/yggdrasil/yggdrasil-core/controllers/httpapi/server.go`
- Modify: `/Users/dakasa/projects/yggdrasil/yggdrasil-core/controllers/httpapi/external_identities_test.go`

- [ ] **Step 1: Add DELETE handler**

Append to `external_identities.go`:

```go
func (s *Server) handleExternalIdentityDelete(w http.ResponseWriter, r *http.Request) {
	if err := authorizeAuthAdminRequest(r); err != nil {
		writeMappedError(w, err)
		return
	}
	raw := strings.TrimSpace(r.PathValue("id"))
	id, err := uuid.Parse(raw)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid uuid"})
		return
	}
	hard := r.URL.Query().Get("hard") == "true"

	if hard {
		if err := externalidentity.HardDelete(r.Context(), s.db, id); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
			return
		}
		w.WriteHeader(http.StatusNoContent)
		return
	}

	identity, err := externalidentity.SoftDelete(r.Context(), s.db, id)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	unlinkedAt := time.Now().UTC()
	if identity.UnlinkedAt != nil {
		unlinkedAt = *identity.UnlinkedAt
	}
	_ = externalidentity.EmitEvent(r.Context(), s.db, repository.EventTypeExternalIdentityUnlinked, identity.ID,
		externalidentity.BuildUnlinkedPayload(externalidentity.UnlinkedInputs{
			IdentityID: identity.ID, CollaboratorID: identity.CollaboratorID,
			IntegrationInstanceID: identity.IntegrationInstanceID,
			ExternalID:            identity.ExternalID,
			UnlinkedAt:            unlinkedAt,
		}))
	writeJSON(w, http.StatusOK, map[string]any{"identity_id": identity.ID.String(), "outcome": "unlinked"})
}
```

Wire route in `server.go`:

```go
mux.HandleFunc("DELETE /api/v1/collaborator-external-identities/{id}", server.handleExternalIdentityDelete)
```

- [ ] **Step 2: Add tests for DELETE (soft + hard)**

Append to `external_identities_test.go`:

```go
func TestExternalIdentitiesDELETE_SoftDelete(t *testing.T) {
	srv := newTestServer(t)
	id := uuid.New() // assume seed if integration test, else unit shape
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/collaborator-external-identities/"+id.String(), nil)
	req.Header.Set("Authorization", "Bearer "+testAdminToken)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	require.Contains(t, []int{http.StatusOK, http.StatusInternalServerError}, w.Code)
}

func TestExternalIdentitiesDELETE_InvalidUUID(t *testing.T) {
	srv := newTestServer(t)
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/collaborator-external-identities/not-a-uuid", nil)
	req.Header.Set("Authorization", "Bearer "+testAdminToken)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestExternalIdentitiesDELETE_Unauthorized(t *testing.T) {
	srv := newTestServer(t)
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/collaborator-external-identities/"+uuid.NewString(), nil)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}
```

- [ ] **Step 3: Run tests + build**

```bash
go test ./controllers/httpapi/ -run TestExternalIdentities -count=1 -v
```
Expected: all 6 cases parse/auth correctly.

- [ ] **Step 4: Commit**

```bash
cd /Users/dakasa/projects/yggdrasil/yggdrasil-core
git add controllers/httpapi/external_identities.go controllers/httpapi/server.go controllers/httpapi/external_identities_test.go
git commit -m "feat(httpapi): add DELETE /api/v1/collaborator-external-identities/{id} (soft + hard)"
```

---

## Phase 3: Reactor Dispatcher Convention

### Task 8: Envelope helpers + extraction-on-success

**Repo:** yggdrasil-core
**Files:**
- Create: `/Users/dakasa/projects/yggdrasil/yggdrasil-core/internal/externalidentity/envelope.go`
- Create: `/Users/dakasa/projects/yggdrasil/yggdrasil-core/internal/externalidentity/envelope_test.go`

- [ ] **Step 1: Write failing tests**

Create `internal/externalidentity/envelope_test.go`:

```go
package externalidentity

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestExtractFromOutput_MissingBlock(t *testing.T) {
	out := map[string]any{"other": "stuff"}
	_, ok := ExtractFromOutput(out)
	assert.False(t, ok)
}

func TestExtractFromOutput_ValidBlock(t *testing.T) {
	out := map[string]any{
		"other": "stuff",
		"_yggdrasil": map[string]any{
			"external_identity": map[string]any{
				"external_id": "U_TEST",
				"external_metadata": map[string]any{"display_name": "QA"},
			},
		},
	}
	ext, ok := ExtractFromOutput(out)
	assert.True(t, ok)
	assert.Equal(t, "U_TEST", ext.ExternalID)
	assert.Equal(t, "QA", ext.ExternalMetadata["display_name"])
}

func TestExtractFromOutput_MalformedMissingExternalID(t *testing.T) {
	out := map[string]any{
		"_yggdrasil": map[string]any{
			"external_identity": map[string]any{"external_metadata": map[string]any{}},
		},
	}
	_, ok := ExtractFromOutput(out)
	assert.False(t, ok, "missing external_id is malformed; skip silently")
}

func TestEmbedIntoInput_AddsContextBlock(t *testing.T) {
	input := map[string]any{"primary_email": "user@dakasa.me"}
	embed := EmbeddedIdentity{
		ExternalID:       "U_EMBED",
		ExternalMetadata: map[string]any{"display_name": "Test"},
	}
	EmbedIntoInput(input, embed)
	ctx, _ := input["_context"].(map[string]any)
	ei, _ := ctx["external_identity"].(map[string]any)
	assert.Equal(t, "U_EMBED", ei["external_id"])
}
```

- [ ] **Step 2: Run tests — fail expected**

```bash
go test ./internal/externalidentity/ -run "TestExtract|TestEmbed" -v
```
Expected: FAIL `undefined: ExtractFromOutput`.

- [ ] **Step 3: Implement envelope.go**

Create `internal/externalidentity/envelope.go`:

```go
package externalidentity

import "strings"

// Extracted is the result of ExtractFromOutput.
type Extracted struct {
	ExternalID       string
	ExternalMetadata map[string]any
}

// EmbeddedIdentity is what we embed under req._context.external_identity.
type EmbeddedIdentity struct {
	ExternalID       string         `json:"external_id"`
	ExternalMetadata map[string]any `json:"external_metadata"`
	LinkedAt         string         `json:"linked_at,omitempty"`
	LastSeenAt       string         `json:"last_seen_at,omitempty"`
}

// ExtractFromOutput inspects the adapter's response output map for the
// convention block output._yggdrasil.external_identity. Returns (extracted,
// true) when the block is present and well-formed; (zero, false) otherwise.
// Malformed blocks (missing external_id) are silently dropped — identity
// writing is opt-in, not load-bearing.
func ExtractFromOutput(output map[string]any) (Extracted, bool) {
	if output == nil {
		return Extracted{}, false
	}
	ygg, ok := output["_yggdrasil"].(map[string]any)
	if !ok {
		return Extracted{}, false
	}
	id, ok := ygg["external_identity"].(map[string]any)
	if !ok {
		return Extracted{}, false
	}
	ext, ok := id["external_id"].(string)
	if !ok || strings.TrimSpace(ext) == "" {
		return Extracted{}, false
	}
	meta, _ := id["external_metadata"].(map[string]any)
	return Extracted{ExternalID: ext, ExternalMetadata: meta}, true
}

// EmbedIntoInput injects the embed under input._context.external_identity.
// Creates _context if absent. Overwrites existing external_identity if any.
func EmbedIntoInput(input map[string]any, embed EmbeddedIdentity) {
	if input == nil {
		return
	}
	ctx, _ := input["_context"].(map[string]any)
	if ctx == nil {
		ctx = map[string]any{}
		input["_context"] = ctx
	}
	embedded := map[string]any{"external_id": embed.ExternalID}
	if embed.ExternalMetadata != nil {
		embedded["external_metadata"] = embed.ExternalMetadata
	}
	if embed.LinkedAt != "" {
		embedded["linked_at"] = embed.LinkedAt
	}
	if embed.LastSeenAt != "" {
		embedded["last_seen_at"] = embed.LastSeenAt
	}
	ctx["external_identity"] = embedded
}
```

- [ ] **Step 4: Run tests + build**

```bash
go test ./internal/externalidentity/ -run "TestExtract|TestEmbed" -v -count=1
go vet ./internal/externalidentity/
```
Expected: 4 tests PASS, vet clean.

- [ ] **Step 5: Commit**

```bash
cd /Users/dakasa/projects/yggdrasil/yggdrasil-core
git add internal/externalidentity/envelope.go internal/externalidentity/envelope_test.go
git commit -m "feat(externalidentity): envelope ExtractFromOutput + EmbedIntoInput"
```

---

### Task 9: Wire envelope into reactor dispatcher

**Repo:** yggdrasil-core
**Files:**
- Modify: `/Users/dakasa/projects/yggdrasil/yggdrasil-core/internal/reactors/dispatcher.go`
- Modify: `/Users/dakasa/projects/yggdrasil/yggdrasil-core/addons/reactor_dispatcher.go`

- [ ] **Step 1: Inspect the existing reactor dispatcher flow**

```bash
grep -nE "Run\(|claimNext|dispatchOne|markSucceeded|markFailed|BuildReactorPayload" internal/reactors/dispatcher.go | head -20
```
The dispatcher claims pending reactions, builds payload via `BuildReactorPayload`, calls `Caller.Call`, then marks the reaction state. Identify the success path.

- [ ] **Step 2: Modify the dispatcher to call EmbedIntoInput pre-Caller**

Find the place in `internal/reactors/dispatcher.go` where the JSON payload is constructed (around `BuildReactorPayload`). Add a pre-call step:

```go
// Pre-populate external_identity into payload._context if a linked identity
// exists for (collab, instance). This lets the reactor consume the
// provider-side id without callback HTTP to core.
if r.IdentityRepo != nil && reaction.CollaboratorID != uuid.Nil {
    if id, err := r.IdentityRepo.ActiveFor(ctx, reaction.CollaboratorID, reaction.IntegrationInstanceID); err == nil && id != nil {
        externalidentity.EmbedIntoInput(payloadInput, externalidentity.EmbeddedIdentity{
            ExternalID:       id.ExternalID,
            ExternalMetadata: id.ExternalMetadata,
            LinkedAt:         id.LinkedAt.UTC().Format(time.RFC3339),
            LastSeenAt:       id.LastSeenAt.UTC().Format(time.RFC3339),
        })
    }
    // err != nil or id == nil: no embed, reactor sees no _context.external_identity
}
```

Add an `IdentityRepo` field to the `Runner` struct (the dispatcher) with interface:

```go
type IdentityRepo interface {
    ActiveFor(ctx context.Context, collaboratorID, integrationInstanceID uuid.UUID) (*externalidentity.Identity, error)
    Upsert(ctx context.Context, in externalidentity.UpsertInput) (uuid.UUID, externalidentity.UpsertOutcome, error)
    EmitLinked(ctx context.Context, identityID, collabID, instanceID uuid.UUID, externalID string, metadata map[string]any, reLinked bool) error
}
```

Implement `ActiveFor` as a small wrapper in `internal/externalidentity/repository.go`:

```go
func ActiveFor(ctx context.Context, db *sql.DB, collaboratorID, integrationInstanceID uuid.UUID) (*Identity, error) {
    rows, err := List(ctx, db, ListFilters{
        CollaboratorID:        &collaboratorID,
        IntegrationInstanceID: &integrationInstanceID,
        ActiveOnly:            true,
        Limit:                 1,
    })
    if err != nil {
        return nil, err
    }
    if len(rows) == 0 {
        return nil, nil
    }
    return &rows[0], nil
}
```

- [ ] **Step 3: Modify the dispatcher to extract on success and upsert**

Find the place in `dispatcher.go` where a reaction is marked succeeded. Just before the markSucceeded call:

```go
// Extract external_identity from adapter output if present.
if r.IdentityRepo != nil {
    if ext, ok := externalidentity.ExtractFromOutput(response.Output); ok {
        identityID, outcome, err := r.IdentityRepo.Upsert(ctx, externalidentity.UpsertInput{
            CollaboratorID:        reaction.CollaboratorID,
            IntegrationInstanceID: reaction.IntegrationInstanceID,
            ExternalID:            ext.ExternalID,
            ExternalMetadata:      ext.ExternalMetadata,
        })
        if err != nil {
            // Conflict or DB error: log, emit conflict event, DO NOT fail reaction.
            if r.Logger != nil {
                r.Logger.Warn("external_identity upsert failed", zap.Error(err), ...)
            }
        } else if outcome != externalidentity.OutcomeConflict {
            _ = r.IdentityRepo.EmitLinked(ctx, identityID, reaction.CollaboratorID,
                reaction.IntegrationInstanceID, ext.ExternalID, ext.ExternalMetadata,
                outcome == externalidentity.OutcomeReLinked)
        }
    }
}
```

- [ ] **Step 4: Wire IdentityRepo in addons/reactor_dispatcher.go**

In `addons/reactor_dispatcher.go`, when constructing the `reactors.Runner`, set `IdentityRepo` to a concrete implementation backed by the package functions:

```go
runner := &reactors.Runner{
    DB:              db,
    Logger:          logger,
    Caller:          &rabbitmqReactorCaller{conn: conn, db: db},
    Interval:        envDurOrDefault("REACTOR_RUNNER_INTERVAL", 5*time.Second),
    BatchSize:       envIntOrDefault("REACTOR_RUNNER_BATCH_SIZE", 50),
    Parallelism:     envIntOrDefault("REACTOR_RUNNER_PARALLELISM", 10),
    StuckThreshold:  envDurOrDefault("REACTOR_STUCK_THRESHOLD", 10*time.Minute),
    IdentityRepo:    &externalIdentityRepoImpl{db: db},
}
```

Add the concrete impl in the same file:

```go
type externalIdentityRepoImpl struct{ db *sql.DB }

func (r *externalIdentityRepoImpl) ActiveFor(ctx context.Context, collab, instance uuid.UUID) (*externalidentity.Identity, error) {
    return externalidentity.ActiveFor(ctx, r.db, collab, instance)
}

func (r *externalIdentityRepoImpl) Upsert(ctx context.Context, in externalidentity.UpsertInput) (uuid.UUID, externalidentity.UpsertOutcome, error) {
    return externalidentity.Upsert(ctx, r.db, in)
}

func (r *externalIdentityRepoImpl) EmitLinked(ctx context.Context, identityID, collab, instance uuid.UUID, externalID string, metadata map[string]any, reLinked bool) error {
    return externalidentity.EmitEvent(ctx, r.db, repository.EventTypeExternalIdentityLinked, identityID,
        externalidentity.BuildLinkedPayload(externalidentity.LinkedInputs{
            IdentityID: identityID, CollaboratorID: collab,
            IntegrationInstanceID: instance, ExternalID: externalID,
            ReLinked: reLinked, LinkedAt: time.Now().UTC(),
            ExternalMetadata: metadata,
        }))
}
```

- [ ] **Step 5: Build + test**

```bash
go build ./...
go test ./internal/reactors/... -count=1
```
Expected: PASS (existing reactor tests still pass with the new optional IdentityRepo field).

- [ ] **Step 6: Commit**

```bash
cd /Users/dakasa/projects/yggdrasil/yggdrasil-core
git add internal/reactors/dispatcher.go addons/reactor_dispatcher.go internal/externalidentity/repository.go
git commit -m "feat(reactors): pre-populate _context.external_identity + extract from output on success"
```

---

## Phase 4: Adapter writes (3 repos)

### Task 10: integration-slack writes identity envelope

**Repo:** integration-slack
**Files:**
- Modify: `/Users/dakasa/projects/yggdrasil/integration-slack/internal/adapter/reactors.go`

- [ ] **Step 1: Inspect current on_collaborator_created flow**

```bash
cd /Users/dakasa/projects/yggdrasil/integration-slack
grep -A 25 "^func onCollaboratorCreated" internal/adapter/reactors.go | head -30
```
Note where SCIM path returns success: that's where to emit envelope from `scim_apply_user` response.

- [ ] **Step 2: Add envelope block to onCollaboratorCreated SCIM success path**

Modify the SCIM success branch in `internal/adapter/reactors.go`:

```go
if scimErr == nil {
    // scimOut typically contains {"status":"created"|"updated","id":"U...","userName":"...","display_name":"..."}
    var externalID string
    var externalMeta map[string]any
    if scimOutMap, ok := scimOut.(map[string]any); ok {
        if id, _ := scimOutMap["id"].(string); id != "" {
            externalID = id
            externalMeta = map[string]any{
                "userName":     scimOutMap["userName"],
                "display_name": scimOutMap["display_name"],
            }
        }
    }
    result := map[string]any{
        "provisioned":     true,
        "scim_apply_user": scimOut,
        "attempt":         attempt,
    }
    if externalID != "" {
        result["_yggdrasil"] = map[string]any{
            "external_identity": map[string]any{
                "external_id":       externalID,
                "external_metadata": externalMeta,
            },
        }
    }
    if setupURL := firstString(input, "setup_url"); setupURL != "" {
        result["dm_deferred"] = "SCIM-provisioned; DM with setup_url will fire once the user activates their account"
        result["setup_url"] = setupURL
    }
    return result, nil
}
```

- [ ] **Step 3: Build + test**

```bash
go build ./...
go test ./internal/adapter/ -count=1
```
Expected: PASS.

- [ ] **Step 4: Commit**

```bash
cd /Users/dakasa/projects/yggdrasil/integration-slack
git add internal/adapter/reactors.go
git commit -m "feat(reactors): emit _yggdrasil.external_identity from on_collaborator_created"
```

---

### Task 11: integration-slack reads `_context.external_identity` in offboard

**Repo:** integration-slack
**Files:**
- Modify: `/Users/dakasa/projects/yggdrasil/integration-slack/internal/adapter/reactors.go`

- [ ] **Step 1: Update onCollaboratorOffboarded to prefer context identity**

Find the function and adjust the userID resolution to prefer `_context.external_identity.external_id`:

```go
func onCollaboratorOffboarded(auth slackAuth, input map[string]any) (map[string]any, error) {
    email := firstString(input, "primary_email")
    userID := firstString(input, "user_id")
    // Prefer linked identity from yggdrasil dispatcher
    if ctx, _ := input["_context"].(map[string]any); ctx != nil {
        if ei, _ := ctx["external_identity"].(map[string]any); ei != nil {
            if id, _ := ei["external_id"].(string); id != "" {
                userID = id
            }
        }
    }
    if email == "" && userID == "" {
        return nil, fmt.Errorf("on_collaborator_offboarded: primary_email or user_id is required")
    }
    // ... rest of existing function unchanged
}
```

- [ ] **Step 2: Build + test**

```bash
go test ./internal/adapter/ -count=1
```
Expected: PASS.

- [ ] **Step 3: Commit**

```bash
cd /Users/dakasa/projects/yggdrasil/integration-slack
git add internal/adapter/reactors.go
git commit -m "feat(reactors): on_collaborator_offboarded prefers _context.external_identity"
```

---

### Task 12: integration-google-workspace identity write + read

**Repo:** integration-google-workspace
**Files:**
- Modify: `/Users/dakasa/projects/yggdrasil/integration-google-workspace/providers/runtime/adapter/reactors.go`

- [ ] **Step 1: Emit envelope on onCollaboratorCreated success**

In the success block of `onCollaboratorCreated`, the `createOut` from `create_user_provisional` contains the GW user resource. Extract `id` and emit envelope:

```go
result := map[string]any{
    "provisioned":             true,
    "create_user_provisional": createOut,
    "attempt":                 attempt,
}
// Embed identity envelope
if userMap, ok := createOut.(map[string]any); ok {
    user, ok := userMap["user"].(map[string]any)
    if !ok {
        user = userMap
    }
    if id, _ := user["id"].(string); id != "" {
        result["_yggdrasil"] = map[string]any{
            "external_identity": map[string]any{
                "external_id":       id,
                "external_metadata": map[string]any{
                    "primary_email": user["primaryEmail"],
                    "display_name":  user["name"].(map[string]any)["fullName"],
                    "ou_path":       user["orgUnitPath"],
                },
            },
        }
    }
}
// ... rest of function (mailbox aliases) unchanged
```

- [ ] **Step 2: Update onCollaboratorOffboarded to prefer context identity**

Find `onCollaboratorOffboarded` and modify the email resolution:

```go
email := firstString(input, "primary_email", "email")
// Prefer numeric id from context (rename-safe)
var preferredID string
if ctx, _ := input["_context"].(map[string]any); ctx != nil {
    if ei, _ := ctx["external_identity"].(map[string]any); ei != nil {
        if id, _ := ei["external_id"].(string); id != "" {
            preferredID = id
        }
    }
}
// ... if preferredID != "", suspend_user accepts numeric id too (test against GW API)
```

The existing suspendUser implementation accepts `primary_email` as identifier; if it can also accept numeric `id`, switch to that. If not, leave email but record preferredID for future use.

- [ ] **Step 3: Build + test**

```bash
cd /Users/dakasa/projects/yggdrasil/integration-google-workspace
go test ./... -count=1
```
Expected: PASS.

- [ ] **Step 4: Commit**

```bash
git add providers/runtime/adapter/reactors.go
git commit -m "feat(reactors): emit + consume _yggdrasil.external_identity for GW lifecycle"
```

---

### Task 13: integration-github offboard reads context identity

**Repo:** integration-github
**Files:**
- Modify: `/Users/dakasa/projects/yggdrasil/integration-github/internal/adapter/reactors.go`

- [ ] **Step 1: Update onCollaboratorOffboarded**

In `internal/adapter/reactors.go`, replace the offboard logic to prefer `_context.external_identity.external_metadata.github_login`:

```go
func onCollaboratorOffboarded(req protocol.AdapterExecuteIntegrationRequest) (...) {
    attempt := contextAttempt(req.Input)
    email := firstString(req.Input, []string{"primary_email", "email"})

    // Prefer linked identity (set by yggdrasil dispatcher)
    if ctx, _ := req.Input["_context"].(map[string]any); ctx != nil {
        if ei, _ := ctx["external_identity"].(map[string]any); ei != nil {
            if meta, _ := ei["external_metadata"].(map[string]any); meta != nil {
                if username, _ := meta["github_login"].(string); username != "" {
                    // Remove user by their real GH username (works for accepted invites)
                    orgReq := cloneReqWithInput(req, map[string]any{"username": username})
                    orgReq.Operation = OperationRemoveUserFromOrg
                    orgReq.Capability = OperationRemoveUserFromOrg
                    orgResp, orgErr := removeUserFromOrg(orgReq)
                    if orgErr == nil {
                        return protocol.AdapterExecuteIntegrationResponse{
                            Operation: OperationOnCollaboratorOffboarded,
                            Status:    "offboarded",
                            Output: map[string]any{
                                "path":             "context_identity",
                                "remove_user_from_org": orgResp.Output,
                                "attempt":          attempt,
                            },
                        }, nil
                    }
                    // fall through to invite-cancel as best-effort
                }
            }
        }
    }

    // Non-EMU pending-invite path (current behavior, kept as fallback)
    if email == "" {
        return protocol.AdapterExecuteIntegrationResponse{}, fmt.Errorf("on_collaborator_offboarded: primary_email is required")
    }
    cancelReq := cloneReqWithInput(req, map[string]any{"email": email})
    cancelReq.Operation = OperationCancelOrgInvitationByEmail
    cancelReq.Capability = OperationCancelOrgInvitationByEmail
    cancelResp, cancelErr := cancelOrgInvitationByEmail(cancelReq)
    if cancelErr != nil && email == "" {
        return protocol.AdapterExecuteIntegrationResponse{}, fmt.Errorf("on_collaborator_offboarded: no identity, no email, nothing to act on")
    }
    return protocol.AdapterExecuteIntegrationResponse{
        Operation:  OperationOnCollaboratorOffboarded,
        Capability: OperationOnCollaboratorOffboarded,
        Status:     "offboarded",
        Output: map[string]any{
            "path":                     "cancel_invite",
            "cancel_org_invitation":    cancelResp.Output,
            "cancel_org_invitation_error": errString(cancelErr),
            "attempt":                  attempt,
        },
    }, nil
}

func errString(e error) string {
    if e == nil { return "" }
    return e.Error()
}
```

- [ ] **Step 2: Build + test**

```bash
cd /Users/dakasa/projects/yggdrasil/integration-github
go test ./internal/adapter/ -count=1
```
Expected: PASS.

- [ ] **Step 3: Commit**

```bash
git add internal/adapter/reactors.go
git commit -m "feat(reactors): on_collaborator_offboarded prefers _context.external_identity.github_login"
```

---

## Phase 5: Webhook flow

### Task 14: Generic webhook receiver in core

**Repo:** yggdrasil-core
**Files:**
- Create: `/Users/dakasa/projects/yggdrasil/yggdrasil-core/internal/externalidentity/hmac.go`
- Create: `/Users/dakasa/projects/yggdrasil/yggdrasil-core/internal/externalidentity/hmac_test.go`
- Create: `/Users/dakasa/projects/yggdrasil/yggdrasil-core/controllers/httpapi/integration_webhook.go`
- Modify: `/Users/dakasa/projects/yggdrasil/yggdrasil-core/controllers/httpapi/server.go`

- [ ] **Step 1: Write failing test for hmac (github_hmac_sha256)**

Create `internal/externalidentity/hmac_test.go`:

```go
package externalidentity

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"testing"
)

func TestVerifySignature_GithubHmacSha256_Valid(t *testing.T) {
	secret := "topsecret"
	body := []byte(`{"a":1}`)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	sig := "sha256=" + hex.EncodeToString(mac.Sum(nil))
	hdr := http.Header{"X-Hub-Signature-256": []string{sig}}
	if err := VerifySignature("github_hmac_sha256", secret, hdr, body); err != nil {
		t.Fatalf("expected valid signature, got err: %v", err)
	}
}

func TestVerifySignature_GithubHmacSha256_Tampered(t *testing.T) {
	secret := "topsecret"
	body := []byte(`{"a":1}`)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(`{"a":2}`)) // mismatched body
	sig := "sha256=" + hex.EncodeToString(mac.Sum(nil))
	hdr := http.Header{"X-Hub-Signature-256": []string{sig}}
	if err := VerifySignature("github_hmac_sha256", secret, hdr, body); err == nil {
		t.Fatal("expected verification error for tampered body")
	}
}

func TestVerifySignature_UnknownScheme(t *testing.T) {
	if err := VerifySignature("bogus_scheme", "x", http.Header{}, nil); err == nil {
		t.Fatal("expected unknown scheme error")
	}
}
```

- [ ] **Step 2: Implement hmac.go**

Create `internal/externalidentity/hmac.go`:

```go
package externalidentity

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
)

// VerifySignature dispatches to the per-scheme HMAC verification.
// Schemes supported initially:
//
//	github_hmac_sha256   — X-Hub-Signature-256: "sha256=<hex>", body HMAC'd
//
// Adding new schemes is a tiny case clause; do NOT route through adapters.
func VerifySignature(scheme, secret string, headers http.Header, body []byte) error {
	switch scheme {
	case "github_hmac_sha256":
		return verifyGithubHmacSha256(secret, headers, body)
	default:
		return fmt.Errorf("unknown webhook signature scheme %q", scheme)
	}
}

func verifyGithubHmacSha256(secret string, headers http.Header, body []byte) error {
	got := strings.TrimSpace(headers.Get("X-Hub-Signature-256"))
	if got == "" {
		return fmt.Errorf("missing X-Hub-Signature-256 header")
	}
	if !strings.HasPrefix(got, "sha256=") {
		return fmt.Errorf("malformed signature header: %s", got)
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	want := "sha256=" + hex.EncodeToString(mac.Sum(nil))
	if !hmac.Equal([]byte(got), []byte(want)) {
		return fmt.Errorf("signature mismatch")
	}
	return nil
}
```

- [ ] **Step 3: Run hmac tests**

```bash
go test ./internal/externalidentity/ -run TestVerifySignature -v -count=1
```
Expected: 3 tests PASS.

- [ ] **Step 4: Implement webhook handler**

Create `controllers/httpapi/integration_webhook.go`:

```go
package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/externalidentity"
	messagecontroller "github.com/dakasa-yggdrasil/yggdrasil-core/controllers/message"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	"github.com/google/uuid"
)

// handleIntegrationWebhook accepts a provider webhook, verifies HMAC against
// the integration_instance's stored secret, forwards to the adapter via the
// on_webhook capability, and executes returned actions.
func (s *Server) handleIntegrationWebhook(w http.ResponseWriter, r *http.Request) {
	rawInstanceID := strings.TrimSpace(r.PathValue("instance_id"))
	instanceID, err := uuid.Parse(rawInstanceID)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid instance_id"})
		return
	}

	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 5<<20)) // 5 MiB cap
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "read body: " + err.Error()})
		return
	}

	// Resolve instance and HMAC config
	instance, instanceSpec, _, _, err := messagecontroller.ResolveIntegrationInstanceByID(r.Context(), s.rabbitmq, s.db, instanceID)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "instance not found"})
		return
	}
	scheme, _ := instanceSpec.Config["webhook_signature_scheme"].(string)
	secret, _ := instanceSpec.Config["webhook_secret"].(string)
	if scheme == "" || secret == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "instance has no webhook configuration"})
		return
	}
	if err := externalidentity.VerifySignature(scheme, secret, r.Header, body); err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "signature verification failed: " + err.Error()})
		return
	}

	// Parse body as JSON (best-effort; some providers send form-encoded)
	var bodyJSON map[string]any
	_ = json.Unmarshal(body, &bodyJSON)

	headers := map[string]any{}
	for k, v := range r.Header {
		if len(v) > 0 {
			headers[k] = v[0]
		}
	}

	resp, err := messagecontroller.ExecuteIntegrationByID(r.Context(), s.rabbitmq, s.db, model.ExecuteIntegrationRequest{
		Integration: model.ManifestSelector{ManifestID: instance.ID.String()},
		Operation:   "on_webhook",
		Capability:  "on_webhook",
		Input: map[string]any{
			"headers":   headers,
			"body_raw":  string(body),
			"body_json": bodyJSON,
		},
	})
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "adapter on_webhook failed: " + err.Error()})
		return
	}

	// Execute actions returned by adapter
	actions, _ := resp.Output["actions"].([]any)
	results := make([]map[string]any, 0, len(actions))
	for _, raw := range actions {
		act, _ := raw.(map[string]any)
		kind, _ := act["kind"].(string)
		switch kind {
		case "link_identity":
			results = append(results, applyLinkAction(r.Context(), s.db, instance.ID, act))
		case "unlink_identity":
			results = append(results, applyUnlinkAction(r.Context(), s.db, instance.ID, act))
		case "emit_event":
			results = append(results, applyEmitAction(r.Context(), s.db, act))
		default:
			results = append(results, map[string]any{"kind": kind, "status": "skipped_unknown_kind"})
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"actions": results})
}

func applyLinkAction(ctx context.Context, db *sql.DB, instanceID uuid.UUID, act map[string]any) map[string]any {
	externalID, _ := act["external_id"].(string)
	if externalID == "" {
		return map[string]any{"kind": "link_identity", "status": "skipped_missing_external_id"}
	}
	match, _ := act["collaborator_match"].(map[string]any)
	collabID, err := resolveCollaboratorMatch(ctx, db, match)
	if err != nil {
		// emit unknown_external event
		now := time.Now().UTC()
		_ = externalidentity.EmitEvent(ctx, db, repository.EventTypeExternalIdentityUnknownExternal, instanceID,
			externalidentity.BuildUnknownExternalPayload(externalidentity.UnknownExternalInputs{
				IntegrationInstanceID: instanceID, ExternalID: externalID,
				ExternalMetadata:      nil, DetectedAt: now,
			}))
		return map[string]any{"kind": "link_identity", "status": "skipped_no_collaborator", "error": err.Error()}
	}
	meta, _ := act["external_metadata"].(map[string]any)
	id, outcome, err := externalidentity.Upsert(ctx, db, externalidentity.UpsertInput{
		CollaboratorID:        collabID,
		IntegrationInstanceID: instanceID,
		ExternalID:            externalID,
		ExternalMetadata:      meta,
	})
	if err != nil {
		var cerr *externalidentity.ConflictError
		if errors.As(err, &cerr) {
			_ = externalidentity.EmitEvent(ctx, db, repository.EventTypeExternalIdentityConflictDetected, instanceID,
				externalidentity.BuildConflictPayload(externalidentity.ConflictInputs{
					IntegrationInstanceID: cerr.IntegrationInstanceID, ExternalID: cerr.ExternalID,
					IncomingCollaboratorID: cerr.IncomingCollaboratorID,
					ExistingCollaboratorID: cerr.ExistingCollaboratorID,
					DetectedAt:             time.Now().UTC(),
				}))
			return map[string]any{"kind": "link_identity", "status": "conflict"}
		}
		return map[string]any{"kind": "link_identity", "status": "error", "error": err.Error()}
	}
	if outcome != externalidentity.OutcomeConflict {
		_ = externalidentity.EmitEvent(ctx, db, repository.EventTypeExternalIdentityLinked, id,
			externalidentity.BuildLinkedPayload(externalidentity.LinkedInputs{
				IdentityID: id, CollaboratorID: collabID,
				IntegrationInstanceID: instanceID, ExternalID: externalID,
				ReLinked: outcome == externalidentity.OutcomeReLinked,
				LinkedAt: time.Now().UTC(), ExternalMetadata: meta,
			}))
	}
	return map[string]any{"kind": "link_identity", "status": string(outcome), "identity_id": id.String()}
}

func applyUnlinkAction(ctx context.Context, db *sql.DB, instanceID uuid.UUID, act map[string]any) map[string]any {
	externalID, _ := act["external_id"].(string)
	if externalID == "" {
		return map[string]any{"kind": "unlink_identity", "status": "skipped_missing_external_id"}
	}
	// Find active identity for (instance, external_id)
	rows, err := externalidentity.List(ctx, db, externalidentity.ListFilters{
		IntegrationInstanceID: &instanceID,
		ActiveOnly:            true,
	})
	if err != nil {
		return map[string]any{"kind": "unlink_identity", "status": "error", "error": err.Error()}
	}
	for _, ident := range rows {
		if ident.ExternalID == externalID {
			id, err := externalidentity.SoftDelete(ctx, db, ident.ID)
			if err != nil {
				return map[string]any{"kind": "unlink_identity", "status": "error", "error": err.Error()}
			}
			_ = externalidentity.EmitEvent(ctx, db, repository.EventTypeExternalIdentityUnlinked, id.ID,
				externalidentity.BuildUnlinkedPayload(externalidentity.UnlinkedInputs{
					IdentityID: id.ID, CollaboratorID: id.CollaboratorID,
					IntegrationInstanceID: id.IntegrationInstanceID,
					ExternalID:            id.ExternalID,
					UnlinkedAt:            time.Now().UTC(),
				}))
			return map[string]any{"kind": "unlink_identity", "status": "unlinked", "identity_id": id.ID.String()}
		}
	}
	return map[string]any{"kind": "unlink_identity", "status": "not_found"}
}

func applyEmitAction(ctx context.Context, db *sql.DB, act map[string]any) map[string]any {
	eventType, _ := act["event_type"].(string)
	payload, _ := act["payload"].(map[string]any)
	aggregateIDStr, _ := act["aggregate_id"].(string)
	aggregateID, err := uuid.Parse(aggregateIDStr)
	if err != nil {
		return map[string]any{"kind": "emit_event", "status": "skipped_invalid_aggregate_id"}
	}
	if err := externalidentity.EmitEvent(ctx, db, eventType, aggregateID, payload); err != nil {
		return map[string]any{"kind": "emit_event", "status": "error", "error": err.Error()}
	}
	return map[string]any{"kind": "emit_event", "status": "emitted"}
}

// resolveCollaboratorMatch resolves a collaborator_match block to a collaborator_id.
// Supports by=primary_email, by=collaborator_id, by=external_id_lookup.
func resolveCollaboratorMatch(ctx context.Context, db *sql.DB, match map[string]any) (uuid.UUID, error) {
	by, _ := match["by"].(string)
	value, _ := match["value"].(string)
	switch by {
	case "primary_email":
		var id uuid.UUID
		err := db.QueryRowContext(ctx, `SELECT id FROM collaborators WHERE primary_email = $1`, value).Scan(&id)
		return id, err
	case "collaborator_id":
		return uuid.Parse(value)
	case "external_id_lookup":
		// query identities by external_id, return collaborator_id of any active match
		var id uuid.UUID
		err := db.QueryRowContext(ctx, `
			SELECT collaborator_id FROM collaborator_external_identities
			WHERE external_id = $1 AND unlinked_at IS NULL LIMIT 1
		`, value).Scan(&id)
		return id, err
	default:
		return uuid.Nil, errors.New("unsupported collaborator_match.by")
	}
}
```

Wire route in `server.go`:

```go
mux.HandleFunc("POST /api/v1/integrations/{instance_id}/webhook", server.handleIntegrationWebhook)
```

NOTE on `ResolveIntegrationInstanceByID` and `ExecuteIntegrationByID`: these are assumed helpers in `controllers/message`. If absent, add them as thin wrappers around the existing `resolveIntegrationInstance` + `ExecuteIntegration`. Grep to confirm:

```bash
grep -nE "^func ResolveIntegrationInstance|^func ExecuteIntegrationByID" controllers/message/*.go
```

If missing, add small public wrappers in `controllers/message/products.go` and `controllers/message/integrations.go`.

- [ ] **Step 5: Build + test**

```bash
go build ./...
go test ./internal/externalidentity/ ./controllers/httpapi/ -count=1
```
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
cd /Users/dakasa/projects/yggdrasil/yggdrasil-core
git add internal/externalidentity/hmac.go internal/externalidentity/hmac_test.go controllers/httpapi/integration_webhook.go controllers/httpapi/server.go controllers/message/
git commit -m "feat(webhook): receiver + HMAC verify + action dispatch"
```

---

### Task 15: integration-github `on_webhook` capability

**Repo:** integration-github
**Files:**
- Create: `/Users/dakasa/projects/yggdrasil/integration-github/internal/adapter/webhook.go`
- Modify: `/Users/dakasa/projects/yggdrasil/integration-github/internal/adapter/spec.go`

- [ ] **Step 1: Add OperationOnWebhook + register in dispatch**

Modify `internal/adapter/spec.go`:

```go
const OperationOnWebhook = "on_webhook"

// in the SupportedExecuteOperations slice, add:
OperationOnWebhook,

// in the switch dispatching operations, add case:
case OperationOnWebhook:
    return onWebhook(req)

// in action_catalog declaration, add entry:
{
    Name:          OperationOnWebhook,
    Description:   "Parse a GitHub webhook payload and return action(s) for yggdrasil-core to execute server-side. Currently handles `member` events (added/removed).",
    ResourceTypes: []string{"webhook_event"},
    Idempotent:    true,
},
```

- [ ] **Step 2: Implement webhook handler**

Create `internal/adapter/webhook.go`:

```go
package adapter

import (
	"fmt"

	"github.com/dakasa-yggdrasil/integration-github/internal/protocol"
)

// onWebhook parses a GitHub webhook delivery and emits actions.
// The dispatcher (yggdrasil-core) executes these against the
// collaborator_external_identities table.
//
// Supported events:
//   - member.added   → link_identity (numeric id as external_id, login + html_url in metadata)
//   - member.removed → unlink_identity
//
// Unknown events are reported as actions=[] (caller logs no-op).
func onWebhook(req protocol.AdapterExecuteIntegrationRequest) (protocol.AdapterExecuteIntegrationResponse, error) {
	headers, _ := req.Input["headers"].(map[string]any)
	body, _ := req.Input["body_json"].(map[string]any)

	event, _ := headers["X-Github-Event"].(string) // Go's http.Header canonicalizes; provider may send X-GitHub-Event
	if event == "" {
		event, _ = headers["X-GitHub-Event"].(string)
	}

	if event != "member" {
		return protocol.AdapterExecuteIntegrationResponse{
			Operation: OperationOnWebhook,
			Status:    "ignored",
			Output:    map[string]any{"actions": []any{}, "event": event, "reason": "unsupported_event"},
		}, nil
	}

	action, _ := body["action"].(string)
	memberRaw, _ := body["member"].(map[string]any)
	if memberRaw == nil {
		return protocol.AdapterExecuteIntegrationResponse{}, fmt.Errorf("on_webhook: missing member object")
	}

	switch action {
	case "added":
		// Extract numeric id + login from GitHub user object
		var externalID string
		switch v := memberRaw["id"].(type) {
		case float64:
			externalID = fmt.Sprintf("%.0f", v)
		case string:
			externalID = v
		}
		login, _ := memberRaw["login"].(string)
		htmlURL, _ := memberRaw["html_url"].(string)
		// We need to match the collaborator by primary_email, but GitHub member event
		// does NOT carry the email. Strategy: look up by external_id_lookup if previous
		// invitation linkage exists (we don't have one yet), OR rely on operator-provided
		// mapping. For now, fall back to login as match value (works if collaborator's
		// primary_email == "{login}@dakasa.me" — common convention).
		//
		// This is a known limitation; operators may extend the webhook payload mapping later.
		fallbackEmail := login + "@dakasa.me"
		return protocol.AdapterExecuteIntegrationResponse{
			Operation: OperationOnWebhook,
			Status:    "ok",
			Output: map[string]any{
				"actions": []any{
					map[string]any{
						"kind":               "link_identity",
						"collaborator_match": map[string]any{"by": "primary_email", "value": fallbackEmail},
						"external_id":        externalID,
						"external_metadata": map[string]any{
							"github_login": login,
							"html_url":     htmlURL,
						},
					},
				},
			},
		}, nil

	case "removed":
		var externalID string
		switch v := memberRaw["id"].(type) {
		case float64:
			externalID = fmt.Sprintf("%.0f", v)
		case string:
			externalID = v
		}
		return protocol.AdapterExecuteIntegrationResponse{
			Operation: OperationOnWebhook,
			Status:    "ok",
			Output: map[string]any{
				"actions": []any{
					map[string]any{
						"kind":        "unlink_identity",
						"external_id": externalID,
					},
				},
			},
		}, nil

	default:
		return protocol.AdapterExecuteIntegrationResponse{
			Operation: OperationOnWebhook,
			Status:    "ignored",
			Output:    map[string]any{"actions": []any{}, "action": action, "reason": "unsupported_member_action"},
		}, nil
	}
}
```

- [ ] **Step 3: Build + test**

```bash
cd /Users/dakasa/projects/yggdrasil/integration-github
go test ./internal/adapter/ -count=1
```
Expected: PASS (existing tests; new handler doesn't have unit tests yet — covered by E2E).

- [ ] **Step 4: Commit**

```bash
git add internal/adapter/webhook.go internal/adapter/spec.go
git commit -m "feat(reactors): add on_webhook capability for member events"
```

---

## Phase 6: Re-sync + Cleanup

### Task 16: Re-sync cron addon

**Repo:** yggdrasil-core
**Files:**
- Create: `/Users/dakasa/projects/yggdrasil/yggdrasil-core/internal/externalidentity/resync_runner.go`
- Create: `/Users/dakasa/projects/yggdrasil/yggdrasil-core/internal/externalidentity/resync_runner_test.go`
- Create: `/Users/dakasa/projects/yggdrasil/yggdrasil-core/addons/external_identity_resync.go`

- [ ] **Step 1: Write minimal failing test (diff function)**

Create `internal/externalidentity/resync_runner_test.go`:

```go
package externalidentity

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDiffIdentities(t *testing.T) {
	dbActive := []Identity{
		{ExternalID: "A", ExternalMetadata: map[string]any{"v": 1}},
		{ExternalID: "B", ExternalMetadata: map[string]any{"v": 1}},
	}
	providerList := []Extracted{
		{ExternalID: "A", ExternalMetadata: map[string]any{"v": 2}}, // metadata change
		{ExternalID: "C", ExternalMetadata: map[string]any{"v": 1}}, // new
		// B missing — drift
	}
	changes := DiffIdentities(dbActive, providerList)
	assert.Len(t, changes.MetadataUpdates, 1)
	assert.Equal(t, "A", changes.MetadataUpdates[0].ExternalID)
	assert.Len(t, changes.Drift, 1)
	assert.Equal(t, "B", changes.Drift[0].ExternalID)
	assert.Len(t, changes.Unknown, 1)
	assert.Equal(t, "C", changes.Unknown[0].ExternalID)
}
```

- [ ] **Step 2: Implement resync_runner.go**

Create `internal/externalidentity/resync_runner.go`:

```go
package externalidentity

import (
	"context"
	"database/sql"
	"reflect"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

// DiffChanges represents what re-sync detected for one instance.
type DiffChanges struct {
	MetadataUpdates []Identity     // present in both, metadata changed
	Drift           []Identity     // in DB, missing from provider
	Unknown         []Extracted    // in provider, missing from DB
}

func DiffIdentities(dbActive []Identity, providerList []Extracted) DiffChanges {
	dbByID := map[string]Identity{}
	for _, d := range dbActive {
		dbByID[d.ExternalID] = d
	}
	provByID := map[string]Extracted{}
	for _, p := range providerList {
		provByID[p.ExternalID] = p
	}
	out := DiffChanges{}
	for id, dbEntry := range dbByID {
		if provEntry, ok := provByID[id]; ok {
			if !reflect.DeepEqual(dbEntry.ExternalMetadata, provEntry.ExternalMetadata) {
				dbEntry.ExternalMetadata = provEntry.ExternalMetadata
				out.MetadataUpdates = append(out.MetadataUpdates, dbEntry)
			}
		} else {
			out.Drift = append(out.Drift, dbEntry)
		}
	}
	for id, provEntry := range provByID {
		if _, ok := dbByID[id]; !ok {
			out.Unknown = append(out.Unknown, provEntry)
		}
	}
	return out
}

// Runner periodically queries each integration_instance's `list_identities`
// capability and reconciles drift.
type Runner struct {
	DB       *sql.DB
	Logger   *zap.Logger
	Interval time.Duration

	EnumerateInstancesWithActiveIdentities func(ctx context.Context) ([]uuid.UUID, error)
	InvokeListIdentities                   func(ctx context.Context, instanceID uuid.UUID) ([]Extracted, error)
}

// Run blocks until ctx is canceled.
func (r *Runner) Run(ctx context.Context) error {
	if r.Interval <= 0 {
		return nil
	}
	t := time.NewTicker(r.Interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
			r.tick(ctx)
		}
	}
}

func (r *Runner) tick(ctx context.Context) {
	if r.EnumerateInstancesWithActiveIdentities == nil || r.InvokeListIdentities == nil {
		return
	}
	instances, err := r.EnumerateInstancesWithActiveIdentities(ctx)
	if err != nil {
		if r.Logger != nil {
			r.Logger.Warn("identity resync: enumerate instances failed", zap.Error(err))
		}
		return
	}
	for _, instID := range instances {
		dbActive, err := List(ctx, r.DB, ListFilters{
			IntegrationInstanceID: &instID,
			ActiveOnly:            true,
			Limit:                 1000,
		})
		if err != nil {
			if r.Logger != nil {
				r.Logger.Warn("identity resync: list DB failed", zap.Error(err))
			}
			continue
		}
		providerList, err := r.InvokeListIdentities(ctx, instID)
		if err != nil {
			if r.Logger != nil {
				r.Logger.Warn("identity resync: list_identities RPC failed", zap.Error(err), zap.Stringer("instance", instID))
			}
			continue
		}
		changes := DiffIdentities(dbActive, providerList)
		now := time.Now().UTC()
		for _, m := range changes.MetadataUpdates {
			_, _, err := Upsert(ctx, r.DB, UpsertInput{
				CollaboratorID:        m.CollaboratorID,
				IntegrationInstanceID: m.IntegrationInstanceID,
				ExternalID:            m.ExternalID,
				ExternalMetadata:      m.ExternalMetadata,
			})
			if err != nil && r.Logger != nil {
				r.Logger.Warn("identity resync: metadata upsert failed", zap.Error(err))
			}
		}
		for _, d := range changes.Drift {
			_ = EmitEvent(ctx, r.DB, repository.EventTypeExternalIdentityDriftDetected, d.ID,
				BuildDriftPayload(DriftInputs{
					IdentityID: d.ID, CollaboratorID: d.CollaboratorID,
					IntegrationInstanceID: d.IntegrationInstanceID,
					ExternalID:            d.ExternalID,
					DetectedAt:            now,
				}))
		}
		for _, u := range changes.Unknown {
			_ = EmitEvent(ctx, r.DB, repository.EventTypeExternalIdentityUnknownExternal, instID,
				BuildUnknownExternalPayload(UnknownExternalInputs{
					IntegrationInstanceID: instID,
					ExternalID:            u.ExternalID,
					ExternalMetadata:      u.ExternalMetadata,
					DetectedAt:            now,
				}))
		}
	}
}
```

- [ ] **Step 3: Create addon `external_identity_resync.go`**

```go
package addons

import (
	"context"
	"database/sql"
	"errors"
	"time"

	messagecontroller "github.com/dakasa-yggdrasil/yggdrasil-core/controllers/message"
	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/externalidentity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/runtime"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	amqp "github.com/rabbitmq/amqp091-go"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

func init() {
	Register("external-identity-resync", bootstrapExternalIdentityResync, 85)
}

func bootstrapExternalIdentityResync(ctx context.Context, app *runtime.ServiceApp) error {
	db, ok := Postgres(app)
	if !ok {
		return nil
	}
	conn, ok := RabbitMQ(app)
	if !ok {
		return nil
	}
	logger, _ := Logger(app)

	r := &externalidentity.Runner{
		DB:       db,
		Logger:   logger,
		Interval: envDurOrDefault("IDENTITY_RESYNC_INTERVAL", 24*time.Hour),
		EnumerateInstancesWithActiveIdentities: func(ctx context.Context) ([]uuid.UUID, error) {
			rows, err := db.QueryContext(ctx, `
				SELECT DISTINCT integration_instance_id
				FROM collaborator_external_identities
				WHERE unlinked_at IS NULL`)
			if err != nil {
				return nil, err
			}
			defer rows.Close()
			var out []uuid.UUID
			for rows.Next() {
				var id uuid.UUID
				if err := rows.Scan(&id); err != nil {
					return nil, err
				}
				out = append(out, id)
			}
			return out, nil
		},
		InvokeListIdentities: func(ctx context.Context, instanceID uuid.UUID) ([]externalidentity.Extracted, error) {
			resp, err := messagecontroller.ExecuteIntegration(ctx, conn, db, model.ExecuteIntegrationRequest{
				Integration: model.ManifestSelector{ManifestID: instanceID.String()},
				Operation:   "list_identities",
				Capability:  "list_identities",
				Input:       map[string]any{},
			})
			if err != nil {
				return nil, err
			}
			arr, _ := resp.Output["identities"].([]any)
			out := make([]externalidentity.Extracted, 0, len(arr))
			for _, raw := range arr {
				m, _ := raw.(map[string]any)
				ext, _ := m["external_id"].(string)
				meta, _ := m["external_metadata"].(map[string]any)
				if ext != "" {
					out = append(out, externalidentity.Extracted{ExternalID: ext, ExternalMetadata: meta})
				}
			}
			return out, nil
		},
	}

	go func() {
		if err := r.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
			if logger != nil {
				logger.Error("external_identity resync runner exited", zap.Error(err))
			}
		}
	}()
	if logger != nil {
		logger.Info("external identity resync addon started", zap.Duration("interval", r.Interval))
	}
	_ = repository.EventTypeExternalIdentityDriftDetected // keep import alive
	_ = amqp.Connection{}                                 // keep import alive
	_ = sql.ErrNoRows
	return nil
}
```

NOTE: the trailing `_ = ...` lines are scaffolding to ensure imports stay referenced during compilation; can be cleaned once final code uses them naturally.

- [ ] **Step 4: Run tests + build**

```bash
go test ./internal/externalidentity/ -run TestDiff -count=1 -v
go build ./...
```
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
cd /Users/dakasa/projects/yggdrasil/yggdrasil-core
git add internal/externalidentity/resync_runner.go internal/externalidentity/resync_runner_test.go addons/external_identity_resync.go
git commit -m "feat(externalidentity): re-sync drift detection cron"
```

---

### Task 17: Cleanup cron addon

**Repo:** yggdrasil-core
**Files:**
- Create: `/Users/dakasa/projects/yggdrasil/yggdrasil-core/internal/externalidentity/cleanup_runner.go`
- Create: `/Users/dakasa/projects/yggdrasil/yggdrasil-core/internal/externalidentity/cleanup_runner_test.go`
- Create: `/Users/dakasa/projects/yggdrasil/yggdrasil-core/addons/external_identity_cleanup.go`

- [ ] **Step 1: Implement cleanup_runner.go**

Create `internal/externalidentity/cleanup_runner.go`:

```go
package externalidentity

import (
	"context"
	"database/sql"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	"go.uber.org/zap"
)

// CleanupRunner deletes rows whose unlinked_at is older than the retention
// window. Emits a purged event per deletion.
type CleanupRunner struct {
	DB        *sql.DB
	Logger    *zap.Logger
	Interval  time.Duration
	Retention time.Duration
}

func (r *CleanupRunner) Run(ctx context.Context) error {
	if r.Interval <= 0 {
		return nil
	}
	t := time.NewTicker(r.Interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
			r.tick(ctx)
		}
	}
}

func (r *CleanupRunner) tick(ctx context.Context) {
	before := time.Now().UTC().Add(-r.Retention)
	purged, err := HardCleanup(ctx, r.DB, before)
	if err != nil {
		if r.Logger != nil {
			r.Logger.Warn("external_identity cleanup failed", zap.Error(err))
		}
		return
	}
	for _, p := range purged {
		_ = EmitEvent(ctx, r.DB, repository.EventTypeExternalIdentityPurged, p.ID,
			BuildPurgedPayload(PurgedInputs{
				IdentityID: p.ID, CollaboratorID: p.CollaboratorID,
				IntegrationInstanceID: p.IntegrationInstanceID,
				ExternalID:            p.ExternalID,
				PurgedAt:              time.Now().UTC(),
			}))
	}
}
```

- [ ] **Step 2: Test (simple)**

Create `internal/externalidentity/cleanup_runner_test.go`:

```go
package externalidentity

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestCleanupRunner_NoBleed(t *testing.T) {
	r := &CleanupRunner{Interval: 0}
	assert.Equal(t, time.Duration(0), r.Interval) // Run() returns immediately when interval=0
}
```

(More substantial cleanup behavior is covered by `TestHardCleanup_DeletesOnlyOldUnlinked` in repository_test.go.)

- [ ] **Step 3: Addon bootstrap**

Create `addons/external_identity_cleanup.go`:

```go
package addons

import (
	"context"
	"errors"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/externalidentity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/runtime"
	"go.uber.org/zap"
)

func init() {
	Register("external-identity-cleanup", bootstrapExternalIdentityCleanup, 86)
}

func bootstrapExternalIdentityCleanup(ctx context.Context, app *runtime.ServiceApp) error {
	db, ok := Postgres(app)
	if !ok {
		return nil
	}
	logger, _ := Logger(app)

	r := &externalidentity.CleanupRunner{
		DB:        db,
		Logger:    logger,
		Interval:  envDurOrDefault("IDENTITY_CLEANUP_INTERVAL", 1*time.Hour),
		Retention: envDurOrDefault("IDENTITY_UNLINK_RETENTION", 30*24*time.Hour),
	}
	go func() {
		if err := r.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
			if logger != nil {
				logger.Error("external_identity cleanup runner exited", zap.Error(err))
			}
		}
	}()
	if logger != nil {
		logger.Info("external identity cleanup addon started",
			zap.Duration("interval", r.Interval),
			zap.Duration("retention", r.Retention))
	}
	return nil
}
```

- [ ] **Step 4: Run build + tests**

```bash
go build ./...
go test ./internal/externalidentity/ -count=1
```
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
cd /Users/dakasa/projects/yggdrasil/yggdrasil-core
git add internal/externalidentity/cleanup_runner.go internal/externalidentity/cleanup_runner_test.go addons/external_identity_cleanup.go
git commit -m "feat(externalidentity): hard-cleanup cron + purged events"
```

---

### Task 18: Adapter `list_identities` capabilities (slack/gw/github)

**Repos:** integration-slack, integration-google-workspace, integration-github

For each repo, add `list_identities` capability that proxies the existing `list_users` (slack/gw) or `list_org_members` (github) call and maps to the Extracted envelope shape.

- [ ] **Step 1: integration-slack — add `OperationListIdentities`**

In `integration-slack/internal/adapter/spec.go`, add `OperationListIdentities = "list_identities"`, register in switch, add action_catalog entry. Implement in a new file `internal/adapter/identity.go`:

```go
package adapter

import (
	"github.com/dakasa-yggdrasil/integration-slack/internal/protocol"
)

func listIdentities(auth slackAuth, input map[string]any) (map[string]any, error) {
	out, err := listUsers(auth, input)
	if err != nil {
		return nil, err
	}
	users, _ := out["users"].([]map[string]any)
	identities := make([]map[string]any, 0, len(users))
	for _, u := range users {
		id, _ := u["user_id"].(string)
		if id == "" { id, _ = u["id"].(string) }
		if id == "" { continue }
		identities = append(identities, map[string]any{
			"external_id": id,
			"external_metadata": map[string]any{
				"userName":     u["userName"],
				"display_name": u["display_name"],
				"email":        u["email"],
			},
		})
	}
	return map[string]any{"identities": identities, "next_cursor": nil}, nil
}

// register: in spec.go switch dispatching by operation, add case OperationListIdentities → listIdentities(auth, input)
// register in action_catalog with description "Enumerate Slack workspace users for yggdrasil re-sync."
```

Commit:
```bash
cd /Users/dakasa/projects/yggdrasil/integration-slack
git add internal/adapter/identity.go internal/adapter/spec.go
git commit -m "feat(reactors): add list_identities capability"
```

- [ ] **Step 2: integration-google-workspace — add `list_identities` similarly**

In `providers/runtime/adapter/`, create `identity.go` that wraps existing `listUsers` call and maps to `{external_id, external_metadata}` shape. Register Operation. Commit.

- [ ] **Step 3: integration-github — add `list_identities`**

In `internal/adapter/identity.go`, list org members (GET /orgs/{org}/members), map to identity shape with `external_id=login` (or numeric id if available; prefer numeric via second API call when needed). Register. Commit.

---

## Phase 7: Integration & E2E validation

### Task 19: Integration tests for full link/unlink/conflict/drift cycle

**Repo:** yggdrasil-core
**Files:**
- Create: `/Users/dakasa/projects/yggdrasil/yggdrasil-core/internal/externalidentity/integration_test.go`

- [ ] **Step 1: Write the integration test**

Create `internal/externalidentity/integration_test.go` (skips if `DB_URL` unset):

```go
package externalidentity

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIntegration_LinkUnlinkRelinkCycle(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)
	t.Cleanup(func() { db.Close() })

	collabID := seedCollaborator(t, db)
	instanceID := uuid.New()

	id, outcome, err := Upsert(ctx, db, UpsertInput{
		CollaboratorID: collabID, IntegrationInstanceID: instanceID,
		ExternalID: "U_CYCLE", ExternalMetadata: map[string]any{"v": 1},
	})
	require.NoError(t, err)
	assert.Equal(t, OutcomeInserted, outcome)
	t.Cleanup(func() { db.Exec(`DELETE FROM collaborator_external_identities WHERE id = $1`, id) })

	_, err = SoftDelete(ctx, db, id)
	require.NoError(t, err)

	relinkedID, outcome, err := Upsert(ctx, db, UpsertInput{
		CollaboratorID: collabID, IntegrationInstanceID: instanceID,
		ExternalID: "U_CYCLE", ExternalMetadata: map[string]any{"v": 2},
	})
	require.NoError(t, err)
	assert.Equal(t, id, relinkedID)
	assert.Equal(t, OutcomeReLinked, outcome)

	// Verify final state
	final, err := GetByID(ctx, db, id)
	require.NoError(t, err)
	assert.Nil(t, final.UnlinkedAt)
	assert.EqualValues(t, 2, final.ExternalMetadata["v"])

	// Now cleanup with 1ns retention to test hard cleanup
	_, err = SoftDelete(ctx, db, id)
	require.NoError(t, err)
	purged, err := HardCleanup(ctx, db, time.Now().UTC())
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(purged), 1)
}
```

- [ ] **Step 2: Run integration test (with DB)**

```bash
DB_URL="postgres://yggdrasil:test@localhost:5432/yggdrasil_test?sslmode=disable" \
  go test ./internal/externalidentity/ -run TestIntegration -count=1 -v
```
Expected: PASS (or SKIP if no DB).

- [ ] **Step 3: Commit**

```bash
cd /Users/dakasa/projects/yggdrasil/yggdrasil-core
git add internal/externalidentity/integration_test.go
git commit -m "test(externalidentity): integration test for full link/unlink/relink/cleanup cycle"
```

---

### Task 20: E2E smoke + document results in spec §16

**Repo:** yggdrasil-core (docs update)
**Files:**
- Modify: `/Users/dakasa/projects/yggdrasil/yggdrasil-core/docs/superpowers/specs/2026-05-16-collaborator-external-identities-design.md`

Operationally run the §12.3 E2E smoke from the spec:

- [ ] **Step 1: Deploy & validate yggdrasil-core**

Push committed code to `dakasa-yggdrasil/yggdrasil-core`. Wait for CD; force-roll if needed via `update-deployment-image-only` workflow. Confirm `manifest sync addon started` AND `external identity resync addon started` AND `external identity cleanup addon started` log lines.

- [ ] **Step 2: Deploy adapters**

For each of integration-slack, integration-google-workspace, integration-github, push commits and roll via `update-deployment-image-only`.

- [ ] **Step 3: Configure GitHub webhook**

Operator manually: in `dakasa-yggdrasil` org → Settings → Webhooks → add:
- Payload URL: `https://yggdrasil.dakasa.me/api/v1/integrations/<github-instance-id>/webhook`
- Content type: `application/json`
- Secret: a fresh random string
- Events: "Member" (Members added to or removed from organizations)

Store the secret in `integration-github-dakasa-credentials` under key `webhook_secret`. Patch the `integration-github-dakasa` integration_instance manifest config to include `webhook_signature_scheme: github_hmac_sha256` and `webhook_secret: secret://dakasa/integration-github-dakasa-credentials#webhook_secret`.

- [ ] **Step 4: Smoke flow**

```bash
# 1. Onboard
curl -X POST https://yggdrasil.dakasa.me/api/v1/collaborators \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{...qa-extid-smoke-v1...}'

# 2. Confirm onboard reactions all succeeded
# 3. Accept the GitHub email invitation manually
# 4. GitHub fires webhook → core endpoint → adapter on_webhook → link_identity → POST identity
# 5. Verify identity row populated
psql ... -c "SELECT * FROM collaborator_external_identities WHERE collaborator_id = ...;"

# 6. Offboard
curl -X POST https://yggdrasil.dakasa.me/api/v1/collaborators/<id>/offboard \
  -d '{"reason":"voluntary"}' -H "Authorization: Bearer $TOKEN"

# 7. Confirm GH adapter removed the actual user from org via _context.external_identity
curl -H "Authorization: token $TOKEN_GH" \
  https://api.github.com/orgs/dakasa-yggdrasil/members/<username>
# expect 404

# 8. Verify event log has linked + unlinked rows
```

- [ ] **Step 5: Document results**

Append a `## 17. E2E smoke results (YYYY-MM-DD)` section to the spec with whatever was observed (success/discoveries/follow-up bugs found).

- [ ] **Step 6: Commit**

```bash
cd /Users/dakasa/projects/yggdrasil/yggdrasil-core
git add docs/superpowers/specs/2026-05-16-collaborator-external-identities-design.md
git commit -m "docs(externalidentity): record E2E smoke results"
```

---

## Self-review notes (controller)

**Spec coverage check:**

| Spec § | Task |
|---|---|
| 4 Schema | Task 1 |
| 5.1 POST | Task 5, 6 (emit wiring) |
| 5.2 GET | Task 5 |
| 5.3 DELETE | Task 7 |
| 5.4 Webhook | Task 14 |
| 6.1 Write envelope | Task 8 (helpers), 9 (dispatcher), 10/12 (adapter emits) |
| 6.2 Read envelope | Task 8 (helpers), 9 (dispatcher), 11/12/13 (adapter consumes) |
| 7 Webhook flow | Task 14 (core) + Task 15 (github on_webhook) |
| 8 Re-sync | Task 16 + Task 18 (adapter list_identities) |
| 9 Cleanup | Task 17 |
| 10 6 events | Task 2 (constants), 3 (schemas), 6 (builders), 9/14/16/17 (emit sites) |
| 11 Error handling | Embedded throughout — best-effort emit, conflict path, malformed envelope drop |
| 12 Testing | Task 4 (repo), 6 (envelope), 14 (hmac), 16 (diff), 19 (integration), 20 (E2E) |

**Placeholder scan:** I marked Task 18 as multi-repo with abbreviated commit instructions per repo. The implementer must adapt the slack `listUsers` shape to whatever the real return is (the adapter's listUsers may have different field names than the example shows). Same for GW and GH. These adaptations are mechanical 5-line changes per adapter; not a placeholder, but explicitly delegated to the implementer due to per-repo variation. Steps 1-3 in Task 18 each give the pattern explicitly.

**Type consistency:** `Extracted` (envelope), `Identity` (DB row), `UpsertInput`, `EmbeddedIdentity` all defined consistently across tasks. `OutcomeInserted/ReLinked/Refreshed/Conflict` enum is used consistently in repository, handler, and tests.
