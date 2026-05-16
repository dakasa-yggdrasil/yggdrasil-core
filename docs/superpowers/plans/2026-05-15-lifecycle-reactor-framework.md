# Lifecycle Reactor Framework Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement declarative reactor framework in yggdrasil-core. Integrations declare which lifecycle events they react to in their `integration_type` manifest; core materializes reactions in the same transaction as `EmitEvent` and dispatches via RabbitMQ with retry/backoff/dead-letter. 11 canon events (6 collaborator, 3 team, 2 team_membership). Workflows lifecycle in dakasa-system are removed. Console UI auto-issues setup-token after creating a person.

**Architecture:** New `integration_event_reactions` table + Materializer (runs inside `EmitEvent` tx) + Runner (addon goroutine with `FOR UPDATE SKIP LOCKED` batch processing + RabbitMQ RPC + retry 1m/5m/15m → dead-letter). Manifest validator rejects reactors outside the 11-event canon. Core handlers audited so each emits its canon event in the same transaction as state mutation. UI gains `SetupURLModal` reusable component.

**Tech Stack:** Go 1.22+, PostgreSQL (Goose migrations, `FOR UPDATE SKIP LOCKED`), `net/http` (`mux.HandleFunc("METHOD /path", handler)`), RabbitMQ (reusing existing `messagecontroller.RunIntegrationOperation`), `repository.EmitEvent` extension, addon registry pattern (priority ~70), React + TypeScript + Vite for surface-console.

**Spec reference:** [docs/superpowers/specs/2026-05-15-lifecycle-reactor-framework-design.md](../specs/2026-05-15-lifecycle-reactor-framework-design.md)

---

## File Structure

### To Create (yggdrasil-core)

| Path | Responsibility |
|---|---|
| `db/migrations/NNNN_integration_event_reactions.sql` | New table + 3 partial indexes |
| `model/reactor.go` | `Reactor`, `ReactorContext`, `IntegrationEventReaction`, `ReactionStatus` types + canon event constants |
| `internal/reactors/backoff.go` | `BackoffFor(attempt int) (time.Duration, bool)` |
| `internal/reactors/backoff_test.go` | Table-driven backoff tests |
| `internal/reactors/payload.go` | `BuildReactorPayload(event, reaction, attempt)` merging `_context` |
| `internal/reactors/payload_test.go` | Unit tests |
| `internal/reactors/dispatcher.go` | Runner: ticker + claim batch + dispatch + retry |
| `internal/reactors/dispatcher_test.go` | Unit tests with mocked RabbitMQ |
| `repository/integration_event_reactions.go` | CRUD + MaterializeReactions + ClaimPendingBatch + status transitions |
| `repository/integration_event_reactions_test.go` | Integration tests |
| `manifest/integration_type_reactors_validate.go` | Reactor block validator |
| `manifest/integration_type_reactors_validate_test.go` | Validation cases |
| `addons/reactor_dispatcher.go` | Bootstrap addon priority 70 |
| `docs/contracts/events/v1/collaborator/absence_started.json` | NEW event schema |
| `docs/contracts/events/v1/collaborator/absence_ended.json` | NEW |
| `docs/contracts/events/v1/collaborator/role_changed.json` | NEW |
| `docs/contracts/events/v1/collaborator/re_onboarded.json` | NEW |
| `docs/contracts/events/v1/team/created.json` | NEW |
| `docs/contracts/events/v1/team/updated.json` | NEW |
| `docs/contracts/events/v1/team/deleted.json` | NEW |
| `docs/contracts/events/v1/team_membership/added.json` | NEW |
| `docs/contracts/events/v1/team_membership/removed.json` | NEW |
| `docs/contracts/reactors/v1/collaborator.created.json` | NEW reactor input schema |
| `docs/contracts/reactors/v1/collaborator.offboarded.json` | NEW |
| `docs/contracts/reactors/v1/collaborator.absence_started.json` | NEW |
| `docs/contracts/reactors/v1/collaborator.absence_ended.json` | NEW |
| `docs/contracts/reactors/v1/collaborator.role_changed.json` | NEW |
| `docs/contracts/reactors/v1/collaborator.re_onboarded.json` | NEW |
| `docs/contracts/reactors/v1/team.created.json` | NEW |
| `docs/contracts/reactors/v1/team.updated.json` | NEW |
| `docs/contracts/reactors/v1/team.deleted.json` | NEW |
| `docs/contracts/reactors/v1/team_membership.added.json` | NEW |
| `docs/contracts/reactors/v1/team_membership.removed.json` | NEW |

### To Modify (yggdrasil-core)

| Path | Change |
|---|---|
| `repository/event.go` | `EmitEvent` invokes `MaterializeReactions(tx, eventID, eventType)` when event_type is canon |
| `repository/event_types.go` (or `repository/event_types_credential.go` neighbor) | +11 canon event constants + `EventTypeReactorDeadLettered` |
| `repository/collaborator.go` or `repository/identity.go` | `CreateCollaborator` also INSERTs `auth_identities` row in same tx (fix existing gap) |
| `repository/collaborator_lifecycle.go` | Audit each handler emit: absence_started/ended, role_changed, re_onboarded |
| `repository/team.go` or equivalent | Emit `team.created/updated/deleted` |
| `repository/team_memberships.go` | Emit `team_membership.added/removed` |
| `manifest/integration_type_validate.go` (or wherever integration_type manifests are validated) | Plug reactor validation hook |
| `controllers/httpapi/collaborator_lifecycle.go` | Audit handlers route emit through repo layer |
| `docs/contracts/events_validator.go` | Register 9 new event schemas |

### To Create (surface-console)

| Path | Responsibility |
|---|---|
| `src/pages/collaborators/SetupURLModal.tsx` | Reusable modal with URL + copy button |
| `src/pages/collaborators/SetupURLModal.css` | Modal styles |

### To Modify (surface-console)

| Path | Change |
|---|---|
| `src/lib/api.ts` | Add `issueSetupToken(collaboratorID)` |
| `src/pages/collaborators/CollaboratorNewPage.tsx` | Chain `createCollaborator` → `issueSetupToken` → open modal |
| `src/pages/collaborators/CollaboratorDetailPage.tsx` | Add "Gerar novo link" button when password_hash null |

### To Delete (dakasa-system)

| Path | Reason |
|---|---|
| `yggdrasil/dakasa/workflows/onboard.json` | Superseded by reactor model |
| `yggdrasil/dakasa/workflows/offboard.json` | Idem |
| `yggdrasil/dakasa/workflows/absence-start.json` | Idem |
| `yggdrasil/dakasa/workflows/absence-end.json` | Idem |
| `yggdrasil/dakasa/workflows/role-change.json` | Idem |
| `yggdrasil/dakasa/workflows/re-onboard.json` | Idem |
| `yggdrasil/dakasa/workflows/cleanup-offboarded-collaborator.json` | Replaced by simple cron-style workflow (Phase 2) |

---

## Phase 1: Foundation — schema + domain types

### Task 1.1: Migration `integration_event_reactions`

**Files:**
- Create: `db/migrations/NNNN_integration_event_reactions.sql`

- [ ] **Step 1: Locate next migration number**

```bash
cd /Users/dakasa/projects/yggdrasil/yggdrasil-core
ls db/migrations/ | tail -5
```

Replace `NNNN` below with the next available 5-digit number (e.g., `00039_`).

- [ ] **Step 2: Write the migration SQL**

```sql
-- +goose Up
-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS public.integration_event_reactions (
  id                            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  event_id                      UUID NOT NULL REFERENCES public.event_log(event_id) ON DELETE CASCADE,
  event_type                    TEXT NOT NULL,
  integration_instance_id       UUID NOT NULL REFERENCES public.manifests(id) ON DELETE CASCADE,
  integration_type_manifest_id  UUID NOT NULL REFERENCES public.manifests(id) ON DELETE CASCADE,
  capability                    TEXT NOT NULL,
  status                        TEXT NOT NULL,
  attempt                       INT  NOT NULL DEFAULT 0,
  next_attempt_at               TIMESTAMPTZ NULL,
  started_at                    TIMESTAMPTZ NULL,
  finished_at                   TIMESTAMPTZ NULL,
  last_error                    TEXT NULL,
  metadata                      JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at                    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at                    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT iers_status_check CHECK (status IN ('pending','in_progress','succeeded','failed','dead_lettered')),
  CONSTRAINT iers_unique_per_event_instance UNIQUE (event_id, integration_instance_id)
);

CREATE INDEX IF NOT EXISTS iers_pending_idx
  ON public.integration_event_reactions (next_attempt_at, status)
  WHERE status IN ('pending','failed');

CREATE INDEX IF NOT EXISTS iers_event_idx ON public.integration_event_reactions (event_id);

CREATE INDEX IF NOT EXISTS iers_instance_idx
  ON public.integration_event_reactions (integration_instance_id, status, created_at DESC);

DROP TRIGGER IF EXISTS integration_event_reactions_touch_updated_at ON public.integration_event_reactions;
CREATE TRIGGER integration_event_reactions_touch_updated_at
    BEFORE UPDATE ON public.integration_event_reactions
    FOR EACH ROW EXECUTE FUNCTION public.touch_updated_at();
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TRIGGER IF EXISTS integration_event_reactions_touch_updated_at ON public.integration_event_reactions;
DROP TABLE IF EXISTS public.integration_event_reactions;
-- +goose StatementEnd
```

- [ ] **Step 3: Skip DB apply (no Postgres available)**

Note in commit message that migration is written but not exercised. Phase 9 will smoke-test against live cluster.

- [ ] **Step 4: Commit**

```bash
git add db/migrations/NNNN_integration_event_reactions.sql
git commit -m "feat(reactors): add integration_event_reactions table"
```

---

### Task 1.2: Canon event type constants

**Files:**
- Modify: `repository/event_types_credential.go` (or wherever event type constants live — verify via `grep -rn "EventTypeCollaboratorCreated\|EventTypeManifestCreated" repository/`)

- [ ] **Step 1: Locate the file**

```bash
grep -rn "EventTypeCollaboratorCreated\|EventTypeManifestCreated\|EventTypeCredentialPasswordChanged" repository/*.go | head -3
```

Use the file most aligned with collaborator/lifecycle events, or create `repository/event_types_lifecycle.go`.

- [ ] **Step 2: Add canon event constants**

```go
// repository/event_types_lifecycle.go
package repository

// Canon lifecycle events that drive the reactor framework.
// These must remain stable — changing a value is a breaking change for every
// integration that has reactors declared against them.
const (
	EventTypeCollaboratorCreated          = "collaborator.created"
	EventTypeCollaboratorOffboarded       = "collaborator.offboarded"
	EventTypeCollaboratorAbsenceStarted   = "collaborator.absence_started"
	EventTypeCollaboratorAbsenceEnded     = "collaborator.absence_ended"
	EventTypeCollaboratorRoleChanged      = "collaborator.role_changed"
	EventTypeCollaboratorReOnboarded      = "collaborator.re_onboarded"
	EventTypeTeamCreated                  = "team.created"
	EventTypeTeamUpdated                  = "team.updated"
	EventTypeTeamDeleted                  = "team.deleted"
	EventTypeTeamMembershipAdded          = "team_membership.added"
	EventTypeTeamMembershipRemoved        = "team_membership.removed"

	// EventTypeReactorDeadLettered is emitted by the Runner when a reaction
	// exhausts retries. It is NOT a canon lifecycle event — the prefix
	// "reactor.*" is reserved and the Materializer skips it (no infinite loop).
	EventTypeReactorDeadLettered = "reactor.dead_lettered"
)

// CanonLifecycleEventTypes is the closed set of events that may have reactors.
// The Materializer consults this set; the manifest validator rejects reactor
// declarations using any event_type outside it.
var CanonLifecycleEventTypes = map[string]struct{}{
	EventTypeCollaboratorCreated:        {},
	EventTypeCollaboratorOffboarded:     {},
	EventTypeCollaboratorAbsenceStarted: {},
	EventTypeCollaboratorAbsenceEnded:   {},
	EventTypeCollaboratorRoleChanged:    {},
	EventTypeCollaboratorReOnboarded:    {},
	EventTypeTeamCreated:                {},
	EventTypeTeamUpdated:                {},
	EventTypeTeamDeleted:                {},
	EventTypeTeamMembershipAdded:        {},
	EventTypeTeamMembershipRemoved:      {},
}

// IsCanonLifecycleEvent returns true when t is in the closed canon set.
func IsCanonLifecycleEvent(t string) bool {
	_, ok := CanonLifecycleEventTypes[t]
	return ok
}
```

- [ ] **Step 3: Verify build**

```bash
go build ./...
```

Expected: zero output.

- [ ] **Step 4: Commit**

```bash
git add repository/event_types_lifecycle.go
git commit -m "feat(reactors): add canon lifecycle event type constants"
```

---

### Task 1.3: Reactor domain types

**Files:**
- Create: `model/reactor.go`

- [ ] **Step 1: Write the types**

```go
// model/reactor.go
package model

import (
	"time"

	"github.com/google/uuid"
)

// ReactionStatus is the lifecycle of a single integration_event_reactions row.
type ReactionStatus string

const (
	ReactionStatusPending      ReactionStatus = "pending"
	ReactionStatusInProgress   ReactionStatus = "in_progress"
	ReactionStatusSucceeded    ReactionStatus = "succeeded"
	ReactionStatusFailed       ReactionStatus = "failed"
	ReactionStatusDeadLettered ReactionStatus = "dead_lettered"
)

// Reactor is the declaration block on an integration_type manifest.
// One Reactor declares: "when event_type fires in core, call my capability".
type Reactor struct {
	EventType   string `json:"event_type"`
	Capability  string `json:"capability"`
	Description string `json:"description,omitempty"`
}

// IntegrationEventReaction represents a single row in
// public.integration_event_reactions.
type IntegrationEventReaction struct {
	ID                         uuid.UUID      `json:"id"`
	EventID                    uuid.UUID      `json:"event_id"`
	EventType                  string         `json:"event_type"`
	IntegrationInstanceID      uuid.UUID      `json:"integration_instance_id"`
	IntegrationTypeManifestID  uuid.UUID      `json:"integration_type_manifest_id"`
	Capability                 string         `json:"capability"`
	Status                     ReactionStatus `json:"status"`
	Attempt                    int            `json:"attempt"`
	NextAttemptAt              *time.Time     `json:"next_attempt_at,omitempty"`
	StartedAt                  *time.Time     `json:"started_at,omitempty"`
	FinishedAt                 *time.Time     `json:"finished_at,omitempty"`
	LastError                  string         `json:"last_error,omitempty"`
	Metadata                   map[string]any `json:"metadata,omitempty"`
	CreatedAt                  time.Time      `json:"created_at"`
	UpdatedAt                  time.Time      `json:"updated_at"`
}

// ReactorContext is the `_context` block injected into every reactor payload.
// Integrations receive it alongside the event payload and use it for
// idempotency (event_id + attempt) and audit (actor + emitted_at).
type ReactorContext struct {
	EventID       string         `json:"event_id"`
	EventType     string         `json:"event_type"`
	SchemaVersion string         `json:"schema_version"`
	EmittedAt     time.Time      `json:"emitted_at"`
	Actor         *EventActor    `json:"actor,omitempty"`
	Attempt       int            `json:"attempt"`
}
```

- [ ] **Step 2: Verify build**

```bash
go build ./...
```

- [ ] **Step 3: Commit**

```bash
git add model/reactor.go
git commit -m "feat(reactors): add reactor domain types"
```

---

### Task 1.4: Backoff function

**Files:**
- Create: `internal/reactors/backoff.go`
- Test: `internal/reactors/backoff_test.go`

- [ ] **Step 1: Failing test**

```go
// internal/reactors/backoff_test.go
package reactors

import (
	"testing"
	"time"
)

func TestBackoffFor(t *testing.T) {
	tests := []struct {
		name      string
		attempt   int
		wantDur   time.Duration
		wantFinal bool
	}{
		{"attempt 1 → 1m", 1, time.Minute, false},
		{"attempt 2 → 5m", 2, 5 * time.Minute, false},
		{"attempt 3 → 15m", 3, 15 * time.Minute, false},
		{"attempt 4 → dead-letter", 4, 0, true},
		{"attempt 10 → dead-letter", 10, 0, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dur, final := BackoffFor(tt.attempt)
			if dur != tt.wantDur {
				t.Errorf("got dur=%v want %v", dur, tt.wantDur)
			}
			if final != tt.wantFinal {
				t.Errorf("got final=%v want %v", final, tt.wantFinal)
			}
		})
	}
}
```

- [ ] **Step 2: Run test (expect fail)**

```bash
go test ./internal/reactors/... -run TestBackoffFor -v
```

Expected: build error (package missing) or test fail.

- [ ] **Step 3: Implement**

```go
// internal/reactors/backoff.go
package reactors

import (
	"os"
	"strconv"
	"strings"
	"time"
)

// BackoffFor returns the wait duration before the next attempt, plus a
// boolean indicating whether the reaction must be dead-lettered instead.
//
// Defaults: attempt 1 → 1m, attempt 2 → 5m, attempt 3 → 15m, attempt 4+ → dead-letter.
// Env overrides: REACTOR_BACKOFF_ATTEMPT_1/2/3 (Go duration syntax: "1m", "30s",
// "2h"), REACTOR_MAX_ATTEMPTS (default 3).
func BackoffFor(attempt int) (time.Duration, bool) {
	maxAttempts := envIntPositive("REACTOR_MAX_ATTEMPTS", 3)
	if attempt < 1 || attempt > maxAttempts {
		return 0, true
	}
	switch attempt {
	case 1:
		return envDuration("REACTOR_BACKOFF_ATTEMPT_1", time.Minute), false
	case 2:
		return envDuration("REACTOR_BACKOFF_ATTEMPT_2", 5*time.Minute), false
	case 3:
		return envDuration("REACTOR_BACKOFF_ATTEMPT_3", 15*time.Minute), false
	default:
		return 0, true
	}
}

func envDuration(key string, def time.Duration) time.Duration {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return def
	}
	d, err := time.ParseDuration(v)
	if err != nil || d <= 0 {
		return def
	}
	return d
}

func envIntPositive(key string, def int) int {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil || n <= 0 {
		return def
	}
	return n
}
```

- [ ] **Step 4: Run test (expect pass)**

```bash
go test ./internal/reactors/... -run TestBackoffFor -v
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/reactors/backoff.go internal/reactors/backoff_test.go
git commit -m "feat(reactors): backoff schedule 1m/5m/15m → dead-letter"
```

---

## Phase 2: Event schemas (canon catalog)

### Task 2.1: New event JSON schemas (9 files)

**Files:**
- Create: `docs/contracts/events/v1/collaborator/absence_started.json`
- Create: `docs/contracts/events/v1/collaborator/absence_ended.json`
- Create: `docs/contracts/events/v1/collaborator/role_changed.json`
- Create: `docs/contracts/events/v1/collaborator/re_onboarded.json`
- Create: `docs/contracts/events/v1/team/created.json`
- Create: `docs/contracts/events/v1/team/updated.json`
- Create: `docs/contracts/events/v1/team/deleted.json`
- Create: `docs/contracts/events/v1/team_membership/added.json`
- Create: `docs/contracts/events/v1/team_membership/removed.json`

- [ ] **Step 1: Verify which already exist**

```bash
ls docs/contracts/events/v1/collaborator/ docs/contracts/events/v1/team/ docs/contracts/events/v1/team_membership/ 2>/dev/null
```

Skip any that already exist (e.g., `created.json`, `offboarded.json` in collaborator).

- [ ] **Step 2: Write each schema**

`docs/contracts/events/v1/collaborator/absence_started.json`:
```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://yggdrasil.io/contracts/events/v1/collaborator/absence_started.json",
  "title": "collaborator.absence_started v1",
  "type": "object",
  "required": ["collaborator_id", "type", "from"],
  "properties": {
    "collaborator_id":   { "type": "string", "format": "uuid" },
    "primary_email":     { "type": "string" },
    "type":              { "type": "string", "enum": ["vacation","leave-medical","leave-parental","leave-sabbatical"] },
    "from":              { "type": "string", "format": "date" },
    "to":                { "type": "string", "format": "date" },
    "duration_days":     { "type": "integer", "minimum": 1 }
  },
  "additionalProperties": false
}
```

`docs/contracts/events/v1/collaborator/absence_ended.json`:
```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://yggdrasil.io/contracts/events/v1/collaborator/absence_ended.json",
  "title": "collaborator.absence_ended v1",
  "type": "object",
  "required": ["collaborator_id"],
  "properties": {
    "collaborator_id": { "type": "string", "format": "uuid" },
    "primary_email":   { "type": "string" }
  },
  "additionalProperties": false
}
```

`docs/contracts/events/v1/collaborator/role_changed.json`:
```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://yggdrasil.io/contracts/events/v1/collaborator/role_changed.json",
  "title": "collaborator.role_changed v1",
  "type": "object",
  "required": ["collaborator_id", "role_to"],
  "properties": {
    "collaborator_id": { "type": "string", "format": "uuid" },
    "primary_email":   { "type": "string" },
    "role_from":       { "type": "string" },
    "role_to":         { "type": "string" }
  },
  "additionalProperties": false
}
```

`docs/contracts/events/v1/collaborator/re_onboarded.json`:
```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://yggdrasil.io/contracts/events/v1/collaborator/re_onboarded.json",
  "title": "collaborator.re_onboarded v1",
  "type": "object",
  "required": ["collaborator_id"],
  "properties": {
    "collaborator_id":         { "type": "string", "format": "uuid" },
    "primary_email":           { "type": "string" },
    "previous_offboarded_at":  { "type": "string", "format": "date-time" }
  },
  "additionalProperties": false
}
```

`docs/contracts/events/v1/team/created.json`:
```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://yggdrasil.io/contracts/events/v1/team/created.json",
  "title": "team.created v1",
  "type": "object",
  "required": ["id", "slug", "name"],
  "properties": {
    "id":              { "type": "string", "format": "uuid" },
    "slug":            { "type": "string" },
    "name":            { "type": "string" },
    "type":            { "type": "string" },
    "parent_team_id":  { "type": "string", "format": "uuid" }
  },
  "additionalProperties": false
}
```

`docs/contracts/events/v1/team/updated.json`:
```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://yggdrasil.io/contracts/events/v1/team/updated.json",
  "title": "team.updated v1",
  "type": "object",
  "required": ["id", "slug", "changed_fields"],
  "properties": {
    "id":              { "type": "string", "format": "uuid" },
    "slug":            { "type": "string" },
    "changed_fields":  { "type": "object" }
  },
  "additionalProperties": false
}
```

`docs/contracts/events/v1/team/deleted.json`:
```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://yggdrasil.io/contracts/events/v1/team/deleted.json",
  "title": "team.deleted v1",
  "type": "object",
  "required": ["id", "slug"],
  "properties": {
    "id":   { "type": "string", "format": "uuid" },
    "slug": { "type": "string" }
  },
  "additionalProperties": false
}
```

`docs/contracts/events/v1/team_membership/added.json`:
```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://yggdrasil.io/contracts/events/v1/team_membership/added.json",
  "title": "team_membership.added v1",
  "type": "object",
  "required": ["collaborator_id", "team_id"],
  "properties": {
    "collaborator_id": { "type": "string", "format": "uuid" },
    "team_id":         { "type": "string", "format": "uuid" },
    "role":            { "type": "string" },
    "source":          { "type": "string" }
  },
  "additionalProperties": false
}
```

`docs/contracts/events/v1/team_membership/removed.json`:
```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://yggdrasil.io/contracts/events/v1/team_membership/removed.json",
  "title": "team_membership.removed v1",
  "type": "object",
  "required": ["collaborator_id", "team_id"],
  "properties": {
    "collaborator_id": { "type": "string", "format": "uuid" },
    "team_id":         { "type": "string", "format": "uuid" }
  },
  "additionalProperties": false
}
```

- [ ] **Step 3: Wire schemas into validator registry**

Find the validator wiring:

```bash
grep -rn "eventTypeToSchemaPath\|ValidateEventPayload" docs/contracts/ | head -5
```

Append entries in the existing `eventTypeToSchemaPath` map (file from grep) for the 9 new types. Pattern follows existing entries.

- [ ] **Step 4: Build + commit**

```bash
go build ./...
git add docs/contracts/events/v1/ docs/contracts/events_validator.go
git commit -m "feat(events): add 9 canon lifecycle event schemas"
```

---

### Task 2.2: Reactor input schemas (11 files)

**Files:**
- Create: `docs/contracts/reactors/v1/<event>.json` for each of the 11 canon events.

Each reactor schema = the corresponding event schema + mandatory `_context` block.

- [ ] **Step 1: Write each schema**

Pattern (replace `<EVENT>`, `<EVENT_PROPS>`, `<REQUIRED_PROPS>` per event):

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://yggdrasil.io/contracts/reactors/v1/<EVENT>.json",
  "title": "<EVENT> reactor input v1",
  "type": "object",
  "required": ["_context", <REQUIRED_PROPS>],
  "properties": {
    "_context": {
      "type": "object",
      "required": ["event_id", "event_type", "schema_version", "emitted_at", "attempt"],
      "properties": {
        "event_id":       { "type": "string", "format": "uuid" },
        "event_type":     { "type": "string", "const": "<EVENT>" },
        "schema_version": { "type": "string", "const": "v1" },
        "emitted_at":     { "type": "string", "format": "date-time" },
        "actor": {
          "type": "object",
          "required": ["type", "id"],
          "properties": {
            "type": { "type": "string" },
            "id":   { "type": "string" }
          }
        },
        "attempt":        { "type": "integer", "minimum": 1 }
      }
    },
    <EVENT_PROPS>
  },
  "additionalProperties": false
}
```

Write 11 files: one per canon event type. Each merges the `_context` block with the event payload schema's properties.

Example for `collaborator.created`:

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://yggdrasil.io/contracts/reactors/v1/collaborator.created.json",
  "title": "collaborator.created reactor input v1",
  "type": "object",
  "required": ["_context", "id", "slug", "primary_email", "display_name"],
  "properties": {
    "_context": {
      "type": "object",
      "required": ["event_id", "event_type", "schema_version", "emitted_at", "attempt"],
      "properties": {
        "event_id":       { "type": "string", "format": "uuid" },
        "event_type":     { "type": "string", "const": "collaborator.created" },
        "schema_version": { "type": "string", "const": "v1" },
        "emitted_at":     { "type": "string", "format": "date-time" },
        "actor": { "type": "object" },
        "attempt":        { "type": "integer", "minimum": 1 }
      }
    },
    "id":              { "type": "string", "format": "uuid" },
    "slug":            { "type": "string" },
    "primary_email":   { "type": "string" },
    "display_name":    { "type": "string" },
    "role":            { "type": "string" },
    "primary_team_id": { "type": "string", "format": "uuid" },
    "employment_data": { "type": "object" }
  },
  "additionalProperties": false
}
```

Repeat the same pattern for the other 10 events.

- [ ] **Step 2: Commit**

```bash
git add docs/contracts/reactors/v1/
git commit -m "feat(reactors): add 11 reactor input schemas"
```

---

## Phase 3: Repository — MaterializeReactions + EmitEvent extension

### Task 3.1: Repository `integration_event_reactions.go`

**Files:**
- Create: `repository/integration_event_reactions.go`
- Test: `repository/integration_event_reactions_test.go`

- [ ] **Step 1: Failing test**

```go
// repository/integration_event_reactions_test.go
package repository

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"testing"

	"github.com/google/uuid"
	_ "github.com/lib/pq"
)

func dbForReactionsTest(t *testing.T) *sql.DB {
	t.Helper()
	dsn := os.Getenv("DB_URL")
	if dsn == "" {
		t.Skip("DB_URL not set; skipping reactions integration test")
	}
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	return db
}

func TestClaimPendingBatchAtomicity(t *testing.T) {
	db := dbForReactionsTest(t)
	defer db.Close()
	ctx := context.Background()

	// Seed: insert 5 pending rows manually (collaborator + integration_instance manifests
	// need to exist; for this unit test the helper creates fixtures).
	// ... (test helper, see comments in implementation)

	claimed, err := ClaimPendingBatch(ctx, db, 5)
	if err != nil {
		t.Fatalf("claim: %v", err)
	}
	if len(claimed) == 0 {
		t.Skip("no fixtures available")
	}

	// Re-claim must return zero — first claim marked them in_progress.
	again, err := ClaimPendingBatch(ctx, db, 5)
	if err != nil {
		t.Fatalf("re-claim: %v", err)
	}
	for _, r := range again {
		for _, c := range claimed {
			if r.ID == c.ID {
				t.Errorf("row %s claimed twice", r.ID)
			}
		}
	}
	_ = errors.New
	_ = uuid.New
}
```

- [ ] **Step 2: Run test (expect skip without DB)**

```bash
go test ./repository/... -run TestClaimPendingBatchAtomicity -v
```

- [ ] **Step 3: Implement repository**

```go
// repository/integration_event_reactions.go
package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

var ErrReactionNotFound = errors.New("integration event reaction not found")

// MaterializeReactions runs inside the same transaction as EmitEvent and
// inserts one integration_event_reactions row per matching (integration_instance,
// reactor declaration). Caller guarantees t is already inside a tx where the
// event_log row was just inserted with the same event_id.
//
// Lookups: only integration_instance manifests with active=true AND whose
// linked integration_type manifest declares a reactor matching eventType.
func MaterializeReactions(ctx context.Context, tx *sql.Tx, eventID uuid.UUID, eventType string) error {
	if !IsCanonLifecycleEvent(eventType) {
		// Non-canon events do not materialize reactions; this includes
		// reactor.dead_lettered which would otherwise loop forever.
		return nil
	}
	_, err := tx.ExecContext(ctx, `
		INSERT INTO integration_event_reactions
			(event_id, event_type, integration_instance_id, integration_type_manifest_id, capability, status, next_attempt_at)
		SELECT $1, $2, ii.id, it.id, r->>'capability', 'pending', NOW()
		FROM manifests ii
		JOIN manifests it ON it.id::text = (ii.spec->>'integration_type_manifest_id')
		JOIN LATERAL jsonb_array_elements(COALESCE(it.spec->'reactors', '[]'::jsonb)) r ON r->>'event_type' = $2
		WHERE ii.kind = 'integration_instance'
		  AND it.kind = 'integration_type'
		  AND ii.active = true
		  AND it.active = true
	`, eventID, eventType)
	if err != nil {
		return fmt.Errorf("materialize reactions: %w", err)
	}
	return nil
}

// ClaimPendingBatch atomically claims up to `limit` pending/failed rows
// whose next_attempt_at <= NOW(), marks them in_progress with attempt+1
// and started_at=NOW(). Uses FOR UPDATE SKIP LOCKED so multiple core pods
// claim disjoint sets.
//
// The Runner calls this every tick; the returned rows are processed
// in parallel by goroutines.
func ClaimPendingBatch(ctx context.Context, db *sql.DB, limit int) ([]model.IntegrationEventReaction, error) {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin: %w", err)
	}
	defer tx.Rollback()

	rows, err := tx.QueryContext(ctx, `
		SELECT id, event_id, event_type, integration_instance_id, integration_type_manifest_id, capability, attempt
		FROM integration_event_reactions
		WHERE status IN ('pending','failed') AND next_attempt_at <= NOW()
		ORDER BY next_attempt_at ASC
		LIMIT $1
		FOR UPDATE SKIP LOCKED
	`, limit)
	if err != nil {
		return nil, fmt.Errorf("select: %w", err)
	}

	type claim struct {
		ID                        uuid.UUID
		EventID                   uuid.UUID
		EventType                 string
		IntegrationInstanceID     uuid.UUID
		IntegrationTypeManifestID uuid.UUID
		Capability                string
		Attempt                   int
	}
	var claims []claim
	for rows.Next() {
		var c claim
		if err := rows.Scan(&c.ID, &c.EventID, &c.EventType, &c.IntegrationInstanceID, &c.IntegrationTypeManifestID, &c.Capability, &c.Attempt); err != nil {
			rows.Close()
			return nil, fmt.Errorf("scan: %w", err)
		}
		claims = append(claims, c)
	}
	rows.Close()
	if rows.Err() != nil {
		return nil, fmt.Errorf("iterate: %w", rows.Err())
	}

	now := time.Now()
	out := make([]model.IntegrationEventReaction, 0, len(claims))
	for _, c := range claims {
		newAttempt := c.Attempt + 1
		if _, err := tx.ExecContext(ctx, `
			UPDATE integration_event_reactions
			SET status='in_progress', attempt=$2, started_at=$3, last_error=NULL
			WHERE id=$1
		`, c.ID, newAttempt, now); err != nil {
			return nil, fmt.Errorf("update claim %s: %w", c.ID, err)
		}
		out = append(out, model.IntegrationEventReaction{
			ID:                        c.ID,
			EventID:                   c.EventID,
			EventType:                 c.EventType,
			IntegrationInstanceID:     c.IntegrationInstanceID,
			IntegrationTypeManifestID: c.IntegrationTypeManifestID,
			Capability:                c.Capability,
			Status:                    model.ReactionStatusInProgress,
			Attempt:                   newAttempt,
			StartedAt:                 &now,
		})
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit: %w", err)
	}
	return out, nil
}

// MarkSucceeded transitions a row in_progress → succeeded.
func MarkSucceeded(ctx context.Context, db *sql.DB, reactionID uuid.UUID) error {
	_, err := db.ExecContext(ctx, `
		UPDATE integration_event_reactions
		SET status='succeeded', finished_at=NOW(), last_error=NULL
		WHERE id=$1
	`, reactionID)
	if err != nil {
		return fmt.Errorf("mark succeeded %s: %w", reactionID, err)
	}
	return nil
}

// MarkFailed transitions in_progress → failed and schedules next_attempt_at.
// Caller passes the backoff duration (from BackoffFor).
func MarkFailed(ctx context.Context, db *sql.DB, reactionID uuid.UUID, errMsg string, backoff time.Duration) error {
	if len(errMsg) > 4096 {
		errMsg = errMsg[:4096]
	}
	_, err := db.ExecContext(ctx, `
		UPDATE integration_event_reactions
		SET status='failed', next_attempt_at=NOW()+$3::interval, last_error=$2
		WHERE id=$1
	`, reactionID, errMsg, backoff.String())
	if err != nil {
		return fmt.Errorf("mark failed %s: %w", reactionID, err)
	}
	return nil
}

// MarkDeadLettered transitions in_progress → dead_lettered (terminal).
func MarkDeadLettered(ctx context.Context, db *sql.DB, reactionID uuid.UUID, errMsg string) error {
	if len(errMsg) > 4096 {
		errMsg = errMsg[:4096]
	}
	_, err := db.ExecContext(ctx, `
		UPDATE integration_event_reactions
		SET status='dead_lettered', finished_at=NOW(), last_error=$2
		WHERE id=$1
	`, reactionID, errMsg)
	if err != nil {
		return fmt.Errorf("mark dead_lettered %s: %w", reactionID, err)
	}
	return nil
}

// HealStuckInProgress marks rows stuck in 'in_progress' for longer than
// threshold as 'failed' with next_attempt_at=NOW() so the Runner re-claims them.
// Called periodically (e.g., once per tick) — fixes pods that crashed mid-dispatch.
func HealStuckInProgress(ctx context.Context, db *sql.DB, threshold time.Duration) (int64, error) {
	res, err := db.ExecContext(ctx, `
		UPDATE integration_event_reactions
		SET status='failed', next_attempt_at=NOW(), last_error='healed from stuck in_progress'
		WHERE status='in_progress' AND started_at < NOW() - $1::interval
	`, threshold.String())
	if err != nil {
		return 0, fmt.Errorf("heal stuck: %w", err)
	}
	n, _ := res.RowsAffected()
	return n, nil
}

// fetchEventPayload returns the event_log.payload as raw JSON for use by the
// Runner when building the reactor payload.
func fetchEventPayload(ctx context.Context, db *sql.DB, eventID uuid.UUID) ([]byte, time.Time, *model.EventActor, error) {
	var raw []byte
	var emittedAt time.Time
	var actorType, actorID sql.NullString
	row := db.QueryRowContext(ctx, `
		SELECT payload, emitted_at, actor_type, actor_id
		FROM event_log
		WHERE event_id=$1
	`, eventID)
	if err := row.Scan(&raw, &emittedAt, &actorType, &actorID); err != nil {
		return nil, time.Time{}, nil, fmt.Errorf("fetch event %s: %w", eventID, err)
	}
	var actor *model.EventActor
	if actorType.Valid && actorID.Valid {
		actor = &model.EventActor{Type: actorType.String, ID: actorID.String}
	}
	return raw, emittedAt, actor, nil
}

// jsonMarshal is a thin alias used by Runner — defined here to keep error
// handling consistent with other repository operations.
func jsonMarshal(v any) ([]byte, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("marshal: %w", err)
	}
	return b, nil
}
```

- [ ] **Step 4: Run tests (DB-skipped)**

```bash
DB_URL="" go test ./repository/... -run TestClaimPendingBatchAtomicity -v
go build ./...
```

- [ ] **Step 5: Commit**

```bash
git add repository/integration_event_reactions.go repository/integration_event_reactions_test.go
git commit -m "feat(repository): MaterializeReactions + ClaimPendingBatch + status transitions"
```

---

### Task 3.2: Extend `EmitEvent` to invoke MaterializeReactions

**Files:**
- Modify: `repository/event.go`

- [ ] **Step 1: Locate `EmitEvent`**

```bash
grep -n "func EmitEvent" repository/event.go
```

- [ ] **Step 2: Insert MaterializeReactions call after successful INSERT into event_log**

Append before the `return eventID, nil`:

```go
// Materialize reactions for canon lifecycle events. This runs in the SAME
// transaction so reactions and the event commit (or rollback) atomically.
// Non-canon events (e.g., reactor.dead_lettered, manifest.created) are a no-op.
if err := MaterializeReactions(ctx, tx, eventID, req.Type); err != nil {
	return uuid.Nil, fmt.Errorf("materialize reactions: %w", err)
}
```

- [ ] **Step 3: Verify build**

```bash
go build ./...
```

- [ ] **Step 4: Commit**

```bash
git add repository/event.go
git commit -m "feat(reactors): EmitEvent materializes reactions in the same tx"
```

---

## Phase 4: Manifest validation

### Task 4.1: Reactor validation hook

**Files:**
- Create: `manifest/integration_type_reactors_validate.go`
- Test: `manifest/integration_type_reactors_validate_test.go`

- [ ] **Step 1: Failing tests**

```go
// manifest/integration_type_reactors_validate_test.go
package manifest

import (
	"encoding/json"
	"errors"
	"testing"
)

func TestValidateReactors(t *testing.T) {
	cases := []struct {
		name string
		spec string
		want error
	}{
		{
			name: "no reactors block — ok",
			spec: `{"action_catalog":[]}`,
			want: nil,
		},
		{
			name: "valid reactor",
			spec: `{"action_catalog":[{"name":"on_collaborator_created"}],
			        "reactors":[{"event_type":"collaborator.created","capability":"on_collaborator_created"}]}`,
			want: nil,
		},
		{
			name: "event_type out of canon",
			spec: `{"action_catalog":[{"name":"on_foo"}],
			        "reactors":[{"event_type":"foo.bar","capability":"on_foo"}]}`,
			want: ErrReactorEventTypeNotCanon,
		},
		{
			name: "capability missing from action_catalog",
			spec: `{"action_catalog":[{"name":"x"}],
			        "reactors":[{"event_type":"collaborator.created","capability":"on_collaborator_created"}]}`,
			want: ErrReactorCapabilityNotInCatalog,
		},
		{
			name: "duplicate event_type",
			spec: `{"action_catalog":[{"name":"a"},{"name":"b"}],
			        "reactors":[
			          {"event_type":"team.created","capability":"a"},
			          {"event_type":"team.created","capability":"b"}
			        ]}`,
			want: ErrReactorDuplicateEventType,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var spec map[string]any
			if err := json.Unmarshal([]byte(tc.spec), &spec); err != nil {
				t.Fatalf("setup: %v", err)
			}
			err := ValidateReactors(spec)
			if !errors.Is(err, tc.want) {
				t.Fatalf("got %v want %v", err, tc.want)
			}
		})
	}
}
```

- [ ] **Step 2: Run test (expect fail)**

```bash
go test ./manifest/... -run TestValidateReactors -v
```

- [ ] **Step 3: Implement**

```go
// manifest/integration_type_reactors_validate.go
package manifest

import (
	"errors"
	"fmt"

	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
)

var (
	ErrReactorEventTypeNotCanon       = errors.New("reactor event_type is not in canon catalog")
	ErrReactorCapabilityNotInCatalog  = errors.New("reactor capability not in action_catalog")
	ErrReactorDuplicateEventType      = errors.New("duplicate reactor event_type in same integration_type")
)

// ValidateReactors enforces the constraints from the lifecycle reactor spec:
//   1. reactors[].event_type ∈ canon catalog
//   2. reactors[].capability ∈ spec.action_catalog[].name
//   3. (integration_type, event_type) is unique
//
// Caller passes the integration_type.spec as map[string]any (unmarshalled).
// Returns nil if the spec has no reactors block (optional field).
func ValidateReactors(spec map[string]any) error {
	rawReactors, ok := spec["reactors"]
	if !ok || rawReactors == nil {
		return nil
	}
	reactors, ok := rawReactors.([]any)
	if !ok {
		return fmt.Errorf("reactors must be an array")
	}

	// Build set of capability names from action_catalog
	catalogNames := map[string]struct{}{}
	if cat, ok := spec["action_catalog"].([]any); ok {
		for _, e := range cat {
			if m, ok := e.(map[string]any); ok {
				if n, ok := m["name"].(string); ok && n != "" {
					catalogNames[n] = struct{}{}
				}
			}
		}
	}

	seen := map[string]struct{}{}
	for i, r := range reactors {
		m, ok := r.(map[string]any)
		if !ok {
			return fmt.Errorf("reactors[%d] is not an object", i)
		}
		eventType, _ := m["event_type"].(string)
		capability, _ := m["capability"].(string)

		if !repository.IsCanonLifecycleEvent(eventType) {
			return fmt.Errorf("%w: %q (must be one of %v)", ErrReactorEventTypeNotCanon, eventType, canonList())
		}
		if _, ok := catalogNames[capability]; !ok {
			return fmt.Errorf("%w: %q (capabilities available: %v)", ErrReactorCapabilityNotInCatalog, capability, sortedKeys(catalogNames))
		}
		if _, dup := seen[eventType]; dup {
			return fmt.Errorf("%w: %q", ErrReactorDuplicateEventType, eventType)
		}
		seen[eventType] = struct{}{}
	}

	return nil
}

func canonList() []string {
	keys := make([]string, 0, len(repository.CanonLifecycleEventTypes))
	for k := range repository.CanonLifecycleEventTypes {
		keys = append(keys, k)
	}
	return keys
}

func sortedKeys(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
```

- [ ] **Step 4: Run tests (expect pass)**

```bash
go test ./manifest/... -run TestValidateReactors -v
```

Expected: 5 PASS.

- [ ] **Step 5: Commit**

```bash
git add manifest/integration_type_reactors_validate.go manifest/integration_type_reactors_validate_test.go
git commit -m "feat(manifest): validate reactor declarations against canon + action_catalog"
```

---

### Task 4.2: Plug validation hook into integration_type apply

**Files:**
- Modify: `manifest/integration_type_validate.go` (or wherever integration_type manifests are validated — find via grep)

- [ ] **Step 1: Locate the validator**

```bash
grep -rn "integration_type.*validate\|ValidateIntegrationType\|validateIntegrationTypeSpec" manifest/ controllers/ | head -5
```

- [ ] **Step 2: Insert ValidateReactors call**

Inside the existing integration_type spec validator function, before final `return nil`:

```go
if err := ValidateReactors(spec); err != nil {
    return fmt.Errorf("integration_type spec: %w", err)
}
```

- [ ] **Step 3: Verify build + run all manifest tests**

```bash
go build ./...
go test ./manifest/... -v
```

- [ ] **Step 4: Commit**

```bash
git add manifest/integration_type_validate.go
git commit -m "feat(manifest): plug reactor validation into integration_type apply"
```

---

## Phase 5: Dispatcher (Runner)

### Task 5.1: Reactor payload builder

**Files:**
- Create: `internal/reactors/payload.go`
- Test: `internal/reactors/payload_test.go`

- [ ] **Step 1: Failing test**

```go
// internal/reactors/payload_test.go
package reactors

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

func TestBuildReactorPayload(t *testing.T) {
	eventPayload := json.RawMessage(`{"id":"abc","slug":"alice","primary_email":"alice@x.io"}`)
	eventID := uuid.MustParse("12345678-1234-1234-1234-123456789abc")
	emittedAt := time.Date(2026, 5, 15, 10, 0, 0, 0, time.UTC)
	actor := &model.EventActor{Type: "collaborator", ID: "actor-uuid"}

	out, err := BuildReactorPayload(eventID, "collaborator.created", "v1", eventPayload, emittedAt, actor, 1)
	if err != nil {
		t.Fatalf("build: %v", err)
	}

	var got map[string]any
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got["id"] != "abc" {
		t.Errorf("event field missing: %+v", got)
	}
	ctx, ok := got["_context"].(map[string]any)
	if !ok {
		t.Fatalf("_context missing or wrong type")
	}
	if ctx["event_type"] != "collaborator.created" {
		t.Errorf("_context.event_type wrong: %v", ctx["event_type"])
	}
	if int(ctx["attempt"].(float64)) != 1 {
		t.Errorf("_context.attempt wrong: %v", ctx["attempt"])
	}
}
```

- [ ] **Step 2: Run (expect fail)**

```bash
go test ./internal/reactors/... -run TestBuildReactorPayload -v
```

- [ ] **Step 3: Implement**

```go
// internal/reactors/payload.go
package reactors

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

// BuildReactorPayload merges the event payload with a `_context` block and
// returns the full JSON sent over RabbitMQ to the integration adapter.
//
// The event payload is the canonical payload (as stored in event_log.payload).
// The `_context` block carries metadata the integration uses for idempotency
// (event_id, attempt) and audit (actor, emitted_at).
//
// If the event payload already has a `_context` key it is overwritten — the
// `_` prefix is reserved for the core.
func BuildReactorPayload(
	eventID uuid.UUID,
	eventType string,
	schemaVersion string,
	eventPayload json.RawMessage,
	emittedAt time.Time,
	actor *model.EventActor,
	attempt int,
) ([]byte, error) {
	var merged map[string]any
	if len(eventPayload) > 0 {
		if err := json.Unmarshal(eventPayload, &merged); err != nil {
			return nil, fmt.Errorf("unmarshal event payload: %w", err)
		}
	}
	if merged == nil {
		merged = map[string]any{}
	}
	ctx := map[string]any{
		"event_id":       eventID.String(),
		"event_type":     eventType,
		"schema_version": schemaVersion,
		"emitted_at":     emittedAt.UTC().Format(time.RFC3339),
		"attempt":        attempt,
	}
	if actor != nil {
		ctx["actor"] = map[string]any{"type": actor.Type, "id": actor.ID}
	}
	merged["_context"] = ctx

	out, err := json.Marshal(merged)
	if err != nil {
		return nil, fmt.Errorf("marshal reactor payload: %w", err)
	}
	return out, nil
}
```

- [ ] **Step 4: Test + commit**

```bash
go test ./internal/reactors/... -run TestBuildReactorPayload -v
git add internal/reactors/payload.go internal/reactors/payload_test.go
git commit -m "feat(reactors): payload builder with _context block"
```

---

### Task 5.2: Runner (Dispatcher)

**Files:**
- Create: `internal/reactors/dispatcher.go`
- Test: `internal/reactors/dispatcher_test.go`

- [ ] **Step 1: Failing test (mocked RabbitMQ)**

```go
// internal/reactors/dispatcher_test.go
package reactors

import (
	"context"
	"errors"
	"testing"
	"time"
)

type mockCaller struct {
	called int
	fail   bool
}

func (m *mockCaller) Call(ctx context.Context, instanceID, capability string, payload []byte) error {
	m.called++
	if m.fail {
		return errors.New("simulated failure")
	}
	return nil
}

func TestRunnerSingleTick_NoRows(t *testing.T) {
	r := &Runner{
		DB:       nil, // No DB needed; mockClaimer below provides empty batch
		Interval: time.Second,
		Caller:   &mockCaller{},
	}
	r.claimBatch = func(ctx context.Context, limit int) ([]ClaimedReaction, error) {
		return nil, nil
	}
	if err := r.tickOnce(context.Background()); err != nil {
		t.Fatalf("tickOnce: %v", err)
	}
}
```

- [ ] **Step 2: Implement Runner**

```go
// internal/reactors/dispatcher.go
package reactors

import (
	"context"
	"database/sql"
	"fmt"
	"sync"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

// Caller abstracts the RabbitMQ RPC to an integration adapter capability.
// Production wires this to messagecontroller's existing RunIntegrationOperation
// helper; tests pass a mock.
type Caller interface {
	Call(ctx context.Context, integrationInstanceID string, capability string, payload []byte) error
}

// ClaimedReaction is a thin row carried from ClaimPendingBatch to the worker.
type ClaimedReaction struct {
	ID                    uuid.UUID
	EventID               uuid.UUID
	EventType             string
	IntegrationInstanceID uuid.UUID
	Capability            string
	Attempt               int
}

// Runner is the background worker that drives the reactor dispatch loop.
type Runner struct {
	DB             *sql.DB
	Logger         *zap.Logger
	Caller         Caller
	Interval       time.Duration
	BatchSize      int
	Parallelism    int
	StuckThreshold time.Duration

	// claimBatch is overridable in tests. Production assigns the repository call.
	claimBatch func(ctx context.Context, limit int) ([]ClaimedReaction, error)
}

// Run loops until ctx is cancelled.
func (r *Runner) Run(ctx context.Context) error {
	r.defaults()
	if r.claimBatch == nil {
		r.claimBatch = r.realClaim
	}
	t := time.NewTicker(r.Interval)
	defer t.Stop()
	for {
		if err := r.tickOnce(ctx); err != nil && r.Logger != nil {
			r.Logger.Error("reactor runner tick failed", zap.Error(err))
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
		}
	}
}

func (r *Runner) defaults() {
	if r.Interval == 0 {
		r.Interval = 5 * time.Second
	}
	if r.BatchSize == 0 {
		r.BatchSize = 50
	}
	if r.Parallelism == 0 {
		r.Parallelism = 10
	}
	if r.StuckThreshold == 0 {
		r.StuckThreshold = 10 * time.Minute
	}
}

func (r *Runner) tickOnce(ctx context.Context) error {
	// Heal first — drag stuck rows back into the pending stream
	if r.DB != nil {
		if _, err := repository.HealStuckInProgress(ctx, r.DB, r.StuckThreshold); err != nil && r.Logger != nil {
			r.Logger.Warn("heal stuck failed", zap.Error(err))
		}
	}

	batch, err := r.claimBatch(ctx, r.BatchSize)
	if err != nil {
		return fmt.Errorf("claim batch: %w", err)
	}
	if len(batch) == 0 {
		return nil
	}

	sem := make(chan struct{}, r.Parallelism)
	var wg sync.WaitGroup
	for _, c := range batch {
		c := c
		sem <- struct{}{}
		wg.Add(1)
		go func() {
			defer func() {
				<-sem
				wg.Done()
			}()
			r.dispatchOne(ctx, c)
		}()
	}
	wg.Wait()
	return nil
}

func (r *Runner) realClaim(ctx context.Context, limit int) ([]ClaimedReaction, error) {
	rows, err := repository.ClaimPendingBatch(ctx, r.DB, limit)
	if err != nil {
		return nil, err
	}
	out := make([]ClaimedReaction, 0, len(rows))
	for _, x := range rows {
		out = append(out, ClaimedReaction{
			ID:                    x.ID,
			EventID:               x.EventID,
			EventType:             x.EventType,
			IntegrationInstanceID: x.IntegrationInstanceID,
			Capability:            x.Capability,
			Attempt:               x.Attempt,
		})
	}
	return out, nil
}

func (r *Runner) dispatchOne(ctx context.Context, c ClaimedReaction) {
	// Build payload from event_log
	rawPayload, emittedAt, actor, err := repository.FetchEventForReactor(ctx, r.DB, c.EventID)
	if err != nil {
		_ = repository.MarkFailed(ctx, r.DB, c.ID, fmt.Sprintf("fetch event: %v", err), backoffForRunner(c.Attempt, r))
		return
	}
	payload, err := BuildReactorPayload(c.EventID, c.EventType, "v1", rawPayload, emittedAt, actor, c.Attempt)
	if err != nil {
		_ = repository.MarkFailed(ctx, r.DB, c.ID, fmt.Sprintf("build payload: %v", err), backoffForRunner(c.Attempt, r))
		return
	}

	if r.Logger != nil {
		r.Logger.Info("reactor dispatched",
			zap.String("reaction_id", c.ID.String()),
			zap.String("event_id", c.EventID.String()),
			zap.String("event_type", c.EventType),
			zap.String("capability", c.Capability),
			zap.Int("attempt", c.Attempt),
		)
	}

	err = r.Caller.Call(ctx, c.IntegrationInstanceID.String(), c.Capability, payload)
	if err == nil {
		_ = repository.MarkSucceeded(ctx, r.DB, c.ID)
		return
	}

	// Failed — decide retry vs dead-letter
	wait, deadLetter := BackoffFor(c.Attempt)
	if deadLetter {
		_ = repository.MarkDeadLettered(ctx, r.DB, c.ID, err.Error())
		// Emit reactor.dead_lettered event (best-effort; outside reactor pipeline)
		r.emitDeadLetterEvent(ctx, c, err)
		return
	}
	_ = repository.MarkFailed(ctx, r.DB, c.ID, err.Error(), wait)
}

func backoffForRunner(attempt int, _ *Runner) time.Duration {
	d, _ := BackoffFor(attempt)
	return d
}

func (r *Runner) emitDeadLetterEvent(ctx context.Context, c ClaimedReaction, finalErr error) {
	tx, err := r.DB.BeginTx(ctx, nil)
	if err != nil {
		if r.Logger != nil {
			r.Logger.Warn("emit dead_lettered begin tx", zap.Error(err))
		}
		return
	}
	defer tx.Rollback()
	_, err = repository.EmitEvent(ctx, tx, model.EmitEventRequest{
		Type:          repository.EventTypeReactorDeadLettered,
		SchemaVersion: "v1",
		AggregateType: "reactor",
		AggregateID:   c.ID.String(),
		Payload: map[string]any{
			"reaction_id":              c.ID.String(),
			"event_id":                 c.EventID.String(),
			"event_type":               c.EventType,
			"integration_instance_id":  c.IntegrationInstanceID.String(),
			"capability":               c.Capability,
			"final_error":              finalErr.Error(),
			"attempts":                 c.Attempt,
		},
	})
	if err != nil {
		if r.Logger != nil {
			r.Logger.Warn("emit dead_lettered", zap.Error(err))
		}
		return
	}
	_ = tx.Commit()
}
```

Note: `repository.FetchEventForReactor` is a small helper, add it to `repository/integration_event_reactions.go`:

```go
// FetchEventForReactor is the exported variant used by the Runner.
func FetchEventForReactor(ctx context.Context, db *sql.DB, eventID uuid.UUID) (json.RawMessage, time.Time, *model.EventActor, error) {
	raw, emittedAt, actor, err := fetchEventPayload(ctx, db, eventID)
	return raw, emittedAt, actor, err
}
```

- [ ] **Step 3: Run tests**

```bash
go test ./internal/reactors/... -v
go build ./...
```

- [ ] **Step 4: Commit**

```bash
git add internal/reactors/dispatcher.go internal/reactors/dispatcher_test.go repository/integration_event_reactions.go
git commit -m "feat(reactors): Runner with claim batch + retry + dead-letter"
```

---

### Task 5.3: Bootstrap addon

**Files:**
- Create: `addons/reactor_dispatcher.go`

- [ ] **Step 1: Locate addon pattern**

```bash
ls addons/ | head -10
head -30 addons/password_rotation.go  # reference pattern from prior PR
```

- [ ] **Step 2: Implement addon**

```go
// addons/reactor_dispatcher.go
package addons

import (
	"context"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/reactors"
	"github.com/dakasa-yggdrasil/yggdrasil-core/messagecontroller"
)

func init() {
	Register(Addon{
		Name:     "reactor-dispatcher",
		Priority: 70,
		Bootstrap: bootstrapReactorDispatcher,
	})
}

func bootstrapReactorDispatcher(ctx context.Context, app *App) error {
	db := Postgres(app)
	if db == nil {
		// Postgres addon not enabled — nothing to do.
		return nil
	}
	logger := Logger(app)
	caller := newRabbitMQReactorCaller(app) // returns reactors.Caller bound to RabbitMQ transport

	runner := &reactors.Runner{
		DB:             db,
		Logger:         logger,
		Caller:         caller,
		Interval:       envDurationOrDefault("REACTOR_RUNNER_INTERVAL", 5*time.Second),
		BatchSize:      envIntOrDefault("REACTOR_RUNNER_BATCH_SIZE", 50),
		Parallelism:    envIntOrDefault("REACTOR_RUNNER_PARALLELISM", 10),
		StuckThreshold: envDurationOrDefault("REACTOR_STUCK_THRESHOLD", 10*time.Minute),
	}

	go func() {
		if err := runner.Run(ctx); err != nil && ctx.Err() == nil {
			logger.Error("reactor runner exited", logField("err", err))
		}
	}()
	return nil
}

// newRabbitMQReactorCaller wraps the existing messagecontroller.RunIntegrationOperation
// (or equivalent) so the Runner can call integration capabilities over RabbitMQ.
// Adjust the function name to whichever helper your codebase already exposes
// — the integration_execute queue contract is identical.
func newRabbitMQReactorCaller(app *App) reactors.Caller {
	return &rabbitCaller{rabbitmq: RabbitMQ(app)}
}

type rabbitCaller struct {
	rabbitmq messagecontroller.Transport // pseudo-type — adjust to real type
}

func (c *rabbitCaller) Call(ctx context.Context, instanceID, capability string, payload []byte) error {
	// Reuse the existing RPC contract. Pseudo-code; replace with the canonical
	// helper signature in your codebase. See messagecontroller/integrations.go.
	return messagecontroller.CallIntegrationCapability(ctx, c.rabbitmq, instanceID, capability, payload, envDurationOrDefault("REACTOR_RPC_TIMEOUT", 30*time.Second))
}

func envDurationOrDefault(key string, def time.Duration) time.Duration {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return def
	}
	d, err := time.ParseDuration(v)
	if err != nil || d <= 0 {
		return def
	}
	return d
}

func envIntOrDefault(key string, def int) int {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil || n <= 0 {
		return def
	}
	return n
}
```

> **Important — adapt to actual codebase**: `messagecontroller.CallIntegrationCapability` is pseudo-named. In real code, find the canonical helper that workflows use to invoke an integration capability via RabbitMQ. Look at `controllers/message/integrations.go:281` for the existing pattern (`transport.Call(rpcCtx, integrationExecuteContract, ...)`) and wrap it.

- [ ] **Step 3: Verify build**

```bash
go build ./...
```

- [ ] **Step 4: Commit**

```bash
git add addons/reactor_dispatcher.go
git commit -m "feat(reactors): bootstrap addon priority 70 starts Runner"
```

---

## Phase 6: Core handlers — emit canon events + fix gaps

### Task 6.1: Fix `CreateCollaborator` — also create `auth_identities`

**Files:**
- Modify: `repository/collaborator.go` (or wherever `CreateCollaborator` lives — find via grep)

- [ ] **Step 1: Locate**

```bash
grep -rn "func CreateCollaborator\b" repository/ | head -3
```

- [ ] **Step 2: Wrap existing INSERT in a transaction that also creates auth_identities**

In the function body, replace the existing single INSERT with:

```go
tx, err := db.BeginTx(ctx, nil)
if err != nil {
	return model.Collaborator{}, fmt.Errorf("begin: %w", err)
}
defer tx.Rollback()

// existing INSERT INTO collaborators ... RETURNING ...
// (call existing code but on tx instead of db)
collab, err := insertCollaboratorInto(ctx, tx, req)  // refactor existing code into helper
if err != nil {
	return model.Collaborator{}, err
}

// NEW: create auth_identities row in the same tx.
// Username defaults to lower(primary_email); if email is empty, use slug.
username := strings.ToLower(strings.TrimSpace(collab.PrimaryEmail))
if username == "" {
	username = collab.Slug
}
if _, err := tx.ExecContext(ctx, `
	INSERT INTO auth_identities (collaborator_id, username) VALUES ($1, $2)
	ON CONFLICT (collaborator_id) DO NOTHING
`, collab.ID, username); err != nil {
	return model.Collaborator{}, fmt.Errorf("create auth_identity: %w", err)
}

if err := tx.Commit(); err != nil {
	return model.Collaborator{}, fmt.Errorf("commit: %w", err)
}
return collab, nil
```

- [ ] **Step 3: Build + run existing collaborator tests**

```bash
go build ./...
DB_URL="" go test ./repository/... -short -run "TestCreateCollaborator" -v
```

- [ ] **Step 4: Commit**

```bash
git add repository/collaborator.go
git commit -m "fix(repository): CreateCollaborator also inserts auth_identities row"
```

---

### Task 6.2: Emit `collaborator.absence_started`

**Files:**
- Modify: `controllers/httpapi/collaborator_lifecycle.go` (handleCollaboratorAbsenceStart, if exists; if not, the verb handler) OR `repository/collaborator_lifecycle.go`

- [ ] **Step 1: Locate handler**

```bash
grep -rn "absence_started\|handleCollaboratorAbsenceStart\|/absence/start" controllers/httpapi/ repository/ | head -5
```

- [ ] **Step 2: Audit emit vs no-emit**

Read the handler. If it already emits `collaborator.absence_started`: skip. If it emits a different event name OR no event: rewrite to emit `repository.EventTypeCollaboratorAbsenceStarted` in the same transaction as the status update.

- [ ] **Step 3: Add emit in the same tx**

Inside the transaction that updates the collaborator status:

```go
_, err = repository.EmitEvent(ctx, tx, model.EmitEventRequest{
	Type:          repository.EventTypeCollaboratorAbsenceStarted,
	SchemaVersion: "v1",
	AggregateType: "collaborator",
	AggregateID:   collab.ID.String(),
	Actor:         actorFromRequest(r),  // or however actor is currently captured
	Payload: map[string]any{
		"collaborator_id":  collab.ID.String(),
		"primary_email":    collab.PrimaryEmail,
		"type":             req.Type,
		"from":             req.From,
		"to":               req.To,
		"duration_days":    req.DurationDays,
	},
})
if err != nil {
	return fmt.Errorf("emit event: %w", err)
}
```

- [ ] **Step 4: Verify build**

```bash
go build ./...
```

- [ ] **Step 5: Commit**

```bash
git add controllers/httpapi/collaborator_lifecycle.go repository/collaborator_lifecycle.go
git commit -m "feat(events): emit collaborator.absence_started in same tx"
```

---

### Task 6.3: Emit `collaborator.absence_ended`, `role_changed`, `re_onboarded`

Repeat the pattern of Task 6.2 for the three remaining collaborator lifecycle handlers.

**Files:** same `collaborator_lifecycle.go` files.

- [ ] **Step 1: For each (absence_ended, role_changed, re_onboarded), locate handler + audit + add emit in same tx**

Use the same emit pattern. Payloads:

| Event | Payload fields |
|---|---|
| `collaborator.absence_ended` | `collaborator_id`, `primary_email` |
| `collaborator.role_changed` | `collaborator_id`, `primary_email`, `role_from`, `role_to` |
| `collaborator.re_onboarded` | `collaborator_id`, `primary_email`, `previous_offboarded_at` |

- [ ] **Step 2: Build + commit**

```bash
go build ./...
git add controllers/httpapi/collaborator_lifecycle.go repository/collaborator_lifecycle.go
git commit -m "feat(events): emit absence_ended + role_changed + re_onboarded"
```

---

### Task 6.4: Emit `team.created`, `team.updated`, `team.deleted`

**Files:**
- Modify: `repository/team.go` (or equivalent — find via grep)
- Modify: `controllers/httpapi/teams*.go` if events are emitted at the handler layer

- [ ] **Step 1: Locate team handlers**

```bash
grep -rn "func CreateTeam\|func UpdateTeam\|func DeleteTeam\|POST.*teams\|PATCH.*teams\|DELETE.*teams" repository/ controllers/httpapi/ | head -10
```

- [ ] **Step 2: For each handler, wrap state mutation + emit in same tx**

Pattern (for `team.created`):

```go
tx, err := db.BeginTx(ctx, nil)
if err != nil { ... }
defer tx.Rollback()

team, err := insertTeamInto(ctx, tx, req)
if err != nil { ... }

_, err = repository.EmitEvent(ctx, tx, model.EmitEventRequest{
	Type:          repository.EventTypeTeamCreated,
	SchemaVersion: "v1",
	AggregateType: "team",
	AggregateID:   team.ID.String(),
	Payload: map[string]any{
		"id":             team.ID.String(),
		"slug":           team.Slug,
		"name":           team.Name,
		"type":           team.Type,
		"parent_team_id": team.ParentTeamID,
	},
})
if err != nil { ... }

return tx.Commit()
```

For `team.updated`: capture `changed_fields` as `map[string]any` containing only the fields the PATCH request modified (compare request body vs. previous state).

For `team.deleted`: emit before the DELETE (cascade has not run yet, so slug is still available).

- [ ] **Step 3: Build + commit**

```bash
go build ./...
git add repository/team.go controllers/httpapi/teams*.go
git commit -m "feat(events): emit team.created/updated/deleted in same tx"
```

---

### Task 6.5: Emit `team_membership.added`, `team_membership.removed`

**Files:**
- Modify: `repository/team_memberships.go` (or equivalent)

- [ ] **Step 1: Locate handlers**

```bash
grep -rn "team_membership\|TeamMembership.*Upsert\|TeamMembership.*Delete" repository/ controllers/httpapi/ | head -10
```

- [ ] **Step 2: Wrap state mutation + emit in same tx**

For `added` (emit only on INSERT, not on UPDATE-by-conflict — pass a flag back from UPSERT if existing):

```go
_, err = repository.EmitEvent(ctx, tx, model.EmitEventRequest{
	Type:          repository.EventTypeTeamMembershipAdded,
	SchemaVersion: "v1",
	AggregateType: "team_membership",
	AggregateID:   membership.ID.String(),
	Payload: map[string]any{
		"collaborator_id": membership.CollaboratorID.String(),
		"team_id":         membership.TeamID.String(),
		"role":            membership.Role,
		"source":          membership.Source,
	},
})
```

For `removed`: emit before the DELETE so collaborator_id and team_id are still readable.

- [ ] **Step 3: Build + commit**

```bash
go build ./...
git add repository/team_memberships.go
git commit -m "feat(events): emit team_membership.added/removed in same tx"
```

---

## Phase 7: UI auto-setup-token + re-issue

### Task 7.1: `SetupURLModal.tsx` reusable component

**Files:**
- Create: `src/pages/collaborators/SetupURLModal.tsx`
- Create: `src/pages/collaborators/SetupURLModal.css`

Note: this work happens in **surface-console** repo, not `yggdrasil-core`.

- [ ] **Step 1: Create modal component**

```tsx
// src/pages/collaborators/SetupURLModal.tsx
import { useState } from "react";

interface Props {
  open: boolean;
  url: string | null;
  expiresAt: string | null;
  collaboratorName: string;
  error?: string | null;
  collaboratorID?: string;
  onClose: () => void;
  onGoToDetail?: () => void;
}

export function SetupURLModal({ open, url, expiresAt, collaboratorName, error, onClose, onGoToDetail }: Props) {
  const [copied, setCopied] = useState(false);
  if (!open) return null;

  async function copy() {
    if (!url) return;
    await navigator.clipboard.writeText(absolutize(url));
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  }

  return (
    <div className="setup-modal-backdrop" onClick={onClose}>
      <div className="setup-modal" onClick={(e) => e.stopPropagation()}>
        <header className="setup-modal__head">
          <h2>Link de primeiro acesso para {collaboratorName}</h2>
        </header>
        {error ? (
          <div className="setup-modal__error">
            <p>A pessoa foi criada com sucesso, mas não consegui gerar o link automaticamente:</p>
            <pre>{error}</pre>
            {onGoToDetail && (
              <button className="casa-btn casa-btn--primary" onClick={onGoToDetail}>
                Ir para a página da pessoa
              </button>
            )}
          </div>
        ) : (
          <>
            <p className="casa-prose">Esse link aparece UMA ÚNICA VEZ. Se perder, gere outro na página da pessoa.</p>
            <pre className="setup-modal__url">{absolutize(url || "")}</pre>
            <p className="casa-prose">Válido até: {expiresAt ? formatDate(expiresAt) : "—"}</p>
            <footer className="setup-modal__actions">
              <button className="casa-btn casa-btn--primary" onClick={copy}>
                {copied ? "Copiado ✓" : "Copiar link"}
              </button>
              <button className="casa-btn" onClick={onClose}>Fechar</button>
            </footer>
          </>
        )}
      </div>
    </div>
  );
}

function absolutize(url: string): string {
  if (url.startsWith("http://") || url.startsWith("https://")) return url;
  return window.location.origin + url;
}

function formatDate(iso: string): string {
  const d = new Date(iso);
  return d.toLocaleString("pt-BR");
}
```

```css
/* src/pages/collaborators/SetupURLModal.css */
.setup-modal-backdrop {
  position: fixed; inset: 0;
  background: rgba(0, 0, 0, 0.45);
  display: flex; align-items: center; justify-content: center;
  z-index: 1000;
}
.setup-modal {
  background: var(--casa-surface, #fff);
  border-radius: 12px; padding: 24px; max-width: 600px; width: 90%;
  box-shadow: 0 20px 60px rgba(0, 0, 0, 0.3);
}
.setup-modal__head h2 { margin: 0 0 16px; }
.setup-modal__url {
  background: var(--casa-bg-muted, #f4f1ec); padding: 12px;
  border-radius: 6px; word-break: break-all; font-family: monospace;
}
.setup-modal__actions { display: flex; gap: 8px; margin-top: 16px; justify-content: flex-end; }
.setup-modal__error pre {
  background: #fee; padding: 12px; border-radius: 6px;
  white-space: pre-wrap;
}
```

- [ ] **Step 2: Import the CSS in the modal file**

Add at top of `SetupURLModal.tsx`:

```tsx
import "./SetupURLModal.css";
```

- [ ] **Step 3: Build to verify**

```bash
cd /Users/dakasa/projects/yggdrasil/yggdrasil/surfaces/yggdrasil-console
npm run build
```

- [ ] **Step 4: Commit**

```bash
git add src/pages/collaborators/SetupURLModal.tsx src/pages/collaborators/SetupURLModal.css
git commit -m "feat(collaborators): SetupURLModal reusable component"
```

---

### Task 7.2: `issueSetupToken` API client

**Files:**
- Modify: `src/lib/api.ts`

- [ ] **Step 1: Add the function**

Find `createCollaborator` in `api.ts` and add nearby:

```ts
export interface SetupTokenResponse {
  token_id: string;
  setup_url: string;
  expires_at: string;
}

export async function issueSetupToken(collaboratorID: string): Promise<SetupTokenResponse> {
  const resp = await fetch("/api/v1/auth/passwords/setup-tokens", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    credentials: "include",
    body: JSON.stringify({ collaborator_id: collaboratorID }),
  });
  if (!resp.ok) {
    const body = await resp.text();
    throw new Error(`issueSetupToken: HTTP ${resp.status} ${body}`);
  }
  return resp.json();
}
```

- [ ] **Step 2: Build + commit**

```bash
npm run build
git add src/lib/api.ts
git commit -m "feat(api): issueSetupToken client"
```

---

### Task 7.3: `CollaboratorNewPage.tsx` chains create → setup-token → modal

**Files:**
- Modify: `src/pages/collaborators/CollaboratorNewPage.tsx`

- [ ] **Step 1: Import modal + add state**

Add imports at top:

```tsx
import { SetupURLModal } from "./SetupURLModal";
import { issueSetupToken } from "../../lib/api";
```

Inside the component, add state:

```tsx
const [setupModal, setSetupModal] = useState<{
  open: boolean;
  url: string | null;
  expiresAt: string | null;
  collaboratorName: string;
  error: string | null;
  collaboratorID: string;
} | null>(null);
```

- [ ] **Step 2: Chain after createCollaborator**

In `submit()`, replace `navigate(`/collaborators/${created.collaborator.id}`)` with:

```tsx
try {
  const token = await issueSetupToken(created.collaborator.id);
  setSetupModal({
    open: true,
    url: token.setup_url,
    expiresAt: token.expires_at,
    collaboratorName: created.collaborator.display_name,
    error: null,
    collaboratorID: created.collaborator.id,
  });
} catch (err) {
  setSetupModal({
    open: true,
    url: null,
    expiresAt: null,
    collaboratorName: created.collaborator.display_name,
    error: err instanceof Error ? err.message : String(err),
    collaboratorID: created.collaborator.id,
  });
}
```

- [ ] **Step 3: Render the modal**

Above the existing JSX return (or inside the wrapper div), add:

```tsx
{setupModal && (
  <SetupURLModal
    open={setupModal.open}
    url={setupModal.url}
    expiresAt={setupModal.expiresAt}
    collaboratorName={setupModal.collaboratorName}
    error={setupModal.error}
    onClose={() => {
      setSetupModal(null);
      navigate(`/collaborators/${setupModal.collaboratorID}`);
    }}
    onGoToDetail={() => {
      setSetupModal(null);
      navigate(`/collaborators/${setupModal.collaboratorID}`);
    }}
  />
)}
```

- [ ] **Step 4: Build + commit**

```bash
npm run build
git add src/pages/collaborators/CollaboratorNewPage.tsx
git commit -m "feat(collaborators): auto-issue setup-token after create + modal"
```

---

### Task 7.4: Re-issue button on `CollaboratorDetailPage.tsx`

**Files:**
- Modify: `src/pages/collaborators/CollaboratorDetailPage.tsx`

- [ ] **Step 1: Locate detail page**

```bash
ls src/pages/collaborators/ | grep -i detail
```

- [ ] **Step 2: Add button + modal state**

Follow the same pattern as `CollaboratorNewPage` but the button is visible only when the loaded collaborator has no password configured. Use the field that indicates this — likely from `auth_identities` join or a flag on the collaborator response. If the API doesn't expose `password_hash` directly, check for absence of `password_updated_at`.

```tsx
{!collaborator.has_password && (
  <button className="casa-btn" onClick={reissueSetupToken}>
    Gerar novo link de primeiro acesso
  </button>
)}
```

```tsx
async function reissueSetupToken() {
  try {
    const token = await issueSetupToken(collaborator.id);
    setSetupModal({
      open: true,
      url: token.setup_url,
      expiresAt: token.expires_at,
      collaboratorName: collaborator.display_name,
      error: null,
      collaboratorID: collaborator.id,
    });
  } catch (err) {
    // ...
  }
}
```

- [ ] **Step 3: Build + commit**

```bash
npm run build
git add src/pages/collaborators/CollaboratorDetailPage.tsx
git commit -m "feat(collaborators): re-issue setup-token from detail page"
```

---

## Phase 8: Migration — delete obsolete workflows

### Task 8.1: Delete lifecycle workflows from `dakasa-system`

**Files:**
- Delete: 7 workflows under `yggdrasil/dakasa/workflows/` (see top of plan)

Note: this happens in the `dakasa-system` repo, not yggdrasil-core.

- [ ] **Step 1: Verify none are applied in the cluster**

```bash
DB_USER=$(kubectl -n dakasa get secret yggdrasil-secrets -o jsonpath='{.data.DB_USER}' | base64 -d)
DB_PASSWORD=$(kubectl -n dakasa get secret yggdrasil-secrets -o jsonpath='{.data.DB_PASSWORD}' | base64 -d)
DB_NAME=$(kubectl -n dakasa get secret yggdrasil-secrets -o jsonpath='{.data.DB_NAME}' | base64 -d)
kubectl -n dakasa exec unified-database-0 -- env PGPASSWORD="$DB_PASSWORD" psql -U "$DB_USER" -d "$DB_NAME" \
  -c "SELECT name FROM manifests WHERE kind='workflow' AND active=true AND name IN ('onboard','offboard','absence-start','absence-end','re-onboard','role-change','cleanup-offboarded-collaborator');"
```

Expected: 0 rows.

- [ ] **Step 2: Delete the JSON files**

```bash
cd /Users/dakasa/projects/dakasa/dakasa-system
rm yggdrasil/dakasa/workflows/onboard.json
rm yggdrasil/dakasa/workflows/offboard.json
rm yggdrasil/dakasa/workflows/absence-start.json
rm yggdrasil/dakasa/workflows/absence-end.json
rm yggdrasil/dakasa/workflows/role-change.json
rm yggdrasil/dakasa/workflows/re-onboard.json
rm yggdrasil/dakasa/workflows/cleanup-offboarded-collaborator.json
```

- [ ] **Step 3: Commit in dakasa-system**

```bash
git add yggdrasil/dakasa/workflows/
git commit -m "🗑️ remove lifecycle workflows (superseded by reactor model)"
```

---

## Phase 9: End-to-end smoke (manual, requires DB + cluster)

### Task 9.1: Apply migrations + smoke test

- [ ] **Step 1: Apply migration to cluster Postgres**

```bash
# Via Yggdrasil workflow if available, OR manually:
kubectl -n dakasa exec -i unified-database-0 -- env PGPASSWORD="$DB_PASSWORD" psql -U "$DB_USER" -d "$DB_NAME" < db/migrations/NNNN_integration_event_reactions.sql
```

- [ ] **Step 2: Roll new yggdrasil-core image**

```bash
# Push commits → release.yml builds → ECR has new sha-XXXXXXX
# Dispatch upgrade-yggdrasil-core-edge workflow with new image
YGG_WF_TOKEN=$(kubectl -n dakasa get secret yggdrasil-secrets -o jsonpath='{.data.YGGDRASIL_WORKFLOW_RUN_TOKEN}' | base64 -d)
curl -sS -X POST "https://yggdrasil.dakasa.me/api/v1/workflow-runs" \
  -H "Authorization: Bearer $YGG_WF_TOKEN" -H 'Content-Type: application/json' \
  -d '{"workflow":{"namespace":"dakasa","name":"upgrade-yggdrasil-core-edge"},"inputs":{"image":"153828470928.dkr.ecr.us-east-1.amazonaws.com/ghcr/dakasa-yggdrasil/yggdrasil-core:sha-XXXXXXX"}}'
```

- [ ] **Step 3: Confirm reactor table empty + reactor addon started in logs**

```bash
kubectl -n dakasa logs deployment/yggdrasil --since=2m 2>&1 | grep -iE "reactor|dispatcher"
```

Expected: log entry "reactor dispatcher addon started" or similar.

- [ ] **Step 4: Add a reactor declaration to one integration_type (use `integration-yggdrasil-self` as fastest path)**

Via API or CLI: PATCH the integration_type manifest to add `reactors: [{event_type: collaborator.created, capability: on_collaborator_created}]`. (Out of plan scope: real integration implements the capability. For smoke, can use a no-op stub.)

- [ ] **Step 5: Create a collaborator via console UI, watch event_log + integration_event_reactions**

```bash
kubectl -n dakasa exec unified-database-0 -- env PGPASSWORD="$DB_PASSWORD" psql -U "$DB_USER" -d "$DB_NAME" \
  -c "SELECT event_id, event_type, integration_instance_id, status, attempt, last_error FROM integration_event_reactions ORDER BY created_at DESC LIMIT 5;"
```

Expected: rows materialized.

- [ ] **Step 6: Tag completion**

```bash
git -C /Users/dakasa/projects/yggdrasil/yggdrasil-core tag -a reactor-framework-v1 -m "Lifecycle reactor framework complete"
```

---

## Self-review follow-ups (engineer notes during implementation)

These are NOT plan placeholders — they are open questions to validate during implementation:

1. **`messagecontroller.CallIntegrationCapability` actual name**: verify against `controllers/message/integrations.go:281`. Adjust caller wrapper.
2. **`integration_instance_id` lookup**: `manifests` table stores integration_instance specs as JSONB. Materialize SQL assumes `ii.spec->>'integration_type_manifest_id'` is the reference field. Verify in real schema.
3. **`event_log.aggregate_type='reactor'` for dead-letter event**: check if `event_log` has a constraint forbidding this value. If yes, add `'reactor'` to allowed list via migration.
4. **`auth_identities.username` unique conflict** in fix for Task 6.1: ON CONFLICT DO NOTHING avoids the issue but means re-creating a collaborator with the same email won't regenerate the auth_identity. Acceptable for now.
5. **`team.updated.changed_fields`** computation: trust the PATCH input or compare snapshot vs. post-update state? Snapshot comparison is more robust; PATCH input may include unchanged fields if the client sent them.
6. **Schema validator wiring** in Task 2.1 Step 3 — file path varies by codebase. Find via grep `eventTypeToSchemaPath`.
7. **Tests for handlers (Phase 6) without DB**: if running tests without Postgres, integration tests skip; verify build alone for those.
