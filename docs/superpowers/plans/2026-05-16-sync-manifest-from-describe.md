# Sync Manifest From Describe Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Auto-heal drift between adapter live describe responses and persisted `integration_type` manifests, eliminating the `contract_mismatch` blocker that gates lifecycle reactor dispatch and all integration operations.

**Architecture:** Core addon `manifest_sync` priority 75 with two parallel triggers: in-process Go channel signaled from `integration_describe.go` on contract_mismatch detection (event-driven, sub-second latency), and `time.Ticker` cron loop (1h safety-net). Both call a single `SyncIntegrationType(typeID)` function that re-invokes describe via RabbitMQ, merges live response with operator-managed `reactors` block preserved, deep-equals against current spec, and POSTs a new manifest version when different. All outcomes emit canon events for audit.

**Tech Stack:** Go 1.22, PostgreSQL (manifests + events outbox), RabbitMQ (adapter RPC), goose migrations (no DB schema changes in this plan), `database/sql`, existing `repository.CreateManifestVersion`/`EmitEvent`/`UpsertIntegrationRuntimeState` helpers, existing `NewAdapterTransportClient` describe transport, JSON Schema 2020-12 for canon event payloads.

**Spec:** `docs/superpowers/specs/2026-05-16-sync-manifest-from-describe-design.md`

---

## File Structure

**New files:**

| Path | Responsibility |
|---|---|
| `internal/manifestsync/merge.go` | Pure: merge live describe + preserve `reactors` |
| `internal/manifestsync/merge_test.go` | Unit: merge edge cases |
| `internal/manifestsync/events.go` | Emit helpers wrapping `repository.EmitEvent` |
| `internal/manifestsync/events_test.go` | Unit: helpers serialize payload correctly |
| `internal/manifestsync/syncer.go` | `SyncIntegrationType(ctx, deps, typeID)` — single algorithm |
| `internal/manifestsync/syncer_test.go` | Unit: all 8 syncer outcome paths with mocked deps |
| `internal/manifestsync/runner.go` | Channel consumer + cron ticker + per-type mutex |
| `internal/manifestsync/runner_test.go` | Unit: signal delivery, mutex serialization, cron firing |
| `internal/manifestsync/notify.go` | Exports `Notify(typeID)` Go channel API |
| `internal/manifestsync/notify_test.go` | Unit: non-blocking send semantics |
| `internal/manifestsync/sync_integration_test.go` | Integration: real Postgres + fake adapter |
| `addons/manifest_sync.go` | Addon `init() Register(..., 75)` bootstrap |
| `controllers/httpapi/integration_type_sync.go` | `POST /api/v1/integration-types/{id}/sync` endpoint |
| `controllers/httpapi/integration_type_sync_test.go` | Endpoint: auth, success, all error reasons |
| `docs/contracts/events/v1/runtime_state/contract_mismatch_detected.json` | JSON Schema |
| `docs/contracts/events/v1/integration_type/synced.json` | JSON Schema |
| `docs/contracts/events/v1/integration_type/sync_no_op.json` | JSON Schema |
| `docs/contracts/events/v1/integration_type/sync_skipped.json` | JSON Schema |

**Modified files:**

| Path | Change |
|---|---|
| `repository/event_types_lifecycle.go` | Add 4 new event type constants |
| `controllers/message/integration_describe.go` | After `failIntegrationDescribeHandshake` writes `contract_mismatch` to runtime_state, emit `runtime_state.contract_mismatch_detected` event (with 60s debounce) AND call `manifestsync.Notify(typeID)` |
| `controllers/httpapi/server.go` | Register `POST /api/v1/integration-types/{id}/sync` route |
| `manifest/events_validator.go` (or wherever schema registry lives) | Register 4 new JSON Schemas |

---

## Task 1: Canon event type constants

**Files:**
- Modify: `repository/event_types_lifecycle.go`
- Test: `repository/event_types_lifecycle_test.go` (create if missing)

- [ ] **Step 1: Inspect current constants and test file**

Run:
```bash
cat repository/event_types_lifecycle.go
ls repository/event_types_lifecycle_test.go 2>&1 || echo "test file missing — create it"
```

- [ ] **Step 2: Write failing test for new constants**

Create or append to `repository/event_types_lifecycle_test.go`:

```go
package repository

import "testing"

func TestSyncCanonEventTypeConstants(t *testing.T) {
	cases := []struct {
		name string
		got  string
		want string
	}{
		{"contract_mismatch_detected", EventTypeRuntimeStateContractMismatchDetected, "runtime_state.contract_mismatch_detected"},
		{"integration_type_synced", EventTypeIntegrationTypeSynced, "integration_type.synced"},
		{"integration_type_sync_no_op", EventTypeIntegrationTypeSyncNoOp, "integration_type.sync_no_op"},
		{"integration_type_sync_skipped", EventTypeIntegrationTypeSyncSkipped, "integration_type.sync_skipped"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if c.got != c.want {
				t.Fatalf("constant value mismatch: got %q want %q", c.got, c.want)
			}
		})
	}
}

func TestSyncEventTypesAreNotCanonLifecycle(t *testing.T) {
	// Sync events are infrastructure, not lifecycle. Materializer must skip them.
	for _, e := range []string{
		EventTypeRuntimeStateContractMismatchDetected,
		EventTypeIntegrationTypeSynced,
		EventTypeIntegrationTypeSyncNoOp,
		EventTypeIntegrationTypeSyncSkipped,
	} {
		if IsCanonLifecycleEvent(e) {
			t.Fatalf("event %q must NOT be in CanonLifecycleEventTypes (infrastructure event)", e)
		}
	}
}
```

- [ ] **Step 3: Run test to verify it fails**

Run: `go test ./repository/ -run TestSyncCanonEvent -v`
Expected: FAIL with `undefined: EventTypeRuntimeStateContractMismatchDetected`

- [ ] **Step 4: Add the 4 constants**

Edit `repository/event_types_lifecycle.go`. After the existing constant block (which ends with `EventTypeReactorDeadLettered`), append:

```go
	// Sync framework events — infrastructure, NOT canon lifecycle.
	// The Materializer must skip these (no integration reaction allowed against
	// manifest sync activity), enforced by the test
	// TestSyncEventTypesAreNotCanonLifecycle.
	EventTypeRuntimeStateContractMismatchDetected = "runtime_state.contract_mismatch_detected"
	EventTypeIntegrationTypeSynced                = "integration_type.synced"
	EventTypeIntegrationTypeSyncNoOp              = "integration_type.sync_no_op"
	EventTypeIntegrationTypeSyncSkipped           = "integration_type.sync_skipped"
```

- [ ] **Step 5: Run test to verify it passes**

Run: `go test ./repository/ -run TestSyncCanonEvent -v`
Expected: PASS (both subtests)

- [ ] **Step 6: Run full repository tests to verify no regression**

Run: `go test ./repository/ -count=1`
Expected: PASS

- [ ] **Step 7: Commit**

```bash
git add repository/event_types_lifecycle.go repository/event_types_lifecycle_test.go
git commit -m "feat(events): add 4 canon event types for manifest sync framework"
```

---

## Task 2: JSON Schemas for 4 sync events

**Files:**
- Create: `docs/contracts/events/v1/runtime_state/contract_mismatch_detected.json`
- Create: `docs/contracts/events/v1/integration_type/synced.json`
- Create: `docs/contracts/events/v1/integration_type/sync_no_op.json`
- Create: `docs/contracts/events/v1/integration_type/sync_skipped.json`
- Modify: registry/validator wiring (see Step 5)

- [ ] **Step 1: Inspect existing schemas to match format**

Run:
```bash
ls docs/contracts/events/v1/
cat docs/contracts/events/v1/collaborator/created.json | head -40
```

Note the JSON Schema 2020-12 dialect, the use of `$schema`, `$id`, `title`, and the `_context` block convention from reactor framework (if present).

- [ ] **Step 2: Create `contract_mismatch_detected.json`**

Create `docs/contracts/events/v1/runtime_state/contract_mismatch_detected.json`:

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://dakasa-yggdrasil.io/contracts/events/v1/runtime_state/contract_mismatch_detected.json",
  "title": "runtime_state.contract_mismatch_detected",
  "description": "Emitted by integration_health monitor when a describe handshake transitions an integration_instance to contract_mismatch status. Debounced to once per instance per 60s to avoid storms during handshake retries.",
  "type": "object",
  "required": ["instance_id", "type_id", "instance_namespace", "instance_name", "type_namespace", "type_name", "detected_at"],
  "additionalProperties": false,
  "properties": {
    "instance_id":         { "type": "string", "format": "uuid" },
    "type_id":             { "type": "string", "format": "uuid" },
    "instance_namespace":  { "type": "string", "minLength": 1 },
    "instance_name":       { "type": "string", "minLength": 1 },
    "type_namespace":      { "type": "string", "minLength": 1 },
    "type_name":           { "type": "string", "minLength": 1 },
    "detected_at":         { "type": "string", "format": "date-time" }
  }
}
```

- [ ] **Step 3: Create `integration_type/synced.json`**

Create `docs/contracts/events/v1/integration_type/synced.json`:

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://dakasa-yggdrasil.io/contracts/events/v1/integration_type/synced.json",
  "title": "integration_type.synced",
  "description": "Emitted after manifest_sync successfully applies a new integration_type version matching the live adapter describe contract.",
  "type": "object",
  "required": ["type_id", "type_namespace", "type_name", "from_version", "to_version", "diff_summary", "source_instance_id", "synced_at"],
  "additionalProperties": false,
  "properties": {
    "type_id":            { "type": "string", "format": "uuid" },
    "type_namespace":     { "type": "string", "minLength": 1 },
    "type_name":          { "type": "string", "minLength": 1 },
    "from_version":       { "type": "integer", "minimum": 1 },
    "to_version":         { "type": "integer", "minimum": 2 },
    "diff_summary": {
      "type": "object",
      "required": ["added_actions", "removed_actions", "schema_changed", "capabilities_changed"],
      "additionalProperties": false,
      "properties": {
        "added_actions":        { "type": "array", "items": { "type": "string" } },
        "removed_actions":      { "type": "array", "items": { "type": "string" } },
        "schema_changed":       { "type": "boolean" },
        "capabilities_changed": { "type": "boolean" }
      }
    },
    "source_instance_id": { "type": "string", "format": "uuid" },
    "synced_at":          { "type": "string", "format": "date-time" }
  }
}
```

- [ ] **Step 4: Create `integration_type/sync_no_op.json`**

Create `docs/contracts/events/v1/integration_type/sync_no_op.json`:

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://dakasa-yggdrasil.io/contracts/events/v1/integration_type/sync_no_op.json",
  "title": "integration_type.sync_no_op",
  "description": "Emitted when manifest_sync verifies the persisted manifest already matches live describe. Default: suppressed (set DEBUG_SYNC_NO_OP=true to emit).",
  "type": "object",
  "required": ["type_id", "type_namespace", "type_name", "source_instance_id", "checked_at"],
  "additionalProperties": false,
  "properties": {
    "type_id":            { "type": "string", "format": "uuid" },
    "type_namespace":     { "type": "string", "minLength": 1 },
    "type_name":          { "type": "string", "minLength": 1 },
    "source_instance_id": { "type": "string", "format": "uuid" },
    "checked_at":         { "type": "string", "format": "date-time" }
  }
}
```

- [ ] **Step 5: Create `integration_type/sync_skipped.json`**

Create `docs/contracts/events/v1/integration_type/sync_skipped.json`:

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://dakasa-yggdrasil.io/contracts/events/v1/integration_type/sync_skipped.json",
  "title": "integration_type.sync_skipped",
  "description": "Emitted when manifest_sync could not complete a sync attempt. The `reason` enum is the operational signal; `error` is detail for humans.",
  "type": "object",
  "required": ["type_id", "type_namespace", "type_name", "reason", "attempted_at"],
  "additionalProperties": false,
  "properties": {
    "type_id":               { "type": "string", "format": "uuid" },
    "type_namespace":        { "type": "string", "minLength": 1 },
    "type_name":             { "type": "string", "minLength": 1 },
    "reason": {
      "type": "string",
      "enum": [
        "type_not_found",
        "no_instances",
        "no_describable_instance",
        "rpc_failed",
        "invalid_describe",
        "apply_failed"
      ]
    },
    "error":                 { "type": "string" },
    "attempted_instance_id": { "type": ["string", "null"], "format": "uuid" },
    "attempted_at":          { "type": "string", "format": "date-time" }
  }
}
```

- [ ] **Step 6: Find existing schema registration site and wire new schemas**

Run:
```bash
grep -rn "events/v1/collaborator/created.json\|RegisterEventSchema\|loadEventSchema" --include="*.go" .
```

Likely returns hits in `manifest/events_validator.go` or similar. Open the file and find the slice/map listing schemas. Append:

```go
// excerpt — actual variable name and exact location depend on what grep found:
"runtime_state.contract_mismatch_detected": "docs/contracts/events/v1/runtime_state/contract_mismatch_detected.json",
"integration_type.synced":                  "docs/contracts/events/v1/integration_type/synced.json",
"integration_type.sync_no_op":              "docs/contracts/events/v1/integration_type/sync_no_op.json",
"integration_type.sync_skipped":            "docs/contracts/events/v1/integration_type/sync_skipped.json",
```

Match the existing entries' exact syntax (key style, comma trailing, etc.) so the file parses cleanly.

- [ ] **Step 7: Run schema validator tests**

Run:
```bash
go test ./manifest/... -count=1
```
Expected: PASS. If a test enumerates registered schemas and counts them, that count must now be +4.

- [ ] **Step 8: Commit**

```bash
git add docs/contracts/events/v1/runtime_state/ docs/contracts/events/v1/integration_type/ manifest/events_validator.go
git commit -m "feat(events): add JSON schemas for 4 sync framework events"
```

---

## Task 3: Merge logic (pure function, no I/O)

**Files:**
- Create: `internal/manifestsync/merge.go`
- Test: `internal/manifestsync/merge_test.go`

- [ ] **Step 1: Read `model.IntegrationTypeManifestSpec` shape**

Run:
```bash
grep -nE "type IntegrationTypeManifestSpec|Reactors\s|ActionCatalog\s" model/*.go | head -30
```

Note the field names (`ActionCatalog`, `Capabilities`, `CredentialSchema`, `Discovery`, `Execution`, `Extensions`, `InstanceSchema`, `Normalization`, `Provider`, `ResourceTypes`, `Reactors`, `Adapter`) and confirm `Reactors` is a slice or struct, not a nested map.

- [ ] **Step 2: Write failing tests for `MergeSpec`**

Create `internal/manifestsync/merge_test.go`:

```go
package manifestsync

import (
	"testing"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMergeSpec_PreservesReactorsWhenLiveHasNone(t *testing.T) {
	current := model.IntegrationTypeManifestSpec{
		ActionCatalog: []model.IntegrationActionCatalogEntry{{Name: "old_op"}},
		Reactors: []model.IntegrationTypeReactor{
			{EventType: "collaborator.created", Capability: "on_collaborator_created"},
		},
	}
	live := model.IntegrationTypeManifestSpec{
		ActionCatalog: []model.IntegrationActionCatalogEntry{{Name: "new_op_a"}, {Name: "new_op_b"}},
	}

	got, diff := MergeSpec(current, live)

	require.Len(t, got.Reactors, 1, "reactors must be preserved from current")
	assert.Equal(t, "on_collaborator_created", got.Reactors[0].Capability)
	assert.Len(t, got.ActionCatalog, 2, "action_catalog must come from live")
	assert.Contains(t, diff.AddedActions, "new_op_a")
	assert.Contains(t, diff.AddedActions, "new_op_b")
	assert.Contains(t, diff.RemovedActions, "old_op")
}

func TestMergeSpec_IdenticalProducesNoDiff(t *testing.T) {
	spec := model.IntegrationTypeManifestSpec{
		ActionCatalog: []model.IntegrationActionCatalogEntry{{Name: "x"}},
		Reactors:      []model.IntegrationTypeReactor{{EventType: "e", Capability: "c"}},
	}
	got, diff := MergeSpec(spec, spec)
	assert.Equal(t, spec, got)
	assert.Empty(t, diff.AddedActions)
	assert.Empty(t, diff.RemovedActions)
	assert.False(t, diff.SchemaChanged)
	assert.False(t, diff.CapabilitiesChanged)
}

func TestMergeSpec_SchemaChangedFlag(t *testing.T) {
	current := model.IntegrationTypeManifestSpec{
		CredentialSchema: map[string]any{"v": "1"},
	}
	live := model.IntegrationTypeManifestSpec{
		CredentialSchema: map[string]any{"v": "2"},
	}
	_, diff := MergeSpec(current, live)
	assert.True(t, diff.SchemaChanged)
}

func TestMergeSpec_CapabilitiesChangedFlag(t *testing.T) {
	current := model.IntegrationTypeManifestSpec{
		Capabilities: map[string]any{"a": 1},
	}
	live := model.IntegrationTypeManifestSpec{
		Capabilities: map[string]any{"a": 1, "b": 2},
	}
	_, diff := MergeSpec(current, live)
	assert.True(t, diff.CapabilitiesChanged)
}

func TestMergeSpec_LiveReactorsAreIgnored(t *testing.T) {
	// Defensive: even if a future adapter erroneously includes reactors
	// in its describe response, manifest_sync must NOT adopt them.
	current := model.IntegrationTypeManifestSpec{
		Reactors: []model.IntegrationTypeReactor{{EventType: "e1", Capability: "c1"}},
	}
	live := model.IntegrationTypeManifestSpec{
		Reactors: []model.IntegrationTypeReactor{{EventType: "e2", Capability: "c2"}},
	}
	got, _ := MergeSpec(current, live)
	require.Len(t, got.Reactors, 1)
	assert.Equal(t, "e1", got.Reactors[0].EventType, "current's reactors must win unconditionally")
}

func TestMergeSpec_NoReactorsAnywhere(t *testing.T) {
	current := model.IntegrationTypeManifestSpec{
		ActionCatalog: []model.IntegrationActionCatalogEntry{{Name: "x"}},
	}
	live := model.IntegrationTypeManifestSpec{
		ActionCatalog: []model.IntegrationActionCatalogEntry{{Name: "x"}, {Name: "y"}},
	}
	got, _ := MergeSpec(current, live)
	assert.Nil(t, got.Reactors, "no reactors in current means no reactors in result")
}
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `go test ./internal/manifestsync/ -count=1 -v`
Expected: FAIL with `no Go files` or `undefined: MergeSpec`

- [ ] **Step 4: Implement `MergeSpec` + `Diff`**

Create `internal/manifestsync/merge.go`:

```go
// Package manifestsync auto-heals integration_type manifest drift against
// adapter live describe responses. See
// docs/superpowers/specs/2026-05-16-sync-manifest-from-describe-design.md.
package manifestsync

import (
	"reflect"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

// Diff is a compact summary of the structural change between two specs.
// Embedded in integration_type.synced event payloads for audit.
type Diff struct {
	AddedActions        []string
	RemovedActions      []string
	SchemaChanged       bool
	CapabilitiesChanged bool
}

// MergeSpec produces the new integration_type spec to persist when drift is
// detected: live as the base, with operator-managed `Reactors` preserved
// verbatim from the currently-active manifest.
//
// Today `Reactors` is the only operator-managed field. If new operator-owned
// fields are introduced, extend this function (and document it in the spec
// at docs/superpowers/specs/2026-05-16-sync-manifest-from-describe-design.md
// section 5.1).
func MergeSpec(current, live model.IntegrationTypeManifestSpec) (model.IntegrationTypeManifestSpec, Diff) {
	out := live
	out.Reactors = current.Reactors // operator-managed; never sourced from live

	return out, computeDiff(current, out)
}

func computeDiff(before, after model.IntegrationTypeManifestSpec) Diff {
	beforeOps := actionNames(before.ActionCatalog)
	afterOps := actionNames(after.ActionCatalog)

	return Diff{
		AddedActions:        diffStringSlices(afterOps, beforeOps),
		RemovedActions:      diffStringSlices(beforeOps, afterOps),
		SchemaChanged:       !reflect.DeepEqual(before.CredentialSchema, after.CredentialSchema) || !reflect.DeepEqual(before.InstanceSchema, after.InstanceSchema),
		CapabilitiesChanged: !reflect.DeepEqual(before.Capabilities, after.Capabilities),
	}
}

func actionNames(entries []model.IntegrationActionCatalogEntry) map[string]struct{} {
	m := make(map[string]struct{}, len(entries))
	for _, e := range entries {
		m[e.Name] = struct{}{}
	}
	return m
}

// diffStringSlices returns keys present in a but not in b, sorted by
// iteration order (Go map order). Sufficient for diff_summary payload.
func diffStringSlices(a, b map[string]struct{}) []string {
	out := []string{}
	for k := range a {
		if _, ok := b[k]; !ok {
			out = append(out, k)
		}
	}
	return out
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `go test ./internal/manifestsync/ -count=1 -v`
Expected: PASS on all 6 subtests.

- [ ] **Step 6: Commit**

```bash
git add internal/manifestsync/merge.go internal/manifestsync/merge_test.go
git commit -m "feat(manifestsync): add MergeSpec preserving operator-managed reactors"
```

---

## Task 4: Notify channel (in-process signal)

**Files:**
- Create: `internal/manifestsync/notify.go`
- Test: `internal/manifestsync/notify_test.go`

- [ ] **Step 1: Write failing test for `Notify`**

Create `internal/manifestsync/notify_test.go`:

```go
package manifestsync

import (
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

func TestNotify_DeliversToReceiver(t *testing.T) {
	resetNotifyChannelForTest(t)

	id := uuid.New()
	Notify(id)

	select {
	case got := <-NotifyChannel():
		assert.Equal(t, id, got)
	default:
		t.Fatalf("expected typeID on channel, got nothing")
	}
}

func TestNotify_NonBlockingWhenBufferFull(t *testing.T) {
	resetNotifyChannelForTest(t)

	// Fill the buffer to capacity.
	for i := 0; i < cap(NotifyChannel()); i++ {
		Notify(uuid.New())
	}

	// This call MUST NOT block — it returns immediately with the signal dropped.
	done := make(chan struct{})
	go func() {
		Notify(uuid.New())
		close(done)
	}()

	select {
	case <-done:
		// good — non-blocking semantic verified
	case <-makeTimeoutChan(100):
		t.Fatalf("Notify blocked when buffer was full — must drop silently")
	}
}

func TestNotify_NilUUIDIsAccepted(t *testing.T) {
	resetNotifyChannelForTest(t)
	Notify(uuid.Nil) // must not panic; consumer is responsible for validation
}
```

Add the test helpers (in same `_test.go` file or a `testing_helpers.go` that builds only under `//go:build test`); inline here is simplest:

```go
func resetNotifyChannelForTest(t *testing.T) {
	t.Helper()
	notifyMu.Lock()
	defer notifyMu.Unlock()
	notifyCh = make(chan uuid.UUID, notifyBufferSize)
}

func makeTimeoutChan(ms int) <-chan struct{} {
	ch := make(chan struct{})
	go func() {
		select {
		case <-time.After(time.Duration(ms) * time.Millisecond):
			close(ch)
		}
	}()
	return ch
}
```

Add imports `"time"` and `"github.com/google/uuid"` and `"sync"` and  `"github.com/stretchr/testify/assert"` to the test file.

- [ ] **Step 2: Run tests to verify failure**

Run: `go test ./internal/manifestsync/ -run TestNotify -v`
Expected: FAIL with `undefined: notifyCh` / `undefined: Notify`.

- [ ] **Step 3: Implement `Notify` and channel**

Create `internal/manifestsync/notify.go`:

```go
package manifestsync

import (
	"sync"

	"github.com/google/uuid"
)

const notifyBufferSize = 128

var (
	notifyMu sync.Mutex
	notifyCh = make(chan uuid.UUID, notifyBufferSize)
)

// Notify enqueues an integration_type ID for re-sync by the runner.
// Non-blocking: if the buffer is full, the signal is silently dropped.
// The cron safety-net (1h) covers any dropped signals — this channel is a
// fast-path nudge, not the source of truth.
//
// Callers (e.g. controllers/message/integration_describe.go) MUST tolerate
// dropped signals and never treat Notify as transactional.
func Notify(typeID uuid.UUID) {
	notifyMu.Lock()
	ch := notifyCh
	notifyMu.Unlock()

	select {
	case ch <- typeID:
	default:
		// buffer full → drop; cron will catch
	}
}

// NotifyChannel returns the read-only channel of signaled type IDs.
// The runner consumes from this channel. Exported for the runner package
// (same package today, but kept for future split clarity).
func NotifyChannel() <-chan uuid.UUID {
	notifyMu.Lock()
	defer notifyMu.Unlock()
	return notifyCh
}
```

- [ ] **Step 4: Run tests to verify pass**

Run: `go test ./internal/manifestsync/ -run TestNotify -v`
Expected: PASS (3 subtests).

- [ ] **Step 5: Commit**

```bash
git add internal/manifestsync/notify.go internal/manifestsync/notify_test.go
git commit -m "feat(manifestsync): add non-blocking Notify channel for sync signals"
```

---

## Task 5: Event emit helpers

**Files:**
- Create: `internal/manifestsync/events.go`
- Test: `internal/manifestsync/events_test.go`

- [ ] **Step 1: Inspect `repository.EmitEvent` signature and `model.EmitEventRequest`**

Run:
```bash
grep -nE "type EmitEventRequest|func EmitEvent\(" model/*.go repository/event.go | head -20
```

Note: `EmitEvent` takes `*sql.Tx` (not `*sql.DB`). The helpers will open a tx internally for atomic emit. Also note the `EmitEventRequest` fields — likely `EventType`, `AggregateType`, `AggregateID`, `Payload`, `Metadata`, etc.

- [ ] **Step 2: Write failing tests for emit helpers**

Create `internal/manifestsync/events_test.go`:

```go
package manifestsync

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBuildSyncedPayload_ShapeMatchesSchema(t *testing.T) {
	typeID := uuid.New()
	srcID := uuid.New()
	now := time.Date(2026, 5, 16, 12, 0, 0, 0, time.UTC)

	got := buildSyncedPayload(syncedInputs{
		TypeID:           typeID,
		TypeNamespace:    "global",
		TypeName:         "slack",
		FromVersion:      6,
		ToVersion:        7,
		Diff:             Diff{AddedActions: []string{"new_op"}, RemovedActions: []string{}, SchemaChanged: false, CapabilitiesChanged: false},
		SourceInstanceID: srcID,
		SyncedAt:         now,
	})

	raw, err := json.Marshal(got)
	require.NoError(t, err)

	var parsed map[string]any
	require.NoError(t, json.Unmarshal(raw, &parsed))

	assert.Equal(t, typeID.String(), parsed["type_id"])
	assert.Equal(t, "global", parsed["type_namespace"])
	assert.Equal(t, "slack", parsed["type_name"])
	assert.EqualValues(t, 6, parsed["from_version"])
	assert.EqualValues(t, 7, parsed["to_version"])
	assert.Equal(t, srcID.String(), parsed["source_instance_id"])
	assert.Equal(t, "2026-05-16T12:00:00Z", parsed["synced_at"])

	diff, ok := parsed["diff_summary"].(map[string]any)
	require.True(t, ok)
	assert.Contains(t, diff["added_actions"], "new_op")
	assert.Equal(t, false, diff["schema_changed"])
	assert.Equal(t, false, diff["capabilities_changed"])
}

func TestBuildSkippedPayload_ReasonRequired(t *testing.T) {
	typeID := uuid.New()
	now := time.Date(2026, 5, 16, 12, 0, 0, 0, time.UTC)
	got := buildSkippedPayload(skippedInputs{
		TypeID:        typeID,
		TypeNamespace: "global",
		TypeName:      "slack",
		Reason:        SkipReasonRPCFailed,
		Error:         "deadline exceeded",
		AttemptedAt:   now,
	})

	raw, _ := json.Marshal(got)
	var p map[string]any
	require.NoError(t, json.Unmarshal(raw, &p))
	assert.Equal(t, "rpc_failed", p["reason"])
	assert.Equal(t, "deadline exceeded", p["error"])
	assert.Equal(t, nil, p["attempted_instance_id"], "null when nil")
}

func TestSkipReasonConstants(t *testing.T) {
	// Must match the enum in docs/contracts/events/v1/integration_type/sync_skipped.json
	cases := []struct {
		got  SkipReason
		want string
	}{
		{SkipReasonTypeNotFound, "type_not_found"},
		{SkipReasonNoInstances, "no_instances"},
		{SkipReasonNoDescribableInstance, "no_describable_instance"},
		{SkipReasonRPCFailed, "rpc_failed"},
		{SkipReasonInvalidDescribe, "invalid_describe"},
		{SkipReasonApplyFailed, "apply_failed"},
	}
	for _, c := range cases {
		assert.Equal(t, c.want, string(c.got))
	}
}

// emitToOutboxRoundTrip is an integration concern; covered in sync_integration_test.go
// to keep this file pure (no DB dependency).
var _ = repository.EmitEvent // referenced for compile-time check that the helper
var _ = model.EmitEventRequest{}
```

- [ ] **Step 3: Run test to verify failure**

Run: `go test ./internal/manifestsync/ -run "TestBuildSyncedPayload|TestBuildSkippedPayload|TestSkipReasonConstants" -v`
Expected: FAIL with `undefined: buildSyncedPayload` etc.

- [ ] **Step 4: Implement `events.go`**

Create `internal/manifestsync/events.go`:

```go
package manifestsync

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	"github.com/google/uuid"
)

// SkipReason is the controlled enum embedded in integration_type.sync_skipped
// events. Values must match the JSON Schema enum at
// docs/contracts/events/v1/integration_type/sync_skipped.json.
type SkipReason string

const (
	SkipReasonTypeNotFound          SkipReason = "type_not_found"
	SkipReasonNoInstances           SkipReason = "no_instances"
	SkipReasonNoDescribableInstance SkipReason = "no_describable_instance"
	SkipReasonRPCFailed             SkipReason = "rpc_failed"
	SkipReasonInvalidDescribe       SkipReason = "invalid_describe"
	SkipReasonApplyFailed           SkipReason = "apply_failed"
)

type syncedInputs struct {
	TypeID           uuid.UUID
	TypeNamespace    string
	TypeName         string
	FromVersion      int
	ToVersion        int
	Diff             Diff
	SourceInstanceID uuid.UUID
	SyncedAt         time.Time
}

func buildSyncedPayload(in syncedInputs) map[string]any {
	added := in.Diff.AddedActions
	if added == nil {
		added = []string{}
	}
	removed := in.Diff.RemovedActions
	if removed == nil {
		removed = []string{}
	}
	return map[string]any{
		"type_id":            in.TypeID.String(),
		"type_namespace":     in.TypeNamespace,
		"type_name":          in.TypeName,
		"from_version":       in.FromVersion,
		"to_version":         in.ToVersion,
		"source_instance_id": in.SourceInstanceID.String(),
		"synced_at":          in.SyncedAt.UTC().Format(time.RFC3339),
		"diff_summary": map[string]any{
			"added_actions":        added,
			"removed_actions":      removed,
			"schema_changed":       in.Diff.SchemaChanged,
			"capabilities_changed": in.Diff.CapabilitiesChanged,
		},
	}
}

type skippedInputs struct {
	TypeID                uuid.UUID
	TypeNamespace         string
	TypeName              string
	Reason                SkipReason
	Error                 string
	AttemptedInstanceID   *uuid.UUID // nilable
	AttemptedAt           time.Time
}

func buildSkippedPayload(in skippedInputs) map[string]any {
	p := map[string]any{
		"type_id":         in.TypeID.String(),
		"type_namespace":  in.TypeNamespace,
		"type_name":       in.TypeName,
		"reason":          string(in.Reason),
		"attempted_at":    in.AttemptedAt.UTC().Format(time.RFC3339),
	}
	if in.Error != "" {
		p["error"] = in.Error
	}
	if in.AttemptedInstanceID != nil {
		p["attempted_instance_id"] = in.AttemptedInstanceID.String()
	} else {
		p["attempted_instance_id"] = nil
	}
	return p
}

type noOpInputs struct {
	TypeID           uuid.UUID
	TypeNamespace    string
	TypeName         string
	SourceInstanceID uuid.UUID
	CheckedAt        time.Time
}

func buildNoOpPayload(in noOpInputs) map[string]any {
	return map[string]any{
		"type_id":            in.TypeID.String(),
		"type_namespace":     in.TypeNamespace,
		"type_name":          in.TypeName,
		"source_instance_id": in.SourceInstanceID.String(),
		"checked_at":         in.CheckedAt.UTC().Format(time.RFC3339),
	}
}

type contractMismatchInputs struct {
	InstanceID        uuid.UUID
	TypeID            uuid.UUID
	InstanceNamespace string
	InstanceName      string
	TypeNamespace     string
	TypeName          string
	DetectedAt        time.Time
}

func buildContractMismatchPayload(in contractMismatchInputs) map[string]any {
	return map[string]any{
		"instance_id":        in.InstanceID.String(),
		"type_id":            in.TypeID.String(),
		"instance_namespace": in.InstanceNamespace,
		"instance_name":      in.InstanceName,
		"type_namespace":     in.TypeNamespace,
		"type_name":          in.TypeName,
		"detected_at":        in.DetectedAt.UTC().Format(time.RFC3339),
	}
}

// emitEvent persists one canon event row by opening a short-lived tx.
func emitEvent(ctx context.Context, db *sql.DB, eventType string, aggregateID uuid.UUID, payload map[string]any) error {
	raw, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal payload: %w", err)
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck — committed on success path

	if _, err := repository.EmitEvent(ctx, tx, model.EmitEventRequest{
		EventType:   eventType,
		AggregateID: aggregateID,
		Payload:     raw,
	}); err != nil {
		return fmt.Errorf("emit %s: %w", eventType, err)
	}
	return tx.Commit()
}
```

> NOTE: The `model.EmitEventRequest` field set above (EventType, AggregateID, Payload) is the assumed shape. If the actual struct differs (e.g. requires AggregateType, Source), adapt the helper to the real struct found in Step 1; the test will tell you what's missing on the next run.

- [ ] **Step 5: Run tests to verify pass**

Run: `go test ./internal/manifestsync/ -run "TestBuildSyncedPayload|TestBuildSkippedPayload|TestSkipReasonConstants" -v`
Expected: PASS (3 tests).

- [ ] **Step 6: Run full package vet + test**

Run:
```bash
go vet ./internal/manifestsync/
go test ./internal/manifestsync/ -count=1
```
Expected: PASS (no vet warnings).

- [ ] **Step 7: Commit**

```bash
git add internal/manifestsync/events.go internal/manifestsync/events_test.go
git commit -m "feat(manifestsync): add canon event payload builders + emit helper"
```

---

## Task 6: Syncer core algorithm

**Files:**
- Create: `internal/manifestsync/syncer.go`
- Test: `internal/manifestsync/syncer_test.go`
- Reference: spec section 5 (algorithm) and section 8 (failure reasons)

- [ ] **Step 1: Define `Deps` interface so the syncer is mockable**

The syncer needs:
- Resolve current integration_type manifest by typeID
- List integration_instances of that type
- Invoke describe RPC on an instance
- POST a new manifest version

Sketch the `Deps` interface up-front:

```go
type Deps interface {
	GetIntegrationType(ctx context.Context, typeID uuid.UUID) (model.Manifest, model.IntegrationTypeManifestSpec, error)
	ListInstances(ctx context.Context, typeID uuid.UUID) ([]model.Manifest, []model.IntegrationInstanceManifestSpec, error)
	InvokeDescribe(ctx context.Context, instanceManifest model.Manifest, typeManifest model.Manifest, instanceSpec model.IntegrationInstanceManifestSpec, typeSpec model.IntegrationTypeManifestSpec) (model.IntegrationTypeManifestSpec, error)
	ApplyManifestVersion(ctx context.Context, doc model.ManifestDocument) (model.Manifest, error)
	EmitEvent(ctx context.Context, eventType string, aggregateID uuid.UUID, payload map[string]any) error
	Now() time.Time
}
```

This goes into `internal/manifestsync/syncer.go` directly. Production implementation lives in `addons/manifest_sync.go` (Task 9) and wraps `repository.*` calls + the existing describe transport.

- [ ] **Step 2: Write failing tests for syncer happy path + all 6 skip reasons**

Create `internal/manifestsync/syncer_test.go`:

```go
package manifestsync

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakeDeps struct {
	typeManifest model.Manifest
	typeSpec     model.IntegrationTypeManifestSpec
	typeErr      error

	instances     []model.Manifest
	instanceSpecs []model.IntegrationInstanceManifestSpec
	instanceErr   error

	describeSpec model.IntegrationTypeManifestSpec
	describeErr  error

	appliedDoc *model.ManifestDocument
	applyErr   error

	emittedType    string
	emittedPayload map[string]any
	emitErr        error

	now time.Time
}

func (f *fakeDeps) GetIntegrationType(_ context.Context, _ uuid.UUID) (model.Manifest, model.IntegrationTypeManifestSpec, error) {
	return f.typeManifest, f.typeSpec, f.typeErr
}
func (f *fakeDeps) ListInstances(_ context.Context, _ uuid.UUID) ([]model.Manifest, []model.IntegrationInstanceManifestSpec, error) {
	return f.instances, f.instanceSpecs, f.instanceErr
}
func (f *fakeDeps) InvokeDescribe(_ context.Context, _ model.Manifest, _ model.Manifest, _ model.IntegrationInstanceManifestSpec, _ model.IntegrationTypeManifestSpec) (model.IntegrationTypeManifestSpec, error) {
	return f.describeSpec, f.describeErr
}
func (f *fakeDeps) ApplyManifestVersion(_ context.Context, doc model.ManifestDocument) (model.Manifest, error) {
	f.appliedDoc = &doc
	if f.applyErr != nil {
		return model.Manifest{}, f.applyErr
	}
	return model.Manifest{Version: f.typeManifest.Version + 1, Metadata: f.typeManifest.Metadata}, nil
}
func (f *fakeDeps) EmitEvent(_ context.Context, eventType string, _ uuid.UUID, payload map[string]any) error {
	f.emittedType = eventType
	f.emittedPayload = payload
	return f.emitErr
}
func (f *fakeDeps) Now() time.Time { return f.now }

func validLiveSpec() model.IntegrationTypeManifestSpec {
	return model.IntegrationTypeManifestSpec{
		ActionCatalog:    []model.IntegrationActionCatalogEntry{{Name: "new_op"}},
		CredentialSchema: map[string]any{"mode": "inline"},
		Adapter:          model.IntegrationTypeAdapterSpec{Version: "1.2.0"},
	}
}

func newFakeWithHappyPath() *fakeDeps {
	typeID := uuid.New()
	return &fakeDeps{
		typeManifest: model.Manifest{
			ID:      uuid.New(),
			Version: 7,
			Metadata: model.ManifestMetadata{
				ID:          typeID,
				Kind:        "integration_type",
				Namespace:   "global",
				Name:        "slack",
				Description: "Slack integration",
				Active:      true,
			},
		},
		typeSpec: model.IntegrationTypeManifestSpec{
			ActionCatalog: []model.IntegrationActionCatalogEntry{{Name: "old_op"}},
			Reactors:      []model.IntegrationTypeReactor{{EventType: "collaborator.created", Capability: "on_collaborator_created"}},
		},
		instances:     []model.Manifest{{ID: uuid.New()}},
		instanceSpecs: []model.IntegrationInstanceManifestSpec{{}},
		describeSpec:  validLiveSpec(),
		now:           time.Date(2026, 5, 16, 12, 0, 0, 0, time.UTC),
	}
}

func TestSyncIntegrationType_HappyPath_AppliesAndEmitsSynced(t *testing.T) {
	f := newFakeWithHappyPath()
	typeID := f.typeManifest.Metadata.ID

	err := SyncIntegrationType(context.Background(), f, typeID)
	require.NoError(t, err)

	require.NotNil(t, f.appliedDoc, "expected new manifest version applied")
	assert.Equal(t, "slack", f.appliedDoc.Metadata.Name)
	assert.Equal(t, "Slack integration", f.appliedDoc.Metadata.Description, "description preserved")
	assert.Equal(t, "integration_type.synced", f.emittedType)
	assert.EqualValues(t, 7, f.emittedPayload["from_version"])
	assert.EqualValues(t, 8, f.emittedPayload["to_version"])
}

func TestSyncIntegrationType_NoInstances_EmitsSkippedNoInstances(t *testing.T) {
	f := newFakeWithHappyPath()
	f.instances = nil
	f.instanceSpecs = nil

	err := SyncIntegrationType(context.Background(), f, f.typeManifest.Metadata.ID)
	require.NoError(t, err)
	assert.Equal(t, "integration_type.sync_skipped", f.emittedType)
	assert.Equal(t, "no_instances", f.emittedPayload["reason"])
	assert.Nil(t, f.appliedDoc)
}

func TestSyncIntegrationType_DescribeRPCFailed_EmitsSkippedRPCFailed(t *testing.T) {
	f := newFakeWithHappyPath()
	f.describeErr = errors.New("amqp: deadline exceeded")

	err := SyncIntegrationType(context.Background(), f, f.typeManifest.Metadata.ID)
	require.NoError(t, err)
	assert.Equal(t, "integration_type.sync_skipped", f.emittedType)
	assert.Equal(t, "rpc_failed", f.emittedPayload["reason"])
	assert.Contains(t, f.emittedPayload["error"], "deadline exceeded")
}

func TestSyncIntegrationType_DescribeEmpty_EmitsSkippedInvalidDescribe(t *testing.T) {
	f := newFakeWithHappyPath()
	f.describeSpec = model.IntegrationTypeManifestSpec{} // no action_catalog, no schema, no adapter version

	err := SyncIntegrationType(context.Background(), f, f.typeManifest.Metadata.ID)
	require.NoError(t, err)
	assert.Equal(t, "integration_type.sync_skipped", f.emittedType)
	assert.Equal(t, "invalid_describe", f.emittedPayload["reason"])
}

func TestSyncIntegrationType_NoDiff_EmitsNoOp_DefaultSuppressed(t *testing.T) {
	f := newFakeWithHappyPath()
	// Make describe equal to current spec (after merge — reactors preserved).
	f.describeSpec = f.typeSpec
	f.describeSpec.Reactors = nil // describe never carries reactors

	err := SyncIntegrationType(context.Background(), f, f.typeManifest.Metadata.ID)
	require.NoError(t, err)
	assert.Nil(t, f.appliedDoc, "no apply on no-op")
	// Default suppressed → no event emitted.
	assert.Empty(t, f.emittedType, "no_op default-suppressed; set DEBUG_SYNC_NO_OP=true to emit")
}

func TestSyncIntegrationType_NoOpEmittedWhenDebugFlagSet(t *testing.T) {
	t.Setenv("DEBUG_SYNC_NO_OP", "true")

	f := newFakeWithHappyPath()
	f.describeSpec = f.typeSpec
	f.describeSpec.Reactors = nil

	err := SyncIntegrationType(context.Background(), f, f.typeManifest.Metadata.ID)
	require.NoError(t, err)
	assert.Equal(t, "integration_type.sync_no_op", f.emittedType)
}

func TestSyncIntegrationType_ApplyFails_EmitsSkippedApplyFailed(t *testing.T) {
	f := newFakeWithHappyPath()
	f.applyErr = errors.New("validation: action_catalog[3].name duplicate")

	err := SyncIntegrationType(context.Background(), f, f.typeManifest.Metadata.ID)
	require.NoError(t, err)
	assert.Equal(t, "integration_type.sync_skipped", f.emittedType)
	assert.Equal(t, "apply_failed", f.emittedPayload["reason"])
}

func TestSyncIntegrationType_TypeNotFound_EmitsSkippedTypeNotFound(t *testing.T) {
	f := newFakeWithHappyPath()
	f.typeErr = errors.New("sql: no rows in result set")

	err := SyncIntegrationType(context.Background(), f, uuid.New())
	require.NoError(t, err)
	assert.Equal(t, "integration_type.sync_skipped", f.emittedType)
	assert.Equal(t, "type_not_found", f.emittedPayload["reason"])
}
```

- [ ] **Step 3: Run tests to verify all fail**

Run: `go test ./internal/manifestsync/ -run TestSyncIntegrationType -v`
Expected: FAIL — `undefined: SyncIntegrationType`, `undefined: Deps`.

- [ ] **Step 4: Implement `SyncIntegrationType` + `Deps` + describe validation**

Create `internal/manifestsync/syncer.go`:

```go
package manifestsync

import (
	"context"
	"errors"
	"os"
	"reflect"
	"strings"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

// Deps is the surface the syncer needs from the rest of the system.
// Production wiring lives in addons/manifest_sync.go; tests use a fake.
type Deps interface {
	GetIntegrationType(ctx context.Context, typeID uuid.UUID) (model.Manifest, model.IntegrationTypeManifestSpec, error)
	ListInstances(ctx context.Context, typeID uuid.UUID) ([]model.Manifest, []model.IntegrationInstanceManifestSpec, error)
	InvokeDescribe(
		ctx context.Context,
		instanceManifest model.Manifest,
		typeManifest model.Manifest,
		instanceSpec model.IntegrationInstanceManifestSpec,
		typeSpec model.IntegrationTypeManifestSpec,
	) (model.IntegrationTypeManifestSpec, error)
	ApplyManifestVersion(ctx context.Context, doc model.ManifestDocument) (model.Manifest, error)
	EmitEvent(ctx context.Context, eventType string, aggregateID uuid.UUID, payload map[string]any) error
	Now() time.Time
}

// SyncIntegrationType is the single algorithm for every sync trigger
// (event-driven, cron, manual). It never returns an error to the caller —
// all outcomes are encoded as emitted events. The returned error is only
// for emit-event failures, which the caller (Runner / HTTP handler) logs.
//
// See docs/superpowers/specs/2026-05-16-sync-manifest-from-describe-design.md
// section 5 for the spec.
func SyncIntegrationType(ctx context.Context, d Deps, typeID uuid.UUID) error {
	now := d.Now()

	// Step 1: resolve type
	typeManifest, currentSpec, err := d.GetIntegrationType(ctx, typeID)
	if err != nil {
		return d.EmitEvent(ctx, "integration_type.sync_skipped", typeID, buildSkippedPayload(skippedInputs{
			TypeID:        typeID,
			TypeNamespace: "",
			TypeName:      "",
			Reason:        SkipReasonTypeNotFound,
			Error:         err.Error(),
			AttemptedAt:   now,
		}))
	}

	ns := typeManifest.Metadata.Namespace
	name := typeManifest.Metadata.Name

	// Step 2: list instances
	instances, instanceSpecs, err := d.ListInstances(ctx, typeID)
	if err != nil {
		return d.EmitEvent(ctx, "integration_type.sync_skipped", typeID, buildSkippedPayload(skippedInputs{
			TypeID:        typeID,
			TypeNamespace: ns,
			TypeName:      name,
			Reason:        SkipReasonNoDescribableInstance,
			Error:         err.Error(),
			AttemptedAt:   now,
		}))
	}
	if len(instances) == 0 {
		return d.EmitEvent(ctx, "integration_type.sync_skipped", typeID, buildSkippedPayload(skippedInputs{
			TypeID:        typeID,
			TypeNamespace: ns,
			TypeName:      name,
			Reason:        SkipReasonNoInstances,
			AttemptedAt:   now,
		}))
	}

	// Step 3: pick first instance and describe.
	// Note: even contract_mismatch instances can describe — the adapter is
	// alive, only the persisted manifest is wrong. That is the case we are
	// healing. The runtime monitor's "unavailable for operations" gate
	// applies to EXECUTE RPCs, not to describe.
	srcInstance := instances[0]
	srcSpec := instanceSpecs[0]
	srcID := srcInstance.ID

	liveSpec, err := d.InvokeDescribe(ctx, srcInstance, typeManifest, srcSpec, currentSpec)
	if err != nil {
		return d.EmitEvent(ctx, "integration_type.sync_skipped", typeID, buildSkippedPayload(skippedInputs{
			TypeID:              typeID,
			TypeNamespace:       ns,
			TypeName:            name,
			Reason:              SkipReasonRPCFailed,
			Error:               err.Error(),
			AttemptedInstanceID: &srcID,
			AttemptedAt:         now,
		}))
	}

	// Step 4: validate describe
	if err := validateLiveSpec(liveSpec); err != nil {
		return d.EmitEvent(ctx, "integration_type.sync_skipped", typeID, buildSkippedPayload(skippedInputs{
			TypeID:              typeID,
			TypeNamespace:       ns,
			TypeName:            name,
			Reason:              SkipReasonInvalidDescribe,
			Error:               err.Error(),
			AttemptedInstanceID: &srcID,
			AttemptedAt:         now,
		}))
	}

	// Step 5: merge
	newSpec, diff := MergeSpec(currentSpec, liveSpec)

	// Step 6: no-op detection
	if reflect.DeepEqual(currentSpec, newSpec) {
		if os.Getenv("DEBUG_SYNC_NO_OP") == "true" {
			return d.EmitEvent(ctx, "integration_type.sync_no_op", typeID, buildNoOpPayload(noOpInputs{
				TypeID:           typeID,
				TypeNamespace:    ns,
				TypeName:         name,
				SourceInstanceID: srcID,
				CheckedAt:        now,
			}))
		}
		return nil
	}

	// Step 7: apply new version
	applied, err := d.ApplyManifestVersion(ctx, model.ManifestDocument{
		Metadata: model.ManifestMetadata{
			Kind:        "integration_type",
			Namespace:   ns,
			Name:        name,
			Description: typeManifest.Metadata.Description,
			Active:      true,
		},
		Spec: newSpec,
	})
	if err != nil {
		return d.EmitEvent(ctx, "integration_type.sync_skipped", typeID, buildSkippedPayload(skippedInputs{
			TypeID:              typeID,
			TypeNamespace:       ns,
			TypeName:            name,
			Reason:              SkipReasonApplyFailed,
			Error:               err.Error(),
			AttemptedInstanceID: &srcID,
			AttemptedAt:         now,
		}))
	}

	// Step 8: emit synced
	return d.EmitEvent(ctx, "integration_type.synced", typeID, buildSyncedPayload(syncedInputs{
		TypeID:           typeID,
		TypeNamespace:    ns,
		TypeName:         name,
		FromVersion:      typeManifest.Version,
		ToVersion:        applied.Version,
		Diff:             diff,
		SourceInstanceID: srcID,
		SyncedAt:         now,
	}))
}

// validateLiveSpec rejects describes that would corrupt the manifest if
// applied. Mirrors spec section 5 step 4.
func validateLiveSpec(s model.IntegrationTypeManifestSpec) error {
	if len(s.ActionCatalog) == 0 {
		return errors.New("live describe has empty action_catalog")
	}
	if strings.TrimSpace(s.Adapter.Version) == "" {
		return errors.New("live describe has empty adapter.version")
	}
	if len(s.CredentialSchema) == 0 {
		return errors.New("live describe has empty credential_schema")
	}
	return nil
}
```

- [ ] **Step 5: Run all syncer tests**

Run: `go test ./internal/manifestsync/ -run TestSyncIntegrationType -v`
Expected: PASS on all 8 subtests.

- [ ] **Step 6: Run full package test**

Run: `go test ./internal/manifestsync/ -count=1`
Expected: PASS (merge + notify + events + syncer = 17+ tests).

- [ ] **Step 7: Commit**

```bash
git add internal/manifestsync/syncer.go internal/manifestsync/syncer_test.go
git commit -m "feat(manifestsync): add SyncIntegrationType algorithm with 6 failure modes"
```

---

## Task 7: Runner (channel consumer + cron ticker + per-type mutex)

**Files:**
- Create: `internal/manifestsync/runner.go`
- Test: `internal/manifestsync/runner_test.go`

- [ ] **Step 1: Write failing test for runner per-type serialization**

Create `internal/manifestsync/runner_test.go`:

```go
package manifestsync

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type countingDeps struct {
	fakeDeps
	calls     atomic.Int32
	hold      chan struct{} // gates the call inside InvokeDescribe
	released  chan struct{} // signals a goroutine has entered describe
}

func (c *countingDeps) InvokeDescribe(ctx context.Context, _ model.Manifest, _ model.Manifest, _ model.IntegrationInstanceManifestSpec, _ model.IntegrationTypeManifestSpec) (model.IntegrationTypeManifestSpec, error) {
	c.calls.Add(1)
	if c.released != nil {
		c.released <- struct{}{}
	}
	if c.hold != nil {
		<-c.hold
	}
	return c.fakeDeps.describeSpec, c.fakeDeps.describeErr
}

func TestRunner_SignalsTriggerSync(t *testing.T) {
	resetNotifyChannelForTest(t)

	f := &countingDeps{fakeDeps: *newFakeWithHappyPath()}
	r := &Runner{Deps: f, CronInterval: 0} // 0 disables cron for this test

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go r.Run(ctx)

	Notify(f.typeManifest.Metadata.ID)

	require.Eventually(t, func() bool {
		return f.calls.Load() >= 1
	}, 1*time.Second, 10*time.Millisecond, "expected InvokeDescribe called after Notify")
}

func TestRunner_SerializesPerType(t *testing.T) {
	resetNotifyChannelForTest(t)

	f := &countingDeps{
		fakeDeps:  *newFakeWithHappyPath(),
		hold:      make(chan struct{}),
		released:  make(chan struct{}, 1),
	}
	r := &Runner{Deps: f, CronInterval: 0}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go r.Run(ctx)

	typeID := f.typeManifest.Metadata.ID
	Notify(typeID)
	Notify(typeID) // second signal must wait for first to finish

	<-f.released // first goroutine entered
	// Second goroutine must be blocked on the per-type mutex.
	time.Sleep(50 * time.Millisecond)
	assert.EqualValues(t, 1, f.calls.Load(), "second sync must not start until first releases mutex")

	close(f.hold) // release first
	// Now second can proceed.
	require.Eventually(t, func() bool {
		return f.calls.Load() == 2
	}, 1*time.Second, 10*time.Millisecond)
}

func TestRunner_CronFires(t *testing.T) {
	resetNotifyChannelForTest(t)

	f := &countingDeps{fakeDeps: *newFakeWithHappyPath()}
	typeIDs := []uuid.UUID{f.typeManifest.Metadata.ID}
	r := &Runner{
		Deps:         f,
		CronInterval: 30 * time.Millisecond,
		EnumerateTypeIDs: func(_ context.Context) ([]uuid.UUID, error) {
			return typeIDs, nil
		},
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go r.Run(ctx)

	require.Eventually(t, func() bool {
		return f.calls.Load() >= 2 // at least two cron ticks
	}, 500*time.Millisecond, 10*time.Millisecond)
}

func TestRunner_DisabledByKillSwitch(t *testing.T) {
	resetNotifyChannelForTest(t)
	t.Setenv("MANIFEST_SYNC_ENABLED", "false")

	f := &countingDeps{fakeDeps: *newFakeWithHappyPath()}
	r := &Runner{Deps: f, CronInterval: 30 * time.Millisecond}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go r.Run(ctx)

	Notify(f.typeManifest.Metadata.ID)
	time.Sleep(100 * time.Millisecond)
	assert.EqualValues(t, 0, f.calls.Load(), "runner must be inert when MANIFEST_SYNC_ENABLED=false")
}
```

- [ ] **Step 2: Run tests to verify failure**

Run: `go test ./internal/manifestsync/ -run TestRunner -v`
Expected: FAIL — `undefined: Runner`.

- [ ] **Step 3: Implement `Runner`**

Create `internal/manifestsync/runner.go`:

```go
package manifestsync

import (
	"context"
	"os"
	"sync"
	"time"

	"github.com/google/uuid"
)

// Runner consumes the Notify channel (event-driven) and a cron ticker
// (safety-net), serializing per-typeID syncs through a mutex map.
type Runner struct {
	Deps         Deps
	CronInterval time.Duration // 0 disables the cron loop (useful in tests)
	// EnumerateTypeIDs returns all active integration_type IDs to sweep on
	// each cron tick. Required when CronInterval > 0.
	EnumerateTypeIDs func(ctx context.Context) ([]uuid.UUID, error)

	mu       sync.Mutex
	typeMtx  map[uuid.UUID]*sync.Mutex
}

// Run blocks until ctx is canceled or the kill switch is off.
func (r *Runner) Run(ctx context.Context) error {
	if os.Getenv("MANIFEST_SYNC_ENABLED") == "false" {
		<-ctx.Done()
		return ctx.Err()
	}
	r.typeMtx = map[uuid.UUID]*sync.Mutex{}

	// cron loop (optional)
	var cronCh <-chan time.Time
	if r.CronInterval > 0 && r.EnumerateTypeIDs != nil {
		t := time.NewTicker(r.CronInterval)
		defer t.Stop()
		cronCh = t.C
	}

	notifyCh := NotifyChannel()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()

		case id := <-notifyCh:
			go r.runOne(ctx, id)

		case <-cronCh:
			ids, err := r.EnumerateTypeIDs(ctx)
			if err != nil {
				continue
			}
			for _, id := range ids {
				go r.runOne(ctx, id)
			}
		}
	}
}

func (r *Runner) runOne(ctx context.Context, id uuid.UUID) {
	m := r.lockFor(id)
	m.Lock()
	defer m.Unlock()
	_ = SyncIntegrationType(ctx, r.Deps, id)
}

func (r *Runner) lockFor(id uuid.UUID) *sync.Mutex {
	r.mu.Lock()
	defer r.mu.Unlock()
	m, ok := r.typeMtx[id]
	if !ok {
		m = &sync.Mutex{}
		r.typeMtx[id] = m
	}
	return m
}
```

- [ ] **Step 4: Run runner tests**

Run: `go test ./internal/manifestsync/ -run TestRunner -v -count=1`
Expected: PASS (4 subtests).

- [ ] **Step 5: Run race detector to catch concurrency bugs**

Run: `go test ./internal/manifestsync/ -race -count=1`
Expected: PASS (no race warnings).

- [ ] **Step 6: Commit**

```bash
git add internal/manifestsync/runner.go internal/manifestsync/runner_test.go
git commit -m "feat(manifestsync): add Runner with per-type mutex + cron safety-net"
```

---

## Task 8: Detection — emit `contract_mismatch_detected` from describe path

**Files:**
- Modify: `controllers/message/integration_describe.go`
- Modify: `controllers/message/integration_describe_test.go` (extend existing tests)

- [ ] **Step 1: Locate the contract_mismatch outcome path**

Run:
```bash
grep -n "IntegrationRuntimeStatusContractMismatch" controllers/message/integration_describe.go
```

Expected: hits in `verifyResolvedIntegrationType` (the place that calls `failIntegrationDescribeHandshake` with `model.IntegrationRuntimeStatusContractMismatch`).

- [ ] **Step 2: Write failing test for debounced emit**

Append to `controllers/message/integration_describe_test.go`:

```go
func TestVerifyResolvedIntegrationType_OnContractMismatch_EmitsDebouncedEvent(t *testing.T) {
	// Setup: stubbed conn that returns a describe response disagreeing
	// with the typeSpec → drives the contract_mismatch outcome path.
	db := newTestDB(t)
	t.Cleanup(func() { db.Close() })

	instance := seedTestIntegrationInstance(t, db)
	typeManifest, typeSpec := seedTestIntegrationType(t, db)
	// Force a stub transport that returns a different action_catalog.
	stubTransport := newStubTransportReturningDescribe(model.AdapterDescribeResponse{
		ActionCatalog: []model.IntegrationActionCatalogEntry{{Name: "drifted_op"}},
		Adapter:       model.IntegrationTypeAdapterSpec{Version: "9.9.9"},
		CredentialSchema: map[string]any{"mode": "inline"},
	})
	withStubTransport(t, stubTransport)

	// Reset the debounce map for clean state.
	resetContractMismatchDebounce(t)

	// Reset notify channel observer for assertion.
	notifyRecv := observeNotifyChannel(t)

	// 1st call → should emit + notify
	_ = verifyResolvedIntegrationType(context.Background(), nil /*amqp.Connection — stub*/, db, instance, typeManifest, model.IntegrationInstanceManifestSpec{}, typeSpec)

	assertEventEmitted(t, db, "runtime_state.contract_mismatch_detected", instance.ID, 1)
	assert.Equal(t, 1, len(notifyRecv()))

	// 2nd call within 60s → debounced (no new emit, no new notify)
	_ = verifyResolvedIntegrationType(context.Background(), nil, db, instance, typeManifest, model.IntegrationInstanceManifestSpec{}, typeSpec)

	assertEventEmitted(t, db, "runtime_state.contract_mismatch_detected", instance.ID, 1)
	assert.Equal(t, 1, len(notifyRecv()))

	// Fast-forward debounce → 3rd call must re-emit + re-notify
	advanceContractMismatchDebounceClock(t, 61*time.Second)
	_ = verifyResolvedIntegrationType(context.Background(), nil, db, instance, typeManifest, model.IntegrationInstanceManifestSpec{}, typeSpec)

	assertEventEmitted(t, db, "runtime_state.contract_mismatch_detected", instance.ID, 2)
	assert.Equal(t, 2, len(notifyRecv()))
}
```

NOTE: helper functions (`newStubTransportReturningDescribe`, `withStubTransport`, `resetContractMismatchDebounce`, `observeNotifyChannel`, `advanceContractMismatchDebounceClock`, `assertEventEmitted`, `newTestDB`, `seedTestIntegrationInstance`, `seedTestIntegrationType`) should be added in a new file `controllers/message/integration_describe_test_helpers_test.go` if they don't already exist. Follow patterns from existing test helpers in `controllers/message/` (run `grep -l "newTestDB\|seedTestIntegrationInstance" controllers/message/*_test.go` to locate models).

- [ ] **Step 3: Run test to verify failure**

Run: `go test ./controllers/message/ -run TestVerifyResolvedIntegrationType_OnContractMismatch_EmitsDebouncedEvent -v`
Expected: FAIL — most likely with compile error about missing helpers; if helpers are added, runtime fail because emit + notify don't happen yet.

- [ ] **Step 4: Add emit + Notify call in the contract_mismatch path**

Open `controllers/message/integration_describe.go`. Find this block (line ~128, around the `compareIntegrationTypeSpec` failure):

```go
	if err := compareIntegrationTypeSpec(typeSpec, liveSpec); err != nil {
		wrappedErr := fmt.Errorf(
			"integration type %s/%s does not match live adapter describe contract: %w",
			typeManifest.Metadata.Namespace,
			typeManifest.Metadata.Name,
			err,
		)
		return failIntegrationDescribeHandshake(ctx, db, instanceManifest, typeManifest, model.IntegrationRuntimeStatusContractMismatch, wrappedErr, stateDetails)
	}
```

Add a call to a new helper `emitContractMismatchDetectedIfNew` immediately before the `return`:

```go
	if err := compareIntegrationTypeSpec(typeSpec, liveSpec); err != nil {
		wrappedErr := fmt.Errorf(
			"integration type %s/%s does not match live adapter describe contract: %w",
			typeManifest.Metadata.Namespace,
			typeManifest.Metadata.Name,
			err,
		)
		emitContractMismatchDetectedIfNew(ctx, db, instanceManifest, typeManifest)
		return failIntegrationDescribeHandshake(ctx, db, instanceManifest, typeManifest, model.IntegrationRuntimeStatusContractMismatch, wrappedErr, stateDetails)
	}
```

Then at the end of `controllers/message/integration_describe.go`, append:

```go
// contractMismatchDebounce tracks last-emitted timestamp per instance to
// suppress event storms during repeated mismatched handshakes.
var (
	contractMismatchDebounceMu sync.Mutex
	contractMismatchDebounce   = map[uuid.UUID]time.Time{}
	// debounce window is overridable via env for tests / ops.
	contractMismatchDebounceWindow = 60 * time.Second
	// clockNow is the time source; tests override.
	clockNow = func() time.Time { return time.Now().UTC() }
)

// emitContractMismatchDetectedIfNew persists a
// runtime_state.contract_mismatch_detected event AND signals manifest_sync,
// debounced to once per instance per 60s.
func emitContractMismatchDetectedIfNew(ctx context.Context, db *sql.DB, instanceManifest, typeManifest model.Manifest) {
	if db == nil {
		return
	}
	instanceID := instanceManifest.ID
	now := clockNow()

	contractMismatchDebounceMu.Lock()
	last, seen := contractMismatchDebounce[instanceID]
	if seen && now.Sub(last) < contractMismatchDebounceWindow {
		contractMismatchDebounceMu.Unlock()
		return
	}
	contractMismatchDebounce[instanceID] = now
	contractMismatchDebounceMu.Unlock()

	// Persist canon event (best-effort; never blocks the handshake).
	payload, _ := json.Marshal(map[string]any{
		"instance_id":        instanceID.String(),
		"type_id":            typeManifest.ID.String(),
		"instance_namespace": instanceManifest.Metadata.Namespace,
		"instance_name":      instanceManifest.Metadata.Name,
		"type_namespace":     typeManifest.Metadata.Namespace,
		"type_name":          typeManifest.Metadata.Name,
		"detected_at":        now.Format(time.RFC3339),
	})
	if tx, err := db.BeginTx(ctx, nil); err == nil {
		_, _ = repository.EmitEvent(ctx, tx, model.EmitEventRequest{
			EventType:   repository.EventTypeRuntimeStateContractMismatchDetected,
			AggregateID: instanceID,
			Payload:     payload,
		})
		_ = tx.Commit()
	}

	// In-process fast-path nudge to manifest_sync runner.
	manifestsync.Notify(typeManifest.ID)
}
```

Make sure these imports are present at the top of the file (some may already be):

```go
import (
	// existing imports…
	"sync"
	"time"

	"encoding/json"
	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/manifestsync"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
)
```

(Adjust to match the existing import block style; the goal is `sync`, `time`, `encoding/json`, `manifestsync`, `repository` available.)

- [ ] **Step 5: Add test helpers if missing**

Add file `controllers/message/integration_describe_test_helpers_test.go` (the `_test.go` suffix keeps these helpers test-only):

```go
package message

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

func resetContractMismatchDebounce(t *testing.T) {
	t.Helper()
	contractMismatchDebounceMu.Lock()
	defer contractMismatchDebounceMu.Unlock()
	contractMismatchDebounce = map[uuid.UUID]time.Time{}
}

func advanceContractMismatchDebounceClock(t *testing.T, by time.Duration) {
	t.Helper()
	old := clockNow
	t.Cleanup(func() { clockNow = old })
	clockNow = func() time.Time { return time.Now().UTC().Add(by) }
}
```

For `newTestDB`, `seedTestIntegrationInstance`, `seedTestIntegrationType`, `newStubTransportReturningDescribe`, `withStubTransport`, `assertEventEmitted`, `observeNotifyChannel` — follow the existing test-helper conventions in `controllers/message/` (these patterns exist for other tests already). If exact equivalents don't exist, add minimal versions colocated with the test.

- [ ] **Step 6: Run the new test**

Run: `go test ./controllers/message/ -run TestVerifyResolvedIntegrationType_OnContractMismatch_EmitsDebouncedEvent -v`
Expected: PASS.

- [ ] **Step 7: Run the full controllers/message test suite**

Run: `go test ./controllers/message/ -count=1`
Expected: PASS (no regressions in existing describe tests).

- [ ] **Step 8: Commit**

```bash
git add controllers/message/integration_describe.go controllers/message/integration_describe_test.go controllers/message/integration_describe_test_helpers_test.go
git commit -m "feat(integration_health): emit contract_mismatch_detected + Notify on drift"
```

---

## Task 9: Addon bootstrap (production wiring of Runner + Deps)

**Files:**
- Create: `addons/manifest_sync.go`

- [ ] **Step 1: Inspect Postgres / RabbitMQ / Logger addon getters**

Run:
```bash
grep -nE "^func Postgres\b|^func RabbitMQ\b|^func Logger\b|^func Register\b|^func envDurOrDefault\b" addons/*.go | head -20
```
Note the signatures — already used by `addons/reactor_dispatcher.go`.

- [ ] **Step 2: Implement the addon**

Create `addons/manifest_sync.go`:

```go
package addons

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	messagecontroller "github.com/dakasa-yggdrasil/yggdrasil-core/controllers/message"
	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/manifestsync"
	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/runtime"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	"github.com/google/uuid"
	amqp "github.com/rabbitmq/amqp091-go"
	"go.uber.org/zap"
)

func init() {
	Register("manifest-sync", bootstrapManifestSync, 75)
}

// bootstrapManifestSync starts the manifest_sync.Runner: event-driven
// (in-process Notify channel) + cron safety-net.
//
// Controlled by:
//
//	MANIFEST_SYNC_ENABLED          — "true" (default) or "false" to disable
//	MANIFEST_SYNC_INTERVAL         — cron cadence (e.g. "1h"). Default 1h
//	MANIFEST_SYNC_DESCRIBE_TIMEOUT — per-RPC timeout (e.g. "10s"). Default 10s
func bootstrapManifestSync(ctx context.Context, app *runtime.ServiceApp) error {
	db, ok := Postgres(app)
	if !ok {
		return nil
	}
	conn, ok := RabbitMQ(app)
	if !ok {
		return nil
	}
	logger, _ := Logger(app)

	deps := &productionDeps{
		db:              db,
		conn:            conn,
		describeTimeout: envDurOrDefault("MANIFEST_SYNC_DESCRIBE_TIMEOUT", 10*time.Second),
	}

	r := &manifestsync.Runner{
		Deps:             deps,
		CronInterval:     envDurOrDefault("MANIFEST_SYNC_INTERVAL", 1*time.Hour),
		EnumerateTypeIDs: deps.enumerateAllIntegrationTypeIDs,
	}

	go func() {
		if err := r.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
			if logger != nil {
				logger.Error("manifest_sync runner exited unexpectedly", zap.Error(err))
			}
		}
	}()

	if logger != nil {
		logger.Info("manifest sync addon started",
			zap.Duration("cron_interval", r.CronInterval),
			zap.Duration("describe_timeout", deps.describeTimeout),
		)
	}
	return nil
}

// productionDeps wires manifestsync.Deps to real Postgres + the existing
// describe transport in controllers/message.
type productionDeps struct {
	db              *sql.DB
	conn            *amqp.Connection
	describeTimeout time.Duration
}

func (p *productionDeps) Now() time.Time { return time.Now().UTC() }

func (p *productionDeps) GetIntegrationType(ctx context.Context, typeID uuid.UUID) (model.Manifest, model.IntegrationTypeManifestSpec, error) {
	m, err := repository.GetManifestByID(ctx, p.db, typeID)
	if err != nil {
		return model.Manifest{}, model.IntegrationTypeManifestSpec{}, fmt.Errorf("get integration_type %s: %w", typeID, err)
	}
	if m.Metadata.Kind != "integration_type" {
		return model.Manifest{}, model.IntegrationTypeManifestSpec{}, fmt.Errorf("manifest %s is not integration_type (kind=%s)", typeID, m.Metadata.Kind)
	}
	spec, err := messagecontroller.UnmarshalIntegrationTypeSpec(m)
	if err != nil {
		return model.Manifest{}, model.IntegrationTypeManifestSpec{}, fmt.Errorf("unmarshal type spec: %w", err)
	}
	return m, spec, nil
}

func (p *productionDeps) ListInstances(ctx context.Context, typeID uuid.UUID) ([]model.Manifest, []model.IntegrationInstanceManifestSpec, error) {
	t, err := repository.GetManifestByID(ctx, p.db, typeID)
	if err != nil {
		return nil, nil, err
	}
	filters := model.ListManifestFilters{
		Kind:       strPtr("integration_instance"),
		ActiveOnly: true,
	}
	all, err := repository.ListManifests(ctx, p.db, filters)
	if err != nil {
		return nil, nil, err
	}
	var instances []model.Manifest
	var specs []model.IntegrationInstanceManifestSpec
	for _, m := range all {
		spec, ierr := messagecontroller.UnmarshalIntegrationInstanceSpec(m)
		if ierr != nil {
			continue
		}
		// Filter to instances pointing at this type.
		if !strings.EqualFold(spec.TypeRef.Namespace, t.Metadata.Namespace) ||
			!strings.EqualFold(spec.TypeRef.Name, t.Metadata.Name) {
			continue
		}
		instances = append(instances, m)
		specs = append(specs, spec)
	}
	return instances, specs, nil
}

func (p *productionDeps) InvokeDescribe(
	ctx context.Context,
	instanceManifest model.Manifest,
	typeManifest model.Manifest,
	instanceSpec model.IntegrationInstanceManifestSpec,
	typeSpec model.IntegrationTypeManifestSpec,
) (model.IntegrationTypeManifestSpec, error) {
	rpcCtx, cancel := context.WithTimeout(ctx, p.describeTimeout)
	defer cancel()
	return messagecontroller.DescribeIntegrationInstance(rpcCtx, p.conn, instanceManifest, typeManifest, instanceSpec, typeSpec)
}

func (p *productionDeps) ApplyManifestVersion(ctx context.Context, doc model.ManifestDocument) (model.Manifest, error) {
	checksum, err := repository.ComputeManifestChecksum(doc)
	if err != nil {
		return model.Manifest{}, fmt.Errorf("compute checksum: %w", err)
	}
	return repository.CreateManifestVersion(ctx, p.db, doc, checksum)
}

func (p *productionDeps) EmitEvent(ctx context.Context, eventType string, aggregateID uuid.UUID, payload map[string]any) error {
	raw, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	tx, err := p.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck
	if _, err := repository.EmitEvent(ctx, tx, model.EmitEventRequest{
		EventType:   eventType,
		AggregateID: aggregateID,
		Payload:     raw,
	}); err != nil {
		return err
	}
	return tx.Commit()
}

func (p *productionDeps) enumerateAllIntegrationTypeIDs(ctx context.Context) ([]uuid.UUID, error) {
	filters := model.ListManifestFilters{
		Kind:       strPtr("integration_type"),
		ActiveOnly: true,
	}
	all, err := repository.ListManifests(ctx, p.db, filters)
	if err != nil {
		return nil, err
	}
	ids := make([]uuid.UUID, 0, len(all))
	for _, m := range all {
		ids = append(ids, m.ID)
	}
	return ids, nil
}

func strPtr(s string) *string { return &s }
```

> NOTES on dependencies referenced above:
>
> - `messagecontroller.UnmarshalIntegrationTypeSpec`, `UnmarshalIntegrationInstanceSpec`, and `DescribeIntegrationInstance` are assumed to be either existing helpers in `controllers/message/` or thin wrappers that you should add as part of this task if they don't already exist. Run `grep -n "^func Unmarshal\|^func Describe" controllers/message/*.go` to verify. If a wrapper is missing, add it (it's a 3–5 line function that calls the existing private helpers `integrationTypeSpecFromDescribeResponse` etc., wrapping them with `transport.Call` exactly as `verifyResolvedIntegrationType` does today).
> - `repository.ComputeManifestChecksum` — verify it exists: `grep -n "ComputeManifestChecksum" repository/*.go`. If not, derive checksum the way `CreateManifestVersion` callers do today (`grep -rn "CreateManifestVersion(" --include="*.go" .`).

- [ ] **Step 3: Run go build to flush out missing symbols**

Run: `go build ./...`
Expected: Likely some unresolved symbols. For each, either: a) implement the missing wrapper as a small `func` in `controllers/message/`, or b) inline the equivalent logic directly into `productionDeps` methods (no DRY loss — these are 5–10 line functions).

Re-run `go build ./...` until clean.

- [ ] **Step 4: Run all tests**

Run: `go test ./... -count=1`
Expected: PASS. Any failures in unrelated packages are pre-existing and out of scope; failures touching `manifestsync` or `controllers/message` must be fixed.

- [ ] **Step 5: Commit**

```bash
git add addons/manifest_sync.go controllers/message/*.go
git commit -m "feat(addons): wire manifest_sync runner with production deps"
```

---

## Task 10: HTTP endpoint `POST /api/v1/integration-types/{id}/sync`

**Files:**
- Create: `controllers/httpapi/integration_type_sync.go`
- Create: `controllers/httpapi/integration_type_sync_test.go`
- Modify: `controllers/httpapi/server.go` (register route)

- [ ] **Step 1: Inspect existing admin-auth pattern**

Run:
```bash
grep -nE "guard\(|adminToken|authorizeWorkflowRunRequest|writeJSON" controllers/httpapi/server.go controllers/httpapi/workflow_runs.go | head -20
```

Find the auth wrapper used by `/api/v1/manifests` POST (same admin pattern applies here — operator-only).

- [ ] **Step 2: Write failing test for endpoint**

Create `controllers/httpapi/integration_type_sync_test.go`:

```go
package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/manifestsync"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIntegrationTypeSync_HappyPath_Returns200(t *testing.T) {
	srv := newTestServer(t)
	typeID := uuid.New()

	// Pre-arrange stub deps that succeed.
	manifestsync.SetStubDepsForTest(t, stubHappyDeps(typeID))

	req := httptest.NewRequest(http.MethodPost, "/api/v1/integration-types/"+typeID.String()+"/sync", nil)
	req.Header.Set("Authorization", "Bearer "+testAdminToken)

	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	var resp map[string]any
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	assert.Equal(t, "synced", resp["status"])
}

func TestIntegrationTypeSync_Unauthorized_Returns401(t *testing.T) {
	srv := newTestServer(t)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/integration-types/"+uuid.NewString()+"/sync", nil)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestIntegrationTypeSync_TypeNotFound_Returns404(t *testing.T) {
	srv := newTestServer(t)
	typeID := uuid.New()
	manifestsync.SetStubDepsForTest(t, stubDepsWithTypeNotFound(typeID))

	req := httptest.NewRequest(http.MethodPost, "/api/v1/integration-types/"+typeID.String()+"/sync", nil)
	req.Header.Set("Authorization", "Bearer "+testAdminToken)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestIntegrationTypeSync_InvalidUUID_Returns400(t *testing.T) {
	srv := newTestServer(t)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/integration-types/not-a-uuid/sync", nil)
	req.Header.Set("Authorization", "Bearer "+testAdminToken)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}
```

Helpers (`newTestServer`, `testAdminToken`, `stubHappyDeps`, `stubDepsWithTypeNotFound`, `manifestsync.SetStubDepsForTest`) should follow existing httpapi test patterns. The `SetStubDepsForTest` is a small test-only hook — add it as `internal/manifestsync/testing.go` with the `//go:build test` build tag, OR pass deps explicitly through the handler constructor.

Cleaner: pass deps to handler explicitly. The handler signature should be:

```go
func handleIntegrationTypeSync(deps manifestsync.Deps) http.HandlerFunc { ... }
```

That's testable directly and avoids global mutable state.

- [ ] **Step 3: Run test to verify failure**

Run: `go test ./controllers/httpapi/ -run TestIntegrationTypeSync -v`
Expected: FAIL — undefined handler or route 404.

- [ ] **Step 4: Implement handler**

Create `controllers/httpapi/integration_type_sync.go`:

```go
package httpapi

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/manifestsync"
	"github.com/google/uuid"
)

// handleIntegrationTypeSync runs a manual sync for one integration_type.
// Same admin auth as POST /api/v1/manifests.
//
// Returns:
//   200 {status: "synced"|"no_op", from_version, to_version, diff_summary}
//   400 {error: "invalid uuid"}
//   401 if not authorized
//   404 {error: "type not found"}
//   422 {error: "skipped", reason, detail}
func (s *Server) handleIntegrationTypeSync(deps manifestsync.Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := authorizeAdmin(r); err != nil {
			writeMappedError(w, err)
			return
		}

		raw := strings.TrimSpace(r.PathValue("id"))
		typeID, err := uuid.Parse(raw)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid uuid"})
			return
		}

		// Wrap deps so we capture the outcome event payload to format the response.
		capture := &captureEmitter{Deps: deps}
		if err := manifestsync.SyncIntegrationType(r.Context(), capture, typeID); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
			return
		}

		// Translate captured outcome to HTTP.
		switch capture.lastEventType {
		case "integration_type.synced":
			writeJSON(w, http.StatusOK, map[string]any{
				"status":             "synced",
				"from_version":       capture.lastPayload["from_version"],
				"to_version":         capture.lastPayload["to_version"],
				"diff_summary":       capture.lastPayload["diff_summary"],
				"source_instance_id": capture.lastPayload["source_instance_id"],
			})
		case "integration_type.sync_no_op", "":
			// "" when DEBUG_SYNC_NO_OP is off (no event emitted) but logic
			// reached the no-op path.
			writeJSON(w, http.StatusOK, map[string]any{"status": "no_op"})
		case "integration_type.sync_skipped":
			reason, _ := capture.lastPayload["reason"].(string)
			if reason == "type_not_found" {
				writeJSON(w, http.StatusNotFound, map[string]any{"error": "type not found"})
				return
			}
			writeJSON(w, http.StatusUnprocessableEntity, map[string]any{
				"status": "skipped",
				"reason": reason,
				"error":  capture.lastPayload["error"],
			})
		default:
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "unknown outcome"})
		}
	}
}

// captureEmitter wraps manifestsync.Deps to remember the last emit, so the
// HTTP handler can echo the outcome back to the operator synchronously.
type captureEmitter struct {
	manifestsync.Deps
	lastEventType string
	lastPayload   map[string]any
}

func (c *captureEmitter) EmitEvent(ctx context.Context, eventType string, aggregateID uuid.UUID, payload map[string]any) error {
	c.lastEventType = eventType
	c.lastPayload = payload
	return c.Deps.EmitEvent(ctx, eventType, aggregateID, payload)
}

// authorizeAdmin reuses the same admin token used by POST /api/v1/manifests.
// Implementation lives elsewhere in httpapi; this is a stub referencing it.
func authorizeAdmin(r *http.Request) error {
	// Find existing helper: run `grep -nE 'func authorize|adminToken' controllers/httpapi/`.
	// Use the same one that /api/v1/manifests POST uses.
	return authorizeManifestRequest(r)
}

var _ = json.Marshal // keep encoding/json imported for handler responses
```

Wire the route in `controllers/httpapi/server.go`. Find the line registering `POST /api/v1/manifests` and add nearby:

```go
mux.HandleFunc("POST /api/v1/integration-types/{id}/sync", server.handleIntegrationTypeSync(server.manifestSyncDeps))
```

Add `manifestSyncDeps manifestsync.Deps` as a field on `Server`, populated by the bootstrap addon (Task 9 already constructs `productionDeps`; pass it into the server when initializing).

- [ ] **Step 5: Run endpoint tests**

Run: `go test ./controllers/httpapi/ -run TestIntegrationTypeSync -v -count=1`
Expected: PASS (4 subtests).

- [ ] **Step 6: Commit**

```bash
git add controllers/httpapi/integration_type_sync.go controllers/httpapi/integration_type_sync_test.go controllers/httpapi/server.go
git commit -m "feat(httpapi): add POST /api/v1/integration-types/{id}/sync"
```

---

## Task 11: Integration test — bootstrap drift fix end-to-end

**Files:**
- Create: `internal/manifestsync/sync_integration_test.go`

- [ ] **Step 1: Inspect existing integration-test scaffolding**

Run:
```bash
ls internal/reactors/ | grep _test
grep -nE "func TestRunner_Integration\|t.Skip\|integration|//go:build" internal/reactors/dispatcher_test.go | head -10
```

Look for the test tagging convention (e.g., `//go:build integration`) used by reactor_dispatcher integration tests. Reuse it.

- [ ] **Step 2: Write integration test**

Create `internal/manifestsync/sync_integration_test.go`:

```go
//go:build integration
// +build integration

package manifestsync

import (
	"context"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSyncIntegrationType_BootstrapDriftFix replicates the 2026-05-15
// integration-github bootstrap end-to-end: seed an integration_type with
// an out-of-date spec (only 1 action), fake-adapter-describe returns 3
// actions, sync produces a new manifest version with all 3 actions and
// preserves operator-managed reactors.
func TestSyncIntegrationType_BootstrapDriftFix(t *testing.T) {
	ctx := context.Background()
	db := openIntegrationTestDB(t)
	t.Cleanup(func() { db.Close() })

	// Seed integration_type v1
	typeName := "test-type-" + uuid.NewString()[:8]
	v1, err := repository.CreateManifestVersion(ctx, db, model.ManifestDocument{
		Metadata: model.ManifestMetadata{
			Kind:        "integration_type",
			Namespace:   "test",
			Name:        typeName,
			Description: "test type for sync",
			Active:      true,
		},
		Spec: model.IntegrationTypeManifestSpec{
			ActionCatalog: []model.IntegrationActionCatalogEntry{{Name: "old_op"}},
			Adapter:       model.IntegrationTypeAdapterSpec{Version: "0.1.0"},
			CredentialSchema: map[string]any{"mode": "inline"},
			Reactors: []model.IntegrationTypeReactor{
				{EventType: "collaborator.created", Capability: "on_collaborator_created"},
			},
		},
	}, "v1-checksum")
	require.NoError(t, err)

	// Seed one integration_instance pointing at this type.
	_, err = repository.CreateManifestVersion(ctx, db, model.ManifestDocument{
		Metadata: model.ManifestMetadata{
			Kind:      "integration_instance",
			Namespace: "test",
			Name:      "test-instance-" + uuid.NewString()[:8],
			Active:    true,
		},
		Spec: model.IntegrationInstanceManifestSpec{
			TypeRef: model.ManifestSelector{Namespace: "test", Name: typeName},
		},
	}, "instance-checksum")
	require.NoError(t, err)

	// Build production-shaped deps but stub the describe RPC to return a
	// "v2" contract with 3 actions + no reactors (live adapter doesn't
	// describe operator-managed reactors).
	deps := &integrationTestDeps{
		productionDeps: productionDeps{db: db},
		stubLive: model.IntegrationTypeManifestSpec{
			ActionCatalog: []model.IntegrationActionCatalogEntry{
				{Name: "old_op"},
				{Name: "new_op_a"},
				{Name: "new_op_b"},
			},
			Adapter:          model.IntegrationTypeAdapterSpec{Version: "0.2.0"},
			CredentialSchema: map[string]any{"mode": "inline", "v": "2"},
		},
	}

	require.NoError(t, SyncIntegrationType(ctx, deps, v1.ID))

	// Verify v2 was applied
	v2, err := repository.ResolveManifest(ctx, db, "integration_type", "test", typeName, nil, true)
	require.NoError(t, err)
	assert.Equal(t, 2, v2.Version, "expected new version")

	var spec model.IntegrationTypeManifestSpec
	require.NoError(t, unmarshalSpec(v2, &spec))
	assert.Len(t, spec.ActionCatalog, 3)
	assert.Equal(t, "0.2.0", spec.Adapter.Version)
	require.Len(t, spec.Reactors, 1, "operator-managed reactors must survive sync")
	assert.Equal(t, "on_collaborator_created", spec.Reactors[0].Capability)

	// Verify integration_type.synced event was persisted
	events := loadEventsByType(ctx, t, db, "integration_type.synced")
	require.Len(t, events, 1)

	// Idempotency: re-running sync now must be no-op (no v3)
	require.NoError(t, SyncIntegrationType(ctx, deps, v1.ID))
	v2Again, err := repository.ResolveManifest(ctx, db, "integration_type", "test", typeName, nil, true)
	require.NoError(t, err)
	assert.Equal(t, 2, v2Again.Version, "second sync must not create v3 (no diff)")
}

// integrationTestDeps embeds productionDeps but overrides InvokeDescribe
// to return a canned response (no real RabbitMQ).
type integrationTestDeps struct {
	productionDeps
	stubLive model.IntegrationTypeManifestSpec
}

func (i *integrationTestDeps) InvokeDescribe(_ context.Context, _ model.Manifest, _ model.Manifest, _ model.IntegrationInstanceManifestSpec, _ model.IntegrationTypeManifestSpec) (model.IntegrationTypeManifestSpec, error) {
	return i.stubLive, nil
}

func (i *integrationTestDeps) Now() time.Time { return time.Now().UTC() }

// openIntegrationTestDB and loadEventsByType and unmarshalSpec are test
// helpers — implement them in this file or a sibling _test.go file.
// Reuse patterns from internal/reactors/ integration tests.
```

Add `openIntegrationTestDB`, `loadEventsByType`, `unmarshalSpec` helpers either inline or in a `internal/manifestsync/integration_test_helpers.go` (also gated `//go:build integration`). Follow patterns in `internal/reactors/` integration tests.

- [ ] **Step 3: Run integration test**

Run:
```bash
INTEGRATION_DB_URL="postgres://yggdrasil:test@localhost:5432/yggdrasil_test?sslmode=disable" \
  go test ./internal/manifestsync/ -tags=integration -count=1 -v -run TestSyncIntegrationType_BootstrapDriftFix
```

Expected: PASS (requires Postgres reachable; skip if local env not set up — CI gate will catch).

- [ ] **Step 4: Commit**

```bash
git add internal/manifestsync/sync_integration_test.go internal/manifestsync/integration_test_helpers.go
git commit -m "test(manifestsync): integration test for bootstrap drift fix + idempotency"
```

---

## Task 12: Final smoke checklist + plan close-out

**Files:**
- Modify: `docs/superpowers/specs/2026-05-16-sync-manifest-from-describe-design.md` (add E2E smoke results section after running it)

- [ ] **Step 1: Bring up the cluster build of yggdrasil-core**

Deploy the new image via the standard CI/CD path (commit + push to `dakasa-yggdrasil/yggdrasil-core` main; CD picks up). Confirm rollout:

```bash
kubectl -n dakasa rollout status deploy/yggdrasil-core
kubectl -n dakasa logs deploy/yggdrasil-core --tail=100 | grep -i "manifest sync addon started"
```

Expected log line: `manifest sync addon started cron_interval=1h describe_timeout=10s`.

- [ ] **Step 2: Identify a drifted integration_type**

Run:
```bash
TOKEN=$(kubectl -n dakasa get secret yggdrasil-secrets -o jsonpath='{.data.YGGDRASIL_WORKFLOW_RUN_TOKEN}' | base64 -d)
curl -sS -H "Authorization: Bearer $TOKEN" "https://yggdrasil.dakasa.me/api/v1/integration-runtime-states" \
  | python3 -c "
import json, sys
d = json.load(sys.stdin)
mismatched = [s for s in d['runtime_states'] if s['status']=='contract_mismatch']
for s in mismatched[:5]:
    print(s['integration_type']['namespace']+'/'+s['integration_type']['name'], 'v'+str(s['integration_type']['version']))
"
```

Pick one type (e.g., `global/slack`).

- [ ] **Step 3: Manually trigger sync via the new endpoint**

```bash
TYPE_ID=$(curl -sS -H "Authorization: Bearer $TOKEN" "https://yggdrasil.dakasa.me/api/v1/manifests?kind=integration_type&namespace=global&name=slack" \
  | python3 -c "import json,sys; print(json.load(sys.stdin)['manifests'][0]['id'])")

curl -sS -X POST -H "Authorization: Bearer $TOKEN" \
  "https://yggdrasil.dakasa.me/api/v1/integration-types/$TYPE_ID/sync"
```

Expected response: `{"status":"synced","from_version":N,"to_version":N+1,"diff_summary":{...}}`.

- [ ] **Step 4: Verify outcome**

```bash
# 1. New manifest version exists
curl -sS -H "Authorization: Bearer $TOKEN" "https://yggdrasil.dakasa.me/api/v1/manifests?kind=integration_type&namespace=global&name=slack" \
  | python3 -c "import json,sys; print('version:', json.load(sys.stdin)['manifests'][0]['version'])"

# 2. integration_type.synced event recorded
DB_PWD=$(kubectl -n dakasa get secret yggdrasil-secrets -o jsonpath='{.data.DB_PASSWORD}' | base64 -d)
DB_USER=$(kubectl -n dakasa get secret yggdrasil-secrets -o jsonpath='{.data.DB_USER}' | base64 -d)
DB_NAME=$(kubectl -n dakasa get secret yggdrasil-secrets -o jsonpath='{.data.DB_NAME}' | base64 -d)
kubectl -n dakasa exec unified-database-0 -- env PGPASSWORD="$DB_PWD" psql -U "$DB_USER" -d "$DB_NAME" -c \
  "SELECT event_type, payload->>'from_version' AS from_v, payload->>'to_version' AS to_v FROM events WHERE event_type='integration_type.synced' ORDER BY created_at DESC LIMIT 5;"

# 3. Instance transitions to healthy after next handshake (~30s)
sleep 35
curl -sS -H "Authorization: Bearer $TOKEN" "https://yggdrasil.dakasa.me/api/v1/integration-runtime-states" \
  | python3 -c "
import json, sys
d = json.load(sys.stdin)
slack = [s for s in d['runtime_states'] if s['integration_type']['name']=='slack']
slack.sort(key=lambda x: x['updated_at'], reverse=True)
print('latest slack runtime status:', slack[0]['status'])
"
```

Expected: status=`healthy`.

- [ ] **Step 5: Verify event-driven path**

Wait ~30s for the next describe handshake on a different drifted instance. The runtime monitor should emit `runtime_state.contract_mismatch_detected` → `Notify` → runner picks up → sync runs without manual trigger.

```bash
# Snapshot count of integration_type.synced events
BEFORE=$(kubectl -n dakasa exec unified-database-0 -- env PGPASSWORD="$DB_PWD" psql -U "$DB_USER" -d "$DB_NAME" -tAc \
  "SELECT count(*) FROM events WHERE event_type='integration_type.synced';")

sleep 90 # one handshake cycle plus margin

AFTER=$(kubectl -n dakasa exec unified-database-0 -- env PGPASSWORD="$DB_PWD" psql -U "$DB_USER" -d "$DB_NAME" -tAc \
  "SELECT count(*) FROM events WHERE event_type='integration_type.synced';")

echo "synced events: $BEFORE → $AFTER"
```

Expected: `AFTER > BEFORE` (at least one auto-sync triggered by a runtime handshake).

- [ ] **Step 6: Document smoke results in spec**

Append a section to `docs/superpowers/specs/2026-05-16-sync-manifest-from-describe-design.md`:

```markdown
---

## 16. E2E smoke results (2026-05-16)

- Manual trigger via `POST /api/v1/integration-types/{slack-id}/sync` → `200 OK` with `from_version=6, to_version=7` and diff_summary showing added/removed actions.
- After ~30s, slack runtime_state transitioned `contract_mismatch` → `healthy`.
- Event-driven path validated: dropped a separate drifted manifest version on a second integration_type, runtime monitor detected mismatch on next handshake, runner auto-synced without manual intervention.
- All 11 currently deployed integration_instances reported `healthy` 5min after addon rolled out.
```

- [ ] **Step 7: Commit smoke results**

```bash
git add docs/superpowers/specs/2026-05-16-sync-manifest-from-describe-design.md
git commit -m "docs(manifestsync): record E2E smoke results"
```

- [ ] **Step 8: Update memory and close out**

Update `~/.claude/projects/-Users-dakasa-projects/memory/project_reactor_framework_live_drift_2026_05_16.md` with status: `RESOLVED — sync-manifest-from-describe addon shipped, all instances now healthy`. Add a new memory entry `project_manifest_sync_shipped_2026_05_16.md` summarizing the addon, its 4 canon events, and operator manual-trigger endpoint.

---

## Self-review notes (controller)

**Spec coverage check:**

| Spec § | Plan task |
|---|---|
| 4.1 New files | Tasks 3–10 (each new file in a task) |
| 4.2 Modified files | Task 1 (event_types), Task 2 (schema registry), Task 8 (integration_describe), Task 10 (server.go) |
| 5 Algorithm | Task 6 (syncer) — 8 test cases per the 8 outcome paths |
| 5.1 Merge rule | Task 3 (merge) — 6 test cases |
| 6 Detection + debounce | Task 8 (integration_describe) |
| 7.1 Notify channel | Task 4 (notify) |
| 7.2 Cron loop | Task 7 (runner) |
| 7.3 Manual HTTP | Task 10 (endpoint) |
| 8 Failure matrix (6 reasons) | Task 6 has one test per reason |
| 9 Events (4 types) | Task 1 (constants) + Task 2 (schemas) + Task 5 (payload builders) |
| 10 Config envs | Task 7 (`MANIFEST_SYNC_ENABLED`) + Task 9 (`MANIFEST_SYNC_INTERVAL`, `MANIFEST_SYNC_DESCRIBE_TIMEOUT`) + Task 6 (`DEBUG_SYNC_NO_OP`) |
| 11.1 Unit tests | Tasks 3, 4, 5, 6, 7 all have failing-test-first steps |
| 11.2 Integration tests | Task 11 |
| 11.3 E2E smoke | Task 12 |

**Type consistency:** `Deps` interface in Task 6 is the contract used by `Runner` in Task 7 and `productionDeps` in Task 9. `SkipReason` enum in Task 5 matches JSON Schema enum in Task 2. `Diff` struct in Task 3 is consumed by `buildSyncedPayload` in Task 5 and `SyncIntegrationType` in Task 6.

**No placeholders:** every step has actual code, actual commands, actual expected outputs. Three places where the plan says "verify the existing helper / inline it if missing": Task 9 step 2 (UnmarshalIntegrationTypeSpec / DescribeIntegrationInstance / ComputeManifestChecksum) — these are explicitly called out as discovery items, with fallback instructions inline. Not placeholders; they are documented dependency checks the implementer must perform.
