# Integration Surfaces — Phase 0b: yggdrasil-core Discovery Implementation Plan (REVISED 2026-05-18)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Extend yggdrasil-core with the backend for federated integration surfaces — `integration_surfaces` table (migration 00042), HTTP handlers under `/api/v1/integration-surfaces*`, an `on_surface_query` proxy, a manifest discovery loop, and 4 canon events.

**COEXISTENCE:** This adds a NEW system alongside the existing server-driven `internal/surface/` + `surface_manifests` (migration 00033) + `/api/v1/ops/surfaces*` system. The old system stays untouched.

**Real codebase patterns used** (verified 2026-05-18 via deep inspection):
- Events: JSON schemas at `docs/contracts/events/v1/<group>/<event>.json`; emission via `repository.EmitEvent(ctx, *sql.Tx, model.EmitEventRequest)`; validation through `docs/contracts.ValidateEventPayload`. **No central event-name constant registry — bare strings inlined at call sites.**
- Operations: bare strings, no enum. New `on_surface_query` lives as a `const OperationOnSurfaceQuery = "on_surface_query"` in `model/operations.go` (NEW file — no existing home).
- manifest_sync: `internal/manifestsync/syncer.go` exposes `SyncIntegrationType(ctx, Deps, typeID)` for integration_types only. The new `integration_surfaces` reconciliation is a SEPARATE concept (it reconciles repo-side YAML manifests, not adapter-described specs), so we add a NEW addon `addons/integration_surface_sync.go` rather than reusing/extending `manifestsync.Syncer`.
- Adapter dispatch: `internal/reactors.Caller.Call(ctx, instanceID, capability, payload []byte) error` (fire-and-forget AMQP) OR `controllers/message/integrations.executeIntegrationRequest(ctx, conn, db, req, 0)` (synchronous RPC). For the HTTP proxy we use synchronous (the latter pattern).
- HTTP routing: `mux.HandleFunc("POST /api/v1/.../{id}/...", ...)` in `controllers/httpapi/server.go`. Helpers: `writeJSON`, `writeJSONError`, `writeMappedError`. Path params: `r.PathValue("id")`.
- DB tests: `DB_URL` env var, skip if absent. Define `openTestDB` helper per test file. Use `t.Cleanup()`.
- Migration numbering: highest existing `00041`; next free is **`00042`** (00040 was skipped — confirmed by inspection).
- Service bootstrap: `main.go` at repo root (NOT `cmd/yggdrasil-core/main.go`). Addons registered via `init()` in `addons/`.

**Tech Stack:** Go 1.22+, PostgreSQL with goose, standard `net/http` (Go 1.22 mux), AMQP via existing controllers.

**Spec reference:** `/Users/dakasa/projects/yggdrasil/yggdrasil-core/docs/superpowers/specs/2026-05-17-integration-surfaces-design.md` §4–§5.

**Working directory:** `/Users/dakasa/projects/yggdrasil/yggdrasil-core/`. Push direct to `main`. No co-author trailers.

---

## Task 1: Migration `00042_integration_surfaces.sql`

**Files:**
- Create: `db/migrations/00042_integration_surfaces.sql`

- [ ] **Step 1: Verify 00042 is free**

```bash
ls db/migrations/ | sort | tail -5
```

Expected highest existing migration: `00041_collaborator_external_identities.sql`. If `00042` is now taken (someone else added a migration since), renumber this plan's references to the next free number.

- [ ] **Step 2: Write migration**

`db/migrations/00042_integration_surfaces.sql`:

```sql
-- +goose Up
-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS integration_surfaces (
    id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name             text NOT NULL UNIQUE,
    integration_type text,
    category         text NOT NULL CHECK (category IN ('integration','core','domain')),
    spec             jsonb NOT NULL,
    active           boolean NOT NULL DEFAULT true,
    registered_at    timestamptz NOT NULL DEFAULT now(),
    updated_at       timestamptz NOT NULL DEFAULT now()
);

-- Note: no FK to integration_types(name) — that table is keyed by uuid, and surfaces
-- reference integration_types by their canonical name string. Enforcement is at the
-- application layer (the syncer rejects unknown types).

CREATE INDEX IF NOT EXISTS integration_surfaces_active_idx
    ON integration_surfaces (active) WHERE active;

CREATE INDEX IF NOT EXISTS integration_surfaces_appears_on_idx
    ON integration_surfaces USING gin ((spec->'display'->'appears_on'));

CREATE INDEX IF NOT EXISTS integration_surfaces_integration_type_idx
    ON integration_surfaces (integration_type) WHERE active;

DROP TRIGGER IF EXISTS integration_surfaces_touch_updated_at ON integration_surfaces;
CREATE TRIGGER integration_surfaces_touch_updated_at
    BEFORE UPDATE ON integration_surfaces
    FOR EACH ROW EXECUTE FUNCTION public.touch_updated_at();
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS integration_surfaces CASCADE;
-- +goose StatementEnd
```

- [ ] **Step 3: Apply locally + verify**

```bash
goose -dir db/migrations postgres "$DATABASE_URL" up
psql "$DATABASE_URL" -c "\d integration_surfaces"
```

Expected: table with 8 columns, 3 indexes, 1 trigger.

- [ ] **Step 4: Commit**

```bash
git add db/migrations/00042_integration_surfaces.sql
git commit -m "feat(db): integration_surfaces table + indexes (federated surfaces, coexists with surface_manifests)"
```

---

## Task 2: Operation constant `on_surface_query`

**Files:**
- Create: `model/operations.go` (NEW file — no existing home for operation constants)

- [ ] **Step 1: Search for any existing similar constants**

```bash
grep -rn '"on_collaborator_created"\|"on_list_identities"\|WorkflowDispatchOperation' model/ controllers/ internal/ 2>/dev/null | head -10
```

Expected output shows operation names as bare strings, with the only related const being `model.WorkflowDispatchOperation = "dispatch_workflow"` in `model/workflow.go`.

- [ ] **Step 2: Write operations.go**

`model/operations.go`:

```go
package model

// Operation name constants for adapter capabilities. Until this file existed,
// these names were bare strings inlined at call sites — that pattern continues
// for legacy operations (on_collaborator_*, on_list_identities, etc.) but new
// operations should be declared here for discoverability.

// OperationOnSurfaceQuery is the adapter capability invoked by the
// /api/v1/integrations/{instance_id}/surface-query HTTP proxy. The
// adapter receives {query_name, params} as Input and returns provider-
// specific JSON in Output. See spec 2026-05-17-integration-surfaces §5.5.
const OperationOnSurfaceQuery = "on_surface_query"
```

- [ ] **Step 3: Write a trivial compile-check test**

`model/operations_test.go`:

```go
package model

import "testing"

func TestOperationOnSurfaceQuery_StableValue(t *testing.T) {
	if OperationOnSurfaceQuery != "on_surface_query" {
		t.Errorf("constant value = %q", OperationOnSurfaceQuery)
	}
}
```

- [ ] **Step 4: Run**

```bash
GOWORK=/Users/dakasa/projects/dakasa/go.work go test ./model/...
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add model/operations.go model/operations_test.go
git commit -m "feat(model): OperationOnSurfaceQuery constant (first in model/operations.go)"
```

---

## Task 3: Domain types in `internal/integrationsurfaces/`

**Files:**
- Create: `internal/integrationsurfaces/types.go`
- Create: `internal/integrationsurfaces/types_test.go`

- [ ] **Step 1: Failing test**

`internal/integrationsurfaces/types_test.go`:

```go
package integrationsurfaces

import (
	"encoding/json"
	"testing"
)

func TestManifestSpec_RoundTrip(t *testing.T) {
	raw := []byte(`{
		"category":"integration",
		"runtime":{"kind":"spa","base_path":"/s/slack","health_path":"/healthz"},
		"display":{"title":"Slack","appears_on":["ops-integrations","console-home"]},
		"core_contracts":["authorization","external_identity"],
		"capabilities":[{"name":"integration-admin","tabs":["overview","drift"]}]
	}`)
	var s ManifestSpec
	if err := json.Unmarshal(raw, &s); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if s.Runtime.Kind != "spa" {
		t.Errorf("runtime.kind = %q", s.Runtime.Kind)
	}
	if got := len(s.Display.AppearsOn); got != 2 {
		t.Errorf("appears_on count = %d", got)
	}
}

func TestIsValidSlot(t *testing.T) {
	want := []string{"console-home", "ops-integrations", "me", "equipe", "orgchart", "colaborador-detail"}
	for _, s := range want {
		if !IsValidSlot(s) {
			t.Errorf("expected %q valid", s)
		}
	}
	if IsValidSlot("unknown") {
		t.Error("unknown should be invalid")
	}
}
```

- [ ] **Step 2: Run — expect FAIL**

`GOWORK=/Users/dakasa/projects/dakasa/go.work go test ./internal/integrationsurfaces/...`

Expected: FAIL — package doesn't exist.

- [ ] **Step 3: Implement types.go**

`internal/integrationsurfaces/types.go`:

```go
package integrationsurfaces

import "time"

type Category string

const (
	CategoryIntegration Category = "integration"
	CategoryCore        Category = "core"
	CategoryDomain      Category = "domain"
)

type Manifest struct {
	ID              string       `json:"id"`
	Name            string       `json:"name"`
	IntegrationType *string      `json:"integration_type,omitempty"`
	Category        Category     `json:"category"`
	Spec            ManifestSpec `json:"spec"`
	Active          bool         `json:"active"`
	RegisteredAt    time.Time    `json:"registered_at"`
	UpdatedAt       time.Time    `json:"updated_at"`
}

type ManifestSpec struct {
	Category      Category         `json:"category"`
	Owners        []string         `json:"owners,omitempty"`
	Runtime       Runtime          `json:"runtime"`
	Display       Display          `json:"display"`
	CoreContracts []string         `json:"core_contracts,omitempty"`
	Capabilities  []CapabilitySpec `json:"capabilities,omitempty"`
}

type Runtime struct {
	Kind       string `json:"kind"` // "spa" | "http_api"
	Exposure   string `json:"exposure,omitempty"`
	BasePath   string `json:"base_path"`
	HealthPath string `json:"health_path,omitempty"`
	Image      string `json:"image,omitempty"`
}

type Display struct {
	Title      string   `json:"title"`
	Subtitle   string   `json:"subtitle,omitempty"`
	Icon       string   `json:"icon,omitempty"`
	ColorToken string   `json:"color_token,omitempty"`
	AppearsOn  []string `json:"appears_on,omitempty"`
}

type CapabilitySpec struct {
	Name string   `json:"name"`
	Tabs []string `json:"tabs,omitempty"`
}

var validSlots = map[string]struct{}{
	"console-home":       {},
	"ops-integrations":   {},
	"me":                 {},
	"equipe":             {},
	"orgchart":           {},
	"colaborador-detail": {},
}

func IsValidSlot(s string) bool {
	_, ok := validSlots[s]
	return ok
}
```

- [ ] **Step 4: Run — expect PASS**

Expected: 2 tests PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/integrationsurfaces
git commit -m "feat(integrationsurfaces): domain types Manifest, ManifestSpec, slot enum"
```

---

## Task 4: Repository

**Files:**
- Create: `internal/integrationsurfaces/repository.go`
- Create: `internal/integrationsurfaces/repository_integration_test.go`

- [ ] **Step 1: Failing integration test (uses real DB via DB_URL)**

`internal/integrationsurfaces/repository_integration_test.go`:

```go
package integrationsurfaces_test

import (
	"context"
	"database/sql"
	"os"
	"testing"

	_ "github.com/lib/pq"
	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/integrationsurfaces"
)

func openTestDB(t *testing.T) *sql.DB {
	t.Helper()
	dsn := os.Getenv("DB_URL")
	if dsn == "" {
		t.Skip("DB_URL not set; skipping integrationsurfaces integration test")
	}
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := db.Ping(); err != nil {
		t.Fatalf("ping: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func cleanup(t *testing.T, db *sql.DB, name string) {
	t.Helper()
	_, _ = db.Exec("DELETE FROM integration_surfaces WHERE name = $1", name)
}

func TestRepository_UpsertGetSoftDeleteByName(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)
	repo := integrationsurfaces.NewRepository(db)
	cleanup(t, db, "surface-test-a")
	t.Cleanup(func() { cleanup(t, db, "surface-test-a") })

	intType := "slack"
	m := integrationsurfaces.Manifest{
		Name:            "surface-test-a",
		IntegrationType: &intType,
		Category:        integrationsurfaces.CategoryIntegration,
		Spec: integrationsurfaces.ManifestSpec{
			Category: integrationsurfaces.CategoryIntegration,
			Runtime:  integrationsurfaces.Runtime{Kind: "spa", BasePath: "/s/test-a"},
			Display:  integrationsurfaces.Display{Title: "Test A", AppearsOn: []string{"ops-integrations"}},
		},
		Active: true,
	}
	if err := repo.Upsert(ctx, &m); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	if m.ID == "" {
		t.Fatal("expected ID populated after upsert")
	}

	got, err := repo.GetByName(ctx, "surface-test-a")
	if err != nil {
		t.Fatalf("GetByName: %v", err)
	}
	if got.Spec.Display.Title != "Test A" {
		t.Errorf("title = %q", got.Spec.Display.Title)
	}

	if err := repo.Deactivate(ctx, "surface-test-a"); err != nil {
		t.Fatalf("Deactivate: %v", err)
	}
	got, _ = repo.GetByName(ctx, "surface-test-a")
	if got.Active {
		t.Error("expected active=false after Deactivate")
	}
}

func TestRepository_List_FilterByAppearsOn(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)
	repo := integrationsurfaces.NewRepository(db)
	cleanup(t, db, "surface-test-b")
	cleanup(t, db, "surface-test-c")
	t.Cleanup(func() { cleanup(t, db, "surface-test-b"); cleanup(t, db, "surface-test-c") })

	mk := func(name string, slots []string) integrationsurfaces.Manifest {
		return integrationsurfaces.Manifest{
			Name:     name,
			Category: integrationsurfaces.CategoryIntegration,
			Spec: integrationsurfaces.ManifestSpec{
				Category: integrationsurfaces.CategoryIntegration,
				Display:  integrationsurfaces.Display{Title: name, AppearsOn: slots},
			},
			Active: true,
		}
	}
	a := mk("surface-test-b", []string{"ops-integrations", "console-home"})
	b := mk("surface-test-c", []string{"me"})
	_ = repo.Upsert(ctx, &a)
	_ = repo.Upsert(ctx, &b)

	items, err := repo.List(ctx, integrationsurfaces.ListFilter{AppearsOn: "ops-integrations"})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, m := range items {
		if m.Name == "surface-test-b" {
			found = true
		}
		if m.Name == "surface-test-c" {
			t.Errorf("surface-test-c should not match appears_on=ops-integrations")
		}
	}
	if !found {
		t.Error("surface-test-b not in results")
	}
}
```

- [ ] **Step 2: Run — expect FAIL**

`GOWORK=/Users/dakasa/projects/dakasa/go.work go test ./internal/integrationsurfaces/...`

Expected: compile error — `NewRepository` undefined.

- [ ] **Step 3: Implement repository.go**

`internal/integrationsurfaces/repository.go`:

```go
package integrationsurfaces

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
)

var ErrNotFound = errors.New("integration surface not found")

type Repository struct {
	db *sql.DB
}

func NewRepository(db *sql.DB) *Repository {
	return &Repository{db: db}
}

func (r *Repository) Upsert(ctx context.Context, m *Manifest) error {
	specJSON, err := json.Marshal(m.Spec)
	if err != nil {
		return fmt.Errorf("marshal spec: %w", err)
	}
	const q = `
INSERT INTO integration_surfaces (name, integration_type, category, spec, active)
VALUES ($1, $2, $3, $4, $5)
ON CONFLICT (name) DO UPDATE
SET integration_type = EXCLUDED.integration_type,
    category = EXCLUDED.category,
    spec = EXCLUDED.spec,
    active = EXCLUDED.active
RETURNING id, registered_at, updated_at`

	row := r.db.QueryRowContext(ctx, q, m.Name, m.IntegrationType, string(m.Category), specJSON, m.Active)
	return row.Scan(&m.ID, &m.RegisteredAt, &m.UpdatedAt)
}

func (r *Repository) GetByName(ctx context.Context, name string) (*Manifest, error) {
	const q = `
SELECT id, name, integration_type, category, spec, active, registered_at, updated_at
FROM integration_surfaces
WHERE name = $1`
	var (
		m       Manifest
		specRaw []byte
		intType sql.NullString
		cat     string
	)
	err := r.db.QueryRowContext(ctx, q, name).Scan(
		&m.ID, &m.Name, &intType, &cat, &specRaw, &m.Active, &m.RegisteredAt, &m.UpdatedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("query: %w", err)
	}
	if intType.Valid {
		s := intType.String
		m.IntegrationType = &s
	}
	m.Category = Category(cat)
	if err := json.Unmarshal(specRaw, &m.Spec); err != nil {
		return nil, fmt.Errorf("unmarshal spec: %w", err)
	}
	return &m, nil
}

type ListFilter struct {
	AppearsOn       string
	IntegrationType string
	Category        string
}

func (r *Repository) List(ctx context.Context, f ListFilter) ([]Manifest, error) {
	where := "active = true"
	args := []any{}
	i := 1
	if f.AppearsOn != "" {
		where += fmt.Sprintf(" AND spec->'display'->'appears_on' @> $%d::jsonb", i)
		args = append(args, fmt.Sprintf(`["%s"]`, f.AppearsOn))
		i++
	}
	if f.IntegrationType != "" {
		where += fmt.Sprintf(" AND integration_type = $%d", i)
		args = append(args, f.IntegrationType)
		i++
	}
	if f.Category != "" {
		where += fmt.Sprintf(" AND category = $%d", i)
		args = append(args, f.Category)
		i++
	}

	q := fmt.Sprintf(`
SELECT id, name, integration_type, category, spec, active, registered_at, updated_at
FROM integration_surfaces
WHERE %s
ORDER BY updated_at DESC`, where)

	rows, err := r.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []Manifest{}
	for rows.Next() {
		var (
			m       Manifest
			specRaw []byte
			intType sql.NullString
			cat     string
		)
		if err := rows.Scan(&m.ID, &m.Name, &intType, &cat, &specRaw, &m.Active, &m.RegisteredAt, &m.UpdatedAt); err != nil {
			return nil, err
		}
		if intType.Valid {
			s := intType.String
			m.IntegrationType = &s
		}
		m.Category = Category(cat)
		if err := json.Unmarshal(specRaw, &m.Spec); err != nil {
			return nil, fmt.Errorf("unmarshal spec for %s: %w", m.Name, err)
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

func (r *Repository) Deactivate(ctx context.Context, name string) error {
	res, err := r.db.ExecContext(ctx, `UPDATE integration_surfaces SET active = false WHERE name = $1`, name)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

func (r *Repository) Touch(ctx context.Context, name string) error {
	res, err := r.db.ExecContext(ctx, `UPDATE integration_surfaces SET updated_at = now() WHERE name = $1`, name)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}
```

- [ ] **Step 4: Run with DB**

```bash
export DB_URL="postgres://yggdrasil:yggdrasil@localhost:5432/yggdrasil?sslmode=disable"
GOWORK=/Users/dakasa/projects/dakasa/go.work go test ./internal/integrationsurfaces/... -v
```

Expected: 4 tests PASS (2 from types_test + 2 from repository_integration_test). If DB_URL unset, repository tests SKIP — that's acceptable.

- [ ] **Step 5: Commit**

```bash
git add internal/integrationsurfaces/repository.go internal/integrationsurfaces/repository_integration_test.go
git commit -m "feat(integrationsurfaces): repository — Upsert, GetByName, List(filter), Deactivate, Touch"
```

---

## Task 5: Event JSON schemas

**Files:**
- Create: `docs/contracts/events/v1/integration_surface/registered.json`
- Create: `docs/contracts/events/v1/integration_surface/updated.json`
- Create: `docs/contracts/events/v1/integration_surface/deactivated.json`
- Create: `docs/contracts/events/v1/integration_surface/drift_detected.json`

- [ ] **Step 1: Inspect an existing schema for shape**

```bash
cat docs/contracts/events/v1/manifest/created.json
```

Note the JSON Schema draft used (`http://json-schema.org/draft-07/schema#` or similar), the `required` set, and `additionalProperties` convention.

- [ ] **Step 2: Write `registered.json`**

`docs/contracts/events/v1/integration_surface/registered.json`:

```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "title": "integration_surface.registered",
  "type": "object",
  "required": ["surface_name", "category", "registered_at"],
  "properties": {
    "surface_name":     { "type": "string", "minLength": 1 },
    "integration_type": { "type": ["string", "null"] },
    "category":         { "type": "string", "enum": ["integration", "core", "domain"] },
    "registered_at":    { "type": "string", "format": "date-time" },
    "spec":             { "type": "object" }
  },
  "additionalProperties": false
}
```

- [ ] **Step 3: Write `updated.json`**

```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "title": "integration_surface.updated",
  "type": "object",
  "required": ["surface_name", "new_spec_hash", "updated_at"],
  "properties": {
    "surface_name":     { "type": "string", "minLength": 1 },
    "integration_type": { "type": ["string", "null"] },
    "prev_spec_hash":   { "type": ["string", "null"] },
    "new_spec_hash":    { "type": "string", "minLength": 1 },
    "updated_at":       { "type": "string", "format": "date-time" }
  },
  "additionalProperties": false
}
```

- [ ] **Step 4: Write `deactivated.json`**

```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "title": "integration_surface.deactivated",
  "type": "object",
  "required": ["surface_name", "reason"],
  "properties": {
    "surface_name": { "type": "string", "minLength": 1 },
    "reason":       { "type": "string", "minLength": 1 }
  },
  "additionalProperties": false
}
```

- [ ] **Step 5: Write `drift_detected.json`**

```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "title": "integration_surface.drift_detected",
  "type": "object",
  "required": ["surface_name", "persisted_spec_hash", "runtime_spec_hash"],
  "properties": {
    "surface_name":         { "type": "string", "minLength": 1 },
    "persisted_spec_hash":  { "type": "string", "minLength": 1 },
    "runtime_spec_hash":    { "type": "string", "minLength": 1 }
  },
  "additionalProperties": false
}
```

- [ ] **Step 6: Verify schemas validate via `contracts.ValidateEventPayload`**

Locate the contracts package validator (`docs/contracts/` or `internal/contracts/`):

```bash
grep -rn "ValidateEventPayload" docs/contracts/ internal/contracts/ 2>/dev/null | head -3
```

If the validator auto-discovers schema files by event name (likely; it does for `manifest.created` → `docs/contracts/events/v1/manifest/created.json`), the four new files will be picked up without code changes.

If a schema registry needs explicit registration, look at how existing schemas register (likely a `go:embed` block or filesystem walk in `docs/contracts/validator.go`). Add the new files to the registration as required.

- [ ] **Step 7: Smoke-validate one payload**

Create a throwaway Go program (or `go test` snippet) that calls `contracts.ValidateEventPayload("integration_surface.registered", "v1", payload)` with a sample payload and expects no error:

```go
// _scratch/validate_check.go (delete after running)
package main

import (
	"fmt"
	"github.com/dakasa-yggdrasil/yggdrasil-core/docs/contracts"
)

func main() {
	payload := map[string]any{
		"surface_name":     "surface-slack",
		"integration_type": "slack",
		"category":         "integration",
		"registered_at":    "2026-05-18T12:00:00Z",
		"spec":             map[string]any{},
	}
	if err := contracts.ValidateEventPayload("integration_surface.registered", "v1", payload); err != nil {
		panic(err)
	}
	fmt.Println("ok")
}
```

```bash
GOWORK=/Users/dakasa/projects/dakasa/go.work go run _scratch/validate_check.go
```

Expected: prints `ok`. If FAIL: schema registration didn't auto-discover; add explicit registration per existing pattern.

- [ ] **Step 8: Cleanup scratch file**

```bash
rm -rf _scratch/
```

- [ ] **Step 9: Commit**

```bash
git add docs/contracts/events/v1/integration_surface/
git commit -m "feat(events): 4 integration_surface canon event schemas (registered/updated/deactivated/drift_detected)"
```

---

## Task 6: Reconciler — `internal/integrationsurfaces/syncer.go`

**Files:**
- Create: `internal/integrationsurfaces/syncer.go`
- Create: `internal/integrationsurfaces/syncer_test.go`

- [ ] **Step 1: Failing test (uses in-memory event recorder)**

`internal/integrationsurfaces/syncer_test.go`:

```go
package integrationsurfaces_test

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/integrationsurfaces"
)

// fakeEmitter captures emitted events without DB or schema validation
// (the schema validation is exercised by the standalone smoke in Task 5).
type fakeEmitter struct {
	calls []emittedEvent
}

type emittedEvent struct {
	EventType   string
	AggregateID string
	Payload     map[string]any
}

func (f *fakeEmitter) Emit(_ context.Context, eventType, aggregateID string, payload map[string]any) error {
	f.calls = append(f.calls, emittedEvent{eventType, aggregateID, payload})
	return nil
}

// fakeStore is an in-memory replacement for the Repository — keyed by manifest name.
type fakeStore struct {
	store map[string]*integrationsurfaces.Manifest
}

func newFakeStore() *fakeStore {
	return &fakeStore{store: map[string]*integrationsurfaces.Manifest{}}
}

func (s *fakeStore) Upsert(_ context.Context, m *integrationsurfaces.Manifest) error {
	cp := *m
	cp.ID = "fake-id"
	s.store[m.Name] = &cp
	m.ID = cp.ID
	return nil
}

func (s *fakeStore) GetByName(_ context.Context, name string) (*integrationsurfaces.Manifest, error) {
	if m, ok := s.store[name]; ok {
		return m, nil
	}
	return nil, integrationsurfaces.ErrNotFound
}

func TestSyncer_ReconcileFromBytes_Insert(t *testing.T) {
	store := newFakeStore()
	em := &fakeEmitter{}
	syncer := integrationsurfaces.NewSyncer(store, em)

	body, _ := json.Marshal(map[string]any{
		"apiVersion": "yggdrasil.io/v1alpha1",
		"kind":       "integration_surface",
		"metadata":   map[string]any{"name": "surface-slack", "integration_type": "slack"},
		"spec": map[string]any{
			"category": "integration",
			"runtime":  map[string]any{"kind": "spa", "base_path": "/s/slack"},
			"display":  map[string]any{"title": "Slack", "appears_on": []any{"ops-integrations"}},
		},
	})

	report, err := syncer.ReconcileFromBytes(context.Background(), body)
	if err != nil {
		t.Fatalf("ReconcileFromBytes: %v", err)
	}
	if report.Action != "inserted" {
		t.Errorf("action = %q, want inserted", report.Action)
	}
	if got := store.store["surface-slack"]; got == nil || got.Spec.Runtime.Kind != "spa" {
		t.Errorf("not persisted as expected: %+v", got)
	}
	if len(em.calls) != 1 || em.calls[0].EventType != "integration_surface.registered" {
		t.Errorf("expected 1 registered emit; got %+v", em.calls)
	}
}

func TestSyncer_ReconcileFromBytes_NoopOnSecondApply(t *testing.T) {
	store := newFakeStore()
	em := &fakeEmitter{}
	syncer := integrationsurfaces.NewSyncer(store, em)

	body, _ := json.Marshal(map[string]any{
		"apiVersion": "yggdrasil.io/v1alpha1",
		"kind":       "integration_surface",
		"metadata":   map[string]any{"name": "surface-x"},
		"spec": map[string]any{
			"category": "integration",
			"runtime":  map[string]any{"kind": "spa", "base_path": "/s/x"},
			"display":  map[string]any{"title": "X"},
		},
	})

	if _, err := syncer.ReconcileFromBytes(context.Background(), body); err != nil {
		t.Fatal(err)
	}
	em.calls = nil

	r, err := syncer.ReconcileFromBytes(context.Background(), body)
	if err != nil {
		t.Fatal(err)
	}
	if r.Action != "noop" {
		t.Errorf("second apply should be noop; got %q", r.Action)
	}
	if len(em.calls) != 0 {
		t.Error("noop should not emit")
	}
}

func TestSyncer_RejectsWrongKind(t *testing.T) {
	syncer := integrationsurfaces.NewSyncer(newFakeStore(), &fakeEmitter{})
	body, _ := json.Marshal(map[string]any{
		"apiVersion": "yggdrasil.io/v1alpha1",
		"kind":       "surface", // old/legacy kind — should be rejected
		"metadata":   map[string]any{"name": "x"},
		"spec":       map[string]any{"category": "integration"},
	})
	if _, err := syncer.ReconcileFromBytes(context.Background(), body); err == nil {
		t.Fatal("expected error for kind=surface")
	}
}
```

- [ ] **Step 2: Run — expect FAIL**

`GOWORK=/Users/dakasa/projects/dakasa/go.work go test ./internal/integrationsurfaces/...`

Expected: compile error — `NewSyncer`, `Emitter`, `Store` undefined.

- [ ] **Step 3: Implement syncer.go**

`internal/integrationsurfaces/syncer.go`:

```go
package integrationsurfaces

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// Emitter abstracts event emission so tests don't need a real DB / schema
// validator. In production, wire it to a function that wraps
// repository.EmitEvent in a transaction (see addons/integration_surface_sync.go).
type Emitter interface {
	Emit(ctx context.Context, eventType, aggregateID string, payload map[string]any) error
}

// Store is the minimal slice of *Repository the syncer uses; tests can fake.
type Store interface {
	Upsert(ctx context.Context, m *Manifest) error
	GetByName(ctx context.Context, name string) (*Manifest, error)
}

type SyncReport struct {
	SurfaceName string
	Action      string // "inserted" | "updated" | "noop"
	NewHash     string
	PrevHash    string
}

type Syncer struct {
	store Store
	bus   Emitter
}

func NewSyncer(s Store, bus Emitter) *Syncer { return &Syncer{store: s, bus: bus} }

type rawManifest struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Metadata   struct {
		Name            string  `json:"name"`
		IntegrationType *string `json:"integration_type,omitempty"`
	} `json:"metadata"`
	Spec ManifestSpec `json:"spec"`
}

func (s *Syncer) ReconcileFromBytes(ctx context.Context, raw []byte) (SyncReport, error) {
	var rm rawManifest
	if err := json.Unmarshal(raw, &rm); err != nil {
		return SyncReport{}, fmt.Errorf("parse manifest: %w", err)
	}
	if rm.Kind != "integration_surface" {
		return SyncReport{}, fmt.Errorf("unexpected kind %q (must be integration_surface)", rm.Kind)
	}
	if rm.Metadata.Name == "" {
		return SyncReport{}, errors.New("metadata.name required")
	}

	specBytes, err := json.Marshal(rm.Spec)
	if err != nil {
		return SyncReport{}, err
	}
	sum := sha256.Sum256(specBytes)
	newHash := hex.EncodeToString(sum[:])

	existing, err := s.store.GetByName(ctx, rm.Metadata.Name)
	if errors.Is(err, ErrNotFound) {
		m := Manifest{
			Name:            rm.Metadata.Name,
			IntegrationType: rm.Metadata.IntegrationType,
			Category:        rm.Spec.Category,
			Spec:            rm.Spec,
			Active:          true,
		}
		if err := s.store.Upsert(ctx, &m); err != nil {
			return SyncReport{}, err
		}
		_ = s.bus.Emit(ctx, "integration_surface.registered", m.ID, map[string]any{
			"surface_name":     m.Name,
			"integration_type": m.IntegrationType,
			"category":         string(m.Category),
			"registered_at":    time.Now().UTC().Format(time.RFC3339),
			"spec":             unmarshalToMap(specBytes),
		})
		return SyncReport{SurfaceName: m.Name, Action: "inserted", NewHash: newHash}, nil
	}
	if err != nil {
		return SyncReport{}, err
	}

	prevBytes, _ := json.Marshal(existing.Spec)
	prevSum := sha256.Sum256(prevBytes)
	prevHash := hex.EncodeToString(prevSum[:])
	if prevHash == newHash {
		return SyncReport{SurfaceName: existing.Name, Action: "noop", NewHash: newHash, PrevHash: prevHash}, nil
	}

	existing.IntegrationType = rm.Metadata.IntegrationType
	existing.Category = rm.Spec.Category
	existing.Spec = rm.Spec
	if err := s.store.Upsert(ctx, existing); err != nil {
		return SyncReport{}, err
	}
	prevHashCopy := prevHash
	_ = s.bus.Emit(ctx, "integration_surface.updated", existing.ID, map[string]any{
		"surface_name":     existing.Name,
		"integration_type": existing.IntegrationType,
		"prev_spec_hash":   prevHashCopy,
		"new_spec_hash":    newHash,
		"updated_at":       time.Now().UTC().Format(time.RFC3339),
	})
	return SyncReport{SurfaceName: existing.Name, Action: "updated", NewHash: newHash, PrevHash: prevHash}, nil
}

func unmarshalToMap(b []byte) map[string]any {
	var m map[string]any
	_ = json.Unmarshal(b, &m)
	return m
}
```

- [ ] **Step 4: Run — expect PASS**

Expected: 3 tests PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/integrationsurfaces/syncer.go internal/integrationsurfaces/syncer_test.go
git commit -m "feat(integrationsurfaces): Syncer.ReconcileFromBytes — kind validation + hash-based diff + event emission"
```

---

## Task 7: HTTP handlers — list / get / sync

**Files:**
- Create: `controllers/httpapi/integration_surfaces.go`
- Create: `controllers/httpapi/integration_surfaces_test.go`

- [ ] **Step 1: Read an existing handler as a model**

```bash
sed -n '1,80p' controllers/httpapi/integration_type_sync.go
```

Notice the patterns: methods on `*Server`, returning `http.HandlerFunc`, using `r.PathValue(...)`, `writeJSON(w, status, payload)`, `writeMappedError(w, err)`.

- [ ] **Step 2: Failing test**

`controllers/httpapi/integration_surfaces_test.go`:

```go
package httpapi

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	_ "github.com/lib/pq"
	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/integrationsurfaces"
)

func openSurfacesTestDB(t *testing.T) *sql.DB {
	t.Helper()
	dsn := os.Getenv("DB_URL")
	if dsn == "" {
		t.Skip("DB_URL not set; skipping handler integration test")
	}
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := db.Ping(); err != nil {
		t.Fatalf("ping: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func TestHandleIntegrationSurfacesList(t *testing.T) {
	db := openSurfacesTestDB(t)
	repo := integrationsurfaces.NewRepository(db)
	ctx := context.Background()
	intType := "slack"
	m := integrationsurfaces.Manifest{
		Name:            "surface-handler-test",
		IntegrationType: &intType,
		Category:        integrationsurfaces.CategoryIntegration,
		Spec: integrationsurfaces.ManifestSpec{
			Category: integrationsurfaces.CategoryIntegration,
			Runtime:  integrationsurfaces.Runtime{Kind: "spa", BasePath: "/s/handler-test"},
			Display:  integrationsurfaces.Display{Title: "Handler Test", AppearsOn: []string{"ops-integrations"}},
		},
		Active: true,
	}
	t.Cleanup(func() { _, _ = db.Exec("DELETE FROM integration_surfaces WHERE name = $1", m.Name) })
	if err := repo.Upsert(ctx, &m); err != nil {
		t.Fatal(err)
	}

	srv := &Server{integrationSurfacesRepo: repo}
	req := httptest.NewRequest("GET", "/api/v1/integration-surfaces?appears_on=ops-integrations", nil)
	w := httptest.NewRecorder()
	srv.handleIntegrationSurfacesList()(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status %d, body %s", w.Code, w.Body.String())
	}
	var body struct {
		Items []integrationsurfaces.Manifest `json:"items"`
		Total int                            `json:"total"`
	}
	if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, it := range body.Items {
		if it.Name == m.Name {
			found = true
		}
	}
	if !found {
		t.Errorf("test manifest not in list: %+v", body)
	}
}

func TestHandleIntegrationSurfacesGet_404(t *testing.T) {
	db := openSurfacesTestDB(t)
	srv := &Server{integrationSurfacesRepo: integrationsurfaces.NewRepository(db)}
	req := httptest.NewRequest("GET", "/api/v1/integration-surfaces/surface-does-not-exist", nil)
	req.SetPathValue("name", "surface-does-not-exist")
	w := httptest.NewRecorder()
	srv.handleIntegrationSurfaceGet()(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404; body=%s", w.Code, w.Body.String())
	}
}

func TestHandleIntegrationSurfaceSync(t *testing.T) {
	db := openSurfacesTestDB(t)
	repo := integrationsurfaces.NewRepository(db)
	ctx := context.Background()
	m := integrationsurfaces.Manifest{
		Name:     "surface-touch-test",
		Category: integrationsurfaces.CategoryCore,
		Spec:     integrationsurfaces.ManifestSpec{Category: integrationsurfaces.CategoryCore, Display: integrationsurfaces.Display{Title: "T"}},
		Active:   true,
	}
	t.Cleanup(func() { _, _ = db.Exec("DELETE FROM integration_surfaces WHERE name = $1", m.Name) })
	if err := repo.Upsert(ctx, &m); err != nil {
		t.Fatal(err)
	}

	srv := &Server{integrationSurfacesRepo: repo}
	req := httptest.NewRequest("POST", "/api/v1/integration-surfaces/"+m.Name+"/sync", strings.NewReader(""))
	req.SetPathValue("name", m.Name)
	w := httptest.NewRecorder()
	srv.handleIntegrationSurfaceSync()(w, req)
	if w.Code != http.StatusAccepted {
		t.Errorf("status = %d, want 202", w.Code)
	}
}
```

- [ ] **Step 3: Run — expect FAIL**

```bash
GOWORK=/Users/dakasa/projects/dakasa/go.work go test ./controllers/httpapi/ -run IntegrationSurface
```

Expected: `Server.integrationSurfacesRepo` not declared / `handleIntegrationSurfacesList` undefined.

- [ ] **Step 4: Implement handlers**

`controllers/httpapi/integration_surfaces.go`:

```go
package httpapi

import (
	"errors"
	"net/http"
	"strings"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/integrationsurfaces"
)

// integrationSurfacesRepo is set by Server constructor wiring (Task 9).
// It exposes a minimal CRUD surface used by these handlers.

func (s *Server) handleIntegrationSurfacesList() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		f := integrationsurfaces.ListFilter{
			AppearsOn:       strings.TrimSpace(r.URL.Query().Get("appears_on")),
			IntegrationType: strings.TrimSpace(r.URL.Query().Get("integration_type")),
			Category:        strings.TrimSpace(r.URL.Query().Get("category")),
		}
		items, err := s.integrationSurfacesRepo.List(r.Context(), f)
		if err != nil {
			writeMappedError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"items": items,
			"total": len(items),
		})
	}
}

func (s *Server) handleIntegrationSurfaceGet() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := strings.TrimSpace(r.PathValue("name"))
		if name == "" {
			writeJSONError(w, http.StatusBadRequest, "missing name")
			return
		}
		m, err := s.integrationSurfacesRepo.GetByName(r.Context(), name)
		if errors.Is(err, integrationsurfaces.ErrNotFound) {
			writeJSONError(w, http.StatusNotFound, "integration surface not found")
			return
		}
		if err != nil {
			writeMappedError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, m)
	}
}

func (s *Server) handleIntegrationSurfaceSync() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := strings.TrimSpace(r.PathValue("name"))
		if name == "" {
			writeJSONError(w, http.StatusBadRequest, "missing name")
			return
		}
		if err := s.integrationSurfacesRepo.Touch(r.Context(), name); err != nil {
			if errors.Is(err, integrationsurfaces.ErrNotFound) {
				writeJSONError(w, http.StatusNotFound, "integration surface not found")
				return
			}
			writeMappedError(w, err)
			return
		}
		writeJSON(w, http.StatusAccepted, map[string]any{"sync_queued": true, "name": name})
	}
}
```

- [ ] **Step 5: Add field to `Server`**

Edit `controllers/httpapi/server.go`. Locate the `Server` struct definition and add a field:

```go
type Server struct {
    // ... existing fields ...
    integrationSurfacesRepo IntegrationSurfacesRepo
}

// IntegrationSurfacesRepo is the slice of *integrationsurfaces.Repository the handlers need.
type IntegrationSurfacesRepo interface {
    List(ctx context.Context, f integrationsurfaces.ListFilter) ([]integrationsurfaces.Manifest, error)
    GetByName(ctx context.Context, name string) (*integrationsurfaces.Manifest, error)
    Touch(ctx context.Context, name string) error
}
```

(Add the `integrationsurfaces` import.)

- [ ] **Step 6: Run — expect PASS**

```bash
DB_URL="postgres://yggdrasil:yggdrasil@localhost:5432/yggdrasil?sslmode=disable" \
  GOWORK=/Users/dakasa/projects/dakasa/go.work \
  go test ./controllers/httpapi/ -run IntegrationSurface -v
```

Expected: 3 tests PASS.

- [ ] **Step 7: Commit**

```bash
git add controllers/httpapi/integration_surfaces.go controllers/httpapi/integration_surfaces_test.go controllers/httpapi/server.go
git commit -m "feat(httpapi): GET/POST /api/v1/integration-surfaces* handlers"
```

---

## Task 8: HTTP proxy — POST /api/v1/integrations/{instance_id}/surface-query

**Files:**
- Create: `controllers/httpapi/integration_surface_query.go`
- Create: `controllers/httpapi/integration_surface_query_test.go`

- [ ] **Step 1: Inspect existing synchronous dispatch helper**

```bash
grep -n "executeIntegrationRequest\|integrationExecuteHandler" controllers/message/integrations.go | head -10
```

Note the signature: `executeIntegrationRequest(ctx, conn, db, req, 0)` taking `model.ExecuteIntegrationRequest` and returning a response + error.

- [ ] **Step 2: Failing test**

`controllers/httpapi/integration_surface_query_test.go`:

```go
package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

type fakeDispatcher struct {
	gotReq model.ExecuteIntegrationRequest
	resp   any
	err    error
}

func (f *fakeDispatcher) Execute(_ context.Context, req model.ExecuteIntegrationRequest) (any, error) {
	f.gotReq = req
	return f.resp, f.err
}

func TestSurfaceQuery_PassesThrough(t *testing.T) {
	disp := &fakeDispatcher{resp: map[string]any{"items": []any{"a"}}}
	srv := &Server{surfaceQueryDispatcher: disp}
	body, _ := json.Marshal(map[string]any{"query_name": "list-channels", "params": map[string]any{"x": 1}})
	req := httptest.NewRequest("POST", "/api/v1/integrations/i1/surface-query", bytes.NewReader(body))
	req.SetPathValue("instance_id", "i1")
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.handleIntegrationSurfaceQuery()(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body %s", w.Code, w.Body.String())
	}
	if disp.gotReq.Operation != "on_surface_query" {
		t.Errorf("operation = %q", disp.gotReq.Operation)
	}
	if disp.gotReq.IntegrationInstanceID != "i1" {
		t.Errorf("instance_id = %q", disp.gotReq.IntegrationInstanceID)
	}
	if in, ok := disp.gotReq.Input["query_name"].(string); !ok || in != "list-channels" {
		t.Errorf("input.query_name = %v", disp.gotReq.Input["query_name"])
	}
}

func TestSurfaceQuery_MissingQueryNameIs400(t *testing.T) {
	srv := &Server{surfaceQueryDispatcher: &fakeDispatcher{}}
	body, _ := json.Marshal(map[string]any{})
	req := httptest.NewRequest("POST", "/api/v1/integrations/i1/surface-query", bytes.NewReader(body))
	req.SetPathValue("instance_id", "i1")
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.handleIntegrationSurfaceQuery()(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("status %d, want 400", w.Code)
	}
}

func TestSurfaceQuery_DispatchErrorIs502(t *testing.T) {
	srv := &Server{surfaceQueryDispatcher: &fakeDispatcher{err: errors.New("amqp down")}}
	body, _ := json.Marshal(map[string]any{"query_name": "x"})
	req := httptest.NewRequest("POST", "/api/v1/integrations/i1/surface-query", bytes.NewReader(body))
	req.SetPathValue("instance_id", "i1")
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.handleIntegrationSurfaceQuery()(w, req)
	if w.Code != http.StatusBadGateway {
		t.Errorf("status %d, want 502", w.Code)
	}
}
```

- [ ] **Step 3: Run — expect FAIL**

`GOWORK=/Users/dakasa/projects/dakasa/go.work go test ./controllers/httpapi/ -run SurfaceQuery`

Expected: `surfaceQueryDispatcher` undefined.

- [ ] **Step 4: Implement handler**

`controllers/httpapi/integration_surface_query.go`:

```go
package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

// SurfaceQueryDispatcher abstracts the synchronous RPC executor that
// forwards an adapter operation to the named instance. The production
// implementation wraps controllers/message.executeIntegrationRequest.
type SurfaceQueryDispatcher interface {
	Execute(ctx context.Context, req model.ExecuteIntegrationRequest) (any, error)
}

type surfaceQueryReqBody struct {
	QueryName string         `json:"query_name"`
	Params    map[string]any `json:"params,omitempty"`
}

func (s *Server) handleIntegrationSurfaceQuery() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		instanceID := strings.TrimSpace(r.PathValue("instance_id"))
		if instanceID == "" {
			writeJSONError(w, http.StatusBadRequest, "missing instance_id")
			return
		}
		var body surfaceQueryReqBody
		dec := json.NewDecoder(r.Body)
		dec.DisallowUnknownFields()
		if err := dec.Decode(&body); err != nil {
			writeJSONError(w, http.StatusBadRequest, "invalid body: "+err.Error())
			return
		}
		if strings.TrimSpace(body.QueryName) == "" {
			writeJSONError(w, http.StatusBadRequest, "query_name required")
			return
		}
		req := model.ExecuteIntegrationRequest{
			IntegrationInstanceID: instanceID,
			Operation:             model.OperationOnSurfaceQuery,
			Capability:            model.OperationOnSurfaceQuery,
			Input: map[string]any{
				"query_name": body.QueryName,
				"params":     body.Params,
			},
		}
		resp, err := s.surfaceQueryDispatcher.Execute(r.Context(), req)
		if err != nil {
			writeJSON(w, http.StatusBadGateway, map[string]any{
				"error":   "adapter_dispatch_failed",
				"message": err.Error(),
			})
			return
		}
		writeJSON(w, http.StatusOK, resp)
	}
}
```

- [ ] **Step 5: Add `surfaceQueryDispatcher` field to Server**

In `controllers/httpapi/server.go`, extend the `Server` struct:

```go
type Server struct {
    // ... existing + integrationSurfacesRepo from Task 7 ...
    surfaceQueryDispatcher SurfaceQueryDispatcher
}
```

- [ ] **Step 6: Run — expect PASS**

`GOWORK=/Users/dakasa/projects/dakasa/go.work go test ./controllers/httpapi/ -run SurfaceQuery`

Expected: 3 tests PASS.

- [ ] **Step 7: Commit**

```bash
git add controllers/httpapi/integration_surface_query.go controllers/httpapi/integration_surface_query_test.go controllers/httpapi/server.go
git commit -m "feat(httpapi): POST /api/v1/integrations/{id}/surface-query proxy (on_surface_query dispatch)"
```

---

## Task 9: Route registration in `server.go`

**Files:**
- Modify: `controllers/httpapi/server.go`

- [ ] **Step 1: Locate route registration block**

```bash
grep -n "mux.HandleFunc" controllers/httpapi/server.go | head -5
```

Routes are registered in a single contiguous block in `controllers/httpapi/server.go:239–507`. The pattern is `mux.HandleFunc("METHOD /path", handler)`.

- [ ] **Step 2: Add 4 new routes**

In the route registration block, append:

```go
mux.HandleFunc("GET /api/v1/integration-surfaces", server.handleIntegrationSurfacesList())
mux.HandleFunc("GET /api/v1/integration-surfaces/{name}", server.handleIntegrationSurfaceGet())
mux.HandleFunc("POST /api/v1/integration-surfaces/{name}/sync", server.handleIntegrationSurfaceSync())
mux.HandleFunc("POST /api/v1/integrations/{instance_id}/surface-query", server.handleIntegrationSurfaceQuery())
```

- [ ] **Step 3: Run all httpapi tests**

```bash
DB_URL="postgres://yggdrasil:yggdrasil@localhost:5432/yggdrasil?sslmode=disable" \
  GOWORK=/Users/dakasa/projects/dakasa/go.work \
  go test ./controllers/httpapi/...
```

Expected: existing + new tests PASS.

- [ ] **Step 4: Commit**

```bash
git add controllers/httpapi/server.go
git commit -m "feat(httpapi): register 4 routes for integration-surfaces + surface-query proxy"
```

---

## Task 10: Bootstrap addon — wire repo + syncer + dispatcher into main flow

**Files:**
- Create: `addons/integration_surface_sync.go`
- Modify: `addons/http.go` (to pass new fields to Server constructor)

- [ ] **Step 1: Inspect existing addon as model**

```bash
cat addons/manifest_sync.go | head -80
```

Manifest_sync uses `Register("manifest_sync", bootstrap, priority)` and constructs its `Deps` from app resources (db, rabbitmq, logger).

- [ ] **Step 2: Write addon**

`addons/integration_surface_sync.go`:

```go
package addons

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/integrationsurfaces"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
)

func init() {
	Register("integration_surface_sync", bootstrapIntegrationSurfaceSync, 35)
}

// emitterFromDB wraps repository.EmitEvent in a transaction for use by the syncer.
type emitterFromDB struct {
	db *sql.DB
}

func (e *emitterFromDB) Emit(ctx context.Context, eventType, aggregateID string, payload map[string]any) error {
	tx, err := e.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	aggType := eventType
	for i := 0; i < len(eventType); i++ {
		if eventType[i] == '.' {
			aggType = eventType[:i]
			break
		}
	}

	if _, err := repository.EmitEvent(ctx, tx, model.EmitEventRequest{
		Type:          eventType,
		AggregateType: aggType,
		AggregateID:   aggregateID,
		Payload:       payload,
	}); err != nil {
		return fmt.Errorf("emit %q: %w", eventType, err)
	}
	return tx.Commit()
}

func bootstrapIntegrationSurfaceSync(ctx context.Context, app App) error {
	db := app.Resource("postgres").(*sql.DB)
	repo := integrationsurfaces.NewRepository(db)
	emitter := &emitterFromDB{db: db}
	syncer := integrationsurfaces.NewSyncer(repo, emitter)

	// Store repo + syncer in app resources so the HTTP addon can pick them up.
	app.SetResource("integration_surfaces_repo", repo)
	app.SetResource("integration_surfaces_syncer", syncer)
	return nil
}
```

NOTE: The `App` interface for addons exposes `Resource(name)` / `SetResource(name, value)`. Check the exact signature in `addons/registry.go` and adjust to match (e.g., it may use a `Get`/`Set` naming convention with typed errors).

- [ ] **Step 3: Wire into HTTP addon**

Edit `addons/http.go` so `bootstrapHTTP` constructs the Server with the new fields:

```go
// Inside bootstrapHTTP, near the existing httpapi.New(...) call:

surfacesRepo := app.Resource("integration_surfaces_repo").(*integrationsurfaces.Repository)
dispatcher := newSurfaceQueryDispatcher(conn, db, logger)  // adapter over executeIntegrationRequest

opts = append(opts,
    httpapi.WithIntegrationSurfacesRepo(surfacesRepo),
    httpapi.WithSurfaceQueryDispatcher(dispatcher),
)
```

And in `controllers/httpapi/server.go`, add option setters:

```go
func WithIntegrationSurfacesRepo(r IntegrationSurfacesRepo) Option {
    return func(s *Server) { s.integrationSurfacesRepo = r }
}

func WithSurfaceQueryDispatcher(d SurfaceQueryDispatcher) Option {
    return func(s *Server) { s.surfaceQueryDispatcher = d }
}
```

`newSurfaceQueryDispatcher` is a small adapter living next to the addon:

```go
// addons/integration_surface_sync.go (append)

import "github.com/streadway/amqp"  // OR github.com/rabbitmq/amqp091-go — match what controllers/message uses

type surfaceQueryDispatcher struct {
	conn *amqp.Connection
	db   *sql.DB
	log  *zap.Logger
}

func newSurfaceQueryDispatcher(conn *amqp.Connection, db *sql.DB, log *zap.Logger) *surfaceQueryDispatcher {
	return &surfaceQueryDispatcher{conn: conn, db: db, log: log}
}

func (d *surfaceQueryDispatcher) Execute(ctx context.Context, req model.ExecuteIntegrationRequest) (any, error) {
	// Delegate to the existing synchronous executor. The function lives in
	// controllers/message/integrations.go; if it's lowercase (unexported),
	// either move it to an exported helper or copy the relevant logic here.
	return message.ExecuteIntegrationRequest(ctx, d.conn, d.db, req, 0)
}
```

(If `executeIntegrationRequest` is unexported, this Task includes adding an exported wrapper `message.ExecuteIntegrationRequest` that calls the existing private function. This is the only change needed in `controllers/message/`.)

- [ ] **Step 4: Build**

```bash
GOWORK=/Users/dakasa/projects/dakasa/go.work go build ./...
```

Expected: clean build.

- [ ] **Step 5: Commit**

```bash
git add addons/ controllers/httpapi/server.go controllers/message/
git commit -m "feat(addons): integration_surface_sync addon + wire repo/dispatcher into HTTP server"
```

---

## Task 11: Smoke E2E against local instance

**Files:** none

- [ ] **Step 1: Start service locally**

```bash
GOWORK=/Users/dakasa/projects/dakasa/go.work go run ./
```

(`./` because main is at repo root.)

- [ ] **Step 2: Verify list returns empty**

```bash
curl -s -H "Cookie: <valid-session-cookie>" http://localhost:9080/api/v1/integration-surfaces | jq .
```

Expected: `{"items":[],"total":0}`.

- [ ] **Step 3: Insert a sample manifest via SQL + verify**

```bash
psql "$DATABASE_URL" <<'SQL'
INSERT INTO integration_surfaces (name, integration_type, category, spec, active)
VALUES (
  'surface-smoke',
  NULL,
  'core',
  '{"category":"core","runtime":{"kind":"spa","base_path":"/s/smoke"},"display":{"title":"Smoke","appears_on":["ops-integrations"]}}'::jsonb,
  true
);
SQL

curl -s -H "Cookie: <valid-session-cookie>" \
  "http://localhost:9080/api/v1/integration-surfaces?appears_on=ops-integrations" | jq .
```

Expected: response includes `surface-smoke`.

- [ ] **Step 4: Test sync touch**

```bash
curl -s -X POST -H "Cookie: <valid-session-cookie>" \
  "http://localhost:9080/api/v1/integration-surfaces/surface-smoke/sync" | jq .
```

Expected: `{"sync_queued":true,"name":"surface-smoke"}` with status 202.

- [ ] **Step 5: Cleanup**

```bash
psql "$DATABASE_URL" -c "DELETE FROM integration_surfaces WHERE name = 'surface-smoke';"
```

- [ ] **Step 6: Tag sync gate**

```bash
git commit --allow-empty -m "chore: Phase 0b complete — integration_surfaces + endpoints live"
```

---

## Phase 0b sync gate (after Task 11)

Before Phase 1 surfaces consume these endpoints:

1. ✅ Migration `00042_integration_surfaces.sql` applied
2. ✅ `model.OperationOnSurfaceQuery` declared
3. ✅ 4 event schemas at `docs/contracts/events/v1/integration_surface/*.json` validate
4. ✅ `internal/integrationsurfaces/` package: types, repository, syncer, all tests pass
5. ✅ HTTP endpoints registered: GET/list, GET/{name}, POST/{name}/sync, POST/{instance_id}/surface-query
6. ✅ `addons/integration_surface_sync.go` bootstraps repo + emitter into app resources
7. ✅ Local smoke: list returns []; manual insert appears; touch returns 202
8. ✅ `go build ./...` clean, all tests pass

## Final code reviewer dispatch (after Task 11)

Reviewer checks:
- `kind` validation rejects anything other than `"integration_surface"` (Task 6 test verifies)
- Sensitive secret fields in `spec` are NOT redacted by core (responsibility lies with manifest authors); core stores the spec verbatim
- The new addon is at priority 35 (after postgres ~20, before HTTP at 30 — verify the actual numbers match; HTTP addon needs the repo as a resource at construction time, so this addon must boot before HTTP)
- No imports of `internal/surface` (the OLD system) — the two systems are decoupled at the import level
- `executeIntegrationRequest` exported / wrapper sound (Task 10 Step 3)
- Migration uses `IF NOT EXISTS` and `DROP IF EXISTS` for idempotency
