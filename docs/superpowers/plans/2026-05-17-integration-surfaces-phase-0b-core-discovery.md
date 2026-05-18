# Integration Surfaces — Phase 0b: yggdrasil-core Discovery Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Extend yggdrasil-core with the backend machinery for federated integration surfaces: `surface_manifests` table, `GET/POST /api/v1/surfaces*` endpoints, `OperationOnSurfaceQuery` proxy, `manifest_sync` extension reconciling surface manifests, and 4 canon events.

**Architecture:** New domain `internal/surfaces` (types + repository + service). HTTP handlers in `controllers/httpapi/`. Manifest_sync addon extended in `internal/manifestsync/` to reconcile two collections (`integration_types`, `surface_manifests`). Operation `on_surface_query` declared in `internal/integrations/operations.go` and proxied via RabbitMQ.

**Tech Stack:** Go 1.22+, PostgreSQL (existing yggdrasil-core db), RabbitMQ (existing operations dispatch), goose migrations, standard `net/http` + chi-style routing pattern already in repo.

**Spec reference:** `/Users/dakasa/projects/yggdrasil/yggdrasil-core/docs/superpowers/specs/2026-05-17-integration-surfaces-design.md` §4 and §5.5 (proxy).

**Working directory:** `/Users/dakasa/projects/yggdrasil/yggdrasil-core/`.

**Commit cadence:** push direct to `main` per DaKasa convention. No co-author trailers.

---

## Task 1: Migration `00045_surface_manifests.sql`

**Files:**
- Create: `db/migrations/00045_surface_manifests.sql`

- [ ] **Step 1: Inspect highest existing migration number to confirm 00045 is next**

```bash
cd /Users/dakasa/projects/yggdrasil/yggdrasil-core
ls db/migrations/ | sort | tail -5
```

Expected: numbers up to ~00044. If 00045 is already used, renumber to next free number and adjust all references in this plan.

- [ ] **Step 2: Write migration SQL**

`db/migrations/00045_surface_manifests.sql`:

```sql
-- +goose Up
-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS surface_manifests (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name text NOT NULL UNIQUE,
  integration_type text,
  category text NOT NULL CHECK (category IN ('integration','core','domain')),
  spec jsonb NOT NULL,
  active boolean NOT NULL DEFAULT true,
  registered_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT fk_surface_integration_type FOREIGN KEY (integration_type)
    REFERENCES integration_types(name) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS surface_manifests_active_idx
  ON surface_manifests (active) WHERE active;

CREATE INDEX IF NOT EXISTS surface_manifests_appears_on_idx
  ON surface_manifests USING gin ((spec->'display'->'appears_on'));

CREATE INDEX IF NOT EXISTS surface_manifests_integration_type_idx
  ON surface_manifests (integration_type) WHERE active;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS surface_manifests;
-- +goose StatementEnd
```

- [ ] **Step 3: Apply migration to local dev DB and verify**

```bash
goose -dir db/migrations postgres "$DATABASE_URL" up
psql "$DATABASE_URL" -c "\d surface_manifests"
```

Expected: table description shows all 8 columns + 3 indexes + FK to integration_types.

- [ ] **Step 4: Commit**

```bash
git add db/migrations/00045_surface_manifests.sql
git commit -m "feat(db): surface_manifests table + indexes (gin appears_on)"
```

---

## Task 2: Domain types

**Files:**
- Create: `internal/surfaces/types.go`
- Create: `internal/surfaces/types_test.go`

- [ ] **Step 1: Write failing test**

`internal/surfaces/types_test.go`:

```go
package surfaces

import (
	"encoding/json"
	"testing"
)

func TestManifestSpec_UnmarshalsCanonical(t *testing.T) {
	raw := []byte(`{
		"runtime":{"kind":"spa","base_path":"/s/slack","health_path":"/healthz","image":"ghcr.io/x"},
		"display":{"title":"Slack","subtitle":"x","icon":"slack","color_token":"brand.slack","appears_on":["ops-integrations"]},
		"core_contracts":["authorization","external_identity"],
		"category":"integration",
		"owners":["team:platform"],
		"capabilities":[{"name":"integration-admin","tabs":["overview","drift"]}]
	}`)
	var s ManifestSpec
	if err := json.Unmarshal(raw, &s); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if s.Runtime.Kind != "spa" {
		t.Errorf("runtime.kind = %q, want spa", s.Runtime.Kind)
	}
	if s.Display.Title != "Slack" {
		t.Errorf("display.title = %q", s.Display.Title)
	}
	if got := len(s.Display.AppearsOn); got != 1 || s.Display.AppearsOn[0] != "ops-integrations" {
		t.Errorf("appears_on = %v", s.Display.AppearsOn)
	}
}

func TestManifestSpec_AppearsOn_AllValid(t *testing.T) {
	cases := []string{"console-home", "ops-integrations", "me", "equipe", "orgchart", "colaborador-detail"}
	for _, slot := range cases {
		if !IsValidSlot(slot) {
			t.Errorf("expected %q to be a valid slot", slot)
		}
	}
	if IsValidSlot("unknown-slot") {
		t.Errorf("expected unknown-slot to be invalid")
	}
}
```

- [ ] **Step 2: Run — expect FAIL**

Run: `go test ./internal/surfaces/...`
Expected: FAIL — `surfaces` package doesn't exist yet.

- [ ] **Step 3: Implement types.go**

`internal/surfaces/types.go`:

```go
package surfaces

import "time"

// Category enumerates the kinds of surface a manifest can declare.
type Category string

const (
	CategoryIntegration Category = "integration"
	CategoryCore        Category = "core"
	CategoryDomain      Category = "domain"
)

// Manifest is the persisted record in surface_manifests.
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

// ManifestSpec is the parsed `spec` block of surface.manifest.json.
type ManifestSpec struct {
	Category      Category          `json:"category"`
	Owners        []string          `json:"owners"`
	Runtime       Runtime           `json:"runtime"`
	Display       Display           `json:"display"`
	CoreContracts []string          `json:"core_contracts"`
	Capabilities  []CapabilitySpec  `json:"capabilities,omitempty"`
}

type Runtime struct {
	Kind       string `json:"kind"` // "spa" | "http_api"
	Exposure   string `json:"exposure"`
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

// validSlots is the V1 enum of recognised slot ids.
var validSlots = map[string]struct{}{
	"console-home":        {},
	"ops-integrations":    {},
	"me":                  {},
	"equipe":              {},
	"orgchart":            {},
	"colaborador-detail":  {},
}

// IsValidSlot returns true if the slot id is one of the known V1 slots.
func IsValidSlot(slot string) bool {
	_, ok := validSlots[slot]
	return ok
}
```

- [ ] **Step 4: Run — expect PASS**

Run: `go test ./internal/surfaces/...`
Expected: PASS — 2 tests.

- [ ] **Step 5: Commit**

```bash
git add internal/surfaces
git commit -m "feat(surfaces): domain types — Manifest, ManifestSpec, slot enum"
```

---

## Task 3: Repository

**Files:**
- Create: `internal/surfaces/repository.go`
- Create: `internal/surfaces/repository_test.go`

- [ ] **Step 1: Write failing integration test (uses test DB)**

`internal/surfaces/repository_test.go`:

```go
package surfaces_test

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/surfaces"
	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/testutil"
)

func TestRepository_UpsertAndGet(t *testing.T) {
	ctx := context.Background()
	db := testutil.MustOpenTestDB(t)
	defer db.Close()
	repo := surfaces.NewRepository(db)

	spec := surfaces.ManifestSpec{
		Category: surfaces.CategoryIntegration,
		Runtime:  surfaces.Runtime{Kind: "spa", BasePath: "/s/slack"},
		Display:  surfaces.Display{Title: "Slack", AppearsOn: []string{"ops-integrations"}},
	}
	intType := "slack"
	m := surfaces.Manifest{
		Name:            "surface-slack",
		IntegrationType: &intType,
		Category:        surfaces.CategoryIntegration,
		Spec:            spec,
		Active:          true,
	}

	if err := repo.Upsert(ctx, &m); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	if m.ID == "" {
		t.Fatal("expected ID to be populated after upsert")
	}

	got, err := repo.GetByName(ctx, "surface-slack")
	if err != nil {
		t.Fatalf("GetByName: %v", err)
	}
	if got.Name != "surface-slack" {
		t.Errorf("name = %q", got.Name)
	}
	if got.Spec.Runtime.Kind != "spa" {
		t.Errorf("runtime.kind = %q", got.Spec.Runtime.Kind)
	}
}

func TestRepository_List_FiltersByAppearsOn(t *testing.T) {
	ctx := context.Background()
	db := testutil.MustOpenTestDB(t)
	defer db.Close()
	repo := surfaces.NewRepository(db)

	mk := func(name string, slots []string) surfaces.Manifest {
		return surfaces.Manifest{
			Name:     name,
			Category: surfaces.CategoryIntegration,
			Spec: surfaces.ManifestSpec{
				Category: surfaces.CategoryIntegration,
				Runtime:  surfaces.Runtime{Kind: "spa", BasePath: "/s/" + name},
				Display:  surfaces.Display{Title: name, AppearsOn: slots},
			},
			Active: true,
		}
	}
	a := mk("surface-a", []string{"ops-integrations", "console-home"})
	b := mk("surface-b", []string{"me"})
	if err := repo.Upsert(ctx, &a); err != nil {
		t.Fatal(err)
	}
	if err := repo.Upsert(ctx, &b); err != nil {
		t.Fatal(err)
	}

	items, err := repo.List(ctx, surfaces.ListFilter{AppearsOn: "ops-integrations"})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(items) != 1 || items[0].Name != "surface-a" {
		t.Errorf("got %+v", items)
	}
}

func TestRepository_Deactivate(t *testing.T) {
	ctx := context.Background()
	db := testutil.MustOpenTestDB(t)
	defer db.Close()
	repo := surfaces.NewRepository(db)
	m := surfaces.Manifest{
		Name:     "surface-x",
		Category: surfaces.CategoryIntegration,
		Spec:     surfaces.ManifestSpec{Category: surfaces.CategoryIntegration, Display: surfaces.Display{Title: "X"}},
		Active:   true,
	}
	if err := repo.Upsert(ctx, &m); err != nil {
		t.Fatal(err)
	}
	if err := repo.Deactivate(ctx, "surface-x"); err != nil {
		t.Fatal(err)
	}
	got, err := repo.GetByName(ctx, "surface-x")
	if err != nil {
		t.Fatal(err)
	}
	if got.Active {
		t.Error("expected active=false after Deactivate")
	}
}

// helper to suppress unused-import on encoding/json in this file
var _ = json.Marshal
```

- [ ] **Step 2: Run — expect FAIL**

Run: `go test ./internal/surfaces/...`
Expected: FAIL — `NewRepository` / `Upsert` / `GetByName` / `List` / `Deactivate` undefined.

- [ ] **Step 3: Implement repository.go**

`internal/surfaces/repository.go`:

```go
package surfaces

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// ErrNotFound is returned when a manifest does not exist.
var ErrNotFound = errors.New("surface manifest not found")

// Repository persists Manifests.
type Repository struct {
	db *sql.DB
}

func NewRepository(db *sql.DB) *Repository {
	return &Repository{db: db}
}

// Upsert inserts or updates a manifest by unique name.
// On insert, sets RegisteredAt; on update, only UpdatedAt.
func (r *Repository) Upsert(ctx context.Context, m *Manifest) error {
	specJSON, err := json.Marshal(m.Spec)
	if err != nil {
		return fmt.Errorf("marshal spec: %w", err)
	}
	const q = `
INSERT INTO surface_manifests (name, integration_type, category, spec, active)
VALUES ($1, $2, $3, $4, $5)
ON CONFLICT (name) DO UPDATE
SET integration_type = EXCLUDED.integration_type,
    category = EXCLUDED.category,
    spec = EXCLUDED.spec,
    active = EXCLUDED.active,
    updated_at = now()
RETURNING id, registered_at, updated_at`

	row := r.db.QueryRowContext(ctx, q, m.Name, m.IntegrationType, string(m.Category), specJSON, m.Active)
	if err := row.Scan(&m.ID, &m.RegisteredAt, &m.UpdatedAt); err != nil {
		return fmt.Errorf("upsert surface_manifest: %w", err)
	}
	return nil
}

// GetByName fetches by unique name.
func (r *Repository) GetByName(ctx context.Context, name string) (*Manifest, error) {
	const q = `
SELECT id, name, integration_type, category, spec, active, registered_at, updated_at
FROM surface_manifests
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

// ListFilter narrows results to active manifests matching the criteria.
type ListFilter struct {
	AppearsOn       string // slot name; if set, manifest's spec.display.appears_on must include
	IntegrationType string
	Category        string
	OnlyActive      bool // default true; pass false to include deactivated
}

func (r *Repository) List(ctx context.Context, f ListFilter) ([]Manifest, error) {
	where := "1=1"
	args := []any{}
	idx := 1
	if f.OnlyActive || f.IntegrationType == "" {
		where += " AND active = true"
	}
	if f.AppearsOn != "" {
		where += fmt.Sprintf(" AND spec->'display'->'appears_on' @> $%d::jsonb", idx)
		args = append(args, fmt.Sprintf(`["%s"]`, f.AppearsOn))
		idx++
	}
	if f.IntegrationType != "" {
		where += fmt.Sprintf(" AND integration_type = $%d", idx)
		args = append(args, f.IntegrationType)
		idx++
	}
	if f.Category != "" {
		where += fmt.Sprintf(" AND category = $%d", idx)
		args = append(args, f.Category)
		idx++
	}
	q := fmt.Sprintf(`
SELECT id, name, integration_type, category, spec, active, registered_at, updated_at
FROM surface_manifests
WHERE %s
ORDER BY updated_at DESC`, where)

	rows, err := r.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("query: %w", err)
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
			return nil, fmt.Errorf("scan: %w", err)
		}
		if intType.Valid {
			s := intType.String
			m.IntegrationType = &s
		}
		m.Category = Category(cat)
		if err := json.Unmarshal(specRaw, &m.Spec); err != nil {
			return nil, fmt.Errorf("unmarshal spec: %w", err)
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// Deactivate flips active=false on a manifest.
func (r *Repository) Deactivate(ctx context.Context, name string) error {
	const q = `UPDATE surface_manifests SET active = false, updated_at = now() WHERE name = $1`
	res, err := r.db.ExecContext(ctx, q, name)
	if err != nil {
		return fmt.Errorf("deactivate: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// TouchUpdatedAt sets updated_at to now() — used during ops force-sync probes.
func (r *Repository) TouchUpdatedAt(ctx context.Context, name string) error {
	const q = `UPDATE surface_manifests SET updated_at = now() WHERE name = $1`
	res, err := r.db.ExecContext(ctx, q, name)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	_ = time.Now() // keep import; harmless
	return nil
}
```

- [ ] **Step 4: Run — expect PASS**

Run: `go test ./internal/surfaces/...`
Expected: PASS — 3 tests.

- [ ] **Step 5: Commit**

```bash
git add internal/surfaces
git commit -m "feat(surfaces): repository with Upsert/GetByName/List(filtered)/Deactivate"
```

---

## Task 4: Canon events + JSON schemas

**Files:**
- Modify: `internal/events/constants.go` (add 4 event names)
- Create: `internal/events/schemas/surface_registered.json`
- Create: `internal/events/schemas/surface_updated.json`
- Create: `internal/events/schemas/surface_deactivated.json`
- Create: `internal/events/schemas/surface_drift_detected.json`
- Create: `internal/surfaces/events.go` (typed emitters)
- Create: `internal/surfaces/events_test.go`

- [ ] **Step 1: Locate existing events constants & schema-loading style**

```bash
cd /Users/dakasa/projects/yggdrasil/yggdrasil-core
grep -rn "external_identity.linked" internal/events/ | head -5
```

Use the same naming pattern. Existing constants will be named like `ExternalIdentityLinked` exporting the string `"external_identity.linked"`.

- [ ] **Step 2: Add 4 constants in internal/events/constants.go**

Append to the existing constants block:

```go
// Surface canon events
const (
	SurfaceRegistered    = "surface.registered"
	SurfaceUpdated       = "surface.updated"
	SurfaceDeactivated   = "surface.deactivated"
	SurfaceDriftDetected = "surface.drift_detected"
)
```

- [ ] **Step 3: Write 4 JSON schemas (one per event)**

`internal/events/schemas/surface_registered.json`:

```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "title": "surface.registered",
  "type": "object",
  "required": ["surface_name", "category", "registered_at", "spec"],
  "properties": {
    "surface_name": { "type": "string" },
    "integration_type": { "type": ["string", "null"] },
    "category": { "type": "string", "enum": ["integration", "core", "domain"] },
    "registered_at": { "type": "string", "format": "date-time" },
    "spec": { "type": "object" }
  },
  "additionalProperties": false
}
```

`internal/events/schemas/surface_updated.json`:

```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "title": "surface.updated",
  "type": "object",
  "required": ["surface_name", "updated_at"],
  "properties": {
    "surface_name": { "type": "string" },
    "integration_type": { "type": ["string", "null"] },
    "prev_spec_hash": { "type": ["string", "null"] },
    "new_spec_hash": { "type": "string" },
    "updated_at": { "type": "string", "format": "date-time" }
  },
  "additionalProperties": false
}
```

`internal/events/schemas/surface_deactivated.json`:

```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "title": "surface.deactivated",
  "type": "object",
  "required": ["surface_name", "reason"],
  "properties": {
    "surface_name": { "type": "string" },
    "reason": { "type": "string" }
  },
  "additionalProperties": false
}
```

`internal/events/schemas/surface_drift_detected.json`:

```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "title": "surface.drift_detected",
  "type": "object",
  "required": ["surface_name", "persisted_spec_hash", "runtime_spec_hash"],
  "properties": {
    "surface_name": { "type": "string" },
    "persisted_spec_hash": { "type": "string" },
    "runtime_spec_hash": { "type": "string" }
  },
  "additionalProperties": false
}
```

- [ ] **Step 4: Write failing test for typed emitters**

`internal/surfaces/events_test.go`:

```go
package surfaces

import (
	"encoding/json"
	"testing"
	"time"
)

func TestRegisteredPayload(t *testing.T) {
	intType := "slack"
	p := RegisteredPayload{
		SurfaceName:     "surface-slack",
		IntegrationType: &intType,
		Category:        CategoryIntegration,
		RegisteredAt:    time.Now().UTC(),
		Spec:            map[string]any{"runtime": map[string]any{"kind": "spa"}},
	}
	b, err := json.Marshal(p)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !contains(string(b), `"surface_name":"surface-slack"`) {
		t.Errorf("expected surface_name in payload; got %s", string(b))
	}
}

func TestDeactivatedPayload(t *testing.T) {
	p := DeactivatedPayload{SurfaceName: "surface-x", Reason: "manifest removed"}
	b, _ := json.Marshal(p)
	if !contains(string(b), `"reason":"manifest removed"`) {
		t.Errorf("got %s", string(b))
	}
}

func contains(haystack, needle string) bool {
	return len(haystack) >= len(needle) && (haystack == needle || (len(haystack) > len(needle) && indexOf(haystack, needle) >= 0))
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
```

- [ ] **Step 5: Run — expect FAIL**

Run: `go test ./internal/surfaces/...`
Expected: FAIL — `RegisteredPayload`/`DeactivatedPayload` undefined.

- [ ] **Step 6: Implement events.go**

`internal/surfaces/events.go`:

```go
package surfaces

import "time"

// RegisteredPayload matches schemas/surface_registered.json.
type RegisteredPayload struct {
	SurfaceName     string         `json:"surface_name"`
	IntegrationType *string        `json:"integration_type,omitempty"`
	Category        Category       `json:"category"`
	RegisteredAt    time.Time      `json:"registered_at"`
	Spec            map[string]any `json:"spec"`
}

// UpdatedPayload matches schemas/surface_updated.json.
type UpdatedPayload struct {
	SurfaceName     string    `json:"surface_name"`
	IntegrationType *string   `json:"integration_type,omitempty"`
	PrevSpecHash    *string   `json:"prev_spec_hash,omitempty"`
	NewSpecHash     string    `json:"new_spec_hash"`
	UpdatedAt       time.Time `json:"updated_at"`
}

// DeactivatedPayload matches schemas/surface_deactivated.json.
type DeactivatedPayload struct {
	SurfaceName string `json:"surface_name"`
	Reason      string `json:"reason"`
}

// DriftDetectedPayload matches schemas/surface_drift_detected.json.
type DriftDetectedPayload struct {
	SurfaceName       string `json:"surface_name"`
	PersistedSpecHash string `json:"persisted_spec_hash"`
	RuntimeSpecHash   string `json:"runtime_spec_hash"`
}
```

- [ ] **Step 7: Run — expect PASS**

Run: `go test ./internal/surfaces/...`
Expected: PASS — 5 tests (existing 3 + 2 new).

- [ ] **Step 8: Commit**

```bash
git add internal/events internal/surfaces/events.go internal/surfaces/events_test.go
git commit -m "feat(events): 4 surface canon events + JSON schemas + typed payloads"
```

---

## Task 5: Manifest_sync extension for surface_manifests

**Files:**
- Modify: `internal/manifestsync/syncer.go` (add SurfaceManifests collection)
- Create: `internal/manifestsync/surface_sync.go`
- Create: `internal/manifestsync/surface_sync_test.go`

- [ ] **Step 1: Inspect existing syncer structure**

```bash
grep -n "type.*Syncer" internal/manifestsync/*.go
grep -n "integration_types" internal/manifestsync/*.go | head -10
```

Understand the current pattern — the syncer likely has a method `ReconcileIntegrationTypes`. We add `ReconcileSurfaceManifests` modeled after it.

- [ ] **Step 2: Write failing test**

`internal/manifestsync/surface_sync_test.go`:

```go
package manifestsync_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/manifestsync"
	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/surfaces"
	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/testutil"
)

func TestReconcileSurfaceManifest_InsertsNewManifest(t *testing.T) {
	ctx := context.Background()
	db := testutil.MustOpenTestDB(t)
	defer db.Close()

	repo := surfaces.NewRepository(db)
	bus := testutil.NewFakeEventBus()
	syncer := manifestsync.NewSurfaceSyncer(repo, bus)

	spec := map[string]any{
		"category": "integration",
		"runtime":  map[string]any{"kind": "spa", "base_path": "/s/slack"},
		"display":  map[string]any{"title": "Slack", "appears_on": []any{"ops-integrations"}},
	}
	manifestJSON, _ := json.Marshal(map[string]any{
		"apiVersion": "yggdrasil.io/v1alpha1",
		"kind":       "surface",
		"metadata":   map[string]any{"name": "surface-slack", "integration_type": "slack"},
		"spec":       spec,
	})

	report, err := syncer.ReconcileFromBytes(ctx, manifestJSON)
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if report.Action != "inserted" {
		t.Errorf("action = %q, want inserted", report.Action)
	}

	got, err := repo.GetByName(ctx, "surface-slack")
	if err != nil {
		t.Fatalf("GetByName: %v", err)
	}
	if got.IntegrationType == nil || *got.IntegrationType != "slack" {
		t.Errorf("integration_type = %v", got.IntegrationType)
	}

	if len(bus.Emitted()) != 1 || bus.Emitted()[0].Topic != "surface.registered" {
		t.Errorf("expected 1 surface.registered emit, got %+v", bus.Emitted())
	}
}

func TestReconcileSurfaceManifest_DetectsUpdateViaHash(t *testing.T) {
	ctx := context.Background()
	db := testutil.MustOpenTestDB(t)
	defer db.Close()
	repo := surfaces.NewRepository(db)
	bus := testutil.NewFakeEventBus()
	syncer := manifestsync.NewSurfaceSyncer(repo, bus)

	v1, _ := json.Marshal(map[string]any{
		"apiVersion": "yggdrasil.io/v1alpha1",
		"kind":       "surface",
		"metadata":   map[string]any{"name": "surface-x"},
		"spec": map[string]any{
			"category": "integration",
			"runtime":  map[string]any{"kind": "spa", "base_path": "/s/x"},
			"display":  map[string]any{"title": "X v1"},
		},
	})
	if _, err := syncer.ReconcileFromBytes(ctx, v1); err != nil {
		t.Fatal(err)
	}

	v2, _ := json.Marshal(map[string]any{
		"apiVersion": "yggdrasil.io/v1alpha1",
		"kind":       "surface",
		"metadata":   map[string]any{"name": "surface-x"},
		"spec": map[string]any{
			"category": "integration",
			"runtime":  map[string]any{"kind": "spa", "base_path": "/s/x"},
			"display":  map[string]any{"title": "X v2"},
		},
	})
	report, err := syncer.ReconcileFromBytes(ctx, v2)
	if err != nil {
		t.Fatal(err)
	}
	if report.Action != "updated" {
		t.Errorf("action = %q, want updated", report.Action)
	}

	bus.Clear()
	report, err = syncer.ReconcileFromBytes(ctx, v2)
	if err != nil {
		t.Fatal(err)
	}
	if report.Action != "noop" {
		t.Errorf("re-applying v2 should be noop; got %q", report.Action)
	}
	if len(bus.Emitted()) != 0 {
		t.Errorf("noop should not emit; got %+v", bus.Emitted())
	}
}

func TestReconcileSurfaceManifest_HashIsStable(t *testing.T) {
	// Property: same JSON yields same hash regardless of key order.
	specA := map[string]any{"a": 1, "b": 2}
	specB := map[string]any{"b": 2, "a": 1}
	bA, _ := json.Marshal(specA)
	bB, _ := json.Marshal(specB)
	hA := sha256.Sum256(bA)
	hB := sha256.Sum256(bB)
	// Go map JSON serialisation IS sorted for top-level (since 1.12) so this holds.
	if hex.EncodeToString(hA[:]) != hex.EncodeToString(hB[:]) {
		t.Errorf("expected stable hash; A=%x B=%x", hA, hB)
	}
}
```

- [ ] **Step 3: Run — expect FAIL**

Run: `go test ./internal/manifestsync/...`
Expected: FAIL — `NewSurfaceSyncer` undefined.

- [ ] **Step 4: Implement surface_sync.go**

`internal/manifestsync/surface_sync.go`:

```go
package manifestsync

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/events"
	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/surfaces"
)

// EventBus is the minimal interface this syncer needs.
type EventBus interface {
	Emit(ctx context.Context, topic string, payload any) error
}

// SurfaceSyncReport describes the outcome of a single reconciliation.
type SurfaceSyncReport struct {
	SurfaceName string
	Action      string // "inserted" | "updated" | "noop"
	NewHash     string
	PrevHash    string
}

// SurfaceSyncer reconciles a single surface.manifest.json blob into surface_manifests.
type SurfaceSyncer struct {
	repo *surfaces.Repository
	bus  EventBus
}

func NewSurfaceSyncer(repo *surfaces.Repository, bus EventBus) *SurfaceSyncer {
	return &SurfaceSyncer{repo: repo, bus: bus}
}

type rawManifest struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Metadata   struct {
		Name            string  `json:"name"`
		IntegrationType *string `json:"integration_type,omitempty"`
	} `json:"metadata"`
	Spec surfaces.ManifestSpec `json:"spec"`
}

// ReconcileFromBytes parses a manifest JSON and upserts it.
func (s *SurfaceSyncer) ReconcileFromBytes(ctx context.Context, raw []byte) (SurfaceSyncReport, error) {
	var rm rawManifest
	if err := json.Unmarshal(raw, &rm); err != nil {
		return SurfaceSyncReport{}, fmt.Errorf("parse manifest: %w", err)
	}
	if rm.Kind != "surface" {
		return SurfaceSyncReport{}, fmt.Errorf("unexpected kind %q", rm.Kind)
	}
	if rm.Metadata.Name == "" {
		return SurfaceSyncReport{}, errors.New("metadata.name required")
	}

	specBytes, err := json.Marshal(rm.Spec)
	if err != nil {
		return SurfaceSyncReport{}, fmt.Errorf("re-marshal spec: %w", err)
	}
	sum := sha256.Sum256(specBytes)
	newHash := hex.EncodeToString(sum[:])

	existing, err := s.repo.GetByName(ctx, rm.Metadata.Name)
	switch {
	case errors.Is(err, surfaces.ErrNotFound):
		m := surfaces.Manifest{
			Name:            rm.Metadata.Name,
			IntegrationType: rm.Metadata.IntegrationType,
			Category:        rm.Spec.Category,
			Spec:            rm.Spec,
			Active:          true,
		}
		if err := s.repo.Upsert(ctx, &m); err != nil {
			return SurfaceSyncReport{}, err
		}
		_ = s.bus.Emit(ctx, events.SurfaceRegistered, surfaces.RegisteredPayload{
			SurfaceName:     m.Name,
			IntegrationType: m.IntegrationType,
			Category:        m.Category,
			RegisteredAt:    time.Now().UTC(),
			Spec:            mustToMap(specBytes),
		})
		return SurfaceSyncReport{SurfaceName: m.Name, Action: "inserted", NewHash: newHash}, nil
	case err != nil:
		return SurfaceSyncReport{}, err
	}

	prevBytes, _ := json.Marshal(existing.Spec)
	prevSum := sha256.Sum256(prevBytes)
	prevHash := hex.EncodeToString(prevSum[:])
	if prevHash == newHash {
		return SurfaceSyncReport{SurfaceName: existing.Name, Action: "noop", NewHash: newHash, PrevHash: prevHash}, nil
	}

	existing.IntegrationType = rm.Metadata.IntegrationType
	existing.Category = rm.Spec.Category
	existing.Spec = rm.Spec
	if err := s.repo.Upsert(ctx, existing); err != nil {
		return SurfaceSyncReport{}, err
	}
	prevHashCopy := prevHash
	_ = s.bus.Emit(ctx, events.SurfaceUpdated, surfaces.UpdatedPayload{
		SurfaceName:     existing.Name,
		IntegrationType: existing.IntegrationType,
		PrevSpecHash:    &prevHashCopy,
		NewSpecHash:     newHash,
		UpdatedAt:       time.Now().UTC(),
	})
	return SurfaceSyncReport{SurfaceName: existing.Name, Action: "updated", NewHash: newHash, PrevHash: prevHash}, nil
}

func mustToMap(b []byte) map[string]any {
	var m map[string]any
	_ = json.Unmarshal(b, &m)
	return m
}
```

- [ ] **Step 5: Run — expect PASS**

Run: `go test ./internal/manifestsync/...`
Expected: PASS — 3 surface-related tests + existing manifest_sync tests still green.

- [ ] **Step 6: Wire SurfaceSyncer into the existing reconcile loop**

Edit `internal/manifestsync/syncer.go`. Locate the addon's main reconcile loop (the one that already iterates `integration_types`) and add an analogous loop that:

1. Calls integration-github via Yggdrasil workflow (existing helper) to list adapter repos.
2. For each repo, fetches the file `surface-ui/surface.manifest.json` (if it exists; ignore 404).
3. Passes the bytes to `SurfaceSyncer.ReconcileFromBytes(ctx, bytes)`.
4. Logs the report; on error, increments `surface_sync_failures_total` metric.

Use this skeleton (adapt to the existing helper names in syncer.go):

```go
// AFTER existing integration_types reconciliation in Run(...)
if err := s.reconcileSurfaceManifests(ctx); err != nil {
    s.log.Warn("surface manifest reconcile failed", "err", err)
}

// NEW method on the existing syncer struct
func (s *Syncer) reconcileSurfaceManifests(ctx context.Context) error {
    repos, err := s.listAdapterRepos(ctx) // existing helper from integration_types path
    if err != nil {
        return fmt.Errorf("list repos: %w", err)
    }
    for _, repo := range repos {
        raw, err := s.fetchFile(ctx, repo, "surface-ui/surface.manifest.json")
        if err != nil {
            if isNotFound(err) {
                continue
            }
            s.log.Warn("fetch surface manifest", "repo", repo, "err", err)
            continue
        }
        report, err := s.surfaceSyncer.ReconcileFromBytes(ctx, raw)
        if err != nil {
            s.log.Error("reconcile surface manifest", "repo", repo, "err", err)
            continue
        }
        s.log.Info("surface manifest reconciled", "name", report.SurfaceName, "action", report.Action)
    }
    return nil
}
```

Pass a `*SurfaceSyncer` into the existing `Syncer` constructor (modify NewSyncer to accept it).

- [ ] **Step 7: Run full manifestsync test suite**

Run: `go test ./internal/manifestsync/...`
Expected: all tests PASS (existing + 3 new surface tests).

- [ ] **Step 8: Commit**

```bash
git add internal/manifestsync
git commit -m "feat(manifestsync): reconcile surface_manifests alongside integration_types"
```

---

## Task 6: HTTP handler — GET /api/v1/surfaces (list)

**Files:**
- Create: `controllers/httpapi/surfaces.go`
- Create: `controllers/httpapi/surfaces_test.go`
- Modify: wherever the HTTP routes are registered (e.g., `controllers/httpapi/router.go`)

- [ ] **Step 1: Write failing test**

`controllers/httpapi/surfaces_test.go`:

```go
package httpapi_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/dakasa-yggdrasil/yggdrasil-core/controllers/httpapi"
	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/surfaces"
	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/testutil"
)

func TestSurfacesHandler_ListAll(t *testing.T) {
	ctx := context.Background()
	db := testutil.MustOpenTestDB(t)
	defer db.Close()
	repo := surfaces.NewRepository(db)
	intType := "slack"
	if err := repo.Upsert(ctx, &surfaces.Manifest{
		Name:            "surface-slack",
		IntegrationType: &intType,
		Category:        surfaces.CategoryIntegration,
		Spec: surfaces.ManifestSpec{
			Category: surfaces.CategoryIntegration,
			Runtime:  surfaces.Runtime{Kind: "spa", BasePath: "/s/slack"},
			Display:  surfaces.Display{Title: "Slack", AppearsOn: []string{"ops-integrations"}},
		},
		Active: true,
	}); err != nil {
		t.Fatal(err)
	}

	h := httpapi.NewSurfacesHandler(repo)
	req := httptest.NewRequest("GET", "/api/v1/surfaces", nil)
	w := httptest.NewRecorder()
	h.List(w, req)

	if w.Code != 200 {
		t.Fatalf("status %d, body %s", w.Code, w.Body.String())
	}
	var body struct {
		Items []surfaces.Manifest `json:"items"`
		Total int                 `json:"total"`
	}
	if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.Total != 1 || body.Items[0].Name != "surface-slack" {
		t.Errorf("got %+v", body)
	}
}

func TestSurfacesHandler_FilterByAppearsOn(t *testing.T) {
	ctx := context.Background()
	db := testutil.MustOpenTestDB(t)
	defer db.Close()
	repo := surfaces.NewRepository(db)
	_ = repo.Upsert(ctx, &surfaces.Manifest{
		Name:     "surface-a",
		Category: surfaces.CategoryIntegration,
		Spec: surfaces.ManifestSpec{
			Category: surfaces.CategoryIntegration,
			Display:  surfaces.Display{Title: "A", AppearsOn: []string{"ops-integrations"}},
		},
		Active: true,
	})
	_ = repo.Upsert(ctx, &surfaces.Manifest{
		Name:     "surface-b",
		Category: surfaces.CategoryIntegration,
		Spec: surfaces.ManifestSpec{
			Category: surfaces.CategoryIntegration,
			Display:  surfaces.Display{Title: "B", AppearsOn: []string{"me"}},
		},
		Active: true,
	})

	h := httpapi.NewSurfacesHandler(repo)
	req := httptest.NewRequest("GET", "/api/v1/surfaces?appears_on=me", nil)
	w := httptest.NewRecorder()
	h.List(w, req)

	if w.Code != 200 {
		t.Fatalf("status %d", w.Code)
	}
	var body struct {
		Items []surfaces.Manifest `json:"items"`
	}
	_ = json.NewDecoder(w.Body).Decode(&body)
	if len(body.Items) != 1 || body.Items[0].Name != "surface-b" {
		t.Errorf("got %+v", body.Items)
	}
}

func TestSurfacesHandler_GetByName_404(t *testing.T) {
	db := testutil.MustOpenTestDB(t)
	defer db.Close()
	repo := surfaces.NewRepository(db)

	h := httpapi.NewSurfacesHandler(repo)
	req := httptest.NewRequest("GET", "/api/v1/surfaces/surface-zzz", nil)
	req = req.WithContext(httpapi.WithPathParam(req.Context(), "name", "surface-zzz"))
	w := httptest.NewRecorder()
	h.Get(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", w.Code)
	}
}

func TestSurfacesHandler_Sync_TriggersTouch(t *testing.T) {
	ctx := context.Background()
	db := testutil.MustOpenTestDB(t)
	defer db.Close()
	repo := surfaces.NewRepository(db)
	if err := repo.Upsert(ctx, &surfaces.Manifest{
		Name:     "surface-touch",
		Category: surfaces.CategoryIntegration,
		Spec:     surfaces.ManifestSpec{Category: surfaces.CategoryIntegration, Display: surfaces.Display{Title: "T"}},
		Active:   true,
	}); err != nil {
		t.Fatal(err)
	}

	h := httpapi.NewSurfacesHandler(repo)
	req := httptest.NewRequest("POST", "/api/v1/surfaces/surface-touch/sync", strings.NewReader(""))
	req = req.WithContext(httpapi.WithPathParam(req.Context(), "name", "surface-touch"))
	w := httptest.NewRecorder()
	h.Sync(w, req)
	if w.Code != http.StatusAccepted {
		t.Errorf("status = %d, want 202", w.Code)
	}
}
```

- [ ] **Step 2: Run — expect FAIL**

Run: `go test ./controllers/httpapi/... -run Surfaces`
Expected: FAIL.

- [ ] **Step 3: Implement surfaces.go**

`controllers/httpapi/surfaces.go`:

```go
package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/surfaces"
)

// pathParamKey is the context-key type used to thread URL path params from
// the router into handlers (mirrors what other handlers in this package
// already do; if a helper exists, swap to use it).
type pathParamKey string

// WithPathParam is a small helper for tests/handlers needing to inject a
// path param; production routing will likely use chi-style param extraction.
func WithPathParam(ctx context.Context, key, value string) context.Context {
	return context.WithValue(ctx, pathParamKey(key), value)
}

func pathParam(r *http.Request, key string) string {
	v, _ := r.Context().Value(pathParamKey(key)).(string)
	return v
}

// SurfacesHandler exposes the GET/POST endpoints over surface_manifests.
type SurfacesHandler struct {
	repo *surfaces.Repository
}

func NewSurfacesHandler(repo *surfaces.Repository) *SurfacesHandler {
	return &SurfacesHandler{repo: repo}
}

// List handles GET /api/v1/surfaces (optionally filtered by query params).
func (h *SurfacesHandler) List(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	f := surfaces.ListFilter{
		AppearsOn:       q.Get("appears_on"),
		IntegrationType: q.Get("integration_type"),
		Category:        q.Get("category"),
		OnlyActive:      true,
	}
	items, err := h.repo.List(r.Context(), f)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "list_failed", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"items": items,
		"total": len(items),
	})
}

// Get handles GET /api/v1/surfaces/{name}.
func (h *SurfacesHandler) Get(w http.ResponseWriter, r *http.Request) {
	name := pathParam(r, "name")
	if name == "" {
		writeJSONError(w, http.StatusBadRequest, "missing_name", "name path segment required")
		return
	}
	m, err := h.repo.GetByName(r.Context(), name)
	if errors.Is(err, surfaces.ErrNotFound) {
		writeJSONError(w, http.StatusNotFound, "not_found", "surface manifest not found")
		return
	}
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "get_failed", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, m)
}

// Sync handles POST /api/v1/surfaces/{name}/sync — forces a re-touch so
// downstream caches see a fresh updated_at. Actual repo-pull is done by
// the manifest_sync addon on its next cycle (or by an out-of-band trigger).
func (h *SurfacesHandler) Sync(w http.ResponseWriter, r *http.Request) {
	name := pathParam(r, "name")
	if name == "" {
		writeJSONError(w, http.StatusBadRequest, "missing_name", "name path segment required")
		return
	}
	if err := h.repo.TouchUpdatedAt(r.Context(), name); err != nil {
		if errors.Is(err, surfaces.ErrNotFound) {
			writeJSONError(w, http.StatusNotFound, "not_found", "surface manifest not found")
			return
		}
		writeJSONError(w, http.StatusInternalServerError, "sync_failed", err.Error())
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]any{"sync_queued": true, "name": name})
}

// --- helpers (placed here if shared helpers already exist, prefer those) ---

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func writeJSONError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, map[string]any{"error": code, "message": message})
}
```

NOTE: if `writeJSON`/`writeJSONError` already exist in this package, REMOVE the duplicates from this file and rely on the shared ones.

- [ ] **Step 4: Register routes in router**

Locate the existing router registration (likely `controllers/httpapi/router.go` or `cmd/yggdrasil-core/main.go`). Add:

```go
sh := NewSurfacesHandler(deps.Surfaces) // wire from main.go where deps are constructed
mux.Handle("GET /api/v1/surfaces", http.HandlerFunc(sh.List))
mux.Handle("GET /api/v1/surfaces/{name}", withPathParam("name", sh.Get))
mux.Handle("POST /api/v1/surfaces/{name}/sync", withPathParam("name", sh.Sync))
```

Use the existing routing idiom (chi, gorilla, or net/http ServeMux Go 1.22 style — match what's already there).

- [ ] **Step 5: Run — expect PASS**

Run: `go test ./controllers/httpapi/... -run Surfaces`
Expected: PASS — 4 tests.

- [ ] **Step 6: Commit**

```bash
git add controllers/httpapi/surfaces.go controllers/httpapi/surfaces_test.go controllers/httpapi/router.go
git commit -m "feat(httpapi): GET/POST /api/v1/surfaces* handlers"
```

---

## Task 7: OperationOnSurfaceQuery constant + adapter contract

**Files:**
- Modify: `internal/integrations/operations.go` (or wherever operation constants live)
- Create: `internal/integrations/operations_test.go` (extend if exists)

- [ ] **Step 1: Locate existing operation constants**

```bash
grep -rn "OperationOnListIdentities\|OperationOnCollaboratorCreated" internal/integrations/*.go | head
```

- [ ] **Step 2: Write failing test**

Append to `internal/integrations/operations_test.go`:

```go
func TestOperationOnSurfaceQuery_Declared(t *testing.T) {
	if OperationOnSurfaceQuery != "on_surface_query" {
		t.Errorf("constant value = %q", OperationOnSurfaceQuery)
	}
}

func TestOperationOnSurfaceQuery_IsValidOperationName(t *testing.T) {
	if !IsValidOperationName(OperationOnSurfaceQuery) {
		t.Errorf("expected %q to pass IsValidOperationName", OperationOnSurfaceQuery)
	}
}
```

- [ ] **Step 3: Run — expect FAIL**

Run: `go test ./internal/integrations/...`
Expected: FAIL — `OperationOnSurfaceQuery` undefined.

- [ ] **Step 4: Add constant**

In `internal/integrations/operations.go`, append to the constants block:

```go
// OperationOnSurfaceQuery is the adapter capability for surface-driven
// provider-specific data queries (e.g., "list-channels" in surface-slack's
// custom Resources tab). The adapter receives {query_name, params} and
// returns arbitrary JSON.
const OperationOnSurfaceQuery = "on_surface_query"
```

If a `IsValidOperationName` or enum list exists, add `OperationOnSurfaceQuery` to it.

- [ ] **Step 5: Run — expect PASS**

Run: `go test ./internal/integrations/...`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/integrations
git commit -m "feat(operations): OperationOnSurfaceQuery — adapter capability for surface queries"
```

---

## Task 8: HTTP proxy — POST /api/v1/integrations/{id}/surface-query

**Files:**
- Create: `controllers/httpapi/integration_surface_query.go`
- Create: `controllers/httpapi/integration_surface_query_test.go`

- [ ] **Step 1: Write failing test**

`controllers/httpapi/integration_surface_query_test.go`:

```go
package httpapi_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/dakasa-yggdrasil/yggdrasil-core/controllers/httpapi"
)

type fakeDispatcher struct {
	called  bool
	request map[string]any
	resp    any
	err     error
}

func (f *fakeDispatcher) Dispatch(ctx context.Context, instanceID string, operation string, input map[string]any) (any, error) {
	f.called = true
	f.request = map[string]any{
		"instance_id": instanceID,
		"operation":   operation,
		"input":       input,
	}
	return f.resp, f.err
}

func TestSurfaceQuery_PassesThroughAndReturnsAdapterResponse(t *testing.T) {
	disp := &fakeDispatcher{resp: map[string]any{"items": []any{"a", "b"}}}
	h := httpapi.NewSurfaceQueryHandler(disp)

	body, _ := json.Marshal(map[string]any{
		"query_name": "list-channels",
		"params":     map[string]any{"filter": "all"},
	})
	req := httptest.NewRequest("POST", "/api/v1/integrations/i1/surface-query", bytes.NewReader(body))
	req = req.WithContext(httpapi.WithPathParam(req.Context(), "instance_id", "i1"))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.Handle(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", w.Code, w.Body.String())
	}
	if !disp.called {
		t.Fatal("expected dispatcher to be called")
	}
	if disp.request["operation"] != "on_surface_query" {
		t.Errorf("operation = %v", disp.request["operation"])
	}
	in := disp.request["input"].(map[string]any)
	if in["query_name"] != "list-channels" {
		t.Errorf("query_name = %v", in["query_name"])
	}

	var out map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	items := out["items"].([]any)
	if len(items) != 2 {
		t.Errorf("items = %v", items)
	}
}

func TestSurfaceQuery_400OnMissingQueryName(t *testing.T) {
	disp := &fakeDispatcher{}
	h := httpapi.NewSurfaceQueryHandler(disp)
	body, _ := json.Marshal(map[string]any{"params": map[string]any{}})
	req := httptest.NewRequest("POST", "/api/v1/integrations/i1/surface-query", bytes.NewReader(body))
	req = req.WithContext(httpapi.WithPathParam(req.Context(), "instance_id", "i1"))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.Handle(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

func TestSurfaceQuery_502OnDispatcherError(t *testing.T) {
	disp := &fakeDispatcher{err: errors.New("amqp down")}
	h := httpapi.NewSurfaceQueryHandler(disp)
	body, _ := json.Marshal(map[string]any{"query_name": "x", "params": map[string]any{}})
	req := httptest.NewRequest("POST", "/api/v1/integrations/i1/surface-query", bytes.NewReader(body))
	req = req.WithContext(httpapi.WithPathParam(req.Context(), "instance_id", "i1"))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.Handle(w, req)
	if w.Code != http.StatusBadGateway {
		t.Errorf("status = %d, want 502", w.Code)
	}
}
```

- [ ] **Step 2: Run — expect FAIL**

Run: `go test ./controllers/httpapi/... -run SurfaceQuery`
Expected: FAIL.

- [ ] **Step 3: Implement handler**

`controllers/httpapi/integration_surface_query.go`:

```go
package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
)

// AdapterDispatcher abstracts the existing RabbitMQ dispatch layer that
// invokes an adapter operation for an instance. The concrete production
// implementation lives in internal/integrations or internal/dispatch;
// the handler depends on the interface for testability.
type AdapterDispatcher interface {
	Dispatch(ctx context.Context, instanceID, operation string, input map[string]any) (any, error)
}

type SurfaceQueryHandler struct {
	dispatcher AdapterDispatcher
}

func NewSurfaceQueryHandler(d AdapterDispatcher) *SurfaceQueryHandler {
	return &SurfaceQueryHandler{dispatcher: d}
}

type surfaceQueryRequest struct {
	QueryName string         `json:"query_name"`
	Params    map[string]any `json:"params,omitempty"`
}

func (h *SurfaceQueryHandler) Handle(w http.ResponseWriter, r *http.Request) {
	instanceID := pathParam(r, "instance_id")
	if instanceID == "" {
		writeJSONError(w, http.StatusBadRequest, "missing_instance_id", "instance_id path segment required")
		return
	}
	var body surfaceQueryRequest
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&body); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid_body", err.Error())
		return
	}
	if body.QueryName == "" {
		writeJSONError(w, http.StatusBadRequest, "missing_query_name", "query_name required")
		return
	}
	input := map[string]any{
		"query_name": body.QueryName,
		"params":     body.Params,
	}
	result, err := h.dispatcher.Dispatch(r.Context(), instanceID, "on_surface_query", input)
	if err != nil {
		writeJSONError(w, http.StatusBadGateway, "adapter_dispatch_failed", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, result)
}
```

- [ ] **Step 4: Wire route**

In the router registration:

```go
sqh := NewSurfaceQueryHandler(deps.Dispatcher)
mux.Handle("POST /api/v1/integrations/{instance_id}/surface-query", withPathParam("instance_id", sqh.Handle))
```

- [ ] **Step 5: Run — expect PASS**

Run: `go test ./controllers/httpapi/... -run SurfaceQuery`
Expected: PASS — 3 tests.

- [ ] **Step 6: Commit**

```bash
git add controllers/httpapi/integration_surface_query.go controllers/httpapi/integration_surface_query_test.go
git commit -m "feat(httpapi): POST /api/v1/integrations/{id}/surface-query proxy"
```

---

## Task 9: Drift status endpoint (if not already present)

**Files:**
- Investigate first: `controllers/httpapi/integration_types.go` (likely exists)
- If missing: Create `controllers/httpapi/integration_types_drift.go` + test

- [ ] **Step 1: Check whether `/integration-types/{name}/drift` exists**

```bash
grep -rn "/integration-types.*drift\|DriftHandler\|drift_status" controllers/httpapi/ internal/manifestsync/ 2>/dev/null
```

If found → SKIP to Task 10. If not found → continue.

- [ ] **Step 2: Write failing test**

`controllers/httpapi/integration_types_drift_test.go`:

```go
package httpapi_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/dakasa-yggdrasil/yggdrasil-core/controllers/httpapi"
	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/manifestsync"
)

type fakeDriftSource struct {
	report manifestsync.DriftReport
	err    error
}

func (f *fakeDriftSource) GetDrift(name string) (manifestsync.DriftReport, error) {
	return f.report, f.err
}

func TestDriftEndpoint_ReturnsReport(t *testing.T) {
	src := &fakeDriftSource{
		report: manifestsync.DriftReport{
			IntegrationType:  "slack",
			InSync:           true,
			DeclaredVersion:  "1.3.0",
			RunningVersion:   "1.3.0",
		},
	}
	h := httpapi.NewIntegrationTypeDriftHandler(src)
	req := httptest.NewRequest("GET", "/api/v1/integration-types/slack/drift", nil)
	req = req.WithContext(httpapi.WithPathParam(req.Context(), "name", "slack"))
	w := httptest.NewRecorder()
	h.Handle(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	var body map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &body)
	if body["in_sync"] != true {
		t.Errorf("in_sync = %v", body["in_sync"])
	}
}
```

- [ ] **Step 3: Run — expect FAIL**

Run: `go test ./controllers/httpapi/... -run Drift`
Expected: FAIL.

- [ ] **Step 4: Implement DriftReport + handler**

If `manifestsync.DriftReport` doesn't exist yet, define it. Otherwise, augment.

In `internal/manifestsync/drift.go` (create if missing):

```go
package manifestsync

// DriftReport summarises the validation state of an integration_type
// manifest in the database against the running adapter.
type DriftReport struct {
	IntegrationType string         `json:"integration_type"`
	InSync          bool           `json:"in_sync"`
	LastSyncAt      string         `json:"last_sync_at,omitempty"`
	DeclaredVersion string         `json:"declared_version,omitempty"`
	RunningVersion  string         `json:"running_version,omitempty"`
	Failures        []DriftFailure `json:"failures,omitempty"`
}

type DriftFailure struct {
	Field  string `json:"field"`
	Reason string `json:"reason"`
}

// DriftSource is the dependency the HTTP handler needs.
type DriftSource interface {
	GetDrift(name string) (DriftReport, error)
}
```

In `controllers/httpapi/integration_types_drift.go`:

```go
package httpapi

import (
	"net/http"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/manifestsync"
)

type IntegrationTypeDriftHandler struct {
	src manifestsync.DriftSource
}

func NewIntegrationTypeDriftHandler(src manifestsync.DriftSource) *IntegrationTypeDriftHandler {
	return &IntegrationTypeDriftHandler{src: src}
}

func (h *IntegrationTypeDriftHandler) Handle(w http.ResponseWriter, r *http.Request) {
	name := pathParam(r, "name")
	if name == "" {
		writeJSONError(w, http.StatusBadRequest, "missing_name", "name path segment required")
		return
	}
	report, err := h.src.GetDrift(name)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "drift_lookup_failed", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, report)
}
```

Wire it up: provide a concrete `DriftSource` impl in `internal/manifestsync/` that joins the syncer's last-known state with the integration_type row. Wire into router:

```go
dh := NewIntegrationTypeDriftHandler(deps.DriftSource)
mux.Handle("GET /api/v1/integration-types/{name}/drift", withPathParam("name", dh.Handle))
```

- [ ] **Step 5: Run — expect PASS**

Run: `go test ./controllers/httpapi/... -run Drift`
Expected: PASS — 1 test.

- [ ] **Step 6: Commit**

```bash
git add controllers/httpapi internal/manifestsync
git commit -m "feat(drift): GET /api/v1/integration-types/{name}/drift endpoint"
```

---

## Task 10: Wire all new handlers in main + verify build

**Files:**
- Modify: `cmd/yggdrasil-core/main.go` (or wherever deps + router are wired)

- [ ] **Step 1: Locate the constructor / dep injection site**

```bash
grep -n "NewSurfacesHandler\|NewSurfaceQueryHandler\|router\|Mux" cmd/yggdrasil-core/main.go controllers/httpapi/router.go 2>/dev/null
```

- [ ] **Step 2: Wire dependencies**

Edit `cmd/yggdrasil-core/main.go` (or equivalent) so that:

1. A `*surfaces.Repository` is constructed from the existing `*sql.DB`.
2. The existing `*manifestsync.Syncer` constructor accepts a `*manifestsync.SurfaceSyncer` (constructed from the repo + existing event bus).
3. `NewSurfacesHandler`, `NewSurfaceQueryHandler`, `NewIntegrationTypeDriftHandler` are constructed.
4. Routes are registered.

Use the existing patterns in that file (typically a `deps` struct + a `registerHTTPRoutes(deps)` call).

- [ ] **Step 3: Build the binary**

```bash
cd /Users/dakasa/projects/yggdrasil/yggdrasil-core
GOWORK=/Users/dakasa/projects/dakasa/go.work go build ./...
```

Expected: 0 errors.

- [ ] **Step 4: Run full test suite**

```bash
GOWORK=/Users/dakasa/projects/dakasa/go.work go test ./...
```

Expected: all tests PASS.

- [ ] **Step 5: Commit**

```bash
git add cmd internal controllers
git commit -m "feat(wire): integrate surfaces handlers + dispatcher into main"
```

---

## Task 11: Smoke E2E against local instance

**Files:** none (verification only)

- [ ] **Step 1: Start yggdrasil-core locally**

```bash
GOWORK=/Users/dakasa/projects/dakasa/go.work go run ./cmd/yggdrasil-core
```

- [ ] **Step 2: From another shell — verify GET returns empty array**

```bash
curl -s -H "Authorization: Bearer $YGGDRASIL_WORKFLOW_RUN_TOKEN" \
  http://localhost:9080/api/v1/surfaces | jq .
```

Expected: `{"items":[],"total":0}`.

- [ ] **Step 3: Manually insert a sample manifest and re-GET**

```bash
psql "$DATABASE_URL" <<'SQL'
INSERT INTO surface_manifests (name, integration_type, category, spec, active)
VALUES (
  'surface-smoke',
  NULL,
  'core',
  '{"category":"core","runtime":{"kind":"spa","base_path":"/s/smoke"},"display":{"title":"Smoke","appears_on":["ops-integrations"]}}'::jsonb,
  true
);
SQL
curl -s http://localhost:9080/api/v1/surfaces?appears_on=ops-integrations | jq .
```

Expected: response includes `surface-smoke`.

- [ ] **Step 4: Cleanup**

```bash
psql "$DATABASE_URL" -c "DELETE FROM surface_manifests WHERE name = 'surface-smoke';"
```

- [ ] **Step 5: Tag the sync gate**

```bash
git commit --allow-empty -m "chore: Phase 0b complete — surface_manifests + endpoints live"
```

---

## Phase 0b sync gate (after Task 11)

Before Phase 1 surfaces may rely on these endpoints:

1. ✅ Migration `00045_surface_manifests.sql` applied
2. ✅ `/api/v1/surfaces` returns 200 + `{items:[], total:0}` in clean state
3. ✅ `/api/v1/surfaces?appears_on=X` correctly filters
4. ✅ `/api/v1/surfaces/{name}/sync` returns 202 for existing, 404 for unknown
5. ✅ `/api/v1/integrations/{instance_id}/surface-query` dispatches `on_surface_query` via existing AMQP layer
6. ✅ `manifest_sync` reconciles surface_manifests when it encounters a new `surface-ui/surface.manifest.json` in any adapter repo
7. ✅ Canon events emit on register/update/deactivate
8. ✅ All Go tests pass; binary builds cleanly

---

## Final code reviewer dispatch (after Task 11)

After all tasks complete, dispatch one final code reviewer subagent. Reviewer checks:

- All routes documented in spec §4.4 are registered
- Operation constant matches spec §5.5 exactly: `on_surface_query`
- Event constants match spec §4.3 exactly: `surface.registered`, `surface.updated`, `surface.deactivated`, `surface.drift_detected`
- All handlers return JSON with `Content-Type: application/json`
- Errors use stable `{error, message}` shape
- Slot filter (`appears_on`) uses `@>` jsonb operator (gin index used)
- No dependency on integration-specific code (`internal/integrations/slack`, etc.) — surface code stays neutral
- Repo method `TouchUpdatedAt` is idempotent
