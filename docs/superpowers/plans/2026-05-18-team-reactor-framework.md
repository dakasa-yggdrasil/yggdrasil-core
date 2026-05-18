# Team Reactor Framework Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the gap where Yggdrasil emits `team.*` canon events but adapters don't fully react — add the missing handlers in slack/github/google-workspace and a provisioning log so the system reconciles pre-existing teams automatically.

**Architecture:** Reuse the existing reactor framework (canon events → MaterializeReactions → AMQP RPC). New table `team_provisioning_log` tracks which (team, integration_instance) pairs have been mirrored externally. Adapters return an `_yggdrasil.team_provisioned` envelope on `on_team_created` ack; the core dispatcher upserts the log. A cron addon (5-min tick) sweeps `teams × instances MINUS log` and re-emits `team.created` for the gaps. Two new endpoints expose state (`/sync`, `/provisioning-status`).

**Tech Stack:** Go 1.25 (yggdrasil-core, integration-slack, integration-github, integration-google-workspace), PostgreSQL (goose migrations), AMQP RPC between core and adapters.

**Spec:** `docs/superpowers/specs/2026-05-18-team-reactor-framework-design.md`

**Conventions to follow:**
- Push directly to `main` on every repo (DaKasa convention — no PRs for integration repos or yggdrasil-core)
- Commits via HEREDOC with `Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>` trailer
- Verify build (`go build ./...`) + tests pass before pushing
- yggdrasil-core repo path: `/Users/dakasa/projects/yggdrasil/yggdrasil-core`
- Adapter repos: `/Users/dakasa/projects/yggdrasil/integration-{slack,github,google-workspace}`

---

## File inventory

### yggdrasil-core
- `migrations/00043_team_provisioning_log.sql` — new
- `model/team_provisioning_log.go` — new
- `repository/team_provisioning_log.go` — new (+ `_test.go`)
- `internal/teamprovisioning/envelope.go` — new (mirror of `internal/externalidentity/envelope.go`) (+ `_test.go`)
- `addons/reactor_dispatcher.go` — modify (call new envelope extractor + persist log)
- `internal/teamreconcile/runner.go` — new (+ `_test.go`)
- `internal/teamreconcile/repository.go` — new (the anti-join SQL) (+ `_test.go`)
- `controllers/httpapi/team_sync.go` — new (both endpoints) (+ `_test.go`)
- `controllers/httpapi/server.go` — modify (route registration, addon wiring)

### integration-slack
- `internal/adapter/spec.go` — modify (3 operation constants + reactor entries)
- `internal/adapter/reactors.go` — modify (`onTeamCreated`, `onTeamUpdated`, `onTeamDeleted`)
- `internal/adapter/reactors_test.go` — modify
- `examples/integration_type.example.json` — modify (3 reactors entries)

### integration-github
- `internal/adapter/spec.go` — modify (2 operation constants + reactor entries)
- `internal/adapter/reactors.go` — modify (`onTeamUpdated`, `onTeamDeleted`)
- `internal/adapter/reactors_test.go` — modify
- `examples/integration_type.example.json` — modify (2 reactors entries)

### integration-google-workspace
- `providers/runtime/adapter/spec.go` — modify (3 operation constants + reactor entries)
- `providers/runtime/adapter/reactors.go` — modify (3 handlers)
- `providers/runtime/adapter/reactors_test.go` — modify
- `providers/runtime/manifest.json` — modify (3 reactors entries)

---

## Phase 0: Core foundation (yggdrasil-core)

### Task 1: Migration `team_provisioning_log`

**Files:**
- Create: `/Users/dakasa/projects/yggdrasil/yggdrasil-core/migrations/00043_team_provisioning_log.sql`

> Verify the next migration number before starting: `ls migrations/ | tail`. If `00042` is not the latest, pick `<latest>+1` and adjust the filename everywhere it appears in this plan.

- [ ] **Step 1: Write the migration file**

```sql
-- +goose Up
-- +goose StatementBegin
CREATE TABLE team_provisioning_log (
    id                       UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    team_id                  UUID NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
    integration_instance_id  UUID NOT NULL REFERENCES manifests(id) ON DELETE CASCADE,
    external_id              TEXT NOT NULL,
    external_metadata        JSONB NOT NULL DEFAULT '{}'::jsonb,
    last_success_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_event_type          TEXT NOT NULL,
    created_at               TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at               TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (team_id, integration_instance_id)
);

CREATE INDEX idx_team_provisioning_log_team ON team_provisioning_log(team_id);
CREATE INDEX idx_team_provisioning_log_instance ON team_provisioning_log(integration_instance_id);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS team_provisioning_log;
-- +goose StatementEnd
```

- [ ] **Step 2: Verify goose understands the file**

Run: `cd /Users/dakasa/projects/yggdrasil/yggdrasil-core && grep -l "team_provisioning_log" migrations/`
Expected: prints `migrations/00043_team_provisioning_log.sql`

- [ ] **Step 3: Build check (no go code changed yet, but confirm clean tree)**

Run: `go build ./...`
Expected: exit 0, no output

- [ ] **Step 4: Commit**

```bash
git add migrations/00043_team_provisioning_log.sql
git commit -m "$(cat <<'EOF'
feat(team-reactor): migration 00043 — team_provisioning_log table

Tracks which (team, integration_instance) pairs have been successfully
provisioned in an external system (slack channel, gh team, gw group).
Powers the reconcile cron and the /teams/{id}/provisioning-status endpoint.

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

---

### Task 2: Model + repository for `team_provisioning_log`

**Files:**
- Create: `/Users/dakasa/projects/yggdrasil/yggdrasil-core/model/team_provisioning_log.go`
- Create: `/Users/dakasa/projects/yggdrasil/yggdrasil-core/repository/team_provisioning_log.go`
- Create: `/Users/dakasa/projects/yggdrasil/yggdrasil-core/repository/team_provisioning_log_test.go`

- [ ] **Step 1: Write the model file**

```go
// model/team_provisioning_log.go
package model

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

// TeamProvisioningLog records that a Yggdrasil team has been mirrored
// into an external system (Slack channel, GitHub team, GW group, ...).
// The reconcile cron uses this table to skip pairs that already have a
// mirror; /teams/{id}/provisioning-status reads it to surface state to
// operators.
type TeamProvisioningLog struct {
	ID                    uuid.UUID       `json:"id"`
	TeamID                uuid.UUID       `json:"team_id"`
	IntegrationInstanceID uuid.UUID       `json:"integration_instance_id"`
	ExternalID            string          `json:"external_id"`
	ExternalMetadata      json.RawMessage `json:"external_metadata"`
	LastSuccessAt         time.Time       `json:"last_success_at"`
	LastEventType         string          `json:"last_event_type"`
	CreatedAt             time.Time       `json:"created_at"`
	UpdatedAt             time.Time       `json:"updated_at"`
}

// UpsertTeamProvisioningLogRequest is the input to
// repository.UpsertTeamProvisioningLog. Called by the reactor dispatcher
// when an adapter returns an `_yggdrasil.team_provisioned` envelope.
type UpsertTeamProvisioningLogRequest struct {
	TeamID                uuid.UUID
	IntegrationInstanceID uuid.UUID
	ExternalID            string
	ExternalMetadata      map[string]any
	LastEventType         string
}
```

- [ ] **Step 2: Write the failing repository tests**

```go
// repository/team_provisioning_log_test.go
package repository

import (
	"context"
	"database/sql"
	"testing"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

func TestUpsertTeamProvisioningLogInsertsThenUpdates(t *testing.T) {
	db := openTestDB(t)
	defer db.Close()

	teamID := seedTeam(t, db)
	instanceID := seedIntegrationInstance(t, db)

	first, err := UpsertTeamProvisioningLog(context.Background(), db, model.UpsertTeamProvisioningLogRequest{
		TeamID:                teamID,
		IntegrationInstanceID: instanceID,
		ExternalID:            "C123",
		ExternalMetadata:      map[string]any{"channel_name": "team-eng"},
		LastEventType:         "team.created",
	})
	if err != nil {
		t.Fatalf("first upsert: %v", err)
	}
	if first.ExternalID != "C123" {
		t.Fatalf("expected external_id C123, got %s", first.ExternalID)
	}

	second, err := UpsertTeamProvisioningLog(context.Background(), db, model.UpsertTeamProvisioningLogRequest{
		TeamID:                teamID,
		IntegrationInstanceID: instanceID,
		ExternalID:            "C123",
		ExternalMetadata:      map[string]any{"channel_name": "team-eng-renamed"},
		LastEventType:         "team.updated",
	})
	if err != nil {
		t.Fatalf("second upsert: %v", err)
	}
	if second.ID != first.ID {
		t.Fatalf("expected same id on conflict (got %s vs %s)", first.ID, second.ID)
	}
	if second.LastEventType != "team.updated" {
		t.Fatalf("expected last_event_type team.updated, got %s", second.LastEventType)
	}
	if !second.UpdatedAt.After(first.UpdatedAt) && !second.UpdatedAt.Equal(first.UpdatedAt) {
		t.Fatalf("expected updated_at to advance, got first=%v second=%v", first.UpdatedAt, second.UpdatedAt)
	}
}

func TestListTeamProvisioningLogByTeam(t *testing.T) {
	db := openTestDB(t)
	defer db.Close()

	teamID := seedTeam(t, db)
	instance1 := seedIntegrationInstance(t, db)
	instance2 := seedIntegrationInstance(t, db)

	for _, inst := range []uuid.UUID{instance1, instance2} {
		if _, err := UpsertTeamProvisioningLog(context.Background(), db, model.UpsertTeamProvisioningLogRequest{
			TeamID:                teamID,
			IntegrationInstanceID: inst,
			ExternalID:            "ext-" + inst.String(),
			LastEventType:         "team.created",
		}); err != nil {
			t.Fatalf("seed: %v", err)
		}
	}

	rows, err := ListTeamProvisioningLogByTeam(context.Background(), db, teamID)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("expected 2 rows, got %d", len(rows))
	}
}

// openTestDB, seedTeam, seedIntegrationInstance are existing test helpers
// — re-use what other repository tests in this package already do. If
// they live in a `testdb_helpers.go` file, add the seeds there.
func openTestDB(t *testing.T) *sql.DB { t.Helper(); return nil }       // implemented in helpers
func seedTeam(t *testing.T, db *sql.DB) uuid.UUID { t.Helper(); return uuid.Nil }
func seedIntegrationInstance(t *testing.T, db *sql.DB) uuid.UUID { t.Helper(); return uuid.Nil }
```

> **Note:** the test helpers (`openTestDB`, `seedTeam`, `seedIntegrationInstance`) are placeholders only when this file is read in isolation. Before running, find the canonical helpers in `repository/` (look at how `identity_test.go` and other existing repository tests bootstrap a DB) and re-use them. Delete the stub functions at the bottom of this file once you wire in the real helpers.

- [ ] **Step 3: Run tests to verify they fail**

Run: `go test ./repository/ -run TestUpsertTeamProvisioningLog -v -count=1`
Expected: FAIL with `undefined: UpsertTeamProvisioningLog`

- [ ] **Step 4: Write the repository implementation**

```go
// repository/team_provisioning_log.go
package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

// UpsertTeamProvisioningLog inserts a new row or updates the existing one
// for the (team_id, integration_instance_id) pair. The adapter envelope
// extractor in addons/reactor_dispatcher.go calls this after a successful
// on_team_created / on_team_updated ack.
func UpsertTeamProvisioningLog(ctx context.Context, db *sql.DB, req model.UpsertTeamProvisioningLogRequest) (model.TeamProvisioningLog, error) {
	meta, err := json.Marshal(req.ExternalMetadata)
	if err != nil {
		return model.TeamProvisioningLog{}, fmt.Errorf("marshal external_metadata: %w", err)
	}
	if len(meta) == 0 || string(meta) == "null" {
		meta = []byte("{}")
	}
	var row model.TeamProvisioningLog
	err = db.QueryRowContext(ctx, `
		INSERT INTO team_provisioning_log
			(team_id, integration_instance_id, external_id, external_metadata, last_event_type)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (team_id, integration_instance_id) DO UPDATE
		SET external_id       = EXCLUDED.external_id,
		    external_metadata = EXCLUDED.external_metadata,
		    last_success_at   = NOW(),
		    last_event_type   = EXCLUDED.last_event_type,
		    updated_at        = NOW()
		RETURNING id, team_id, integration_instance_id, external_id,
		          external_metadata, last_success_at, last_event_type,
		          created_at, updated_at
	`, req.TeamID, req.IntegrationInstanceID, req.ExternalID, meta, req.LastEventType).
		Scan(&row.ID, &row.TeamID, &row.IntegrationInstanceID, &row.ExternalID,
			&row.ExternalMetadata, &row.LastSuccessAt, &row.LastEventType,
			&row.CreatedAt, &row.UpdatedAt)
	if err != nil {
		return model.TeamProvisioningLog{}, fmt.Errorf("upsert team_provisioning_log: %w", err)
	}
	return row, nil
}

// ListTeamProvisioningLogByTeam returns every mirror entry for a single team.
// Used by GET /api/v1/teams/{id}/provisioning-status to render the
// per-adapter mirror state.
func ListTeamProvisioningLogByTeam(ctx context.Context, db *sql.DB, teamID uuid.UUID) ([]model.TeamProvisioningLog, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT id, team_id, integration_instance_id, external_id, external_metadata,
		       last_success_at, last_event_type, created_at, updated_at
		FROM team_provisioning_log
		WHERE team_id = $1
		ORDER BY created_at ASC
	`, teamID)
	if err != nil {
		return nil, fmt.Errorf("list team_provisioning_log: %w", err)
	}
	defer rows.Close()

	var out []model.TeamProvisioningLog
	for rows.Next() {
		var r model.TeamProvisioningLog
		if err := rows.Scan(&r.ID, &r.TeamID, &r.IntegrationInstanceID, &r.ExternalID,
			&r.ExternalMetadata, &r.LastSuccessAt, &r.LastEventType,
			&r.CreatedAt, &r.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan: %w", err)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `go test ./repository/ -run TeamProvisioningLog -v -count=1`
Expected: PASS

- [ ] **Step 6: Build the whole tree**

Run: `go build ./...`
Expected: exit 0

- [ ] **Step 7: Commit**

```bash
git add model/team_provisioning_log.go repository/team_provisioning_log.go repository/team_provisioning_log_test.go
git commit -m "$(cat <<'EOF'
feat(team-reactor): model + repository for team_provisioning_log

UpsertTeamProvisioningLog: ON CONFLICT (team_id, integration_instance_id)
DO UPDATE — idempotent under repeated adapter envelopes.

ListTeamProvisioningLogByTeam: per-team mirror inventory for
/provisioning-status endpoint.

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

---

### Task 3: Envelope extractor + dispatcher wire-up

**Files:**
- Create: `/Users/dakasa/projects/yggdrasil/yggdrasil-core/internal/teamprovisioning/envelope.go`
- Create: `/Users/dakasa/projects/yggdrasil/yggdrasil-core/internal/teamprovisioning/envelope_test.go`
- Modify: `/Users/dakasa/projects/yggdrasil/yggdrasil-core/addons/reactor_dispatcher.go`

- [ ] **Step 1: Write the failing envelope test**

```go
// internal/teamprovisioning/envelope_test.go
package teamprovisioning

import "testing"

func TestExtractFromOutput_MissingBlock(t *testing.T) {
	if _, ok := ExtractFromOutput(map[string]any{"foo": "bar"}); ok {
		t.Fatal("expected no extraction when _yggdrasil missing")
	}
}

func TestExtractFromOutput_ValidBlock(t *testing.T) {
	out := map[string]any{
		"_yggdrasil": map[string]any{
			"team_provisioned": map[string]any{
				"external_id":       "C123",
				"external_metadata": map[string]any{"channel_name": "team-eng"},
			},
		},
	}
	ext, ok := ExtractFromOutput(out)
	if !ok {
		t.Fatal("expected extraction to succeed")
	}
	if ext.ExternalID != "C123" {
		t.Fatalf("expected external_id C123, got %s", ext.ExternalID)
	}
	if ext.ExternalMetadata["channel_name"] != "team-eng" {
		t.Fatalf("expected channel_name team-eng, got %v", ext.ExternalMetadata["channel_name"])
	}
}

func TestExtractFromOutput_MalformedMissingExternalID(t *testing.T) {
	out := map[string]any{
		"_yggdrasil": map[string]any{
			"team_provisioned": map[string]any{"external_metadata": map[string]any{}},
		},
	}
	if _, ok := ExtractFromOutput(out); ok {
		t.Fatal("expected extraction to fail without external_id")
	}
}

func TestExtractFromOutput_NilInput(t *testing.T) {
	if _, ok := ExtractFromOutput(nil); ok {
		t.Fatal("expected no extraction for nil input")
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/teamprovisioning/ -v -count=1`
Expected: FAIL with `undefined: ExtractFromOutput`

- [ ] **Step 3: Write the envelope implementation**

```go
// internal/teamprovisioning/envelope.go
package teamprovisioning

import "strings"

// Extracted is the result of ExtractFromOutput.
type Extracted struct {
	ExternalID       string
	ExternalMetadata map[string]any
}

// ExtractFromOutput inspects the adapter's response output map for the
// convention block output._yggdrasil.team_provisioned. Returns (extracted,
// true) when the block is present and well-formed; (zero, false) otherwise.
// Malformed blocks (missing external_id) are silently dropped — log writing
// is opt-in metadata, never load-bearing.
//
// Mirror of internal/externalidentity/envelope.go ExtractFromOutput. Kept
// in its own package so the dependency direction stays one-way (adapters
// → core).
func ExtractFromOutput(output map[string]any) (Extracted, bool) {
	if output == nil {
		return Extracted{}, false
	}
	ygg, ok := output["_yggdrasil"].(map[string]any)
	if !ok {
		return Extracted{}, false
	}
	tp, ok := ygg["team_provisioned"].(map[string]any)
	if !ok {
		return Extracted{}, false
	}
	ext, ok := tp["external_id"].(string)
	if !ok || strings.TrimSpace(ext) == "" {
		return Extracted{}, false
	}
	meta, _ := tp["external_metadata"].(map[string]any)
	return Extracted{ExternalID: ext, ExternalMetadata: meta}, true
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/teamprovisioning/ -v -count=1`
Expected: PASS (4 tests)

- [ ] **Step 5: Wire dispatcher to call extractor + persist**

> First read the dispatcher: `cat addons/reactor_dispatcher.go | head -180`. Look for the existing `externalidentity.ExtractFromOutput` call site (around line 157 in the current tree). Add a sibling block right after it that does the team variant.

In `addons/reactor_dispatcher.go`, immediately after the existing `if ext, ok := externalidentity.ExtractFromOutput(outputMap); ok { … }` block, add:

```go
		// Team provisioning envelope: when on_team_created / on_team_updated
		// returns `_yggdrasil.team_provisioned`, upsert team_provisioning_log so
		// the reconcile cron skips this pair and /provisioning-status shows it.
		if c.db != nil {
			if outputMap, ok := resp.Output.(map[string]any); ok {
				if ext, ok := teamprovisioning.ExtractFromOutput(outputMap); ok {
					c.persistTeamProvisioning(ctx, integrationInstanceID, input, ext, eventType)
				}
			}
		}
```

> Replace `eventType` and `input` and `integrationInstanceID` with whatever the local variables in the `Call` method are named — read the file to confirm. The pattern should match how `persistExternalIdentity` is invoked.

Then add the persist helper at the bottom of the file (mirror of `persistExternalIdentity`):

```go
// persistTeamProvisioning upserts the extracted team mirror metadata.
// All errors are logged and swallowed — the reaction has already
// succeeded; failing to write the log row would not undo the external
// resource. The reconcile cron will pick the gap up next tick if needed.
func (c *rabbitmqReactorCaller) persistTeamProvisioning(
	ctx context.Context,
	integrationInstanceID string,
	input map[string]any,
	ext teamprovisioning.Extracted,
	eventType string,
) {
	teamIDStr, _ := input["id"].(string)
	if strings.TrimSpace(teamIDStr) == "" {
		// payload didn't carry the team id — nothing to anchor the log against
		return
	}
	teamID, err := uuid.Parse(teamIDStr)
	if err != nil {
		return
	}
	instanceID, err := uuid.Parse(integrationInstanceID)
	if err != nil {
		return
	}
	if _, err := repository.UpsertTeamProvisioningLog(ctx, c.db, model.UpsertTeamProvisioningLogRequest{
		TeamID:                teamID,
		IntegrationInstanceID: instanceID,
		ExternalID:            ext.ExternalID,
		ExternalMetadata:      ext.ExternalMetadata,
		LastEventType:         eventType,
	}); err != nil {
		// best-effort; the reaction itself already succeeded
		if c.logger != nil {
			c.logger.Warn("persist team_provisioning_log failed",
				zap.String("team_id", teamIDStr),
				zap.String("integration_instance_id", integrationInstanceID),
				zap.Error(err))
		}
	}
}
```

Add to imports at the top of the file:

```go
	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/teamprovisioning"
```

> If `model`, `repository`, `strings`, `uuid`, `zap` aren't already imported in this file, add them. Verify with `goimports -w addons/reactor_dispatcher.go` after editing.

- [ ] **Step 6: Build + test**

Run: `go build ./... && go test ./addons/ ./internal/teamprovisioning/ -count=1`
Expected: exit 0, all PASS

- [ ] **Step 7: Commit**

```bash
git add internal/teamprovisioning/ addons/reactor_dispatcher.go
git commit -m "$(cat <<'EOF'
feat(team-reactor): envelope extractor + dispatcher persist hook

ExtractFromOutput mirrors externalidentity.ExtractFromOutput for the
team_provisioned block. Dispatcher persists the log row best-effort
after a successful adapter ack — failures swallowed, reconcile cron is
the safety net.

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

---

### Task 4: HTTP `POST /api/v1/teams/{id}/sync`

**Files:**
- Create: `/Users/dakasa/projects/yggdrasil/yggdrasil-core/controllers/httpapi/team_sync.go`
- Create: `/Users/dakasa/projects/yggdrasil/yggdrasil-core/controllers/httpapi/team_sync_test.go`
- Modify: `/Users/dakasa/projects/yggdrasil/yggdrasil-core/controllers/httpapi/server.go` (route registration)

- [ ] **Step 1: Write the failing HTTP test**

```go
// controllers/httpapi/team_sync_test.go
package httpapi

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func TestPostTeamSyncEmitsTeamCreated(t *testing.T) {
	srv, db := newTestServer(t)
	defer db.Close()

	teamID := seedActiveTeam(t, db)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/teams/"+teamID.String()+"/sync", strings.NewReader(""))
	rr := httptest.NewRecorder()
	srv.ServeHTTP(rr, req)

	if rr.Code != http.StatusAccepted {
		t.Fatalf("expected 202 Accepted, got %d (body=%s)", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), `"events_emitted"`) {
		t.Fatalf("expected events_emitted in response, got: %s", rr.Body.String())
	}

	// Confirm a team.created row landed in event_log
	var count int
	if err := db.QueryRow(`
		SELECT COUNT(*) FROM event_log
		WHERE type = 'team.created' AND aggregate_id = $1
	`, teamID.String()).Scan(&count); err != nil {
		t.Fatalf("query event_log: %v", err)
	}
	if count == 0 {
		t.Fatal("expected event_log row for team.created")
	}
}

func TestPostTeamSyncReturns404ForUnknownTeam(t *testing.T) {
	srv, db := newTestServer(t)
	defer db.Close()

	req := httptest.NewRequest(http.MethodPost, "/api/v1/teams/"+uuid.NewString()+"/sync", strings.NewReader(""))
	rr := httptest.NewRecorder()
	srv.ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", rr.Code)
	}
}
```

> Re-use the existing `newTestServer` and `seedActiveTeam` helpers — look at any of the existing `*_test.go` files in `controllers/httpapi/` for the pattern (e.g. how `team_membership_test.go` or `team_create_test.go` bootstrap).

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./controllers/httpapi/ -run TestPostTeamSync -v -count=1`
Expected: FAIL with 404 (route not registered)

- [ ] **Step 3: Write the handler**

```go
// controllers/httpapi/team_sync.go
package httpapi

import (
	"fmt"
	"net/http"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	"github.com/google/uuid"
)

// handleTeamSync re-emits a team.created canon event for the given team.
// Operator-triggered escape hatch when the automatic reconcile cron
// hasn't caught a gap yet (or as a debugging aid after an adapter fix).
// Adapter idempotency makes this safe to invoke arbitrarily.
//
// Returns 202 Accepted + {events_emitted: 1} on success — the event is
// inserted in event_log, and MaterializeReactions schedules one reaction
// row per matching active integration_instance.
func (s *Server) handleTeamSync(w http.ResponseWriter, r *http.Request) {
	teamIDStr := r.PathValue("id")
	teamID, err := uuid.Parse(teamIDStr)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid team id"})
		return
	}

	team, err := repository.GetTeamByID(r.Context(), s.db, teamID)
	if err != nil {
		writeMappedError(w, err)
		return
	}

	tx, err := s.db.BeginTx(r.Context(), nil)
	if err != nil {
		writeMappedError(w, fmt.Errorf("begin tx: %w", err))
		return
	}
	defer func() { _ = tx.Rollback() }()

	payload := map[string]any{
		"id":   team.ID.String(),
		"slug": team.Slug,
		"name": team.Name,
		"type": team.Type,
	}
	if team.ParentTeamID != nil {
		payload["parent_team_id"] = team.ParentTeamID.String()
	}

	if _, err := repository.EmitEvent(r.Context(), tx, model.EmitEventRequest{
		Type:          repository.EventTypeTeamCreated,
		SchemaVersion: "v1",
		AggregateType: "team",
		AggregateID:   team.ID.String(),
		Payload:       payload,
		Actor: &model.EventActor{
			Type: model.ActorTypeAPI,
			ID:   actorIDFromRequest(r),
		},
	}); err != nil {
		writeMappedError(w, fmt.Errorf("emit team.created: %w", err))
		return
	}

	if err := tx.Commit(); err != nil {
		writeMappedError(w, fmt.Errorf("commit team.sync: %w", err))
		return
	}

	writeJSON(w, http.StatusAccepted, map[string]any{
		"team_id":         team.ID,
		"events_emitted":  1,
		"event_type":      repository.EventTypeTeamCreated,
	})
}
```

> If `repository.GetTeamByID` doesn't exist yet, find what the codebase uses today (likely `GetTeam` or `FindTeamByID`). Use whichever returns a single team with a 404-friendly error.

- [ ] **Step 4: Register the route**

In `controllers/httpapi/server.go`, find the block where team routes are registered (search for `mux.HandleFunc.*teams/{id}`). Add immediately after the team CRUD routes:

```go
	mux.HandleFunc("POST /api/v1/teams/{id}/sync", guard(server.handleTeamSync))
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `go test ./controllers/httpapi/ -run TestPostTeamSync -v -count=1`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add controllers/httpapi/team_sync.go controllers/httpapi/team_sync_test.go controllers/httpapi/server.go
git commit -m "$(cat <<'EOF'
feat(team-reactor): POST /api/v1/teams/{id}/sync endpoint

Re-emits team.created for one team. Adapter idempotency makes it safe
to call any number of times. Operator escape hatch when the reconcile
cron hasn't caught a gap yet.

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

---

### Task 5: HTTP `GET /api/v1/teams/{id}/provisioning-status`

**Files:**
- Modify: `/Users/dakasa/projects/yggdrasil/yggdrasil-core/controllers/httpapi/team_sync.go` (add handler)
- Modify: `/Users/dakasa/projects/yggdrasil/yggdrasil-core/controllers/httpapi/team_sync_test.go` (add test)
- Modify: `/Users/dakasa/projects/yggdrasil/yggdrasil-core/controllers/httpapi/server.go` (route)

- [ ] **Step 1: Write the failing test**

Append to `team_sync_test.go`:

```go
func TestGetTeamProvisioningStatus(t *testing.T) {
	srv, db := newTestServer(t)
	defer db.Close()

	teamID := seedActiveTeam(t, db)
	slackInstance := seedIntegrationInstance(t, db)
	githubInstance := seedIntegrationInstance(t, db)

	// One mirror present (slack), one missing (github).
	if _, err := db.Exec(`
		INSERT INTO team_provisioning_log
		    (team_id, integration_instance_id, external_id, last_event_type)
		VALUES ($1, $2, 'C123', 'team.created')
	`, teamID, slackInstance); err != nil {
		t.Fatalf("seed log: %v", err)
	}

	// Inject a pending reaction row for github so it shows up under "pending".
	if _, err := db.Exec(`
		INSERT INTO integration_event_reactions
		    (event_id, event_type, integration_instance_id, integration_type_manifest_id, capability, status, next_attempt_at)
		VALUES (gen_random_uuid(), 'team.created', $1, $1, 'on_team_created', 'pending', NOW())
	`, githubInstance); err != nil {
		t.Fatalf("seed reaction: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/teams/"+teamID.String()+"/provisioning-status", nil)
	rr := httptest.NewRecorder()
	srv.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d (body=%s)", rr.Code, rr.Body.String())
	}
	for _, want := range []string{`"provisioning"`, `"pending"`, `"dead_lettered"`, `"C123"`} {
		if !strings.Contains(rr.Body.String(), want) {
			t.Fatalf("expected %s in body, got: %s", want, rr.Body.String())
		}
	}
}
```

- [ ] **Step 2: Run to verify FAIL**

Run: `go test ./controllers/httpapi/ -run TestGetTeamProvisioningStatus -v -count=1`
Expected: FAIL — 404 (route missing)

- [ ] **Step 3: Implement the handler**

Append to `team_sync.go`:

```go
// handleTeamProvisioningStatus returns the per-adapter provisioning state
// for a team: which integration_instances have a mirror (from
// team_provisioning_log), which have a pending/failed reaction
// (integration_event_reactions), and which were dead_lettered.
//
// Shape:
//   {
//     "team_id": "...",
//     "provisioning": [{integration_instance_id, external_id, last_success_at, last_event_type}, …],
//     "pending":      [{integration_instance_id, capability, attempt, last_error}, …],
//     "dead_lettered":[{integration_instance_id, capability, attempt, last_error}, …]
//   }
func (s *Server) handleTeamProvisioningStatus(w http.ResponseWriter, r *http.Request) {
	teamIDStr := r.PathValue("id")
	teamID, err := uuid.Parse(teamIDStr)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid team id"})
		return
	}

	provisioning, err := repository.ListTeamProvisioningLogByTeam(r.Context(), s.db, teamID)
	if err != nil {
		writeMappedError(w, err)
		return
	}

	// Reactions whose underlying event was emitted for this team
	// (event_log.aggregate_type='team' AND aggregate_id=teamID).
	reactionRows, err := s.db.QueryContext(r.Context(), `
		SELECT r.integration_instance_id, r.capability, r.attempt,
		       COALESCE(r.last_error, ''), r.status
		FROM integration_event_reactions r
		JOIN event_log e ON e.event_id = r.event_id
		WHERE e.aggregate_type = 'team'
		  AND e.aggregate_id = $1
		  AND r.status IN ('pending','failed','dead_lettered')
		ORDER BY r.id DESC
		LIMIT 200
	`, teamID.String())
	if err != nil {
		writeMappedError(w, err)
		return
	}
	defer reactionRows.Close()

	type reaction struct {
		IntegrationInstanceID uuid.UUID `json:"integration_instance_id"`
		Capability            string    `json:"capability"`
		Attempt               int       `json:"attempt"`
		LastError             string    `json:"last_error,omitempty"`
	}
	var pending, deadLettered []reaction
	for reactionRows.Next() {
		var rx reaction
		var status string
		if err := reactionRows.Scan(&rx.IntegrationInstanceID, &rx.Capability, &rx.Attempt, &rx.LastError, &status); err != nil {
			writeMappedError(w, err)
			return
		}
		switch status {
		case "dead_lettered":
			deadLettered = append(deadLettered, rx)
		default:
			pending = append(pending, rx)
		}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"team_id":       teamID,
		"provisioning": provisioning,
		"pending":       pending,
		"dead_lettered": deadLettered,
	})
}
```

- [ ] **Step 4: Register the route**

In `controllers/httpapi/server.go`, add next to the `/sync` route:

```go
	mux.HandleFunc("GET /api/v1/teams/{id}/provisioning-status", guard(server.handleTeamProvisioningStatus))
```

- [ ] **Step 5: Run to verify PASS**

Run: `go test ./controllers/httpapi/ -run "TestPostTeamSync|TestGetTeamProvisioningStatus" -v -count=1`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add controllers/httpapi/team_sync.go controllers/httpapi/team_sync_test.go controllers/httpapi/server.go
git commit -m "$(cat <<'EOF'
feat(team-reactor): GET /teams/{id}/provisioning-status endpoint

Surfaces per-adapter mirror state for a team: which instances are
provisioned, which have pending/failed reactions, which dead-lettered.
Designed to back the future TeamDetailPage "Sistemas vinculados" card.

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

---

### Task 6: Reconcile cron addon

**Files:**
- Create: `/Users/dakasa/projects/yggdrasil/yggdrasil-core/internal/teamreconcile/repository.go`
- Create: `/Users/dakasa/projects/yggdrasil/yggdrasil-core/internal/teamreconcile/repository_test.go`
- Create: `/Users/dakasa/projects/yggdrasil/yggdrasil-core/internal/teamreconcile/runner.go`
- Create: `/Users/dakasa/projects/yggdrasil/yggdrasil-core/internal/teamreconcile/runner_test.go`

- [ ] **Step 1: Write the failing repository test**

```go
// internal/teamreconcile/repository_test.go
package teamreconcile

import (
	"context"
	"testing"
)

func TestListUnprovisionedPairsFindsGap(t *testing.T) {
	db := openTestDB(t)
	defer db.Close()

	teamID := seedTeam(t, db)
	slack := seedIntegrationInstance(t, db, "slack")    // has team.created reactor
	github := seedIntegrationInstance(t, db, "github") // has team.created reactor

	// Provision slack but not github.
	if _, err := db.Exec(`
		INSERT INTO team_provisioning_log
		    (team_id, integration_instance_id, external_id, last_event_type)
		VALUES ($1, $2, 'C123', 'team.created')
	`, teamID, slack); err != nil {
		t.Fatalf("seed: %v", err)
	}

	pairs, err := ListUnprovisionedPairs(context.Background(), db)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	gotGitHub := false
	for _, p := range pairs {
		if p.TeamID == teamID && p.IntegrationInstanceID == github {
			gotGitHub = true
		}
		if p.TeamID == teamID && p.IntegrationInstanceID == slack {
			t.Fatalf("slack pair already provisioned but appeared in unprovisioned list")
		}
	}
	if !gotGitHub {
		t.Fatal("expected github pair in unprovisioned list")
	}
}

// helpers — implement using existing repository test infrastructure
func openTestDB(t *testing.T) *sql.DB                       { t.Helper(); return nil }
func seedTeam(t *testing.T, db *sql.DB) uuid.UUID            { t.Helper(); return uuid.Nil }
func seedIntegrationInstance(t *testing.T, db *sql.DB, integrationType string) uuid.UUID { t.Helper(); return uuid.Nil }
```

> Add the `database/sql` and `github.com/google/uuid` imports. As with Task 2, replace the stub helpers with the canonical ones — `seedIntegrationInstance` here additionally needs to create a matching `integration_type` manifest whose `spec.reactors` contains a `team.created` entry. Mirror what `manifestsync` tests do.

- [ ] **Step 2: Run to verify FAIL**

Run: `go test ./internal/teamreconcile/ -count=1`
Expected: FAIL with `undefined: ListUnprovisionedPairs`

- [ ] **Step 3: Implement the query**

```go
// internal/teamreconcile/repository.go
package teamreconcile

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/google/uuid"
)

// UnprovisionedPair represents (team, integration_instance) pairs that
// have no entry in team_provisioning_log despite both being active and
// the integration_type declaring an `on team.created` reactor.
type UnprovisionedPair struct {
	TeamID                uuid.UUID
	IntegrationInstanceID uuid.UUID
}

// ListUnprovisionedPairs walks every active team across every active
// integration_instance whose integration_type declares a reactor on
// team.created, and returns those without a matching team_provisioning_log
// row. This is the "gap" set the reconcile cron will re-emit team.created
// for.
//
// Anti-join via LEFT JOIN + WHERE log.id IS NULL. Same shape as the SQL
// in internal/manifestsync.
func ListUnprovisionedPairs(ctx context.Context, db *sql.DB) ([]UnprovisionedPair, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT t.id AS team_id, ii.id AS instance_id
		FROM teams t
		CROSS JOIN manifests ii
		JOIN manifests it
		  ON it.kind = 'integration_type'
		  AND it.namespace = (ii.spec->'type_ref'->>'namespace')
		  AND it.name = (ii.spec->'type_ref'->>'name')
		  AND it.active = true
		LEFT JOIN team_provisioning_log tpl
		  ON tpl.team_id = t.id
		  AND tpl.integration_instance_id = ii.id
		WHERE t.deleted_at IS NULL
		  AND ii.kind = 'integration_instance'
		  AND ii.active = true
		  AND EXISTS (
		    SELECT 1 FROM jsonb_array_elements(COALESCE(it.spec->'reactors','[]'::jsonb)) r
		    WHERE r->>'event_type' = 'team.created'
		  )
		  AND tpl.id IS NULL
	`)
	if err != nil {
		return nil, fmt.Errorf("list unprovisioned pairs: %w", err)
	}
	defer rows.Close()

	var out []UnprovisionedPair
	for rows.Next() {
		var p UnprovisionedPair
		if err := rows.Scan(&p.TeamID, &p.IntegrationInstanceID); err != nil {
			return nil, fmt.Errorf("scan: %w", err)
		}
		out = append(out, p)
	}
	return out, rows.Err()
}
```

- [ ] **Step 4: Verify repository test passes**

Run: `go test ./internal/teamreconcile/ -run TestListUnprovisionedPairs -v -count=1`
Expected: PASS

- [ ] **Step 5: Write the runner test**

```go
// internal/teamreconcile/runner_test.go
package teamreconcile

import (
	"context"
	"testing"
	"time"
)

func TestRunnerTickEmitsForGaps(t *testing.T) {
	db := openTestDB(t)
	defer db.Close()

	teamID := seedTeam(t, db)
	github := seedIntegrationInstance(t, db, "github")
	_ = github // gap intended

	r := &Runner{DB: db}
	if err := r.tick(context.Background()); err != nil {
		t.Fatalf("tick: %v", err)
	}

	var count int
	if err := db.QueryRow(`
		SELECT COUNT(*) FROM event_log
		WHERE type = 'team.created' AND aggregate_id = $1
	`, teamID.String()).Scan(&count); err != nil {
		t.Fatalf("query event_log: %v", err)
	}
	if count != 1 {
		t.Fatalf("expected 1 team.created event after tick, got %d", count)
	}
}

func TestRunnerTickIsNoOpWhenAllProvisioned(t *testing.T) {
	db := openTestDB(t)
	defer db.Close()

	teamID := seedTeam(t, db)
	github := seedIntegrationInstance(t, db, "github")
	if _, err := db.Exec(`
		INSERT INTO team_provisioning_log (team_id, integration_instance_id, external_id, last_event_type)
		VALUES ($1, $2, 'X', 'team.created')
	`, teamID, github); err != nil {
		t.Fatalf("seed: %v", err)
	}

	r := &Runner{DB: db}
	if err := r.tick(context.Background()); err != nil {
		t.Fatalf("tick: %v", err)
	}

	var count int
	_ = db.QueryRow(`SELECT COUNT(*) FROM event_log WHERE type = 'team.created' AND aggregate_id = $1`, teamID.String()).Scan(&count)
	if count != 0 {
		t.Fatalf("expected 0 events after tick (all provisioned), got %d", count)
	}
}

func TestRunnerRespectsKillSwitch(t *testing.T) {
	t.Setenv("TEAM_RECONCILE_ENABLED", "false")
	r := &Runner{DB: nil, Interval: time.Millisecond}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if err := r.Run(ctx); err != nil && err != context.DeadlineExceeded {
		t.Fatalf("Run returned unexpected error: %v", err)
	}
	// success = doesn't panic, exits when ctx cancels
}
```

- [ ] **Step 6: Run to verify FAIL**

Run: `go test ./internal/teamreconcile/ -run TestRunner -v -count=1`
Expected: FAIL with `undefined: Runner`

- [ ] **Step 7: Implement the runner**

```go
// internal/teamreconcile/runner.go
package teamreconcile

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	"go.uber.org/zap"
)

// Runner sweeps team_provisioning_log gaps and re-emits team.created
// for each (team, integration_instance) pair that hasn't been mirrored.
// Adapter idempotency makes the re-emit safe — adapters that already
// have a row in team_provisioning_log will receive the reaction and
// respond with their no-op idempotent path.
//
// Kill switch: TEAM_RECONCILE_ENABLED=false skips the loop entirely.
type Runner struct {
	DB       *sql.DB
	Interval time.Duration
	Logger   *zap.Logger
}

const defaultInterval = 5 * time.Minute

// Run blocks until ctx is canceled.
func (r *Runner) Run(ctx context.Context) error {
	if os.Getenv("TEAM_RECONCILE_ENABLED") == "false" {
		<-ctx.Done()
		return ctx.Err()
	}
	interval := r.Interval
	if interval == 0 {
		interval = defaultInterval
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		if err := r.tick(ctx); err != nil && r.Logger != nil {
			r.Logger.Warn("team reconcile tick failed", zap.Error(err))
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
		}
	}
}

// tick is a single sweep — visible so tests can drive it directly.
func (r *Runner) tick(ctx context.Context) error {
	pairs, err := ListUnprovisionedPairs(ctx, r.DB)
	if err != nil {
		return fmt.Errorf("list unprovisioned: %w", err)
	}
	if len(pairs) == 0 {
		return nil
	}

	// Group by team so we emit one event per team (MaterializeReactions
	// fans out to every matching integration_instance automatically; we
	// don't need to emit per-instance).
	seen := map[string]struct{}{}
	for _, p := range pairs {
		if _, ok := seen[p.TeamID.String()]; ok {
			continue
		}
		seen[p.TeamID.String()] = struct{}{}
		if err := r.reEmit(ctx, p.TeamID.String()); err != nil && r.Logger != nil {
			r.Logger.Warn("reEmit team.created failed", zap.String("team_id", p.TeamID.String()), zap.Error(err))
		}
	}
	return nil
}

// reEmit looks up the team and emits a team.created canon event. The
// payload mirrors what the team create handler emits, so downstream
// adapter handlers see identical input shape regardless of source.
func (r *Runner) reEmit(ctx context.Context, teamID string) error {
	row := r.DB.QueryRowContext(ctx, `
		SELECT id, slug, name, type, parent_team_id
		FROM teams
		WHERE id = $1 AND deleted_at IS NULL
	`, teamID)
	var id, slug, name, ttype string
	var parent sql.NullString
	if err := row.Scan(&id, &slug, &name, &ttype, &parent); err != nil {
		return fmt.Errorf("scan team: %w", err)
	}

	tx, err := r.DB.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	payload := map[string]any{
		"id":   id,
		"slug": slug,
		"name": name,
		"type": ttype,
	}
	if parent.Valid {
		payload["parent_team_id"] = parent.String
	}
	if _, err := repository.EmitEvent(ctx, tx, model.EmitEventRequest{
		Type:          repository.EventTypeTeamCreated,
		SchemaVersion: "v1",
		AggregateType: "team",
		AggregateID:   id,
		Payload:       payload,
		Actor: &model.EventActor{
			Type: model.ActorTypeSystem,
			ID:   "team_reconcile_addon",
		},
	}); err != nil {
		return fmt.Errorf("emit: %w", err)
	}
	return tx.Commit()
}
```

> If `model.ActorTypeSystem` doesn't exist, use whatever the codebase calls "system actor" — search for `ActorType` constants. Don't add a new one without confirming.

- [ ] **Step 8: Run to verify all tests PASS**

Run: `go test ./internal/teamreconcile/ -v -count=1`
Expected: PASS (3 tests)

- [ ] **Step 9: Commit**

```bash
git add internal/teamreconcile/
git commit -m "$(cat <<'EOF'
feat(team-reactor): reconcile cron addon + repository

5-min tick scans (active_teams × active_instances_with_team.created_reactor)
MINUS team_provisioning_log and re-emits team.created for the gaps.
Adapter idempotency keeps repeated emits safe.

Kill switch: TEAM_RECONCILE_ENABLED=false.

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

---

### Task 7: Wire reconcile addon into server lifecycle

**Files:**
- Modify: `/Users/dakasa/projects/yggdrasil/yggdrasil-core/controllers/httpapi/server.go` (or wherever the manifestsync addon is started)

> First locate where `manifestsync.Runner` is started today — grep for `manifestsync` in `controllers/`, `addons/`, `cmd/`. The team reconcile addon plugs into the same lifecycle.

- [ ] **Step 1: Find the boot path**

Run: `grep -rn "manifestsync" /Users/dakasa/projects/yggdrasil/yggdrasil-core/controllers/ /Users/dakasa/projects/yggdrasil/yggdrasil-core/addons/ /Users/dakasa/projects/yggdrasil/yggdrasil-core/cmd/ 2>/dev/null | grep -v _test`
Expected: returns at least one file that constructs and calls `manifestsync.Runner.Run`.

- [ ] **Step 2: Add the parallel goroutine**

In whichever file starts `manifestsync.Runner`, immediately after that, add:

```go
	teamReconcileRunner := &teamreconcile.Runner{DB: db, Logger: logger}
	go func() {
		if err := teamReconcileRunner.Run(ctx); err != nil && ctx.Err() == nil {
			logger.Error("team reconcile runner exited", zap.Error(err))
		}
	}()
```

Add the import:

```go
	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/teamreconcile"
```

> Match the exact `ctx`, `db`, `logger` variable names from the surrounding code.

- [ ] **Step 3: Build + smoke**

Run: `go build ./... && go test ./... -count=1`
Expected: exit 0, all PASS

- [ ] **Step 4: Commit**

```bash
git add controllers/httpapi/server.go
git commit -m "$(cat <<'EOF'
feat(team-reactor): wire teamreconcile.Runner into server lifecycle

Starts as a goroutine alongside manifestsync. Same kill-switch pattern
(env var), same exit on ctx cancel.

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

---

### Task 8: Push core to main

**Files:** none (push only)

> All Phase 0 commits already on `main` locally. This task pushes them so CD deploys before adapters land.

- [ ] **Step 1: Verify clean tree**

Run: `git status -s`
Expected: empty output

- [ ] **Step 2: Verify recent commits**

Run: `git log --oneline -10`
Expected: 7 new commits from Tasks 1-7 on top of the previously-pending `dcdc219` and the spec commit `3c40f1a`. Confirm the order makes sense.

- [ ] **Step 3: Push**

Run: `git push origin main`
Expected: success. CD will detect the push and rebuild.

- [ ] **Step 4: Wait for deploy + verify endpoints up**

Run: `until curl -sf https://yggdrasil.dakasa.me/healthz | grep -q ok; do sleep 10; done && echo deployed`
Expected: "deployed" once the pod swaps. May take ~3-5 min.

Then sanity check (substitute a real team id from staging):

```bash
curl -sS -H "Authorization: Bearer $YGGDRASIL_ADMIN_TOKEN" \
  "https://yggdrasil.dakasa.me/api/v1/teams/<some-team-id>/provisioning-status" | jq
```

Expected: 200 with empty `provisioning`, `pending`, `dead_lettered` arrays.

---

## Phase 1: Adapter coverage

> **Order**: any order works — the three adapters are independent. The plan lists slack → github → google-workspace; do them in whichever order you prefer.

### Task 9: integration-slack team handlers

**Files:**
- Modify: `/Users/dakasa/projects/yggdrasil/integration-slack/internal/adapter/spec.go`
- Modify: `/Users/dakasa/projects/yggdrasil/integration-slack/internal/adapter/reactors.go`
- Modify: `/Users/dakasa/projects/yggdrasil/integration-slack/internal/adapter/reactors_test.go`
- Modify: `/Users/dakasa/projects/yggdrasil/integration-slack/examples/integration_type.example.json`

> **Defaults (from spec):** channel name is `"team-" + slug`. Always private (`is_private: true`). Idempotent: `name_taken` → lookup via `conversations.list`. Returns `_yggdrasil.team_provisioned` envelope with `external_id = channel_id`.

- [ ] **Step 1: Add operation constants in spec.go**

Find the existing `Operation*` constants block (around `OperationOnTeamMembershipAdded`). Add:

```go
	OperationOnTeamCreated  = "on_team_created"
	OperationOnTeamUpdated  = "on_team_updated"
	OperationOnTeamDeleted  = "on_team_deleted"
```

- [ ] **Step 2: Add capabilities to the Reactors slice in spec.go**

In the `Spec()` function's reactor list (where `OperationOnTeamMembershipAdded` etc are declared), add three entries:

```go
		{
			Name:          OperationOnTeamCreated,
			Description:   "Lifecycle reactor for team.created: create private slack channel team-<slug>.",
			ResourceTypes: []string{"team"},
			Idempotent:    true,
		},
		{
			Name:          OperationOnTeamUpdated,
			Description:   "Lifecycle reactor for team.updated: rename slack channel to team-<new_slug>.",
			ResourceTypes: []string{"team"},
			Idempotent:    true,
		},
		{
			Name:          OperationOnTeamDeleted,
			Description:   "Lifecycle reactor for team.deleted: archive the slack channel.",
			ResourceTypes: []string{"team"},
			Idempotent:    true,
		},
```

- [ ] **Step 3: Write the failing handler tests**

Append to `reactors_test.go` (look at how `TestOnCollaboratorCreated` builds its mock `slackAuth` and `slackHTTPClient` — re-use the same pattern):

```go
func TestOnTeamCreatedCreatesPrivateChannel(t *testing.T) {
	mockHTTP := newMockSlack(t, map[string]any{
		"/api/conversations.create": map[string]any{
			"ok": true,
			"channel": map[string]any{"id": "C123", "name": "team-eng", "is_private": true},
		},
	})
	auth := slackAuth{Token: "xoxb-test", HTTP: mockHTTP}

	out, err := onTeamCreated(auth, map[string]any{
		"id":   "00000000-0000-0000-0000-000000000001",
		"slug": "eng",
		"name": "Engineering",
	})
	if err != nil {
		t.Fatalf("onTeamCreated: %v", err)
	}

	envelope, ok := out["_yggdrasil"].(map[string]any)
	if !ok {
		t.Fatalf("missing _yggdrasil envelope: %v", out)
	}
	tp, ok := envelope["team_provisioned"].(map[string]any)
	if !ok {
		t.Fatalf("missing team_provisioned: %v", envelope)
	}
	if tp["external_id"] != "C123" {
		t.Fatalf("expected external_id C123, got %v", tp["external_id"])
	}
}

func TestOnTeamCreatedHandlesNameTakenViaList(t *testing.T) {
	mockHTTP := newMockSlack(t, map[string]any{
		"/api/conversations.create": map[string]any{"ok": false, "error": "name_taken"},
		"/api/conversations.list": map[string]any{
			"ok": true,
			"channels": []map[string]any{
				{"id": "C999", "name": "team-eng"},
			},
		},
	})
	auth := slackAuth{Token: "xoxb-test", HTTP: mockHTTP}

	out, err := onTeamCreated(auth, map[string]any{
		"id":   "00000000-0000-0000-0000-000000000001",
		"slug": "eng",
		"name": "Engineering",
	})
	if err != nil {
		t.Fatalf("onTeamCreated: %v", err)
	}
	tp := out["_yggdrasil"].(map[string]any)["team_provisioned"].(map[string]any)
	if tp["external_id"] != "C999" {
		t.Fatalf("expected external_id C999 from list lookup, got %v", tp["external_id"])
	}
}

func TestOnTeamUpdatedRenamesChannel(t *testing.T) {
	mockHTTP := newMockSlack(t, map[string]any{
		"/api/conversations.rename": map[string]any{
			"ok": true,
			"channel": map[string]any{"id": "C123", "name": "team-platform"},
		},
	})
	auth := slackAuth{Token: "xoxb-test", HTTP: mockHTTP}

	out, err := onTeamUpdated(auth, map[string]any{
		"id":   "00000000-0000-0000-0000-000000000001",
		"slug": "platform",
		"name": "Platform",
		"_context": map[string]any{
			"team_provisioned": map[string]any{"external_id": "C123"},
		},
	})
	if err != nil {
		t.Fatalf("onTeamUpdated: %v", err)
	}
	tp := out["_yggdrasil"].(map[string]any)["team_provisioned"].(map[string]any)
	if tp["external_id"] != "C123" {
		t.Fatalf("expected external_id unchanged on rename, got %v", tp["external_id"])
	}
}

func TestOnTeamDeletedArchivesChannel(t *testing.T) {
	mockHTTP := newMockSlack(t, map[string]any{
		"/api/conversations.archive": map[string]any{"ok": true},
	})
	auth := slackAuth{Token: "xoxb-test", HTTP: mockHTTP}

	out, err := onTeamDeleted(auth, map[string]any{
		"id":   "00000000-0000-0000-0000-000000000001",
		"slug": "eng",
		"_context": map[string]any{
			"team_provisioned": map[string]any{"external_id": "C123"},
		},
	})
	if err != nil {
		t.Fatalf("onTeamDeleted: %v", err)
	}
	if out["archived"] != true {
		t.Fatalf("expected archived=true, got %v", out["archived"])
	}
}
```

> The `_context.team_provisioned.external_id` field is what the dispatcher should embed before sending the reaction to the adapter (mirror of how `_context.external_identity` is embedded for `on_collaborator_offboarded`). If the dispatcher doesn't embed this yet, you'll add that in Task 16.

- [ ] **Step 4: Run to verify FAIL**

Run: `cd /Users/dakasa/projects/yggdrasil/integration-slack && go test ./internal/adapter/ -run "TestOnTeam(Created|Updated|Deleted)" -v -count=1`
Expected: FAIL with `undefined: onTeamCreated`

- [ ] **Step 5: Implement the handlers**

Append to `internal/adapter/reactors.go`:

```go
// onTeamCreated provisions a private slack channel named "team-<slug>".
// Idempotent: when conversations.create returns name_taken, falls back to
// conversations.list to locate the existing channel ID.
//
// Expected input fields (from team.created canon event payload):
//
//	id    — yggdrasil team UUID (used as aggregate)
//	slug  — yggdrasil team slug; channel name = "team-" + slug
//	name  — human-readable team name (used as channel topic)
func onTeamCreated(auth slackAuth, input map[string]any) (map[string]any, error) {
	slug := firstString(input, "slug")
	if slug == "" {
		return nil, fmt.Errorf("on_team_created: slug is required")
	}
	channelName := "team-" + slug
	attempt := contextAttempt(input)

	createOut, err := createConversation(auth, map[string]any{
		"name":       channelName,
		"is_private": true,
	})
	if err != nil {
		// name_taken → look the existing channel up so we still return a usable id
		if isNameTaken(err) {
			channelID, lookupErr := lookupChannelIDByName(auth, channelName)
			if lookupErr != nil {
				return nil, fmt.Errorf("on_team_created: name_taken and lookup failed: %w (original: %v)", lookupErr, err)
			}
			return teamProvisionedEnvelope(channelID, map[string]any{"channel_name": channelName, "via_lookup": true, "attempt": attempt}), nil
		}
		return nil, fmt.Errorf("on_team_created: conversations.create failed: %w", err)
	}

	channel, _ := createOut["channel"].(map[string]any)
	channelID, _ := channel["id"].(string)
	if channelID == "" {
		return nil, fmt.Errorf("on_team_created: conversations.create returned no channel id (out=%v)", createOut)
	}
	return teamProvisionedEnvelope(channelID, map[string]any{"channel_name": channelName, "attempt": attempt}), nil
}

// onTeamUpdated renames the slack channel to track the team slug change.
// Adapter receives the new slug in input.slug; the existing external_id
// must come in input._context.team_provisioned.external_id (embedded by
// the dispatcher from team_provisioning_log).
func onTeamUpdated(auth slackAuth, input map[string]any) (map[string]any, error) {
	slug := firstString(input, "slug")
	externalID := externalIDFromContext(input)
	if externalID == "" {
		return nil, fmt.Errorf("on_team_updated: external_id missing from _context.team_provisioned")
	}
	newName := "team-" + slug
	attempt := contextAttempt(input)

	if _, err := renameConversation(auth, map[string]any{
		"channel": externalID,
		"name":    newName,
	}); err != nil {
		// Same-name renames return ok on Slack; other errors propagate.
		return nil, fmt.Errorf("on_team_updated: conversations.rename failed: %w", err)
	}
	return teamProvisionedEnvelope(externalID, map[string]any{"channel_name": newName, "attempt": attempt}), nil
}

// onTeamDeleted archives the slack channel. Archive is reversible and the
// preferred provider operation — Slack has no "delete channel" API.
func onTeamDeleted(auth slackAuth, input map[string]any) (map[string]any, error) {
	externalID := externalIDFromContext(input)
	if externalID == "" {
		return nil, fmt.Errorf("on_team_deleted: external_id missing from _context.team_provisioned")
	}
	attempt := contextAttempt(input)

	if _, err := archiveConversation(auth, map[string]any{"channel": externalID}); err != nil {
		if isAlreadyArchived(err) {
			return map[string]any{"archived": true, "already_archived": true, "attempt": attempt}, nil
		}
		return nil, fmt.Errorf("on_team_deleted: conversations.archive failed: %w", err)
	}
	return map[string]any{"archived": true, "attempt": attempt}, nil
}

// teamProvisionedEnvelope returns a map shaped for the dispatcher's
// _yggdrasil.team_provisioned extractor. metadata is opaque — slack
// stores channel_name and any extras.
func teamProvisionedEnvelope(externalID string, metadata map[string]any) map[string]any {
	out := map[string]any{
		"provisioned": true,
	}
	if metadata != nil {
		out["channel"] = metadata
	}
	out["_yggdrasil"] = map[string]any{
		"team_provisioned": map[string]any{
			"external_id":       externalID,
			"external_metadata": metadata,
		},
	}
	return out
}

// externalIDFromContext extracts _context.team_provisioned.external_id, returning ""
// when the block is absent or malformed.
func externalIDFromContext(input map[string]any) string {
	ctx, _ := input["_context"].(map[string]any)
	if ctx == nil {
		return ""
	}
	tp, _ := ctx["team_provisioned"].(map[string]any)
	if tp == nil {
		return ""
	}
	id, _ := tp["external_id"].(string)
	return id
}

func isNameTaken(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), "name_taken")
}

func isAlreadyArchived(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), "already_archived") || strings.Contains(err.Error(), "channel_not_found")
}
```

> If `createConversation`, `renameConversation`, `archiveConversation`, `lookupChannelIDByName` don't already exist in the adapter as thin wrappers over the slack client, add them in the same file or wherever `addToChannel` / `removeFromChannel` live. Match their existing signature pattern.

- [ ] **Step 6: Register the operations in the operation dispatcher**

Find the `switch req.Operation` (or equivalent) block where existing operations route to handlers. Add cases:

```go
	case OperationOnTeamCreated:
		out, err := onTeamCreated(auth, req.Input)
		// ... existing pattern: wrap into AdapterExecuteIntegrationResponse
	case OperationOnTeamUpdated:
		out, err := onTeamUpdated(auth, req.Input)
		// ...
	case OperationOnTeamDeleted:
		out, err := onTeamDeleted(auth, req.Input)
		// ...
```

Match the exact wrapping done for `OperationOnTeamMembershipAdded`.

- [ ] **Step 7: Run tests to verify they PASS**

Run: `go test ./internal/adapter/ -run "TestOnTeam(Created|Updated|Deleted)" -v -count=1`
Expected: PASS (4 tests)

- [ ] **Step 8: Update the example manifest**

Edit `examples/integration_type.example.json`. In the `reactors` array, append:

```json
,
{"event_type": "team.created", "capability": "on_team_created", "description": "Provision private slack channel team-<slug>"},
{"event_type": "team.updated", "capability": "on_team_updated", "description": "Rename slack channel to track team slug"},
{"event_type": "team.deleted", "capability": "on_team_deleted", "description": "Archive slack channel"}
```

(prefix the comma if the previous entry doesn't end with one — confirm by reading the existing JSON).

Validate the JSON:

```bash
python3 -c 'import json; json.load(open("examples/integration_type.example.json"))' && echo OK
```

Expected: `OK`

- [ ] **Step 9: Final build**

Run: `go build ./...`
Expected: exit 0

- [ ] **Step 10: Commit + push**

```bash
git add internal/adapter/spec.go internal/adapter/reactors.go internal/adapter/reactors_test.go examples/integration_type.example.json
git commit -m "$(cat <<'EOF'
feat(team-reactor): add on_team_created/updated/deleted handlers

Provisions/renames/archives a private slack channel named team-<slug>
on every team.created/updated/deleted canon event. Idempotent:
name_taken → lookup, already_archived → success. Returns
_yggdrasil.team_provisioned envelope so yggdrasil-core writes the log row.

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
git push origin main
```

---

### Task 10: integration-github team handlers (updated + deleted only — created already exists)

**Files:**
- Modify: `/Users/dakasa/projects/yggdrasil/integration-github/internal/adapter/spec.go`
- Modify: `/Users/dakasa/projects/yggdrasil/integration-github/internal/adapter/reactors.go`
- Modify: `/Users/dakasa/projects/yggdrasil/integration-github/internal/adapter/reactors_test.go`
- Modify: `/Users/dakasa/projects/yggdrasil/integration-github/examples/integration_type.example.json`

> **Defaults:** team is `closed` privacy, no repo grants. Slug = team slug from yggdrasil. Idempotent: `422 already_exists` → GET by slug; `404` → success on delete.

- [ ] **Step 1: Update existing `on_team_created` to return the envelope**

Find `onTeamCreated` in `reactors.go`. Currently it returns `create_team` output but no `_yggdrasil.team_provisioned`. Replace its `return` block with:

```go
	return protocol.AdapterExecuteIntegrationResponse{
		Operation:  OperationOnTeamCreated,
		Capability: OperationOnTeamCreated,
		Status:     "applied",
		Output: map[string]any{
			"create_team": teamResp.Output,
			"attempt":     attempt,
			"_yggdrasil": map[string]any{
				"team_provisioned": map[string]any{
					"external_id":       slugFromOutput(teamResp.Output),
					"external_metadata": map[string]any{"name": name, "org": firstString(req.Input, []string{"org", "organization"})},
				},
			},
		},
		Metadata: map[string]any{
			"provider": Provider,
			"name":     name,
		},
	}, nil
```

Add a helper just below the function:

```go
// slugFromOutput pulls the slug field out of a teams API create response.
// Falls back to the name when slug isn't present (older responses).
func slugFromOutput(out any) string {
	m, _ := out.(map[string]any)
	if m == nil {
		return ""
	}
	if s, ok := m["slug"].(string); ok && s != "" {
		return s
	}
	if s, ok := m["name"].(string); ok {
		return s
	}
	return ""
}
```

- [ ] **Step 2: Add operation constants**

In `spec.go`, near the existing `OperationOnTeamCreated`:

```go
	OperationOnTeamUpdated  = "on_team_updated"
	OperationOnTeamDeleted  = "on_team_deleted"
```

- [ ] **Step 3: Add capabilities to Reactors slice**

Next to the existing `OperationOnTeamCreated` entry:

```go
		{
			Name:          OperationOnTeamUpdated,
			Description:   "Lifecycle reactor for team.updated: PATCH the github org team to track yggdrasil name/slug changes.",
			ResourceTypes: []string{"team"},
			Idempotent:    true,
		},
		{
			Name:          OperationOnTeamDeleted,
			Description:   "Lifecycle reactor for team.deleted: DELETE the github org team.",
			ResourceTypes: []string{"team"},
			Idempotent:    true,
		},
```

- [ ] **Step 4: Write the failing tests**

Append to `reactors_test.go`:

```go
func TestOnTeamUpdatedPatchesGitHubTeam(t *testing.T) {
	mock := newMockGitHub(t, map[string]any{
		"PATCH /orgs/dakasa/teams/eng": map[string]any{
			"slug": "platform",
			"name": "Platform",
		},
	})
	req := makeAdapterRequest(t, mock, map[string]any{
		"id":   "00000000-0000-0000-0000-000000000001",
		"slug": "platform",
		"name": "Platform",
		"_context": map[string]any{
			"team_provisioned": map[string]any{"external_id": "eng"},
		},
	})
	req.Input["org"] = "dakasa"

	resp, err := onTeamUpdated(req)
	if err != nil {
		t.Fatalf("onTeamUpdated: %v", err)
	}
	env, _ := resp.Output.(map[string]any)["_yggdrasil"].(map[string]any)
	tp, _ := env["team_provisioned"].(map[string]any)
	if tp["external_id"] != "platform" {
		t.Fatalf("expected external_id platform (new slug), got %v", tp["external_id"])
	}
}

func TestOnTeamDeletedDELETEsGitHubTeam(t *testing.T) {
	mock := newMockGitHub(t, map[string]any{
		"DELETE /orgs/dakasa/teams/eng": map[string]any{},
	})
	req := makeAdapterRequest(t, mock, map[string]any{
		"id":   "00000000-0000-0000-0000-000000000001",
		"slug": "eng",
		"_context": map[string]any{
			"team_provisioned": map[string]any{"external_id": "eng"},
		},
	})
	req.Input["org"] = "dakasa"

	resp, err := onTeamDeleted(req)
	if err != nil {
		t.Fatalf("onTeamDeleted: %v", err)
	}
	if resp.Status != "applied" {
		t.Fatalf("expected status applied, got %s", resp.Status)
	}
}

func TestOnTeamDeleted404IsSuccess(t *testing.T) {
	mock := newMockGitHubNotFound(t, "/orgs/dakasa/teams/eng")
	req := makeAdapterRequest(t, mock, map[string]any{
		"id":   "00000000-0000-0000-0000-000000000001",
		"slug": "eng",
		"_context": map[string]any{
			"team_provisioned": map[string]any{"external_id": "eng"},
		},
	})
	req.Input["org"] = "dakasa"

	resp, err := onTeamDeleted(req)
	if err != nil {
		t.Fatalf("on_team_deleted should treat 404 as success, got error: %v", err)
	}
	if resp.Status != "applied" {
		t.Fatalf("expected applied even on 404, got %s", resp.Status)
	}
}
```

> Re-use existing `newMockGitHub`, `makeAdapterRequest` helpers from the test file — match the calling shape of `TestOnTeamCreated` if it exists, or `TestOnCollaboratorCreated`. The mocks here are sketches; adjust to your real harness shape.

- [ ] **Step 5: Verify FAIL**

Run: `cd /Users/dakasa/projects/yggdrasil/integration-github && go test ./internal/adapter/ -run "TestOnTeamUpdated|TestOnTeamDeleted" -v -count=1`
Expected: FAIL with `undefined: onTeamUpdated`

- [ ] **Step 6: Implement the handlers**

```go
// onTeamUpdated PATCHes the GitHub org team to track a yggdrasil slug or
// name change. The existing GH team slug arrives in
// input._context.team_provisioned.external_id; the new slug/name come from
// the canon event payload. GitHub responds with the new slug, which we
// return as the new external_id so future updates target the right team.
func onTeamUpdated(req protocol.AdapterExecuteIntegrationRequest) (protocol.AdapterExecuteIntegrationResponse, error) {
	attempt := contextAttempt(req.Input)
	oldSlug := externalIDFromContext(req.Input)
	if oldSlug == "" {
		return protocol.AdapterExecuteIntegrationResponse{}, fmt.Errorf("on_team_updated: external_id missing from _context.team_provisioned")
	}
	newName := firstString(req.Input, []string{"name", "team_name"})
	newSlug := firstString(req.Input, []string{"slug"})
	if newName == "" && newSlug == "" {
		return protocol.AdapterExecuteIntegrationResponse{}, fmt.Errorf("on_team_updated: name or slug required")
	}
	org := firstString(req.Input, []string{"org", "organization"})

	patchReq := cloneReqWithInput(req, map[string]any{
		"team_slug": oldSlug,
		"org":       org,
		"name":      newName,
		"slug":      newSlug,
	})
	patchReq.Operation = OperationUpdateTeam
	patchReq.Capability = OperationUpdateTeam

	patchResp, err := updateTeam(patchReq)
	if err != nil {
		return protocol.AdapterExecuteIntegrationResponse{}, fmt.Errorf("on_team_updated: update_team failed: %w", err)
	}

	resolvedSlug := slugFromOutput(patchResp.Output)
	if resolvedSlug == "" {
		resolvedSlug = oldSlug
	}

	return protocol.AdapterExecuteIntegrationResponse{
		Operation:  OperationOnTeamUpdated,
		Capability: OperationOnTeamUpdated,
		Status:     "applied",
		Output: map[string]any{
			"update_team": patchResp.Output,
			"attempt":     attempt,
			"_yggdrasil": map[string]any{
				"team_provisioned": map[string]any{
					"external_id":       resolvedSlug,
					"external_metadata": map[string]any{"name": newName, "org": org},
				},
			},
		},
		Metadata: map[string]any{"provider": Provider, "slug": resolvedSlug},
	}, nil
}

// onTeamDeleted DELETEs the GitHub org team. 404 is treated as success —
// the desired end-state (team absent) is satisfied either way.
func onTeamDeleted(req protocol.AdapterExecuteIntegrationRequest) (protocol.AdapterExecuteIntegrationResponse, error) {
	attempt := contextAttempt(req.Input)
	slug := externalIDFromContext(req.Input)
	if slug == "" {
		slug = firstString(req.Input, []string{"slug"})
	}
	if slug == "" {
		return protocol.AdapterExecuteIntegrationResponse{}, fmt.Errorf("on_team_deleted: slug missing")
	}
	org := firstString(req.Input, []string{"org", "organization"})

	delReq := cloneReqWithInput(req, map[string]any{"team_slug": slug, "org": org})
	delReq.Operation = OperationDeleteTeam
	delReq.Capability = OperationDeleteTeam

	if _, err := deleteTeam(delReq); err != nil {
		if isNotFound(err) {
			return protocol.AdapterExecuteIntegrationResponse{
				Operation:  OperationOnTeamDeleted,
				Capability: OperationOnTeamDeleted,
				Status:     "applied",
				Output:     map[string]any{"already_absent": true, "attempt": attempt},
			}, nil
		}
		return protocol.AdapterExecuteIntegrationResponse{}, fmt.Errorf("on_team_deleted: delete_team failed: %w", err)
	}

	return protocol.AdapterExecuteIntegrationResponse{
		Operation:  OperationOnTeamDeleted,
		Capability: OperationOnTeamDeleted,
		Status:     "applied",
		Output:     map[string]any{"deleted": true, "attempt": attempt},
	}, nil
}

// externalIDFromContext reads input._context.team_provisioned.external_id.
func externalIDFromContext(input map[string]any) string {
	ctx, _ := input["_context"].(map[string]any)
	if ctx == nil {
		return ""
	}
	tp, _ := ctx["team_provisioned"].(map[string]any)
	if tp == nil {
		return ""
	}
	id, _ := tp["external_id"].(string)
	return id
}

func isNotFound(err error) bool {
	return err != nil && strings.Contains(err.Error(), "404")
}
```

> `updateTeam` and `deleteTeam` should already exist as capability wrappers (alongside `createTeam`). If not, add them in the same file using the existing GitHub HTTP client. Match the call shape of `createTeam`. `OperationUpdateTeam` / `OperationDeleteTeam` likewise — add the constants in `spec.go` if missing.

- [ ] **Step 7: Wire dispatcher cases**

In the operation switch (same one that routes `OperationOnTeamCreated`):

```go
	case OperationOnTeamUpdated:
		return onTeamUpdated(req)
	case OperationOnTeamDeleted:
		return onTeamDeleted(req)
```

- [ ] **Step 8: Run tests to verify PASS**

Run: `go test ./internal/adapter/ -run "TestOnTeamCreated|TestOnTeamUpdated|TestOnTeamDeleted" -v -count=1`
Expected: PASS

- [ ] **Step 9: Update example manifest**

In `examples/integration_type.example.json`, find the `team.created` reactor entry and append two siblings:

```json
{"event_type": "team.updated", "capability": "on_team_updated", "description": "Rename/repurpose the github org team"},
{"event_type": "team.deleted", "capability": "on_team_deleted", "description": "Delete the github org team"}
```

Validate JSON.

- [ ] **Step 10: Build + commit + push**

```bash
go build ./...
git add internal/adapter/spec.go internal/adapter/reactors.go internal/adapter/reactors_test.go examples/integration_type.example.json
git commit -m "$(cat <<'EOF'
feat(team-reactor): add on_team_updated/deleted handlers + envelope on created

on_team_created now returns _yggdrasil.team_provisioned so yggdrasil-core
records the gh team slug. on_team_updated/deleted handle rename and delete,
treating 404 on delete as success. Idempotent across the board.

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
git push origin main
```

---

### Task 11: integration-google-workspace team handlers

**Files:**
- Modify: `/Users/dakasa/projects/yggdrasil/integration-google-workspace/providers/runtime/adapter/spec.go`
- Modify: `/Users/dakasa/projects/yggdrasil/integration-google-workspace/providers/runtime/adapter/reactors.go`
- Modify: `/Users/dakasa/projects/yggdrasil/integration-google-workspace/providers/runtime/adapter/reactors_test.go`
- Modify: `/Users/dakasa/projects/yggdrasil/integration-google-workspace/providers/runtime/manifest.json`

> **Defaults:** mailing-list group, email `<slug>@<workspace-domain>`, name = team.name. Group email is **immutable** on rename — onTeamUpdated only patches the `name` field; email stays at the original slug.

- [ ] **Step 1: Add operation constants in spec.go**

```go
	OperationOnTeamCreated  = "on_team_created"
	OperationOnTeamUpdated  = "on_team_updated"
	OperationOnTeamDeleted  = "on_team_deleted"
```

- [ ] **Step 2: Add capabilities to Reactors slice**

```go
		{Name: OperationOnTeamCreated, Description: "Lifecycle reactor for team.created: create a GW mailing-list group <slug>@<domain>.", ResourceTypes: []string{"team"}, Idempotent: true},
		{Name: OperationOnTeamUpdated, Description: "Lifecycle reactor for team.updated: patch the GW group name (email is immutable).", ResourceTypes: []string{"team"}, Idempotent: true},
		{Name: OperationOnTeamDeleted, Description: "Lifecycle reactor for team.deleted: delete the GW group.", ResourceTypes: []string{"team"}, Idempotent: true},
```

- [ ] **Step 3: Write failing tests**

Append to `reactors_test.go`:

```go
func TestOnTeamCreatedInsertsGroup(t *testing.T) {
	mock := newMockGoogleWorkspaceClient(t, map[string]any{
		"InsertGroup{Email:eng@dakasa.me}": map[string]any{"id": "g123", "email": "eng@dakasa.me", "name": "Engineering"},
	})
	auth := googleAuth{Domain: "dakasa.me", Client: mock}

	out, err := onTeamCreated(context.Background(), auth, map[string]any{
		"id":   "00000000-0000-0000-0000-000000000001",
		"slug": "eng",
		"name": "Engineering",
	})
	if err != nil {
		t.Fatalf("onTeamCreated: %v", err)
	}
	env, _ := out.(map[string]any)["_yggdrasil"].(map[string]any)
	tp, _ := env["team_provisioned"].(map[string]any)
	if tp["external_id"] != "eng@dakasa.me" {
		t.Fatalf("expected external_id eng@dakasa.me, got %v", tp["external_id"])
	}
}

func TestOnTeamCreatedHandlesEntityExistsViaGet(t *testing.T) {
	mock := newMockGoogleWorkspaceClient(t, map[string]any{
		"InsertGroup{Email:eng@dakasa.me}": entityExistsError(),
		"GetGroup{Email:eng@dakasa.me}":    map[string]any{"id": "gExisting", "email": "eng@dakasa.me", "name": "Engineering"},
	})
	auth := googleAuth{Domain: "dakasa.me", Client: mock}

	out, err := onTeamCreated(context.Background(), auth, map[string]any{
		"id":   "00000000-0000-0000-0000-000000000001",
		"slug": "eng",
		"name": "Engineering",
	})
	if err != nil {
		t.Fatalf("onTeamCreated: %v", err)
	}
	env, _ := out.(map[string]any)["_yggdrasil"].(map[string]any)
	tp, _ := env["team_provisioned"].(map[string]any)
	if tp["external_id"] != "eng@dakasa.me" {
		t.Fatalf("expected lookup-recovered external_id, got %v", tp["external_id"])
	}
}

func TestOnTeamUpdatedPatchesName(t *testing.T) {
	mock := newMockGoogleWorkspaceClient(t, map[string]any{
		"PatchGroup{Key:eng@dakasa.me,Name:Platform}": map[string]any{"id": "g123", "name": "Platform"},
	})
	auth := googleAuth{Domain: "dakasa.me", Client: mock}

	out, err := onTeamUpdated(context.Background(), auth, map[string]any{
		"id":   "00000000-0000-0000-0000-000000000001",
		"slug": "platform",
		"name": "Platform",
		"_context": map[string]any{"team_provisioned": map[string]any{"external_id": "eng@dakasa.me"}},
	})
	if err != nil {
		t.Fatalf("onTeamUpdated: %v", err)
	}
	env, _ := out.(map[string]any)["_yggdrasil"].(map[string]any)
	tp, _ := env["team_provisioned"].(map[string]any)
	if tp["external_id"] != "eng@dakasa.me" {
		t.Fatalf("expected external_id unchanged on rename (email immutable), got %v", tp["external_id"])
	}
}

func TestOnTeamDeletedDeletesGroup(t *testing.T) {
	mock := newMockGoogleWorkspaceClient(t, map[string]any{
		"DeleteGroup{Key:eng@dakasa.me}": map[string]any{},
	})
	auth := googleAuth{Domain: "dakasa.me", Client: mock}

	out, err := onTeamDeleted(context.Background(), auth, map[string]any{
		"id":   "00000000-0000-0000-0000-000000000001",
		"slug": "eng",
		"_context": map[string]any{"team_provisioned": map[string]any{"external_id": "eng@dakasa.me"}},
	})
	if err != nil {
		t.Fatalf("onTeamDeleted: %v", err)
	}
	if out.(map[string]any)["deleted"] != true {
		t.Fatalf("expected deleted=true, got %v", out)
	}
}
```

> Re-use the existing GW SDK fake — the test names above are illustrative (`InsertGroup{...}` keys). Match the real fake's expectation format.

- [ ] **Step 4: Verify FAIL**

Run: `cd /Users/dakasa/projects/yggdrasil/integration-google-workspace && go test ./providers/runtime/adapter/ -run "TestOnTeam" -v -count=1`
Expected: FAIL

- [ ] **Step 5: Implement handlers**

```go
// onTeamCreated creates a GW mailing-list group at <slug>@<domain>.
// Idempotent: on 409 entityExists, falls back to groups.get to recover
// the existing group id.
func onTeamCreated(ctx context.Context, auth googleAuth, input map[string]any) (any, error) {
	slug := firstString(input, "slug")
	name := firstString(input, "name")
	if slug == "" {
		return nil, fmt.Errorf("on_team_created: slug is required")
	}
	if name == "" {
		name = slug
	}
	email := slug + "@" + auth.Domain
	attempt := contextAttempt(input)

	insertOut, err := auth.Client.InsertGroup(ctx, map[string]any{
		"email":       email,
		"name":        name,
		"description": "Time " + name,
	})
	if err != nil {
		if isEntityExists(err) {
			getOut, getErr := auth.Client.GetGroup(ctx, email)
			if getErr != nil {
				return nil, fmt.Errorf("on_team_created: entityExists + get failed: %w (original: %v)", getErr, err)
			}
			return teamProvisionedEnvelope(email, getOut, attempt, true), nil
		}
		return nil, fmt.Errorf("on_team_created: groups.insert failed: %w", err)
	}
	return teamProvisionedEnvelope(email, insertOut, attempt, false), nil
}

// onTeamUpdated patches only the group name — the email is immutable.
// If the team slug changes in yggdrasil, the GW group email stays at the
// original slug. Documented limitation.
func onTeamUpdated(ctx context.Context, auth googleAuth, input map[string]any) (any, error) {
	email := externalIDFromContext(input)
	if email == "" {
		return nil, fmt.Errorf("on_team_updated: external_id missing from _context.team_provisioned")
	}
	name := firstString(input, "name")
	if name == "" {
		return nil, fmt.Errorf("on_team_updated: name required")
	}
	attempt := contextAttempt(input)

	patchOut, err := auth.Client.PatchGroup(ctx, email, map[string]any{"name": name})
	if err != nil {
		return nil, fmt.Errorf("on_team_updated: groups.patch failed: %w", err)
	}
	return teamProvisionedEnvelope(email, patchOut, attempt, false), nil
}

// onTeamDeleted deletes the GW group. 404 is treated as success.
func onTeamDeleted(ctx context.Context, auth googleAuth, input map[string]any) (any, error) {
	email := externalIDFromContext(input)
	if email == "" {
		return nil, fmt.Errorf("on_team_deleted: external_id missing from _context.team_provisioned")
	}
	attempt := contextAttempt(input)
	if err := auth.Client.DeleteGroup(ctx, email); err != nil {
		if isNotFound(err) {
			return map[string]any{"deleted": true, "already_absent": true, "attempt": attempt}, nil
		}
		return nil, fmt.Errorf("on_team_deleted: groups.delete failed: %w", err)
	}
	return map[string]any{"deleted": true, "attempt": attempt}, nil
}

func teamProvisionedEnvelope(email string, raw any, attempt int, viaLookup bool) map[string]any {
	meta := map[string]any{}
	if m, ok := raw.(map[string]any); ok {
		if id, _ := m["id"].(string); id != "" {
			meta["group_id"] = id
		}
		if n, _ := m["name"].(string); n != "" {
			meta["name"] = n
		}
	}
	if viaLookup {
		meta["via_lookup"] = true
	}
	return map[string]any{
		"provisioned": true,
		"attempt":     attempt,
		"group":       raw,
		"_yggdrasil": map[string]any{
			"team_provisioned": map[string]any{
				"external_id":       email,
				"external_metadata": meta,
			},
		},
	}
}

func externalIDFromContext(input map[string]any) string {
	ctx, _ := input["_context"].(map[string]any)
	if ctx == nil {
		return ""
	}
	tp, _ := ctx["team_provisioned"].(map[string]any)
	if tp == nil {
		return ""
	}
	id, _ := tp["external_id"].(string)
	return id
}

func isEntityExists(err error) bool {
	return err != nil && (strings.Contains(err.Error(), "entityExists") || strings.Contains(err.Error(), "409"))
}

func isNotFound(err error) bool {
	return err != nil && strings.Contains(err.Error(), "404")
}
```

> `InsertGroup`, `GetGroup`, `PatchGroup`, `DeleteGroup` are the thin wrappers around the Admin SDK. If they don't exist yet, add them next to the existing `AddMember` / `RemoveMember`.

- [ ] **Step 6: Wire dispatcher cases**

In the operation switch, add:

```go
	case OperationOnTeamCreated:
		return onTeamCreated(ctx, auth, req.Input)
	case OperationOnTeamUpdated:
		return onTeamUpdated(ctx, auth, req.Input)
	case OperationOnTeamDeleted:
		return onTeamDeleted(ctx, auth, req.Input)
```

- [ ] **Step 7: Run tests to verify PASS**

Run: `go test ./providers/runtime/adapter/ -run "TestOnTeam" -v -count=1`
Expected: PASS

- [ ] **Step 8: Update `providers/runtime/manifest.json`**

In the `reactors` array, append:

```json
{"event_type": "team.created", "capability": "on_team_created", "description": "Create GW mailing-list group"},
{"event_type": "team.updated", "capability": "on_team_updated", "description": "Patch GW group name (email immutable)"},
{"event_type": "team.deleted", "capability": "on_team_deleted", "description": "Delete GW group"}
```

Validate JSON.

- [ ] **Step 9: Build + commit + push**

```bash
go build ./...
git add providers/runtime/adapter/spec.go providers/runtime/adapter/reactors.go providers/runtime/adapter/reactors_test.go providers/runtime/manifest.json
git commit -m "$(cat <<'EOF'
feat(team-reactor): add on_team_created/updated/deleted handlers

Creates/patches/deletes a GW mailing-list group at <slug>@<domain>.
Email is immutable across renames (documented limitation) — onTeamUpdated
only patches the display name. Idempotent: 409 entityExists → lookup,
404 → success on delete.

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
git push origin main
```

---

## Phase 2: Integration test + wire dispatcher embed

### Task 12: Embed `_context.team_provisioned` before adapter dispatch

**Files:**
- Modify: `/Users/dakasa/projects/yggdrasil/yggdrasil-core/addons/reactor_dispatcher.go`

> For `team.updated` and `team.deleted` to find the existing `external_id`, the dispatcher must look up `team_provisioning_log` for the (team, instance) pair and inject the row under `input._context.team_provisioned` before sending the reaction over AMQP. This is the mirror of how `_context.external_identity` is embedded today.

- [ ] **Step 1: Find the embed call site**

Run: `grep -n "EmbedIntoInput\|external_identity" /Users/dakasa/projects/yggdrasil/yggdrasil-core/addons/reactor_dispatcher.go | head -10`

Expected: finds the existing call to `externalidentity.EmbedIntoInput` before the AMQP dispatch. This is the spot to add a sibling team embed.

- [ ] **Step 2: Add team embed helper**

Append to `reactor_dispatcher.go`:

```go
// embedTeamProvisioned reads team_provisioning_log for the (team, instance)
// pair the reaction targets, and injects the row under
// input._context.team_provisioned. Mirror of EmbedIntoInput from
// externalidentity. No-op when the reaction is not a team.* event, or
// when no log row exists yet (first-time team.created).
func (c *rabbitmqReactorCaller) embedTeamProvisioned(
	ctx context.Context,
	eventType string,
	integrationInstanceID string,
	input map[string]any,
) {
	if !strings.HasPrefix(eventType, "team.") {
		return
	}
	teamIDStr, _ := input["id"].(string)
	if strings.TrimSpace(teamIDStr) == "" {
		return
	}
	teamID, err := uuid.Parse(teamIDStr)
	if err != nil {
		return
	}
	instanceID, err := uuid.Parse(integrationInstanceID)
	if err != nil {
		return
	}

	row, err := repository.GetTeamProvisioningLog(ctx, c.db, teamID, instanceID)
	if err != nil || row.ExternalID == "" {
		return // no log row yet — adapter will create from scratch
	}

	ctxBlock, _ := input["_context"].(map[string]any)
	if ctxBlock == nil {
		ctxBlock = map[string]any{}
		input["_context"] = ctxBlock
	}
	ctxBlock["team_provisioned"] = map[string]any{
		"external_id":       row.ExternalID,
		"external_metadata": json.RawMessage(row.ExternalMetadata),
	}
}
```

Add the supporting repo helper in `repository/team_provisioning_log.go`:

```go
// GetTeamProvisioningLog returns the log row for one (team, instance) pair,
// or a zero-value row with no error when no row exists.
func GetTeamProvisioningLog(ctx context.Context, db *sql.DB, teamID, instanceID uuid.UUID) (model.TeamProvisioningLog, error) {
	var r model.TeamProvisioningLog
	err := db.QueryRowContext(ctx, `
		SELECT id, team_id, integration_instance_id, external_id, external_metadata,
		       last_success_at, last_event_type, created_at, updated_at
		FROM team_provisioning_log
		WHERE team_id = $1 AND integration_instance_id = $2
	`, teamID, instanceID).Scan(&r.ID, &r.TeamID, &r.IntegrationInstanceID, &r.ExternalID,
		&r.ExternalMetadata, &r.LastSuccessAt, &r.LastEventType, &r.CreatedAt, &r.UpdatedAt)
	if err == sql.ErrNoRows {
		return model.TeamProvisioningLog{}, nil
	}
	if err != nil {
		return model.TeamProvisioningLog{}, err
	}
	return r, nil
}
```

- [ ] **Step 3: Invoke the embed before AMQP dispatch**

In the dispatcher's `Call` method, immediately before the existing `externalidentity.EmbedIntoInput` call (or wherever the input is finalized before being sent):

```go
	c.embedTeamProvisioned(ctx, eventType, integrationInstanceID, input)
```

- [ ] **Step 4: Build + test**

Run: `cd /Users/dakasa/projects/yggdrasil/yggdrasil-core && go build ./... && go test ./addons/ ./repository/ -count=1`
Expected: exit 0, PASS

- [ ] **Step 5: Commit + push**

```bash
git add addons/reactor_dispatcher.go repository/team_provisioning_log.go
git commit -m "$(cat <<'EOF'
feat(team-reactor): embed _context.team_provisioned before adapter dispatch

Mirror of externalidentity.EmbedIntoInput. Looks up team_provisioning_log
for the (team, instance) pair the reaction targets and injects the row
under input._context.team_provisioned. Lets on_team_updated and
on_team_deleted target the right external resource without a fresh list
call.

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
git push origin main
```

---

## Phase 3: Manual E2E + wrap-up

### Task 13: Manual end-to-end validation

**Files:** none (operator-driven)

> Wait for CD to finish deploying all four repos (core, slack, github, gw). Check pod status: `kubectl get pods -n yggdrasil` should show fresh `yggdrasil-core`, `integration-slack`, `integration-github`, `integration-google-workspace` pods, all Ready.

- [ ] **Step 1: Verify reactor declarations live on staging**

```bash
curl -sS -H "Authorization: Bearer $YGGDRASIL_ADMIN_TOKEN" \
  "https://yggdrasil.dakasa.me/api/v1/manifests?kind=integration_type" \
  | jq '.manifests[] | select(.spec.reactors[]?.event_type == "team.created") | .name'
```

Expected: prints `"slack"`, `"github"`, `"google-workspace"` (any order).

- [ ] **Step 2: Bootstrap — confirm existing teams reconcile**

The cron should re-emit `team.created` for every existing team during its first sweep after deploy. Wait ~5 min then:

```bash
psql $YGGDRASIL_DB_URL -c "SELECT integration_instance_id, COUNT(*) FROM team_provisioning_log GROUP BY 1;"
```

Expected: 3 rows (one per slack/gh/gw instance), each with N rows where N = number of teams.

If 0 rows: check `kubectl logs -n yggdrasil deploy/yggdrasil-core | grep team_reconcile` and confirm `TEAM_RECONCILE_ENABLED != "false"`.

- [ ] **Step 3: Happy path — create a brand-new team**

In the surface-console UI: create team "smoke-test-team". Within 30s:

```bash
psql $YGGDRASIL_DB_URL -c "SELECT integration_instance_id, external_id FROM team_provisioning_log WHERE team_id = '<smoke-test-team-uuid>';"
```

Expected: 3 rows with non-empty `external_id` per row.

In Slack: confirm `#team-smoke-test-team` channel exists, is private. In GitHub `dakasa-co` org: confirm team `smoke-test-team` exists, closed visibility. In Google Workspace admin: confirm group `smoke-test-team@dakasa.me` exists.

- [ ] **Step 4: Rename test**

In surface-console: edit team name (e.g. `smoke-test-team` → `smoke-renamed`). Within 30s:

- Slack channel: should be `#team-smoke-renamed`
- GitHub team: slug should be `smoke-renamed`
- GW group: name updates to "Smoke Renamed"; **email stays `smoke-test-team@dakasa.me`** (intentional)

- [ ] **Step 5: Delete test**

Delete the team via surface-console. Within 30s:

- Slack: channel archived (search `is:archived` to confirm)
- GitHub: team gone (404 on the URL)
- GW: group deleted (404 in admin)

- [ ] **Step 6: Adapter-down test**

Scale integration-slack to 0:

```bash
kubectl scale -n yggdrasil deploy/integration-slack --replicas=0
```

Create a new team. `team_provisioning_log` will get rows for github + gw, but the slack row will be pending in `integration_event_reactions`:

```bash
psql $YGGDRASIL_DB_URL -c "SELECT status, COUNT(*) FROM integration_event_reactions GROUP BY 1;"
```

Expected: at least one row in `pending` or `failed`.

Restore:

```bash
kubectl scale -n yggdrasil deploy/integration-slack --replicas=1
```

Within 1-2 cron ticks, the slack row appears in `team_provisioning_log`.

- [ ] **Step 7: Wrap-up — close all the related tasks**

Update memory or tracker with:
- Deployed at `<date/time>`
- Bootstrap reconcile completed for N existing teams
- 5 manual scenarios passed
- Open issues (if any)

No commit — this is observational.

---

## Self-review checklist

Run this list before considering the plan executed:

- [ ] All 4 repos pushed to `main` with team-reactor commits
- [ ] CD shows fresh pods running latest image
- [ ] `team_provisioning_log` populated for every active team × adapter
- [ ] `/api/v1/teams/<id>/provisioning-status` returns expected shape
- [ ] Happy path, rename, delete, adapter-down scenarios all pass
- [ ] No new `dead_lettered` reactions for `team.*` events

If any item is unchecked: file an issue and stop. Don't move on to surface-UI work or item #3 (Tartaro) until V1 of this plan is fully validated.
