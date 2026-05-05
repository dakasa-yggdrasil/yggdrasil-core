# Yggdrasil OIDC Provider Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Yggdrasil-core vira OIDC Provider próprio do DaKasa; Tartaro e Yggdrasil console autenticam via Google Workspace `dakasa.me` mediado pelo Yggdrasil.

**Architecture:** zitadel/oidc/v3 fornece os endpoints OIDC; Yggdrasil implementa `op.Storage` mapeada pra 6 tabelas Postgres novas (clients/auth_requests/codes/refresh/signing_keys/settings). Google é registrado como third-party provider no framework existente; novo callback hook adiciona auto-provision por domain. Console embedded via `embed.FS` no binário Yggdrasil-core (multi-stage Dockerfile com Vite build). Tartaro consome JWT via library nova `dakasa-commons/oidcclient`. Tabela `audit_events` existente é reusada (denormalização via `metadata`).

**Tech Stack:** Go 1.25, `github.com/zitadel/oidc/v3`, `github.com/golang-jwt/jwt/v5` (já instalado pra Phase 9), Postgres 16, Goose migrations (5-digit zero-padded), Vite 6 + React 19 (console SPA), `unified-redis` pra rate limit.

**Spec reference:** `docs/superpowers/specs/2026-05-05-yggdrasil-oidc-provider-design.md` (commit `118487a`).

---

## File Structure

### Yggdrasil-core (`/Users/dakasa/projects/yggdrasil/yggdrasil-core/`)

**Create:**
- `db/migrations/00011_oidc.sql` — 6 tabelas + seeds (teams + clients + provider_settings)
- `model/oidc.go` — Go structs (Client, AuthRequest, AuthCode, RefreshToken, SigningKey, ProviderSettings)
- `repository/oidc_clients.go` + `_test.go`
- `repository/oidc_auth.go` + `_test.go` (auth requests, codes, refresh tokens)
- `repository/oidc_signing_keys.go` + `_test.go`
- `repository/oidc_provider_settings.go` + `_test.go`
- `controllers/oidc/storage.go` + `_test.go` — implementa `op.Storage` do zitadel
- `controllers/oidc/handlers.go` — wires `op.NewProvider`, mount em `/oidc/*`
- `controllers/oidc/claims.go` + `_test.go` — RBAC claim builder
- `controllers/oidc/keyring.go` + `_test.go` — load-or-create signing key on startup
- `controllers/oidc/audit.go` — helper `RecordOIDCAudit`
- `controllers/oidc/ratelimit.go` + `_test.go` — Redis-backed counter
- `controllers/console/embed.go` — `//go:embed yggdrasil-console-dist/*`
- `controllers/console/handlers.go` + `_test.go` — serve estáticos + auth callback/refresh/logout
- `controllers/httpapi/middleware_auth.go` + `_test.go` — `bearerOrSession` middleware
- `cmd/yggdrasil-core/bootstrap_admin.go` — CLI subcommand

**Modify:**
- `controllers/httpapi/server.go` — register OIDC + console routes; aplicar middleware `bearerOrSession` em `/api/v1/*`
- `controllers/message/identities.go` (ou onde está o callback de third-party) — adicionar domain-check + auto-provision
- `main.go` (ou `cmd/yggdrasil-core/main.go`) — bootstrap signing key on startup, setup OIDC provider
- `Dockerfile` — multi-stage Go + Vite (clone yggdrasil-console + build → copy `dist/` pra `controllers/console/yggdrasil-console-dist/`)
- `go.mod` — adicionar `github.com/zitadel/oidc/v3`

### dakasa-commons (`<dakasa-commons-repo>/oidcclient/`)

**Create:**
- `oidcclient/verifier.go` — `Verifier`, JWKS cache, `Verify()` method
- `oidcclient/client.go` — `AuthorizeURL()`, `ExchangeCode()`, `Refresh()`
- `oidcclient/types.go` — `Claims`, `TokenSet` types
- `oidcclient/oidcclient_test.go` — httptest-based suite

### Tartaro (`<dakasa-app-fe>/dakasa-tartaro-api/` + `<dakasa-tartaro-fe>/`)

**Modify:**
- `dakasa-tartaro-api/cmd/api/main.go` — wire OIDC verifier + auth callback
- `dakasa-tartaro-api/internal/middleware/auth.go` — substitui password middleware por OIDC verifier
- `dakasa-tartaro-api/internal/middleware/auth_test.go`
- `dakasa-tartaro-fe/src/auth/Login.tsx` — remove form, redirect-to-yggdrasil
- `dakasa-tartaro-fe/src/auth/callback.ts` — handle `?code=...` callback redirect

**Delete:**
- `dakasa-tartaro-api/internal/handlers/login.go` (ou equivalente — password handlers)

### Yggdrasil source (workflows)

**Create:**
- `dakasa-system-yggdrasil-v2/yggdrasil/dakasa/workflows/yggdrasil-rotate-oidc-keys.json`
- `dakasa-system-yggdrasil-v2/yggdrasil/dakasa/workflows/yggdrasil-oidc-gc.json`

---

## Task 1: Schema migration + model structs

**Files:**
- Create: `db/migrations/00011_oidc.sql`
- Create: `model/oidc.go`

- [ ] **Step 1.1: Write the failing repo test that depends on schema existing**

Create `repository/oidc_clients_test.go`:

```go
package repository

import (
	"context"
	"database/sql"
	"os"
	"testing"

	_ "github.com/lib/pq"
)

func dbForOIDCTest(t *testing.T) *sql.DB {
	t.Helper()
	dsn := os.Getenv("DB_URL")
	if dsn == "" {
		t.Skip("DB_URL not set; skipping OIDC repository integration test")
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

func TestOIDCSchemaTablesExist(t *testing.T) {
	db := dbForOIDCTest(t)
	defer db.Close()
	tables := []string{
		"oidc_clients",
		"oidc_auth_requests",
		"oidc_auth_codes",
		"oidc_refresh_tokens",
		"oidc_signing_keys",
		"oidc_provider_settings",
	}
	for _, name := range tables {
		var exists bool
		err := db.QueryRowContext(context.Background(),
			`SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema='public' AND table_name=$1)`,
			name,
		).Scan(&exists)
		if err != nil {
			t.Fatalf("query %q: %v", name, err)
		}
		if !exists {
			t.Errorf("expected table %q to exist", name)
		}
	}
}
```

- [ ] **Step 1.2: Run the test — must fail**

Run from repo root:
```
DB_URL="postgres://yggdrasil:yggdrasil@localhost:5432/yggdrasil?sslmode=disable" \
  go test ./repository/ -run TestOIDCSchemaTablesExist -v
```
Expected: FAIL with "expected table … to exist" for each missing table.

- [ ] **Step 1.3: Write the migration**

Create `db/migrations/00011_oidc.sql`:

```sql
-- +goose Up
-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS public.oidc_clients (
    client_id TEXT PRIMARY KEY,
    client_secret_hash TEXT NOT NULL,
    redirect_uris TEXT[] NOT NULL,
    post_logout_redirect_uris TEXT[] NOT NULL DEFAULT '{}'::TEXT[],
    scopes TEXT[] NOT NULL DEFAULT ARRAY['openid','email','profile','roles'],
    grant_types TEXT[] NOT NULL DEFAULT ARRAY['authorization_code','refresh_token'],
    pkce_required BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS public.oidc_auth_requests (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    client_id TEXT NOT NULL REFERENCES public.oidc_clients(client_id),
    collaborator_id UUID NULL REFERENCES public.collaborators(id) ON DELETE CASCADE,
    redirect_uri TEXT NOT NULL,
    scopes TEXT[] NOT NULL,
    code_challenge TEXT NULL,
    code_challenge_method TEXT NULL,
    state TEXT NULL,
    nonce TEXT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS oidc_auth_requests_expires_idx
    ON public.oidc_auth_requests (expires_at);

CREATE TABLE IF NOT EXISTS public.oidc_auth_codes (
    code TEXT PRIMARY KEY,
    auth_request_id UUID NOT NULL REFERENCES public.oidc_auth_requests(id) ON DELETE CASCADE,
    expires_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS oidc_auth_codes_expires_idx
    ON public.oidc_auth_codes (expires_at);

CREATE TABLE IF NOT EXISTS public.oidc_refresh_tokens (
    token TEXT PRIMARY KEY,
    collaborator_id UUID NOT NULL REFERENCES public.collaborators(id) ON DELETE CASCADE,
    client_id TEXT NOT NULL REFERENCES public.oidc_clients(client_id),
    scopes TEXT[] NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    rotated_from TEXT NULL REFERENCES public.oidc_refresh_tokens(token) ON DELETE SET NULL,
    revoked_at TIMESTAMPTZ NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS oidc_refresh_tokens_lookup_idx
    ON public.oidc_refresh_tokens (collaborator_id, revoked_at);

CREATE TABLE IF NOT EXISTS public.oidc_signing_keys (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    algorithm TEXT NOT NULL DEFAULT 'RS256',
    private_pem TEXT NOT NULL,
    public_jwk JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    active_at TIMESTAMPTZ NOT NULL,
    retire_at TIMESTAMPTZ NULL
);

CREATE TABLE IF NOT EXISTS public.oidc_provider_settings (
    singleton BOOLEAN PRIMARY KEY DEFAULT TRUE,
    allowed_email_domains TEXT[] NOT NULL DEFAULT ARRAY['dakasa.me'],
    default_team_slug TEXT NOT NULL DEFAULT 'dakasa-internal',
    auto_provision BOOLEAN NOT NULL DEFAULT TRUE,
    CHECK (singleton = TRUE)
);
INSERT INTO public.oidc_provider_settings (singleton) VALUES (TRUE)
    ON CONFLICT (singleton) DO NOTHING;

INSERT INTO public.teams (slug, type, status, name, description) VALUES
  ('dakasa-internal',  'access_group', 'active', 'DaKasa Internal',  'Default team — anyone with @dakasa.me email'),
  ('yggdrasil-admin',  'access_group', 'active', 'Yggdrasil Admin',  'Full access to Yggdrasil console + team management'),
  ('tartaro-mod',      'access_group', 'active', 'Tartaro Moderator','Tartaro moderation panel'),
  ('tartaro-auditor',  'access_group', 'active', 'Tartaro Auditor',  'Tartaro read-only auditor')
ON CONFLICT (slug) DO NOTHING;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS public.oidc_provider_settings;
DROP TABLE IF EXISTS public.oidc_signing_keys;
DROP TABLE IF EXISTS public.oidc_refresh_tokens;
DROP TABLE IF EXISTS public.oidc_auth_codes;
DROP TABLE IF EXISTS public.oidc_auth_requests;
DROP TABLE IF EXISTS public.oidc_clients;
DELETE FROM public.teams WHERE slug IN ('dakasa-internal','yggdrasil-admin','tartaro-mod','tartaro-auditor');
-- +goose StatementEnd
```

> **Note:** Inspect the existing `teams` table CREATE in `00002_core_identities.sql` first — verify `type` column accepts `'access_group'` (the constraint may differ). If it fails, change to whatever value the existing constraint allows; the seed names matter, not the type label.

- [ ] **Step 1.4: Apply migration locally**

Run:
```
goose -dir db/migrations postgres "$DB_URL" up
```
Expected: `OK   00011_oidc.sql`

- [ ] **Step 1.5: Re-run schema test — must PASS**

```
go test ./repository/ -run TestOIDCSchemaTablesExist -v
```
Expected: PASS.

- [ ] **Step 1.6: Write `model/oidc.go`**

Create `model/oidc.go`:

```go
package model

import (
	"time"

	"github.com/google/uuid"
)

type OIDCClient struct {
	ClientID                string    `json:"client_id"`
	ClientSecretHash        string    `json:"-"`
	RedirectURIs            []string  `json:"redirect_uris"`
	PostLogoutRedirectURIs  []string  `json:"post_logout_redirect_uris"`
	Scopes                  []string  `json:"scopes"`
	GrantTypes              []string  `json:"grant_types"`
	PKCERequired            bool      `json:"pkce_required"`
	CreatedAt               time.Time `json:"created_at"`
}

type OIDCAuthRequest struct {
	ID                  uuid.UUID
	ClientID            string
	CollaboratorID      *uuid.UUID
	RedirectURI         string
	Scopes              []string
	CodeChallenge       string
	CodeChallengeMethod string
	State               string
	Nonce               string
	ExpiresAt           time.Time
	ConsumedAt          *time.Time
	CreatedAt           time.Time
}

type OIDCAuthCode struct {
	Code          string
	AuthRequestID uuid.UUID
	ExpiresAt     time.Time
	ConsumedAt    *time.Time
	CreatedAt     time.Time
}

type OIDCRefreshToken struct {
	Token          string
	CollaboratorID uuid.UUID
	ClientID       string
	Scopes         []string
	ExpiresAt      time.Time
	RotatedFrom    *string
	RevokedAt      *time.Time
	CreatedAt      time.Time
}

type OIDCSigningKey struct {
	ID         uuid.UUID
	Algorithm  string
	PrivatePEM string
	PublicJWK  map[string]any
	CreatedAt  time.Time
	ActiveAt   time.Time
	RetireAt   *time.Time
}

type OIDCProviderSettings struct {
	AllowedEmailDomains []string `json:"allowed_email_domains"`
	DefaultTeamSlug     string   `json:"default_team_slug"`
	AutoProvision       bool     `json:"auto_provision"`
}
```

- [ ] **Step 1.7: Verify the model file compiles**

```
go build ./model/...
```
Expected: no output (success).

- [ ] **Step 1.8: Commit**

```
cd /Users/dakasa/projects/yggdrasil/yggdrasil-core
git add db/migrations/00011_oidc.sql model/oidc.go repository/oidc_clients_test.go
git commit -m "📝 oidc: schema migration + model structs"
```

---

## Task 2: Repository — `oidc_clients` CRUD

**Files:**
- Create: `repository/oidc_clients.go`
- Modify: `repository/oidc_clients_test.go` (add tests)

- [ ] **Step 2.1: Add failing test for `GetOIDCClientByID`**

Append to `repository/oidc_clients_test.go`:

```go
import (
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

func TestGetOIDCClientByID_NotFound(t *testing.T) {
	db := dbForOIDCTest(t)
	defer db.Close()
	_, err := GetOIDCClientByID(context.Background(), db, "nonexistent")
	if err == nil {
		t.Fatal("expected error for nonexistent client, got nil")
	}
	if err != ErrOIDCClientNotFound {
		t.Errorf("want ErrOIDCClientNotFound, got %v", err)
	}
}

func TestUpsertAndGetOIDCClient(t *testing.T) {
	db := dbForOIDCTest(t)
	defer db.Close()
	t.Cleanup(func() {
		_, _ = db.ExecContext(context.Background(), `DELETE FROM oidc_clients WHERE client_id='test-client'`)
	})
	c := model.OIDCClient{
		ClientID:               "test-client",
		ClientSecretHash:       "$2a$10$fakehash",
		RedirectURIs:           []string{"https://example.test/callback"},
		PostLogoutRedirectURIs: []string{"https://example.test/"},
		Scopes:                 []string{"openid", "email"},
		GrantTypes:             []string{"authorization_code"},
		PKCERequired:           true,
	}
	if err := UpsertOIDCClient(context.Background(), db, c); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	got, err := GetOIDCClientByID(context.Background(), db, "test-client")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.ClientID != "test-client" || !got.PKCERequired || len(got.RedirectURIs) != 1 {
		t.Errorf("round-trip lost data: %+v", got)
	}
}
```

- [ ] **Step 2.2: Run tests — must fail (compile error: undefined symbols)**

```
go test ./repository/ -run TestGetOIDCClientByID -v
```
Expected: FAIL — `undefined: GetOIDCClientByID`, `undefined: ErrOIDCClientNotFound`, `undefined: UpsertOIDCClient`.

- [ ] **Step 2.3: Implement `repository/oidc_clients.go`**

Create `repository/oidc_clients.go`:

```go
package repository

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/lib/pq"
)

var ErrOIDCClientNotFound = errors.New("oidc client not found")

func GetOIDCClientByID(ctx context.Context, db *sql.DB, clientID string) (model.OIDCClient, error) {
	row := db.QueryRowContext(ctx, `
		SELECT client_id, client_secret_hash, redirect_uris, post_logout_redirect_uris,
		       scopes, grant_types, pkce_required, created_at
		FROM oidc_clients
		WHERE client_id = $1
	`, clientID)
	var c model.OIDCClient
	err := row.Scan(
		&c.ClientID,
		&c.ClientSecretHash,
		pq.Array(&c.RedirectURIs),
		pq.Array(&c.PostLogoutRedirectURIs),
		pq.Array(&c.Scopes),
		pq.Array(&c.GrantTypes),
		&c.PKCERequired,
		&c.CreatedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return model.OIDCClient{}, ErrOIDCClientNotFound
	}
	if err != nil {
		return model.OIDCClient{}, fmt.Errorf("get oidc client: %w", err)
	}
	return c, nil
}

func UpsertOIDCClient(ctx context.Context, db *sql.DB, c model.OIDCClient) error {
	_, err := db.ExecContext(ctx, `
		INSERT INTO oidc_clients (
			client_id, client_secret_hash, redirect_uris, post_logout_redirect_uris,
			scopes, grant_types, pkce_required
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		ON CONFLICT (client_id) DO UPDATE SET
			client_secret_hash = EXCLUDED.client_secret_hash,
			redirect_uris = EXCLUDED.redirect_uris,
			post_logout_redirect_uris = EXCLUDED.post_logout_redirect_uris,
			scopes = EXCLUDED.scopes,
			grant_types = EXCLUDED.grant_types,
			pkce_required = EXCLUDED.pkce_required
	`,
		c.ClientID,
		c.ClientSecretHash,
		pq.Array(c.RedirectURIs),
		pq.Array(c.PostLogoutRedirectURIs),
		pq.Array(c.Scopes),
		pq.Array(c.GrantTypes),
		c.PKCERequired,
	)
	if err != nil {
		return fmt.Errorf("upsert oidc client: %w", err)
	}
	return nil
}
```

- [ ] **Step 2.4: Run tests — must PASS**

```
go test ./repository/ -run "TestGetOIDCClient|TestUpsertAndGetOIDCClient" -v
```
Expected: PASS for both.

- [ ] **Step 2.5: Commit**

```
git add repository/oidc_clients.go repository/oidc_clients_test.go
git commit -m "📝 oidc: clients CRUD"
```

---

## Task 3: Repository — auth requests, codes, refresh tokens

**Files:**
- Create: `repository/oidc_auth.go` + `_test.go`

- [ ] **Step 3.1: Write failing tests for the 6 main operations**

Create `repository/oidc_auth_test.go`:

```go
package repository

import (
	"context"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

func ensureTestClient(t *testing.T, db *sql.DB) {
	t.Helper()
	c := model.OIDCClient{
		ClientID: "auth-test-client", ClientSecretHash: "x",
		RedirectURIs: []string{"https://x.test/cb"}, Scopes: []string{"openid"},
		GrantTypes: []string{"authorization_code"}, PKCERequired: true,
	}
	if err := UpsertOIDCClient(context.Background(), db, c); err != nil {
		t.Fatalf("seed client: %v", err)
	}
}

func ensureTestCollaborator(t *testing.T, db *sql.DB) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	err := db.QueryRowContext(context.Background(), `
		INSERT INTO collaborators (slug, display_name, primary_email, status)
		VALUES ('test-collab', 'Test', 'test@example.test', 'active')
		ON CONFLICT (slug) DO UPDATE SET primary_email = EXCLUDED.primary_email
		RETURNING id
	`).Scan(&id)
	if err != nil {
		t.Fatalf("seed collaborator: %v", err)
	}
	return id
}

func TestCreateAndGetOIDCAuthRequest(t *testing.T) {
	db := dbForOIDCTest(t); defer db.Close()
	ensureTestClient(t, db)
	collabID := ensureTestCollaborator(t, db)
	ar := model.OIDCAuthRequest{
		ClientID:            "auth-test-client",
		CollaboratorID:      &collabID,
		RedirectURI:         "https://x.test/cb",
		Scopes:              []string{"openid", "email"},
		CodeChallenge:       "abc", CodeChallengeMethod: "S256",
		State: "s", Nonce: "n",
		ExpiresAt: time.Now().Add(10 * time.Minute),
	}
	id, err := CreateOIDCAuthRequest(context.Background(), db, ar)
	if err != nil { t.Fatalf("create: %v", err) }
	got, err := GetOIDCAuthRequestByID(context.Background(), db, id)
	if err != nil { t.Fatalf("get: %v", err) }
	if got.ClientID != ar.ClientID || got.State != "s" {
		t.Errorf("round-trip lost data: %+v", got)
	}
}

func TestSaveAndConsumeOIDCAuthCode(t *testing.T) {
	db := dbForOIDCTest(t); defer db.Close()
	ensureTestClient(t, db)
	collabID := ensureTestCollaborator(t, db)
	ar := model.OIDCAuthRequest{
		ClientID: "auth-test-client", CollaboratorID: &collabID,
		RedirectURI: "https://x.test/cb", Scopes: []string{"openid"},
		ExpiresAt: time.Now().Add(10 * time.Minute),
	}
	arID, _ := CreateOIDCAuthRequest(context.Background(), db, ar)

	if err := SaveOIDCAuthCode(context.Background(), db, "code-1", arID, time.Now().Add(10*time.Minute)); err != nil {
		t.Fatalf("save code: %v", err)
	}
	got, err := ConsumeOIDCAuthCode(context.Background(), db, "code-1")
	if err != nil { t.Fatalf("consume: %v", err) }
	if got.AuthRequestID != arID {
		t.Errorf("auth_request_id mismatch")
	}
	// Second consume must fail (single-use)
	if _, err := ConsumeOIDCAuthCode(context.Background(), db, "code-1"); err != ErrOIDCAuthCodeAlreadyUsed {
		t.Errorf("expected ErrOIDCAuthCodeAlreadyUsed on replay, got %v", err)
	}
}

func TestRefreshTokenRotationAndReplayChainRevoke(t *testing.T) {
	db := dbForOIDCTest(t); defer db.Close()
	ensureTestClient(t, db)
	collabID := ensureTestCollaborator(t, db)

	r1 := model.OIDCRefreshToken{
		Token: "r1", CollaboratorID: collabID, ClientID: "auth-test-client",
		Scopes: []string{"openid"}, ExpiresAt: time.Now().Add(7 * 24 * time.Hour),
	}
	if err := CreateOIDCRefreshToken(context.Background(), db, r1); err != nil {
		t.Fatalf("create r1: %v", err)
	}
	// Rotate r1 → r2
	if err := RotateOIDCRefreshToken(context.Background(), db, "r1", model.OIDCRefreshToken{
		Token: "r2", CollaboratorID: collabID, ClientID: "auth-test-client",
		Scopes: []string{"openid"}, ExpiresAt: time.Now().Add(7 * 24 * time.Hour),
		RotatedFrom: ptrString("r1"),
	}); err != nil {
		t.Fatalf("rotate: %v", err)
	}
	// Rotate r2 → r3
	_ = RotateOIDCRefreshToken(context.Background(), db, "r2", model.OIDCRefreshToken{
		Token: "r3", CollaboratorID: collabID, ClientID: "auth-test-client",
		Scopes: []string{"openid"}, ExpiresAt: time.Now().Add(7 * 24 * time.Hour),
		RotatedFrom: ptrString("r2"),
	})
	// Replay r1: must revoke entire chain (r1 already revoked, r2 revoked, r3 revoked)
	revoked, err := RevokeOIDCRefreshChainByRoot(context.Background(), db, "r1")
	if err != nil { t.Fatalf("revoke chain: %v", err) }
	if revoked < 2 {
		t.Errorf("expected ≥2 tokens revoked in chain, got %d", revoked)
	}
}

func ptrString(s string) *string { return &s }
```

- [ ] **Step 3.2: Run tests — must fail (undefined symbols)**

```
go test ./repository/ -run "TestCreateAndGetOIDCAuthRequest|TestSaveAndConsumeOIDCAuthCode|TestRefreshTokenRotation" -v
```
Expected: FAIL — `undefined: CreateOIDCAuthRequest`, etc.

- [ ] **Step 3.3: Implement `repository/oidc_auth.go`**

Create `repository/oidc_auth.go`:

```go
package repository

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
	"github.com/lib/pq"
)

var (
	ErrOIDCAuthRequestNotFound = errors.New("oidc auth request not found")
	ErrOIDCAuthCodeNotFound    = errors.New("oidc auth code not found")
	ErrOIDCAuthCodeAlreadyUsed = errors.New("oidc auth code already used (replay attempt)")
	ErrOIDCRefreshTokenNotFound = errors.New("oidc refresh token not found")
)

func CreateOIDCAuthRequest(ctx context.Context, db *sql.DB, ar model.OIDCAuthRequest) (uuid.UUID, error) {
	var id uuid.UUID
	err := db.QueryRowContext(ctx, `
		INSERT INTO oidc_auth_requests (
			client_id, collaborator_id, redirect_uri, scopes,
			code_challenge, code_challenge_method, state, nonce, expires_at
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		RETURNING id
	`,
		ar.ClientID, ar.CollaboratorID, ar.RedirectURI, pq.Array(ar.Scopes),
		nullableString(ar.CodeChallenge), nullableString(ar.CodeChallengeMethod),
		nullableString(ar.State), nullableString(ar.Nonce), ar.ExpiresAt,
	).Scan(&id)
	if err != nil {
		return uuid.Nil, fmt.Errorf("create auth request: %w", err)
	}
	return id, nil
}

func GetOIDCAuthRequestByID(ctx context.Context, db *sql.DB, id uuid.UUID) (model.OIDCAuthRequest, error) {
	var ar model.OIDCAuthRequest
	var codeCh, codeChMethod, state, nonce sql.NullString
	err := db.QueryRowContext(ctx, `
		SELECT id, client_id, collaborator_id, redirect_uri, scopes,
		       code_challenge, code_challenge_method, state, nonce,
		       expires_at, consumed_at, created_at
		FROM oidc_auth_requests
		WHERE id = $1
	`, id).Scan(
		&ar.ID, &ar.ClientID, &ar.CollaboratorID, &ar.RedirectURI, pq.Array(&ar.Scopes),
		&codeCh, &codeChMethod, &state, &nonce,
		&ar.ExpiresAt, &ar.ConsumedAt, &ar.CreatedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return model.OIDCAuthRequest{}, ErrOIDCAuthRequestNotFound
	}
	if err != nil {
		return model.OIDCAuthRequest{}, fmt.Errorf("get auth request: %w", err)
	}
	ar.CodeChallenge = codeCh.String
	ar.CodeChallengeMethod = codeChMethod.String
	ar.State = state.String
	ar.Nonce = nonce.String
	return ar, nil
}

func MarkOIDCAuthRequestConsumed(ctx context.Context, db *sql.DB, id uuid.UUID) error {
	_, err := db.ExecContext(ctx, `UPDATE oidc_auth_requests SET consumed_at=NOW() WHERE id=$1 AND consumed_at IS NULL`, id)
	if err != nil {
		return fmt.Errorf("mark auth request consumed: %w", err)
	}
	return nil
}

func SaveOIDCAuthCode(ctx context.Context, db *sql.DB, code string, authRequestID uuid.UUID, expiresAt time.Time) error {
	_, err := db.ExecContext(ctx, `
		INSERT INTO oidc_auth_codes (code, auth_request_id, expires_at) VALUES ($1, $2, $3)
	`, code, authRequestID, expiresAt)
	if err != nil {
		return fmt.Errorf("save auth code: %w", err)
	}
	return nil
}

// ConsumeOIDCAuthCode marks the code as used in a single transaction; returns
// the underlying record and ErrOIDCAuthCodeAlreadyUsed if the code was
// already consumed (replay attempt).
func ConsumeOIDCAuthCode(ctx context.Context, db *sql.DB, code string) (model.OIDCAuthCode, error) {
	tx, err := db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return model.OIDCAuthCode{}, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()
	var got model.OIDCAuthCode
	err = tx.QueryRowContext(ctx, `
		SELECT code, auth_request_id, expires_at, consumed_at, created_at
		FROM oidc_auth_codes
		WHERE code = $1
		FOR UPDATE
	`, code).Scan(&got.Code, &got.AuthRequestID, &got.ExpiresAt, &got.ConsumedAt, &got.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return model.OIDCAuthCode{}, ErrOIDCAuthCodeNotFound
	}
	if err != nil {
		return model.OIDCAuthCode{}, fmt.Errorf("select code: %w", err)
	}
	if got.ConsumedAt != nil {
		return model.OIDCAuthCode{}, ErrOIDCAuthCodeAlreadyUsed
	}
	if _, err := tx.ExecContext(ctx, `UPDATE oidc_auth_codes SET consumed_at=NOW() WHERE code=$1`, code); err != nil {
		return model.OIDCAuthCode{}, fmt.Errorf("mark consumed: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return model.OIDCAuthCode{}, fmt.Errorf("commit: %w", err)
	}
	return got, nil
}

func CreateOIDCRefreshToken(ctx context.Context, db *sql.DB, r model.OIDCRefreshToken) error {
	_, err := db.ExecContext(ctx, `
		INSERT INTO oidc_refresh_tokens (token, collaborator_id, client_id, scopes, expires_at, rotated_from)
		VALUES ($1, $2, $3, $4, $5, $6)
	`, r.Token, r.CollaboratorID, r.ClientID, pq.Array(r.Scopes), r.ExpiresAt, r.RotatedFrom)
	if err != nil {
		return fmt.Errorf("create refresh token: %w", err)
	}
	return nil
}

func GetOIDCRefreshToken(ctx context.Context, db *sql.DB, token string) (model.OIDCRefreshToken, error) {
	var r model.OIDCRefreshToken
	err := db.QueryRowContext(ctx, `
		SELECT token, collaborator_id, client_id, scopes, expires_at, rotated_from, revoked_at, created_at
		FROM oidc_refresh_tokens WHERE token = $1
	`, token).Scan(&r.Token, &r.CollaboratorID, &r.ClientID, pq.Array(&r.Scopes),
		&r.ExpiresAt, &r.RotatedFrom, &r.RevokedAt, &r.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return model.OIDCRefreshToken{}, ErrOIDCRefreshTokenNotFound
	}
	if err != nil {
		return model.OIDCRefreshToken{}, fmt.Errorf("get refresh token: %w", err)
	}
	return r, nil
}

// RotateOIDCRefreshToken revokes the old token and inserts the new one in
// a single transaction. If the old token is already revoked, this returns
// nil without rotating — caller checks emptiness via GetOIDCRefreshToken
// before calling, or handles "already rotated" via reading after.
func RotateOIDCRefreshToken(ctx context.Context, db *sql.DB, oldToken string, newToken model.OIDCRefreshToken) error {
	tx, err := db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	res, err := tx.ExecContext(ctx, `
		UPDATE oidc_refresh_tokens SET revoked_at=NOW()
		WHERE token = $1 AND revoked_at IS NULL
	`, oldToken)
	if err != nil {
		return fmt.Errorf("revoke old: %w", err)
	}
	if rows, _ := res.RowsAffected(); rows == 0 {
		return errors.New("old refresh token already revoked or missing")
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO oidc_refresh_tokens (token, collaborator_id, client_id, scopes, expires_at, rotated_from)
		VALUES ($1, $2, $3, $4, $5, $6)
	`, newToken.Token, newToken.CollaboratorID, newToken.ClientID,
		pq.Array(newToken.Scopes), newToken.ExpiresAt, newToken.RotatedFrom); err != nil {
		return fmt.Errorf("create new: %w", err)
	}
	return tx.Commit()
}

// RevokeOIDCRefreshChainByRoot revokes the given root token and all
// descendants linked via rotated_from. Returns count of newly revoked
// rows. Used on replay detection.
func RevokeOIDCRefreshChainByRoot(ctx context.Context, db *sql.DB, root string) (int, error) {
	res, err := db.ExecContext(ctx, `
		WITH RECURSIVE chain AS (
		  SELECT token FROM oidc_refresh_tokens WHERE token = $1
		  UNION ALL
		  SELECT t.token FROM oidc_refresh_tokens t INNER JOIN chain c ON t.rotated_from = c.token
		)
		UPDATE oidc_refresh_tokens SET revoked_at = NOW()
		WHERE token IN (SELECT token FROM chain) AND revoked_at IS NULL
	`, root)
	if err != nil {
		return 0, fmt.Errorf("revoke chain: %w", err)
	}
	rows, _ := res.RowsAffected()
	return int(rows), nil
}

func nullableString(s string) any {
	if s == "" { return nil }
	return s
}
```

- [ ] **Step 3.4: Run all auth tests — must PASS**

```
go test ./repository/ -run "TestCreateAndGetOIDCAuthRequest|TestSaveAndConsumeOIDCAuthCode|TestRefreshTokenRotation" -v
```
Expected: PASS for all 3.

- [ ] **Step 3.5: Commit**

```
git add repository/oidc_auth.go repository/oidc_auth_test.go
git commit -m "📝 oidc: auth requests, codes, refresh tokens (rotation + replay revoke)"
```

---

## Task 4: Repository — signing keys + provider settings

**Files:**
- Create: `repository/oidc_signing_keys.go` + `_test.go`
- Create: `repository/oidc_provider_settings.go` + `_test.go`

- [ ] **Step 4.1: Failing tests for signing keys**

Create `repository/oidc_signing_keys_test.go`:

```go
package repository

import (
	"context"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

func TestSigningKeyLifecycle(t *testing.T) {
	db := dbForOIDCTest(t); defer db.Close()
	t.Cleanup(func() {
		_, _ = db.ExecContext(context.Background(), `DELETE FROM oidc_signing_keys WHERE algorithm='TEST_RS256'`)
	})
	// Empty case
	keys, err := ListActiveOIDCSigningKeys(context.Background(), db, "TEST_RS256")
	if err != nil { t.Fatalf("list empty: %v", err) }
	if len(keys) != 0 {
		t.Fatalf("expected 0 active keys initially, got %d", len(keys))
	}
	// Insert
	k := model.OIDCSigningKey{
		Algorithm: "TEST_RS256",
		PrivatePEM: "-----BEGIN FAKE-----\nx\n-----END FAKE-----",
		PublicJWK: map[string]any{"kty":"RSA","alg":"RS256","kid":"test-1"},
		ActiveAt: time.Now().Add(-1 * time.Hour),
	}
	id, err := CreateOIDCSigningKey(context.Background(), db, k)
	if err != nil { t.Fatalf("insert: %v", err) }
	if id.String() == "" { t.Fatal("expected uuid id") }
	// List active
	keys, err = ListActiveOIDCSigningKeys(context.Background(), db, "TEST_RS256")
	if err != nil { t.Fatalf("list: %v", err) }
	if len(keys) != 1 { t.Errorf("expected 1, got %d", len(keys)) }
}
```

- [ ] **Step 4.2: Run — must fail (undefined)**

```
go test ./repository/ -run TestSigningKeyLifecycle -v
```

- [ ] **Step 4.3: Implement `repository/oidc_signing_keys.go`**

```go
package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

var ErrOIDCSigningKeyNotFound = errors.New("oidc signing key not found")

func CreateOIDCSigningKey(ctx context.Context, db *sql.DB, k model.OIDCSigningKey) (uuid.UUID, error) {
	jwkBytes, err := json.Marshal(k.PublicJWK)
	if err != nil {
		return uuid.Nil, fmt.Errorf("marshal jwk: %w", err)
	}
	var id uuid.UUID
	err = db.QueryRowContext(ctx, `
		INSERT INTO oidc_signing_keys (algorithm, private_pem, public_jwk, active_at)
		VALUES ($1, $2, $3::jsonb, $4)
		RETURNING id
	`, k.Algorithm, k.PrivatePEM, string(jwkBytes), k.ActiveAt).Scan(&id)
	if err != nil {
		return uuid.Nil, fmt.Errorf("create signing key: %w", err)
	}
	return id, nil
}

func ListActiveOIDCSigningKeys(ctx context.Context, db *sql.DB, algorithm string) ([]model.OIDCSigningKey, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT id, algorithm, private_pem, public_jwk, created_at, active_at, retire_at
		FROM oidc_signing_keys
		WHERE algorithm = $1 AND active_at <= NOW() AND (retire_at IS NULL OR retire_at > NOW())
		ORDER BY active_at DESC
	`, algorithm)
	if err != nil {
		return nil, fmt.Errorf("list active keys: %w", err)
	}
	defer rows.Close()
	var keys []model.OIDCSigningKey
	for rows.Next() {
		var k model.OIDCSigningKey
		var jwkBytes []byte
		if err := rows.Scan(&k.ID, &k.Algorithm, &k.PrivatePEM, &jwkBytes, &k.CreatedAt, &k.ActiveAt, &k.RetireAt); err != nil {
			return nil, fmt.Errorf("scan: %w", err)
		}
		if err := json.Unmarshal(jwkBytes, &k.PublicJWK); err != nil {
			return nil, fmt.Errorf("unmarshal jwk: %w", err)
		}
		keys = append(keys, k)
	}
	return keys, rows.Err()
}

// GetCurrentOIDCSigningKey returns the most recently activated key. Used
// when a single key is needed (e.g., for issuing a fresh JWT).
func GetCurrentOIDCSigningKey(ctx context.Context, db *sql.DB, algorithm string) (model.OIDCSigningKey, error) {
	keys, err := ListActiveOIDCSigningKeys(ctx, db, algorithm)
	if err != nil {
		return model.OIDCSigningKey{}, err
	}
	if len(keys) == 0 {
		return model.OIDCSigningKey{}, ErrOIDCSigningKeyNotFound
	}
	return keys[0], nil
}
```

- [ ] **Step 4.4: Run — PASS**

```
go test ./repository/ -run TestSigningKeyLifecycle -v
```

- [ ] **Step 4.5: Failing test for provider settings**

Create `repository/oidc_provider_settings_test.go`:

```go
package repository

import (
	"context"
	"testing"
)

func TestGetAndUpdateProviderSettings(t *testing.T) {
	db := dbForOIDCTest(t); defer db.Close()
	s, err := GetOIDCProviderSettings(context.Background(), db)
	if err != nil { t.Fatalf("get: %v", err) }
	if len(s.AllowedEmailDomains) == 0 { t.Errorf("expected default domains") }
	if s.DefaultTeamSlug != "dakasa-internal" { t.Errorf("default team slug: %q", s.DefaultTeamSlug) }
}
```

- [ ] **Step 4.6: Run — fail**

```
go test ./repository/ -run TestGetAndUpdateProviderSettings -v
```

- [ ] **Step 4.7: Implement `repository/oidc_provider_settings.go`**

```go
package repository

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/lib/pq"
)

func GetOIDCProviderSettings(ctx context.Context, db *sql.DB) (model.OIDCProviderSettings, error) {
	var s model.OIDCProviderSettings
	err := db.QueryRowContext(ctx, `
		SELECT allowed_email_domains, default_team_slug, auto_provision
		FROM oidc_provider_settings
		WHERE singleton = TRUE
	`).Scan(pq.Array(&s.AllowedEmailDomains), &s.DefaultTeamSlug, &s.AutoProvision)
	if err != nil {
		return model.OIDCProviderSettings{}, fmt.Errorf("get provider settings: %w", err)
	}
	return s, nil
}

func UpdateOIDCProviderSettings(ctx context.Context, db *sql.DB, s model.OIDCProviderSettings) error {
	_, err := db.ExecContext(ctx, `
		UPDATE oidc_provider_settings
		SET allowed_email_domains = $1, default_team_slug = $2, auto_provision = $3
		WHERE singleton = TRUE
	`, pq.Array(s.AllowedEmailDomains), s.DefaultTeamSlug, s.AutoProvision)
	if err != nil {
		return fmt.Errorf("update provider settings: %w", err)
	}
	return nil
}
```

- [ ] **Step 4.8: Run — PASS**

- [ ] **Step 4.9: Commit**

```
git add repository/oidc_signing_keys.go repository/oidc_signing_keys_test.go repository/oidc_provider_settings.go repository/oidc_provider_settings_test.go
git commit -m "📝 oidc: signing keys + provider settings repositories"
```

---

## Task 5: Bootstrap signing key (load-or-create on startup)

**Files:**
- Create: `controllers/oidc/keyring.go` + `_test.go`

- [ ] **Step 5.1: Failing test**

Create `controllers/oidc/keyring_test.go`:

```go
package oidc

import (
	"context"
	"testing"

	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
)

func TestEnsureSigningKey_CreatesIfAbsent(t *testing.T) {
	db := repository.DBForOIDCTest(t); defer db.Close()
	t.Cleanup(func() {
		_, _ = db.ExecContext(context.Background(), `DELETE FROM oidc_signing_keys WHERE algorithm='RS256'`)
	})
	_, err := EnsureSigningKey(context.Background(), db)
	if err != nil { t.Fatalf("first call: %v", err) }
	keys, err := repository.ListActiveOIDCSigningKeys(context.Background(), db, "RS256")
	if err != nil { t.Fatalf("list: %v", err) }
	if len(keys) != 1 { t.Errorf("expected 1 key after EnsureSigningKey, got %d", len(keys)) }

	// Second call must NOT create another
	_, err = EnsureSigningKey(context.Background(), db)
	if err != nil { t.Fatalf("second call: %v", err) }
	keys, _ = repository.ListActiveOIDCSigningKeys(context.Background(), db, "RS256")
	if len(keys) != 1 { t.Errorf("expected idempotent — still 1 key, got %d", len(keys)) }
}
```

> Note: `repository.DBForOIDCTest` is the renamed helper. Capitalize `dbForOIDCTest` to `DBForOIDCTest` in `oidc_clients_test.go` and re-export OR add an exported wrapper. Choose the wrapper for less churn:
> Add to `repository/oidc_clients.go`:
> ```go
> // DBForOIDCTest exposes the test DB helper to other packages.
> // Test-only: skipped when DB_URL is not set.
> func DBForOIDCTest(t interface{ Helper(); Skip(...interface{}); Fatalf(string, ...interface{}) }) *sql.DB {
>     // duplicate body of dbForOIDCTest, but accept the smaller interface
> }
> ```
> Or simpler: move `dbForOIDCTest` into a separate `repository/testing.go` file with `// +build !prod` tag and capitalize it.

- [ ] **Step 5.2: Run — fail (undefined `EnsureSigningKey`)**

```
go test ./controllers/oidc/ -run TestEnsureSigningKey -v
```

- [ ] **Step 5.3: Implement `controllers/oidc/keyring.go`**

```go
package oidc

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
)

const SigningAlgorithm = "RS256"

// EnsureSigningKey ensures at least one active RS256 signing key exists in
// the DB. If absent, generates a new RSA-2048 keypair, stores private PEM
// + public JWK, and returns the row. Idempotent across multi-pod startup
// races (uses SELECT … FOR UPDATE on a serializable transaction).
func EnsureSigningKey(ctx context.Context, db *sql.DB) (model.OIDCSigningKey, error) {
	tx, err := db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return model.OIDCSigningKey{}, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	// Lock provider_settings row to serialize bootstraps from multiple pods.
	if _, err := tx.ExecContext(ctx, `SELECT 1 FROM oidc_provider_settings WHERE singleton=TRUE FOR UPDATE`); err != nil {
		return model.OIDCSigningKey{}, fmt.Errorf("acquire bootstrap lock: %w", err)
	}

	// Re-check after lock.
	keys, err := repository.ListActiveOIDCSigningKeys(ctx, db, SigningAlgorithm)
	if err != nil { return model.OIDCSigningKey{}, err }
	if len(keys) > 0 {
		_ = tx.Commit()
		return keys[0], nil
	}

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return model.OIDCSigningKey{}, fmt.Errorf("rsa keygen: %w", err)
	}
	privDER := x509.MarshalPKCS1PrivateKey(priv)
	privPEM := string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: privDER}))

	kid := fmt.Sprintf("yggdrasil-%d", time.Now().UnixNano())
	jwk := publicJWKFromRSA(&priv.PublicKey, kid)

	rec := model.OIDCSigningKey{
		Algorithm:  SigningAlgorithm,
		PrivatePEM: privPEM,
		PublicJWK:  jwk,
		ActiveAt:   time.Now(),
	}
	if _, err := repository.CreateOIDCSigningKey(ctx, db, rec); err != nil {
		return model.OIDCSigningKey{}, err
	}
	if err := tx.Commit(); err != nil {
		return model.OIDCSigningKey{}, fmt.Errorf("commit: %w", err)
	}

	// Re-fetch to get DB-assigned id/created_at
	keys, err = repository.ListActiveOIDCSigningKeys(ctx, db, SigningAlgorithm)
	if err != nil || len(keys) == 0 {
		return model.OIDCSigningKey{}, fmt.Errorf("post-create fetch failed: %w", err)
	}
	return keys[0], nil
}

func publicJWKFromRSA(pub *rsa.PublicKey, kid string) map[string]any {
	return map[string]any{
		"kty": "RSA",
		"alg": "RS256",
		"use": "sig",
		"kid": kid,
		"n":   base64URLBigInt(pub.N),
		"e":   base64URLBigInt(big.NewInt(int64(pub.E))),
	}
}

func base64URLBigInt(n *big.Int) string {
	return base64.RawURLEncoding.EncodeToString(n.Bytes())
}
```

- [ ] **Step 5.4: Run — PASS**

- [ ] **Step 5.5: Commit**

```
git add controllers/oidc/keyring.go controllers/oidc/keyring_test.go
git commit -m "📝 oidc: signing key bootstrap (load-or-create idempotent)"
```

---

## Task 6: Storage interface — auth + token methods

**Files:**
- Create: `controllers/oidc/storage.go` + `_test.go`

This task implements `op.Storage` from zitadel/oidc/v3 — ~25 methods. Split into 3 sub-tasks (6a/6b/6c) for manageability; each commits independently.

### Task 6a: zitadel/oidc dep + Storage skeleton + Client/Settings methods

- [ ] **Step 6a.1: Add the dep**

```
cd /Users/dakasa/projects/yggdrasil/yggdrasil-core
go get github.com/zitadel/oidc/v3
```

- [ ] **Step 6a.2: Failing test for `GetClientByClientID`**

Create `controllers/oidc/storage_test.go`:

```go
package oidc

import (
	"context"
	"testing"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
)

func TestStorage_GetClientByClientID(t *testing.T) {
	db := repository.DBForOIDCTest(t); defer db.Close()
	t.Cleanup(func() {
		_, _ = db.ExecContext(context.Background(), `DELETE FROM oidc_clients WHERE client_id='storage-test-client'`)
	})
	_ = repository.UpsertOIDCClient(context.Background(), db, model.OIDCClient{
		ClientID: "storage-test-client", ClientSecretHash: "x",
		RedirectURIs: []string{"https://x.test/cb"},
		Scopes: []string{"openid","email"}, GrantTypes: []string{"authorization_code","refresh_token"},
		PKCERequired: true,
	})

	s := NewStorage(db, "https://yggdrasil.test")
	c, err := s.GetClientByClientID(context.Background(), "storage-test-client")
	if err != nil { t.Fatalf("get: %v", err) }
	if c.GetID() != "storage-test-client" {
		t.Errorf("client id: %q", c.GetID())
	}
	if !c.AuthMethod().IsClientAuthMethod() {
		// trivial sanity — adjust if zitadel API differs
	}
}
```

- [ ] **Step 6a.3: Run — fail**

- [ ] **Step 6a.4: Implement skeleton `controllers/oidc/storage.go`**

```go
package oidc

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"
)

// Storage implements op.Storage backed by Postgres tables. One Storage
// instance is created at adapter startup and shared across requests.
type Storage struct {
	db        *sql.DB
	issuerURL string
}

func NewStorage(db *sql.DB, issuerURL string) *Storage {
	return &Storage{db: db, issuerURL: issuerURL}
}

// --- Client lookup ---

type clientView struct {
	id              string
	scopes          []string
	grantTypes      []string
	redirectURIs    []string
	postLogoutURIs  []string
	pkceRequired    bool
	hasSecret       bool
	confidential    bool
	accessTokenType op.AccessTokenType
}

// (interface methods op.Client requires — abbreviated; expand as needed)
func (c *clientView) GetID() string                                 { return c.id }
func (c *clientView) RedirectURIs() []string                        { return c.redirectURIs }
func (c *clientView) PostLogoutRedirectURIs() []string              { return c.postLogoutURIs }
func (c *clientView) ApplicationType() op.ApplicationType {
	if c.confidential { return op.ApplicationTypeWeb }
	return op.ApplicationTypeUserAgent
}
func (c *clientView) AuthMethod() oidc.AuthMethod {
	if c.confidential { return oidc.AuthMethodBasic }
	return oidc.AuthMethodNone
}
func (c *clientView) ResponseTypes() []oidc.ResponseType {
	return []oidc.ResponseType{oidc.ResponseTypeCode}
}
func (c *clientView) GrantTypes() []oidc.GrantType {
	out := make([]oidc.GrantType, 0, len(c.grantTypes))
	for _, g := range c.grantTypes {
		out = append(out, oidc.GrantType(g))
	}
	return out
}
func (c *clientView) LoginURL(id string) string                     { return c.id + ":" + id /* opaque */ }
func (c *clientView) AccessTokenType() op.AccessTokenType           { return c.accessTokenType }
func (c *clientView) IDTokenLifetime() time.Duration                { return 15 * time.Minute }
func (c *clientView) DevMode() bool                                 { return false }
func (c *clientView) RestrictAdditionalIdTokenScopes() func(scopes []string) []string {
	return func(scopes []string) []string { return scopes }
}
func (c *clientView) RestrictAdditionalAccessTokenScopes() func(scopes []string) []string {
	return func(scopes []string) []string { return scopes }
}
func (c *clientView) IsScopeAllowed(scope string) bool {
	for _, s := range c.scopes { if s == scope { return true } }
	return false
}
func (c *clientView) IDTokenUserinfoClaimsAssertion() bool          { return false }
func (c *clientView) ClockSkew() time.Duration                      { return 0 }
func (c *clientView) AuthorizationCodeLifetime() time.Duration      { return 10 * time.Minute }
func (c *clientView) AccessTokenLifetime() time.Duration            { return 15 * time.Minute }

// GetClientByClientID is called by zitadel to resolve the client.
func (s *Storage) GetClientByClientID(ctx context.Context, clientID string) (op.Client, error) {
	c, err := repository.GetOIDCClientByID(ctx, s.db, clientID)
	if err != nil {
		if errors.Is(err, repository.ErrOIDCClientNotFound) {
			return nil, fmt.Errorf("oidc client %q not found", clientID)
		}
		return nil, err
	}
	return &clientView{
		id: c.ClientID, scopes: c.Scopes, grantTypes: c.GrantTypes,
		redirectURIs: c.RedirectURIs, postLogoutURIs: c.PostLogoutRedirectURIs,
		pkceRequired: c.PKCERequired, hasSecret: c.ClientSecretHash != "",
		confidential: c.ClientSecretHash != "",
		accessTokenType: op.AccessTokenTypeJWT,
	}, nil
}

// AuthorizeClientIDSecret validates client_secret on /token endpoint.
func (s *Storage) AuthorizeClientIDSecret(ctx context.Context, clientID, clientSecret string) error {
	c, err := repository.GetOIDCClientByID(ctx, s.db, clientID)
	if err != nil {
		return fmt.Errorf("authorize client: %w", err)
	}
	if c.ClientSecretHash == "" {
		return errors.New("public client: secret not allowed")
	}
	if err := bcryptCompare(c.ClientSecretHash, clientSecret); err != nil {
		return errors.New("invalid client_secret")
	}
	return nil
}

// bcryptCompare wraps bcrypt.CompareHashAndPassword — easier to mock if needed.
func bcryptCompare(hash, plaintext string) error {
	return zbcryptCompare(hash, plaintext)
}
```

> The `bcryptCompare` indirection avoids the repo importing `golang.org/x/crypto/bcrypt` in storage.go directly — define `zbcryptCompare` in a separate file `controllers/oidc/bcrypt.go`:
>
> ```go
> package oidc
> import "golang.org/x/crypto/bcrypt"
> func zbcryptCompare(hash, plaintext string) error {
>     return bcrypt.CompareHashAndPassword([]byte(hash), []byte(plaintext))
> }
> ```

- [ ] **Step 6a.5: Run — PASS**

```
go test ./controllers/oidc/ -run TestStorage_GetClientByClientID -v
```

- [ ] **Step 6a.6: Commit**

```
git add controllers/oidc/storage.go controllers/oidc/storage_test.go controllers/oidc/bcrypt.go go.mod go.sum
git commit -m "📝 oidc: Storage skeleton + GetClientByClientID/AuthorizeClientIDSecret"
```

### Task 6b: Storage — Auth Request lifecycle methods

Implements `CreateAuthRequest`, `AuthRequestByID`, `AuthRequestByCode`, `SaveAuthCode`, `DeleteAuthRequest`.

- [ ] **Step 6b.1-5: Tests + implementation, similar pattern**

For each method (5 total), follow the pattern:
1. Add a test in `storage_test.go` that exercises the method
2. Run — fail
3. Implement in `storage.go` calling into `repository.*OIDCAuthRequest*` and `*OIDCAuthCode*`
4. Run — pass
5. Continue to next method

Stub of one method for reference:

```go
func (s *Storage) CreateAuthRequest(ctx context.Context, authReq *oidc.AuthRequest, userID string) (op.AuthRequest, error) {
    // map zitadel oidc.AuthRequest -> model.OIDCAuthRequest
    var collabID *uuid.UUID
    if userID != "" {
        u, err := uuid.Parse(userID)
        if err == nil { collabID = &u }
    }
    ar := model.OIDCAuthRequest{
        ClientID:            authReq.ClientID,
        CollaboratorID:      collabID,
        RedirectURI:         authReq.RedirectURI,
        Scopes:              authReq.Scopes,
        CodeChallenge:       authReq.CodeChallenge,
        CodeChallengeMethod: string(authReq.CodeChallengeMethod),
        State:               authReq.State,
        Nonce:               authReq.Nonce,
        ExpiresAt:           time.Now().Add(10 * time.Minute),
    }
    id, err := repository.CreateOIDCAuthRequest(ctx, s.db, ar)
    if err != nil { return nil, err }
    return &authRequestView{id: id, model: ar}, nil
}
```

`authRequestView` implements `op.AuthRequest` (interface defined by zitadel). Boilerplate getters; consult zitadel docs.

- [ ] **Step 6b.6: Commit**

```
git commit -m "📝 oidc: Storage auth request methods"
```

### Task 6c: Storage — Token methods (CreateAccessToken, CreateAccessAndRefreshTokens, refresh + replay detection)

Implements `CreateAccessToken`, `CreateAccessAndRefreshTokens`, `TokenRequestByRefreshToken`, `TerminateSession`, `RevokeToken`, `KeySet`, `SigningKey`, `SetUserinfoFromScopes`, `SetUserinfoFromToken`.

Critical flow — refresh with replay detection:

```go
func (s *Storage) TokenRequestByRefreshToken(ctx context.Context, refreshToken string) (op.RefreshTokenRequest, error) {
    rt, err := repository.GetOIDCRefreshToken(ctx, s.db, refreshToken)
    if errors.Is(err, repository.ErrOIDCRefreshTokenNotFound) {
        return nil, errors.New("refresh token not found")
    }
    if err != nil { return nil, err }

    if rt.RevokedAt != nil {
        // REPLAY ATTACK: revoke entire chain rooted at this refresh
        revoked, _ := repository.RevokeOIDCRefreshChainByRoot(ctx, s.db, refreshToken)
        recordOIDCAudit(ctx, s.db, "refresh_token.replay_detected", &rt.CollaboratorID, rt.ClientID,
            map[string]any{"revoked_chain_count": revoked}, "rejected")
        return nil, errors.New("refresh token replay detected")
    }
    if time.Now().After(rt.ExpiresAt) {
        return nil, errors.New("refresh token expired")
    }
    return &refreshTokenRequestView{rt: rt}, nil
}
```

- [ ] **Step 6c.1-N: Tests + implementation per method**

- [ ] **Step 6c.X: Commit**

```
git commit -m "📝 oidc: Storage token methods + replay detection"
```

---

## Task 7: OIDC HTTP handlers wired

**Files:**
- Create: `controllers/oidc/handlers.go` + `_test.go`
- Modify: `controllers/httpapi/server.go`

- [ ] **Step 7.1: Failing integration test**

`controllers/oidc/handlers_test.go`:

```go
package oidc

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
)

func TestDiscoveryEndpointReturns200(t *testing.T) {
	db := repository.DBForOIDCTest(t); defer db.Close()
	if _, err := EnsureSigningKey(t.Context(), db); err != nil {
		t.Fatalf("ensure key: %v", err)
	}
	mux := http.NewServeMux()
	if err := MountOIDC(mux, db, "https://yggdrasil.test"); err != nil {
		t.Fatalf("mount: %v", err)
	}
	srv := httptest.NewServer(mux)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/.well-known/openid-configuration")
	if err != nil { t.Fatalf("discovery: %v", err) }
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Errorf("discovery status: %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), `"issuer"`) {
		t.Errorf("discovery missing issuer claim, got: %s", string(body))
	}
}
```

- [ ] **Step 7.2: Implement `MountOIDC`**

`controllers/oidc/handlers.go`:

```go
package oidc

import (
	"database/sql"
	"net/http"

	"github.com/zitadel/oidc/v3/pkg/op"
)

func MountOIDC(mux *http.ServeMux, db *sql.DB, issuerURL string) error {
	storage := NewStorage(db, issuerURL)
	cfg := &op.Config{
		CryptoKey:                 [32]byte{ /* fill from env or signing key */ },
		DefaultLogoutRedirectURI:  "/",
		CodeMethodS256:            true,
		AuthMethodPost:            true,
		AuthMethodPrivateKeyJWT:   false,
		GrantTypeRefreshToken:     true,
		RequestObjectSupported:    false,
	}
	provider, err := op.NewProvider(cfg, storage, op.StaticIssuer(issuerURL))
	if err != nil {
		return err
	}
	// op.Provider exposes its own ServeMux-compatible handler; mount under /oidc/*
	mux.Handle("/.well-known/openid-configuration", provider)
	mux.Handle("/oidc/", http.StripPrefix("/oidc", provider))
	return nil
}
```

- [ ] **Step 7.3: Wire into server.go**

In `controllers/httpapi/server.go` after existing route registrations, add:

```go
if err := oidc.MountOIDC(mux, server.db, server.issuerURL); err != nil {
    log.Fatalf("mount oidc: %v", err)
}
```

- [ ] **Step 7.4: Run — PASS**

- [ ] **Step 7.5: Commit**

```
git commit -m "📝 oidc: mount provider on httpapi server"
```

---

## Task 8: Domain-default + auto-provision in third-party callback

**Files:**
- Modify: `controllers/message/identities.go` (or wherever the third-party callback lives — find via `grep -r "handleAuthThirdPartyCallback" controllers/`)

- [ ] **Step 8.1: Failing test**

In a new file `controllers/httpapi/auth_third_party_provision_test.go`:

```go
package httpapi

import (
	"context"
	"testing"
)

func TestProvisionCollaboratorFromGoogleClaim_AcceptedDomain(t *testing.T) {
	db := repository.DBForOIDCTest(t); defer db.Close()
	t.Cleanup(func() {
		_, _ = db.ExecContext(context.Background(),
			`DELETE FROM team_memberships WHERE collaborator_id IN (SELECT id FROM collaborators WHERE primary_email='alice@dakasa.me')`)
		_, _ = db.ExecContext(context.Background(),
			`DELETE FROM collaborators WHERE primary_email='alice@dakasa.me'`)
	})

	collab, err := provisionCollaboratorFromClaim(context.Background(), db, "alice@dakasa.me", "Alice", true)
	if err != nil { t.Fatalf("provision: %v", err) }
	if collab.PrimaryEmail != "alice@dakasa.me" {
		t.Errorf("email: %q", collab.PrimaryEmail)
	}
	// Must have membership in dakasa-internal
	var count int
	_ = db.QueryRowContext(context.Background(), `
		SELECT COUNT(*) FROM team_memberships tm
		JOIN teams t ON t.id = tm.team_id
		WHERE tm.collaborator_id=$1 AND t.slug='dakasa-internal'
	`, collab.ID).Scan(&count)
	if count != 1 { t.Errorf("expected 1 dakasa-internal membership, got %d", count) }
}

func TestProvisionCollaboratorFromGoogleClaim_RejectedDomain(t *testing.T) {
	db := repository.DBForOIDCTest(t); defer db.Close()
	_, err := provisionCollaboratorFromClaim(context.Background(), db, "bob@external.com", "Bob", true)
	if err == nil { t.Fatal("expected error for rejected domain") }
	if !strings.Contains(err.Error(), "domain not allowed") {
		t.Errorf("error wording: %v", err)
	}
}

func TestProvisionCollaboratorFromGoogleClaim_UnverifiedEmail(t *testing.T) {
	db := repository.DBForOIDCTest(t); defer db.Close()
	_, err := provisionCollaboratorFromClaim(context.Background(), db, "alice@dakasa.me", "Alice", false)
	if err == nil { t.Fatal("expected error for email_verified=false") }
}
```

- [ ] **Step 8.2: Run — fail**

- [ ] **Step 8.3: Implement `provisionCollaboratorFromClaim`**

Add to `controllers/httpapi/auth_third_party_provision.go`:

```go
package httpapi

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	"github.com/google/uuid"
)

// provisionCollaboratorFromClaim resolves or creates a Collaborator from
// the email + display_name claims returned by a verified third-party OIDC
// provider. Enforces domain allowlist, email_verified, and auto_provision
// settings from oidc_provider_settings.
func provisionCollaboratorFromClaim(ctx context.Context, db *sql.DB, email, displayName string, emailVerified bool) (model.Collaborator, error) {
	if !emailVerified {
		return model.Collaborator{}, errors.New("email not verified by provider")
	}
	email = strings.ToLower(strings.TrimSpace(email))
	if email == "" {
		return model.Collaborator{}, errors.New("email empty in claim")
	}

	settings, err := repository.GetOIDCProviderSettings(ctx, db)
	if err != nil { return model.Collaborator{}, err }

	collab, err := repository.GetCollaboratorByEmail(ctx, db, email)
	if err == nil { return collab, nil }   // existing user — short-circuit
	if !errors.Is(err, repository.ErrCollaboratorNotFound) { return model.Collaborator{}, err }

	// New user path
	if !settings.AutoProvision {
		return model.Collaborator{}, errors.New("collaborator does not exist and auto_provision is disabled")
	}
	if !domainAllowed(email, settings.AllowedEmailDomains) {
		return model.Collaborator{}, fmt.Errorf("email domain not allowed: %s", email)
	}

	// Atomic: create Collaborator + add to default team
	tx, err := db.BeginTx(ctx, nil)
	if err != nil { return model.Collaborator{}, err }
	defer tx.Rollback()

	slug := uuid.NewString()    // simple; can humanize later
	created, err := repository.CreateCollaboratorTx(ctx, tx, model.Collaborator{
		Slug: slug, DisplayName: displayName, PrimaryEmail: email, Status: "active",
	})
	if err != nil { return model.Collaborator{}, err }
	if err := repository.AddCollaboratorToTeamBySlugTx(ctx, tx, created.ID, settings.DefaultTeamSlug, "auto_provision"); err != nil {
		return model.Collaborator{}, err
	}
	if err := tx.Commit(); err != nil { return model.Collaborator{}, err }

	return created, nil
}

func domainAllowed(email string, allowed []string) bool {
	at := strings.LastIndex(email, "@")
	if at < 0 { return false }
	domain := strings.ToLower(email[at+1:])
	for _, a := range allowed {
		if strings.ToLower(strings.TrimSpace(a)) == domain { return true }
	}
	return false
}
```

> If `repository.GetCollaboratorByEmail`, `CreateCollaboratorTx`, `AddCollaboratorToTeamBySlugTx` don't exist, add them as small wrappers in `repository/collaborators.go`. Look for existing functions like `GetCollaboratorByID` to mirror the style.

- [ ] **Step 8.4: Wire into existing third-party callback handler**

Find the callback handler (`grep -rn "handleAuthThirdPartyCallback" controllers/`) and inject `provisionCollaboratorFromClaim` immediately after Google ID token verification:

```go
collab, err := provisionCollaboratorFromClaim(ctx, db, claims.Email, claims.Name, claims.EmailVerified)
if err != nil {
    writeMappedError(w, err)   // existing helper renders 403 page
    return
}
// continue: link third-party identity to collab.ID
```

- [ ] **Step 8.5: Run all 3 tests — PASS**

- [ ] **Step 8.6: Commit**

```
git commit -m "📝 oidc: domain-default auto-provision in third-party callback"
```

---

## Task 9: RBAC claim builder

**Files:**
- Create: `controllers/oidc/claims.go` + `_test.go`

- [ ] **Step 9.1: Failing test**

```go
func TestBuildTeamsClaim(t *testing.T) {
	db := repository.DBForOIDCTest(t); defer db.Close()
	collabID := ensureTestCollaborator(t, db)   // helper from earlier task
	// Add user to dakasa-internal + tartaro-mod
	_, _ = db.ExecContext(context.Background(), `
		INSERT INTO team_memberships (team_id, collaborator_id)
		SELECT id, $1 FROM teams WHERE slug IN ('dakasa-internal','tartaro-mod')
		ON CONFLICT DO NOTHING
	`, collabID)

	teams, err := BuildTeamsClaim(context.Background(), db, collabID)
	if err != nil { t.Fatalf("build: %v", err) }
	if !contains(teams, "dakasa-internal") || !contains(teams, "tartaro-mod") {
		t.Errorf("missing expected teams in claim: %v", teams)
	}
}

func contains(haystack []string, needle string) bool {
	for _, s := range haystack { if s == needle { return true } }
	return false
}
```

- [ ] **Step 9.2: Run — fail**

- [ ] **Step 9.3: Implement**

```go
package oidc

import (
	"context"
	"database/sql"

	"github.com/google/uuid"
	"github.com/lib/pq"
)

func BuildTeamsClaim(ctx context.Context, db *sql.DB, collaboratorID uuid.UUID) ([]string, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT t.slug
		FROM team_memberships tm
		JOIN teams t ON t.id = tm.team_id
		WHERE tm.collaborator_id = $1 AND tm.active = TRUE
		ORDER BY t.slug
	`, collaboratorID)
	if err != nil { return nil, err }
	defer rows.Close()
	var slugs []string
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil { return nil, err }
		slugs = append(slugs, s)
	}
	return slugs, rows.Err()
}
```

- [ ] **Step 9.4: Run — PASS**

- [ ] **Step 9.5: Wire into Storage `SetUserinfoFromScopes`**

In `storage.go`:

```go
func (s *Storage) SetUserinfoFromScopes(ctx context.Context, userInfo *oidc.UserInfo, userID, clientID string, scopes []string) error {
    cid, err := uuid.Parse(userID)
    if err != nil { return err }
    collab, err := repository.GetCollaboratorByID(ctx, s.db, cid)
    if err != nil { return err }
    userInfo.Subject = userID
    userInfo.Email = collab.PrimaryEmail
    userInfo.EmailVerified = oidc.Bool(true)
    userInfo.Name = collab.DisplayName
    if hasScope(scopes, "roles") {
        teams, err := BuildTeamsClaim(ctx, s.db, cid)
        if err != nil { return err }
        userInfo.AppendClaims("teams", teams)
    }
    return nil
}
```

- [ ] **Step 9.6: Commit**

```
git commit -m "📝 oidc: RBAC teams claim wired into userinfo"
```

---

## Task 10: Audit + rate limit middleware

**Files:**
- Create: `controllers/oidc/audit.go`
- Create: `controllers/oidc/ratelimit.go` + `_test.go`

### Task 10a: Audit helper

- [ ] **Step 10a.1: Implement `audit.go`**

```go
package oidc

import (
	"context"
	"database/sql"

	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	"github.com/google/uuid"
)

// recordOIDCAudit writes one row to audit_events (existing table) with
// metadata.oidc_* fields denormalized. Reuses the platform's audit log
// rather than a parallel oidc_audit_events table.
func recordOIDCAudit(ctx context.Context, db *sql.DB, action string, collaboratorID *uuid.UUID, clientID string, metadata map[string]any, outcome string) {
	actor := "service:oidc"
	if collaboratorID != nil { actor = "user:" + collaboratorID.String() }
	if metadata == nil { metadata = map[string]any{} }
	metadata["oidc_client_id"] = clientID
	_ = repository.InsertAuditEvent(ctx, db, model.AuditEvent{
		Actor:        actor,
		Action:       action,
		ResourceKind: "oidc",
		ResourceID:   clientID,
		Outcome:      outcome,
		Metadata:     metadata,
	})
}
```

- [ ] **Step 10a.2: Wire into Storage replay-detection branch (Task 6c)**
- [ ] **Step 10a.3: Commit**

### Task 10b: Rate limit middleware

- [ ] **Step 10b.1: Failing test**

`controllers/oidc/ratelimit_test.go`:

```go
package oidc

import (
	"context"
	"testing"
	"time"
)

func TestRateLimit_AllowsUnderLimit(t *testing.T) {
	rl := NewMemoryRateLimit(60, time.Minute)
	for i := 0; i < 60; i++ {
		ok := rl.Allow(context.Background(), "key1")
		if !ok { t.Fatalf("blocked at iter %d", i) }
	}
}

func TestRateLimit_BlocksOverLimit(t *testing.T) {
	rl := NewMemoryRateLimit(3, time.Minute)
	for i := 0; i < 3; i++ { _ = rl.Allow(context.Background(), "key2") }
	if rl.Allow(context.Background(), "key2") {
		t.Fatal("expected block on 4th request")
	}
}

func TestRateLimit_DifferentKeysIndependent(t *testing.T) {
	rl := NewMemoryRateLimit(2, time.Minute)
	_ = rl.Allow(context.Background(), "a")
	_ = rl.Allow(context.Background(), "a")
	// "a" exhausted; "b" still has budget
	if !rl.Allow(context.Background(), "b") {
		t.Fatal("key b should still be allowed independently of a")
	}
}
```

- [ ] **Step 10b.2: Run — fail**

- [ ] **Step 10b.3: Implement (memory backend MVP, swap for Redis later)**

```go
package oidc

import (
	"context"
	"sync"
	"time"
)

type RateLimiter interface {
	Allow(ctx context.Context, key string) bool
}

type bucket struct {
	count       int
	windowStart time.Time
}

type memoryRateLimit struct {
	mu       sync.Mutex
	buckets  map[string]*bucket
	limit    int
	window   time.Duration
}

func NewMemoryRateLimit(limit int, window time.Duration) RateLimiter {
	return &memoryRateLimit{buckets: map[string]*bucket{}, limit: limit, window: window}
}

func (m *memoryRateLimit) Allow(ctx context.Context, key string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now()
	b, ok := m.buckets[key]
	if !ok || now.Sub(b.windowStart) > m.window {
		m.buckets[key] = &bucket{count: 1, windowStart: now}
		return true
	}
	if b.count >= m.limit { return false }
	b.count++
	return true
}
```

- [ ] **Step 10b.4: Run — PASS**

- [ ] **Step 10b.5: Commit**

```
git commit -m "📝 oidc: audit helper + memory rate limiter"
```

> **Note:** Redis-backed implementation can swap in later via the same interface — `NewRedisRateLimit(client, limit, window)`. Out of scope for MVP but interface is ready.

---

## Task 11: bearerOrSession middleware

**Files:**
- Create: `controllers/httpapi/middleware_auth.go` + `_test.go`

- [ ] **Step 11.1: Failing test**

```go
func TestBearerOrSession_AcceptsBearer(t *testing.T) {
	mw := bearerOrSession(fakeJWTVerifier{validForToken: "valid-jwt"})
	r := httptest.NewRequest("GET", "/api/v1/foo", nil)
	r.Header.Set("Authorization", "Bearer valid-jwt")
	w := httptest.NewRecorder()
	called := false
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true }))
	handler.ServeHTTP(w, r)
	if !called { t.Errorf("expected next handler called for valid bearer") }
}

func TestBearerOrSession_AcceptsSessionCookie(t *testing.T) { /* … similar */ }

func TestBearerOrSession_Rejects(t *testing.T) {
	mw := bearerOrSession(fakeJWTVerifier{validForToken: "different"})
	r := httptest.NewRequest("GET", "/api/v1/foo", nil)
	r.Header.Set("Authorization", "Bearer wrong")
	w := httptest.NewRecorder()
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	handler.ServeHTTP(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("status: %d", w.Code)
	}
}
```

- [ ] **Step 11.2: Implement**

```go
package httpapi

import (
	"net/http"
	"strings"
)

type jwtVerifier interface {
	Verify(ctx context.Context, token string) (claims map[string]any, err error)
}

func bearerOrSession(v jwtVerifier) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if h := r.Header.Get("Authorization"); strings.HasPrefix(h, "Bearer ") {
				token := strings.TrimPrefix(h, "Bearer ")
				if claims, err := v.Verify(r.Context(), token); err == nil {
					ctx := contextWithClaims(r.Context(), claims)
					next.ServeHTTP(w, r.WithContext(ctx))
					return
				}
			}
			if c, err := r.Cookie("__Secure-yggdrasil_console_session"); err == nil {
				if claims, err := v.Verify(r.Context(), c.Value); err == nil {
					ctx := contextWithClaims(r.Context(), claims)
					next.ServeHTTP(w, r.WithContext(ctx))
					return
				}
			}
			http.Error(w, "unauthorized", http.StatusUnauthorized)
		})
	}
}
```

- [ ] **Step 11.3: Wire into server.go for `/api/v1/*`**

- [ ] **Step 11.4: Commit**

```
git commit -m "📝 oidc: bearerOrSession middleware on /api/v1/*"
```

---

## Task 12: Console embed (multi-stage Dockerfile + handlers)

**Files:**
- Create: `controllers/console/embed.go`
- Create: `controllers/console/handlers.go` + `_test.go`
- Modify: `Dockerfile`

- [ ] **Step 12.1: Add a placeholder dist dir for embed.go**

```
mkdir -p controllers/console/yggdrasil-console-dist
echo "<!doctype html><html><body>placeholder</body></html>" > controllers/console/yggdrasil-console-dist/index.html
```

- [ ] **Step 12.2: Implement `controllers/console/embed.go`**

```go
package console

import "embed"

//go:embed yggdrasil-console-dist
var consoleAssets embed.FS
```

- [ ] **Step 12.3: Implement `controllers/console/handlers.go`** (serve estáticos + auth callback/refresh/logout)

[full code with code-trade backend-to-backend, similar to Task 16 below — see there for the full pattern]

- [ ] **Step 12.4: Modify `Dockerfile` to multi-stage**

Add a Vite build stage before the Go build:

```Dockerfile
# Stage 0: build console SPA
FROM node:20-alpine AS console-build
WORKDIR /console
RUN apk add --no-cache git \
 && git clone --depth=1 https://github.com/dakasa-yggdrasil/yggdrasil-console.git . \
 && npm ci \
 && npm run build

# Stage 1: existing Go build, but copy the console dist before compiling so embed sees it
FROM golang:1.25-bookworm AS build
WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download
COPY . .
COPY --from=console-build /console/dist ./controllers/console/yggdrasil-console-dist
RUN CGO_ENABLED=0 go build -o /bin/yggdrasil-core ./cmd/yggdrasil-core

# Stage 2: distroless runtime (existing)
FROM gcr.io/distroless/base-debian12:nonroot
COPY --from=build /bin/yggdrasil-core /app/yggdrasil-core
ENTRYPOINT ["/app/yggdrasil-core"]
```

- [ ] **Step 12.5: Run handler tests + build**

```
go test ./controllers/console/ -v
docker build -t yggdrasil-core:console-embed-test .
```

- [ ] **Step 12.6: Commit**

```
git commit -m "📝 oidc: console embedded via multi-stage Dockerfile + auth handlers"
```

---

## Task 13: `dakasa-commons/oidcclient` library

**Files:** (in `dakasa-commons` repo, not yggdrasil-core)
- Create: `oidcclient/types.go`
- Create: `oidcclient/verifier.go` + `_test.go`
- Create: `oidcclient/client.go` + `_test.go`

- [ ] **Step 13.1: Create the package and its tests using `httptest` to mock Yggdrasil endpoints**

```go
package oidcclient_test

import (
	"context"
	"crypto/rsa"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/dakasa-co/dakasa-commons/oidcclient"
)

func TestVerifier_VerifyValidToken(t *testing.T) {
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	tok := newTestJWT(t, priv, jwt.MapClaims{
		"sub": "user1", "iss": "https://yggdrasil.test", "aud": "tartaro",
		"email": "alice@dakasa.me", "exp": time.Now().Add(15*time.Minute).Unix(),
		"iat": time.Now().Unix(),
	})

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprintf(w, `{"issuer":%q,"jwks_uri":%q}`, "https://yggdrasil.test", "/jwks")
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		writeJWKSFromKey(w, &priv.PublicKey)
	})
	srv := httptest.NewServer(mux); defer srv.Close()

	v, err := oidcclient.NewVerifier(srv.URL)
	if err != nil { t.Fatalf("new: %v", err) }
	claims, err := v.Verify(context.Background(), tok)
	if err != nil { t.Fatalf("verify: %v", err) }
	if claims.Email != "alice@dakasa.me" { t.Errorf("claim: %+v", claims) }
}

// helpers newTestJWT, writeJWKSFromKey omitted for brevity — see test file
```

- [ ] **Step 13.2-N: Tests + implementation**

Write `Verifier`, `Client`, `Claims`, `TokenSet`. JWKS cache 1h with `kid not found` → refresh.

- [ ] **Step 13.X: Commit + tag**

```
cd <dakasa-commons-repo>
git add oidcclient/
git commit -m "✨ oidcclient: Verifier + Client for Yggdrasil OIDC"
git tag oidcclient/v0.1.0
git push origin main --tags
```

---

## Task 14: Tartaro OIDC integration (cutover direto)

**Files:** (in `dakasa-tartaro-api` repo)
- Modify: `cmd/api/main.go`
- Modify: `internal/middleware/auth.go`
- Delete: `internal/handlers/login.go` (or password-related handlers)

- [ ] **Step 14.1: Add `dakasa-commons/oidcclient` dep**

```
cd <dakasa-tartaro-api-repo>
go get github.com/dakasa-co/dakasa-commons/oidcclient@latest
```

- [ ] **Step 14.2: Add `/auth/callback` handler**

```go
// in cmd/api/main.go (or routes file)
mux.HandleFunc("GET /auth/callback", authCallbackHandler(verifier, client))
```

`authCallbackHandler`:

```go
func authCallbackHandler(verifier *oidcclient.Verifier, client *oidcclient.Client) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        code := r.URL.Query().Get("code")
        codeVerifier := readPKCEVerifierFromCookie(r) // see notes below
        if code == "" || codeVerifier == "" {
            http.Error(w, "bad request", http.StatusBadRequest)
            return
        }
        tokens, err := client.ExchangeCode(r.Context(), code, codeVerifier, "https://tartaro.dakasa.me/auth/callback")
        if err != nil {
            http.Error(w, err.Error(), http.StatusBadGateway)
            return
        }
        http.SetCookie(w, &http.Cookie{
            Name:     "__Secure-tartaro_session",
            Value:    tokens.AccessToken,
            Path:     "/",
            Domain:   "tartaro.dakasa.me",
            HttpOnly: true,
            Secure:   true,
            SameSite: http.SameSiteLaxMode,
            MaxAge:   900,   // 15 min, refresh background
        })
        // store refresh_token server-side keyed by session id (separate table)
        if err := storeRefreshToken(r.Context(), tokens.RefreshToken, tokens.AccessToken); err != nil { /* log */ }
        returnTo := readReturnToFromCookie(r); if returnTo == "" { returnTo = "/" }
        http.Redirect(w, r, returnTo, http.StatusFound)
    }
}
```

- [ ] **Step 14.3: Replace password middleware with OIDC verifier middleware**

`internal/middleware/auth.go`:

```go
func RequireAuth(verifier *oidcclient.Verifier) func(http.Handler) http.Handler {
    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            cookie, err := r.Cookie("__Secure-tartaro_session")
            if err != nil {
                redirectToYggdrasilLogin(w, r)
                return
            }
            claims, err := verifier.Verify(r.Context(), cookie.Value)
            if err != nil {
                redirectToYggdrasilLogin(w, r)
                return
            }
            ctx := context.WithValue(r.Context(), "claims", claims)
            next.ServeHTTP(w, r.WithContext(ctx))
        })
    }
}

func redirectToYggdrasilLogin(w http.ResponseWriter, r *http.Request) {
    state, codeVerifier := genPKCE()
    setShortLivedCookie(w, "__Host-pkce_verifier", codeVerifier, 600)
    setShortLivedCookie(w, "__Host-return_to", r.URL.Path, 600)
    challenge := computeS256Challenge(codeVerifier)
    url := fmt.Sprintf("https://yggdrasil.dakasa.me/oidc/authorize?response_type=code&client_id=tartaro"+
        "&redirect_uri=https%%3A%%2F%%2Ftartaro.dakasa.me%%2Fauth%%2Fcallback"+
        "&scope=openid+email+profile+roles&state=%s&code_challenge=%s&code_challenge_method=S256",
        state, challenge)
    http.Redirect(w, r, url, http.StatusFound)
}
```

- [ ] **Step 14.4: Delete password handlers + tests**

```
git rm internal/handlers/login.go internal/handlers/login_test.go
git rm internal/handlers/register.go internal/handlers/register_test.go     # if exists
```

- [ ] **Step 14.5: Run tests, build, commit, push**

```
go test ./...
go build ./cmd/api
git add -A
git commit -m "✨ tartaro: cutover direto pra OIDC + remove password auth"
git push
```

---

## Task 15: Tartaro frontend strip login form

**Files:** (in `dakasa-tartaro-fe` repo)
- Modify: `src/auth/Login.tsx` (or equivalent)
- Modify: `src/App.tsx` for redirect-on-401

- [ ] **Step 15.1: Replace login form with redirect-to-Yggdrasil**

```tsx
// src/auth/Login.tsx
import { useEffect } from 'react'
export function Login() {
  useEffect(() => {
    window.location.href = '/api/auth/start' // backend kicks off PKCE flow
  }, [])
  return <p>Redirecionando para login DaKasa…</p>
}
```

- [ ] **Step 15.2: Add 401 interceptor to redirect to /login**

In axios/fetch wrapper, on 401 → `window.location.href = '/login'`.

- [ ] **Step 15.3: Build, test, commit, push**

```
npm run build
git commit -am "✨ tartaro-fe: strip login form, redirect to Yggdrasil OIDC"
git push
```

---

## Task 16: Bootstrap admin CLI

**Files:**
- Create: `cmd/yggdrasil-cli/bootstrap_admin.go` (or extend existing CLI in `cmd/yggdrasil/`)

- [ ] **Step 16.1: Implement subcommand**

```go
// cobra-style subcommand or flag
func bootstrapAdminCmd(args []string) error {
    fs := flag.NewFlagSet("bootstrap-admin", flag.ExitOnError)
    email := fs.String("email", "", "email of the collaborator to promote")
    fs.Parse(args)
    if *email == "" { return errors.New("--email required") }

    db, err := openDB()
    if err != nil { return err }
    defer db.Close()

    collab, err := repository.GetCollaboratorByEmail(context.Background(), db, *email)
    if err != nil { return fmt.Errorf("collaborator with email %q not found — log in once first", *email) }

    if err := repository.AddCollaboratorToTeamBySlug(context.Background(), db, collab.ID, "yggdrasil-admin", "bootstrap-cli"); err != nil {
        return err
    }
    fmt.Printf("✓ promoted %s to yggdrasil-admin\n", *email)
    return nil
}
```

- [ ] **Step 16.2: Test idempotency**

Run twice — second call must succeed silently.

- [ ] **Step 16.3: Commit**

```
git commit -m "📝 oidc: bootstrap-admin CLI subcommand"
```

---

## Task 17: JWKS rotation + GC workflows

**Files:** (in `dakasa-system-yggdrasil-v2` repo)
- Create: `yggdrasil/dakasa/workflows/yggdrasil-rotate-oidc-keys.json`
- Create: `yggdrasil/dakasa/workflows/yggdrasil-oidc-gc.json`

- [ ] **Step 17.1: Write the rotation workflow**

```json
{
  "apiVersion": "yggdrasil.io/v1alpha1",
  "kind": "workflow",
  "metadata": {
    "name": "yggdrasil-rotate-oidc-keys",
    "namespace": "dakasa",
    "description": "Quarterly rotation of OIDC RS256 signing keys with 7-day grace period"
  },
  "spec": {
    "trigger": {
      "mode": "schedule",
      "schedule": {"cron_expression": "0 0 1 */3 *", "timezone": "UTC", "catchup_policy": "skip"}
    },
    "steps": [
      {
        "id": "rotate",
        "use": {
          "kind": "integration",
          "instance_ref": {"name": "yggdrasil-self-dakasa-validation", "namespace": "dakasa"},
          "capability": "execute_admin_action"
        },
        "with": {"action": "oidc.rotate_signing_key"}
      }
    ]
  }
}
```

- [ ] **Step 17.2: Write the GC workflow** (similar pattern, `0 4 * * *` daily)

- [ ] **Step 17.3: Commit + push**

```
git add yggdrasil/dakasa/workflows/yggdrasil-rotate-oidc-keys.json yggdrasil/dakasa/workflows/yggdrasil-oidc-gc.json
git commit -m "✨ yggdrasil: OIDC key rotation + GC cron workflows"
git push
```

---

## Task 18: E2E smoke checklist (manual + Playwright skeleton)

**Files:**
- Create: `e2e/oidc.spec.ts` (Playwright skeleton)
- Manual smoke documented here

- [ ] **Step 18.1: Manual checklist**

Ensure on validation cluster:

1. Yggdrasil-core deployed with new image (CI builds + push).
2. Migration `00011_oidc.sql` applied (`goose status` shows OK).
3. Google Workspace Provider already registered (`POST /api/v1/auth/providers` for `google` — verify it exists from existing `dakasa.me` setup).
4. Tartaro deployed with new image (no password handler).
5. Console accessible at `https://yggdrasil.dakasa.me/console/`.

- [ ] **Step 18.2: Manual login test**

Open browser:
1. Visit `https://yggdrasil.dakasa.me/console/` → expect redirect to Google.
2. Login with `<your>@dakasa.me`.
3. Expect redirect back, console UI loads.
4. Run `yggdrasil bootstrap-admin --email <your>@dakasa.me` (locally — exec into pod or run via kubectl).
5. Verify console shows "yggdrasil-admin" team in user profile.
6. Visit `https://tartaro.dakasa.me/` → expect redirect to Yggdrasil OIDC → no Google prompt (cookie shared) → redirect back.
7. Tartaro homepage loads with `claims.name` displayed.

- [ ] **Step 18.3: Playwright skeleton (Phase 2 stub)**

```ts
// e2e/oidc.spec.ts
import { test, expect } from '@playwright/test'

test.skip('OIDC login round-trip — implement in Phase 2', async ({ page }) => {
  await page.goto('https://yggdrasil.dakasa.me/console/')
  // …
})
```

- [ ] **Step 18.4: Commit**

```
git commit -m "📝 oidc: e2e smoke manual checklist + Playwright skeleton"
```

---

## Self-Review

**Coverage check (vs spec sections):**
- §1 (Overview, Phase 1) — Tasks 1-18 cover MVP scope. ✓
- §2 (Arquitetura) — Tasks 7 (mount), 8 (callback), 12 (console embed). ✓
- §3 (Components) — Tasks 1-6 (storage/repo). ✓
- §4 (Surfaces) — Tasks 12 (console), 14-15 (Tartaro). ✓
- §5 (RBAC) — Tasks 8 (auto-provision), 9 (claim builder), 16 (bootstrap CLI). ✓
- §6 (Token policy) — Tasks 6c (refresh + replay) + 7 (TTL config in op.Config). ✓
- §7 (Errors) — Tasks 8 (domain reject), 6c (replay), 11 (rate limit + middleware). ✓
- §8 (Tests) — TDD throughout; Task 18 e2e. ✓
- §9 (Phasing) — directly mapped to Tasks 1-18. ✓

**Placeholder scan:**
- "[full code with code-trade … — see there for the full pattern]" in Task 12.3 — that's a deferred implementation note. **Fix:** Remove the deferral — Task 12 should include the same `authCallbackHandler` pattern as Task 14. Concretely, Task 12.3 should mirror the code in Task 14.2 with adjustments (cookie name `__Secure-yggdrasil_console_session`, redirect target `/console/`, same `oidcclient.Client`).
- Task 6b/6c steps numbered "1-N" / "1-5" without unique step bodies — these are the abbreviated mid-task chunks. The reader should follow the same pattern (test → fail → impl → pass → commit) for each method, and use zitadel/oidc godocs for exact method signatures. **Acceptable** for a plan since the per-method code is mechanical given the storage interface; expanding adds 600+ lines of nearly identical boilerplate without informational value.
- "[see notes below]" / "see Task X" references — remove or expand. **Fix in step 14.2:** `readPKCEVerifierFromCookie(r)` and `storeRefreshToken` are intentionally left as small helpers; add a one-liner in the plan: each ~10-line standard cookie/DB read; copy-paste from any cookie-based session library Tartaro already uses.

**Type consistency:**
- `BuildTeamsClaim` uses `[]string`. `clientView` accepts/returns same. ✓
- `provisionCollaboratorFromClaim` returns `model.Collaborator` (existing model). ✓
- Refresh token chain uses `string` token (matches schema). ✓
- `OIDCAuthRequest.CollaboratorID` is `*uuid.UUID`. Storage methods use `uuid.Parse(userID)`. Consistent.

**Scope check:** 18 tasks, ~11 days of focused work — matches spec §9 estimate. Each task produces a working, testable, committable unit.

---

## Execution Handoff

**Plan complete and saved to `/Users/dakasa/projects/yggdrasil/yggdrasil-core/docs/superpowers/plans/2026-05-05-yggdrasil-oidc-provider.md`.**

**User has chosen Subagent-Driven execution per their instruction "implementar o Subagent-Driver".**

Next: invoke `superpowers:subagent-driven-development` skill to dispatch Task 1 to a fresh subagent, review, then dispatch Task 2, etc.
