# Credential Lifecycle Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement credential lifecycle for password-based collaborators in yggdrasil-core: setup-link onboarding, MFA-gated change/reset, hard rotation, anti-enum forgot, and unification of `password_hash` into `auth_identities` (deprecating `collaborator_password_credentials` and the legacy `yggdrasil-identities` service).

**Architecture:** Extend `auth_identities` with password columns; add `auth_credential_tokens` for single-use setup/reset; new `internal/auth/password` domain package; 5 new HTTP endpoints under `/api/v1/auth/passwords/*`; middleware that blocks all authenticated routes when `password_must_change`/`mfa_enrollment_required`; 1 cron runner for rotation marking; 5 new `event_log.type` constants with JSON schema contracts.

**Tech Stack:** Go 1.22+, PostgreSQL (Goose migrations), `net/http` (`mux.HandleFunc("METHOD /path", handler)`), `argon2id` via `golang.org/x/crypto/argon2`, `crypto/rand` for tokens, existing `repository.EmitEvent`, existing `internal/auth/mfa` enforcer, existing `time.Ticker` pattern from `internal/operator/reconciler.go`.

**Spec reference:** [docs/superpowers/specs/2026-05-15-credential-lifecycle-design.md](../specs/2026-05-15-credential-lifecycle-design.md)

---

## File Structure

### To Create

| Path | Responsibility |
|---|---|
| `db/migrations/00027_unify_credentials.sql` | Add 6 password columns to auth_identities, backfill from collaborator_password_credentials, drop the old table |
| `db/migrations/00028_auth_credential_tokens.sql` | Create auth_credential_tokens with indexes |
| `internal/auth/password/hasher.go` | argon2id hash + multi-scheme verify dispatcher |
| `internal/auth/password/hasher_test.go` | Round-trip + cross-scheme verify tests |
| `internal/auth/password/token.go` | 32-byte random token generation + sha256 hashing |
| `internal/auth/password/token_test.go` | Entropy + length + charset assertions |
| `internal/auth/password/policy.go` | ValidateStrength + URL helpers (user-contributed) |
| `internal/auth/password/policy_test.go` | Table-driven policy assertions |
| `internal/auth/password/common_top1000.txt` | Common passwords blacklist (copied from upstream list) |
| `internal/auth/password/rotation.go` | SelectRotationBatch + MarkForRotation + Runner |
| `internal/auth/password/rotation_test.go` | Batch selection + marker tests |
| `model/credential_token.go` | CredentialToken struct + request/response DTOs |
| `model/auth_identity_password.go` | Extended AuthIdentity fields + DTOs for setup/change/forgot/reset |
| `repository/credential_tokens.go` | Token CRUD with single-use guarantees |
| `repository/credential_tokens_test.go` | Integration tests for token lifecycle |
| `repository/credentials.go` | Password field CRUD on auth_identities |
| `repository/credentials_test.go` | Integration tests for password ops |
| `controllers/httpapi/credentials.go` | 5 handlers + middleware |
| `controllers/httpapi/credentials_test.go` | E2E happy paths for each endpoint |
| `controllers/httpapi/middleware_credentials.go` | password_change_required + mfa_enrollment_required middleware |
| `controllers/httpapi/middleware_credentials_test.go` | Middleware behavior tests |
| `docs/contracts/events/credential.setup_token_issued.v1.json` | Event payload schema |
| `docs/contracts/events/credential.password_setup_completed.v1.json` | Event payload schema |
| `docs/contracts/events/credential.password_changed.v1.json` | Event payload schema |
| `docs/contracts/events/credential.reset_token_issued.v1.json` | Event payload schema |
| `docs/contracts/events/credential.password_rotation_required.v1.json` | Event payload schema |
| `cmd/yggdrasil/auth_passwords.go` | CLI `auth passwords setup-token` (path verify in T7.1) |

### To Modify

| Path | Change |
|---|---|
| `repository/auth.go` | Replace 2 queries that read `collaborator_password_credentials` (lines ~65 and ~363) with reads from `auth_identities` |
| `repository/event_types.go` (or equivalent constants file) | Add 5 new event type constants |
| `controllers/httpapi/auth.go` | Extend `authLoginResponse` with `password_change_required`, `password_change_url`, `mfa_enrollment_required`, `mfa_enroll_url` flags |
| `controllers/httpapi/server.go` | Register 5 new routes; apply credentials middleware to authenticated routes |
| `main.go` (yggdrasil-core entrypoint) | Start password rotation runner alongside existing services |
| `yggdrasil-identities/README.md` | Add deprecation banner |

---

## Phase 1: Migrations

### Task 1.1: Migration 00027 — Unify credentials into auth_identities

**Files:**
- Create: `db/migrations/00027_unify_credentials.sql`

- [ ] **Step 1: Write the migration SQL**

```sql
-- +goose Up
-- +goose StatementBegin
ALTER TABLE public.auth_identities
  ADD COLUMN password_hash         TEXT          NULL,
  ADD COLUMN password_scheme       TEXT          NULL,
  ADD COLUMN password_updated_at   TIMESTAMPTZ   NULL,
  ADD COLUMN password_expires_at   TIMESTAMPTZ   NULL,
  ADD COLUMN password_must_change  BOOLEAN       NOT NULL DEFAULT false,
  ADD COLUMN password_metadata     JSONB         NOT NULL DEFAULT '{}'::jsonb;

CREATE INDEX auth_identities_password_expires_idx
  ON public.auth_identities (password_expires_at)
  WHERE password_expires_at IS NOT NULL;

UPDATE public.auth_identities ai
SET password_hash       = cpc.password_hash,
    password_scheme     = cpc.password_scheme,
    password_updated_at = cpc.password_updated_at,
    password_metadata   = cpc.metadata
FROM public.collaborator_password_credentials cpc
WHERE ai.collaborator_id = cpc.collaborator_id;

DROP TRIGGER IF EXISTS collaborator_password_credentials_touch_updated_at ON public.collaborator_password_credentials;
DROP TABLE public.collaborator_password_credentials;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
CREATE TABLE public.collaborator_password_credentials (
    collaborator_id UUID PRIMARY KEY REFERENCES public.collaborators(id) ON DELETE CASCADE,
    status TEXT NOT NULL DEFAULT 'active',
    password_scheme TEXT NOT NULL DEFAULT 'pbkdf2_sha256',
    password_hash TEXT NOT NULL,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    password_updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TRIGGER collaborator_password_credentials_touch_updated_at
    BEFORE UPDATE ON public.collaborator_password_credentials
    FOR EACH ROW EXECUTE FUNCTION public.touch_updated_at();

INSERT INTO public.collaborator_password_credentials
    (collaborator_id, status, password_scheme, password_hash, metadata, password_updated_at)
SELECT collaborator_id, 'active', COALESCE(password_scheme, 'pbkdf2_sha256'),
       password_hash, password_metadata, COALESCE(password_updated_at, NOW())
FROM public.auth_identities
WHERE password_hash IS NOT NULL;

DROP INDEX IF EXISTS auth_identities_password_expires_idx;

ALTER TABLE public.auth_identities
  DROP COLUMN password_metadata,
  DROP COLUMN password_must_change,
  DROP COLUMN password_expires_at,
  DROP COLUMN password_updated_at,
  DROP COLUMN password_scheme,
  DROP COLUMN password_hash;
-- +goose StatementEnd
```

- [ ] **Step 2: Apply migration to a scratch DB**

```bash
cd /Users/dakasa/projects/yggdrasil/yggdrasil-core
DB_URL="postgres://localhost:5432/ygg_test?sslmode=disable" \
  goose -dir db/migrations postgres "$DB_URL" up
```

Expected: `OK   00027_unify_credentials.sql`, no errors.

- [ ] **Step 3: Verify schema**

```bash
psql "$DB_URL" -c "\d public.auth_identities" | grep -E 'password_(hash|scheme|updated_at|expires_at|must_change|metadata)'
psql "$DB_URL" -c "\dt public.collaborator_password_credentials"
```

Expected: 6 password columns present; old table not found.

- [ ] **Step 4: Verify down migration**

```bash
goose -dir db/migrations postgres "$DB_URL" down
psql "$DB_URL" -c "\dt public.collaborator_password_credentials"
goose -dir db/migrations postgres "$DB_URL" up
```

Expected: old table reappears on down, disappears on up again.

- [ ] **Step 5: Commit**

```bash
git add db/migrations/00027_unify_credentials.sql
git commit -m "feat(auth): migrate password_hash into auth_identities (00027)"
```

---

### Task 1.2: Migration 00028 — auth_credential_tokens

**Files:**
- Create: `db/migrations/00028_auth_credential_tokens.sql`

- [ ] **Step 1: Write the migration SQL**

```sql
-- +goose Up
-- +goose StatementBegin
CREATE TABLE public.auth_credential_tokens (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  collaborator_id UUID NOT NULL REFERENCES public.collaborators(id) ON DELETE CASCADE,
  purpose         TEXT NOT NULL CHECK (purpose IN ('setup','reset')),
  token_hash      TEXT NOT NULL,
  expires_at      TIMESTAMPTZ NOT NULL,
  consumed_at     TIMESTAMPTZ NULL,
  created_by      UUID NULL REFERENCES public.collaborators(id),
  metadata        JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT auth_credential_tokens_hash_unique UNIQUE (token_hash)
);

CREATE INDEX auth_credential_tokens_active_idx
  ON public.auth_credential_tokens (collaborator_id, purpose)
  WHERE consumed_at IS NULL;

CREATE INDEX auth_credential_tokens_expires_idx
  ON public.auth_credential_tokens (expires_at)
  WHERE consumed_at IS NULL;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS public.auth_credential_tokens;
-- +goose StatementEnd
```

- [ ] **Step 2: Apply + verify + roll back + reapply**

```bash
goose -dir db/migrations postgres "$DB_URL" up
psql "$DB_URL" -c "\d public.auth_credential_tokens"
goose -dir db/migrations postgres "$DB_URL" down
psql "$DB_URL" -c "\dt public.auth_credential_tokens"   # expect: not found
goose -dir db/migrations postgres "$DB_URL" up
```

Expected: table present after up, absent after down, present again.

- [ ] **Step 3: Commit**

```bash
git add db/migrations/00028_auth_credential_tokens.sql
git commit -m "feat(auth): add auth_credential_tokens table (00028)"
```

---

## Phase 2: Domain — password package

### Task 2.1: Password hasher (argon2id + pbkdf2 verify)

**Files:**
- Create: `internal/auth/password/hasher.go`
- Test: `internal/auth/password/hasher_test.go`

- [ ] **Step 1: Write the failing test**

```go
// internal/auth/password/hasher_test.go
package password

import (
	"strings"
	"testing"
)

func TestArgon2idRoundTrip(t *testing.T) {
	plain := "correct horse battery staple!"
	scheme, hash, err := Hash(plain)
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	if scheme != SchemeArgon2id {
		t.Fatalf("expected scheme %q, got %q", SchemeArgon2id, scheme)
	}
	if !strings.HasPrefix(hash, "$argon2id$") {
		t.Fatalf("expected argon2id-encoded hash, got %q", hash)
	}
	if err := Verify(scheme, hash, plain); err != nil {
		t.Fatalf("verify accept: %v", err)
	}
	if err := Verify(scheme, hash, "wrong"); err != ErrPasswordMismatch {
		t.Fatalf("verify reject: got %v want %v", err, ErrPasswordMismatch)
	}
}

func TestVerifyLegacyPBKDF2(t *testing.T) {
	// Hash produced by the previous pbkdf2_sha256 implementation.
	// Replace with a known fixture from a snapshot of the previous
	// repository.UpsertPasswordCredential output.
	legacyHash := "pbkdf2_sha256$600000$AAAAAAAAAAAAAAAA$kNcixYbiPGgLrTpQzv0Eqg=="
	plain := "legacy-known-password"
	if err := Verify(SchemePBKDF2SHA256, legacyHash, plain); err != nil {
		t.Fatalf("legacy verify: %v", err)
	}
}

func TestVerifyUnknownScheme(t *testing.T) {
	if err := Verify(Scheme("bcrypt-future"), "x", "y"); err != ErrSchemeUnknown {
		t.Fatalf("expected ErrSchemeUnknown, got %v", err)
	}
}
```

- [ ] **Step 2: Run to verify failure**

```bash
cd /Users/dakasa/projects/yggdrasil/yggdrasil-core
go test ./internal/auth/password/...
```

Expected: build error or test fail (no package yet).

- [ ] **Step 3: Implement hasher.go**

```go
// internal/auth/password/hasher.go
package password

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/pbkdf2"
	"crypto/sha256"
)

type Scheme string

const (
	SchemeArgon2id     Scheme = "argon2id"
	SchemePBKDF2SHA256 Scheme = "pbkdf2_sha256"
)

var (
	ErrPasswordMismatch = errors.New("password mismatch")
	ErrSchemeUnknown    = errors.New("password scheme unknown")
	ErrHashCorrupt      = errors.New("password hash corrupt")
)

type argon2Params struct {
	Memory  uint32
	Time    uint32
	Threads uint8
	KeyLen  uint32
}

func argonParamsFromEnv() argon2Params {
	return argon2Params{
		Memory:  uint32(envInt("AUTH_PASSWORD_ARGON2ID_MEMORY_KB", 65536)),
		Time:    uint32(envInt("AUTH_PASSWORD_ARGON2ID_TIME", 3)),
		Threads: uint8(envInt("AUTH_PASSWORD_ARGON2ID_THREADS", 4)),
		KeyLen:  32,
	}
}

func envInt(key string, def int) int {
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

// Hash returns the active scheme and the encoded hash string.
func Hash(plain string) (Scheme, string, error) {
	params := argonParamsFromEnv()
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", "", fmt.Errorf("salt: %w", err)
	}
	key := argon2.IDKey([]byte(plain), salt, params.Time, params.Memory, params.Threads, params.KeyLen)
	encoded := fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s",
		params.Memory, params.Time, params.Threads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key),
	)
	return SchemeArgon2id, encoded, nil
}

// Verify checks plain against encoded under the given scheme.
func Verify(scheme Scheme, encoded, plain string) error {
	switch scheme {
	case SchemeArgon2id:
		return verifyArgon2id(encoded, plain)
	case SchemePBKDF2SHA256:
		return verifyPBKDF2(encoded, plain)
	default:
		return ErrSchemeUnknown
	}
}

func verifyArgon2id(encoded, plain string) error {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return ErrHashCorrupt
	}
	var memory, time uint32
	var threads uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &time, &threads); err != nil {
		return ErrHashCorrupt
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return ErrHashCorrupt
	}
	want, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return ErrHashCorrupt
	}
	got := argon2.IDKey([]byte(plain), salt, time, memory, threads, uint32(len(want)))
	if subtle.ConstantTimeCompare(want, got) != 1 {
		return ErrPasswordMismatch
	}
	return nil
}

func verifyPBKDF2(encoded, plain string) error {
	parts := strings.Split(encoded, "$")
	if len(parts) != 4 || parts[0] != "pbkdf2_sha256" {
		return ErrHashCorrupt
	}
	iter, err := strconv.Atoi(parts[1])
	if err != nil {
		return ErrHashCorrupt
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[2])
	if err != nil {
		return ErrHashCorrupt
	}
	want, err := base64.RawStdEncoding.DecodeString(parts[3])
	if err != nil {
		return ErrHashCorrupt
	}
	got := pbkdf2.Key([]byte(plain), salt, iter, len(want), sha256.New)
	if subtle.ConstantTimeCompare(want, got) != 1 {
		return ErrPasswordMismatch
	}
	return nil
}
```

- [ ] **Step 4: Add dependency**

```bash
go get golang.org/x/crypto/argon2 golang.org/x/crypto/pbkdf2
go mod tidy
```

- [ ] **Step 5: Run tests**

```bash
go test ./internal/auth/password/... -run "TestArgon2idRoundTrip|TestVerifyUnknownScheme" -v
```

Expected: PASS. (`TestVerifyLegacyPBKDF2` may fail until a real legacy fixture is supplied — leave skipped or `t.Skip("waiting for fixture")` if there's no captured hash to validate yet.)

- [ ] **Step 6: Commit**

```bash
git add internal/auth/password/hasher.go internal/auth/password/hasher_test.go go.mod go.sum
git commit -m "feat(password): argon2id hasher + pbkdf2 legacy verify"
```

---

### Task 2.2: Token generation

**Files:**
- Create: `internal/auth/password/token.go`
- Test: `internal/auth/password/token_test.go`

- [ ] **Step 1: Failing test**

```go
// internal/auth/password/token_test.go
package password

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestGenerateTokenDistinct(t *testing.T) {
	seen := make(map[string]struct{}, 1000)
	for i := 0; i < 1000; i++ {
		tok, err := GenerateToken()
		if err != nil {
			t.Fatalf("gen: %v", err)
		}
		if len(tok.Raw) < 40 {
			t.Fatalf("raw too short: %d", len(tok.Raw))
		}
		if _, err := base64.RawURLEncoding.DecodeString(tok.Raw); err != nil {
			t.Fatalf("raw not base64url: %v (%q)", err, tok.Raw)
		}
		if strings.ContainsAny(tok.Raw, "+/=") {
			t.Fatalf("raw must be url-safe: %q", tok.Raw)
		}
		if _, dup := seen[tok.Raw]; dup {
			t.Fatalf("duplicate raw token at i=%d", i)
		}
		seen[tok.Raw] = struct{}{}
		if len(tok.Hash) != 64 {
			t.Fatalf("hash must be 64 hex chars, got %d", len(tok.Hash))
		}
	}
}

func TestHashTokenStable(t *testing.T) {
	h1 := HashToken("abc")
	h2 := HashToken("abc")
	if h1 != h2 {
		t.Fatalf("HashToken not deterministic: %s vs %s", h1, h2)
	}
	if h1 == HashToken("abd") {
		t.Fatalf("HashToken collision on different inputs")
	}
}
```

- [ ] **Step 2: Run (expect fail)**

```bash
go test ./internal/auth/password/... -run "TestGenerateToken|TestHashToken" -v
```

- [ ] **Step 3: Implement token.go**

```go
// internal/auth/password/token.go
package password

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
)

// GeneratedToken pairs a raw token (returned to the caller exactly once)
// with the hash that will be persisted in auth_credential_tokens.
type GeneratedToken struct {
	Raw  string // url-safe base64, 32-byte entropy
	Hash string // hex sha256(raw)
}

// GenerateToken produces a fresh 32-byte token and its sha256 hash.
func GenerateToken() (GeneratedToken, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return GeneratedToken{}, fmt.Errorf("token rand: %w", err)
	}
	raw := base64.RawURLEncoding.EncodeToString(buf)
	return GeneratedToken{Raw: raw, Hash: HashToken(raw)}, nil
}

// HashToken is the canonical hashing applied before storage and lookup.
func HashToken(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}
```

- [ ] **Step 4: Run tests**

```bash
go test ./internal/auth/password/... -run "TestGenerateToken|TestHashToken" -v
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/auth/password/token.go internal/auth/password/token_test.go
git commit -m "feat(password): 32-byte token gen + sha256 storage hash"
```

---

### Task 2.3: Password strength policy (user-contributed implementation)

**Files:**
- Create: `internal/auth/password/policy.go`
- Test: `internal/auth/password/policy_test.go`
- Create: `internal/auth/password/common_top1000.txt` (one password per line, lowercased; copy from the SecLists project's `10-million-password-list-top-1000.txt` or equivalent)

- [ ] **Step 1: Write the failing test table**

```go
// internal/auth/password/policy_test.go
package password

import (
	"errors"
	"testing"
)

func TestValidateStrength(t *testing.T) {
	common := map[string]struct{}{
		"password":   {},
		"qwerty":     {},
		"letmein123": {},
		"sunshine":   {},
	}
	tests := []struct {
		name       string
		password   string
		minLen     int
		userTokens []string
		want       error
	}{
		{"valid", "z9-Forest-River-Iceland", 12, []string{"ana@dakasa.co", "ana"}, nil},
		{"too short", "abc123", 12, nil, ErrPasswordTooShort},
		{"contains email local", "ana-needs-coffee-now", 12, []string{"ana@dakasa.co", "ana"}, ErrPasswordContainsIdentity},
		{"contains display name word", "iLoveSilvaMartins!", 12, []string{"Silva Martins", "smartins"}, ErrPasswordContainsIdentity},
		{"too common", "letmein123", 8, nil, ErrPasswordTooCommon},
		{"common case-insensitive", "Password", 8, nil, ErrPasswordTooCommon},
		{"short token ignored", "uuuuuuuuuuuuuu", 12, []string{"u"}, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateStrength(tt.password, tt.minLen, common, tt.userTokens)
			if !errors.Is(err, tt.want) {
				t.Fatalf("got %v want %v", err, tt.want)
			}
		})
	}
}
```

- [ ] **Step 2: Run (expect fail)**

```bash
go test ./internal/auth/password/... -run TestValidateStrength -v
```

- [ ] **Step 3: Implement policy.go (user contribution — see spec §11)**

```go
// internal/auth/password/policy.go
package password

import (
	"errors"
	"strings"
)

var (
	ErrPasswordTooShort         = errors.New("password too short")
	ErrPasswordContainsIdentity = errors.New("password contains personal identifier")
	ErrPasswordTooCommon        = errors.New("password is too common")
)

// ValidateStrength applies the active NIST 800-63B 2017+ policy:
//   1. min length
//   2. cannot contain any userToken of length >= 4 (case-insensitive)
//   3. lowercased password must not be in commonPasswords
//
// Design decisions deferred to the human author (see spec §11):
//   - substring vs Levenshtein for userToken match (current: case-insensitive substring)
//   - threshold for userToken length (current: 4)
//   - Unicode normalization (current: none — ASCII-leaning)
//
// Returns nil when all checks pass.
func ValidateStrength(password string, minLength int, commonPasswords map[string]struct{}, userTokens []string) error {
	if len(password) < minLength {
		return ErrPasswordTooShort
	}
	lowered := strings.ToLower(password)
	for _, token := range userTokens {
		t := strings.ToLower(strings.TrimSpace(token))
		if len(t) < 4 {
			continue
		}
		// also split on common separators so "ana@dakasa.co" yields "ana", "dakasa", "co"
		for _, part := range splitIdentityToken(t) {
			if len(part) < 4 {
				continue
			}
			if strings.Contains(lowered, part) {
				return ErrPasswordContainsIdentity
			}
		}
	}
	if _, hit := commonPasswords[lowered]; hit {
		return ErrPasswordTooCommon
	}
	return nil
}

func splitIdentityToken(t string) []string {
	t = strings.ToLower(t)
	seps := []string{"@", ".", "-", "_", " "}
	parts := []string{t}
	for _, s := range seps {
		var next []string
		for _, p := range parts {
			next = append(next, strings.Split(p, s)...)
		}
		parts = next
	}
	return parts
}

// LoadCommonPasswords reads common_top1000.txt at startup (one password per line).
func LoadCommonPasswords(path string) (map[string]struct{}, error) {
	data, err := readFile(path)
	if err != nil {
		return nil, err
	}
	out := make(map[string]struct{}, 1000)
	for _, line := range strings.Split(strings.TrimSpace(data), "\n") {
		l := strings.ToLower(strings.TrimSpace(line))
		if l == "" {
			continue
		}
		out[l] = struct{}{}
	}
	return out, nil
}

// indirected for ease of test override; keep simple
func readFile(p string) (string, error) {
	b, err := osReadFile(p)
	return string(b), err
}
```

- [ ] **Step 4: Add the os/readfile bridge**

```go
// internal/auth/password/io.go
package password

import "os"

var osReadFile = os.ReadFile
```

- [ ] **Step 5: Seed the wordlist**

```bash
curl -fsSL https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10-million-password-list-top-1000.txt \
  -o internal/auth/password/common_top1000.txt
wc -l internal/auth/password/common_top1000.txt
```

Expected: ~1000 lines.

- [ ] **Step 6: Run policy test**

```bash
go test ./internal/auth/password/... -run TestValidateStrength -v
```

Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add internal/auth/password/policy.go internal/auth/password/policy_test.go internal/auth/password/io.go internal/auth/password/common_top1000.txt
git commit -m "feat(password): NIST 2017+ strength policy + common-password blacklist"
```

---

### Task 2.4: Rotation primitives

**Files:**
- Create: `internal/auth/password/rotation.go`
- Test: `internal/auth/password/rotation_test.go`

- [ ] **Step 1: Failing test (integration, requires DB)**

```go
// internal/auth/password/rotation_test.go
package password

import (
	"context"
	"database/sql"
	"os"
	"testing"
	"time"

	_ "github.com/lib/pq"
)

func dbForRotationTest(t *testing.T) *sql.DB {
	t.Helper()
	dsn := os.Getenv("DB_URL")
	if dsn == "" {
		t.Skip("DB_URL not set; skipping rotation integration test")
	}
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	return db
}

func TestSelectRotationBatchExcludesNonActive(t *testing.T) {
	db := dbForRotationTest(t)
	defer db.Close()
	ctx := context.Background()

	// Insert two collaborators: one active (eligible), one suspended (ineligible).
	// Both have password_expires_at < NOW() and password_must_change=false.
	_, _ = db.Exec(`DELETE FROM auth_identities WHERE collaborator_id IN (SELECT id FROM collaborators WHERE slug LIKE 'rot-test-%')`)
	_, _ = db.Exec(`DELETE FROM collaborators WHERE slug LIKE 'rot-test-%'`)

	for _, suffix := range []string{"active", "suspended"} {
		status := "active"
		if suffix == "suspended" {
			status = "suspended"
		}
		_, err := db.Exec(`
            INSERT INTO collaborators (slug, display_name, primary_email, status)
            VALUES ($1, $1, $1 || '@test.dakasa.co', $2)
        `, "rot-test-"+suffix, status)
		if err != nil {
			t.Fatalf("insert collaborator %s: %v", suffix, err)
		}
		_, err = db.Exec(`
            INSERT INTO auth_identities (collaborator_id, username, password_hash, password_scheme, password_updated_at, password_expires_at)
            SELECT id, slug, 'h', 'argon2id', NOW() - INTERVAL '120 days', NOW() - INTERVAL '30 days'
            FROM collaborators WHERE slug = $1
        `, "rot-test-"+suffix)
		if err != nil {
			t.Fatalf("insert auth_identity %s: %v", suffix, err)
		}
	}

	ids, err := SelectRotationBatch(ctx, db, 100)
	if err != nil {
		t.Fatalf("select: %v", err)
	}
	// Expect: only the active collaborator returned.
	// Implementation choice: include 'on_leave', skip 'suspended' and 'offboarded'.
	if len(ids) != 1 {
		t.Fatalf("expected 1 eligible, got %d", len(ids))
	}

	if err := MarkForRotation(ctx, db, ids); err != nil {
		t.Fatalf("mark: %v", err)
	}
	var mustChange bool
	if err := db.QueryRow(`SELECT password_must_change FROM auth_identities WHERE collaborator_id = $1`, ids[0]).Scan(&mustChange); err != nil {
		t.Fatalf("scan: %v", err)
	}
	if !mustChange {
		t.Fatalf("expected must_change=true after MarkForRotation")
	}
	// idempotent: a second select must skip the just-marked id
	again, _ := SelectRotationBatch(ctx, db, 100)
	for _, id := range again {
		if id == ids[0] {
			t.Fatalf("MarkForRotation not idempotent: id reappears")
		}
	}
	_ = time.Now()
}
```

- [ ] **Step 2: Run (expect fail / skip)**

```bash
DB_URL="postgres://localhost:5432/ygg_test?sslmode=disable" \
  go test ./internal/auth/password/... -run TestSelectRotationBatch -v
```

- [ ] **Step 3: Implement rotation.go (user-tunable — see spec §11)**

```go
// internal/auth/password/rotation.go
package password

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// SelectRotationBatch returns up to `limit` collaborator IDs whose passwords
// have expired and have not yet been marked must_change.
//
// Eligibility rule (user-tunable — see spec §11):
//   - status IN ('active', 'on_leave')
//   - password_expires_at < NOW()
//   - password_must_change = false
//   - password_hash IS NOT NULL  (no SSO-only rows)
//
// Ordering: oldest expiry first so the backlog drains predictably.
func SelectRotationBatch(ctx context.Context, db *sql.DB, limit int) ([]uuid.UUID, error) {
	if limit <= 0 {
		limit = 1000
	}
	rows, err := db.QueryContext(ctx, `
        SELECT ai.collaborator_id
        FROM auth_identities ai
        JOIN collaborators c ON c.id = ai.collaborator_id
        WHERE ai.password_expires_at IS NOT NULL
          AND ai.password_expires_at < NOW()
          AND ai.password_must_change = false
          AND ai.password_hash IS NOT NULL
          AND c.status IN ('active','on_leave')
        ORDER BY ai.password_expires_at ASC
        LIMIT $1
    `, limit)
	if err != nil {
		return nil, fmt.Errorf("select rotation batch: %w", err)
	}
	defer rows.Close()
	var ids []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("scan: %w", err)
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

// MarkForRotation flips password_must_change=true for the given collaborator IDs.
// Caller is responsible for emitting credential.password_rotation_required events
// per ID (see repository.MarkPasswordsRequiringRotation for the event-emitting
// counterpart that uses this primitive).
func MarkForRotation(ctx context.Context, db *sql.DB, ids []uuid.UUID) error {
	if len(ids) == 0 {
		return nil
	}
	uuidStrings := make([]string, len(ids))
	for i, id := range ids {
		uuidStrings[i] = id.String()
	}
	res, err := db.ExecContext(ctx, `
        UPDATE auth_identities
        SET password_must_change = true
        WHERE collaborator_id = ANY($1::uuid[])
          AND password_must_change = false
    `, uuidStrings)
	if err != nil {
		return fmt.Errorf("mark rotation: %w", err)
	}
	_, _ = res.RowsAffected()
	return nil
}

// Runner is a periodic worker that scans expired passwords and marks them.
type Runner struct {
	DB       *sql.DB
	Interval time.Duration
	Batch    int
	Logger   Logger
	// EmitMark is called per marked collaborator_id; the controller wires this
	// to repository event emission. Leave nil to skip emission (tests).
	EmitMark func(ctx context.Context, id uuid.UUID) error
}

type Logger interface {
	Info(msg string, args ...any)
	Error(msg string, args ...any)
}

// Run blocks until ctx is cancelled.
func (r *Runner) Run(ctx context.Context) error {
	interval := r.Interval
	if interval <= 0 {
		interval = time.Hour
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		if err := r.runOnce(ctx); err != nil && r.Logger != nil {
			r.Logger.Error("rotation runner failed", "err", err)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
		}
	}
}

func (r *Runner) runOnce(ctx context.Context) error {
	ids, err := SelectRotationBatch(ctx, r.DB, r.Batch)
	if err != nil {
		return err
	}
	if len(ids) == 0 {
		return nil
	}
	if err := MarkForRotation(ctx, r.DB, ids); err != nil {
		return err
	}
	if r.EmitMark == nil {
		return nil
	}
	for _, id := range ids {
		if err := r.EmitMark(ctx, id); err != nil && r.Logger != nil {
			r.Logger.Error("emit rotation event", "id", id.String(), "err", err)
		}
	}
	return nil
}
```

- [ ] **Step 4: Run tests**

```bash
DB_URL="postgres://localhost:5432/ygg_test?sslmode=disable" \
  go test ./internal/auth/password/... -run TestSelectRotationBatch -v
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/auth/password/rotation.go internal/auth/password/rotation_test.go
git commit -m "feat(password): rotation batch + marker + ticker runner"
```

---

## Phase 3: Event contracts

### Task 3.1: Add 5 JSON Schema files + event type constants

**Files:**
- Create:
  - `docs/contracts/events/credential.setup_token_issued.v1.json`
  - `docs/contracts/events/credential.password_setup_completed.v1.json`
  - `docs/contracts/events/credential.password_changed.v1.json`
  - `docs/contracts/events/credential.reset_token_issued.v1.json`
  - `docs/contracts/events/credential.password_rotation_required.v1.json`
- Modify: repository event-types constants file (find via grep — see Step 1)

- [ ] **Step 1: Locate the constants file**

```bash
grep -rn "manifest.created\b" /Users/dakasa/projects/yggdrasil/yggdrasil-core/repository/ /Users/dakasa/projects/yggdrasil/yggdrasil-core/docs/contracts/ 2>/dev/null | head -5
```

Expected: a Go file with a constant `EventTypeManifestCreated = "manifest.created"`. Note the path.

- [ ] **Step 2: Write the 5 JSON Schema files**

`docs/contracts/events/credential.setup_token_issued.v1.json`:

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "credential.setup_token_issued v1",
  "type": "object",
  "required": ["token_id", "collaborator_id", "expires_at", "purpose"],
  "properties": {
    "token_id":       { "type": "string", "format": "uuid" },
    "collaborator_id":{ "type": "string", "format": "uuid" },
    "expires_at":     { "type": "string", "format": "date-time" },
    "issued_by_id":   { "type": "string", "format": "uuid" },
    "purpose":        { "type": "string", "enum": ["setup"] }
  },
  "additionalProperties": false
}
```

`docs/contracts/events/credential.password_setup_completed.v1.json`:

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "credential.password_setup_completed v1",
  "type": "object",
  "required": ["collaborator_id", "token_id", "source"],
  "properties": {
    "collaborator_id":{ "type": "string", "format": "uuid" },
    "token_id":       { "type": "string", "format": "uuid" },
    "source":         { "type": "string", "enum": ["setup"] },
    "ip":             { "type": "string" },
    "user_agent":     { "type": "string" }
  },
  "additionalProperties": false
}
```

`docs/contracts/events/credential.password_changed.v1.json`:

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "credential.password_changed v1",
  "type": "object",
  "required": ["collaborator_id", "source"],
  "properties": {
    "collaborator_id":{ "type": "string", "format": "uuid" },
    "source":         { "type": "string", "enum": ["voluntary","rotation","reset"] },
    "ip":             { "type": "string" }
  },
  "additionalProperties": false
}
```

`docs/contracts/events/credential.reset_token_issued.v1.json`:

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "credential.reset_token_issued v1",
  "type": "object",
  "required": ["token_id", "collaborator_id", "expires_at", "source", "purpose"],
  "properties": {
    "token_id":       { "type": "string", "format": "uuid" },
    "collaborator_id":{ "type": "string", "format": "uuid" },
    "expires_at":     { "type": "string", "format": "date-time" },
    "source":         { "type": "string", "enum": ["self_service"] },
    "purpose":        { "type": "string", "enum": ["reset"] }
  },
  "additionalProperties": false
}
```

`docs/contracts/events/credential.password_rotation_required.v1.json`:

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "credential.password_rotation_required v1",
  "type": "object",
  "required": ["collaborator_id", "expires_at", "marked_at"],
  "properties": {
    "collaborator_id":{ "type": "string", "format": "uuid" },
    "expires_at":     { "type": "string", "format": "date-time" },
    "marked_at":      { "type": "string", "format": "date-time" }
  },
  "additionalProperties": false
}
```

- [ ] **Step 3: Add 5 event type constants to repository/(file from Step 1)**

Append (adjust file path based on Step 1):

```go
const (
    EventTypeCredentialSetupTokenIssued        = "credential.setup_token_issued"
    EventTypeCredentialPasswordSetupCompleted  = "credential.password_setup_completed"
    EventTypeCredentialPasswordChanged         = "credential.password_changed"
    EventTypeCredentialResetTokenIssued        = "credential.reset_token_issued"
    EventTypeCredentialPasswordRotationRequired = "credential.password_rotation_required"
)
```

- [ ] **Step 4: Wire schemas into the validator registry**

Find the function/map that `contracts.ValidateEventPayload` consults (likely `docs/contracts/events/registry.go` or similar):

```bash
grep -rn "ValidateEventPayload\|schemaRegistry" /Users/dakasa/projects/yggdrasil/yggdrasil-core/docs/contracts/ 2>/dev/null | head -5
```

Register each of the 5 new schemas there following the existing pattern (e.g., `embed.FS` plus a `map[string]string` from `(type, version)` → schema filename).

- [ ] **Step 5: Verify build**

```bash
go build ./...
```

Expected: success.

- [ ] **Step 6: Commit**

```bash
git add docs/contracts/events/credential.*.v1.json repository/
git commit -m "feat(events): add credential.* event payload schemas + constants"
```

---

## Phase 4: Model types

### Task 4.1: Add DTOs and extend AuthIdentity

**Files:**
- Create: `model/credential_token.go`
- Create: `model/auth_identity_password.go`
- Modify: `model/auth_identity.go` (path to be confirmed — likely already exists since `model.AuthIdentity` is referenced in `repository/auth_identity.go`)

- [ ] **Step 1: Find the existing AuthIdentity model**

```bash
grep -rln "type AuthIdentity struct" /Users/dakasa/projects/yggdrasil/yggdrasil-core/model/
```

- [ ] **Step 2: Extend AuthIdentity with password fields**

In the file found in Step 1, add fields:

```go
// inside type AuthIdentity struct { ... }
PasswordHash         *string    `json:"-"`
PasswordScheme       *string    `json:"-"`
PasswordUpdatedAt    *time.Time `json:"password_updated_at,omitempty"`
PasswordExpiresAt    *time.Time `json:"password_expires_at,omitempty"`
PasswordMustChange   bool       `json:"password_must_change"`
PasswordMetadata     map[string]any `json:"password_metadata,omitempty"`
```

- [ ] **Step 3: Create model/credential_token.go**

```go
// model/credential_token.go
package model

import "time"

type CredentialTokenPurpose string

const (
	CredentialTokenPurposeSetup CredentialTokenPurpose = "setup"
	CredentialTokenPurposeReset CredentialTokenPurpose = "reset"
)

type CredentialToken struct {
	ID             string                 `json:"id"`
	CollaboratorID string                 `json:"collaborator_id"`
	Purpose        CredentialTokenPurpose `json:"purpose"`
	ExpiresAt      time.Time              `json:"expires_at"`
	ConsumedAt     *time.Time             `json:"consumed_at,omitempty"`
	CreatedBy      *string                `json:"created_by,omitempty"`
	CreatedAt      time.Time              `json:"created_at"`
}
```

- [ ] **Step 4: Create model/auth_identity_password.go**

```go
// model/auth_identity_password.go
package model

type IssueSetupTokenRequest struct {
	CollaboratorID   string `json:"collaborator_id"`
	ExpiresInSeconds int    `json:"expires_in_seconds,omitempty"`
}

type IssueSetupTokenResponse struct {
	TokenID   string `json:"token_id"`
	SetupURL  string `json:"setup_url"`
	ExpiresAt string `json:"expires_at"`
}

type SetupProfile struct {
	DisplayName  *string        `json:"display_name,omitempty"`
	Timezone     *string        `json:"timezone,omitempty"`
	PersonalData map[string]any `json:"personal_data,omitempty"`
}

type PasswordSetupRequest struct {
	Token       string        `json:"token"`
	NewPassword string        `json:"new_password"`
	Profile     *SetupProfile `json:"profile,omitempty"`
}

type PasswordChangeRequest struct {
	CurrentPassword     string         `json:"current_password"`
	NewPassword         string         `json:"new_password"`
	TOTPCode            string         `json:"totp_code,omitempty"`
	RecoveryCode        string         `json:"recovery_code,omitempty"`
	WebAuthnAssertion   map[string]any `json:"webauthn_assertion,omitempty"`
}

type PasswordForgotRequest struct {
	Identifier string `json:"identifier"`
}

type PasswordResetRequest struct {
	Token             string         `json:"token"`
	NewPassword       string         `json:"new_password"`
	TOTPCode          string         `json:"totp_code,omitempty"`
	RecoveryCode      string         `json:"recovery_code,omitempty"`
	WebAuthnAssertion map[string]any `json:"webauthn_assertion,omitempty"`
}
```

- [ ] **Step 5: Build**

```bash
go build ./...
```

- [ ] **Step 6: Commit**

```bash
git add model/
git commit -m "feat(model): credential DTOs + AuthIdentity password fields"
```

---

## Phase 5: Repository

### Task 5.1: repository/credentials.go (password CRUD on auth_identities)

**Files:**
- Create: `repository/credentials.go`
- Test: `repository/credentials_test.go`

- [ ] **Step 1: Failing integration test**

```go
// repository/credentials_test.go
package repository

import (
	"context"
	"database/sql"
	"os"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/auth/password"
	"github.com/google/uuid"
	_ "github.com/lib/pq"
)

func dbForCredentialsTest(t *testing.T) *sql.DB {
	t.Helper()
	dsn := os.Getenv("DB_URL")
	if dsn == "" {
		t.Skip("DB_URL not set; skipping credentials integration test")
	}
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	return db
}

func seedCredCollaborator(t *testing.T, db *sql.DB, suffix string) uuid.UUID {
	t.Helper()
	row := db.QueryRow(`
        INSERT INTO collaborators (slug, display_name, primary_email, status)
        VALUES ($1, $1, $1 || '@cred-test.dakasa.co', 'active')
        RETURNING id
    `, "cred-test-"+suffix)
	var id uuid.UUID
	if err := row.Scan(&id); err != nil {
		t.Fatalf("seed collaborator: %v", err)
	}
	_, err := db.Exec(`
        INSERT INTO auth_identities (collaborator_id, username)
        VALUES ($1, $2)
    `, id, "cred-test-"+suffix)
	if err != nil {
		t.Fatalf("seed identity: %v", err)
	}
	return id
}

func cleanCredFixtures(t *testing.T, db *sql.DB) {
	t.Helper()
	_, _ = db.Exec(`DELETE FROM auth_credential_tokens WHERE collaborator_id IN (SELECT id FROM collaborators WHERE slug LIKE 'cred-test-%')`)
	_, _ = db.Exec(`DELETE FROM auth_identities WHERE collaborator_id IN (SELECT id FROM collaborators WHERE slug LIKE 'cred-test-%')`)
	_, _ = db.Exec(`DELETE FROM collaborators WHERE slug LIKE 'cred-test-%'`)
}

func TestSetPasswordHashRoundTrip(t *testing.T) {
	db := dbForCredentialsTest(t)
	defer db.Close()
	cleanCredFixtures(t, db)
	defer cleanCredFixtures(t, db)

	id := seedCredCollaborator(t, db, "alice")
	exp := time.Now().Add(90 * 24 * time.Hour)
	scheme, hash, _ := password.Hash("test-correct-horse-1!")
	if err := SetPasswordHash(context.Background(), db, id, hash, string(scheme), exp); err != nil {
		t.Fatalf("set: %v", err)
	}

	got, err := GetPasswordCredentialState(context.Background(), db, id)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.PasswordHash == nil || *got.PasswordHash != hash {
		t.Fatalf("hash mismatch")
	}
	if got.PasswordMustChange {
		t.Fatalf("expected must_change=false after fresh set")
	}
}
```

- [ ] **Step 2: Run (expect fail)**

```bash
DB_URL="postgres://localhost:5432/ygg_test?sslmode=disable" go test ./repository/... -run TestSetPasswordHashRoundTrip -v
```

- [ ] **Step 3: Implement repository/credentials.go**

```go
// repository/credentials.go
package repository

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

var ErrPasswordCredentialNotFound = errors.New("password credential not found")

// SetPasswordHash updates the auth_identities row with a fresh password.
// password_must_change is reset to false; password_updated_at = NOW().
func SetPasswordHash(ctx context.Context, db DBExecer, collaboratorID uuid.UUID, hash, scheme string, expiresAt time.Time) error {
	res, err := db.ExecContext(ctx, `
        UPDATE auth_identities
        SET password_hash = $2,
            password_scheme = $3,
            password_updated_at = NOW(),
            password_expires_at = $4,
            password_must_change = false
        WHERE collaborator_id = $1
    `, collaboratorID, hash, scheme, expiresAt)
	if err != nil {
		return fmt.Errorf("set password: %w", err)
	}
	rows, _ := res.RowsAffected()
	if rows == 0 {
		return ErrPasswordCredentialNotFound
	}
	return nil
}

// GetPasswordCredentialState returns the password-related fields.
// Returns ErrPasswordCredentialNotFound if no auth_identities row.
func GetPasswordCredentialState(ctx context.Context, db DBQuerier, collaboratorID uuid.UUID) (model.AuthIdentity, error) {
	var ai model.AuthIdentity
	row := db.QueryRowContext(ctx, `
        SELECT collaborator_id, username,
               password_hash, password_scheme, password_updated_at, password_expires_at, password_must_change, password_metadata
        FROM auth_identities
        WHERE collaborator_id = $1
    `, collaboratorID)
	var hash, scheme sql.NullString
	var updatedAt, expiresAt sql.NullTime
	if err := row.Scan(&ai.CollaboratorID, &ai.Username, &hash, &scheme, &updatedAt, &expiresAt, &ai.PasswordMustChange, /* metadata scanner */ new(sql.NullString)); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ai, ErrPasswordCredentialNotFound
		}
		return ai, fmt.Errorf("scan: %w", err)
	}
	if hash.Valid {
		ai.PasswordHash = &hash.String
	}
	if scheme.Valid {
		ai.PasswordScheme = &scheme.String
	}
	if updatedAt.Valid {
		ai.PasswordUpdatedAt = &updatedAt.Time
	}
	if expiresAt.Valid {
		ai.PasswordExpiresAt = &expiresAt.Time
	}
	return ai, nil
}

// VerifyPassword compares plaintext against the stored hash via the
// internal/auth/password dispatcher. Returns nil on match.
// Re-hashing upon legacy scheme detection is a caller concern.
func VerifyPassword(ctx context.Context, db DBQuerier, collaboratorID uuid.UUID, plaintext string) error {
	ai, err := GetPasswordCredentialState(ctx, db, collaboratorID)
	if err != nil {
		return err
	}
	if ai.PasswordHash == nil || ai.PasswordScheme == nil {
		return ErrPasswordCredentialNotFound
	}
	// Hand the verify to the password package via a small bridge to avoid cyclic imports.
	return verifyPasswordBridge(*ai.PasswordScheme, *ai.PasswordHash, plaintext)
}

// verifyPasswordBridge is set by package init from a non-circular wiring file.
var verifyPasswordBridge = func(scheme, encoded, plaintext string) error {
	return errors.New("verifyPasswordBridge not wired")
}

// DBExecer / DBQuerier interfaces allow callers to pass *sql.DB or *sql.Tx.
type DBExecer interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}
type DBQuerier interface {
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

// RevokeAllOtherSessions marks every active session for the collaborator
// as revoked, except the one matching exceptSessionID. Returns count affected.
func RevokeAllOtherSessions(ctx context.Context, db DBExecer, collaboratorID, exceptSessionID uuid.UUID) (int64, error) {
	res, err := db.ExecContext(ctx, `
        UPDATE auth_sessions
        SET status = 'revoked', revoked_at = NOW()
        WHERE collaborator_id = $1
          AND id <> $2
          AND revoked_at IS NULL
    `, collaboratorID, exceptSessionID)
	if err != nil {
		return 0, fmt.Errorf("revoke sessions: %w", err)
	}
	n, _ := res.RowsAffected()
	return n, nil
}
```

- [ ] **Step 4: Wire verify bridge (no cyclic deps)**

Create `repository/wiring.go`:

```go
// repository/wiring.go
package repository

import "github.com/dakasa-yggdrasil/yggdrasil-core/internal/auth/password"

func init() {
	verifyPasswordBridge = func(scheme, encoded, plaintext string) error {
		return password.Verify(password.Scheme(scheme), encoded, plaintext)
	}
}
```

- [ ] **Step 5: Run test**

```bash
DB_URL="postgres://localhost:5432/ygg_test?sslmode=disable" go test ./repository/... -run TestSetPasswordHashRoundTrip -v
```

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add repository/credentials.go repository/credentials_test.go repository/wiring.go
git commit -m "feat(repository): credentials CRUD (set/get/verify/revoke-sessions)"
```

---

### Task 5.2: repository/credential_tokens.go (single-use tokens)

**Files:**
- Create: `repository/credential_tokens.go`
- Test: `repository/credential_tokens_test.go`

- [ ] **Step 1: Failing test**

```go
// repository/credential_tokens_test.go
package repository

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/auth/password"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
	_ "github.com/lib/pq"
)

func TestCredentialTokenLifecycle(t *testing.T) {
	db := dbForCredentialsTest(t)
	defer db.Close()
	cleanCredFixtures(t, db)
	defer cleanCredFixtures(t, db)

	collabID := seedCredCollaborator(t, db, "bob")
	ctx := context.Background()
	expires := time.Now().Add(48 * time.Hour)

	// Issue
	tk, _ := password.GenerateToken()
	issued, err := IssueCredentialToken(ctx, db, IssueCredentialTokenInput{
		CollaboratorID: collabID, Purpose: model.CredentialTokenPurposeSetup,
		TokenHash: tk.Hash, ExpiresAt: expires, CreatedBy: nil,
	})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if issued.ConsumedAt != nil {
		t.Fatalf("fresh token cannot be consumed")
	}

	// Consume - succeeds first time
	out, err := ConsumeCredentialToken(ctx, db, ConsumeCredentialTokenInput{
		TokenHash: tk.Hash, Purpose: model.CredentialTokenPurposeSetup,
	})
	if err != nil {
		t.Fatalf("consume: %v", err)
	}
	if out.CollaboratorID != collabID.String() {
		t.Fatalf("collaborator mismatch")
	}

	// Second consume - errors
	_, err = ConsumeCredentialToken(ctx, db, ConsumeCredentialTokenInput{
		TokenHash: tk.Hash, Purpose: model.CredentialTokenPurposeSetup,
	})
	if !errors.Is(err, ErrCredentialTokenInvalid) {
		t.Fatalf("expected ErrCredentialTokenInvalid, got %v", err)
	}

	// Issue another, invalidate prior actives, ensure single-active
	tk2, _ := password.GenerateToken()
	_, err = IssueCredentialToken(ctx, db, IssueCredentialTokenInput{
		CollaboratorID: collabID, Purpose: model.CredentialTokenPurposeSetup,
		TokenHash: tk2.Hash, ExpiresAt: expires, InvalidatePrior: true,
	})
	if err != nil {
		t.Fatalf("issue 2: %v", err)
	}
	var activeCount int
	if err := db.QueryRow(`SELECT COUNT(*) FROM auth_credential_tokens WHERE collaborator_id=$1 AND purpose='setup' AND consumed_at IS NULL`, collabID).Scan(&activeCount); err != nil {
		t.Fatalf("count: %v", err)
	}
	if activeCount != 1 {
		t.Fatalf("expected 1 active setup token, got %d", activeCount)
	}
	_ = sql.ErrNoRows
}
```

- [ ] **Step 2: Run (expect fail)**

```bash
DB_URL="postgres://localhost:5432/ygg_test?sslmode=disable" go test ./repository/... -run TestCredentialTokenLifecycle -v
```

- [ ] **Step 3: Implement repository/credential_tokens.go**

```go
// repository/credential_tokens.go
package repository

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

var ErrCredentialTokenInvalid = errors.New("credential token invalid")

type IssueCredentialTokenInput struct {
	CollaboratorID  uuid.UUID
	Purpose         model.CredentialTokenPurpose
	TokenHash       string
	ExpiresAt       time.Time
	CreatedBy       *uuid.UUID
	Metadata        map[string]any
	InvalidatePrior bool
}

type ConsumeCredentialTokenInput struct {
	TokenHash string
	Purpose   model.CredentialTokenPurpose
}

func IssueCredentialToken(ctx context.Context, db *sql.DB, in IssueCredentialTokenInput) (model.CredentialToken, error) {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return model.CredentialToken{}, fmt.Errorf("begin: %w", err)
	}
	defer tx.Rollback()

	if in.InvalidatePrior {
		if _, err := tx.ExecContext(ctx, `
            UPDATE auth_credential_tokens
            SET consumed_at = NOW()
            WHERE collaborator_id = $1 AND purpose = $2 AND consumed_at IS NULL
        `, in.CollaboratorID, in.Purpose); err != nil {
			return model.CredentialToken{}, fmt.Errorf("invalidate prior: %w", err)
		}
	}

	var t model.CredentialToken
	var createdBy sql.NullString
	if in.CreatedBy != nil {
		createdBy = sql.NullString{String: in.CreatedBy.String(), Valid: true}
	}
	var metaJSON []byte
	if in.Metadata != nil {
		var err error
		metaJSON, err = marshalJSON(in.Metadata)
		if err != nil {
			return t, err
		}
	} else {
		metaJSON = []byte("{}")
	}
	row := tx.QueryRowContext(ctx, `
        INSERT INTO auth_credential_tokens (collaborator_id, purpose, token_hash, expires_at, created_by, metadata)
        VALUES ($1, $2, $3, $4, $5, $6)
        RETURNING id, created_at
    `, in.CollaboratorID, in.Purpose, in.TokenHash, in.ExpiresAt, createdBy, metaJSON)
	if err := row.Scan(&t.ID, &t.CreatedAt); err != nil {
		return t, fmt.Errorf("insert token: %w", err)
	}
	t.CollaboratorID = in.CollaboratorID.String()
	t.Purpose = in.Purpose
	t.ExpiresAt = in.ExpiresAt
	if in.CreatedBy != nil {
		cb := in.CreatedBy.String()
		t.CreatedBy = &cb
	}
	if err := tx.Commit(); err != nil {
		return t, fmt.Errorf("commit: %w", err)
	}
	return t, nil
}

// ConsumeCredentialToken atomically consumes the active matching token.
// Returns ErrCredentialTokenInvalid if no row matches OR row is already consumed/expired/wrong-purpose.
func ConsumeCredentialToken(ctx context.Context, db *sql.DB, in ConsumeCredentialTokenInput) (model.CredentialToken, error) {
	var t model.CredentialToken
	var createdBy sql.NullString
	row := db.QueryRowContext(ctx, `
        UPDATE auth_credential_tokens
        SET consumed_at = NOW()
        WHERE token_hash = $1
          AND purpose = $2
          AND consumed_at IS NULL
          AND expires_at > NOW()
        RETURNING id, collaborator_id, purpose, expires_at, consumed_at, created_by, created_at
    `, in.TokenHash, in.Purpose)
	var consumedAt sql.NullTime
	if err := row.Scan(&t.ID, &t.CollaboratorID, &t.Purpose, &t.ExpiresAt, &consumedAt, &createdBy, &t.CreatedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return t, ErrCredentialTokenInvalid
		}
		return t, fmt.Errorf("consume token: %w", err)
	}
	if consumedAt.Valid {
		ct := consumedAt.Time
		t.ConsumedAt = &ct
	}
	if createdBy.Valid {
		s := createdBy.String
		t.CreatedBy = &s
	}
	return t, nil
}

// marshalJSON is a helper; if the codebase already has a marshaller utility, replace.
func marshalJSON(v any) ([]byte, error) {
	b, err := jsonMarshal(v)
	if err != nil {
		return nil, fmt.Errorf("marshal: %w", err)
	}
	return b, nil
}
```

Add the import for `jsonMarshal`. Since the codebase likely has `encoding/json` directly, just inline:

```go
// at top of credential_tokens.go change marshalJSON body to:
import "encoding/json"
// ...
func marshalJSON(v any) ([]byte, error) { return json.Marshal(v) }
```

- [ ] **Step 4: Run test**

```bash
DB_URL="postgres://localhost:5432/ygg_test?sslmode=disable" go test ./repository/... -run TestCredentialTokenLifecycle -v
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add repository/credential_tokens.go repository/credential_tokens_test.go
git commit -m "feat(repository): single-use credential tokens (setup/reset)"
```

---

### Task 5.3: Refactor repository/auth.go to use auth_identities for password

**Files:**
- Modify: `repository/auth.go` (2 sites at lines ~65 and ~363 that read from `collaborator_password_credentials`)

- [ ] **Step 1: Locate the two queries**

```bash
grep -n "collaborator_password_credentials" /Users/dakasa/projects/yggdrasil/yggdrasil-core/repository/auth.go
```

- [ ] **Step 2: Read the surrounding 30 lines of each occurrence and rewrite the query**

Both queries currently `SELECT/INSERT/UPDATE` columns `password_hash, password_scheme, password_updated_at, metadata` from `public.collaborator_password_credentials`. After this change:

Query at ~line 65 (within `UpsertPasswordCredential`-style flow): point to `auth_identities`. SELECT/INSERT becomes UPDATE on auth_identities (rows already exist after migration 00027 backfill).

```go
// Replace the INSERT-into-collaborator_password_credentials block with:
_, err = tx.ExecContext(ctx, `
    UPDATE auth_identities
    SET password_hash = $2,
        password_scheme = $3,
        password_updated_at = NOW(),
        password_metadata = COALESCE($4, password_metadata),
        password_must_change = false
    WHERE collaborator_id = $1
`, collaboratorID, passwordHash, passwordScheme, metadataJSON)
```

Query at ~line 363 (within `VerifyPasswordCredential`-style flow):

```go
// Replace SELECT from collaborator_password_credentials with:
row := db.QueryRowContext(ctx, `
    SELECT password_hash, password_scheme
    FROM auth_identities
    WHERE collaborator_id = $1 AND password_hash IS NOT NULL
`, collaboratorID)
```

- [ ] **Step 3: Build + run existing tests**

```bash
go build ./...
DB_URL="postgres://localhost:5432/ygg_test?sslmode=disable" go test ./repository/... -run "TestUpsertPasswordCredential|TestVerifyPasswordCredential|TestUpsertAndGetAuthIdentity" -v
```

Expected: previously-passing tests still pass.

- [ ] **Step 4: Commit**

```bash
git add repository/auth.go
git commit -m "refactor(repository): move password CRUD from cpc table to auth_identities"
```

---

## Phase 6: HTTP middleware + login extension

### Task 6.1: Credentials middleware

**Files:**
- Create: `controllers/httpapi/middleware_credentials.go`
- Test: `controllers/httpapi/middleware_credentials_test.go`

- [ ] **Step 1: Failing test (using httptest)**

```go
// controllers/httpapi/middleware_credentials_test.go
package httpapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

func TestRequirePasswordValid_BlocksRotationExpired(t *testing.T) {
	server := newTestServer(t) // existing helper (verify; see controllers/httpapi/auth_test.go)
	t.Cleanup(server.Close)

	collab, session := server.SeedCollabWithSession(t)
	server.SetPasswordExpiresAt(t, collab.ID, time.Now().Add(-1*time.Hour))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/manifests", nil)
	req.Header.Set("Authorization", "Bearer "+session.Token)
	rec := httptest.NewRecorder()
	server.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d body=%s", rec.Code, rec.Body.String())
	}
	var body map[string]any
	_ = json.NewDecoder(strings.NewReader(rec.Body.String())).Decode(&body)
	if body["code"] != "password_change_required" {
		t.Fatalf("expected code password_change_required, got %v", body["code"])
	}
	if body["change_url"] != "/api/v1/auth/passwords/change" {
		t.Fatalf("expected change_url, got %v", body["change_url"])
	}
}

func TestRequirePasswordValid_BlocksMFAEnrollmentMissing(t *testing.T) {
	server := newTestServer(t)
	t.Cleanup(server.Close)
	_, session := server.SeedCollabWithSessionMFANotEnrolled(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/manifests", nil)
	req.Header.Set("Authorization", "Bearer "+session.Token)
	rec := httptest.NewRecorder()
	server.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", rec.Code)
	}
	var body map[string]any
	_ = json.NewDecoder(strings.NewReader(rec.Body.String())).Decode(&body)
	if body["code"] != "mfa_enrollment_required" {
		t.Fatalf("expected code mfa_enrollment_required, got %v", body["code"])
	}
	_ = model.AuthSession{}
}
```

> Note: `newTestServer`, `SeedCollabWithSession`, `SetPasswordExpiresAt`, `SeedCollabWithSessionMFANotEnrolled` may need to be added or extracted from existing test helpers. Check `controllers/httpapi/auth_test.go` for `newTestServer` (or similar) and extend with the missing helpers before running.

- [ ] **Step 2: Run (expect fail)**

```bash
DB_URL="postgres://localhost:5432/ygg_test?sslmode=disable" go test ./controllers/httpapi/... -run TestRequirePasswordValid -v
```

- [ ] **Step 3: Implement middleware**

```go
// controllers/httpapi/middleware_credentials.go
package httpapi

import (
	"net/http"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
)

// requirePasswordValid is a middleware that blocks authenticated requests
// when MFA is not enrolled OR when the password is past its expiry / has been
// marked must_change. Bypassed for explicit allowlist of endpoints.
func (s *Server) requirePasswordValid(allowlist []string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		for _, p := range allowlist {
			if r.URL.Path == p {
				next(w, r)
				return
			}
		}
		token, ok := extractAuthToken(r)
		if !ok {
			writeJSON(w, http.StatusUnauthorized, map[string]any{"code": "unauthenticated"})
			return
		}
		_, collaborator, err := repository.ResolveAuthSession(r.Context(), s.db, token)
		if err != nil {
			writeJSON(w, http.StatusUnauthorized, map[string]any{"code": "unauthenticated"})
			return
		}
		identity, err := repository.GetPasswordCredentialState(r.Context(), s.db, collaborator.ID)
		if err != nil && err != repository.ErrPasswordCredentialNotFound {
			writeMappedError(w, err)
			return
		}
		// MFA enrollment check first (most-restrictive)
		if collaborator.MFAEnrolledAt == nil {
			writeJSON(w, http.StatusForbidden, map[string]any{
				"code":       "mfa_enrollment_required",
				"enroll_url": "/api/v1/auth/mfa/enroll",
			})
			return
		}
		if identity.PasswordMustChange ||
			(identity.PasswordExpiresAt != nil && identity.PasswordExpiresAt.Before(time.Now())) {
			reason := "rotation_expired"
			if identity.PasswordMustChange && (identity.PasswordExpiresAt == nil || !identity.PasswordExpiresAt.Before(time.Now())) {
				reason = "admin_forced"
			}
			writeJSON(w, http.StatusForbidden, map[string]any{
				"code":       "password_change_required",
				"change_url": "/api/v1/auth/passwords/change",
				"reason":     reason,
			})
			return
		}
		next(w, r)
	}
}
```

- [ ] **Step 4: Run tests**

```bash
DB_URL="postgres://localhost:5432/ygg_test?sslmode=disable" go test ./controllers/httpapi/... -run TestRequirePasswordValid -v
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add controllers/httpapi/middleware_credentials.go controllers/httpapi/middleware_credentials_test.go
git commit -m "feat(httpapi): middleware blocks expired/unenrolled credentials"
```

---

### Task 6.2: Extend login response with flags

**Files:**
- Modify: `controllers/httpapi/auth.go` (around `authLoginResponse` struct at top, and `handleAuthLogin`)

- [ ] **Step 1: Extend the response struct**

```go
type authLoginResponse struct {
    Collaborator             model.Collaborator `json:"collaborator"`
    Session                  model.AuthSession  `json:"session"`
    Token                    string             `json:"token"`
    PasswordChangeRequired   bool               `json:"password_change_required"`
    PasswordChangeURL        string             `json:"password_change_url,omitempty"`
    MFAEnrollmentRequired    bool               `json:"mfa_enrollment_required"`
    MFAEnrollURL             string             `json:"mfa_enroll_url,omitempty"`
}
```

- [ ] **Step 2: Populate flags at write time inside handleAuthLogin**

Where `authLoginResponse{...}` is constructed in the success path, query `repository.GetPasswordCredentialState` and the collaborator's `mfa_enrolled_at`, then set:

```go
needsPwdChange := identity.PasswordMustChange ||
    (identity.PasswordExpiresAt != nil && identity.PasswordExpiresAt.Before(time.Now()))
needsMFA := collaborator.MFAEnrolledAt == nil

resp := authLoginResponse{
    Collaborator:           collaborator,
    Session:                session,
    Token:                  token,
    PasswordChangeRequired: needsPwdChange,
    PasswordChangeURL:      "/api/v1/auth/passwords/change",
    MFAEnrollmentRequired:  needsMFA,
    MFAEnrollURL:           "/api/v1/auth/mfa/enroll",
}
```

If `needsPwdChange` is false, leave `PasswordChangeURL` empty (`omitempty` will hide it). Same for MFA.

- [ ] **Step 3: Test — extend existing TestHandleAuthLogin to assert flags**

Find the existing login test (`auth_test.go`) and add an assertion case for an expired-password collaborator returning `password_change_required: true` in response body.

- [ ] **Step 4: Run + commit**

```bash
DB_URL="..." go test ./controllers/httpapi/... -run TestHandleAuthLogin -v
git add controllers/httpapi/auth.go controllers/httpapi/auth_test.go
git commit -m "feat(httpapi): login response carries password/mfa flags"
```

---

## Phase 7: HTTP endpoints (5 handlers)

### Task 7.1: POST /api/v1/auth/passwords/setup-tokens

**Files:**
- Create: `controllers/httpapi/credentials.go` (start with the setup-tokens handler; subsequent tasks append to this file)
- Test: `controllers/httpapi/credentials_test.go` (start, append per task)

- [ ] **Step 1: Failing E2E test**

```go
// controllers/httpapi/credentials_test.go (initial)
package httpapi

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestIssueSetupToken_AdminAuthorized(t *testing.T) {
	server := newTestServer(t)
	t.Cleanup(server.Close)

	admin, adminSession := server.SeedAdminWithSession(t)
	target := server.SeedCollab(t, "newhire")

	body, _ := json.Marshal(map[string]any{"collaborator_id": target.ID.String()})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/passwords/setup-tokens", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+adminSession.Token)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	server.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d body=%s", rec.Code, rec.Body.String())
	}
	var resp struct {
		TokenID   string `json:"token_id"`
		SetupURL  string `json:"setup_url"`
		ExpiresAt string `json:"expires_at"`
	}
	_ = json.NewDecoder(rec.Body).Decode(&resp)
	if resp.SetupURL == "" || resp.TokenID == "" {
		t.Fatalf("missing fields in response: %+v", resp)
	}
	_ = admin
}
```

- [ ] **Step 2: Implement the handler**

```go
// controllers/httpapi/credentials.go (initial)
package httpapi

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/auth/password"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	"github.com/google/uuid"
)

// handleIssueSetupToken — POST /api/v1/auth/passwords/setup-tokens
func (s *Server) handleIssueSetupToken(w http.ResponseWriter, r *http.Request) {
	tokenStr, ok := extractAuthToken(r)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"code": "unauthenticated"})
		return
	}
	_, admin, err := repository.ResolveAuthSession(r.Context(), s.db, tokenStr)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"code": "unauthenticated"})
		return
	}
	if err := requirePermission(r.Context(), s.db, admin.ID, "iam.collaborators.invite"); err != nil {
		writeJSON(w, http.StatusForbidden, map[string]any{"code": "forbidden"})
		return
	}

	var req model.IssueSetupTokenRequest
	if err := decodeJSON(r, &req); err != nil {
		writeMappedError(w, err)
		return
	}
	collabID, err := uuid.Parse(req.CollaboratorID)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"code": "invalid_collaborator_id"})
		return
	}
	ttl := time.Duration(req.ExpiresInSeconds) * time.Second
	if ttl <= 0 {
		ttl = envDuration("AUTH_PASSWORD_SETUP_TOKEN_TTL", 48*time.Hour)
	}
	gen, err := password.GenerateToken()
	if err != nil {
		writeMappedError(w, err)
		return
	}
	issued, err := repository.IssueCredentialToken(r.Context(), s.db, repository.IssueCredentialTokenInput{
		CollaboratorID:  collabID,
		Purpose:         model.CredentialTokenPurposeSetup,
		TokenHash:       gen.Hash,
		ExpiresAt:       time.Now().Add(ttl),
		CreatedBy:       &admin.ID,
		InvalidatePrior: true,
	})
	if err != nil {
		writeMappedError(w, err)
		return
	}

	// Emit event (same connection, dedicated tx)
	if err := emitCredentialEvent(r.Context(), s.db, repository.EventTypeCredentialSetupTokenIssued, "collaborator", collabID.String(), &admin.ID, map[string]any{
		"token_id":        issued.ID,
		"collaborator_id": collabID.String(),
		"expires_at":      issued.ExpiresAt,
		"issued_by_id":    admin.ID.String(),
		"purpose":         "setup",
	}); err != nil {
		// log only; token already persisted
		s.logger.Error("emit credential.setup_token_issued", "err", err)
	}

	setupURL := buildSetupURL(os.Getenv("YGGDRASIL_PUBLIC_BASE_URL"), gen.Raw)
	writeJSON(w, http.StatusCreated, model.IssueSetupTokenResponse{
		TokenID:   issued.ID,
		SetupURL:  setupURL,
		ExpiresAt: issued.ExpiresAt.UTC().Format(time.RFC3339),
	})
}

func buildSetupURL(base, raw string) string {
	base = strings.TrimRight(strings.TrimSpace(base), "/")
	if base == "" {
		base = "/"
	}
	return fmt.Sprintf("%s/setup?token=%s", base, raw)
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

// emitCredentialEvent wraps repository.EmitEvent inside a fresh tx.
func emitCredentialEvent(ctx context.Context, db *sql.DB, evtType, aggType, aggID string, actorID *uuid.UUID, payload map[string]any) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	req := model.EmitEventRequest{
		Type: evtType, SchemaVersion: "v1",
		AggregateType: aggType, AggregateID: aggID, Payload: payload,
	}
	if actorID != nil {
		req.Actor = &model.EventActor{Type: "collaborator", ID: actorID.String()}
	}
	if _, err := repository.EmitEvent(ctx, tx, req); err != nil {
		return err
	}
	return tx.Commit()
}
```

Add imports `context`, `database/sql` to the file. Adjust if a helper like `s.emitEvent` already exists; reuse it.

- [ ] **Step 3: Register route in server.go**

```go
// in server.go, mux setup block:
mux.HandleFunc("POST /api/v1/auth/passwords/setup-tokens", server.handleIssueSetupToken)
```

- [ ] **Step 4: Run test**

```bash
DB_URL="..." go test ./controllers/httpapi/... -run TestIssueSetupToken -v
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add controllers/httpapi/credentials.go controllers/httpapi/credentials_test.go controllers/httpapi/server.go
git commit -m "feat(httpapi): POST /auth/passwords/setup-tokens (admin invite)"
```

---

### Task 7.2: POST /api/v1/auth/passwords/setup

**Files:**
- Modify: `controllers/httpapi/credentials.go` (append handler)
- Modify: `controllers/httpapi/credentials_test.go` (append test)

- [ ] **Step 1: Failing test**

```go
func TestSetup_RedeemsTokenAndOpensSession(t *testing.T) {
	server := newTestServer(t)
	t.Cleanup(server.Close)

	collab := server.SeedCollab(t, "newhire-setup")
	gen, _ := password.GenerateToken()
	_, _ = server.IssueRawToken(t, collab.ID, model.CredentialTokenPurposeSetup, gen.Hash, time.Now().Add(time.Hour))

	body, _ := json.Marshal(map[string]any{
		"token":        gen.Raw,
		"new_password": "Z9-Forest-River-Iceland",
		"profile": map[string]any{
			"display_name": "Maria Onboarded",
			"timezone":     "America/Sao_Paulo",
			"personal_data": map[string]any{"avatar_url": "https://x"},
		},
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/passwords/setup", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	server.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rec.Code, rec.Body.String())
	}
	var resp struct {
		MFAEnrollmentRequired bool `json:"mfa_enrollment_required"`
	}
	_ = json.NewDecoder(rec.Body).Decode(&resp)
	if !resp.MFAEnrollmentRequired {
		t.Fatalf("expected mfa_enrollment_required=true")
	}
}

func TestSetup_UnknownFieldsRejected(t *testing.T) {
	server := newTestServer(t)
	t.Cleanup(server.Close)
	collab := server.SeedCollab(t, "uk-setup")
	gen, _ := password.GenerateToken()
	_, _ = server.IssueRawToken(t, collab.ID, model.CredentialTokenPurposeSetup, gen.Hash, time.Now().Add(time.Hour))

	body, _ := json.Marshal(map[string]any{
		"token":        gen.Raw,
		"new_password": "Z9-Forest-River-Iceland",
		"profile":      map[string]any{"role": "admin"}, // not allowed
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/passwords/setup", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	server.Handler().ServeHTTP(rec, req)
	if rec.Code != 422 {
		t.Fatalf("expected 422 unknown_fields, got %d", rec.Code)
	}
}
```

- [ ] **Step 2: Implement handler (user contribution — orchestration, see spec §11)**

```go
// in controllers/httpapi/credentials.go (append)

// handleSetupCommit — POST /api/v1/auth/passwords/setup
func (s *Server) handleSetupCommit(w http.ResponseWriter, r *http.Request) {
	var req model.PasswordSetupRequest
	if err := decodeJSON(r, &req); err != nil {
		writeMappedError(w, err)
		return
	}

	// 1. Validate profile whitelist BEFORE any DB write
	if err := validateSetupProfile(req.Profile); err != nil {
		writeJSON(w, 422, map[string]any{"code": "setup_unknown_fields", "rejected": err.Error()})
		return
	}

	// 2. Validate password policy
	commonPasswords, _ := s.commonPasswords()
	if err := password.ValidateStrength(req.NewPassword, envInt("AUTH_PASSWORD_MIN_LENGTH", 12), commonPasswords, []string{}); err != nil {
		writeJSON(w, 422, map[string]any{"code": "password_too_weak", "reason": err.Error()})
		return
	}

	// 3. Atomic redemption + password set + profile update + session open
	tx, err := s.db.BeginTx(r.Context(), nil)
	if err != nil {
		writeMappedError(w, err)
		return
	}
	committed := false
	defer func() {
		if !committed {
			tx.Rollback()
		}
	}()

	tokenHash := password.HashToken(req.Token)
	row := tx.QueryRowContext(r.Context(), `
        UPDATE auth_credential_tokens
        SET consumed_at = NOW()
        WHERE token_hash = $1 AND purpose = 'setup' AND consumed_at IS NULL AND expires_at > NOW()
        RETURNING id, collaborator_id, expires_at
    `, tokenHash)
	var tokenID, collabID uuid.UUID
	var expiresAt time.Time
	if err := row.Scan(&tokenID, &collabID, &expiresAt); err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"code": "setup_token_invalid"})
		return
	}

	scheme, hash, err := password.Hash(req.NewPassword)
	if err != nil {
		writeMappedError(w, err)
		return
	}
	rotation := envDuration("AUTH_PASSWORD_ROTATION_PERIOD", 90*24*time.Hour)
	if _, err := tx.ExecContext(r.Context(), `
        UPDATE auth_identities
        SET password_hash=$2, password_scheme=$3, password_updated_at=NOW(), password_expires_at=NOW()+$4::interval, password_must_change=false
        WHERE collaborator_id=$1
    `, collabID, hash, string(scheme), rotation.String()); err != nil {
		writeMappedError(w, err)
		return
	}

	// Profile patch (whitelist already validated)
	if req.Profile != nil {
		args := []any{collabID}
		setParts := []string{}
		if req.Profile.DisplayName != nil {
			setParts = append(setParts, "display_name = $"+strconv.Itoa(len(args)+1))
			args = append(args, *req.Profile.DisplayName)
		}
		if req.Profile.Timezone != nil {
			setParts = append(setParts, "timezone = $"+strconv.Itoa(len(args)+1))
			args = append(args, *req.Profile.Timezone)
		}
		if req.Profile.PersonalData != nil {
			pd, _ := json.Marshal(req.Profile.PersonalData)
			setParts = append(setParts, "personal_data = personal_data || $"+strconv.Itoa(len(args)+1)+"::jsonb")
			args = append(args, string(pd))
		}
		if len(setParts) > 0 {
			q := "UPDATE collaborators SET " + strings.Join(setParts, ", ") + " WHERE id = $1"
			if _, err := tx.ExecContext(r.Context(), q, args...); err != nil {
				writeMappedError(w, err)
				return
			}
		}
	}

	// Open session for the collaborator. The codebase must already have a
	// repository.CreateAuthSession-or-similar; locate and reuse.
	session, sessionToken, err := repository.CreateAuthSessionTx(r.Context(), tx, collabID, sessionMetadataFromRequest(r))
	if err != nil {
		writeMappedError(w, err)
		return
	}

	// Emit event inside the same tx (best-effort; rollback rolls event back)
	_, _ = repository.EmitEvent(r.Context(), tx, model.EmitEventRequest{
		Type: repository.EventTypeCredentialPasswordSetupCompleted, SchemaVersion: "v1",
		AggregateType: "collaborator", AggregateID: collabID.String(),
		Actor: &model.EventActor{Type: "collaborator", ID: collabID.String()},
		Payload: map[string]any{
			"collaborator_id": collabID.String(),
			"token_id":        tokenID.String(),
			"source":          "setup",
			"ip":              r.RemoteAddr,
			"user_agent":      r.UserAgent(),
		},
	})

	if err := tx.Commit(); err != nil {
		writeMappedError(w, err)
		return
	}
	committed = true

	// Fetch the resulting collaborator to include in response
	collaborator, err := repository.GetCollaboratorByID(r.Context(), s.db, collabID)
	if err != nil {
		writeMappedError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"session":                 session,
		"token":                   sessionToken,
		"collaborator":            collaborator,
		"mfa_enrollment_required": collaborator.MFAEnrolledAt == nil,
		"mfa_enroll_url":          "/api/v1/auth/mfa/enroll",
	})
}

// validateSetupProfile rejects any keys outside the whitelist.
func validateSetupProfile(p *model.SetupProfile) error {
	// Since SetupProfile is a typed struct, the JSON decoder already drops
	// unknown fields silently unless DisallowUnknownFields is on. To enforce
	// strict rejection, the decoder used in decodeJSON must use DisallowUnknownFields.
	// If decodeJSON does NOT disallow unknown fields, do a second pass: decode
	// the request body into map[string]any and assert that "profile" only contains
	// keys ∈ {display_name, timezone, personal_data}.
	// (See decodeJSON helper for current behavior.)
	return nil // assumes decodeJSON is configured with DisallowUnknownFields
}
```

> **Note for the agent:** Verify `decodeJSON` enables `DisallowUnknownFields`. If not, this task must ALSO update `decodeJSON` to do so (decision: enable globally vs add a strict variant). If a strict variant is preferred, name it `decodeJSONStrict` and use it here.

- [ ] **Step 3: Register route**

```go
// in server.go:
mux.HandleFunc("POST /api/v1/auth/passwords/setup", server.handleSetupCommit)
```

- [ ] **Step 4: Run tests + commit**

```bash
DB_URL="..." go test ./controllers/httpapi/... -run "TestSetup_" -v
git add controllers/httpapi/credentials.go controllers/httpapi/credentials_test.go controllers/httpapi/server.go
git commit -m "feat(httpapi): POST /auth/passwords/setup (token redeem + profile + session)"
```

---

### Task 7.3: POST /api/v1/auth/passwords/change

**Files:**
- Modify: `controllers/httpapi/credentials.go` (append)
- Modify: `controllers/httpapi/credentials_test.go` (append)

- [ ] **Step 1: Failing test**

```go
func TestChange_HappyPath_RevokesOtherSessions(t *testing.T) {
	server := newTestServer(t)
	t.Cleanup(server.Close)
	collab, session1 := server.SeedCollabWithSessionAndPassword(t, "Z9-Forest-River-Iceland")
	_, session2 := server.OpenSecondSession(t, collab.ID)
	totp := server.EnrollTOTP(t, collab.ID)

	body, _ := json.Marshal(map[string]any{
		"current_password": "Z9-Forest-River-Iceland",
		"new_password":     "Q3-Forest-River-Iceland",
		"totp_code":        totp.Now(),
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/passwords/change", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+session1.Token)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	server.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rec.Code, rec.Body.String())
	}
	// session2 must be revoked
	if !server.IsSessionRevoked(t, session2.ID) {
		t.Fatalf("session2 should be revoked after password change")
	}
}

func TestChange_InvalidMFA_Rejected(t *testing.T) {
	server := newTestServer(t)
	t.Cleanup(server.Close)
	collab, session := server.SeedCollabWithSessionAndPassword(t, "Z9-Forest-River-Iceland")
	server.EnrollTOTP(t, collab.ID)

	body, _ := json.Marshal(map[string]any{
		"current_password": "Z9-Forest-River-Iceland",
		"new_password":     "Q3-Forest-River-Iceland",
		"totp_code":        "000000",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/passwords/change", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+session.Token)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	server.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 invalid_mfa, got %d", rec.Code)
	}
}
```

- [ ] **Step 2: Implement handler**

```go
// in controllers/httpapi/credentials.go (append)

// handlePasswordChange — POST /api/v1/auth/passwords/change
func (s *Server) handlePasswordChange(w http.ResponseWriter, r *http.Request) {
	tokenStr, ok := extractAuthToken(r)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"code": "unauthenticated"})
		return
	}
	session, collab, err := repository.ResolveAuthSession(r.Context(), s.db, tokenStr)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"code": "unauthenticated"})
		return
	}

	var req model.PasswordChangeRequest
	if err := decodeJSON(r, &req); err != nil {
		writeMappedError(w, err)
		return
	}

	// Verify current
	if err := repository.VerifyPassword(r.Context(), s.db, collab.ID, req.CurrentPassword); err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"code": "invalid_current_password"})
		return
	}

	// MFA gate (must be enrolled; supply a factor inline)
	if err := mfa.EnforceMFAEnrolled(r.Context(), s.db, collab.ID); err != nil {
		writeJSON(w, http.StatusPreconditionRequired, map[string]any{"code": "mfa_not_enrolled"})
		return
	}
	if err := verifyMFAInline(r.Context(), s.db, collab.ID, req.TOTPCode, req.RecoveryCode, req.WebAuthnAssertion); err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"code": "invalid_mfa"})
		return
	}

	// Policy
	commonPasswords, _ := s.commonPasswords()
	if err := password.ValidateStrength(req.NewPassword, envInt("AUTH_PASSWORD_MIN_LENGTH", 12), commonPasswords, []string{collab.PrimaryEmail, collab.Slug, collab.DisplayName}); err != nil {
		writeJSON(w, 422, map[string]any{"code": "password_too_weak", "reason": err.Error()})
		return
	}
	// new == current?
	if err := repository.VerifyPassword(r.Context(), s.db, collab.ID, req.NewPassword); err == nil {
		writeJSON(w, 422, map[string]any{"code": "password_unchanged"})
		return
	}

	scheme, hash, err := password.Hash(req.NewPassword)
	if err != nil {
		writeMappedError(w, err)
		return
	}
	rotation := envDuration("AUTH_PASSWORD_ROTATION_PERIOD", 90*24*time.Hour)
	tx, _ := s.db.BeginTx(r.Context(), nil)
	committed := false
	defer func() {
		if !committed {
			tx.Rollback()
		}
	}()
	if _, err := tx.ExecContext(r.Context(), `
        UPDATE auth_identities
        SET password_hash=$2, password_scheme=$3, password_updated_at=NOW(), password_expires_at=NOW()+$4::interval, password_must_change=false
        WHERE collaborator_id=$1
    `, collab.ID, hash, string(scheme), rotation.String()); err != nil {
		writeMappedError(w, err)
		return
	}
	if _, err := tx.ExecContext(r.Context(), `
        UPDATE auth_sessions
        SET status='revoked', revoked_at=NOW()
        WHERE collaborator_id=$1 AND id<>$2 AND revoked_at IS NULL
    `, collab.ID, session.ID); err != nil {
		writeMappedError(w, err)
		return
	}
	source := "voluntary"
	if r.Header.Get("X-Yggdrasil-Rotation-Triggered") == "true" {
		source = "rotation"
	}
	_, _ = repository.EmitEvent(r.Context(), tx, model.EmitEventRequest{
		Type: repository.EventTypeCredentialPasswordChanged, SchemaVersion: "v1",
		AggregateType: "collaborator", AggregateID: collab.ID.String(),
		Actor:   &model.EventActor{Type: "collaborator", ID: collab.ID.String()},
		Payload: map[string]any{"collaborator_id": collab.ID.String(), "source": source, "ip": r.RemoteAddr},
	})
	if err := tx.Commit(); err != nil {
		writeMappedError(w, err)
		return
	}
	committed = true

	state, _ := repository.GetPasswordCredentialState(r.Context(), s.db, collab.ID)
	writeJSON(w, http.StatusOK, map[string]any{
		"password_updated_at": state.PasswordUpdatedAt,
		"password_expires_at": state.PasswordExpiresAt,
	})
}
```

- [ ] **Step 3: Implement verifyMFAInline helper**

```go
// in controllers/httpapi/credentials.go
func verifyMFAInline(ctx context.Context, db *sql.DB, collaboratorID uuid.UUID, totp, recovery string, webauthn map[string]any) error {
	if totp != "" {
		return mfa.VerifyTOTP(ctx, db, collaboratorID, totp)
	}
	if recovery != "" {
		return mfa.ConsumeRecoveryCode(ctx, db, collaboratorID, recovery)
	}
	if webauthn != nil {
		return mfa.VerifyWebAuthnAssertion(ctx, db, collaboratorID, webauthn)
	}
	return mfa.ErrMFARequired
}
```

> Verify these functions exist in `internal/auth/mfa` or its callers. If signatures differ, adjust to the canonical ones (probably `mfa.VerifyTOTPCode(ctx, db, id, code)` — see existing `mfa.go` handlers).

- [ ] **Step 4: Register route + run + commit**

```bash
# in server.go, add: mux.HandleFunc("POST /api/v1/auth/passwords/change", server.handlePasswordChange)
DB_URL="..." go test ./controllers/httpapi/... -run "TestChange_" -v
git add controllers/httpapi/credentials.go controllers/httpapi/credentials_test.go controllers/httpapi/server.go
git commit -m "feat(httpapi): POST /auth/passwords/change (MFA inline + revoke other sessions)"
```

---

### Task 7.4: POST /api/v1/auth/passwords/forgot

**Files:**
- Modify: `controllers/httpapi/credentials.go` (append)
- Modify: `controllers/httpapi/credentials_test.go` (append)

- [ ] **Step 1: Failing tests**

```go
func TestForgot_AlwaysReturns202(t *testing.T) {
	server := newTestServer(t)
	t.Cleanup(server.Close)
	collab := server.SeedCollab(t, "forgot-known")

	for _, id := range []string{collab.PrimaryEmail, "nobody@nowhere.invalid", collab.Slug} {
		body, _ := json.Marshal(map[string]any{"identifier": id})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/passwords/forgot", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		server.Handler().ServeHTTP(rec, req)
		if rec.Code != http.StatusAccepted {
			t.Fatalf("identifier=%s expected 202, got %d", id, rec.Code)
		}
	}
	// known identifier MUST have created an active reset token
	var n int
	if err := server.DB().QueryRow(`SELECT COUNT(*) FROM auth_credential_tokens WHERE collaborator_id=$1 AND purpose='reset' AND consumed_at IS NULL`, collab.ID).Scan(&n); err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != 1 {
		t.Fatalf("expected 1 active reset token for known identifier, got %d", n)
	}
}
```

- [ ] **Step 2: Implement handler**

```go
// handlePasswordForgot — POST /api/v1/auth/passwords/forgot
func (s *Server) handlePasswordForgot(w http.ResponseWriter, r *http.Request) {
	const acceptedBody = `{"status":"if_account_exists_token_was_generated"}`
	var req model.PasswordForgotRequest
	if err := decodeJSON(r, &req); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(acceptedBody))
		return
	}

	identifier := strings.TrimSpace(req.Identifier)
	if identifier == "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(acceptedBody))
		return
	}

	collab, err := repository.LookupCollaboratorByIdentifier(r.Context(), s.db, identifier)
	if err != nil || collab == nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(acceptedBody))
		return
	}

	if err := enforceRateLimit(r.Context(), s.db, "forgot:"+identifier, envInt("AUTH_PASSWORD_FORGOT_RATE_LIMIT_PER_HOUR", 3), time.Hour); err != nil {
		// limit hit; emit nothing, return 202
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(acceptedBody))
		return
	}

	gen, _ := password.GenerateToken()
	ttl := envDuration("AUTH_PASSWORD_RESET_TOKEN_TTL", 24*time.Hour)
	issued, err := repository.IssueCredentialToken(r.Context(), s.db, repository.IssueCredentialTokenInput{
		CollaboratorID: collab.ID, Purpose: model.CredentialTokenPurposeReset,
		TokenHash: gen.Hash, ExpiresAt: time.Now().Add(ttl), InvalidatePrior: true,
	})
	if err == nil {
		_ = emitCredentialEvent(r.Context(), s.db, repository.EventTypeCredentialResetTokenIssued, "collaborator", collab.ID.String(), nil, map[string]any{
			"token_id":        issued.ID,
			"collaborator_id": collab.ID.String(),
			"expires_at":      issued.ExpiresAt,
			"source":          "self_service",
			"purpose":         "reset",
		})
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	_, _ = w.Write([]byte(acceptedBody))
}
```

`enforceRateLimit` and `repository.LookupCollaboratorByIdentifier`:

```go
// repository/lookup.go (create)
package repository

import (
	"context"
	"database/sql"
	"errors"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

// LookupCollaboratorByIdentifier returns the collaborator matching either
// primary_email (case-insensitive) or slug. Returns (nil, nil) if no match
// (to keep anti-enum callers branchless).
func LookupCollaboratorByIdentifier(ctx context.Context, db *sql.DB, identifier string) (*model.Collaborator, error) {
	row := db.QueryRowContext(ctx, `
        SELECT id, slug, display_name, primary_email, status, mfa_enrolled_at
        FROM collaborators
        WHERE LOWER(primary_email) = LOWER($1) OR slug = $1
        LIMIT 1
    `, identifier)
	var c model.Collaborator
	if err := row.Scan(&c.ID, &c.Slug, &c.DisplayName, &c.PrimaryEmail, &c.Status, &c.MFAEnrolledAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return &c, nil
}
```

`enforceRateLimit`: if a generic rate-limit utility exists in the codebase (check `internal/middleware/` or `internal/ratelimit/`), reuse it. Otherwise create the simplest possible in-process token-bucket keyed by `(identifier, window_start_hour)`:

```go
// controllers/httpapi/rate_limit.go (create only if no existing helper)
package httpapi

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

var ErrRateLimitExceeded = errors.New("rate limit exceeded")

// enforceRateLimit is a coarse, per-key, sliding window enforcement using
// auth_credential_tokens.created_at as the source of truth for the limit on
// reset issuance. This avoids adding a new table.
func enforceRateLimit(ctx context.Context, db *sql.DB, key string, maxPerWindow int, window time.Duration) error {
	var count int
	row := db.QueryRowContext(ctx, `
        SELECT COUNT(*) FROM auth_credential_tokens
        WHERE purpose = 'reset'
          AND created_at > NOW() - $1::interval
          AND metadata ->> 'rl_key' = $2
    `, window.String(), key)
	if err := row.Scan(&count); err != nil {
		return err
	}
	if count >= maxPerWindow {
		return ErrRateLimitExceeded
	}
	return nil
}
```

> If `enforceRateLimit` uses `metadata ->> 'rl_key'`, ensure `IssueCredentialToken` callers stamp `Metadata: { "rl_key": "forgot:<identifier>" }` for forgot-flow tokens.

- [ ] **Step 3: Register route + run + commit**

```bash
# server.go: mux.HandleFunc("POST /api/v1/auth/passwords/forgot", server.handlePasswordForgot)
DB_URL="..." go test ./controllers/httpapi/... -run "TestForgot_" -v
git add controllers/httpapi/credentials.go controllers/httpapi/credentials_test.go controllers/httpapi/rate_limit.go controllers/httpapi/server.go repository/lookup.go
git commit -m "feat(httpapi): POST /auth/passwords/forgot (anti-enum, rate-limited)"
```

---

### Task 7.5: POST /api/v1/auth/passwords/reset

**Files:**
- Modify: `controllers/httpapi/credentials.go` (append)
- Modify: `controllers/httpapi/credentials_test.go` (append)

- [ ] **Step 1: Failing test**

```go
func TestReset_RedeemsTokenAndOpensSession(t *testing.T) {
	server := newTestServer(t)
	t.Cleanup(server.Close)
	collab := server.SeedCollab(t, "reset-user")
	gen, _ := password.GenerateToken()
	_, _ = server.IssueRawToken(t, collab.ID, model.CredentialTokenPurposeReset, gen.Hash, time.Now().Add(time.Hour))
	totp := server.EnrollTOTP(t, collab.ID)

	body, _ := json.Marshal(map[string]any{
		"token": gen.Raw, "new_password": "F0rest-Iceland-2026!", "totp_code": totp.Now(),
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/passwords/reset", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	server.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestReset_NoMFAEnrolled_428(t *testing.T) {
	server := newTestServer(t)
	t.Cleanup(server.Close)
	collab := server.SeedCollab(t, "reset-nomfa")
	gen, _ := password.GenerateToken()
	_, _ = server.IssueRawToken(t, collab.ID, model.CredentialTokenPurposeReset, gen.Hash, time.Now().Add(time.Hour))

	body, _ := json.Marshal(map[string]any{"token": gen.Raw, "new_password": "F0rest-Iceland-2026!"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/passwords/reset", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	server.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusPreconditionRequired {
		t.Fatalf("expected 428, got %d", rec.Code)
	}
}
```

- [ ] **Step 2: Implement handler**

```go
// handlePasswordReset — POST /api/v1/auth/passwords/reset
func (s *Server) handlePasswordReset(w http.ResponseWriter, r *http.Request) {
	var req model.PasswordResetRequest
	if err := decodeJSON(r, &req); err != nil {
		writeMappedError(w, err)
		return
	}

	// Consume token
	tokenHash := password.HashToken(req.Token)
	out, err := repository.ConsumeCredentialToken(r.Context(), s.db, repository.ConsumeCredentialTokenInput{
		TokenHash: tokenHash, Purpose: model.CredentialTokenPurposeReset,
	})
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"code": "reset_token_invalid"})
		return
	}
	collabID := uuid.MustParse(out.CollaboratorID)

	// MFA gate
	if err := mfa.EnforceMFAEnrolled(r.Context(), s.db, collabID); err != nil {
		writeJSON(w, http.StatusPreconditionRequired, map[string]any{"code": "mfa_not_enrolled"})
		return
	}
	if err := verifyMFAInline(r.Context(), s.db, collabID, req.TOTPCode, req.RecoveryCode, req.WebAuthnAssertion); err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"code": "invalid_mfa"})
		return
	}

	collab, err := repository.GetCollaboratorByID(r.Context(), s.db, collabID)
	if err != nil {
		writeMappedError(w, err)
		return
	}
	commonPasswords, _ := s.commonPasswords()
	if err := password.ValidateStrength(req.NewPassword, envInt("AUTH_PASSWORD_MIN_LENGTH", 12), commonPasswords, []string{collab.PrimaryEmail, collab.Slug, collab.DisplayName}); err != nil {
		writeJSON(w, 422, map[string]any{"code": "password_too_weak", "reason": err.Error()})
		return
	}

	scheme, hash, _ := password.Hash(req.NewPassword)
	tx, _ := s.db.BeginTx(r.Context(), nil)
	committed := false
	defer func() {
		if !committed {
			tx.Rollback()
		}
	}()
	rotation := envDuration("AUTH_PASSWORD_ROTATION_PERIOD", 90*24*time.Hour)
	_, _ = tx.ExecContext(r.Context(), `
        UPDATE auth_identities
        SET password_hash=$2, password_scheme=$3, password_updated_at=NOW(), password_expires_at=NOW()+$4::interval, password_must_change=false
        WHERE collaborator_id=$1
    `, collabID, hash, string(scheme), rotation.String())
	_, _ = tx.ExecContext(r.Context(), `
        UPDATE auth_sessions SET status='revoked', revoked_at=NOW()
        WHERE collaborator_id=$1 AND revoked_at IS NULL
    `, collabID)
	session, sessionToken, err := repository.CreateAuthSessionTx(r.Context(), tx, collabID, sessionMetadataFromRequest(r))
	if err != nil {
		writeMappedError(w, err)
		return
	}
	_, _ = repository.EmitEvent(r.Context(), tx, model.EmitEventRequest{
		Type: repository.EventTypeCredentialPasswordChanged, SchemaVersion: "v1",
		AggregateType: "collaborator", AggregateID: collabID.String(),
		Actor:   &model.EventActor{Type: "collaborator", ID: collabID.String()},
		Payload: map[string]any{"collaborator_id": collabID.String(), "source": "reset", "ip": r.RemoteAddr},
	})
	if err := tx.Commit(); err != nil {
		writeMappedError(w, err)
		return
	}
	committed = true
	writeJSON(w, http.StatusOK, map[string]any{
		"session":      session,
		"token":        sessionToken,
		"collaborator": collab,
	})
}
```

- [ ] **Step 3: Register route + run + commit**

```bash
# server.go: mux.HandleFunc("POST /api/v1/auth/passwords/reset", server.handlePasswordReset)
DB_URL="..." go test ./controllers/httpapi/... -run "TestReset_" -v
git add controllers/httpapi/credentials.go controllers/httpapi/credentials_test.go controllers/httpapi/server.go
git commit -m "feat(httpapi): POST /auth/passwords/reset (token + MFA + new session)"
```

---

### Task 7.6: Apply middleware to authenticated routes

**Files:**
- Modify: `controllers/httpapi/server.go`

- [ ] **Step 1: Wrap authenticated route handlers**

Identify all `/api/v1/*` routes that today resolve a session (everything except `/auth/login`, `/auth/third-party/login`, `/auth/third-party/start/{provider}`, `/auth/third-party/callback/{provider}`, `/auth/passwords/forgot`, `/auth/passwords/setup`, `/auth/passwords/reset`, `/healthz`, `/readyz`, `/metrics`, `/api/v1/events` if internal).

Wrap them:

```go
authenticatedAllowlist := []string{
    "/api/v1/auth/passwords/change",
    "/api/v1/auth/logout",
    "/api/v1/auth/session",
    "/api/v1/auth/mfa/enroll/request",
    "/api/v1/auth/mfa/enroll/validate",
    "/api/v1/auth/mfa/factors/totp/begin",
    "/api/v1/auth/mfa/factors/totp/finish",
}

guard := func(h http.HandlerFunc) http.HandlerFunc {
    return server.requirePasswordValid(authenticatedAllowlist, h)
}

mux.HandleFunc("GET /api/v1/manifests",  guard(server.handleManifestListGeneric))
mux.HandleFunc("POST /api/v1/manifests", guard(server.handleManifestCreateGeneric))
// ... apply guard to all other authenticated routes that currently call ResolveAuthSession internally.
```

> Important: the `guard` wrapper duplicates the auth check the handler also does. For now, keep both; in a follow-up refactor, the handler can trust the guard. The test in Task 6.1 already verifies the guard path.

- [ ] **Step 2: Run a wide test to ensure no regression**

```bash
DB_URL="..." go test ./... -short
```

- [ ] **Step 3: Commit**

```bash
git add controllers/httpapi/server.go
git commit -m "feat(httpapi): apply credentials guard to authenticated routes"
```

---

## Phase 8: Rotation cron wiring

### Task 8.1: Start the rotation runner from main

**Files:**
- Modify: `main.go` (yggdrasil-core entrypoint — verify path: `cmd/yggdrasil-core/main.go` OR root `main.go`)

- [ ] **Step 1: Locate the main entrypoint**

```bash
grep -rln "func main()" /Users/dakasa/projects/yggdrasil/yggdrasil-core/ --include="*.go" | head -5
```

- [ ] **Step 2: Start the runner inside the existing service goroutine block**

```go
// near the other long-running services in main:
{
    runner := &password.Runner{
        DB:       db,
        Interval: envDurationOrDefault("AUTH_PASSWORD_ROTATION_CRON_INTERVAL", time.Hour),
        Batch:    1000,
        Logger:   logger,
        EmitMark: func(ctx context.Context, id uuid.UUID) error {
            return emitCredentialEvent(ctx, db, repository.EventTypeCredentialPasswordRotationRequired, "collaborator", id.String(), nil, map[string]any{
                "collaborator_id": id.String(),
                "marked_at":       time.Now().UTC().Format(time.RFC3339),
                "expires_at":      time.Now().UTC().Format(time.RFC3339), // best-effort; could re-read
            })
        },
    }
    go func() {
        if err := runner.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
            logger.Error("password rotation runner exited", "err", err)
        }
    }()
}
```

- [ ] **Step 3: Smoke check — start the binary, wait 1 minute, inspect logs**

```bash
go build -o /tmp/ygg-core ./cmd/yggdrasil-core   # adjust path
AUTH_PASSWORD_ROTATION_CRON_INTERVAL=10s DB_URL="$DB_URL" /tmp/ygg-core &
sleep 30
pgrep -af ygg-core   # confirm running
kill %1
```

Expected: process runs without crashing; no `runner exited` error in logs.

- [ ] **Step 4: Commit**

```bash
git add main.go   # adjust path
git commit -m "feat(core): start password rotation runner in main"
```

---

## Phase 9: CLI

### Task 9.1: yggdrasil auth passwords setup-token

**Files:**
- Create: `cmd/yggdrasil/auth_passwords.go` (path verify in Step 1)

- [ ] **Step 1: Locate the CLI root**

```bash
grep -rln "cobra.Command\|rootCmd" /Users/dakasa/projects/yggdrasil/yggdrasil-core/cmd/ 2>/dev/null | head -5
```

- [ ] **Step 2: Implement the subcommand (cobra)**

```go
// cmd/yggdrasil/auth_passwords.go
package main // adjust to actual package name

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"

	"github.com/spf13/cobra"
)

func newAuthPasswordsSetupTokenCmd() *cobra.Command {
	var collaboratorSlug string
	var collaboratorID string
	cmd := &cobra.Command{
		Use:   "setup-token",
		Short: "Issue a password setup link for a collaborator",
		RunE: func(cmd *cobra.Command, args []string) error {
			// Resolve slug → id if needed (call admin GET /collaborators/{slug})
			id := collaboratorID
			if id == "" && collaboratorSlug != "" {
				resolved, err := resolveCollabIDBySlug(collaboratorSlug)
				if err != nil {
					return err
				}
				id = resolved
			}
			if id == "" {
				return fmt.Errorf("--collaborator (slug) or --id required")
			}
			body, _ := json.Marshal(map[string]any{"collaborator_id": id})
			req, _ := http.NewRequest(http.MethodPost, ygdrasilURL("/api/v1/auth/passwords/setup-tokens"), bytes.NewReader(body))
			authenticateAdminRequest(req)
			req.Header.Set("Content-Type", "application/json")
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				return err
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusCreated {
				_, _ = os.Stderr.WriteString(fmt.Sprintf("error: %s\n", resp.Status))
				return fmt.Errorf("non-201")
			}
			io := json.NewDecoder(resp.Body)
			var out map[string]any
			if err := io.Decode(&out); err != nil {
				return err
			}
			pretty, _ := json.MarshalIndent(out, "", "  ")
			fmt.Println(string(pretty))
			return nil
		},
	}
	cmd.Flags().StringVar(&collaboratorSlug, "collaborator", "", "collaborator slug")
	cmd.Flags().StringVar(&collaboratorID, "id", "", "collaborator UUID")
	return cmd
}

// ygdrasilURL, authenticateAdminRequest, resolveCollabIDBySlug: reuse existing CLI helpers; otherwise inline minimal versions that read YGGDRASIL_URL and YGGDRASIL_TOKEN env vars.
```

- [ ] **Step 3: Register in the auth command tree**

Find where `auth` subcommand registers children (likely an `init()` in a `cmd/yggdrasil/auth.go` or similar) and add:

```go
authCmd.AddCommand(newAuthPasswordsCmd()) // which itself adds setup-token
```

- [ ] **Step 4: Smoke test**

```bash
go build -o /tmp/ygg ./cmd/yggdrasil
YGGDRASIL_URL=http://localhost:9080 YGGDRASIL_TOKEN=$ADMIN_TOKEN /tmp/ygg auth passwords setup-token --collaborator some-known-slug
```

Expected: JSON with `token_id`, `setup_url`, `expires_at`.

- [ ] **Step 5: Commit**

```bash
git add cmd/yggdrasil/auth_passwords.go cmd/yggdrasil/auth.go   # if modified
git commit -m "feat(cli): yggdrasil auth passwords setup-token"
```

---

## Phase 10: Deprecation banner

### Task 10.1: Mark yggdrasil-identities deprecated

**Files:**
- Modify: `/Users/dakasa/projects/yggdrasil/yggdrasil-identities/README.md`

> This file lives outside `yggdrasil-core`. The commit goes to the `yggdrasil-identities` repo. Open it in its own working tree before editing.

- [ ] **Step 1: Insert deprecation banner at top**

```markdown
> **⚠️ DEPRECATED.** `yggdrasil-identities` is replaced by the credential lifecycle in `yggdrasil-core` (`auth_identities` schema + `/api/v1/auth/passwords/*` endpoints + MFA enforcer). See `yggdrasil-core/docs/superpowers/specs/2026-05-15-credential-lifecycle-design.md`. No new work should land here; removal is tracked as a follow-up issue.
```

- [ ] **Step 2: Commit in the yggdrasil-identities repo**

```bash
cd /Users/dakasa/projects/yggdrasil/yggdrasil-identities
git add README.md
git commit -m "docs: mark yggdrasil-identities DEPRECATED (superseded by core)"
```

---

## Phase 11: End-to-end smoke

### Task 11.1: Run all integration tests in sequence

- [ ] **Step 1: Boot postgres + apply migrations**

```bash
docker compose up -d postgres   # or whatever the existing test fixture uses
DB_URL="postgres://localhost:5432/ygg_test?sslmode=disable" goose -dir db/migrations postgres "$DB_URL" up
```

- [ ] **Step 2: Run the full credentials suite**

```bash
DB_URL="$DB_URL" go test ./internal/auth/password/... ./repository/... ./controllers/httpapi/... -v -count=1 -run "Token|Credential|Password|Setup|Forgot|Reset|Change|Rotation"
```

Expected: all PASS.

- [ ] **Step 3: Cycle a real collaborator end-to-end via curl**

```bash
# 1. login admin
ADMIN_TOKEN=$(curl -sS -X POST http://localhost:9080/api/v1/auth/login \
  -H 'content-type: application/json' \
  -d '{"identifier":"admin","password":"<admin-pw>","totp_code":"<totp>"}' | jq -r .token)

# 2. issue setup token
COLLAB_ID=$(curl -sS "http://localhost:9080/api/v1/collaborators?slug=newhire" -H "Authorization: Bearer $ADMIN_TOKEN" | jq -r .id)
SETUP=$(curl -sS -X POST http://localhost:9080/api/v1/auth/passwords/setup-tokens \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H 'content-type: application/json' \
  -d "{\"collaborator_id\":\"$COLLAB_ID\"}")
RAW=$(echo "$SETUP" | jq -r .setup_url | sed 's/.*token=//')

# 3. complete setup
curl -sS -X POST http://localhost:9080/api/v1/auth/passwords/setup \
  -H 'content-type: application/json' \
  -d "{\"token\":\"$RAW\",\"new_password\":\"F0rest-Iceland-2026!\",\"profile\":{\"display_name\":\"New Hire\"}}"

# 4. verify event_log has the two credential.* events
psql "$DB_URL" -c "SELECT type, payload FROM event_log WHERE type LIKE 'credential.%' ORDER BY created_at DESC LIMIT 5;"
```

Expected: two events visible (`credential.setup_token_issued`, `credential.password_setup_completed`), session opened, response carries `mfa_enrollment_required: true`.

- [ ] **Step 4: Tag the milestone in git**

```bash
git -C /Users/dakasa/projects/yggdrasil/yggdrasil-core tag -a credential-lifecycle-v1 -m "Credential lifecycle feature complete (spec 2026-05-15)"
```

---

## Self-review notes (engineering follow-ups)

These are flagged for review during implementation, NOT plan placeholders:

1. **`decodeJSON` strictness** (Task 7.2): the plan assumes `DisallowUnknownFields` is on globally. If it isn't, T7.2 must also add a strict variant before merging or the whitelist check is a no-op.
2. **Existing `mfa` package function signatures** (Task 7.3): `mfa.VerifyTOTP`, `mfa.ConsumeRecoveryCode`, `mfa.VerifyWebAuthnAssertion` are referenced. Verify exact names; if `controllers/httpapi/mfa.go` uses different ones, swap in those.
3. **`repository.CreateAuthSessionTx`** (Task 7.2, 7.5): assumed to exist as the tx variant of the session creation. If only a `*sql.DB` variant exists, refactor to accept `DBExecer` interface OR start session creation outside the main tx (acceptable race: cap one-second window where token consumed but session creation fails on retry).
4. **CLI path** (Task 9.1): inferred from typical layouts. If `cmd/yggdrasil` differs, adjust the file path.
5. **`event_log.aggregate_type='collaborator'`** (Task 3.1): verify the `event_log` schema permits this string. If a constrained enum exists, add `'collaborator'` to it first via a small migration.

These items DO NOT block running the plan — they trigger a 1-line investigation each before merging the corresponding task.
