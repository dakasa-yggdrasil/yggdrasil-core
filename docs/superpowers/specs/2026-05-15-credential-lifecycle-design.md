# Yggdrasil Credential Lifecycle — Design

**Status**: approved (brainstorming 2026-05-15) — pending implementation plan via `writing-plans` skill.
**Driver**: yggdrasil-core já tem login com password+MFA, sessions e third-party (OIDC), mas falta o ciclo de vida da credencial password — onboarding via setup-link, troca autenticada, recovery por esqueci-senha e rotação periódica. Sem esse ciclo, novos colabs só entram via SSO/IdP, senhas locais nunca rotacionam, e perda de senha exige intervenção manual em DB.
**Scope**: ciclo de vida completo de credencial password no yggdrasil-core, com unificação do modelo de credenciais (`password_hash` migra de `collaborator_password_credentials` pra `auth_identities`), 5 endpoints novos, middleware de enforcement, cron de rotação, eventos emitidos pra extensão opt-in, e deprecação do serviço `yggdrasil-identities` legacy.

---

## 1. Visão geral e objetivos

A feature entrega:

- **Onboarding via setup-link**: admin gera link de primeiro acesso; colab consome, define senha + perfil pessoal limitado; sessão é aberta com `mfa_enrollment_required=true` que força enroll antes de qualquer uso da plataforma.
- **Change autenticado com MFA inline**: usuário troca senha apresentando senha atual + new password + 1 fator MFA (TOTP/recovery/webauthn) na mesma request.
- **Rotação hard com expiração configurável**: cron marca senhas vencidas (`password_must_change=true`); middleware bloqueia 99% dos endpoints até troca; surface recebe payload padronizado pra redirecionar.
- **Recovery por esqueci-senha**: endpoint público anti-enumeration; reset token requer MFA gate na redenção.
- **Eventos emitidos**: 5 novos `event_log.type` permitem que workflows opt-in disparem notificação via integration-{slack,email,...} sem core depender delas.
- **Unificação de credenciais**: `password_hash` + colunas relacionadas migram pra `auth_identities` (já dona de webauthn/totp/recovery_codes/mfa state). Tabela `collaborator_password_credentials` é deprecada e dropada na mesma migração.
- **Deprecação `yggdrasil-identities`**: serviço legacy standalone (JWT direto, sem MFA, sem sessions) é marcado `DEPRECATED` no README como parte desta feature; remoção física fica pra release seguinte.

**Princípios aplicados** (do CLAUDE.md / brainstorming):

1. **Só yggdrasil-core importa estruturalmente**. Surfaces e integrations são opt-in/substituíveis. A API do core é auto-suficiente: response carrega tudo que um cliente arbitrário precisa.
2. **Zero dependência de integration**. Caminho admin-assisted funciona em instalação Yggdrasil pura; integrations dão caminho alternativo via outbox de eventos.
3. **YAGNI**. Nada de "preparar o terreno pra credencial futura X". Modelagem cirúrgica.

**Out of scope** (Phase 2 / follow-up):

- Remoção física do `yggdrasil-identities` (issue separada).
- UI nova no console-ops pra mostrar tokens pendentes (assumido: console-ops já consegue renderizar via API genérica de admin; verificar na implementação).
- Workflow oficial de "envia setup-link via Slack" — fica como exemplo de extensão; consumer real é spec separado.
- Password history (impedir reuso das últimas N senhas) — não pedido, NIST 800-63B 2017+ não exige.
- Step-up flow separado pra change — escolhemos MFA inline no body por consistência com login.

---

## 2. Arquitetura

### 2.1 Modelo de credenciais (após unificação)

`auth_identities` (1:1 com `collaborators`) passa a ser **a única fonte de verdade** de credenciais de autenticação local:

| Coluna existente | Domínio |
|---|---|
| `username` | Identifier de login (CITEXT, único) |
| `webauthn_credentials` JSONB | WebAuthn |
| `totp_secret_ciphertext` BYTEA + `totp_secret_dek` BYTEA | TOTP (envelope-encrypted) |
| `recovery_codes_hashes` TEXT[] | Recovery codes (hashed) |
| `mfa_enrolled_at` TIMESTAMPTZ | Gate de enrollment |
| `failed_attempts` INT + `locked_until` TIMESTAMPTZ | Lockout |

| Coluna nova (migração 00027) | Domínio |
|---|---|
| `password_hash` TEXT NULL | Hash da senha (null = sem senha local, só SSO) |
| `password_scheme` TEXT NULL | `'argon2id'` (novo) ou `'pbkdf2_sha256'` (legacy, verify-only) |
| `password_updated_at` TIMESTAMPTZ NULL | Para audit e cálculo de rotation |
| `password_expires_at` TIMESTAMPTZ NULL | Quando expira (null = sem rotação) |
| `password_must_change` BOOLEAN NOT NULL DEFAULT false | Flag explícita (set pelo cron de rotação OU pelo admin) |
| `password_metadata` JSONB NOT NULL DEFAULT '{}'::jsonb | Para extensão futura sem ALTER TABLE |

`collaborator_password_credentials` é **dropada** na mesma migração (backfill antes do drop, mesma transação).

### 2.2 Tabela nova de tokens de credencial

`auth_credential_tokens` (migração 00028) cobre invite/setup e reset/forgot.

| Coluna | Tipo | Função |
|---|---|---|
| `id` | UUID PK | Identificador opaco (usado pra audit + render endpoint) |
| `collaborator_id` | UUID FK collaborators ON DELETE CASCADE | Sujeito do token |
| `purpose` | TEXT CHECK IN ('setup','reset') | Tipo do token |
| `token_hash` | TEXT UNIQUE | sha256(raw_token); raw nunca persiste |
| `expires_at` | TIMESTAMPTZ NOT NULL | TTL absoluto |
| `consumed_at` | TIMESTAMPTZ NULL | Marca de redenção (single-use) |
| `created_by` | UUID NULL FK collaborators | Admin emissor; NULL pra forgot (autosserviço) |
| `metadata` | JSONB DEFAULT '{}' | Audit livre (IP origem, etc) |
| `created_at` | TIMESTAMPTZ DEFAULT NOW() | |

Index parcial `(collaborator_id, purpose) WHERE consumed_at IS NULL` pra lookup O(1) de tokens ativos.

### 2.3 Componentes

| Componente | Tipo | Path |
|---|---|---|
| Migration: estende auth_identities + backfill + drop tabela velha | novo | `db/migrations/00027_unify_credentials.sql` |
| Migration: cria auth_credential_tokens | novo | `db/migrations/00028_auth_credential_tokens.sql` |
| Domínio: policy de força + token gen + hash dispatcher | novo | `internal/auth/password/` |
| Domínio: cron de rotação | novo | `internal/auth/password/rotation.go` |
| Repository: credentials (CRUD password fields + tokens) | novo | `repository/credentials.go` + `_test.go` |
| Repository: refator das 2 queries que liam tabela velha | extensão | `repository/auth.go` |
| Controller: 5 endpoints novos | novo | `controllers/httpapi/credentials.go` + `_test.go` |
| Middleware: password_change_required + mfa_enrollment_required | novo | `controllers/httpapi/middleware_credentials.go` |
| Login response: adicionar flags | extensão | `controllers/httpapi/auth.go` |
| Event types novos | extensão | `repository/events.go` (lista de constantes) |
| CLI: `yggdrasil auth passwords setup-token` | novo | `cmd/yggdrasil/auth/passwords.go` (path inferido, validar) |
| README do `yggdrasil-identities` marcado DEPRECATED | extensão | `yggdrasil-identities/README.md` |

---

## 3. Schema (migrações)

### 3.1 Migration 00027 — unify credentials

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

### 3.2 Migration 00028 — auth_credential_tokens

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

---

## 4. API contracts

Todos endpoints novos vivem sob `/api/v1/auth/passwords/*`.

### 4.1 `POST /api/v1/auth/passwords/setup-tokens` (admin)

Gera invite link pra um colaborador.

**Auth**: requer permission `iam.collaborators.invite`.

```http
POST /api/v1/auth/passwords/setup-tokens
Authorization: Bearer <admin session>
Content-Type: application/json

{
  "collaborator_id": "01935...",
  "expires_in_seconds": 172800           // opcional; default = AUTH_PASSWORD_SETUP_TOKEN_TTL (48h)
}
```

```http
201 Created
{
  "token_id":   "01935...",
  "setup_url":  "https://<YGGDRASIL_PUBLIC_BASE_URL>/setup?token=<raw_token>",
  "expires_at": "2026-05-17T22:00:00Z"
}
```

**Comportamento**:

- Gera 32 bytes `crypto/rand`, base64url-encoded → `raw_token` (256 bits de entropia).
- Persiste apenas `sha256(raw_token)` em `token_hash`; raw token só aparece neste response.
- Invalida tokens `purpose='setup'` ativos anteriores do mesmo `collaborator_id` (UPDATE `consumed_at = NOW()` em mesma transação) — single-active policy.
- Emit `credential.setup_token_issued` na mesma tx.
- 404 se `collaborator_id` não existir; 403 sem permissão.

### 4.2 `POST /api/v1/auth/passwords/setup` (público, com token)

Consome invite, define senha + perfil pessoal limitado, abre sessão.

```http
POST /api/v1/auth/passwords/setup
Content-Type: application/json

{
  "token":         "<raw_token>",
  "new_password": "...",
  "profile": {                              // opcional
    "display_name": "Giovanni Martins",
    "timezone":     "America/Sao_Paulo",
    "personal_data": {
      "avatar_url": "https://...",
      "bio":        "..."
    }
  }
}
```

```http
200 OK
Set-Cookie: yggdrasil_session=...; Secure; HttpOnly; SameSite=Lax
{
  "session": { "id": "...", "expires_at": "...", "token": "..." },
  "collaborator": { ... },
  "mfa_enrollment_required": true,
  "mfa_enroll_url": "/api/v1/auth/mfa/enroll"
}
```

**Comportamento**:

- Valida `sha256(token) == token_hash`, `consumed_at IS NULL`, `expires_at > NOW()`. Falha → 401 `setup_token_invalid`.
- Aplica `password.ValidateStrength` (Seção 6). Falha → 422 `password_too_weak` + reason.
- Whitelist de `profile`: `display_name`, `timezone`, `personal_data`. Qualquer outro campo no objeto → 422 `setup_unknown_fields` + lista dos rejeitados. **Email, slug, role, status, employment_data, metadata, traits, manager_id, primary_team_id, third_party_identities** são bloqueados.
- Numa **única transação** Postgres:
  1. `UPDATE auth_credential_tokens SET consumed_at = NOW() WHERE id = $1 AND consumed_at IS NULL RETURNING ...` (atomicidade de redenção).
  2. `UPDATE auth_identities SET password_hash, password_scheme = 'argon2id', password_updated_at = NOW(), password_expires_at = NOW() + AUTH_PASSWORD_ROTATION_PERIOD, password_must_change = false WHERE collaborator_id = $1`.
  3. `UPDATE collaborators SET display_name = COALESCE($2, display_name), timezone = COALESCE($3, timezone), personal_data = personal_data || $4 WHERE id = $1`.
  4. `INSERT INTO auth_sessions ...`.
  5. `EmitEvent credential.password_setup_completed`.
- Response sinaliza `mfa_enrollment_required: true` porque `auth_identities.mfa_enrolled_at IS NULL` neste ponto. Surface DEVE redirecionar; middleware (Seção 4.6) bloqueia tudo exceto `/auth/mfa/enroll` até `mfa_enrolled_at` ser preenchido.

### 4.3 `POST /api/v1/auth/passwords/change` (autenticado + MFA inline)

Usuário troca senha (voluntário ou forçado por rotação).

```http
POST /api/v1/auth/passwords/change
Authorization: Bearer <session>
Content-Type: application/json

{
  "current_password": "...",
  "new_password":     "...",
  "totp_code":        "123456"
  // OU: "recovery_code": "ABCD-EFGH-IJKL-MNOP"
  // OU: "webauthn_assertion": { ... }
}
```

```http
200 OK
{ "password_updated_at": "...", "password_expires_at": "..." }
```

**Comportamento**:

- Bypassa o middleware `password_change_required` (este endpoint é a saída do estado).
- Valida `current_password` contra `auth_identities.password_hash` via dispatcher (Seção 7). Falha → 401 `invalid_current_password`.
- Exige MFA inline reusando `internal/auth/mfa` enforcer. Mesma máquina de estado do login: sem fator enrolled → 428 `mfa_not_enrolled`; fator inválido → 401 `invalid_mfa`.
- Valida policy. Falha → 422 `password_too_weak`.
- Valida que `new_password != current_password` (hash compare). Igual → 422 `password_unchanged`.
- Numa tx:
  1. Atualiza hash + `password_scheme='argon2id'` + `password_updated_at=NOW()` + `password_expires_at=NOW()+rotation_period` + `must_change=false`.
  2. Se MFA foi `recovery_code`: marca código consumido (existente em `internal/auth/mfa/recovery_codes.go`).
  3. Revoga **todas as outras** auth_sessions: `UPDATE auth_sessions SET revoked_at=NOW(), status='revoked' WHERE collaborator_id = $1 AND id <> $current AND revoked_at IS NULL`.
  4. `EmitEvent credential.password_changed { source: "voluntary" | "rotation" }` (source vem do request context: se o middleware deu trigger=must_change, source=rotation; senão voluntary).

### 4.4 `POST /api/v1/auth/passwords/forgot` (público, anti-enum)

Inicia recovery por esqueci-senha.

```http
POST /api/v1/auth/passwords/forgot
Content-Type: application/json

{ "identifier": "ana@dakasa.co" }       // email OU slug
```

```http
202 Accepted
{ "status": "if_account_exists_token_was_generated" }
```

**Comportamento**:

- **Sempre retorna 202**, independente de match (anti-enumeration).
- Resolve `identifier` por `LOWER(primary_email)` ou `slug` em `collaborators`.
- Se match e rate-limit livre (≤ `AUTH_PASSWORD_FORGOT_RATE_LIMIT_PER_HOUR` por identifier por hora):
  1. Gera token (mesmo formato do setup), TTL = `AUTH_PASSWORD_RESET_TOKEN_TTL` (24h default).
  2. Persiste `auth_credential_tokens` com `purpose='reset'`, `created_by=NULL` (autosserviço), `metadata.source_ip = c.ClientIP()`.
  3. Invalida resets ativos anteriores do mesmo colab.
  4. Emit `credential.reset_token_issued`.
- Rate-limit: tabela própria `auth_credential_rate_limits (identifier, purpose, window_start, count)` ou reuso de mecanismo existente (validar na implementação). Excedido → não cria token, mas retorna 202 igual.

### 4.5 `POST /api/v1/auth/passwords/reset` (público, com token + MFA)

Consome reset token.

```http
POST /api/v1/auth/passwords/reset
Content-Type: application/json

{
  "token":        "<raw_token>",
  "new_password": "...",
  "totp_code":    "123456"      // OU recovery_code OU webauthn_assertion
}
```

```http
200 OK
Set-Cookie: yggdrasil_session=...; Secure; HttpOnly; SameSite=Lax
{ "session": { ... }, "collaborator": { ... } }
```

**Comportamento**:

- Valida token igual ao setup (hash match, not consumed, not expired).
- Carrega colab + auth_identity; **exige MFA gate** com pelo menos 1 fator enrolled.
- Sem MFA enrolled → 428 `mfa_not_enrolled`. Recuperação real desse caso só por admin emitindo novo setup-token (canal humano).
- Aplica policy.
- Tx: consume token, atualiza hash, revoga outras sessions, abre nova session, emit `credential.password_changed { source: "reset" }`.

### 4.6 Middleware `password_change_required` + `mfa_enrollment_required`

Aplicado a **todas as rotas autenticadas em `/api/v1/*` exceto**:

- `POST /auth/passwords/change`
- `POST /auth/logout`
- `GET /auth/session`
- `POST /auth/mfa/enroll` (quando `mfa_enrollment_required` ativo)
- `GET /auth/mfa/enroll/*` (challenges/verify de enroll)

**Ordem das checagens** (cada uma para o request):

```go
identity, err := repository.GetAuthIdentityByCollaboratorID(ctx, db, collaboratorID)
if err != nil { /* 401 */ }

if identity.MFAEnrolledAt == nil {
    c.JSON(403, gin.H{
        "code":       "mfa_enrollment_required",
        "enroll_url": "/api/v1/auth/mfa/enroll",
    })
    c.Abort(); return
}

if identity.PasswordMustChange ||
   (identity.PasswordExpiresAt != nil && identity.PasswordExpiresAt.Before(time.Now())) {
    c.JSON(403, gin.H{
        "code":       "password_change_required",
        "change_url": "/api/v1/auth/passwords/change",
        "reason":     "rotation_expired",     // ou "admin_forced"
    })
    c.Abort(); return
}
```

### 4.7 Login response: adicionar flags

`POST /api/v1/auth/login` (já existe) passa a incluir no body de sucesso:

```json
{
  "session": { ... },
  "collaborator": { ... },
  "mfa_enrollment_required": false,
  "password_change_required": true,
  "password_change_url": "/api/v1/auth/passwords/change"
}
```

Surface pode redirecionar **imediatamente** baseado nesses flags. Middleware (4.6) é belt-and-suspenders se surface esquecer.

---

## 5. Policy de senha + configs

### 5.1 Configs (env / manifest)

| Config | Default | Significado |
|---|---|---|
| `AUTH_PASSWORD_ROTATION_PERIOD` | `90d` | Idade máxima antes de marcar `must_change` |
| `AUTH_PASSWORD_SETUP_TOKEN_TTL` | `48h` | TTL do invite token |
| `AUTH_PASSWORD_RESET_TOKEN_TTL` | `24h` | TTL do reset token |
| `AUTH_PASSWORD_MIN_LENGTH` | `12` | Tamanho mínimo |
| `AUTH_PASSWORD_HASH_SCHEME` | `argon2id` | Scheme novo (verify do legacy mantido) |
| `AUTH_PASSWORD_ARGON2ID_MEMORY_KB` | `65536` | Memory cost (64 MiB) |
| `AUTH_PASSWORD_ARGON2ID_TIME` | `3` | Time cost |
| `AUTH_PASSWORD_ARGON2ID_THREADS` | `4` | Parallelism |
| `AUTH_PASSWORD_FORGOT_RATE_LIMIT_PER_HOUR` | `3` | Por identifier por hora |
| `AUTH_PASSWORD_ROTATION_CRON_INTERVAL` | `1h` | Período do cron de marker |
| `AUTH_CREDENTIAL_EVENTS_ENABLED` | `true` | Liga emit de credential.* |

### 5.2 Policy de força — NIST 800-63B 2017+ moderna

Aplicada em `password.ValidateStrength`:

1. `len(password) < AUTH_PASSWORD_MIN_LENGTH` → `ErrPasswordTooShort`.
2. `password` (case-insensitive, normalizado) contém qualquer `userToken` de tamanho ≥ 4 → `ErrPasswordContainsIdentity`. `userToken`s são: split de `primary_email` antes/depois do `@`, palavras do `display_name`, `slug`.
3. `lowered(password)` está em `commonPasswords` (set carregado do arquivo `internal/auth/password/common_top1000.txt` no startup) → `ErrPasswordTooCommon`.
4. Sem regras de classe (NIST recomenda não exigir). Sem detecção de sequências.

A função é um dos **pontos de contribuição** (Seção 11) — usuário escreve a implementação porque envolve decisões de domínio (substring vs Levenshtein, threshold mínimo do userToken, normalização Unicode).

---

## 6. Eventos emitidos

Novos `event_log.type` (constantes em `repository/events.go`):

| Type | Quando | Aggregate type | Payload |
|---|---|---|---|
| `credential.setup_token_issued` | Admin via `/setup-tokens` | `collaborator` | `{ token_id, collaborator_id, expires_at, issued_by_id, purpose: "setup" }` |
| `credential.password_setup_completed` | Colab via `/setup` | `collaborator` | `{ collaborator_id, token_id, source: "setup", ip, user_agent }` |
| `credential.password_changed` | `/change` ou `/reset` | `collaborator` | `{ collaborator_id, source: "voluntary"\|"rotation"\|"reset", ip }` |
| `credential.reset_token_issued` | `/forgot` resolve em token | `collaborator` | `{ token_id, collaborator_id, expires_at, source: "self_service", purpose: "reset" }` |
| `credential.password_rotation_required` | Cron marca must_change | `collaborator` | `{ collaborator_id, expires_at, marked_at }` |

**Payloads nunca carregam `raw_token` nem `setup_url`** — `event_log` é tabela auditada com SELECT relativamente amplo. Consumer que precisa do URL chama endpoint protegido `GET /api/v1/auth/passwords/tokens/{id}/render` (Seção 9, out-of-MVP) com permission `iam.credentials.render_token`. Pra MVP, admin-assisted resolve via `GET /collaborators/{id}/credential-tokens` que reconstrói o URL na resposta com auth de admin.

Workflows opt-in podem se inscrever via outbox tail (padrão atual descrito em `docs/features/events.md`). Se nenhum workflow plugado, eventos ficam parados — admin-assisted segue funcionando.

---

## 7. Hash scheme & migração transparente

Default novo: `argon2id` (resistente a GPU, RFC 9106). Legacy `pbkdf2_sha256` mantido só pra verify.

`internal/auth/password/hasher.go`:

```go
package password

import "errors"

type Scheme string

const (
    SchemeArgon2id      Scheme = "argon2id"
    SchemePBKDF2SHA256  Scheme = "pbkdf2_sha256"
)

// Hash retorna scheme + hash codificado. Sempre usa SchemeArgon2id.
func Hash(plaintext string) (Scheme, string, error) { /* ... */ }

// Verify dispatcha por scheme. Erro silencioso = mismatch.
func Verify(scheme Scheme, encodedHash, plaintext string) error { /* ... */ }

var ErrSchemeUnknown = errors.New("password scheme unknown")
```

**Re-hash transparente no login bem-sucedido**: se `scheme == SchemePBKDF2SHA256`, após `Verify` ok, gera novo hash com `SchemeArgon2id` e atualiza row. Login não bloqueia se o re-hash falhar (log warning, próxima tentativa retenta).

---

## 8. Cron de rotação

`internal/auth/password/rotation.go`:

```go
package password

// SelectRotationBatch retorna até `limit` collaborator_ids com senha expirada
// e ainda não marcados como must_change.
// Decisões: skipar status='suspended'/'offboarded'? incluir 'on_leave'?
// (Ponto de contribuição — Seção 11.)
func SelectRotationBatch(ctx context.Context, db *sql.DB, limit int) ([]uuid.UUID, error) { /* ... */ }

// MarkForRotation marca os ids como must_change e emite o evento por id, tudo
// num batch transacional.
func MarkForRotation(ctx context.Context, db *sql.DB, ids []uuid.UUID) error { /* ... */ }
```

Loop runner roda a cada `AUTH_PASSWORD_ROTATION_CRON_INTERVAL` (1h default). Batch size 1000 pra não segurar lock longo. Index `auth_identities_password_expires_idx` garante seek eficiente.

Cron registra-se no scheduler existente do core (verificar pattern — `internal/scheduler/` ou similar; provavelmente segue padrão dos crons que já existem pra session reaping mencionado em `docs/features/sessions.md`).

---

## 9. Edge cases & error responses

| Cenário | Status | `code` |
|---|---|---|
| Setup token inválido/consumido/expirado | 401 | `setup_token_invalid` |
| Setup com campo fora da whitelist no profile | 422 | `setup_unknown_fields` |
| Setup com password fraco | 422 | `password_too_weak` (+ `reason`: `too_short` \| `common` \| `contains_identity`) |
| Change com current_password errado | 401 | `invalid_current_password` |
| Change com new_password == current_password | 422 | `password_unchanged` |
| Change/reset com MFA inválido | 401 | `invalid_mfa` |
| Change/reset sem MFA enrolled | 428 | `mfa_not_enrolled` |
| Reset token inválido/expirado/consumido | 401 | `reset_token_invalid` |
| Rate limit forgot | 202 | (resposta genérica idêntica — não revela) |
| Endpoint autenticado com `must_change=true` | 403 | `password_change_required` (+ `change_url`, `reason`) |
| Endpoint autenticado sem MFA enrolled | 403 | `mfa_enrollment_required` (+ `enroll_url`) |
| Setup-token gen sem permissão | 403 | `forbidden` |
| Colab `status != 'active'` tentando setup/reset | 403 | `collaborator_inactive` |

**Concorrência**:

- `UNIQUE(token_hash)` impede duplicatas.
- Redenção atômica via `UPDATE ... WHERE consumed_at IS NULL RETURNING id` numa transação — 2 redenções paralelas: só uma vence.
- Cron de rotação usa `UPDATE ... WHERE password_expires_at < NOW() AND password_must_change = false RETURNING collaborator_id` — idempotente.

---

## 10. Testing approach

### 10.1 Unitários — `internal/auth/password/`

- `ValidateStrength`: table-driven com casos (short, common, contains identity em cada userToken, valid casing edge).
- `GenerateToken`: 1000 iterações; assertion sobre distinct + length + base64url charset.
- `Hash` + `Verify` round-trip: argon2id self; cross-scheme verify (legacy hash → ok).
- `SelectRotationBatch`: testar inclusão/exclusão por status + must_change flag + ordering por expiry.

### 10.2 Repository — `repository/credentials_test.go`

- `CreateCredentialToken` invalida ativos anteriores do mesmo purpose.
- `ConsumeCredentialToken`: erro pra consumed, erro pra expired, erro pra hash mismatch, sucesso single-shot.
- Event emission no mesmo tx — rollback do tx rola back evento (assert via `SELECT FROM event_log` pós-rollback).
- `MarkPasswordsForRotation` em batch — concorrência simulada não duplica eventos.

### 10.3 Integration — `controllers/httpapi/credentials_test.go`

Suite usa Postgres real (testcontainers ou docker-compose, seguir padrão atual do core). E2E happy path pra cada um dos 5 endpoints:

- Setup: admin gera token → colab consome → response carrega `mfa_enrollment_required=true`.
- Setup duplicado: segundo redempt → 401.
- Setup com whitelist violation → 422 lista os campos.
- Change voluntary com TOTP ok → senha trocada, sessions outras revogadas.
- Change com TOTP errado → 401 sem alterar.
- Forgot pra identifier inexistente → 202 idem.
- Forgot rate-limit excedido → 202 idem mas sem token criado (assert via SELECT).
- Reset com MFA → senha trocada, session aberta.
- Cron tick → identidade marcada must_change → request seguinte retorna 403.

### 10.4 Smoke — CLI

`yggdrasil auth passwords setup-token --collaborator <slug>` valida o fluxo admin sem precisar de surface.

---

## 11. Pontos de contribuição (learning)

4 locais onde decisões de domínio DaKasa moldam o comportamento (5-10 linhas cada — autor humano escreve):

| Arquivo | Função | Decisões abertas |
|---|---|---|
| `internal/auth/password/policy.go` | `ValidateStrength` | substring vs Levenshtein no match de userToken; threshold do userToken (3? 4? 5?); normalização Unicode (NFKD?); ordem de erro-curto-circuito |
| `internal/auth/password/policy.go` | `GeneratePasswordResetURL` | usa `YGGDRASIL_PUBLIC_BASE_URL` ou infer do request `Host`? assinar URL com HMAC adicional? path `/setup` vs `/passwords/setup`? |
| `internal/auth/password/rotation.go` | `SelectRotationBatch` | rotar em `status='on_leave'`? skipar `suspended`/`offboarded`? ordering critério (mais antigo primeiro)? |
| `controllers/httpapi/credentials.go` | `handleSetupCommit` | rollback strategy se `EmitEvent` falhar após token consumido? (recomendação: deixar tx errar, cliente retenta) |

---

## 12. Migration plan & deprecação `yggdrasil-identities`

**Esta feature (1 release)**:

1. Migrações 00027 + 00028.
2. Refator `repository/auth.go` (2 sites tocando `collaborator_password_credentials` passam a ler `auth_identities`).
3. Novos endpoints + middleware + cron.
4. Login response estendido com `password_change_required` e `mfa_enrollment_required`.
5. Banner `DEPRECATED — use yggdrasil-core auth flows` no `README.md` do `yggdrasil-identities`.

**Release seguinte (fora deste spec)**:

- Remoção física do `yggdrasil-identities` do monorepo (issue separada). Assume zero consumers (não há referência cruzada no monorepo).

---

## 13. Open questions pra implementação

Pontos a validar quando o plano de implementação for escrito:

- Confirmar nome/path do scheduler existente do core (provavelmente `internal/scheduler/`) pra registrar o cron de rotação.
- Confirmar se há mecanismo de rate-limit existente reusável (e.g. middleware em `internal/middleware/`) ou se a tabela `auth_credential_rate_limits` é nova.
- Confirmar path do CLI (`cmd/yggdrasil/...`) e padrão de subcomando.
- Definir RBAC permission `iam.collaborators.invite` e `iam.credentials.render_token` no bootstrap seed (já há seed de bootstrap addon mencionado em `docs/getting-started.md`).
- Confirmar que `event_log` aceita `aggregate_type='collaborator'` (padrão é `manifest`/`workflow`; verificar no schema da tabela).
