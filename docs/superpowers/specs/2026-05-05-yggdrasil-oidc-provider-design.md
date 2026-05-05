# Yggdrasil OIDC Provider — Design (Phase 1: SSO interno DaKasa)

**Status**: approved (brainstorming 2026-05-05) — pending implementation plan via `writing-plans` skill.
**Driver**: criar tier "enterprise" no DaKasa exige autenticação federada interna. Yggdrasil já é fonte da verdade da plataforma; auth de pessoas DaKasa também passa a ser dele.
**Scope**: SSO interno para equipe DaKasa (`@dakasa.me`), com Yggdrasil-core atuando como OIDC Provider e Google Workspace como Identity Provider backend. Tartaro e Yggdrasil console são as duas primeiras surfaces no MVP.

---

## 1. Visão geral e objetivos

Yggdrasil-core hoje tem um framework genérico de third-party auth (`/auth/providers`, `/auth/third-party/start/{provider}`, `/auth/third-party-identities`) usado pra login de operadores no console via OAuth/OIDC. Falta a peça que torna o Yggdrasil **autoridade central de identidade** pra outras surfaces DaKasa: emitir tokens verificáveis que Tartaro, console e futuras surfaces possam consumir.

**Phase 1 entrega**:

- Yggdrasil-core expõe **OIDC Provider completo** (discovery, JWKS, `/authorize`, `/token`, `/userinfo`, `/end_session`).
- **Google Workspace `dakasa.me`** registrado como identity broker (Yggdrasil delega autenticação real).
- **Tartaro** vira OIDC confidential client (cutover direto, sem feature flag — código de password removido).
- **Yggdrasil console** vira OIDC confidential client embedded no próprio Yggdrasil-core (build estático servido via `embed.FS`).
- **RBAC**: domain-default Team `dakasa-internal` no primeiro login pra qualquer `@dakasa.me`; admin promove pra teams com mais permissão (`yggdrasil-admin`, `tartaro-mod`) via console.
- JWT 15min, refresh 7d sliding rotativo com replay detection (BCP-225), PKCE obrigatório, local logout (não federated).

**Phase 2 (não inclusa)**: Group sync Google Workspace → Teams, federated logout (SLO), `private_pem` em managed-secret, Playwright E2E, console UI de audit + team management.

**Phase 3 (não inclusa, tracked como follow-up)**: Adicionar IdPs (Apple, Microsoft, Facebook); multi-tenant orgs (clientes B2B do "enterprise tier") com per-org SSO config — outro design doc.

---

## 2. Arquitetura

### 2.1 Fluxo de autenticação (Tartaro como exemplo)

```
User → Tartaro frontend (não autenticado)
  → Tartaro backend redirect 302 → Yggdrasil /oidc/authorize?client_id=tartaro&...&code_challenge=…
    → Yggdrasil checa cookie de sessão local (.dakasa.me)
       (se ausente)
       → redirect 302 → /auth/third-party/start/google
         → Google OAuth flow
         → callback /auth/third-party/callback/google
           → Yggdrasil cria/atualiza Collaborator(email)
             → attach Team(dakasa-internal) se domain matches e novo
             → set cookie httpOnly em .dakasa.me
       (se presente)
       → continue
    → Yggdrasil redirect 302 → tartaro.dakasa.me/auth/callback?code=<auth_code>
  → Tartaro backend POST /oidc/token (client_id + client_secret + code + code_verifier)
    → Yggdrasil retorna access_token (JWT 15min) + refresh_token (opaque 7d) + id_token
  → Tartaro set cookie __Secure-tartaro_session=<JWT>, redireciona pra /
```

### 2.2 Componentes

| Componente | Tipo | Repo | Status |
|---|---|---|---|
| OIDC Provider endpoints | novo | `yggdrasil-core/controllers/oidc/` | a criar |
| OIDC Storage (zitadel/oidc interface) | novo | `yggdrasil-core/controllers/oidc/storage.go` | a criar |
| OIDC schema migration | novo | `yggdrasil-core/migrations/20260505_oidc.sql` | a criar |
| Google IdP registration (seed) | extensão | `yggdrasil-core` bootstrap | a estender |
| Yggdrasil console embedded handlers | extensão | `yggdrasil-core/controllers/console/` | a criar |
| Console build embed | extensão | `yggdrasil-core/Dockerfile` (multi-stage Go + Vite) | a estender |
| `dakasa-commons/oidcclient` Go library | novo | `dakasa-co/dakasa-commons/oidcclient/` | a criar |
| Tartaro OIDC client | extensão | `dakasa-tartaro-api` + `dakasa-tartaro-fe` | a estender |
| JWKS rotation cron workflow | novo | `dakasa-system/yggdrasil/dakasa/workflows/yggdrasil-rotate-oidc-keys.json` | a criar |

### 2.3 Library escolhida

`github.com/zitadel/oidc/v3/pkg/op` — provider OIDC mantido pelo Zitadel team, MIT, suporta v3 spec, expõe interface `op.Storage` que Yggdrasil implementa.

---

## 3. Componentes novos no Yggdrasil-core

### 3.1 OIDC Provider HTTP endpoints

Mounted em `/oidc/*`, providos por `zitadel/oidc/v3/pkg/op`:

| Endpoint | Método | Função |
|---|---|---|
| `/.well-known/openid-configuration` | GET | discovery (auto) |
| `/.well-known/jwks.json` | GET | JWKS (auto, lê do Storage) |
| `/oidc/authorize` | GET | inicia flow + delega pra `/auth/third-party/start/google` se sem sessão |
| `/oidc/token` | POST | trade code → tokens; refresh rotation |
| `/oidc/userinfo` | GET | bearer JWT → claims |
| `/oidc/end_session` | GET/POST | logout local |

Endpoints existentes (`/auth/login`, `/auth/third-party/*`) continuam funcionando — não substituem.

### 3.2 Storage interface (`controllers/oidc/storage.go`)

Implementa `op.Storage` do zitadel. ~25 métodos. Mapping pra tabelas:

| Método | Tabela |
|---|---|
| `CreateAuthRequest`, `AuthRequestByID` | `oidc_auth_requests` (TTL 10min) |
| `SaveAuthCode`, `AuthRequestByCode` | `oidc_auth_codes` (TTL 10min, single-use) |
| `CreateAccessToken`, `CreateAccessAndRefreshTokens` | `oidc_refresh_tokens` (access stateless JWT, só refresh persiste) |
| `TokenRequestByRefreshToken`, `TerminateSession` | `oidc_refresh_tokens` + revoke flag |
| `GetClientByClientID` | `oidc_clients` |
| `AuthorizeClientIDSecret` | bcrypt compare on `client_secret_hash` |
| `SetUserinfoFromScopes`, `SetUserinfoFromToken` | join `Collaborators` + `TeamMemberships` |
| `KeySet`, `SigningKey` | `oidc_signing_keys` (current + previous) |

### 3.3 Schema migration

```sql
CREATE TABLE oidc_clients (
  client_id           text PRIMARY KEY,
  client_secret_hash  text NOT NULL,             -- bcrypt; empty for public clients (não usados no MVP)
  redirect_uris       text[] NOT NULL,
  post_logout_redirect_uris text[] NOT NULL DEFAULT '{}',
  scopes              text[] NOT NULL DEFAULT '{openid,email,profile,roles}',
  grant_types         text[] NOT NULL DEFAULT '{authorization_code,refresh_token}',
  pkce_required       boolean NOT NULL DEFAULT true,
  created_at          timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE oidc_auth_requests (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  client_id       text NOT NULL REFERENCES oidc_clients(client_id),
  collaborator_id uuid REFERENCES collaborators(id),
  redirect_uri    text NOT NULL,
  scopes          text[] NOT NULL,
  code_challenge  text,
  code_challenge_method text,
  state           text,
  nonce           text,
  expires_at      timestamptz NOT NULL,
  consumed_at     timestamptz
);

CREATE TABLE oidc_auth_codes (
  code            text PRIMARY KEY,
  auth_request_id uuid NOT NULL REFERENCES oidc_auth_requests(id),
  expires_at      timestamptz NOT NULL,
  consumed_at     timestamptz
);

CREATE TABLE oidc_refresh_tokens (
  token           text PRIMARY KEY,
  collaborator_id uuid NOT NULL REFERENCES collaborators(id),
  client_id       text NOT NULL REFERENCES oidc_clients(client_id),
  scopes          text[] NOT NULL,
  expires_at      timestamptz NOT NULL,
  rotated_from    text REFERENCES oidc_refresh_tokens(token),
  revoked_at      timestamptz
);

CREATE TABLE oidc_signing_keys (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  algorithm   text NOT NULL DEFAULT 'RS256',
  private_pem text NOT NULL,                     -- plain text MVP; managed-secret-ref Phase 2
  public_jwk  jsonb NOT NULL,
  created_at  timestamptz NOT NULL DEFAULT now(),
  active_at   timestamptz NOT NULL,
  retire_at   timestamptz
);

CREATE TABLE oidc_provider_settings (
  singleton            boolean PRIMARY KEY DEFAULT true,
  allowed_email_domains text[] NOT NULL DEFAULT ARRAY['dakasa.me'],
  default_team_name    text NOT NULL DEFAULT 'dakasa-internal',
  auto_provision       boolean NOT NULL DEFAULT true,
  CHECK (singleton = true)
);
INSERT INTO oidc_provider_settings DEFAULT VALUES;

CREATE TABLE oidc_audit_events (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  occurred_at     timestamptz NOT NULL DEFAULT now(),
  kind            text NOT NULL,
  collaborator_id uuid REFERENCES collaborators(id),
  client_id       text,
  email           text,
  remote_addr     text,
  user_agent      text,
  metadata        jsonb,
  outcome         text NOT NULL                  -- 'success' | 'rejected' | 'error'
);

CREATE INDEX ON oidc_auth_requests (expires_at);
CREATE INDEX ON oidc_auth_codes (expires_at);
CREATE INDEX ON oidc_refresh_tokens (collaborator_id, revoked_at);
CREATE INDEX ON oidc_audit_events (occurred_at DESC);
CREATE INDEX ON oidc_audit_events (collaborator_id, occurred_at DESC) WHERE collaborator_id IS NOT NULL;
CREATE INDEX ON oidc_audit_events (kind, outcome) WHERE outcome = 'rejected';

-- Seed clients
INSERT INTO oidc_clients (client_id, client_secret_hash, redirect_uris, post_logout_redirect_uris) VALUES
  ('tartaro',           '<bcrypt-hash-from-bootstrap>', ARRAY['https://tartaro.dakasa.me/auth/callback'],   ARRAY['https://tartaro.dakasa.me/']),
  ('yggdrasil-console', '<bcrypt-hash-from-bootstrap>', ARRAY['https://yggdrasil.dakasa.me/console/auth/callback'], ARRAY['https://yggdrasil.dakasa.me/console/']);

-- Seed teams
INSERT INTO teams (name, description) VALUES
  ('dakasa-internal',  'Default team — anyone with @dakasa.me email'),
  ('yggdrasil-admin',  'Full access to Yggdrasil console + team management'),
  ('tartaro-mod',      'Tartaro moderation panel'),
  ('tartaro-auditor',  'Tartaro read-only auditor');
```

### 3.4 GC cron

Cron Yggdrasil próprio (workflow JSON em `dakasa-system/yggdrasil/dakasa/workflows/yggdrasil-oidc-gc.json`, schedule `0 4 * * *` daily at 04:00 UTC):

```sql
DELETE FROM oidc_auth_requests WHERE expires_at < now() - interval '24 hours';
DELETE FROM oidc_auth_codes    WHERE expires_at < now() - interval '24 hours';
DELETE FROM oidc_refresh_tokens WHERE revoked_at < now() - interval '30 days';
```

---

## 4. Surfaces como OIDC clients

### 4.1 Tartaro (confidential client externo)

- **Frontend** (`dakasa-tartaro-fe`): remove form de login, redirect-to-`/auth/callback` em 401. Mostra `claims.name` na top bar.
- **Backend** (`dakasa-tartaro-api`):
  - Novo handler `GET /auth/callback` que troca code → tokens, set cookie httpOnly `__Secure-tartaro_session=<JWT>`, redireciona pra `return_to`.
  - Novo middleware `requireAuth` que valida JWT via `oidcclient.Verifier` (com cache JWKS 1h), coloca claims no context.
  - Remove handlers de password login (deprecated).
  - `client_secret` lido de Yggdrasil managed-secret no startup (env `TARTARO_OIDC_CLIENT_SECRET_REF`).
- **Cutover direto**: sem feature flag. Re-deploy do binário antigo é o caminho de rollback.

### 4.2 Yggdrasil console (confidential client embedded)

- **Embed**: `yggdrasil-core` Dockerfile vira multi-stage (Vite build + Go build), copia `yggdrasil-console/dist/*` pra `embed.FS` do core.
- **Handlers** (`controllers/console/`):
  - `GET /console/*` serve estáticos do `embed.FS`.
  - `GET /console/auth/callback` faz code-trade backend-to-backend, set cookie `__Secure-yggdrasil_console_session=<JWT>` em `.dakasa.me`, redireciona pra `/console/`.
  - `POST /console/auth/refresh` valida refresh em DB, emite novo JWT.
  - `POST /console/auth/logout` invalida refresh, limpa cookie.
- **Frontend SPA** (`yggdrasil-console`): adiciona redirect-to-`/console/auth/callback` em 401; chama `/api/v1/*` com cookie.
- **Yggdrasil-core** ganha middleware `bearerOrSession` em `/api/v1/*`: aceita Bearer JWT (consumidores externos) **ou** cookie `__Secure-yggdrasil_console_session` (console).

### 4.3 Library `dakasa-co/dakasa-commons/oidcclient`

Toolkit Go (~150 LOC):

```go
type Verifier struct { ... }

func NewVerifier(issuerURL string) (*Verifier, error)
func (v *Verifier) Verify(ctx context.Context, token string) (*Claims, error)
func (v *Verifier) AuthorizeURL(state, nonce, codeChallenge string) string
func (v *Verifier) ExchangeCode(ctx, code, codeVerifier, redirectURI string) (*TokenSet, error)
func (v *Verifier) Refresh(ctx, refreshToken string) (*TokenSet, error)

type Claims struct {
  Subject  string    `json:"sub"`
  Email    string    `json:"email"`
  Name     string    `json:"name"`
  Teams    []string  `json:"teams"`
  IssuedAt time.Time `json:"iat"`
  Expires  time.Time `json:"exp"`
}
```

JWKS cached por 1h; refresh on-demand quando JWT verify retorna `kid not found`.

---

## 5. RBAC mapping

### 5.1 Fluxo do primeiro login

```
1. Yggdrasil callback recebe id_token Google com email + email_verified.
2. Lookup Collaborator por email.
3. Se NÃO existe:
   3a. Se email domain NÃO está em allowed_email_domains → REJEITA, 403.
   3b. Se auto_provision = false → REJEITA, 403.
   3c. Senão → cria Collaborator + TeamMembership(default_team_name).
   3d. Audit event 'collaborator.auto_provisioned'.
4. Continue OIDC flow com claim teams=[lista de Teams do Collaborator].
```

### 5.2 Bootstrap admin

CLI `yggdrasil bootstrap-admin --email <email>` (idempotente):
- Verifica se Collaborator existe (depois do primeiro login).
- Adiciona TeamMembership('yggdrasil-admin').

Pré-requisito: você loga uma vez pelo flow normal (vira `dakasa-internal`), depois roda o CLI pra promover a si mesmo.

### 5.3 Claim mapping (JWT)

```json
{
  "iss": "https://yggdrasil.dakasa.me",
  "aud": "tartaro",
  "sub": "<collaborator-uuid>",
  "email": "giovanni@dakasa.me",
  "email_verified": true,
  "name": "Giovanni Martins",
  "teams": ["dakasa-internal", "yggdrasil-admin", "tartaro-mod"],
  "exp": <unix>,
  "iat": <unix>,
  "nonce": "<from-original-request>"
}
```

Yggdrasil **não** popula `roles` ou `permissions`. Surface decide localmente baseado em `teams`.

---

## 6. Token policy + logout

### 6.1 Lifetimes

| Token | TTL | Storage | Rotação |
|---|---|---|---|
| Authorization code | 10 min | DB single-use | n/a |
| Access token (JWT) | 15 min | stateless | via refresh |
| ID token (JWT) | 15 min | stateless | n/a |
| Refresh token | 7 dias sliding | DB | rotativo (replay detection) |
| Cookie de sessão | 15 min, refresh background | cookie + DB | invisível ao user |

### 6.2 Refresh rotation (BCP-225)

1. Trade `R1` → `(A2, R2)`. Yggdrasil marca `R1.revoked_at=now`, cria `R2` com `R2.rotated_from=R1`.
2. Replay detected (`R1` apresentado novamente) → revoga chain inteira via `WITH RECURSIVE` em `rotated_from`.
3. Audit event `refresh_token.replay_detected`.

### 6.3 Logout

`GET /oidc/end_session?id_token_hint=...&post_logout_redirect_uri=...`:
- Valida `id_token_hint` (assinatura + sub).
- Revoga refresh associado.
- Limpa cookie `.dakasa.me`.
- Redirect pra `post_logout_redirect_uri` (validado contra `oidc_clients.post_logout_redirect_uris`).

**Local logout, não federated**: Google session continua. Phase 2 adiciona SLO.

### 6.4 Cookies

```
__Secure-yggdrasil_console_session=<JWT>
  Domain=.dakasa.me
  Path=/
  HttpOnly
  Secure
  SameSite=Lax       # not Strict — survives redirects pós-Google
  Max-Age=900
```

`__Secure-tartaro_session` segue mesmo padrão, escopo `tartaro.dakasa.me`.

### 6.5 JWKS rotation

Workflow Yggdrasil cron `0 0 1 */3 *` (day 1 of every 3rd month):
1. Gera novo RSA-2048, insere com `active_at = now + 7d`.
2. Próximo tick: marca antigo `retire_at = now`.
3. Após 30d: hard delete.

JWKS endpoint serve ambas as keys durante grace period — surfaces com cache 1h migram naturalmente.

---

## 7. Error handling + edge cases

### 7.1 Tabela de erros usuário-visíveis

| Cenário | Status | Mensagem |
|---|---|---|
| Email domain não permitido | 403 | "Sua conta `<email>` não tem permissão. Contacte um admin DaKasa." |
| `email_verified=false` no Google | 403 | "Email não verificado no Google. Verifique e tente novamente." |
| `auto_provision=false` + new email | 403 | "Conta inexistente. Contacte um admin pra criar." |
| Refresh replay | 401 | client backend força re-login |
| Refresh expirado (>7d) | 401 | client backend força re-login |
| Auth code expirado (>10min) | 400 | redirect-to-`/oidc/authorize` |
| PKCE mismatch | 400 | log + 400 |
| Invalid `client_id` | 401 | error page "Cliente desconhecido" |
| Invalid `redirect_uri` | 400 | error page (não redireciona — security) |
| Google IdP down | 502 | "Serviço de autenticação Google indisponível, tente em instantes" |
| Yggdrasil core down | n/a | surface mostra error genérica + retry |

### 7.2 Edge cases críticos

1. **Cold start sem signing key**: `loadOrCreateSigningKey()` no startup do OIDC handler.
2. **Multi-pod race em key generation**: `INSERT … ON CONFLICT DO NOTHING` + `SELECT … FOR UPDATE` em transaction.
3. **JWKS cache poisoning**: middleware client retry com refresh JWKS quando `kid not found`. JWKS endpoint inclui `Cache-Control: max-age=3600`.
4. **Refresh storm em deploy**: client middleware faz backoff exponencial (1s, 2s, 4s, 8s) com jitter; 4 tentativas falham → 401 pra user re-auth.

### 7.3 Audit trail

Tabela `oidc_audit_events` (definida em §3.3). Console UI ganha route `/admin/audit-log` em Phase 2 (Phase 1 expõe via API only).

### 7.4 Rate limiting

Endpoints `/oidc/authorize`, `/oidc/token`, `/oidc/end_session`:
- Per-IP: 60/min, TTL 5min.
- Per-`client_id`: 600/min.

Storage: `unified-redis` (já no cluster). Excesso → 429 + Retry-After.

---

## 8. Testing strategy

| Camada | Testes |
|---|---|
| Storage interface | Unit, Postgres real via `testcontainers-go`. Cobre TTL expiry, single-use, refresh chain, replay detection. |
| OIDC HTTP endpoints | Integration via `httptest`. Full code flow + PKCE happy/mismatch + invalid client + replay. |
| Domain check + auto-provision | Unit matrix: email × `allowed_email_domains` × `auto_provision` × Collaborator pré-existente. |
| Console embedded auth flow | Integration via `httptest` + cookie jar. |
| Tartaro middleware | Integration com fake JWKS server. |
| End-to-end | Manual smoke MVP, Playwright Phase 2. |

Cobertura mínima 80% nos arquivos novos. CI gate via `go test -cover`.

---

## 9. Phasing

### Phase 1 (MVP) — ~11 dias

| # | Tarefa | Estimativa |
|---|---|---|
| 1.1 | Schema migration + bootstrap signing key | 0.5d |
| 1.2 | Storage interface implementation | 2d |
| 1.3 | OIDC HTTP handlers | 1d |
| 1.4 | Domain-default + auto-provision logic | 0.5d |
| 1.5 | RBAC claim builder | 0.5d |
| 1.6 | Audit log + write hooks | 0.5d |
| 1.7 | Rate limit middleware (Redis) | 0.5d |
| 1.8 | JWKS rotation cron workflow | 0.5d |
| 1.9 | Console embed + auth handlers | 1d |
| 1.10 | `dakasa-commons/oidcclient` library | 1d |
| 1.11 | Tartaro backend OIDC + remove password (cutover direto) | 1d |
| 1.12 | Tartaro frontend strip login form | 0.5d |
| 1.13 | E2E smoke + Playwright skeleton | 0.5d |
| 1.14 | Bootstrap CLI command | 0.5d |
| | **Total** | **~11d** (3 weeks com sessão paralela) |

### Phase 2 (hardening, fora do escopo deste design)

- Group sync Google Workspace → Teams.
- Federated logout (SLO).
- `private_pem` em managed-secret.
- Playwright E2E completo.
- Console UI: `/admin/audit-log` + `/admin/teams` CRUD.

### Phase 3 (consumer / B2B, fora do escopo deste design)

- Adicionar IdPs (Apple, Microsoft, Facebook).
- Multi-tenant orgs com per-org SSO config (separate design doc).

### 9.1 Rollout

```
Day 1-3:   Phase 1.1-1.8 — Yggdrasil-core OIDC provider deployed em validation, smoke via curl
Day 4-5:   Phase 1.9 — console embed validation, login funciona via Google em yggdrasil.dakasa.me
Day 6-7:   Phase 1.10-1.12 — Tartaro cutover direto pra OIDC em validation
Day 8-9:   Phase 1.13-1.14 — E2E smoke + bootstrap CLI; você loga, promove a si próprio em yggdrasil-admin
Day 10-11: Smoke 1 semana em validation antes de produção (se aplicável)
```

**Rollback**: re-deploy do binário Tartaro antigo (~10min). Yggdrasil-core OIDC endpoints são additivos — desligar = remover route registrations.

---

## 10. Decisões registradas

| Decisão | Escolha | Rejeitadas |
|---|---|---|
| Audience SSO | C (interno) | A (B2B), B (consumer), D (múltiplos) |
| Surfaces MVP | C (Tartaro + Yggdrasil console) | A (só Tartaro), B (RBAC sem 2ª surface), D (todos 4) |
| Segunda surface | A (Yggdrasil console) | B (Porão) |
| Protocolo de confiança | A (OIDC completo) | B (JWT custom + JWKS), C (cookie + introspection) |
| RBAC mapping | D (hybrid: domain-default + admin) | A (manual), B (só domain), C (Google groups sync) |
| Console packaging | A (embed no Yggdrasil-core) | B (BFF separado) |
| Tartaro cutover | direto, sem feature flag | both/legacy/oidc com flag |
| Logout | local | federated (Phase 2) |
| `private_pem` MVP | plain text | managed-secret (Phase 2) |

---

## 11. Riscos conhecidos

1. **Storage interface modelagem incorreta** → refactor doloroso. Mitigação: 1.1-1.2 antes de qualquer outro componente, smoke-test imediato.
2. **Cookie `SameSite` config errada** → callback do Google quebra cross-origin. Mitigação: `Lax` (não `Strict`) + smoke real em validation antes de Tartaro.
3. **Console embed dist drift** → frontend e backend desyncados em runtime. Mitigação: build em multi-stage Dockerfile garante version lock.
4. **JWKS cache stale** → 401 inesperado pós-rotation. Mitigação: middleware client retry com JWKS refresh on `kid not found`.
5. **Replay detection edge** → falsos positivos por client retry concorrente. Mitigação: rotation com transação serializável; client middleware coordena 1 refresh por vez (singleflight).
