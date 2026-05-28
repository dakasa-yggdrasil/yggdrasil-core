# Error Code Catalog (§14 INTEGRATION_CONTRACT)

This file is the canonical source of truth for the `code` strings
yggdrasil-core emits in RFC 7807 Problem+JSON error responses. Surfaces
key off these codes in their per-locale message tables — never on the
English `title` / `detail` strings.

## Wire shape

Every 4xx/5xx response from yggdrasil-core conforms to RFC 7807:

```
HTTP/1.1 401 Unauthorized
Content-Type: application/problem+json

{
  "type":     "https://yggdrasil.dakasa.me/errors/auth/invalid_credentials",
  "title":    "Unauthorized",
  "status":   401,
  "code":     "auth.invalid_credentials",
  "detail":   "invalid credentials",
  "error":    "invalid credentials",   // LEGACY — preserved for one minor
  "instance": "/api/v1/auth/login"
}
```

**Surface contract**: read `code` and look up the localized message.
Treat `error` as deprecated — it disappears in the next minor release.

## Code namespaces

Codes are dotted: `<category>.<specific>`. Categories are stable and
exhaustive. Add new specific codes as needed; do NOT rename existing
ones (the FE i18n key is the code string).

| Code | HTTP | English title | Suggested pt-BR | Notes |
|------|------|---------------|------------------|-------|
| `auth.invalid_credentials` | 401 | Invalid credentials | Email ou senha incorretos. | Wrong password OR email |
| `auth.account_locked` | 423 | Account locked | Conta bloqueada após várias tentativas. | Brute-force lockout — locked_until extra field carries the unlock timestamp |
| `auth.mfa_required` | 428 (4xx) / 202 (login flow signalling) | MFA required | Verificação em duas etapas é obrigatória. | The factors[] extra field lists supported methods. Note: handleAuthLogin emits this with HTTP 202 (MFA challenge mid-flow), not as an error — the surface treats it as a state transition |
| `auth.mfa_not_enrolled` | 428 / 403 | MFA not enrolled | Você precisa cadastrar duas etapas antes de continuar. | enroll_url extra field carries the next step |
| `auth.mfa_invalid` | 401 | Invalid MFA | Código de verificação inválido. | `factor` extra field carries the failing factor (totp/recovery_code) |
| `auth.mfa_factor_unavailable` | 400 | MFA factor unavailable | Fator MFA indisponível para esta conta. | Login attempted with a factor not enrolled (e.g. TOTP code but TOTP never set up); `factor` extra field names which |
| `auth.session_expired` | 401 | Session expired | Sua sessão expirou. Faça login novamente. | |
| `auth.session_not_found` | 401 | Session not found | Sessão não encontrada. | Token was deleted/expired before request |
| `auth.unauthenticated` | 401 | Unauthenticated | Faça login para continuar. | Generic unauth — missing/bad token |
| `auth.webauthn_not_implemented` | 501 | WebAuthn not implemented | Verificação WebAuthn ainda não implementada. | Phase 1 stub — inline WebAuthn assertion landing in Phase 2 |
| `auth.password_too_weak` | 422 | Password too weak | A senha não atende aos requisitos. | `reason` extra field carries the specific violation (too_short, common_password, contains_user_token, etc.) |
| `auth.password_unchanged` | 422 | Password unchanged | A nova senha deve ser diferente da atual. | |
| `auth.password_change_required` | 403 | Password change required | Você precisa trocar sua senha. | `change_url` and `reason` (rotation_expired / admin_forced) carry next step |
| `auth.invalid_current_password` | 401 | Invalid current password | Senha atual incorreta. | Self-service password change — distinct from `auth.invalid_credentials` (login) so the surface can surface the right field |
| `auth.setup_token_invalid` | 401 | Invalid setup token | Token de configuração inválido ou expirado. | Single-use bootstrap setup token consumed or expired |
| `auth.reset_token_invalid` | 401 | Invalid reset token | Token de recuperação inválido ou expirado. | Single-use password-reset token consumed or expired |
| `auth.kek_not_configured` | 503 | KEK not configured | Servidor não configurado para MFA (envelope ausente). | YGGDRASIL_AUTH_KEK_BASE64 missing — MFA secrets-at-rest unavailable. Operator config error |
| `permission.denied` | 403 | Permission denied | Você não tem permissão para esta ação. | required extra field carries the missing permission |
| `manifest.validation_failed` | 422 | Validation failed | O manifesto enviado tem erros de validação. | errors[] extra field lists per-field problems |
| `manifest.not_found` | 404 | Manifest not found | Manifesto não encontrado. | |
| `manifest.conflict` | 409 | Conflict | Conflito com manifesto existente. | |
| `integration.not_found` | 404 | Not found | Recurso não encontrado. | Generic 404 fallback |
| `integration.unavailable` | 503 | Integration unavailable | A integração está temporariamente indisponível. | Adapter transport down |
| `workflow.not_found` | 404 | Workflow not found | Workflow não encontrado. | |
| `workflow.invalid` | 400 | Invalid workflow | Workflow inválido. | |
| `rate_limit.exceeded` | 429 | Rate limit exceeded | Muitas tentativas. Tente novamente em alguns instantes. | retry_after extra field |
| `input.invalid` | 400 | Invalid input | Dados inválidos. | Generic 400 fallback |
| `input.missing_field` | 400 | Missing field | Campo obrigatório ausente. | The `errors` extra array names which field(s) |
| `input.malformed_body` | 400 | Malformed body | Corpo da requisição malformado. | JSON parse error |
| `input.unknown_fields` | 422 | Unknown fields | Campos não reconhecidos. | `rejected` extra field lists the offending keys (whitelist-based field validation) |
| `internal.error` | 500 | Internal server error | Erro interno do servidor. | Last-resort — surfaces should show retry button |

## Adding a new code

1. Pick the category (auth/permission/manifest/integration/workflow/
   rate_limit/input/internal). Don't invent new top-level categories
   without discussion — surfaces have one table per locale that lists
   every code.
2. Add the constant to `internal/httperr/problem.go`.
3. Add the row to this table with English title + suggested pt-BR.
4. If the code maps to a typed error (errors.Is chain), update
   `codeFromError` in `controllers/httpapi/server.go`.
5. Surface engineers add the pt-BR translation to the per-locale table
   in their repo (no backend coupling).

## Migration timeline

- v0.x (current): both `code` and `error` keys in every response. New
  surfaces SHOULD use `code`; legacy callers keep working.
- v0.(x+1): the `error` key is removed. Surfaces still on the legacy
  field break — track via deprecation warning in v0.x release notes.

## Migration status (per §14 close — 2026-05-28)

| Phase | Scope | Status |
|-------|-------|--------|
| 2B-core | Universal `writeMappedError` / `writeJSONError` writers | DONE — every typed-error path emits Problem+JSON |
| 2B-close | Hand-rolled `writeJSON(w, status, map[string]any{"code": "..."})` in auth/MFA/password handlers | **DONE 2026-05-28** — 25 sites migrated to `httperr.WriteProblem` |
| 2C (future) | Removal of legacy `error` key | Pending one-minor deprecation window |

## Regression guard

Reviewers and CI should reject new hand-rolled error envelopes by
grepping for the legacy shape:

```bash
# Forbidden: hand-rolled error map[string]any with a "code" key.
# Whitelist: SUCCESS-path responses (StatusOK / StatusCreated / StatusAccepted).
git diff --name-only origin/main...HEAD \
  | xargs grep -nE 'writeJSON\(.*http\.Status(BadRequest|Unauthorized|Forbidden|NotFound|Conflict|UnprocessableEntity|Locked|TooManyRequests|PreconditionRequired|NotImplemented|ServiceUnavailable|InternalServerError).*map\[string\]' \
  && { echo "::error::§14 violation — use httperr.WriteProblem instead"; exit 1; } \
  || true
```

A pre-commit hook implementing this lives in
`scripts/lint-no-legacy-error-envelopes.sh` (added 2026-05-28). The
canonical entry points are:

- `httperr.WriteProblem(w, status, code, title, detail, opts...)` —
  preferred for hand-coded error sites with stable codes.
- `writeMappedError(w, err)` — for typed errors that already have a
  mapping in `codeFromError()` (server.go).
- `writeJSONError(w, status, msg)` — for plain-string error messages
  (the generic 400/500 fallback path).

## References

- RFC 7807 Problem Details for HTTP APIs: https://www.rfc-editor.org/rfc/rfc7807
- §14 of `INTEGRATION_CONTRACT.md` in integration-template
- 2026-05-27 co-design audit (humanizer-table sprawl analysis):
  `~/.claude/projects/-Users-dakasa-projects/memory/reference_yggdrasil_ui_backend_codesign_audit_2026_05_27.md` §1.9
