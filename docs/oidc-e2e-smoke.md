# Yggdrasil OIDC — E2E Smoke Checklist

Manual smoke procedure for verifying the OIDC Provider end-to-end.
Two scopes are documented:

- **Phase 1 partial (current)** — what Tasks 1–12 + 16 enable today, runnable
  against any Yggdrasil-core deploy with the OIDC migration applied.
- **Phase 1 full E2E** — what Tasks 13–18 will enable; gated on cross-repo
  work (`dakasa-commons/oidcclient`, Tartaro cutover, JWKS rotation workflows).

A skeleton Playwright spec lives at [e2e/oidc.spec.ts](../e2e/oidc.spec.ts).
Most cases are `test.skip`'d until the full E2E prerequisites land.

---

## Prerequisites (any scope)

1. Yggdrasil-core deployed with image containing Tasks 1–12 + 16. The
   feature branch is `feature/phase-1-oidc-provider`. Image tag should
   include the merge SHA.
2. Migration `00019_oidc.sql` applied. Verify with:

   ```bash
   kubectl -n dakasa exec -it deploy/yggdrasil-core -- /app/goose status \
     | grep -E '00019_oidc|00006_core_auth|00017_audit_events'
   # all three should report Applied
   ```

   Note: the original plan referenced `00011_oidc.sql`; the slot was
   already taken by `00011_auth_providers`, so the OIDC migration
   ended up at `00019`. Old docs/plans may carry the stale `00011`.
3. `psql` access to the `dakasa` namespace's Yggdrasil DB (for the
   bootstrap-admin step and seed verification).
4. Google Workspace OIDC provider already registered for
   `dakasa.me` — verify with:

   ```bash
   curl -s https://yggdrasil.dakasa.me/api/v1/auth/providers \
     | jq '.[] | select(.name=="google")'
   ```

   Should return a non-empty object.

---

## Phase 1 partial (runnable now)

These verify the surfaces shipped by Tasks 1–12 + 16. They do **not**
exercise full OAuth flow against Google because the client side
(Tartaro / console JS) hasn't been wired yet.

### S1. OIDC discovery endpoint

```bash
curl -s https://yggdrasil.dakasa.me/.well-known/openid-configuration | jq .
```

**Expect:**

- HTTP 200
- `.issuer == "https://yggdrasil.dakasa.me"` (or whatever was passed via
  `WithOIDCIssuer` ServerOption — empty issuer means OIDC is not mounted
  in this deploy; check `httpapi.New` call site)
- `.authorization_endpoint`, `.token_endpoint`, `.userinfo_endpoint`,
  `.jwks_uri` all present
- `.id_token_signing_alg_values_supported` contains `"RS256"`
- `.code_challenge_methods_supported` contains `"S256"` (PKCE
  enforcement, set in `op.Config.CodeMethodS256`)

### S2. JWKS endpoint exposes active signing key

```bash
curl -s https://yggdrasil.dakasa.me/oidc/keys | jq .
```

**Expect:**

- HTTP 200
- `.keys` is a non-empty array
- `.keys[0].alg == "RS256"`, `.keys[0].kty == "RSA"`
- `.keys[0].n` and `.keys[0].e` are populated (modulus + exponent)

If `keys` is empty, the bootstrap signing key wasn't created on
startup. Check pod logs for `EnsureSigningKey` errors and verify the
`oidc_provider_settings` singleton row exists (Task 4).

### S3. Bootstrap signing key is idempotent across pod restarts

```bash
kubectl -n dakasa rollout restart deploy/yggdrasil-core
kubectl -n dakasa rollout status deploy/yggdrasil-core
# Re-run S2 — keys[0].kid must be the same as before the restart
```

Verifies Task 5's `SELECT ... FOR UPDATE` lock primitive against the
`oidc_provider_settings` singleton row.

### S4. Auto-provision on third-party callback (Task 8)

Trigger Google login for a fresh `@dakasa.me` user. Easiest from a
browser; the response carries a 302 to Google so cURL is awkward.

After login completes:

```bash
psql ... -c "SELECT id, primary_email, status FROM collaborators \
  WHERE primary_email='alice@dakasa.me';"
psql ... -c "SELECT t.slug FROM team_memberships tm \
  JOIN teams t ON t.id=tm.team_id WHERE tm.collaborator_id='<id>' \
  AND tm.active=TRUE;"
```

**Expect:**

- One row in `collaborators` with `status='active'`
- `dakasa-internal` membership present (auto-provision default team)
- **No** `yggdrasil-admin` membership — that requires step S5.

### S5. Bootstrap-admin CLI promotes user (Task 16)

After step S4, in a shell with DB env vars set:

```bash
kubectl -n dakasa exec -it deploy/yggdrasil-core -- \
  /app/yggdrasil-bootstrap-admin --email alice@dakasa.me
```

**Expect:**

- Stdout: `OK promoted alice@dakasa.me to yggdrasil-admin (collaborator_id=<uuid>)`
- Exit code 0
- Re-run is idempotent — same stdout, no error, no duplicate membership row

Then verify in DB:

```bash
psql ... -c "SELECT t.slug FROM team_memberships tm JOIN teams t ON t.id=tm.team_id \
  WHERE tm.collaborator_id=(SELECT id FROM collaborators WHERE primary_email='alice@dakasa.me') \
  AND tm.active=TRUE ORDER BY t.slug;"
```

Should list both `dakasa-internal` and `yggdrasil-admin`.

### S6. Console placeholder serves at /console/ (Task 12)

If `console.Handler("/console")` is mounted (depends on caller wiring —
not enabled in `httpapi.New` by default):

```bash
curl -sI https://yggdrasil.dakasa.me/console/
curl -s https://yggdrasil.dakasa.me/console/ | grep "Yggdrasil Console"
```

**Expect:**

- `Cache-Control: no-cache` header on index.html responses
- Body contains `Yggdrasil Console`
- A request for `/console/foo/route` (no extension) ALSO returns 200
  with the same HTML (SPA fallback)
- A request for `/console/assets/nonexistent.js` returns **404** (not
  HTML — verifies the asset-vs-route split)

Note: the Phase 1 image ships a placeholder `index.html`. The real Vite
bundle ships only when the multi-stage Dockerfile is built with the
`console-build` stage successfully cloning/building
`yggdrasil-console`.

### S7. Refresh-token replay defense + audit row (Tasks 6c + 10a)

Steel-thread requires a real OIDC client (Phase 1 full E2E). For
Phase 1 partial, exercise via repository-level tests:

```bash
DB_URL=postgres://yggdrasil:yggdrasil@... go test \
  ./controllers/oidc/... -run TestRotateOIDCRefreshToken -v
```

Confirms: rotation atomic; second rotation of same root revokes the
chain; replay attempt produces an `oidc.refresh_token.replay_detected`
row in `audit_events` with `outcome='denied'` (Task 10a).

```bash
psql ... -c "SELECT action, outcome, metadata FROM audit_events \
  WHERE action LIKE 'oidc.%' ORDER BY created_at DESC LIMIT 5;"
```

### S8. Rate limiter behavior (Task 10b)

In-memory limiter; verify via unit test, not deployed surface:

```bash
go test ./controllers/oidc/... -run TestRateLimit -v
```

All five `TestRateLimit_*` should pass, including the concurrent test
that asserts no race in `count++` under 20 goroutines × 50 calls.

---

## Phase 1 full E2E (after Tasks 13–17)

These need cross-repo work (`dakasa-commons/oidcclient`, Tartaro
cutover, JWKS rotation workflows). Listed here so the checklist is
complete; **do not run until prerequisites are met.**

### F1. Console → Google → console claims displayed

1. Visit `https://yggdrasil.dakasa.me/console/`.
2. Expect redirect to Google.
3. Login with `<your>@dakasa.me`.
4. Expect redirect back to `/console/`.
5. Console UI should show the `name`, `email`, and `teams` claim.
6. After step S5 above (bootstrap-admin promotion), the `teams` claim
   should include `yggdrasil-admin` AFTER a fresh login (the JWT is
   minted from current DB state, so the existing token won't include
   it — re-login is required).

### F2. Tartaro single-sign-on via shared cookie

1. With the console session active from F1, visit
   `https://tartaro.dakasa.me/`.
2. Expect redirect to `https://yggdrasil.dakasa.me/authorize?...` →
   immediate redirect back to Tartaro **without** a Google prompt
   (the OP recognizes the existing session cookie).
3. Tartaro homepage loads with `claims.name` displayed.

### F3. JWT validation, expiry, and refresh

- Tartaro should refresh access tokens silently every ~10 min (TTL set
  by `AccessTokenLifetime`).
- After 7 days of inactivity, the refresh token expires (sliding
  window per `RefreshTokenLifetime`); next request must re-authenticate.
- Manually expire a refresh token via `psql` and verify Tartaro
  recovers via re-login.

### F4. JWKS rotation does not break in-flight tokens

Trigger the JWKS rotation workflow (Task 17, lives in
`dakasa-system-yggdrasil-v2`). After it runs:

- New tokens use the new key (verifiable via `kid` header in id_token).
- Old tokens remain valid until their `exp` expires (the OP keeps the
  retired key in the JWKS response for the configured grace period).

### F5. Replay defense in real flow

Capture a refresh-token exchange, replay it, expect chain revocation
+ all subsequent refresh attempts in the chain to fail.

---

## Operator quick-reference

| Surface | URL | Method | Owner task |
|---|---|---|---|
| Discovery | `/.well-known/openid-configuration` | GET | 7 |
| JWKS | `/oidc/keys` | GET | 6c+7 |
| Authorize | `/oidc/authorize` | GET (browser) | 7 (provider) |
| Token | `/oidc/token` | POST | 7 (provider) |
| Userinfo | `/oidc/userinfo` | GET (Bearer) | 9 |
| Console | `/console/` | GET | 12 |
| Bootstrap | (CLI in pod) | `yggdrasil-bootstrap-admin --email` | 16 |

## Known stale references

- Plan refers to migration `00011_oidc.sql`; actual is `00019_oidc.sql`.
- Plan calls `repository.InsertAuditEvent` and `repository.GetCollaboratorByEmail`; actual names are `RecordAuditEvent` and `GetCollaboratorByPrimaryEmail`.
- Plan Task 12 step 12.3 says "see Task 16 for the auth callback pattern" — Task 16 is the bootstrap CLI, not an OAuth handler. The console callback flow lives in Task 14 (Tartaro integration repo) and was not implemented in this iteration of Task 12.
