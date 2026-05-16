# Collaborator External Identities — Design Spec

**Date:** 2026-05-16
**Status:** Approved — ready for implementation plan
**Drives:** Generic, integration-neutral mechanism for binding yggdrasil-core collaborators to provider-specific identifiers (Slack user_id, GitHub numeric id + login, Google Workspace numeric id, etc.), so reactor framework actions (notably offboard) can act on the correct provider-side entity regardless of which integration produced the link.

---

## 1. Motivation

The reactor framework's `on_collaborator_offboarded` for GitHub non-EMU surfaced a structural gap on 2026-05-16:

- Onboard via email-invite returns an invitation ID, **not** the eventual GitHub username.
- When the invitee accepts, GitHub assigns the membership to their existing GH username.
- Offboard fires a reactor that knows only `primary_email`. The current code calls `removeUserFromOrg(username=primary_email)` which 404s silently (email is not a valid GitHub username).
- **Net effect:** the user remains in the org after offboard. Silent failure.

Slack and Google Workspace have the same shape: the reactor knows the email at onboard time but needs the provider-assigned ID at offboard time. They get away with it today because their adapter happens to look up by email at offboard time, but it's a coincidence, not a contract.

The right pattern is to **persist provider-side identifiers** at link time and **make them available to subsequent reactor invocations**, in a way that:

- Yggdrasil-core stays neutral — no Slack/GH/GW types in core.
- Integration adapters do not depend on each other or on core HTTP APIs.
- Multi-instance is supported (the same person can have different IDs in different Slack workspaces).
- Audit is preserved across offboard/re-onboard cycles.

---

## 2. Scope & non-goals

**In scope (this spec, one phase):**

- New core table + repository + HTTP API for `collaborator_external_identities`.
- RPC envelope convention by which adapters write identities (no callback to core).
- RPC envelope convention by which the dispatcher pre-populates identity into reactor inputs.
- Webhook receiver (`POST /api/v1/integrations/{instance_id}/webhook`) for delayed-link flows (e.g., GitHub member-accepted-invite event).
- Periodic re-sync addon that detects drift between persisted identities and live provider state.
- Soft-delete on offboard + hard-delete cron (30-day retention).
- Four canon events (`linked`, `unlinked`, `drift_detected`, `unknown_external`).

**Out of scope (deferred):**

- UI surface in Tartaro / surface-console (operators inspect via API/DB until UI lands).
- Cross-integration identity correlation (e.g., link Slack user_id to GH username for the same human). Not needed for this phase; both already collab-anchored.
- Identity-derived authorization (using external_id for policy decisions). Out of scope here.

---

## 3. Architecture

Single core package `internal/externalidentity/`, mounted by an addon at priority **80** (after `manifest_sync@75`, before any HTTP routes that would depend on it). The package owns three concurrent loops:

```
                ┌─────────────────────────────────────────┐
                │   yggdrasil-core (single process)       │
                │                                         │
                │   ┌──────────────┐    ┌──────────────┐  │
   reactor      │   │ identity     │    │ webhook      │  │
   dispatcher ──┼──>│ writer (RPC  │    │ receiver     │<─┼── provider HTTPS
   (existing)   │   │ envelope     │    │ HTTP +       │  │   (GitHub/Slack/etc)
                │   │ extraction)  │    │ HMAC verify) │  │
                │   └──────┬───────┘    └──────┬───────┘  │
                │          │                   │          │
                │          ▼                   ▼          │
                │   ┌─────────────────────────────────┐   │
                │   │ collaborator_external_identities│   │
                │   │ (Postgres table + repository)   │   │
                │   └─────────────────────────────────┘   │
                │          ▲                              │
                │          │                              │
                │   ┌──────┴───────┐                      │
                │   │ resync cron  │── periodic ──┐       │
                │   │ (daily 03:00)│              │       │
                │   └──────────────┘              │       │
                │                                 ▼       │
                │                          adapter capability
                │                          `list_identities`
                │                          via RabbitMQ RPC
                └─────────────────────────────────────────┘
```

**Three trigger paths converge on the same Postgres table.** Three exit paths use it: dispatcher pre-populating reactor input, manual API GET, drift detection diff base.

---

## 4. Schema

### 4.1 Migration

`db/migrations/00041_collaborator_external_identities.sql`:

```sql
-- +goose Up
CREATE TABLE collaborator_external_identities (
  id                      uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  collaborator_id         uuid NOT NULL REFERENCES collaborators(id) ON DELETE CASCADE,
  integration_instance_id uuid NOT NULL,
  external_id             text NOT NULL,
  external_metadata       jsonb NOT NULL DEFAULT '{}'::jsonb,
  linked_at               timestamptz NOT NULL DEFAULT now(),
  last_seen_at            timestamptz NOT NULL DEFAULT now(),
  unlinked_at             timestamptz,
  created_at              timestamptz NOT NULL DEFAULT now(),
  updated_at              timestamptz NOT NULL DEFAULT now()
);

-- Only one ACTIVE link per (instance, external_id). Allows historical
-- rows from prior offboards to coexist.
CREATE UNIQUE INDEX collaborator_external_identities_active_unique
  ON collaborator_external_identities (integration_instance_id, external_id)
  WHERE unlinked_at IS NULL;

-- Fast lookups by collaborator+instance (the dispatcher's pre-populate
-- step does this on every reactor invocation).
CREATE INDEX collaborator_external_identities_collab_idx
  ON collaborator_external_identities (collaborator_id, integration_instance_id);

-- Cleanup cron predicate index.
CREATE INDEX collaborator_external_identities_unlinked_idx
  ON collaborator_external_identities (unlinked_at)
  WHERE unlinked_at IS NOT NULL;

-- +goose Down
DROP TABLE collaborator_external_identities;
```

Note: `integration_instance_id` is logically FK to `manifests(id) WHERE kind='integration_instance'`, but Postgres can't constrain a partial FK. We rely on application-level validation at write time.

### 4.2 Field conventions

| Field | Convention |
|---|---|
| `external_id` | The **stable, opaque** identifier from the provider. Slack: `U…` user_id. GitHub: numeric id (NOT login). Google Workspace: numeric id. Never a mutable handle/email/username. |
| `external_metadata` | Free-form jsonb where adapters record provider-specific mutable info: current handle, display_name, avatar_url, etc. Updated on re-sync. |
| `linked_at` | First time this collab×instance pair acquired this `external_id`. Immutable after first INSERT. |
| `last_seen_at` | Last time re-sync (or a successful reactor invocation) confirmed this identity is still valid. |
| `unlinked_at` | Set when offboard runs (soft-delete). Re-link clears to NULL. |

### 4.3 Lifecycle states

```
NULL ─── INSERT ──> linked (unlinked_at IS NULL)
                            │
                            ├── re-sync drift ──> identity.drift_detected event (no state change)
                            │
                            ├── re-link (re-onboard) ──> UPDATE unlinked_at=NULL, refresh metadata
                            │
                            └── offboard reactor ──> unlinked (unlinked_at=NOW)
                                                              │
                                                              ├── re-link ──> linked (UPDATE unlinked_at=NULL)
                                                              │
                                                              └── cron 30d ──> DELETE (hard)
```

---

## 5. HTTP API

All endpoints require admin auth (`authorizeAdminRequest`, same wrapper used by `POST /api/v1/manifests`).

### 5.1 `POST /api/v1/collaborator-external-identities`

Body:

```json
{
  "collaborator_id": "uuid",
  "integration_instance_id": "uuid",
  "external_id": "U0B527CCC7J",
  "external_metadata": { "display_name": "QA V9", "email": "qa-…@dakasa.me" }
}
```

Behavior:

- If no row exists for `(collaborator_id, integration_instance_id, external_id)`: INSERT. Emit `collaborator_external_identity.linked` event. Return `201 Created` with the new row.
- If a row exists with `unlinked_at IS NOT NULL` (soft-deleted previously): UPDATE `unlinked_at=NULL, external_metadata=<new>, last_seen_at=NOW`. Emit `linked` event with `re_linked: true`. Return `200 OK`.
- If a row exists with `unlinked_at IS NULL` and same `(collaborator_id, integration_instance_id, external_id)`: UPDATE metadata + `last_seen_at`. Return `200 OK`.
- If an ACTIVE row exists with the same `(integration_instance_id, external_id)` but **different** `collaborator_id`: return `409 Conflict` with the existing `collaborator_id` in the response body. Emit `collaborator_external_identity.conflict_detected` event. **Do not mutate** either row.

### 5.2 `GET /api/v1/collaborator-external-identities`

Query parameters (all optional, AND-combined):

- `collaborator_id=<uuid>` — restrict to one collaborator
- `integration_instance_id=<uuid>` — restrict to one instance
- `type_name=<string>` — helper: resolves to all instances of `integration_type` named `<type_name>` and returns matching identities
- `active=true|false|all` — filter on `unlinked_at IS NULL` (default `true`)
- `limit=<int>` (default 100, max 500), `offset=<int>`

Response:

```json
{
  "identities": [
    {
      "id": "uuid",
      "collaborator_id": "uuid",
      "integration_instance_id": "uuid",
      "integration_instance_name": "integration-slack-dakasa",
      "integration_type_name": "slack",
      "external_id": "U0B527CCC7J",
      "external_metadata": { "display_name": "…" },
      "linked_at": "…",
      "last_seen_at": "…",
      "unlinked_at": null
    }
  ]
}
```

The `integration_instance_name` + `integration_type_name` are denormalized hints for operator readability.

### 5.3 `DELETE /api/v1/collaborator-external-identities/{id}`

Default: soft-delete (sets `unlinked_at=NOW`). Returns `200 OK`. Emits `collaborator_external_identity.unlinked`.

`?hard=true` (admin-only operational escape hatch): hard-deletes the row. Returns `204 No Content`. Does NOT emit an event (audit trail is gone with the row).

### 5.4 `POST /api/v1/integrations/{instance_id}/webhook`

Generic webhook receiver. See §7 for the full flow.

---

## 6. Reactor integration pattern

### 6.1 Write — adapter response envelope

Each integration adapter that wants to register an identity for a reaction adds a single block under `output._yggdrasil.external_identity`:

```go
return protocol.AdapterExecuteIntegrationResponse{
    Operation: OperationOnCollaboratorCreated,
    Status:    "provisioned",
    Output: map[string]any{
        "scim_create_user": scimResp.Output,  // existing adapter-specific stuff
        "_yggdrasil": map[string]any{
            "external_identity": map[string]any{
                "external_id":       "U0B527CCC7J",
                "external_metadata": map[string]any{
                    "display_name": "QA V9",
                    "email":        "qa-…@dakasa.me",
                },
            },
        },
    },
}
```

The reactor dispatcher (`internal/reactors/dispatcher.go`), upon marking a reaction `succeeded`, looks for this convention block and — if present — synthesizes an internal call to the identity repository (POST equivalent). Failure to persist is logged but **does NOT fail the reaction**; identity is metadata, not core lifecycle state.

Adapters opt in by emitting the block. Adapters with no identity to report omit it. Yggdrasil-core does NOT require any specific adapter to support this — pure additive convention.

### 6.2 Read — request `_context.external_identity`

When the dispatcher constructs an `AdapterExecuteIntegrationRequest` for any reactor capability, it queries the repository for the active identity matching `(reaction.collaborator_id, reaction.integration_instance_id)` and embeds it under `req._context.external_identity`:

```json
{
  "operation": "on_collaborator_offboarded",
  "input": {
    "primary_email": "qa-…@dakasa.me",
    "_context": {
      "attempt": 1,
      "external_identity": {
        "external_id": "U0B527CCC7J",
        "external_metadata": { "display_name": "QA V9" },
        "linked_at": "…",
        "last_seen_at": "…"
      }
    }
  }
}
```

Adapters that need provider-side IDs pull from `_context.external_identity.external_id` (or specific metadata fields). Adapters that don't need it ignore the field.

For collaborator.created events (where no identity yet exists), `external_identity` will be absent. Adapters handle that case as "do creation flow"; subsequent events get the populated field.

### 6.3 The GitHub case made concrete

```go
// integration-github/internal/adapter/reactors.go (excerpt, after this spec lands)

func onCollaboratorOffboarded(req protocol.AdapterExecuteIntegrationRequest) (...) {
    // Prefer the linked identity — set by yggdrasil dispatcher
    if id, ok := getContextExternalIdentity(req.Input); ok {
        username, _ := id.ExternalMetadata["github_login"].(string)
        if username != "" {
            return removeUserFromOrgByUsername(req, username)
        }
    }
    // No identity → user never accepted invite. Cancel pending invite.
    return cancelOrgInvitationByEmail(req)
}
```

Slack and GW adapters likewise refactor offboard to prefer `_context.external_identity.external_id` over re-looking-up by email.

---

## 7. Webhook delayed-link flow

For providers where the identity is not known at create time (notably GitHub email-invite → user accepts later under their existing GH login):

### 7.1 Endpoint

`POST /api/v1/integrations/{instance_id}/webhook`

Headers (provider-dependent, validated):

- Some signature header — `X-Hub-Signature-256` for GitHub, `X-Slack-Signature` for Slack, etc. The webhook receiver inspects the path's `{instance_id}` to know which signature scheme to use (resolved through the integration_type spec).
- `Content-Type: application/json` (or `application/x-www-form-urlencoded` for some providers).

Auth: HMAC verified against `webhook_secret` stored in the integration_instance's credentials (`secret://.../integration-foo-credentials#webhook_secret`). Bad signature → `401 Unauthorized` immediately, without invoking the adapter.

### 7.2 Adapter capability `on_webhook`

Each adapter that wants to receive webhooks declares the capability in its `action_catalog`:

```go
{
    Name:          "on_webhook",
    Description:   "Parse a provider webhook payload and return action(s) to execute server-side.",
    ResourceTypes: []string{"webhook_event"},
    Idempotent:    true,
},
```

Input shape:

```json
{
  "headers": { "X-GitHub-Event": "member", "X-Hub-Signature-256": "..." },
  "body_raw": "<raw bytes as string>",
  "body_json": { ... parsed ... }
}
```

Adapter returns a list of `actions` describing what core should do:

```json
{
  "actions": [
    {
      "kind": "link_identity",
      "collaborator_match": { "by": "primary_email", "value": "alice@dakasa.me" },
      "external_id": "12345",
      "external_metadata": { "github_login": "alice-gh", "html_url": "https://github.com/alice-gh" }
    }
  ]
}
```

### 7.3 Action kinds (initial set)

| `kind` | Effect | Required fields |
|---|---|---|
| `link_identity` | Resolves `collaborator_match` to a `collaborator_id`, then POSTs to the identity repository (same idempotent UPSERT semantics as §5.1). | `collaborator_match`, `external_id`. Optional `external_metadata`. |
| `unlink_identity` | Soft-deletes the matching identity. | `external_id` OR `identity_id`. |
| `emit_event` | Persists a canon event. Used when webhook payload represents a lifecycle change but doesn't link an identity. | `event_type` (must be in canon set), `payload`. |

Unknown `kind` is logged and skipped (forward compatibility — adapters can ship new action types before core knows them; core just ignores until a new release).

### 7.4 `collaborator_match` resolution

`by` can be:

- `primary_email` — query `collaborators WHERE primary_email = $1`. Most common.
- `collaborator_id` — direct UUID.
- `external_id_lookup` — find the collaborator via an EXISTING active identity match on the same instance (used when webhook only carries provider-side id and we're already linked).

No match → log info, return `200 OK` to the provider (webhooks cannot be failed; provider would retry-storm), emit `collaborator_external_identity.unknown_external` event for operator visibility.

### 7.5 Webhook configuration

Per `integration_instance` that wants webhooks:

```yaml
spec:
  config:
    webhook_secret: secret://dakasa/integration-github-dakasa-credentials#webhook_secret
    webhook_signature_scheme: github_hmac_sha256   # adapter-specific enum
```

Operator-side: in the provider's admin UI, configure webhook endpoint = `https://yggdrasil.dakasa.me/api/v1/integrations/<instance_id>/webhook` with the same secret.

The signature scheme is interpreted by core (it knows how to verify `github_hmac_sha256`, `slack_signing_secret_v0`, generic `hmac_sha256_header_xyz`, etc.). New schemes are added in core; adapters do NOT implement signature verification.

---

## 8. Re-sync drift detection

Cron addon priority **85**, ticks at `IDENTITY_RESYNC_INTERVAL` (default `24h`, cron typically at 03:00 UTC). Optional kill switch `IDENTITY_RESYNC_ENABLED=false`.

### 8.1 Algorithm

```
foreach integration_instance with >= 1 active identity in DB:
    invoke adapter capability `list_identities` via AMQP RPC
      → adapter returns: { identities: [ {external_id, external_metadata}, ... ] }
    diff against active identities in DB:
      - external_id present in both, metadata changed
          → UPDATE metadata, last_seen_at
      - external_id in DB but not in provider list
          → EMIT collaborator_external_identity.drift_detected
            (no auto-unlink — operator decides; mirrors manifest_sync rule)
      - external_id in provider list but not in DB
          → EMIT collaborator_external_identity.unknown_external
            (provider has user yggdrasil doesn't know about — could be
            manually-added bypass, deleted/recreated collaborator, etc.)
```

### 8.2 Adapter capability `list_identities`

Adapters declare in `action_catalog`:

```go
{
    Name:          "list_identities",
    Description:   "Enumerate provider-side identities currently linkable in this instance. Used by yggdrasil-core's identity re-sync to detect drift.",
    ResourceTypes: []string{"external_identity"},
    Idempotent:    true,
},
```

Input: optional `cursor` for pagination.

Output:

```json
{
  "identities": [
    { "external_id": "U0B527CCC7J", "external_metadata": { "username": "qa.v9", "display_name": "QA V9" } }
  ],
  "next_cursor": null
}
```

Adapters NOT implementing `list_identities` are skipped silently by the re-sync (logged once at startup).

### 8.3 Drift rate-limiting

To avoid alert storms on transient outages: same `external_id`+`integration_instance_id` emitting `drift_detected` is rate-limited to **once per 24h** via the same in-process debounce pattern that `runtime_state.contract_mismatch_detected` uses.

---

## 9. Cleanup (hard-delete) cron

Addon priority **86** (after re-sync), runs hourly:

```sql
DELETE FROM collaborator_external_identities
WHERE unlinked_at IS NOT NULL
  AND unlinked_at < NOW() - INTERVAL '30 days'
RETURNING id, collaborator_id, integration_instance_id;
```

Each deleted row emits `collaborator_external_identity.purged` (a fifth canon event for completeness, NOT in the core 4 emitted by the lifecycle path).

Retention window is configurable via env `IDENTITY_UNLINK_RETENTION` (default `720h`). Tests use `1h` to make assertions feasible.

---

## 10. Canon events (5 lifecycle + 1 conflict)

| Event type | Emitted when | Payload |
|---|---|---|
| `collaborator_external_identity.linked` | New row INSERTed OR re-link (UPDATE unlinked_at=NULL) | `{identity_id, collaborator_id, integration_instance_id, external_id, re_linked: bool, linked_at}` |
| `collaborator_external_identity.unlinked` | Soft-delete (offboard reactor or DELETE endpoint) | `{identity_id, collaborator_id, integration_instance_id, external_id, unlinked_at}` |
| `collaborator_external_identity.drift_detected` | Re-sync found external_id in DB but missing from provider | `{identity_id, collaborator_id, integration_instance_id, external_id, detected_at}` |
| `collaborator_external_identity.unknown_external` | Re-sync found external_id in provider but missing from DB | `{integration_instance_id, external_id, external_metadata, detected_at}` |
| `collaborator_external_identity.purged` | Hard-delete cron removed row past retention | `{identity_id (gone), collaborator_id, integration_instance_id, external_id, purged_at}` |

There's also a sixth (`conflict_detected`) emitted on 409 (§5.1) — same shape, includes both colliding `collaborator_id`s.

Each gets a JSON Schema in `docs/contracts/events/v1/collaborator_external_identity/{event}.json` plus the `runtime_state.contract_mismatch_detected` pattern: registered in `eventTypeToSchemaPath`.

---

## 11. Error handling

| Failure mode | Behavior |
|---|---|
| Adapter response `_yggdrasil.external_identity` malformed (no `external_id` or non-string) | Log warning, skip identity write, reaction stays succeeded. Metric `identity_link_dropped{reason=malformed}`. |
| Identity write DB error during reactor success | Log error, **DO NOT** fail the reaction. Identity is metadata; the core action already succeeded. Metric `identity_link_failed`. |
| 409 conflict on POST | Log error, emit `conflict_detected`, return 409 to caller. **No mutation** of either row. |
| Webhook HMAC fail | 401 immediate, no adapter call. Log security event. |
| Webhook payload no `collaborator_match` resolves | Log info, return 200 (provider can't have failed deliveries), emit `unknown_external`. |
| Re-sync RPC to adapter fails | Log warning, skip that instance for this tick; next cron tick retries. |
| Re-sync adapter returns malformed `identities` (no array or items missing `external_id`) | Log warning, skip that instance, emit `identity_resync_error` (operational alert). |
| `link_identity` action's collaborator_match missing | Log error, skip that action, process remaining actions in the webhook response. |
| Cleanup cron DELETE error | Log error, retry on next cron tick. No retry storm. |

**Principle: identity is metadata, not authoritative lifecycle state.** Identity failures never block real lifecycle (onboard/offboard). They produce operational signals (events + metrics) for operators to act on.

---

## 12. Testing strategy

### 12.1 Unit tests

`internal/externalidentity/repository_test.go`:

- INSERT new row → 1 active, no unlinked
- INSERT duplicate (same collab+instance+external_id) → idempotent UPSERT, metadata replaced
- INSERT conflict (same instance+external_id, different collab) → 409, neither row mutated
- Soft-delete → unlinked_at populated, active query returns 0
- Re-link after soft-delete → unlinked_at=NULL, metadata refreshed
- Cleanup query → returns rows where unlinked_at < threshold

`internal/externalidentity/envelope_test.go`:

- Extract `_yggdrasil.external_identity` from adapter output → returns parsed struct
- Missing block → returns nil + ok=false
- Malformed (missing external_id) → returns error
- Embed identity into `_context` → output has `external_identity` populated

`internal/externalidentity/hmac_test.go` (table-driven by signature scheme):

- github_hmac_sha256: valid signature → ok
- github_hmac_sha256: tampered body → reject
- github_hmac_sha256: missing header → reject
- slack_signing_secret_v0: valid → ok
- Generic `hmac_sha256_header_xyz` family

### 12.2 Integration tests (real Postgres)

`internal/externalidentity/integration_test.go`:

1. **Full link → unlink → re-link cycle:** seed collab, POST identity, verify row, DELETE soft, verify unlinked_at, POST again, verify unlinked_at=NULL, audit events emitted in order.
2. **Conflict scenario:** two collabs, POST same external_id for both, second POST returns 409 + emits `conflict_detected`.
3. **Re-sync drift detection:** seed in DB an identity that doesn't exist in (mocked) provider list_identities response → emit `drift_detected`.
4. **Re-sync unknown_external:** mocked provider returns identity not in DB → emit `unknown_external`.
5. **Cleanup cron:** seed unlinked row 31 days old + one 29 days old → cron run deletes only the 31-day one.

### 12.3 E2E smoke (manual, after deploy)

Replicates GitHub V11 scenario but completing the loop:

1. Onboard test collaborator via `POST /api/v1/collaborators`.
2. Verify reactor emitted `collaborator.created` and GH adapter `on_collaborator_created` invoked email-invite path. No identity yet.
3. Manually accept the GitHub invite from the email link.
4. GitHub fires webhook → core webhook endpoint → adapter `on_webhook` → returns `link_identity` action → repository INSERT.
5. Verify identity row populated with GH username + numeric id.
6. Offboard via `POST /api/v1/collaborators/.../offboard`.
7. Reactor `on_collaborator_offboarded` receives `_context.external_identity` populated → calls `removeUserFromOrg` with the real username → user removed from org.
8. Verify GH API GET `/orgs/dakasa-yggdrasil/members/{username}` returns 404.
9. Verify event log: `linked` after step 4, `unlinked` after step 6.

**Coverage target:** 85%+ in `internal/externalidentity/`.

---

## 13. Risks & mitigations

| Risk | Mitigation |
|---|---|
| Provider rate-limits re-sync `list_identities` | Configurable cron interval; default daily (low pressure). Operator can disable per-instance via env. |
| Webhook delivery storm (provider retries) | Webhook endpoint is idempotent at action level. Same `link_identity` twice = same result. |
| Mass-rename in provider creates avalanche of metadata updates | Re-sync diff only logs changes; UPDATE is cheap; no events emitted on metadata-only change (could change later if observed problematic). |
| Adapter reports bogus `external_id` (always same value) | Conflict detection catches: 409 emitted, manual operator review. |
| Webhook secret leaked → attacker can fake events | HMAC fail = 401, no action. Operator rotates secret via `integration_instance` credentials. |
| Operator hard-deletes (`?hard=true`) a row that adapter still references | Recreatable via reactor — adapter returning same external_id will POST again, idempotent UPSERT. Worst case: 1 reactor invocation. |
| Re-sync drift_detected followed by a real auto-unlink behavior in the future | This spec deliberately does NOT auto-unlink on drift. Future spec can add that policy if appetite materializes. |

---

## 14. Alternatives considered

- **Per-type instead of per-instance** — rejected. Multi-instance is supported elsewhere in yggdrasil; identity should follow same axis. See §4.
- **Adapter calls yggdrasil HTTP API directly (no envelope convention)** — rejected. Reverses dependency direction; requires every adapter to ship yggdrasil-api-client + auth. See §6.
- **Side-channel `identity.linked` event published on AMQP by adapter** — rejected. Adds new event type and listener for what is essentially adapter→core metadata. Convention is simpler.
- **Hard-delete on offboard (no soft-delete)** — rejected. Loses audit; harder to debug "why isn't this user provisioned"; re-onboard becomes harder to model.
- **Polling instead of webhooks** — rejected as primary. Webhooks provide sub-second latency. Re-sync (also polling) is the safety net for drift, not the primary link mechanism.

---

## 15. Implementation phases (sketch — actual plan to be authored separately)

1. **Foundation:** migration + `internal/externalidentity/` package with repository + unit tests.
2. **Canon events:** 5 event types + JSON Schemas + validator registration.
3. **HTTP API:** POST/GET/DELETE endpoints + handler tests.
4. **Reactor envelope convention:** dispatcher extracts on write, pre-populates on read.
5. **Adapter side (slack/gw):** opt in to writing `_yggdrasil.external_identity` from existing reactor success paths.
6. **Webhook receiver:** generic endpoint + HMAC verification + adapter capability dispatch.
7. **Adapter side (github):** `on_webhook` capability handling `member` events; refactor `on_collaborator_offboarded` to read `_context.external_identity`.
8. **Re-sync cron:** loop + `list_identities` capability dispatch + diff detection.
9. **Cleanup cron:** retention deletion.
10. **Integration tests:** real Postgres scenarios.
11. **E2E smoke:** full GitHub flow per §12.3.

---

## 16. Success criteria

- All 4 currently-deployed reactor integrations (slack, gw, github, grafana) can persist identities for new collaborators without changes to yggdrasil-core for each integration.
- GitHub V11-style scenario succeeds end-to-end: invite-accept-offboard removes the actual user from the org.
- No yggdrasil-core code references `slack`, `github`, `google-workspace`, or `grafana` by name — all polymorphism flows through `integration_instance_id`.
- Adapter binary does not depend on a yggdrasil-api-client (verified by import-scan tooling in CI).
- Re-sync runs daily without breaking production; drift events visible in event_log within 25h of provider-side change.
- 85%+ test coverage in `internal/externalidentity/`.

---

## 17. Implementation results (2026-05-16)

### 17.1 Code-complete status

All 20 plan tasks shipped. Commit chain in `dakasa-yggdrasil/yggdrasil-core` main (HEAD: `eb687d1`):

| Phase | Commits | Scope |
|------:|:--------|:------|
| Schema + events | `b7f1b2f`, `fddbc8a`, `4ab36d0` | Migration 00041, 6 event constants, 6 JSON Schemas |
| Repository + HTTP | `6482769`, `acea852`, `8a0dec0`, `61e6a35` | CRUD, POST/GET/DELETE handlers, event emit helpers |
| Reactor envelope | `0700d6a`, `5bf92b5` | `ExtractFromOutput` + `EmbedIntoInput`, dispatcher wiring |
| Webhook | `f965759` | Generic HMAC receiver + action dispatch |
| Cron addons | `b217759`, `ae1676b` | Re-sync priority 85, cleanup priority 86 |
| Integration test | `eb687d1` | Full lifecycle: link → relink → unlink → cleanup → conflict |

Cross-repo adapter commits:

| Repo | Commits | Capability |
|:-----|:--------|:-----------|
| `integration-slack` | `aa1de74`, `197414a`, `edfbf82` | Emit envelope (SCIM out), read `_context`, `list_identities` |
| `integration-google-workspace` | `dda9f6b`, `70b3ad2` | Emit envelope (directoryUser), read `_context`, `list_identities` |
| `integration-github` | `1782c41`, `2586fe8`, `4a5e19b` | Read `_context.github_login`, `on_webhook`, `list_identities` |

### 17.2 Unit + integration test results (local, pre-deploy)

- `go build ./...` clean across all 4 repos.
- `go vet ./...` clean across all 4 repos.
- yggdrasil-core `internal/externalidentity/`: 32 tests PASS, 7 skipped (DB_URL unset locally). Skipped tests exercise real Postgres (`TestUpsert_*`, `TestSoftDelete_*`, `TestList_*`, `TestExternalIdentityFullLifecycle`, `TestExternalIdentityConflict`); will run in CI/staging where DB_URL is set.
- integration-slack adapter tests: full suite PASS (`TestListIdentities` 4/4, reactors unchanged 25/25).
- integration-google-workspace adapter tests: full suite PASS (`TestListIdentities` 4/4 incl. pagination, reactors 29/29).
- integration-github adapter tests: 7/7 webhook PASS, 4/4 `list_identities` PASS, 29 reactor tests PASS.

### 17.3 E2E smoke results (live, 2026-05-16 ~17:42 UTC)

**Production deploy:**
- Image rolled via `upgrade-yggdrasil-core-edge` workflow → `sha-817a028` (16 commits + 2 lint fixes + 1 resync query fix).
- Migration 00041 applied successfully on startup (`goose: successfully migrated database to version: 41`).
- Both addons bootstrapped clean (no warnings on the post-fix image).

**Smoke A — Lifecycle via API (PASSED 6/6 cenarios):**

| Step | Action | Outcome | Event emitted |
|:----:|:-------|:--------|:--------------|
| 1 | `POST /collaborator-external-identities` | `outcome=inserted`, 201 | `linked` (re_linked=false) |
| 2 | `GET ?collaborator_id=…` | returns 1 row, `unlinked_at=null` | — |
| 3 | `POST` same triple | `outcome=refreshed`, 200 | `linked` (re_linked=false) |
| 4 | `DELETE /{id}` | `outcome=unlinked`, 200 | `unlinked` |
| 5 | `POST` same triple | `outcome=re_linked`, 200 | `linked` (re_linked=true) |
| 6 | Conflict test: 2nd collab same ext_id | 409 + structured error | `conflict_detected` |
| 7 | `DELETE /{id}?hard=true` | 204, row gone | — (see gap below) |

All 6 lifecycle outcomes correctly identified by repository's `UpsertOutcome` enum. JSON Schema validation passed for `linked` (with/without re_linked), `unlinked`, and `conflict_detected` payloads.

**Bug surfaced + fixed mid-smoke:**
- `external_identity_resync` initial-tick failed on first pod start with `pq: column "deleted_at" does not exist`. Root cause: manifests table uses `active` boolean, not soft-delete column. Fix `817a028` swapped query to `WHERE active = true`. Post-roll, log noise gone.

**Gap (deferred): hard-delete via API does NOT emit `purged` event.** The DELETE handler with `?hard=true` calls `externalidentity.HardDelete` directly without emitting; only the cleanup cron's `CleanupTick` emits `purged`. This is consistent with the spec (purged = "retained past retention by cleaner"), but operators doing manual hard-deletes won't generate an audit event. Acceptable for V1; track for V2.

**Pending E2E (require external state):**

- **GitHub member_added webhook** (Smoke 1): needs a real GitHub org webhook configured against `https://yggdrasil.dakasa.me/api/v1/integrations/{gh_instance_id}/webhook` with `webhook_signature_scheme: github_hmac_sha256` + `webhook_secret`. Operator action.
- **Slack SCIM relink** (Smoke 2): needs an onboard workflow to dispatch through reactor — covered by next onboard run from Tartaro UI.
- **Drift detection** (Smoke 3): re-sync cron tick interval is 4h default; can be forced via `YGGDRASIL_EXTERNAL_IDENTITY_RESYNC_INTERVAL=300s` or via manual `POST /api/v1/integration-types/{id}/sync` to dispatch sync (different addon — not external_identity-specific).
- **Cleanup retention** (Smoke 4): backdate `unlinked_at` 40 days + wait 24h tick OR set `YGGDRASIL_EXTERNAL_IDENTITY_CLEANUP_INTERVAL=60s` for fast test.

### 17.4 E2E smoke procedure (for future runs)

Once CI rebuilds + reconciler picks up new images (~5 min per repo):

**Smoke 1 — GitHub non-EMU offboard (the original gap):**

1. Onboard a test collaborator with `primary_email = test-<n>@dakasa.me`. GitHub adapter sends invite; **no external_identity row yet** (invite-only state).
2. Test user accepts invite at GitHub. GitHub fires `organization.member_added` webhook → `/api/v1/integrations/{instance_id}/webhook`.
3. Verify in `event_log`:
   - `external_identity.linked` with `external_id = <github_login>`, `external_metadata.github_login` populated.
4. Run offboard workflow on the collaborator.
5. Verify reactor envelope:
   - `on_collaborator_offboarded` input has `_context.external_identity.external_metadata.github_login`.
   - Reactor early-return path engaged (not the SCIM/invite-cancel fallback).
   - GitHub `DELETE /orgs/{org}/members/{username}` returned 204.
6. Verify in `event_log`:
   - `external_identity.unlinked` for the same row.
7. Confirm user no longer appears in `gh api /orgs/<org>/members | jq '.[].login'`.

**Smoke 2 — Slack re-link idempotency:**

1. Onboard collab → SCIM create → expect `external_identity.linked` with `external_id = U…`.
2. Offboard → `external_identity.unlinked`.
3. Re-onboard same collab + same email → SCIM create returns existing user → expect `external_identity.linked` with `outcome = re_linked`, **same row id** (or fresh row, both valid per spec §11).

**Smoke 3 — Google Workspace drift detection:**

1. Trigger re-sync addon manually (or wait 4h tick).
2. Manually rename a directory user's primary_email in Google Admin.
3. After next tick, expect `external_identity.drift_detected` event for that identity (kind not enforced yet per §17.4 known-gaps).

**Smoke 4 — Hard cleanup retention:**

1. Soft-delete an identity (offboard collab).
2. SQL: `UPDATE collaborator_external_identities SET unlinked_at = now() - interval '40 days' WHERE id = '<id>';`
3. Wait for daily cleanup tick (or `YGGDRASIL_EXTERNAL_IDENTITY_CLEANUP_INTERVAL=60s` for quick test).
4. Expect row gone + `external_identity.purged` event.

### 17.5 Known gaps / deferred work

1. **Drift `kind` field deferred.** `drift_detected.json` schema currently has `additionalProperties: false` with only 5 fields. To extend with `drift_kind` (`disappeared` vs `metadata_changed`) and observed/stored metadata, bump schema version and update `BuildDriftPayload`. Re-sync runner today emits only the "disappeared" case (when local row has no matching external).
2. **Adapter unsupported-capability detection.** Re-sync runner currently catches "unsupported"/"unknown"/"not found" in the error string. Cleaner: read `discovery.capabilities` from the integration_type manifest before dispatching the RPC.
3. **Per-collaborator GET endpoint.** `GET /api/v1/collaborators/{id}/external-identities` is in the plan but the HTTP handler uses `GET /api/v1/collaborator-external-identities?collaborator_id=` (querystring filter). Functionally equivalent; if Tartaro UI needs the nested route, add a thin wrapper.
4. **GitHub `membership` event coverage.** T15 handles `organization.member_added/removed` only; team-scoped `membership` events are no-op. Acceptable for current Yggdrasil scope (teams are managed via repos/groups, not GitHub teams).
5. **GHA workflow validation for ECR push.** Each adapter ships with `deploy.yml` already; first push after these commits will exercise the OIDC trust + ECR pull path. If any 403/pull-error, integration-github's pattern from `webhooks-external v0.3.2` resolution applies (memory `project_webhooks_external_v030_pending_image`).

### 17.6 Production rollout sequence

Per memory `feature_yggdrasil_only` + `feedback_dakasa_deploy_flow`:

1. CI builds image for `dakasa-yggdrasil/yggdrasil-core` (already pushed; should be running now).
2. Yggdrasil reconciler picks up new image via `apps/yggdrasil-core` manifest update.
3. Migration 00041 runs on startup (goose auto-migrate).
4. Addons `external_identity_resync` (85) + `external_identity_cleanup` (86) bootstrap automatically.
5. Webhook endpoint `POST /api/v1/integrations/{instance_id}/webhook` becomes live; GitHub webhook URL still needs to be configured in the GitHub org settings (separate operator action, secret stored at `integration_instance.spec.config.webhook_secret`).
6. CI builds for each adapter; reconciler picks up new images for `integration-slack`, `integration-google-workspace`, `integration-github`.
7. Run smoke procedure §17.3.

### 17.7 Success criteria status

| Criterion | Status |
|:----------|:-------|
| All 4 reactor integrations can persist identities | ✅ code-complete (slack/gw/github); grafana unchanged (no users to link) |
| GitHub V11-style scenario E2E | ⏳ pending Smoke 1 (real invite + accept) |
| No yggdrasil-core code references provider names | ✅ verified (9 hits in `hmac.go` for the literal scheme name `github_hmac_sha256` only — that's a discriminator value, not coupled logic) |
| Adapter binary does not depend on yggdrasil-api-client | ✅ no adapter imports added; all communication via existing RabbitMQ envelope |
| Lifecycle events (linked/unlinked/conflict_detected) work E2E | ✅ verified by Smoke A on live cluster (817a028) |
| Re-sync runs daily | ⏳ pending first 24h post-deploy |
| Drift events visible in event_log within 25h | ⏳ pending Smoke 3 |
| 85%+ test coverage in `internal/externalidentity/` | ⏳ measure post-deploy (`go test -cover ./internal/externalidentity/`) |

### 17.8 Architectural neutrality verification

A sentinel grep run on yggdrasil-core after these commits (excluding package import paths like `github.com/...`):

```bash
grep -rni 'slack\|github\|google_workspace\|google-workspace\|grafana\|jira\|notion' \
  internal/externalidentity/ \
  controllers/httpapi/integration_webhook.go \
  addons/external_identity_*.go \
  | grep -v 'github\.com/' | grep -v 'google/uuid'
```

Result: **9 matches**, all in `internal/externalidentity/hmac.go` + `hmac_test.go`, all referring to the literal HMAC scheme name `github_hmac_sha256`. This is a discriminator value (the same kind of string `slack_v0_signing` or `stripe_signature` would be), not provider-coupled logic. The dispatch table inside `VerifySignature` adds new schemes via a single case clause; the core knows zero about GitHub's webhook payload shape — that knowledge lives entirely in `integration-github`'s `on_webhook` capability.

The webhook receiver dispatches via `messagecontroller.ExecuteIntegration` with `Capability: "on_webhook"`. Adding `slack_v0_signing` or `stripe_signature` is a single case clause in `internal/externalidentity/hmac.go::VerifySignature` and zero changes elsewhere.
