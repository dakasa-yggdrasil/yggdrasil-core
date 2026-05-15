# Yggdrasil Lifecycle Reactor Framework — Design

**Status**: approved (brainstorming 2026-05-15) — pending implementation plan via `writing-plans` skill.

**Driver**: Yggdrasil hoje não propaga lifecycle de pessoas/grupos para integrações automaticamente. Criar um colaborador no console não dispara nada em Slack, GitHub, Google Workspace, AWS, etc. Workflows lifecycle (`onboard.json`, `offboard.json`, `absence-*`, etc.) existem como JSON em `dakasa-system` mas nunca foram aplicados no cluster, e seu modelo hardcoded ("workflow lista cada integration step a step") não escala — adicionar nova integração exigiria editar workflow central. Sem propagation automático, Yggdrasil vira "diretório de pessoas com pouco valor".

**Scope**: framework declarativo de reactors no core. Cada integração declara em seu `integration_type` manifest quais events de lifecycle ela reage e qual capability deve ser chamada. Core mantém um catálogo fechado de 11 events canon, materializa reactions na mesma transação do state mutation, dispatcha via RabbitMQ com retry+dead-letter, e expõe observabilidade. Workflows lifecycle existentes em `dakasa-system` são removidos. UI do console ganha auto-issue de setup-token após criar pessoa.

**Out of scope** explícito: implementação das capabilities por integração (cada integration tem PR próprio no seu repo); inspection API + UI dashboard (Phase 2); backfill/replay de events para integrações recém-instaladas; eventos de tenant/integration/role-permission (não estão no catálogo canon); cron-style cleanup (cleanup-offboarded vira workflow simples sem reactors).

---

## 1. Princípios

1. **Integrations reagem APENAS a entidades canon do core** (collaborator, team, team_membership). Eventos emitidos por integrações **não** disparam reactors em outras integrações — evita grafo direcionado complexo.
2. **Catálogo de events FECHADO**: 11 events canon imutáveis. Naming reservado. Schema validado.
3. **Produto cresce sem tocar no core**: nova integração declara `reactors` no seu manifest e funciona — zero linha de código no core.
4. **Falha isolada**: reactor X falhando não impede reactor Y do mesmo event. Retry 3x com backoff exponencial → dead-letter.
5. **Side effects internos** (revoke sessions, archive provider_state, status updates): permanecem dentro dos handlers do core. Reactor model é puramente **downstream propagation para integrations**.
6. **Materialização transacional**: reactions são criadas no mesmo `*sql.Tx` do `EmitEvent` — sem janelas onde event existe mas reactions sumiram.

---

## 2. Catálogo canon de events

Tabela imutável (qualquer mudança = breaking change com cuidado):

| Event type | Aggregate type | Quando emitir | Payload mínimo |
|---|---|---|---|
| `collaborator.created` | `collaborator` | `POST /collaborators` ou `/console/collaborators` | id, slug, primary_email, display_name, role, primary_team_id, employment_data |
| `collaborator.offboarded` | `collaborator` | `POST /collaborators/{id}/offboard` | id, primary_email, reason, end_date |
| `collaborator.absence_started` | `collaborator` | `POST /collaborators/{id}/absence/start` | id, primary_email, type, from, to, duration_days |
| `collaborator.absence_ended` | `collaborator` | `POST /collaborators/{id}/absence/end` | id, primary_email |
| `collaborator.role_changed` | `collaborator` | `POST /collaborators/{id}/role-change` | id, primary_email, role_from, role_to |
| `collaborator.re_onboarded` | `collaborator` | `POST /collaborators/{id}/re-onboard` | id, primary_email, previous_offboarded_at |
| `team.created` | `team` | `POST /teams` | id, slug, name, type, parent_team_id |
| `team.updated` | `team` | `PATCH /teams/{id}` | id, slug, changed_fields (object) |
| `team.deleted` | `team` | `DELETE /teams/{id}` | id, slug |
| `team_membership.added` | `team_membership` | `POST /team-memberships` | collaborator_id, team_id, role, source |
| `team_membership.removed` | `team_membership` | `DELETE /team-memberships/{id}` | collaborator_id, team_id |

Cada um vira JSON Schema em `docs/contracts/events/v1/<aggregate>/<event>.json`. Schemas existentes (`collaborator.created`, `collaborator.offboarded`) são reaproveitados; 9 schemas novos serão criados.

**`reactor.dead_lettered`** é meta-event emitido em event_log quando reactor esgota retries, mas **fica fora do reactor pipeline** (não dispara reactors). Consumido por canal externo (Grafana alert, Prometheus rule). Prefix `reactor.*` é reservado.

---

## 3. Arquitetura

### 3.1 Reactor declaration no integration_type manifest

Schema do `integration_type.spec` ganha campo opcional `reactors`:

```json
{
  "name": "integration-slack",
  "kind": "integration_type",
  "spec": {
    "transport": "rabbitmq",
    "action_catalog": [
      {
        "name": "on_collaborator_created",
        "description": "Provisiona usuário Slack + DM com setup_url.",
        "resource_types": ["collaborator"],
        "idempotent": true,
        "input_schema": { "$ref": "yggdrasil.io/contracts/reactors/v1/collaborator.created.json" }
      }
    ],
    "reactors": [
      {
        "event_type": "collaborator.created",
        "capability": "on_collaborator_created",
        "description": "Provisiona Slack ao onboard."
      }
    ]
  }
}
```

**Constraints validadas pelo manifest validator:**

- `reactors[].event_type` ∈ catálogo canon de 11 events. Qualquer outro → manifest rejected.
- `reactors[].capability` ∈ `action_catalog[].name`. Senão → rejected.
- `(integration_type_manifest_id, event_type)` UNIQUE: uma integration tem no máximo 1 reactor por event type.
- Convention warning (não erro): `capability` nome casa `on_<event_type_with_dot_replaced_by_underscore>`.

### 3.2 Capability payload contract

Quando core dispatcha reactor, envia para a integration via RabbitMQ um payload no formato:

```json
{
  "_context": {
    "event_id": "019e2dac-caf4-75c0-bd1b-78e4c037f983",
    "event_type": "collaborator.created",
    "schema_version": "v1",
    "emitted_at": "2026-05-15T22:45:51Z",
    "actor": { "type": "collaborator", "id": "f926cc6d-..." },
    "attempt": 1
  },
  "id": "0c686775-...",
  "slug": "joao-souza",
  "primary_email": "joao.souza@dakasa.me",
  "display_name": "João Vitor Souza",
  "role": "CMO",
  "primary_team_id": null,
  "employment_data": { "role": "CMO", "title": "CMO" }
}
```

- `_context` reservado para metadados do core. Prefix `_` reservado para o core.
- Restante do payload = exatamente o que está em `event_log.payload` para esse evento.
- **Idempotency é responsabilidade da integration**: `_context.attempt` indica número da tentativa. Reactor deve tolerar receber o mesmo `event_id` mais de uma vez.

Schemas em `docs/contracts/reactors/v1/<event>.json` (11 schemas) — derivam do event schema + `_context` mandatório.

### 3.3 Tracking: `integration_event_reactions`

```sql
CREATE TABLE public.integration_event_reactions (
  id                            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  event_id                      UUID NOT NULL REFERENCES public.event_log(event_id) ON DELETE CASCADE,
  event_type                    TEXT NOT NULL,
  integration_instance_id       UUID NOT NULL REFERENCES public.manifests(id) ON DELETE CASCADE,
  integration_type_manifest_id  UUID NOT NULL REFERENCES public.manifests(id) ON DELETE CASCADE,
  capability                    TEXT NOT NULL,
  status                        TEXT NOT NULL,
  attempt                       INT  NOT NULL DEFAULT 0,
  next_attempt_at               TIMESTAMPTZ NULL,
  started_at                    TIMESTAMPTZ NULL,
  finished_at                   TIMESTAMPTZ NULL,
  last_error                    TEXT NULL,
  metadata                      JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at                    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at                    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT iers_status_check CHECK (status IN ('pending','in_progress','succeeded','failed','dead_lettered')),
  CONSTRAINT iers_unique_per_event_instance UNIQUE (event_id, integration_instance_id)
);

CREATE INDEX iers_pending_idx
  ON public.integration_event_reactions (next_attempt_at, status)
  WHERE status IN ('pending','failed');

CREATE INDEX iers_event_idx ON public.integration_event_reactions (event_id);
CREATE INDEX iers_instance_idx
  ON public.integration_event_reactions (integration_instance_id, status, created_at DESC);
```

**Uma row por par (event, integration_instance)**. Independência total entre reactors.

### 3.4 Dispatcher: Materializer + Runner

**Worker A — Materializer (transacional, in-process do EmitEvent)**

`repository.EmitEvent` (já existe) é estendido: quando `req.Type` está no catálogo canon, na mesma transação executa:

```sql
INSERT INTO integration_event_reactions
  (event_id, event_type, integration_instance_id, integration_type_manifest_id, capability, status, next_attempt_at)
SELECT $1, $2, ii.id, it.id, r->>'capability', 'pending', NOW()
FROM manifests ii
JOIN manifests it ON it.id::text = (ii.spec->>'integration_type_manifest_id')
JOIN LATERAL jsonb_array_elements(COALESCE(it.spec->'reactors', '[]'::jsonb)) r ON r->>'event_type' = $2
WHERE ii.kind = 'integration_instance'
  AND it.kind = 'integration_type'
  AND ii.active = true;
```

ACID: se event commit, reactions commit; se rollback, ambos. Zero janela de skew.

**Worker B — Runner (addon goroutine)**

Bootstrap addon `addons/reactor_dispatcher.go` priority ~70, registra Runner que:

```
Every 5s (configurable via REACTOR_RUNNER_INTERVAL):
  In a transaction:
    SELECT id, event_id, event_type, integration_instance_id, capability, attempt
    FROM integration_event_reactions
    WHERE status IN ('pending','failed') AND next_attempt_at <= NOW()
    ORDER BY next_attempt_at ASC
    LIMIT 50
    FOR UPDATE SKIP LOCKED
  → claim batch (UPDATE status='in_progress', attempt+=1, started_at=NOW())
  COMMIT

  For each claimed row (1 goroutine cada, limit by REACTOR_RUNNER_PARALLELISM=10):
    Build payload: merge event_log.payload + _context (event_id, event_type, attempt, actor, emitted_at)
    Call integration_instance.capability via RabbitMQ (reuse messagecontroller.RunIntegrationOperation or similar)
    On success:
      UPDATE … SET status='succeeded', finished_at=NOW()
    On failure:
      If attempt < 3:
        UPDATE … SET status='failed', next_attempt_at = NOW() + backoff(attempt), last_error=truncate(err, 4096)
        (backoff: 1m, 5m, 15m — configurable via env)
      Else:
        UPDATE … SET status='dead_lettered', finished_at=NOW(), last_error=…
        EmitEvent('reactor.dead_lettered', payload={event_id, event_type, integration_instance_id, capability, final_error}, aggregate_type='reactor', aggregate_id=reaction.id)
```

`FOR UPDATE SKIP LOCKED` permite múltiplos pods do core sem coordenação externa — Postgres faz o lock distribution.

### 3.5 Failure isolation

Reactions são processadas independentemente. Reactor A falhar em 3 tentativas e dead-letter NÃO afeta Reactor B do mesmo `event_id` (linha separada). Cada reaction tem seu próprio `attempt` counter e `next_attempt_at`.

---

## 4. Handlers do core: side effects internos + emit dos canon events

Pattern em cada handler:

```
1. validate input
2. UPDATE state in DB (atomic, dentro de transação)
3. perform internal side effects (revoke sessions, archive state, status change)
4. emit canon event in SAME transaction (chama repository.EmitEvent, que materializa reactions)
5. commit
6. respond
```

| Handler | Side effects internos | Canon event |
|---|---|---|
| `POST /collaborators` ou `/console/collaborators` | INSERT collaborators + INSERT auth_identities (gap atual fixar) | `collaborator.created` |
| `POST /collaborators/{id}/offboard` | status='offboarded' + revoke ALL auth_sessions + archive provider_state + lifecycle_event | `collaborator.offboarded` |
| `POST /collaborators/{id}/absence/start` | status='on_leave' + lifecycle_event | `collaborator.absence_started` |
| `POST /collaborators/{id}/absence/end` | status='active' + lifecycle_event | `collaborator.absence_ended` |
| `POST /collaborators/{id}/role-change` | UPDATE role + lifecycle_event | `collaborator.role_changed` |
| `POST /collaborators/{id}/re-onboard` | status='active' + lifecycle_event | `collaborator.re_onboarded` |
| `POST /teams` | INSERT teams | `team.created` |
| `PATCH /teams/{id}` | UPDATE teams + diff capture | `team.updated` com `changed_fields` |
| `DELETE /teams/{id}` | DELETE teams (CASCADE limpa team_memberships) | `team.deleted` |
| `POST /team-memberships` | INSERT (or UPDATE) team_memberships | `team_membership.added` |
| `DELETE /team-memberships/{id}` | DELETE team_memberships | `team_membership.removed` |

### 4.1 Gap descoberto durante brainstorming (fix incluso)

`handleCollaboratorCreate` hoje **não cria `auth_identities` row**. Resultado: setup endpoint faz UPDATE com 0 rows affected silenciosamente. Fix: `repository.CreateCollaborator` cria `auth_identities` na mesma transação. Username default = `LOWER(primary_email)`.

### 4.2 Audit pendente

Confirmado que `collaborator.created` e `collaborator.offboarded` já emitidos. Outros 9 events precisam audit + completar emit no mesmo tx. Trabalho seco do spec.

---

## 5. UI auto-setup-token + re-issue

### 5.1 Após criar pessoa (`CollaboratorNewPage.tsx`)

```ts
async function submit() {
  const created = await createCollaborator(payload);
  try {
    const setupToken = await issueSetupToken(created.collaborator.id);
    setModalState({
      open: true,
      url: absolutize(setupToken.setup_url),
      expiresAt: setupToken.expires_at,
      collaboratorName: created.collaborator.display_name,
    });
  } catch (err) {
    setModalState({ open: true, url: null, error: err.message, collaboratorId: created.collaborator.id });
  }
}
```

`SetupURLModal` component (novo, reutilizável):

- Exibe URL completa (resolve path relativo concat `window.location.origin`).
- Botão "Copiar link" (clipboard API).
- "Válido até `<expires_at>`".
- Aviso: "Esse link aparece UMA ÚNICA VEZ. Se perder, gere outro na página da pessoa."
- Caso erro: mostra mensagem + botão "Ir para a página da pessoa pra gerar manualmente".

### 5.2 Re-issue na detail page

`CollaboratorDetailPage` ganha botão "Gerar novo link de primeiro acesso", visível se `auth_identities.password_hash IS NULL`. Clique → mesma chamada `issueSetupToken` → mesmo modal. `InvalidatePrior=true` do handler garante tokens antigos virem inválidos.

### 5.3 Failure no UI

`createCollaborator` ok mas `issueSetupToken` fail → modal mostra que pessoa foi criada com sucesso, com erro do token + botão para detail page para re-issue.

---

## 6. Observability

### 6.1 Métricas Prometheus em `/metrics`

```
yggdrasil_reactor_dispatched_total{event_type, integration_instance}
yggdrasil_reactor_succeeded_total{event_type, integration_instance}
yggdrasil_reactor_failed_total{event_type, integration_instance, attempt}
yggdrasil_reactor_dead_lettered_total{event_type, integration_instance}
yggdrasil_reactor_latency_seconds{event_type, integration_instance} (histogram)
yggdrasil_reactor_backlog_size{status} (gauge, atualizado pelo Runner a cada tick)
```

### 6.2 Logging estruturado

```json
{"level":"info","msg":"reactor dispatched","event_id":"...","event_type":"collaborator.created","integration_instance":"integration-slack-dakasa","capability":"on_collaborator_created","attempt":1}
{"level":"info","msg":"reactor succeeded","reaction_id":"...","duration_ms":234}
{"level":"warn","msg":"reactor failed, will retry","reaction_id":"...","attempt":1,"next_attempt_at":"...","error":"..."}
{"level":"error","msg":"reactor dead-lettered","reaction_id":"...","attempt":3,"final_error":"..."}
```

### 6.3 Phase 2 (out of scope)

Inspection API (`GET /api/v1/integration-event-reactions`, retry manual endpoint) + console UI dashboard. Métricas + logging cobrem o MVP.

---

## 7. Migration plan

### 7.1 Workflows lifecycle deletados de `dakasa-system`

PR contra `dakasa/dakasa-system`:

- `yggdrasil/dakasa/workflows/onboard.json` → DELETE
- `yggdrasil/dakasa/workflows/offboard.json` → DELETE
- `yggdrasil/dakasa/workflows/absence-start.json` → DELETE
- `yggdrasil/dakasa/workflows/absence-end.json` → DELETE
- `yggdrasil/dakasa/workflows/role-change.json` → DELETE
- `yggdrasil/dakasa/workflows/re-onboard.json` → DELETE
- `yggdrasil/dakasa/workflows/cleanup-offboarded-collaborator.json` → DELETE (substituído por workflow simples sem reactor — Phase 2)

Validação prévia: `SELECT name FROM manifests WHERE kind='workflow' AND active=true AND name IN (...)` → 0 rows. Nenhum dos workflows está aplicado. Delete é cosmético.

### 7.2 Integration types ganham reactors (PRs separados, paralelos)

Esses PRs vivem fora desse spec — um por repo. Recomendações (sugestão):

| Integration | Reactors recomendados |
|---|---|
| `integration-slack` | on_collaborator_created (DM setup_url), on_collaborator_offboarded (deactivate), on_collaborator_absence_started/ended (status update), on_team_created (channel), on_team_deleted (archive channel), on_team_membership_added/removed |
| `integration-github` | on_collaborator_created (org invite), on_collaborator_offboarded (remove from org), on_collaborator_absence_started (disable PR auto-assign), on_team_created (GH team), on_team_deleted, on_team_membership_added/removed |
| `integration-google-workspace` | on_collaborator_created (provision), on_collaborator_offboarded (suspend), on_collaborator_absence_*, on_team_created (Google Group) |
| `integration-aws` | on_collaborator_created (Identity Center), on_collaborator_offboarded (deactivate), on_collaborator_role_changed (IAM groups) |
| `integration-grafana` | on_collaborator_created/offboarded |
| `integration-tartaro` | on_collaborator_created (admin), on_collaborator_offboarded |
| `integration-employment-clt` | on_collaborator_created (admission), on_collaborator_offboarded (termination), on_collaborator_role_changed |

Cada PR inclui: `reactors` block no `integration_type.spec` + capabilities no `action_catalog` + implementação no adapter + tests.

### 7.3 Backfill?

Default **não**. Reactor model só processa events emitted **após** integration declarar reactor + ativar. Quem precisa propagar pessoas pré-existentes: workflow ad-hoc `replay-events-for-integration` (Phase 2).

---

## 8. Componentes (file structure)

### 8.1 Novo em `yggdrasil-core`

| Path | Responsabilidade |
|---|---|
| `db/migrations/NNNN_integration_event_reactions.sql` | Cria tabela + indexes |
| `model/reactor.go` | Types: Reactor, ReactionStatus, IntegrationEventReaction, ReactorContext |
| `repository/integration_event_reactions.go` | CRUD + MaterializeReactions(tx, eventID, eventType), ClaimPendingBatch, MarkSucceeded/Failed/DeadLettered |
| `repository/integration_event_reactions_test.go` | Integration tests |
| `internal/reactors/dispatcher.go` | Worker B Runner com ticker + FOR UPDATE SKIP LOCKED + RabbitMQ call + retry logic |
| `internal/reactors/dispatcher_test.go` | Unit tests + mocked RabbitMQ |
| `internal/reactors/backoff.go` | BackoffFor(attempt int) time.Duration (1m, 5m, 15m, dead-letter) |
| `internal/reactors/payload.go` | Builder do _context + merge com event payload |
| `manifest/integration_type_reactors_validate.go` | Validation hook |
| `addons/reactor_dispatcher.go` | Bootstrap addon priority ~70 |
| `docs/contracts/events/v1/team/created.json` | NOVO |
| `docs/contracts/events/v1/team/updated.json` | NOVO |
| `docs/contracts/events/v1/team/deleted.json` | NOVO |
| `docs/contracts/events/v1/team_membership/added.json` | NOVO |
| `docs/contracts/events/v1/team_membership/removed.json` | NOVO |
| `docs/contracts/events/v1/collaborator/absence_started.json` | NOVO (verificar) |
| `docs/contracts/events/v1/collaborator/absence_ended.json` | NOVO |
| `docs/contracts/events/v1/collaborator/role_changed.json` | NOVO |
| `docs/contracts/events/v1/collaborator/re_onboarded.json` | NOVO |
| `docs/contracts/reactors/v1/<event>.json` × 11 | Reactor input schemas |

### 8.2 Modificar em `yggdrasil-core`

| Path | Mudança |
|---|---|
| `repository/collaborator.go` (ou equivalente) | `CreateCollaborator` cria `auth_identities` na mesma tx (fix gap) |
| `repository/event.go` | `EmitEvent` invoca `MaterializeReactions` na mesma tx automaticamente quando event_type ∈ catálogo canon |
| `repository/collaborator_lifecycle.go` | Audit + emit do canon event no mesmo tx do state mutation |
| `repository/team.go` | Idem pra team.* |
| `repository/team_memberships.go` | Idem pra team_membership.* |
| `manifest/integration_type_validate.go` | Plug do reactor validation hook |
| `repository/event_types.go` | +11 const + `reactor.dead_lettered` const |
| `controllers/httpapi/collaborator_lifecycle.go` | Audit handlers chamam emit |

### 8.3 Novo em `surface-console`

| Path | Responsabilidade |
|---|---|
| `src/pages/collaborators/SetupURLModal.tsx` | NEW component reutilizável |
| `src/pages/collaborators/CollaboratorNewPage.tsx` | Chain createCollaborator → issueSetupToken → modal |
| `src/pages/collaborators/CollaboratorDetailPage.tsx` | Botão "Gerar novo link" se password_hash IS NULL |
| `src/lib/api.ts` | `issueSetupToken(id)` |

### 8.4 Delete em `dakasa-system`

Listado em §7.1.

---

## 9. Edge cases e error responses

| Cenário | Comportamento |
|---|---|
| Integration_instance inactive | Materializer não cria row pra ela (`WHERE active = true`) |
| Integration_type sem reactors declarados | Materializer pula (LEFT JOIN não match) |
| Reactor declara event_type fora do catálogo | Manifest apply rejeita 400 com lista de canon válidos |
| Reactor declara capability ausente do action_catalog | Manifest apply rejeita 400 |
| Duplicate reactor pro mesmo event_type no mesmo integration_type | Manifest apply rejeita 400 (UNIQUE constraint lógico) |
| Reactor dispatch timeout (RabbitMQ RPC 30s default) | Conta como failure, marca failed, retry conforme backoff |
| Integration adapter offline | RabbitMQ enqueue OK; consumer não responde dentro do timeout → failure → retry |
| Pod do core morre durante dispatch | Reaction fica em `in_progress`. Próximo Runner tick detecta rows com `started_at < NOW() - 10m AND status='in_progress'` → marca failed pra retry. Migration cobre esse healing. |
| Event sem reactors aplicáveis | Materializer não cria nenhuma row. Event ainda persistido normalmente em event_log. |
| Mesma integration_instance criada após event | Não retroage. Reactions só pra events emitidos após reactor declaration vir ativa. |
| `reactor.dead_lettered` emit gera infinite loop | NÃO — meta-event prefix `reactor.*` é reserved, não bate em catálogo canon, Materializer não cria reactions pra ele |
| `team_membership` mesmo par adicionado 2x | Handler UPSERT — emit `team_membership.added` só se INSERT real (não no conflict update). |

---

## 10. Testing approach

### 10.1 Unit tests

- `internal/reactors/backoff.go`: table-driven (attempt 0→1m, 1→5m, 2→15m, 3→ErrDeadLetter).
- `internal/reactors/payload.go`: build do `_context` com timestamps + actor + attempt; assert merge não sobrescreve fields do event payload.
- `manifest/integration_type_reactors_validate.go`: cada constraint (event_type out of canon, capability missing, duplicate).

### 10.2 Repository (integration tests com Postgres)

- `MaterializeReactions`: simula event emit com 3 integrations matching reactor, valida 3 rows criadas com status='pending'.
- `ClaimPendingBatch`: 2 goroutines concorrentes, `FOR UPDATE SKIP LOCKED` garante distinct rows.
- `MarkSucceeded/Failed/DeadLettered`: state transitions atomicas, backoff schedule correto.
- Stuck `in_progress` rows: healer marca failed após threshold.

### 10.3 Dispatcher end-to-end

Mock RabbitMQ client. Cenários:
- Single reaction: dispatched → succeeded.
- Multiple reactions same event: paralelas, falhas independentes.
- Reactor falha 1x → retry após 1m → success.
- Reactor falha 3x → dead-letter + `reactor.dead_lettered` event emit.

### 10.4 Manifest validation

- Apply integration_type com reactor válido → ok, manifest persisted.
- Apply com event_type "foo.bar" → 400 + mensagem com canon list.
- Apply com capability "nope" não no action_catalog → 400.
- Apply 2 reactors mesmo event_type → 400.

### 10.5 Handler integration tests

Pra cada um dos 11 handlers do core, integration test:
1. Seed integration_type com reactor declarado pra esse event.
2. Seed integration_instance ativa.
3. POST do handler.
4. Assert: 1 row em integration_event_reactions com status='pending'.
5. Assert: event_log tem 1 entry com type canônico.
6. Mesmo tx — se handler falhar, NEM event NEM reaction persistem.

### 10.6 UI tests (surface-console)

- `CollaboratorNewPage` E2E: cria pessoa → modal abre com URL.
- `SetupURLModal`: copy button funciona, fechar navega pra detail page.
- `CollaboratorDetailPage`: botão "Gerar novo link" só visível se sem password.

---

## 11. Critério de pronto

1. `EmitEvent(canon_event, …)` no mesmo tx materializa N rows em `integration_event_reactions` (uma por integration_instance ativa com reactor declarado).
2. Worker dispatcher pega pending, chama capability via RabbitMQ, registra resultado.
3. Retry com backoff 1m/5m/15m → dead-letter na 4ª tentativa, emit `reactor.dead_lettered`.
4. Failure isolation comprovado: reactor A falha + reactor B sucede no mesmo event → independência.
5. Manifest validation rejeita reactor com event_type fora do canon list.
6. Manifest validation rejeita reactor referenciando capability ausente do action_catalog.
7. Console UI: criar pessoa → modal aparece com setup_url + copy button.
8. Re-issue funciona na detail page; token antigo automaticamente invalidated.
9. `CreateCollaborator` cria `auth_identities` row (fix gap).
10. Cada um dos 11 canon events tem JSON schema + handler do core emite no mesmo tx do state mutation.
11. Métricas Prometheus expostas em `/metrics`.
12. Workflows lifecycle deletados de `dakasa-system`.

---

## 12. Configs e ambientes

| Env var | Default | Significado |
|---|---|---|
| `REACTOR_RUNNER_INTERVAL` | `5s` | Tick interval do Runner |
| `REACTOR_RUNNER_BATCH_SIZE` | `50` | Rows por tick |
| `REACTOR_RUNNER_PARALLELISM` | `10` | Goroutines em paralelo por tick |
| `REACTOR_RPC_TIMEOUT` | `30s` | RabbitMQ call timeout |
| `REACTOR_BACKOFF_ATTEMPT_1` | `1m` | Espera após 1ª falha |
| `REACTOR_BACKOFF_ATTEMPT_2` | `5m` | Espera após 2ª |
| `REACTOR_BACKOFF_ATTEMPT_3` | `15m` | Espera após 3ª |
| `REACTOR_MAX_ATTEMPTS` | `3` | Após N falhas → dead-letter |
| `REACTOR_STUCK_THRESHOLD` | `10m` | Após qto tempo `in_progress` vira failed pra retry |

---

## 13. Open questions deixadas pra implementação (não bloqueantes)

1. **Validation: trigger DB ou validation Go?** Go primeiro (portável). Trigger se houver necessidade real de defense-in-depth.
2. **`auth_identities` create em `CreateCollaborator`**: username default `LOWER(primary_email)`. Pra collaborators sem email (legacy?): username default `slug`. Verificar na implementação.
3. **`changed_fields` em `team.updated`**: como diff é capturado? Patch input vs full reload + comparison. Mais simples: serializar campos do request explicitamente (não tentar full diff).
4. **Setup_url absolutização**: backend hoje retorna path relativo se `YGGDRASIL_PUBLIC_BASE_URL` não set. UI concatena `window.location.origin`. Pra robustez, considerar setar essa env no deploy do core.
5. **Concurrent UPDATE em manifests durante validation**: `integration_type` manifest mudar enquanto reaction está em vôo. Reaction usa snapshot do capability name (já no row). Manifest update novo: novas reactions usam novo capability. Reactions pendentes usam capability do momento da materialização. Snapshot-based, sem race.

---

## 14. Stretch / Phase 2 (out of scope claro)

1. Inspection API + UI dashboard de reactor health.
2. Replay/backfill de events pra integrations recém-ativadas.
3. Workflow `cleanup-offboarded-collaborator` reescrito sem reactors (cron schedule simples).
4. Catálogo expandido (tenant.*, integration.installed/uninstalled) — só se houver demanda real.
5. Per-instance disable de reactor (ex: pausar Slack reactor sem desinstalar integration).
6. Metrics no event_log (sequence consumption lag).
