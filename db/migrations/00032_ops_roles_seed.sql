-- +goose Up
-- +goose StatementBegin

-- Phase 2 ops RBAC seed. Permissions live in permissions_catalog
-- (registered_by = 'core' since these are core ops surfaces, not
-- contributed by an integration). Role bindings live in
-- role_permission_bindings.

INSERT INTO public.permissions_catalog (name, description, registered_by) VALUES
    ('ops:workflows:read',       'Listar workflow runs e detalhes',                'core'),
    ('ops:workflows:retry',      'Repetir um run que falhou',                      'core'),
    ('ops:workflows:abort',      'Abortar um run em execução',                     'core'),
    ('ops:workflows:replay',     'Re-executar um run com inputs editados',         'core'),
    ('ops:integrations:read',    'Listar integrations e detalhes',                 'core'),
    ('ops:integrations:invoke',  'Invocar capability manualmente',                 'core'),
    ('ops:approvals:read',       'Ver fila de approvals pendentes',                'core'),
    ('ops:approvals:decide',     'Aprovar/rejeitar approval pendente',             'core'),
    ('ops:drift:read',           'Ver objetos drift do reconcile loop',            'core'),
    ('ops:drift:reconcile',      'Forçar reconcile imediato em objeto drift',      'core'),
    ('ops:catalog:read',         'Ler registry de adapters/capabilities/etc.',     'core'),
    ('ops:system:read',          'Ler health do core (queues, outbox, AMQP, etc.)','core'),
    ('ops:system:trigger',       'Disparar manuais (force-flush, force-reconcile)','core'),
    ('ops:audit:read',           'Ler stream raw de audit events',                 'core'),
    ('ops:audit:export',         'Exportar audit como CSV',                        'core')
ON CONFLICT (name) DO UPDATE
    SET description = EXCLUDED.description,
        updated_at  = NOW();

-- ops-viewer: read-only across the board
INSERT INTO public.role_permission_bindings (role, permission_name, bound_by) VALUES
    ('role:ops-viewer', 'ops:workflows:read',    'core-seed'),
    ('role:ops-viewer', 'ops:integrations:read', 'core-seed'),
    ('role:ops-viewer', 'ops:approvals:read',    'core-seed'),
    ('role:ops-viewer', 'ops:drift:read',        'core-seed'),
    ('role:ops-viewer', 'ops:catalog:read',      'core-seed'),
    ('role:ops-viewer', 'ops:system:read',       'core-seed'),
    ('role:ops-viewer', 'ops:audit:read',        'core-seed')
ON CONFLICT (role, permission_name) DO NOTHING;

-- ops-operator: viewer + retry + invoke
INSERT INTO public.role_permission_bindings (role, permission_name, bound_by) VALUES
    ('role:ops-operator', 'ops:workflows:read',     'core-seed'),
    ('role:ops-operator', 'ops:workflows:retry',    'core-seed'),
    ('role:ops-operator', 'ops:integrations:read',  'core-seed'),
    ('role:ops-operator', 'ops:integrations:invoke','core-seed'),
    ('role:ops-operator', 'ops:approvals:read',     'core-seed'),
    ('role:ops-operator', 'ops:drift:read',         'core-seed'),
    ('role:ops-operator', 'ops:catalog:read',       'core-seed'),
    ('role:ops-operator', 'ops:system:read',        'core-seed'),
    ('role:ops-operator', 'ops:audit:read',         'core-seed')
ON CONFLICT (role, permission_name) DO NOTHING;

-- ops-admin: every ops:* permission
INSERT INTO public.role_permission_bindings (role, permission_name, bound_by)
SELECT 'role:ops-admin', name, 'core-seed'
FROM public.permissions_catalog
WHERE registered_by = 'core' AND name LIKE 'ops:%'
ON CONFLICT (role, permission_name) DO NOTHING;

-- sre: same as ops-admin at seed time. Phase 3 surface install logic will
-- auto-bind newly registered surface permissions to role:sre.
INSERT INTO public.role_permission_bindings (role, permission_name, bound_by)
SELECT 'role:sre', name, 'core-seed'
FROM public.permissions_catalog
WHERE registered_by = 'core' AND name LIKE 'ops:%'
ON CONFLICT (role, permission_name) DO NOTHING;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

DELETE FROM public.role_permission_bindings
    WHERE role IN ('role:ops-viewer', 'role:ops-operator',
                   'role:ops-admin', 'role:sre')
      AND bound_by = 'core-seed';

DELETE FROM public.permissions_catalog
    WHERE registered_by = 'core' AND name LIKE 'ops:%';

-- +goose StatementEnd
