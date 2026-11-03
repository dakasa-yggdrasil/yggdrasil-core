"""Actual migration92 and complete CAS busy SELECT on mandatory CI-only PG16.

The pinned logical history is a declared planner-eligibility fixture, not a
production timing benchmark or a substitute for full Goose/image qualification.
The NULL-status case relaxes only this disposable fixture's NOT NULL constraint.
"""
import json
from pathlib import Path
import re
import unittest

import test_g8pair_core_cas as base
import test_r6pair_core_cas_postgres as r6


REPO = Path(__file__).resolve().parents[3]
M92 = REPO / 'db/migrations/00092_workflow_runs_busy_logical_index.sql'
CAS = REPO / 'ops/network-guardian/rollout/core_image_cas_once_g9.py'
INDEX = 'workflow_runs_busy_logical_idx'
AWS = 'notify-aws-elastic-capacity'
HZ = 'notify-hetzner-elastic-capacity'
HISTORY_ROWS = 120000


def uid(number):
    return '92000000-0000-0000-0000-' + str(number).zfill(12)


def migration_section(path, direction):
    text = path.read_text()
    if text.count('-- +goose Up\n') != 1 or text.count('-- +goose Down\n') != 1:
        raise AssertionError('exact single Up/Down migration sections required')
    up, down = text.split('-- +goose Up\n', 1)[1].split('-- +goose Down\n', 1)
    return up if direction == 'Up' else down


def actual_busy_select():
    """Use the actual complete count SELECT, never a copied/narrowed predicate."""
    found = re.findall(r'SELECT count\(\*\) AS root_held_busy_runs FROM \(\n.*?\n\) AS busy_run_ids',
                       CAS.read_text(), re.S)
    if len(found) != 1:
        raise AssertionError('exactly one actual held busy SELECT required')
    sql = found[0]
    if (sql.count('SELECT wr.id FROM') != 2 or sql.count('\n UNION\n') != 1
            or sql.count("COALESCE(wr.status,'') NOT IN('succeeded','failed','cancelled') OR wr.finished_at IS NULL") != 2
            or 'JOIN public.workflow_runs wr ON wr.workflow_id=m.id' not in sql
            or "m.kind='workflow' AND m.namespace='dakasa-production'" not in sql
            or "wr.workflow_namespace='dakasa-production'" not in sql
            or sql.count("IN('notify-aws-elastic-capacity','notify-hetzner-elastic-capacity')") != 2
            or any(token in sql for token in ('m.active', 'created_at', ' LIMIT ', 'UNION ALL'))):
        raise AssertionError('complete UUID/logical UNION and complete busy predicate required')
    return sql + ';'


class WorkflowBusyIndex92PostgresTests(unittest.TestCase):
    setUpClass = classmethod(base.G8CASPostgresTests.setUpClass.__func__)
    pg = base.G8CASPostgresTests.pg

    def setUp(self):
        self.pg('DROP SCHEMA public CASCADE; CREATE SCHEMA public; CREATE EXTENSION pgcrypto;')
        self.pg(base.source_create_table('00001_initial.sql', 'manifests'))
        self.pg(migration_section(REPO / 'db/migrations/00018_workflow_runs.sql', 'Up'))
        self.pg(migration_section(REPO / 'db/migrations/00089_workflow_runs_workflow_id_index.sql', 'Up'))
        self.pg("INSERT INTO public.manifests(id,api_version,kind,namespace,name,version,active,spec,checksum) VALUES "
                "('" + uid(101) + "','v1','workflow','dakasa-production','" + AWS + "',1,false,'{}','declared-old'),"
                "('" + uid(102) + "','v1','workflow','dakasa-production','" + AWS + "',2,true,'{}','declared-current'),"
                "('" + uid(103) + "','v1','workflow','dakasa-production','" + HZ + "',1,true,'{}','declared-HZ'),"
                "('" + uid(104) + "','v1','workflow','foreign','" + AWS + "',1,true,'{}','declared-foreign');")
        self.pg(migration_section(M92, 'Up'))
        self.assertEqual(int(self.pg("SELECT current_setting('server_version_num')::int/10000;").stdout), 16)

    def add_run(self, number, *, workflow=102, namespace='dakasa-production', name=AWS,
                status='running', finished=True):
        workflow_sql = 'NULL' if workflow is None else "'" + uid(workflow) + "'"
        status_sql = 'NULL' if status is None else "'" + status + "'"
        finished_sql = "'2000-01-02T00:00:00Z'" if finished else 'NULL'
        self.pg("INSERT INTO public.workflow_runs(id,workflow_id,workflow_namespace,workflow_name,status,finished_at,created_at) VALUES('"
                + uid(number) + "'," + workflow_sql + ",'" + namespace + "','" + name + "'," + status_sql
                + ',' + finished_sql + ",'2000-01-01T00:00:00Z');")

    def busy_count(self):
        return int(self.pg("BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY; "
                           "SET LOCAL statement_timeout='8000ms'; SET LOCAL lock_timeout='1000ms'; "
                           + actual_busy_select() + ' COMMIT;').stdout)

    def index_facts(self):
        return json.loads(self.pg("SELECT jsonb_build_object('oid',i.indexrelid,'valid',i.indisvalid,"
            "'ready',i.indisready,'live',i.indislive,'unique',i.indisunique,'keys',i.indnkeyatts,"
            "'attributes',i.indnatts,'expressions',i.indexprs IS NOT NULL,'table',i.indrelid::regclass::text,"
            "'method',am.amname,'definition',pg_get_indexdef(i.indexrelid)) "
            "FROM pg_index i JOIN pg_class c ON c.oid=i.indexrelid JOIN pg_am am ON am.oid=c.relam "
            "WHERE i.indexrelid=to_regclass('public." + INDEX + "');").stdout)

    def assert_actual_index_admission(self, expected):
        self.assertEqual(self.pg('SELECT ' + r6.cas.workflow_busy_logical_index92_sql() + ';').stdout.strip(),
                         b't' if expected else b'f')

    def test_migration92_exact_catalog_and_name_idempotency(self):
        self.assertTrue(M92.read_text().startswith('-- +goose NO TRANSACTION\n-- +goose Up\n'))
        # PostgreSQL parses the independently declared expected definition; do
        # not depend on a particular pg_get_indexdef type-cast/spacing format.
        expected = 'workflow_runs_busy_logical_expected_idx'
        self.pg('CREATE INDEX ' + expected + ' ON public.workflow_runs USING btree '
                "(workflow_namespace,workflow_name,id) WHERE (COALESCE(status,'') "
                "NOT IN ('succeeded','failed','cancelled') OR finished_at IS NULL);")
        facts = self.index_facts()
        definition = self.pg("SELECT pg_get_indexdef('public." + expected + "'::regclass);").stdout.decode().strip()
        self.assertEqual(facts['definition'], definition.replace(expected, INDEX))
        self.assertEqual({k: facts[k] for k in ('valid','ready','live','unique','keys','attributes','expressions','table','method')},
                         {'valid':True,'ready':True,'live':True,'unique':False,'keys':3,'attributes':3,
                          'expressions':False,'table':'workflow_runs','method':'btree'})
        self.assert_actual_index_admission(True)
        self.add_run(1)
        self.pg(migration_section(M92, 'Up'))
        self.assertEqual(self.index_facts(), facts, 'name-idempotency must retain the same actual index')
        self.pg(migration_section(M92, 'Down'))
        self.assertEqual(self.pg("SELECT to_regclass('public." + INDEX + "') IS NULL;").stdout.strip(), b't')
        self.pg(migration_section(M92, 'Down'))
        self.pg(migration_section(M92, 'Up'))
        self.assertEqual(self.busy_count(), 1, 'index lifecycle must preserve the actual workflow row')

    def test_existing_wrong_definition_is_preserved_for_operator_hold(self):
        self.pg(migration_section(M92, 'Down'))
        self.pg('CREATE INDEX ' + INDEX + ' ON public.workflow_runs(workflow_id);')
        before = self.index_facts()
        self.pg(migration_section(M92, 'Up'))
        self.assertEqual(self.index_facts(), before)
        self.assertNotIn('(workflow_namespace, workflow_name, id)', before['definition'])
        self.assert_actual_index_admission(False)

    def test_existing_invalid_index_is_preserved_for_operator_hold(self):
        self.pg(migration_section(M92, 'Down'))
        self.add_run(1)
        self.add_run(2)
        failed = base.REAL_RUN(['docker','exec','-i',self.container,'psql','-X','-q','-v','ON_ERROR_STOP=1',
            '-U','guardian_ci','-d','yggdrasil','-At'], input=('CREATE UNIQUE INDEX CONCURRENTLY ' + INDEX
            + ' ON public.workflow_runs(workflow_namespace,workflow_name);').encode(), capture_output=True, timeout=12)
        self.assertNotEqual(failed.returncode, 0)
        self.assertIn(b'duplicate key', failed.stderr)
        before = self.index_facts()
        self.assertFalse(before['valid'])
        self.pg(migration_section(M92, 'Up'))
        self.assertEqual(self.index_facts(), before, 'invalid same-name index requires HOLD, never automatic repair')
        self.assert_actual_index_admission(False)

    def test_actual_complete_busy_union_preserves_all_identity_and_terminal_cases(self):
        cases = [
            ('historical UUID with mismatched logical identity', {'workflow':101,'namespace':'foreign','name':'mismatch'}, 1),
            ('logical identity with foreign UUID', {'workflow':104}, 1),
            ('logical identity without UUID', {'workflow':None,'name':HZ}, 1),
            ('nonterminal with finished timestamp', {'status':'pending'}, 1),
            ('terminal succeeded without finish', {'status':'succeeded','finished':False}, 1),
            ('terminal failed without finish', {'status':'failed','finished':False,'name':HZ}, 1),
            ('terminal cancelled without finish', {'status':'cancelled','finished':False}, 1),
            ('fully finished succeeded', {'status':'succeeded'}, 0),
            ('fully finished failed', {'status':'failed'}, 0),
            ('fully finished cancelled', {'status':'cancelled'}, 0),
            ('foreign namespace and UUID', {'workflow':104,'namespace':'foreign'}, 0),
            ('foreign name and UUID', {'workflow':104,'name':'mismatch'}, 0),
        ]
        for label, overrides, expected in cases:
            with self.subTest(declared_case=label):
                self.pg('TRUNCATE public.workflow_runs;')
                self.add_run(1, **overrides)
                self.assertEqual(self.busy_count(), expected)
        # Defensive contract case only: production M18 retains NOT NULL, and
        # migration92 never alters workflow data or table constraints.
        self.pg('TRUNCATE public.workflow_runs; ALTER TABLE public.workflow_runs ALTER COLUMN status DROP NOT NULL;')
        self.add_run(1, workflow=104, status=None)
        self.assertEqual(self.busy_count(), 1)

    def test_actual_complete_busy_union_deduplicates_overlap(self):
        self.add_run(1)
        self.add_run(2, workflow=101, namespace='foreign', name='mismatch')
        self.add_run(3, workflow=104, name=HZ)
        self.assertEqual(self.busy_count(), 3, 'one both-arm row, one UUID-only row, one logical-only row')

    def test_actual_busy_query_can_use_covering_partial_index_over_pinned_history(self):
        # Pin terminal history, identity skew, timestamps and busy outliers.
        # Its row count is deliberately bounded for CI; no latency assertion.
        self.pg("INSERT INTO public.workflow_runs(id,workflow_id,workflow_namespace,workflow_name,status,finished_at,created_at) "
            "SELECT ('93000000-0000-0000-0000-' || lpad(n::text,12,'0'))::uuid,'" + uid(101) + "',"
            "'dakasa-production',CASE WHEN n%2=0 THEN '" + AWS + "' ELSE 'history-' || (n%31)::text END,"
            "'succeeded','2000-01-02T00:00:00Z','2000-01-01T00:00:00Z' FROM generate_series(1,"
            + str(HISTORY_ROWS) + ') n;')
        self.add_run(1)
        self.add_run(2, workflow=101, namespace='foreign', name='mismatch')
        self.add_run(3, workflow=104, name=HZ, status='failed', finished=False)
        self.pg('VACUUM (ANALYZE) public.workflow_runs; ANALYZE public.manifests;')
        self.assertEqual(int(self.pg('SELECT count(*) FROM public.workflow_runs;').stdout), HISTORY_ROWS + 3)
        self.assertEqual(self.busy_count(), 3)
        # Disabling competing paths proves eligibility, not a speed claim or a
        # fragile cost choice on a small fixture. GUCs are local to CI EXPLAIN.
        plan = json.loads(self.pg('BEGIN READ ONLY; SET LOCAL enable_seqscan=off; '
            'SET LOCAL enable_bitmapscan=off; EXPLAIN (COSTS OFF, FORMAT JSON) '
            + actual_busy_select() + ' COMMIT;').stdout)[0]['Plan']
        def nodes(node):
            yield node
            for child in node.get('Plans', []):
                yield from nodes(child)
        self.assertTrue(any(n.get('Index Name') == INDEX and n['Node Type'] == 'Index Only Scan'
                            for n in nodes(plan)), json.dumps(plan, sort_keys=True))
        print('WORKFLOW_BUSY_INDEX92_REAL_PG16 ' + json.dumps({'case':self.id(),'history_rows':HISTORY_ROWS,
            'busy_count':3,'covering_index_eligible':True,'production_timing_or_health_claim':False}, sort_keys=True))
