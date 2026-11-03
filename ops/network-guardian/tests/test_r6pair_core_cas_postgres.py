"""Actual retained-terminal/HELD count SQL on the mandatory CI-only PG16.

Declared relevant columns and initial histories are not signed/provider facts.
The production schema, live canonical query and full typed DAO are separately
mandatory in the same head's product91 PostgreSQL16/17 workflow.
"""
import copy
import datetime
import json
from pathlib import Path
import re
import tempfile
import unittest
from unittest.mock import patch

import test_g9pair_core_cas as base


cas = base.cas
REPO = Path(__file__).resolve().parents[3]
M91 = REPO / 'db/migrations/00091_recorded_http_maintenance_dispatch_dispositions.sql'
HTTP_TABLE = 'capacity_dispatch_http_maintenance_dispositions'
HTTP_DDL = '''
ALTER TABLE capacity_dispatch_jobs ADD COLUMN created_at timestamptz,ADD COLUMN updated_at timestamptz;
CREATE TABLE capacity_dispatch_http_maintenance_dispositions(
 id uuid,job_id uuid,run_id uuid,original_dispatch_sha256 text,original_dispatch_updated_at timestamptz,
 original_run_sha256 text,original_returned_at timestamptz,current_members_sha256 text,executor_barrier text,
 disposing_core_process_started_at timestamptz,disposing_core_hostname text,disposing_core_pid integer,
 disposing_core_source_commit text,issuer text,reason text,historical_return text,recorded_at timestamptz,
 provider_mutation_evidence jsonb);
'''


def actual_retained_function():
    text = M91.read_text()
    found = re.search(r'CREATE OR REPLACE FUNCTION public\.http_maintenance_dispatch_effect_scan_tolerable\(scan jsonb\)\n'
                      r'RETURNS boolean LANGUAGE sql IMMUTABLE AS \$\$.*?\n\$\$;', text, re.S)
    if found is None:
        raise AssertionError('actual migration91 pure retained function required')
    source = found.group()
    if 'public.http_maintenance_dispatch_effect_scan(' in source:
        raise AssertionError('retained function must not perform a new live scan')
    return source


class R6CASPostgresTests(unittest.TestCase):
    setUpClass = classmethod(base.G9CASPostgresTests.setUpClass.__func__)
    seed = base.G9CASPostgresTests.seed
    terminal_insert = base.G9CASPostgresTests.terminal_insert

    def pg(self, sql):
        return base.G9CASPostgresTests.pg(self, "SET TIME ZONE 'UTC'; " + sql)

    def setUp(self):
        base.G9CASPostgresTests.setUp(self)
        self.pg(HTTP_DDL + actual_retained_function())

    def full_snapshot(self):
        names = json.loads(self.pg("SELECT json_agg(tablename ORDER BY tablename) FROM pg_tables WHERE schemaname='public';").stdout)
        self.assertTrue(all(re.fullmatch('[a-z_]+', name) for name in names))
        expressions = ["'" + name + "',(SELECT encode(sha256(convert_to(COALESCE(jsonb_agg(to_jsonb(t) ORDER BY to_jsonb(t)::text),'[]'::jsonb)::text,'UTF8')),'hex') FROM " + name + ' t)' for name in names]
        return self.pg('SELECT jsonb_build_object(' + ','.join(expressions) + ');').stdout

    def seed_http(self, *, terminal, defect=None, provider='hetzner'):
        """Build every declared operand before its first tested INSERT."""
        self.seed()
        known = cas.HTTP_MAINTENANCE_HELD_IDENTITY
        job, run, receipt = known['job_id'], known['run_id'], base.uid(3000)
        workflow = self.expected['workflow_id'] if provider == 'aws' else base.uid(2)
        workflow_name = 'notify-' + provider + '-elastic-capacity'
        dimension = 'original_notify_' + provider + '_vm_members'
        started, returned, expires = '2020-01-01T00:00:00Z', '2020-01-01T00:00:20Z', '2020-01-01T00:01:00Z'
        original_updated, recorded = returned, '2020-01-01T00:20:00Z'
        envelope = {'job_id':job,'run_id':run,'protocol':'capacity_dispatch_prestart_v1',
            'realm':'dakasa-production','environment':'production','domain':'notify','dimension':dimension,
            'source_tick':'declared-CI-http-tick','workflow':{'id':workflow,'namespace':'dakasa-production',
            'name':workflow_name,'version':1},'inputs':{'policy':'declared'},'metadata':{'declared':'stored'}}
        body = base.cut.C.wire(envelope).decode()
        error = known['error']
        w = {'id':run,'workflow_id':None if defect == 'nullable_workflow' else workflow,
            'workflow_namespace':'dakasa-production','workflow_name':workflow_name,'workflow_version':1,
            'inputs':envelope['inputs'],'metadata':envelope['metadata'],'status':'failed','error':error,
            'started_at':started,'finished_at':returned,'updated_at':returned,
            'result':{'status':'failed','workflow':{**envelope['workflow'],'kind':'workflow'}}}
        if defect == 'foreign_workflow':
            w['workflow_id'] = base.uid(3001)
        if defect == 'unfinished':
            w['finished_at'] = None
        self.terminal_insert('workflow_runs', w)
        j = {'id':job,'run_id':run,'realm':'dakasa-production','environment':'production','domain':'notify',
            'dimension':dimension,'protocol':'capacity_dispatch_prestart_v1','source_tick':envelope['source_tick'],
            'envelope':body,'envelope_sha256':cas.sha(body.encode()),'fencing_token':21,
            'lease_owner':base.uid(3002),'lease_expires_at':expires,'started_at':started,
            'pending_wake_count':2,'state':'http_maintenance_disposed' if terminal else 'unknown',
            'return_status':'failed','return_error':error,'finalization_error':error,'returned_at':returned,
            'finalization_ack_at':None,'created_at':started,
            'updated_at':'2020-01-01T00:21:00Z' if terminal else original_updated}
        if defect == 'ACK':
            j['finalization_ack_at'] = returned
        if defect == 'foreign_cause':
            j['finalization_error'] = 'other recorded cause'
        if defect == 'pointer':
            j['abandoned_disposition_id'] = base.uid(3003)
        if defect == 'envelope_hash':
            j['envelope_sha256'] = 'f' * 64
        self.terminal_insert('capacity_dispatch_jobs', j)
        self.pg("INSERT INTO goose_db_version(id,version_id,is_applied,tstamp) VALUES(4,91,true,'2020-01-01T00:00:00Z');")
        run_sha = self.pg("SELECT encode(sha256(convert_to(to_jsonb(w)::text,'UTF8')),'hex') FROM workflow_runs w WHERE id='" + run + "';").stdout.decode().strip()
        job_sha = self.pg("SELECT encode(sha256(convert_to((to_jsonb(j)||jsonb_build_object('state','unknown','updated_at','" + original_updated + "'::timestamptz))::text,'UTF8')),'hex') FROM capacity_dispatch_jobs j WHERE id='" + job + "';").stdout.decode().strip()
        member = {'slot':1,'resource_id':'declared-' + provider + '-member','preregistration_id':base.uid(3004),
                  'policy_id':base.uid(3005),'policy_checksum':'a' * 64,'enrollment_sha256':'b' * 64,
                  'installation_sha256':'c' * 64,'slot_sha256':'d' * 64}
        if defect == 'member_extra':
            member['undeclared_authority'] = True
        members = [member]
        members_sha = self.pg("SELECT encode(sha256(convert_to(" + self.value(members) + "::text,'UTF8')),'hex');").stdout.decode().strip()
        counter = copy.deepcopy(base.TERMINAL_ZERO83)
        counter.update(schema='finalization_lost_dispatch_effect_scan_v1',
            base_schema='abandoned_started_dispatch_effect_scan_v2',pure_assessment_intent_updates=0,
            observation_refresh_slot_updates=0)
        for name in ('canary_challenges_since_start','canary_nonces_since_start','canary_possible_sends_since_start','canary_returns_since_start'):
            counter[name] = 1
        scan = {'schema':'recorded_http_maintenance_dispatch_effect_scan_v1','base':counter,
                'current_members':members,'current_members_sha256':members_sha,'current_member_count':1,
                'policy_epoch_valid':True,'refresh_only_result':True,'invalid_maintenance_canary_rows':0}
        if defect == 'scan_extra':
            scan['undeclared_extra'] = False
        if defect == 'scan_missing':
            del scan['policy_epoch_valid']
        if defect == 'effect':
            scan['base']['native_commands_since_start'] = 1
        if defect == 'overflow':
            scan['base']['resource_slots_updated_since_start'] = 9223372036854775808
            scan['base']['observation_refresh_slot_updates'] = 9223372036854775808
        if defect == 'decimal_integer':
            scan['current_member_count'] = 1.0
        d = {'id':receipt,'job_id':job,'run_id':run,'original_dispatch_sha256':job_sha,
             'original_dispatch_updated_at':original_updated,'original_run_sha256':run_sha,
             'original_returned_at':returned,'current_members_sha256':members_sha,
             'executor_barrier':'disposing_core_process_started_after_lease_expiry_v1',
             'disposing_core_process_started_at':'2020-01-01T00:10:00Z','disposing_core_hostname':'declared-ci',
             'disposing_core_pid':4242,'disposing_core_source_commit':cas.OLD_SOURCE,
             'issuer':'collaborator:' + base.uid(3006),'reason':'recorded_context_refused_http_maintenance_dispatch_disposed',
             'historical_return':'unknown','recorded_at':recorded,'provider_mutation_evidence':scan}
        if defect == 'missing_receipt':
            d = None
        elif defect == 'foreign_job':
            d['job_id'] = base.uid(3007)
        elif defect == 'foreign_run':
            d['run_id'] = base.uid(3008)
        elif defect == 'job_sha':
            d['original_dispatch_sha256'] = 'f' * 64
        elif defect == 'run_sha':
            d['original_run_sha256'] = 'f' * 64
        elif defect == 'old_update':
            d['original_dispatch_updated_at'] = '2020-01-01T00:00:19Z'
        elif defect == 'members_sha':
            d['current_members_sha256'] = 'f' * 64
        elif defect == 'old_process':
            d['disposing_core_process_started_at'] = expires
        elif defect == 'wrong_reason':
            d['reason'] = 'unknown_failed_maintenance_dispatch_disposed'
        if terminal and d is not None:
            self.terminal_insert(HTTP_TABLE, d)
        projection = {'observed_at_pg':datetime.datetime.now(datetime.timezone.utc).isoformat(),
            'job_id':job,'run_id':run,'original_dispatch_sha256':job_sha,'original_run_sha256':run_sha,
            'cas':{'job_id':job,'expected_run_id':run,'expected_envelope_sha256':j['envelope_sha256'],
                'expected_fencing_token':21,'expected_lease_owner':j['lease_owner'],'expected_pending_wake_count':2,
                'expected_returned_at':returned,'expected_run_sha256':run_sha,'expected_members_sha256':members_sha},
            'effect_scan':scan,'admission':True}
        return projection

    def actual_sql(self, sql, expected, allow_hold=False):
        before = self.full_snapshot()
        result = base.old.REAL_RUN(['docker','exec','-i',self.container,'psql','-X','-q','-v','ON_ERROR_STOP=1',
            '-U','guardian_ci','-d','yggdrasil','-At'], input=sql.encode(), capture_output=True, timeout=12)
        if allow_hold and result.returncode != 0:
            self.assertRegex(result.stderr.decode(errors='replace'), r'(?i)(json|invalid|syntax|encoding)')
        else:
            self.assertEqual(result.returncode, 0, result.stderr.decode(errors='replace'))
            self.assertEqual(json.loads(result.stdout), expected)
        self.assertEqual(self.full_snapshot(), before, 'actual read-only guard changed fixture originals')

    def terminal_sql(self, schema):
        return "BEGIN READ ONLY; SET LOCAL TIME ZONE 'UTC'; WITH " + cas.retained_dispatch_terminal_ctes(schema) + \
            " SELECT jsonb_build_object('busy_jobs',(SELECT count(*) FROM dispatch_candidates j WHERE NOT EXISTS(SELECT 1 FROM dispatch_terminal_witnesses d WHERE d.job_id=j.id))); COMMIT;"

    def test_schema89_never_queries_the_absent91_table_or_validator(self):
        self.seed()
        self.pg('DROP TABLE ' + HTTP_TABLE + '; DROP FUNCTION http_maintenance_dispatch_effect_scan_tolerable(jsonb);')
        sql = self.terminal_sql(89)
        self.assertNotIn(HTTP_TABLE, sql)
        self.assertNotIn('http_maintenance_dispatch_effect_scan_tolerable', sql)
        self.actual_sql(sql, {'busy_jobs':0})

    def test_schema91_valid_retained_receipt_is_terminal_without_fresh_scan_or_policy(self):
        for provider, defect in (('aws', None), ('hetzner', None), ('hetzner', 'nullable_workflow')):
            with self.subTest(provider=provider, declared_variant=defect):
                self.setUp()
                self.seed_http(terminal=True, provider=provider, defect=defect)
                sql = self.terminal_sql(91)
                self.assertNotIn('public.http_maintenance_dispatch_effect_scan(', sql)
                self.actual_sql(sql, {'busy_jobs':0})
                self.actual_sql(self.terminal_sql(89), {'busy_jobs':1})

    def test_schema91_missing_malformed_or_foreign_retained_proofs_stay_busy(self):
        for defect in ('missing_receipt','foreign_job','foreign_run','job_sha','run_sha','old_update',
                       'members_sha','old_process','wrong_reason','ACK','pointer','foreign_cause',
                       'foreign_workflow','unfinished','envelope_hash','scan_extra','scan_missing',
                       'member_extra','effect','overflow','decimal_integer'):
            with self.subTest(declared_defect=defect):
                self.setUp()
                self.seed_http(terminal=True, defect=defect)
                self.actual_sql(self.terminal_sql(91), {'busy_jobs':1})

    def test_exact_http_HELD_counts_are_one_one_zero_and_never_a_generic_busy_allowance(self):
        for schema in (89, 91):
            with self.subTest(schema=schema, declared_class='one exact known UNKNOWN'):
                self.setUp()
                projection = self.seed_http(terminal=False)
                self.actual_sql(cas.http_maintenance_counts_sql(projection, schema),
                                {'total_jobs':1,'held_jobs':1,'unrelated_jobs':0})
                wrong = copy.deepcopy(projection)
                wrong['original_dispatch_sha256'] = 'f' * 64
                self.actual_sql(cas.http_maintenance_counts_sql(wrong, schema),
                                {'total_jobs':1,'held_jobs':0,'unrelated_jobs':1})
                self.terminal_insert('capacity_dispatch_jobs', {'id':base.uid(3300),'run_id':base.uid(3301),
                    'realm':'dakasa-production','environment':'production','domain':'notify',
                    'dimension':'original_notify_aws_vm_members','state':'queued'})
                self.actual_sql(cas.http_maintenance_counts_sql(projection, schema),
                                {'total_jobs':2,'held_jobs':1,'unrelated_jobs':1})
        for phase in ('PRESEND', 'AFTER-ACK'):
            with self.subTest(phase=phase, declared_real_PG_current_member_drift=True):
                self.assert_actual_current_member_drift(phase)

    def assert_actual_current_member_drift(self, phase):
        """Exercise the actual boundary comparator over actual changing PG rows.

        The query input is a declared CI projection codec, not production ef9.
        Full ef9/function parity stays mandatory in product91 PG16/17. Only
        transport/custody operands and compiled test-input constants are bound;
        no validator, count predicate or database result is replaced.
        """
        self.setUp()
        projection = self.seed_http(terminal=False)
        member = projection['effect_scan']['current_members'][0]
        self.terminal_insert('capacity_resource_slots', {'namespace':'dakasa-production',
            'environment':'production','domain':'notify','dimension':'original_notify_hetzner_vm_members',
            'integration_instance_id':base.uid(3400),'scope_checksum':'f' * 64,
            'profile_name':'declared-CI-http','slot':1,'resource_id':member['resource_id'],
            'revision':1,'slot_record':member})
        query = ("WITH requested AS (SELECT $1::uuid AS id), members AS ("
            "SELECT jsonb_agg(slot_record ORDER BY slot) AS value FROM capacity_resource_slots "
            "WHERE dimension='original_notify_hetzner_vm_members') SELECT " + self.value(projection) +
            " || jsonb_build_object('observed_at_pg',clock_timestamp(),'job_id',requested.id,"
            "'cas'," + self.value(projection['cas']) + " || jsonb_build_object('expected_members_sha256',"
            "encode(sha256(convert_to(members.value::text,'UTF8')),'hex')),"
            "'effect_scan'," + self.value(projection['effect_scan']) +
            " || jsonb_build_object('current_members',members.value,'current_members_sha256',"
            "encode(sha256(convert_to(members.value::text,'UTF8')),'hex'))) FROM members,requested;\n").encode()
        bundle = {'projection':projection,'query':query}
        recorded = []

        def transport(argv, **kwargs):
            self.assertEqual(argv[:len(base.cut.KUBE)], base.cut.KUBE)
            self.assertEqual(kwargs['timeout'], 12)
            result = self.pg(kwargs['input'].decode())
            recorded.append(json.loads(result.stdout))
            return result

        with tempfile.TemporaryDirectory() as folder, base.binding(self.expected), \
                patch.multiple(cas, HTTP_MAINTENANCE_UPGRADE_BOUND=True,
                               HTTP_MAINTENANCE_PRE91_QUERY_SHA256=cas.sha(query)), \
                patch.object(base.cut.C, 'read', side_effect=lambda path, *_: Path(path).read_bytes()), \
                patch.object(base.cut.subprocess, 'run', side_effect=transport), \
                patch.object(cas.API, 'request', side_effect=AssertionError('no native API')) as api:
            before = self.full_snapshot()
            accepted = Path(folder) / 'accepted'
            accepted.mkdir()
            self.assertEqual(cas.http_maintenance_current_preimage(base.cut, accepted, bundle, phase),
                             {'total_jobs':1,'held_jobs':1,'unrelated_jobs':0})
            self.assertEqual(len(recorded), 2)
            self.assertEqual(self.full_snapshot(), before)
            # This declared concurrent change is outside either read-only guard.
            # Job/run originals remain unchanged; a counts-only guard still passes.
            self.pg("UPDATE capacity_resource_slots SET slot_record=slot_record || "
                    "'{\"installation_sha256\":\"" + '9' * 64 + "\"}'::jsonb "
                    "WHERE dimension='original_notify_hetzner_vm_members';")
            self.actual_sql(cas.http_maintenance_counts_sql(projection, 91),
                            {'total_jobs':1,'held_jobs':1,'unrelated_jobs':0})
            changed = self.full_snapshot()
            refused = Path(folder) / 'refused'
            refused.mkdir()
            with self.assertRaisesRegex(cas.Hold, 'FRESH_CANONICAL_HTTP_PROJECTION_MATCHES_COMPLETE_REVIEWED_ORIGINAL'):
                cas.http_maintenance_current_preimage(base.cut, refused, bundle, phase)
            self.assertEqual(len(recorded), 3, 'changed semantics must refuse before a second counts read')
            self.assertEqual(self.full_snapshot(), changed, 'refused boundary must not repair the changed row')
            api.assert_not_called()
