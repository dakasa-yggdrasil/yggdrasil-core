"""G8 typed CAS tests. Native boundaries are simulated; SQL uses CI PG16.

The disposable PostgreSQL fixture uses exact relevant Source table DDL. Its
Goose rows are declared fixture metadata, not full migration qualification;
the separately required full PostgreSQL/Native gates remain mandatory.
"""
import ast
import copy
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import types
import unittest
from unittest.mock import Mock, patch

import test_g8pair_tools as tools


REPO = tools.source.ROOT.parents[1]
CAS_PATH = tools.source.ROOT / 'rollout/core_image_cas_once_g8.py'
spec = importlib.util.spec_from_file_location('g8_actual_typed_cas_CI', CAS_PATH)
cas = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cas)
cut = tools.load_tool('g8cut')
REAL_RUN = subprocess.run
SQL_SHA = '7269ff606ca948d30a08fe7efed5594d616442ed050d0df3c0c613c6826428dd'


def database_sql():
    tree = ast.parse(CAS_PATH.read_text())
    fn = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'database_preflight')
    assignment = next(n for n in fn.body if isinstance(n, ast.Assign)
                      and any(isinstance(t, ast.Name) and t.id == 'sql' for t in n.targets))
    return ast.literal_eval(assignment.value)


def core_preimage():
    """Declared CI API data, not a native snapshot or future readiness receipt."""
    image = cut.C.IMAGE_PREFIX + cut.C.OLD_DIGEST
    deployment = {'apiVersion': 'apps/v1', 'kind': 'Deployment',
                  'metadata': {'namespace': 'dakasa', 'name': 'yggdrasil', 'uid': cas.UID,
                               'generation': cas.GENERATION, 'resourceVersion': '100',
                               'annotations': {'dakasa.io/core-source-commit': cas.OLD_SOURCE}},
                  'spec': {'replicas': 1, 'template': {'spec': {'containers': [{'name': 'core', 'image': image}]}}},
                  'status': {'observedGeneration': cas.GENERATION, 'readyReplicas': 1,
                             'updatedReplicas': 1, 'availableReplicas': 1}}
    pod = {'metadata': {'uid': cas.OLD_POD, 'name': 'declared-CI-old-core'},
           'spec': {'containers': [{'name': 'core', 'image': image}]},
           'status': {'phase': 'Running', 'podIP': '10.42.0.1', 'containerStatuses': [
               {'name': 'core', 'ready': True, 'restartCount': 0, 'state': {'running': {'startedAt': '2026-11-03T00:00:00Z'}},
                'imageID': image, 'containerID': 'containerd://declared-CI-container'}]}}
    return deployment, {'items': [pod]}


def declared_acceptance():
    """Simulated physical/publication facts; all raw-byte hashes are real."""
    manifest = tools.declared_manifest()
    controller = copy.deepcopy(manifest['expected_controller_identity'])
    guardian = copy.deepcopy(manifest['expected_guardian_identity'])
    full = {**controller, 'cmdline_sha256': '6' * 64, 'initial_R42_admitted_lifetime': False}
    standing = b'declared-CI-standing-not-native-authority'
    own = {'schema': 'Root_owning_finite512_current15_readonly_observation_v1',
           'source_sha256': cas.SOURCE_PIN, 'standing_config_sha256': cut.C.sha(standing),
           'identity': full, 'measurement': {'qualified_15_seconds': True, 'all_requested_rows_accounted_for': True},
           'kernel': {'all_four_backends_and_reverse_sources_positive': True}}
    observation = {k: copy.deepcopy(own[k]) for k in ('identity', 'measurement', 'kernel')}
    key = '7' * 64
    full_path = cut.C.LEDGER / (key + '-QUALIFIED.PUBLIC.json')
    own_path = cut.C.LEDGER / (guardian['boot_id'] + '-GUARDIAN-' + guardian['InvocationID'] + '-FIRST-CURRENT15-RETURN.PUBLIC.json')
    bodies = {cut.C.NEW_STANDING: standing, full_path: b'declared-CI-original120', own_path: cut.C.wire(own)}
    owner = types.SimpleNamespace(identity=Mock(return_value=full), key=lambda _: key,
             original_qualification_measurement=Mock(return_value={'declared_recomputed120': True}),
             current15_readonly=Mock(return_value=(observation, b'prefix', b'suffix', [])),
             sha=cas.SOURCE_PIN, raw_config=standing)
    backend = types.SimpleNamespace(files=Mock(), protected=Mock(return_value=tools.protected_refs()))
    result = {'source_commit': manifest['source_commit'], 'source_R': cas.CORE_R, 'amd64_D': cut.C.NEW_DIGEST,
              'new_guardian_source_sha256': cas.SOURCE_PIN, 'controller_config_sha256': cut.C.HEAD_CONFIG_SHA,
              'independent_current15': True, 'all_inherited_budget_and_original_refs_unchanged': True,
              'Core_Cold_Hub_or_provider_mutation': False, 'conservative_per_role_gap_seconds': {'declared-role': 0},
              'standing_sha256': cut.C.sha(standing), 'controller': controller, 'guardian': guardian,
              'actual_new_full120_ref': {'path': str(full_path), 'sha256': cut.C.sha(bodies[full_path])},
              'own_daemon_first_current15_ref': {'path': str(own_path), 'sha256': cut.C.sha(bodies[own_path])}}
    returned = {'schema': 'g8_pair_swap_return_v1', 'status': 'CONFIG_SWAP_OK', 'result': result,
                'automatic_replay': False, 'Guest_or_Core_business_authority': False}
    return manifest, returned, owner, backend, bodies, observation


class G8CASTests(unittest.TestCase):
    def test_bound_cas_is_outside_runtime_package_and_pins_actual_r4_tools(self):
        self.assertEqual(cas.CORE_R, tools.source.SOURCE_R)
        self.assertEqual(cas.SOURCE_PIN, tools.source.digest((tools.source.NEW / 'source/network_guardian.py').read_bytes()))
        self.assertEqual(cas.TOOL_PINS, {name: tools.source.digest((tools.TOOLS / name).read_bytes()) for name in cut.C.TOOLS})
        self.assertEqual(cas.EXPECTED_INHERITED_REFS, tools.protected_refs())
        self.assertEqual(cas.GENERATION, 271)
        self.assertNotIn('rollout/core_image_cas_once_g8.py', json.loads((tools.source.NEW / 'PACKAGE.json').read_bytes())['files'])
        self.assertEqual(tools.source.digest(database_sql().encode()), SQL_SHA)
        evidence = Path(os.environ['GUARDIAN_CI_EVIDENCE'])
        evidence.mkdir(parents=True, exist_ok=True)
        (evidence / 'g8-cas-full-readonly-query.sql').write_text(database_sql())

    def test_api_makes_one_request_and_closes_on_timeout_nonzero_or_oversize(self):
        for variant in ('success', 'request-timeout', 'read-timeout', 'oversize'):
            response = Mock(status=200)
            response.getheader.side_effect = lambda name: {'Audit-Id': 'declared-CI-audit', 'Date': 'declared-CI-date'}[name]
            response.read.return_value = b'{}'
            conn = Mock()
            conn.getresponse.return_value = response
            if variant == 'request-timeout':
                conn.request.side_effect = TimeoutError('declared native ACK uncertainty')
            elif variant == 'read-timeout':
                response.read.side_effect = TimeoutError('declared original read uncertainty')
            elif variant == 'oversize':
                response.read.return_value = b'x' * ((16 << 20) + 1)
            api = cas.API.__new__(cas.API)
            api.context = object()
            with self.subTest(variant=variant), patch.object(cas.http.client, 'HTTPSConnection', return_value=conn) as connect:
                if variant == 'success':
                    status, raw, headers = api.request('PATCH', cas.DEP_URI, b'[]')
                    self.assertEqual((status, raw), (200, b'{}'))
                    self.assertEqual(headers['audit_id'], 'declared-CI-audit')
                else:
                    with self.assertRaises((TimeoutError, cas.Hold)):
                        api.request('PATCH', cas.DEP_URI, b'[]')
                connect.assert_called_once()
                conn.request.assert_called_once()
                conn.close.assert_called_once()

    def test_api_read_retains_original_malformed_and_non200_bytes_before_parse(self):
        for status, raw in ((200, b'{malformed original'), (409, b'declared-original-conflict')):
            stored = {}
            C = types.SimpleNamespace(once=lambda p, b: stored.setdefault(Path(p).name, b), wire=cut.C.wire, loads=cut.C.loads)
            api = types.SimpleNamespace(request=Mock(return_value=(status, raw, {'audit_id': 'declared-CI'})))
            with self.subTest(status=status), self.assertRaises((cas.Hold, ValueError)):
                cas.api_read(api, C, Path('/declared-CI'), 'READ', cas.DEP_URI)
            self.assertEqual(stored['READ.json'], raw)
            api.request.assert_called_once_with('GET', cas.DEP_URI)

    def test_full_core_preimage_refuses_source_uid_rv_restarts_duplicates_and_imageid(self):
        deployment, pods = core_preimage()
        self.assertEqual(cas.core_before(deployment, pods, cut.C)['pod_uid'], cas.OLD_POD)
        for variant in ('source', 'uid', 'rv', 'restart', 'duplicate', 'imageID', 'generation', 'replicas'):
            d, p = copy.deepcopy(deployment), copy.deepcopy(pods)
            if variant == 'source':
                d['metadata']['annotations']['dakasa.io/core-source-commit'] = tools.source.SOURCE_R
            elif variant == 'uid':
                d['metadata']['uid'] = 'foreign'
            elif variant == 'rv':
                d['metadata']['resourceVersion'] = 'unknown'
            elif variant == 'restart':
                p['items'][0]['status']['containerStatuses'][0]['restartCount'] = 1
            elif variant == 'duplicate':
                p['items'].append(copy.deepcopy(p['items'][0]))
            elif variant == 'imageID':
                p['items'][0]['status']['containerStatuses'][0]['imageID'] = cut.C.IMAGE_PREFIX + cut.C.NEW_DIGEST
            elif variant == 'generation':
                d['metadata']['generation'] += 1
            else:
                d['spec']['replicas'] = 2
            with self.subTest(variant=variant), self.assertRaises(cas.Hold):
                cas.core_before(d, p, cut.C)

    def test_patch_result_allows_only_image_source_and_change_cause(self):
        before, _ = core_preimage()
        after = copy.deepcopy(before)
        after['spec']['template']['spec']['containers'][0]['image'] = cut.C.IMAGE_PREFIX + cut.C.NEW_DIGEST
        after['metadata']['generation'] += 1
        after['metadata']['resourceVersion'] = '101'
        after['metadata']['annotations'].update({'dakasa.io/core-source-commit': cas.CORE_R,
                                                'kubernetes.io/change-cause': cas.CHANGE_CAUSE})
        cas.result_shape(before, after, cut.C)
        for variant in ('extra-spec', 'wrong-source', 'foreign-uid', 'wrong-generation'):
            wrong = copy.deepcopy(after)
            if variant == 'extra-spec':
                wrong['spec']['replicas'] = 2
            elif variant == 'wrong-source':
                wrong['metadata']['annotations']['dakasa.io/core-source-commit'] = cas.OLD_SOURCE
            elif variant == 'foreign-uid':
                wrong['metadata']['uid'] = 'foreign'
            else:
                wrong['metadata']['generation'] += 1
            with self.subTest(variant=variant), self.assertRaises(cas.Hold):
                cas.result_shape(before, wrong, cut.C)

    def test_raw_current15_abi_binds_owner_source_without_invented_envelope_keys(self):
        for variant in ('valid-raw', 'owner-source', 'owner-standing', 'raw-identity', 'missing120', 'kernel-false'):
            manifest, returned, owner, backend, bodies, observation = declared_acceptance()
            self.assertNotIn('source_sha256', observation)
            self.assertNotIn('standing_config_sha256', observation)
            if variant == 'owner-source':
                owner.sha = tools.source.G7_SOURCE
            elif variant == 'owner-standing':
                owner.raw_config += b'drift'
            elif variant == 'raw-identity':
                observation['identity'] = {**observation['identity'], 'pid': 999}
            elif variant == 'missing120':
                owner.original_qualification_measurement.return_value = None
            elif variant == 'kernel-false':
                observation['kernel']['all_four_backends_and_reverse_sources_positive'] = False
            G = types.SimpleNamespace(Owner=Mock(return_value=owner))
            result = returned['result']
            with self.subTest(variant=variant), patch.object(cut, 'Backend', return_value=backend), \
                    patch.object(cut.C, 'read', side_effect=lambda p, *_: bodies[Path(p)]), \
                    patch.object(cut.C, 'once'), patch.object(cut.C, 'load_guardian', return_value=G), \
                    patch.object(cut, 'physical_identity', side_effect=[result['controller'], result['guardian']]), \
                    patch.object(cut, 'native', side_effect=AssertionError('no native acceptance effect')) as native:
                if variant == 'valid-raw':
                    accepted = cas.g8_acceptance(cut, tools.TOOLS.parent, manifest, returned, Path('/declared-CI'))
                    self.assertIs(accepted[0], backend)
                else:
                    with self.assertRaises(cas.Hold):
                        cas.g8_acceptance(cut, tools.TOOLS.parent, manifest, returned, Path('/declared-CI'))
                native.assert_not_called()

    def test_actual_cas_main_has_one_live_patch_after_both_durable_markers(self):
        tree = ast.parse(CAS_PATH.read_text())
        fn = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'main')
        requests = [n for n in ast.walk(fn) if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
                    and n.func.attr == 'request' and isinstance(n.func.value, ast.Name) and n.func.value.id == 'api']
        self.assertEqual(len(requests), 2)
        self.assertTrue(all(ast.literal_eval(n.args[0]) == 'PATCH' for n in requests))
        dry = next(n for n in requests if 'dryRun=All' in ast.get_source_segment(CAS_PATH.read_text(), n))
        live = next(n for n in requests if n is not dry)
        markers = [n for n in ast.walk(fn) if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
                   and n.func.attr == 'once' and 'POSSIBLE' in ast.get_source_segment(CAS_PATH.read_text(), n)]
        self.assertEqual(len(markers), 2)
        self.assertTrue(all(dry.lineno < n.lineno < live.lineno for n in markers))
        self.assertFalse(any(isinstance(n, (ast.For, ast.While)) and n.lineno <= live.lineno <= n.end_lineno for n in ast.walk(fn)))


def source_create_table(filename, table):
    raw = (REPO / 'db/migrations' / filename).read_text()
    match = re.search(r'CREATE TABLE IF NOT EXISTS public\.' + re.escape(table) + r'\s*\([\s\S]*?\n\);', raw)
    if not match:
        raise AssertionError('exact Source fixture DDL missing: ' + table)
    return match.group(0)


class G8CASPostgresTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.container = os.environ.get('GUARDIAN_CI_POSTGRES_CONTAINER', '')
        if os.environ.get('GITHUB_ACTIONS') != 'true' or not re.fullmatch('[a-f0-9]{64}', cls.container):
            raise RuntimeError('mandatory disposable GitHub CI PG16 service; never skip or use a remote DB')
        if os.environ.get('DOCKER_HOST') not in (None, '', 'unix:///var/run/docker.sock'):
            raise RuntimeError('local disposable Docker service only')
        image = REAL_RUN(['docker', 'inspect', '--format', '{{.Config.Image}}', cls.container],
                         capture_output=True, text=True, timeout=8)
        if image.returncode != 0 or image.stdout.strip() != 'postgres:16':
            raise RuntimeError('exact disposable postgres:16 job service required')

    def pg(self, sql):
        result = REAL_RUN(['docker', 'exec', '-i', self.container, 'psql', '-X', '-q', '-v', 'ON_ERROR_STOP=1',
                           '-U', 'guardian_ci', '-d', 'yggdrasil', '-At'], input=sql.encode(),
                          capture_output=True, timeout=12)
        self.assertEqual(result.returncode, 0, result.stderr.decode(errors='replace'))
        return result

    def setUp(self):
        self.pg('DROP SCHEMA public CASCADE; CREATE SCHEMA public; CREATE EXTENSION IF NOT EXISTS pgcrypto;')
        statements = [source_create_table(file, table) for file, table in (
            ('00001_initial.sql', 'manifests'), ('00018_workflow_runs.sql', 'workflow_runs'),
            ('00056_capacity_intents.sql', 'capacity_intents'), ('00057_capacity_mutation_grants.sql', 'capacity_mutation_grants'),
            ('00063_capacity_vm_original_retirement.sql', 'capacity_vm_provisioning_preregistrations'),
            ('00061_capacity_dispatch_jobs.sql', 'capacity_dispatch_jobs'),
            ('00088_failed_serving_guest_disposal.sql', 'capacity_guest_failed_serving_disposals'))]
        self.pg('\n'.join(statements) + '''
CREATE UNIQUE INDEX manifests_single_active_uidx ON public.manifests(kind,namespace,name) WHERE active;
CREATE UNIQUE INDEX manifests_identity_version_uidx ON public.manifests(kind,namespace,name,version);
CREATE INDEX workflow_runs_workflow_id_idx ON public.workflow_runs(workflow_id);
CREATE INDEX workflow_runs_workflow_idx ON public.workflow_runs(workflow_namespace,workflow_name,created_at DESC);
CREATE TABLE public.goose_db_version(id bigint PRIMARY KEY,version_id bigint NOT NULL,is_applied boolean NOT NULL,tstamp timestamp NOT NULL DEFAULT now());
INSERT INTO public.goose_db_version(id,version_id,is_applied) VALUES(1,88,true),(2,89,true);
INSERT INTO public.manifests(id,api_version,kind,namespace,name,version,active,spec,checksum) VALUES
 ('10000000-0000-0000-0000-000000000001','v1','workflow','dakasa-production','notify-aws-elastic-capacity',1,false,'{}','declared-CI-old'),
 ('10000000-0000-0000-0000-000000000002','v1','workflow','dakasa-production','notify-aws-elastic-capacity',2,true,'{}','declared-CI-current'),
 ('20000000-0000-0000-0000-000000000001','v1','workflow','dakasa-production','notify-hetzner-elastic-capacity',1,true,'{}','declared-CI-HZ'),
 ('30000000-0000-0000-0000-000000000001','v1','workflow','foreign','notify-aws-elastic-capacity',1,true,'{}','declared-CI-foreign');
INSERT INTO public.capacity_intents(namespace,environment,domain,dimension,intent) VALUES
 ('dakasa-production','production','notify','original_notify_aws_vm_members','{"phase":"promoted","recovery_only":false}'),
 ('dakasa-production','production','notify','original_notify_hetzner_vm_members','{"phase":"promoted","recovery_only":false}');
''')
        major = int(self.pg("SELECT current_setting('server_version_num')::int/10000").stdout)
        self.assertEqual(major, 16)

    def add_run(self, number, workflow_id, namespace, name, status, finished):
        wid = 'NULL' if workflow_id is None else "'" + workflow_id + "'"
        end = 'clock_timestamp()' if finished else 'NULL'
        rid = '40000000-0000-0000-0000-' + str(number).zfill(12)
        self.pg("INSERT INTO public.workflow_runs(id,workflow_id,workflow_namespace,workflow_name,status,finished_at) VALUES('" + rid + "'," + wid + ",'" + namespace + "','" + name + "','" + status + "'," + end + ');')
        return rid

    def observe(self, success, busy_runs=None):
        captured, originals = [], []
        def transport(argv, **kwargs):
            self.assertEqual(argv[:len(cut.KUBE)], cut.KUBE)
            self.assertEqual(kwargs['timeout'], 12)
            self.assertEqual(tools.source.digest(kwargs['input']), SQL_SHA)
            result = self.pg(kwargs['input'].decode())
            captured.append(json.loads(result.stdout))
            originals.append(result.stdout)
            return result
        with tempfile.TemporaryDirectory() as folder, patch.object(cut.subprocess, 'run', side_effect=transport) as run, \
                patch.object(cut.C, 'read', side_effect=lambda p, *_: Path(p).read_bytes()):
            # Only root-owned readback custody is simulated in a CI temp dir;
            # the real exclusive/fsync writer and actual PG result are retained.
            if success:
                cas.database_preflight(cut, Path(folder))
            else:
                with self.assertRaises(cas.Hold):
                    cas.database_preflight(cut, Path(folder))
            run.assert_called_once()
            self.assertEqual((Path(folder) / 'DB-READONLY.stdout').read_bytes(), originals[0])
            if busy_runs is not None:
                self.assertEqual(captured[0]['busy_runs'], busy_runs)
            print('G8_CAS_REAL_PG16 ' + json.dumps({'case': self.id(), 'facts': captured[0],
                  'fixture_schema_metadata_not_full_Goose_qualification': True}, sort_keys=True))
        return captured[0]

    def test_actual_full_query_readonly_catalog_and_zero_guard_baseline(self):
        value = self.observe(True, 0)
        self.assertEqual(value['readonly'], 'on')
        self.assertTrue(value['index89_valid'])
        self.assertEqual(value['schema'], 89)

    def test_union_deduplicates_overlapping_uuid_and_logical_identity(self):
        self.add_run(1, '10000000-0000-0000-0000-000000000002', 'dakasa-production', 'notify-aws-elastic-capacity', 'running', False)
        self.observe(False, 1)

    def test_inactive_historical_uuid_with_foreign_logical_identity_still_blocks(self):
        self.add_run(1, '10000000-0000-0000-0000-000000000001', 'foreign', 'mismatched-logical', 'running', True)
        self.observe(False, 1)

    def test_null_uuid_logical_identity_and_terminal_without_finish_still_block(self):
        self.add_run(1, None, 'dakasa-production', 'notify-hetzner-elastic-capacity', 'succeeded', False)
        self.observe(False, 1)

    def test_proper_terminal_and_unrelated_namespace_profile_are_not_busy(self):
        self.add_run(1, '10000000-0000-0000-0000-000000000001', 'dakasa-production', 'notify-aws-elastic-capacity', 'failed', True)
        self.add_run(2, '30000000-0000-0000-0000-000000000001', 'foreign', 'notify-aws-elastic-capacity', 'running', False)
        self.add_run(3, None, 'dakasa-production', 'unrelated-profile-workflow', 'running', False)
        self.pg("INSERT INTO public.capacity_intents(namespace,environment,domain,dimension,intent) VALUES('dakasa-production','production','notify','unrelated-profile','{\"phase\":\"pending\",\"lease_owner\":\"unrelated\"}')")
        self.observe(True, 0)

    def test_actual_index_guard_refuses_missing_unique_partial_and_wrong_key(self):
        for ddl in ('', 'CREATE UNIQUE INDEX workflow_runs_workflow_id_idx ON public.workflow_runs(workflow_id);',
                    "CREATE INDEX workflow_runs_workflow_id_idx ON public.workflow_runs(workflow_id) WHERE status='running';",
                    'CREATE INDEX workflow_runs_workflow_id_idx ON public.workflow_runs(id);'):
            self.pg('DROP INDEX IF EXISTS public.workflow_runs_workflow_id_idx;' + ddl)
            with self.subTest(index=ddl):
                self.assertFalse(self.observe(False, 0)['index89_valid'])
