"""Scripted CI-only operator operands; no native/Root acceptance is declared.

This module is authored for mandatory CI invocation. It is not run locally.
The declared API/defaults and SHA operands are storage/transport fixtures only.
"""
import copy
import importlib.util
import json
from pathlib import Path
import types
import unittest
from unittest.mock import patch

PATH = Path(__file__).resolve().parents[1] / 'rollout/goose92_native_once.py'
spec = importlib.util.spec_from_file_location('goose92_declared_ci_only', PATH)
G = importlib.util.module_from_spec(spec)
spec.loader.exec_module(G)
Q, D = '1' * 40, '2' * 64
JID = '11111111-1111-4111-8111-111111111111'
UID = '22222222-2222-4222-8222-222222222222'
PUID = '33333333-3333-4333-8333-333333333333'
S = types.SimpleNamespace(CORE_NODE='ip-172-31-9-242')


def binding():
    return patch.multiple(G, COMPANION_SOURCE_Q=Q, COMPANION_IMAGE_D=D, JOB_UUID=JID)


class Files:
    def __init__(self):
        self.data = {}
        self.order = []

    def once(self, path, raw):
        if path in self.data:
            raise G.Hold('DECLARED_EXCLUSIVE_WRITE')
        self.data[path] = raw
        self.order.append(path)


class Claim:
    def __init__(self, files):
        self.files = files

    def exists(self):
        return self in self.files.data


class Inner:
    def __init__(self, replies):
        self.replies, self.calls = list(replies), []

    def request(self, method, uri, body):
        self.calls.append((method, uri, body))
        value = self.replies.pop(0)
        if isinstance(value, BaseException):
            raise value
        return value


def qualification_operands():
    refs = {k: {'path': '/declared/' + k, 'sha256': 'a' * 64}
            for k in ('companion_image_proof', 'source_ci_gate', 'companion_sql_roster', 'baseline91_acceptance')}
    ci_ref = {'path': '/declared/ci', 'sha256': 'b' * 64}
    roster = {'schema': 'qualified_companion_SQL_SHA_size_roster_v1', 'source': Q,
              'files': {'%05d_declared.sql' % v: {'version': v, 'bytes': 9, 'sha256': 'c' * 64}
                        for v in range(1, 93) if v != 40}}
    roster['files']['00092_workflow_runs_busy_logical_index.sql'] = roster['files'].pop('00092_declared.sql')
    roster['files']['00092_workflow_runs_busy_logical_index.sql']['sha256'] = G.M92
    proof = {'schema': 'root_actual_goose92_companion_release_image_ECR_qualification_v1',
             'source': Q, 'amd64_manifest_digest': 'sha256:' + D, 'ecr_image': G.PREFIX + D,
             'ecr_exact_GHCR_manifest_body': True,
             'shipped_SQL_versions': [v for v in range(1, 93) if v != 40],
             'all_SQL_SHA_and_bytes_equal_exact_source_both_architectures': True,
             'independent_four_AMD64_ELF_nonexecutable_clean_source_build_info': True,
             'independent_four_ARM64_ELF_nonexecutable_clean_source_build_info': True,
             'SQL_source_roster': refs['companion_sql_roster']}
    gate = {'schema': 'root_goose92_companion_Source_prerequisite_v1', 'ops_source': Q,
            'reviewed_by_root': True, 'workflow_runs': 1, 'jobs': 1, 'attempt': 1,
            'all_success': True, 'ci_attestation': ci_ref}
    ci = {'schema': 'guardian_goose92_companion_exact_source_ci_v1', 'commit': Q,
          'reviewed_by_root': True, 'runs': [{'id': 1, 'name': 'declared', 'event': 'pull_request',
                                           'head_sha': Q, 'status': 'completed', 'conclusion': 'success', 'attempt': 1}]}
    baseline = {'schema': 'root_goose91_independent_acceptance_v1', 'reviewed_by_root': True,
                'source': G.SELECTED_CORE_R, 'complete_history_sha256': 'd' * 64,
                'schema90_91_catalog_sha256': 'e' * 64}
    bodies = dict(zip((refs[k]['path'] for k in ('companion_image_proof', 'source_ci_gate', 'companion_sql_roster', 'baseline91_acceptance')),
                      (proof, gate, roster, baseline)))
    bodies['/declared/ci'] = ci
    return refs, bodies


def catalogs():
    rows = [{'id': i + 1, 'version_id': v, 'is_applied': True, 'tstamp': '2026-01-01T00:00:00Z'}
            for i, v in enumerate([0] + [v for v in range(1, 92) if v != 40])]
    oldwire = json.dumps(rows)
    before = {'database': 'yggdrasil', 'readonly': 'on', 'latest_versions': [0] + [v for v in range(1, 92) if v != 40],
              'rows90': 1, 'rows91': 1, 'complete_history_wire': oldwire,
              'other_migrators_ddl': 0, 'other_cic': 0, 'ddl_locks': 0,
              'catalog90': {'declared': 'unchanged90'}, 'catalog91': {'declared': 'unchanged91'}}
    accepted = {'complete_history_sha256': G.sha(oldwire.encode()),
                'schema90_91_catalog_sha256': G.sha(G.wire({'catalog90': before['catalog90'], 'catalog91': before['catalog91']}))}
    index = {'readonly': 'on', 'rows92': 0, 'index_absent': True, 'index92_valid': False,
             'index_definition': None, 'old91_history_wire': oldwire}
    after = copy.deepcopy(before)
    after['latest_versions'].append(92)
    after['complete_history_wire'] = json.dumps(rows + [{'id': len(rows) + 1, 'version_id': 92,
                                                       'is_applied': True, 'tstamp': '2026-01-01T00:01:00Z'}])
    after_index = dict(index, rows92=1, index_absent=False, index92_valid=True,
                       index_definition='declared index; actual helper PG16 and full Goose PG16/17 are separate')
    return before, index, accepted, after, after_index


def native_objects(job):
    """Declared native defaults from the existing Goose91 fixture contract."""
    actual = copy.deepcopy(job)
    actual['metadata']['uid'] = UID
    native_spec = actual['spec']['template']['spec']
    native_spec.update(dnsPolicy='ClusterFirst', schedulerName='default-scheduler', serviceAccount='yggdrasil')
    native_spec['containers'][0].update(terminationMessagePath='/dev/termination-log', terminationMessagePolicy='File')
    actual['spec'].update(completionMode='NonIndexed', manualSelector=False, podReplacementPolicy='TerminatingOrFailed',
                          suspend=False, selector={'matchLabels': {'batch.kubernetes.io/controller-uid': UID}})
    actual['status'] = {'conditions': [{'type': 'Complete', 'status': 'True'}], 'succeeded': 1}
    ps = copy.deepcopy(native_spec)
    ps.update(enableServiceLinks=True, nodeName=S.CORE_NODE, priority=0, preemptionPolicy='PreemptLowerPriority',
              tolerations=[{'effect': 'NoExecute', 'key': 'node.kubernetes.io/not-ready', 'operator': 'Exists', 'tolerationSeconds': 300},
                           {'effect': 'NoExecute', 'key': 'node.kubernetes.io/unreachable', 'operator': 'Exists', 'tolerationSeconds': 300}])
    pod = {'metadata': {'uid': PUID, 'name': job['metadata']['name'] + '-abcde',
                        'labels': copy.deepcopy(job['metadata']['labels']),
                        'ownerReferences': [{'kind': 'Job', 'controller': True, 'uid': UID, 'name': job['metadata']['name']}]},
           'spec': ps, 'status': {'phase': 'Succeeded', 'containerStatuses': [
               {'name': 'migrator', 'restartCount': 0, 'imageID': G.PREFIX + D,
                'state': {'terminated': {'exitCode': 0}}}]}}
    return actual, pod


class Goose92NativeOnceTests(unittest.TestCase):
    def test_bindings_fail_before_input_and_credentials(self):
        with patch.object(G, 'private_read', side_effect=AssertionError('input must not be read')):
            with self.assertRaises(G.Hold):
                G.main()
        self.assertFalse(G.SOURCE_BOUND)
        for key in ('COMPANION_SOURCE_Q', 'COMPANION_IMAGE_D', 'COMPANION_IMAGE_PROOF_SHA256',
                    'SOURCE_CI_GATE_SHA256', 'CAS_SOURCE_SHA256', 'CONFIG_SHA256', 'JOB_UUID', 'JOB_MANIFEST_SHA256'):
            self.assertIsNone(getattr(G, key))

    def test_companion_image_and_ci_are_separate_axes(self):
        refs, bodies = qualification_operands()
        def read(ref, cap=4 << 20):
            return G.wire(bodies[ref['path']])
        with binding(), patch.multiple(G, COMPANION_IMAGE_PROOF_SHA256='a' * 64, SOURCE_CI_GATE_SHA256='a' * 64,
                                      BASELINE91_ACCEPTANCE_SHA256='a' * 64, EXPECTED_RUNS=1, EXPECTED_JOBS=1,
                                      REQUIRED_CI=frozenset({('declared', 'pull_request')})), patch.object(G, 'reference', side_effect=read):
            self.assertEqual(G.qualification(refs), bodies['/declared/baseline91_acceptance'])
            for case in ('proof_source_currentP', 'proof_image_selectedCore', 'missing92', 'bad92sha',
                         'CI_head_currentP', 'CI_attempt2', 'wrong_roster_join', 'baseline_wrong_source'):
                with self.subTest(case=case):
                    original = copy.deepcopy(bodies)
                    if case == 'proof_source_currentP': bodies['/declared/companion_image_proof']['source'] = G.CURRENT_OPS_P
                    elif case == 'proof_image_selectedCore': bodies['/declared/companion_image_proof']['amd64_manifest_digest'] = 'sha256:' + G.SELECTED_CORE_D
                    elif case == 'missing92': bodies['/declared/companion_image_proof']['shipped_SQL_versions'].remove(92)
                    elif case == 'bad92sha': bodies['/declared/companion_sql_roster']['files']['00092_workflow_runs_busy_logical_index.sql']['sha256'] = '0' * 64
                    elif case == 'CI_head_currentP': bodies['/declared/ci']['runs'][0]['head_sha'] = G.CURRENT_OPS_P
                    elif case == 'CI_attempt2': bodies['/declared/ci']['runs'][0]['attempt'] = 2
                    elif case == 'wrong_roster_join': bodies['/declared/companion_image_proof']['SQL_source_roster'] = {'path': '/other', 'sha256': 'f' * 64}
                    else: bodies['/declared/baseline91_acceptance']['source'] = Q
                    with self.assertRaises(G.Hold): G.qualification(refs)
                    bodies.clear(); bodies.update(original)

    def test_job_body_is_disjoint_bounded_goose_up(self):
        with binding():
            job = G.job_manifest()
            self.assertEqual(job['metadata']['name'], 'core-goose92-' + JID.replace('-', ''))
            self.assertNotEqual(job['metadata']['labels']['app'], 'yggdrasil')
            self.assertEqual(job['metadata']['labels']['app'], G.APP)
            self.assertEqual({k: job['spec'][k] for k in ('backoffLimit', 'activeDeadlineSeconds', 'parallelism', 'completions')},
                             {'backoffLimit': 0, 'activeDeadlineSeconds': 240, 'parallelism': 1, 'completions': 1})
            pod = job['spec']['template']['spec']; c = pod['containers'][0]
            self.assertEqual(pod['restartPolicy'], 'Never'); self.assertFalse(pod['automountServiceAccountToken'])
            self.assertEqual(c['image'], G.PREFIX + D)
            self.assertNotIn('volumes', pod); self.assertNotIn('volumeMounts', c)
            self.assertEqual(c['command'], ['/bin/sh', '-ceu', '/app/goose up'])
            self.assertEqual({r['name']: r['valueFrom'] for r in c['env'] if r['name'].startswith('DB_')}, G.DB_REFS)
            self.assertIn('statement_timeout=120000ms', next(r['value'] for r in c['env'] if r['name'] == 'PGOPTIONS'))
            actual, _ = native_objects(job)
            G.job_shape(actual, job, UID, S)
            for case in ('overlay', 'wrong_app', 'retry', 'down'):
                with self.subTest(case=case):
                    bad = copy.deepcopy(actual)
                    if case == 'overlay': bad['spec']['template']['spec']['volumes'] = [{'name': 'sql-overlay'}]
                    elif case == 'wrong_app': bad['spec']['template']['metadata']['labels']['app'] = 'yggdrasil'
                    elif case == 'retry': bad['spec']['backoffLimit'] = 1
                    else: bad['spec']['template']['spec']['containers'][0]['command'][-1] = '/app/goose down'
                    with self.assertRaises(G.Hold): G.job_shape(bad, job, UID, S)

    def test_catalog92_preserves_every91_wire_and_catalog(self):
        before, bi, accepted, after, ai = catalogs()
        G.check_catalog(before, bi, accepted)
        G.check_catalog(after, ai, accepted, old=before)
        for case in ('old_wire_changed', 'old_row_changed', 'catalog90_changed', 'catalog91_changed',
                     'two92', 'unapplied92', 'other_DDL', 'other_CIC', 'DDL_lock'):
            with self.subTest(case=case):
                value, index = copy.deepcopy(after), copy.deepcopy(ai)
                if case == 'old_wire_changed': index['old91_history_wire'] += ' '
                elif case == 'old_row_changed':
                    rows = G.loads(value['complete_history_wire']); rows[0]['tstamp'] = 'changed'; value['complete_history_wire'] = json.dumps(rows)
                elif case == 'catalog90_changed': value['catalog90']['declared'] = 'changed'
                elif case == 'catalog91_changed': value['catalog91']['declared'] = 'changed'
                elif case == 'two92': index['rows92'] = 2
                elif case == 'unapplied92':
                    rows = G.loads(value['complete_history_wire']); rows[-1]['is_applied'] = False; value['complete_history_wire'] = json.dumps(rows)
                elif case == 'other_DDL': value['other_migrators_ddl'] = 1
                elif case == 'other_CIC': value['other_cic'] = 1
                else: value['ddl_locks'] = 1
                with self.assertRaises(G.Hold): G.check_catalog(value, index, accepted, old=before)

    def test_index_guard_is_typed_absent_then_exact(self):
        before, bi, accepted, after, ai = catalogs()
        for key, val in (('index_absent', False), ('index92_valid', True), ('rows92', 1), ('index_definition', 'preexisting')):
            with self.subTest(before_key=key):
                bad = dict(bi); bad[key] = val
                with self.assertRaises(G.Hold): G.check_catalog(before, bad, accepted)
        for key, val in (('index_absent', True), ('index92_valid', False), ('rows92', 0), ('index_definition', None)):
            with self.subTest(after_key=key):
                bad = dict(ai); bad[key] = val
                with self.assertRaises(G.Hold): G.check_catalog(after, bad, accepted, old=before)
        # Real predicate/helper semantics belong to the PG16 index test; full Goose has separate PG16/17 gates.
        codec = types.SimpleNamespace(workflow_busy_logical_index92_sql=lambda: '(declared_boolean_source_operand)')
        query = G.index_sql(codec)
        self.assertIn('(declared_boolean_source_operand)', query)
        self.assertIn("to_regclass('public.workflow_runs_busy_logical_idx') IS NULL", query)
        self.assertIn('WHERE version_id<>92', query)
        self.assertNotIn('SET LOCAL enable_', query)
        self.assertNotIn('count(*) FROM workflow_runs', query)

    def test_http_scope_framing_raw_custody_and_consumed_post(self):
        with binding():
            files = Files(); run = Path('/declared/run')
            inner = Inner([(200, b'{bad-json', {'framing_valid': False})])
            api = G.CapturedAPI(inner, files, run, True)
            with self.assertRaises(G.Hold): api.get(G.JOB_URI + '/' + G.job_name())
            self.assertEqual(files.data[run / 'API-0001.raw'], b'{bad-json')
            self.assertIn(run / 'API-0001.HTTP.json', files.data)
            for method, uri in (('DELETE', G.JOB_URI), ('PATCH', G.DEP_URI), ('POST', G.DEP_URI), ('GET', '/api/v1/secrets'), ('GET', None)):
                with self.subTest(method=method, uri=uri):
                    with self.assertRaises(G.Hold): api.request(method, uri)
            api = G.CapturedAPI(Inner([(200, b'{}', {'framing_valid': True})]), Files(), run, True)
            api.get(G.DEP_URI)
            self.assertNotIn(run / 'API-0001.raw', api.C.data)
            self.assertFalse(G.loads(api.C.data[run / 'API-0001.HTTP.json'])['raw_retained'])

    def test_one_global_possible_before_one_post_and_unknown_hold(self):
        with binding(), patch.object(G.time, 'monotonic', return_value=0):
            job = G.job_manifest(); body = G.wire(job); run = Path('/declared/run')
            for case in ('ack201', 'timeout', 'partial201', 'conflict409'):
                with self.subTest(case=case):
                    files = Files(); claim = Claim(files)
                    notfound = (404, G.wire({'kind': 'Status', 'reason': 'NotFound', 'code': 404}), {'framing_valid': True})
                    result = TimeoutError() if case == 'timeout' else (201 if case != 'conflict409' else 409,
                              G.wire({'metadata': {'uid': UID, 'name': G.job_name(), 'namespace': 'dakasa'}}),
                              {'framing_valid': case != 'partial201'})
                    inner = Inner([notfound, result])
                    original = inner.request
                    def request(method, uri, data):
                        if method == 'POST':
                            self.assertIn(claim, files.data)
                            self.assertIn(run / 'POSSIBLE-CREATE.json', files.data)
                        return original(method, uri, data)
                    inner.request = request
                    api = G.CapturedAPI(inner, files, run, True)
                    with patch.object(G, 'CLAIM', claim), patch.object(G, 'JOB_MANIFEST_SHA256', G.sha(body)):
                        if case == 'ack201': self.assertEqual(G.create_once(api, files, run, job, 'a' * 64, 'b' * 64, 500), UID)
                        else:
                            with self.assertRaises((G.Hold, TimeoutError)):
                                G.create_once(api, files, run, job, 'a' * 64, 'b' * 64, 500)
                        self.assertTrue(claim.exists())
                        with self.assertRaises(G.Hold): G.create_once(api, files, run, job, 'a' * 64, 'b' * 64, 500)
                        with self.assertRaises(G.Hold): api.request('POST', G.JOB_URI, body)
                    self.assertEqual(sum(c[0] == 'POST' for c in inner.calls), 1)

    def test_owned_job_pod_image_uid_and_exit_are_mandatory(self):
        with binding(), patch.object(G.time, 'monotonic', return_value=0):
            job = G.job_manifest(); good, pod = native_objects(job)
            for case in ('complete', 'foreign_uid', 'foreign_owner', 'wrong_image', 'restart', 'exit1', 'failed', 'two_pods', 'missing_log'):
                with self.subTest(case=case):
                    j, p = copy.deepcopy(good), copy.deepcopy(pod)
                    if case == 'foreign_uid': j['metadata']['uid'] = PUID
                    elif case == 'foreign_owner': p['metadata']['ownerReferences'][0]['uid'] = PUID
                    elif case == 'wrong_image': p['status']['containerStatuses'][0]['imageID'] = G.PREFIX + 'f' * 64
                    elif case == 'restart': p['status']['containerStatuses'][0]['restartCount'] = 1
                    elif case == 'exit1': p['status']['containerStatuses'][0]['state']['terminated']['exitCode'] = 1
                    elif case == 'failed': j['status']['conditions'].append({'type': 'Failed', 'status': 'True'})
                    logs = b'no migration' if case == 'missing_log' else b'OK 00092_workflow_runs_busy_logical_index.sql\nsuccessfully migrated database to version: 92\n'
                    class Reads:
                        def __init__(self): self.calls = []; self.pod_name = None
                        def get(self, uri):
                            self.calls.append(('GET', uri))
                            return j if uri.startswith(G.JOB_URI) else {'items': [p, p] if case == 'two_pods' else [p]}
                        def request(self, method, uri, body=None):
                            self.calls.append((method, uri)); return 200, logs, {'framing_valid': True}
                    api = Reads()
                    if case == 'complete': self.assertEqual(G.observe_owned_job(api, job, S, UID, 500)[:2], (UID, PUID))
                    else:
                        with self.assertRaises(G.Hold): G.observe_owned_job(api, job, S, UID, 500)
                    self.assertTrue(all(c[0] == 'GET' for c in api.calls))

    def test_reconcile_transport_has_no_post_authority(self):
        with binding(), patch.object(G, 'JOB_MANIFEST_SHA256', 'a' * 64):
            api = G.CapturedAPI(Inner([]), Files(), Path('/declared/reconcile'), False)
            with self.assertRaises(G.Hold): api.request('POST', G.JOB_URI, b'not-a-new-claim')
            self.assertEqual(api.inner.calls, [])
            self.assertEqual(api.post_count, 0)


if __name__ == '__main__':
    unittest.main(verbosity=2)
