#!/usr/bin/env python3
"""Root-only one-shot additive Goose92 companion Job; inert until literal binding.

No ordinary quiet/business authority. Never deploys the companion to Core,
replays an uncertain POST, repairs an existing index, runs down or deletes a Job.
"""
import argparse
import base64
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import stat
import sys
import time
import types
import uuid

SOURCE_BOUND = False
COMPANION_SOURCE_Q = None
COMPANION_IMAGE_D = None
COMPANION_IMAGE_PROOF_SHA256 = None
SOURCE_CI_GATE_SHA256 = None
REQUIRED_CI = None
EXPECTED_RUNS = None
EXPECTED_JOBS = None
CAS_SOURCE_SHA256 = None
RUNTIME_MANIFEST_SHA256 = None
G9_RETURN_SHA256 = None
BASELINE91_ACCEPTANCE_SHA256 = None
CONFIG_SHA256 = None
JOB_UUID = None
JOB_MANIFEST_SHA256 = None
CURRENT_OPS_P = '44588c8328a8326d3bd2cbfb88cf2614f16da382'
SELECTED_CORE_R = 'c02512e9d11d29cad4e4ff67186602d3485d6fa3'
SELECTED_CORE_D = '7f86e55cebd3dfcd3e1e027d8ddb573358ba8b42753348bfbda108bf6d39a0b6'
CURRENT_CORE_R = 'd451ac07c6e412bd2eae06f648935799e046ea31'
CURRENT_CORE_D = '0970e1188ceb5fa3ba52a1a11337f5fae7ac0657a66a69e08d24f9888f813826'
GUARDIAN_S = '6defe12adc0cac920c767c09c49c25db589d9ec9a0dee5abc0f3cc03dfe18765'
CONTROLLER_C = '3d8ed6cf0341d6fe36ff190ade585321a1c88274577b9ebb57f8e7c235654111'
M92 = 'ddc3be6589b6bc55ae786f75752f69e20f5241e25d053f3d817fb6b1caeb9f33'
GOOSE91_READER_SHA = 'f5bca87437b23b9b2e2bf70a1928d3d7dced52eba90fbee4a64fd18c5bbfb335'
GOOSE91_SUPPORT_SHA = '9e2f8fe524331c9ea1c2f5742588977abe47d99b6ff635e88e431f343b96c004'
ROOT = Path('/var/lib/dakasa-core-rollout/goose92-workflow-index')
CLAIM = ROOT / 'GOOSE92-POSSIBLE-CREATE.json'
JOB_URI = '/apis/batch/v1/namespaces/dakasa/jobs'
DEP_URI = '/apis/apps/v1/namespaces/dakasa/deployments/yggdrasil'
CORE_PODS_URI = '/api/v1/namespaces/dakasa/pods?labelSelector=app%3Dyggdrasil'
PREFIX = '153828470928.dkr.ecr.us-east-1.amazonaws.com/ghcr/dakasa-yggdrasil/yggdrasil-core@sha256:'
APP = 'yggdrasil-goose92-companion'
DB_REFS = {k: {'configMapKeyRef': {'name': 'yggdrasil-config', 'key': k}}
           for k in ('DB_HOST', 'DB_NAME', 'DB_PORT', 'DB_USER')}
DB_REFS['DB_PASSWORD'] = {'secretKeyRef': {'name': 'yggdrasil-secrets', 'key': 'DB_PASSWORD'}}


class Hold(RuntimeError):
    pass


def need(value, guard):
    if not value:
        raise Hold(guard)


def digest(value):
    return type(value) is str and re.fullmatch('[a-f0-9]{64}', value) and value != '0' * 64


def source(value):
    return type(value) is str and re.fullmatch('[a-f0-9]{40}', value) and value != '0' * 40


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def closed(value, fields, guard):
    need(type(value) is dict and set(value) == set(fields.split()), guard)


def wire(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode()


def loads(raw):
    def unique(rows):
        value = {}
        for key, item in rows:
            need(key not in value, 'NO_DUPLICATE_JSON_KEY')
            value[key] = item
        return value
    return json.loads(raw, object_pairs_hook=unique,
                      parse_constant=lambda _: (_ for _ in ()).throw(Hold('FINITE_JSON_ONLY')))


def private_read(path, cap=1 << 20):
    path = Path(path)
    need(path.is_absolute() and '..' not in path.parts, 'ABSOLUTE_PRIVATE_REFERENCE')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_uid == 0 and before.st_nlink == 1
             and stat.S_IMODE(before.st_mode) == 0o600 and 0 < before.st_size <= cap,
             'ROOT600_SINGLE_LINK_BOUNDED_INPUT')
        raw = bytearray()
        while len(raw) <= cap:
            part = os.read(fd, min(65536, cap + 1 - len(raw)))
            if not part:
                break
            raw.extend(part)
        after, named = os.fstat(fd), path.lstat()
        key = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
        need(key(before) == key(after) == key(named) and len(raw) == before.st_size <= cap,
             'COMPLETE_UNCHANGED_PRIVATE_INPUT')
        return bytes(raw)
    finally:
        os.close(fd)


def reference(ref, cap=4 << 20):
    closed(ref, 'path sha256', 'CLOSED_PINNED_REFERENCE')
    need(digest(ref['sha256']), 'NONZERO_REFERENCE_SHA')
    raw = private_read(Path(ref['path']), cap)
    need(sha(raw) == ref['sha256'], 'ACTUAL_REFERENCE_BYTES')
    return raw


def load_definitions(ref, pin, name):
    need(ref['sha256'] == pin, 'EXACT_REVIEWED_SOURCE_PIN')
    raw = reference(ref)
    module = types.ModuleType(name)
    module.__file__ = ref['path']
    exec(compile(raw, ref['path'], 'exec'), module.__dict__)
    return module


def require_bound():
    pins = (COMPANION_IMAGE_D, COMPANION_IMAGE_PROOF_SHA256, SOURCE_CI_GATE_SHA256,
            CAS_SOURCE_SHA256, RUNTIME_MANIFEST_SHA256, G9_RETURN_SHA256,
            BASELINE91_ACCEPTANCE_SHA256, CONFIG_SHA256, JOB_MANIFEST_SHA256)
    need(SOURCE_BOUND is True and source(COMPANION_SOURCE_Q) and all(digest(v) for v in pins)
         and COMPANION_SOURCE_Q not in (SELECTED_CORE_R, CURRENT_CORE_R, CURRENT_OPS_P)
         and COMPANION_IMAGE_D not in (SELECTED_CORE_D, CURRENT_CORE_D)
         and type(REQUIRED_CI) is frozenset and type(EXPECTED_RUNS) is int
         and EXPECTED_RUNS > 0 and len(REQUIRED_CI) == EXPECTED_RUNS
         and type(EXPECTED_JOBS) is int and EXPECTED_JOBS >= EXPECTED_RUNS
         and type(JOB_UUID) is str and str(uuid.UUID(JOB_UUID)) == JOB_UUID
         and uuid.UUID(JOB_UUID).int != 0,
         'INERT_COMPANION_SOURCE_IMAGE_CI_RUNTIME_AND_JOB_BINDINGS_BEFORE_IO')


def qualification(cfg):
    proof = loads(reference(cfg['companion_image_proof']))
    need(cfg['companion_image_proof']['sha256'] == COMPANION_IMAGE_PROOF_SHA256
         and proof['schema'] == 'root_actual_goose92_companion_release_image_ECR_qualification_v1'
         and proof['source'] == COMPANION_SOURCE_Q
         and proof['amd64_manifest_digest'] == 'sha256:' + COMPANION_IMAGE_D
         and proof['ecr_image'] == PREFIX + COMPANION_IMAGE_D
         and proof['ecr_exact_GHCR_manifest_body'] is True
         and proof['shipped_SQL_versions'] == [v for v in range(1, 93) if v != 40]
         and proof['all_SQL_SHA_and_bytes_equal_exact_source_both_architectures'] is True
         and proof['independent_four_AMD64_ELF_nonexecutable_clean_source_build_info'] is True
         and proof['independent_four_ARM64_ELF_nonexecutable_clean_source_build_info'] is True,
         'QUALIFIED_COMPANION_Q_IMAGE_FULL_SOURCE_SQL92_NO_OVERLAY')
    gate = loads(reference(cfg['source_ci_gate']))
    closed(gate, 'schema ops_source reviewed_by_root workflow_runs jobs attempt all_success ci_attestation',
           'CLOSED_COMPANION_SOURCE_CI_GATE')
    need(cfg['source_ci_gate']['sha256'] == SOURCE_CI_GATE_SHA256
         and gate['schema'] == 'root_goose92_companion_Source_prerequisite_v1'
         and gate['ops_source'] == COMPANION_SOURCE_Q and gate['reviewed_by_root'] is True
         and type(gate['workflow_runs']) is int and gate['workflow_runs'] == EXPECTED_RUNS
         and type(gate['jobs']) is int and gate['jobs'] == EXPECTED_JOBS
         and type(gate['attempt']) is int and gate['attempt'] == 1 and gate['all_success'] is True,
         'ACTUAL_NEW_Q_CI_NOT_CURRENT44588_OUTCOME_TRANSFER')
    ci = loads(reference(gate['ci_attestation']))
    closed(ci, 'schema commit reviewed_by_root runs', 'CLOSED_COMPANION_CI_ATTESTATION')
    need(ci['schema'] == 'guardian_goose92_companion_exact_source_ci_v1'
         and ci['commit'] == COMPANION_SOURCE_Q and ci['reviewed_by_root'] is True
         and type(ci['runs']) is list and len(ci['runs']) == EXPECTED_RUNS, 'ACTUAL_Q_CI_ROWS')
    for row in ci['runs']:
        closed(row, 'id name event head_sha status conclusion attempt', 'CLOSED_Q_CI_ROW')
        need(type(row['id']) is int and row['id'] > 0 and row['head_sha'] == COMPANION_SOURCE_Q
             and row['status'] == 'completed' and row['conclusion'] == 'success'
             and type(row['attempt']) is int and row['attempt'] == 1, 'ACTUAL_EACH_Q_CI_ATTEMPT1_SUCCESS')
    need(len({r['id'] for r in ci['runs']}) == EXPECTED_RUNS
         and {(r['name'], r['event']) for r in ci['runs']} == REQUIRED_CI, 'EXACT_NEW_Q_EVENT_ROSTER')
    roster = loads(reference(cfg['companion_sql_roster']))
    closed(roster, 'schema source files', 'CLOSED_COMPANION_SQL_SOURCE_ROSTER')
    need(roster['schema'] == 'qualified_companion_SQL_SHA_size_roster_v1'
         and roster['source'] == COMPANION_SOURCE_Q and type(roster['files']) is dict
         and len(roster['files']) == 91, 'ACTUAL_Q_NINETY_ONE_SQL_FILES')
    rows = list(roster['files'].values())
    for value in rows:
        closed(value, 'version bytes sha256', 'CLOSED_QUALIFIED_SQL_ENTRY')
        need(type(value['version']) is int and type(value['bytes']) is int and value['bytes'] > 0
             and digest(value['sha256']), 'QUALIFIED_SQL_SOURCE_SIZE_SHA')
    need(sorted(v['version'] for v in rows) == [v for v in range(1, 93) if v != 40]
         and roster['files']['00092_workflow_runs_busy_logical_index.sql']['sha256'] == M92,
         'FULL_Q_SQL_ROSTER_INCLUDING_CANONICAL92')
    # The complete roster ref is included in the exact SHA-pinned image proof.
    need(proof['SQL_source_roster'] == cfg['companion_sql_roster'], 'ACTUAL_SHIPPED_IMAGE_TO_SOURCE_SQL_ROSTER_JOIN')
    baseline = loads(reference(cfg['baseline91_acceptance']))
    need(cfg['baseline91_acceptance']['sha256'] == BASELINE91_ACCEPTANCE_SHA256
         and baseline['schema'] == 'root_goose91_independent_acceptance_v1'
         and baseline['reviewed_by_root'] is True and baseline['source'] == SELECTED_CORE_R
         and digest(baseline['complete_history_sha256']) and digest(baseline['schema90_91_catalog_sha256']),
         'ROOT_ACCEPTED_ACTUAL_HISTORY91_CATALOG90_91_NOT_A_NEW_APPROVAL')
    return baseline


def job_name():
    return 'core-goose92-' + uuid.UUID(JOB_UUID).hex


def job_manifest():
    name = job_name()
    labels = {'app': APP, 'dakasa.io/core-schema-owner': name}
    env = [{'name': k, 'valueFrom': copy.deepcopy(DB_REFS[k])} for k in sorted(DB_REFS)]
    env += [{'name': 'PGAPPNAME', 'value': name},
            {'name': 'PGOPTIONS', 'value': '-c lock_timeout=3000ms -c statement_timeout=120000ms -c idle_in_transaction_session_timeout=15000ms'}]
    return {'apiVersion': 'batch/v1', 'kind': 'Job',
            'metadata': {'namespace': 'dakasa', 'name': name, 'labels': labels},
            'spec': {'backoffLimit': 0, 'activeDeadlineSeconds': 240, 'completions': 1, 'parallelism': 1,
                     'template': {'metadata': {'labels': copy.deepcopy(labels)}, 'spec': {
                         'serviceAccountName': 'yggdrasil', 'automountServiceAccountToken': False,
                         'imagePullSecrets': [{'name': 'ecr-pull-fresh'}], 'restartPolicy': 'Never',
                         'terminationGracePeriodSeconds': 5,
                         'securityContext': {'runAsUser': 65532, 'runAsGroup': 65532, 'fsGroup': 65532,
                                             'seccompProfile': {'type': 'RuntimeDefault'}},
                         'containers': [{'name': 'migrator', 'image': PREFIX + COMPANION_IMAGE_D,
                                         'imagePullPolicy': 'IfNotPresent', 'workingDir': '/app',
                                         'command': ['/bin/sh', '-ceu', '/app/goose up'], 'env': env,
                                         'resources': {'requests': {'cpu': '0', 'memory': '64Mi'},
                                                       'limits': {'cpu': '1', 'memory': '256Mi'}},
                                         'securityContext': {'allowPrivilegeEscalation': False,
                                                             'capabilities': {'drop': ['ALL']},
                                                             'readOnlyRootFilesystem': True}}]}}}}


def job_shape(actual, expected, uid, S, pod=False):
    """Same closed native defaults as Goose91; only the disjoint app label is added."""
    spec = actual['spec'] if pod else actual['spec']['template']['spec']
    wanted = copy.deepcopy(expected['spec']['template']['spec'])
    wanted['containers'][0].update(terminationMessagePath='/dev/termination-log', terminationMessagePolicy='File')
    wanted.update(dnsPolicy='ClusterFirst', schedulerName='default-scheduler', serviceAccount='yggdrasil')
    if pod:
        wanted.update(enableServiceLinks=True, nodeName=S.CORE_NODE, priority=0,
                      preemptionPolicy='PreemptLowerPriority', tolerations=[
                          {'effect': 'NoExecute', 'key': 'node.kubernetes.io/not-ready', 'operator': 'Exists', 'tolerationSeconds': 300},
                          {'effect': 'NoExecute', 'key': 'node.kubernetes.io/unreachable', 'operator': 'Exists', 'tolerationSeconds': 300}])
    need(spec == wanted, 'EXACT_JOB_POD_SPEC_NO_OVERLAY_COMMAND_OR_RETRY')
    meta = actual['metadata'] if pod else actual['spec']['template']['metadata']
    labels = meta.get('labels', {})
    allowed = {**expected['metadata']['labels'], 'controller-uid': uid,
               'batch.kubernetes.io/controller-uid': uid, 'job-name': expected['metadata']['name'],
               'batch.kubernetes.io/job-name': expected['metadata']['name']}
    need(all(labels.get(k) == v for k, v in expected['metadata']['labels'].items())
         and all(k in allowed and allowed[k] == v for k, v in labels.items())
         and labels.get('app') == APP != 'yggdrasil', 'EXACT_DISJOINT_APP_AND_NATIVE_OWNERSHIP_LABELS')
    if not pod:
        need(set(meta) <= {'labels', 'creationTimestamp'} and meta.get('creationTimestamp') is None,
             'CLOSED_JOB_TEMPLATE_METADATA')
        top = copy.deepcopy(actual['spec']); top.pop('template')
        target = copy.deepcopy(expected['spec']); target.pop('template')
        target.update(completionMode='NonIndexed', manualSelector=False, podReplacementPolicy='TerminatingOrFailed',
                      suspend=False, selector={'matchLabels': {'batch.kubernetes.io/controller-uid': uid}})
        need(top == target and actual['metadata']['labels'] == expected['metadata']['labels'], 'CLOSED_JOB_TOP_LEVEL_DEFAULTS')


class CapturedAPI:
    """Fixed create+read scope over the reviewed no-retry mTLS/framing transport."""
    def __init__(self, inner, C, run, allow_post):
        self.inner, self.C, self.run, self.allow_post = inner, C, run, allow_post
        self.sequence = 0
        self.pod_name = None
        self.post_count = 0

    def request(self, method, uri, body=None):
        job = JOB_URI + '/' + job_name()
        pods = '/api/v1/namespaces/dakasa/pods?labelSelector=job-name%3D' + job_name()
        log = None if self.pod_name is None else '/api/v1/namespaces/dakasa/pods/' + self.pod_name + '/log?container=migrator&timestamps=true'
        need(type(uri) is str and uri.startswith('/') and ((method == 'GET' and body is None and uri in (DEP_URI, CORE_PODS_URI, job, pods, log))
             or (method == 'POST' and uri == JOB_URI and self.allow_post and self.post_count == 0
                 and type(body) is bytes and sha(body) == JOB_MANIFEST_SHA256)), 'CLOSED_SINGLE_JOB_HTTP_SCOPE')
        if method == 'POST':
            self.post_count += 1  # A raised/uncertain transport still consumes this instance's POST.
        self.sequence += 1
        label = 'API-%04d' % self.sequence
        status, raw, meta, error = None, b'', {}, None
        started, mono = time.time_ns(), time.monotonic_ns()
        try:
            status, raw, meta = self.inner.request(method, uri, body)
            return status, raw, meta
        except BaseException as caught:
            error = type(caught).__name__
            raise
        finally:
            # Core env values are never retained: only hashes/clocks, as in Goose91.
            retain = uri not in (DEP_URI, CORE_PODS_URI)
            if retain:
                self.C.once(self.run / (label + '.raw'), raw)
            self.C.once(self.run / (label + '.HTTP.json'), wire({
                'method': method, 'uri': uri, 'status': status, 'raw_bytes': len(raw),
                'raw_sha256': sha(raw), 'raw_retained': retain, 'started_unix_ns': started,
                'returned_unix_ns': time.time_ns(), 'started_monotonic_ns': mono,
                'returned_monotonic_ns': time.monotonic_ns(), 'raised_error_class': error, **meta}))

    def get(self, uri, absent=False):
        status, raw, meta = self.request('GET', uri)
        need(meta.get('framing_valid') is True, 'COMPLETE_ORIGINAL_GET_FRAMING')
        value = loads(raw)
        if absent and status == 404:
            need(value.get('kind') == 'Status' and value.get('reason') == 'NotFound'
                 and value.get('code') == 404, 'EXACT_TYPED_JOB_NOTFOUND')
            return None
        need(status == 200, 'ORIGINAL_GET200')
        return value


def index_sql(V):
    # The pure predicate Source is owned/tested with migration92 in this Q.
    return """BEGIN READ ONLY; SET LOCAL statement_timeout='8000ms'; SET LOCAL lock_timeout='1000ms'; SET LOCAL TIME ZONE 'UTC';
SELECT jsonb_build_object('readonly',current_setting('transaction_read_only'),
 'rows92',(SELECT count(*) FROM public.goose_db_version WHERE version_id=92),
 'index_absent',to_regclass('public.workflow_runs_busy_logical_idx') IS NULL,
 'index92_valid',""" + V.workflow_busy_logical_index92_sql() + """,
 'index_definition',(SELECT pg_get_indexdef(to_regclass('public.workflow_runs_busy_logical_idx'))),
 'old91_history_wire',(SELECT COALESCE(jsonb_agg(to_jsonb(v) ORDER BY id),'[]'::jsonb)::text FROM public.goose_db_version v WHERE version_id<>92));
COMMIT;"""


def check_catalog(value, index, accepted, old=None):
    schema = 91 if old is None else 92
    need(value['database'] == 'yggdrasil' and value['readonly'] == index['readonly'] == 'on'
         and value['latest_versions'] == [0] + [v for v in range(1, schema + 1) if v != 40]
         and value['rows90'] == value['rows91'] == 1
         and all(value[k] == 0 for k in ('other_migrators_ddl', 'other_cic', 'ddl_locks')),
         'FULL_HISTORY_VERSION_AND_NO_OTHER_MIGRATOR_DDL_CIC')
    need(sha(index['old91_history_wire'].encode()) == accepted['complete_history_sha256']
         and sha(wire({'catalog90': value['catalog90'], 'catalog91': value['catalog91']}))
         == accepted['schema90_91_catalog_sha256'], 'BYTE_EXACT_ACCEPTED_91_HISTORY_AND_CATALOG90_91')
    if old is None:
        need(index['rows92'] == 0 and index['index_absent'] is True
             and index['index92_valid'] is False and index['index_definition'] is None
             and value['complete_history_wire'] == index['old91_history_wire'],
             'SCHEMA91_INDEX92_ABSENT_NO_ADOPTION_REPAIR_OR_DROP')
    else:
        rows = loads(value['complete_history_wire']); prior = loads(old['complete_history_wire'])
        added = [r for r in rows if r['version_id'] == 92]
        need(index['rows92'] == 1 and index['index_absent'] is False and index['index92_valid'] is True
             and type(index['index_definition']) is str and len(added) == 1 and added[0]['is_applied'] is True
             and len(rows) == len(prior) + 1 and [r for r in rows if r['version_id'] != 92] == prior
             and index['old91_history_wire'] == old['complete_history_wire']
             and added[0]['id'] > max(r['id'] for r in prior), 'ONE92_ROW_EXACT_INDEX_AND_ALL91_OLD_ROWS_UNCHANGED')
    return value


def core(api, V, C, env_from):
    d = api.get(DEP_URI); pods = api.get(CORE_PODS_URI)
    result = V.core_before(d, pods, C)
    need(V.OLD_SOURCE == CURRENT_CORE_R and V.CORE_R == SELECTED_CORE_R
         and C.OLD_DIGEST == CURRENT_CORE_D and C.NEW_DIGEST == SELECTED_CORE_D,
         'CURRENT_R4_SELECTED_R6_AND_COMPANION_Q_ARE_DISTINCT_AXES')
    container = d['spec']['template']['spec']['containers'][0]
    env = {r['name']: r for r in container.get('env', [])}
    need(len(env) == len(container.get('env', [])), 'NO_DUPLICATE_CURRENT_CORE_ENV')
    inherited = [{'configMapRef': {'name': 'yggdrasil-config'}}, {'secretRef': {'name': 'yggdrasil-secrets'}}]
    refs = container.get('envFrom', [])
    need(refs == env_from and refs in ([], inherited, list(reversed(inherited))), 'ACTUAL_CORE_ENVFROM_REFERENCES')
    for name, ref in DB_REFS.items():
        if name in env:
            need(set(env[name]) == {'name', 'valueFrom'} and env[name]['valueFrom'] == ref,
                 'EXACT_DB_REFERENCE_NO_SECRET_VALUES')
    need(all(k in env for k in DB_REFS) or refs in (inherited, list(reversed(inherited))), 'COMPLETE_EXISTING_CORE_DB_REFERENCES')
    return {'identity': result, 'spec_sha256': sha(wire(d['spec'])),
            'annotations_sha256': sha(wire(d['metadata']['annotations'])),
            'envFrom': refs, 'explicit_DB_refs': {k: env[k]['valueFrom'] for k in DB_REFS if k in env}}


def runtime(V, cut, folder, manifest, returned, run):
    backend, protected, ctrl, guard, observed = V.g9_acceptance(cut, folder, manifest, returned, run)
    need(ctrl['pid'] == 3441694 and guard['pid'] == 3441887 and len(protected) == 41
         and V.SOURCE_PIN == GUARDIAN_S and cut.C.HEAD_CONFIG_SHA == CONTROLLER_C,
         'SAME_INSTALLED_G9_P44588_LIFETIMES_41REFS_BUDGET1')
    return backend, protected, ctrl, guard, observed


def create_once(api, C, run, job, config_sha, script_sha, deadline):
    need(not CLAIM.exists(), 'GLOBAL_GOOSE92_CLAIM_ABSENT_NEVER_REPLAY')
    body = wire(job)
    need(sha(body) == JOB_MANIFEST_SHA256, 'EXACT_ROOT_REVIEWED_JOB_BODY')
    need(api.get(JOB_URI + '/' + job_name(), absent=True) is None, 'NEW_UNIQUE_UUID_JOB_ABSENT')
    marker = {'schema': 'goose92_companion_job_possible_v1', 'source_Q': COMPANION_SOURCE_Q,
              'companion_image_D': COMPANION_IMAGE_D, 'current_ops_P': CURRENT_OPS_P,
              'job_uuid': JOB_UUID, 'job_name': job_name(), 'manifest_sha256': sha(body),
              'config_sha256': config_sha, 'script_sha256': script_sha, 'evidence_dir': str(run),
              'automatic_retry': False, 'effects_may_have_happened_after_marker': True}
    C.once(CLAIM, wire(marker)); C.once(run / 'POSSIBLE-CREATE.json', wire(marker))
    need(deadline - time.monotonic() >= 420, 'ORIGINAL_REMAINING_POST_BUDGET_AFTER_FSYNC')
    status, raw, meta = api.request('POST', JOB_URI, body)
    need(status == 201 and meta.get('framing_valid') is True, 'ORIGINAL_COMPLETE_201_ONLY_UNKNOWN_ACK_HOLD')
    value = loads(raw)
    need(value['metadata']['name'] == job_name() and value['metadata']['namespace'] == 'dakasa'
         and str(uuid.UUID(value['metadata']['uid'])) == value['metadata']['uid'], 'ACTUAL_ORIGINAL_JOB_ACK_UUID')
    return value['metadata']['uid']


def observe_owned_job(api, job, S, uid, deadline):
    uri = JOB_URI + '/' + job_name()
    end = min(deadline, time.monotonic() + 245)
    while True:
        need(time.monotonic() < end, 'ORIGINAL_JOB_DEADLINE_NO_RECREATE')
        current = api.get(uri)
        if uid is None:
            uid = current['metadata']['uid']
        need(current['metadata']['uid'] == uid and current['metadata']['name'] == job_name()
             and current['metadata']['namespace'] == 'dakasa' and str(uuid.UUID(uid)) == uid,
             'SAME_EXACT_ORIGINAL_JOB_UID')
        job_shape(current, job, uid, S)
        flags = {r['type']: r['status'] for r in current.get('status', {}).get('conditions', [])}
        if flags.get('Complete') == 'True' or flags.get('Failed') == 'True':
            break
        time.sleep(2)
    pods = api.get('/api/v1/namespaces/dakasa/pods?labelSelector=job-name%3D' + job_name())
    need(len(pods['items']) == 1, 'ONE_OWNED_ORIGINAL_JOB_POD')
    pod = pods['items'][0]; job_shape(pod, job, uid, S, pod=True)
    pm = pod['metadata']; cs = pod['status'].get('containerStatuses', [])
    need(re.fullmatch('[a-z0-9](?:[-a-z0-9]*[a-z0-9])?', pm['name']) and len(pm['name']) <= 253
         and str(uuid.UUID(pm['uid'])) == pm['uid']
         and any(r.get('kind') == 'Job' and r.get('controller') is True and r.get('uid') == uid
                 and r.get('name') == job_name() for r in pm.get('ownerReferences', [])), 'ACTUAL_OWNED_POD_UUID')
    need(flags.get('Complete') == 'True' and flags.get('Failed') != 'True'
         and current['status'].get('succeeded') == 1 and current['status'].get('failed', 0) == 0
         and pod['status']['phase'] == 'Succeeded' and len(cs) == 1 and cs[0]['name'] == 'migrator'
         and cs[0]['restartCount'] == 0 and cs[0]['imageID'].rsplit(':', 1)[-1] == COMPANION_IMAGE_D
         and cs[0].get('state', {}).get('terminated', {}).get('exitCode') == 0,
         'ORIGINAL_JOB_AND_POD_COMPANION_PLATFORM_EXIT0')
    api.pod_name = pm['name']
    status, logs, meta = api.request('GET', '/api/v1/namespaces/dakasa/pods/' + pm['name'] + '/log?container=migrator&timestamps=true')
    need(status == 200 and meta.get('framing_valid') is True
         and b'00092_workflow_runs_busy_logical_index.sql' in logs
         and b'successfully migrated database to version: 92' in logs, 'ORIGINAL_GOOSE92_LOG_COMPLETE_EXIT0')
    return uid, pm['uid'], sha(logs)


def main():
    require_bound()  # All future Q/image/job/config bindings precede input or credential IO.
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--config', type=Path, required=True)
    p.add_argument('--manifest', type=Path, required=True)
    p.add_argument('--expected-script-sha256', required=True)
    p.add_argument('--evidence-dir', type=Path, required=True)
    action = p.add_mutually_exclusive_group(required=True)
    action.add_argument('--execute-one-job-create', action='store_true')
    action.add_argument('--reconcile-get-only', action='store_true')
    a = p.parse_args()
    need(os.geteuid() == 0 and sys.platform == 'linux' and sys.flags.optimize == 0
         and os.cpu_count() == 4, 'ROOT_LINUX_FOUR_CPU_UNOPTIMIZED')
    need(sha(private_read(Path(__file__).absolute())) == a.expected_script_sha256, 'EXACT_ROOT_REVIEWED_SCRIPT')
    deadline = time.monotonic() + 595
    def stop(number, _):
        raise Hold('SIGNAL_%d_UNKNOWN_RECONCILE_GET_ONLY' % number)
    for sig in (signal.SIGALRM, signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(sig, stop)
    signal.setitimer(signal.ITIMER_REAL, 595)
    raw = private_read(a.config); need(sha(raw) == CONFIG_SHA256, 'EXACT_ROOT_CONFIG_SHA')
    cfg = loads(raw)
    closed(cfg, 'schema companion_image_proof companion_sql_roster source_ci_gate runtime_package g9_return held_admission held_http_upgrade baseline91_acceptance goose91_runner goose91_support cas_source core_envFrom_projection', 'CLOSED_GOOSE92_COMPANION_CONFIG')
    need(cfg['schema'] == 'root_goose92_companion_once_config_v1', 'ROOT_TYPED_GOOSE92_CONFIG')
    accepted = qualification(cfg)
    S = load_definitions(cfg['goose91_support'], GOOSE91_SUPPORT_SHA, 'readonly_goose91_support_for92')
    N = load_definitions(cfg['goose91_runner'], GOOSE91_READER_SHA, 'readonly_goose91_catalog_for92'); N.S = S
    V = load_definitions(cfg['cas_source'], CAS_SOURCE_SHA256, 'reviewed_runtime_and_index92_definitions')
    folder = Path(cfg['runtime_package']); cut = V.load_tools(folder); C = cut.C
    folder, manifest = C.package(folder, RUNTIME_MANIFEST_SHA256)
    need(manifest['source_commit'] == CURRENT_OPS_P and V.CORE_R == SELECTED_CORE_R
         and C.NEW_DIGEST == SELECTED_CORE_D and V.SOURCE_PIN == GUARDIAN_S,
         'CURRENT_INSTALLED_PACKAGE_NOT_COMPANION_Q_IMAGE_DEPLOYMENT')
    need(cfg['g9_return']['sha256'] == G9_RETURN_SHA256, 'ACTUAL_INSTALLED_G9_RETURN_PIN')
    returned = loads(reference(cfg['g9_return'], 32 << 20))
    held, _ = V.load_held_admission(C, Path(cfg['held_admission']['path']), cfg['held_admission']['sha256'])
    need(held['history']['sha256'] == accepted['complete_history_sha256'], 'HELD_INPUT_HAS_FULL_ACTUAL_BASELINE91_HISTORY')
    http, http_raw = S.load_http_maintenance_upgrade(S, Path(cfg['held_http_upgrade']['path']), cfg['held_http_upgrade']['sha256'])
    job = job_manifest(); body = private_read(a.manifest)
    need(sha(body) == JOB_MANIFEST_SHA256 and body == wire(job), 'EXACT_ROOT_EXTERNAL_MANIFEST_NO_EMISSION')
    C.shared_parent(ROOT.parent); C.private_dir(ROOT, create=not ROOT.exists())
    run = a.evidence_dir.absolute()
    need(run.parent == ROOT and re.fullmatch('(?:migration92|reconcile92)-[a-f0-9-]{36}', run.name), 'NEW_PRIVATE_GOOSE92_EVIDENCE_LEAF')
    C.private_dir(run, create=True)
    possible = False
    try:
        with V.operation_lock():
            api = CapturedAPI(S.API(cut), C, run, not a.reconcile_get_only)
            C.once(run / 'INPUTS.PUBLIC.json', wire({'source_Q': COMPANION_SOURCE_Q, 'companion_D': COMPANION_IMAGE_D,
                   'current_ops_P': CURRENT_OPS_P, 'selected_Core_R': SELECTED_CORE_R, 'selected_Core_D': SELECTED_CORE_D,
                   'script_sha256': a.expected_script_sha256, 'config_sha256': CONFIG_SHA256, 'manifest_sha256': JOB_MANIFEST_SHA256,
                   'migration92_sha256': M92, 'ordinary_quiet_or_business_authority_claimed': False}))
            if a.reconcile_get_only:
                marker = loads(C.read(CLAIM, 32768, 0o600))
                closed(marker, 'schema source_Q companion_image_D current_ops_P job_uuid job_name manifest_sha256 config_sha256 script_sha256 evidence_dir automatic_retry effects_may_have_happened_after_marker', 'CLOSED_ORIGINAL_POSSIBLE_CLAIM')
                need(marker['schema'] == 'goose92_companion_job_possible_v1' and marker['current_ops_P'] == CURRENT_OPS_P
                     and marker['job_name'] == job_name() and marker['automatic_retry'] is False
                     and marker['script_sha256'] == a.expected_script_sha256 and marker['source_Q'] == COMPANION_SOURCE_Q and marker['companion_image_D'] == COMPANION_IMAGE_D
                     and marker['job_uuid'] == JOB_UUID and marker['manifest_sha256'] == JOB_MANIFEST_SHA256
                     and marker['config_sha256'] == CONFIG_SHA256, 'EXACT_CONSUMED_ORIGINAL_CLAIM_GET_ONLY')
                uid, pod_uid, logs_sha = observe_owned_job(api, job, S, None, deadline)
                result = {'schema': 'goose92_reconcile_readonly_return_v1', 'status': 'ORIGINAL_JOB_OBSERVED_ROOT_INDEPENDENT_ACCEPTANCE_PENDING',
                          'job_uid': uid, 'pod_uid': pod_uid, 'logs_sha256': logs_sha, 'POST_sent': False,
                          'schema92_or_current_runtime_qualified': False, 'automatic_retry': False}
            else:
                need(not CLAIM.exists(), 'GLOBAL_GOOSE92_CLAIM_ABSENT_NEVER_REPLAY')
                before = core(api, V, C, cfg['core_envFrom_projection']); ones = N.oneshots(cut)
                catalog = N.run_sql(cut, run, 'BEFORE-HISTORY-CATALOG', N.catalog_sql())
                index = N.run_sql(cut, run, 'BEFORE-INDEX92', index_sql(V))
                check_catalog(catalog, index, accepted)
                S.held_current_preimage(cut, run, held, 'PRESEND', N.run_sql)
                V.http_maintenance_canonical_preimage(cut, run, http, 'PRESEND')
                C.once(run / 'HTTP-HELD-INPUT.json', http_raw)
                rdir = run / 'G9-BEFORE'; C.private_dir(rdir, create=True)
                backend, protected, ctrl, guard, observed = runtime(V, cut, folder, manifest, returned, rdir)
                need(core(api, V, C, cfg['core_envFrom_projection']) == before and N.oneshots(cut) == ones,
                     'UNCHANGED_R4_CORE_DB_REFS_AND_COLD_HUB_BEFORE_JOB')
                need(time.monotonic() - observed <= 15 and deadline - time.monotonic() >= 420,
                     'FRESH_CURRENT15_AND_ORIGINAL_PARENT_BUDGET')
                # The global marker is written before the sole possible POST. A lost return never replays.
                possible = True
                fresh = N.run_sql(cut, run, 'PRESEND-HISTORY-CATALOG', N.catalog_sql())
                index = N.run_sql(cut, run, 'PRESEND-INDEX92', index_sql(V))
                check_catalog(fresh, index, accepted)
                need(fresh == catalog and time.monotonic() - observed <= 15, 'SAME_HISTORY_CATALOG_INDEX_ABSENT_WITHIN_CURRENT15')
                signal.setitimer(signal.ITIMER_REAL, min(420, deadline - time.monotonic()))
                uid = create_once(api, C, run, job, CONFIG_SHA256, a.expected_script_sha256, deadline)
                uid, pod_uid, logs_sha = observe_owned_job(api, job, S, uid, min(deadline, time.monotonic() + 420))
                after = N.run_sql(cut, run, 'AFTER-HISTORY-CATALOG', N.catalog_sql())
                index = N.run_sql(cut, run, 'AFTER-INDEX92', index_sql(V))
                check_catalog(after, index, accepted, old=catalog)
                S.held_current_preimage(cut, run, held, 'AFTER-ACK', N.run_sql)
                V.http_maintenance_canonical_preimage(cut, run, http, 'AFTER-ACK')
                need(core(api, V, C, cfg['core_envFrom_projection']) == before and N.oneshots(cut) == ones,
                     'UNCHANGED_R4_CORE_AND_COLD_HUB_AFTER_JOB')
                rdir = run / 'G9-AFTER'; C.private_dir(rdir, create=True)
                _, refs2, ctrl2, guard2, _ = runtime(V, cut, folder, manifest, returned, rdir)
                need((refs2, ctrl2, guard2) == (protected, ctrl, guard), 'SAME_G9_LIFETIMES_41REFS_BUDGET1_AFTER_JOB')
                result = {'schema': 'goose92_companion_job_return_v1', 'status': 'JOB_ACK_PLUS_OBSERVATIONS_ROOT_INDEPENDENT_ACCEPTANCE_PENDING',
                          'companion_source_Q': COMPANION_SOURCE_Q, 'companion_image_D': COMPANION_IMAGE_D,
                          'current_ops_P': CURRENT_OPS_P, 'selected_Core_source': SELECTED_CORE_R, 'selected_Core_D': SELECTED_CORE_D,
                          'job_uid': uid, 'pod_uid': pod_uid, 'exit_code': 0, 'migration92_sha256': M92,
                          'schema_before': 91, 'schema_after': 92, 'history92_sha256': sha(after['complete_history_wire'].encode()),
                          'prior91_history_sha256': sha(index['old91_history_wire'].encode()), 'logs_sha256': logs_sha,
                          'index92_exact_valid_ready_live': True, 'catalog90_91_unchanged': True,
                          'Core_G9_41refs_budget1_ColdHub_unchanged': True, 'native_create_attempts': 1,
                          'ordinary_quiet_or_business_authority_claimed': False, 'provider_Guest_Core_mutations_sent': 0,
                          'automatic_retry_down_cleanup_or_index_repair': False}
            C.once(run / 'RETURN.PUBLIC.json', wire(result)); signal.setitimer(signal.ITIMER_REAL, 0)
            print(wire(result).decode(), end='', flush=True)
    except BaseException as error:
        signal.setitimer(signal.ITIMER_REAL, 0)
        result = {'schema': 'goose92_companion_hold_v1', 'status': 'HOLD_UNKNOWN_RECONCILE_GET_ONLY_NO_REPLAY',
                  'possible_send': CLAIM.exists(), 'error_class': type(error).__name__,
                  'guard': str(error) if isinstance(error, Hold) and re.fullmatch('[A-Z0-9_]{1,160}', str(error)) else 'INCOMPLETE_OR_INCONSISTENT_OBSERVATION',
                  'automatic_retry_down_cleanup_or_index_repair': False}
        C.once(run / 'HOLD.PUBLIC.json', wire(result)); print(wire(result).decode(), end='', flush=True)
        raise SystemExit(20) from None


if __name__ == '__main__':
    try:
        main()
    except SystemExit:
        raise
    except Exception as error:
        print(json.dumps({'status': 'HOLD_BEFORE_COMPLETE_CUSTODY', 'error_class': type(error).__name__, 'automatic_retry': False}), flush=True)
        raise SystemExit(20) from None
