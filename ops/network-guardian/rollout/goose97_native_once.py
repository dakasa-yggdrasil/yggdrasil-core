#!/usr/bin/env python3
"""Inert one-Job Goose97 typed normal-finish recovery maintenance. No Core adoption or provider/Guest action.

Root supplies actual qualification and data. A lost create ACK is GET-only forever.
"""
import argparse
import base64
import copy
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import stat
import subprocess
import sys
import time
import types
import uuid

SOURCE_BOUND = False
COMPANION_SOURCE_Q = None
COMPANION_IMAGE_D = None
COMPANION_IMAGE_PROOF_SHA256 = None
SOURCE_CI_GATE_SHA256 = None
CAS_SOURCE_SHA256 = None
RUNTIME_MANIFEST_SHA256 = None
G15_RETURN_SHA256 = None
BASELINE96_ACCEPTANCE_SHA256 = 'c44e5ef3554ee494001815358434119c31832977db90a44eb925097df137c9d6'
NORMAL_FINISH_PREIMAGE_SHA256 = None
CONFIG_SHA256 = None
JOB_UUID = None
JOB_MANIFEST_SHA256 = None
EXPECTED_RUNS = None
EXPECTED_JOBS = None
EXPECTED_CHECKS = None
EXPECTED_EXTRA_CHECKS = None
REQUIRED_CI = None
CURRENT_OPS_P = None
PREDECESSOR_G13_OPS = '75db7941ec9f6b714d785a8a9cd7ae0158ca34a7'
PREDECESSOR_G13_MANIFEST = '8c96b10f94a52c615f058f5ab688b56e1fcabacfd374b6c1fc4e0acad1b8ad0a'
PREDECESSOR_G13_SOURCE = 'f5f0e218f774deefe909e884988d845be93d8c746fc5047820f68759852e7d9f'
PREDECESSOR_G13_CONFIG = '2fafe364344596ec0ab4a87a1887c8a4bcc581b103937fedb807e624fc3e6ac0'
CURRENT_CORE_R = '21003808115d0b5cd62ae503ef16e65e13d4798f'
CURRENT_CORE_D = '311e5c19868a67f900b318e059a806e45e5dd217d0c411a03bcd598f6f10d5ce'
CURRENT_CORE_CONFIG = 'c3432f11bbd59585bd2c6983ebf67fe269d5854681b824c18c64324db6156354'
CURRENT_CORE_UID = None
CURRENT_CORE_POD_UID = None
CURRENT_CORE_GENERATION = None
GUARDIAN_S = None
M94 = '2850db98eddbfd629b98df879eb61266036d70210118e8e20289782d2b37a78c'  # Frozen Source only; no migration qualification.
M93 = 'cc2b2843d14d4183ea68d25dbb9b9b58d1a353044e6ebf46ece6b93778e937e9'
LEGACY_CATALOG_SHA = 'c9d3664e43ef876a9a7a89c031bf75f761dbb0c70a664db2408058a6ce2431eb'
TRANSPORT_SHA = '9e2f8fe524331c9ea1c2f5742588977abe47d99b6ff635e88e431f343b96c004'
E70_SHA = 'fa519e39989b31a7faa3c23358506992b057d6bf17ce2aad709dfe6fecd5c2c8'
ROOT = Path('/var/lib/dakasa-core-rollout/goose97-guest-retirement-normal-finish-recovery')
CLAIM = ROOT/'GOOSE97-POSSIBLE-CREATE.json'
JOB_URI = '/apis/batch/v1/namespaces/dakasa/jobs'
DEP_URI = '/apis/apps/v1/namespaces/dakasa/deployments/yggdrasil'
RS_URI = None
CURRENT_RS_UID = None
CORE_PODS_URI = '/api/v1/namespaces/dakasa/pods?labelSelector=app%3Dyggdrasil'
PREFIX = '153828470928.dkr.ecr.us-east-1.amazonaws.com/ghcr/dakasa-yggdrasil/yggdrasil-core@sha256:'
APP = 'yggdrasil-schema97-companion'
A3_GRANT = 'c117f03f-27db-4da2-b990-c2729f98a46f'
A3_PRE = '4677b2cf-9cfa-4218-bc3d-930de13591a8'
A3_RUN = 'efad3324-4280-4928-b2e0-becc7eda08a9'
A3_JOB = '71001a02-6e60-4df1-aef7-b25cf9e07aa5'
A3_POLICY = 'ab057719-e52e-4549-8490-92766fafd24f'
A3_RESOURCE = 'i-074579943eddcf392'
A3_BIRTH = '2026-11-05T00:20:14Z'
A3_ACTION = '47557dad-d455-4e57-9af2-28e62b9e1b53'
A3_ATTEMPT = '661c977d-5dd6-4aec-a2ab-754b064c63bf'
A3_CREATOR = 'c34e330d8b266bb88e29ae7cf7b01df6f9fd96ce'
S1_RESOURCE = 'i-070b5767a35c7f0d5'
S1_BIRTH = '2026-11-03T01:17:18Z'
M94_FUNCTIONS = ('guard_failed_unwitnessed_expansion_cleanup', 'failed_expansion_absence_read_valid', 'guard_failed_unwitnessed_expansion_cleanup_event', 'guard_failed_unwitnessed_expansion_cleanup_grant', 'guard_failed_unwitnessed_expansion_cleanup_intent', 'immutable_failed_unwitnessed_expansion_cleanup')
NEW_TABLES = frozenset(('public.capacity_failed_unwitnessed_expansion_cleanups','public.capacity_failed_unwitnessed_expansion_cleanup_events'))
CHILD_COLUMN = 'failed_unwitnessed_expansion_cleanup_id'
REPLACED = frozenset(('guard_retirement_forward','guard_retirement_forward_read','guard_retirement_forward_delete_binding'))
ADDED = frozenset(('retirement_forward_continuation_quiet','retirement_forward_continuation_valid'))
CHECKS93 = frozenset(('retirement_forward_mode93','retirement_forward_continuation93'))
DB_REFS = {k: {'configMapKeyRef': {'name': 'yggdrasil-config', 'key': k}}
           for k in ('DB_HOST', 'DB_NAME', 'DB_PORT', 'DB_USER')}
DB_REFS['DB_PASSWORD'] = {'secretKeyRef': {'name': 'yggdrasil-secrets', 'key': 'DB_PASSWORD'}}

M95 = '50f2f1f712a91abf3ccd17d0fb2040d30b4bd2c6455268902e1452e922a94808'
M95_FUNCTION = 'guard_failed_unwitnessed_expansion_cleanup_event'
RUNTIME_CONFIG_REF = None
CLEANUP_ID = '838331bb-fb7b-4ea3-9e67-3ffd3f539402'
CHILD_ID = 'e0059c6d-4773-4232-b047-f7561601f613'
CLEANUP_RUN = '6c23f323-f607-4015-9564-f676e8bc5d9d'

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

def normal_finish_baseline(ref):
    # Complete case transport retains the existing8MiB bound; other refs4MiB.
    return loads(reference(ref,8 << 20))

def load_definitions(ref, pin, name):
    need(ref['sha256'] == pin, 'EXACT_REVIEWED_SOURCE_PIN')
    raw = reference(ref)
    module = types.ModuleType(name)
    module.__file__ = ref['path']
    exec(compile(raw, ref['path'], 'exec'), module.__dict__)
    return module

def require_bound():
    pins = (M97, M96, M95, M94, COMPANION_IMAGE_D, COMPANION_IMAGE_PROOF_SHA256, SOURCE_CI_GATE_SHA256,
            CAS_SOURCE_SHA256, RUNTIME_MANIFEST_SHA256, G15_RETURN_SHA256,
            BASELINE96_ACCEPTANCE_SHA256, NORMAL_FINISH_PREIMAGE_SHA256, CONFIG_SHA256, JOB_MANIFEST_SHA256)
    need(SOURCE_BOUND is True and source(COMPANION_SOURCE_Q) and all(digest(v) for v in pins)
         and source(CURRENT_OPS_P) and digest(GUARDIAN_S)
         and COMPANION_SOURCE_Q not in (CURRENT_CORE_R, CURRENT_OPS_P)
         and COMPANION_IMAGE_D != CURRENT_CORE_D
         and type(RS_URI) is str and RS_URI.startswith('/apis/apps/v1/namespaces/dakasa/replicasets/')
         and type(CURRENT_RS_UID) is str
         and all(type(x)is str and str(uuid.UUID(x))==x and uuid.UUID(x).int!=0 for x in (CURRENT_CORE_UID,CURRENT_CORE_POD_UID))
         and type(CURRENT_CORE_GENERATION)is int and CURRENT_CORE_GENERATION==280
         and type(REQUIRED_CI) is frozenset and type(EXPECTED_RUNS) is int and EXPECTED_RUNS > 0
         and len(REQUIRED_CI) == EXPECTED_RUNS and type(EXPECTED_JOBS) is int and EXPECTED_JOBS >= EXPECTED_RUNS
         and type(EXPECTED_CHECKS) is frozenset and type(EXPECTED_EXTRA_CHECKS) is frozenset
         and len(EXPECTED_CHECKS) == EXPECTED_JOBS + len(EXPECTED_EXTRA_CHECKS)
         and all(type(row) is tuple and len(row) == 4 and type(row[0]) is int and row[0] > 0
                 and row[2:] == ('completed','success') for row in EXPECTED_CHECKS)
         and EXPECTED_EXTRA_CHECKS <= EXPECTED_CHECKS
         and type(JOB_UUID) is str and str(uuid.UUID(JOB_UUID)) == JOB_UUID and uuid.UUID(JOB_UUID).int != 0,
         'INERT_ACTUAL_QUALIFICATION_AND_CASE_BINDINGS_BEFORE_ANY_IO')

def job_name():
    return 'core-goose97-' + uuid.UUID(JOB_UUID).hex

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
        need(type(uri) is str and uri.startswith('/') and ((method == 'GET' and body is None and uri in (DEP_URI, RS_URI, CORE_PODS_URI, job, pods, log))
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
            retain = uri not in (DEP_URI, RS_URI, CORE_PODS_URI)
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

def create_once(api, C, run, job, config_sha, script_sha, deadline, observed):
    need(not CLAIM.exists(), 'GLOBAL_GOOSE97_CLAIM_ABSENT_NEVER_REPLAY')
    body = wire(job)
    need(sha(body) == JOB_MANIFEST_SHA256, 'EXACT_ROOT_REVIEWED_JOB_BODY')
    need(api.get(JOB_URI + '/' + job_name(), absent=True) is None, 'NEW_UNIQUE_UUID_JOB_ABSENT')
    marker = {'schema': 'goose97_companion_job_possible_v1', 'source_Q': COMPANION_SOURCE_Q,
              'companion_image_D': COMPANION_IMAGE_D, 'current_ops_P': CURRENT_OPS_P,
              'job_uuid': JOB_UUID, 'job_name': job_name(), 'manifest_sha256': sha(body),
              'config_sha256': config_sha, 'script_sha256': script_sha, 'evidence_dir': str(run),
              'automatic_retry': False, 'effects_may_have_happened_after_marker': True}
    C.once(CLAIM, wire(marker)); C.once(run / 'POSSIBLE-CREATE.json', wire(marker))
    need(deadline - time.monotonic() >= 420, 'ORIGINAL_REMAINING_POST_BUDGET_AFTER_FSYNC')
    need(0 <= time.monotonic() - observed <= 15, 'SAME_CURRENT15_AFTER_DURABLE_MARKERS_BEFORE_POST')
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
         and b'00097_guest_retirement_normal_finish_recovery.sql' in logs
         and b'successfully migrated database to version: 97' in logs, 'ORIGINAL_GOOSE97_LOG_COMPLETE_EXIT0')
    return uid, pm['uid'], sha(logs)

def source_ci_valid(ci):
    need(ci['schema'] == 'root_core_retirement_observer_exact_source_CI_acceptance_v1'
         and ci['reviewed_by_root'] is True and ci['source'] == COMPANION_SOURCE_Q
         and len(ci['runs']) == ci['workflow_count'] == EXPECTED_RUNS
         and len(ci['jobs']) == ci['job_count'] == EXPECTED_JOBS
         and {(r['name'], r['event']) for r in ci['runs']} == REQUIRED_CI
         and len({r['id'] for r in ci['runs']}) == EXPECTED_RUNS
         and len({r['id'] for r in ci['jobs']}) == EXPECTED_JOBS, 'EXACT_CURRENT_SOURCE_RUN_AND_JOB_ROSTER')
    checks = {(r['id'],r['name'],r['status'],r['conclusion']) for r in ci['check_runs']}
    need(len(checks) == len(ci['check_runs']) == len(EXPECTED_CHECKS)
         and len({r['id'] for r in ci['check_runs']}) == len(checks) and checks == EXPECTED_CHECKS
         and all(r[2:] == ('completed','success') for r in checks), 'FULL_EXACT_ROOT_REVIEWED_CHECK_ROSTER_NOT_JOB_COUNT')
    by_id = {r[0]:r for r in checks}; jobs = {r['id'] for r in ci['jobs']}
    need(all(row['id'] in by_id and by_id[row['id']][1:] == (row['name'],'completed','success') for row in ci['jobs'])
         and frozenset(row for row in checks if row[0] not in jobs) == EXPECTED_EXTRA_CHECKS,
         'EVERY_JOB_HAS_MATCHING_SUCCESS_CHECK_AND_ONLY_EXACT_REVIEWED_EXTRA_CHECKS')


def qualification(cfg):
    ci = loads(reference(cfg['source_ci_acceptance']))
    need(cfg['source_ci_acceptance']['sha256'] == SOURCE_CI_GATE_SHA256, 'EXACT_ROOT_SOURCE_CI_ACCEPTANCE_BYTES')
    source_ci_valid(ci)
    proof = loads(reference(cfg['companion_image_proof']))
    need(cfg['companion_image_proof']['sha256'] == COMPANION_IMAGE_PROOF_SHA256
         and proof['schema'] == 'root_core_R_qualified_image_registry_acceptance_v1'
         and proof['source'] == COMPANION_SOURCE_Q
         and proof['amd64_manifest_digest'] == 'sha256:' + COMPANION_IMAGE_D
         and proof['image'] == PREFIX + COMPANION_IMAGE_D
         and proof['original_HTTP200_exact_body_complete'] is True
         and proof['qualified_for_existing_image_only_production_CAS'] is True,
         'ACTUAL_COMPANION_IMAGE_SOURCE_ECR_EXACT_BODY_QUALIFIED')
    full = loads(reference(proof['Source_CI_manual_release_all_layers_ELF_and_SQL_acceptance']))
    need(full['schema'] == 'root_actual_compiler_GHCR_image_acceptance_v1'
         and full['source'] == COMPANION_SOURCE_Q and full['amd64_D'] == COMPANION_IMAGE_D
         and full['CI_acceptance_sha256'] == SOURCE_CI_GATE_SHA256
         and full['all17manualrelease_steps_success'] is True
         and full['Source_SQL_roster_sha256'] == cfg['companion_sql_roster']['sha256']
         and set(full['platforms']) == {'amd64', 'arm64'}
         and all(p['all4_ELF_headers_metadata_CGO0_clean_actualSource'] is True
                 and p['later_relevant_whiteout_or_file_mutations'] == [] for p in full['platforms'].values()),
         'ACTUAL_FULL_IMAGE_SQL_ROSTER_AND_BOTH_ARCHITECTURES_NOT_COMPANION_ADOPTION')
    roster = loads(reference(cfg['companion_sql_roster']))
    need(roster['schema'] == 'qualified_companion_SQL_SHA_size_roster_v1'
         and roster['source'] == COMPANION_SOURCE_Q and len(roster['files']) == 96
         and sorted(r['version'] for r in roster['files'].values()) == [v for v in range(1, 98) if v != 40]
         and all(digest(r['sha256']) and type(r['bytes']) is int and r['bytes'] > 0 for r in roster['files'].values())
         and roster['files']['00093_guest_retirement_settled_absence_continuation.sql']['sha256'] == M93
         and roster['files']['00094_failed_unwitnessed_expansion_cleanups.sql']['sha256'] == M94
         and roster['files']['00095_failed_expansion_read_failure_continuation.sql']['sha256'] == M95
         and roster['files']['00096_guest_retirement_pre_read_continuation.sql']['sha256']==M96
         and roster['files']['00097_guest_retirement_normal_finish_recovery.sql']['sha256']==M97
         and cfg['migration97_sql']['source_ref']['sha256']==M97, 'EXACT_QUALIFIED_IMAGE_SHIPPED_SQL_HEAD97')
    baseline = loads(reference(cfg['baseline96_acceptance']))
    closed(baseline, 'schema reviewed_by_root schema_before schema_after current_core_source current_ops_source business_source amd64_D migration96_sha256 complete_history_sha256 prior95_history_sha256 catalog96_sha256 index92_definition_sha256 catalog90_91_sha256 job_uid pod_uid exit_code single_job_create provider_guest_core_mutations old_records_and_sdk_preserved original_refs', 'EXACT_IMMUTABLE_ROOT96_RECEIPT21')
    need(cfg['baseline96_acceptance']['sha256'] == BASELINE96_ACCEPTANCE_SHA256
         and baseline['schema'] == 'root_goose96_guest_retirement_pre_read_continuation_acceptance_v1'
         and baseline['reviewed_by_root'] is True and baseline['schema_before'] == 95 and baseline['schema_after'] == 96
         and baseline['current_core_source'] == '33a846d31a5b123b2c1141192671bc830bf6d9c8'
         and baseline['current_ops_source'] == '33873025539cfb5691154fb8ded4fc4fd94eaf94'
         and baseline['business_source'] == '045176d16947555ccbc33a8b51635b08d2d9270e'
         and baseline['amd64_D'] == '85be238c7f5b15760f7eb903646cc48f6b4b86a6995d0a4727a1ba0d86d06876'
         and baseline['migration96_sha256'] == M96 and type(baseline['exit_code']) is int and baseline['exit_code'] == 0
         and baseline['single_job_create'] is True and type(baseline['provider_guest_core_mutations']) is int
         and baseline['provider_guest_core_mutations'] == 0 and baseline['old_records_and_sdk_preserved'] is True
         and all(digest(baseline[k]) for k in ('complete_history_sha256','prior95_history_sha256','catalog96_sha256','index92_definition_sha256','catalog90_91_sha256')),
         'ORIGINAL_ROOT96_NOT_RETYPED_AS97_OR_CURRENT_CORE7')
    closed(baseline['original_refs'], 'migration_result before_catalog after_catalog source_ci qualified_image', 'ROOT96_ORIGINAL_FIVE_ROLES_UNCHANGED')
    for original in baseline['original_refs'].values():
        need(len(reference(original)) > 1, 'ROOT96_WHOLE_ORIGINAL_CUSTODY')
    return baseline


def stable_metadata(value):
    return {k: v for k, v in value['metadata'].items() if k not in ('resourceVersion', 'managedFields')}


def core(api, expected):
    closed(expected, 'deployment_uid generation deployment_spec_sha256 deployment_metadata_sha256 replicaset_name replicaset_uid replicaset_spec_sha256 replicaset_metadata_sha256 pod_name pod_uid container_id container_started_at node_name pod_spec_sha256', 'CLOSED_ACTUAL_CORE14')
    need(expected['deployment_uid'] == CURRENT_CORE_UID
         and expected['generation'] == CURRENT_CORE_GENERATION == 280 and expected['pod_uid'] == CURRENT_CORE_POD_UID
         and expected['replicaset_uid'] == CURRENT_RS_UID
         and expected['replicaset_name'] == RS_URI.rsplit('/', 1)[-1], 'ACTUAL_RETAINED_CORE5_LIFETIME_NOT_CORE6_ADOPTION')
    dep, rs, pods = api.get(DEP_URI), api.get(RS_URI), api.get(CORE_PODS_URI)
    for label, obj in (('deployment', dep), ('replicaset', rs)):
        need(obj['metadata']['uid'] == expected[label + '_uid'] and not obj['metadata'].get('deletionTimestamp')
             and sha(wire(obj['spec'])) == expected[label + '_spec_sha256']
             and sha(wire(stable_metadata(obj))) == expected[label + '_metadata_sha256'], 'UNCHANGED_FULL_CORE_AND_RS_SPEC_STABLE_METADATA')
    need(dep['metadata']['generation'] == dep['status']['observedGeneration'] == CURRENT_CORE_GENERATION
         and dep['metadata']['annotations']['dakasa.io/core-source-commit'] == CURRENT_CORE_R
         and dep['spec']['replicas'] == 1 and all(dep['status'].get(k) == 1 for k in ('readyReplicas','updatedReplicas','availableReplicas'))
         and dep['status'].get('unavailableReplicas', 0) == 0
         and any(o.get('controller') is True and o.get('uid') == expected['deployment_uid'] for o in rs['metadata']['ownerReferences']), 'SAME_READY_SINGLETON_CORE_AND_OWNED_RS')
    need(pods['kind'] == 'PodList' and not pods['metadata'].get('continue') and len(pods['items']) == 1, 'COMPLETE_SINGLE_CORE_POD_LIST')
    pod = pods['items'][0]; meta, status = pod['metadata'], pod['status']; rows = status['containerStatuses']
    need(meta['uid'] == expected['pod_uid'] and meta['name'] == expected['pod_name'] and not meta.get('deletionTimestamp')
         and len(meta['ownerReferences']) == 1 and meta['ownerReferences'][0]['uid'] == expected['replicaset_uid']
         and meta['ownerReferences'][0]['controller'] is True and status['phase'] == 'Running'
         and sha(wire(pod['spec'])) == expected['pod_spec_sha256'] and pod['spec']['nodeName'] == expected['node_name']
         and len(rows) == len(pod['spec']['containers']) == len(dep['spec']['template']['spec']['containers']) == 1,
         'SAME_EXACT_CORE_POD_SPEC_OWNERSHIP_LIFETIME')
    row = rows[0]
    need(row['name'] == 'core' and row['ready'] is True and row['restartCount'] == 0
         and row['containerID'] == expected['container_id'] and set(row['state']) == {'running'}
         and row['state']['running']['startedAt'] == expected['container_started_at']
         and row['imageID'].rsplit(':', 1)[-1] == CURRENT_CORE_D and row['image'] == 'sha256:' + CURRENT_CORE_CONFIG
         and pod['spec']['containers'][0]['image'] == dep['spec']['template']['spec']['containers'][0]['image'] == PREFIX + CURRENT_CORE_D,
         'SAME_QUALIFIED_CORE_IMAGE_CONFIG_AND_NO_RESTART')
    return copy.deepcopy(expected)


def runtime(V, cut, folder, manifest, returned, run):
    need(manifest['source_commit'] == CURRENT_OPS_P and V.CORE_R == COMPANION_SOURCE_Q
         and V.SOURCE_PIN == GUARDIAN_S and cut.C.NEW_DIGEST == COMPANION_IMAGE_D
         and len(manifest['protected_refs']) == 43, 'ACTUAL_G15_APPEND_D5_D6_NOT_PREDECESSOR_OR_CORE_ADOPTION')
    return V.g15_acceptance(cut, folder, manifest, returned, run)


def oneshots(cut):
    result = {}
    fixed = {cut.COLD: ('1861','a9e3007603694e08b5de045430e3abfd','17981074'),
             cut.HUB: ('14339','879eb7e50692482e9e4de2780b5f1179','45273170')}
    for unit, identity in fixed.items():
        p = cut.properties(unit)
        result[unit] = {k: p[k] for k in (*cut.IDENTITY_PROPS, 'NRestarts','ActiveState','SubState','Result')}
        need((p['ExecMainPID'], p['InvocationID'], p['ExecMainStartTimestampMonotonic']) == identity
             and p['MainPID'] == '0' and p['ActiveState'] == 'active' and p['SubState'] == 'exited'
             and p['Result'] == 'success' and p['NRestarts'] == '0', 'RETAINED_COLD_HUB_ONESHOTS_NO_EXECUTION')
    return result


def raw_json_member(raw, wanted):
    """Return one exact JSON value token, retaining Go order/escapes/whitespace."""
    need(type(raw) is bytes and len(raw) <= 2<<20, 'BOUNDED_ORIGINAL_JSON_WIRE')
    loads(raw)  # Closed duplicate-key/finite JSON validation precedes slicing.
    text = raw.decode('utf-8'); decoder = json.JSONDecoder(); index = 0
    while index < len(text) and text[index] in ' \t\r\n': index += 1
    need(index < len(text) and text[index] == '{', 'ORIGINAL_JSON_OBJECT')
    index += 1
    while True:
        while index < len(text) and text[index] in ' \t\r\n': index += 1
        need(index < len(text) and text[index] != '}', 'EXACT_REQUIRED_JSON_MEMBER')
        key, index = decoder.raw_decode(text, index)
        while index < len(text) and text[index] in ' \t\r\n': index += 1
        need(type(key) is str and text[index] == ':', 'JSON_MEMBER_COLON')
        index += 1
        while index < len(text) and text[index] in ' \t\r\n': index += 1
        begin = index; _, index = decoder.raw_decode(text, index)
        if key == wanted: return text[begin:index].encode('utf-8')
        while index < len(text) and text[index] in ' \t\r\n': index += 1
        need(index < len(text) and text[index] == ',', 'REQUIRED_MEMBER_BEFORE_OBJECT_END')
        index += 1



def stamp_ns(value):
    need(type(value) is str, 'ORIGINAL_TYPED_TIMESTAMP')
    match = re.fullmatch(r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d{1,9}))?(Z|[+-](?:[01]\d|2[0-3]):[0-5]\d)', value)
    need(match is not None, 'ORIGINAL_RFC3339_NANO_TIMEZONE')
    base, fraction, zone = match.groups()
    at = datetime.datetime.fromisoformat(base+('+00:00' if zone == 'Z' else zone))
    delta = at-datetime.datetime(1970,1,1,tzinfo=datetime.timezone.utc)
    return (delta.days*86400+delta.seconds)*1000000000+int((fraction or '').ljust(9,'0') or '0')





def catalog_sql(legacy, V):
    need(sha(legacy.encode()) == LEGACY_CATALOG_SHA and legacy.endswith(';\nCOMMIT;'), 'EXACT_REVIEWED_CATALOG_QUERY_OPERANDS')
    header, select = legacy.split('\nSELECT ', 1)
    select = select[:-len(';\nCOMMIT;')]
    return header + '\nWITH legacy AS (SELECT ' + select + ") SELECT jsonb_build_object('legacy',(SELECT * FROM legacy),'supplement',jsonb_build_object(" + """
'functions93',(SELECT COALESCE(jsonb_agg(jsonb_build_object('name',p.proname,'arguments',pg_get_function_identity_arguments(p.oid),'result',pg_get_function_result(p.oid),'language',l.lanname,'volatility',p.provolatile,'config',p.proconfig,'body',p.prosrc,'definition',pg_get_functiondef(p.oid)) ORDER BY p.proname),'[]'::jsonb) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace JOIN pg_language l ON l.oid=p.prolang WHERE n.nspname='public' AND p.proname IN('guard_retirement_forward','guard_retirement_forward_read','guard_retirement_forward_delete_binding','retirement_forward_continuation_quiet','retirement_forward_continuation_valid')),
'columns90_91',(SELECT COALESCE(jsonb_agg(jsonb_build_object('table',a.attrelid::regclass::text,'name',a.attname,'number',a.attnum,'type',format_type(a.atttypid,a.atttypmod),'not_null',a.attnotnull,'default',pg_get_expr(d.adbin,d.adrelid)) ORDER BY a.attrelid,a.attnum),'[]'::jsonb) FROM pg_attribute a LEFT JOIN pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum WHERE a.attrelid IN('public.capacity_guest_retirement_forwards'::regclass,'public.capacity_guest_retirement_forward_reads'::regclass,'public.capacity_dispatch_http_maintenance_dispositions'::regclass) AND a.attnum>0 AND NOT a.attisdropped),
'index92_definition',(SELECT pg_get_indexdef(to_regclass('public.workflow_runs_busy_logical_idx'))),
'index92_valid',""" + V.workflow_busy_logical_index92_sql() + """,
'old_records',jsonb_build_object(
 'forwards',(SELECT jsonb_build_object('rows',count(*),'sha256',encode(digest(COALESCE(jsonb_agg(to_jsonb(x) ORDER BY id,stage),'[]'::jsonb)::text,'sha256'),'hex')) FROM public.capacity_guest_retirement_forwards x),
 'forward_reads',(SELECT jsonb_build_object('rows',count(*),'sha256',encode(digest(COALESCE(jsonb_agg(to_jsonb(x) ORDER BY id,stage),'[]'::jsonb)::text,'sha256'),'hex')) FROM public.capacity_guest_retirement_forward_reads x),
 'http_dispositions',(SELECT jsonb_build_object('rows',count(*),'sha256',encode(digest(COALESCE(jsonb_agg(to_jsonb(x) ORDER BY id),'[]'::jsonb)::text,'sha256'),'hex')) FROM public.capacity_dispatch_http_maintenance_dispositions x))
));
COMMIT;"""


def run_catalog(cut, run, label, sql):
    C = cut.C; C.once(run/(label+'.sql'), sql.encode())
    command = 'PGOPTIONS="-c default_transaction_read_only=on -c statement_timeout=8000 -c lock_timeout=1000 -c timezone=UTC" exec psql -XqAt -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -d yggdrasil'
    wall, mono = time.time_ns(), time.monotonic_ns(); rc = None; out = err = b''; timeout = False
    try:
        p = subprocess.run(cut.KUBE+['-n','dakasa','exec','-i','unified-database-0','--','sh','-c',command],
                           input=sql.encode(), stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=12, check=False)
        out, err, rc = p.stdout, p.stderr, p.returncode
    except subprocess.TimeoutExpired as caught:
        out, err, timeout = caught.stdout or b'', caught.stderr or b'', True
    finally:
        C.once(run/(label+'.stdout'),out); C.once(run/(label+'.stderr'),err)
        C.once(run/(label+'.RETURN.json'),wire({'started_unix_ns':wall,'finished_unix_ns':time.time_ns(),
               'started_monotonic_ns':mono,'finished_monotonic_ns':time.monotonic_ns(),'returncode':rc,'timed_out':timeout}))
    need(rc == 0 and not timeout and not err and len(out) <= 4<<20, 'COMPLETE_ORIGINAL_CATALOG_READONLY_8_1_12_ZERO')
    return loads(out)



def catalog_projection(value):
    """Stable catalog identity; history, activity and ledger facts are separate."""
    v, s = value['legacy'], value['supplement']
    return {'catalog90': v['catalog90'], 'catalog91': v['catalog91'],
            **{key: s[key] for key in ('columns90_91','functions93','index92_valid','index92_definition')}}


def main():
    require_bound()  # Before argv/input/credential IO; future image/CI/job are not facts.
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', type=Path, required=True); parser.add_argument('--manifest', type=Path, required=True)
    parser.add_argument('--expected-script-sha256', required=True); parser.add_argument('--evidence-dir', type=Path, required=True)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument('--execute-one-job-create', action='store_true'); action.add_argument('--reconcile-get-only', action='store_true')
    args = parser.parse_args()
    need(os.geteuid() == 0 and sys.platform == 'linux' and not sys.flags.optimize and os.cpu_count() == 4, 'ROOT_LINUX_FOUR_CPU_UNOPTIMIZED')
    need(sha(private_read(Path(__file__).absolute())) == args.expected_script_sha256, 'EXACT_REVIEWED_OPERATOR_SOURCE')
    deadline = time.monotonic()+595
    def stop(number, _): raise Hold('SIGNAL_UNKNOWN_RECONCILE_GET_ONLY')
    for sig in (signal.SIGALRM,signal.SIGTERM,signal.SIGINT,signal.SIGHUP): signal.signal(sig,stop)
    signal.setitimer(signal.ITIMER_REAL,595)
    raw = private_read(args.config); need(sha(raw) == CONFIG_SHA256,'EXACT_ROOT_CONFIG')
    cfg = loads(raw)
    closed(cfg,'schema source_ci_acceptance companion_image_proof companion_sql_roster baseline96_acceptance runtime_package g15_return g15_cas_source runtime_config_ref transport_source core_preimage e70_sql_data normal_finish_preimage case migration97_sql legacy_catalog_sql','CLOSED_GOOSE97_CONFIG')
    need(cfg['schema'] == 'root_goose97_normal_finish_recovery_companion_config_v1','TYPED_NEW_MAINTENANCE_CASE_NO_ADMIN_ADMISSION')
    accepted = qualification(cfg)
    S = load_definitions(cfg['transport_source'],TRANSPORT_SHA,'reviewed_generic_job_mtls_transport')
    V = load_definitions(cfg['g15_cas_source'],CAS_SOURCE_SHA256,'reviewed_actual_g15_runtime_only')
    V.CONFIG_REF = V.validated_config_ref(cfg['runtime_config_ref']['path'],cfg['runtime_config_ref']['sha256']); V.require_bound()
    reference(cfg['runtime_config_ref'])
    cut = V.load_tools(Path(cfg['runtime_package'])); C = cut.C
    folder, manifest = C.package(Path(cfg['runtime_package']),RUNTIME_MANIFEST_SHA256)
    need(cfg['g15_return']['sha256'] == G15_RETURN_SHA256,'ACTUAL_PHYSICAL_G15_RETURN')
    returned = loads(reference(cfg['g15_return'],32<<20))
    need(cfg['e70_sql_data']['sha256'] == E70_SHA and cfg['normal_finish_preimage']['sha256'] == NORMAL_FINISH_PREIMAGE_SHA256,'EXACT_ORIGINAL_E70_AND_KNOWN_NORMAL_FINISH_BASELINE')
    e70, baseline = loads(reference(cfg['e70_sql_data'])), normal_finish_baseline(cfg['normal_finish_preimage'])
    validate_normal_finish97(baseline,cfg['case'])
    need(cfg['legacy_catalog_sql']['sha256'] == LEGACY_CATALOG_SHA,'EXACT_LEGACY_CATALOG_SQL')
    legacy = reference(cfg['legacy_catalog_sql']).decode()
    carrier=cfg['migration97_sql'];closed(carrier,'source_ref constraint97_deparse_ref','CLOSED_SOURCE97_AND_PG_ORIGINAL_CARRIER')
    m97=reference(carrier['source_ref']).decode();deparse=carrier['constraint97_deparse_ref']
    expected = migration97_functions(m97); sql = catalog94_sql(legacy,V)
    job = job_manifest(); need(private_read(args.manifest) == wire(job) and sha(wire(job)) == JOB_MANIFEST_SHA256,'ACTUAL_ROOT_REVIEWED_EXTERNAL_JOB_BODY')
    C.shared_parent(ROOT.parent); C.private_dir(ROOT,create=not ROOT.exists()); run = args.evidence_dir.absolute()
    need(run.parent == ROOT and re.fullmatch('(?:migration97|reconcile97)-[a-f0-9-]{36}',run.name),'NEW_EXCLUSIVE_GOOSE97_EVIDENCE_LEAF')
    C.private_dir(run,create=True)
    try:
        with V.operation_lock():
            api = CapturedAPI(S.API(cut),C,run,not args.reconcile_get_only)
            if args.reconcile_get_only:
                marker = loads(C.read(CLAIM,32768,0o600))
                need(marker['schema'] == 'goose97_companion_job_possible_v1' and marker['source_Q'] == COMPANION_SOURCE_Q
                     and marker['companion_image_D'] == COMPANION_IMAGE_D and marker['current_ops_P'] == CURRENT_OPS_P
                     and marker['job_uuid'] == JOB_UUID and marker['manifest_sha256'] == JOB_MANIFEST_SHA256
                     and marker['config_sha256'] == CONFIG_SHA256 and marker['script_sha256'] == args.expected_script_sha256
                     and marker['automatic_retry'] is False,'EXACT_CONSUMED_JOB_CLAIM_GET_ONLY')
                uid,pod_uid,logs = observe_owned_job(api,job,S,None,deadline)
                result = {'schema':'goose97_reconcile_return_v1','status':'ORIGINAL_JOB_OBSERVED_ROOT_INDEPENDENT_ACCEPTANCE_PENDING',
                          'job_uid':uid,'pod_uid':pod_uid,'logs_sha256':logs,'POST_sent':False,'automatic_retry':False}
            else:
                need(not CLAIM.exists(),'GLOBAL_GOOSE97_CLAIM_ABSENT_NO_RESET')
                before_core, before_ones = core(api,cfg['core_preimage']), oneshots(cut)
                before_db = database(V,cut,run,e70,baseline,cfg['case'],'BEFORE')
                before = run_catalog(cut,run,'BEFORE-CATALOG',sql); check_catalog(before,accepted,expected,migration=deparse)
                gdir = run/'G15-BEFORE'; C.private_dir(gdir,create=True)
                _,refs,ctrl,guard,observed = runtime(V,cut,folder,manifest,returned,gdir)
                need(core(api,cfg['core_preimage']) == before_core and oneshots(cut) == before_ones,'SAME_CORE_AND_ONESHOTS_BEFORE_JOB')
                fresh = run_catalog(cut,run,'PRESEND-CATALOG',sql); check_catalog(fresh,accepted,expected,migration=deparse)
                need(fresh == before and database(V,cut,run,e70,baseline,cfg['case'],'PRESEND') == before_db
                     and time.monotonic()-observed <= 15 and deadline-time.monotonic() >= 420,'SAME_FULL_PREIMAGES_WITHIN_EXISTING_CURRENT15')
                signal.setitimer(signal.ITIMER_REAL,min(420,deadline-time.monotonic()))
                uid = create_once(api,C,run,job,CONFIG_SHA256,args.expected_script_sha256,deadline,observed)
                uid,pod_uid,logs = observe_owned_job(api,job,S,uid,min(deadline,time.monotonic()+420))
                after = run_catalog(cut,run,'AFTER-CATALOG',sql); check_catalog(after,accepted,expected,old=before,migration=deparse)
                need(database(V,cut,run,e70,baseline,cfg['case'],'AFTER',after=True) == before_db
                     and core(api,cfg['core_preimage']) == before_core and oneshots(cut) == before_ones,'SAME_CORE_NORMAL_FINISH_GUARDS_AND_ONESHOTS_AFTER_JOB')
                gdir = run/'G15-AFTER'; C.private_dir(gdir,create=True)
                _,refs2,ctrl2,guard2,_ = runtime(V,cut,folder,manifest,returned,gdir)
                need((refs2,ctrl2,guard2) == (refs,ctrl,guard),'SAME_ALL43_REFS_BUDGET1_AND_CONTROLLER_GUARDIAN_LIFETIMES')
                result = {'schema':'goose97_companion_job_return_v1','status':'JOB_ACK_PLUS_OBSERVATIONS_ROOT_INDEPENDENT_ACCEPTANCE_PENDING',
                          'companion_source_Q':COMPANION_SOURCE_Q,'companion_image_D':COMPANION_IMAGE_D,'current_ops_P':CURRENT_OPS_P,
                          'current_Core_source':CURRENT_CORE_R,'current_Core_D':CURRENT_CORE_D,'job_uid':uid,'pod_uid':pod_uid,'exit_code':0,
                          'migration97_sha256':M97,'schema_before':96,'schema_after':97,'history97_sha256':sha(after['legacy']['complete_history_wire'].encode()),
                          'prior96_history_sha256':sha(before['legacy']['complete_history_wire'].encode()),'catalog97_sha256':sha(wire(catalog94_projection(after))),
                          'catalog97_original':{'path':str(run/'AFTER-CATALOG.stdout'),'sha256':sha(C.read(run/'AFTER-CATALOG.stdout',4<<20,0o600))},
                          'catalog97_full_definitions_Root_review_pending':True,'logs_sha256':logs,'native_create_attempts':1,
                          'Core_G15_all43_budget1_Cold_Hub_and_old_records_SDK_unchanged':True,'ordinary_quiet_or_business_authority_claimed':False,
                          'provider_Guest_Core_mutations_sent':0,'automatic_retry_down_cleanup_or_repair':False}
            C.once(run/'RETURN.PUBLIC.json',wire(result)); signal.setitimer(signal.ITIMER_REAL,0)
            print(wire(result).decode(),end='',flush=True)
    except BaseException as caught:
        signal.setitimer(signal.ITIMER_REAL,0)
        result = {'schema':'goose97_companion_hold_v1','status':'HOLD_UNKNOWN_RECONCILE_GET_ONLY_NO_REPLAY','possible_send':CLAIM.exists(),
                  'error_class':type(caught).__name__,'guard':str(caught) if isinstance(caught,Hold) and re.fullmatch('[A-Z0-9_]{1,160}',str(caught)) else 'INCOMPLETE_OR_INCONSISTENT_OBSERVATION','automatic_retry':False}
        C.once(run/'HOLD.PUBLIC.json',wire(result)); print(wire(result).decode(),end='',flush=True)
        raise SystemExit(20) from None


def digest_value(value):
    return digest(value)

def utc(value):
    need(type(value) is str and re.fullmatch(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:\d{2})', value), 'ACTUAL_ZONED_TIMESTAMP')
    # Python before 3.11 accepts only 3/6 fractional digits; retain the raw wire
    # and parse its accepted 1..9 digits at datetime's microsecond precision.
    normalized = re.sub(r'\.(\d{1,9})(?=Z|[+-])', lambda match: '.' + (match.group(1) + '000000')[:6], value)
    return datetime.datetime.fromisoformat(normalized.replace('Z', '+00:00'))











def database(V,cut,run,e70,baseline,case,label,after=False):
    result={}
    for provider,key in (('aws','original_notify_aws_vm_members'),('hetzner','original_notify_hetzner_vm_members')):
        value=V.query(cut,run,label+'-'+provider.upper(),e70['queries'][key]);lanes={k:value[k]for k in ('jobs_busy','runs_busy','forward_unreturned_reads','live_unreturned_canaries','intent_count','intent_busy','pending_authority','forward_markers')}
        need(lanes==case['provider_lanes'][provider]and all(type(x)is int for x in lanes.values())and lanes['intent_count']==1 and all(type(lanes[k])is int and lanes[k]==0 for k in ('jobs_busy','runs_busy','forward_unreturned_reads','live_unreturned_canaries','pending_authority','forward_markers')) and type(lanes['intent_busy'])is int and lanes['intent_busy']in(0,1),'EXACT_BOTH_SOURCE_LANES_NO_GUESSED_AUTHORITY')
        result[provider]={**lanes,**{key:value[key] for key in ('intent_identity','owned_slots','active_policies','policy_catalog_wire')}}
    actual=V.query(cut,run,label+'-NORMAL-FINISH',NORMAL_FINISH_SQL);validate_normal_finish97(actual,case);need(actual['records_wire']==baseline['records_wire'],'ENTIRE_NORMAL_FINISH_CALLER_FAILED_OFF_ACK_PREIMAGE_EXACT');return result




def catalog94_sql(legacy,V):
    """Same shared CAS SELECT; retain Goose's exact 8/1/12 transaction wrapper."""
    need(sha(legacy.encode()) == LEGACY_CATALOG_SHA,'EXACT_LEGACY_QUERY_BEFORE_COMPOSITION')
    header = legacy.split('\nSELECT ',1)[0]
    select = catalog97_select(legacy)
    grants = "(SELECT jsonb_build_object('rows',count(*),'sha256',encode(digest(COALESCE(jsonb_agg(to_jsonb(g) ORDER BY id),'[]'::jsonb)::text,'sha256'),'hex'),'new_nonnull',count(*) FILTER(WHERE (to_jsonb(g)->>'failed_unwitnessed_expansion_cleanup_id') IS NOT NULL)) FROM public.capacity_mutation_grants g)"
    ledger = "(SELECT jsonb_agg(v ORDER BY v->>'name') FROM (SELECT jsonb_build_object('name','public.capacity_failed_unwitnessed_expansion_cleanups','rows',count(*),'sha256',encode(digest(COALESCE(jsonb_agg(to_jsonb(x) ORDER BY id),'[]'::jsonb)::text,'sha256'),'hex')) v FROM public.capacity_failed_unwitnessed_expansion_cleanups x UNION ALL SELECT jsonb_build_object('name','public.capacity_failed_unwitnessed_expansion_cleanup_events','rows',count(*),'sha256',encode(digest(COALESCE(jsonb_agg(to_jsonb(x) ORDER BY cleanup_id,sequence),'[]'::jsonb)::text,'sha256'),'hex')) FROM public.capacity_failed_unwitnessed_expansion_cleanup_events x) retained94)"
    return header+'\nWITH current94(v) AS ('+select+") SELECT v || jsonb_build_object('old_grants',"+grants+",'ledgers94',"+ledger+') FROM current94;\nCOMMIT;'


def catalog94_projection(value):
    """Keep the entire immutable six-key93 projection; add only M94 catalog."""
    s = value['schema94']
    need(type(s) is dict and set(s) == {'tables','columns','constraints','indexes','triggers','functions'}
         and all(type(rows) is list for rows in s.values()), 'CLOSED_STABLE_SCHEMA94_CATALOG_ARRAYS')
    return {**catalog_projection(value), 'schema94':s}


def check_catalog(value, accepted, expected_functions, old=None, migration=None):
    v,s=value['legacy'],value['supplement'];version=96 if old is None else 97
    need(v['database']=='yggdrasil' and v['readonly']=='on'
         and v['latest_versions']==[0]+[x for x in range(1,version+1) if x!=40]
         and v['rows90']==v['rows91']==1
         and all(v[k]==0 for k in ('other_migrators_ddl','other_cic','ddl_locks'))
         and s['index92_valid'] is True
         and sha(s['index92_definition'].encode())==accepted['index92_definition_sha256'],
         'EXACT97_HEAD_HISTORY_INDEX_AND_NO_OTHER_DDL')
    prior=catalog94_projection(value if old is None else old)
    definitions=constraint97_definitions(prior,migration,reference,COMPANION_SOURCE_Q)
    if old is None:
        need(sha(v['complete_history_wire'].encode())==accepted['complete_history_sha256']
             and sha(wire(prior))==accepted['catalog96_sha256'],
             'EXACT_PRIOR_ROOT96_RAW_HISTORY_AND_SEVEN_KEY_CATALOG')
        return
    previous,current=loads(old['legacy']['complete_history_wire']),loads(v['complete_history_wire'])
    added=[x for x in current if x['version_id']==97]
    need(len(added)==1 and added[0]['is_applied'] is True and len(current)==len(previous)+1
         and [x for x in current if x['version_id']!=97]==previous
         and added[0]['id']>max(x['id'] for x in previous),
         'SOLE97_APPEND_ALL_PRIOR96_VALUES_EXACT')
    need(s['old_records']==old['supplement']['old_records'] and value['old_grants']==old['old_grants']
         and value['ledgers94']==old['ledgers94'],'ALL_OLD_ROWS_SDK_AND94_LEDGERS_EXACT')
    catalog97_delta(prior,catalog94_projection(value),expected_functions,definitions)


    # Complete actual table CHECK/index/trigger definitions are retained for
    # Root's independent Source review; this operator cannot issue Root acceptance.


def workflow_busy_logical_index92_sql():
    """Closed complete busy predicate, including PostgreSQL's lossless casts."""
    predicates = (
        "(((COALESCE(status, ''::character varying))::text <> ALL ('{succeeded,failed,cancelled}'::text[])) OR (finished_at IS NULL))",
        "(((COALESCE(status, ''::character varying))::text <> ALL ((ARRAY['succeeded'::character varying, 'failed'::character varying, 'cancelled'::character varying])::text[])) OR (finished_at IS NULL))",
    )
    quoted = ','.join("'" + value.replace("'", "''") + "'" for value in predicates)
    return """COALESCE((SELECT i.indisvalid AND i.indisready AND i.indislive AND NOT i.indisunique
 AND i.indrelid='public.workflow_runs'::regclass AND i.indnkeyatts=3 AND i.indnatts=3
 AND i.indexprs IS NULL AND i.indpred IS NOT NULL AND a.amname='btree'
 AND pg_get_indexdef(i.indexrelid,1,false)='workflow_namespace'
 AND pg_get_indexdef(i.indexrelid,2,false)='workflow_name'
 AND pg_get_indexdef(i.indexrelid,3,false)='id'
 AND pg_get_expr(i.indpred,i.indrelid,false) IN (""" + quoted + """)
 FROM pg_index i JOIN pg_class c ON c.oid=i.indexrelid JOIN pg_am a ON a.oid=c.relam
 WHERE i.indexrelid=to_regclass('public.workflow_runs_busy_logical_idx')),false)"""

def catalog_select(legacy):
    # Keep the shared SELECT byte-for-byte. Only the CAS reader's established
    # RR/RO3s/.5s/process8 transaction wrapper replaces the migration wrapper.
    whole = catalog_sql(legacy,types.SimpleNamespace(workflow_busy_logical_index92_sql=workflow_busy_logical_index92_sql))
    need(whole.endswith(';\nCOMMIT;') and '\nWITH legacy AS ' in whole,'CLOSED_COMMON_CATALOG_SELECT')
    return 'WITH '+whole.split('\nWITH ',1)[1][:-len(';\nCOMMIT;')]

def catalog94_select(legacy):
    old = catalog_select(legacy)
    tables = "to_regclass('public.capacity_failed_unwitnessed_expansion_cleanups'),to_regclass('public.capacity_failed_unwitnessed_expansion_cleanup_events'),'public.capacity_mutation_grants'::regclass,'public.capacity_intents'::regclass"
    functions = ','.join("'" + n + "'" for n in M94_FUNCTIONS)
    return "WITH old93(v) AS (" + old + ") SELECT jsonb_build_object('legacy',(SELECT v->'legacy' FROM old93),'supplement',(SELECT v->'supplement' FROM old93),'schema94',jsonb_build_object(" + """
'tables',(SELECT COALESCE(jsonb_agg(jsonb_build_object('name',format('%I.%I','public',c.relname),'kind',c.relkind,'persistence',c.relpersistence,'replica_identity',c.relreplident,'row_security',c.relrowsecurity,'force_row_security',c.relforcerowsecurity) ORDER BY format('%I.%I','public',c.relname)),'[]'::jsonb) FROM pg_class c WHERE c.oid IN(""" + tables + """)),
'columns',(SELECT COALESCE(jsonb_agg(jsonb_build_object('table',format('%I.%I','public',(SELECT relname FROM pg_class WHERE oid=a.attrelid)),'name',a.attname,'number',a.attnum,'type',format_type(a.atttypid,a.atttypmod),'not_null',a.attnotnull,'identity',a.attidentity,'generated',a.attgenerated,'default',pg_get_expr(d.adbin,d.adrelid)) ORDER BY format('%I.%I','public',(SELECT relname FROM pg_class WHERE oid=a.attrelid)),a.attnum),'[]'::jsonb) FROM pg_attribute a LEFT JOIN pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum WHERE a.attrelid IN(""" + tables + """) AND a.attnum>0 AND NOT a.attisdropped),
'constraints',(SELECT COALESCE(jsonb_agg(jsonb_build_object('table',format('%I.%I','public',(SELECT relname FROM pg_class WHERE oid=c.conrelid)),'name',c.conname,'type',c.contype,'validated',c.convalidated,'deferrable',c.condeferrable,'deferred',c.condeferred,'definition',pg_get_constraintdef(c.oid,false)) ORDER BY format('%I.%I','public',(SELECT relname FROM pg_class WHERE oid=c.conrelid)),c.conname),'[]'::jsonb) FROM pg_constraint c WHERE c.conrelid IN(""" + tables + """)),
'indexes',(SELECT COALESCE(jsonb_agg(jsonb_build_object('table',format('%I.%I','public',(SELECT relname FROM pg_class WHERE oid=i.indrelid)),'name',format('%I.%I','public',(SELECT relname FROM pg_class WHERE oid=i.indexrelid)),'valid',i.indisvalid,'ready',i.indisready,'live',i.indislive,'unique',i.indisunique,'definition',pg_get_indexdef(i.indexrelid)) ORDER BY format('%I.%I','public',(SELECT relname FROM pg_class WHERE oid=i.indrelid)),format('%I.%I','public',(SELECT relname FROM pg_class WHERE oid=i.indexrelid))),'[]'::jsonb) FROM pg_index i WHERE i.indrelid IN(""" + tables + """)),
'triggers',(SELECT COALESCE(jsonb_agg(jsonb_build_object('table',format('%I.%I','public',(SELECT relname FROM pg_class WHERE oid=t.tgrelid)),'name',t.tgname,'enabled',t.tgenabled,'function',t.tgfoid::regprocedure::text,'definition',pg_get_triggerdef(t.oid,false)) ORDER BY format('%I.%I','public',(SELECT relname FROM pg_class WHERE oid=t.tgrelid)),t.tgname),'[]'::jsonb) FROM pg_trigger t WHERE NOT t.tgisinternal AND t.tgrelid IN(""" + tables + """)),
'functions',(SELECT COALESCE(jsonb_agg(jsonb_build_object('name',p.proname,'qualified_name',format('%I.%I',n.nspname,p.proname),'arguments',pg_get_function_identity_arguments(p.oid),'result',pg_get_function_result(p.oid),'language',l.lanname,'volatility',p.provolatile,'config',p.proconfig,'body',p.prosrc,'definition',pg_get_functiondef(p.oid)) ORDER BY p.proname,pg_get_function_identity_arguments(p.oid)),'[]'::jsonb) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace JOIN pg_language l ON l.oid=p.prolang WHERE n.nspname='public' AND p.proname IN(""" + functions + "))))"




M96 = 'bd28596ba82cc1607ac1a732ec5c401ac5de6bcfba3035d91f1c3a2f0a42d88d'




# INERT PURE SOURCE FRAGMENT. Closure: copy, need, sha; parent Source gate/refs remain unbound.
# expected96_check_definition is a SOURCE/data binding of the exact pg_get_constraintdef
# rendering from the complete pinned PG16 CI artifact; no result is invented here.




NORMAL_FINISH_CASE_SCHEMA = 'root_original_normal_finish_failed_case_v1'

NORMAL_FINISH_TARGET = {
    'retirement_request_id': '2c4f52ef-21d3-4f50-890a-34140caa79b4',
    'preregistration_id': '079677b7-fa87-4b8f-a2ff-3a87d33c0176',
    'run_id': 'f705fab4-e3f3-4529-baf8-4d60383caca7',
    'generation': 37, 'fence': 76,
    'lease_owner': '83b746d8-c9bb-4e94-bd20-80ad9da7da39',
    'executor_id': '4c394a88-d210-4a70-931c-a67ff39554e1',
}

NORMAL_FINISH_SQL = "WITH request AS MATERIALIZED (\n SELECT * FROM public.capacity_vm_retirement_intents\n WHERE id='2c4f52ef-21d3-4f50-890a-34140caa79b4'::uuid\n AND preregistration_id='079677b7-fa87-4b8f-a2ff-3a87d33c0176'::uuid\n), pre AS MATERIALIZED (\n SELECT * FROM public.capacity_vm_provisioning_preregistrations\n WHERE id='079677b7-fa87-4b8f-a2ff-3a87d33c0176'::uuid\n), owners AS MATERIALIZED (\n SELECT w.* FROM public.capacity_dispatch_jobs j JOIN public.workflow_runs w ON w.id=j.run_id\n WHERE j.realm='dakasa-production' AND j.environment='production' AND j.domain='notify'\n AND j.dimension='original_notify_aws_vm_members' AND\n (w.id='f705fab4-e3f3-4529-baf8-4d60383caca7'::uuid OR\n  (w.result#>>'{steps,0,metadata,generation}'='37'\n   AND w.result#>>'{steps,0,metadata,fencing_token}'='76'\n   AND w.result#>>'{steps,0,metadata,lease_owner}'='83b746d8-c9bb-4e94-bd20-80ad9da7da39'))\n), bindings AS MATERIALIZED (\n SELECT * FROM public.capacity_vm_retirement_delete_bindings\n WHERE intent_id='2c4f52ef-21d3-4f50-890a-34140caa79b4'::uuid\n), snapshot(v) AS (SELECT jsonb_build_object(\n 'selected_runtime_source','21003808115d0b5cd62ae503ef16e65e13d4798f',\n 'target',jsonb_build_object('retirement_request_id','2c4f52ef-21d3-4f50-890a-34140caa79b4','preregistration_id','079677b7-fa87-4b8f-a2ff-3a87d33c0176'),\n 'current_intent',(SELECT to_jsonb(i) FROM public.capacity_intents i WHERE i.namespace='dakasa-production' AND i.environment='production' AND i.domain='notify' AND i.dimension='original_notify_aws_vm_members'),\n 'current_intent_pgtext',(SELECT i.intent::text FROM public.capacity_intents i WHERE i.namespace='dakasa-production' AND i.environment='production' AND i.domain='notify' AND i.dimension='original_notify_aws_vm_members'),\n 'active_policies',(SELECT COALESCE(jsonb_agg(jsonb_build_object('id',p.id,'version',p.version,'checksum',p.checksum,'spec',p.spec) ORDER BY p.version),'[]'::jsonb) FROM public.manifests p WHERE p.kind='capacity_policy' AND p.namespace='dakasa-production' AND p.name='notify-aws-elastic-capacity' AND p.active),\n 'retirement_requests',(SELECT COALESCE(jsonb_agg(to_jsonb(x)||jsonb_build_object('wire_hex',encode(x.original_wire,'hex'))),'[]'::jsonb) FROM request x),\n 'preregistrations',(SELECT COALESCE(jsonb_agg(to_jsonb(x)||jsonb_build_object('wire_hex',encode(x.original_wire,'hex'))),'[]'::jsonb) FROM pre x),\n 'create_grants',(SELECT COALESCE(jsonb_agg(to_jsonb(g)||jsonb_build_object('grant_pgtext',g.grant_record::text) ORDER BY g.id),'[]'::jsonb) FROM public.capacity_mutation_grants g JOIN pre ON pre.create_grant_id=g.id),\n 'retirement_contexts',(SELECT COALESCE(jsonb_agg(to_jsonb(x)),'[]'::jsonb) FROM public.capacity_guest_original_retirement_contexts x JOIN request r ON r.id=x.intent_id),\n 'caller_returns',(SELECT COALESCE(jsonb_agg(to_jsonb(x)||jsonb_build_object('wire_hex',encode(x.original_wire,'hex')) ORDER BY x.recorded_at),'[]'::jsonb) FROM public.capacity_guest_original_caller_returns x JOIN request r ON r.id=x.intent_id),\n 'original_returns',(SELECT COALESCE(jsonb_agg(to_jsonb(x)||jsonb_build_object('wire_hex',encode(x.original_wire,'hex')) ORDER BY x.sequence),'[]'::jsonb) FROM public.capacity_vm_retirement_original_returns x JOIN request r ON r.id=x.intent_id),\n 'native_poweroff_reads',(SELECT COALESCE(jsonb_agg(to_jsonb(x)||jsonb_build_object('wire_hex',encode(x.original_wire,'hex')) ORDER BY x.recorded_at,x.id),'[]'::jsonb) FROM public.capacity_guest_original_native_poweroff_reads x JOIN request r ON r.id=x.intent_id),\n 'forward_rows',(SELECT COALESCE(jsonb_agg(to_jsonb(x) ORDER BY x.recorded_at,x.id,x.stage),'[]'::jsonb) FROM public.capacity_guest_retirement_forwards x JOIN request r ON r.id=x.retirement_request_id),\n 'forward_reads',(SELECT COALESCE(jsonb_agg(to_jsonb(x) ORDER BY x.recorded_at,x.id,x.stage),'[]'::jsonb) FROM public.capacity_guest_retirement_forward_reads x JOIN request r ON r.id=x.retirement_request_id),\n 'delete_bindings',(SELECT COALESCE(jsonb_agg(to_jsonb(x)),'[]'::jsonb) FROM bindings x),\n 'destroy_grants',(SELECT COALESCE(jsonb_agg(to_jsonb(g)||jsonb_build_object('grant_pgtext',g.grant_record::text) ORDER BY g.id),'[]'::jsonb) FROM public.capacity_mutation_grants g WHERE g.id IN(SELECT destroy_grant_id FROM bindings) OR (g.generation=37 AND g.grant_record#>>'{grant,capability}'=g.grant_record#>>'{binding,destroy_capability}' AND EXISTS(SELECT 1 FROM pre JOIN public.capacity_mutation_grants created ON created.id=pre.create_grant_id WHERE g.integration_instance_id=created.integration_instance_id AND g.scope_checksum=created.scope_checksum AND g.profile_name=created.profile_name AND g.slot=created.slot))),\n 'workflow_runs',(SELECT COALESCE(jsonb_agg(to_jsonb(w)||jsonb_build_object('run_wire',row_to_json(w)::text) ORDER BY w.id),'[]'::jsonb) FROM owners w),\n 'owning_dispatch_jobs',(SELECT COALESCE(jsonb_agg(to_jsonb(j)||jsonb_build_object('dispatch_wire',to_jsonb(j)::text) ORDER BY j.created_at,j.id),'[]'::jsonb) FROM public.capacity_dispatch_jobs j JOIN owners w ON w.id=j.run_id)\n)) SELECT jsonb_build_object('observed_at_pg',clock_timestamp(),'records',v,'records_wire',v::text,'records_sha256',encode(sha256(convert_to(v::text,'UTF8')),'hex')) FROM snapshot"


ROOT97_CURRENT_CORE_SOURCE = '21003808115d0b5cd62ae503ef16e65e13d4798f'

ROOT97_CURRENT_CORE_DIGEST = '311e5c19868a67f900b318e059a806e45e5dd217d0c411a03bcd598f6f10d5ce'

M97_FUNCTIONS = ('guard_retirement_forward', 'retirement_forward_normal_finish_recovery_valid')

ROOT96_SHA = 'c44e5ef3554ee494001815358434119c31832977db90a44eb925097df137c9d6'


def full_id(value):
    return type(value) is str and re.fullmatch('[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}', value) is not None



def image_snapshot(value, expected):
    closed(value,'observed_at_pg records records_wire records_sha256','CLOSED_IMAGE_ONLY_CURRENT_SNAPSHOT')
    need(type(value['records_wire'])is str and loads(value['records_wire'])==value['records'] and sha(value['records_wire'].encode())==value['records_sha256']==expected,'WHOLE_IMAGE_ONLY_PG_WIRE_NOT_REENCODED')
    return value['records']



def paid_original_sdk(stored, tuple_, destroy):
    record=stored['grant_record'];g=record['grant'];s=record['settlement'];b=record['binding']
    key='original_provider_destroy_return'if destroy else'original_provider_create_return';sdk=s.get(key)
    need(loads(stored['grant_pgtext'])==record and stored['id']==g['grant_id'] and stored['state']==g['state'] and g['state']in(('settled','confirmed')if destroy else('confirmed',)) and g.get('compensation_of','')=='' and s['outcome']=='accepted' and s['transport_completed']is True and g['capability']==b['destroy_capability'if destroy else'ensure_capability'] and all(g[k]==b[a]for k,a in (('binding_name','name'),('integration_instance_id','integration_instance_id'),('scope_checksum','scope_checksum'),('profile_name','profile_name'))),'EXACT_IMAGE_ONLY_KNOWN_ORIGINAL_GRANT_BINDING')
    need(type(sdk)is dict and sdk['schema']==('aws_original_terminate_instances_return_v1'if destroy else'aws_original_run_instances_return_v1') and sdk['provider']=='aws' and sdk['adapter_source_commit']==b['original_provider_source_commit']==A3_CREATOR and type(sdk['response_status'])is int and sdk['response_status']==200 and digest_value(sdk['response_body_sha256']) and type(sdk['response_bytes'])is int and 2<=sdk['response_bytes']<=2<<20 and sdk['grant_id']==g['grant_id'] and sdk['attempt_id']==record['attempt_id'] and sdk['request_sha256']==g['request_sha256']==s['request_sha256'] and sdk['action_id']==s['action_id'] and sdk.get('next_action_ids')==s.get('next_action_ids',[])==[],'EXACT_IMAGE_ONLY_PAID_C34_SDK200')
    need(sdk['resource_id']==s['resource_id']==tuple_['resource_id'] and sdk['resource_created_at']==s['resource_created_at']==tuple_['resource_created_at'] and g['slot']==tuple_['slot'] and g['profile_name']==tuple_['profile'] and g['integration_instance_id']==tuple_['integration_instance_id'] and g['scope_checksum']==tuple_['scope_checksum'] and utc(sdk['called_at'])<=utc(sdk['returned_at'])<utc(sdk['context_deadline'])<=utc(g['expires_at']),'EXACT_IMAGE_ONLY_SDK_TARGET_AND_ORIGINAL_CLOCK')
    if destroy:
        need(g['expected_resource_id']==tuple_['resource_id'] and g['expected_resource_created_at']==tuple_['resource_created_at'] and s['auxiliary_inventory_complete']is True and len(s['auxiliary_resources'])==2 and {x['kind']for x in s['auxiliary_resources']}=={'aws_ebs_volume','aws_network_interface'},'EXACT_IMAGE_ONLY_PAID_DESTROY_AUX2')
    return record



def catalog97_select(legacy):
    """Same seven-key catalog, explicitly retaining the new M97 function."""
    sql = catalog94_select(legacy)
    old = "p.proname IN('guard_retirement_forward','guard_retirement_forward_read','guard_retirement_forward_delete_binding','retirement_forward_continuation_quiet','retirement_forward_continuation_valid')"
    need(sql.count(old) == 1, 'EXACT_HISTORICAL_FUNCTION_SELECTOR_FOR97')
    return sql.replace(old, old[:-1] + ",'retirement_forward_normal_finish_recovery_valid')", 1)



def migration97_functions(sql):
    need(digest_value(M97) and sha(sql.encode()) == M97, 'EXACT_PINNED_M97_SOURCE')
    up = sql.split('-- +goose Down', 1)[0]
    patterns = {
        'retirement_forward_normal_finish_recovery_valid':
            (r"CREATE OR REPLACE FUNCTION public\.retirement_forward_normal_finish_recovery_valid\(r jsonb, retirement uuid\) RETURNS boolean\nLANGUAGE plpgsql STABLE SET timezone='UTC' AS \$\$(.*?)\$\$;",
             'r jsonb, retirement uuid', 'boolean', 's', ['TimeZone=UTC']),
        'guard_retirement_forward':
            (r"CREATE OR REPLACE FUNCTION public\.guard_retirement_forward\(\) RETURNS trigger LANGUAGE plpgsql AS \$\$(.*?)\$\$;",
             '', 'trigger', 'v', None),
    }
    result = {}
    for name, (pattern, arguments, output, volatility, config) in patterns.items():
        rows = re.findall(pattern, up, re.S)
        need(len(rows) == 1 and rows[0], 'ONE_EXACT_SOURCE97_FUNCTION_' + name)
        result[name] = {'arguments': arguments, 'result': output, 'language': 'plpgsql',
                        'volatility': volatility, 'config': config, 'body': rows[0]}
    return result



def constraint97_definitions(prior96, carrier, read_ref, expected_source):
    """Authenticate unchanged CI originals through explicit same-hash copies."""
    closed(carrier, 'artifact_ref before96_ref after97_ref', 'CLOSED97_PG_ORIGINAL_CUSTODY_CARRIER')
    raw = {key: read_ref(value) for key, value in carrier.items()}
    artifact = loads(raw['artifact_ref'])
    closed(artifact, 'schema source_commit postgres_major fixture_only native_authority before96_ref after97_ref migration97_sha256 old_continuation_functions_unchanged old_continuation_constraints_unchanged old_mode93_absent new_mode97_and_normal_finish97_validated', 'CLOSED_ACTUAL97_PG_CI_ARTIFACT12')
    need(artifact['schema'] == 'normal_finish_recovery_schema97_pg_catalog_v1'
         and source(expected_source) and artifact['source_commit'] == expected_source
         and artifact['postgres_major'] in (16, 17)
         and type(artifact['postgres_major']) is int and artifact['fixture_only'] is True
         and artifact['native_authority'] is False and artifact['migration97_sha256'] == M97
         and all(artifact[key] is True for key in (
             'old_continuation_functions_unchanged', 'old_continuation_constraints_unchanged',
             'old_mode93_absent', 'new_mode97_and_normal_finish97_validated')),
         'ACTUAL97_SOURCE_PG_CI_FACTS_NOT_NATIVE_QUALIFICATION')
    views = {}
    for key in ('before96_ref', 'after97_ref'):
        original = artifact[key]
        closed(original, 'path sha256 bytes', 'CLOSED_CANONICAL97_PG_CI_ORIGINAL_REF')
        need(type(original['path']) is str and Path(original['path']).is_absolute()
             and digest_value(original['sha256']) and type(original['bytes']) is int
             and 0 < original['bytes'] <= CAP and len(raw[key]) == original['bytes']
             and sha(raw[key]) == original['sha256'] == carrier[key]['sha256'],
             'COMPLETE97_PG_ORIGINAL_SAME_SHA_COPY')
        view = loads(raw[key])
        closed(view, 'server_version_num functions constraints', 'CLOSED97_PG_RAW_CATALOG')
        need(type(view['server_version_num']) is int
             and view['server_version_num'] // 10000 == artifact['postgres_major']
             and type(view['functions']) is dict and type(view['constraints']) is list,
             'ACTUAL97_PG_VERSION_AND_FULL_CATALOG_SHAPES')
        views[key] = view
    before, after = views['before96_ref'], views['after97_ref']
    need(before['server_version_num'] == after['server_version_num'], 'SAME97_CI_PG_SERVER')
    old_names = {'guard_retirement_forward', 'retirement_forward_continuation_valid',
                 'retirement_forward_continuation_quiet'}
    need(set(before['functions']) == old_names
         and set(after['functions']) == old_names | {'retirement_forward_normal_finish_recovery_valid'}
         and all(type(value) is str and value for value in before['functions'].values())
         and all(type(value) is str and value for value in after['functions'].values()),
         'EXACT97_CHANGED_ADDED_AND_HISTORICAL_FUNCTION_ROSTER')
    prior_functions = {row['name']: row for row in prior96['functions93']}
    need(all(before['functions'][name] == prior_functions[name]['definition'] for name in old_names)
         and all(after['functions'][name] == before['functions'][name] for name in (
             'retirement_forward_continuation_valid', 'retirement_forward_continuation_quiet'))
         and after['functions']['guard_retirement_forward'] != before['functions']['guard_retirement_forward'],
         'ORIGINAL96_FUNCTIONS_AND_ONLY97_GUARD_CHANGE')
    checks = {}
    for label, view in (('before', before), ('after', after)):
        rows = view['constraints']
        for row in rows:
            closed(row, 'name validated definition', 'CLOSED97_PG_CHECK_ORIGINAL')
            need(type(row['name']) is str and row['validated'] is True
                 and type(row['definition']) is str and row['definition'].startswith('CHECK ('),
                 'ALL97_PG_CHECKS_VALIDATED_AND_COMPLETE')
        need(len({row['name'] for row in rows}) == len(rows), 'UNIQUE97_CHECK_NAMES')
        checks[label] = {row['name']: row for row in rows}
    prior_checks = {row['name']: {'name': row['name'], 'validated': row['validated'],
                                'definition': row['definition']}
                    for row in prior96['catalog90']['constraints']
                    if row['table'] == 'capacity_guest_retirement_forwards'
                    and row['definition'].startswith('CHECK (')}
    need(checks['before'] == prior_checks and 'retirement_forward_mode93' in checks['before']
         and set(checks['after']) == (set(checks['before']) - {'retirement_forward_mode93'}) |
             {'retirement_forward_mode97', 'retirement_forward_normal_finish97'}
         and all(checks['after'][name] == row for name, row in checks['before'].items()
                 if name != 'retirement_forward_mode93'), 'ONLY97_MODE_REPLACEMENT_AND_NEW_PROOF_CHECK')
    return {'checks': {name: checks['after'][name]['definition'] for name in (
                'retirement_forward_mode97', 'retirement_forward_normal_finish97')},
            'functions': after['functions']}




def catalog97_delta(prior96, actual97, functions, definitions):
    need(set(prior96) == set(actual97) == {
        'catalog90', 'catalog91', 'columns90_91', 'functions93',
        'index92_definition', 'index92_valid', 'schema94'},
        'SAME_COMPLETE_SEVEN_KEY_CATALOG_AT97')
    need(set(functions) == set(M97_FUNCTIONS)
         and set(definitions['checks']) == {
             'retirement_forward_mode97', 'retirement_forward_normal_finish97'},
         'EXACT_SOURCE97_FUNCTION_AND_CHECK_DELTA')
    expected = copy.deepcopy(prior96)
    old = [row for row in expected['functions93'] if row['name'] == 'guard_retirement_forward']
    need(len(old) == 1, 'ONE_PRIOR96_FORWARD_GUARD')
    for name in M97_FUNCTIONS:
        rows = [row for row in actual97['functions93'] if row['name'] == name]
        need(len(rows) == 1 and rows[0]['body'] == functions[name]['body']
             and all(rows[0][key] == functions[name][key] for key in (
                 'arguments', 'result', 'language', 'volatility', 'config'))
             and rows[0]['definition'] == definitions['functions'][name]
             and rows[0]['definition'].count(rows[0]['body']) == 1,
             'WHOLE97_SOURCE_AND_ACTUAL_PG_DEFINITION_' + name)
        if name == 'guard_retirement_forward':
            need(set(rows[0]) == set(old[0])
                 and all(rows[0][key] == old[0][key] for key in (
                     'name', 'arguments', 'result', 'language', 'volatility', 'config')),
                 'UNCHANGED97_FORWARD_GUARD_SIGNATURE')
            old[0].update(body=rows[0]['body'], definition=rows[0]['definition'])
        else:
            need(not any(row['name'] == name for row in expected['functions93']),
                 'NEW97_NORMAL_FINISH_FUNCTION_NOT_PRIOR_AUTHORITY')
            expected['functions93'].append(copy.deepcopy(rows[0]))
    expected['functions93'].sort(key=lambda row: row['name'])
    mode = [row for row in expected['catalog90']['constraints']
            if row['table'] == 'capacity_guest_retirement_forwards'
            and row['name'] == 'retirement_forward_mode93']
    need(len(mode) == 1 and mode[0]['validated'] is True, 'ONE_PRIOR96_MODE_CHECK')
    new_check = copy.deepcopy(mode[0])
    mode[0].update(name='retirement_forward_mode97',
                   definition=definitions['checks']['retirement_forward_mode97'])
    new_check.update(name='retirement_forward_normal_finish97',
                     definition=definitions['checks']['retirement_forward_normal_finish97'])
    expected['catalog90']['constraints'].append(new_check)
    expected['catalog90']['constraints'].sort(key=lambda row: (row['table'], row['name']))
    need(expected == actual97, 'ALL_OTHER96_CATALOG_FUNCTION_INDEX_TRIGGER_BYTES_UNCHANGED')
    return actual97



def root97_overlay(receipt_raw, prior96_raw, pins, read_ref):
    need(sha(prior96_raw) == ROOT96_SHA, 'IMMUTABLE_ROOT96_WHOLE_ORIGINAL')
    previous, value = loads(prior96_raw), loads(receipt_raw)
    closed(value, 'schema reviewed_by_root schema_before schema_after current_core_source current_ops_source business_source amd64_D migration97_sha256 complete_history_sha256 prior96_history_sha256 catalog97_sha256 index92_definition_sha256 catalog90_91_sha256 job_uid pod_uid exit_code single_job_create provider_guest_core_mutations old_records_and_sdk_preserved original_refs', 'ROOT97_CLOSED21')
    need(previous['schema'] == 'root_goose96_guest_retirement_pre_read_continuation_acceptance_v1'
         and previous['reviewed_by_root'] is True and previous['schema_after'] == 96
         and value['schema'] == 'root_goose97_normal_finish_recovery_acceptance_v1'
         and value['reviewed_by_root'] is True and value['schema_before'] == 96
         and value['schema_after'] == 97, 'ROOT97_DISTINCT_FROM_HISTORICAL96')
    need(value['current_core_source'] == ROOT97_CURRENT_CORE_SOURCE
         and value['current_ops_source'] == pins['current_ops_source']
         and source(value['current_ops_source']) and value['business_source'] == pins['business_source']
         and source(value['business_source']) and value['amd64_D'] == pins['amd64_D']
         and digest_value(value['amd64_D']), 'ROOT97_ACTUAL_CORE7_AND_QUALIFIED_CORE8_COMPANION')
    need(digest_value(M97) and value['migration97_sha256'] == M97
         and value['complete_history_sha256'] == pins['complete_history_sha256']
         and value['prior96_history_sha256'] == previous['complete_history_sha256'] == pins['prior96_history_sha256']
         and value['catalog97_sha256'] == pins['catalog97_sha256']
         and value['index92_definition_sha256'] == previous['index92_definition_sha256'] == pins['index92_definition_sha256']
         and value['catalog90_91_sha256'] == pins['catalog90_91_sha256'],
         'ACTUAL97_WHOLE_HISTORY_CATALOG_AND_PRIOR96')
    need(full_id(value['job_uid']) and full_id(value['pod_uid'])
         and type(value['exit_code']) is int and value['exit_code'] == 0
         and value['single_job_create'] is True
         and type(value['provider_guest_core_mutations']) is int and value['provider_guest_core_mutations'] == 0
         and value['old_records_and_sdk_preserved'] is True, 'ROOT97_ONE_JOB_NO_PROVIDER_OR_CORE_MUTATION')
    closed(value['original_refs'], 'migration_result before_catalog after_catalog source_ci qualified_image',
           'ROOT97_FIVE_ORIGINAL_ROLES')
    need(len({ref['sha256'] for ref in value['original_refs'].values()}) == 5,
         'ROOT97_DISTINCT_ORIGINAL_ROLES')
    for ref in value['original_refs'].values():
        original = read_ref(ref)
        need(type(original) is bytes and len(original) > 1, 'ROOT97_COMPLETE_ORIGINAL_CUSTODY')
    return value



def normal_finish_wire(row, record_key, digest_key):
    raw = bytes.fromhex(row['wire_hex'])
    need(normal_pg_bytea(row['original_wire']) == raw
         and loads(raw) == row[record_key] and sha(raw) == row[digest_key],
         'COMPLETE_NORMAL_FINISH_ORIGINAL_WIRE')
    return raw




def validate_normal_finish97(value, case):
    closed(case, 'schema retirement_request_id preregistration_id current_runtime_source current_generation current_fencing_token current_lease_owner current_executor_id current_failed_run_id expected_records_sha256 provider_lanes',
           'CLOSED_NORMAL_FINISH_IMAGE_CASE11')
    t = NORMAL_FINISH_TARGET
    need(case['schema'] == NORMAL_FINISH_CASE_SCHEMA
         and case['retirement_request_id'] == t['retirement_request_id']
         and case['preregistration_id'] == t['preregistration_id']
         and case['current_runtime_source'] == ROOT97_CURRENT_CORE_SOURCE
         and type(case['current_generation']) is int and case['current_generation'] == t['generation']
         and type(case['current_fencing_token']) is int and case['current_fencing_token'] == t['fence']
         and case['current_lease_owner'] == t['lease_owner']
         and case['current_executor_id'] == t['executor_id']
         and case['current_failed_run_id'] == t['run_id'], 'EXACT_G37_NORMAL_FINISH_OWNER_NOT_LIVE')
    r = image_snapshot(value, case['expected_records_sha256'])
    closed(r, 'selected_runtime_source target current_intent current_intent_pgtext active_policies retirement_requests preregistrations create_grants retirement_contexts caller_returns original_returns native_poweroff_reads forward_rows forward_reads delete_bindings destroy_grants workflow_runs owning_dispatch_jobs',
           'FULL_NORMAL_FINISH_RECORD_SET')
    need(r['selected_runtime_source'] == ROOT97_CURRENT_CORE_SOURCE
         and r['target'] == {k: t[k] for k in ('retirement_request_id','preregistration_id')}
         and r['forward_rows'] == r['forward_reads'] == r['delete_bindings'] == r['destroy_grants'] == [],
         'NO_NORMAL_FINISH_FORWARD_OR_DELETE_AUTHORITY_INVENTED')
    current = r['current_intent']['intent']
    need(loads(r['current_intent_pgtext']) == current
         and current['generation'] == t['generation'] and current['fencing_token'] == t['fence']
         and current['lease_owner'] == t['lease_owner'] and current['lease_executor_id'] == t['executor_id']
         and current['phase'] in ('draining','drained') and current.get('recovery_only',False) is False
         and current.get('floor_degraded',False) is False and current.get('retirement_forward') is None
         and utc(current['lease_expires_at']) < utc(value['observed_at_pg']),
         'EXACT_EXPIRED_NORMAL_EPOCH_NO_MARKER_OR_CLOCK_RESET')
    need(len(r['active_policies']) == 1 and r['active_policies'][0]['id'] == current['policy_id']
         and r['active_policies'][0]['checksum'] == current['policy_checksum'],
         'NORMAL_FINISH_CURRENT_POLICY_NOT_RELABELED')
    need(len(r['retirement_requests']) == len(r['preregistrations']) == len(r['create_grants'])
         == len(r['retirement_contexts']) == len(r['caller_returns']) == 1,
         'ONE_ORIGINAL_NORMAL_RETIREMENT_CALLER_AND_CREATE')
    request, pre = r['retirement_requests'][0], r['preregistrations'][0]
    need(request['id'] == t['retirement_request_id'] and request['preregistration_id'] == pre['id']
         == t['preregistration_id'], 'ORIGINAL_NORMAL_REQUEST_PREREGISTRATION')
    request_raw = bytes.fromhex(request['wire_hex'])
    need(request_raw == normal_pg_bytea(request['original_wire'])
         and loads(request_raw)['intent'] == request['intent_record']
         and sha(raw_json_member(request_raw,'intent')) == request['intent_sha256'],
         'COMPLETE_DURABLE_NORMAL_REQUEST_WITH_EXACT_INTENT_TOKEN_HASH')
    intent = request['intent_record']
    need(intent['schema'] == 'original_guest_production_retirement_intent_v2'
         and intent['request_id'] == request['id'] and intent['attempt_id'] == request['attempt_id']
         and intent['preregistration_id'] == pre['id']
         and intent['generation'] == t['generation'] and intent['fence'] == t['fence']
         and intent['lease_owner'] == t['lease_owner'] and loads(request_raw)['nonce'] == '',
         'EXACT_ORIGINAL_NORMAL_REQUEST_OWNER_AND_DURABLE_REDACTED_NONCE')
    caller = r['caller_returns'][0]; caller_raw = normal_finish_wire(caller,'original_record','return_sha256')
    c = caller['original_record']
    need(caller['intent_id'] == request['id'] and c['request_id'] == request['id']
         and c['attempt_id'] == request['attempt_id'] and type(c['status']) is int and c['status'] == 200
         and c['body_persisted'] is True and all(c[k] is False for k in (
             'preflight_failed','do_failed','read_failed','close_failed','original_context_failed'))
         and utc(c['original_deadline']) == utc(request['original_deadline'])
         and utc(request['intent_record']['issued_at']) <= utc(c['started_at']) <= utc(c['do_started_at'])
         <= utc(c['do_returned_at']) <= utc(c['read_returned_at']) <= utc(c['close_returned_at'])
         <= utc(c['driver_returned_at']) < utc(request['original_deadline']),
         'GENUINE_ORIGINAL_NORMAL_CALLER200_COMPLETE_BEFORE_DEADLINE')
    original = r['original_returns']
    need(len(original) == 5 and [x['sequence'] for x in original] == [1,2,3,4,5]
         and all(x['intent_id'] == request['id'] for x in original)
         and [x['original_return_record']['record']['sequence'] for x in original[1:]] == [1,2,3,4]
         and [x['kind'] for x in original] == ['production_clock_nonce_v2'] + [
             'production_retirement_v2:' + state for state in (
                 'possible_start','quiescent','poweroff_possible_start','poweroff_command_returned')],
         'ALL_FIVE_NORMAL_ORIGINAL_RETIREMENT_RETURNS')
    raws = []
    for index,row in enumerate(original):
        raw = bytes.fromhex(row['wire_hex'])
        need(raw == normal_pg_bytea(row['original_wire'])
             and loads(raw) == row['original_return_record']
             and sha(raw if index == 0 else raw_json_member(raw,'record')) == row['return_sha256'],
             'COMPLETE_NORMAL_NONCE_OR_JOURNAL_WITH_ITS_SOURCE_DIGEST_DOMAIN')
        raws.append(raw)
    nonce = original[0]['original_return_record']
    need(original[0]['kind'] == 'production_clock_nonce_v2'
         and nonce['schema'] == 'original_core_guest_retirement_nonce_return_v2'
         and nonce['preflight_sha256'] == request['intent_sha256'],
         'AUTHENTICATED_ORIGINAL_NORMAL_NONCE_NOT_JSON_RECODE')
    final_request = nonce['final_request']; final_intent = final_request['intent']
    final_request_raw = raw_json_member(raws[0], 'final_request')
    final_intent_raw = raw_json_member(final_request_raw, 'intent')
    final_sha = sha(final_intent_raw)
    need(loads(final_intent_raw) == final_intent and final_intent['tuple'] == request['intent_record']['tuple']
         and final_request['nonce'] == ''
         and all(final_intent[k] == intent[k] for k in (
             'schema','request_id','attempt_id','preregistration_id','generation','fence','lease_owner')),
         'EXACT_FINALIZED_NORMAL_INTENT_RAW_TOKEN')
    returned = original[4]['original_return_record']
    need(original[4]['kind'] == 'production_retirement_v2:poweroff_command_returned'
         and loads(base64.b64decode(c['body'],validate=True)) == returned
         and returned['journal_complete'] is True and returned['hold_reasons'] == []
         and returned['record']['sequence'] == 4 and returned['record']['poweroff_command_returned'] is True
         and returned['record']['writer_quiescence_evidence'] is True
         and returned['record']['powered_off_observed'] is False,
         'NORMAL_RETIRE_SUCCESS_IS_NOT_NATIVE_OFF_OR_DELETE_AUTHORITY')
    tuple_ = final_intent['tuple']
    need(tuple_['slot'] == 2 and current['decision']['units'] == 1
         and final_intent['policy_id'] == current['policy_id']
         and final_intent['policy_checksum'] == current['policy_checksum'],
         'NORMAL_FINISH_EXACT_SLOT2_AND_CURRENT_POLICY')
    created = paid_original_sdk(r['create_grants'][0],tuple_,False)
    need(pre['create_grant_id'] == created['grant']['grant_id'], 'NORMAL_FINISH_SAME_PAID_ORIGINAL_CREATE')
    context = r['retirement_contexts'][0]
    need(context['intent_id'] == request['id']
         and context['executor_id'] == t['executor_id']
         and context['core_actual_source_commit'] == ROOT97_CURRENT_CORE_SOURCE
         and utc(context['original_context_deadline']) < utc(value['observed_at_pg'])
         and utc(request['original_deadline']) < utc(value['observed_at_pg']),
         'NATURAL_NORMAL_CONTEXT_AND_LEASE_EXPIRY')
    reads = r['native_poweroff_reads']
    need(len(reads) == 2, 'EXACT_NORMAL_OFF_PREPARED_AND_FAILED_RETURN')
    prepared = [x for x in reads if x['original_record'].get('schema') == 'original_core_guest_native_poweroff_read_challenge_v2']
    replies = [x for x in reads if x['original_record'].get('schema') == 'original_core_guest_native_poweroff_read_return_v2']
    need(len(prepared) == len(replies) == 1, 'NO_UNKNOWN_OR_EXTRA_NORMAL_OFF_ORIGINAL')
    prepared, reply = prepared[0], replies[0]
    challenge_raw = normal_finish_wire(prepared,'original_record','observation_sha256')
    normal_finish_wire(reply,'original_record','observation_sha256')
    d, v = prepared['original_record'], reply['original_record']
    need(normal_pg_bytea(reply['original_native_join_wire']) == challenge_raw
         and v['challenge'] == d and d['read_id'] == prepared['id'] and d['intent_id'] == request['id']
         and d['intent_sha256'] == final_sha and d['original_caller_sha256'] == caller['return_sha256']
         and d['tuple'] == tuple_ and digest_value(d['mutation_binding_sha256'])
         and d['adapter_source_commit'] == created['binding']['original_provider_source_commit']
         and utc(caller['recorded_at']) < utc(prepared['recorded_at']) <= utc(reply['recorded_at'])
         and utc(d['issued_at_core']) < utc(d['original_deadline_core'])
         <= utc(d['issued_at_core']) + datetime.timedelta(seconds=5),
         'EXACT_ORIGINAL_NORMAL_OFF_CHALLENGE_JOIN_AND_FIVE_SECOND_CAP')
    need(v['call_failed'] is True and v['original_context_failed'] is False
         and v['status'] in ('','observed') and 'plan' not in v
         and utc(d['issued_at_core']) <= utc(v['started_at_core'])
         <= utc(v['original_returned_at_core']) < utc(d['original_deadline_core'])
         and utc(v['original_returned_at_core']) <= utc(reply['recorded_at']),
         'ACTUAL_FAILED_NORMAL_OFF_WITHOUT_OBSERVED_AUTHORITY')
    need(len(r['workflow_runs']) == len(r['owning_dispatch_jobs']) == 1,
         'UNIQUE_NORMAL_FINISH_ORIGINAL_WORKFLOW_OWNER')
    w,j = r['workflow_runs'][0],r['owning_dispatch_jobs'][0]
    need(loads(w['run_wire']) == {k:v for k,v in w.items() if k!='run_wire'}
         and loads(j['dispatch_wire']) == {k:v for k,v in j.items() if k!='dispatch_wire'}
         and w['id'] == j['run_id'] == t['run_id'] and w['status'] == w['result']['status']
         == j['return_status'] == 'failed' and j['state'] == 'returned'
         and utc(reply['recorded_at']) <= utc(w['finished_at']) == utc(j['returned_at'])
         <= utc(j['finalization_ack_at']) <= utc(value['observed_at_pg'])
         and w['metadata']['capacity_dispatch_job_id'] == j['id']
         and w['metadata']['triggered_by'] == 'workflow_scheduler'
         and loads(j['envelope'])['workflow']['id'] == final_intent['workflow_id'],
         'EXACT_NORMAL_FINISH_FAILED_WORKFLOW_AND_FINAL_ACK')
    steps=w['result']['steps'];need(len(steps)==7 and len({x['id'] for x in steps})==7,
                                  'EXACT_NORMAL_FINISH_SEVEN_STEPS')
    steps={x['id']:x for x in steps};plan=steps['plan-original-guest'];retired=steps['retire-original-guest']
    need(plan['status']=='succeeded' and plan['metadata']['generation']==t['generation']
         and plan['metadata']['fencing_token']==t['fence']
         and plan['metadata']['lease_owner']==t['lease_owner']
         and retired['status']=='succeeded' and retired['metadata']['request_id']==request['id']
         and retired['metadata']['intent_sha256']==final_sha
         and retired['metadata']['native_poweroff_known'] is False
         and steps['finish-original-retirement']['status']=='failed'
         and all(steps[k]['status']=='skipped' for k in (
             'provision-original-notify','complete-original-provision',
             'refresh-original-membership','complete-original-retirement')),
         'FAILED_NORMAL_FINISH_NOT_FAILED_PLAN_OR_LIVE_FORWARD')
    return True




M97 = 'b90086284a3a9230ed7fb19e2348b8ca785f6172b819e1a08fc28d6e5c8d550f'
CAP = 16 << 20

def normal_pg_bytea(value):
    need(type(value) is str and re.fullmatch(r'\\x(?:[0-9a-f]{2})*',value),
         'CANONICAL_POSTGRES_JSON_BYTEA_HEX')
    return bytes.fromhex(value[2:])



if __name__=="__main__":main()
