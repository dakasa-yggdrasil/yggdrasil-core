#!/usr/bin/env python3
"""Inert one-Job Goose96 typed pre-read continuation maintenance. No Core adoption or provider/Guest action.

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
BASELINE95_ACCEPTANCE_SHA256 = 'b80ec307962a67b8a28722c8fbf88add02c25de08847253fbae7838de1c0153d'
PRE_READ_PREIMAGE_SHA256 = None
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
CURRENT_CORE_R = '33a846d31a5b123b2c1141192671bc830bf6d9c8'
CURRENT_CORE_D = '35195e4ddff2a69f2ae7fca8f24b43177c61c49f12117a4fe4925a43e9cd6fde'
CURRENT_CORE_CONFIG = '1556bb6d9b43dadbe35e09124413d73c6395703af4261527781c9c459fe10188'
CURRENT_CORE_UID = None
CURRENT_CORE_POD_UID = None
CURRENT_CORE_GENERATION = None
GUARDIAN_S = None
M94 = '2850db98eddbfd629b98df879eb61266036d70210118e8e20289782d2b37a78c'  # Frozen Source only; no migration qualification.
M93 = 'cc2b2843d14d4183ea68d25dbb9b9b58d1a353044e6ebf46ece6b93778e937e9'
LEGACY_CATALOG_SHA = 'c9d3664e43ef876a9a7a89c031bf75f761dbb0c70a664db2408058a6ce2431eb'
TRANSPORT_SHA = '9e2f8fe524331c9ea1c2f5742588977abe47d99b6ff635e88e431f343b96c004'
E70_SHA = 'fa519e39989b31a7faa3c23358506992b057d6bf17ce2aad709dfe6fecd5c2c8'
ROOT = Path('/var/lib/dakasa-core-rollout/goose96-guest-retirement-pre-read-continuation')
CLAIM = ROOT/'GOOSE96-POSSIBLE-CREATE.json'
JOB_URI = '/apis/batch/v1/namespaces/dakasa/jobs'
DEP_URI = '/apis/apps/v1/namespaces/dakasa/deployments/yggdrasil'
RS_URI = None
CURRENT_RS_UID = None
CORE_PODS_URI = '/api/v1/namespaces/dakasa/pods?labelSelector=app%3Dyggdrasil'
PREFIX = '153828470928.dkr.ecr.us-east-1.amazonaws.com/ghcr/dakasa-yggdrasil/yggdrasil-core@sha256:'
APP = 'yggdrasil-schema96-companion'
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

def pre_read_baseline(ref):
    # The complete S8 snapshot is 5300214 bytes with all88 original read rows.
    # Use its existing8MiB case-transport bound; keep other references at4MiB.
    return loads(reference(ref,8 << 20))

def load_definitions(ref, pin, name):
    need(ref['sha256'] == pin, 'EXACT_REVIEWED_SOURCE_PIN')
    raw = reference(ref)
    module = types.ModuleType(name)
    module.__file__ = ref['path']
    exec(compile(raw, ref['path'], 'exec'), module.__dict__)
    return module

def require_bound():
    pins = (M96, M95, M94, COMPANION_IMAGE_D, COMPANION_IMAGE_PROOF_SHA256, SOURCE_CI_GATE_SHA256,
            CAS_SOURCE_SHA256, RUNTIME_MANIFEST_SHA256, G15_RETURN_SHA256,
            BASELINE95_ACCEPTANCE_SHA256, PRE_READ_PREIMAGE_SHA256, CONFIG_SHA256, JOB_MANIFEST_SHA256)
    need(SOURCE_BOUND is True and source(COMPANION_SOURCE_Q) and all(digest(v) for v in pins)
         and source(CURRENT_OPS_P) and digest(GUARDIAN_S)
         and COMPANION_SOURCE_Q not in (CURRENT_CORE_R, CURRENT_OPS_P)
         and COMPANION_IMAGE_D != CURRENT_CORE_D
         and type(RS_URI) is str and RS_URI.startswith('/apis/apps/v1/namespaces/dakasa/replicasets/')
         and type(CURRENT_RS_UID) is str
         and all(type(x)is str and str(uuid.UUID(x))==x and uuid.UUID(x).int!=0 for x in (CURRENT_CORE_UID,CURRENT_CORE_POD_UID))
         and type(CURRENT_CORE_GENERATION)is int and CURRENT_CORE_GENERATION==278
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
    return 'core-goose96-' + uuid.UUID(JOB_UUID).hex

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
    need(not CLAIM.exists(), 'GLOBAL_GOOSE96_CLAIM_ABSENT_NEVER_REPLAY')
    body = wire(job)
    need(sha(body) == JOB_MANIFEST_SHA256, 'EXACT_ROOT_REVIEWED_JOB_BODY')
    need(api.get(JOB_URI + '/' + job_name(), absent=True) is None, 'NEW_UNIQUE_UUID_JOB_ABSENT')
    marker = {'schema': 'goose96_companion_job_possible_v1', 'source_Q': COMPANION_SOURCE_Q,
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
         and b'00096_guest_retirement_pre_read_continuation.sql' in logs
         and b'successfully migrated database to version: 96' in logs, 'ORIGINAL_GOOSE96_LOG_COMPLETE_EXIT0')
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
         and roster['source'] == COMPANION_SOURCE_Q and len(roster['files']) == 95
         and sorted(r['version'] for r in roster['files'].values()) == [v for v in range(1, 97) if v != 40]
         and all(digest(r['sha256']) and type(r['bytes']) is int and r['bytes'] > 0 for r in roster['files'].values())
         and roster['files']['00093_guest_retirement_settled_absence_continuation.sql']['sha256'] == M93
         and roster['files']['00094_failed_unwitnessed_expansion_cleanups.sql']['sha256'] == M94
         and roster['files']['00095_failed_expansion_read_failure_continuation.sql']['sha256'] == M95
         and roster['files']['00096_guest_retirement_pre_read_continuation.sql']['sha256']==M96 and cfg['migration96_sql']['source_ref']['sha256']==M96, 'EXACT_QUALIFIED_IMAGE_SHIPPED_SQL_HEAD96')
    baseline = loads(reference(cfg['baseline95_acceptance']))
    closed(baseline, 'schema reviewed_by_root schema_before schema_after current_core_source current_ops_source business_source amd64_D migration95_sha256 complete_history_sha256 prior94_history_sha256 catalog95_sha256 index92_definition_sha256 catalog90_91_sha256 job_uid pod_uid exit_code single_job_create provider_guest_core_mutations old_records_and_sdk_preserved original_refs', 'EXACT_IMMUTABLE_ROOT95_RECEIPT21')
    need(cfg['baseline95_acceptance']['sha256'] == BASELINE95_ACCEPTANCE_SHA256
         and baseline['schema'] == 'root_goose95_failed_expansion_read_continuation_acceptance_v1'
         and baseline['reviewed_by_root'] is True and baseline['schema_before'] == 94 and baseline['schema_after'] == 95
         and baseline['current_core_source'] == '7cd5cea0834bcee901c282bc81b9486d5c16513b'
         and baseline['current_ops_source'] == '85be49ecdc4c5610f57dc1331a5781f37721d6d2'
         and baseline['business_source'] == CURRENT_CORE_R and baseline['amd64_D'] == CURRENT_CORE_D
         and baseline['migration95_sha256'] == M95 and baseline['exit_code'] == 0
         and baseline['single_job_create'] is True and baseline['provider_guest_core_mutations'] == 0
         and baseline['old_records_and_sdk_preserved'] is True
         and all(digest(baseline[k]) for k in ('complete_history_sha256','prior94_history_sha256','catalog95_sha256','index92_definition_sha256','catalog90_91_sha256')),
         'ORIGINAL_ROOT95_NOT_RETYPED_AS96_OR_FUTURE_R5_ADOPTION')
    closed(baseline['original_refs'], 'migration_result before_catalog after_catalog source_ci qualified_image', 'ROOT95_ORIGINAL_FIVE_ROLES_UNCHANGED')
    for original in baseline['original_refs'].values():
        need(len(reference(original)) > 1, 'ROOT95_WHOLE_ORIGINAL_CUSTODY')
    return baseline


def stable_metadata(value):
    return {k: v for k, v in value['metadata'].items() if k not in ('resourceVersion', 'managedFields')}


def core(api, expected):
    closed(expected, 'deployment_uid generation deployment_spec_sha256 deployment_metadata_sha256 replicaset_name replicaset_uid replicaset_spec_sha256 replicaset_metadata_sha256 pod_name pod_uid container_id container_started_at node_name pod_spec_sha256', 'CLOSED_ACTUAL_CORE14')
    need(expected['deployment_uid'] == CURRENT_CORE_UID
         and expected['generation'] == CURRENT_CORE_GENERATION == 278 and expected['pod_uid'] == CURRENT_CORE_POD_UID
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
    closed(cfg,'schema source_ci_acceptance companion_image_proof companion_sql_roster baseline95_acceptance runtime_package g15_return g15_cas_source runtime_config_ref transport_source core_preimage e70_sql_data pre_read_preimage case migration96_sql legacy_catalog_sql','CLOSED_GOOSE96_CONFIG')
    need(cfg['schema'] == 'root_goose96_pre_read_continuation_companion_config_v1','TYPED_NEW_MAINTENANCE_CASE_NO_ADMIN_ADMISSION')
    accepted = qualification(cfg)
    S = load_definitions(cfg['transport_source'],TRANSPORT_SHA,'reviewed_generic_job_mtls_transport')
    V = load_definitions(cfg['g15_cas_source'],CAS_SOURCE_SHA256,'reviewed_actual_g15_runtime_only')
    V.CONFIG_REF = V.validated_config_ref(cfg['runtime_config_ref']['path'],cfg['runtime_config_ref']['sha256']); V.require_bound()
    reference(cfg['runtime_config_ref'])
    cut = V.load_tools(Path(cfg['runtime_package'])); C = cut.C
    folder, manifest = C.package(Path(cfg['runtime_package']),RUNTIME_MANIFEST_SHA256)
    need(cfg['g15_return']['sha256'] == G15_RETURN_SHA256,'ACTUAL_PHYSICAL_G15_RETURN')
    returned = loads(reference(cfg['g15_return'],32<<20))
    need(cfg['e70_sql_data']['sha256'] == E70_SHA and cfg['pre_read_preimage']['sha256'] == PRE_READ_PREIMAGE_SHA256,'EXACT_ORIGINAL_E70_AND_KNOWN_S8_PRE_READ_BASELINE')
    e70, baseline = loads(reference(cfg['e70_sql_data'])), pre_read_baseline(cfg['pre_read_preimage'])
    validate_pre_read96(baseline,cfg['case'])
    need(cfg['legacy_catalog_sql']['sha256'] == LEGACY_CATALOG_SHA,'EXACT_LEGACY_CATALOG_SQL')
    legacy = reference(cfg['legacy_catalog_sql']).decode()
    carrier=cfg['migration96_sql'];closed(carrier,'source_ref constraint96_deparse_ref','CLOSED_SOURCE96_AND_PG16_DEPARSE_REFS')
    m96=reference(carrier['source_ref']).decode();deparse=loads(reference(carrier['constraint96_deparse_ref']))
    expected = source_functions(m96); sql = catalog94_sql(legacy,V)
    job = job_manifest(); need(private_read(args.manifest) == wire(job) and sha(wire(job)) == JOB_MANIFEST_SHA256,'ACTUAL_ROOT_REVIEWED_EXTERNAL_JOB_BODY')
    C.shared_parent(ROOT.parent); C.private_dir(ROOT,create=not ROOT.exists()); run = args.evidence_dir.absolute()
    need(run.parent == ROOT and re.fullmatch('(?:migration96|reconcile96)-[a-f0-9-]{36}',run.name),'NEW_EXCLUSIVE_GOOSE96_EVIDENCE_LEAF')
    C.private_dir(run,create=True)
    try:
        with V.operation_lock():
            api = CapturedAPI(S.API(cut),C,run,not args.reconcile_get_only)
            if args.reconcile_get_only:
                marker = loads(C.read(CLAIM,32768,0o600))
                need(marker['schema'] == 'goose96_companion_job_possible_v1' and marker['source_Q'] == COMPANION_SOURCE_Q
                     and marker['companion_image_D'] == COMPANION_IMAGE_D and marker['current_ops_P'] == CURRENT_OPS_P
                     and marker['job_uuid'] == JOB_UUID and marker['manifest_sha256'] == JOB_MANIFEST_SHA256
                     and marker['config_sha256'] == CONFIG_SHA256 and marker['script_sha256'] == args.expected_script_sha256
                     and marker['automatic_retry'] is False,'EXACT_CONSUMED_JOB_CLAIM_GET_ONLY')
                uid,pod_uid,logs = observe_owned_job(api,job,S,None,deadline)
                result = {'schema':'goose96_reconcile_return_v1','status':'ORIGINAL_JOB_OBSERVED_ROOT_INDEPENDENT_ACCEPTANCE_PENDING',
                          'job_uid':uid,'pod_uid':pod_uid,'logs_sha256':logs,'POST_sent':False,'automatic_retry':False}
            else:
                need(not CLAIM.exists(),'GLOBAL_GOOSE96_CLAIM_ABSENT_NO_RESET')
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
                     and core(api,cfg['core_preimage']) == before_core and oneshots(cut) == before_ones,'SAME_CORE_S8_PRE_READ_GUARDS_AND_ONESHOTS_AFTER_JOB')
                gdir = run/'G15-AFTER'; C.private_dir(gdir,create=True)
                _,refs2,ctrl2,guard2,_ = runtime(V,cut,folder,manifest,returned,gdir)
                need((refs2,ctrl2,guard2) == (refs,ctrl,guard),'SAME_ALL43_REFS_BUDGET1_AND_CONTROLLER_GUARDIAN_LIFETIMES')
                result = {'schema':'goose96_companion_job_return_v1','status':'JOB_ACK_PLUS_OBSERVATIONS_ROOT_INDEPENDENT_ACCEPTANCE_PENDING',
                          'companion_source_Q':COMPANION_SOURCE_Q,'companion_image_D':COMPANION_IMAGE_D,'current_ops_P':CURRENT_OPS_P,
                          'current_Core_source':CURRENT_CORE_R,'current_Core_D':CURRENT_CORE_D,'job_uid':uid,'pod_uid':pod_uid,'exit_code':0,
                          'migration96_sha256':M96,'schema_before':95,'schema_after':96,'history96_sha256':sha(after['legacy']['complete_history_wire'].encode()),
                          'prior95_history_sha256':sha(before['legacy']['complete_history_wire'].encode()),'catalog96_sha256':sha(wire(catalog94_projection(after))),
                          'catalog96_original':{'path':str(run/'AFTER-CATALOG.stdout'),'sha256':sha(C.read(run/'AFTER-CATALOG.stdout',4<<20,0o600))},
                          'catalog96_full_definitions_Root_review_pending':True,'logs_sha256':logs,'native_create_attempts':1,
                          'Core_G15_all43_budget1_Cold_Hub_and_old_records_SDK_unchanged':True,'ordinary_quiet_or_business_authority_claimed':False,
                          'provider_Guest_Core_mutations_sent':0,'automatic_retry_down_cleanup_or_repair':False}
            C.once(run/'RETURN.PUBLIC.json',wire(result)); signal.setitimer(signal.ITIMER_REAL,0)
            print(wire(result).decode(),end='',flush=True)
    except BaseException as caught:
        signal.setitimer(signal.ITIMER_REAL,0)
        result = {'schema':'goose96_companion_hold_v1','status':'HOLD_UNKNOWN_RECONCILE_GET_ONLY_NO_REPLAY','possible_send':CLAIM.exists(),
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
        need(lanes==case['provider_lanes'][provider]and lanes['intent_count']==1 and all(type(lanes[k])is int and lanes[k]==0 for k in ('jobs_busy','runs_busy','forward_unreturned_reads','live_unreturned_canaries')),'EXACT_BOTH_SOURCE_LANES_NO_GUESSED_AUTHORITY')
        result[provider]=lanes
    actual=V.query(cut,run,label+'-S8-PRE-READ',PRE_READ_SQL);validate_pre_read96(actual,case);need(actual['records_wire']==baseline['records_wire'],'ENTIRE_S8_PENDING_SDK_FAILED_ACK_PREIMAGE_EXACT');return result


def source_functions(sql):
    need(sha(sql.encode())==M96,'EXACT_PINNED_M96_SOURCE_BYTES')
    up=sql.split('-- +goose Down',1)[0]
    pattern=r"CREATE OR REPLACE FUNCTION public\.retirement_forward_continuation_valid\(r jsonb, retirement uuid\) RETURNS boolean\nLANGUAGE plpgsql STABLE SET timezone='UTC' AS \$\$(.*?)\$\$;"
    rows=re.findall(pattern,up,re.S);need(len(rows)==1 and sha(rows[0].encode())==M96_BODY_SHA,'ONE_EXACT_SOURCE96_BOOLEAN_STABLE_GUARD')
    return {M96_FUNCTION:{'arguments':'r jsonb, retirement uuid','result':'boolean','language':'plpgsql','volatility':'s','config':['TimeZone=UTC'],'body':rows[0]}}


def catalog94_sql(legacy,V):
    """Same shared CAS SELECT; retain Goose's exact 8/1/12 transaction wrapper."""
    need(sha(legacy.encode()) == LEGACY_CATALOG_SHA,'EXACT_LEGACY_QUERY_BEFORE_COMPOSITION')
    header = legacy.split('\nSELECT ',1)[0]
    select = catalog94_select(legacy)
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
    v,s=value['legacy'],value['supplement'];version=95 if old is None else 96
    need(v['database']=='yggdrasil'and v['readonly']=='on'and v['latest_versions']==[0]+[x for x in range(1,version+1)if x!=40]and v['rows90']==v['rows91']==1 and all(v[k]==0 for k in ('other_migrators_ddl','other_cic','ddl_locks'))and s['index92_valid']is True and sha(s['index92_definition'].encode())==accepted['index92_definition_sha256'],'EXACT96_HEAD_HISTORY_INDEX_AND_NO_OTHER_DDL')
    if old is None:
        if migration is not None:constraint96_definition(catalog94_projection(value),migration)
        need(sha(v['complete_history_wire'].encode())==accepted['complete_history_sha256']and sha(wire(catalog94_projection(value)))==accepted['catalog95_sha256'],'EXACT_PRIOR_ROOT95_RAW_HISTORY_AND_SEVEN_KEY_CATALOG');return
    prior,current=loads(old['legacy']['complete_history_wire']),loads(v['complete_history_wire']);added=[x for x in current if x['version_id']==96]
    need(len(added)==1 and added[0]['is_applied']is True and len(current)==len(prior)+1 and [x for x in current if x['version_id']!=96]==prior and added[0]['id']>max(x['id']for x in prior),'SOLE96_APPEND_ALL_PRIOR95_VALUES_EXACT')
    need(s['old_records']==old['supplement']['old_records']and value['old_grants']==old['old_grants']and value['ledgers94']==old['ledgers94'],'ALL_OLD_ROWS_SDK_AND94_LEDGERS_EXACT')
    need(set(expected_functions)=={M96_FUNCTION},'ONE_REPLACED96_FUNCTION_ONLY')
    before=catalog94_projection(old);after=catalog94_projection(value);catalog96_delta(before,after,expected_functions[M96_FUNCTION]['body'],constraint96_definition(before,migration))


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
M96_BODY_SHA = 'd8cba69410381611df09c6d5c8823310be2a989026e51ab46c9885ddfc05d9f3'
M96_FUNCTION = 'retirement_forward_continuation_valid'

PRE_READ_TARGET = {'root_admission_id':'b8f529ca-43eb-4351-9ac3-a8774f90f562','failed_admission_id':'756a0af2-3ce3-4992-8fe2-116bb8da12cd','retirement_request_id':'87f9530e-0868-4538-98e7-96f241462c49','preregistration_id':'9cdb3d59-3085-4ecb-b384-49f47b2b03b4','destroy_grant_id':'c46345dc-a21f-4d7d-834b-e8e8f38b7643','failed_run_id':'ef121889-8828-4a8b-b821-873a13c15032','pending_read_id':'41de89ba-bec2-479a-87f6-cf5e4a602213','resource_id':'i-03d9ec5b7702b6ee6'}
PRE_READ_SQL = "-- Exact S8 pre-read continuation case; read-only snapshot, no authority or mutation.\n-- All reads/owners for this retirement are retained without success filtering.\nWITH f AS MATERIALIZED (\n SELECT * FROM public.capacity_guest_retirement_forwards\n WHERE retirement_request_id='87f9530e-0868-4538-98e7-96f241462c49'::uuid\n), r AS MATERIALIZED (\n SELECT * FROM public.capacity_guest_retirement_forward_reads\n WHERE retirement_request_id='87f9530e-0868-4538-98e7-96f241462c49'::uuid\n), recent_reads AS (\n SELECT * FROM r ORDER BY recorded_at DESC,id DESC,stage DESC LIMIT 6\n), bindings AS MATERIALIZED (\n SELECT * FROM public.capacity_vm_retirement_delete_bindings\n WHERE intent_id='87f9530e-0868-4538-98e7-96f241462c49'::uuid\n), last_scope_jobs AS MATERIALIZED (\n SELECT * FROM public.capacity_dispatch_jobs j\n WHERE j.realm='dakasa-production' AND j.environment='production'\n AND j.domain='notify' AND j.dimension='original_notify_aws_vm_members'\n ORDER BY j.created_at DESC,j.id DESC LIMIT 6\n), run_ids AS (\n SELECT DISTINCT CASE WHEN original_record->>'run_id' ~ '^[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}$'\n   THEN (original_record->>'run_id')::uuid ELSE NULL::uuid END id FROM f\n), runs AS MATERIALIZED (\n SELECT w.* FROM public.workflow_runs w JOIN run_ids x ON w.id=x.id\n), owner_jobs AS (\n SELECT j.* FROM public.capacity_dispatch_jobs j JOIN runs w ON w.id=j.run_id\n), snapshot(v) AS (SELECT jsonb_build_object(\n 'observed_at_pg',clock_timestamp(),\n 'selected_runtime_source','33a846d31a5b123b2c1141192671bc830bf6d9c8',\n 'target',jsonb_build_object('parent_forward_id','b8f529ca-43eb-4351-9ac3-a8774f90f562',\n   'retirement_request_id','87f9530e-0868-4538-98e7-96f241462c49',\n   'preregistration_id','9cdb3d59-3085-4ecb-b384-49f47b2b03b4','resource_id','i-03d9ec5b7702b6ee6'),\n 'current_intent',(SELECT to_jsonb(i) FROM public.capacity_intents i WHERE i.namespace='dakasa-production'\n   AND i.environment='production' AND i.domain='notify' AND i.dimension='original_notify_aws_vm_members'),\n 'current_intent_pgtext',(SELECT i.intent::text FROM public.capacity_intents i WHERE i.namespace='dakasa-production'\n   AND i.environment='production' AND i.domain='notify' AND i.dimension='original_notify_aws_vm_members'),\n 'active_policies',(SELECT COALESCE(jsonb_agg(jsonb_build_object('id',p.id,'version',p.version,'checksum',p.checksum,'spec',p.spec) ORDER BY p.version),'[]'::jsonb)\n   FROM public.manifests p WHERE p.kind='capacity_policy' AND p.namespace='dakasa-production'\n   AND p.name='notify-aws-elastic-capacity' AND p.active),\n 'forward_rows',(SELECT COALESCE(jsonb_agg(to_jsonb(x)||jsonb_build_object('wire_hex',encode(x.original_wire,'hex')) ORDER BY x.recorded_at,x.id,x.stage),'[]'::jsonb) FROM f x),\n 'retirement_contexts',(SELECT COALESCE(jsonb_agg(to_jsonb(x)),'[]'::jsonb)\n   FROM public.capacity_guest_original_retirement_contexts x WHERE x.intent_id='87f9530e-0868-4538-98e7-96f241462c49'::uuid),\n 'delete_bindings',(SELECT COALESCE(jsonb_agg(to_jsonb(x)||jsonb_build_object('wire_hex',encode(x.original_wire,'hex'))),'[]'::jsonb) FROM bindings x),\n 'destroy_grants',(SELECT COALESCE(jsonb_agg(to_jsonb(g)||jsonb_build_object('grant_pgtext',g.grant_record::text) ORDER BY g.id),'[]'::jsonb)\n   FROM public.capacity_mutation_grants g JOIN bindings b ON b.destroy_grant_id=g.id),\n 'read_counts',(SELECT COALESCE(jsonb_agg(to_jsonb(x) ORDER BY x.kind,x.stage),'[]'::jsonb)\n   FROM(SELECT kind,stage,count(*) rows,min(recorded_at) first_at,max(recorded_at) last_at FROM r GROUP BY kind,stage)x),\n 'own_read_count',(SELECT count(*) FROM r WHERE admission_id='756a0af2-3ce3-4992-8fe2-116bb8da12cd'::uuid),\n 'all_read_rows',(SELECT COALESCE(jsonb_agg(to_jsonb(x)||jsonb_build_object('wire_hex',encode(x.original_wire,'hex')) ORDER BY x.recorded_at,x.id,x.stage),'[]'::jsonb) FROM r x),\n 'unreturned_prepared',(SELECT COALESCE(jsonb_agg(to_jsonb(p)||jsonb_build_object('wire_hex',encode(p.original_wire,'hex')) ORDER BY p.recorded_at,p.id),'[]'::jsonb)\n   FROM r p WHERE p.stage='prepared' AND NOT EXISTS(SELECT 1 FROM r v WHERE v.id=p.id AND v.stage='returned')),\n 'latest_reads_all_outcomes',(SELECT COALESCE(jsonb_agg(to_jsonb(x)||jsonb_build_object('wire_hex',encode(x.original_wire,'hex')) ORDER BY x.recorded_at,x.id,x.stage),'[]'::jsonb) FROM recent_reads x),\n 'workflow_runs',(SELECT COALESCE(jsonb_agg(to_jsonb(w)||jsonb_build_object('run_wire',row_to_json(w)::text) ORDER BY w.id),'[]'::jsonb) FROM runs w),\n 'workflow_run_steps',(SELECT COALESCE(jsonb_agg(jsonb_build_object('run_id',w.id,'status',w.status,'finished_at',w.finished_at,'steps',w.result->'steps') ORDER BY w.id),'[]'::jsonb) FROM runs w),\n 'owning_dispatch_jobs',(SELECT COALESCE(jsonb_agg(to_jsonb(j)||jsonb_build_object('dispatch_wire',to_jsonb(j)::text) ORDER BY j.created_at,j.id),'[]'::jsonb) FROM owner_jobs j))) SELECT jsonb_build_object('observed_at_pg',clock_timestamp(),'records',(v-'observed_at_pg'),'records_wire',(v-'observed_at_pg')::text,'records_sha256',encode(sha256(convert_to((v-'observed_at_pg')::text,'UTF8')),'hex')) FROM snapshot"

def pre_read_wire(row, field='record_sha256'):
    raw=row['wire_hex'];need(type(raw)is str and re.fullmatch('(?:[0-9a-f]{2})+',raw),'EXACT_RETIREMENT_ORIGINAL_HEX')
    b=bytes.fromhex(raw);need(sha(b)==row[field] and loads(b)==row['original_record'],'EXACT_RETIREMENT_RAW_WIRE_SHA_RECORD');return b

def validate_pre_read96(v, case):
    """Closed known failed read-only S8 owner; this proves no absence or new authority."""
    closed(v,'observed_at_pg records records_wire records_sha256','CLOSED_S8_PRE_READ_SNAPSHOT')
    closed(case,'retirement_request_id failed_admission_id root_admission_id destroy_grant_id expected_records_sha256 provider_lanes','CLOSED_S8_ROOT_OPERANDS')
    for k in ('retirement_request_id','failed_admission_id','root_admission_id','destroy_grant_id'):need(case[k]==PRE_READ_TARGET[k],'EXACT_KNOWN_S8_'+k.upper())
    r=v['records'];need(type(v['records_wire'])is str and loads(v['records_wire'])==r and sha(v['records_wire'].encode())==v['records_sha256']==case['expected_records_sha256'],'WHOLE_PG_SNAPSHOT_WIRE_NOT_REENCODED')
    closed(r,'selected_runtime_source target current_intent current_intent_pgtext active_policies forward_rows retirement_contexts delete_bindings destroy_grants read_counts own_read_count all_read_rows unreturned_prepared latest_reads_all_outcomes workflow_runs workflow_run_steps owning_dispatch_jobs','CLOSED_COMPLETE_S8_RECORD_SET')
    need(r['selected_runtime_source']=='33a846d31a5b123b2c1141192671bc830bf6d9c8' and r['target']=={'parent_forward_id':PRE_READ_TARGET['root_admission_id'],'retirement_request_id':PRE_READ_TARGET['retirement_request_id'],'preregistration_id':PRE_READ_TARGET['preregistration_id'],'resource_id':PRE_READ_TARGET['resource_id']},'SOURCE_R5_AND_IMMUTABLE_S8_TARGET')
    need(type(r['own_read_count'])is int and r['own_read_count']==0 and r['unreturned_prepared']==[] and type(r['all_read_rows'])is list and r['all_read_rows'],'ZERO_ANY_OWN_READ_NOT_LAST_SUCCESS_FILTER')
    rows=r['forward_rows'];need(type(rows)is list and len(rows)==4,'COMPLETE_CURRENT_TWO_FORWARD_FRAMES')
    for row in rows:pre_read_wire(row)
    def one(ident,stage):
        x=[a for a in rows if a['id']==ident and a['stage']==stage];need(len(x)==1,'ONE_EXACT_FORWARD_STAGE');return x[0]
    parent=one(PRE_READ_TARGET['failed_admission_id'],'admitted');requested=one(parent['id'],'requested');anchor=one(PRE_READ_TARGET['root_admission_id'],'admitted');root_off=one(anchor['id'],'off_qualified')
    p,q,a=parent['original_record'],requested['original_record'],anchor['original_record'];proof=p['continuation']
    closed(proof,'schema requesting_run_id failed_run_id failed_run_sha256 dispatch_id dispatch_sha256 destroy_grant_sha256 delete_eligibility_sha256 pending_read_id pending_read_sha256','CLOSED_RETAINED_CLASSIC_PROOF10')
    need(p['mode']==q['mode']=='settled_absence_continuation' and p['stage']=='admitted' and q['stage']=='requested' and p['id']==q['id']==parent['id'] and p['root_admission_id']==q['root_admission_id']==anchor['id'] and p['parent_admission_id']==q['parent_admission_id']==root_off['id'] and p['parent_admission_sha256']==q['parent_admission_sha256']==root_off['record_sha256'] and proof==q['continuation'] and proof['schema']=='original_settled_absence_continuation_v1' and proof['pending_read_id']==PRE_READ_TARGET['pending_read_id'] and p['destroy_grant_id']==q['destroy_grant_id']==PRE_READ_TARGET['destroy_grant_id'] and p['run_id']==proof['requesting_run_id']==PRE_READ_TARGET['failed_run_id'] and q['run_id']=='','SAME_RETAINED_CLASSIC_REQUEST_AND_CURRENT_FAILED_OWNER')
    for k in ('root_admission_id','retirement_request_id','preregistration_id','prefix_sha256','original_caller_sha256','evidence','original'):
        need(p[k]==q[k]==a[k],'IMMUTABLE_ROOT_PREFIX_TUPLE_EVIDENCE_'+k.upper())
    need({k:x for k,x in p.items()if k not in ('stage','recorded_at','fence','lease_owner','executor_id','run_id')}=={k:x for k,x in q.items()if k not in ('stage','recorded_at','fence','lease_owner','executor_id','run_id')} and p['fence']==q['fence']+1 and utc(q['recorded_at'])<=utc(p['recorded_at']),'GENUINE_NEW_FENCE_WITHOUT_OLD_RECORD_REWRITE')
    current=r['current_intent']['intent'];need(loads(r['current_intent_pgtext'])==current and current['retirement_forward']['id']==parent['id'] and current['retirement_forward']['stage']=='admitted' and current['retirement_forward']['mode']=='settled_absence_continuation' and current['generation']==p['generation'] and current['fencing_token']==p['fence'] and current['lease_owner']==p['lease_owner'] and current['lease_executor_id']==p['executor_id'] and utc(current['lease_expires_at'])<=utc(v['observed_at_pg']) and current['phase']=='drained','EXACT_EXPIRED_CURRENT_FENCED_OWNER_NO_LEASE_EXTENSION')
    need(len(r['active_policies'])==1 and r['active_policies'][0]['id']==current['policy_id'] and r['active_policies'][0]['checksum']==current['policy_checksum'],'CURRENT_SINGLE_POLICY_NO_OLD_TRIAL_ALIAS')
    for row in r['all_read_rows']:pre_read_wire(row)
    need(not any(x['admission_id']==parent['id'] for x in r['all_read_rows']),'NO_PREPARED_OR_RETURNED_OF_ANY_KIND_FOR_FAILED_OWNER')
    returned=[x for x in r['all_read_rows']if x['stage']=='returned'];need(returned,'ACTUAL_HISTORICAL_PENDING_REQUIRED');last=max(returned,key=lambda x:(utc(x['recorded_at']),x['id']))
    need(last['id']==proof['pending_read_id'] and last['record_sha256']==proof['pending_read_sha256'] and last['admission_id']==anchor['id'] and last['kind']=='absence','LATEST_ALL_OUTCOMES_IS_INHERITED_PENDING_NOT_IGNORED_RAW')
    prepared=[x for x in r['all_read_rows']if x['id']==last['id']and x['stage']=='prepared'];need(len(prepared)==1,'ONE_ACTUAL_PENDING_CHALLENGE');prepared=prepared[0];ret=last['original_record'];rd=ret['read']
    need(rd==prepared['original_record'] and rd['admission_id']==anchor['id'] and rd['admission_sha256']==anchor['record_sha256'] and rd['destroy_grant_id']==p['destroy_grant_id'] and rd['retirement_request_id']==p['retirement_request_id'] and rd['prefix_sha256']==p['prefix_sha256'] and rd['original_caller_sha256']==p['original_caller_sha256'] and rd['tuple']==p['original']['Request']['intent']['tuple'] and ret['status']=='observed' and ret['call_failed']is False and ret['original_context_failed']is False and 'plan'not in ret,'SAME_TIMELY_OBSERVED_ANCESTOR_PENDING_NOT_CURRENT_ABSENCE')
    need(utc(rd['issued_at_core'])<=utc(ret['started_at_core'])<=utc(ret['original_returned_at_core'])<utc(rd['original_deadline_core']) and (utc(rd['original_deadline_core'])-utc(rd['issued_at_core'])).total_seconds()<=5 and utc(anchor['recorded_at'])<=utc(last['recorded_at'])<utc(parent['recorded_at']),'HISTORICAL_ORIGINAL_FIVE_SECOND_READ_CLOCK_NOT_RETIMED')
    need(len(r['destroy_grants'])==len(r['delete_bindings'])==1,'ONE_ORIGINAL_PAID_DESTROY_BINDING');g=r['destroy_grants'][0];b=r['delete_bindings'][0];record=g['grant_record'];grant=record['grant'];settlement=record['settlement']
    need(g['id']==grant['grant_id']==b['destroy_grant_id']==p['destroy_grant_id'] and g['state']==grant['state']=='settled' and all(g[k]is None for k in ('original_disposition_id','failed_original_disposition_id','native_denied_disposition_id','enrolled_failed_disposition_id','failed_unwitnessed_expansion_cleanup_id')) and sha(g['grant_pgtext'].encode())==proof['destroy_grant_sha256'] and loads(g['grant_pgtext'])==record and grant.get('compensation_of','')=='' and settlement['outcome']=='accepted' and settlement['transport_completed']is True and settlement['auxiliary_inventory_complete']is True and len(settlement['auxiliary_resources'])==2,'SAME_SETTLED_PAID_AUX2_NO_NEW_DELETE')
    raw=bytes.fromhex(b['wire_hex']);need(sha(raw)==b['eligibility_sha256']==proof['delete_eligibility_sha256'] and loads(raw)==b['original_eligibility_record'] and b['intent_id']==p['retirement_request_id'],'WHOLE_ORIGINAL_DELETE_ELIGIBILITY_WIRE')
    receipt=ret['original_destroy_receipt'];need(receipt['grant']==grant and receipt['attempt_id']==record['attempt_id'] and all(receipt[k]==settlement[k]for k in ('outcome','transport_completed','action_id','resource_id','resource_created_at','auxiliary_resources','auxiliary_inventory_complete')) and receipt['resource_id']==grant['expected_resource_id']==PRE_READ_TARGET['resource_id'] and receipt['resource_created_at']==grant['expected_resource_created_at'],'SAME_ORIGINAL_RECEIPT_GRANT_ATTEMPT_ACTION_BIRTH')
    sdk=settlement.get('original_provider_destroy_return');need(type(sdk)is dict and sdk['schema']=='aws_original_terminate_instances_return_v1'and sdk['provider']=='aws'and sdk['adapter_source_commit']=='c34e330d8b266bb88e29ae7cf7b01df6f9fd96ce'and type(sdk['response_status'])is int and sdk['response_status']==200 and sdk['grant_id']==g['id'] and sdk['attempt_id']==record['attempt_id'] and sdk['action_id']==settlement['action_id'] and sdk['request_sha256']==settlement['request_sha256']==grant['request_sha256'] and sdk['resource_id']==receipt['resource_id'] and sdk['resource_created_at']==receipt['resource_created_at'] and sdk.get('next_action_ids',[])==[] and utc(sdk['called_at'])<=utc(sdk['returned_at'])<utc(sdk['context_deadline'])<=utc(grant['expires_at']),'ACTUAL_IMMUTABLE_C34_TERMINATE200_WITH_ORIGINAL_CLOCK')
    observer=loads(base64.b64decode(ret['original_observer_return'],validate=True));closed(observer,'schema observer_source_commit original_adapter_source_commit read_id read_sha256 original_receipt_sha256 observation','CLOSED_GENUINE_H7_WRAPPER')
    need(observer['schema']=='original_settled_retirement_absence_read_return_v1' and observer['observer_source_commit']==ret['observer_source_commit']=='d8cbbf48873d24439216f98c30afe2669a525b54' and observer['original_adapter_source_commit']==rd['adapter_source_commit']=='c34e330d8b266bb88e29ae7cf7b01df6f9fd96ce' and observer['read_id']==rd['read_id']==prepared['id'] and observer['read_sha256']==prepared['record_sha256'] and observer['original_receipt_sha256']==sha(raw_json_member(bytes.fromhex(last['wire_hex']),'original_destroy_receipt')) and observer['observation']==ret['observation'],'EXACT_H7_ORIGINAL_CHALLENGE_AND_GO_RECEIPT_TOKEN_SHA')
    o=ret['observation'];need(o['destroy_grant_id']==g['id']and o['destroy_grant_state']=='settled'and o['id']==receipt['resource_id']and o['created_at']==receipt['resource_created_at']and o['original_outcome']=='accepted'and o['original_transport_completed']is True and o['auxiliary_inventory_complete']is True and o['billable_resources_absent']is False and o['retirement_complete']is False and not o.get('writer_quiescence_evidence',False)and not o.get('provider_fencing_evidence',False)and not o.get('invoice_reconciled',False)and 'billing_exposure'not in o and o.get('compensation_of','')=='','GENUINE_PENDING_NOT_COMPLETION_OR_AUTHORITY')
    lifecycle=o['aws_retirement_lifecycle'];state=lifecycle['ec2_state'];absent=state in ('terminated','not_found');need(lifecycle['schema']=='aws_original_terminate_and_native_absence_v1'and lifecycle['request_id']==receipt['action_id']and state in ('pending','running','stopping','stopped','shutting-down','terminated','not_found')and o['server_absent']is absent and o['server_absence_complete']is absent and (o.get('server_status','')==''if absent else o['server_status']==state)and o['next_actions']==[]and o.get('delete_action',{})in ({},{'known':False,'observed':False})and len(o['auxiliary_resources'])==2 and 1<=len(o['hold_reasons'])<=3 and len(set(o['hold_reasons']))==len(o['hold_reasons']),'EXACT_AWS_PENDING_LIFECYCLE_FULL_AUX_INVENTORY')
    holds=set(o['hold_reasons']);need(holds<=set(('instance_not_terminated','aws_ebs_volume_still_present','aws_network_interface_still_present')) and ('instance_not_terminated'in holds)!=absent,'NO_FAVORABLE_PENDING_HOLD_SUFFIX')
    for aux,paid in zip(o['auxiliary_resources'],receipt['auxiliary_resources']):need(aux['kind']==paid['kind']and aux['id']==paid['id']and type(aux['absent'])is bool and ((aux['kind']+'_still_present')in holds)!=aux['absent'],'EXACT_PAID_AUX_ID_AND_PENDING_STATUS')
    runs=r['workflow_runs'];jobs=r['owning_dispatch_jobs'];own=[w for w in runs if w['id']==p['run_id']];need(len(own)==1,'ONE_CURRENT_FAILED_RUN');w=own[0];j=[j for j in jobs if j['run_id']==w['id']];need(len(j)==1,'ONE_CURRENT_FAILED_DISPATCH');j=j[0]
    need(w['status']==j['return_status']=='failed'and j['state']=='returned'and utc(w['finished_at'])==utc(j['returned_at'])<=utc(j['finalization_ack_at'])<=utc(v['observed_at_pg'])and loads(w['run_wire'])=={k:x for k,x in w.items()if k!='run_wire'}and loads(j['dispatch_wire'])=={k:x for k,x in j.items()if k!='dispatch_wire'},'GENUINE_FAILED_SOURCE_RUN_ONE_FINAL_ACK_NO_UNKNOWN')
    env=loads(j['envelope']);need(env['workflow']['id']==p['original']['Request']['intent']['workflow_id']and w['metadata']['capacity_dispatch_job_id']==j['id']and w['metadata']['triggered_by']=='workflow_scheduler','ACTUAL_SCHEDULER_ENVELOPE_AND_OWNING_JOB')
    steps=w['result']['steps'];need(w['result']['status']=='failed'and len(steps)==7 and len({x['id']for x in steps})==7,'WHOLE_CLOSED_FAILED_SEVEN_STEP_RESULT');steps={x['id']:x for x in steps}
    need(steps['plan-original-guest']['status']=='succeeded'and steps['plan-original-guest']['metadata']['generation']==p['generation']and steps['plan-original-guest']['metadata']['fencing_token']==p['fence']and steps['plan-original-guest']['metadata']['lease_owner']==p['lease_owner']and steps['retire-original-guest']['status']=='succeeded'and steps['retire-original-guest']['metadata']['retirement_forward_id']==p['id']and steps['retire-original-guest']['metadata']['request_id']==p['retirement_request_id']and steps['finish-original-retirement']['status']=='failed'and all(steps[k]['status']=='skipped'for k in ('provision-original-notify','complete-original-provision','refresh-original-membership','complete-original-retirement')),'FAILED_PRE_READ_OWNER_FULL_ORDINARY_WORKFLOW_NO_REPLAY')
    historical=[x for x in runs if x['id']==proof['failed_run_id']];need(len(historical)==1 and historical[0]['id']==a['run_id'],'ONE_ORIGINAL_ANCESTOR_FAILED_RUN');historical=historical[0]
    oldjob=[x for x in jobs if x['id']==proof['dispatch_id']and x['run_id']==historical['id']];need(len(oldjob)==1,'ONE_ORIGINAL_ANCESTOR_ACK');oldjob=oldjob[0]
    failed_raw=base64.b64decode(q['failed_run'],validate=True)
    need(sha(failed_raw)==proof['failed_run_sha256']==sha(historical['run_wire'].encode()) and loads(failed_raw)==loads(historical['run_wire']) and sha(oldjob['dispatch_wire'].encode())==proof['dispatch_sha256'] and historical['status']==oldjob['return_status']=='failed'and oldjob['state']=='returned'and utc(historical['finished_at'])==utc(oldjob['returned_at'])<=utc(oldjob['finalization_ack_at'])<=utc(q['recorded_at'])and utc(ret['original_returned_at_core'])<=utc(oldjob['returned_at']),'HISTORICAL_PENDING_FAILED_RUN_AND_ACK_RAW_BYTES_NOT_NEW_AUTHORITY')
    eligibility=b['original_eligibility_record'];need(eligibility['schema']=='original_guest_partial_poweroff_delete_eligibility_v1'and eligibility['admission_id']==anchor['id']and eligibility['admission_sha256']==anchor['record_sha256']and g['generation']==record['generation']==a['generation']and record['fencing_token']==a['fence']and record['lease_owner']==a['lease_owner']and record['executor_id']==a['executor_id'],'ORIGINAL_PAID_DELETE_BOUND_TO_ACTUAL_ANCESTOR_EPOCH')
    return True

# INERT PURE SOURCE FRAGMENT. Closure: copy, need, sha; parent Source gate/refs remain unbound.
# expected96_check_definition is a SOURCE/data binding of the exact pg_get_constraintdef
# rendering from the complete pinned PG16 CI artifact; no result is invented here.
def catalog96_delta(prior95, actual96, source96_body, expected96_check_definition):
    need(type(expected96_check_definition)is str and expected96_check_definition and type(source96_body)is str,'BOUND_EXACT_M96_SOURCE_AND_CONSTRAINT_DEFINITION')
    need(set(prior95)==set(actual96)=={'catalog90','catalog91','columns90_91','functions93','index92_definition','index92_valid','schema94'},'SAME_COMPLETE_SEVEN_KEY_CATALOG_ABI')
    need(sha(source96_body.encode())=='d8cba69410381611df09c6d5c8823310be2a989026e51ab46c9885ddfc05d9f3','EXACT_PINNED_M96_UP_PROSRC')
    expected=copy.deepcopy(prior95)
    old=[x for x in expected['functions93']if x['name']=='retirement_forward_continuation_valid']; new=[x for x in actual96['functions93']if x['name']=='retirement_forward_continuation_valid']
    need(len(old)==len(new)==1 and all(old[0][k]==new[0][k]for k in ('name','arguments','result','language','volatility','config')),'ONE96_FUNCTION_HEADER_UNCHANGED')
    need(old[0]['body'] and old[0]['definition'].count(old[0]['body'])==1 and new[0]['body']==source96_body,'WHOLE96_SOURCE_PROSRC')
    old[0]['definition']=old[0]['definition'].replace(old[0]['body'],source96_body,1);old[0]['body']=source96_body
    before=[x for x in expected['catalog90']['constraints']if x['table']=='capacity_guest_retirement_forwards'and x['name']=='retirement_forward_continuation93'];after=[x for x in actual96['catalog90']['constraints']if x['table']=='capacity_guest_retirement_forwards'and x['name']=='retirement_forward_continuation96']
    need(len(before)==len(after)==1 and before[0]['validated']is True and after[0]['validated']is True and set(before[0])==set(after[0]) and {k:v for k,v in before[0].items()if k not in ('name','definition')}=={k:v for k,v in after[0].items()if k not in ('name','definition')} and after[0]['definition']==expected96_check_definition,'ONLY_EXACT96_PROOF_CONSTRAINT_REPLACEMENT')
    before[0]['name']='retirement_forward_continuation96';before[0]['definition']=expected96_check_definition
    need(expected==actual96,'ALL_OTHER_TABLE_COLUMN_CONSTRAINT_INDEX_TRIGGER_FUNCTION_BYTES_EXACT95')
    return actual96

def constraint96_definition(prior95, artifact):
    rows=[x for x in prior95['catalog90']['constraints']if x['table']=='capacity_guest_retirement_forwards'and x['name']=='retirement_forward_continuation93']
    need(len(rows)==1 and rows[0]['validated']is True,'ONE_ORIGINAL93_PROOF_CHECK')
    closed(artifact,'schema migration93_sha256 migration96_sha256 before_definition after scope Native_or_Job_qualification','CLOSED_ACTUAL_PG16_CI_CHECK_DEPARSE')
    actual=artifact['after'];closed(actual,'server_version server_version_num database definition validated old_constraint_rows','CLOSED_ACTUAL_PG16_CHECK96')
    need(artifact['schema']=='declared_M96_PG16_exact_Source_CHECK_deparse_v1'and artifact['migration93_sha256']=='cc2b2843d14d4183ea68d25dbb9b9b58d1a353044e6ebf46ece6b93778e937e9'and artifact['migration96_sha256']==M96 and artifact['before_definition']==rows[0]['definition']and artifact['scope']=='disposable minimum table CHECK only'and artifact['Native_or_Job_qualification']is False,'EXACT_SOURCE93_96_AND_PRIOR95_CHECK_NOT_NATIVE_QUALIFICATION')
    need(type(actual['server_version_num'])is int and 160000<=actual['server_version_num']<170000 and type(actual['server_version'])is str and actual['server_version']and type(actual['database'])is str and re.fullmatch('goose96_deparse_[0-9a-f]{32}',actual['database'])and actual['validated']is True and type(actual['old_constraint_rows'])is int and actual['old_constraint_rows']==0 and type(actual['definition'])is str and actual['definition'].startswith('CHECK (')and actual['definition']!=rows[0]['definition'],'ACTUAL_PG16_CI_CHECK96_DEPARSE_DATA_NOT_GUESSED')
    return actual['definition']

if __name__=="__main__":main()
