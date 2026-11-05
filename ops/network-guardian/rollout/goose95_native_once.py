#!/usr/bin/env python3
"""Inert one-Job Goose95 failed unwitnessed expansion maintenance. No Core adoption or provider/Guest action.

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
COMPANION_SOURCE_Q = '33a846d31a5b123b2c1141192671bc830bf6d9c8'
COMPANION_IMAGE_D = '35195e4ddff2a69f2ae7fca8f24b43177c61c49f12117a4fe4925a43e9cd6fde'
COMPANION_IMAGE_PROOF_SHA256 = None
SOURCE_CI_GATE_SHA256 = '5d316c4e6d588d82b436d0e6c6d7d012490ba46e3c69bf1d06c3765a0167a2fc'
CAS_SOURCE_SHA256 = None
RUNTIME_MANIFEST_SHA256 = None
G14_RETURN_SHA256 = None
BASELINE94_ACCEPTANCE_SHA256 = '3ad88f1ada8cc96db0d6c6b0c3844a4de070e18f458cd6b053ab3a468b90c5e4'
CLEANUP_PREIMAGE_SHA256 = None
CONFIG_SHA256 = None
JOB_UUID = None
JOB_MANIFEST_SHA256 = None
EXPECTED_RUNS = 18
EXPECTED_JOBS = 41
EXPECTED_CHECKS = frozenset([(127142692301, 'source-contracts', 'completed', 'success'), (127142692495, 'guest-pg-public-auth', 'completed', 'success'), (127142692579, 'native-cli-build', 'completed', 'success'), (127142692651, 'host-factory-source-pg', 'completed', 'success'), (127142692661, 'original-provider-source', 'completed', 'success'), (127142692727, 'svc-doctor', 'completed', 'success'), (127142692741, 'original-http-transport', 'completed', 'success'), (127142714223, 'Analyze (javascript-typescript)', 'completed', 'success'), (127142714650, 'Analyze (go)', 'completed', 'success'), (127142714676, 'Analyze (python)', 'completed', 'success'), (127142714691, 'Analyze (actions)', 'completed', 'success'), (127142725642, 'closed-administrative-boundary', 'completed', 'success'), (127142725991, 'capacity-owned-http', 'completed', 'success'), (127142726332, 'original-provider-source', 'completed', 'success'), (127142726458, 'signed-postgres-recovery', 'completed', 'success'), (127142726482, 'retirement-forward (17)', 'completed', 'success'), (127142726502, 'focused-linux', 'completed', 'success'), (127142726563, 'addons-smoke', 'completed', 'success'), (127142726570, 'synthetic-resume-transaction', 'completed', 'success'), (127142726603, 'native-oidc-postgres', 'completed', 'success'), (127142726694, 'source-contracts', 'completed', 'success'), (127142726706, 'guest-pg-public-auth', 'completed', 'success'), (127142726707, 'original-http-transport', 'completed', 'success'), (127142726718, 'host-factory-source-pg', 'completed', 'success'), (127142726765, 'native-cli-build', 'completed', 'success'), (127142726803, 'capacity-postgres', 'completed', 'success'), (127142726870, 'bounded-source-and-history (17)', 'completed', 'success'), (127142726881, 'retirement-forward (16)', 'completed', 'success'), (127142726914, 'unit-tests', 'completed', 'success'), (127142726916, 'gate-regression', 'completed', 'success'), (127142726966, 'Scheduler skip Source kernel (PostgreSQL 17)', 'completed', 'success'), (127142727006, 'native-core-kind', 'completed', 'success'), (127142727042, 'HTTP maintenance disposition (PostgreSQL 17)', 'completed', 'success'), (127142727077, 'bounded-source-and-history (16)', 'completed', 'success'), (127142727084, 'HTTP maintenance disposition (PostgreSQL 16)', 'completed', 'success'), (127142727117, 'Scheduler skip Source kernel (PostgreSQL 16)', 'completed', 'success'), (127142727201, 'lint', 'completed', 'success'), (127142727220, 'focused-linux', 'completed', 'success'), (127142727414, 'svc-doctor', 'completed', 'success'), (127142727478, 'reconcile', 'completed', 'success'), (127142728909, 'focused-linux', 'completed', 'success'), (127143013927, 'CodeQL', 'completed', 'success')])
EXPECTED_EXTRA_CHECKS = frozenset([(127143013927, 'CodeQL', 'completed', 'success')])
REQUIRED_CI = frozenset([('Capacity intent PostgreSQL protocol', 'pull_request'), ('Capacity source-owned HTTP qualification', 'pull_request'), ('Docs freshness', 'pull_request'), ('Failed installed Guest administrative HTTP Source', 'pull_request'), ('Failed serving Guest Source and PostgreSQL', 'pull_request'), ('Guest historical unknown read recovery', 'pull_request'), ('Installed Guest reconciliation Source', 'pull_request'), ('Native OIDC protocol integration', 'pull_request'), ('Original Guest Core source and PostgreSQL gates', 'pull_request'), ('Original Guest Core source and PostgreSQL gates', 'push'), ('Original and native denied disposition Source', 'pull_request'), ('PR #142', 'dynamic'), ('Partial Guest native OFF reconciliation Source', 'pull_request'), ('Protected native capacity API qualification', 'pull_request'), ('Recorded HTTP maintenance disposition Source and PostgreSQL', 'pull_request'), ('Service contract', 'pull_request'), ('Service contract', 'push'), ('template-go-api CI', 'pull_request')])
CURRENT_OPS_P = None
PREDECESSOR_G13_OPS = '75db7941ec9f6b714d785a8a9cd7ae0158ca34a7'
PREDECESSOR_G13_MANIFEST = '8c96b10f94a52c615f058f5ab688b56e1fcabacfd374b6c1fc4e0acad1b8ad0a'
PREDECESSOR_G13_SOURCE = 'f5f0e218f774deefe909e884988d845be93d8c746fc5047820f68759852e7d9f'
PREDECESSOR_G13_CONFIG = '2fafe364344596ec0ab4a87a1887c8a4bcc581b103937fedb807e624fc3e6ac0'
CURRENT_CORE_R = '7cd5cea0834bcee901c282bc81b9486d5c16513b'
CURRENT_CORE_D = 'd8a86c844f0b2df14aa3ae3b0281f43be14a7f6aed3b1bf962816a603e966a1b'
CURRENT_CORE_CONFIG = 'b9c30840baa7a965df9ead416ec1613ec55c4972dab51a8e8f19a7b211768179'
GUARDIAN_S = None
M94 = '2850db98eddbfd629b98df879eb61266036d70210118e8e20289782d2b37a78c'  # Frozen Source only; no migration qualification.
M93 = 'cc2b2843d14d4183ea68d25dbb9b9b58d1a353044e6ebf46ece6b93778e937e9'
LEGACY_CATALOG_SHA = 'c9d3664e43ef876a9a7a89c031bf75f761dbb0c70a664db2408058a6ce2431eb'
TRANSPORT_SHA = '9e2f8fe524331c9ea1c2f5742588977abe47d99b6ff635e88e431f343b96c004'
E70_SHA = 'e70f1bfc0821be5eaf44ec2248656da06ff269cfa57079ff487ae74f4cfe1054'
ROOT = Path('/var/lib/dakasa-core-rollout/goose95-failed-expansion-read-continuation')
CLAIM = ROOT / 'GOOSE95-POSSIBLE-CREATE.json'
JOB_URI = '/apis/batch/v1/namespaces/dakasa/jobs'
DEP_URI = '/apis/apps/v1/namespaces/dakasa/deployments/yggdrasil'
RS_URI = '/apis/apps/v1/namespaces/dakasa/replicasets/yggdrasil-7bd787488d'
CURRENT_RS_UID = '9327ba57-bb88-4855-b4cf-c77e874ba42f'
CORE_PODS_URI = '/api/v1/namespaces/dakasa/pods?labelSelector=app%3Dyggdrasil'
PREFIX = '153828470928.dkr.ecr.us-east-1.amazonaws.com/ghcr/dakasa-yggdrasil/yggdrasil-core@sha256:'
APP = 'yggdrasil-goose95-companion'
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
CLEANUP_SQL = "WITH a AS (SELECT * FROM public.capacity_failed_unwitnessed_expansion_cleanups WHERE grant_id='c117f03f-27db-4da2-b990-c2729f98a46f'::uuid),\n ev AS (SELECT e.* FROM public.capacity_failed_unwitnessed_expansion_cleanup_events e JOIN a ON e.cleanup_id=a.id)\nSELECT jsonb_build_object('observed_at_pg',clock_timestamp(),\n 'admissions',(SELECT COALESCE(jsonb_agg(to_jsonb(x)||jsonb_build_object('wire_hex',encode(x.original_wire,'hex')) ORDER BY x.id),'[]'::jsonb) FROM a x),\n 'events',(SELECT COALESCE(jsonb_agg(to_jsonb(x)||jsonb_build_object('wire_hex',encode(x.original_wire,'hex')) ORDER BY x.sequence),'[]'::jsonb) FROM ev x),\n 'intent',(SELECT to_jsonb(i) FROM public.capacity_intents i WHERE namespace='dakasa-production' AND environment='production' AND domain='notify' AND dimension='original_notify_aws_vm_members'),\n 'parent',(SELECT to_jsonb(g) FROM public.capacity_mutation_grants g WHERE id='c117f03f-27db-4da2-b990-c2729f98a46f'::uuid),\n 'parent_sdk_pgtext',(SELECT (grant_record#>'{settlement,original_provider_create_return}')::text FROM public.capacity_mutation_grants WHERE id='c117f03f-27db-4da2-b990-c2729f98a46f'::uuid),\n 'child',(SELECT to_jsonb(g) FROM public.capacity_mutation_grants g JOIN a ON g.id=a.child_grant_id),\n 'workflow_run',(SELECT to_jsonb(w) FROM public.workflow_runs w WHERE id='6c23f323-f607-4015-9564-f676e8bc5d9d'::uuid),\n 'dispatch',(SELECT COALESCE(jsonb_agg(to_jsonb(j) ORDER BY j.id),'[]'::jsonb) FROM public.capacity_dispatch_jobs j WHERE run_id='6c23f323-f607-4015-9564-f676e8bc5d9d'::uuid))"
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

def load_definitions(ref, pin, name):
    need(ref['sha256'] == pin, 'EXACT_REVIEWED_SOURCE_PIN')
    raw = reference(ref)
    module = types.ModuleType(name)
    module.__file__ = ref['path']
    exec(compile(raw, ref['path'], 'exec'), module.__dict__)
    return module

def require_bound():
    pins = (M95, M94, COMPANION_IMAGE_D, COMPANION_IMAGE_PROOF_SHA256, SOURCE_CI_GATE_SHA256,
            CAS_SOURCE_SHA256, RUNTIME_MANIFEST_SHA256, G14_RETURN_SHA256,
            BASELINE94_ACCEPTANCE_SHA256, CLEANUP_PREIMAGE_SHA256, CONFIG_SHA256, JOB_MANIFEST_SHA256)
    need(SOURCE_BOUND is True and source(COMPANION_SOURCE_Q) and all(digest(v) for v in pins)
         and source(CURRENT_OPS_P) and digest(GUARDIAN_S)
         and COMPANION_SOURCE_Q not in (CURRENT_CORE_R, CURRENT_OPS_P)
         and COMPANION_IMAGE_D != CURRENT_CORE_D
         and type(RS_URI) is str and RS_URI.startswith('/apis/apps/v1/namespaces/dakasa/replicasets/')
         and type(CURRENT_RS_UID) is str
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
    return 'core-goose95-' + uuid.UUID(JOB_UUID).hex

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
    need(not CLAIM.exists(), 'GLOBAL_GOOSE94_CLAIM_ABSENT_NEVER_REPLAY')
    body = wire(job)
    need(sha(body) == JOB_MANIFEST_SHA256, 'EXACT_ROOT_REVIEWED_JOB_BODY')
    need(api.get(JOB_URI + '/' + job_name(), absent=True) is None, 'NEW_UNIQUE_UUID_JOB_ABSENT')
    marker = {'schema': 'goose95_companion_job_possible_v1', 'source_Q': COMPANION_SOURCE_Q,
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
         and b'00095_failed_expansion_read_failure_continuation.sql' in logs
         and b'successfully migrated database to version: 95' in logs, 'ORIGINAL_GOOSE95_LOG_COMPLETE_EXIT0')
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
         and roster['source'] == COMPANION_SOURCE_Q and len(roster['files']) == 94
         and sorted(r['version'] for r in roster['files'].values()) == [v for v in range(1, 96) if v != 40]
         and all(digest(r['sha256']) and type(r['bytes']) is int and r['bytes'] > 0 for r in roster['files'].values())
         and roster['files']['00093_guest_retirement_settled_absence_continuation.sql']['sha256'] == M93
         and roster['files']['00094_failed_unwitnessed_expansion_cleanups.sql']['sha256'] == M94
         and roster['files']['00095_failed_expansion_read_failure_continuation.sql']['sha256'] == M95
         and cfg['migration95_sql']['sha256'] == M95, 'EXACT_QUALIFIED_IMAGE_SHIPPED_SQL_HEAD95')
    baseline = loads(reference(cfg['baseline94_acceptance']))
    closed(baseline, 'schema reviewed_by_root schema_before schema_after current_core_source current_ops_source business_source amd64_D migration94_sha256 complete_history_sha256 prior93_history_sha256 catalog94_sha256 index92_definition_sha256 catalog90_91_sha256 job_uid pod_uid exit_code single_job_create provider_guest_core_mutations old_records_and_sdk_preserved original_refs', 'EXACT_IMMUTABLE_ROOT94_RECEIPT21')
    need(cfg['baseline94_acceptance']['sha256'] == BASELINE94_ACCEPTANCE_SHA256
         and baseline['schema'] == 'root_goose94_failed_unwitnessed_expansion_cleanup_acceptance_v1'
         and baseline['reviewed_by_root'] is True and baseline['schema_before'] == 93 and baseline['schema_after'] == 94
         and baseline['current_core_source'] == 'ee8e3377ba91ff3efc3fde3a9751790608ac7066'
         and baseline['current_ops_source'] == '3e617cc176026cd70ee885ede753fbc6f6dd17a6'
         and baseline['business_source'] == CURRENT_CORE_R and baseline['amd64_D'] == CURRENT_CORE_D
         and baseline['migration94_sha256'] == M94 and baseline['exit_code'] == 0
         and baseline['single_job_create'] is True and baseline['provider_guest_core_mutations'] == 0
         and baseline['old_records_and_sdk_preserved'] is True
         and all(digest(baseline[k]) for k in ('complete_history_sha256','prior93_history_sha256','catalog94_sha256','index92_definition_sha256','catalog90_91_sha256')),
         'ORIGINAL_ROOT94_NOT_RETYPED_AS95_OR_FUTURE_R5_ADOPTION')
    closed(baseline['original_refs'], 'migration_result before_catalog after_catalog source_ci qualified_image', 'ROOT94_ORIGINAL_FIVE_ROLES_UNCHANGED')
    for original in baseline['original_refs'].values():
        need(len(reference(original)) > 1, 'ROOT94_WHOLE_ORIGINAL_CUSTODY')
    return baseline


def stable_metadata(value):
    return {k: v for k, v in value['metadata'].items() if k not in ('resourceVersion', 'managedFields')}


def core(api, expected):
    closed(expected, 'deployment_uid generation deployment_spec_sha256 deployment_metadata_sha256 replicaset_name replicaset_uid replicaset_spec_sha256 replicaset_metadata_sha256 pod_name pod_uid container_id container_started_at node_name pod_spec_sha256', 'CLOSED_ACTUAL_CORE14')
    need(expected['deployment_uid'] == 'a58ab8c2-da48-46c1-ae62-a650141eeb86'
         and expected['generation'] == 277 and expected['pod_uid'] == '52a8f447-4a72-4672-8287-2023a8934e92'
         and expected['replicaset_uid'] == CURRENT_RS_UID
         and expected['replicaset_name'] == RS_URI.rsplit('/', 1)[-1], 'ACTUAL_RETAINED_R4_LIFETIME_NOT_R5_ADOPTION')
    dep, rs, pods = api.get(DEP_URI), api.get(RS_URI), api.get(CORE_PODS_URI)
    for label, obj in (('deployment', dep), ('replicaset', rs)):
        need(obj['metadata']['uid'] == expected[label + '_uid'] and not obj['metadata'].get('deletionTimestamp')
             and sha(wire(obj['spec'])) == expected[label + '_spec_sha256']
             and sha(wire(stable_metadata(obj))) == expected[label + '_metadata_sha256'], 'UNCHANGED_FULL_CORE_AND_RS_SPEC_STABLE_METADATA')
    need(dep['metadata']['generation'] == dep['status']['observedGeneration'] == 277
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
         and len(manifest['protected_refs']) == 43, 'ACTUAL_G14_APPEND_D4_D5_NOT_PREDECESSOR_OR_CORE_ADOPTION')
    return V.g14_acceptance(cut, folder, manifest, returned, run)


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
    closed(cfg,'schema source_ci_acceptance companion_image_proof companion_sql_roster baseline94_acceptance runtime_package g14_return g14_cas_source runtime_config_ref transport_source core_preimage e70_sql_data cleanup_preimage case migration95_sql legacy_catalog_sql','CLOSED_GOOSE94_CONFIG')
    need(cfg['schema'] == 'root_goose95_failed_read_continuation_companion_config_v1','TYPED_NEW_MAINTENANCE_CASE_NO_ADMIN_ADMISSION')
    accepted = qualification(cfg)
    S = load_definitions(cfg['transport_source'],TRANSPORT_SHA,'reviewed_generic_job_mtls_transport')
    V = load_definitions(cfg['g14_cas_source'],CAS_SOURCE_SHA256,'reviewed_actual_g14_runtime_only')
    V.CONFIG_REF = V.validated_config_ref(cfg['runtime_config_ref']['path'],cfg['runtime_config_ref']['sha256']); V.require_bound()
    reference(cfg['runtime_config_ref'])
    cut = V.load_tools(Path(cfg['runtime_package'])); C = cut.C
    folder, manifest = C.package(Path(cfg['runtime_package']),RUNTIME_MANIFEST_SHA256)
    need(cfg['g14_return']['sha256'] == G14_RETURN_SHA256,'ACTUAL_PHYSICAL_G14_RETURN')
    returned = loads(reference(cfg['g14_return'],32<<20))
    need(cfg['e70_sql_data']['sha256'] == E70_SHA and cfg['cleanup_preimage']['sha256'] == CLEANUP_PREIMAGE_SHA256,'EXACT_ORIGINAL_E70_AND_KNOWN_C117_FAILED_READ_BASELINE')
    e70, baseline = loads(reference(cfg['e70_sql_data'])), loads(reference(cfg['cleanup_preimage']))
    validate_cleanup95(baseline,cfg['case'])
    need(cfg['legacy_catalog_sql']['sha256'] == LEGACY_CATALOG_SHA,'EXACT_LEGACY_CATALOG_SQL')
    legacy = reference(cfg['legacy_catalog_sql']).decode(); m95 = reference(cfg['migration95_sql']).decode()
    expected = source_functions(m95); sql = catalog94_sql(legacy,V)
    job = job_manifest(); need(private_read(args.manifest) == wire(job) and sha(wire(job)) == JOB_MANIFEST_SHA256,'ACTUAL_ROOT_REVIEWED_EXTERNAL_JOB_BODY')
    C.shared_parent(ROOT.parent); C.private_dir(ROOT,create=not ROOT.exists()); run = args.evidence_dir.absolute()
    need(run.parent == ROOT and re.fullmatch('(?:migration95|reconcile95)-[a-f0-9-]{36}',run.name),'NEW_EXCLUSIVE_GOOSE94_EVIDENCE_LEAF')
    C.private_dir(run,create=True)
    try:
        with V.operation_lock():
            api = CapturedAPI(S.API(cut),C,run,not args.reconcile_get_only)
            if args.reconcile_get_only:
                marker = loads(C.read(CLAIM,32768,0o600))
                need(marker['schema'] == 'goose95_companion_job_possible_v1' and marker['source_Q'] == COMPANION_SOURCE_Q
                     and marker['companion_image_D'] == COMPANION_IMAGE_D and marker['current_ops_P'] == CURRENT_OPS_P
                     and marker['job_uuid'] == JOB_UUID and marker['manifest_sha256'] == JOB_MANIFEST_SHA256
                     and marker['config_sha256'] == CONFIG_SHA256 and marker['script_sha256'] == args.expected_script_sha256
                     and marker['automatic_retry'] is False,'EXACT_CONSUMED_JOB_CLAIM_GET_ONLY')
                uid,pod_uid,logs = observe_owned_job(api,job,S,None,deadline)
                result = {'schema':'goose95_reconcile_return_v1','status':'ORIGINAL_JOB_OBSERVED_ROOT_INDEPENDENT_ACCEPTANCE_PENDING',
                          'job_uid':uid,'pod_uid':pod_uid,'logs_sha256':logs,'POST_sent':False,'automatic_retry':False}
            else:
                need(not CLAIM.exists(),'GLOBAL_GOOSE94_CLAIM_ABSENT_NO_RESET')
                before_core, before_ones = core(api,cfg['core_preimage']), oneshots(cut)
                before_db = database(V,cut,run,e70,baseline,cfg['case'],'BEFORE')
                before = run_catalog(cut,run,'BEFORE-CATALOG',sql); check_catalog(before,accepted,expected)
                gdir = run/'G14-BEFORE'; C.private_dir(gdir,create=True)
                _,refs,ctrl,guard,observed = runtime(V,cut,folder,manifest,returned,gdir)
                need(core(api,cfg['core_preimage']) == before_core and oneshots(cut) == before_ones,'SAME_CORE_AND_ONESHOTS_BEFORE_JOB')
                fresh = run_catalog(cut,run,'PRESEND-CATALOG',sql); check_catalog(fresh,accepted,expected)
                need(fresh == before and database(V,cut,run,e70,baseline,cfg['case'],'PRESEND') == before_db
                     and time.monotonic()-observed <= 15 and deadline-time.monotonic() >= 420,'SAME_FULL_PREIMAGES_WITHIN_EXISTING_CURRENT15')
                signal.setitimer(signal.ITIMER_REAL,min(420,deadline-time.monotonic()))
                uid = create_once(api,C,run,job,CONFIG_SHA256,args.expected_script_sha256,deadline,observed)
                uid,pod_uid,logs = observe_owned_job(api,job,S,uid,min(deadline,time.monotonic()+420))
                after = run_catalog(cut,run,'AFTER-CATALOG',sql); check_catalog(after,accepted,expected,old=before,migration=m95)
                need(database(V,cut,run,e70,baseline,cfg['case'],'AFTER',after=True) == before_db
                     and core(api,cfg['core_preimage']) == before_core and oneshots(cut) == before_ones,'SAME_CORE_A3_DEBT_GUARDS_AND_ONESHOTS_AFTER_JOB')
                gdir = run/'G14-AFTER'; C.private_dir(gdir,create=True)
                _,refs2,ctrl2,guard2,_ = runtime(V,cut,folder,manifest,returned,gdir)
                need((refs2,ctrl2,guard2) == (refs,ctrl,guard),'SAME_ALL43_REFS_BUDGET1_AND_CONTROLLER_GUARDIAN_LIFETIMES')
                result = {'schema':'goose95_companion_job_return_v1','status':'JOB_ACK_PLUS_OBSERVATIONS_ROOT_INDEPENDENT_ACCEPTANCE_PENDING',
                          'companion_source_Q':COMPANION_SOURCE_Q,'companion_image_D':COMPANION_IMAGE_D,'current_ops_P':CURRENT_OPS_P,
                          'current_Core_source':CURRENT_CORE_R,'current_Core_D':CURRENT_CORE_D,'job_uid':uid,'pod_uid':pod_uid,'exit_code':0,
                          'migration95_sha256':M95,'schema_before':94,'schema_after':95,'history95_sha256':sha(after['legacy']['complete_history_wire'].encode()),
                          'prior94_history_sha256':sha(before['legacy']['complete_history_wire'].encode()),'catalog95_sha256':sha(wire(catalog94_projection(after))),
                          'catalog95_original':{'path':str(run/'AFTER-CATALOG.stdout'),'sha256':sha(C.read(run/'AFTER-CATALOG.stdout',4<<20,0o600))},
                          'catalog95_full_definitions_Root_review_pending':True,'logs_sha256':logs,'native_create_attempts':1,
                          'Core_G14_all43_budget1_Cold_Hub_and_old_records_SDK_unchanged':True,'ordinary_quiet_or_business_authority_claimed':False,
                          'provider_Guest_Core_mutations_sent':0,'automatic_retry_down_cleanup_or_repair':False}
            C.once(run/'RETURN.PUBLIC.json',wire(result)); signal.setitimer(signal.ITIMER_REAL,0)
            print(wire(result).decode(),end='',flush=True)
    except BaseException as caught:
        signal.setitimer(signal.ITIMER_REAL,0)
        result = {'schema':'goose95_companion_hold_v1','status':'HOLD_UNKNOWN_RECONCILE_GET_ONLY_NO_REPLAY','possible_send':CLAIM.exists(),
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

def original_preregistration_member(pre, p, grant, binding, C):
    """The stored GRB owns member names; mutation binding names remain profile-wide."""
    need(type(pre.get('binding_wire')) is str and pre['binding_wire'].startswith('\\x'), 'ORIGINAL_GRB_BINDING_WIRE_HEX_PREFIX')
    try:
        raw = bytes.fromhex(pre['binding_wire'][2:])
    except ValueError:
        raise Hold('ORIGINAL_GRB_BINDING_WIRE_HEX') from None
    stored = C.loads(raw)
    need(type(stored) is dict and stored.get('mutation_binding_name') == binding['name']
         and type(stored.get('members')) is list, 'ORIGINAL_GRB_PROFILE_MUTATION_JOIN')
    members = [member for member in stored['members'] if type(member) is dict
               and type(member.get('slot')) is int and member['slot'] == grant['slot'] == p['slot']]
    need(len(members) == 1 and type(members[0].get('name')) is str
         and members[0]['name'] == p['binding_name'], 'ORIGINAL_GRB_UNIQUE_SLOT_MEMBER')


def validate_a3(v, c, C, after=False):
    need(type(v) is dict and set(v) == {'observed_at_pg','intent_pgtext','run_pgtext','dispatch','grant_pgtext','preregistration','active_policy','survivors','target_witnesses','target_enrollments','target_installations','target_retirements','factory_bindings','compensations','cleanup_admissions'}, 'CLOSED_ACTUAL_A3_SNAPSHOT')
    k = c['case']
    closed(k,'workflow_id lease_owner executor_id lease_expires_at policy_checksum intent_sha256 run_sha256 grant_sha256 preregistration_sha256','CLOSED_ROOT_ORIGINAL_A3_CASE')
    for field, pin in (('intent_pgtext','intent_sha256'),('run_pgtext','run_sha256'),('grant_pgtext','grant_sha256')):
        need(type(v[field]) is str, 'ACTUAL_A3_PG_WIRE_STRING')
        if field != 'grant_pgtext' or not after:
            need(sha(v[field].encode()) == k[pin], 'WHOLE_ACTUAL_A3_PG_WIRE_' + field)
    i, w, g = (C.loads(v[x]) for x in ('intent_pgtext','run_pgtext','grant_pgtext'))
    need(i['generation'] == 22 and i['fencing_token'] == 43 and i['phase'] == 'preparing'
         and i['lease_owner'] == k['lease_owner'] and i['lease_executor_id'] == k['executor_id']
         and i['lease_expires_at'] == k['lease_expires_at'] and utc(v['observed_at_pg']) > utc(k['lease_expires_at'])
         and i['baseline_snapshot']['units'] == i['assessment']['snapshot']['units'] == 1
         and i['decision']['units'] == 2 and i['policy_id'] == A3_POLICY
         and i['policy_checksum'] == k['policy_checksum']
         and all(i.get(x) is None for x in ('retirement_forward','failed_installed_disposal','failed_serving_disposal','original_notify_window'))
         and not i.get('recovery_only',False) and not i.get('floor_degraded',False), 'ONLY_EXPIRED_FAILED_EXPANSION_N1_TO_N2_NOT_RETIREMENT')
    need(w['id'] == A3_RUN and w['status'] == 'failed' and w['finished_at'] is not None
         and type(v['dispatch']) is list and len(v['dispatch']) == 1, 'ONE_ACTUAL_FAILED_FINISHED_A3_RUN')
    steps = w.get('result',{}).get('steps',[])
    need(type(steps) is list and sum(x.get('status') == 'failed' and x.get('metadata',{}).get('original_guest_refusal_predicate') == 'original-guest-step-25' for x in steps) == 1, 'ACTUAL_ORIGINAL_READ_STEP25_FAILURE')
    j = v['dispatch'][0]; e = C.loads(j['envelope']) if type(j['envelope']) is str else j['envelope']
    need(j['id'] == A3_JOB and j['run_id'] == A3_RUN and j['state'] == 'returned' and j['return_status'] == 'failed'
         and e['workflow']['id'] == k['workflow_id'] and utc(j['returned_at']) == utc(w['finished_at'])
         and j['finalization_ack_at'] is not None and utc(j['finalization_ack_at']) >= utc(j['returned_at'])
         and j['lease_expires_at'] is not None and utc(j['lease_expires_at']) < utc(v['observed_at_pg']), 'EXACT_RETURNED_FAILED_ACK_EXPIRED_DISPATCH_NO_UNKNOWN')
    record = g['grant_record']; grant, settlement, binding = record['grant'], record['settlement'], record['binding']
    need(g['id'] == A3_GRANT and g['state'] == grant['state'] == 'settled' and grant['grant_id'] == A3_GRANT
         and grant['capability'] == binding['ensure_capability'] == 'ensure_ec2_instance' and grant['slot'] == 2
         and grant['binding_name'] == binding['name'] and grant['integration_instance_id'] == binding['integration_instance_id']
         and grant['scope_checksum'] == binding['scope_checksum'] and grant['profile_name'] == binding['profile_name']
         and not grant.get('compensation_of') and g['namespace'] == 'dakasa-production'
         and g['environment'] == 'production' and g['domain'] == 'notify' and g['dimension'] == 'original_notify_aws_vm_members'
         and record['policy_id'] == A3_POLICY and record['policy_checksum'] == k['policy_checksum']
         and record['workflow_id'] == k['workflow_id'] and record['generation'] == 22 and record['fencing_token'] == 43
         and record['lease_owner'] == k['lease_owner'] and record['executor_id'] == k['executor_id']
         and record['attempt_id'] == A3_ATTEMPT
         and all(g[x] is None for x in ('original_disposition_id','failed_original_disposition_id','native_denied_disposition_id','enrolled_failed_disposition_id'))
         and (not after or CHILD_COLUMN in g and g[CHILD_COLUMN] is None), 'EXACT_UNDISPOSED_ORIGINAL_SETTLED_A3_CREATE_NOT_CHILD')
    need(settlement['grant_id'] == A3_GRANT and settlement['attempt_id'] == A3_ATTEMPT
         and settlement['outcome'] == 'accepted' and settlement['transport_completed'] is True
         and settlement['request_sha256'] == grant['request_sha256'] and digest_value(grant['request_sha256'])
         and settlement['action_id'] == A3_ACTION and settlement['resource_id'] == A3_RESOURCE
         and settlement['resource_created_at'] == A3_BIRTH and not settlement.get('original_provider_destroy_return')
         and not settlement.get('next_action_ids'), 'OWNING_CREATE_ACCEPTED_TRANSPORT_AND_EXACT_NEW_VM')
    sdk = settlement['original_provider_create_return']
    need(type(sdk) is dict and set(sdk) == {'schema','provider','adapter_source_commit','grant_id','attempt_id','request_sha256','resource_id','resource_created_at','action_id','next_action_ids','called_at','returned_at','context_deadline','response_status','response_body_sha256','response_bytes'}
         and sdk['schema'] == 'aws_original_run_instances_return_v1' and sdk['provider'] == 'aws'
         and sdk['adapter_source_commit'] == binding['original_provider_source_commit'] == A3_CREATOR
         and sdk['grant_id'] == A3_GRANT and sdk['attempt_id'] == A3_ATTEMPT and sdk['action_id'] == A3_ACTION
         and sdk['resource_id'] == A3_RESOURCE and sdk['resource_created_at'] == A3_BIRTH
         and sdk['request_sha256'] == grant['request_sha256'] and sdk['response_status'] == 200
         and digest_value(sdk['response_body_sha256']) and type(sdk['response_bytes']) is int and 2 <= sdk['response_bytes'] <= 2 << 20
         and utc(sdk['called_at']) <= utc(sdk['returned_at']) < utc(sdk['context_deadline'])
         and utc(sdk['returned_at']) <= utc(settlement['observed_at']) <= utc(w['finished_at'])
         and type(sdk['next_action_ids']) is list and sdk['next_action_ids'] == [], 'ACTUAL_SINGLE_SDK_RUN200_NOT_RETRIED_OR_READ_INFERENCE')
    pre = v['preregistration']
    need(type(pre['original_wire']) is str and pre['original_wire'].startswith('\\x'), 'ORIGINAL_PREREGISTRATION_WIRE_HEX_PREFIX')
    try:
        wire = bytes.fromhex(pre['original_wire'][2:])
    except ValueError:
        raise Hold('ORIGINAL_PREREGISTRATION_WIRE_HEX') from None
    need(sha(wire) == k['preregistration_sha256']
         and pre['id'] == A3_PRE and pre['create_grant_id'] == A3_GRANT
         and C.loads(wire) == pre['preregistration_record'], 'EXACT_ORIGINAL_PREREGISTRATION_WIRE')
    p = pre['preregistration_record']
    original_preregistration_member(pre, p, grant, binding, C)
    need(p['preregistration_id'] == A3_PRE and p['original_create_grant_id'] == A3_GRANT
         and p['original_create_request_sha256'] == grant['request_sha256'] and p['slot'] == 2
         and p['policy_id'] == A3_POLICY and p['policy_checksum'] == k['policy_checksum']
         and p['workflow_id'] == k['workflow_id'] and p['generation'] == 22 and p['fence'] == 43
         and p['lease_owner'] == k['lease_owner'] and p['executor_id'] == k['executor_id']
         and utc(p['original_deadline']) == utc(pre['original_deadline']) < utc(v['observed_at_pg']), 'EXPIRED_ORIGINAL_CREATE_DEADLINE_NO_REWRITE')
    need(utc(sdk['called_at']) >= utc(p['reserved_at']) and utc(sdk['context_deadline']) <= utc(grant['expires_at'])
         and utc(sdk['resource_created_at']) >= utc(p['reserved_at'])-datetime.timedelta(seconds=5)
         and utc(sdk['resource_created_at']) <= utc(sdk['returned_at'])+datetime.timedelta(seconds=5), 'CANONICAL_ORIGINAL_SDK_CLOCKS_AND_BIRTH_NOT_FRESHNESS_RELABELLING')
    policy = v['active_policy']
    need(policy['id'] == A3_POLICY and policy['kind'] == 'capacity_policy' and policy['active'] is True
         and policy['checksum'] == k['policy_checksum'], 'CURRENT_EXACT_A3_POLICY_NO_CAS_REBASE')
    survivors = v['survivors']
    need(type(survivors) is list and len(survivors) == 1 and survivors[0]['slot'] == 1
         and survivors[0]['resource_id'] == S1_RESOURCE
         and survivors[0]['slot_record']['resource_created_at'] == S1_BIRTH
         and survivors[0]['slot_record']['resource_id'] == S1_RESOURCE and survivors[0]['slot_record']['tombstone'] is False
         and survivors[0]['integration_instance_id'] == grant['integration_instance_id']
         and survivors[0]['scope_checksum'] == grant['scope_checksum'] and survivors[0]['profile_name'] == grant['profile_name'], 'EXACT_ONLY_CURRENT_S1_OWNED_NATIVE_ROSTER')
    enrolled = survivors[0]['enrollments']
    need(type(enrolled) is list and len(enrolled) == 1
         and enrolled[0]['enrollment']['preregistration_id'] == enrolled[0]['witness']['preregistration_id'] == enrolled[0]['installation']['preregistration_id']
         and enrolled[0]['enrollment']['enrollment_record']['statement']['tuple']['resource_id'] == S1_RESOURCE
         and enrolled[0]['enrollment']['enrollment_record']['statement']['tuple']['resource_created_at'] == S1_BIRTH,
         'S1_ONLY_HAS_RETAINED_ENROLLMENT_WITNESS_AND_INSTALLATION')
    need(all(v[x] == [] for x in ('target_witnesses','target_enrollments','target_installations','target_retirements','factory_bindings','compensations','cleanup_admissions')), 'NO_TARGET_WITNESS_ENROLL_INSTALL_RETIRE_OR_EARLY_CLEANUP_AUTHORITY')
    return True


A3_SQL = "SELECT jsonb_build_object(\n'observed_at_pg',clock_timestamp(),\n'intent_pgtext',(SELECT intent::text FROM public.capacity_intents WHERE namespace='dakasa-production' AND environment='production' AND domain='notify' AND dimension='original_notify_aws_vm_members'),\n'run_pgtext',(SELECT to_jsonb(w)::text FROM public.workflow_runs w WHERE id='efad3324-4280-4928-b2e0-becc7eda08a9'),\n'dispatch',(SELECT COALESCE(jsonb_agg(to_jsonb(j) ORDER BY j.id),'[]'::jsonb) FROM public.capacity_dispatch_jobs j WHERE run_id='efad3324-4280-4928-b2e0-becc7eda08a9'),\n'grant_pgtext',(SELECT to_jsonb(g)::text FROM public.capacity_mutation_grants g WHERE id='c117f03f-27db-4da2-b990-c2729f98a46f'),\n'preregistration',(SELECT to_jsonb(p) FROM public.capacity_vm_provisioning_preregistrations p WHERE id='4677b2cf-9cfa-4218-bc3d-930de13591a8'),\n'active_policy',(SELECT to_jsonb(m) FROM public.manifests m WHERE id='ab057719-e52e-4549-8490-92766fafd24f'),\n'survivors',(SELECT COALESCE(jsonb_agg(to_jsonb(s)||jsonb_build_object('enrollments',(SELECT COALESCE(jsonb_agg(jsonb_build_object('enrollment',to_jsonb(e),'witness',to_jsonb(w),'installation',to_jsonb(i)) ORDER BY e.preregistration_id),'[]'::jsonb) FROM public.capacity_vm_original_enrollments e JOIN public.capacity_vm_provisioning_preregistrations p ON p.id=e.preregistration_id JOIN public.capacity_guest_original_create_witnesses w ON w.preregistration_id=e.preregistration_id JOIN public.capacity_guest_original_installations i ON i.preregistration_id=e.preregistration_id WHERE (p.preregistration_record->>'slot')::integer=s.slot AND e.enrollment_record->'statement'->'tuple'->>'resource_id'=s.resource_id AND e.enrollment_record->'statement'->'tuple'->>'resource_created_at'=s.slot_record->>'resource_created_at')) ORDER BY s.slot),'[]'::jsonb) FROM public.capacity_resource_slots s WHERE namespace='dakasa-production' AND environment='production' AND domain='notify' AND dimension='original_notify_aws_vm_members' AND resource_id<>''),\n'target_witnesses',(SELECT COALESCE(jsonb_agg(to_jsonb(x) ORDER BY preregistration_id),'[]'::jsonb) FROM public.capacity_guest_original_create_witnesses x WHERE preregistration_id='4677b2cf-9cfa-4218-bc3d-930de13591a8'),\n'target_enrollments',(SELECT COALESCE(jsonb_agg(to_jsonb(x) ORDER BY preregistration_id),'[]'::jsonb) FROM public.capacity_vm_original_enrollments x WHERE preregistration_id='4677b2cf-9cfa-4218-bc3d-930de13591a8'),\n'target_installations',(SELECT COALESCE(jsonb_agg(to_jsonb(x) ORDER BY preregistration_id),'[]'::jsonb) FROM public.capacity_guest_original_installations x WHERE preregistration_id='4677b2cf-9cfa-4218-bc3d-930de13591a8'),\n'target_retirements',(SELECT COALESCE(jsonb_agg(to_jsonb(x) ORDER BY id),'[]'::jsonb) FROM public.capacity_vm_retirement_intents x WHERE preregistration_id='4677b2cf-9cfa-4218-bc3d-930de13591a8'),\n'factory_bindings',(SELECT COALESCE(jsonb_agg(to_jsonb(x) ORDER BY grant_id),'[]'::jsonb) FROM public.capacity_factory_original_grant_bindings x WHERE grant_id='c117f03f-27db-4da2-b990-c2729f98a46f'),\n'compensations',(SELECT COALESCE(jsonb_agg(to_jsonb(x) ORDER BY id),'[]'::jsonb) FROM public.capacity_mutation_grants x WHERE grant_record#>>'{grant,compensation_of}'='c117f03f-27db-4da2-b990-c2729f98a46f'),\n'cleanup_admissions','[]'::jsonb)"


def a3_preserved(actual, original, after=False):
    """All original columns/SDK bytes persist; M94 adds one NULL child FK."""
    a, b = copy.deepcopy(actual), copy.deepcopy(original)
    a.pop('observed_at_pg'); b.pop('observed_at_pg')
    ar, br = loads(a.pop('grant_pgtext')), loads(b.pop('grant_pgtext'))
    if after:
        need(CHILD_COLUMN in ar and ar.pop(CHILD_COLUMN) is None, 'ONLY_NEW_NULL_CHILD_FK_ON_ORIGINAL_PARENT')
    need(ar == br and a == b, 'ALL_ORIGINAL_A3_COLUMNS_AND_PREREG_RUN_DISPATCH_UNCHANGED')
    need(raw_json_member(actual['grant_pgtext'].encode(),'grant_record') == raw_json_member(original['grant_pgtext'].encode(),'grant_record'), 'EXACT_ORIGINAL_SDK_GRANT_RECORD_RAW_BYTES')


def validate_cleanup95(v, case):
    """Known paid child + genuine failed read custody; never cleanup/admission authority."""
    closed(v, 'observed_at_pg admissions events intent parent parent_sdk_pgtext child workflow_run dispatch', 'CLOSED_CURRENT_C117_READ_FAILURE_CASE')
    closed(case, 'cleanup_id child_grant_id owning_run_id latest_sequence lease_expires_at provider_lanes', 'CLOSED_ROOT_CURRENT_READ_FAILURE_OPERANDS')
    need(case['cleanup_id'] == CLEANUP_ID and case['child_grant_id'] == CHILD_ID and case['owning_run_id'] == CLEANUP_RUN
         and case['latest_sequence'] == 135 and type(v['admissions']) is list and len(v['admissions']) == 1
         and type(v['events']) is list and len(v['events']) >= 3, 'EXACT_KNOWN_C117_CHILD_AND_FAILED_READ_SUFFIX')
    a = v['admissions'][0]; ad = a['original_record']; parent, child = v['parent'], v['child']
    for row, pin in [(a,'admission_sha256')] + [(e,'event_sha256') for e in v['events']]:
        raw = row['wire_hex']; need(type(raw) is str and re.fullmatch('(?:[0-9a-f]{2})+',raw), 'WHOLE_IMMUTABLE94_WIRE_HEX')
        decoded = bytes.fromhex(raw)
        need(sha(decoded) == row[pin] and loads(decoded) == row['original_record'], 'WHOLE_IMMUTABLE94_WIRE_SHA_AND_RECORD')
    need(a['id'] == ad['id'] == CLEANUP_ID and a['grant_id'] == ad['grant_id'] == A3_GRANT
         and a['child_grant_id'] == ad['child_grant_id'] == child['id'] == CHILD_ID
         and ad['job_id'] == A3_JOB and ad['run_id'] == A3_RUN and ad['preregistration_id'] == A3_PRE
         and ad['resource_id'] == A3_RESOURCE and ad['resource_created_at'] == A3_BIRTH
         and ad['slot'] == 2 and ad['survivor_count'] == 1
         and parent['state'] == parent['grant_record']['grant']['state'] == child['state'] == child['grant_record']['grant']['state'] == 'settled'
         and parent[CHILD_COLUMN] is None and child[CHILD_COLUMN] == CLEANUP_ID,
         'SAME_IMMUTABLE_ADMISSION_AND_STILL_SETTLED_OWNING_CHILD_NO_SECOND_DELETE')
    sdk = loads(v['parent_sdk_pgtext']); settlement = child['grant_record']['settlement']
    need(sha(v['parent_sdk_pgtext'].encode()) == ad['original_SDK_return_sha256']
         and sdk == parent['grant_record']['settlement']['original_provider_create_return']
         and sdk['schema'] == 'aws_original_run_instances_return_v1' and sdk['response_status'] == 200
         and sdk['adapter_source_commit'] == A3_CREATOR and sdk['grant_id'] == A3_GRANT
         and sdk['resource_id'] == A3_RESOURCE and sdk['resource_created_at'] == A3_BIRTH
         and child['grant_record']['grant'].get('compensation_of','') == ''
         and settlement['outcome'] == 'accepted' and settlement['transport_completed'] is True
         and settlement['auxiliary_inventory_complete'] is True
         and len(settlement['auxiliary_resources']) == 2
         and {r['kind'] for r in settlement['auxiliary_resources']} == {'aws_ebs_volume','aws_network_interface'},
         'ORIGINAL_CREATE200_AND_ONE_PAID_SEALED_AUX2_DESTROY_PRESERVED')
    record = child['grant_record']; grant = record['grant']
    destroy = settlement.get('original_provider_destroy_return')
    need(type(destroy) is dict and destroy.get('schema') == 'aws_original_terminate_instances_return_v1'
         and destroy.get('provider') == 'aws' and destroy.get('adapter_source_commit') == A3_CREATOR
         and type(destroy.get('response_status')) is int and destroy['response_status'] == 200
         and destroy.get('grant_id') == settlement['grant_id'] == grant['grant_id'] == CHILD_ID
         and destroy.get('attempt_id') == settlement['attempt_id'] == record['attempt_id']
         and type(destroy.get('action_id')) is str and bool(destroy['action_id'])
         and destroy['action_id'] == settlement['action_id']
         and destroy.get('request_sha256') == settlement['request_sha256'] == grant['request_sha256']
         and digest(destroy['request_sha256'])
         and destroy.get('resource_id') == settlement['resource_id'] == grant['expected_resource_id'] == A3_RESOURCE
         and destroy.get('resource_created_at') == settlement['resource_created_at'] == grant['expected_resource_created_at'] == A3_BIRTH
         and destroy.get('next_action_ids', []) == [],
         'ACTUAL_OWNING_C34_TERMINATE200_GRANT_ATTEMPT_ACTION_REQUEST_TARGET_JOINS')
    need(utc(destroy['called_at']) <= utc(destroy['returned_at']) < utc(destroy['context_deadline'])
         <= utc(grant['expires_at']), 'ORIGINAL_CHILD_SDK_CALL_RETURN_DEADLINE_NOT_RETIMED')
    q,p,r = v['events'][-3:]
    need(q['stage'] == 'pending_absence' and p['stage'] == 'absence_prepared' and r['stage'] == 'absence_returned'
         and p['sequence'] == q['sequence']+1 and r['sequence'] == p['sequence']+1 == case['latest_sequence']
         and all(e['run_id'] == CLEANUP_RUN and e['child_grant_id'] == CHILD_ID and e['cleanup_id'] == CLEANUP_ID for e in (q,p,r))
         and all(e['original_record'][k] == q['original_record'][k] for e in (p,r)
                 for k in ('generation','fencing_token','lease_owner','executor_id','lease_expires_at')),
         'EXACT_CONTIGUOUS_SAME_OLD_OWNER_133_134_135_NOT_A_NEW_READ')
    good, failed, read = q['original_record']['evidence'], r['original_record']['evidence'], p['original_record']['evidence']
    need(good['schema'] == failed['schema'] == 'failed_unwitnessed_expansion_native_return_v1'
         and good['status'] == 'observed' and good['pending'] is True and good['complete'] is False
         and good['call_failed'] is False and good['original_context_failed'] is False
         and failed['call_failed'] is True and failed['original_context_failed'] is True
         and failed['status'] == '' and failed['pending'] is False and failed['complete'] is False
         and not any(k in failed for k in ('plan','observation','observer_source_commit','original_observer_return'))
         and failed['read'] == read and read['kind'] == 'absence' and read['cleanup_id'] == CLEANUP_ID
         and read['child_grant_id'] == CHILD_ID and read['admission_sha256'] == a['admission_sha256']
         and read['read_id'] != good['read']['read_id'], 'FAILED_RAW_RETURN_REMAINS_FAILURE_NOT_PROOF')
    rw,pw = base64.b64decode(good['read_wire'],validate=True),base64.b64decode(good['receipt_wire'],validate=True)
    observer = loads(base64.b64decode(good['original_observer_return'],validate=True))
    need(loads(rw) == good['read'] and loads(pw) == good['receipt']
         and set(observer) == {'schema','observer_source_commit','original_adapter_source_commit','read_id','read_sha256','original_receipt_sha256','observation'}
         and observer['schema'] == 'original_settled_retirement_absence_read_return_v1'
         and observer['observer_source_commit'] == good['observer_source_commit'] == 'd8cbbf48873d24439216f98c30afe2669a525b54'
         and observer['original_adapter_source_commit'] == A3_CREATOR and observer['read_id'] == good['read']['read_id']
         and observer['read_sha256'] == sha(rw) and observer['original_receipt_sha256'] == sha(pw)
         and observer['observation'] == good['observation']
         and base64.b64decode(failed['receipt_wire'],validate=True) == pw and failed['receipt'] == good['receipt']
         and loads(base64.b64decode(failed['read_wire'],validate=True)) == read,
         'LAST_GENUINE_H7_AND_FAILED_READ_RAW_RECEIPT_BYTES_PRESERVED')
    claims = [e for e in v['events'] if e['stage'] == 'claimed']
    need(claims, 'ACTUAL_OLD_CLAIM_ROW_REQUIRED')
    claim = claims[-1]
    need(good['read']['kind'] == 'absence' and good['read']['cleanup_id'] == CLEANUP_ID
         and good['read']['child_grant_id'] == CHILD_ID and good['read']['admission_sha256'] == a['admission_sha256']
         and good['read']['claim_sequence'] == read['claim_sequence'] == claim['sequence'] < q['sequence']
         and good['receipt']['grant'] == child['grant_record']['grant']
         and good['receipt']['resource_id'] == A3_RESOURCE and good['receipt']['resource_created_at'] == A3_BIRTH
         and all(good['receipt'][k] == settlement[k] for k in ('outcome','transport_completed','action_id','auxiliary_resources','auxiliary_inventory_complete'))
         and all(q['original_record'][k] == claim['original_record'][k] for k in ('generation','fencing_token','lease_owner','executor_id','lease_expires_at')),
         'SAME_ORIGINAL_CLAIM_AND_OWNING_PAID_CHILD_RECEIPT_NO_FOREIGN_PROOF')
    o = good['observation']
    need(o['server_absent'] is True and o['server_absence_complete'] is True
         and o['auxiliary_inventory_complete'] is True
         and o['hold_reasons'] == ['aws_network_interface_still_present']
         and len(o['auxiliary_resources']) == 2
         and {(x['kind'],x['absent']) for x in o['auxiliary_resources']} == {('aws_ebs_volume',True),('aws_network_interface',False)},
         'ACTUAL_LAST_PENDING_ENI_NOT_FULL_ABSENCE')
    expires = utc(case['lease_expires_at']); observed = utc(v['observed_at_pg'])
    need(utc(q['original_record']['lease_expires_at']) == expires <= observed
         and utc(read['issued_at_core']) <= utc(failed['started_at_core']) < utc(read['original_deadline_core'])
         and utc(read['original_deadline_core']) <= expires
         and utc(read['original_deadline_core']) <= utc(failed['returned_at_core']) <= utc(r['recorded_at'])
         and (utc(read['original_deadline_core'])-utc(read['issued_at_core'])).total_seconds() <= 5,
         'REAL_ORIGINAL_READ_DEADLINE_AND_NATURALLY_EXPIRED_OWNER_NO_REWRITE')
    w = v['workflow_run']; need(type(v['dispatch']) is list and len(v['dispatch']) == 1, 'ONE_GENUINE_OWNING_DISPATCH')
    j = v['dispatch'][0]
    need(w['id'] == j['run_id'] == CLEANUP_RUN and w['status'] == j['return_status'] == 'failed' and j['state'] == 'returned'
         and utc(j['finalization_ack_at']) >= utc(j['returned_at']) == utc(w['finished_at']) >= utc(r['recorded_at']),
         'ACTUAL_FAILED_RETURN_AND_FINAL_ACK_AFTER_RAW_READ')
    return True


def database(V, cut, run, e70, baseline, case, label, after=False):
    result = {}
    for provider,key in (('aws','original_notify_aws_vm_members'),('hetzner','original_notify_hetzner_vm_members')):
        value = V.query(cut,run,label+'-'+provider.upper(),e70['queries'][key])
        need(value['intent_count'] == 1 and all(type(value[k]) is int and value[k] == 0
             for k in ('jobs_busy','runs_busy','forward_unreturned_reads','live_unreturned_canaries')),
             'BOTH_LANES_NO_OTHER_ACTIVE_OR_UNRETURNED_ORIGINALS')
        result[provider] = {k:value[k] for k in ('jobs_busy','runs_busy','forward_unreturned_reads','live_unreturned_canaries','intent_count','intent_busy','pending_authority','forward_markers')}
        need(type(case['provider_lanes']) is dict and set(case['provider_lanes']) == {'aws','hetzner'}
             and type(case['provider_lanes'][provider]) is dict and set(case['provider_lanes'][provider]) == set(result[provider])
             and all(type(v) is int and v >= 0 for v in case['provider_lanes'][provider].values())
             and result[provider] == case['provider_lanes'][provider], 'EXACT_ROOT_CAPTURED_E70_COUNTS_NO_GUESSED_PARENT_CHILD_EXCEPTION')
    actual = V.query(cut,run,label+'-C117',CLEANUP_SQL)
    validate_cleanup95(actual,case)
    need({k:v for k,v in actual.items() if k != 'observed_at_pg'}
         == {k:v for k,v in baseline.items() if k != 'observed_at_pg'}, 'WHOLE_KNOWN_C117_ROWS_SDK_AND_FAILED_READ_CUSTODY_UNCHANGED')
    need(all(type(v) is dict for v in result.values()), 'FULL_BOTH_E70_LANE_PROJECTIONS')
    return result


def source_functions(sql):
    """The sole Source95 replacement; old94 SQL and all other catalog rows remain immutable."""
    need(sha(sql.encode()) == M95, 'EXACT_FINAL_SOURCE95_BYTES')
    up = sql.split('-- +goose Down', 1)[0]
    pattern = r'CREATE OR REPLACE FUNCTION public\.([a-z0-9_]+)\(([^)]*)\)\s+RETURNS\s+(boolean|trigger)\s+(.*?)\$\$(.*?)\$\$;'
    matches = re.findall(pattern, up, re.S)
    need(len(matches) == 1 and matches[0][0] == M95_FUNCTION, 'ONLY_ONE_EXISTING_EVENT_GUARD_REPLACEMENT95')
    name,args,result,header,body = matches[0]
    need(args == '' and result == 'trigger' and re.fullmatch(r'LANGUAGE\s+plpgsql\s+AS\s*', header.strip()), 'EXACT_UNCHANGED_EVENT_GUARD_HEADER95')
    return {name: {'arguments':'','result':'trigger','language':'plpgsql','volatility':'v','config':None,'body':body}}


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
    v, supplement = value['legacy'], value['supplement']
    version = 94 if old is None else 95
    need(v['database'] == 'yggdrasil' and v['readonly'] == 'on'
         and v['latest_versions'] == [0]+[x for x in range(1,version+1) if x != 40]
         and v['rows90'] == v['rows91'] == 1
         and all(v[k] == 0 for k in ('other_migrators_ddl','other_cic','ddl_locks'))
         and supplement['index92_valid'] is True
         and sha(supplement['index92_definition'].encode()) == accepted['index92_definition_sha256'],
         'EXACT95_HEAD_HISTORY_INDEX92_AND_NO_OTHER_DDL')
    if old is None:
        need(sha(v['complete_history_wire'].encode()) == accepted['complete_history_sha256']
             and sha(wire(catalog94_projection(value))) == accepted['catalog94_sha256'], 'WHOLE_ROOT94_HISTORY_AND_SEVEN_FIELD_CATALOG')
        return
    prior,current = loads(old['legacy']['complete_history_wire']), loads(v['complete_history_wire'])
    added = [r for r in current if r['version_id'] == 95]
    need(len(added) == 1 and added[0]['is_applied'] is True and len(current) == len(prior)+1
         and [r for r in current if r['version_id'] != 95] == prior
         and added[0]['id'] > max(r['id'] for r in prior), 'SOLE95_ROW_ALL_PRIOR94_ROWS_BYTE_VALUES_UNCHANGED')
    need(catalog_projection(value) == catalog_projection(old)
         and supplement['old_records'] == old['supplement']['old_records']
         and value['old_grants'] == old['old_grants'] and value['ledgers94'] == old['ledgers94'],
         'ENTIRE_OLD_CATALOG_RECORDS_SDK_AND_EXISTING94_LEDGERS_UNCHANGED')
    before = copy.deepcopy(old['schema94']); after = value['schema94']
    need(set(before) == set(after) == {'tables','columns','constraints','indexes','triggers','functions'}
         and all(before[k] == after[k] for k in ('tables','columns','constraints','indexes','triggers')),
         'NO95_TABLE_COLUMN_CONSTRAINT_INDEX_OR_TRIGGER_DELTA')
    need(len(before['functions']) == len(after['functions']) == 6
         and {r['name'] for r in before['functions']} == {r['name'] for r in after['functions']} == set(M94_FUNCTIONS)
         and set(expected_functions) == {M95_FUNCTION}, 'EXACT_SAME_SIX_FUNCTION_ROSTER_ONLY_ONE95_REPLACED')
    expected = expected_functions[M95_FUNCTION]
    changed = [r for r in before['functions'] if r['name'] == M95_FUNCTION]
    need(len(changed) == 1, 'EXACT_OLD_EVENT_GUARD_ROW')
    row = changed[0]
    need(all(row[k] == expected[k] for k in ('arguments','result','language','volatility','config'))
         and row['qualified_name'] == 'public.'+M95_FUNCTION
         and type(row['body']) is str and row['body'] and row['definition'].count(row['body']) == 1,
         'UNCHANGED_EVENT_GUARD_HEADER_AND_WHOLE_OLD_DEFINITION')
    row['definition'] = row['definition'].replace(row['body'], expected['body'], 1)
    row['body'] = expected['body']
    need(before == after, 'ONLY_SOURCE95_EVENT_GUARD_BODY_AND_EXACT_BODY_SUBSTITUTION_DEFINITION')


def check_grant_delta(current,old,sql):
    """Existing grant relation changes only by reviewed nullable child FK/index/guards."""
    table='public.capacity_mutation_grants'
    def rows(c,key): return [copy.deepcopy(r) for r in c[key] if r.get('table',r.get('name')) == table]
    need(rows(current,'tables') == rows(old,'tables'),'ORIGINAL_GRANT_RELATION_PROPERTIES_UNCHANGED')
    columns=rows(current,'columns'); fresh=[r for r in columns if r['name'] == CHILD_COLUMN]
    need(len(fresh) == 1 and fresh[0]['type'] == 'uuid' and fresh[0]['not_null'] is False
         and fresh[0]['default'] is None and not fresh[0]['identity'] and not fresh[0]['generated']
         and [r for r in columns if r['name'] != CHILD_COLUMN] == rows(old,'columns'),'ONLY_ONE_NULLABLE_UUID_CHILD_COLUMN')
    up=sql.split('-- +goose Down',1)[0]
    dropped=set(re.findall(r'ALTER TABLE\s+public\.capacity_mutation_grants\s+DROP CONSTRAINT(?: IF EXISTS)?\s+([a-z0-9_]+)',up))
    state_names=set(re.findall(r'ALTER TABLE\s+public\.capacity_mutation_grants\s+ADD CONSTRAINT\s+([a-z0-9_]+)\s+CHECK\s*\(',up))
    need(len(state_names) == 1 and state_names <= dropped,'ONE_SOURCE_NAMED_EXISTING_STATE_CHECK_REPLACEMENT')
    state=next(iter(state_names))
    a,b=rows(current,'constraints'),rows(old,'constraints')
    ac=[r for r in a if r['name'] == state];bc=[r for r in b if r['name'] == state]
    need(len(ac) == len(bc) == 1 and ac[0]['type'] == bc[0]['type'] == 'c' and ac[0]['validated'] is True,'ONE_VALIDATED_SOURCE_NAMED_STATE_CHECK')
    ar,br=copy.deepcopy(ac[0]),copy.deepcopy(bc[0]);definition=ar.pop('definition');previous=br.pop('definition')
    enum=", 'cleanup_closed'::text"
    need(definition.count(enum) == 1 and definition.count('cleanup_closed') == 1
         and 'cleanup_closed' not in previous and definition.replace(enum,'') == previous and ar == br,'ONLY_ONE_CLEANUP_CLOSED_ENUM_NO_OTHER_STATE_CHECK_CHANGE')
    new_constraints=set(re.findall(r'ALTER TABLE\s+public\.capacity_mutation_grants\s+ADD CONSTRAINT\s+([a-z0-9_]+)\s+FOREIGN KEY',up))
    extra=[r for r in a if r['name'] in new_constraints]
    need(len(extra) == len(new_constraints) == 1 and extra[0]['type'] == 'f'
         and extra[0]['definition'] == 'FOREIGN KEY (failed_unwitnessed_expansion_cleanup_id, id) REFERENCES capacity_failed_unwitnessed_expansion_cleanups(id, child_grant_id)'
         and [r for r in a if r['name'] not in new_constraints | state_names] == [r for r in b if r['name'] not in state_names],'ONLY_EXACT_CHILD_PAIR_FK_AND_STATE_CHECK_ALL_OTHER_GRANT_CONSTRAINTS_UNCHANGED')
    a,b=rows(current,'indexes'),rows(old,'indexes'); name='public.capacity_mutation_grants_open_slot_idx'
    ai=[r for r in a if r['name'] == name];bi=[r for r in b if r['name'] == name]
    need(len(ai) == len(bi) == 1,'ONE_ORIGINAL_OPEN_SLOT_INDEX')
    ar,br=ai[0],bi[0]; definition=ar.pop('definition'); previous=br.pop('definition')
    suffix=' AND (failed_unwitnessed_expansion_cleanup_id IS NULL)'
    need(definition.count(suffix) == 1 and definition.replace(suffix,'') == previous and ar == br
         and [r for r in a if r['name'] != name] == [r for r in b if r['name'] != name],'ONLY_TYPED_CHILD_EXEMPT_PARENT_OPEN_SLOT_INDEX_UNCHANGED')
    added_triggers=re.findall(r'CREATE TRIGGER ([a-z0-9_]+) .*? ON public\.([a-z0-9_]+).*? EXECUTE FUNCTION public\.([a-z0-9_]+)\(\);',up)
    actual=current['triggers'];names={x[0] for x in added_triggers}
    fresh=[r for r in actual if r['name'] in names]
    need(len(fresh) == len(added_triggers) and {(r['name'],r['table'],r['function'][len('public.'):] if r['function'].startswith('public.') else r['function']) for r in fresh} == {(name,'public.'+table,function+'()') for name,table,function in added_triggers}
         and all(r['enabled'] == 'O' for r in fresh)
         and [r for r in actual if r['name'] not in names] == old['triggers'], 'EXACT_SOURCE_NEW94_TRIGGERS_ALL_OLD_GRANT_TRIGGERS_UNCHANGED')
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

def check_intent_delta(current,old,sql):
    """M94 permits only its new intent latch trigger, never an old relation change."""
    table='public.capacity_intents'
    def rows(c,key):return [r for r in c[key] if r.get('table',r.get('name')) == table]
    need(len(rows(current,'tables')) == len(rows(old,'tables')) == 1,'ONE_RETAINED_CAPACITY_INTENTS_RELATION')
    for key in ('tables','columns','constraints','indexes'):
        need(rows(current,key) == rows(old,key),'ALL_OLD_INTENT_'+key.upper()+'_BYTE_EXACT')
    up=sql.split('-- +goose Down',1)[0]
    definitions=re.findall(r'CREATE TRIGGER ([a-z0-9_]+) (.*?) ON public\.capacity_intents(.*?) EXECUTE FUNCTION public\.([a-z0-9_]+)\(\);',up)
    need(len(definitions) == 1 and definitions[0][1] == 'BEFORE UPDATE'
         and definitions[0][2] == ' FOR EACH ROW' and definitions[0][3] == 'guard_failed_unwitnessed_expansion_cleanup_intent','ONLY_FINAL_SOURCE_INTENT_BEFORE_UPDATE_GUARD')
    name,_,_,function=definitions[0]
    new=[r for r in rows(current,'triggers') if r['name'] == name]
    definition='CREATE TRIGGER '+name+' BEFORE UPDATE ON public.capacity_intents FOR EACH ROW EXECUTE FUNCTION '+function+'()'
    need(len(new) == 1 and new[0]['enabled'] == 'O' and new[0]['function'] in (function+'()','public.'+function+'()')
         and new[0]['definition'] in (definition,definition.replace('EXECUTE FUNCTION ','EXECUTE FUNCTION public.',1))
         and [r for r in rows(current,'triggers') if r['name'] != name] == rows(old,'triggers'),'NEW_INTENT_GUARD_ONLY_ALL_OLD_TRIGGERS_UNCHANGED')


if __name__ == '__main__':
    try: main()
    except SystemExit: raise
    except Exception as caught:
        print(json.dumps({'status':'HOLD_BEFORE_COMPLETE_CUSTODY','error_class':type(caught).__name__,'automatic_retry':False}),flush=True)
        raise SystemExit(20) from None
