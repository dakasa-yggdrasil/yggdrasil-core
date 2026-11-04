#!/usr/bin/env python3
"""Inert one-Job Goose93 maintenance. No Core adoption or provider/Guest action.

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

SOURCE_BOUND = True
COMPANION_SOURCE_Q = 'ee8e3377ba91ff3efc3fde3a9751790608ac7066'
COMPANION_IMAGE_D = 'b0ee27bd53443260e8e05123f9474454e8108310c4b94a7e72b6bae107cf1ac2'
COMPANION_IMAGE_PROOF_SHA256 = 'edd13d137fd603303f559132d086249e4d7010a2d526cb100a64ab2eca1f0735'
SOURCE_CI_GATE_SHA256 = 'f5027f6108819d163b61258453702f81f4436bcb27c22fb066b15d3c79f8bf9a'
CAS_SOURCE_SHA256 = '436926ef24b64b4683b8bde5d8f6dbe79ef4c057f63b7883db47d2e22a3bf99f'
RUNTIME_MANIFEST_SHA256 = '7d82a9549ecc32dc9b219e1ad38490b48370b2996292c3252ef85c38d2e27dc1'
G11_RETURN_SHA256 = '1a0333b68e4232fb778d1d16b768935241d6babc2d8690e45600045a250d52fc'
BASELINE92_ACCEPTANCE_SHA256 = '0898cba85f5da361e984d9d4540f186c4a9c07c03ec5a4e27863b6cbf382ea1b'
S2_PREIMAGE_SHA256 = 'fe951731833749ce0dae96afc0b8c5bf4b0cb6d6dbe5cea2df2c4d23191d45e4'
CONFIG_SHA256 = '6966fc4d42696928e12b335990ab8f53da7bf65b8004829c81f36990346c403a'
JOB_UUID = '8389d8ac-2e6b-4f92-af6e-72f0edf958d9'
JOB_MANIFEST_SHA256 = '350b0918761cbc53876045186eecd7497f249b3a354a0860cef41f6064960171'
EXPECTED_RUNS = 20
EXPECTED_JOBS = 43
EXPECTED_CHECKS = frozenset(((126766760899, 'svc-doctor', 'completed', 'success'), (126766761547, 'original-http-transport', 'completed', 'success'), (126766761833, 'guest-pg-public-auth', 'completed', 'success'), (126766761943, 'native-cli-build', 'completed', 'success'), (126766761980, 'original-provider-source', 'completed', 'success'), (126766762286, 'host-factory-source-pg', 'completed', 'success'), (126766762453, 'source-contracts', 'completed', 'success'), (126766780293, 'Analyze (go)', 'completed', 'success'), (126766780712, 'Analyze (python)', 'completed', 'success'), (126766780811, 'Analyze (javascript-typescript)', 'completed', 'success'), (126766780860, 'Analyze (actions)', 'completed', 'success'), (126766802989, 'closed-administrative-boundary', 'completed', 'success'), (126766803518, 'capacity-owned-http', 'completed', 'success'), (126766803882, 'native-oidc-postgres', 'completed', 'success'), (126766804079, 'addons-smoke', 'completed', 'success'), (126766804195, 'native-cli-build', 'completed', 'success'), (126766804229, 'native-core-kind', 'completed', 'success'), (126766804312, 'focused-linux', 'completed', 'success'), (126766804584, 'unit-tests', 'completed', 'success'), (126766804641, 'exact-source-and-historical-proof', 'completed', 'success'), (126766804740, 'original-http-transport', 'completed', 'success'), (126766804757, 'lint', 'completed', 'success'), (126766804911, 'svc-doctor', 'completed', 'success'), (126766804917, 'source-contracts', 'completed', 'success'), (126766804933, 'lint', 'completed', 'success'), (126766804934, 'guest-pg-public-auth', 'completed', 'success'), (126766805071, 'HTTP maintenance disposition (PostgreSQL 16)', 'completed', 'success'), (126766805076, 'gate-regression', 'completed', 'success'), (126766805120, 'capacity-postgres', 'completed', 'success'), (126766805142, 'host-factory-source-pg', 'completed', 'success'), (126766805379, 'focused-linux', 'completed', 'success'), (126766805481, 'Scheduler skip Source kernel (PostgreSQL 17)', 'completed', 'success'), (126766805491, 'original-provider-source', 'completed', 'success'), (126766805725, 'reconcile', 'completed', 'success'), (126766805847, 'Scheduler skip Source kernel (PostgreSQL 16)', 'completed', 'success'), (126766805928, 'HTTP maintenance disposition (PostgreSQL 17)', 'completed', 'success'), (126766806243, 'focused-linux', 'completed', 'success'), (126766806495, 'signed-postgres-recovery', 'completed', 'success'), (126766806666, 'synthetic-resume-transaction', 'completed', 'success'), (126766807070, 'retirement-forward (17)', 'completed', 'success'), (126766807550, 'bounded-source-and-history (16)', 'completed', 'success'), (126766807630, 'retirement-forward (16)', 'completed', 'success'), (126766807684, 'bounded-source-and-history (17)', 'completed', 'success'), (126767253165, 'CodeQL', 'completed', 'success')))
EXPECTED_EXTRA_CHECKS = frozenset(((126767253165, 'CodeQL', 'completed', 'success'),))
REQUIRED_CI = frozenset((('Capacity intent PostgreSQL protocol', 'pull_request'), ('Capacity source-owned HTTP qualification', 'pull_request'), ('Context Freshness (ADR + durable context)', 'pull_request'), ('Docs freshness', 'pull_request'), ('Failed installed Guest administrative HTTP Source', 'pull_request'), ('Failed serving Guest Source and PostgreSQL', 'pull_request'), ('Guest historical unknown read recovery', 'pull_request'), ('Installed Guest reconciliation Source', 'pull_request'), ('Native OIDC protocol integration', 'pull_request'), ('Original Guest Core source and PostgreSQL gates', 'pull_request'), ('Original Guest Core source and PostgreSQL gates', 'push'), ('Original and native denied disposition Source', 'pull_request'), ('Owned Network Guardian', 'pull_request'), ('PR #139', 'dynamic'), ('Partial Guest native OFF reconciliation Source', 'pull_request'), ('Protected native capacity API qualification', 'pull_request'), ('Recorded HTTP maintenance disposition Source and PostgreSQL', 'pull_request'), ('Service contract', 'pull_request'), ('Service contract', 'push'), ('template-go-api CI', 'pull_request')))
CURRENT_OPS_P = '2366addce77900be34b3d98bf26348cff112863f'
CURRENT_CORE_R = 'ed5a5501db226c2fedcc4185474aae2698b5415d'
CURRENT_CORE_D = '8e6d44d86bbae4463652d4bf9b3583241483a0813a4d34c7254b9c2e56dccafc'
CURRENT_CORE_CONFIG = 'ef5ce9985258a837244f7753bb95f93baa2f72cc6da254c2ac03b425aec44a31'
GUARDIAN_S = '243fe177ed4be0ea7fe8be1e4472b1eee5c73db1cfd109c929cb297622959710'
AWS_OBSERVER_SOURCE = 'd8cbbf48873d24439216f98c30afe2669a525b54'
M93 = 'cc2b2843d14d4183ea68d25dbb9b9b58d1a353044e6ebf46ece6b93778e937e9'
LEGACY_CATALOG_SHA = 'c9d3664e43ef876a9a7a89c031bf75f761dbb0c70a664db2408058a6ce2431eb'
TRANSPORT_SHA = '9e2f8fe524331c9ea1c2f5742588977abe47d99b6ff635e88e431f343b96c004'
E70_SHA = 'e70f1bfc0821be5eaf44ec2248656da06ff269cfa57079ff487ae74f4cfe1054'
ROOT = Path('/var/lib/dakasa-core-rollout/goose93-settled-absence')
CLAIM = ROOT / 'GOOSE93-POSSIBLE-CREATE.json'
JOB_URI = '/apis/batch/v1/namespaces/dakasa/jobs'
DEP_URI = '/apis/apps/v1/namespaces/dakasa/deployments/yggdrasil'
RS_URI = '/apis/apps/v1/namespaces/dakasa/replicasets/yggdrasil-75ddcf9b8'
CORE_PODS_URI = '/api/v1/namespaces/dakasa/pods?labelSelector=app%3Dyggdrasil'
PREFIX = '153828470928.dkr.ecr.us-east-1.amazonaws.com/ghcr/dakasa-yggdrasil/yggdrasil-core@sha256:'
APP = 'yggdrasil-goose93-companion'
S2_INTENT = 'fd24881a-01ea-429c-a04c-13a738684ea5'
S2_FORWARD = '05192d81-bc0b-4076-9b06-766094240a9d'
S2_RUN = 'b3ba7554-034e-4c71-b712-5161711135f0'
S2_GRANT = 'd1ac8d0e-f38f-49eb-a5ab-17ed9204d979'
REPLACED = frozenset(('guard_retirement_forward','guard_retirement_forward_read','guard_retirement_forward_delete_binding'))
ADDED = frozenset(('retirement_forward_continuation_quiet','retirement_forward_continuation_valid'))
CHECKS93 = frozenset(('retirement_forward_mode93','retirement_forward_continuation93'))
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
            CAS_SOURCE_SHA256, RUNTIME_MANIFEST_SHA256, G11_RETURN_SHA256,
            BASELINE92_ACCEPTANCE_SHA256, S2_PREIMAGE_SHA256, CONFIG_SHA256, JOB_MANIFEST_SHA256)
    need(SOURCE_BOUND is True and source(COMPANION_SOURCE_Q) and all(digest(v) for v in pins)
         and COMPANION_SOURCE_Q not in (CURRENT_CORE_R, CURRENT_OPS_P)
         and COMPANION_IMAGE_D != CURRENT_CORE_D
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
    return 'core-goose93-' + uuid.UUID(JOB_UUID).hex

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
    need(not CLAIM.exists(), 'GLOBAL_GOOSE93_CLAIM_ABSENT_NEVER_REPLAY')
    body = wire(job)
    need(sha(body) == JOB_MANIFEST_SHA256, 'EXACT_ROOT_REVIEWED_JOB_BODY')
    need(api.get(JOB_URI + '/' + job_name(), absent=True) is None, 'NEW_UNIQUE_UUID_JOB_ABSENT')
    marker = {'schema': 'goose93_companion_job_possible_v1', 'source_Q': COMPANION_SOURCE_Q,
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
         and b'00093_guest_retirement_settled_absence_continuation.sql' in logs
         and b'successfully migrated database to version: 93' in logs, 'ORIGINAL_GOOSE93_LOG_COMPLETE_EXIT0')
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
         and roster['source'] == COMPANION_SOURCE_Q and len(roster['files']) == 92
         and sorted(r['version'] for r in roster['files'].values()) == [v for v in range(1, 94) if v != 40]
         and all(digest(r['sha256']) and type(r['bytes']) is int and r['bytes'] > 0 for r in roster['files'].values())
         and roster['files']['00093_guest_retirement_settled_absence_continuation.sql']['sha256'] == M93
         and cfg['migration93_sql']['sha256'] == M93, 'EXACT_QUALIFIED_IMAGE_SHIPPED_SQL_HEAD93')
    baseline = loads(reference(cfg['baseline92_acceptance']))
    need(cfg['baseline92_acceptance']['sha256'] == BASELINE92_ACCEPTANCE_SHA256
         and baseline['schema'] == 'root_goose92_independent_acceptance_v1'
         and baseline['reviewed_by_root'] is True
         and all(digest(baseline[k]) for k in ('complete_history_sha256', 'schema90_91_catalog_sha256', 'index92_definition_sha256')),
         'HISTORICAL_ROOT92_DATA_PROOF_NOT_CURRENT_RUNTIME_OR_NEW_ADMISSION_AUTHORITY')
    return baseline


def stable_metadata(value):
    return {k: v for k, v in value['metadata'].items() if k not in ('resourceVersion', 'managedFields')}


def core(api, expected):
    closed(expected, 'deployment_uid generation deployment_spec_sha256 deployment_metadata_sha256 replicaset_name replicaset_uid replicaset_spec_sha256 replicaset_metadata_sha256 pod_name pod_uid container_id container_started_at node_name pod_spec_sha256', 'CLOSED_ACTUAL_CORE14')
    need(expected['deployment_uid'] == 'a58ab8c2-da48-46c1-ae62-a650141eeb86'
         and expected['generation'] == 275 and expected['pod_uid'] == '39bca7e9-9c6d-4f45-8f66-346f9f58b562'
         and expected['replicaset_uid'] == '9c353ffa-63e5-48b6-97f6-efccb6d01b73'
         and expected['replicaset_name'] == RS_URI.rsplit('/', 1)[-1], 'ACTUAL_RETAINED_ED5_CORE_LIFETIME_NOT_R3_ADOPTION')
    dep, rs, pods = api.get(DEP_URI), api.get(RS_URI), api.get(CORE_PODS_URI)
    for label, obj in (('deployment', dep), ('replicaset', rs)):
        need(obj['metadata']['uid'] == expected[label + '_uid'] and not obj['metadata'].get('deletionTimestamp')
             and sha(wire(obj['spec'])) == expected[label + '_spec_sha256']
             and sha(wire(stable_metadata(obj))) == expected[label + '_metadata_sha256'], 'UNCHANGED_FULL_CORE_AND_RS_SPEC_STABLE_METADATA')
    need(dep['metadata']['generation'] == dep['status']['observedGeneration'] == 275
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
    need(manifest['source_commit'] == CURRENT_OPS_P and V.CORE_R == CURRENT_CORE_R
         and V.SOURCE_PIN == GUARDIAN_S and cut.C.NEW_DIGEST == CURRENT_CORE_D
         and len(manifest['protected_refs']) == 43, 'PHYSICAL_G11_NOT_FUTURE_OPS_OR_COMPANION_IMAGE')
    return V.g11_acceptance(cut, folder, manifest, returned, run)


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


S2_SQL = """SELECT jsonb_build_object(
'intent_pgtext',(SELECT intent::text FROM public.capacity_intents WHERE namespace='dakasa-production' AND environment='production' AND domain='notify' AND dimension='original_notify_aws_vm_members'),
'forwards',(SELECT COALESCE(jsonb_agg(to_jsonb(f) ORDER BY recorded_at,id,stage),'[]'::jsonb) FROM public.capacity_guest_retirement_forwards f WHERE retirement_request_id='fd24881a-01ea-429c-a04c-13a738684ea5'),
'failed_run',(SELECT to_jsonb(w) FROM public.workflow_runs w WHERE id='b3ba7554-034e-4c71-b712-5161711135f0'),
'dispatch',(SELECT jsonb_agg(to_jsonb(j) ORDER BY id) FROM public.capacity_dispatch_jobs j WHERE run_id='b3ba7554-034e-4c71-b712-5161711135f0'),
'delete_binding',(SELECT to_jsonb(b) FROM public.capacity_vm_retirement_delete_bindings b WHERE intent_id='fd24881a-01ea-429c-a04c-13a738684ea5'),
'destroy_grant',(SELECT to_jsonb(g) FROM public.capacity_mutation_grants g WHERE id='d1ac8d0e-f38f-49eb-a5ab-17ed9204d979'),
'forward_reads',(SELECT jsonb_build_object('rows',count(*),'prepared_absence',count(*) FILTER(WHERE kind='absence' AND stage='prepared'),'returned_absence',count(*) FILTER(WHERE kind='absence' AND stage='returned'),'sha256',encode(digest(COALESCE(jsonb_agg(to_jsonb(v) ORDER BY recorded_at,id,stage),'[]'::jsonb)::text,'sha256'),'hex')) FROM public.capacity_guest_retirement_forward_reads v WHERE retirement_request_id='fd24881a-01ea-429c-a04c-13a738684ea5'),
'last_absence',(SELECT to_jsonb(v) FROM public.capacity_guest_retirement_forward_reads v WHERE retirement_request_id='fd24881a-01ea-429c-a04c-13a738684ea5' AND kind='absence' AND stage='returned' ORDER BY recorded_at DESC,id DESC LIMIT 1),
'last_challenge',(SELECT to_jsonb(p) FROM public.capacity_guest_retirement_forward_reads p WHERE p.stage='prepared' AND p.id=(SELECT v.id FROM public.capacity_guest_retirement_forward_reads v WHERE v.retirement_request_id='fd24881a-01ea-429c-a04c-13a738684ea5' AND v.kind='absence' AND v.stage='returned' ORDER BY v.recorded_at DESC,v.id DESC LIMIT 1)),
'original_intent',(SELECT to_jsonb(i) FROM public.capacity_vm_retirement_intents i WHERE id='fd24881a-01ea-429c-a04c-13a738684ea5'),
'original_returns',(SELECT COALESCE(jsonb_agg(to_jsonb(v) ORDER BY sequence),'[]'::jsonb) FROM public.capacity_vm_retirement_original_returns v WHERE intent_id='fd24881a-01ea-429c-a04c-13a738684ea5'))"""


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


def wire_row(row):
    value = row['original_wire']
    need(type(value) is str and re.fullmatch(r'\\x(?:[0-9a-f]{2}){1,2097152}', value), 'ORIGINAL_PG_BYTEA_HEX')
    raw = bytes.fromhex(value[2:])
    need(sha(raw) == row['record_sha256'] and loads(raw) == row['original_record'], 'ORIGINAL_ROW_WIRE_SHA_AND_JSON_EQUAL')
    return raw


def stamp_ns(value):
    need(type(value) is str, 'ORIGINAL_TYPED_TIMESTAMP')
    match = re.fullmatch(r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d{1,9}))?(Z|[+-](?:[01]\d|2[0-3]):[0-5]\d)', value)
    need(match is not None, 'ORIGINAL_RFC3339_NANO_TIMEZONE')
    base, fraction, zone = match.groups()
    at = datetime.datetime.fromisoformat(base+('+00:00' if zone == 'Z' else zone))
    delta = at-datetime.datetime(1970,1,1,tzinfo=datetime.timezone.utc)
    return (delta.days*86400+delta.seconds)*1000000000+int((fraction or '').ljust(9,'0') or '0')


def pending_absence_valid(prepared_row, returned_row, admitted_row, grant_row, expected_observer_source):
    """Only the known AWS terminated/EBS-gone/ENI-pending original, not eligibility.

    Original records/clocks remain history. This creates no current absence,
    caller/process authority, admission or permission to repeat a native DELETE.
    """
    try:
        p_raw, r_raw, a_raw = wire_row(prepared_row), wire_row(returned_row), wire_row(admitted_row)
        p, r, a = loads(p_raw), loads(r_raw), loads(a_raw)
        closed(p,'schema read_id admission_id retirement_request_id kind admission_sha256 prefix_sha256 original_caller_sha256 mutation_binding_sha256 adapter_source_commit tuple destroy_grant_id issued_at_core original_deadline_core','EXACT_PREPARED_CORE_READ')
        need(prepared_row['stage'] == 'prepared' and returned_row['stage'] == 'returned'
             and prepared_row['kind'] == returned_row['kind'] == p['kind'] == 'absence'
             and prepared_row['id'] == returned_row['id'] == p['read_id']
             and prepared_row['admission_id'] == returned_row['admission_id'] == admitted_row['id'] == p['admission_id']
             and admitted_row['stage'] == a['stage'] == 'admitted'
             and prepared_row['retirement_request_id'] == returned_row['retirement_request_id'] == a['retirement_request_id'] == p['retirement_request_id']
             and p['schema'] == 'original_core_guest_retirement_forward_read_v1'
             and p['admission_sha256'] == admitted_row['record_sha256']
             and p['prefix_sha256'] == a['prefix_sha256'] and p['original_caller_sha256'] == a['original_caller_sha256']
             and digest(p['mutation_binding_sha256']) and p['tuple'] == a['original']['Request']['intent']['tuple'], 'EXACT_IMMUTABLE_CHALLENGE_ADMISSION_PREFIX_CALLER_TUPLE')
        closed(r,'schema read status observation original_destroy_receipt started_at_core original_returned_at_core call_failed original_context_failed observer_source_commit original_observer_return','EXACT_ACTUAL_CORE_RETURN')
        need(r['schema'] == 'original_core_guest_retirement_forward_read_return_v1' and r['read'] == p
             and raw_json_member(r_raw,'read') == p_raw and r['status'] == 'observed'
             and r['call_failed'] is False and r['original_context_failed'] is False, 'COMPLETE_ORIGINAL_CORE_READ_NO_FAILED_DIAGNOSTIC')
        issued, deadline = stamp_ns(p['issued_at_core']), stamp_ns(p['original_deadline_core'])
        started, ended = stamp_ns(r['started_at_core']), stamp_ns(r['original_returned_at_core'])
        need(0 < issued <= started <= ended < deadline and 0 < deadline-issued <= 5000000000
             and stamp_ns(returned_row['recorded_at']) >= stamp_ns(prepared_row['recorded_at']), 'ORIGINAL_FIVE_SECOND_CHALLENGE_AND_PG_RETURN_ORDER')
        g = grant_row['grant_record']; grant = g['grant']; settled = g['settlement']; binding = g['binding']
        need(grant_row['id'] == grant['grant_id'] == p['destroy_grant_id']
             and grant_row['state'] == grant['state'] == 'settled' and settled['outcome'] == 'accepted'
             and settled['transport_completed'] is True and settled['auxiliary_inventory_complete'] is True
             and all(grant_row[key] is None for key in ('original_disposition_id','failed_original_disposition_id','native_denied_disposition_id','enrolled_failed_disposition_id'))
             and grant.get('compensation_of','') == '' and p['tuple']['provider'] == 'aws'
             and p['tuple']['resource_id'] == grant['expected_resource_id'] == settled['resource_id']
             and p['tuple']['resource_created_at'] == grant['expected_resource_created_at'] == settled['resource_created_at']
             and p['tuple']['integration_instance_id'] == grant['integration_instance_id']
             and p['tuple']['scope_checksum'] == grant['scope_checksum'] and p['tuple']['profile'] == grant['profile_name']
             and p['adapter_source_commit'] == binding['original_provider_source_commit'], 'ORIGINAL_OWNING_UNDISPOSED_SETTLED_DELETE_TARGET_SCOPE')
        expected = {'grant':grant,'transport_completed':True}
        for key in ('attempt_id','outcome','resource_id','resource_created_at','action_id','next_action_ids','auxiliary_resources','auxiliary_inventory_complete'):
            value = g.get(key) if key == 'attempt_id' else settled.get(key)
            if value: expected[key] = value
        receipt = r['original_destroy_receipt']
        need(receipt == expected and len(receipt['auxiliary_resources']) == 2
             and [x['kind'] for x in receipt['auxiliary_resources']] == ['aws_ebs_volume','aws_network_interface']
             and all(type(x['id']) is str and x['id'] for x in receipt['auxiliary_resources']), 'EXACT_COMPLETE_OWNING_RECEIPT_AND_TWO_AUX_IDENTITIES')
        sdk = settled['original_provider_destroy_return']
        closed(sdk,'schema provider adapter_source_commit grant_id attempt_id request_sha256 resource_id resource_created_at action_id next_action_ids called_at returned_at context_deadline response_status response_body_sha256 response_bytes','CLOSED_ORIGINAL_SDK_TERMINATE_RETURN')
        need(sdk['schema'] == 'aws_original_terminate_instances_return_v1' and sdk['provider'] == 'aws'
             and sdk['adapter_source_commit'] == p['adapter_source_commit'] and source(sdk['adapter_source_commit'])
             and sdk['grant_id'] == grant['grant_id'] and sdk['attempt_id'] == g['attempt_id']
             and sdk['request_sha256'] == grant['request_sha256'] and sdk['resource_id'] == settled['resource_id']
             and sdk['resource_created_at'] == settled['resource_created_at'] and sdk['action_id'] == settled['action_id']
             and sdk['next_action_ids'] == [] and settled.get('next_action_ids',[]) == []
             and type(sdk['response_status']) is int and sdk['response_status'] == 200
             and digest(sdk['response_body_sha256']) and type(sdk['response_bytes']) is int and 2 <= sdk['response_bytes'] <= 2<<20,
             'EXACT_ORIGINAL_TERMINATE200_REQUEST_ATTEMPT_ACTION_AND_COMPLETE_BODY')
        called, returned, limit = stamp_ns(sdk['called_at']), stamp_ns(sdk['returned_at']), stamp_ns(sdk['context_deadline'])
        need(0 < called <= returned < limit and limit-called <= 60000000000, 'UNCHANGED_ORIGINAL_SDK_CONTEXT_RETURN')
        need(source(expected_observer_source) and expected_observer_source != p['adapter_source_commit']
             and r['observer_source_commit'] == expected_observer_source, 'ACTUAL_PUBLISHED_SEPARATE_OBSERVER_SOURCE')
        observed_raw = base64.b64decode(r['original_observer_return'],validate=True); observed = loads(observed_raw)
        closed(observed,'schema observer_source_commit original_adapter_source_commit read_id read_sha256 original_receipt_sha256 observation','CLOSED_ORIGINAL_READONLY_SEVEN_FIELD_RETURN')
        o = r['observation']
        need(observed['schema'] == 'original_settled_retirement_absence_read_return_v1'
             and observed['observer_source_commit'] == expected_observer_source
             and observed['original_adapter_source_commit'] == p['adapter_source_commit'] and observed['read_id'] == p['read_id']
             and observed['read_sha256'] == sha(p_raw) and observed['original_receipt_sha256'] == sha(raw_json_member(r_raw,'original_destroy_receipt'))
             and observed['observation'] == o, 'EXACT_RAW_CANONICAL_READ_RECEIPT_HASH_AND_NATIVE_DTO_JOIN')
        need(o['destroy_grant_id'] == grant['grant_id'] and o['destroy_grant_state'] == 'settled'
             and o['id'] == settled['resource_id'] and o['created_at'] == settled['resource_created_at']
             and o['original_outcome'] == 'accepted' and o['original_transport_completed'] is True
             and o['server_absent'] is True and o['server_absence_complete'] is True and o.get('server_status','') == ''
             and o['auxiliary_inventory_complete'] is True and o['billable_resources_absent'] is False and o['retirement_complete'] is False
             and o['hold_reasons'] == ['aws_network_interface_still_present'] and o['next_actions'] == []
             and o['delete_action'] == {'known':False,'observed':False} and o.get('compensation_of','') == ''
             and o['writer_quiescence_evidence'] is False and o['provider_fencing_evidence'] is False and o['invoice_reconciled'] is False
             and o.get('billing_exposure') is None, 'EXACT_KNOWN_TERMINATED_EBS_GONE_ENI_PENDING_NO_BUSINESS_AUTHORITY')
        life = o['aws_retirement_lifecycle']
        need(life['schema'] == 'aws_original_terminate_and_native_absence_v1' and life['request_id'] == settled['action_id']
             and life['ec2_state'] == 'terminated' and len(o['auxiliary_resources']) == 2, 'SAME_ORIGINAL_TERMINATE_REQUEST_NATIVE_LIFECYCLE')
        begin, server, finish = stamp_ns(o['observation_started_at']), stamp_ns(o['server_observed_at']), stamp_ns(o['observed_at'])
        need(0 < begin <= server <= finish and finish-begin <= 60000000000 and stamp_ns(life['observed_at']) == finish, 'ORIGINAL_NATIVE_OBSERVATION_CLOCKS_NOT_FRESHNESS_NOW')
        for index, item in enumerate(o['auxiliary_resources']):
            need(item['kind'] == receipt['auxiliary_resources'][index]['kind'] and item['id'] == receipt['auxiliary_resources'][index]['id']
                 and item['absent'] is (index == 0) and begin <= stamp_ns(item['observed_at']) <= finish, 'EXACT_TWO_OWNED_AUX_ABSENCE_OBSERVATIONS')
        return True
    except (Hold,KeyError,TypeError,ValueError,UnicodeError,OverflowError,IndexError,StopIteration):
        return False


def s2_valid(value):
    closed(value, 'intent_pgtext forwards failed_run dispatch delete_binding destroy_grant forward_reads last_absence last_challenge original_intent original_returns', 'CLOSED_ACTUAL_S2_PENDING_PREIMAGE')
    intent = loads(value['intent_pgtext']); grant = value['destroy_grant']; binding = value['delete_binding']
    need(intent['generation'] == 15 and intent['fencing_token'] == 33 and intent['phase'] == 'drained'
         and intent['retirement_forward']['id'] == S2_FORWARD and intent['retirement_forward']['stage'] == 'off_qualified'
         and value['failed_run']['id'] == S2_RUN and value['failed_run']['status'] == 'failed'
         and len(value['dispatch']) == 1 and value['dispatch'][0]['run_id'] == S2_RUN
         and value['dispatch'][0]['state'] == 'returned' and value['dispatch'][0]['return_status'] == 'failed'
         and value['failed_run']['finished_at'] == value['dispatch'][0]['returned_at']
         and value['dispatch'][0]['finalization_ack_at'] is not None, 'KNOWN_S2_ORIGINAL_FAILED_ACK_CURRENT_EPOCH_NOT_QUIET')
    need(grant['id'] == S2_GRANT and grant['state'] == 'settled'
         and all(grant[k] is None for k in ('original_disposition_id','failed_original_disposition_id','native_denied_disposition_id','enrolled_failed_disposition_id'))
         and grant['grant_record']['settlement']['outcome'] == 'accepted'
         and grant['grant_record']['settlement']['transport_completed'] is True
         and grant['grant_record']['settlement']['auxiliary_inventory_complete'] is True
         and binding['destroy_grant_id'] == S2_GRANT and binding['intent_id'] == S2_INTENT
         and binding['original_eligibility_record']['schema'] == 'original_guest_partial_poweroff_delete_eligibility_v1'
         and binding['original_eligibility_record']['admission_id'] == S2_FORWARD
         and {(r['id'], r['stage']) for r in value['forwards']} == {(S2_FORWARD,'admitted'),(S2_FORWARD,'off_qualified')}
         and len(value['forwards']) == 2, 'ONLY_ORIGINAL_SETTLED_S2_DELETE_NO_CHILD_OR_CONFIRM')
    authority = next(r for r in value['forwards'] if r['stage'] == 'admitted')
    need(value['forward_reads']['prepared_absence'] == value['forward_reads']['returned_absence'] > 0
         and digest(value['forward_reads']['sha256'])
         and pending_absence_valid(value['last_challenge'],value['last_absence'],authority,grant,AWS_OBSERVER_SOURCE)
         and stamp_ns(value['last_absence']['recorded_at']) <= stamp_ns(value['dispatch'][0]['returned_at'])
         and intent['lease_owner'] == authority['original_record']['lease_owner']
         and intent['lease_executor_id'] == authority['original_record']['executor_id'],
         'AUTHENTIC_ORIGINAL_FIVE_SECOND_S2_PENDING_PROVENANCE_NOT_CURRENT_ABSENCE')
    need(binding['original_eligibility_record']['admission_sha256'] == authority['record_sha256']
         and grant['generation'] == 15 and grant['grant_record']['fencing_token'] == 33
         and value['original_intent']['id'] == S2_INTENT and len(value['original_returns']) in (4,5), 'SAME_S2_IMMUTABLE_PREFIX_ELIGIBILITY_AND_OWNING_DELETE')


def database(V, cut, run, e70, baseline, label):
    result = {}
    for provider, key in (('aws','original_notify_aws_vm_members'),('hetzner','original_notify_hetzner_vm_members')):
        sql = e70['queries'][key]
        if provider == 'aws':
            actual = V.query(cut, run, label+'-AWS', "SELECT jsonb_build_object('guard',("+sql+"),'s2',("+S2_SQL+"))")
            value = actual['guard']; s2_valid(actual['s2'])
            need(actual['s2'] == baseline, 'SAME_WHOLE_S2_PREIMAGE_NOT_OLD_S3_DDEA_OR_F31')
        else:
            value = V.query(cut, run, label+'-HZ', sql)
        keys = ('jobs_busy','runs_busy','forward_unreturned_reads','live_unreturned_canaries')
        need(value['intent_count'] == 1 and all(type(value[k]) is int and value[k] == 0 for k in keys)
             and tuple(value[k] for k in ('intent_busy','pending_authority','forward_markers')) == ((1,1,1) if provider == 'aws' else (0,0,0)),
             'FULL_EIGHT_LANE_QUIET_EXCEPT_EXACT_KNOWN_S2_PENDING_OWNER')
        result[provider] = {k: value[k] for k in (*keys,'intent_count','intent_busy','pending_authority','forward_markers')}
    return result
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


def source_functions(sql):
    pattern = r'CREATE OR REPLACE FUNCTION public\.([a-z0-9_]+)\(([^)]*)\)\s+RETURNS\s+(boolean|trigger)\s+(.*?)\$\$(.*?)\$\$;'
    rows = {}
    for name, args, result, header, body in re.findall(pattern, sql, re.S):
        if name in REPLACED | ADDED:
            need(name not in rows, 'ONE_SOURCE_DEFINITION_PER_M93_FUNCTION')
            language = re.search(r'LANGUAGE\s+(sql|plpgsql)', header).group(1)
            rows[name] = {'arguments': ', '.join(' '.join(a.split()) for a in args.split(',')) if args else '',
                          'result':result,'language':language,'volatility':'s' if 'STABLE' in header else 'v',
                          'config':['timezone=UTC'] if "SET timezone='UTC'" in header else None,'body':body}
    need(set(rows) == REPLACED | ADDED, 'EXACT_FIVE_QUALIFIED_M93_FUNCTION_SOURCES')
    return rows


def catalog_projection(value):
    """Stable catalog identity; history, activity and ledger facts are separate."""
    v, s = value['legacy'], value['supplement']
    return {'catalog90': v['catalog90'], 'catalog91': v['catalog91'],
            **{key: s[key] for key in ('columns90_91','functions93','index92_valid','index92_definition')}}


def check_catalog(value, accepted, expected_functions, old=None):
    v, s = value['legacy'], value['supplement']; version = 92 if old is None else 93
    need(v['database'] == 'yggdrasil' and v['readonly'] == 'on'
         and v['latest_versions'] == [0]+[n for n in range(1,version+1) if n != 40]
         and v['rows90'] == v['rows91'] == 1
         and all(v[k] == 0 for k in ('other_migrators_ddl','other_cic','ddl_locks'))
         and s['index92_valid'] is True
         and sha(s['index92_definition'].encode()) == accepted['index92_definition_sha256'], 'EXACT_HISTORY_HEAD_AND_UNCHANGED_VALID_INDEX92_NO_OTHER_DDL')
    if old is None:
        need(sha(v['complete_history_wire'].encode()) == accepted['complete_history_sha256']
             and sha(wire({'catalog90':v['catalog90'],'catalog91':v['catalog91']})) == accepted['schema90_91_catalog_sha256']
             and {r['name'] for r in s['functions93']} == REPLACED, 'ACTUAL_ROOT_ACCEPTED_92_DATA_NO_PREEXISTING93_ADOPTION')
        return
    prior, current = loads(old['legacy']['complete_history_wire']), loads(v['complete_history_wire'])
    added = [r for r in current if r['version_id'] == 93]
    need(len(added) == 1 and added[0]['is_applied'] is True and len(current) == len(prior)+1
         and [r for r in current if r['version_id'] != 93] == prior
         and added[0]['id'] > max(r['id'] for r in prior), 'ONE_APPLIED93_ROW_ALL_PRIOR92_ROWS_UNCHANGED')
    need(s['columns90_91'] == old['supplement']['columns90_91']
         and s['old_records'] == old['supplement']['old_records']
         and v['catalog91'] == old['legacy']['catalog91'], 'ALL_OLD_COLUMNS_RECORDS_AND_ENTIRE91_CATALOG_UNCHANGED')
    a, b = copy.deepcopy(old['legacy']['catalog90']), copy.deepcopy(v['catalog90'])
    a['functions'] = [r for r in a['functions'] if r['name'] not in REPLACED]
    b['functions'] = [r for r in b['functions'] if r['name'] not in REPLACED]
    mode = [r for r in a['constraints'] if 'mode' in r['definition'] and 'actual_core_source' in r['definition']]
    fresh = [r for r in b['constraints'] if r['name'] in CHECKS93]
    need(len(mode) == 1 and len(fresh) == 2 and {r['name'] for r in fresh} == CHECKS93
         and all(r['validated'] is True and r['table'] == mode[0]['table'] for r in fresh), 'ONLY_EXACT_OLD_MODE_CHECK_REPLACED_TWO_NAMED93_CHECKS')
    a['constraints'] = [r for r in a['constraints'] if r not in mode]
    b['constraints'] = [r for r in b['constraints'] if r['name'] not in CHECKS93]
    need(a == b, 'ALL_OTHER_90_CATALOG_BYTES_TRIGGERS_READ_CAPS_INDEXES_CONSTRAINTS_UNCHANGED')
    need(len(s['functions93']) == 5 and {r['name'] for r in s['functions93']} == REPLACED | ADDED, 'EXACT_NEW_AND_REPLACED_FUNCTION_SET')
    for row in s['functions93']:
        actual = {k:row[k] for k in expected_functions[row['name']]}
        if actual['config'] is not None:
            # GUC names are case-insensitive; PostgreSQL may print TimeZone.
            # Keep each value and every body byte unchanged, including UTC.
            actual['config'] = [key.lower()+'='+value for key,value in (x.split('=',1) for x in actual['config'])]
        need(actual == expected_functions[row['name']], 'LITERAL_QUALIFIED_M93_FUNCTION_HEADER_AND_PROSRC_NO_NORMALIZATION')
    # Complete two named CHECK predicates are retained, not certified by substring
    # guessing. Root independently compares their actual definitions before93 acceptance.


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
    closed(cfg,'schema source_ci_acceptance companion_image_proof companion_sql_roster baseline92_acceptance runtime_package g11_return g11_cas_source transport_source core_preimage e70_sql_data s2_preimage migration93_sql legacy_catalog_sql','CLOSED_GOOSE93_CONFIG')
    need(cfg['schema'] == 'root_goose93_settled_absence_companion_config_v1','TYPED_NEW_MAINTENANCE_CASE_NO_ADMIN_ADMISSION')
    accepted = qualification(cfg)
    S = load_definitions(cfg['transport_source'],TRANSPORT_SHA,'reviewed_generic_job_mtls_transport')
    V = load_definitions(cfg['g11_cas_source'],CAS_SOURCE_SHA256,'reviewed_actual_g11_runtime_only')
    cut = V.load_tools(Path(cfg['runtime_package'])); C = cut.C
    folder, manifest = C.package(Path(cfg['runtime_package']),RUNTIME_MANIFEST_SHA256)
    need(cfg['g11_return']['sha256'] == G11_RETURN_SHA256,'ACTUAL_PHYSICAL_G11_RETURN')
    returned = loads(reference(cfg['g11_return'],32<<20))
    need(cfg['e70_sql_data']['sha256'] == E70_SHA and cfg['s2_preimage']['sha256'] == S2_PREIMAGE_SHA256,'EXACT_ORIGINAL_E70_AND_TYPED_S2_BASELINE')
    e70, baseline = loads(reference(cfg['e70_sql_data'])), loads(reference(cfg['s2_preimage']))
    s2_valid(baseline)
    need(cfg['legacy_catalog_sql']['sha256'] == LEGACY_CATALOG_SHA,'EXACT_LEGACY_CATALOG_SQL')
    legacy = reference(cfg['legacy_catalog_sql']).decode(); m93 = reference(cfg['migration93_sql']).decode()
    expected = source_functions(m93); sql = catalog_sql(legacy,V)
    job = job_manifest(); need(private_read(args.manifest) == wire(job) and sha(wire(job)) == JOB_MANIFEST_SHA256,'ACTUAL_ROOT_REVIEWED_EXTERNAL_JOB_BODY')
    C.shared_parent(ROOT.parent); C.private_dir(ROOT,create=not ROOT.exists()); run = args.evidence_dir.absolute()
    need(run.parent == ROOT and re.fullmatch('(?:migration93|reconcile93)-[a-f0-9-]{36}',run.name),'NEW_EXCLUSIVE_GOOSE93_EVIDENCE_LEAF')
    C.private_dir(run,create=True)
    try:
        with V.operation_lock():
            api = CapturedAPI(S.API(cut),C,run,not args.reconcile_get_only)
            if args.reconcile_get_only:
                marker = loads(C.read(CLAIM,32768,0o600))
                need(marker['schema'] == 'goose93_companion_job_possible_v1' and marker['source_Q'] == COMPANION_SOURCE_Q
                     and marker['companion_image_D'] == COMPANION_IMAGE_D and marker['current_ops_P'] == CURRENT_OPS_P
                     and marker['job_uuid'] == JOB_UUID and marker['manifest_sha256'] == JOB_MANIFEST_SHA256
                     and marker['config_sha256'] == CONFIG_SHA256 and marker['script_sha256'] == args.expected_script_sha256
                     and marker['automatic_retry'] is False,'EXACT_CONSUMED_JOB_CLAIM_GET_ONLY')
                uid,pod_uid,logs = observe_owned_job(api,job,S,None,deadline)
                result = {'schema':'goose93_reconcile_return_v1','status':'ORIGINAL_JOB_OBSERVED_ROOT_INDEPENDENT_ACCEPTANCE_PENDING',
                          'job_uid':uid,'pod_uid':pod_uid,'logs_sha256':logs,'POST_sent':False,'automatic_retry':False}
            else:
                need(not CLAIM.exists(),'GLOBAL_GOOSE93_CLAIM_ABSENT_NO_RESET')
                before_core, before_ones = core(api,cfg['core_preimage']), oneshots(cut)
                before_db = database(V,cut,run,e70,baseline,'BEFORE')
                before = run_catalog(cut,run,'BEFORE-CATALOG',sql); check_catalog(before,accepted,expected)
                gdir = run/'G11-BEFORE'; C.private_dir(gdir,create=True)
                _,refs,ctrl,guard,observed = runtime(V,cut,folder,manifest,returned,gdir)
                need(core(api,cfg['core_preimage']) == before_core and oneshots(cut) == before_ones,'SAME_CORE_AND_ONESHOTS_BEFORE_JOB')
                fresh = run_catalog(cut,run,'PRESEND-CATALOG',sql); check_catalog(fresh,accepted,expected)
                need(fresh == before and database(V,cut,run,e70,baseline,'PRESEND') == before_db
                     and time.monotonic()-observed <= 15 and deadline-time.monotonic() >= 420,'SAME_FULL_PREIMAGES_WITHIN_EXISTING_CURRENT15')
                signal.setitimer(signal.ITIMER_REAL,min(420,deadline-time.monotonic()))
                uid = create_once(api,C,run,job,CONFIG_SHA256,args.expected_script_sha256,deadline,observed)
                uid,pod_uid,logs = observe_owned_job(api,job,S,uid,min(deadline,time.monotonic()+420))
                after = run_catalog(cut,run,'AFTER-CATALOG',sql); check_catalog(after,accepted,expected,old=before)
                need(database(V,cut,run,e70,baseline,'AFTER') == before_db
                     and core(api,cfg['core_preimage']) == before_core and oneshots(cut) == before_ones,'SAME_CORE_S2_DEBT_GUARDS_AND_ONESHOTS_AFTER_JOB')
                gdir = run/'G11-AFTER'; C.private_dir(gdir,create=True)
                _,refs2,ctrl2,guard2,_ = runtime(V,cut,folder,manifest,returned,gdir)
                need((refs2,ctrl2,guard2) == (refs,ctrl,guard),'SAME_ALL43_REFS_BUDGET1_AND_CONTROLLER_GUARDIAN_LIFETIMES')
                result = {'schema':'goose93_companion_job_return_v1','status':'JOB_ACK_PLUS_OBSERVATIONS_ROOT_INDEPENDENT_ACCEPTANCE_PENDING',
                          'companion_source_Q':COMPANION_SOURCE_Q,'companion_image_D':COMPANION_IMAGE_D,'current_ops_P':CURRENT_OPS_P,
                          'current_Core_source':CURRENT_CORE_R,'current_Core_D':CURRENT_CORE_D,'job_uid':uid,'pod_uid':pod_uid,'exit_code':0,
                          'migration93_sha256':M93,'schema_before':92,'schema_after':93,'history93_sha256':sha(after['legacy']['complete_history_wire'].encode()),
                          'prior92_history_sha256':sha(before['legacy']['complete_history_wire'].encode()),'catalog93_sha256':sha(wire(catalog_projection(after))),
                          'catalog_delta':{'replaced_functions':sorted(REPLACED),'added_functions':sorted(ADDED),'replaced_old_mode_CHECK':1,'added_named_CHECKs':sorted(CHECKS93)},
                          'named_CHECK_predicates_Root_review_pending':True,'logs_sha256':logs,'native_create_attempts':1,
                          'Core_G11_all43_budget1_Cold_Hub_and_old_records_unchanged':True,'ordinary_quiet_or_business_authority_claimed':False,
                          'provider_Guest_Core_mutations_sent':0,'automatic_retry_down_cleanup_or_repair':False}
            C.once(run/'RETURN.PUBLIC.json',wire(result)); signal.setitimer(signal.ITIMER_REAL,0)
            print(wire(result).decode(),end='',flush=True)
    except BaseException as caught:
        signal.setitimer(signal.ITIMER_REAL,0)
        result = {'schema':'goose93_companion_hold_v1','status':'HOLD_UNKNOWN_RECONCILE_GET_ONLY_NO_REPLAY','possible_send':CLAIM.exists(),
                  'error_class':type(caught).__name__,'guard':str(caught) if isinstance(caught,Hold) and re.fullmatch('[A-Z0-9_]{1,160}',str(caught)) else 'INCOMPLETE_OR_INCONSISTENT_OBSERVATION','automatic_retry':False}
        C.once(run/'HOLD.PUBLIC.json',wire(result)); print(wire(result).decode(),end='',flush=True)
        raise SystemExit(20) from None


if __name__ == '__main__':
    try: main()
    except SystemExit: raise
    except Exception as caught:
        print(json.dumps({'status':'HOLD_BEFORE_COMPLETE_CUSTODY','error_class':type(caught).__name__,'automatic_retry':False}),flush=True)
        raise SystemExit(20) from None
