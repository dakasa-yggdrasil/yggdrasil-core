#!/usr/bin/env python3
"""Prepared operational scratch. One Core image PATCH after actual G8 acceptance.

No action on import. No test, rollout retry, rollback, reset, policy or provider
operation. Full API evidence stays on the Brain in a root-private directory.
The sole stdout result is a selected public projection, never an env/spec dump.
"""
import argparse
import base64
import contextlib
import copy
import datetime
import fcntl
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import signal
import ssl
import stat
import sys
import time
import types


CORE_R = 'd451ac07c6e412bd2eae06f648935799e046ea31'
OLD_SOURCE = 'c9f260432ce5a10886df0385c958ec7d643648df'
SOURCE_PIN = '8259638127d811079d6a461d3bd7407f8a53ff3ebb75e8061bf8538dcf6508b9'
UID = 'a58ab8c2-da48-46c1-ae62-a650141eeb86'
OLD_POD = '390538cb-9f9a-4de4-a607-77f618c40184'
GENERATION = 271
DEP_URI = '/apis/apps/v1/namespaces/dakasa/deployments/yggdrasil'
PODS_URI = '/api/v1/namespaces/dakasa/pods?labelSelector=app%3Dyggdrasil'
KUBECONFIG = Path('/etc/rancher/k3s/k3s.yaml')
ROOT = Path('/var/lib/dakasa-core-rollout/g8pair')
OPLOCK = Path('/var/lib/dakasa-capacity-network-r13-cutover/operation.lock')
TOOL_PINS = {'derive_g8pair_controller_config.py': '9fb3d8bff6f4d930ba23040b7e1bd27fabaff82e6ae4772c80eb49cca76bae7c',
 'derive_standing_config.py': '3c0a0d4a9b881d7289dd69b23fcd81d1b15446756c65e9f27a9c7ff654ce3df6',
 'g8cut.py': '53c25db74382d12b31de0049ec051077aec38c5ad381256f5227ddd3e439ab72',
 'pair_change_contract.py': '077fabdf4c359180499e839aba6a1aeb91590f0b2b588ae3d59978cfb8542b05'}
EXPECTED_INHERITED_REFS = {'/var/lib/dakasa-capacity-network-recovery/100b6c2d207cb8e39a6b52839c7cddca65bd8e0dde90f86386cf57e686d05a92-ORIGINAL-CLOSING.JSONL': '42b5834830c09b9c4b044171c69c7c2d9d4aabe68223c4bbbc887162d3b61991',
 '/var/lib/dakasa-capacity-network-recovery/100b6c2d207cb8e39a6b52839c7cddca65bd8e0dde90f86386cf57e686d05a92-ORIGINAL-PREFIX.JSONL': '6240b7f21932747366be7ce5ce6778559b3a5b63594c6d521ba7c2ab293d55ca',
 '/var/lib/dakasa-capacity-network-recovery/100b6c2d207cb8e39a6b52839c7cddca65bd8e0dde90f86386cf57e686d05a92-QUALIFIED.PUBLIC.json': '21e4697326aa0e74b1e169a897870b10e4668328ca04d497900a2f297bc99a31',
 '/var/lib/dakasa-capacity-network-recovery/16318aeaf6613083dbbfa093d40e5c48e5a1704d41563a9b69e8fc47032f2af0-ORIGINAL-START-CALLER.PUBLIC.json': '0b6123e439384db4c8a484bc6d892269430ad1d0ef5a86a4897863835cfc19c1',
 '/var/lib/dakasa-capacity-network-recovery/2b7e9be2-e45a-4cd5-86f2-6f0a3372576d-GUARDIAN-651c798b400048929e705c00f8185931-FIRST-CURRENT15-READ-000.PUBLIC': 'b4e72700d714bafa9a32615b17c77891beb947d43d4513aadc5e933894cff731',
 '/var/lib/dakasa-capacity-network-recovery/2b7e9be2-e45a-4cd5-86f2-6f0a3372576d-GUARDIAN-651c798b400048929e705c00f8185931-FIRST-CURRENT15-READ-001.PUBLIC': 'b4e72700d714bafa9a32615b17c77891beb947d43d4513aadc5e933894cff731',
 '/var/lib/dakasa-capacity-network-recovery/2b7e9be2-e45a-4cd5-86f2-6f0a3372576d-GUARDIAN-651c798b400048929e705c00f8185931-FIRST-CURRENT15-READ-002.PUBLIC': 'b4e72700d714bafa9a32615b17c77891beb947d43d4513aadc5e933894cff731',
 '/var/lib/dakasa-capacity-network-recovery/2b7e9be2-e45a-4cd5-86f2-6f0a3372576d-GUARDIAN-651c798b400048929e705c00f8185931-FIRST-CURRENT15-READ-003.PUBLIC': 'a5ae600dbc46ec7147d2d9eebf6332d802b88fddd666a636c69100041e8f664c',
 '/var/lib/dakasa-capacity-network-recovery/2b7e9be2-e45a-4cd5-86f2-6f0a3372576d-GUARDIAN-651c798b400048929e705c00f8185931-FIRST-CURRENT15-READ-004.PUBLIC': 'eab45a8f8f3ffa517ff2f69ec34788aecad0c0fa13b75905416f170174ae832a',
 '/var/lib/dakasa-capacity-network-recovery/2b7e9be2-e45a-4cd5-86f2-6f0a3372576d-GUARDIAN-651c798b400048929e705c00f8185931-FIRST-CURRENT15-READ-005.PUBLIC': '0c0c38cb4f58bc74626a88f11cb1d2fa9a99cf7914c8ecc8d07fdd76e48a49e4',
 '/var/lib/dakasa-capacity-network-recovery/2b7e9be2-e45a-4cd5-86f2-6f0a3372576d-GUARDIAN-651c798b400048929e705c00f8185931-FIRST-CURRENT15-READ-006.PUBLIC': '9ad05fe413a30ab815daf199bad5affa8f5333adac0533e9f1adfeb61fbe475e',
 '/var/lib/dakasa-capacity-network-recovery/2b7e9be2-e45a-4cd5-86f2-6f0a3372576d-GUARDIAN-651c798b400048929e705c00f8185931-FIRST-CURRENT15-READ-007.PUBLIC': '33ec2a8b760fc8be311d5c8c11677e06a4c5c23e4c9715838b43dbc1934e730a',
 '/var/lib/dakasa-capacity-network-recovery/2b7e9be2-e45a-4cd5-86f2-6f0a3372576d-GUARDIAN-651c798b400048929e705c00f8185931-FIRST-CURRENT15-READ-008.PUBLIC': '0e67570f63931bf4cd8e6a8c25adfa2d49e1c83778e0ea8ae37a83079a45524d',
 '/var/lib/dakasa-capacity-network-recovery/2b7e9be2-e45a-4cd5-86f2-6f0a3372576d-GUARDIAN-651c798b400048929e705c00f8185931-FIRST-CURRENT15-READ-009.PUBLIC': '3b15998a1dfdcc7694406b238ec922ee18ac0245a8e82db538d3ae79050b45eb',
 '/var/lib/dakasa-capacity-network-recovery/2b7e9be2-e45a-4cd5-86f2-6f0a3372576d-GUARDIAN-651c798b400048929e705c00f8185931-FIRST-CURRENT15-READ-010.PUBLIC': '7c57e0b8c8fde6b1e348f3529565c3db10de18730a3b0b0bf6c030a624d208e8',
 '/var/lib/dakasa-capacity-network-recovery/2b7e9be2-e45a-4cd5-86f2-6f0a3372576d-GUARDIAN-651c798b400048929e705c00f8185931-FIRST-CURRENT15-READ-011.PUBLIC': '444a9a7809645adb806965188d2acc66b4baac2ac3709f96dccd5c4b84d78882',
 '/var/lib/dakasa-capacity-network-recovery/2b7e9be2-e45a-4cd5-86f2-6f0a3372576d-GUARDIAN-651c798b400048929e705c00f8185931-FIRST-CURRENT15-READ-012.PUBLIC': '4a97f07c2a4c1a4093c4980916c5df080a6e6a03e374f1063b162464d4005a37',
 '/var/lib/dakasa-capacity-network-recovery/2b7e9be2-e45a-4cd5-86f2-6f0a3372576d-GUARDIAN-651c798b400048929e705c00f8185931-FIRST-CURRENT15-READ-013.PUBLIC': '56662ef0bd85f39ef3acd8b7a0f081bafdbca1dbdcc9e68de184762a16696018',
 '/var/lib/dakasa-capacity-network-recovery/2b7e9be2-e45a-4cd5-86f2-6f0a3372576d-GUARDIAN-651c798b400048929e705c00f8185931-FIRST-CURRENT15-READ-014.PUBLIC': 'b58c052f197a0c0965eec6f589ec6a98c1258799f0f0402f44a0255fcdd2f748',
 '/var/lib/dakasa-capacity-network-recovery/2b7e9be2-e45a-4cd5-86f2-6f0a3372576d-GUARDIAN-651c798b400048929e705c00f8185931-FIRST-CURRENT15-READ-015.PUBLIC': '87000b3e7b94475084db03fcd5ec687818aa1aac8c9506837670b0be546b47b8',
 '/var/lib/dakasa-capacity-network-recovery/2b7e9be2-e45a-4cd5-86f2-6f0a3372576d-GUARDIAN-651c798b400048929e705c00f8185931-FIRST-CURRENT15-READ-016.PUBLIC': '46c33d8621dc5a1a235ce881fea0ac167546a45fc0e9c3ff092b82247ec151b2',
 '/var/lib/dakasa-capacity-network-recovery/2b7e9be2-e45a-4cd5-86f2-6f0a3372576d-GUARDIAN-651c798b400048929e705c00f8185931-FIRST-CURRENT15-READ-017.PUBLIC': 'b8e78b562498ff7b0802089c1d3d7f8b3543f2eacc26b328039be98aa526c623',
 '/var/lib/dakasa-capacity-network-recovery/2b7e9be2-e45a-4cd5-86f2-6f0a3372576d-GUARDIAN-651c798b400048929e705c00f8185931-FIRST-CURRENT15-READ-018.PUBLIC': '5fbb03fb64fe747ff71f432939cb079b6167e10370656310f1933361f185ed31',
 '/var/lib/dakasa-capacity-network-recovery/2b7e9be2-e45a-4cd5-86f2-6f0a3372576d-GUARDIAN-651c798b400048929e705c00f8185931-FIRST-CURRENT15-READ-019.PUBLIC': '740d7d3f97947a82657fbc52fc5b88496b9ca124952c2361c4d8d5457f42dbd0',
 '/var/lib/dakasa-capacity-network-recovery/2b7e9be2-e45a-4cd5-86f2-6f0a3372576d-GUARDIAN-651c798b400048929e705c00f8185931-FIRST-CURRENT15-READ-020.PUBLIC': 'b4e72700d714bafa9a32615b17c77891beb947d43d4513aadc5e933894cff731',
 '/var/lib/dakasa-capacity-network-recovery/2b7e9be2-e45a-4cd5-86f2-6f0a3372576d-GUARDIAN-651c798b400048929e705c00f8185931-FIRST-CURRENT15-READ-021.PUBLIC': 'a5ae600dbc46ec7147d2d9eebf6332d802b88fddd666a636c69100041e8f664c',
 '/var/lib/dakasa-capacity-network-recovery/2b7e9be2-e45a-4cd5-86f2-6f0a3372576d-GUARDIAN-651c798b400048929e705c00f8185931-FIRST-CURRENT15-READ-022.PUBLIC': 'eab45a8f8f3ffa517ff2f69ec34788aecad0c0fa13b75905416f170174ae832a',
 '/var/lib/dakasa-capacity-network-recovery/2b7e9be2-e45a-4cd5-86f2-6f0a3372576d-GUARDIAN-651c798b400048929e705c00f8185931-FIRST-CURRENT15-READ-023.PUBLIC': '0c0c38cb4f58bc74626a88f11cb1d2fa9a99cf7914c8ecc8d07fdd76e48a49e4',
 '/var/lib/dakasa-capacity-network-recovery/2b7e9be2-e45a-4cd5-86f2-6f0a3372576d-GUARDIAN-651c798b400048929e705c00f8185931-FIRST-CURRENT15-READ-024.PUBLIC': '9ad05fe413a30ab815daf199bad5affa8f5333adac0533e9f1adfeb61fbe475e',
 '/var/lib/dakasa-capacity-network-recovery/2b7e9be2-e45a-4cd5-86f2-6f0a3372576d-GUARDIAN-651c798b400048929e705c00f8185931-FIRST-CURRENT15-READ-025.PUBLIC': '33ec2a8b760fc8be311d5c8c11677e06a4c5c23e4c9715838b43dbc1934e730a',
 '/var/lib/dakasa-capacity-network-recovery/2b7e9be2-e45a-4cd5-86f2-6f0a3372576d-GUARDIAN-651c798b400048929e705c00f8185931-FIRST-CURRENT15-READ-026.PUBLIC': '0e67570f63931bf4cd8e6a8c25adfa2d49e1c83778e0ea8ae37a83079a45524d',
 '/var/lib/dakasa-capacity-network-recovery/2b7e9be2-e45a-4cd5-86f2-6f0a3372576d-GUARDIAN-651c798b400048929e705c00f8185931-FIRST-CURRENT15-READ-027.PUBLIC': '415c3f6a7adcc100d3e6c81a03bacad35a35adc5cb936f5f783a97b569bc991b',
 '/var/lib/dakasa-capacity-network-recovery/2b7e9be2-e45a-4cd5-86f2-6f0a3372576d-GUARDIAN-651c798b400048929e705c00f8185931-FIRST-CURRENT15-READ-028.PUBLIC': 'e85cdc89e63efa30a55bc82b76f12de66f67d1e80588278fde30b55a8e91e65f',
 '/var/lib/dakasa-capacity-network-recovery/2b7e9be2-e45a-4cd5-86f2-6f0a3372576d-GUARDIAN-651c798b400048929e705c00f8185931-FIRST-CURRENT15-READ-029.PUBLIC': 'b3b18ab331ab9a438fe5c5b68296f8d7a85b0cd3c3c611151c9dfdcae555cc5c',
 '/var/lib/dakasa-capacity-network-recovery/2b7e9be2-e45a-4cd5-86f2-6f0a3372576d-GUARDIAN-651c798b400048929e705c00f8185931-FIRST-CURRENT15-READ-030.PUBLIC': 'b4e72700d714bafa9a32615b17c77891beb947d43d4513aadc5e933894cff731',
 '/var/lib/dakasa-capacity-network-recovery/2b7e9be2-e45a-4cd5-86f2-6f0a3372576d-GUARDIAN-651c798b400048929e705c00f8185931-FIRST-CURRENT15-RETURN.PUBLIC.json': 'c7ea2e766170be89868bb3bad661b448bcda458d587137e40bd019dc3ab5dcee',
 '/var/lib/dakasa-capacity-network-recovery/2b7e9be2-e45a-4cd5-86f2-6f0a3372576d-RECOVERY-16318aeaf6613083dbbfa093d40e5c48e5a1704d41563a9b69e8fc47032f2af0-POSSIBLE-START.PUBLIC.json': 'c135e28d51f47fbe04cd4ad1ac2869e15e974043998df6a08c9a35e00d42a865',
 '/var/lib/dakasa-capacity-network-recovery/da4532e3a6d1391f2d25947f0a326e8c4c6a1e133c3fd40a9a0a54e69c194972-QUALIFIED.PUBLIC.json': '5ddec8e4df310b344a8066984066f207e9e63b781d923ec8c94b95437ebf6564',
 '/var/lib/dakasa-capacity-network-recovery/2b7e9be2-e45a-4cd5-86f2-6f0a3372576d-GUARDIAN-f75222a9f6ef4348842c653ebe3f1ac7-FIRST-CURRENT15-RETURN.PUBLIC.json': 'b98254514e5975fb2773212b912e9695b67f97a0fae5be152c3dde2934098931'}
CHANGE_CAUSE = ('Core qualified source ' + CORE_R + ' by immutable linux/amd64 manifest; independent post-rollout acceptance required') if isinstance(CORE_R,str) else None


class Hold(RuntimeError):
    pass


def need(ok, guard):
    if not ok:
        raise Hold(guard)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def read(path, cap=32 << 20, mode=None):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        a = os.fstat(fd)
        need(stat.S_ISREG(a.st_mode) and a.st_uid == 0 and a.st_nlink == 1
             and (stat.S_IMODE(a.st_mode) == mode if mode is not None else not stat.S_IMODE(a.st_mode) & 0o022), 'ROOT_PRIVATE_STABLE_INPUT')
        rows, size = [], 0
        while True:
            row = os.read(fd, min(65536, cap + 1 - size))
            if not row:
                break
            size += len(row)
            need(size <= cap, 'BOUNDED_INPUT')
            rows.append(row)
        b = os.fstat(fd)
        need((a.st_dev, a.st_ino, a.st_size, a.st_mtime_ns, a.st_ctime_ns) ==
             (b.st_dev, b.st_ino, b.st_size, b.st_mtime_ns, b.st_ctime_ns), 'UNCHANGED_FULL_INPUT')
        return b''.join(rows)
    finally:
        os.close(fd)


def load_tools(folder):
    for name, pin in TOOL_PINS.items():
        need(sha(read(folder / 'tools' / name)) == pin, 'EXACT_REVIEWED_G8_TOOL')
    path = folder / 'tools/g8cut.py'
    module = types.ModuleType('reviewed_g8cut_for_core_cas')
    module.__file__ = str(path)
    exec(compile(read(path), str(path), 'exec'), module.__dict__)
    return module


@contextlib.contextmanager
def operation_lock():
    fd = os.open(OPLOCK, os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        s = os.fstat(fd)
        need(stat.S_ISREG(s.st_mode) and s.st_uid == 0 and s.st_nlink == 1
             and stat.S_IMODE(s.st_mode) == 0o600, 'EXACT_EXISTING_OPERATION_MUTEX')
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield (s.st_dev, s.st_ino)
        current = OPLOCK.lstat()
        need((current.st_dev, current.st_ino) == (s.st_dev, s.st_ino), 'SAME_OPERATION_MUTEX_INODE')
    finally:
        os.close(fd)


class API:
    """Exactly one HTTP request per call; no redirects, reconnect or retry.

    Credentials are read only from the exact private kubeconfig and held in RAM.
    The client certificate/key are loaded through anonymous Linux memfd, never
    emitted, written to evidence, or passed as command arguments.
    """
    def __init__(self, cut):
        need(KUBECONFIG.lstat().st_uid == 0 and stat.S_IMODE(KUBECONFIG.lstat().st_mode) == 0o600
             and not KUBECONFIG.is_symlink(), 'EXACT_PRIVATE_K3S_KUBECONFIG')
        input_pin = sha(read(KUBECONFIG, 1 << 20, 0o600))
        raw = cut.native(cut.KUBE + ['config', 'view', '--minify', '--raw', '-o', 'json'], 8, 1 << 20)
        need(raw.returncode == 0 and sha(read(KUBECONFIG, 1 << 20, 0o600)) == input_pin, 'LOCAL_KUBECONFIG_STABLE_READ_ZERO')
        config = cut.C.loads(raw.stdout)
        need(len(config['clusters']) == len(config['users']) == len(config['contexts']) == 1, 'ONE_LOCAL_K3S_CONTEXT')
        cluster, user = config['clusters'][0]['cluster'], config['users'][0]['user']
        need(set(cluster) == {'server', 'certificate-authority-data'} and cluster['server'] == 'https://127.0.0.1:6443'
             and set(user) == {'client-certificate-data', 'client-key-data'}, 'EXACT_LOOPBACK_K3S_MTLS_NO_EXEC_TOKEN_OR_PROXY')
        ctx = ssl.create_default_context(cadata=base64.b64decode(cluster['certificate-authority-data'], validate=True).decode())
        cert = base64.b64decode(user['client-certificate-data'], validate=True)
        key = base64.b64decode(user['client-key-data'], validate=True)
        fd = os.memfd_create('core-cas-client-mtls', os.MFD_CLOEXEC)
        try:
            os.fchmod(fd, 0o600)
            material = memoryview(cert + b'\n' + key)
            while material:
                n = os.write(fd, material)
                need(n > 0, 'FULL_PRIVATE_MEMFD_WRITE')
                material = material[n:]
            ctx.load_cert_chain('/proc/self/fd/' + str(fd))
        finally:
            os.close(fd)
        self.context = ctx

    def request(self, method, uri, body=None):
        need(method in ('GET', 'PATCH') and uri.startswith('/'), 'CLOSED_K3S_METHOD')
        conn = http.client.HTTPSConnection('127.0.0.1', 6443, context=self.context, timeout=12)
        try:
            headers = {'Accept': 'application/json'}
            if method == 'PATCH':
                headers['Content-Type'] = 'application/json-patch+json'
            conn.request(method, uri, body=body, headers=headers)
            response = conn.getresponse()
            raw = response.read((16 << 20) + 1)
            need(len(raw) <= 16 << 20, 'BOUNDED_API_RESPONSE')
            return response.status, raw, {'audit_id': response.getheader('Audit-Id'), 'date': response.getheader('Date')}
        finally:
            conn.close()


def api_read(api, C, run, name, uri):
    status, raw, headers = api.request('GET', uri)
    C.once(run / (name + '.json'), raw)
    C.once(run / (name + '.HTTP.json'), C.wire({'status': status, **headers}))
    need(status == 200, 'READ_ONLY_API_GET_200_' + name)
    return C.loads(raw)


def core_before(d, ps, C):
    need(C.OLD_DIGEST == 'f809040367a1c6c9fea0e8f4b31486970f03ed68a979a5bdcd412ed95bd70dcb', 'EXACT_OLD_C9_AMD64')
    m, s = d['metadata'], d['status']
    need(d['apiVersion'] == 'apps/v1' and d['kind'] == 'Deployment' and m['namespace'] == 'dakasa'
         and m['name'] == 'yggdrasil' and m['uid'] == UID and m['generation'] == GENERATION
         and m['resourceVersion'].isdecimal() and not m.get('deletionTimestamp')
         and m['annotations']['dakasa.io/core-source-commit'] == OLD_SOURCE, 'EXACT_OLD_CORE_UID_GENERATION_SOURCE')
    need(d['spec'].get('replicas', 1) == 1 and s['observedGeneration'] == GENERATION
         and all(s.get(k) == 1 for k in ('readyReplicas', 'updatedReplicas', 'availableReplicas'))
         and s.get('unavailableReplicas', 0) == 0
         and [(v['name'], v['image']) for v in d['spec']['template']['spec']['containers']] == [('core', C.IMAGE_PREFIX + C.OLD_DIGEST)], 'EXACT_OLD_READY_SINGLE_CORE')
    need(len(ps['items']) == 1, 'ONE_OLD_CORE_POD')
    p = ps['items'][0]
    need(p['metadata']['uid'] == OLD_POD and not p['metadata'].get('deletionTimestamp')
         and p['status']['phase'] == 'Running' and len(p['status']['containerStatuses']) == 1
         and [(v['name'], v['image']) for v in p['spec']['containers']] == [('core', C.IMAGE_PREFIX + C.OLD_DIGEST)], 'EXACT_OLD_RUNNING_POD_TUPLE')
    c = p['status']['containerStatuses'][0]
    need(c['name'] == 'core' and c['ready'] is True and c['restartCount'] == 0 and c.get('state', {}).get('running')
         and c['imageID'].rsplit(':', 1)[-1] == C.OLD_DIGEST, 'EXACT_OLD_AMD64_IMAGEID_ZERO_RESTART')
    return {'deployment_uid': UID, 'generation': GENERATION, 'pod_uid': OLD_POD,
            'pod_name': p['metadata']['name'], 'pod_ip': p['status']['podIP'],
            'image': C.IMAGE_PREFIX + C.OLD_DIGEST, 'imageID': c['imageID'], 'containerID': c['containerID']}


def result_shape(before, after, C):
    expected_spec = copy.deepcopy(before['spec'])
    expected_spec['template']['spec']['containers'][0]['image'] = C.IMAGE_PREFIX + C.NEW_DIGEST
    need(after['apiVersion'] == before['apiVersion'] and after['kind'] == before['kind']
         and after['spec'] == expected_spec, 'FULL_SPEC_DIFF_ONLY_CORE_IMAGE')
    a, b = copy.deepcopy(before['metadata']), copy.deepcopy(after['metadata'])
    a['annotations']['dakasa.io/core-source-commit'] = CORE_R
    a['annotations']['kubernetes.io/change-cause'] = CHANGE_CAUSE
    for key in ('resourceVersion', 'generation', 'managedFields'):
        a.pop(key, None)
        b.pop(key, None)
    need(a == b and after['metadata']['uid'] == UID and after['metadata']['generation'] == GENERATION + 1,
         'ONLY_EXPLICIT_SOURCE_AND_CHANGE_CAUSE_METADATA_DIFF')


def database_preflight(cut, run):
    sql = """BEGIN READ ONLY;
SET LOCAL statement_timeout='8000ms';
SELECT jsonb_build_object('database',current_database(),'readonly',current_setting('transaction_read_only'),
'schema',(SELECT max(version_id) FROM goose_db_version WHERE is_applied),
'migration88_applied',(SELECT count(*) FROM goose_db_version WHERE version_id=88 AND is_applied),
'migration89_applied',(SELECT count(*) FROM goose_db_version WHERE version_id=89 AND is_applied),
'new_table_present',to_regclass('public.capacity_guest_failed_serving_disposals') IS NOT NULL,
'index89_valid',COALESCE((SELECT i.indisvalid AND i.indisready AND i.indislive AND NOT i.indisunique
 AND i.indrelid='public.workflow_runs'::regclass AND i.indnkeyatts=1 AND i.indnatts=1
 AND i.indpred IS NULL AND i.indexprs IS NULL AND a.amname='btree'
 AND pg_get_indexdef(i.indexrelid,1,false)='workflow_id'
 FROM pg_index i JOIN pg_class c ON c.oid=i.indexrelid JOIN pg_am a ON a.oid=c.relam
 WHERE i.indexrelid=to_regclass('public.workflow_runs_workflow_id_idx')),false),
'busy_jobs',(SELECT count(*) FROM public.capacity_dispatch_jobs WHERE realm='dakasa-production' AND environment='production' AND domain='notify' AND dimension IN('original_notify_aws_vm_members','original_notify_hetzner_vm_members') AND (state IN('queued','started','unknown') OR (state='returned' AND finalization_ack_at IS NULL))),
'busy_runs',(SELECT count(*) FROM (
 SELECT wr.id FROM public.manifests m JOIN public.workflow_runs wr ON wr.workflow_id=m.id
 WHERE m.kind='workflow' AND m.namespace='dakasa-production' AND m.name IN('notify-aws-elastic-capacity','notify-hetzner-elastic-capacity')
 AND (COALESCE(wr.status,'') NOT IN('succeeded','failed','cancelled') OR wr.finished_at IS NULL)
 UNION
 SELECT wr.id FROM public.workflow_runs wr
 WHERE wr.workflow_namespace='dakasa-production' AND wr.workflow_name IN('notify-aws-elastic-capacity','notify-hetzner-elastic-capacity')
 AND (COALESCE(wr.status,'') NOT IN('succeeded','failed','cancelled') OR wr.finished_at IS NULL)
 ) AS busy_run_ids),
'live_dimension_leases',(SELECT count(*) FROM public.capacity_intents WHERE namespace='dakasa-production' AND environment='production' AND domain='notify' AND dimension IN('original_notify_aws_vm_members','original_notify_hetzner_vm_members') AND (COALESCE(intent->>'lease_owner','')<>'' OR COALESCE(intent->>'lease_executor_id','')<>'' OR (intent->>'lease_expires_at')::timestamptz>clock_timestamp())),
'nonsteady_intents',(SELECT count(*) FROM public.capacity_intents WHERE namespace='dakasa-production' AND environment='production' AND domain='notify' AND dimension IN('original_notify_aws_vm_members','original_notify_hetzner_vm_members') AND (intent->>'lease_expires_at' IS NOT NULL OR coalesce((intent->>'recovery_only')::boolean,false) OR coalesce(intent->>'phase','') NOT IN('promoted','reconciled','reconciled_partial') OR coalesce(intent#>>'{original_notify_window,state}','original_returns_observed')<>'original_returns_observed')));
COMMIT;
"""
    # Values stay inside the already-running DB container; never echo its env.
    command = 'PGOPTIONS="-c default_transaction_read_only=on -c statement_timeout=8000" psql -X -q -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -d yggdrasil -At'
    result = cut.subprocess.run(cut.KUBE + ['-n', 'dakasa', 'exec', '-i', 'unified-database-0', '--', 'sh', '-c', command],
                                input=sql.encode(), stdout=cut.subprocess.PIPE, stderr=cut.subprocess.PIPE,
                                timeout=12, env={'PATH': '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C.UTF-8'})
    cut.C.once(run / 'DB-READONLY.stdout', result.stdout)
    cut.C.once(run / 'DB-READONLY.stderr', result.stderr)
    need(result.returncode == 0 and len(result.stdout) < 32768 and len(result.stderr) < 32768, 'BOUNDED_READONLY_DB_RETURN_ZERO')
    value = cut.C.loads(result.stdout)
    need(value == {'database':'yggdrasil','readonly':'on','schema':89,'migration88_applied':1,'migration89_applied':1,
                   'new_table_present':True,'index89_valid':True,'busy_jobs':0,'busy_runs':0,
                   'live_dimension_leases':0,'nonsteady_intents':0}, 'FRESH_SCHEMA89_VALID_INDEX_SCOPED_QUIET_STEADY_NO_LEASE')


def g8_acceptance(cut, folder, manifest, returned, run):
    C = cut.C
    need(set(returned) == {'schema', 'status', 'result', 'automatic_replay', 'Guest_or_Core_business_authority'}
         and returned['schema'] == 'g8_pair_swap_return_v1' and returned['status'] == 'CONFIG_SWAP_OK'
         and returned['automatic_replay'] is False and returned['Guest_or_Core_business_authority'] is False, 'ACTUAL_CLOSED_G8_SWAP_RETURN')
    result = returned['result']
    need(result['source_commit'] == manifest['source_commit'] and result['source_R'] == CORE_R and result['amd64_D'] == C.NEW_DIGEST
         and result['new_guardian_source_sha256'] == SOURCE_PIN and result['controller_config_sha256'] == C.HEAD_CONFIG_SHA
         and result['independent_current15'] is True and result['all_inherited_budget_and_original_refs_unchanged'] is True
         and result['Core_Cold_Hub_or_provider_mutation'] is False
         and all(v == 0 for v in result['conservative_per_role_gap_seconds'].values()), 'QUALIFIED_G8_RETURN_EXACT_P_R_D_AND_NO_ROLE_GAP')
    refs = manifest['protected_refs']
    need(len(refs) == len(EXPECTED_INHERITED_REFS) and len({r['path'] for r in refs}) == len(refs)
         and {r['path']:r['sha256'] for r in refs} == EXPECTED_INHERITED_REFS,
         'EXACT_ORIGINAL37_PLUS_ACTUAL_G7_FULL120_AND_OWN15_REFS')
    backend = cut.Backend(folder, manifest, '', run, {}, [], {})
    backend.files(successor=True)
    protected = backend.protected()
    C.once(run / 'PROTECTED-REFS-BEFORE.json', C.wire(protected))
    need(C.sha(C.read(C.NEW_STANDING, 32768, 0o600)) == result['standing_sha256'], 'EXACT_ACCEPTED_G8_STANDING')
    for key in ('controller', 'guardian'):
        C.identity(result[key])
    ctrl = cut.physical_identity(C.CTRL, cut.controller_argv(C.NEW_CONFIG))
    guard = cut.physical_identity(C.GUARD, cut.guardian_argv(C.NEW_SOURCE, SOURCE_PIN))
    need(ctrl == result['controller'] and guard == result['guardian'], 'SAME_ACCEPTED_G8_CONTROLLER_GUARDIAN')
    G = C.load_guardian(C.NEW_SOURCE, SOURCE_PIN)
    owner = G.Owner(SOURCE_PIN)
    full = owner.identity()
    need({k: full[k] for k in ctrl} == ctrl and owner.original_qualification_measurement(full) is not None, 'RECOMPUTED_ACTUAL_G8_FULL120_SAME_LIFETIME')
    full_path = C.LEDGER / (owner.key(full) + '-QUALIFIED.PUBLIC.json')
    own_path = C.LEDGER / (guard['boot_id'] + '-GUARDIAN-' + guard['InvocationID'] + '-FIRST-CURRENT15-RETURN.PUBLIC.json')
    for field, expected_path in (('actual_new_full120_ref', full_path), ('own_daemon_first_current15_ref', own_path)):
        ref = result[field]
        need(set(ref) == {'path', 'sha256'} and ref['path'] == str(expected_path)
             and C.sha(C.read(expected_path, 16 << 20, 0o600)) == ref['sha256'], 'SAME_G8_ACTUAL_ORIGINAL_QUALIFICATION_REF')
    own = C.loads(C.read(own_path, 16 << 20, 0o600))
    need(own['schema'] == 'Root_owning_finite512_current15_readonly_observation_v1' and own['source_sha256'] == SOURCE_PIN
         and own['standing_config_sha256'] == result['standing_sha256'] and own['identity'] == full
         and own['measurement']['qualified_15_seconds'] is True and own['measurement']['all_requested_rows_accounted_for'] is True
         and own['kernel']['all_four_backends_and_reverse_sources_positive'] is True, 'ACTUAL_G8_DAEMON_OWN15_NOT_ASSESSOR_SUBSTITUTE')
    observation, prefix, suffix, reads = owner.current15_readonly()
    # Raw observe() omits persist() envelope fields. Bind its real native
    # observation to the same authenticated Source/standing Owner instead.
    need(observation['identity'] == full and owner.sha == SOURCE_PIN
         and C.sha(owner.raw_config) == result['standing_sha256']
         and observation['measurement']['qualified_15_seconds'] is True
         and observation['measurement']['all_requested_rows_accounted_for'] is True
         and observation['kernel']['all_four_backends_and_reverse_sources_positive'] is True, 'FRESH_INDEPENDENT_CURRENT15_ALL_FOUR')
    C.once(run / 'FRESH-INDEPENDENT-CURRENT15-PREFIX.JSONL', prefix)
    C.once(run / 'FRESH-INDEPENDENT-CURRENT15-CLOSING.JSONL', suffix)
    C.once(run / 'FRESH-INDEPENDENT-CURRENT15.json', C.wire({'observation': observation, 'native_read_count': len(reads)}))
    return backend, protected, ctrl, guard, time.monotonic()


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--package', required=True, type=Path)
    p.add_argument('--expected-ops-source', required=True)
    p.add_argument('--expected-manifest-sha256', required=True)
    p.add_argument('--g8-swap-return', required=True, type=Path)
    p.add_argument('--expected-g8-swap-return-sha256', required=True)
    p.add_argument('--evidence-dir', required=True, type=Path)
    p.add_argument('--execute-core-image-cas-once', action='store_true', required=True)
    a = p.parse_args()
    need(os.geteuid() == 0 and sys.platform == 'linux', 'ROOT_LINUX_BRAIN_ONLY')
    folder = a.package.absolute()
    cut = load_tools(folder)
    C = cut.C
    folder, manifest = C.package(folder, a.expected_manifest_sha256)
    need(re.fullmatch('[a-f0-9]{40}', a.expected_ops_source) and a.expected_ops_source != '0' * 40
         and manifest['source_commit'] == a.expected_ops_source and manifest['files']['source/network_guardian.py'] == SOURCE_PIN
         and manifest['tools'] == TOOL_PINS, 'EXACT_QUALIFIED_P_AND_SOURCE_TOOLS')
    returned_path = a.g8_swap_return.absolute()
    need(returned_path.name == 'RETURN.json' and returned_path.parent.parent == ROOT
         and returned_path.parent.name.startswith('swap-once-'), 'EXACT_ACTUAL_G8_SWAP_RETURN_PATH')
    C.private_dir(returned_path.parent)
    raw_return = C.read(returned_path, 32 << 20, 0o600)
    need(C.digest(a.expected_g8_swap_return_sha256) and C.sha(raw_return) == a.expected_g8_swap_return_sha256, 'ROOT_REVIEWED_ACTUAL_G8_RETURN_SHA')
    need(not (returned_path.parent / 'HOLD.json').exists(), 'NO_G8_HOLD_ADOPTION')
    claim = C.loads(C.read(ROOT / ('SWAP-' + a.expected_manifest_sha256 + '-POSSIBLE.json'), 32768, 0o600))
    need(set(claim) == {'schema', 'manifest_sha256', 'old_controller', 'old_guardian', 'run', 'automatic_replay'}
         and claim['schema'] == 'g8_once_only_swap_claim_v1' and claim['manifest_sha256'] == a.expected_manifest_sha256
         and claim['old_controller'] == manifest['expected_controller_identity']
         and claim['old_guardian'] == manifest['expected_guardian_identity']
         and claim['run'] == str(returned_path.parent) and claim['automatic_replay'] is False,
         'ACTUAL_G8_GLOBAL_ONCE_CLAIM_BINDS_EXACT_MANIFEST_AND_RETURN_DIRECTORY')
    run = a.evidence_dir.absolute()
    need(run.parent == ROOT and re.fullmatch('core-image-cas-[A-Za-z0-9_-]{1,96}', run.name), 'CLOSED_NEW_CAS_EVIDENCE_DIRECTORY')
    C.private_dir(ROOT)
    C.private_dir(run, create=True)
    sent = False
    def interrupted(signum, _):
        raise Hold('SIGNAL_' + str(signum) + '_RECONCILE_NO_REPLAY')
    for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP, signal.SIGALRM):
        signal.signal(sig, interrupted)
    signal.alarm(120)
    try:
        with operation_lock() as inode:
            need(not (ROOT / ('CORE-IMAGE-F809-TO-' + C.NEW_DIGEST + '-POSSIBLE.json')).exists(), 'GLOBAL_ONCE_CLAIM_ALREADY_EXISTS_NO_REPLAY')
            api = API(cut)
            before = api_read(api, C, run, 'DEPLOYMENT-BEFORE', DEP_URI)
            pods = api_read(api, C, run, 'PODS-BEFORE', PODS_URI)
            old_tuple = core_before(before, pods, C)
            original = C.loads(C.read(returned_path.parent / 'BEFORE.json', 32 << 20, 0o600))
            need(original['core'] == old_tuple and original['controller'] == manifest['expected_controller_identity']
                 and original['guardian'] == manifest['expected_guardian_identity'], 'SAME_G8_ORIGINAL_CORE_AND_MANIFEST_LINEAGE')
            C.once(run / 'INPUTS.json', C.wire({'schema': 'core_image_cas_inputs_v1', 'at': now(), 'script_sha256': sha(read(__file__)),
                    'manifest_sha256': a.expected_manifest_sha256, 'G8_return_path': str(returned_path),
                    'G8_return_sha256': a.expected_g8_swap_return_sha256, 'ops_P': a.expected_ops_source, 'Core_R': CORE_R,
                    'actual_schema89_receipt_is_independent': True, 'operation_mutex_inode': list(inode),
                    'maintenance_mutex_held': False, 'external_admin_exclusion_claimed': False}))
            backend, protected, ctrl, guard, observed = g8_acceptance(cut, folder, manifest, C.loads(raw_return), run)
            need(original['protected_refs'] == protected, 'SAME_G8_39_REFS_AND_ONE_OF_THREE_BUDGET')
            patch = [
                {'op': 'test', 'path': '/metadata/uid', 'value': UID},
                {'op': 'test', 'path': '/metadata/resourceVersion', 'value': before['metadata']['resourceVersion']},
                {'op': 'test', 'path': '/metadata/generation', 'value': GENERATION},
                {'op': 'test', 'path': '/metadata/annotations', 'value': before['metadata']['annotations']},
                {'op': 'test', 'path': '/spec', 'value': before['spec']},
                {'op': 'replace', 'path': '/spec/template/spec/containers/0/image', 'value': C.IMAGE_PREFIX + C.NEW_DIGEST},
                {'op': 'add', 'path': '/metadata/annotations/dakasa.io~1core-source-commit', 'value': CORE_R},
                {'op': 'add', 'path': '/metadata/annotations/kubernetes.io~1change-cause', 'value': CHANGE_CAUSE},
            ]
            patch_wire = C.wire(patch)
            C.once(run / 'PATCH.json', patch_wire)
            status, raw, headers = api.request('PATCH', DEP_URI + '?dryRun=All&fieldManager=core-image-cas-once', patch_wire)
            C.once(run / 'SERVER-DRYRUN.json', raw)
            C.once(run / 'SERVER-DRYRUN.HTTP.json', C.wire({'status': status, **headers}))
            need(status == 200, 'SERVER_DRYRUN_200')
            result_shape(before, C.loads(raw), C)
            database_preflight(cut, run)
            fresh = api_read(api, C, run, 'DEPLOYMENT-FRESH-PRESEND', DEP_URI)
            fresh_pods = api_read(api, C, run, 'PODS-FRESH-PRESEND', PODS_URI)
            need(core_before(fresh, fresh_pods, C) == old_tuple and fresh['metadata']['resourceVersion'] == before['metadata']['resourceVersion']
                 and fresh['spec'] == before['spec'] and fresh['metadata']['annotations'] == before['metadata']['annotations'], 'UNCHANGED_FRESH_API_PREIMAGE_NO_REBASE')
            backend.files(successor=True)
            need(backend.protected() == protected
                 and cut.physical_identity(C.CTRL, cut.controller_argv(C.NEW_CONFIG)) == ctrl
                 and cut.physical_identity(C.GUARD, cut.guardian_argv(C.NEW_SOURCE, SOURCE_PIN)) == guard, 'SAME_ACCEPTED_G8_AUTHORITY_IMMEDIATELY_BEFORE_PATCH')
            current_lock = OPLOCK.lstat()
            need((current_lock.st_dev, current_lock.st_ino) == inode and time.monotonic() - observed <= 15, 'SAME_LOCK_AND_CURRENT15_COMPLETED_WITHIN15S')
            marker = {'schema': 'core_image_cas_possible_send_v1', 'at': now(), 'method': 'PATCH', 'uri': DEP_URI,
                      'deployment_uid': UID, 'generation': GENERATION, 'resourceVersion': before['metadata']['resourceVersion'],
                      'patch_sha256': C.sha(patch_wire), 'script_sha256': sha(read(__file__)),
                      'manifest_sha256': a.expected_manifest_sha256, 'G8_return_sha256': a.expected_g8_swap_return_sha256,
                      'evidence_dir': str(run), 'automatic_retry': False, 'effects_may_have_happened_after_this_marker': True}
            # Both files and both parent directories are durable before the call.
            C.once(ROOT / ('CORE-IMAGE-F809-TO-' + C.NEW_DIGEST + '-POSSIBLE.json'), C.wire(marker))
            C.once(run / 'POSSIBLE-SEND.json', C.wire(marker))
            need(time.monotonic() - observed <= 15, 'CURRENT15_STILL_FRESH_AFTER_DURABLE_MARKERS_NO_SEND')
            sent = True
            status, raw, headers = api.request('PATCH', DEP_URI + '?fieldManager=core-image-cas-once', patch_wire)
            C.once(run / 'PATCH-ACTUAL-RETURN.json', raw)
            C.once(run / 'PATCH-ACTUAL-RETURN.HTTP.json', C.wire({'status': status, **headers}))
            need(status == 200, 'ACTUAL_PATCH_NOT_ACKNOWLEDGED_200_RECONCILE_NO_RETRY')
            after = C.loads(raw)
            result_shape(before, after, C)
            result = {'schema': 'core_image_cas_return_v1', 'status': 'PATCH_ACKNOWLEDGED_ACCEPTANCE_PENDING',
                      'deployment_uid': UID, 'generation': after['metadata']['generation'], 'resourceVersion': after['metadata']['resourceVersion'],
                      'old_pod_uid': OLD_POD, 'Core_source': CORE_R, 'image': C.IMAGE_PREFIX + C.NEW_DIGEST,
                      'manifest_sha256': a.expected_manifest_sha256, 'G8_return_sha256': a.expected_g8_swap_return_sha256,
                      'patch_sha256': C.sha(patch_wire), 'automatic_retry': False, 'new_pod_readiness_proven': False,
                      'post_rollout_G8_and_E2E_acceptance_proven': False, 'evidence_dir': str(run)}
            C.once(run / 'RETURN.PUBLIC.json', C.wire(result))
        signal.alarm(0)
        print(C.wire(result).decode(), end='', flush=True)
    except Exception as error:
        # No API or service follow-up, even if the acknowledgement was lost.
        signal.alarm(0)
        C.once(run / 'HOLD.PUBLIC.json', C.wire({'schema': 'core_image_cas_hold_v1', 'error_class': type(error).__name__,
               'guard': str(error)[:160] if isinstance(error, (Hold, C.Hold)) else 'NATIVE_OR_EVIDENCE_FAILURE',
               'possible_send': sent, 'automatic_retry': False, 'actual_api_readback_required': sent}))
        print(C.wire({'status': 'HOLD', 'possible_send': sent, 'automatic_retry': False, 'evidence_dir': str(run)}).decode(), end='', flush=True)
        raise SystemExit(20)


if __name__ == '__main__':
    main()
