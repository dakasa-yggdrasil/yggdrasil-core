#!/usr/bin/env python3
"""Prepared operational scratch. One Core image PATCH after actual G10 acceptance.

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
import subprocess
import sys
import time
import types


PROPOSAL_BOUND = True
CORE_R = 'd7d7adcff71807e60b782f50c8473bbb5981b9c9'
OLD_SOURCE = 'c02512e9d11d29cad4e4ff67186602d3485d6fa3'
SOURCE_PIN = '4283341a25e1a9c344cdf564f06604f560c14a7dc7e3738039f17cb9ee3c9bb7'
UID = 'a58ab8c2-da48-46c1-ae62-a650141eeb86'
OLD_POD = '0b47fd47-7654-4f8b-8dca-204bc9bd9de6'
GENERATION = 273
DEP_URI = '/apis/apps/v1/namespaces/dakasa/deployments/yggdrasil'
PODS_URI = '/api/v1/namespaces/dakasa/pods?labelSelector=app%3Dyggdrasil'
KUBECONFIG = Path('/etc/rancher/k3s/k3s.yaml')
ROOT = Path('/var/lib/dakasa-core-rollout/g10pair')
OPLOCK = Path('/var/lib/dakasa-capacity-network-r13-cutover/operation.lock')
TOOL_PINS = {'pair_change_contract.py': '569f645a12675f49e88dcb6b9d710dadc3bf6c2154adda5954abb27b29d7e1db', 'derive_g10pair_controller_config.py': 'e685f255c02d13845439ce91515bb47238f433e420c7c0c097d433803e395e15', 'derive_standing_config.py': '26ac78a36c093723e9d188b021e904f05960e7c8312c568ff4cfdbc6a495d4b7', 'g10cut.py': 'a8479c7c03612616cddee67c965378e03ae764661883947a4bfab5541d6dc61f'}

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
    require_bound()
    for name, pin in TOOL_PINS.items():
        need(sha(read(folder / 'tools' / name)) == pin, 'EXACT_REVIEWED_G10_TOOL')
    path = folder / 'tools/g10cut.py'
    module = types.ModuleType('reviewed_g10cut_for_core_cas')
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
    need(C.OLD_DIGEST == '7f86e55cebd3dfcd3e1e027d8ddb573358ba8b42753348bfbda108bf6d39a0b6', 'EXACT_OLD_C025_AMD64')
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


def database_steady_preflight(cut, run):
    sql = """BEGIN READ ONLY;
SET LOCAL statement_timeout='8000ms';
SELECT jsonb_build_object('database',current_database(),'readonly',current_setting('transaction_read_only'),
'schema',(SELECT max(version_id) FROM goose_db_version WHERE is_applied),
'migration88_applied',(SELECT count(*) FROM goose_db_version WHERE version_id=88 AND is_applied),
'migration89_applied',(SELECT count(*) FROM goose_db_version WHERE version_id=89 AND is_applied),
'migration90_applied',(SELECT count(*) FROM goose_db_version WHERE version_id=90 AND is_applied),
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
    need(value == {'database':'yggdrasil','readonly':'on','schema':90,'migration88_applied':1,'migration89_applied':1,'migration90_applied':1,
                   'new_table_present':True,'index89_valid':True,'busy_jobs':0,'busy_runs':0,
                   'live_dimension_leases':0,'nonsteady_intents':0}, 'FRESH_SCHEMA90_VALID_INDEX_SCOPED_QUIET_STEADY_NO_LEASE')


def g10_acceptance(cut, folder, manifest, returned, run):
    C = cut.C
    need(set(returned) == {'schema', 'status', 'result', 'automatic_replay', 'Guest_or_Core_business_authority'}
         and returned['schema'] == 'g10_pair_swap_return_v1' and returned['status'] == 'CONFIG_SWAP_OK'
         and returned['automatic_replay'] is False and returned['Guest_or_Core_business_authority'] is False, 'ACTUAL_CLOSED_G10_SWAP_RETURN')
    result = returned['result']
    need(result['source_commit'] == manifest['source_commit'] and result['source_R'] == CORE_R and result['amd64_D'] == C.NEW_DIGEST
         and result['new_guardian_source_sha256'] == SOURCE_PIN and result['controller_config_sha256'] == C.HEAD_CONFIG_SHA
         and result['independent_current15'] is True and result['all_inherited_budget_and_original_refs_unchanged'] is True
         and result['Core_Cold_Hub_or_provider_mutation'] is False
         and all(v == 0 for v in result['conservative_per_role_gap_seconds'].values()), 'QUALIFIED_G10_RETURN_EXACT_P_R_D_AND_NO_ROLE_GAP')
    refs = manifest['protected_refs']
    need(len(refs) == len(required_protected_refs()) and len({r['path'] for r in refs}) == len(refs)
         and {r['path']:r['sha256'] for r in refs} == required_protected_refs(),
         'EXACT_INHERITED41_PLUS_ACTUAL_G9_FULL120_AND_OWN15_REFS')
    backend = cut.Backend(folder, manifest, '', run, {}, [], {})
    backend.files(successor=True)
    protected = backend.protected()
    C.once(run / 'PROTECTED-REFS-BEFORE.json', C.wire(protected))
    need(C.sha(C.read(C.NEW_STANDING, 32768, 0o600)) == result['standing_sha256'], 'EXACT_ACCEPTED_G10_STANDING')
    for key in ('controller', 'guardian'):
        C.identity(result[key])
    ctrl = cut.physical_identity(C.CTRL, cut.controller_argv(C.NEW_CONFIG))
    guard = cut.physical_identity(C.GUARD, cut.guardian_argv(C.NEW_SOURCE, SOURCE_PIN))
    need(ctrl == result['controller'] and guard == result['guardian'], 'SAME_ACCEPTED_G10_CONTROLLER_GUARDIAN')
    G = C.load_guardian(C.NEW_SOURCE, SOURCE_PIN)
    owner = G.Owner(SOURCE_PIN)
    full = owner.identity()
    need({k: full[k] for k in ctrl} == ctrl and owner.original_qualification_measurement(full) is not None, 'RECOMPUTED_ACTUAL_G10_FULL120_SAME_LIFETIME')
    full_path = C.LEDGER / (owner.key(full) + '-QUALIFIED.PUBLIC.json')
    own_path = C.LEDGER / (guard['boot_id'] + '-GUARDIAN-' + guard['InvocationID'] + '-FIRST-CURRENT15-RETURN.PUBLIC.json')
    for field, expected_path in (('actual_new_full120_ref', full_path), ('own_daemon_first_current15_ref', own_path)):
        ref = result[field]
        need(set(ref) == {'path', 'sha256'} and ref['path'] == str(expected_path)
             and C.sha(C.read(expected_path, 16 << 20, 0o600)) == ref['sha256'], 'SAME_G10_ACTUAL_ORIGINAL_QUALIFICATION_REF')
    own = C.loads(C.read(own_path, 16 << 20, 0o600))
    need(own['schema'] == 'Root_owning_finite512_current15_readonly_observation_v1' and own['source_sha256'] == SOURCE_PIN
         and own['standing_config_sha256'] == result['standing_sha256'] and own['identity'] == full
         and own['measurement']['qualified_15_seconds'] is True and own['measurement']['all_requested_rows_accounted_for'] is True
         and own['kernel']['all_four_backends_and_reverse_sources_positive'] is True, 'ACTUAL_G10_DAEMON_OWN15_NOT_ASSESSOR_SUBSTITUTE')
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
    require_bound()
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--package', required=True, type=Path)
    p.add_argument('--expected-ops-source', required=True)
    p.add_argument('--expected-manifest-sha256', required=True)
    p.add_argument('--g10-swap-return', required=True, type=Path)
    p.add_argument('--expected-g10-swap-return-sha256', required=True)
    p.add_argument('--evidence-dir', required=True, type=Path)
    p.add_argument('--execute-core-image-cas-once', action='store_true', required=True)
    a = p.parse_args()
    need(os.geteuid() == 0 and sys.platform == 'linux', 'ROOT_LINUX_BRAIN_ONLY')
    folder = a.package.absolute()
    cut = load_tools(folder)
    C = cut.C
    config, config_raw, sql = maintenance_inputs(C)
    folder, manifest = C.package(folder, a.expected_manifest_sha256)
    need(re.fullmatch('[a-f0-9]{40}', a.expected_ops_source) and a.expected_ops_source != '0' * 40
         and manifest['source_commit'] == a.expected_ops_source and manifest['files']['source/network_guardian.py'] == SOURCE_PIN
         and manifest['tools'] == TOOL_PINS, 'EXACT_QUALIFIED_P_AND_SOURCE_TOOLS')
    returned_path = a.g10_swap_return.absolute()
    need(returned_path.name == 'RETURN.json' and returned_path.parent.parent == ROOT
         and returned_path.parent.name.startswith('swap-once-'), 'EXACT_ACTUAL_G10_SWAP_RETURN_PATH')
    C.private_dir(returned_path.parent)
    raw_return = C.read(returned_path, 32 << 20, 0o600)
    need(C.digest(a.expected_g10_swap_return_sha256) and C.sha(raw_return) == a.expected_g10_swap_return_sha256, 'ROOT_REVIEWED_ACTUAL_G10_RETURN_SHA')
    need(not (returned_path.parent / 'HOLD.json').exists(), 'NO_G10_HOLD_ADOPTION')
    claim = C.loads(C.read(ROOT / ('SWAP-' + a.expected_manifest_sha256 + '-POSSIBLE.json'), 32768, 0o600))
    need(set(claim) == {'schema', 'manifest_sha256', 'old_controller', 'old_guardian', 'run', 'automatic_replay'}
         and claim['schema'] == 'g10_once_only_swap_claim_v1' and claim['manifest_sha256'] == a.expected_manifest_sha256
         and claim['old_controller'] == manifest['expected_controller_identity']
         and claim['old_guardian'] == manifest['expected_guardian_identity']
         and claim['run'] == str(returned_path.parent) and claim['automatic_replay'] is False,
         'ACTUAL_G10_GLOBAL_ONCE_CLAIM_BINDS_EXACT_MANIFEST_AND_RETURN_DIRECTORY')
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
            need(not (ROOT / ('CORE-IMAGE-7F86-TO-' + C.NEW_DIGEST + '-POSSIBLE.json')).exists(), 'GLOBAL_ONCE_CLAIM_ALREADY_EXISTS_NO_REPLAY')
            C.once(run / 'MAINTENANCE-INPUT.original.json', config_raw)
            api = API(cut)
            before = api_read(api, C, run, 'DEPLOYMENT-BEFORE', DEP_URI)
            pods = api_read(api, C, run, 'PODS-BEFORE', PODS_URI)
            old_tuple = core_before(before, pods, C)
            need(sha(C.wire(before['spec'])) == config['core_preimage']['spec_sha256']
                 and sha(C.wire(before['metadata']['annotations'])) == config['core_preimage']['annotations_sha256']
                 and old_tuple['containerID'] == config['core_preimage']['container_id'], 'EXACT_ROOT_CURRENT_FULL_CORE_PREIMAGE')
            original = C.loads(C.read(returned_path.parent / 'BEFORE.json', 32 << 20, 0o600))
            need(original['core'] == old_tuple and original['controller'] == manifest['expected_controller_identity']
                 and original['guardian'] == manifest['expected_guardian_identity'], 'SAME_G10_ORIGINAL_CORE_AND_MANIFEST_LINEAGE')
            C.once(run / 'INPUTS.json', C.wire({'schema': 'core_image_cas_inputs_v1', 'at': now(), 'script_sha256': sha(read(__file__)),
                    'manifest_sha256': a.expected_manifest_sha256, 'G10_return_path': str(returned_path),
                    'G10_return_sha256': a.expected_g10_swap_return_sha256, 'ops_P': a.expected_ops_source, 'Core_R': CORE_R,
                    'actual_schema92_receipt_is_independent': True, 'operation_mutex_inode': list(inode),
                    'maintenance_mutex_held': False, 'external_admin_exclusion_claimed': False}))
            need(original['protected_refs'] == required_protected_refs(), 'SAME_G10_43_REFS_AND_ONE_OF_THREE_BUDGET')
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
            database_known_child(cut, run, config, sql, 'BEFORE')
            fresh = api_read(api, C, run, 'DEPLOYMENT-FRESH-PRESEND', DEP_URI)
            fresh_pods = api_read(api, C, run, 'PODS-FRESH-PRESEND', PODS_URI)
            need(core_before(fresh, fresh_pods, C) == old_tuple and fresh['metadata']['resourceVersion'] == before['metadata']['resourceVersion']
                 and fresh['spec'] == before['spec'] and fresh['metadata']['annotations'] == before['metadata']['annotations'], 'UNCHANGED_FRESH_API_PREIMAGE_NO_REBASE')
            backend, protected, ctrl, guard, observed = g10_acceptance(cut, folder, manifest, C.loads(raw_return), run)
            need(original['protected_refs'] == protected, 'SAME_G10_43_REFS_AND_ONE_OF_THREE_BUDGET')
            backend.files(successor=True)
            need(backend.protected() == protected
                 and cut.physical_identity(C.CTRL, cut.controller_argv(C.NEW_CONFIG)) == ctrl
                 and cut.physical_identity(C.GUARD, cut.guardian_argv(C.NEW_SOURCE, SOURCE_PIN)) == guard, 'SAME_ACCEPTED_G10_AUTHORITY_IMMEDIATELY_BEFORE_PATCH')
            database_known_child(cut, run, config, sql, 'PRESEND')
            current_lock = OPLOCK.lstat()
            need((current_lock.st_dev, current_lock.st_ino) == inode and time.monotonic() - observed <= 15, 'SAME_LOCK_AND_CURRENT15_COMPLETED_WITHIN15S')
            marker = {'schema': 'core_image_cas_possible_send_v1', 'at': now(), 'method': 'PATCH', 'uri': DEP_URI,
                      'deployment_uid': UID, 'generation': GENERATION, 'resourceVersion': before['metadata']['resourceVersion'],
                      'patch_sha256': C.sha(patch_wire), 'script_sha256': sha(read(__file__)),
                      'manifest_sha256': a.expected_manifest_sha256, 'G10_return_sha256': a.expected_g10_swap_return_sha256,
                      'evidence_dir': str(run), 'automatic_retry': False, 'effects_may_have_happened_after_this_marker': True}
            # Both files and both parent directories are durable before the call.
            C.once(ROOT / ('CORE-IMAGE-7F86-TO-' + C.NEW_DIGEST + '-POSSIBLE.json'), C.wire(marker))
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
                      'manifest_sha256': a.expected_manifest_sha256, 'G10_return_sha256': a.expected_g10_swap_return_sha256,
                      'patch_sha256': C.sha(patch_wire), 'automatic_retry': False, 'new_pod_readiness_proven': False,
                      'post_rollout_G10_and_E2E_acceptance_proven': False, 'evidence_dir': str(run)}
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



# Root selected this exact image-only branch; actual fresh admission evidence
# remains a separately reviewed, SHA-pinned late input before any API.
ROOT_ROLLOUT_MODE = 'exact_known_held_child8b_image_maintenance'
# This successor remains inert until Root binds a qualified product image that
# actually supplies ADR0103. It is separate from the unchanged old held mode.
HTTP_MAINTENANCE_UPGRADE_BOUND = False
HTTP_MAINTENANCE_PRE91_QUERY_SHA256 = 'ef9cc17ac3551ecbb5dea4f73e866e1e7194c78e497f5599e9cd7b994fda3a7d'
HTTP_MAINTENANCE_HELD_IDENTITY = {
    'job_id': '9e6d3b13-b887-4822-9532-3c133d8df58f',
    'run_id': '51540911-1389-41b5-a8a4-5cc1b3ee7493',
    'realm': 'dakasa-production', 'environment': 'production', 'domain': 'notify',
    'dimension': 'original_notify_hetzner_vm_members',
    'error': 'capacity dispatch original context refused',
}
# Fixed original lineage only. Fresh history/catalog/slot snapshots and native
# clocks are supplied in a separately Root-reviewed, SHA-pinned private input.
HELD_ORIGINAL_IDENTITY = {'dimension': 'original_notify_aws_vm_members',
 'domain': 'notify',
 'environment': 'production',
 'executor_id': '5f35983a-b02f-4963-929c-1a12b0709afd',
 'fence': 28,
 'generation': 14,
 'historical_survivors': [{'frame_sha256': 'f21f4f241fd6e383c68e0a232207052d5db49fd6713921abafc541014d62e93a',
                           'publication_challenge_id': '201a1922-9f8b-46ce-a9c3-1e6dfec5eb22',
                           'publication_return_sha256': 'a1bdae09df3d9eaac6bd25662ca094c744adb939ed527bb1d68e7ad46611852a',
                           'read_challenge_id': 'a70975da-50bc-4842-879e-b864ee5c3890',
                           'read_return_sha256': 'ca356092656796b5e2f31702a29bbd86549b6631e6c47bea53b2858a119d0663',
                           'slot': 1},
                          {'frame_sha256': '618d6020861a5e9d2f6e213714789117408a11eaca3c867c56ee8014b9af7ebc',
                           'publication_challenge_id': '5168b453-72dc-4e30-b4e3-f3aee466651e',
                           'publication_return_sha256': '2985e3bcc84bb13165f2d5723d823c1ea42f8b6b238cdd61435d190883d00ed8',
                           'read_challenge_id': '9e053ef4-7cbf-4146-a027-72889c237ffd',
                           'read_return_sha256': 'c1410065bba7f85e7b9a13139f6fa8ff15bba6b23f2eb17cf16bf7bd87925308',
                           'slot': 2}],
 'intent_pgtext_sha256': '3c2791bd1ee7d8bdd6f303ce91ebc9e4d16d165bf9fc7fd609cfde14e95c60ee',
 'lease_owner': 'f28d3398-1a5f-4c03-8f1b-705259409015',
 'namespace': 'dakasa-production',
 'native_members': [{'create_grant_id': '12c1c3d8-3a7e-4180-8764-608fc3914468',
                     'enrollment_sha256': 'f2f714b3feb5c80de0708e06c39c6200a7a9b5ff44232378fb8d51fb5a7bd701',
                     'preregistration_id': '92786167-e141-415d-9b5b-7987bdcb0d29',
                     'resource_created_at': '2026-11-03T01:17:18Z',
                     'resource_id': 'i-070b5767a35c7f0d5',
                     'slot': 1,
                     'tags': {'Name': 'dakasa-notify-notify-aws-elastic-1',
                              'yggdrasil.io/intent': '12c1c3d8-3a7e-4180-8764-608fc3914468',
                              'yggdrasil.io/owner': 'elastic-production-20261021',
                              'yggdrasil.io/profile': 'notify-aws-elastic',
                              'yggdrasil.io/scope': 'kpvmd54niya4k5ncouun47xer55uh6zdud4bd427kfzyew5qicbq',
                              'yggdrasil.io/slot': '1',
                              'yggdrasil.io/spec': '7n7blmqyoyn4ykwmpqaxeyjb2eiheangclu7yqruldyckjzsx7yq'}},
                    {'create_grant_id': 'c4a84075-5dd9-4e4d-9366-80d8fba5f9ef',
                     'enrollment_sha256': 'b211aff85fe8a470b62ed94bc77999b8130433b2e78460d59904c66e7ddb6a35',
                     'preregistration_id': '81b839ef-c8fd-4661-a44b-5a05bc6cca34',
                     'resource_created_at': '2026-11-03T05:00:07Z',
                     'resource_id': 'i-0e1656927db62d75b',
                     'slot': 2,
                     'tags': {'Name': 'dakasa-notify-notify-aws-elastic-2',
                              'yggdrasil.io/intent': 'c4a84075-5dd9-4e4d-9366-80d8fba5f9ef',
                              'yggdrasil.io/owner': 'elastic-production-20261021',
                              'yggdrasil.io/profile': 'notify-aws-elastic',
                              'yggdrasil.io/scope': 'kpvmd54niya4k5ncouun47xer55uh6zdud4bd427kfzyew5qicbq',
                              'yggdrasil.io/slot': '2',
                              'yggdrasil.io/spec': '7n7blmqyoyn4ykwmpqaxeyjb2eiheangclu7yqruldyckjzsx7yq'}},
                    {'create_grant_id': '42a0690d-1e32-4024-96a8-94e1a2dbcd18',
                     'enrollment_sha256': '36d3b4e2f485ab35d20e7bf7d4d747cd48fe14aaa82b3d0c9d33ccda4729a1e7',
                     'preregistration_id': '20e58827-cfe9-403e-8e34-765547326927',
                     'resource_created_at': '2026-11-03T05:10:09Z',
                     'resource_id': 'i-0de5b9d0da65f9e93',
                     'slot': 3,
                     'tags': {'Name': 'dakasa-notify-notify-aws-elastic-3',
                              'yggdrasil.io/intent': '42a0690d-1e32-4024-96a8-94e1a2dbcd18',
                              'yggdrasil.io/owner': 'elastic-production-20261021',
                              'yggdrasil.io/profile': 'notify-aws-elastic',
                              'yggdrasil.io/scope': 'kpvmd54niya4k5ncouun47xer55uh6zdud4bd427kfzyew5qicbq',
                              'yggdrasil.io/slot': '3',
                              'yggdrasil.io/spec': '7n7blmqyoyn4ykwmpqaxeyjb2eiheangclu7yqruldyckjzsx7yq'}}],
 'native_tuple': {'provider': 'aws',
                  'resource_created_at': '2026-11-03T05:10:09Z',
                  'resource_id': 'i-0de5b9d0da65f9e93',
                  'slot': 3},
 'original_caller_sha256': '87b5e539413300eaf026ebc88c9a218cc14375bc797653bd32eaeee8caaebbc9',
 'original_frame_sha256': '58465dd3e2c68bc95a39545ba23ac4e8d296aa42065f915a6cee85df265edb55',
 'original_run_id': '43b1dbee-2d4b-43dc-ab93-8117fae6c3ab',
 'physical_profile': {'integration_instance_id': '143beb1c-ed53-4027-b11d-dcc49b35f571',
                      'profile_name': 'notify-aws-elastic',
                      'scope_checksum': '53eac1f78d4601c575a27528de7ee48f7b43fb23a0f811f35f5173825bb04083'},
 'policy_checksum': '59bf55ab6a5ac144bfee7f211022bd0a85074d54a146a28b30dc034f050629af',
 'policy_id': '6a6b1aed-f10c-42bc-8a6c-25a0f6e37cba',
 'preregistration_id': '20e58827-cfe9-403e-8e34-765547326927',
 'retirement_request_id': '376a7e86-905d-44dd-8583-c8fed2ecac1a',
 'schema': 'root_exact_held_partial_poweroff_image_rollout_v1',
 'workflow_checksum': 'ef0b83536632a6c86a157b56bc0ce22f4ff4b3ba446d12cd5f8154bf07e2da85',
 'workflow_id': '9bb4a35b-6eb4-4983-9133-73bd96cfea94'}
EXPECTED_CURRENT_G8_PROOF_REFS = {'/var/lib/dakasa-capacity-network-recovery/d323cc228bec43596ac73c99cc473298896b8f2d88b06219aa69a549633925b3-QUALIFIED.PUBLIC.json': '68f5b3bcd33a9ab8e1ad29f3fdbf52a83166b694b81f5bce474e2fe85afecce3', '/var/lib/dakasa-capacity-network-recovery/2b7e9be2-e45a-4cd5-86f2-6f0a3372576d-GUARDIAN-a1826878088e4dbaa5e7adfb67cba5c6-FIRST-CURRENT15-RETURN.PUBLIC.json': 'e406648a4ecd503ff8231e5fde8d6969a091fe9327c4e8e0927815eb929711c4'}

def required_protected_refs():
    require_bound()
    out = dict(EXPECTED_INHERITED_REFS)
    for rows in (EXPECTED_CURRENT_G8_PROOF_REFS, EXPECTED_CURRENT_G9_PROOF_REFS):
        for path, pin in rows.items():
            need(path not in out and re.fullmatch('[a-f0-9]{64}', str(pin)), 'NO_ORIGINAL_REF_REPLACEMENT')
            out[path] = pin
    need(len(out) == 43, 'EXACT_ROOT_ACCEPTED_43_REF_UNION')
    return out
def require_bound():
    need(PROPOSAL_BOUND is True and re.fullmatch('[a-f0-9]{40}', str(CORE_R)) and CORE_R != '0' * 40
         and re.fullmatch('[a-f0-9]{64}', str(SOURCE_PIN)) and SOURCE_PIN != '0' * 64
         and type(GENERATION) is int and GENERATION > 0 and full_id(OLD_POD)
         and type(TOOL_PINS) is dict and set(TOOL_PINS) == {'pair_change_contract.py', 'derive_g10pair_controller_config.py', 'derive_standing_config.py', 'g10cut.py'}
         and all(re.fullmatch('[a-f0-9]{64}', str(v)) and v != '0' * 64 for v in TOOL_PINS.values())
         and ROOT_ROLLOUT_MODE == 'exact_known_held_child8b_image_maintenance'
         and type(EXPECTED_CURRENT_G9_PROOF_REFS) is dict and len(EXPECTED_CURRENT_G9_PROOF_REFS) == 2
         and type(CONFIG_REF) is dict and type(SQL_DATA_REF) is dict,
         'G10_QUALIFIED_RELEASE_PACKAGE_CURRENT_PREIMAGES_NOT_BOUND')
    for ref in (CONFIG_REF, SQL_DATA_REF):
        need(set(ref) == {'path', 'sha256'} and type(ref['path']) is str and Path(ref['path']).is_absolute()
             and re.fullmatch('[a-f0-9]{64}', str(ref['sha256'])) and ref['sha256'] != '0' * 64, 'CLOSED_LATE_INPUT_REF')
    need(SQL_DATA_REF['sha256'] == POLICY92_SQL_SHA, 'EXACT_E70_EIGHT_TERMINAL_M92_SQL_DATA')
def full_id(value):
    return type(value) is str and re.fullmatch('[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}', value) is not None


def digest_value(value):
    return type(value) is str and re.fullmatch('[0-9a-f]{64}', value) is not None and value != '0' * 64


def utc_time(value):
    need(type(value) is str and re.fullmatch('[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:[.][0-9]{1,9})?Z', value) is not None, 'EXPLICIT_CANONICAL_UTC_CLOCK')
    # datetime on Python3.9 accepts six fractional digits; preserve the raw wire.
    normalized = re.sub(r'\.([0-9]{1,9})Z$', lambda m: '.' + (m[1] + '000000')[:6] + 'Z', value)
    return datetime.datetime.fromisoformat(normalized[:-1] + '+00:00')


def evidence_ref(value):
    need(type(value) is dict and set(value) == {'path', 'sha256'} and digest_value(value['sha256']), 'CLOSED_ACTUAL_ROOT_EVIDENCE_REFERENCE')
    path = Path(value['path']) if type(value['path']) is str else Path('.')
    need(path.is_absolute() and path.parent != path and '..' not in path.parts
         and str(path).startswith('/var/lib/dakasa-core-rollout/'), 'ROOT_PRIVATE_ROLLOUT_EVIDENCE_PATH')
    return value


def validate_held_original(value):
    keys = {'schema','namespace','environment','domain','dimension','preregistration_id','retirement_request_id','original_run_id',
            'policy_id','policy_checksum','workflow_id','workflow_checksum','generation','fence','lease_owner','executor_id',
            'intent_pgtext_sha256','original_frame_sha256','original_caller_sha256','native_tuple','Root_review_ref',
            'history','catalog','physical_profile','native_members','historical_survivors','native_observation_ref'}
    need(type(value) is dict and set(value) == keys and value['schema'] == 'root_exact_held_partial_poweroff_image_rollout_v1', 'CLOSED_HELD_IMAGE_ROLLOUT_ADMISSION')
    need((value['namespace'],value['environment'],value['domain'],value['dimension'],value['generation'],value['fence'])
         == ('dakasa-production','production','notify','original_notify_aws_vm_members',14,28), 'ONE_ORIGINAL_AWS_S3_EPOCH_ONLY')
    for key in ('preregistration_id','retirement_request_id','original_run_id','policy_id','workflow_id','lease_owner','executor_id'):
        need(full_id(value[key]), 'FULL_ORIGINAL_IDS_NOT_PREFIX_SELECTORS')
    for key in ('policy_checksum','workflow_checksum','intent_pgtext_sha256','original_frame_sha256','original_caller_sha256'):
        need(digest_value(value[key]), 'ACTUAL_HELD_ORIGINAL_HASHES')
    target = value['native_tuple']
    need(type(target) is dict and set(target) == {'provider','resource_id','resource_created_at','slot'}
         and target['provider'] == 'aws' and type(target['slot']) is int and target['slot'] == 3
         and re.fullmatch('i-[0-9a-f]{17}', str(target['resource_id'])) is not None, 'EXACT_OWNED_S3_NOT_ABSENCE_AUTHORITY')
    utc_time(target['resource_created_at'])
    for key in ('history', 'catalog'):
        pin = value[key]
        need(type(pin) is dict and set(pin) == {'rows','sha256'} and type(pin['rows']) is int and 0 < pin['rows'] <= 100000
             and digest_value(pin['sha256']), 'COMPLETE_' + key.upper() + '_ROWSET_PIN')
    profile = value['physical_profile']
    need(type(profile) is dict and set(profile) == {'integration_instance_id','scope_checksum','profile_name'}
         and full_id(profile['integration_instance_id']) and digest_value(profile['scope_checksum'])
         and profile['profile_name'] == 'notify-aws-elastic', 'EXACT_PHYSICAL_PROFILE')
    members = value['native_members']
    need(type(members) is list and len(members) == 3 and [m.get('slot') for m in members if type(m) is dict] == [1,2,3], 'COMPLETE_ORDERED_THREE_MEMBER_PREIMAGE')
    tags = {'Name','yggdrasil.io/intent','yggdrasil.io/owner','yggdrasil.io/profile','yggdrasil.io/scope','yggdrasil.io/slot','yggdrasil.io/spec'}
    for m in members:
        need(set(m) == {'slot','resource_id','resource_created_at','preregistration_id','create_grant_id','enrollment_sha256','slot_revision','slot_record_sha256','tags'}
             and type(m['slot']) is int and re.fullmatch('i-[0-9a-f]{17}', str(m['resource_id'])) is not None
             and full_id(m['preregistration_id']) and full_id(m['create_grant_id']) and digest_value(m['enrollment_sha256'])
             and type(m['slot_revision']) is int and m['slot_revision'] > 0 and digest_value(m['slot_record_sha256']), 'EXACT_NATIVE_MEMBER_LEDGER_IDENTITY')
        utc_time(m['resource_created_at'])
        need(type(m['tags']) is dict and set(m['tags']) == tags and all(type(v) is str and re.fullmatch('[A-Za-z0-9._:/+-]{1,256}', v) for v in m['tags'].values())
             and m['tags']['yggdrasil.io/intent'] == m['create_grant_id'] and m['tags']['yggdrasil.io/slot'] == str(m['slot'])
             and m['tags']['yggdrasil.io/profile'] == profile['profile_name']
             and m['tags']['yggdrasil.io/scope'] == base64.b32encode(bytes.fromhex(profile['scope_checksum'])).decode().lower().rstrip('='), 'EXACT_SEVEN_NATIVE_OWNERSHIP_TAGS')
    need(len({m['resource_id'] for m in members}) == len({m['preregistration_id'] for m in members}) == len({m['create_grant_id'] for m in members}) == 3
         and len({m['tags']['yggdrasil.io/owner'] for m in members}) == 1
         and all(members[2][k] == target[k] for k in ('resource_id','resource_created_at','slot'))
         and members[2]['preregistration_id'] == value['preregistration_id'], 'TARGET_AND_SURVIVORS_SAME_COMPLETE_OWNED_PROFILE')
    historical = value['historical_survivors']
    need(type(historical) is list and len(historical) == 2 and [m.get('slot') for m in historical if type(m) is dict] == [1,2], 'TWO_HISTORICAL_USEFUL_SURVIVORS_NOT_FRESH_CANARIES')
    for m in historical:
        need(set(m) == {'slot','read_challenge_id','publication_challenge_id','read_return_sha256','publication_return_sha256','frame_sha256'}
             and type(m['slot']) is int and all(full_id(m[k]) for k in ('read_challenge_id','publication_challenge_id'))
             and m['read_challenge_id'] != m['publication_challenge_id']
             and all(digest_value(m[k]) for k in ('read_return_sha256','publication_return_sha256','frame_sha256')), 'EXACT_RETAINED_HISTORICAL_PUBLICATION_AND_READ')
    for key in ('Root_review_ref','native_observation_ref'):
        evidence_ref(value[key])
    return value


def held_identity(value):
    """Separate immutable original lineage from late operational observations."""
    e = validate_held_original(value)
    fixed = {key:copy.deepcopy(item) for key,item in e.items()
             if key not in ('history','catalog','Root_review_ref','native_observation_ref','native_members')}
    fixed['native_members'] = [{key:copy.deepcopy(item) for key,item in member.items()
                               if key not in ('slot_revision','slot_record_sha256')} for member in e['native_members']]
    return fixed


def validate_held_identity(value):
    keys = {'schema','namespace','environment','domain','dimension','preregistration_id','retirement_request_id','original_run_id',
            'policy_id','policy_checksum','workflow_id','workflow_checksum','generation','fence','lease_owner','executor_id',
            'intent_pgtext_sha256','original_frame_sha256','original_caller_sha256','native_tuple','physical_profile',
            'native_members','historical_survivors'}
    need(type(value) is dict and set(value) == keys
         and value['schema'] == 'root_exact_held_partial_poweroff_image_rollout_v1'
         and (value['namespace'],value['environment'],value['domain'],value['dimension'],value['generation'],value['fence'])
         == ('dakasa-production','production','notify','original_notify_aws_vm_members',14,28), 'FIXED_SOURCE_ONE_HELD_ORIGINAL_IDENTITY')
    for key in ('preregistration_id','retirement_request_id','original_run_id','policy_id','workflow_id','lease_owner','executor_id'):
        need(full_id(value[key]), 'FIXED_SOURCE_ORIGINAL_UUID')
    for key in ('policy_checksum','workflow_checksum','intent_pgtext_sha256','original_frame_sha256','original_caller_sha256'):
        need(digest_value(value[key]), 'FIXED_SOURCE_ORIGINAL_HASH')
    need(type(value['native_members']) is list and len(value['native_members']) == 3
         and type(value['historical_survivors']) is list and len(value['historical_survivors']) == 2,
         'FIXED_SOURCE_THREE_MEMBERS_AND_TWO_HISTORICAL_PROVENANCES')
    return value


def match_held_identity(value):
    e = validate_held_original(value)
    need(held_identity(e) == validate_held_identity(HELD_ORIGINAL_IDENTITY), 'LATE_ADMISSION_MATCHES_EXACT_SOURCE_ORIGINAL_NOT_ANOTHER_FRAME')
    return e


def load_held_admission(C, path, expected_sha256):
    """One stable private late input; no provider/API call or runtime setter.

    Root reviews this file and SHA separately AFTER actual schema90/G10 facts.
    CI-qualified helper bytes and fixed historical Source lineage never change.
    """
    require_bound()
    need(ROOT_ROLLOUT_MODE == 'exact_held_partial_poweroff_original', 'SOURCE_SELECTS_HELD_IMAGE_ONLY_BRANCH')
    evidence_ref({'path':str(path),'sha256':expected_sha256})
    raw = read(path, 128 << 10, 0o600)
    need(sha(raw) == expected_sha256, 'EXACT_ROOT_REVIEWED_LATE_HELD_ADMISSION_SHA')
    return match_held_identity(C.loads(raw)), raw


def validate_held_native_observation(expected, loads):
    """Read Root's independently captured originals; never call a provider.

    This authenticates immutable Root custody and parses actual AWS raw content.
    Historical canary utility is separately pinned by the read-only SQL. This
    image-only receipt never confers ADR101 retirement or fresh business authority.
    """
    e = validate_held_original(expected)
    ref = e['native_observation_ref']
    raw = read(ref['path'], 65536, 0o600)
    need(sha(raw) == ref['sha256'], 'PINNED_INDEPENDENT_NATIVE_OBSERVATION')
    v = loads(raw)
    need(type(v) is dict and set(v) == {'schema','observation_id','boot_id','started_monotonic_ns','returned_monotonic_ns',
         'started_at','returned_at','held_intent_pgtext_sha256','region','account','request_ref','identity_ref','fleet_ref'}
         and v['schema'] == 'root_same_boot_complete_aws_profile_native_readonly_v1' and full_id(v['observation_id'])
         and full_id(v['boot_id']) and v['account'] == '153828470928' and v['region'] == 'us-east-1'
         and v['held_intent_pgtext_sha256'] == e['intent_pgtext_sha256'], 'CLOSED_FRESH_NATIVE_OBSERVATION_IDENTITY')
    boot = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    start, end = utc_time(v['started_at']), utc_time(v['returned_at'])
    mono = time.monotonic_ns()
    need(v['boot_id'] == boot and type(v['started_monotonic_ns']) is int and type(v['returned_monotonic_ns']) is int
         and 0 <= v['started_monotonic_ns'] <= v['returned_monotonic_ns'] <= mono
         and 0 <= (end-start).total_seconds() <= 20
         and 0 <= (v['returned_monotonic_ns']-v['started_monotonic_ns']) / 1e9 <= 20
         and abs((end-start).total_seconds()-(v['returned_monotonic_ns']-v['started_monotonic_ns']) / 1e9) <= 1
         and 0 <= (datetime.datetime.now(datetime.timezone.utc)-end).total_seconds()
         and 0 <= (datetime.datetime.now(datetime.timezone.utc)-start).total_seconds() <= 60
         and (mono-v['started_monotonic_ns']) / 1e9 <= 60, 'SAME_BOOT_MONOTONIC_AND_UTC_NATIVE_FULL_READ_WITHIN60S')
    originals = {}
    for key in ('request_ref','identity_ref','fleet_ref'):
        r = evidence_ref(v[key])
        body = read(r['path'], 4 << 20, 0o600)
        need(sha(body) == r['sha256'], 'UNCHANGED_FULL_NATIVE_ORIGINAL_' + key)
        originals[key] = loads(body)
    owner = e['native_members'][0]['tags']['yggdrasil.io/owner']
    scope = e['native_members'][0]['tags']['yggdrasil.io/scope']
    request = {'service':'ec2','operation':'DescribeInstances','region':'us-east-1','filters':[
        {'Name':'tag:yggdrasil.io/owner','Values':[owner]},
        {'Name':'tag:yggdrasil.io/profile','Values':['notify-aws-elastic']},
        {'Name':'tag:yggdrasil.io/scope','Values':[scope]},
        {'Name':'instance-state-name','Values':['pending','running','shutting-down','stopping','stopped']}]}
    need(originals['request_ref'] == request, 'COMPLETE_NONTERMINATED_PROFILE_QUERY_NO_INSTANCE_ID_NARROWING')
    identity = originals['identity_ref']
    need(type(identity) is dict and set(identity) == {'UserId','Account','Arn'} and identity['Account'] == '153828470928'
         and type(identity['Arn']) is str and identity['Arn'].startswith('arn:aws:') and ':153828470928:' in identity['Arn'], 'ACTUAL_STS_ACCOUNT_ORIGINAL')
    fleet = originals['fleet_ref']
    need(type(fleet) is dict and set(fleet) == {'Reservations'} and type(fleet['Reservations']) is list, 'COMPLETE_EC2_BODY_NO_PAGINATION_OR_FILTERED_PROJECTION')
    instances = []
    for reservation in fleet['Reservations']:
        need(type(reservation) is dict and reservation.get('OwnerId') == '153828470928' and type(reservation.get('Instances')) is list, 'ALL_RESERVATIONS_SAME_ACTUAL_ACCOUNT')
        instances.extend(reservation['Instances'])
    need(len(instances) == 3 and len({i.get('InstanceId') for i in instances}) == 3, 'EXACT_COMPLETE_THREE_INSTANCE_FLEET')
    for m in e['native_members']:
        selected = [i for i in instances if i.get('InstanceId') == m['resource_id']]
        need(len(selected) == 1, 'EXACT_NATIVE_TARGET_OR_SURVIVOR')
        i = selected[0]
        t = i.get('Tags')
        need(type(t) is list and len(t) == 7 and all(type(x) is dict and set(x) == {'Key','Value'} for x in t)
             and len({x['Key'] for x in t}) == 7 and {x['Key']:x['Value'] for x in t} == m['tags']
             and datetime.datetime.fromisoformat(i['LaunchTime'].replace('Z','+00:00')) == utc_time(m['resource_created_at'])
             and i.get('State',{}).get('Name') == ('stopped' if m['slot'] == 3 else 'running'), 'EXACT_BIRTH_OWNERSHIP_AND_NATIVE_OFF_OR_RUNNING')
    return {'schema':'image_only_fresh_native_off_and_historical_useful_provenance_v1',
            'observation_id':v['observation_id'],'native_observation_sha256':ref['sha256'],
            'historical_useful_provenance_is_fresh_business_authority':False,'retirement_authority':False}


def database_preflight(cut, run, held_admission=None):
    require_bound()
    if ROOT_ROLLOUT_MODE == 'steady':
        need(held_admission is None, 'NO_HELD_INPUT_IN_UNCHANGED_STEADY_BRANCH')
        return database_steady_preflight(cut, run)
    return database_held_preflight(cut, run, match_held_identity(held_admission))


def held_original_frame_sql(retirement):
    return "SELECT jsonb_build_object('returns',(SELECT jsonb_agg(to_jsonb(r) ORDER BY sequence) FROM public.capacity_vm_retirement_original_returns r WHERE intent_id=$1),'caller',(SELECT to_jsonb(c) FROM public.capacity_guest_original_caller_returns c WHERE intent_id=$1),'attempt',(SELECT to_jsonb(a) FROM public.capacity_guest_original_caller_attempts a WHERE intent_id=$1),'authority',(SELECT jsonb_agg(jsonb_build_object('read',to_jsonb(r),'return',to_jsonb(v)) ORDER BY CASE r.phase WHEN 'before_start' THEN 0 ELSE 1 END,r.ordinal) FROM public.capacity_guest_original_authority_reads r LEFT JOIN public.capacity_guest_original_authority_returns v ON v.read_id=r.id WHERE r.intent_id=$1),'transport',(SELECT jsonb_agg(to_jsonb(t) ORDER BY t.read_id,t.native_stage) FROM public.capacity_guest_original_authority_transport_returns t JOIN public.capacity_guest_original_authority_reads r ON r.id=t.read_id WHERE r.intent_id=$1))::text".replace('$1', retirement)


def retained_dispatch_terminal_ctes(schema_version):
    """Closed schema89/91 retained proofs; never a live terminal effect scan.

    The schema89 text is the reviewed seven-lane query, byte-identical. Only
    schema91 can name its eighth immutable receipt table and pure validator.
    """
    need(type(schema_version) is int and schema_version in (89, 91), 'CLOSED_RETAINED_TERMINAL_SCHEMA_89_OR_91')
    original = r'''dispatch_candidates AS MATERIALIZED (
 SELECT j.* FROM public.capacity_dispatch_jobs j
 WHERE j.realm='dakasa-production' AND j.environment='production' AND j.domain='notify'
  AND j.dimension IN('original_notify_aws_vm_members','original_notify_hetzner_vm_members')
  AND (j.state='returned' AND j.returned_at IS NOT NULL AND j.finalization_ack_at IS NOT NULL
   AND num_nonnulls(j.failed_original_disposition_id,j.native_denied_disposition_id,j.enrolled_failed_disposition_id,
        j.abandoned_disposition_id,j.finalization_lost_disposition_id,j.unknown_maintenance_disposition_id)=0
   AND j.rejected_at IS NULL AND j.rejection_reason IS NULL AND j.rejection_issuer IS NULL
   AND j.superseded_policy_id IS NULL AND j.superseded_policy_checksum IS NULL
   AND j.superseding_policy_id IS NULL AND j.superseding_policy_checksum IS NULL) IS NOT TRUE
),
dispatch_original_identity AS MATERIALIZED (
 SELECT j.id FROM dispatch_candidates j
 WHERE j.protocol='capacity_dispatch_prestart_v1'
  AND j.envelope_sha256=encode(sha256(convert_to(j.envelope,'UTF8')),'hex')
  AND (j.state='prestart_rejected' OR num_nonnulls(j.rejected_at,j.rejection_reason,j.rejection_issuer,
       j.superseded_policy_id,j.superseded_policy_checksum,j.superseding_policy_id,j.superseding_policy_checksum)=0)
  AND (j.envelope IS JSON OBJECT WITH UNIQUE KEYS) IS TRUE
  AND (j.envelope::jsonb->>'job_id',j.envelope::jsonb->>'run_id',j.envelope::jsonb->>'protocol',
       j.envelope::jsonb->>'realm',j.envelope::jsonb->>'environment',j.envelope::jsonb->>'domain',
       j.envelope::jsonb->>'dimension',j.envelope::jsonb->>'source_tick')
      IS NOT DISTINCT FROM
      (j.id::text,j.run_id::text,j.protocol,j.realm,j.environment,j.domain,j.dimension,j.source_tick)
),
dispatch_grant_terminals AS MATERIALIZED (
 SELECT 'failed_disposed'::text terminal,d.id,d.grant_id,d.preregistration_id,d.job_id,d.run_id,
  d.original_grant_sha256,d.original_preregistration_sha256,d.original_witness_sha256,
  d.original_dispatch_sha256,d.original_run_sha256,d.disposition_sha256,d.original_wire,d.disposition_record,
  d.closed_generation,d.closed_fencing_token,d.recorded_at,
  NULL::text original_registration_sha256,NULL::text original_receipt_sha256,NULL::text original_enrollment_sha256
 FROM public.capacity_failed_original_dispositions d JOIN dispatch_candidates j
  ON j.state='failed_disposed' AND (j.failed_original_disposition_id,j.id,j.run_id)=(d.id,d.job_id,d.run_id)
 UNION ALL
 SELECT 'native_denied_disposed',d.id,d.grant_id,d.preregistration_id,d.job_id,d.run_id,
  d.original_grant_sha256,d.original_preregistration_sha256,NULL::text,
  d.original_dispatch_sha256,d.original_run_sha256,d.disposition_sha256,d.original_wire,d.disposition_record,
  d.closed_generation,d.closed_fencing_token,d.recorded_at,NULL::text,NULL::text,NULL::text
 FROM public.capacity_native_denied_dispositions d JOIN dispatch_candidates j
  ON j.state='native_denied_disposed' AND (j.native_denied_disposition_id,j.id,j.run_id)=(d.id,d.job_id,d.run_id)
 UNION ALL
 SELECT 'enrolled_failed_disposed',d.id,d.grant_id,d.preregistration_id,d.job_id,d.run_id,
  d.original_grant_sha256,d.original_preregistration_sha256,d.original_witness_sha256,
  d.original_dispatch_sha256,d.original_run_sha256,d.disposition_sha256,d.original_wire,d.disposition_record,
  d.closed_generation,d.closed_fencing_token,d.recorded_at,
  d.original_registration_sha256,d.original_receipt_sha256,d.original_enrollment_sha256
 FROM public.capacity_enrolled_failed_original_dispositions d JOIN dispatch_candidates j
  ON j.state='enrolled_failed_disposed' AND (j.enrolled_failed_disposition_id,j.id,j.run_id)=(d.id,d.job_id,d.run_id)
),
dispatch_valid_grant_terminal AS MATERIALIZED (
 SELECT j.id job_id FROM dispatch_candidates j JOIN dispatch_original_identity ji ON ji.id=j.id
 JOIN dispatch_grant_terminals d ON d.job_id=j.id AND d.run_id=j.run_id AND d.terminal=j.state
 JOIN public.capacity_mutation_grants g ON g.id=d.grant_id
 JOIN public.capacity_vm_provisioning_preregistrations p ON p.id=d.preregistration_id AND p.create_grant_id=g.id
 JOIN public.workflow_runs w ON w.id=d.run_id
 LEFT JOIN public.capacity_guest_original_create_witnesses witness ON witness.preregistration_id=p.id
 LEFT JOIN public.capacity_vm_original_enrollments en ON en.preregistration_id=p.id
 WHERE num_nonnulls(j.failed_original_disposition_id,j.native_denied_disposition_id,j.enrolled_failed_disposition_id,
        j.abandoned_disposition_id,j.finalization_lost_disposition_id,j.unknown_maintenance_disposition_id)=1
  AND num_nonnulls(g.original_disposition_id,g.failed_original_disposition_id,g.native_denied_disposition_id,g.enrolled_failed_disposition_id)=1
  AND CASE j.state WHEN 'failed_disposed' THEN g.failed_original_disposition_id=d.id
      WHEN 'native_denied_disposed' THEN g.native_denied_disposition_id=d.id
      WHEN 'enrolled_failed_disposed' THEN g.enrolled_failed_disposition_id=d.id ELSE false END IS TRUE
  AND (j.realm,j.environment,j.domain,j.dimension)=(g.namespace,g.environment,g.domain,g.dimension)
  AND j.started_at IS NOT NULL AND j.returned_at IS NOT NULL AND j.lease_owner IS NOT NULL AND j.lease_expires_at IS NOT NULL
  AND j.rejected_at IS NULL AND j.rejection_reason IS NULL AND j.rejection_issuer IS NULL
  AND d.original_dispatch_sha256 ~ '^[a-f0-9]{64}$'
  AND NOT EXISTS(SELECT 1 FROM jsonb_each(d.disposition_record) x
    WHERE (x.key ~ '^original_.*_sha256$' OR x.key='observation_sha256')
     AND (jsonb_typeof(x.value)='string' AND x.value#>>'{}' ~ '^[a-f0-9]{64}$') IS NOT TRUE)
  AND d.disposition_record->>'original_binding_sha256'=encode(sha256(p.binding_wire),'hex')
  AND d.original_grant_sha256=encode(sha256(convert_to(g.grant_record::text,'UTF8')),'hex')
  AND d.original_preregistration_sha256=encode(sha256(p.original_wire),'hex')
  AND d.original_run_sha256=encode(sha256(convert_to(to_jsonb(w)::text,'UTF8')),'hex')
  AND d.disposition_sha256=encode(sha256(d.original_wire),'hex')
  AND (convert_from(d.original_wire,'UTF8') IS JSON OBJECT WITH UNIQUE KEYS) IS TRUE
  AND d.disposition_record=convert_from(d.original_wire,'UTF8')::jsonb
  AND jsonb_typeof(d.disposition_record)='object'
  AND (d.disposition_record->>'id',d.disposition_record->>'grant_id',d.disposition_record->>'preregistration_id',
       d.disposition_record->>'job_id',d.disposition_record->>'run_id')
      IS NOT DISTINCT FROM (d.id::text,d.grant_id::text,d.preregistration_id::text,d.job_id::text,d.run_id::text)
  AND (d.disposition_record->>'original_grant_sha256',d.disposition_record->>'original_preregistration_sha256',
       d.disposition_record->>'original_dispatch_sha256',d.disposition_record->>'original_run_sha256')
      IS NOT DISTINCT FROM (d.original_grant_sha256,d.original_preregistration_sha256,d.original_dispatch_sha256,d.original_run_sha256)
  AND d.disposition_record->'original_generation'=g.grant_record->'generation'
  AND d.disposition_record->'original_fencing_token'=g.grant_record->'fencing_token'
  AND (d.disposition_record->>'original_deadline')::timestamptz=p.original_deadline
  AND d.disposition_record->>'historical_core_source_commit'=p.preregistration_record->>'core_source_commit'
  AND d.disposition_record->'closed_generation'=to_jsonb(d.closed_generation)
  AND d.disposition_record->'closed_fencing_token'=to_jsonb(d.closed_fencing_token)
  AND (d.disposition_record->>'recorded_at')::timestamptz=d.recorded_at
  AND jsonb_typeof(d.disposition_record->'issuer')='string'
  AND d.disposition_record->>'issuer' ~ '^collaborator:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
  AND jsonb_typeof(d.disposition_record->'observation')='object'
  AND w.status='failed' AND w.started_at IS NOT NULL AND w.finished_at IS NOT NULL
  AND (w.workflow_id IS NULL OR w.workflow_id::text=j.envelope::jsonb#>>'{workflow,id}')
  AND (w.workflow_namespace,w.workflow_name,w.workflow_version::text)
      IS NOT DISTINCT FROM (j.envelope::jsonb#>>'{workflow,namespace}',j.envelope::jsonb#>>'{workflow,name}',j.envelope::jsonb#>>'{workflow,version}')
  AND w.inputs IS NOT DISTINCT FROM j.envelope::jsonb->'inputs' AND w.metadata IS NOT DISTINCT FROM j.envelope::jsonb->'metadata'
  AND w.result->>'status'='failed' AND w.result#>>'{workflow,id}'=j.envelope::jsonb#>>'{workflow,id}'
  AND (w.result#>>'{workflow,namespace}',w.result#>>'{workflow,name}',w.result#>>'{workflow,version}')
      IS NOT DISTINCT FROM (j.envelope::jsonb#>>'{workflow,namespace}',j.envelope::jsonb#>>'{workflow,name}',j.envelope::jsonb#>>'{workflow,version}')
  AND j.envelope::jsonb#>>'{policy,id}'=g.grant_record->>'policy_id'
  AND j.envelope::jsonb#>>'{policy,checksum}'=g.grant_record->>'policy_checksum'
  AND j.envelope::jsonb#>>'{workflow,id}'=g.grant_record->>'workflow_id'
  AND CASE j.state
   WHEN 'failed_disposed' THEN
    j.finalization_ack_at IS NULL AND d.disposition_record->>'schema'='failed_original_guest_terminal_disposition_v1'
    AND ARRAY(SELECT k FROM jsonb_object_keys(d.disposition_record) AS k ORDER BY k COLLATE "C")=ARRAY['closed_fencing_token','closed_generation','grant_id','historical_core_source_commit','historical_writer_start_state','id','issuer','job_id','observation','observation_sha256','original_accepted_unchanged','original_binding_sha256','original_deadline','original_dispatch_sha256','original_fencing_token','original_generation','original_grant_sha256','original_policy_sha256','original_preregistration_sha256','original_run_sha256','original_settlement_sha256','original_unknown_ACK_preserved','original_witness_preserved','original_witness_sha256','original_workflow_sha256','preregistration_id','recorded_at','run_id','schema','serving_or_business_or_savings_authority']::text[]
    AND d.original_witness_sha256=encode(sha256(witness.original_wire),'hex')
    AND d.disposition_record->>'original_witness_sha256'=d.original_witness_sha256
    AND d.disposition_record->'original_accepted_unchanged'='true'::jsonb
    AND d.disposition_record->'original_witness_preserved'='true'::jsonb
    AND d.disposition_record->'original_unknown_ACK_preserved'='true'::jsonb
    AND d.disposition_record->>'historical_writer_start_state'='unknown'
    AND d.disposition_record->'serving_or_business_or_savings_authority'='false'::jsonb
   WHEN 'enrolled_failed_disposed' THEN
    j.finalization_ack_at IS NULL AND d.disposition_record->>'schema'='enrolled_failed_original_guest_terminal_disposition_v1'
    AND ARRAY(SELECT k FROM jsonb_object_keys(d.disposition_record) AS k ORDER BY k COLLATE "C")=ARRAY['Guest_quiescence_proved','closed_fencing_token','closed_generation','grant_id','historical_core_source_commit','historical_writer_start_state','id','installation_or_serving_authority','issuer','job_id','observation','observation_sha256','original_accepted_unchanged','original_binding_sha256','original_deadline','original_dispatch_sha256','original_enrollment_preserved','original_enrollment_sha256','original_fencing_token','original_generation','original_grant_sha256','original_policy_sha256','original_preregistration_sha256','original_receipt_sha256','original_registration_sha256','original_run_sha256','original_settlement_sha256','original_unknown_ACK_preserved','original_witness_preserved','original_witness_sha256','original_workflow_sha256','preregistration_id','recorded_at','run_id','schema','serving_or_business_or_savings_authority']::text[]
    AND d.original_witness_sha256=encode(sha256(witness.original_wire),'hex')
    AND d.disposition_record->>'original_witness_sha256'=d.original_witness_sha256
    AND en.enrollment_sha256=d.original_enrollment_sha256
    AND encode(sha256(en.registration_wire),'hex')=d.original_registration_sha256
    AND encode(sha256(en.receipt_wire),'hex')=d.original_receipt_sha256
    AND d.disposition_record->>'original_binding_sha256'=encode(sha256(p.binding_wire),'hex')
    AND d.disposition_record->>'original_registration_sha256'=d.original_registration_sha256
    AND d.disposition_record->>'original_receipt_sha256'=d.original_receipt_sha256
    AND d.disposition_record->>'original_enrollment_sha256'=d.original_enrollment_sha256
    AND d.disposition_record->'original_accepted_unchanged'='true'::jsonb
    AND d.disposition_record->'original_witness_preserved'='true'::jsonb
    AND d.disposition_record->'original_unknown_ACK_preserved'='true'::jsonb
    AND d.disposition_record->'original_enrollment_preserved'='true'::jsonb
    AND d.disposition_record->'Guest_quiescence_proved'='false'::jsonb
    AND d.disposition_record->'installation_or_serving_authority'='false'::jsonb
    AND d.disposition_record->>'historical_writer_start_state'='unknown'
    AND d.disposition_record->'serving_or_business_or_savings_authority'='false'::jsonb
   WHEN 'native_denied_disposed' THEN
    w.started_at=j.started_at AND w.finished_at=j.returned_at
    AND d.disposition_record->'original_uncertain_and_NULL_identities_unchanged'='true'::jsonb
    AND d.disposition_record->'witness_enrollment_installation_absent'='true'::jsonb
    AND d.disposition_record->'serving_or_business_or_savings_authority'='false'::jsonb
    AND CASE d.disposition_record->>'schema'
       WHEN 'original_native_authorization_denied_terminal_disposition_v1'
        THEN ARRAY(SELECT k FROM jsonb_object_keys(d.disposition_record) AS k ORDER BY k COLLATE "C")=ARRAY['closed_fencing_token','closed_generation','grant_id','historical_core_source_commit','id','issuer','job_id','observation','observation_sha256','original_binding_sha256','original_deadline','original_dispatch_sha256','original_fencing_token','original_generation','original_grant_sha256','original_policy_sha256','original_preregistration_sha256','original_run_sha256','original_settlement_sha256','original_uncertain_and_NULL_identities_unchanged','original_unknown_ACK_preserved','original_workflow_sha256','preregistration_id','recorded_at','run_id','schema','serving_or_business_or_savings_authority','witness_enrollment_installation_absent']::text[]
       WHEN 'original_native_authorization_denied_failed_returned_ack_terminal_disposition_v2'
        THEN ARRAY(SELECT k FROM jsonb_object_keys(d.disposition_record) AS k ORDER BY k COLLATE "C")=ARRAY['closed_fencing_token','closed_generation','grant_id','historical_core_source_commit','id','issuer','job_id','observation','observation_sha256','original_binding_sha256','original_deadline','original_dispatch_sha256','original_dispatch_state','original_failed_workflow_ACK_preserved','original_fencing_token','original_finalization_ack_at','original_generation','original_grant_sha256','original_policy_sha256','original_preregistration_sha256','original_run_sha256','original_settlement_sha256','original_uncertain_and_NULL_identities_unchanged','original_unknown_ACK_preserved','original_workflow_sha256','preregistration_id','recorded_at','run_id','schema','serving_or_business_or_savings_authority','witness_enrollment_installation_absent']::text[] ELSE false END IS TRUE
    AND public.native_denied_original_ack_matches(d.disposition_record,
       CASE d.disposition_record->>'schema' WHEN 'original_native_authorization_denied_terminal_disposition_v1' THEN 'unknown'
       WHEN 'original_native_authorization_denied_failed_returned_ack_terminal_disposition_v2' THEN 'returned' ELSE NULL END,
       j.finalization_ack_at,j.returned_at,j.lease_expires_at,j.return_status) IS TRUE
   ELSE false END IS TRUE
),
dispatch_terminal_witnesses AS MATERIALIZED (
 SELECT j.id job_id FROM dispatch_candidates j JOIN dispatch_original_identity ji ON ji.id=j.id
 JOIN public.capacity_dispatch_prestart_rejections d ON d.job_id=j.id AND d.run_id=j.run_id
 JOIN public.workflow_runs w ON w.id=d.run_id
 WHERE j.state='prestart_rejected' AND j.started_at IS NULL AND j.returned_at IS NULL
  AND j.return_status IS NULL AND j.return_error IS NULL AND j.finalization_error IS NULL AND j.finalization_ack_at IS NULL
  AND num_nonnulls(j.failed_original_disposition_id,j.native_denied_disposition_id,j.enrolled_failed_disposition_id,
        j.abandoned_disposition_id,j.finalization_lost_disposition_id,j.unknown_maintenance_disposition_id)=0
  AND (d.envelope_sha256,d.fencing_token,d.reason,d.issuer,d.recorded_at,d.superseded_policy_id,d.superseded_policy_checksum,d.superseding_policy_id,d.superseding_policy_checksum)
      IS NOT DISTINCT FROM
      (j.envelope_sha256,j.fencing_token,j.rejection_reason,j.rejection_issuer,j.rejected_at,j.superseded_policy_id,j.superseded_policy_checksum,j.superseding_policy_id,j.superseding_policy_checksum)
  AND d.reason='policy_superseded_before_start' AND d.superseded_policy_id<>d.superseding_policy_id
  AND d.superseded_policy_checksum ~ '^[a-f0-9]{64}$' AND d.superseding_policy_checksum ~ '^[a-f0-9]{64}$'
  AND d.issuer ~ '^collaborator:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
  AND w.status='cancelled' AND w.started_at IS NULL AND w.result IS NULL AND w.finished_at=d.recorded_at AND w.error=d.reason
 UNION
 SELECT job_id FROM dispatch_valid_grant_terminal
 UNION
 SELECT j.id FROM dispatch_candidates j JOIN dispatch_original_identity ji ON ji.id=j.id
 JOIN public.capacity_dispatch_abandoned_dispositions d ON (j.abandoned_disposition_id,j.id,j.run_id)=(d.id,d.job_id,d.run_id)
 JOIN public.workflow_runs w ON w.id=d.run_id
 WHERE j.state='abandoned_disposed' AND j.started_at IS NOT NULL AND j.returned_at IS NULL
  AND j.return_status IS NULL AND j.return_error IS NULL AND j.finalization_error IS NULL AND j.finalization_ack_at IS NULL
  AND num_nonnulls(j.failed_original_disposition_id,j.native_denied_disposition_id,j.enrolled_failed_disposition_id,
        j.abandoned_disposition_id,j.finalization_lost_disposition_id,j.unknown_maintenance_disposition_id)=1
  AND (d.realm,d.environment,d.domain,d.dimension,d.envelope_sha256,d.fencing_token,d.lease_owner,d.lease_expires_at,d.started_at,d.pending_wake_count)
      IS NOT DISTINCT FROM (j.realm,j.environment,j.domain,j.dimension,j.envelope_sha256,j.fencing_token,j.lease_owner,j.lease_expires_at,j.started_at,j.pending_wake_count)
  AND d.lease_owner IS NOT NULL AND d.fencing_token>0 AND d.started_at<d.lease_expires_at
  AND d.executor_barrier='disposing_core_process_started_after_lease_expiry_v1' AND d.minimum_lease_age_seconds=900
  AND d.disposing_core_process_started_at>d.lease_expires_at AND d.disposing_core_process_started_at<=d.recorded_at
  AND d.recorded_at>=d.lease_expires_at+interval '15 minutes'
  AND d.reason='abandoned_started_dispatch_disposed' AND d.historical_return='unknown'
  AND d.run_status='failed' AND d.run_error='abandoned_started_dispatch_disposed: historical outcome unknown'
  AND w.status=d.run_status AND w.error=d.run_error AND w.started_at=d.started_at AND w.finished_at=d.recorded_at AND w.result IS NULL
  AND d.original_dispatch_sha256 ~ '^[a-f0-9]{64}$' AND d.original_run_sha256 ~ '^[a-f0-9]{64}$'
  AND d.provider_mutation_evidence='{"authority_reads_since_start":0,"authority_returns_since_start":0,"authority_transport_returns_since_start":0,"caller_possible_sends_since_start":0,"caller_returns_since_start":0,"canary_challenges_since_start":0,"canary_nonces_since_start":0,"canary_possible_sends_since_start":0,"canary_returns_since_start":0,"clock_skew_margin_seconds":30,"create_witnesses_since_start":0,"enrollments_since_start":0,"executor_activity_updated_since_start":0,"grants_created_or_updated_since_start":0,"installations_since_start":0,"intent_events_since_start":0,"intents_updated_since_start":0,"native_commands_since_start":0,"native_lifetime_archives_since_start":0,"native_lifetimes_updated_since_start":0,"native_pod_checkpoints_since_start":0,"native_poweroff_reads_since_start":0,"notify_window_markers_for_job":0,"open_undisposed_grants":0,"partial_nativeoff_reads_since_start":0,"partial_nativeoff_reconciliations_since_start":0,"prejournal_refusal_recoveries_since_start":0,"preregistrations_since_start":0,"presend_retirement_recoveries_since_start":0,"provider_quiescence_proved":false,"provider_read_performed":false,"qualification_native_source_returns_since_start":0,"qualification_probe_challenges_since_start":0,"resource_slots_updated_since_start":0,"retirement_contexts_since_start":0,"retirement_delete_bindings_since_start":0,"retirement_intents_since_start":0,"retirement_native_readbacks_since_start":0,"retirement_original_returns_since_start":0,"runtime_snapshot_challenges_since_start":0,"runtime_snapshot_returns_since_start":0,"schema":"abandoned_started_dispatch_effect_scan_v2","source_recovery_cleanup_challenges_since_start":0,"source_recovery_cleanup_effect_permits_since_start":0}'::jsonb
 UNION
 SELECT j.id FROM dispatch_candidates j JOIN dispatch_original_identity ji ON ji.id=j.id
 JOIN public.capacity_dispatch_finalization_lost_dispositions d ON (j.finalization_lost_disposition_id,j.id,j.run_id)=(d.id,d.job_id,d.run_id)
 JOIN public.workflow_runs w ON w.id=d.run_id
 WHERE j.state='finalization_lost_disposed' AND j.started_at IS NOT NULL AND j.returned_at IS NULL
  AND j.return_status IS NULL AND j.return_error IS NULL AND j.finalization_error IS NULL AND j.finalization_ack_at IS NULL
  AND num_nonnulls(j.failed_original_disposition_id,j.native_denied_disposition_id,j.enrolled_failed_disposition_id,
        j.abandoned_disposition_id,j.finalization_lost_disposition_id,j.unknown_maintenance_disposition_id)=1
  AND (d.realm,d.environment,d.domain,d.dimension,d.envelope_sha256,d.fencing_token,d.lease_owner,d.lease_expires_at,d.started_at,d.pending_wake_count)
      IS NOT DISTINCT FROM (j.realm,j.environment,j.domain,j.dimension,j.envelope_sha256,j.fencing_token,j.lease_owner,j.lease_expires_at,j.started_at,j.pending_wake_count)
  AND d.lease_owner IS NOT NULL AND d.fencing_token>0 AND d.started_at<d.lease_expires_at
  AND d.executor_barrier='disposing_core_process_started_after_lease_expiry_v1' AND d.minimum_lease_age_seconds=900
  AND d.disposing_core_process_started_at>d.lease_expires_at AND d.disposing_core_process_started_at<=d.recorded_at
  AND d.recorded_at>=d.lease_expires_at+interval '15 minutes'
  AND d.reason='finalization_lost_started_dispatch_disposed' AND d.return_observation='observed_by_operator_evidence_not_recorded'
  AND d.historical_return='unknown' AND d.run_status='failed'
  AND d.run_error='finalization_lost_disposed: return observed but not recorded; historical outcome unknown'
  AND w.status=d.run_status AND w.error=d.run_error AND w.started_at=d.started_at AND w.finished_at=d.recorded_at AND w.result IS NULL
  AND d.original_dispatch_sha256 ~ '^[a-f0-9]{64}$' AND d.original_run_sha256 ~ '^[a-f0-9]{64}$'
  AND octet_length(d.operator_evidence) BETWEEN 1 AND 8192
  AND d.operator_evidence_sha256=encode(sha256(convert_to(d.operator_evidence,'UTF8')),'hex')
  AND ARRAY(SELECT k FROM jsonb_object_keys(d.provider_mutation_evidence) AS k ORDER BY k COLLATE "C")=ARRAY['authority_reads_since_start','authority_returns_since_start','authority_transport_returns_since_start','base_schema','caller_possible_sends_since_start','caller_returns_since_start','canary_challenges_since_start','canary_nonces_since_start','canary_possible_sends_since_start','canary_returns_since_start','clock_skew_margin_seconds','create_witnesses_since_start','enrollments_since_start','executor_activity_updated_since_start','grants_created_or_updated_since_start','installations_since_start','intent_events_since_start','intents_updated_since_start','native_commands_since_start','native_lifetime_archives_since_start','native_lifetimes_updated_since_start','native_pod_checkpoints_since_start','native_poweroff_reads_since_start','notify_window_markers_for_job','observation_refresh_slot_updates','open_undisposed_grants','partial_nativeoff_reads_since_start','partial_nativeoff_reconciliations_since_start','prejournal_refusal_recoveries_since_start','preregistrations_since_start','presend_retirement_recoveries_since_start','provider_quiescence_proved','provider_read_performed','pure_assessment_intent_updates','qualification_native_source_returns_since_start','qualification_probe_challenges_since_start','resource_slots_updated_since_start','retirement_contexts_since_start','retirement_delete_bindings_since_start','retirement_intents_since_start','retirement_native_readbacks_since_start','retirement_original_returns_since_start','runtime_snapshot_challenges_since_start','runtime_snapshot_returns_since_start','schema','source_recovery_cleanup_challenges_since_start','source_recovery_cleanup_effect_permits_since_start']::text[]
  AND NOT EXISTS(SELECT 1 FROM jsonb_each(d.provider_mutation_evidence) e
   WHERE e.key NOT IN('schema','base_schema','clock_skew_margin_seconds','provider_read_performed','provider_quiescence_proved')
    AND (CASE WHEN jsonb_typeof(e.value)='number' THEN (e.value::text)::numeric>=0
         AND (e.value::text)::numeric<=9223372036854775807
         AND trunc((e.value::text)::numeric)=(e.value::text)::numeric ELSE false END) IS NOT TRUE)
  AND (d.provider_mutation_evidence->>'intents_updated_since_start')::numeric>=0
  AND (d.provider_mutation_evidence->>'resource_slots_updated_since_start')::numeric>=0
  AND public.finalization_lost_dispatch_effect_scan_tolerable(d.provider_mutation_evidence) IS TRUE
 UNION
 SELECT j.id FROM dispatch_candidates j JOIN dispatch_original_identity ji ON ji.id=j.id
 JOIN public.capacity_dispatch_unknown_maintenance_dispositions d ON (j.unknown_maintenance_disposition_id,j.id,j.run_id)=(d.id,d.job_id,d.run_id)
 JOIN public.workflow_runs w ON w.id=d.run_id
 WHERE j.state='unknown_maintenance_disposed' AND j.started_at IS NOT NULL AND j.returned_at=d.original_returned_at
  AND j.finalization_ack_at IS NULL AND j.finalization_error IS NULL
  AND num_nonnulls(j.failed_original_disposition_id,j.native_denied_disposition_id,j.enrolled_failed_disposition_id,
        j.abandoned_disposition_id,j.finalization_lost_disposition_id,j.unknown_maintenance_disposition_id)=1
  AND j.started_at<j.returned_at AND j.returned_at<j.lease_expires_at
  AND d.executor_barrier='disposing_core_process_started_after_lease_expiry_v1'
  AND d.disposing_core_process_started_at>j.lease_expires_at AND d.disposing_core_process_started_at<=d.recorded_at
  AND d.recorded_at>=j.lease_expires_at+interval '15 minutes'
  AND d.reason='unknown_failed_maintenance_dispatch_disposed' AND d.historical_return='unknown'
  AND j.return_status='failed' AND w.status='failed'
  AND j.return_error='capacity dispatch original deadline exceeded' AND w.error=j.return_error
  AND w.started_at=j.started_at AND w.finished_at=j.returned_at AND w.result IS NOT NULL
  AND d.original_dispatch_sha256 ~ '^[a-f0-9]{64}$'
  AND d.original_run_sha256=encode(sha256(convert_to(to_jsonb(w)::text,'UTF8')),'hex')
  AND ARRAY(SELECT k FROM jsonb_object_keys(d.provider_mutation_evidence) AS k ORDER BY k COLLATE "C")=ARRAY['base','current_member_count','current_members','current_members_sha256','invalid_maintenance_canary_rows','policy_epoch_valid','refresh_only_result','schema']::text[]
  AND ARRAY(SELECT k FROM jsonb_object_keys(d.provider_mutation_evidence->'base') AS k ORDER BY k COLLATE "C")=ARRAY['authority_reads_since_start','authority_returns_since_start','authority_transport_returns_since_start','base_schema','caller_possible_sends_since_start','caller_returns_since_start','canary_challenges_since_start','canary_nonces_since_start','canary_possible_sends_since_start','canary_returns_since_start','clock_skew_margin_seconds','create_witnesses_since_start','enrollments_since_start','executor_activity_updated_since_start','grants_created_or_updated_since_start','installations_since_start','intent_events_since_start','intents_updated_since_start','native_commands_since_start','native_lifetime_archives_since_start','native_lifetimes_updated_since_start','native_pod_checkpoints_since_start','native_poweroff_reads_since_start','notify_window_markers_for_job','observation_refresh_slot_updates','open_undisposed_grants','partial_nativeoff_reads_since_start','partial_nativeoff_reconciliations_since_start','prejournal_refusal_recoveries_since_start','preregistrations_since_start','presend_retirement_recoveries_since_start','provider_quiescence_proved','provider_read_performed','pure_assessment_intent_updates','qualification_native_source_returns_since_start','qualification_probe_challenges_since_start','resource_slots_updated_since_start','retirement_contexts_since_start','retirement_delete_bindings_since_start','retirement_intents_since_start','retirement_native_readbacks_since_start','retirement_original_returns_since_start','runtime_snapshot_challenges_since_start','runtime_snapshot_returns_since_start','schema','source_recovery_cleanup_challenges_since_start','source_recovery_cleanup_effect_permits_since_start']::text[]
  AND NOT EXISTS(SELECT 1 FROM jsonb_each(d.provider_mutation_evidence->'base') e
   WHERE e.key NOT IN('schema','base_schema','clock_skew_margin_seconds','provider_read_performed','provider_quiescence_proved')
    AND (CASE WHEN jsonb_typeof(e.value)='number' THEN (e.value::text)::numeric>=0
         AND (e.value::text)::numeric<=9223372036854775807
         AND trunc((e.value::text)::numeric)=(e.value::text)::numeric ELSE false END) IS NOT TRUE)
  AND (d.provider_mutation_evidence#>>'{base,intents_updated_since_start}')::numeric>=0
  AND (d.provider_mutation_evidence#>>'{base,resource_slots_updated_since_start}')::numeric>=0
  AND d.current_members_sha256=d.provider_mutation_evidence->>'current_members_sha256'
  AND public.unknown_maintenance_dispatch_effect_scan_tolerable(d.provider_mutation_evidence) IS TRUE
)'''
    if schema_version == 89:
        return original
    return original[:-1] + r'''
 UNION
 SELECT j.id FROM dispatch_candidates j JOIN dispatch_original_identity ji ON ji.id=j.id
 JOIN public.capacity_dispatch_http_maintenance_dispositions d ON (j.id,j.run_id)=(d.job_id,d.run_id)
 JOIN public.workflow_runs w ON w.id=d.run_id
 WHERE j.state='http_maintenance_disposed' AND d.id<>'00000000-0000-0000-0000-000000000000'::uuid
  AND j.started_at IS NOT NULL AND j.returned_at=d.original_returned_at AND j.lease_expires_at IS NOT NULL
  AND j.finalization_ack_at IS NULL
  AND num_nonnulls(j.failed_original_disposition_id,j.native_denied_disposition_id,j.enrolled_failed_disposition_id,
        j.abandoned_disposition_id,j.finalization_lost_disposition_id,j.unknown_maintenance_disposition_id)=0
  AND j.started_at<j.returned_at AND j.returned_at<j.lease_expires_at
  AND d.executor_barrier='disposing_core_process_started_after_lease_expiry_v1'
  AND d.disposing_core_process_started_at>j.lease_expires_at AND d.disposing_core_process_started_at<=d.recorded_at
  AND d.recorded_at>=j.lease_expires_at+interval '15 minutes'
  AND d.disposing_core_hostname ~ '^[A-Za-z0-9][A-Za-z0-9.-]{0,252}$' AND d.disposing_core_pid>0
  AND d.disposing_core_source_commit ~ '^[a-f0-9]{40}$'
  AND d.issuer ~ '^collaborator:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
  AND d.reason='recorded_context_refused_http_maintenance_dispatch_disposed' AND d.historical_return='unknown'
  AND j.return_status='failed' AND w.status='failed'
  AND j.return_error='capacity dispatch original context refused' AND j.finalization_error=j.return_error AND w.error=j.return_error
  AND w.started_at=j.started_at AND w.finished_at=j.returned_at AND w.result IS NOT NULL
  AND (w.workflow_id IS NULL OR w.workflow_id::text=j.envelope::jsonb#>>'{workflow,id}')
  AND (w.workflow_namespace,w.workflow_name,w.workflow_version::text) IS NOT DISTINCT FROM
      (j.envelope::jsonb#>>'{workflow,namespace}',j.envelope::jsonb#>>'{workflow,name}',j.envelope::jsonb#>>'{workflow,version}')
  AND w.inputs=j.envelope::jsonb->'inputs' AND w.metadata=j.envelope::jsonb->'metadata'
  AND (w.result#>>'{workflow,id}',w.result#>>'{workflow,kind}',w.result#>>'{workflow,namespace}',w.result#>>'{workflow,name}',w.result#>>'{workflow,version}')
      IS NOT DISTINCT FROM (j.envelope::jsonb#>>'{workflow,id}','workflow',j.envelope::jsonb#>>'{workflow,namespace}',j.envelope::jsonb#>>'{workflow,name}',j.envelope::jsonb#>>'{workflow,version}')
  AND d.original_dispatch_updated_at IS NOT NULL AND d.original_dispatch_updated_at<=d.recorded_at
  AND d.original_dispatch_sha256 ~ '^[a-f0-9]{64}$'
  AND d.original_dispatch_sha256=encode(sha256(convert_to((to_jsonb(j)||jsonb_build_object('state','unknown','updated_at',d.original_dispatch_updated_at))::text,'UTF8')),'hex')
  AND d.original_run_sha256=encode(sha256(convert_to(to_jsonb(w)::text,'UTF8')),'hex')
  AND ARRAY(SELECT k FROM jsonb_object_keys(d.provider_mutation_evidence) AS k ORDER BY k COLLATE "C")=ARRAY['base','current_member_count','current_members','current_members_sha256','invalid_maintenance_canary_rows','policy_epoch_valid','refresh_only_result','schema']::text[]
  AND ARRAY(SELECT k FROM jsonb_object_keys(d.provider_mutation_evidence->'base') AS k ORDER BY k COLLATE "C")=ARRAY['authority_reads_since_start','authority_returns_since_start','authority_transport_returns_since_start','base_schema','caller_possible_sends_since_start','caller_returns_since_start','canary_challenges_since_start','canary_nonces_since_start','canary_possible_sends_since_start','canary_returns_since_start','clock_skew_margin_seconds','create_witnesses_since_start','enrollments_since_start','executor_activity_updated_since_start','grants_created_or_updated_since_start','installations_since_start','intent_events_since_start','intents_updated_since_start','native_commands_since_start','native_lifetime_archives_since_start','native_lifetimes_updated_since_start','native_pod_checkpoints_since_start','native_poweroff_reads_since_start','notify_window_markers_for_job','observation_refresh_slot_updates','open_undisposed_grants','partial_nativeoff_reads_since_start','partial_nativeoff_reconciliations_since_start','prejournal_refusal_recoveries_since_start','preregistrations_since_start','presend_retirement_recoveries_since_start','provider_quiescence_proved','provider_read_performed','pure_assessment_intent_updates','qualification_native_source_returns_since_start','qualification_probe_challenges_since_start','resource_slots_updated_since_start','retirement_contexts_since_start','retirement_delete_bindings_since_start','retirement_intents_since_start','retirement_native_readbacks_since_start','retirement_original_returns_since_start','runtime_snapshot_challenges_since_start','runtime_snapshot_returns_since_start','schema','source_recovery_cleanup_challenges_since_start','source_recovery_cleanup_effect_permits_since_start']::text[]
  AND NOT EXISTS(SELECT 1 FROM jsonb_each(d.provider_mutation_evidence->'base') e
   WHERE e.key NOT IN('schema','base_schema','clock_skew_margin_seconds','provider_read_performed','provider_quiescence_proved')
    AND (CASE WHEN jsonb_typeof(e.value)='number' THEN (e.value::text)::numeric>=0
         AND (e.value::text)::numeric<=9223372036854775807
         AND trunc((e.value::text)::numeric)=(e.value::text)::numeric ELSE false END) IS NOT TRUE)
  AND (d.provider_mutation_evidence#>>'{base,intents_updated_since_start}')::numeric>=0
  AND (d.provider_mutation_evidence#>>'{base,resource_slots_updated_since_start}')::numeric>=0
  AND d.current_members_sha256=d.provider_mutation_evidence->>'current_members_sha256'
  AND d.current_members_sha256 ~ '^[a-f0-9]{64}$'
  AND jsonb_typeof(d.provider_mutation_evidence->'current_member_count')='number'
  AND d.provider_mutation_evidence->>'current_member_count'='1'
  AND jsonb_typeof(d.provider_mutation_evidence->'invalid_maintenance_canary_rows')='number'
  AND d.provider_mutation_evidence->>'invalid_maintenance_canary_rows'='0'
  AND d.provider_mutation_evidence#>>'{base,clock_skew_margin_seconds}'='30'
  AND NOT EXISTS(SELECT 1 FROM jsonb_each(d.provider_mutation_evidence->'base') e
   WHERE e.key NOT IN('schema','base_schema','clock_skew_margin_seconds','provider_read_performed','provider_quiescence_proved')
    AND e.value::text !~ '^(0|[1-9][0-9]*)$')
  AND NOT EXISTS(SELECT 1 FROM jsonb_array_elements(d.provider_mutation_evidence->'current_members') m
   WHERE (ARRAY(SELECT k FROM jsonb_object_keys(m) AS k ORDER BY k COLLATE "C")) IS DISTINCT FROM
    ARRAY['enrollment_sha256','installation_sha256','policy_checksum','policy_id','preregistration_id','resource_id','slot','slot_sha256']::text[]
    OR jsonb_typeof(m->'slot') IS DISTINCT FROM 'number' OR m->>'slot' IS DISTINCT FROM '1'
    OR jsonb_typeof(m->'resource_id') IS DISTINCT FROM 'string' OR COALESCE(m->>'resource_id','')='' OR octet_length(m->>'resource_id')>256
    OR EXISTS(SELECT 1 FROM unnest(ARRAY['policy_id','preregistration_id']) k WHERE jsonb_typeof(m->k) IS DISTINCT FROM 'string'
      OR COALESCE(m->>k,'') !~ '^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$' OR m->>k='00000000-0000-0000-0000-000000000000')
    OR EXISTS(SELECT 1 FROM unnest(ARRAY['enrollment_sha256','installation_sha256','slot_sha256','policy_checksum']) k
      WHERE jsonb_typeof(m->k) IS DISTINCT FROM 'string' OR COALESCE(m->>k,'') !~ '^[a-f0-9]{64}$'))
  AND public.http_maintenance_dispatch_effect_scan_tolerable(d.provider_mutation_evidence) IS TRUE
)'''

def held_database_sql(expected):
    e = validate_held_original(expected)
    # Every interpolated operand is a closed UUID, hex digest or strict UTC
    # birth checked above. No caller SQL, identifiers or credentials are accepted.
    quote = lambda value: "'" + value.replace("'", "''") + "'"
    retirement, prereg, run = (quote(e[k]) for k in ('retirement_request_id','preregistration_id','original_run_id'))
    policy, workflow = quote(e['policy_id']), quote(e['workflow_id'])
    wire, frame_pin, caller = (quote(e[k]) for k in ('intent_pgtext_sha256','original_frame_sha256','original_caller_sha256'))
    resource, birth = quote(e['native_tuple']['resource_id']), quote(e['native_tuple']['resource_created_at'])
    owner, executor = quote(e['lease_owner']), quote(e['executor_id'])
    members = quote(json.dumps(e['native_members'], sort_keys=True, separators=(',',':')))
    survivors = quote(json.dumps(e['historical_survivors'], sort_keys=True, separators=(',',':')))
    profile = e['physical_profile']
    frame_sql = held_original_frame_sql(retirement)
    return f"""BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY;
SET LOCAL enable_indexscan=on;
SET LOCAL statement_timeout='8000ms';
SET LOCAL lock_timeout='1000ms';
SET LOCAL TIME ZONE 'UTC';
SELECT count(*) AS root_held_busy_runs FROM (
 SELECT wr.id FROM public.manifests m JOIN public.workflow_runs wr ON wr.workflow_id=m.id
 WHERE m.kind='workflow' AND m.namespace='dakasa-production' AND m.name IN('notify-aws-elastic-capacity','notify-hetzner-elastic-capacity')
 AND (COALESCE(wr.status,'') NOT IN('succeeded','failed','cancelled') OR wr.finished_at IS NULL)
 UNION
 SELECT wr.id FROM public.workflow_runs wr
 WHERE wr.workflow_namespace='dakasa-production' AND wr.workflow_name IN('notify-aws-elastic-capacity','notify-hetzner-elastic-capacity')
 AND (COALESCE(wr.status,'') NOT IN('succeeded','failed','cancelled') OR wr.finished_at IS NULL)
) AS busy_run_ids
\\gset
SET LOCAL enable_indexscan=off;
WITH scoped AS (SELECT * FROM public.capacity_intents WHERE namespace='dakasa-production' AND environment='production' AND domain='notify' AND dimension IN('original_notify_aws_vm_members','original_notify_hetzner_vm_members')),
 held AS (SELECT * FROM scoped WHERE dimension='original_notify_aws_vm_members' AND encode(digest(intent::text,'sha256'),'hex')={wire}),
 original AS (SELECT * FROM public.capacity_vm_retirement_intents WHERE id={retirement}::uuid AND preregistration_id={prereg}::uuid),
 frame(frame_text) AS ({frame_sql}),
 policies AS MATERIALIZED (SELECT p.* FROM public.manifests p
  WHERE p.kind='capacity_policy' AND p.namespace='dakasa-production'
   AND p.name IN('notify-aws-elastic-capacity','notify-hetzner-elastic-capacity') AND p.active
   AND NOT EXISTS(SELECT 1 FROM public.manifests n WHERE (n.kind,n.namespace,n.name)=(p.kind,p.namespace,p.name) AND n.version>p.version)),
 bindings AS MATERIALIZED (SELECT b.value b FROM policies p CROSS JOIN LATERAL jsonb_array_elements(p.spec->'mutation_bindings') b),
 member_inputs AS (SELECT value m FROM jsonb_array_elements({members}::jsonb)),
 survivor_inputs AS (SELECT value h FROM jsonb_array_elements({survivors}::jsonb)),
 current_members AS MATERIALIZED (
  SELECT m.m,p.id preregistration_id,en.enrollment_sha256,en.enrollment_record,w.original_record witness,
   sl.slot_record,sl.revision,g.grant_record
  FROM member_inputs m JOIN public.capacity_resource_slots sl ON
   sl.integration_instance_id={quote(profile['integration_instance_id'])}::uuid
   AND sl.scope_checksum={quote(profile['scope_checksum'])} AND sl.profile_name='notify-aws-elastic'
   AND sl.slot=(m.m->>'slot')::int
  JOIN public.capacity_vm_provisioning_preregistrations p ON p.id=(m.m->>'preregistration_id')::uuid
  JOIN public.capacity_mutation_grants g ON g.id=p.create_grant_id AND g.id=(m.m->>'create_grant_id')::uuid
  JOIN public.capacity_vm_original_enrollments en ON en.preregistration_id=p.id
  JOIN public.capacity_guest_original_create_witnesses w ON w.preregistration_id=p.id
  WHERE sl.resource_id=m.m->>'resource_id' AND sl.slot_record->>'resource_id'=sl.resource_id
   AND (sl.slot_record->>'resource_created_at')::timestamptz=(m.m->>'resource_created_at')::timestamptz
   AND COALESCE(sl.slot_record->>'tombstone','false')='false' AND NOT(sl.slot_record ? 'authority_kind')
   AND sl.namespace='dakasa-production' AND sl.environment='production' AND sl.domain='notify' AND sl.dimension='original_notify_aws_vm_members'
   AND sl.revision=(m.m->>'slot_revision')::bigint AND encode(digest(sl.slot_record::text,'sha256'),'hex')=m.m->>'slot_record_sha256'
   AND g.state='confirmed' AND g.slot=sl.slot AND g.integration_instance_id=sl.integration_instance_id
   AND g.scope_checksum=sl.scope_checksum AND g.profile_name=sl.profile_name
   AND g.original_disposition_id IS NULL AND g.failed_original_disposition_id IS NULL AND g.native_denied_disposition_id IS NULL AND g.enrolled_failed_disposition_id IS NULL
   AND en.enrollment_sha256=m.m->>'enrollment_sha256' AND en.enrollment_record#>>'{{statement,tuple,provider}}'='aws'
   AND en.enrollment_record#>>'{{statement,tuple,resource_id}}'=sl.resource_id
   AND (en.enrollment_record#>>'{{statement,tuple,resource_created_at}}')::timestamptz=(m.m->>'resource_created_at')::timestamptz
   AND w.original_record->'tuple'=en.enrollment_record#>'{{statement,tuple}}'),
 historical_useful AS MATERIALIZED (
  SELECT h.h,m.m,
   jsonb_build_object('enrollment',to_jsonb(en),'witness',to_jsonb(w),'read_challenge',to_jsonb(c),
    'read_return',to_jsonb(r),'read_nonce',to_jsonb(n),'publication_challenge',to_jsonb(pc),
    'publication_return',to_jsonb(pub),'publication_nonce',to_jsonb(pn))::text frame_text
  FROM survivor_inputs h JOIN current_members m ON (m.m->>'slot')::int=(h.h->>'slot')::int
  JOIN public.capacity_vm_original_enrollments en ON en.preregistration_id=m.preregistration_id
  JOIN public.capacity_guest_original_create_witnesses w ON w.preregistration_id=m.preregistration_id
  JOIN public.capacity_guest_notify_canary_challenges c ON c.id=(h.h->>'read_challenge_id')::uuid AND c.preregistration_id=m.preregistration_id
  JOIN public.capacity_guest_notify_canary_returns r ON r.challenge_id=c.id AND r.outcome='accepted'
  JOIN public.capacity_guest_notify_canary_nonces n ON n.challenge_id=c.id
  JOIN public.capacity_guest_notify_canary_challenges pc ON pc.id=c.record_challenge_id AND pc.id=(h.h->>'publication_challenge_id')::uuid
  JOIN public.capacity_guest_notify_canary_returns pub ON pub.challenge_id=pc.id AND pub.outcome='accepted'
  JOIN public.capacity_guest_notify_canary_nonces pn ON pn.challenge_id=pc.id
  WHERE c.phase='read' AND pc.phase='publish' AND pc.preregistration_id=c.preregistration_id AND pc.id=pc.record_challenge_id
   AND c.policy_id={policy}::uuid AND pc.policy_id=c.policy_id AND c.workflow_id={workflow}::uuid AND pc.workflow_id=c.workflow_id
   AND c.generation=14 AND c.fence=28 AND pc.generation=c.generation AND pc.fence=c.fence
   AND c.lease_owner={owner} AND pc.lease_owner=c.lease_owner AND c.executor_id=pc.executor_id
   AND c.original_record->>'usage_class'='before_retirement_floor' AND pc.original_record->>'usage_class'='before_retirement_floor'
   AND c.original_record->>'enrollment_sha256'=en.enrollment_sha256 AND pc.original_record->>'enrollment_sha256'=en.enrollment_sha256
   AND c.original_record->'tuple'=en.enrollment_record#>'{{statement,tuple}}' AND pc.original_record->'tuple'=c.original_record->'tuple'
   AND r.return_sha256=h.h->>'read_return_sha256' AND pub.return_sha256=h.h->>'publication_return_sha256'
   AND encode(digest(r.original_wire,'sha256'),'hex')=r.return_sha256 AND encode(digest(pub.original_wire,'sha256'),'hex')=pub.return_sha256
   AND encode(digest(c.original_wire,'sha256'),'hex')=c.challenge_sha256 AND encode(digest(pc.original_wire,'sha256'),'hex')=pc.challenge_sha256
   AND encode(digest(n.final_challenge_wire,'sha256'),'hex')=n.final_challenge_sha256
   AND encode(digest(pn.final_challenge_wire,'sha256'),'hex')=pn.final_challenge_sha256
   AND r.business_observation->>'creation_freshness_class'='original_challenge_publish_consume_read_v2'
   AND r.business_observation->>'creation_upper_bound_seconds'='5'
   AND r.original_transport->>'Status'='200' AND pub.original_transport->>'Status'='200'
   AND r.original_transport->>'ResponseBodyScope'='complete_original_body_read' AND pub.original_transport->>'ResponseBodyScope'='complete_original_body_read'
   AND r.original_transport->>'PreflightFailed'='false' AND r.original_transport->>'DoFailed'='false' AND r.original_transport->>'ReadFailed'='false' AND r.original_transport->>'CloseFailed'='false' AND r.original_transport->>'OriginalContextFailed'='false'
   AND pub.original_transport->>'PreflightFailed'='false' AND pub.original_transport->>'DoFailed'='false' AND pub.original_transport->>'ReadFailed'='false' AND pub.original_transport->>'CloseFailed'='false' AND pub.original_transport->>'OriginalContextFailed'='false'
   AND (r.original_transport->>'DriverReturnedAt')::timestamptz>=(pub.original_transport->>'StartedAt')::timestamptz
   AND (r.original_transport->>'DriverReturnedAt')::timestamptz-(pub.original_transport->>'StartedAt')::timestamptz<=interval '5 seconds'
   AND r.recorded_at<=(SELECT original_deadline FROM original)),
{retained_dispatch_terminal_ctes(89)}
SELECT jsonb_build_object(
 'database',current_database(),'readonly',current_setting('transaction_read_only'),
 'schema',(SELECT max(version_id) FROM goose_db_version WHERE is_applied),
 'migration90_applied',(SELECT count(*) FROM goose_db_version WHERE version_id=90 AND is_applied),
 'migration88_applied',(SELECT count(*) FROM goose_db_version WHERE version_id=88 AND is_applied),
 'migration89_applied',(SELECT count(*) FROM goose_db_version WHERE version_id=89 AND is_applied),
 'history_rows',(SELECT count(*) FROM goose_db_version),
 'history_exact',(SELECT encode(digest(COALESCE(jsonb_agg(to_jsonb(v) ORDER BY id),'[]'::jsonb)::text,'sha256'),'hex')={quote(e['history']['sha256'])} FROM goose_db_version v),
 'catalog_rows',(SELECT count(*) FROM public.manifests),
 'catalog_exact',(SELECT encode(digest(COALESCE(jsonb_agg(to_jsonb(m) ORDER BY kind,namespace,name,version,id),'[]'::jsonb)::text,'sha256'),'hex')={quote(e['catalog']['sha256'])} FROM public.manifests m),
 'index89_valid',COALESCE((SELECT i.indisvalid AND i.indisready AND i.indislive AND NOT i.indisunique
 AND i.indrelid='public.workflow_runs'::regclass AND i.indnkeyatts=1 AND i.indnatts=1
 AND i.indpred IS NULL AND i.indexprs IS NULL AND a.amname='btree'
 AND pg_get_indexdef(i.indexrelid,1,false)='workflow_id'
 FROM pg_index i JOIN pg_class c ON c.oid=i.indexrelid JOIN pg_am a ON a.oid=c.relam
 WHERE i.indexrelid=to_regclass('public.workflow_runs_workflow_id_idx')),false),
 'active_latest_policies',(SELECT count(*) FROM policies),
 'current_original_catalog',(SELECT count(*) FROM policies p JOIN public.manifests w ON w.id={workflow}::uuid AND w.kind='workflow' AND w.namespace=p.spec#>>'{{workflow,namespace}}' AND w.name=p.spec#>>'{{workflow,name}}'
  WHERE p.id={policy}::uuid AND p.checksum={quote(e['policy_checksum'])} AND w.checksum={quote(e['workflow_checksum'])} AND w.active
  AND NOT EXISTS(SELECT 1 FROM public.manifests n WHERE (n.kind,n.namespace,n.name)=(w.kind,w.namespace,w.name) AND n.version>w.version)),
 'current_original_binding',(SELECT count(*) FROM bindings b JOIN public.manifests i ON i.id=(b.b->>'integration_instance_id')::uuid AND i.kind='integration_instance'
 JOIN public.manifests t ON t.id=(b.b->>'integration_type_id')::uuid AND t.kind='integration_type'
 WHERE b.b->>'integration_instance_id'={quote(profile['integration_instance_id'])} AND b.b->>'scope_checksum'={quote(profile['scope_checksum'])} AND b.b->>'profile_name'='notify-aws-elastic'
 AND i.active AND i.checksum=b.b->>'integration_checksum' AND t.active AND t.checksum=b.b->>'integration_type_checksum'),
 'current_physical_members',(SELECT count(*) FROM current_members),
 'physical_profile_slot_count',(SELECT count(*) FROM public.capacity_resource_slots WHERE integration_instance_id={quote(profile['integration_instance_id'])}::uuid AND scope_checksum={quote(profile['scope_checksum'])} AND profile_name='notify-aws-elastic' AND resource_id<>'' AND COALESCE(slot_record->>'tombstone','false')='false'),
 'historical_useful_survivors',(SELECT count(*) FROM historical_useful WHERE encode(digest(frame_text,'sha256'),'hex')=h->>'frame_sha256'),

 'forward_table_present',to_regclass('public.capacity_guest_retirement_forwards') IS NOT NULL,
 'held_count',(SELECT count(*) FROM held),
 'held_unchanged_expired',(SELECT count(*) FROM held WHERE intent->>'generation'='14' AND intent->>'fencing_token'='28' AND intent->>'phase'='draining' AND intent->>'policy_id'={policy} AND intent->>'policy_checksum'={quote(e['policy_checksum'])} AND intent->>'lease_owner'={owner} AND intent->>'lease_executor_id'={executor} AND (intent->>'lease_expires_at')::timestamptz<=clock_timestamp() AND COALESCE((intent->>'recovery_only')::boolean,false)=false AND COALESCE((intent->>'floor_degraded')::boolean,false)=false AND COALESCE(intent->'retirement_forward','null'::jsonb)='null'::jsonb AND COALESCE(intent->'failed_installed_disposal','null'::jsonb)='null'::jsonb AND COALESCE(intent->'failed_serving_disposal','null'::jsonb)='null'::jsonb AND intent#>>'{{baseline_snapshot,units}}'='3' AND intent#>>'{{decision,units}}'='2' AND intent#>>'{{decision,profile}}'='notify-aws-elastic'),
 'known_original',(SELECT count(*) FROM original r JOIN public.capacity_guest_original_retirement_contexts c ON c.intent_id=r.id JOIN public.capacity_vm_provisioning_preregistrations p ON p.id=r.preregistration_id JOIN public.capacity_mutation_grants g ON g.id=p.create_grant_id WHERE r.original_deadline<=clock_timestamp() AND c.original_context_deadline<=clock_timestamp() AND c.executor_id::text={executor} AND c.core_actual_source_commit='{OLD_SOURCE}' AND r.intent_record->>'generation'='14' AND r.intent_record->>'fence'='28' AND r.intent_record->>'lease_owner'={owner} AND r.intent_record->>'policy_id'={policy} AND r.intent_record->>'policy_checksum'={quote(e['policy_checksum'])} AND r.intent_record->>'workflow_id'={workflow} AND r.intent_record->>'workflow_checksum'={quote(e['workflow_checksum'])} AND r.intent_record#>>'{{tuple,provider}}'='aws' AND r.intent_record#>>'{{tuple,resource_id}}'={resource} AND r.intent_record#>>'{{tuple,resource_created_at}}'={birth} AND r.intent_record->>'slot'='3' AND g.state='confirmed'),
 'closed_original_run',(SELECT count(*) FROM public.workflow_runs w JOIN public.capacity_dispatch_jobs j ON j.run_id=w.id WHERE w.id={run}::uuid AND (w.workflow_id IS NULL OR w.workflow_id={workflow}::uuid) AND j.envelope::jsonb#>>'{{workflow,id}}'={workflow} AND w.status='failed' AND j.state='returned' AND j.return_status='failed' AND j.returned_at IS NOT NULL AND w.finished_at=j.returned_at AND j.finalization_ack_at IS NOT NULL AND w.result#>>'{{steps,0,metadata,generation}}'='14' AND w.result#>>'{{steps,0,metadata,fencing_token}}'='28' AND w.result#>>'{{steps,0,metadata,lease_owner}}'={owner}),
 'original_frame_exact',(SELECT encode(digest(frame.frame_text,'sha256'),'hex')={frame_pin} FROM frame),
 'original_row_count',(SELECT count(*) FROM public.capacity_vm_retirement_original_returns WHERE intent_id={retirement}::uuid),
 'original_failed_caller',(SELECT count(*) FROM public.capacity_guest_original_caller_returns WHERE intent_id={retirement}::uuid AND return_sha256={caller} AND original_record->>'status'='0' AND original_record->>'do_failed'='true' AND original_record->>'original_context_failed'='true' AND original_record->>'body_persisted'='false'),
 'authority_reads',(SELECT count(*) FROM public.capacity_guest_original_authority_reads WHERE intent_id={retirement}::uuid),
 'authority_returns',(SELECT count(*) FROM public.capacity_guest_original_authority_returns v JOIN public.capacity_guest_original_authority_reads r ON r.id=v.read_id WHERE r.intent_id={retirement}::uuid),
 'journal_transports',(SELECT count(*) FROM public.capacity_guest_original_authority_transport_returns t JOIN public.capacity_guest_original_authority_reads r ON r.id=t.read_id WHERE r.intent_id={retirement}::uuid),
 'delete_bindings',(SELECT count(*) FROM public.capacity_vm_retirement_delete_bindings WHERE intent_id={retirement}::uuid),
 'forward_admissions',(SELECT count(*) FROM public.capacity_guest_retirement_forwards WHERE retirement_request_id={retirement}::uuid),
 'other_leases',(SELECT count(*) FROM scoped c WHERE NOT(c.dimension='original_notify_aws_vm_members' AND encode(digest(c.intent::text,'sha256'),'hex')={wire}) AND (COALESCE(c.intent->>'lease_owner','')<>'' OR COALESCE(c.intent->>'lease_executor_id','')<>'' OR (c.intent->>'lease_expires_at')::timestamptz>clock_timestamp())),
 'other_nonsteady',(SELECT count(*) FROM scoped c WHERE NOT(c.dimension='original_notify_aws_vm_members' AND encode(digest(c.intent::text,'sha256'),'hex')={wire}) AND (c.intent->>'lease_expires_at' IS NOT NULL OR coalesce((c.intent->>'recovery_only')::boolean,false) OR coalesce(c.intent->>'phase','') NOT IN('promoted','reconciled','reconciled_partial') OR coalesce(c.intent#>>'{{original_notify_window,state}}','original_returns_observed')<>'original_returns_observed')),
 'busy_jobs',(SELECT count(*) FROM dispatch_candidates j WHERE NOT EXISTS(SELECT 1 FROM dispatch_terminal_witnesses d WHERE d.job_id=j.id)),
 'busy_runs',:'root_held_busy_runs'::bigint,
 'native_authority',(SELECT count(*) FROM public.capacity_mutation_grants g
 WHERE g.original_disposition_id IS NULL AND g.failed_original_disposition_id IS NULL AND g.native_denied_disposition_id IS NULL AND g.enrolled_failed_disposition_id IS NULL
 AND ((g.namespace='dakasa-production' AND g.environment='production' AND g.domain='notify' AND g.dimension IN('original_notify_aws_vm_members','original_notify_hetzner_vm_members'))
  OR EXISTS(SELECT 1 FROM bindings b WHERE (g.integration_instance_id::text,g.scope_checksum,g.profile_name)=(b.b->>'integration_instance_id',b.b->>'scope_checksum',b.b->>'profile_name')))
 AND (g.state IS NULL OR g.state NOT IN('confirmed','rejected','expired','compensated'))));
COMMIT;
"""

def held_current_preimage(cut, run, expected, phase):
    """Cheap exact retained-frame CAS read immediately before/after image PATCH.

    It is a separate read-only observation, never a cross-system lock or an
    authorization to repair a changed frame. Any unknown or mismatch holds.
    """
    require_bound()
    e = match_held_identity(expected)
    need(phase in ('PRESEND','AFTER-ACK'), 'CLOSED_HELD_CURRENT_READ_PHASE')
    frame = held_original_frame_sql("'" + e['retirement_request_id'] + "'")
    sql = """BEGIN READ ONLY;
SET LOCAL statement_timeout='8000ms';
SET LOCAL lock_timeout='1000ms';
SET LOCAL TIME ZONE 'UTC';
WITH current_held AS (SELECT * FROM public.capacity_intents WHERE namespace='dakasa-production'
 AND environment='production' AND domain='notify' AND dimension='original_notify_aws_vm_members'),
 frame(frame_text) AS (""" + frame + """)
SELECT jsonb_build_object('held_count',(SELECT count(*) FROM current_held),
 'intent_exact',(SELECT encode(digest(intent::text,'sha256'),'hex')='""" + e['intent_pgtext_sha256'] + """' FROM current_held),
 'frame_exact',(SELECT encode(digest(frame_text,'sha256'),'hex')='""" + e['original_frame_sha256'] + """' FROM frame));
COMMIT;
"""
    name = 'HELD-CURRENT-' + phase
    cut.C.once(run / (name + '.sql'), sql.encode())
    command = 'PGOPTIONS="-c default_transaction_read_only=on -c statement_timeout=8000" psql -X -q -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -d yggdrasil -At'
    result = cut.subprocess.run(cut.KUBE + ['-n','dakasa','exec','-i','unified-database-0','--','sh','-c',command], input=sql.encode(), stdout=cut.subprocess.PIPE, stderr=cut.subprocess.PIPE, timeout=12, env={'PATH':'/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin','LANG':'C.UTF-8'})
    cut.C.once(run / (name + '.stdout'), result.stdout)
    cut.C.once(run / (name + '.stderr'), result.stderr)
    need(result.returncode == 0 and len(result.stdout) < 32768 and len(result.stderr) < 32768
         and cut.C.loads(result.stdout) == {'held_count':1,'intent_exact':True,'frame_exact':True},
         'UNCHANGED_HELD_PGTEXT_AND_ENTIRE_ORIGINAL_' + phase)


def database_held_preflight(cut, run, expected):
    require_bound()
    expected = match_held_identity(expected)
    review = expected['Root_review_ref']
    need(sha(read(review['path'], 1 << 20, 0o600)) == review['sha256'], 'ACTUAL_ROOT_HELD_ROLLOUT_REVIEW_STILL_PINNED')
    native = validate_held_native_observation(expected, cut.C.loads)
    sql = held_database_sql(expected)
    cut.C.once(run / 'DB-HELD-READONLY.sql', sql.encode())
    command = 'PGOPTIONS="-c default_transaction_read_only=on -c statement_timeout=8000" psql -X -q -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -d yggdrasil -At'
    result = cut.subprocess.run(cut.KUBE + ['-n','dakasa','exec','-i','unified-database-0','--','sh','-c',command], input=sql.encode(), stdout=cut.subprocess.PIPE, stderr=cut.subprocess.PIPE, timeout=12, env={'PATH':'/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin','LANG':'C.UTF-8'})
    cut.C.once(run / 'DB-HELD-READONLY.stdout', result.stdout)
    cut.C.once(run / 'DB-HELD-READONLY.stderr', result.stderr)
    need(result.returncode == 0 and len(result.stdout) < 32768 and len(result.stderr) < 32768, 'BOUNDED_HELD_READONLY_DB_RETURN_ZERO')
    value = cut.C.loads(result.stdout)
    need(value == {'database':'yggdrasil','readonly':'on','schema':90,
         'migration88_applied':1,'migration89_applied':1,'migration90_applied':1,
         'history_rows':expected['history']['rows'],'history_exact':True,
         'catalog_rows':expected['catalog']['rows'],'catalog_exact':True,'index89_valid':True,
         'active_latest_policies':2,'current_original_catalog':1,'current_original_binding':1,
         'current_physical_members':3,'physical_profile_slot_count':3,'historical_useful_survivors':2,
         'forward_table_present':True,'held_count':1,'held_unchanged_expired':1,
         'known_original':1,'closed_original_run':1,'original_frame_exact':True,'original_row_count':4,
         'original_failed_caller':1,'authority_reads':4,'authority_returns':4,'journal_transports':3,
         'delete_bindings':0,'forward_admissions':0,'other_leases':0,'other_nonsteady':0,
         'busy_jobs':0,'busy_runs':0,'native_authority':0},
         'ONLY_EXACT_CLOSED_HELD_ORIGINAL_IMAGE_ROLLOUT_NO_RETIREMENT_AUTHORITY')
    # Re-read the same immutable originals, not a new provider GET. No later
    # process may refresh an old receipt's clock or turn pending into OFF.
    need(validate_held_native_observation(expected, cut.C.loads) == native, 'SAME_FRESH_NATIVE_ORIGINALS_AFTER_DB')
    cut.C.once(run / 'HELD-ROLLOUT-READONLY-RETURN.PUBLIC.json', cut.C.wire({
         'schema':'image_only_fresh_native_off_historical_useful_readonly_admission_v1',
         'retirement_authority':False,'provider_mutations':False,'Guest_replay':False,
         'original_held_pgtext_sha256':expected['intent_pgtext_sha256'],
         'original_failure_relabelled':False,'historical_useful_is_fresh_business_authority':False,
         'native_observation':native,'history':expected['history'],'catalog':expected['catalog'],
         'snapshot_only_not_cross_system_atomicity':True}))
    return value


def require_http_maintenance_upgrade_bound():
    require_bound()
    need(HTTP_MAINTENANCE_UPGRADE_BOUND is True
         and ROOT_ROLLOUT_MODE == 'exact_held_partial_poweroff_original'
         and digest_value(HTTP_MAINTENANCE_PRE91_QUERY_SHA256),
         'QUALIFIED_R6_HTTP_MAINTENANCE_IMAGE_UPGRADE_NOT_BOUND')


def pg_utc_time(value):
    """Parse PG's UTC offset without changing its retained original wire."""
    need(type(value) is str and (value.endswith('Z') or value.endswith('+00:00')),
         'ACTUAL_PG_UTC_CLOCK_REQUIRED')
    return utc_time(value[:-6] + 'Z' if value.endswith('+00:00') else value)


def validate_http_maintenance_projection(value):
    need(type(value) is dict and set(value) == {'observed_at_pg','job_id','run_id',
         'original_dispatch_sha256','original_run_sha256','cas','effect_scan','admission'},
         'CLOSED_CANONICAL_HTTP_MAINTENANCE_PROJECTION')
    identity = HTTP_MAINTENANCE_HELD_IDENTITY
    need(value['job_id'] == identity['job_id'] and value['run_id'] == identity['run_id']
         and value['admission'] is True, 'ONLY_EXACT_KNOWN_HTTP_MAINTENANCE_HELD_ORIGINAL')
    pg_utc_time(value['observed_at_pg'])
    cas = value['cas']
    need(type(cas) is dict and set(cas) == {'job_id','expected_run_id','expected_envelope_sha256',
         'expected_fencing_token','expected_lease_owner','expected_pending_wake_count',
         'expected_returned_at','expected_run_sha256','expected_members_sha256'}, 'CLOSED_CANONICAL_NINE_CAS')
    need(cas['job_id'] == identity['job_id'] and cas['expected_run_id'] == identity['run_id']
         and full_id(cas['expected_lease_owner']) and cas['expected_lease_owner'] != '00000000-0000-0000-0000-000000000000'
         and type(cas['expected_fencing_token']) is int and 1 <= cas['expected_fencing_token'] <= 9007199254740991
         and type(cas['expected_pending_wake_count']) is int and 1 <= cas['expected_pending_wake_count'] <= 32,
         'EXACT_HTTP_MAINTENANCE_CAS_IDENTITIES_AND_BOUNDS')
    pg_utc_time(cas['expected_returned_at'])
    for key in ('expected_envelope_sha256','expected_run_sha256','expected_members_sha256'):
        need(digest_value(cas[key]), 'CLOSED_HTTP_MAINTENANCE_CAS_DIGEST')
    need(digest_value(value['original_dispatch_sha256'])
         and value['original_run_sha256'] == cas['expected_run_sha256'], 'WHOLE_HTTP_MAINTENANCE_ORIGINAL_ROW_PINS')
    scan = value['effect_scan']
    need(type(scan) is dict and set(scan) == {'schema','base','current_members','current_members_sha256',
         'current_member_count','policy_epoch_valid','refresh_only_result','invalid_maintenance_canary_rows'}
         and scan['schema'] == 'recorded_http_maintenance_dispatch_effect_scan_v1'
         and scan['current_members_sha256'] == cas['expected_members_sha256'], 'CANONICAL_HTTP_MAINTENANCE_SCAN_SHAPE_NOT_CALLER_PROOF')
    # Its full semantics are checked by the actual Source-derived SQL, not a
    # Python duplicate of the database or complete Go ADR0094 validator.
    return value


def load_http_maintenance_upgrade(C, path, expected_sha256):
    """Separate stable Root input, loaded before any possible native API call."""
    require_http_maintenance_upgrade_bound()
    evidence_ref({'path':str(path),'sha256':expected_sha256})
    raw = read(path, 128 << 10, 0o600)
    need(sha(raw) == expected_sha256, 'ROOT_REVIEWED_HTTP_MAINTENANCE_UPGRADE_SHA')
    value = C.loads(raw)
    need(type(value) is dict and set(value) == {'schema','identity','query_ref','projection_ref','Root_review_ref'}
         and value['schema'] == 'root_exact_recorded_http_maintenance_image_upgrade_v1'
         and value['identity'] == HTTP_MAINTENANCE_HELD_IDENTITY, 'FIXED_HTTP_MAINTENANCE_UPGRADE_IDENTITY_NOT_ANOTHER_UNKNOWN')
    original = {}
    for key in ('query_ref','projection_ref','Root_review_ref'):
        ref = evidence_ref(value[key])
        original[key] = read(ref['path'], 128 << 10, 0o600)
        need(sha(original[key]) == ref['sha256'], 'PINNED_HTTP_MAINTENANCE_' + key.upper())
    query = original['query_ref']
    need(sha(query) == HTTP_MAINTENANCE_PRE91_QUERY_SHA256
         and query.count(b'$1::uuid') == 1, 'EXACT_REVIEWED_CANONICAL_PRE91_QUERY_BYTES')
    projection = validate_http_maintenance_projection(C.loads(original['projection_ref']))
    review = C.loads(original['Root_review_ref'])
    identity = {key:value for key,value in projection.items() if key != 'observed_at_pg'}
    need(type(review) is dict and set(review) == {'schema','reviewed_by_root','unknown_state',
         'identity_sha256','pre91_query_sha256'}
         and review['schema'] == 'root_goose91_HTTP_HELD_upgrade_review_v1'
         and review['reviewed_by_root'] is True and review['unknown_state'] == 'UNKNOWN'
         and review['identity_sha256'] == sha(C.wire(identity))
         and review['pre91_query_sha256'] == HTTP_MAINTENANCE_PRE91_QUERY_SHA256,
         'ACTUAL_ROOT_REVIEWED_EXACT_HTTP_HELD_IDENTITY_NOT_DISPOSITION')
    return {'input':value,'projection':projection,'query':query}, raw


def http_maintenance_counts_sql(projection, schema_version):
    """Actual fixed-scope SQL: keep one exact UNKNOWN distinct from terminals."""
    e = validate_http_maintenance_projection(projection)
    identity = HTTP_MAINTENANCE_HELD_IDENTITY
    quote = lambda v: "'" + v.replace("'", "''") + "'"
    return """BEGIN READ ONLY;
SET LOCAL statement_timeout='8000ms';
SET LOCAL lock_timeout='1000ms';
SET LOCAL enable_indexscan=off;
SET LOCAL TIME ZONE 'UTC';
WITH """ + retained_dispatch_terminal_ctes(schema_version) + """,
http_maintenance_exact_held AS MATERIALIZED (
 SELECT j.id FROM dispatch_candidates j JOIN public.workflow_runs w ON w.id=j.run_id
 WHERE j.id=""" + quote(identity['job_id']) + """::uuid AND j.run_id=""" + quote(identity['run_id']) + """::uuid
 AND (j.realm,j.environment,j.domain,j.dimension)=('dakasa-production','production','notify','original_notify_hetzner_vm_members')
 AND j.protocol='capacity_dispatch_prestart_v1' AND j.state='unknown'
 AND j.return_status='failed' AND j.return_error='capacity dispatch original context refused'
 AND j.finalization_error=j.return_error AND w.status='failed' AND w.error=j.return_error
 AND j.started_at IS NOT NULL AND j.returned_at IS NOT NULL AND j.lease_expires_at IS NOT NULL
 AND j.started_at<j.returned_at AND j.returned_at<j.lease_expires_at AND j.lease_expires_at<clock_timestamp()
 AND w.started_at=j.started_at AND w.finished_at=j.returned_at AND j.finalization_ack_at IS NULL
 AND num_nonnulls(j.failed_original_disposition_id,j.native_denied_disposition_id,j.enrolled_failed_disposition_id,
  j.abandoned_disposition_id,j.finalization_lost_disposition_id,j.unknown_maintenance_disposition_id)=0
 AND encode(sha256(convert_to(to_jsonb(j)::text,'UTF8')),'hex')=""" + quote(e['original_dispatch_sha256']) + """
 AND encode(sha256(convert_to(to_jsonb(w)::text,'UTF8')),'hex')=""" + quote(e['original_run_sha256']) + """
)
SELECT jsonb_build_object(
 'total_jobs',(SELECT count(*) FROM dispatch_candidates j WHERE NOT EXISTS(SELECT 1 FROM dispatch_terminal_witnesses d WHERE d.job_id=j.id)),
 'held_jobs',(SELECT count(*) FROM http_maintenance_exact_held),
 'unrelated_jobs',(SELECT count(*) FROM dispatch_candidates j WHERE NOT EXISTS(SELECT 1 FROM dispatch_terminal_witnesses d WHERE d.job_id=j.id)
  AND NOT EXISTS(SELECT 1 FROM http_maintenance_exact_held h WHERE h.id=j.id)));
COMMIT;
"""


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


def held_r6_database_sql(expected):
    """Require the separately accepted index-only92; protocol91 stays exact."""
    sql = held_database_sql(expected)
    prior = retained_dispatch_terminal_ctes(89)
    need(sql.count(prior) == 1 and sql.count(" 'migration90_applied',") == 1,
         'EXACT_PRIOR_HELD_QUERY_FOR_SCHEMA92_INDEX_EXTENSION')
    return sql.replace(prior, retained_dispatch_terminal_ctes(91), 1).replace(
        " 'migration90_applied',",
        " 'migration92_applied',(SELECT count(*) FROM goose_db_version WHERE version_id=92 AND is_applied),\n"
        " 'history_max_version',(SELECT max(version_id) FROM goose_db_version),\n"
        " 'index92_valid'," + workflow_busy_logical_index92_sql() + ",\n"
        " 'migration91_applied',(SELECT count(*) FROM goose_db_version WHERE version_id=91 AND is_applied),\n 'migration90_applied',", 1)


def http_upgrade_db_read(cut, run, name, sql):
    """One read-only subprocess with original custody before semantic parsing."""
    need(re.fullmatch('DB-R6-[A-Z-]{1,64}', name), 'CLOSED_HTTP_UPGRADE_DB_EVIDENCE_NAME')
    cut.C.once(run / (name + '.sql'), sql.encode())
    command = 'PGOPTIONS="-c default_transaction_read_only=on -c statement_timeout=8000" psql -X -q -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -d yggdrasil -At'
    started_utc, started_mono = now(), time.monotonic()
    try:
        result = cut.subprocess.run(cut.KUBE + ['-n','dakasa','exec','-i','unified-database-0','--','sh','-c',command],
            input=sql.encode(), stdout=cut.subprocess.PIPE, stderr=cut.subprocess.PIPE, timeout=12,
            env={'PATH':'/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin','LANG':'C.UTF-8'})
    except cut.subprocess.TimeoutExpired as error:
        cut.C.once(run / (name + '.stdout'), error.stdout or b'')
        cut.C.once(run / (name + '.stderr'), error.stderr or b'')
        cut.C.once(run / (name + '.RETURN.json'), cut.C.wire({'started_at':started_utc,
            'returned_at':now(),'started_monotonic':started_mono,'returned_monotonic':time.monotonic(),
            'returncode':None,'timeout':True,'automatic_retry':False}))
        raise Hold('HTTP_MAINTENANCE_READONLY_TIMEOUT_NO_RETRY') from error
    cut.C.once(run / (name + '.stdout'), result.stdout)
    cut.C.once(run / (name + '.stderr'), result.stderr)
    cut.C.once(run / (name + '.RETURN.json'), cut.C.wire({'started_at':started_utc,
        'returned_at':now(),'started_monotonic':started_mono,'returned_monotonic':time.monotonic(),
        'returncode':result.returncode,'timeout':False,'automatic_retry':False}))
    need(result.returncode == 0 and len(result.stdout) < 128 << 10 and len(result.stderr) < 32768,
         'HTTP_MAINTENANCE_BOUNDED_READONLY_RETURN_ZERO')
    return cut.C.loads(result.stdout)


def http_maintenance_canonical_preimage(cut, run, upgrade, phase):
    """Fresh complete canonical semantics, never only the unchanged job/run."""
    require_http_maintenance_upgrade_bound()
    need(phase in ('PREFLIGHT','PRESEND','AFTER-ACK'), 'CLOSED_HTTP_MAINTENANCE_CURRENT_PHASE')
    query = upgrade['query']
    need(type(query) is bytes and sha(query) == HTTP_MAINTENANCE_PRE91_QUERY_SHA256
         and query.count(b'$1::uuid') == 1, 'PINNED_CANONICAL_HTTP_QUERY_NO_SOURCE_EVALUATION')
    sql = "BEGIN READ ONLY;\nSET LOCAL statement_timeout='8000ms';\nSET LOCAL lock_timeout='1000ms';\nSET LOCAL enable_indexscan=off;\nSET LOCAL standard_conforming_strings=on;\nSET LOCAL TIME ZONE 'UTC';\n"
    sql += query.decode('utf-8').replace('$1::uuid', "'" + HTTP_MAINTENANCE_HELD_IDENTITY['job_id'] + "'::uuid", 1)
    sql += '\nCOMMIT;\n'
    actual = validate_http_maintenance_projection(http_upgrade_db_read(cut, run,
        'DB-R6-HTTP-CANONICAL-' + phase, sql))
    wanted = validate_http_maintenance_projection(upgrade['projection'])
    need({k:v for k,v in actual.items() if k != 'observed_at_pg'} == {k:v for k,v in wanted.items() if k != 'observed_at_pg'},
         'FRESH_CANONICAL_HTTP_PROJECTION_MATCHES_COMPLETE_REVIEWED_ORIGINAL')
    age = (datetime.datetime.now(datetime.timezone.utc) - pg_utc_time(actual['observed_at_pg'])).total_seconds()
    need(0 <= age <= 15, 'ACTUAL_PG_OBSERVATION_FRESH_NOT_RELABELED')
    return actual


def http_maintenance_current_preimage(cut, run, upgrade, phase):
    require_http_maintenance_upgrade_bound()
    need(phase in ('PREFLIGHT','PRESEND','AFTER-ACK'), 'CLOSED_HTTP_MAINTENANCE_CURRENT_PHASE')
    projection = validate_http_maintenance_projection(upgrade['projection'])
    if phase in ('PRESEND','AFTER-ACK'):
        http_maintenance_canonical_preimage(cut, run, upgrade, phase)
    counts = http_upgrade_db_read(cut, run, 'DB-R6-HTTP-' + phase,
                                  http_maintenance_counts_sql(projection, 91))
    need(counts == {'total_jobs':1,'held_jobs':1,'unrelated_jobs':0},
         'EXACT_HTTP_HELD_ONE_TOTAL_ONE_HELD_ZERO_UNRELATED_' + phase)
    return counts


def validate_r6_held_database(value, e):
    """Exact92 snapshot response; no widening of the original held predicates."""
    need(value == {'database':'yggdrasil','readonly':'on','schema':92,
         'migration88_applied':1,'migration89_applied':1,'migration90_applied':1,'migration91_applied':1,
         'migration92_applied':1,'history_max_version':92,'index92_valid':True,
         'history_rows':e['history']['rows'],'history_exact':True,
         'catalog_rows':e['catalog']['rows'],'catalog_exact':True,'index89_valid':True,
         'active_latest_policies':2,'current_original_catalog':1,'current_original_binding':1,
         'current_physical_members':3,'physical_profile_slot_count':3,'historical_useful_survivors':2,
         'forward_table_present':True,'held_count':1,'held_unchanged_expired':1,
         'known_original':1,'closed_original_run':1,'original_frame_exact':True,'original_row_count':4,
         'original_failed_caller':1,'authority_reads':4,'authority_returns':4,'journal_transports':3,
         'delete_bindings':0,'forward_admissions':0,'other_leases':0,'other_nonsteady':0,
         'busy_jobs':1,'busy_runs':0,'native_authority':0},
         'ONLY_ORIGINAL_S3_AND_DISTINCT_EXACT_HTTP_HELD_UPGRADE_NOT_STEADY_PROOF')
    return value


def database_r6_held_preflight(cut, run, expected, upgrade):
    require_http_maintenance_upgrade_bound()
    e = match_held_identity(expected)
    review = e['Root_review_ref']
    need(sha(read(review['path'], 1 << 20, 0o600)) == review['sha256'], 'ACTUAL_ROOT_HELD_ROLLOUT_REVIEW_STILL_PINNED')
    request = upgrade['input']
    for key in ('query_ref','projection_ref','Root_review_ref'):
        ref = evidence_ref(request[key])
        need(sha(read(ref['path'], 128 << 10, 0o600)) == ref['sha256'], 'HTTP_UPGRADE_ORIGINAL_REFERENCE_STILL_PINNED')
    native = validate_held_native_observation(e, cut.C.loads)
    value = http_upgrade_db_read(cut, run, 'DB-R6-HELD-READONLY', held_r6_database_sql(e))
    validate_r6_held_database(value, e)
    wanted = http_maintenance_canonical_preimage(cut, run, upgrade, 'PREFLIGHT')
    counts = http_maintenance_current_preimage(cut, run, upgrade, 'PREFLIGHT')
    need(validate_held_native_observation(e, cut.C.loads) == native, 'SAME_FRESH_NATIVE_ORIGINALS_AFTER_R6_DB')
    cut.C.once(run / 'R6-HELD-UPGRADE-READONLY-RETURN.PUBLIC.json', cut.C.wire({
        'schema':'exact_partial_poweroff_and_recorded_HTTP_HELD_image_upgrade_readonly_v1',
        'retirement_authority':False,'provider_mutations':False,'Guest_replay':False,
        'steady_or_no_busy_proof':False,'total_jobs':counts['total_jobs'],'held_jobs':counts['held_jobs'],
        'unrelated_jobs':counts['unrelated_jobs'],'http_job_id':wanted['job_id'],'http_run_id':wanted['run_id'],
        'original_failure_relabelled':False,'original_finalization_ACK_fabricated':False,
        'snapshot_only_not_cross_system_atomicity':True}))
    return value




# Fixed maintenance posture, not retirement eligibility or absence authority.
CONFIG_REF = {'path': '/var/lib/dakasa-core-rollout/g10pair/actual-binding-20261104/CORE-IMAGE-MAINTENANCE.json', 'sha256': 'b700c1dfd92bce9f3e4d340eab5097aecee4e7a794c1cacaf409f11357924557'}
SQL_DATA_REF = {'path': '/var/lib/dakasa-core-rollout/policy92-readonly-measure-d33f0ee4-5764-42ad-8a1f-95f0d55eeabb/EXACT-SQL-DATA.original.json', 'sha256': 'e70f1bfc0821be5eaf44ec2248656da06ff269cfa57079ff487ae74f4cfe1054'}
EXPECTED_CURRENT_G9_PROOF_REFS = {'/var/lib/dakasa-capacity-network-recovery/eeb07b5f3d171544f5eddc02c4d0cbad6d07854bdf2958d697ef56d33c5e9c5c-QUALIFIED.PUBLIC.json': 'c3d6f4cac12d61e8ade4189012d065fff95e213f9cdc8edaeea757887234b16d', '/var/lib/dakasa-capacity-network-recovery/2b7e9be2-e45a-4cd5-86f2-6f0a3372576d-GUARDIAN-821ba94c6a3d4b32a22f022949691a1e-FIRST-CURRENT15-RETURN.PUBLIC.json': '2c18fb8de9ab3d1aeffd0302ac8d93f4797936ff6fb475e6f32061880ce17f56'}
POLICY92_SQL_SHA = 'e70f1bfc0821be5eaf44ec2248656da06ff269cfa57079ff487ae74f4cfe1054'
CAP = 16 << 20
CHILD = '8b70e285-90f3-4911-9d0c-9f12afc30329'
PARENT = '54422821-d260-4241-bcc1-f069c0c02e34'
FAILED = '5e30d367-8353-4d5c-8d87-04836611c02b'
DESTROY = 'ddea9e69-1567-4a11-9b9a-4e6fe57adf3b'
LEASE = '2026-11-04T04:48:08.006687Z'

def query(cut,run,name,sql):
    body="BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY; SET LOCAL statement_timeout='3s'; SET LOCAL lock_timeout='500ms'; SET LOCAL timezone='UTC';\n"+sql+"\n;\nROLLBACK;\n"
    cut.C.once(run/(name+'.sql'),body.encode())
    cmd='PGOPTIONS="-c default_transaction_read_only=on -c statement_timeout=3000 -c lock_timeout=500 -c timezone=UTC" exec psql -XqAt -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -d yggdrasil'
    start=datetime.datetime.now(datetime.timezone.utc).isoformat();mono=time.monotonic();code=None;out=b'';err=b'';timeout=False
    try:
        result=subprocess.run(cut.KUBE+['-n','dakasa','exec','-i','unified-database-0','--','sh','-c',cmd],input=body.encode(),stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=8,check=False)
        out,err,code=result.stdout,result.stderr,result.returncode
    except subprocess.TimeoutExpired as e:out=e.stdout or b'';err=e.stderr or b'';timeout=True
    finally:
        cut.C.once(run/(name+'.stdout'),out);cut.C.once(run/(name+'.stderr'),err)
        cut.C.once(run/(name+'.RETURN.json'),cut.C.wire({'started_at':start,'ended_at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'elapsed_seconds':time.monotonic()-mono,'returncode':code,'timed_out':timeout}))
    need(code==0 and not timeout and not err and len(out)<=CAP,'COMPLETE_READONLY_SQL_RETURN_ZERO');return cut.C.loads(out)


def schema_facts(c,s):
    v=s['schema_facts']
    need(v['database']=='yggdrasil' and v['readonly']=='on'
         and v['latest_versions']==[0]+[n for n in range(1,93)if n!=40]
         and v['history_max_version']==92 and v['rows90']==v['rows91']==v['rows92']==1
         and s['index89_valid']is True and s['index92_valid']is True,
         'EXACT_SCHEMA92_FULL_HISTORY_AND_BOTH_VALID_WORKFLOW_INDEXES_REQUIRED')
    full=v['complete_history_wire'];prior=v['prior_history_wire'];prior91=v['prior91_history_wire']
    need(type(full)is str and type(prior)is str and type(prior91)is str
         and sha(full.encode())==c['complete_history_sha256']
         and sha(prior.encode())==c['prior89_history_sha256']
         and sha(prior91.encode())==c['prior91_history_sha256'], 'ALL_ORDERED_ORIGINAL_HISTORY_WIRES_HASH_EXACT')
    rows=json.loads(full);old=json.loads(prior);old91=json.loads(prior91)
    need(type(rows)is list and type(old)is list and type(old91)is list and len(rows)==len(old)+3
         and all(len([r for r in rows if r['version_id']==n and r['is_applied']is True])==1 for n in(90,91,92))
         and old==[r for r in rows if r['version_id']not in(90,91,92)]
         and len(rows)==len(old91)+1 and old91==[r for r in rows if r['version_id']!=92],
         'RAM_PRIOR89_AND_PRIOR91_REMOVE_ONLY_ACTUAL_90_91_92_ROWS_NO_REWRITE')
    need(type(s['index92_definition'])is str and sha(s['index92_definition'].encode())==c['index92_definition_sha256'],
         'ACTUAL_INDEX92_DEFINITION_MATCHES_INDEPENDENT_ROOT_ACCEPTANCE')
    need(sha(canonical({'catalog90':v['catalog90'],'catalog91':v['catalog91']}))==c['catalog90_91_sha256']
         and all(type(v[k])is int and v[k]==0 for k in('other_migrators_ddl','other_cic','ddl_locks')),
         'FULL_BOTH_CATALOGS_UNCHANGED_AND_NO_OTHER_DDL')
    return {'complete_history_sha256':sha(full.encode()),'prior89_history_sha256':sha(prior.encode()),
            'prior91_history_sha256':sha(prior91.encode()),'index92_definition_sha256':sha(s['index92_definition'].encode()),
            'catalog90_91_sha256':sha(canonical({'catalog90':v['catalog90'],'catalog91':v['catalog91']}))}



def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode()


def utc(value):
    need(type(value) is str and re.fullmatch(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:\d{2})', value), 'ACTUAL_ZONED_TIMESTAMP')
    # Python before 3.11 accepts only 3/6 fractional digits; retain the raw wire
    # and parse its accepted 1..9 digits at datetime's microsecond precision.
    normalized = re.sub(r'\.(\d{1,9})(?=Z|[+-])', lambda match: '.' + (match.group(1) + '000000')[:6], value)
    return datetime.datetime.fromisoformat(normalized.replace('Z', '+00:00'))


def input_ref(C, ref):
    need(type(ref) is dict and set(ref) == {'path', 'sha256'} and type(ref['path']) is str
         and Path(ref['path']).is_absolute() and C.digest(ref['sha256']), 'CLOSED_PRIVATE_ORIGINAL_REF')
    raw = C.read(ref['path'], CAP, 0o600)
    need(sha(raw) == ref['sha256'], 'EXACT_PRIVATE_ORIGINAL_BYTES')
    return raw


def maintenance_inputs(C):
    require_bound()
    raw = input_ref(C, CONFIG_REF)
    c = C.loads(raw)
    need(type(c) is dict and set(c) == {'schema', 'source_R', 'amd64_D', 'core_preimage', 'schema_pins',
         'policy_state', 'current_preimage_ref', 'current_intent_sha256', 'failed_run_sha256', 'root_review_ref'},
         'CLOSED_KNOWN_CHILD_IMAGE_MAINTENANCE_INPUT')
    need(c['schema'] == 'g10_known_child8b_image_maintenance_v1' and c['source_R'] == CORE_R
         and c['source_R'] == C.SOURCE_R and c['amd64_D'] == C.NEW_DIGEST
         and C.OLD_CORE_UID == UID and C.OLD_CORE_GENERATION == GENERATION and C.OLD_CORE_POD_UID == OLD_POD,
         'ONE_QUALIFIED_RELEASE_AND_CURRENT_CORE_PREIMAGE')
    p = c['core_preimage']
    need(type(p) is dict and set(p) == {'deployment_uid', 'generation', 'pod_uid', 'container_id', 'spec_sha256', 'annotations_sha256'}
         and p['deployment_uid'] == UID and type(p['generation']) is int and p['generation'] == GENERATION
         and p['pod_uid'] == OLD_POD and type(p['container_id']) is str
         and re.fullmatch('containerd://[a-f0-9]{64}', p['container_id'])
         and C.digest(p['spec_sha256']) and C.digest(p['annotations_sha256']), 'ROOT_FULL_CORE_SPEC_AND_LIFETIME_PREIMAGE')
    need(type(c['schema_pins']) is dict and set(c['schema_pins']) == {'complete_history_sha256', 'prior89_history_sha256',
         'prior91_history_sha256', 'index92_definition_sha256', 'catalog90_91_sha256'}
         and all(C.digest(x) for x in c['schema_pins'].values()), 'ACTUAL_ACCEPTED_SCHEMA92_FULL_HISTORY_INDEX_CATALOG_PINS')
    need(type(c['policy_state']) is dict and set(c['policy_state']) == {'aws', 'hetzner'}
         and all(type(v) is dict and set(v) == {'intent_identity', 'owned_slots', 'active_policies', 'policy_catalog_wire'}
                 for v in c['policy_state'].values()) and C.digest(c['current_intent_sha256']) and C.digest(c['failed_run_sha256']),
         'FULL_POLICY_ROSTER_AND_CURRENT_PRIVATE_ROW_PINS')
    review = input_ref(C, c['root_review_ref'])
    need(120 <= len(review) <= 8192, 'ACTUAL_SEPARATE_ROOT_REVIEW_NOT_GENERATED')
    expected = C.loads(input_ref(C, c['current_preimage_ref']))
    validate_known_child(expected, c, C.loads)
    sql = C.loads(input_ref(C, SQL_DATA_REF))
    need(sql['schema'] == 'fixed_policy_publication_schema92_SQL_data_v1'
         and set(sql['queries']) == {'original_notify_aws_vm_members', 'original_notify_hetzner_vm_members'},
         'EXACT_E70_POLICY92_QUERY_ROSTER')
    return c, raw, sql


KNOWN_CHILD_SQL = """SELECT jsonb_build_object(
 'observed_at_pg',clock_timestamp(),
 'intent_pgtext',(SELECT intent::text FROM public.capacity_intents WHERE namespace='dakasa-production' AND environment='production' AND domain='notify' AND dimension='original_notify_aws_vm_members'),
 'failed_run_pgtext',(SELECT to_jsonb(w)::text FROM public.workflow_runs w WHERE id='5e30d367-8353-4d5c-8d87-04836611c02b'),
 'dispatch',(SELECT jsonb_agg(to_jsonb(j) ORDER BY j.id) FROM public.capacity_dispatch_jobs j WHERE run_id='5e30d367-8353-4d5c-8d87-04836611c02b'),
 'forwards',(SELECT jsonb_agg(to_jsonb(f) ORDER BY f.id,f.stage) FROM public.capacity_guest_retirement_forwards f WHERE preregistration_id='20e58827-cfe9-403e-8e34-765547326927'),
 'destroy',(SELECT to_jsonb(g) FROM public.capacity_mutation_grants g WHERE id='ddea9e69-1567-4a11-9b9a-4e6fe57adf3b'),
 'delete_bindings',(SELECT jsonb_agg(to_jsonb(b) ORDER BY b.destroy_grant_id) FROM public.capacity_vm_retirement_delete_bindings b WHERE intent_id='376a7e86-905d-44dd-8583-c8fed2ecac1a'),
 'original_intent',(SELECT to_jsonb(i) FROM public.capacity_vm_retirement_intents i WHERE id='376a7e86-905d-44dd-8583-c8fed2ecac1a'),
 'original_returns',(SELECT jsonb_agg(to_jsonb(r) ORDER BY r.sequence) FROM public.capacity_vm_retirement_original_returns r WHERE intent_id='376a7e86-905d-44dd-8583-c8fed2ecac1a'),
 'original_callers',(SELECT jsonb_agg(to_jsonb(c) ORDER BY c.return_sha256) FROM public.capacity_guest_original_caller_returns c WHERE intent_id='376a7e86-905d-44dd-8583-c8fed2ecac1a'),
 'original_authorities',(SELECT jsonb_agg(jsonb_build_object('read',to_jsonb(r),'return',to_jsonb(v)) ORDER BY CASE r.phase WHEN 'before_start' THEN 0 ELSE 1 END,r.ordinal) FROM public.capacity_guest_original_authority_reads r LEFT JOIN public.capacity_guest_original_authority_returns v ON v.read_id=r.id WHERE r.intent_id='376a7e86-905d-44dd-8583-c8fed2ecac1a'))
"""


def validate_known_child(v, c, loads):
    need(type(v) is dict and set(v) == {'observed_at_pg', 'intent_pgtext', 'failed_run_pgtext', 'dispatch', 'forwards',
         'destroy', 'delete_bindings', 'original_intent', 'original_returns', 'original_callers', 'original_authorities'}, 'CLOSED_WHOLE_KNOWN_CHILD_PREIMAGE')
    need(type(v['intent_pgtext']) is str and sha(v['intent_pgtext'].encode()) == c['current_intent_sha256']
         and type(v['failed_run_pgtext']) is str and sha(v['failed_run_pgtext'].encode()) == c['failed_run_sha256'], 'WHOLE_CURRENT_INTENT_AND_FAILED_RUN_BYTES')
    i, w = loads(v['intent_pgtext']), loads(v['failed_run_pgtext'])
    need(i['generation'] == 14 and i['fencing_token'] == 30 and i['phase'] == 'drained'
         and i['lease_owner'] == 'ee16e55c-3efa-4667-bfd1-b1deb2313432'
         and i['lease_executor_id'] == '7f039d97-8374-4f53-919f-4640e718ffb8'
         and i['lease_expires_at'] == LEASE and utc(v['observed_at_pg']) > utc(LEASE), 'ONLY_EXPIRED_KNOWN_F30_LIFETIME')
    mark = i['retirement_forward']
    need(mark['id'] == CHILD and mark['stage'] == 'admitted'
         and mark['retirement_request_id'] == '376a7e86-905d-44dd-8583-c8fed2ecac1a'
         and mark['preregistration_id'] == '20e58827-cfe9-403e-8e34-765547326927', 'ONLY_EXACT_KNOWN_CHILD_MARKER')
    need(w['id'] == FAILED and w['status'] == 'failed' and w['finished_at'] is not None
         and type(v['dispatch']) is list and len(v['dispatch']) == 1, 'ONE_FAILED_FINISHED_RUN')
    j = v['dispatch'][0]
    envelope = loads(j['envelope']) if type(j['envelope']) is str else j['envelope']
    need(j['id'] == '4d861caf-b785-4726-952a-4a93da13169c' and j['run_id'] == FAILED
         and j['state'] == 'returned' and j['return_status'] == 'failed'
         and envelope['workflow']['id'] == '9bb4a35b-6eb4-4983-9133-73bd96cfea94'
         and utc(j['returned_at']) == utc(w['finished_at']) and utc(j['finalization_ack_at']) >= utc(j['returned_at']),
         'SOURCE_FAILED_RUN_COMPLETE_RETURN_AND_ACK')
    rows = v['forwards']
    need(type(rows) is list and len(rows) == 5
         and {(r['id'], r['stage']) for r in rows} == {(PARENT, 'requested'), (PARENT, 'admitted'), (PARENT, 'off_qualified'), (CHILD, 'requested'), (CHILD, 'admitted')},
         'EXACT_ROOT_THREE_AND_CHILD_TWO_NO_NEW_DESCENDANT')
    by = {(r['id'], r['stage']): r for r in rows}
    for r in rows:
        need(type(r['original_wire']) is str and r['original_wire'].startswith('\\x'), 'ACTUAL_PG_BYTEA_ORIGINAL_WIRE')
        raw = bytes.fromhex(r['original_wire'][2:])
        need(len(raw) <= 2 << 20 and sha(raw) == r['record_sha256'] and loads(raw) == r['original_record'], 'SEALED_ORIGINAL_FORWARD_WIRE')
        x = r['original_record']
        need(x['id'] == r['id'] and x['stage'] == r['stage'] and x['root_admission_id'] == PARENT
             and x['original'] == by[(PARENT, 'requested')]['original_record']['original']
             and x['evidence'] == by[(PARENT, 'requested')]['original_record']['evidence']
             and x['original_caller_sha256'] == x['evidence']['caller_sha256'], 'UNCHANGED_FULL_ORIGINAL_FRAME_CALLER_AND_EVIDENCE')
        if r['id'] == CHILD:
            need(x['parent_admission_id'] == PARENT and x['parent_admission_sha256'] == by[(PARENT, 'off_qualified')]['record_sha256'], 'EXACT_CHILD_ROOT_AND_PARENT_SHA')
    admitted = by[(CHILD, 'admitted')]['original_record']
    need(admitted['generation'] == 14 and admitted['fence'] == 30 and admitted['lease_owner'] == i['lease_owner']
         and admitted['executor_id'] == i['lease_executor_id'] and admitted['run_id'] == FAILED
         and admitted['destroy_grant_id'] == DESTROY, 'EXACT_CURRENT_CHILD_CLAIM_AND_ADOPTED_DESTROY')
    grant = v['destroy']; settlement = grant['grant_record']['settlement']
    need(grant['id'] == DESTROY and grant['state'] == 'settled'
         and grant['namespace'] == 'dakasa-production' and grant['environment'] == 'production'
         and grant['domain'] == 'notify' and grant['dimension'] == 'original_notify_aws_vm_members'
         and all(grant[k] is None for k in ('original_disposition_id', 'failed_original_disposition_id', 'native_denied_disposition_id', 'enrolled_failed_disposition_id'))
         and settlement['grant_id'] == DESTROY and settlement['outcome'] == 'accepted'
         and settlement['transport_completed'] is True and settlement['auxiliary_inventory_complete'] is True,
         'ONLY_ORIGINAL_ACCEPTED_SETTLED_DESTROY_NO_NEW_MUTATION_AUTHORITY')
    bindings = v['delete_bindings']
    need(type(bindings) is list and len(bindings) == 1, 'ONE_ORIGINAL_DELETE_BINDING')
    b = bindings[0]; eligibility = b['original_eligibility_record']
    need(b['destroy_grant_id'] == DESTROY and b['intent_id'] == mark['retirement_request_id']
         and eligibility['schema'] == 'original_guest_partial_poweroff_delete_eligibility_v1'
         and eligibility['admission_id'] == PARENT and eligibility['admission_sha256'] == by[(PARENT, 'admitted')]['record_sha256']
         and b['original_wire'].startswith('\\x') and loads(bytes.fromhex(b['original_wire'][2:])) == eligibility,
         'ORIGINAL_DELETE_BINDING_STAYS_WITH_PARENT_ADMISSION')
    evidence = admitted['evidence']; returns = v['original_returns']; authorities = v['original_authorities']; callers = v['original_callers']
    need(type(returns) is list and len(returns) in (4, 5) and [r['sequence'] for r in returns] == list(range(1, len(returns)+1))
         and returns[0]['kind'] == 'production_clock_nonce_v2' and returns[0]['return_sha256'] == evidence['nonce_sha256']
         and [r['return_sha256'] for r in returns[1:]] == evidence['journal_sha256']
         and type(authorities) is list and len(authorities) == 4 and all(type(r['return']) is dict for r in authorities)
         and [r['return']['authority_sha256'] for r in authorities] == evidence['authority_sha256']
         and type(callers) is list and len(callers) == 1 and callers[0]['return_sha256'] == evidence['caller_sha256'],
         'WHOLE_NONCE_JOURNAL_CALLER_AND_FOUR_ORIGINAL_AUTHORITY_ROWS')
    need(v['original_intent']['id'] == mark['retirement_request_id']
         and returns[0]['original_return_record']['final_request'] == admitted['original']['Request'], 'ORIGINAL_RETAINED_REQUEST_NO_RETIMING')
    return True


def database_known_child(cut, run, c, sql, phase):
    need(phase in ('BEFORE', 'PRESEND'), 'FIXED_MAINTENANCE_CAPTURE_PHASE')
    C = cut.C
    expected = C.loads(input_ref(C, c['current_preimage_ref']))
    for provider, key in (('aws', 'original_notify_aws_vm_members'), ('hetzner', 'original_notify_hetzner_vm_members')):
        v = query(cut, run, phase+'-'+provider, sql['queries'][key])
        schema_facts(c['schema_pins'], v)
        need(v['intent_count'] == 1 and all(type(v[k]) is int and v[k] == 0 for k in
             ('jobs_busy', 'runs_busy', 'forward_unreturned_reads', 'live_unreturned_canaries')), 'ALL_EIGHT_TERMINAL_LANES_NO_UNRELATED_BUSY')
        keys = ('intent_busy', 'pending_authority', 'forward_markers')
        need(all(type(v[k]) is int for k in keys) and tuple(v[k] for k in keys) == ((1, 1, 1) if provider == 'aws' else (0, 0, 0)),
             'ONLY_KNOWN_CHILD_INTENT_SETTLED_GRANT_AND_MARKER')
        need({k: v[k] for k in ('intent_identity', 'owned_slots', 'active_policies', 'policy_catalog_wire')} == c['policy_state'][provider],
             'EXACT_CURRENT_NON_TARGET_ROSTER_POLICIES_AND_INTENT')
    current = query(cut, run, phase+'-known-child', KNOWN_CHILD_SQL)
    need({k: v for k, v in current.items() if k != 'observed_at_pg'} == {k: v for k, v in expected.items() if k != 'observed_at_pg'},
         'WHOLE_CURRENT_AND_ORIGINAL_PRIVATE_PREIMAGES_UNCHANGED')
    validate_known_child(current, c, C.loads)


if __name__ == '__main__':
    main()
