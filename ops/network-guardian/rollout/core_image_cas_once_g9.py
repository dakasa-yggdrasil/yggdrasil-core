#!/usr/bin/env python3
"""Prepared operational scratch. One Core image PATCH after actual G9 acceptance.

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


PROPOSAL_BOUND = True
CORE_R = 'ed76cef2d66d7f5368b96b41aaa22fc80a2233c4'  # Actual qualified R5 Source; ops/rollout acceptance remain separate.
OLD_SOURCE = 'd451ac07c6e412bd2eae06f648935799e046ea31'
SOURCE_PIN = 'c5d6a86f0741686382e10257ce880734d65b38da6b2c96fea35444ee6ccbf6eb'
UID = 'a58ab8c2-da48-46c1-ae62-a650141eeb86'
OLD_POD = '30695e40-3349-4186-90e4-6db3951e34c2'
GENERATION = 272
DEP_URI = '/apis/apps/v1/namespaces/dakasa/deployments/yggdrasil'
PODS_URI = '/api/v1/namespaces/dakasa/pods?labelSelector=app%3Dyggdrasil'
KUBECONFIG = Path('/etc/rancher/k3s/k3s.yaml')
ROOT = Path('/var/lib/dakasa-core-rollout/g9pair')
OPLOCK = Path('/var/lib/dakasa-capacity-network-r13-cutover/operation.lock')
TOOL_PINS = {'pair_change_contract.py': '0ef83ad2d4bbb28ad3d2319193bf3d9434ff04abbcf5c9b77c5993644f605a0a', 'derive_g9pair_controller_config.py': '967f7d8c01aad882a6158a38bfbdb04a24161a0b9b5400be0a2d70d4c8bafa7c', 'derive_standing_config.py': 'f151cff807091fd205fdd24f67bccfa9ca9557209176c4e187ffeafafc7821c9', 'g9cut.py': '9cf7995b2a63e6b395c71ef46f574d90872404b3dcd815c53bc45a19daa91dec'}

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
        need(sha(read(folder / 'tools' / name)) == pin, 'EXACT_REVIEWED_G9_TOOL')
    path = folder / 'tools/g9cut.py'
    module = types.ModuleType('reviewed_g9cut_for_core_cas')
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
    need(C.OLD_DIGEST == '0970e1188ceb5fa3ba52a1a11337f5fae7ac0657a66a69e08d24f9888f813826', 'EXACT_OLD_R4_AMD64')
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


def g9_acceptance(cut, folder, manifest, returned, run):
    C = cut.C
    need(set(returned) == {'schema', 'status', 'result', 'automatic_replay', 'Guest_or_Core_business_authority'}
         and returned['schema'] == 'g9_pair_swap_return_v1' and returned['status'] == 'CONFIG_SWAP_OK'
         and returned['automatic_replay'] is False and returned['Guest_or_Core_business_authority'] is False, 'ACTUAL_CLOSED_G9_SWAP_RETURN')
    result = returned['result']
    need(result['source_commit'] == manifest['source_commit'] and result['source_R'] == CORE_R and result['amd64_D'] == C.NEW_DIGEST
         and result['new_guardian_source_sha256'] == SOURCE_PIN and result['controller_config_sha256'] == C.HEAD_CONFIG_SHA
         and result['independent_current15'] is True and result['all_inherited_budget_and_original_refs_unchanged'] is True
         and result['Core_Cold_Hub_or_provider_mutation'] is False
         and all(v == 0 for v in result['conservative_per_role_gap_seconds'].values()), 'QUALIFIED_G9_RETURN_EXACT_P_R_D_AND_NO_ROLE_GAP')
    refs = manifest['protected_refs']
    need(len(refs) == len(required_protected_refs()) and len({r['path'] for r in refs}) == len(refs)
         and {r['path']:r['sha256'] for r in refs} == required_protected_refs(),
         'EXACT_INHERITED39_PLUS_ACTUAL_G8_FULL120_AND_OWN15_REFS')
    backend = cut.Backend(folder, manifest, '', run, {}, [], {})
    backend.files(successor=True)
    protected = backend.protected()
    C.once(run / 'PROTECTED-REFS-BEFORE.json', C.wire(protected))
    need(C.sha(C.read(C.NEW_STANDING, 32768, 0o600)) == result['standing_sha256'], 'EXACT_ACCEPTED_G9_STANDING')
    for key in ('controller', 'guardian'):
        C.identity(result[key])
    ctrl = cut.physical_identity(C.CTRL, cut.controller_argv(C.NEW_CONFIG))
    guard = cut.physical_identity(C.GUARD, cut.guardian_argv(C.NEW_SOURCE, SOURCE_PIN))
    need(ctrl == result['controller'] and guard == result['guardian'], 'SAME_ACCEPTED_G9_CONTROLLER_GUARDIAN')
    G = C.load_guardian(C.NEW_SOURCE, SOURCE_PIN)
    owner = G.Owner(SOURCE_PIN)
    full = owner.identity()
    need({k: full[k] for k in ctrl} == ctrl and owner.original_qualification_measurement(full) is not None, 'RECOMPUTED_ACTUAL_G9_FULL120_SAME_LIFETIME')
    full_path = C.LEDGER / (owner.key(full) + '-QUALIFIED.PUBLIC.json')
    own_path = C.LEDGER / (guard['boot_id'] + '-GUARDIAN-' + guard['InvocationID'] + '-FIRST-CURRENT15-RETURN.PUBLIC.json')
    for field, expected_path in (('actual_new_full120_ref', full_path), ('own_daemon_first_current15_ref', own_path)):
        ref = result[field]
        need(set(ref) == {'path', 'sha256'} and ref['path'] == str(expected_path)
             and C.sha(C.read(expected_path, 16 << 20, 0o600)) == ref['sha256'], 'SAME_G9_ACTUAL_ORIGINAL_QUALIFICATION_REF')
    own = C.loads(C.read(own_path, 16 << 20, 0o600))
    need(own['schema'] == 'Root_owning_finite512_current15_readonly_observation_v1' and own['source_sha256'] == SOURCE_PIN
         and own['standing_config_sha256'] == result['standing_sha256'] and own['identity'] == full
         and own['measurement']['qualified_15_seconds'] is True and own['measurement']['all_requested_rows_accounted_for'] is True
         and own['kernel']['all_four_backends_and_reverse_sources_positive'] is True, 'ACTUAL_G9_DAEMON_OWN15_NOT_ASSESSOR_SUBSTITUTE')
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
    p.add_argument('--g9-swap-return', required=True, type=Path)
    p.add_argument('--expected-g9-swap-return-sha256', required=True)
    p.add_argument('--evidence-dir', required=True, type=Path)
    p.add_argument('--held-admission', type=Path)
    p.add_argument('--expected-held-admission-sha256')
    p.add_argument('--execute-core-image-cas-once', action='store_true', required=True)
    a = p.parse_args()
    need(os.geteuid() == 0 and sys.platform == 'linux', 'ROOT_LINUX_BRAIN_ONLY')
    folder = a.package.absolute()
    cut = load_tools(folder)
    C = cut.C
    if ROOT_ROLLOUT_MODE == 'exact_held_partial_poweroff_original':
        need(a.held_admission is not None and a.expected_held_admission_sha256 is not None, 'EXPLICIT_LATE_HELD_ADMISSION_AND_REVIEW_SHA_REQUIRED')
        held, held_raw = load_held_admission(C, a.held_admission.absolute(), a.expected_held_admission_sha256)
    else:
        need(a.held_admission is None and a.expected_held_admission_sha256 is None, 'NO_HELD_INPUT_IN_UNCHANGED_STEADY_BRANCH')
        held, held_raw = None, None
    folder, manifest = C.package(folder, a.expected_manifest_sha256)
    need(re.fullmatch('[a-f0-9]{40}', a.expected_ops_source) and a.expected_ops_source != '0' * 40
         and manifest['source_commit'] == a.expected_ops_source and manifest['files']['source/network_guardian.py'] == SOURCE_PIN
         and manifest['tools'] == TOOL_PINS, 'EXACT_QUALIFIED_P_AND_SOURCE_TOOLS')
    returned_path = a.g9_swap_return.absolute()
    need(returned_path.name == 'RETURN.json' and returned_path.parent.parent == ROOT
         and returned_path.parent.name.startswith('swap-once-'), 'EXACT_ACTUAL_G9_SWAP_RETURN_PATH')
    C.private_dir(returned_path.parent)
    raw_return = C.read(returned_path, 32 << 20, 0o600)
    need(C.digest(a.expected_g9_swap_return_sha256) and C.sha(raw_return) == a.expected_g9_swap_return_sha256, 'ROOT_REVIEWED_ACTUAL_G9_RETURN_SHA')
    need(not (returned_path.parent / 'HOLD.json').exists(), 'NO_G9_HOLD_ADOPTION')
    claim = C.loads(C.read(ROOT / ('SWAP-' + a.expected_manifest_sha256 + '-POSSIBLE.json'), 32768, 0o600))
    need(set(claim) == {'schema', 'manifest_sha256', 'old_controller', 'old_guardian', 'run', 'automatic_replay'}
         and claim['schema'] == 'g9_once_only_swap_claim_v1' and claim['manifest_sha256'] == a.expected_manifest_sha256
         and claim['old_controller'] == manifest['expected_controller_identity']
         and claim['old_guardian'] == manifest['expected_guardian_identity']
         and claim['run'] == str(returned_path.parent) and claim['automatic_replay'] is False,
         'ACTUAL_G9_GLOBAL_ONCE_CLAIM_BINDS_EXACT_MANIFEST_AND_RETURN_DIRECTORY')
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
            need(not (ROOT / ('CORE-IMAGE-0970-TO-' + C.NEW_DIGEST + '-POSSIBLE.json')).exists(), 'GLOBAL_ONCE_CLAIM_ALREADY_EXISTS_NO_REPLAY')
            if held_raw is not None:
                C.once(run / 'HELD-ADMISSION.INPUT.json', held_raw)
                C.once(run / 'HELD-ADMISSION.INPUT-SHA256.json', C.wire({'sha256':a.expected_held_admission_sha256,'reviewed_input_only_not_retirement_authority':True}))
            api = API(cut)
            before = api_read(api, C, run, 'DEPLOYMENT-BEFORE', DEP_URI)
            pods = api_read(api, C, run, 'PODS-BEFORE', PODS_URI)
            old_tuple = core_before(before, pods, C)
            original = C.loads(C.read(returned_path.parent / 'BEFORE.json', 32 << 20, 0o600))
            need(original['core'] == old_tuple and original['controller'] == manifest['expected_controller_identity']
                 and original['guardian'] == manifest['expected_guardian_identity'], 'SAME_G9_ORIGINAL_CORE_AND_MANIFEST_LINEAGE')
            C.once(run / 'INPUTS.json', C.wire({'schema': 'core_image_cas_inputs_v1', 'at': now(), 'script_sha256': sha(read(__file__)),
                    'manifest_sha256': a.expected_manifest_sha256, 'G9_return_path': str(returned_path),
                    'G9_return_sha256': a.expected_g9_swap_return_sha256, 'ops_P': a.expected_ops_source, 'Core_R': CORE_R,
                    'actual_schema90_receipt_is_independent': True, 'operation_mutex_inode': list(inode),
                    'maintenance_mutex_held': False, 'external_admin_exclusion_claimed': False}))
            need(original['protected_refs'] == required_protected_refs(), 'SAME_G9_41_REFS_AND_ONE_OF_THREE_BUDGET')
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
            database_preflight(cut, run, held)
            fresh = api_read(api, C, run, 'DEPLOYMENT-FRESH-PRESEND', DEP_URI)
            fresh_pods = api_read(api, C, run, 'PODS-FRESH-PRESEND', PODS_URI)
            need(core_before(fresh, fresh_pods, C) == old_tuple and fresh['metadata']['resourceVersion'] == before['metadata']['resourceVersion']
                 and fresh['spec'] == before['spec'] and fresh['metadata']['annotations'] == before['metadata']['annotations'], 'UNCHANGED_FRESH_API_PREIMAGE_NO_REBASE')
            backend, protected, ctrl, guard, observed = g9_acceptance(cut, folder, manifest, C.loads(raw_return), run)
            need(original['protected_refs'] == protected, 'SAME_G9_41_REFS_AND_ONE_OF_THREE_BUDGET')
            backend.files(successor=True)
            need(backend.protected() == protected
                 and cut.physical_identity(C.CTRL, cut.controller_argv(C.NEW_CONFIG)) == ctrl
                 and cut.physical_identity(C.GUARD, cut.guardian_argv(C.NEW_SOURCE, SOURCE_PIN)) == guard, 'SAME_ACCEPTED_G9_AUTHORITY_IMMEDIATELY_BEFORE_PATCH')
            if ROOT_ROLLOUT_MODE == 'exact_held_partial_poweroff_original':
                held_current_preimage(cut, run, held, 'PRESEND')
            current_lock = OPLOCK.lstat()
            need((current_lock.st_dev, current_lock.st_ino) == inode and time.monotonic() - observed <= 15, 'SAME_LOCK_AND_CURRENT15_COMPLETED_WITHIN15S')
            marker = {'schema': 'core_image_cas_possible_send_v1', 'at': now(), 'method': 'PATCH', 'uri': DEP_URI,
                      'deployment_uid': UID, 'generation': GENERATION, 'resourceVersion': before['metadata']['resourceVersion'],
                      'patch_sha256': C.sha(patch_wire), 'script_sha256': sha(read(__file__)),
                      'manifest_sha256': a.expected_manifest_sha256, 'G9_return_sha256': a.expected_g9_swap_return_sha256,
                      'evidence_dir': str(run), 'automatic_retry': False, 'effects_may_have_happened_after_this_marker': True}
            # Both files and both parent directories are durable before the call.
            C.once(ROOT / ('CORE-IMAGE-0970-TO-' + C.NEW_DIGEST + '-POSSIBLE.json'), C.wire(marker))
            C.once(run / 'POSSIBLE-SEND.json', C.wire(marker))
            need(time.monotonic() - observed <= 15, 'CURRENT15_STILL_FRESH_AFTER_DURABLE_MARKERS_NO_SEND')
            if ROOT_ROLLOUT_MODE == 'exact_held_partial_poweroff_original':
                validate_held_native_observation(held, C.loads)
            sent = True
            status, raw, headers = api.request('PATCH', DEP_URI + '?fieldManager=core-image-cas-once', patch_wire)
            C.once(run / 'PATCH-ACTUAL-RETURN.json', raw)
            C.once(run / 'PATCH-ACTUAL-RETURN.HTTP.json', C.wire({'status': status, **headers}))
            need(status == 200, 'ACTUAL_PATCH_NOT_ACKNOWLEDGED_200_RECONCILE_NO_RETRY')
            after = C.loads(raw)
            result_shape(before, after, C)
            if ROOT_ROLLOUT_MODE == 'exact_held_partial_poweroff_original':
                held_current_preimage(cut, run, held, 'AFTER-ACK')
            result = {'schema': 'core_image_cas_return_v1', 'status': 'PATCH_ACKNOWLEDGED_ACCEPTANCE_PENDING',
                      'deployment_uid': UID, 'generation': after['metadata']['generation'], 'resourceVersion': after['metadata']['resourceVersion'],
                      'old_pod_uid': OLD_POD, 'Core_source': CORE_R, 'image': C.IMAGE_PREFIX + C.NEW_DIGEST,
                      'manifest_sha256': a.expected_manifest_sha256, 'G9_return_sha256': a.expected_g9_swap_return_sha256,
                      'patch_sha256': C.sha(patch_wire), 'automatic_retry': False, 'new_pod_readiness_proven': False,
                      'post_rollout_G9_and_E2E_acceptance_proven': False, 'evidence_dir': str(run)}
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
ROOT_ROLLOUT_MODE = 'exact_held_partial_poweroff_original'
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
    out=dict(EXPECTED_INHERITED_REFS)
    for path,pin in EXPECTED_CURRENT_G8_PROOF_REFS.items():
        need(path not in out or out[path]==pin, 'NO_CURRENT_G8_REF_MAY_REPLACE_OLD_BYTES')
        out[path]=pin
    need(len(out)==41,'EXACT_ROOT_ACCEPTED_41_REF_UNION')
    return out

def require_bound():
    need(PROPOSAL_BOUND and re.fullmatch('[a-f0-9]{40}', str(CORE_R)) and re.fullmatch('[a-f0-9]{64}', str(SOURCE_PIN))
         and type(GENERATION) is int and GENERATION > 0 and re.fullmatch('[a-f0-9-]{36}', str(OLD_POD))
         and type(TOOL_PINS) is dict and len(TOOL_PINS) == 4
         and ROOT_ROLLOUT_MODE in ('steady', 'exact_held_partial_poweroff_original')
         and type(EXPECTED_CURRENT_G8_PROOF_REFS) is dict and bool(EXPECTED_CURRENT_G8_PROOF_REFS),
         'G9_ACTUAL_RELEASE_SOURCE_PREIMAGES_AND_ROLLOUT_ADMISSION_NOT_BOUND')
    if ROOT_ROLLOUT_MODE == 'exact_held_partial_poweroff_original':
        validate_held_identity(HELD_ORIGINAL_IDENTITY)

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

    Root reviews this file and SHA separately AFTER actual schema90/G9 facts.
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
    return f"""BEGIN READ ONLY;
SET LOCAL statement_timeout='8000ms';
SET LOCAL lock_timeout='1000ms';
SET LOCAL TIME ZONE 'UTC';
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
   AND r.recorded_at<=(SELECT original_deadline FROM original))
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
 'busy_jobs',(SELECT count(*) FROM public.capacity_dispatch_jobs WHERE realm='dakasa-production' AND environment='production' AND domain='notify' AND dimension IN('original_notify_aws_vm_members','original_notify_hetzner_vm_members') AND (state IS NULL OR state NOT IN('returned') OR returned_at IS NULL OR finalization_ack_at IS NULL)),
 'busy_runs',(SELECT count(*) FROM (
 SELECT wr.id FROM public.manifests m JOIN public.workflow_runs wr ON wr.workflow_id=m.id
 WHERE m.kind='workflow' AND m.namespace='dakasa-production' AND m.name IN('notify-aws-elastic-capacity','notify-hetzner-elastic-capacity')
 AND (COALESCE(wr.status,'') NOT IN('succeeded','failed','cancelled') OR wr.finished_at IS NULL)
 UNION
 SELECT wr.id FROM public.workflow_runs wr
 WHERE wr.workflow_namespace='dakasa-production' AND wr.workflow_name IN('notify-aws-elastic-capacity','notify-hetzner-elastic-capacity')
 AND (COALESCE(wr.status,'') NOT IN('succeeded','failed','cancelled') OR wr.finished_at IS NULL)
 ) AS busy_run_ids),
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


if __name__ == '__main__':
    main()
