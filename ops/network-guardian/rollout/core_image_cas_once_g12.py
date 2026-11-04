#!/usr/bin/env python3
"""INERT G12/R2-to-R3 one-shot Core image maintenance for exact settled S2.

No business/provider/Guest operation. No action on import. Actual release,
Root data/config and G12 acceptance remain independent unbound prerequisites.
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

SOURCE_BOUND = True
CORE_R = 'ee8e3377ba91ff3efc3fde3a9751790608ac7066'
NEW_DIGEST = 'b0ee27bd53443260e8e05123f9474454e8108310c4b94a7e72b6bae107cf1ac2'
SOURCE_PIN = '67f8a8ffed5af5acbf3523c6d83bf0a5422e9ddaae984e75b4d322cc2dba79db'
TOOL_PINS = {'pair_change_contract.py': '76266689bbc75689dafca7cda2ff060138d3850b4ab78d10c1d4de10ac248f1b', 'derive_g12pair_controller_config.py': '8451ee1ed27226cdf942ef24406b6322c91b615cfb6dfec4439042332aee70f1', 'derive_standing_config.py': '4fb5e935b65e3574979cfd1f229313fc52d295591c1ac4619b8d990b1602788c', 'g12cut.py': '5606e30171b111f3cffe8ad110a59408b2c082945630ccb41a0444d7e02c1989'}
CONFIG_REF = {'path': '/var/lib/dakasa-core-rollout/goose93-settled-absence/posthold-readonly-2113b178-855f-487a-b14f-0ff5d4ef034b/CORE-CAS-G12-CONFIG.PRIVATE.json', 'sha256': '7b6f1b571eb09d832e9f5704d0129e70850ff6f15cd627127f53afc56189987a'}
SQL_DATA_REF = {'path': '/var/lib/dakasa-core-rollout/g11pair/readonly-R3-goose93-baseline-f5e9bbee-5c87-4485-ba6d-d99dbb9c1e15/EXACT-SQL-DATA.original.json', 'sha256': 'e70f1bfc0821be5eaf44ec2248656da06ff269cfa57079ff487ae74f4cfe1054'}
OLD_SOURCE = 'ed5a5501db226c2fedcc4185474aae2698b5415d'
OLD_DIGEST = '8e6d44d86bbae4463652d4bf9b3583241483a0813a4d34c7254b9c2e56dccafc'
UID = 'a58ab8c2-da48-46c1-ae62-a650141eeb86'
OLD_POD = '39bca7e9-9c6d-4f45-8f66-346f9f58b562'
GENERATION = 275
# Exact full container/config identities are fresh Root data, never prefixes.
OLD_CONTAINER_ID = 'containerd://6f2893db9664022dda81e29915088306ddf8100e3928498cd695eba11674a45a'
OLD_IMAGE_CONFIG_DIGEST = 'sha256:ef5ce9985258a837244f7753bb95f93baa2f72cc6da254c2ac03b425aec44a31'
RETIREMENT = 'fd24881a-01ea-429c-a04c-13a738684ea5'
FORWARD = '05192d81-bc0b-4076-9b06-766094240a9d'
DESTROY = 'd1ac8d0e-f38f-49eb-a5ab-17ed9204d979'
DEP_URI = '/apis/apps/v1/namespaces/dakasa/deployments/yggdrasil'
PODS_URI = '/api/v1/namespaces/dakasa/pods?labelSelector=app%3Dyggdrasil'
KUBECONFIG = Path('/etc/rancher/k3s/k3s.yaml')
ROOT = Path('/var/lib/dakasa-core-rollout/g12pair')
OPLOCK = Path('/var/lib/dakasa-capacity-network-r13-cutover/operation.lock')
POLICY92_SQL_SHA = 'e70f1bfc0821be5eaf44ec2248656da06ff269cfa57079ff487ae74f4cfe1054'
CAP = 16 << 20
CHANGE_CAUSE = ('Core qualified source ' + CORE_R + ' by immutable linux/amd64 manifest; independent post-rollout acceptance required') if isinstance(CORE_R, str) else None

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

EXPECTED_CURRENT_G8_PROOF_REFS = {'/var/lib/dakasa-capacity-network-recovery/d323cc228bec43596ac73c99cc473298896b8f2d88b06219aa69a549633925b3-QUALIFIED.PUBLIC.json': '68f5b3bcd33a9ab8e1ad29f3fdbf52a83166b694b81f5bce474e2fe85afecce3', '/var/lib/dakasa-capacity-network-recovery/2b7e9be2-e45a-4cd5-86f2-6f0a3372576d-GUARDIAN-a1826878088e4dbaa5e7adfb67cba5c6-FIRST-CURRENT15-RETURN.PUBLIC.json': 'e406648a4ecd503ff8231e5fde8d6969a091fe9327c4e8e0927815eb929711c4'}

EXPECTED_CURRENT_G9_PROOF_REFS = {'/var/lib/dakasa-capacity-network-recovery/eeb07b5f3d171544f5eddc02c4d0cbad6d07854bdf2958d697ef56d33c5e9c5c-QUALIFIED.PUBLIC.json': 'c3d6f4cac12d61e8ade4189012d065fff95e213f9cdc8edaeea757887234b16d', '/var/lib/dakasa-capacity-network-recovery/2b7e9be2-e45a-4cd5-86f2-6f0a3372576d-GUARDIAN-821ba94c6a3d4b32a22f022949691a1e-FIRST-CURRENT15-RETURN.PUBLIC.json': '2c18fb8de9ab3d1aeffd0302ac8d93f4797936ff6fb475e6f32061880ce17f56'}

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

def full_id(value):
    return type(value) is str and re.fullmatch('[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}', value) is not None

def digest_value(value):
    return type(value) is str and re.fullmatch('[0-9a-f]{64}', value) is not None and value != '0' * 64

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

def required_protected_refs():
    require_bound()
    out = dict(EXPECTED_INHERITED_REFS)
    for rows in (EXPECTED_CURRENT_G8_PROOF_REFS, EXPECTED_CURRENT_G9_PROOF_REFS):
        for path, pin in rows.items():
            need(path not in out and re.fullmatch('[a-f0-9]{64}', str(pin)), 'NO_ORIGINAL_REF_REPLACEMENT')
            out[path] = pin
    need(len(out) == 43, 'EXACT_ROOT_ACCEPTED_43_REF_UNION')
    return out

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

def g12_acceptance(cut, folder, manifest, returned, run):
    require_bound()
    C = cut.C
    need(set(returned) == {'schema', 'status', 'result', 'automatic_replay', 'Guest_or_Core_business_authority'}
         and returned['schema'] == 'g12_pair_swap_return_v1' and returned['status'] == 'CONFIG_SWAP_OK'
         and returned['automatic_replay'] is False and returned['Guest_or_Core_business_authority'] is False, 'ACTUAL_CLOSED_G12_SWAP_RETURN')
    result = returned['result']
    need(result['source_commit'] == manifest['source_commit'] and result['source_R'] == CORE_R and result['amd64_D'] == C.NEW_DIGEST
         and result['new_guardian_source_sha256'] == SOURCE_PIN and result['controller_config_sha256'] == C.HEAD_CONFIG_SHA
         and result['independent_current15'] is True and result['all_inherited_budget_and_original_refs_unchanged'] is True
         and result['Core_Cold_Hub_or_provider_mutation'] is False
         and all(v == 0 for v in result['conservative_per_role_gap_seconds'].values()), 'QUALIFIED_G12_RETURN_EXACT_P_R_D_AND_NO_ROLE_GAP')
    refs = manifest['protected_refs']
    need(len(refs) == len(required_protected_refs()) and len({r['path'] for r in refs}) == len(refs)
         and {r['path']:r['sha256'] for r in refs} == required_protected_refs(),
         'EXACT_INHERITED41_PLUS_ACTUAL_G9_FULL120_AND_OWN15_REFS')
    backend = cut.Backend(folder, manifest, '', run, {}, [], {})
    backend.files(successor=True)
    protected = backend.protected()
    C.once(run / 'PROTECTED-REFS-BEFORE.json', C.wire(protected))
    need(C.sha(C.read(C.NEW_STANDING, 32768, 0o600)) == result['standing_sha256'], 'EXACT_ACCEPTED_G12_STANDING')
    for key in ('controller', 'guardian'):
        C.identity(result[key])
    ctrl = cut.physical_identity(C.CTRL, cut.controller_argv(C.NEW_CONFIG))
    guard = cut.physical_identity(C.GUARD, cut.guardian_argv(C.NEW_SOURCE, SOURCE_PIN))
    need(ctrl == result['controller'] and guard == result['guardian'], 'SAME_ACCEPTED_G12_CONTROLLER_GUARDIAN')
    G = C.load_guardian(C.NEW_SOURCE, SOURCE_PIN)
    owner = G.Owner(SOURCE_PIN)
    full = owner.identity()
    need({k: full[k] for k in ctrl} == ctrl and owner.original_qualification_measurement(full) is not None, 'RECOMPUTED_ACTUAL_G12_FULL120_SAME_LIFETIME')
    full_path = C.LEDGER / (owner.key(full) + '-QUALIFIED.PUBLIC.json')
    own_path = C.LEDGER / (guard['boot_id'] + '-GUARDIAN-' + guard['InvocationID'] + '-FIRST-CURRENT15-RETURN.PUBLIC.json')
    for field, expected_path in (('actual_new_full120_ref', full_path), ('own_daemon_first_current15_ref', own_path)):
        ref = result[field]
        need(set(ref) == {'path', 'sha256'} and ref['path'] == str(expected_path)
             and C.sha(C.read(expected_path, 16 << 20, 0o600)) == ref['sha256'], 'SAME_G12_ACTUAL_ORIGINAL_QUALIFICATION_REF')
    own = C.loads(C.read(own_path, 16 << 20, 0o600))
    need(own['schema'] == 'Root_owning_finite512_current15_readonly_observation_v1' and own['source_sha256'] == SOURCE_PIN
         and own['standing_config_sha256'] == result['standing_sha256'] and own['identity'] == full
         and own['measurement']['qualified_15_seconds'] is True and own['measurement']['all_requested_rows_accounted_for'] is True
         and own['kernel']['all_four_backends_and_reverse_sources_positive'] is True, 'ACTUAL_G12_DAEMON_OWN15_NOT_ASSESSOR_SUBSTITUTE')
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

def require_bound():
    need(SOURCE_BOUND is True and full_id(UID) and full_id(OLD_POD)
         and re.fullmatch('[a-f0-9]{40}', str(CORE_R)) and CORE_R != OLD_SOURCE
         and digest_value(NEW_DIGEST) and NEW_DIGEST != OLD_DIGEST
         and digest_value(SOURCE_PIN) and type(TOOL_PINS) is dict
         and set(TOOL_PINS) == {'pair_change_contract.py', 'derive_g12pair_controller_config.py', 'derive_standing_config.py', 'g12cut.py'}
         and all(digest_value(v) for v in TOOL_PINS.values())
         and re.fullmatch('containerd://[a-f0-9]{64}', str(OLD_CONTAINER_ID))
         and re.fullmatch('sha256:[a-f0-9]{64}', str(OLD_IMAGE_CONFIG_DIGEST)),
         'G12_RELEASE_AND_FRESH_R2_PREIMAGES_NOT_BOUND')
    for ref in (CONFIG_REF, SQL_DATA_REF):
        need(type(ref) is dict and set(ref) == {'path', 'sha256'} and Path(ref['path']).is_absolute()
             and digest_value(ref['sha256']), 'CLOSED_ROOT_BOUND_INPUT_REF')
    need(SQL_DATA_REF['sha256'] == POLICY92_SQL_SHA, 'EXACT_UNMODIFIED_E70_QUERY_FACTORY')


def load_tools(folder):
    require_bound()
    for name, pin in TOOL_PINS.items():
        need(sha(read(folder / 'tools' / name)) == pin, 'EXACT_REVIEWED_G12_TOOL')
    path = folder / 'tools/g12cut.py'
    module = types.ModuleType('reviewed_g12cut_for_core_cas')
    module.__file__ = str(path)
    exec(compile(read(path), str(path), 'exec'), module.__dict__)
    return module


def core_before(d, ps, C):
    need(C.OLD_DIGEST == OLD_DIGEST and C.OLD_CORE_SOURCE == OLD_SOURCE, 'EXACT_CURRENT_R2_AMD64_SOURCE')
    m, s = d['metadata'], d['status']
    need(d['apiVersion'] == 'apps/v1' and d['kind'] == 'Deployment' and m['namespace'] == 'dakasa'
         and m['name'] == 'yggdrasil' and m['uid'] == UID and m['generation'] == GENERATION
         and m['resourceVersion'].isdecimal() and not m.get('deletionTimestamp')
         and m['annotations']['dakasa.io/core-source-commit'] == OLD_SOURCE, 'EXACT_R2_UID_GENERATION_SOURCE')
    need(d['spec'].get('replicas', 1) == 1 and s['observedGeneration'] == GENERATION
         and all(s.get(k) == 1 for k in ('readyReplicas', 'updatedReplicas', 'availableReplicas'))
         and s.get('unavailableReplicas', 0) == 0
         and [(v['name'], v['image']) for v in d['spec']['template']['spec']['containers']] == [('core', C.IMAGE_PREFIX + OLD_DIGEST)], 'EXACT_READY_SINGLE_R2_CORE')
    need(len(ps['items']) == 1, 'ONE_CURRENT_R2_POD')
    p = ps['items'][0]
    need(p['metadata']['uid'] == OLD_POD and not p['metadata'].get('deletionTimestamp')
         and p['status']['phase'] == 'Running' and len(p['status']['containerStatuses']) == 1
         and [(v['name'], v['image']) for v in p['spec']['containers']] == [('core', C.IMAGE_PREFIX + OLD_DIGEST)], 'EXACT_R2_POD_TUPLE')
    c = p['status']['containerStatuses'][0]
    need(c['name'] == 'core' and c['ready'] is True and c['restartCount'] == 0 and c.get('state', {}).get('running')
         and c['imageID'].rsplit(':', 1)[-1] == OLD_DIGEST and c['containerID'] == OLD_CONTAINER_ID, 'EXACT_R2_IMAGEID_CONTAINER_ZERO_RESTART')
    return {'deployment_uid': UID, 'generation': GENERATION, 'pod_uid': OLD_POD,
            'pod_name': p['metadata']['name'], 'pod_ip': p['status']['podIP'],
            'image': C.IMAGE_PREFIX + OLD_DIGEST, 'imageID': c['imageID'], 'containerID': c['containerID']}


def build_patch(before, C):
    return [
        {'op': 'test', 'path': '/metadata/uid', 'value': UID},
        {'op': 'test', 'path': '/metadata/resourceVersion', 'value': before['metadata']['resourceVersion']},
        {'op': 'test', 'path': '/metadata/generation', 'value': GENERATION},
        {'op': 'test', 'path': '/metadata/annotations', 'value': before['metadata']['annotations']},
        {'op': 'test', 'path': '/spec', 'value': before['spec']},
        {'op': 'replace', 'path': '/spec/template/spec/containers/0/image', 'value': C.IMAGE_PREFIX + C.NEW_DIGEST},
        {'op': 'add', 'path': '/metadata/annotations/dakasa.io~1core-source-commit', 'value': CORE_R},
        {'op': 'add', 'path': '/metadata/annotations/kubernetes.io~1change-cause', 'value': CHANGE_CAUSE},
    ]


S2_SQL = """SELECT jsonb_build_object(
'observed_at_pg',clock_timestamp(),
'intent_pgtext',(SELECT intent::text FROM public.capacity_intents WHERE namespace='dakasa-production' AND environment='production' AND domain='notify' AND dimension='original_notify_aws_vm_members'),
'run_pgtext',(SELECT to_jsonb(w)::text FROM public.workflow_runs w WHERE id=(SELECT (original_record->>'run_id')::uuid FROM public.capacity_guest_retirement_forwards WHERE id='05192d81-bc0b-4076-9b06-766094240a9d' AND stage='admitted')),
'dispatch',(SELECT jsonb_agg(to_jsonb(j) ORDER BY j.id) FROM public.capacity_dispatch_jobs j WHERE run_id=(SELECT (original_record->>'run_id')::uuid FROM public.capacity_guest_retirement_forwards WHERE id='05192d81-bc0b-4076-9b06-766094240a9d' AND stage='admitted')),
'forwards',(SELECT jsonb_agg(to_jsonb(f) ORDER BY f.recorded_at,f.stage) FROM public.capacity_guest_retirement_forwards f WHERE retirement_request_id='fd24881a-01ea-429c-a04c-13a738684ea5'),
'grant',(SELECT to_jsonb(g) FROM public.capacity_mutation_grants g WHERE id='d1ac8d0e-f38f-49eb-a5ab-17ed9204d979'),
'bindings',(SELECT jsonb_agg(to_jsonb(b) ORDER BY b.destroy_grant_id) FROM public.capacity_vm_retirement_delete_bindings b WHERE intent_id='fd24881a-01ea-429c-a04c-13a738684ea5'),
'original_intent',(SELECT to_jsonb(i) FROM public.capacity_vm_retirement_intents i WHERE id='fd24881a-01ea-429c-a04c-13a738684ea5'),
'original_returns',(SELECT jsonb_agg(to_jsonb(r) ORDER BY sequence) FROM public.capacity_vm_retirement_original_returns r WHERE intent_id='fd24881a-01ea-429c-a04c-13a738684ea5'),
'original_callers',(SELECT jsonb_agg(to_jsonb(c) ORDER BY return_sha256) FROM public.capacity_guest_original_caller_returns c WHERE intent_id='fd24881a-01ea-429c-a04c-13a738684ea5'),
'original_context',(SELECT to_jsonb(c) FROM public.capacity_guest_original_retirement_contexts c WHERE c.intent_id='fd24881a-01ea-429c-a04c-13a738684ea5'),
'original_attempts',(SELECT jsonb_agg(to_jsonb(a) ORDER BY attempt_id) FROM public.capacity_guest_original_caller_attempts a WHERE a.intent_id='fd24881a-01ea-429c-a04c-13a738684ea5'),
'authority_transports',(SELECT jsonb_agg(to_jsonb(v) ORDER BY v.read_id,v.native_stage) FROM public.capacity_guest_original_authority_transport_returns v JOIN public.capacity_guest_original_authority_reads r ON r.id=v.read_id WHERE r.intent_id='fd24881a-01ea-429c-a04c-13a738684ea5'),
'original_authorities',(SELECT jsonb_agg(jsonb_build_object('read',to_jsonb(r),'return',to_jsonb(v)) ORDER BY CASE r.phase WHEN 'before_start' THEN 0 ELSE 1 END,r.ordinal) FROM public.capacity_guest_original_authority_reads r LEFT JOIN public.capacity_guest_original_authority_returns v ON v.read_id=r.id WHERE r.intent_id='fd24881a-01ea-429c-a04c-13a738684ea5'),
'reads',(SELECT jsonb_agg(to_jsonb(r) ORDER BY recorded_at,id,stage) FROM public.capacity_guest_retirement_forward_reads r WHERE retirement_request_id='fd24881a-01ea-429c-a04c-13a738684ea5'))"""



def digest(value):
    return type(value) is str and re.fullmatch('[a-f0-9]{64}', value) and value != '0' * 64

def source(value):
    return type(value) is str and re.fullmatch('[a-f0-9]{40}', value) and value != '0' * 40

def closed(value, fields, guard):
    need(type(value) is dict and set(value) == set(fields.split()), guard)

def loads(raw):
    def unique(rows):
        value = {}
        for key, item in rows:
            need(key not in value, 'NO_DUPLICATE_JSON_KEY')
            value[key] = item
        return value
    return json.loads(raw, object_pairs_hook=unique,
                      parse_constant=lambda _: (_ for _ in ()).throw(Hold('FINITE_JSON_ONLY')))


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


def sealed(row, C):
    need(type(row) is dict and type(row['original_wire']) is str and row['original_wire'].startswith('\\x'), 'ACTUAL_PG_ORIGINAL_WIRE')
    raw = bytes.fromhex(row['original_wire'][2:])
    need(len(raw) <= 2 << 20 and sha(raw) == row['record_sha256'] and C.loads(raw) == row['original_record'], 'UNCHANGED_SEALED_ORIGINAL')
    return raw, row['original_record']


def validate_s2(v, c, C):
    need(type(v) is dict and set(v) == {'observed_at_pg','intent_pgtext','run_pgtext','dispatch','forwards','grant','bindings','original_intent','original_returns','original_callers','original_context','original_attempts','authority_transports','original_authorities','reads'}, 'CLOSED_S2_SNAPSHOT')
    k = c['case']
    need(type(v['intent_pgtext']) is str and sha(v['intent_pgtext'].encode()) == k['intent_sha256']
         and type(v['run_pgtext']) is str and sha(v['run_pgtext'].encode()) == k['run_sha256'], 'EXACT_S2_INTENT_AND_FAILED_RUN_BYTES')
    i, w = C.loads(v['intent_pgtext']), C.loads(v['run_pgtext'])
    need(i['generation'] == 15 and i['fencing_token'] == 33 and i['phase'] == 'drained'
         and i['lease_owner'] == k['lease_owner'] and i['lease_executor_id'] == k['executor_id']
         and i['lease_expires_at'] == k['lease_expires_at'] and utc(v['observed_at_pg']) > utc(k['lease_expires_at']), 'ONLY_EXPIRED_ORIGINAL_S2_OWNER_NO_RESET')
    m = i['retirement_forward']
    need(m['id'] == FORWARD and m['retirement_request_id'] == RETIREMENT and m['stage'] == 'off_qualified', 'EXACT_S2_MARKER')
    need(w['id'] == k['run_id'] and w['status'] == 'failed' and w['finished_at'] is not None
         and type(v['dispatch']) is list and len(v['dispatch']) == 1, 'ONE_EXACT_FAILED_FINISHED_S2_RUN')
    j = v['dispatch'][0]; e = C.loads(j['envelope']) if type(j['envelope']) is str else j['envelope']
    need(j['id'] == k['dispatch_id'] and j['run_id'] == w['id'] and j['state'] == 'returned' and j['return_status'] == 'failed'
         and e['workflow']['id'] == k['workflow_id'] and utc(j['returned_at']) == utc(w['finished_at'])
         and j['finalization_ack_at'] is not None and utc(j['finalization_ack_at']) >= utc(j['returned_at']), 'ORIGINAL_S2_RETURN_AND_ACK_NO_UNKNOWN')
    rows = v['forwards']
    need(type(rows) is list and len(rows) == 2 and {(r['id'],r['stage']) for r in rows} == {(FORWARD,'admitted'),(FORWARD,'off_qualified')}, 'EXACT_TWO_ORIGINAL_S2_FRAMES_NO_CHILD')
    by = {r['stage']: r for r in rows}; frames = {}
    for row in rows:
        _, x = sealed(row, C); frames[row['stage']] = x
        need(x['id'] == FORWARD and x['root_admission_id'] == FORWARD and x['mode'] == 'live'
             and x['generation'] == 15 and x['fence'] == 33 and x['lease_owner'] == k['lease_owner']
             and x['executor_id'] == k['executor_id'] and x['run_id'] == w['id'], 'ONLY_ORIGINAL_LIVE_S2_AUTHORITY')
    a, off = frames['admitted'], frames['off_qualified']
    need(a['original'] == off['original'] and a['evidence'] == off['evidence']
         and off['admission_sha256'] == by['admitted']['record_sha256']
         and off['original_caller_sha256'] == a['evidence']['caller_sha256'], 'S2_WHOLE_ORIGINAL_FRAME_AND_EVIDENCE')
    g = v['grant']; record = g['grant_record']; settlement = record['settlement']; grant = record['grant']
    need(g['id'] == DESTROY and g['state'] == 'settled' and grant['grant_id'] == DESTROY and grant['state'] == 'settled'
         and record['fencing_token'] == 33 and record['lease_owner'] == k['lease_owner'] and record['executor_id'] == k['executor_id']
         and g['namespace'] == 'dakasa-production' and g['dimension'] == 'original_notify_aws_vm_members'
         and all(g[x] is None for x in ('original_disposition_id','failed_original_disposition_id','native_denied_disposition_id','enrolled_failed_disposition_id'))
         and settlement['grant_id'] == DESTROY and settlement['outcome'] == 'accepted' and settlement['transport_completed'] is True
         and settlement['auxiliary_inventory_complete'] is True and settlement['action_id'] == k['action_id'], 'ONLY_ORIGINAL_ACCEPTED_SETTLED_DELETE')
    sdk = settlement['original_provider_destroy_return']
    need(sdk['schema'] == 'aws_original_terminate_instances_return_v1' and sdk['provider'] == 'aws'
         and sdk['grant_id'] == DESTROY and sdk['attempt_id'] == record['attempt_id'] and sdk['request_sha256'] == grant['request_sha256']
         and sdk['action_id'] == k['action_id'] and sdk['response_status'] == 200
         and digest_value(sdk['response_body_sha256']) and 2 <= sdk['response_bytes'] <= 2 << 20
         and sdk['resource_id'] == grant['expected_resource_id'] and sdk['resource_created_at'] == grant['expected_resource_created_at']
         and utc(sdk['called_at']) <= utc(sdk['returned_at']) < utc(sdk['context_deadline'])
         and (utc(sdk['context_deadline'])-utc(sdk['called_at'])).total_seconds() <= 60, 'ORIGINAL_SDK_TERMINATE_200_NEVER_REISSUED')
    need(type(v['bindings']) is list and len(v['bindings']) == 1, 'ONE_ORIGINAL_S2_DELETE_BINDING')
    binding = v['bindings'][0]; wire = bytes.fromhex(binding['original_wire'][2:]); eligibility = binding['original_eligibility_record']
    need(binding['destroy_grant_id'] == DESTROY and binding['intent_id'] == RETIREMENT and sha(wire) == binding['eligibility_sha256']
         and C.loads(wire) == eligibility and eligibility['schema'] == 'original_guest_partial_poweroff_delete_eligibility_v1'
         and eligibility['admission_id'] == FORWARD and eligibility['admission_sha256'] == by['admitted']['record_sha256'], 'EXACT_ORIGINAL_DELETE_ELIGIBILITY')
    evidence = a['evidence']; returns = v['original_returns']; authorities = v['original_authorities']; callers = v['original_callers']
    need(len(returns) == k['journal_rows']+1 and [r['sequence'] for r in returns] == list(range(1,len(returns)+1))
         and returns[0]['kind'] == 'production_clock_nonce_v2' and returns[0]['return_sha256'] == evidence['nonce_sha256']
         and [r['return_sha256'] for r in returns[1:]] == evidence['journal_sha256']
         and len(authorities) == 4 and all(type(r['return']) is dict for r in authorities)
         and [r['return']['authority_sha256'] for r in authorities] == evidence['authority_sha256']
         and len(callers) == 1 and callers[0]['return_sha256'] == evidence['caller_sha256']
         and v['original_intent']['id'] == RETIREMENT and returns[0]['original_return_record']['final_request'] == a['original']['Request'], 'WHOLE_ORIGINAL_S2_NONCE_PREFIX_CALLER_AUTHORITY_ROWS')
    reads = v['reads']; need(type(reads) is list and len(reads) == k['read_rows'], 'ALL_ORIGINAL_READ_ROWS')
    prepared = {r['id']:r for r in reads if r['stage'] == 'prepared'}
    returned = [r for r in reads if r['stage'] == 'returned']
    need(len(prepared) == len(returned) and {r['id'] for r in returned} == set(prepared), 'NO_UNRETURNED_OR_EXTRA_READ')
    for r in reads: sealed(r,C)
    last = max(returned,key=lambda r:(utc(r['recorded_at']),r['id']))
    raw, rr = sealed(last,C); challenge_raw, challenge = sealed(prepared[last['id']],C)
    need(last['id'] == k['pending_read_id'] and last['record_sha256'] == k['pending_read_sha256']
         and utc(last['recorded_at']) <= utc(j['returned_at'])
         and pending_absence_valid(prepared[last['id']], last, by['admitted'], g, k['observer_source']),
         'LAST_AUTHENTIC_ORIGINAL_PENDING_WITH_EXACT_RAW_READ_AND_RECEIPT')
    need(sha(raw_json_member(raw,'original_destroy_receipt')) == k['receipt_sha256'], 'ROOT_PIN_MATCHES_ACTUAL_ORIGINAL_RECEIPT_BYTES')
    return True
LEGACY_CATALOG_SHA = 'c9d3664e43ef876a9a7a89c031bf75f761dbb0c70a664db2408058a6ce2431eb'

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


def catalog_projection(value):
    """Stable catalog identity; history, activity and ledger facts are separate."""
    v, s = value['legacy'], value['supplement']
    return {'catalog90': v['catalog90'], 'catalog91': v['catalog91'],
            **{key: s[key] for key in ('columns90_91','functions93','index92_valid','index92_definition')}}


def catalog_select(legacy):
    # Keep the shared SELECT byte-for-byte. Only the CAS reader's established
    # RR/RO3s/.5s/process8 transaction wrapper replaces the migration wrapper.
    whole = catalog_sql(legacy,types.SimpleNamespace(workflow_busy_logical_index92_sql=workflow_busy_logical_index92_sql))
    need(whole.endswith(';\nCOMMIT;') and '\nWITH legacy AS ' in whole,'CLOSED_COMMON_CATALOG_SELECT')
    return 'WITH '+whole.split('\nWITH ',1)[1][:-len(';\nCOMMIT;')]


def maintenance_inputs(C):
    require_bound()
    raw = input_ref(C, CONFIG_REF); c = C.loads(raw)
    need(type(c) is dict and set(c) == {'schema','source_R','amd64_D','core_preimage','case','schema_pins','policy_state','current_preimage_ref','schema93_catalog_ref','prior92_history_ref','legacy_catalog_sql_ref','acceptance_refs'}, 'CLOSED_G12_S2_INPUT')
    need(c['schema'] == 'g12_known_settled_S2_image_maintenance_v1' and c['source_R'] == CORE_R == C.SOURCE_R
         and c['amd64_D'] == NEW_DIGEST == C.NEW_DIGEST
         and C.OLD_CORE_UID == UID and C.OLD_CORE_GENERATION == GENERATION and C.OLD_CORE_POD_UID == OLD_POD, 'ONE_QUALIFIED_RELEASE_AND_CURRENT_R2')
    p = c['core_preimage']
    need(type(p) is dict and set(p) == {'deployment_uid','generation','pod_uid','container_id','image_config_digest','spec_sha256','annotations_sha256'}
         and p['deployment_uid'] == UID and p['generation'] == GENERATION and p['pod_uid'] == OLD_POD
         and p['container_id'] == OLD_CONTAINER_ID and p['image_config_digest'] == OLD_IMAGE_CONFIG_DIGEST
         and all(digest_value(p[x]) for x in ('spec_sha256','annotations_sha256')), 'ROOT_FULL_CURRENT_R2_LIFETIME_SPEC_AND_ANNOTATIONS')
    k = c['case']
    need(type(k) is dict and set(k) == {'run_id','dispatch_id','workflow_id','lease_owner','executor_id','lease_expires_at','action_id','journal_rows','read_rows','intent_sha256','run_sha256','pending_read_id','pending_read_sha256','observer_source','receipt_sha256'}
         and all(full_id(k[x]) for x in ('run_id','dispatch_id','workflow_id','lease_owner','executor_id','action_id','pending_read_id'))
         and k['journal_rows'] in (3,4) and type(k['read_rows']) is int and k['read_rows'] >= 2
         and all(digest_value(k[x]) for x in ('intent_sha256','run_sha256','pending_read_sha256','receipt_sha256'))
         and re.fullmatch('[a-f0-9]{40}', str(k['observer_source'])) and utc(k['lease_expires_at']), 'ROOT_EXACT_S2_ORIGINAL_IDENTITIES_NOT_PREFIXES')
    need(type(c['acceptance_refs']) is dict and set(c['acceptance_refs']) == {'qualified_business_release','business_Source_CI','Root_Goose93_acceptance','Root_separate_rollout_review'}, 'DISTINCT_RELEASE_CI_GOOSE_AND_ROLLOUT_EVIDENCE')
    for ref in c['acceptance_refs'].values():
        need(len(input_ref(C,ref)) > 1, 'ACTUAL_ROOT_PINNED_INDEPENDENT_ACCEPTANCE_REF')
    need(type(c['policy_state']) is dict and set(c['policy_state']) == {'aws','hetzner'}
         and all(type(v) is dict and set(v) == {'intent_identity','owned_slots','active_policies','policy_catalog_wire'} for v in c['policy_state'].values()), 'BOTH_EXACT_POLICY_ROSTERS_AND_OWNERS')
    validate_s2(C.loads(input_ref(C,c['current_preimage_ref'])),c,C)
    sql = C.loads(input_ref(C,SQL_DATA_REF))
    need(sql['schema'] == 'fixed_policy_publication_schema92_SQL_data_v1'
         and set(sql['queries']) == {'original_notify_aws_vm_members','original_notify_hetzner_vm_members'}, 'EXACT_UNMODIFIED_E70_EIGHT_TERMINAL_QUERIES')
    return c, raw, sql


def schema93_facts(c, legacy, current, C):
    v = legacy['schema_facts']; pins = c['schema_pins']
    need(current['legacy']['database'] == 'yggdrasil' and current['legacy']['readonly'] == 'on'
         and current['legacy']['latest_versions'] == [0]+[n for n in range(1,94) if n != 40]
         and v['database'] == 'yggdrasil' and v['readonly'] == 'on' and v['history_max_version'] == 93
         and v['latest_versions'] == [0]+[n for n in range(1,94) if n != 40]
         and v['rows90'] == v['rows91'] == v['rows92'] == 1
         and legacy['index89_valid'] is True and legacy['index92_valid'] is True, 'EXACT_SCHEMA93_HEAD_HISTORY_AND_EXISTING_INDEXES')
    # E70 prior*_wire fields retain their head92 ABI and include93 now.
    # Compare the actual complete prior92 receipt instead of relabelling them.
    full = C.loads(v['complete_history_wire']); prior92 = C.loads(input_ref(C,c['prior92_history_ref']))
    need(C.loads(current['legacy']['complete_history_wire']) == full and len(full) == len(prior92)+1
         and prior92 == [r for r in full if r['version_id'] != 93]
         and len([r for r in full if r['version_id'] == 93 and r['is_applied'] is True]) == 1
         and all(r['is_applied'] is True for r in full), 'ONE_ACTUAL93_AND_ALL_PRIOR92_HISTORY_BYTES_PRESERVED')
    need(set(pins) == {'complete_history_sha256','index92_definition_sha256','catalog90_91_sha256','schema93_catalog_sha256'}
         and all(digest_value(p) for p in pins.values())
         and sha(v['complete_history_wire'].encode()) == pins['complete_history_sha256']
         and sha(legacy['index92_definition'].encode()) == pins['index92_definition_sha256']
         and sha(canonical({'catalog90':v['catalog90'],'catalog91':v['catalog91']})) == pins['catalog90_91_sha256']
         and sha(canonical(catalog_projection(current))) == pins['schema93_catalog_sha256'], 'ROOT_ACCEPTED93_COMPLETE_HISTORY_AND_CATALOG_NO_OTHER_DRIFT')
    expected = C.loads(input_ref(C,c['schema93_catalog_ref']))
    projection = catalog_projection(current)
    need(projection == expected and all(current['legacy'][k] == 0 for k in ('other_migrators_ddl','other_cic','ddl_locks'))
         and {r['name'] for r in current['supplement']['functions93']} == {'guard_retirement_forward','guard_retirement_forward_read','guard_retirement_forward_delete_binding','retirement_forward_continuation_quiet','retirement_forward_continuation_valid'}
         and len(current['supplement']['functions93']) == 5 and all(r['definition'] and r['body'] for r in current['supplement']['functions93'])
         and all(r['validated'] is True for r in current['legacy']['catalog90']['constraints'])
         and {'retirement_forward_mode93','retirement_forward_continuation93'} <= {r['name'] for r in current['legacy']['catalog90']['constraints']}
         and all(type(v[k]) is int and v[k] == 0 for k in ('other_migrators_ddl','other_cic','ddl_locks')), 'EXACT_ROOT_GOOSE93_CATALOG_AND_NO_CONCURRENT_DDL')


def database_s2(cut, run, c, sql, phase):
    require_bound()
    need(phase in ('BEFORE','PRESEND'), 'ONLY_PREPATCH_S2_FROZEN_PHASES')
    C = cut.C
    need(c['legacy_catalog_sql_ref']['sha256'] == LEGACY_CATALOG_SHA,'EXACT_SHARED_C9_CATALOG_SOURCE')
    legacy_sql = input_ref(C,c['legacy_catalog_sql_ref']).decode()
    current = query(cut,run,phase+'-SCHEMA93',catalog_select(legacy_sql))
    for provider,key in (('aws','original_notify_aws_vm_members'),('hetzner','original_notify_hetzner_vm_members')):
        v = query(cut,run,phase+'-'+provider,sql['queries'][key])
        schema93_facts(c,v,current,C)
        need(v['intent_count'] == 1 and all(type(v[k]) is int and v[k] == 0 for k in ('jobs_busy','runs_busy','forward_unreturned_reads','live_unreturned_canaries')), 'BOTH_PROVIDERS_NO_BUSY_JOBS_RUNS_OR_UNRETURNED_PROOF')
        need(tuple(v[k] for k in ('intent_busy','pending_authority','forward_markers')) == ((1,1,1) if provider == 'aws' else (0,0,0)), 'ONLY_KNOWN_SETTLED_S2_AUTHORITY')
        need({k:v[k] for k in ('intent_identity','owned_slots','active_policies','policy_catalog_wire')} == c['policy_state'][provider], 'ALL_OTHER_POLICY_AND_ROSTER_BYTES_EXACT')
    actual = query(cut,run,phase+'-S2',S2_SQL); expected = C.loads(input_ref(C,c['current_preimage_ref']))
    need({k:v for k,v in actual.items() if k != 'observed_at_pg'} == {k:v for k,v in expected.items() if k != 'observed_at_pg'}, 'WHOLE_S2_PREIMAGE_UNCHANGED_NO_REBASE')
    need(0 <= (datetime.datetime.now(datetime.timezone.utc)-utc(actual['observed_at_pg'])).total_seconds() <= 15, 'FRESH_S2_DB_READ')
    validate_s2(actual,c,C)


def global_marker(C):
    return ROOT / ('CORE-IMAGE-8E6D44D-TO-'+C.NEW_DIGEST+'-POSSIBLE.json')


def patch_once(api, C, run, wire, marker, observed):
    require_bound()
    """Both durable possible-send markers precede the only actual PATCH."""
    C.once(global_marker(C),C.wire(marker))
    C.once(run/'POSSIBLE-SEND.json',C.wire(marker))
    need(time.monotonic()-observed <= 15,'CURRENT15_STILL_FRESH_AFTER_DURABLE_MARKERS_NO_SEND')
    try:
        status, raw, headers = api.request('PATCH',DEP_URI+'?fieldManager=core-image-cas-once',wire)
        C.once(run/'PATCH-ACTUAL-RETURN.json',raw)
        C.once(run/'PATCH-ACTUAL-RETURN.HTTP.json',C.wire({'status':status,**headers}))
        need(status == 200,'ACTUAL_PATCH_NOT_ACKNOWLEDGED_200_NO_RETRY')
        return C.loads(raw)
    except Exception:
        # One forensic GET is permitted after possible-send. It cannot retry,
        # approve, roll back or claim rollout/business completion.
        try:
            api_read(api,C,run,'LOST-ACK-GET-ONLY',DEP_URI)
        except Exception:
            pass
        raise Hold('POSSIBLE_PATCH_RECONCILE_GET_ONLY_NO_RETRY') from None


def main():
    require_bound()
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--package',required=True,type=Path)
    p.add_argument('--expected-ops-source',required=True)
    p.add_argument('--expected-manifest-sha256',required=True)
    p.add_argument('--g12-swap-return',required=True,type=Path)
    p.add_argument('--expected-g12-swap-return-sha256',required=True)
    p.add_argument('--evidence-dir',required=True,type=Path)
    p.add_argument('--execute-core-image-cas-once',action='store_true',required=True)
    a = p.parse_args()
    need(os.geteuid() == 0 and sys.platform == 'linux','ROOT_LINUX_BRAIN_ONLY')
    folder = a.package.absolute(); cut = load_tools(folder); C = cut.C
    c, original_config, sql = maintenance_inputs(C)
    folder, manifest = C.package(folder,a.expected_manifest_sha256)
    need(manifest['source_commit'] == a.expected_ops_source and re.fullmatch('[a-f0-9]{40}',a.expected_ops_source)
         and manifest['files']['source/network_guardian.py'] == SOURCE_PIN and manifest['tools'] == TOOL_PINS,'EXACT_SEPARATELY_QUALIFIED_G12_OPERATIONAL_SOURCE')
    returned_path = a.g12_swap_return.absolute()
    need(returned_path.name == 'RETURN.json' and returned_path.parent.parent == ROOT and returned_path.parent.name.startswith('swap-once-'),'EXACT_ACTUAL_G12_RETURN_PATH')
    C.private_dir(returned_path.parent); returned_raw = C.read(returned_path,32<<20,0o600)
    need(sha(returned_raw) == a.expected_g12_swap_return_sha256 and digest_value(a.expected_g12_swap_return_sha256)
         and not (returned_path.parent/'HOLD.json').exists(),'EXACT_ACTUAL_G12_SUCCESS_RETURN_NOT_HOLD')
    swap_claim = C.loads(C.read(ROOT/('SWAP-'+a.expected_manifest_sha256+'-POSSIBLE.json'),32768,0o600))
    need(set(swap_claim) == {'schema','manifest_sha256','old_controller','old_guardian','run','automatic_replay'}
         and swap_claim['schema'] == 'g12_once_only_swap_claim_v1' and swap_claim['manifest_sha256'] == a.expected_manifest_sha256
         and swap_claim['old_controller'] == manifest['expected_controller_identity'] and swap_claim['old_guardian'] == manifest['expected_guardian_identity']
         and swap_claim['run'] == str(returned_path.parent) and swap_claim['automatic_replay'] is False,'G12_ACTUAL_ONCE_CLAIM_BINDS_MANIFEST_AND_RETURN')
    run = a.evidence_dir.absolute()
    need(run.parent == ROOT and re.fullmatch('core-image-cas-[A-Za-z0-9_-]{1,96}',run.name),'CLOSED_NEW_CAS_EVIDENCE_DIRECTORY')
    C.private_dir(ROOT); C.private_dir(run,create=True)
    sent = False
    def interrupted(signum,_): raise Hold('SIGNAL_'+str(signum)+'_RECONCILE_NO_REPLAY')
    for sig in (signal.SIGTERM,signal.SIGINT,signal.SIGHUP,signal.SIGALRM): signal.signal(sig,interrupted)
    signal.alarm(120)
    try:
        with operation_lock() as inode:
            need(not global_marker(C).exists(),'NEW_R2_TO_R3_GLOBAL_ONCE_ALREADY_CLAIMED')
            C.once(run/'MAINTENANCE-INPUT.original.json',original_config)
            api = API(cut)
            before = api_read(api,C,run,'DEPLOYMENT-BEFORE',DEP_URI)
            pods = api_read(api,C,run,'PODS-BEFORE',PODS_URI); old_tuple = core_before(before,pods,C)
            need(sha(C.wire(before['spec'])) == c['core_preimage']['spec_sha256'] and sha(C.wire(before['metadata']['annotations'])) == c['core_preimage']['annotations_sha256'],'EXACT_ROOT_FULL_R2_PREIMAGE')
            lineage = C.loads(C.read(returned_path.parent/'BEFORE.json',32<<20,0o600))
            need(lineage['core'] == old_tuple and lineage['controller'] == manifest['expected_controller_identity']
                 and lineage['guardian'] == manifest['expected_guardian_identity'] and lineage['protected_refs'] == required_protected_refs(),'SAME_G12_PREDECESSOR_CORE_AND_PROTECTED_ORIGINALS')
            wire = C.wire(build_patch(before,C)); C.once(run/'PATCH.json',wire)
            status, raw, headers = api.request('PATCH',DEP_URI+'?dryRun=All&fieldManager=core-image-cas-once',wire)
            C.once(run/'SERVER-DRYRUN.json',raw); C.once(run/'SERVER-DRYRUN.HTTP.json',C.wire({'status':status,**headers}))
            need(status == 200,'SERVER_DRYRUN_200'); result_shape(before,C.loads(raw),C)
            database_s2(cut,run,c,sql,'BEFORE')
            backend, protected, ctrl, guard, observed = g12_acceptance(cut,folder,manifest,C.loads(returned_raw),run)
            need(protected == lineage['protected_refs'],'SAME43_ORIGINALS_AND_ONE_OF_THREE_BUDGET')
            fresh = api_read(api,C,run,'DEPLOYMENT-FRESH-PRESEND',DEP_URI)
            fresh_pods = api_read(api,C,run,'PODS-FRESH-PRESEND',PODS_URI)
            need(core_before(fresh,fresh_pods,C) == old_tuple and fresh['metadata']['resourceVersion'] == before['metadata']['resourceVersion']
                 and fresh['spec'] == before['spec'] and fresh['metadata']['annotations'] == before['metadata']['annotations'],'UNCHANGED_FULL_API_PREIMAGE_NO_REBASE')
            backend.files(successor=True)
            need(backend.protected() == protected and cut.physical_identity(C.CTRL,cut.controller_argv(C.NEW_CONFIG)) == ctrl
                 and cut.physical_identity(C.GUARD,cut.guardian_argv(C.NEW_SOURCE,SOURCE_PIN)) == guard,'SAME_ACCEPTED_G12_LIFETIMES_IMMEDIATELY_BEFORE_PATCH')
            database_s2(cut,run,c,sql,'PRESEND')
            current_lock = OPLOCK.lstat()
            need((current_lock.st_dev,current_lock.st_ino) == inode and time.monotonic()-observed <= 15,'SAME_MUTEX_AND_FRESH_CURRENT15')
            marker = {'schema':'g12_R2_to_R3_core_image_possible_send_v1','at':now(),'method':'PATCH','uri':DEP_URI,
                'deployment_uid':UID,'generation':GENERATION,'resourceVersion':before['metadata']['resourceVersion'],
                'patch_sha256':sha(wire),'script_sha256':sha(read(__file__)),'manifest_sha256':a.expected_manifest_sha256,
                'G12_return_sha256':a.expected_g12_swap_return_sha256,'evidence_dir':str(run),'automatic_retry':False,
                'effects_may_have_happened_after_this_marker':True}
            sent = True; after = patch_once(api,C,run,wire,marker,observed); result_shape(before,after,C)
            # S2 may now be automatically completed by new Core. No AFTER-ACK
            # query falsely requires the intentionally unblocked S2 to stay held.
            result = {'schema':'g12_core_image_cas_return_v1','status':'PATCH_ACKNOWLEDGED_ACCEPTANCE_PENDING',
                'deployment_uid':UID,'generation':after['metadata']['generation'],'resourceVersion':after['metadata']['resourceVersion'],
                'old_pod_uid':OLD_POD,'Core_source':CORE_R,'image':C.IMAGE_PREFIX+C.NEW_DIGEST,'manifest_sha256':a.expected_manifest_sha256,
                'G12_return_sha256':a.expected_g12_swap_return_sha256,'patch_sha256':sha(wire),'automatic_retry':False,
                'new_pod_readiness_proven':False,'post_rollout_G12_and_E2E_acceptance_proven':False,'evidence_dir':str(run)}
            C.once(run/'RETURN.PUBLIC.json',C.wire(result))
        signal.alarm(0); print(C.wire(result).decode(),end='',flush=True)
    except Exception as error:
        signal.alarm(0)
        C.once(run/'HOLD.PUBLIC.json',C.wire({'schema':'g12_core_image_cas_HOLD_v1','error_class':type(error).__name__,
            'guard':str(error)[:160] if isinstance(error,(Hold,C.Hold)) else 'NATIVE_OR_EVIDENCE_FAILURE','possible_send':sent,
            'automatic_retry':False,'actual_api_GET_only_readback_required':sent}))
        raise SystemExit(20) from None


if __name__ == '__main__':
    main()
