#!/usr/bin/env python3
"""INERT G13/R3-to-R4 one-shot Core image maintenance for exact failed unwitnessed A3 create.

No business/provider/Guest operation or cleanup admission. No action on import. Actual release,
Root data/config and G13 acceptance remain independent unbound prerequisites.
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

SOURCE_BOUND = False
CORE_R = None
NEW_DIGEST = None
SOURCE_PIN = None
TOOL_PINS = None
CONFIG_REF = None
SQL_DATA_REF = None
OLD_SOURCE = 'ee8e3377ba91ff3efc3fde3a9751790608ac7066'
OLD_DIGEST = 'b0ee27bd53443260e8e05123f9474454e8108310c4b94a7e72b6bae107cf1ac2'
UID = 'a58ab8c2-da48-46c1-ae62-a650141eeb86'
OLD_POD = '61a21926-d006-4994-80f4-0025d6434d30'
GENERATION = 276
# Exact full container/config identities are fresh Root data, never prefixes.
OLD_CONTAINER_ID = None
OLD_IMAGE_CONFIG_DIGEST = 'sha256:a09e74731d09a41e369677ac50b24cafeee7ad9e1e23bc6573b7ad1474e905b8'
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
M94_MIGRATION_SHA = None
M94_NEW_TRIGGERS = None
M94_FUNCTIONS = ('guard_failed_unwitnessed_expansion_cleanup', 'failed_expansion_absence_read_valid', 'guard_failed_unwitnessed_expansion_cleanup_event', 'guard_failed_unwitnessed_expansion_cleanup_grant', 'guard_failed_unwitnessed_expansion_cleanup_intent', 'immutable_failed_unwitnessed_expansion_cleanup')
# Exact immutable Source metadata; future release/Root binding remains unbound.
M94_FINAL_SQL_SHA256 = '0dc53b56f1a872c05da85be9c65c2ceeb3c8e8a40a7b8f08a62ec96289481b39'
M94_FUNCTION_SPECS = {'guard_failed_unwitnessed_expansion_cleanup': {'arguments': '', 'result': 'trigger', 'language': 'plpgsql', 'volatility': 'v', 'config': None, 'body_sha256': 'b0fe3b600ba0369096fdb300aad09d0d9501b31fb0df1d5edb025ea44c3afe70'}, 'failed_expansion_absence_read_valid': {'arguments': 'r jsonb, a jsonb', 'result': 'boolean', 'language': 'plpgsql', 'volatility': 's', 'config': None, 'body_sha256': '34b97c96e67ba85dcc11d44f023bde718acd2d6d3b5343f7da05420944408890'}, 'guard_failed_unwitnessed_expansion_cleanup_event': {'arguments': '', 'result': 'trigger', 'language': 'plpgsql', 'volatility': 'v', 'config': None, 'body_sha256': '67d8cb0aa8408b9bc06f1b514f11606d17f76079206260c0cc63ad5f3dc7b143'}, 'guard_failed_unwitnessed_expansion_cleanup_grant': {'arguments': '', 'result': 'trigger', 'language': 'plpgsql', 'volatility': 'v', 'config': None, 'body_sha256': 'fb640789db25deeab3a9fbf62e8694456b13a9aeb7e08cd089a301e6dc56a777'}, 'guard_failed_unwitnessed_expansion_cleanup_intent': {'arguments': '', 'result': 'trigger', 'language': 'plpgsql', 'volatility': 'v', 'config': None, 'body_sha256': '318ae28c59482a05f78120d5bc7699725e5871285599b49d7783f2571c599a22'}, 'immutable_failed_unwitnessed_expansion_cleanup': {'arguments': '', 'result': 'trigger', 'language': 'plpgsql', 'volatility': 'v', 'config': None, 'body_sha256': '235d3654a225b91607eba3c84bdbf84be2ace3c8aaf64e65b44cba1e2947d584'}}
M94_INTENT_TRIGGER = 'failed_unwitnessed_expansion_cleanup_intent_guard'
M94_INTENT_TRIGGER_DEFINITION = 'CREATE TRIGGER failed_unwitnessed_expansion_cleanup_intent_guard BEFORE UPDATE ON public.capacity_intents FOR EACH ROW EXECUTE FUNCTION public.guard_failed_unwitnessed_expansion_cleanup_intent()'
DEP_URI = '/apis/apps/v1/namespaces/dakasa/deployments/yggdrasil'
PODS_URI = '/api/v1/namespaces/dakasa/pods?labelSelector=app%3Dyggdrasil'
KUBECONFIG = Path('/etc/rancher/k3s/k3s.yaml')
ROOT = Path('/var/lib/dakasa-core-rollout/g13pair')
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

def g13_acceptance(cut, folder, manifest, returned, run):
    require_bound()
    C = cut.C
    need(set(returned) == {'schema', 'status', 'result', 'automatic_replay', 'Guest_or_Core_business_authority'}
         and returned['schema'] == 'g13_pair_swap_return_v1' and returned['status'] == 'CONFIG_SWAP_OK'
         and returned['automatic_replay'] is False and returned['Guest_or_Core_business_authority'] is False, 'ACTUAL_CLOSED_G13_SWAP_RETURN')
    result = returned['result']
    need(result['source_commit'] == manifest['source_commit'] and result['source_R'] == CORE_R and result['amd64_D'] == C.NEW_DIGEST
         and result['new_guardian_source_sha256'] == SOURCE_PIN and result['controller_config_sha256'] == C.HEAD_CONFIG_SHA
         and result['independent_current15'] is True and result['all_inherited_budget_and_original_refs_unchanged'] is True
         and result['Core_Cold_Hub_or_provider_mutation'] is False
         and all(v == 0 for v in result['conservative_per_role_gap_seconds'].values()), 'QUALIFIED_G13_RETURN_EXACT_P_R_D_AND_NO_ROLE_GAP')
    refs = manifest['protected_refs']
    need(len(refs) == len(required_protected_refs()) and len({r['path'] for r in refs}) == len(refs)
         and {r['path']:r['sha256'] for r in refs} == required_protected_refs(),
         'EXACT_INHERITED41_PLUS_ACTUAL_G9_FULL120_AND_OWN15_REFS')
    backend = cut.Backend(folder, manifest, '', run, {}, [], {})
    backend.files(successor=True)
    protected = backend.protected()
    C.once(run / 'PROTECTED-REFS-BEFORE.json', C.wire(protected))
    need(C.sha(C.read(C.NEW_STANDING, 32768, 0o600)) == result['standing_sha256'], 'EXACT_ACCEPTED_G13_STANDING')
    for key in ('controller', 'guardian'):
        C.identity(result[key])
    ctrl = cut.physical_identity(C.CTRL, cut.controller_argv(C.NEW_CONFIG))
    guard = cut.physical_identity(C.GUARD, cut.guardian_argv(C.NEW_SOURCE, SOURCE_PIN))
    need(ctrl == result['controller'] and guard == result['guardian'], 'SAME_ACCEPTED_G13_CONTROLLER_GUARDIAN')
    G = C.load_guardian(C.NEW_SOURCE, SOURCE_PIN)
    owner = G.Owner(SOURCE_PIN)
    full = owner.identity()
    need({k: full[k] for k in ctrl} == ctrl and owner.original_qualification_measurement(full) is not None, 'RECOMPUTED_ACTUAL_G13_FULL120_SAME_LIFETIME')
    full_path = C.LEDGER / (owner.key(full) + '-QUALIFIED.PUBLIC.json')
    own_path = C.LEDGER / (guard['boot_id'] + '-GUARDIAN-' + guard['InvocationID'] + '-FIRST-CURRENT15-RETURN.PUBLIC.json')
    for field, expected_path in (('actual_new_full120_ref', full_path), ('own_daemon_first_current15_ref', own_path)):
        ref = result[field]
        need(set(ref) == {'path', 'sha256'} and ref['path'] == str(expected_path)
             and C.sha(C.read(expected_path, 16 << 20, 0o600)) == ref['sha256'], 'SAME_G13_ACTUAL_ORIGINAL_QUALIFICATION_REF')
    own = C.loads(C.read(own_path, 16 << 20, 0o600))
    need(own['schema'] == 'Root_owning_finite512_current15_readonly_observation_v1' and own['source_sha256'] == SOURCE_PIN
         and own['standing_config_sha256'] == result['standing_sha256'] and own['identity'] == full
         and own['measurement']['qualified_15_seconds'] is True and own['measurement']['all_requested_rows_accounted_for'] is True
         and own['kernel']['all_four_backends_and_reverse_sources_positive'] is True, 'ACTUAL_G13_DAEMON_OWN15_NOT_ASSESSOR_SUBSTITUTE')
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
         and set(TOOL_PINS) == {'pair_change_contract.py', 'derive_g13pair_controller_config.py', 'derive_standing_config.py', 'g13cut.py'}
         and all(digest_value(v) for v in TOOL_PINS.values())
         and re.fullmatch('containerd://[a-f0-9]{64}', str(OLD_CONTAINER_ID))
         and re.fullmatch('sha256:[a-f0-9]{64}', str(OLD_IMAGE_CONFIG_DIGEST))
         and M94_MIGRATION_SHA == M94_FINAL_SQL_SHA256 and type(M94_NEW_TRIGGERS) is tuple and len(M94_NEW_TRIGGERS)>0
         and len(set(M94_NEW_TRIGGERS))==len(M94_NEW_TRIGGERS)
         and all(type(n) is str and re.fullmatch('[a-z_][a-z0-9_]*',n) for n in M94_NEW_TRIGGERS),
         'G13_RELEASE_AND_FRESH_R3_PREIMAGES_NOT_BOUND')
    for ref in (CONFIG_REF, SQL_DATA_REF):
        need(type(ref) is dict and set(ref) == {'path', 'sha256'} and Path(ref['path']).is_absolute()
             and digest_value(ref['sha256']), 'CLOSED_ROOT_BOUND_INPUT_REF')
    need(SQL_DATA_REF['sha256'] == POLICY92_SQL_SHA, 'EXACT_UNMODIFIED_E70_QUERY_FACTORY')


def load_tools(folder):
    require_bound()
    for name, pin in TOOL_PINS.items():
        need(sha(read(folder / 'tools' / name)) == pin, 'EXACT_REVIEWED_G13_TOOL')
    path = folder / 'tools/g13cut.py'
    module = types.ModuleType('reviewed_g13cut_for_core_cas')
    module.__file__ = str(path)
    exec(compile(read(path), str(path), 'exec'), module.__dict__)
    return module


def core_before(d, ps, C):
    need(C.OLD_DIGEST == OLD_DIGEST and C.OLD_CORE_SOURCE == OLD_SOURCE, 'EXACT_CURRENT_R3_AMD64_SOURCE')
    m, s = d['metadata'], d['status']
    need(d['apiVersion'] == 'apps/v1' and d['kind'] == 'Deployment' and m['namespace'] == 'dakasa'
         and m['name'] == 'yggdrasil' and m['uid'] == UID and m['generation'] == GENERATION
         and m['resourceVersion'].isdecimal() and not m.get('deletionTimestamp')
         and m['annotations']['dakasa.io/core-source-commit'] == OLD_SOURCE, 'EXACT_R3_UID_GENERATION_SOURCE')
    need(d['spec'].get('replicas', 1) == 1 and s['observedGeneration'] == GENERATION
         and all(s.get(k) == 1 for k in ('readyReplicas', 'updatedReplicas', 'availableReplicas'))
         and s.get('unavailableReplicas', 0) == 0
         and [(v['name'], v['image']) for v in d['spec']['template']['spec']['containers']] == [('core', C.IMAGE_PREFIX + OLD_DIGEST)], 'EXACT_READY_SINGLE_R3_CORE')
    need(len(ps['items']) == 1, 'ONE_CURRENT_R3_POD')
    p = ps['items'][0]
    need(p['metadata']['uid'] == OLD_POD and not p['metadata'].get('deletionTimestamp')
         and p['status']['phase'] == 'Running' and len(p['status']['containerStatuses']) == 1
         and [(v['name'], v['image']) for v in p['spec']['containers']] == [('core', C.IMAGE_PREFIX + OLD_DIGEST)], 'EXACT_R3_POD_TUPLE')
    c = p['status']['containerStatuses'][0]
    need(c['name'] == 'core' and c['ready'] is True and c['restartCount'] == 0 and c.get('state', {}).get('running')
         and c['imageID'].rsplit(':', 1)[-1] == OLD_DIGEST and c['containerID'] == OLD_CONTAINER_ID, 'EXACT_R3_IMAGEID_CONTAINER_ZERO_RESTART')
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


















A3_SQL = """SELECT jsonb_build_object(
'observed_at_pg',clock_timestamp(),
'intent_pgtext',(SELECT intent::text FROM public.capacity_intents WHERE namespace='dakasa-production' AND environment='production' AND domain='notify' AND dimension='original_notify_aws_vm_members'),
'run_pgtext',(SELECT to_jsonb(w)::text FROM public.workflow_runs w WHERE id='efad3324-4280-4928-b2e0-becc7eda08a9'),
'dispatch',(SELECT COALESCE(jsonb_agg(to_jsonb(j) ORDER BY j.id),'[]'::jsonb) FROM public.capacity_dispatch_jobs j WHERE run_id='efad3324-4280-4928-b2e0-becc7eda08a9'),
'grant_pgtext',(SELECT to_jsonb(g)::text FROM public.capacity_mutation_grants g WHERE id='c117f03f-27db-4da2-b990-c2729f98a46f'),
'preregistration',(SELECT to_jsonb(p) FROM public.capacity_vm_provisioning_preregistrations p WHERE id='4677b2cf-9cfa-4218-bc3d-930de13591a8'),
'active_policy',(SELECT to_jsonb(m) FROM public.manifests m WHERE id='ab057719-e52e-4549-8490-92766fafd24f'),
'survivors',(SELECT COALESCE(jsonb_agg(to_jsonb(s)||jsonb_build_object('enrollments',(SELECT COALESCE(jsonb_agg(jsonb_build_object('enrollment',to_jsonb(e),'witness',to_jsonb(w),'installation',to_jsonb(i)) ORDER BY e.preregistration_id),'[]'::jsonb) FROM public.capacity_vm_original_enrollments e JOIN public.capacity_vm_provisioning_preregistrations p ON p.id=e.preregistration_id JOIN public.capacity_guest_original_create_witnesses w ON w.preregistration_id=e.preregistration_id JOIN public.capacity_guest_original_installations i ON i.preregistration_id=e.preregistration_id WHERE (p.preregistration_record->>'slot')::integer=s.slot AND e.enrollment_record->'statement'->'tuple'->>'resource_id'=s.resource_id AND e.enrollment_record->'statement'->'tuple'->>'resource_created_at'=s.slot_record->>'resource_created_at')) ORDER BY s.slot),'[]'::jsonb) FROM public.capacity_resource_slots s WHERE namespace='dakasa-production' AND environment='production' AND domain='notify' AND dimension='original_notify_aws_vm_members' AND resource_id<>''),
'target_witnesses',(SELECT COALESCE(jsonb_agg(to_jsonb(x) ORDER BY preregistration_id),'[]'::jsonb) FROM public.capacity_guest_original_create_witnesses x WHERE preregistration_id='4677b2cf-9cfa-4218-bc3d-930de13591a8'),
'target_enrollments',(SELECT COALESCE(jsonb_agg(to_jsonb(x) ORDER BY preregistration_id),'[]'::jsonb) FROM public.capacity_vm_original_enrollments x WHERE preregistration_id='4677b2cf-9cfa-4218-bc3d-930de13591a8'),
'target_installations',(SELECT COALESCE(jsonb_agg(to_jsonb(x) ORDER BY preregistration_id),'[]'::jsonb) FROM public.capacity_guest_original_installations x WHERE preregistration_id='4677b2cf-9cfa-4218-bc3d-930de13591a8'),
'target_retirements',(SELECT COALESCE(jsonb_agg(to_jsonb(x) ORDER BY id),'[]'::jsonb) FROM public.capacity_vm_retirement_intents x WHERE preregistration_id='4677b2cf-9cfa-4218-bc3d-930de13591a8'),
'factory_bindings',(SELECT COALESCE(jsonb_agg(to_jsonb(x) ORDER BY grant_id),'[]'::jsonb) FROM public.capacity_factory_original_grant_bindings x WHERE grant_id='c117f03f-27db-4da2-b990-c2729f98a46f'),
'compensations',(SELECT COALESCE(jsonb_agg(to_jsonb(x) ORDER BY id),'[]'::jsonb) FROM public.capacity_mutation_grants x WHERE grant_record#>>'{grant,compensation_of}'='c117f03f-27db-4da2-b990-c2729f98a46f'),
'cleanup_admissions',(SELECT COALESCE(jsonb_agg(to_jsonb(x) ORDER BY id),'[]'::jsonb) FROM public.capacity_failed_unwitnessed_expansion_cleanups x))"""

def validate_a3(v, c, C):
    need(type(v) is dict and set(v) == {'observed_at_pg','intent_pgtext','run_pgtext','dispatch','grant_pgtext','preregistration','active_policy','survivors','target_witnesses','target_enrollments','target_installations','target_retirements','factory_bindings','compensations','cleanup_admissions'}, 'CLOSED_ACTUAL_A3_SNAPSHOT')
    k = c['case']
    for field, pin in (('intent_pgtext','intent_sha256'),('run_pgtext','run_sha256'),('grant_pgtext','grant_sha256')):
        need(type(v[field]) is str and sha(v[field].encode()) == k[pin], 'WHOLE_ACTUAL_A3_PG_WIRE_' + field)
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
         and all(g[x] is None for x in ('original_disposition_id','failed_original_disposition_id','native_denied_disposition_id','enrolled_failed_disposition_id','failed_unwitnessed_expansion_cleanup_id')), 'EXACT_UNDISPOSED_ORIGINAL_SETTLED_A3_CREATE_NOT_CHILD')
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
    need(p['preregistration_id'] == A3_PRE and p['original_create_grant_id'] == A3_GRANT
         and p['original_create_request_sha256'] == grant['request_sha256'] and p['slot'] == 2
         and p['policy_id'] == A3_POLICY and p['policy_checksum'] == k['policy_checksum']
         and p['workflow_id'] == k['workflow_id'] and p['generation'] == 22 and p['fence'] == 43
         and p['lease_owner'] == k['lease_owner'] and p['executor_id'] == k['executor_id']
         and p['binding_name'] == binding['name']
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


def catalog94_projection(value):
    """Keep the entire immutable six-key93 projection; add only M94 catalog."""
    s = value['schema94']
    need(type(s) is dict and set(s) == {'tables','columns','constraints','indexes','triggers','functions'}
         and all(type(rows) is list for rows in s.values()), 'CLOSED_STABLE_SCHEMA94_CATALOG_ARRAYS')
    return {**catalog_projection(value), 'schema94':s}


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
    need(type(c) is dict and set(c) == {'schema','source_R','amd64_D','core_preimage','case','schema_pins','policy_state','current_preimage_ref','schema94_catalog_ref','prior93_history_ref','legacy_catalog_sql_ref','acceptance_refs'}, 'CLOSED_G13_A3_INPUT')
    need(c['schema'] == 'g13_failed_unwitnessed_A3_image_maintenance_v1' and c['source_R'] == CORE_R == C.SOURCE_R
         and c['amd64_D'] == NEW_DIGEST == C.NEW_DIGEST
         and C.OLD_CORE_UID == UID and C.OLD_CORE_GENERATION == GENERATION and C.OLD_CORE_POD_UID == OLD_POD, 'ONE_QUALIFIED_R4_RELEASE_AND_CURRENT_R3')
    p = c['core_preimage']
    need(type(p) is dict and set(p) == {'deployment_uid','generation','pod_uid','container_id','image_config_digest','spec_sha256','annotations_sha256'}
         and p['deployment_uid'] == UID and p['generation'] == GENERATION and p['pod_uid'] == OLD_POD
         and p['container_id'] == OLD_CONTAINER_ID and p['image_config_digest'] == OLD_IMAGE_CONFIG_DIGEST
         and all(digest_value(p[x]) for x in ('spec_sha256','annotations_sha256')), 'ROOT_FULL_CURRENT_R3_LIFETIME_SPEC_AND_ANNOTATIONS')
    k = c['case']
    need(type(k) is dict and set(k) == {'workflow_id','lease_owner','executor_id','lease_expires_at','policy_checksum','intent_sha256','run_sha256','grant_sha256','preregistration_sha256'}
         and all(full_id(k[x]) for x in ('workflow_id','lease_owner','executor_id'))
         and all(digest_value(k[x]) for x in ('policy_checksum','intent_sha256','run_sha256','grant_sha256','preregistration_sha256'))
         and utc(k['lease_expires_at']), 'ROOT_EXACT_A3_CURRENT_CAS_AND_WHOLE_ORIGINALS')
    need(type(c['acceptance_refs']) is dict and set(c['acceptance_refs']) == {'qualified_business_release','business_Source_CI','Root_Goose94_acceptance','Root_separate_rollout_review'}, 'DISTINCT_RELEASE_CI_GOOSE94_AND_ROLLOUT_EVIDENCE')
    for ref in c['acceptance_refs'].values():
        need(len(input_ref(C,ref)) > 1, 'ACTUAL_ROOT_PINNED_INDEPENDENT_ACCEPTANCE_REF')
    need(type(c['policy_state']) is dict and set(c['policy_state']) == {'aws','hetzner'}
         and all(type(v) is dict and set(v) == {'intent_identity','owned_slots','active_policies','policy_catalog_wire'} for v in c['policy_state'].values()), 'BOTH_EXACT_POLICY_ROSTERS_AND_OWNERS')
    validate_a3(C.loads(input_ref(C,c['current_preimage_ref'])),c,C)
    sql = C.loads(input_ref(C,SQL_DATA_REF))
    need(sql['schema'] == 'fixed_policy_publication_schema92_SQL_data_v1'
         and set(sql['queries']) == {'original_notify_aws_vm_members','original_notify_hetzner_vm_members'}, 'EXACT_UNMODIFIED_E70_EIGHT_TERMINAL_QUERIES')
    return c, raw, sql


def schema94_facts(c, legacy, current, C):
    v = legacy['schema_facts']; pins = c['schema_pins']
    expected_versions = [0]+[n for n in range(1,95) if n != 40]
    need(current['legacy']['database'] == 'yggdrasil' and current['legacy']['readonly'] == 'on'
         and current['legacy']['latest_versions'] == expected_versions
         and v['database'] == 'yggdrasil' and v['readonly'] == 'on' and v['history_max_version'] == 94
         and v['latest_versions'] == expected_versions
         and v['rows90'] == v['rows91'] == v['rows92'] == 1
         and legacy['index89_valid'] is True and legacy['index92_valid'] is True, 'EXACT_SCHEMA94_HEAD_AND_EXISTING_WORKFLOW_INDEXES')
    full = C.loads(v['complete_history_wire']); prior_raw = input_ref(C,c['prior93_history_ref']); prior93 = C.loads(prior_raw)
    need(C.loads(current['legacy']['complete_history_wire']) == full and len(full) == len(prior93)+1
         and prior93 == [r for r in full if r['version_id'] != 94]
         and len([r for r in full if r['version_id'] == 94 and r['is_applied'] is True]) == 1
         and all(r['is_applied'] is True for r in full), 'ONE_ACTUAL94_AND_WHOLE_PRIOR93_HISTORY_PRESERVED')
    need(set(pins) == {'complete_history_sha256','index92_definition_sha256','catalog90_91_sha256','schema94_catalog_sha256'}
         and all(digest_value(p) for p in pins.values())
         and sha(v['complete_history_wire'].encode()) == pins['complete_history_sha256']
         and sha(legacy['index92_definition'].encode()) == pins['index92_definition_sha256']
         and sha(canonical({'catalog90':v['catalog90'],'catalog91':v['catalog91']})) == pins['catalog90_91_sha256']
         and sha(canonical(catalog94_projection(current))) == pins['schema94_catalog_sha256'], 'ROOT_ACCEPTED94_COMPLETE_HISTORY_AND_CATALOG_NO_DRIFT')
    expected = C.loads(input_ref(C,c['schema94_catalog_ref'])); projected = catalog94_projection(current)
    s = projected['schema94']
    need(projected == expected and {r['name'] for r in s['functions']} == set(M94_FUNCTIONS)
         and len(s['functions']) == len(M94_FUNCTIONS) and all(r['definition'] and r['body'] for r in s['functions'])
         and {r['name'] for r in s['tables']} == {'public.capacity_failed_unwitnessed_expansion_cleanups','public.capacity_failed_unwitnessed_expansion_cleanup_events','public.capacity_mutation_grants','public.capacity_intents'}
         and set(M94_NEW_TRIGGERS) <= {r['name'] for r in s['triggers']}
         and all(r['validated'] is True for r in s['constraints'])
         and all(r['valid'] is True and r['ready'] is True and r['live'] is True for r in s['indexes'])
         and all(type(v[k]) is int and v[k] == 0 for k in ('other_migrators_ddl','other_cic','ddl_locks'))
         and all(current['legacy'][k] == 0 for k in ('other_migrators_ddl','other_cic','ddl_locks')), 'EXACT_ROOT_GOOSE94_SCHEMA_AND_NO_CONCURRENT_DDL')
    # Function Source is known now; its future image/Root receipt is not.
    # PostgreSQL preserves prosrc literally, while pg_get_functiondef is also
    # retained and independently Root-pinned in the complete catalog.
    for row in s['functions']:
        spec = M94_FUNCTION_SPECS[row['name']]
        need(row['qualified_name'] == 'public.'+row['name']
             and all(row[k] == spec[k] for k in ('arguments','result','language','volatility','config'))
             and type(row['body']) is str and sha(row['body'].encode()) == spec['body_sha256'],
             'EXACT_FINAL_M94_SIX_FUNCTION_HEADERS_AND_LITERAL_BODIES')
    intent = [r for r in s['triggers'] if r['table'] == 'public.capacity_intents' and r['name'] == M94_INTENT_TRIGGER]
    need(len(intent) == 1 and intent[0]['enabled'] == 'O'
         and intent[0]['function'] in ('guard_failed_unwitnessed_expansion_cleanup_intent()', 'public.guard_failed_unwitnessed_expansion_cleanup_intent()')
         and intent[0]['definition'] in (M94_INTENT_TRIGGER_DEFINITION, M94_INTENT_TRIGGER_DEFINITION.replace('FUNCTION public.','FUNCTION ')),
         'ONLY_SOURCE_DECLARED_NEW_INTENT_TRIGGER_WITH_FULL_OLD_INTENT_CATALOG_PINNED')
    root94 = C.loads(input_ref(C,c['acceptance_refs']['Root_Goose94_acceptance']))
    need(type(root94) is dict and set(root94) == {'schema','reviewed_by_root','schema_before','schema_after','current_core_source','current_ops_source','business_source','amd64_D','migration94_sha256','complete_history_sha256','prior93_history_sha256','catalog94_sha256','index92_definition_sha256','catalog90_91_sha256','job_uid','pod_uid','exit_code','single_job_create','provider_guest_core_mutations','old_records_and_sdk_preserved','original_refs'}
         and root94['schema'] == 'root_goose94_failed_unwitnessed_expansion_cleanup_acceptance_v1'
         and root94['reviewed_by_root'] is True and root94['schema_before'] == 93 and root94['schema_after'] == 94
         and root94['current_core_source'] == OLD_SOURCE
         and root94['current_ops_source'] == '3e617cc176026cd70ee885ede753fbc6f6dd17a6'
         and root94['business_source'] == CORE_R and root94['amd64_D'] == NEW_DIGEST
         and root94['migration94_sha256'] == M94_MIGRATION_SHA
         and root94['complete_history_sha256'] == pins['complete_history_sha256']
         and root94['prior93_history_sha256'] == sha(prior_raw)
         and root94['catalog94_sha256'] == pins['schema94_catalog_sha256']
         and root94['index92_definition_sha256'] == pins['index92_definition_sha256']
         and root94['catalog90_91_sha256'] == pins['catalog90_91_sha256']
         and full_id(root94['job_uid']) and full_id(root94['pod_uid'])
         and type(root94['exit_code']) is int and root94['exit_code'] == 0 and root94['single_job_create'] is True
         and type(root94['provider_guest_core_mutations']) is int and root94['provider_guest_core_mutations'] == 0
         and root94['old_records_and_sdk_preserved'] is True
         and type(root94['original_refs']) is dict
         and set(root94['original_refs']) == {'migration_result','before_catalog','after_catalog','source_ci','qualified_image'}, 'GENUINE_ROOT94_RECEIPT_EXACT_RELEASE_HISTORY_AND_CATALOG')
    for ref in root94['original_refs'].values():
        need(len(input_ref(C,ref)) > 1, 'GENUINE_ROOT94_ORIGINAL_FIVE_ROLE_CUSTODY')


def database_a3(cut, run, c, sql, phase):
    require_bound()
    need(phase in ('BEFORE','PRESEND'), 'ONLY_PREPATCH_A3_FROZEN_PHASES')
    C = cut.C
    need(c['legacy_catalog_sql_ref']['sha256'] == LEGACY_CATALOG_SHA,'EXACT_SHARED_C9_CATALOG_SOURCE')
    legacy_sql = input_ref(C,c['legacy_catalog_sql_ref']).decode()
    current = query(cut,run,phase+'-SCHEMA94',catalog94_select(legacy_sql))
    for provider,key in (('aws','original_notify_aws_vm_members'),('hetzner','original_notify_hetzner_vm_members')):
        v = query(cut,run,phase+'-'+provider,sql['queries'][key])
        schema94_facts(c,v,current,C)
        need(v['intent_count'] == 1 and all(type(v[k]) is int and v[k] == 0 for k in ('jobs_busy','runs_busy','forward_unreturned_reads','live_unreturned_canaries')), 'BOTH_PROVIDERS_NO_BUSY_JOBS_RUNS_OR_UNRETURNED_PROOF')
        need(tuple(v[k] for k in ('intent_busy','pending_authority','forward_markers')) == ((1,1,0) if provider == 'aws' else (0,0,0)), 'ONLY_KNOWN_A3_CREATE_AND_EXPIRED_INTENT_NO_RETIREMENT')
        need({k:v[k] for k in ('intent_identity','owned_slots','active_policies','policy_catalog_wire')} == c['policy_state'][provider], 'ALL_OTHER_POLICY_AND_ROSTER_BYTES_EXACT')
    actual = query(cut,run,phase+'-A3',A3_SQL); expected = C.loads(input_ref(C,c['current_preimage_ref']))
    need({k:v for k,v in actual.items() if k != 'observed_at_pg'} == {k:v for k,v in expected.items() if k != 'observed_at_pg'}, 'WHOLE_A3_PREIMAGE_UNCHANGED_NO_REBASE')
    need(0 <= (datetime.datetime.now(datetime.timezone.utc)-utc(actual['observed_at_pg'])).total_seconds() <= 15, 'FRESH_A3_DB_READ')
    validate_a3(actual,c,C)


def global_marker(C):
    return ROOT / ('CORE-IMAGE-EE8E-B0EE27-TO-'+CORE_R+'-'+C.NEW_DIGEST+'-POSSIBLE.json')


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
    p.add_argument('--g13-swap-return',required=True,type=Path)
    p.add_argument('--expected-g13-swap-return-sha256',required=True)
    p.add_argument('--evidence-dir',required=True,type=Path)
    p.add_argument('--execute-core-image-cas-once',action='store_true',required=True)
    a = p.parse_args()
    need(os.geteuid() == 0 and sys.platform == 'linux','ROOT_LINUX_BRAIN_ONLY')
    folder = a.package.absolute(); cut = load_tools(folder); C = cut.C
    c, original_config, sql = maintenance_inputs(C)
    folder, manifest = C.package(folder,a.expected_manifest_sha256)
    need(manifest['source_commit'] == a.expected_ops_source and re.fullmatch('[a-f0-9]{40}',a.expected_ops_source)
         and manifest['files']['source/network_guardian.py'] == SOURCE_PIN and manifest['tools'] == TOOL_PINS,'EXACT_SEPARATELY_QUALIFIED_G13_OPERATIONAL_SOURCE')
    returned_path = a.g13_swap_return.absolute()
    need(returned_path.name == 'RETURN.json' and returned_path.parent.parent == ROOT and returned_path.parent.name.startswith('swap-once-'),'EXACT_ACTUAL_G13_RETURN_PATH')
    C.private_dir(returned_path.parent); returned_raw = C.read(returned_path,32<<20,0o600)
    need(sha(returned_raw) == a.expected_g13_swap_return_sha256 and digest_value(a.expected_g13_swap_return_sha256)
         and not (returned_path.parent/'HOLD.json').exists(),'EXACT_ACTUAL_G13_SUCCESS_RETURN_NOT_HOLD')
    swap_claim = C.loads(C.read(ROOT/('SWAP-'+a.expected_manifest_sha256+'-POSSIBLE.json'),32768,0o600))
    need(set(swap_claim) == {'schema','manifest_sha256','old_controller','old_guardian','run','automatic_replay'}
         and swap_claim['schema'] == 'g13_once_only_swap_claim_v1' and swap_claim['manifest_sha256'] == a.expected_manifest_sha256
         and swap_claim['old_controller'] == manifest['expected_controller_identity'] and swap_claim['old_guardian'] == manifest['expected_guardian_identity']
         and swap_claim['run'] == str(returned_path.parent) and swap_claim['automatic_replay'] is False,'G13_ACTUAL_ONCE_CLAIM_BINDS_MANIFEST_AND_RETURN')
    run = a.evidence_dir.absolute()
    need(run.parent == ROOT and re.fullmatch('core-image-cas-[A-Za-z0-9_-]{1,96}',run.name),'CLOSED_NEW_CAS_EVIDENCE_DIRECTORY')
    C.private_dir(ROOT); C.private_dir(run,create=True)
    sent = False
    def interrupted(signum,_): raise Hold('SIGNAL_'+str(signum)+'_RECONCILE_NO_REPLAY')
    for sig in (signal.SIGTERM,signal.SIGINT,signal.SIGHUP,signal.SIGALRM): signal.signal(sig,interrupted)
    signal.alarm(120)
    try:
        with operation_lock() as inode:
            need(not global_marker(C).exists(),'NEW_R3_TO_R4_GLOBAL_ONCE_ALREADY_CLAIMED')
            C.once(run/'MAINTENANCE-INPUT.original.json',original_config)
            api = API(cut)
            before = api_read(api,C,run,'DEPLOYMENT-BEFORE',DEP_URI)
            pods = api_read(api,C,run,'PODS-BEFORE',PODS_URI); old_tuple = core_before(before,pods,C)
            need(sha(C.wire(before['spec'])) == c['core_preimage']['spec_sha256'] and sha(C.wire(before['metadata']['annotations'])) == c['core_preimage']['annotations_sha256'],'EXACT_ROOT_FULL_R3_PREIMAGE')
            lineage = C.loads(C.read(returned_path.parent/'BEFORE.json',32<<20,0o600))
            need(lineage['core'] == old_tuple and lineage['controller'] == manifest['expected_controller_identity']
                 and lineage['guardian'] == manifest['expected_guardian_identity'] and lineage['protected_refs'] == required_protected_refs(),'SAME_G13_PREDECESSOR_CORE_AND_PROTECTED_ORIGINALS')
            wire = C.wire(build_patch(before,C)); C.once(run/'PATCH.json',wire)
            status, raw, headers = api.request('PATCH',DEP_URI+'?dryRun=All&fieldManager=core-image-cas-once',wire)
            C.once(run/'SERVER-DRYRUN.json',raw); C.once(run/'SERVER-DRYRUN.HTTP.json',C.wire({'status':status,**headers}))
            need(status == 200,'SERVER_DRYRUN_200'); result_shape(before,C.loads(raw),C)
            database_a3(cut,run,c,sql,'BEFORE')
            backend, protected, ctrl, guard, observed = g13_acceptance(cut,folder,manifest,C.loads(returned_raw),run)
            need(protected == lineage['protected_refs'],'SAME43_ORIGINALS_AND_ONE_OF_THREE_BUDGET')
            fresh = api_read(api,C,run,'DEPLOYMENT-FRESH-PRESEND',DEP_URI)
            fresh_pods = api_read(api,C,run,'PODS-FRESH-PRESEND',PODS_URI)
            need(core_before(fresh,fresh_pods,C) == old_tuple and fresh['metadata']['resourceVersion'] == before['metadata']['resourceVersion']
                 and fresh['spec'] == before['spec'] and fresh['metadata']['annotations'] == before['metadata']['annotations'],'UNCHANGED_FULL_API_PREIMAGE_NO_REBASE')
            backend.files(successor=True)
            need(backend.protected() == protected and cut.physical_identity(C.CTRL,cut.controller_argv(C.NEW_CONFIG)) == ctrl
                 and cut.physical_identity(C.GUARD,cut.guardian_argv(C.NEW_SOURCE,SOURCE_PIN)) == guard,'SAME_ACCEPTED_G13_LIFETIMES_IMMEDIATELY_BEFORE_PATCH')
            database_a3(cut,run,c,sql,'PRESEND')
            current_lock = OPLOCK.lstat()
            need((current_lock.st_dev,current_lock.st_ino) == inode and time.monotonic()-observed <= 15,'SAME_MUTEX_AND_FRESH_CURRENT15')
            marker = {'schema':'g13_R3_to_R4_core_image_possible_send_v1','at':now(),'method':'PATCH','uri':DEP_URI,
                'deployment_uid':UID,'generation':GENERATION,'resourceVersion':before['metadata']['resourceVersion'],
                'patch_sha256':sha(wire),'script_sha256':sha(read(__file__)),'manifest_sha256':a.expected_manifest_sha256,
                'G13_return_sha256':a.expected_g13_swap_return_sha256,'evidence_dir':str(run),'automatic_retry':False,
                'effects_may_have_happened_after_this_marker':True}
            sent = True; after = patch_once(api,C,run,wire,marker,observed); result_shape(before,after,C)
            # Image ACK is not cleanup admission or runtime readiness. The explicit
            # separately accepted cleanup and post-rollout observations follow.
            result = {'schema':'g13_core_image_cas_return_v1','status':'PATCH_ACKNOWLEDGED_ACCEPTANCE_PENDING',
                'deployment_uid':UID,'generation':after['metadata']['generation'],'resourceVersion':after['metadata']['resourceVersion'],
                'old_pod_uid':OLD_POD,'Core_source':CORE_R,'image':C.IMAGE_PREFIX+C.NEW_DIGEST,'manifest_sha256':a.expected_manifest_sha256,
                'G13_return_sha256':a.expected_g13_swap_return_sha256,'patch_sha256':sha(wire),'automatic_retry':False,
                'new_pod_readiness_proven':False,'post_rollout_G13_and_E2E_acceptance_proven':False,'evidence_dir':str(run)}
            C.once(run/'RETURN.PUBLIC.json',C.wire(result))
        signal.alarm(0); print(C.wire(result).decode(),end='',flush=True)
    except Exception as error:
        signal.alarm(0)
        C.once(run/'HOLD.PUBLIC.json',C.wire({'schema':'g13_core_image_cas_HOLD_v1','error_class':type(error).__name__,
            'guard':str(error)[:160] if isinstance(error,(Hold,C.Hold)) else 'NATIVE_OR_EVIDENCE_FAILURE','possible_send':sent,
            'automatic_retry':False,'actual_api_GET_only_readback_required':sent}))
        raise SystemExit(20) from None


if __name__ == '__main__':
    main()
