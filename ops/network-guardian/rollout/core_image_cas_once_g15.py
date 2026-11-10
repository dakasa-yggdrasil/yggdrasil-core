#!/usr/bin/env python3
"""INERT G15/Core5-to-Core6 one-shot image maintenance for the exact S8 zero-own-read case.

No direct business/provider/Guest operation. Core6 may resume the already-admitted
read-only retirement after rollout. Actual release, Root data/config and normal
G15 acceptance remain independent unbound prerequisites. No action on import.
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
G15_OPS_P = None
REPAIR_HELPER_SHA256 = None
M95_MIGRATION_SHA = '50f2f1f712a91abf3ccd17d0fb2040d30b4bd2c6455268902e1452e922a94808'
M95_EVENT_BODY_SHA = '8830bda75d61322a993c0f5572268ed912e8816aab69abdfae4ccb264194a351'
CLEANUP_ID = '838331bb-fb7b-4ea3-9e67-3ffd3f539402'
CHILD_ID = 'e0059c6d-4773-4232-b047-f7561601f613'
CLEANUP_RUN = '6c23f323-f607-4015-9564-f676e8bc5d9d'
CHILD_COLUMN = 'failed_unwitnessed_expansion_cleanup_id'
SQL_DATA_REF = None
OLD_SOURCE = '33a846d31a5b123b2c1141192671bc830bf6d9c8'
OLD_DIGEST = '35195e4ddff2a69f2ae7fca8f24b43177c61c49f12117a4fe4925a43e9cd6fde'
UID = None
OLD_POD = None
GENERATION = None
# Exact full container/config identities are fresh Root data, never prefixes.
OLD_CONTAINER_ID = None
OLD_IMAGE_CONFIG_DIGEST = None
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
M94_MIGRATION_SHA = '2850db98eddbfd629b98df879eb61266036d70210118e8e20289782d2b37a78c'
M94_NEW_TRIGGERS = ('failed_unwitnessed_expansion_cleanup_event_guard', 'failed_unwitnessed_expansion_cleanup_grant_guard', 'failed_unwitnessed_expansion_cleanup_intent_guard', 'failed_unwitnessed_expansion_cleanup_admission', 'failed_unwitnessed_expansion_cleanup_immutable', 'failed_unwitnessed_expansion_cleanup_event_immutable')
M94_FUNCTIONS = ('guard_failed_unwitnessed_expansion_cleanup', 'failed_expansion_absence_read_valid', 'guard_failed_unwitnessed_expansion_cleanup_event', 'guard_failed_unwitnessed_expansion_cleanup_grant', 'guard_failed_unwitnessed_expansion_cleanup_intent', 'immutable_failed_unwitnessed_expansion_cleanup')
# Exact immutable Source metadata; future release/Root binding remains unbound.
M94_FINAL_SQL_SHA256 = '2850db98eddbfd629b98df879eb61266036d70210118e8e20289782d2b37a78c'
M94_FUNCTION_SPECS = {'guard_failed_unwitnessed_expansion_cleanup': {'arguments': '', 'result': 'trigger', 'language': 'plpgsql', 'volatility': 'v', 'config': None, 'body_sha256': 'b0fe3b600ba0369096fdb300aad09d0d9501b31fb0df1d5edb025ea44c3afe70'}, 'failed_expansion_absence_read_valid': {'arguments': 'r jsonb, a jsonb', 'result': 'boolean', 'language': 'plpgsql', 'volatility': 's', 'config': None, 'body_sha256': '34b97c96e67ba85dcc11d44f023bde718acd2d6d3b5343f7da05420944408890'}, 'guard_failed_unwitnessed_expansion_cleanup_event': {'arguments': '', 'result': 'trigger', 'language': 'plpgsql', 'volatility': 'v', 'config': None, 'body_sha256': '1a3da0cedfb6f77bbec3fd2f64195768ba72c0f4d321cd6a24007315d3b82b92'}, 'guard_failed_unwitnessed_expansion_cleanup_grant': {'arguments': '', 'result': 'trigger', 'language': 'plpgsql', 'volatility': 'v', 'config': None, 'body_sha256': 'fb640789db25deeab3a9fbf62e8694456b13a9aeb7e08cd089a301e6dc56a777'}, 'guard_failed_unwitnessed_expansion_cleanup_intent': {'arguments': '', 'result': 'trigger', 'language': 'plpgsql', 'volatility': 'v', 'config': None, 'body_sha256': '318ae28c59482a05f78120d5bc7699725e5871285599b49d7783f2571c599a22'}, 'immutable_failed_unwitnessed_expansion_cleanup': {'arguments': '', 'result': 'trigger', 'language': 'plpgsql', 'volatility': 'v', 'config': None, 'body_sha256': '235d3654a225b91607eba3c84bdbf84be2ace3c8aaf64e65b44cba1e2947d584'}}
M94_INTENT_TRIGGER = 'failed_unwitnessed_expansion_cleanup_intent_guard'
M94_INTENT_TRIGGER_DEFINITION = 'CREATE TRIGGER failed_unwitnessed_expansion_cleanup_intent_guard BEFORE UPDATE ON public.capacity_intents FOR EACH ROW EXECUTE FUNCTION public.guard_failed_unwitnessed_expansion_cleanup_intent()'
DEP_URI = '/apis/apps/v1/namespaces/dakasa/deployments/yggdrasil'
PODS_URI = '/api/v1/namespaces/dakasa/pods?labelSelector=app%3Dyggdrasil'
KUBECONFIG = Path('/etc/rancher/k3s/k3s.yaml')
ROOT = Path('/var/lib/dakasa-core-rollout/g15pair')
OPLOCK = ROOT/'CORE-IMAGE-CAS.LOCK'
POLICY92_SQL_SHA = 'fa519e39989b31a7faa3c23358506992b057d6bf17ce2aad709dfe6fecd5c2c8'
CAP = 16 << 20
CHANGE_CAUSE = 'Root one Core5 to qualified Core6 CAS; exact schema96 typed pre-read continuation, no provider replay'

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

def closed_g15_return_path(path, state):
    # Lexical normal-G15 namespace check precedes directory and file access.
    need(path.name == 'RETURN.json' and path.parent.parent == ROOT == state
         and path.parent.name.startswith('swap-once-'),
         'CLOSED_G15_NORMAL_RETURN_NAMESPACE_BEFORE_IO')


def accepted_guardian(cut,returned):
    require_bound()
    C=cut.C;actual=cut.physical_identity(C.GUARD,cut.guardian_argv(C.NEW_SOURCE,SOURCE_PIN))
    need(actual==returned['result']['guardian'],'SAME_ACTUAL_G15_GUARDIAN_LIFETIME');return actual


def g15_acceptance(cut, folder, manifest, returned, run):
    require_bound()
    C = cut.C
    need(set(returned)=={'schema','status','result','automatic_replay','Guest_or_Core_business_authority'}and returned['schema']=='g15_pair_swap_return_v1'and returned['status']=='CONFIG_SWAP_OK'and returned['automatic_replay']is False and returned['Guest_or_Core_business_authority']is False,'ACTUAL_CLOSED_G15_SWAP_RETURN')
    result = returned['result']
    need(result['source_commit'] == manifest['source_commit'] and result['source_R'] == CORE_R and result['amd64_D'] == C.NEW_DIGEST
         and result['new_guardian_source_sha256'] == SOURCE_PIN and result['controller_config_sha256'] == C.HEAD_CONFIG_SHA
         and result['independent_current15'] is True and result['all_inherited_budget_and_original_refs_unchanged'] is True
         and result['Core_Cold_Hub_or_provider_mutation'] is False
         and all(v == 0 for v in result['conservative_per_role_gap_seconds'].values()), 'QUALIFIED_G15_RETURN_EXACT_P_R_D_AND_NO_ROLE_GAP')
    refs = manifest['protected_refs']
    need(len(refs) == len(required_protected_refs()) and len({r['path'] for r in refs}) == len(refs)
         and {r['path']:r['sha256'] for r in refs} == required_protected_refs(),
         'EXACT_INHERITED41_PLUS_ACTUAL_G9_FULL120_AND_OWN15_REFS')
    backend = cut.Backend(folder, manifest, '', run, {}, [], {})
    backend.files(successor=True)
    protected = backend.protected()
    C.once(run / 'PROTECTED-REFS-BEFORE.json', C.wire(protected))
    need(C.sha(C.read(C.NEW_STANDING, 32768, 0o600)) == result['standing_sha256'], 'EXACT_ACCEPTED_G15_STANDING')
    for key in ('controller', 'guardian'):
        C.identity(result[key])
    ctrl = cut.physical_identity(C.CTRL, cut.controller_argv(C.NEW_CONFIG))
    guard = accepted_guardian(cut, returned)
    need(ctrl == result['controller'] and guard == result['guardian'], 'SAME_ACCEPTED_G15_CONTROLLER_GUARDIAN')
    G = C.load_guardian(C.NEW_SOURCE, SOURCE_PIN)
    owner = G.Owner(SOURCE_PIN)
    full = owner.identity()
    need({k: full[k] for k in ctrl} == ctrl and owner.original_qualification_measurement(full) is not None, 'RECOMPUTED_ACTUAL_G15_FULL120_SAME_LIFETIME')
    full_path = C.LEDGER / (owner.key(full) + '-QUALIFIED.PUBLIC.json')
    own_path = C.LEDGER / (guard['boot_id'] + '-GUARDIAN-' + guard['InvocationID'] + '-FIRST-CURRENT15-RETURN.PUBLIC.json')
    for field, expected_path in (('actual_new_full120_ref', full_path), ('own_daemon_first_current15_ref', own_path)):
        ref = result[field]
        need(set(ref) == {'path', 'sha256'} and ref['path'] == str(expected_path)
             and C.sha(C.read(expected_path, 16 << 20, 0o600)) == ref['sha256'], 'SAME_G15_ACTUAL_ORIGINAL_QUALIFICATION_REF')
    own = C.loads(C.read(own_path, 16 << 20, 0o600))
    need(own['schema'] == 'Root_owning_finite512_current15_readonly_observation_v1' and own['source_sha256'] == SOURCE_PIN
         and own['standing_config_sha256'] == result['standing_sha256'] and own['identity'] == full
         and own['measurement']['qualified_15_seconds'] is True and own['measurement']['all_requested_rows_accounted_for'] is True
         and own['kernel']['all_four_backends_and_reverse_sources_positive'] is True, 'ACTUAL_G15_DAEMON_OWN15_NOT_ASSESSOR_SUBSTITUTE')
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

def require_source_bound():
    need(SOURCE_BOUND is True and full_id(UID) and full_id(OLD_POD)
         and source(G15_OPS_P) and re.fullmatch('[a-f0-9]{40}', str(CORE_R)) and CORE_R != OLD_SOURCE
         and digest_value(NEW_DIGEST) and NEW_DIGEST != OLD_DIGEST
         and digest_value(SOURCE_PIN) and type(TOOL_PINS) is dict
         and set(TOOL_PINS) == {'pair_change_contract.py', 'derive_g15pair_controller_config.py', 'derive_standing_config.py', 'g15cut.py'}
         and all(digest_value(v) for v in TOOL_PINS.values())
         and re.fullmatch('containerd://[a-f0-9]{64}', str(OLD_CONTAINER_ID))
         and re.fullmatch('sha256:[a-f0-9]{64}', str(OLD_IMAGE_CONFIG_DIGEST))
         and M94_MIGRATION_SHA == M94_FINAL_SQL_SHA256 and type(M94_NEW_TRIGGERS) is tuple and len(M94_NEW_TRIGGERS)>0
         and len(set(M94_NEW_TRIGGERS))==len(M94_NEW_TRIGGERS)
         and all(type(n) is str and re.fullmatch('[a-z_][a-z0-9_]*',n) for n in M94_NEW_TRIGGERS),
         'G15_RELEASE_AND_FRESH_R5_PREIMAGES_NOT_BOUND')
    ref = SQL_DATA_REF
    need(type(ref) is dict and set(ref) == {'path', 'sha256'} and Path(ref['path']).is_absolute()
         and digest_value(ref['sha256']), 'CLOSED_ROOT_BOUND_INPUT_REF')
    need(SQL_DATA_REF['sha256'] == POLICY92_SQL_SHA, 'EXACT_UNMODIFIED_E70_QUERY_FACTORY')


def validated_config_ref(path, expected_sha256):
    # Lexical validation only: no resolve/stat/read, credential or native access.
    need(type(path) is str and path != '/' and '\x00' not in path
         and Path(path).is_absolute() and not path.startswith('//')
         and str(Path(path)) == path and '..' not in Path(path).parts
         and digest_value(expected_sha256), 'CLOSED_ROOT_RUNTIME_CONFIG_REF')
    return {'path': path, 'sha256': expected_sha256}


def require_bound():
    require_source_bound()
    need(type(CONFIG_REF) is dict and set(CONFIG_REF) == {'path', 'sha256'}, 'CLOSED_ROOT_BOUND_INPUT_REF')
    validated_config_ref(CONFIG_REF['path'], CONFIG_REF['sha256'])


def load_tools(folder):
    require_bound()
    for name, pin in TOOL_PINS.items():
        need(sha(read(folder / 'tools' / name)) == pin, 'EXACT_REVIEWED_G14_TOOL')
    path = folder / 'tools/g15cut.py'
    module = types.ModuleType('reviewed_g14cut_for_core_cas')
    module.__file__ = str(path)
    exec(compile(read(path), str(path), 'exec'), module.__dict__)
    return module


def core_before(d, ps, C):
    need(C.OLD_DIGEST == OLD_DIGEST and C.OLD_CORE_SOURCE == OLD_SOURCE, 'EXACT_CURRENT_R5_AMD64_SOURCE')
    m, s = d['metadata'], d['status']
    need(d['apiVersion'] == 'apps/v1' and d['kind'] == 'Deployment' and m['namespace'] == 'dakasa'
         and m['name'] == 'yggdrasil' and m['uid'] == UID and m['generation'] == GENERATION
         and m['resourceVersion'].isdecimal() and not m.get('deletionTimestamp')
         and m['annotations']['dakasa.io/core-source-commit'] == OLD_SOURCE, 'EXACT_R5_UID_GENERATION_SOURCE')
    need(d['spec'].get('replicas', 1) == 1 and s['observedGeneration'] == GENERATION
         and all(s.get(k) == 1 for k in ('readyReplicas', 'updatedReplicas', 'availableReplicas'))
         and s.get('unavailableReplicas', 0) == 0
         and [(v['name'], v['image']) for v in d['spec']['template']['spec']['containers']] == [('core', C.IMAGE_PREFIX + OLD_DIGEST)], 'EXACT_READY_SINGLE_R5_CORE')
    need(len(ps['items']) == 1, 'ONE_CURRENT_R5_POD')
    p = ps['items'][0]
    need(p['metadata']['uid'] == OLD_POD and not p['metadata'].get('deletionTimestamp')
         and p['status']['phase'] == 'Running' and len(p['status']['containerStatuses']) == 1
         and [(v['name'], v['image']) for v in p['spec']['containers']] == [('core', C.IMAGE_PREFIX + OLD_DIGEST)], 'EXACT_R5_POD_TUPLE')
    c = p['status']['containerStatuses'][0]
    need(c['name'] == 'core' and c['ready'] is True and c['restartCount'] == 0 and c.get('state', {}).get('running')
         and c['imageID'].rsplit(':', 1)[-1] == OLD_DIGEST and c['containerID'] == OLD_CONTAINER_ID, 'EXACT_R5_IMAGEID_CONTAINER_ZERO_RESTART')
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
    require_bound();raw=input_ref(C,CONFIG_REF);c=loads(raw)
    closed(c,'schema source_R amd64_D core_preimage pre_read_case schema_pins policy_state pre_read_preimage_ref schema94_catalog_ref schema95_catalog_ref prior93_history_ref prior94_history_ref legacy_catalog_sql_ref acceptance_refs schema96_catalog_ref prior95_history_ref','CLOSED16_PRE_READ96_MAINTENANCE')
    need(c['schema']=='g15_pre_read_continuation_image_maintenance_v1'and c['source_R']==CORE_R==C.SOURCE_R and c['amd64_D']==NEW_DIGEST==C.NEW_DIGEST and C.OLD_CORE_UID==UID and C.OLD_CORE_GENERATION==GENERATION and C.OLD_CORE_POD_UID==OLD_POD,'QUALIFIED_R6_AND_CURRENT_R5_PREIMAGE')
    p=c['core_preimage'];closed(p,'deployment_uid generation pod_uid container_id image_config_digest spec_sha256 annotations_sha256','CLOSED_CURRENT5_LIFETIME')
    need(p['deployment_uid']==UID and p['generation']==GENERATION and p['pod_uid']==OLD_POD and p['container_id']==OLD_CONTAINER_ID and p['image_config_digest']==OLD_IMAGE_CONFIG_DIGEST and all(digest_value(p[k])for k in ('spec_sha256','annotations_sha256')),'EXACT_ROOT_CURRENT5_WHOLE_SPEC_AND_ANNOTATIONS')
    closed(c['acceptance_refs'],'qualified_business_release business_Source_CI Root_Goose94_acceptance Root_Goose95_acceptance Root_Goose96_acceptance Root_separate_rollout_review','DISTINCT_ROOT_RELEASE_CI_94_95_96_AND_ROLLOUT')
    for r in c['acceptance_refs'].values():need(len(input_ref(C,r))>1,'ACTUAL_COMPLETE_PINNED_ACCEPTANCE_ORIGINAL')
    need(type(c['policy_state'])is dict and set(c['policy_state'])=={'aws','hetzner'}and all(type(v)is dict and set(v)=={'intent_identity','owned_slots','active_policies','policy_catalog_wire'}for v in c['policy_state'].values()),'BOTH_WHOLE_POLICY_ROSTERS_UNCHANGED')
    validate_pre_read96(loads(input_ref(C,c['pre_read_preimage_ref'])),c['pre_read_case'])
    sql=loads(input_ref(C,SQL_DATA_REF));need(sql['schema']=='fixed_policy_publication_schema92_SQL_data_v1'and set(sql['queries'])=={'original_notify_aws_vm_members','original_notify_hetzner_vm_members'},'EXACT_SOURCE_E70_QUERIES_WITHOUT_RECONSTRUCTION');return c,raw,sql


def schema96_facts(c, legacy, current, C):
    v,pins=legacy['schema_facts'],c['schema_pins'];versions=[0]+[x for x in range(1,97)if x!=40]
    need(current['legacy']['database']==v['database']=='yggdrasil'and current['legacy']['readonly']==v['readonly']=='on'and current['legacy']['latest_versions']==v['latest_versions']==versions and v['history_max_version']==96 and v['rows90']==v['rows91']==v['rows92']==1 and legacy['index89_valid']is True and legacy['index92_valid']is True,'EXACT96_HEAD_OLD_INDEXES_NO_SCHEMA_ALIAS')
    closed(pins,'complete_history_sha256 index92_definition_sha256 catalog90_91_sha256 schema94_catalog_sha256 schema95_catalog_sha256 schema96_catalog_sha256 constraint96_deparse_ref','CLOSED96_CATALOG_HISTORY_PINS')
    need(all(digest_value(pins[k])for k in pins if k!='constraint96_deparse_ref'),'REAL96_DIGEST_PINS')
    prior_raw=input_ref(C,c['prior95_history_ref']);prior=loads(prior_raw);full=loads(v['complete_history_wire'])
    need(loads(current['legacy']['complete_history_wire'])==full and len(full)==len(prior)+1 and [x for x in full if x['version_id']!=96]==prior and len([x for x in full if x['version_id']==96 and x['is_applied']is True])==1 and all(x['is_applied']is True for x in full)and sha(v['complete_history_wire'].encode())==pins['complete_history_sha256'],'SOLE96_WHOLE_PRIOR95_RAW_VALUES_PRESERVED')
    prior_catalog=loads(input_ref(C,c['schema95_catalog_ref']));actual=catalog94_projection(current);expected=loads(input_ref(C,c['schema96_catalog_ref']))
    need(actual==expected and sha(C.wire(actual))==pins['schema96_catalog_sha256']and sha(C.wire(prior_catalog))==pins['schema95_catalog_sha256']and sha(legacy['index92_definition'].encode())==pins['index92_definition_sha256']and sha(C.wire({'catalog90':v['catalog90'],'catalog91':v['catalog91']}))==pins['catalog90_91_sha256'],'ROOT96_EXACT_SEVEN_KEY_CATALOG_AND_CURRENT90_91_HASH')
    row=[x for x in actual['functions93']if x['name']==M96_FUNCTION];need(len(row)==1 and sha(row[0]['body'].encode())==M96_BODY_SHA,'EXACT_SOURCE96_PROSRC')
    catalog96_delta(prior_catalog,actual,row[0]['body'],constraint96_definition(prior_catalog,loads(input_ref(C,pins['constraint96_deparse_ref']))))
    need(all(v[k]==0 and current['legacy'][k]==0 for k in ('other_migrators_ddl','other_cic','ddl_locks')),'NO_OTHER_MIGRATOR_CIC_OR_DDL_LOCK')
    previous_ref=c['acceptance_refs']['Root_Goose95_acceptance'];need(previous_ref['sha256']==ROOT95_SHA,'IMMUTABLE_ROOT95_REF_NOT_RELABELED')
    previous_raw=input_ref(C,previous_ref);previous=loads(previous_raw)
    need(previous['catalog95_sha256']==pins['schema95_catalog_sha256']and previous['complete_history_sha256']==sha(prior_raw)and previous['prior94_history_sha256']==sha(input_ref(C,c['prior94_history_ref']))and sha(C.wire(loads(input_ref(C,c['schema94_catalog_ref']))))==pins['schema94_catalog_sha256'],'HISTORICAL95_AND94_REFS_REMAIN_EXACT')
    r96=loads(input_ref(C,c['acceptance_refs']['Root_Goose96_acceptance']))
    root96_overlay(input_ref(C,c['acceptance_refs']['Root_Goose96_acceptance']),previous_raw,{'current_ops_source':G15_OPS_P,'business_source':CORE_R,'amd64_D':NEW_DIGEST,'complete_history_sha256':pins['complete_history_sha256'],'prior95_history_sha256':sha(prior_raw),'catalog96_sha256':pins['schema96_catalog_sha256'],'index92_definition_sha256':pins['index92_definition_sha256'],'catalog90_91_sha256':pins['catalog90_91_sha256']},lambda r:input_ref(C,r))
    need(c['acceptance_refs']['Root_Goose94_acceptance']['sha256']=='3ad88f1ada8cc96db0d6c6b0c3844a4de070e18f458cd6b053ab3a468b90c5e4','IMMUTABLE_HISTORICAL94_ROOT')


def database_pre_read96(cut,run,c,sql,label):
    require_bound()
    result={}
    for provider,key in (('aws','original_notify_aws_vm_members'),('hetzner','original_notify_hetzner_vm_members')):
        value=query(cut,run,label+'-'+provider.upper(),sql['queries'][key]);expected=c['policy_state'][provider]
        need(all(value[k]==expected[k]for k in ('intent_identity','owned_slots','active_policies','policy_catalog_wire')),'ALL_OTHER_POLICY_AND_ROSTER_BYTES_EXACT')
        lanes={k:value[k]for k in ('jobs_busy','runs_busy','forward_unreturned_reads','live_unreturned_canaries','intent_count','intent_busy','pending_authority','forward_markers')}
        need(lanes==c['pre_read_case']['provider_lanes'][provider]and lanes['intent_count']==1 and all(type(lanes[k])is int and lanes[k]==0 for k in ('jobs_busy','runs_busy','forward_unreturned_reads','live_unreturned_canaries')),'EXACT_CURRENT_SOURCE_LANES_NO_GUESSED_QUIET')
        result[provider]=lanes
    actual=query(cut,run,label+'-S8-PRE-READ',PRE_READ_SQL);validate_pre_read96(actual,c['pre_read_case'])
    need(actual['records_wire']==loads(input_ref(cut.C,c['pre_read_preimage_ref']))['records_wire'],'WHOLE_S8_ORIGINAL_PREIMAGE_UNCHANGED')
    # Existing exact schema/history/index observations remain part of pre-PATCH admission.
    current=query(cut,run,label+'-SCHEMA96',catalog94_select(input_ref(cut.C,c['legacy_catalog_sql_ref']).decode()))
    first=query(cut,run,label+'-SOURCE-SCHEMA96',sql['queries']['original_notify_aws_vm_members'])
    schema96_facts(c,first,current,cut.C);return result





def global_marker(C):
    return ROOT/('CORE-IMAGE-R5-33A-D35195-TO-'+CORE_R+'-'+C.NEW_DIGEST+'-POSSIBLE.json')


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
    global CONFIG_REF
    require_source_bound()
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--package',required=True,type=Path)
    p.add_argument('--expected-ops-source',required=True)
    p.add_argument('--expected-manifest-sha256',required=True)
    p.add_argument('--g15-swap-return',required=True,type=Path)
    p.add_argument('--expected-g15-swap-return-sha256',required=True)
    p.add_argument('--evidence-dir',required=True,type=Path)
    p.add_argument('--config-ref-path',required=True)
    p.add_argument('--expected-config-sha256',required=True)
    p.add_argument('--execute-core-image-cas-once',action='store_true',required=True)
    a = p.parse_args()
    CONFIG_REF = validated_config_ref(a.config_ref_path, a.expected_config_sha256)
    require_bound()
    need(os.geteuid() == 0 and sys.platform == 'linux','ROOT_LINUX_BRAIN_ONLY')
    folder = a.package.absolute(); cut = load_tools(folder); C = cut.C
    c, original_config, sql = maintenance_inputs(C)
    folder, manifest = C.package(folder,a.expected_manifest_sha256)
    need(manifest['source_commit'] == a.expected_ops_source == G15_OPS_P and re.fullmatch('[a-f0-9]{40}',a.expected_ops_source)
         and manifest['files']['source/network_guardian.py'] == SOURCE_PIN and manifest['tools'] == TOOL_PINS,'EXACT_SEPARATELY_QUALIFIED_G15_OPERATIONAL_SOURCE')
    returned_path = a.g15_swap_return.absolute()
    closed_g15_return_path(returned_path, C.STATE)
    C.private_dir(returned_path.parent); returned_raw = C.read(returned_path,32<<20,0o600)
    need(sha(returned_raw) == a.expected_g15_swap_return_sha256 and digest_value(a.expected_g15_swap_return_sha256), 'EXACT_G15_RETURN_BYTES')
    returned = C.loads(returned_raw)
    need(returned_path.name=='RETURN.json'and returned_path.parent.parent==ROOT and returned_path.parent.name.startswith('swap-once-')and not (returned_path.parent/'HOLD.json').exists(),'EXACT_G15_NORMAL_SWAP_RETURN_NOT_OLD_REPAIR')
    swap_claim=C.loads(C.read(ROOT/('SWAP-'+a.expected_manifest_sha256+'-POSSIBLE.json'),32768,0o600))
    need(set(swap_claim)=={'schema','manifest_sha256','old_controller','old_guardian','run','automatic_replay'}and swap_claim['schema']=='g15_once_only_swap_claim_v1'and swap_claim['manifest_sha256']==a.expected_manifest_sha256 and swap_claim['old_controller']==manifest['expected_controller_identity']and swap_claim['old_guardian']==manifest['expected_guardian_identity']and swap_claim['run']==str(returned_path.parent)and swap_claim['automatic_replay']is False,'ACTUAL_G15_ONCE_CLAIM_AND_RETURN')
    run = a.evidence_dir.absolute()
    need(run.parent == ROOT and re.fullmatch('core-image-cas-[A-Za-z0-9_-]{1,96}',run.name),'CLOSED_NEW_CAS_EVIDENCE_DIRECTORY')
    C.private_dir(ROOT); C.private_dir(run,create=True)
    sent = False
    def interrupted(signum,_): raise Hold('SIGNAL_'+str(signum)+'_RECONCILE_NO_REPLAY')
    for sig in (signal.SIGTERM,signal.SIGINT,signal.SIGHUP,signal.SIGALRM): signal.signal(sig,interrupted)
    signal.alarm(120)
    try:
        with operation_lock() as inode:
            need(not global_marker(C).exists(),'NEW_R5_TO_R6_GLOBAL_ONCE_ALREADY_CLAIMED')
            C.once(run/'MAINTENANCE-INPUT.original.json',original_config)
            api = API(cut)
            before = api_read(api,C,run,'DEPLOYMENT-BEFORE',DEP_URI)
            pods = api_read(api,C,run,'PODS-BEFORE',PODS_URI); old_tuple = core_before(before,pods,C)
            need(sha(C.wire(before['spec'])) == c['core_preimage']['spec_sha256'] and sha(C.wire(before['metadata']['annotations'])) == c['core_preimage']['annotations_sha256'],'EXACT_ROOT_FULL_R5_PREIMAGE')
            lineage=C.loads(C.read(returned_path.parent/'BEFORE.json',32<<20,0o600))
            need(lineage['core']==old_tuple and lineage['controller']==manifest['expected_controller_identity']and lineage['guardian']==manifest['expected_guardian_identity']and lineage['protected_refs']==required_protected_refs(),'NEW_G15_BEFORE_IS_CURRENT_CORE5_AND_EXACT_PROTECTED_PREDECESSOR')
            wire = C.wire(build_patch(before,C)); C.once(run/'PATCH.json',wire)
            status, raw, headers = api.request('PATCH',DEP_URI+'?dryRun=All&fieldManager=core-image-cas-once',wire)
            C.once(run/'SERVER-DRYRUN.json',raw); C.once(run/'SERVER-DRYRUN.HTTP.json',C.wire({'status':status,**headers}))
            need(status == 200,'SERVER_DRYRUN_200'); result_shape(before,C.loads(raw),C)
            database_pre_read96(cut,run,c,sql,'BEFORE')
            backend, protected, ctrl, guard, observed = g15_acceptance(cut,folder,manifest,C.loads(returned_raw),run)
            need(protected == lineage['protected_refs'],'SAME43_ORIGINALS_AND_ONE_OF_THREE_BUDGET')
            fresh = api_read(api,C,run,'DEPLOYMENT-FRESH-PRESEND',DEP_URI)
            fresh_pods = api_read(api,C,run,'PODS-FRESH-PRESEND',PODS_URI)
            need(core_before(fresh,fresh_pods,C) == old_tuple and fresh['metadata']['resourceVersion'] == before['metadata']['resourceVersion']
                 and fresh['spec'] == before['spec'] and fresh['metadata']['annotations'] == before['metadata']['annotations'],'UNCHANGED_FULL_API_PREIMAGE_NO_REBASE')
            backend.files(successor=True)
            need(backend.protected() == protected and cut.physical_identity(C.CTRL,cut.controller_argv(C.NEW_CONFIG)) == ctrl
                 and accepted_guardian(cut,returned) == guard,'SAME_ACCEPTED_G15_LIFETIMES_IMMEDIATELY_BEFORE_PATCH')
            database_pre_read96(cut,run,c,sql,'PRESEND')
            current_lock = OPLOCK.lstat()
            need((current_lock.st_dev,current_lock.st_ino) == inode and time.monotonic()-observed <= 15,'SAME_MUTEX_AND_FRESH_CURRENT15')
            marker = {'schema':'g15_R5_to_R6_core_image_possible_send_v1','at':now(),'method':'PATCH','uri':DEP_URI,
                'deployment_uid':UID,'generation':GENERATION,'resourceVersion':before['metadata']['resourceVersion'],
                'patch_sha256':sha(wire),'script_sha256':sha(read(__file__)),'manifest_sha256':a.expected_manifest_sha256,
                'G15_return_sha256':a.expected_g15_swap_return_sha256,'evidence_dir':str(run),'automatic_retry':False,
                'effects_may_have_happened_after_this_marker':True}
            sent = True; after = patch_once(api,C,run,wire,marker,observed); result_shape(before,after,C)
            # Image ACK is not runtime readiness or cycle credit. The already
            # admitted read-only retirement may resume as soon as Core6 starts.
            result = {'schema':'g15_core_image_cas_return_v1','status':'PATCH_ACKNOWLEDGED_ACCEPTANCE_PENDING',
                'deployment_uid':UID,'generation':after['metadata']['generation'],'resourceVersion':after['metadata']['resourceVersion'],
                'old_pod_uid':OLD_POD,'Core_source':CORE_R,'image':C.IMAGE_PREFIX+C.NEW_DIGEST,'manifest_sha256':a.expected_manifest_sha256,
                'G15_return_sha256':a.expected_g15_swap_return_sha256,'patch_sha256':sha(wire),'automatic_retry':False,
                'new_pod_readiness_proven':False,'post_rollout_G15_and_E2E_acceptance_proven':False,'evidence_dir':str(run)}
            C.once(run/'RETURN.PUBLIC.json',C.wire(result))
        signal.alarm(0); print(C.wire(result).decode(),end='',flush=True)
    except Exception as error:
        signal.alarm(0)
        C.once(run/'HOLD.PUBLIC.json',C.wire({'schema':'g15_core_image_cas_HOLD_v1','error_class':type(error).__name__,
            'guard':str(error)[:160] if isinstance(error,(Hold,C.Hold)) else 'NATIVE_OR_EVIDENCE_FAILURE','possible_send':sent,
            'automatic_retry':False,'actual_api_GET_only_readback_required':sent}))
        raise SystemExit(20) from None




M96 = 'bd28596ba82cc1607ac1a732ec5c401ac5de6bcfba3035d91f1c3a2f0a42d88d'
M96_BODY_SHA = 'd8cba69410381611df09c6d5c8823310be2a989026e51ab46c9885ddfc05d9f3'
M96_FUNCTION = 'retirement_forward_continuation_valid'
ROOT95_SHA = 'b80ec307962a67b8a28722c8fbf88add02c25de08847253fbae7838de1c0153d'

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

# INERT SOURCE FRAGMENT. Parent operator SOURCE_BOUND remains False until actual bindings.
# Closure: closed, need, source, digest_value, full_id, sha, loads; existing read_ref only.
def root96_overlay(receipt_raw, prior95_raw, pins, read_ref):
    need(sha(prior95_raw)=='b80ec307962a67b8a28722c8fbf88add02c25de08847253fbae7838de1c0153d','IMMUTABLE_ROOT95_WHOLE_ORIGINAL')
    previous=loads(prior95_raw); r=loads(receipt_raw)
    closed(r,'schema reviewed_by_root schema_before schema_after current_core_source current_ops_source business_source amd64_D migration96_sha256 complete_history_sha256 prior95_history_sha256 catalog96_sha256 index92_definition_sha256 catalog90_91_sha256 job_uid pod_uid exit_code single_job_create provider_guest_core_mutations old_records_and_sdk_preserved original_refs','ROOT96_CLOSED21')
    need(previous['schema']=='root_goose95_failed_expansion_read_continuation_acceptance_v1' and previous['reviewed_by_root']is True and previous['schema_after']==95,'ROOT95_REMAINS_HISTORICAL')
    need(r['schema']=='root_goose96_guest_retirement_pre_read_continuation_acceptance_v1' and r['reviewed_by_root']is True and r['schema_before']==95 and r['schema_after']==96,'ROOT96_DISTINCT_ACTUAL_OVERLAY')
    need(r['current_core_source']==previous['business_source']=='33a846d31a5b123b2c1141192671bc830bf6d9c8' and r['current_ops_source']==pins['current_ops_source'] and source(r['current_ops_source']) and r['business_source']==pins['business_source'] and source(r['business_source']) and r['amd64_D']==pins['amd64_D'] and digest_value(r['amd64_D']),'ROOT96_ACTUAL_CURRENT_G15_AND_R6_IMAGE_NOT_OLD95')
    need(r['migration96_sha256']=='bd28596ba82cc1607ac1a732ec5c401ac5de6bcfba3035d91f1c3a2f0a42d88d' and r['complete_history_sha256']==pins['complete_history_sha256'] and r['prior95_history_sha256']==previous['complete_history_sha256']==pins['prior95_history_sha256'] and r['catalog96_sha256']==pins['catalog96_sha256'] and r['index92_definition_sha256']==previous['index92_definition_sha256']==pins['index92_definition_sha256'] and r['catalog90_91_sha256']==pins['catalog90_91_sha256'],'ACTUAL96_RAW_HISTORY_AND_EXACT_CATALOG_PINS')
    need(full_id(r['job_uid']) and full_id(r['pod_uid']) and type(r['exit_code'])is int and r['exit_code']==0 and r['single_job_create']is True and type(r['provider_guest_core_mutations'])is int and r['provider_guest_core_mutations']==0 and r['old_records_and_sdk_preserved']is True,'ROOT96_SINGLE_JOB_NO_PROVIDER_OR_CORE_MUTATION')
    need(type(r['original_refs'])is dict and set(r['original_refs'])=={'migration_result','before_catalog','after_catalog','source_ci','qualified_image'},'ROOT96_EXACT_FIVE_ORIGINAL_ROLES')
    for ref in r['original_refs'].values():need(len(read_ref(ref))>1,'ROOT96_COMPLETE_PINNED_ORIGINAL')
    return r

if __name__=="__main__":main()
