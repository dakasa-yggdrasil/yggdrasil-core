"""Closed G7 operational ABI. Definitions only; no native action on import.

The image-pair prefix and the two Guardian ancestry axes are independent.
Callers pin the complete operational package by its reviewed manifest hash.
"""
import hashlib
import ipaddress
import json
import math
import os
from pathlib import Path
import re
import stat
import types

ROOT = Path('/opt/dakasa/capacity-network')
ETC = Path('/etc/dakasa/capacity-network')
UNIT_DIR = Path('/etc/systemd/system')
CTRL = 'dakasa-capacity-network.service'
GUARD = 'dakasa-capacity-network-guardian.service'
COLD = 'dakasa-capacity-network-cold-transport.service'
HUB = 'dakasa-capacity-network-hub.service'
UNITS = (CTRL, GUARD, COLD, HUB)
SOURCE_R = 'c9f260432ce5a10886df0385c958ec7d643648df'
OLD_DIGEST = '750d5e46aee679075c2b88c163d22036093cf893edbe16bb5c2ca484f4275838'
NEW_DIGEST = 'f809040367a1c6c9fea0e8f4b31486970f03ed68a979a5bdcd412ed95bd70dcb'
IMAGE_PREFIX = '153828470928.dkr.ecr.us-east-1.amazonaws.com/ghcr/dakasa-yggdrasil/yggdrasil-core@sha256:'
G6_CONFIG_SHA = '8b74f1de7e49e44b4ad140b59767e441cc6adaf6c0689d684ecdc301bcee6c5e'
G7_CONFIG_SHA = 'd68912a7e24b68e6cc51faeedba4c0987c65b2a14d439d18483706bd3fd18fbf'
G6_SOURCE_SHA = '6c2cc19f1f962d9d8eaec0cd5e6f813bf49004f8ff6fef9c9fe9f8f0310d8f1b'
G6_STANDING_SHA = 'be5b25495056bd25e1512827b5ccbe7236f84928b4d20515f5000383771dcc79'
F315_SOURCE_SHA = 'f3152cc6d8c5d7edee2e5349db17fac4b8650a18423dfc207c04fcc116955e6d'
F315_STANDING_SHA = 'faa6b2cb3132ce2e0ee4304bd833d7f0f999850244014d355f1c33ed176ebb83'
OLD_SOURCE = ROOT / 'network-boot-recovery-r13-g6pair-boot-v2-source-v1'
NEW_SOURCE = ROOT / 'network-boot-recovery-r13-g7pair-source-v1'
OLD_STANDING = ETC / 'network-recovery.r13-g6pair-boot-v2.production.json'
NEW_STANDING = ETC / 'network-recovery.r13-g7pair.production.json'
OLD_CONFIG = ETC / 'controller.r13-netlink-g6pair.production.json'
NEW_CONFIG = ETC / 'controller.r13-netlink-g7pair.production.json'
RUNTIME = ROOT / 'source-r13-netlink-v1'
LEDGER = Path('/var/lib/dakasa-capacity-network-recovery')
STATE = Path('/var/lib/dakasa-core-rollout/g7pair')
MAINTENANCE = Path('/run/dakasa-capacity-network/guardian-maintenance.lock')
DROPIN = Path('/etc/systemd/system.control') / (CTRL + '.d/50-CPUQuota.conf')
# The existing CPU quota override is deliberately retained.
DROPIN_SHA = '2acd3272d2ee396203c519bc353c089be5871c3b70d79eff9e27f8ef70f14994'
OLD_UNIT_SHAS = {CTRL: '12671f666b11b6176701735e08c9e6f53280f145fe19c7ec9add9fe1fc2b2327',
                 COLD: 'd63c9e804f5d109ea5738c4f2365b778c520e6afa20e29a60462576c939d1e5e',
                 GUARD: '17556975adcefc6ac6e93fc80793f70ee4bf099a5cf021d174d23d72209e3a7f',
                 HUB: '4ae45486e7b25c5c3f525409a5714568c22d16f72c4e6d8afad9bc3b3576ebfe'}
MODULES = ('network_guardian.py', 'coverage.py', 'journal_contract.py', 'proof_cache.py',
           'current15_bounded_reader.py', 'current15_bounded_tail_contract.py',
           'initial_boot_Cold_read_adoption.py', 'qualification_initializer.py')
TOOLS = ('pair_change_contract.py', 'derive_g7pair_controller_config.py', 'derive_standing_config.py', 'g7cut.py')
HELPERS = {'coverage.py': 'eb7ed1fcbcc665cdc3603812a10103b4e19dd0b66693b99dc8cfeb15adceeb88',
           'journal_contract.py': 'b0c153b69cc8275e1e330cb3c584b498c1685c1b999c4b5c7b972f164c96db6c',
           'proof_cache.py': 'c2e0b981a2843c15dd5907cc186e4c23a7d844a78c1ce4f7e2e3578704eb5b4b',
           'current15_bounded_reader.py': '1124dfbfbd57c60decc4fdcb0233c03253e87a941f50c8fa5b6aad3e28ae30cd',
           'current15_bounded_tail_contract.py': 'c18809987960f9aea524240f7ea6886a1ed782e5c4001e68edac875bbbe3431d',
           'initial_boot_Cold_read_adoption.py': '0e690f4b74303da774aa7d5a651444e7f74c8445428af38002192bf1079b5799',
           'qualification_initializer.py': 'd73ade12564ba7b672a4dbdf8225e99af13a64a9b8aff4a41fb1a0225bef9ec8'}
PREFIX_STANDINGS = {'f5pair': 'afcfe2e5cad8dbf59732fb805e7f6c4a709608f36ba77bc112ca6633c8e3833c',
                    'g2pair': '494a57d8d4995f9f52348e6153bca5e00a73b873fbd69e8e36c187407cc0f57f',
                    'g3pair': '2922be85534c7d93257a9d703af8509c72e585e5683edfd35496ff8294df40d9',
                    'g4pair': '385928fe10e25980b918ca44bacd5b7e8b901cd2cbcde2bae8304e58d8931997',
                    'g5pair': '180b38fa905099e57776e944eda2be856ccc89bc070ad6b67a9142ab380139ca'}
ANCESTORS = {'g6_predecessor_guardian_source_sha256': G6_SOURCE_SHA,
             'g6_predecessor_standing_config_sha256': G6_STANDING_SHA,
             'g6_boot_v2_predecessor_guardian_source_sha256': F315_SOURCE_SHA,
             'g6_boot_v2_predecessor_standing_config_sha256': F315_STANDING_SHA}
DERIVATION_SCHEMA = 'r13_g7pair_guardian_standing_config_derivation_v1'
PACKAGE_SCHEMA = 'guardian_g7pair_operational_package_v1'
STAGED_SCHEMA = 'guardian_g7pair_staged_v1'
REQUIRED_CI = frozenset((('Capacity intent PostgreSQL protocol', 'pull_request'), ('Capacity source-owned HTTP qualification', 'pull_request'), ('Context Freshness (ADR + durable context)', 'pull_request'), ('Docs freshness', 'pull_request'), ('Failed installed Guest administrative HTTP Source', 'pull_request'), ('Failed serving Guest Source and PostgreSQL', 'pull_request'), ('Guest historical unknown read recovery', 'pull_request'), ('Installed Guest reconciliation Source', 'pull_request'), ('Native OIDC protocol integration', 'pull_request'), ('Original Guest Core source and PostgreSQL gates', 'pull_request'), ('Original Guest Core source and PostgreSQL gates', 'push'), ('Original and native denied disposition Source', 'pull_request'), ('Owned Network Guardian', 'pull_request'), ('Partial Guest native OFF reconciliation Source', 'pull_request'), ('Protected native capacity API qualification', 'pull_request'), ('Service contract', 'pull_request'), ('Service contract', 'push'), ('template-go-api CI', 'pull_request')))


class Hold(RuntimeError):
    """Preserve evidence and reconcile actual state; never automatically replay."""


def need(ok, guard):
    if not ok:
        raise Hold(guard)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def wire(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode()


def loads(raw):
    def unique(rows):
        out = {}
        for key, value in rows:
            need(key not in out, 'DUPLICATE_JSON_KEY')
            out[key] = value
        return out
    def reject(_):
        raise Hold('NONFINITE_JSON')
    def finite_float(text):
        value = float(text)
        need(math.isfinite(value), 'NONFINITE_JSON')
        return value
    return json.loads(raw, object_pairs_hook=unique, parse_constant=reject, parse_float=finite_float)


def digest(value):
    return type(value) is str and re.fullmatch('[a-f0-9]{64}', value) is not None and value != '0' * 64


def identity(value):
    need(type(value) is dict and set(value) == {'boot_id', 'pid', 'start_ticks', 'InvocationID', 'ExecMainStartTimestampMonotonic'}, 'CLOSED_NATIVE_IDENTITY')
    need(re.fullmatch('[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}', str(value['boot_id']))
         and type(value['pid']) is int and value['pid'] > 1 and type(value['start_ticks']) is int and value['start_ticks'] > 0
         and re.fullmatch('[a-f0-9]{32}', str(value['InvocationID'])) and re.fullmatch('[1-9][0-9]*', str(value['ExecMainStartTimestampMonotonic'])), 'EXACT_PHYSICAL_NATIVE_IDENTITY')


def read(path, cap=1 << 20, mode=None):
    path = Path(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        a = os.fstat(fd)
        need(stat.S_ISREG(a.st_mode) and a.st_uid == 0 and a.st_nlink == 1 and
             (stat.S_IMODE(a.st_mode) == mode if mode is not None else not stat.S_IMODE(a.st_mode) & 0o022), 'ROOT_STABLE_REGULAR_FILE')
        chunks, size = [], 0
        while True:
            row = os.read(fd, min(65536, cap + 1 - size))
            if not row:
                break
            size += len(row)
            need(size <= cap, 'BOUNDED_FILE')
            chunks.append(row)
        b = os.fstat(fd)
        need((a.st_dev, a.st_ino, a.st_size, a.st_mtime_ns, a.st_ctime_ns) ==
             (b.st_dev, b.st_ino, b.st_size, b.st_mtime_ns, b.st_ctime_ns), 'STABLE_FULL_READ')
        return b''.join(chunks)
    finally:
        os.close(fd)


def sync_dir(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def shared_parent(path):
    """Inspect the existing shared parent; never chmod or replace it."""
    path = Path(path)
    s = path.lstat()
    need(stat.S_ISDIR(s.st_mode) and s.st_uid == 0 and not path.is_symlink()
         and not stat.S_IMODE(s.st_mode) & 0o022, 'ROOT_SHARED_PARENT_NOT_SYMLINK_OR_WRITABLE')


def private_dir(path, create=False):
    path = Path(path)
    if create:
        path.mkdir(mode=0o700, exist_ok=False)
        sync_dir(path.parent)
    s = path.lstat()
    need(stat.S_ISDIR(s.st_mode) and s.st_uid == 0 and stat.S_IMODE(s.st_mode) == 0o700 and not path.is_symlink(), 'ROOT_PRIVATE_DIRECTORY')


def once(path, raw, mode=0o600):
    path = Path(path)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, mode)
    try:
        os.fchmod(fd, mode)
        view = memoryview(raw)
        while view:
            n = os.write(fd, view)
            need(n > 0, 'FULL_WRITE')
            view = view[n:]
        os.fsync(fd)
    finally:
        os.close(fd)
    sync_dir(path.parent)
    need(read(path, max(len(raw), 1), mode) == raw, 'NEW_FILE_READBACK')


def load_guardian(path, expected_sha):
    raw = read(Path(path) / 'network_guardian.py')
    need(digest(expected_sha) and sha(raw) == expected_sha, 'EXACT_GUARDIAN_DEFINITIONS')
    module = types.ModuleType('exact_g7_operational_guardian_definitions')
    module.__file__ = str(Path(path) / 'network_guardian.py')
    exec(compile(raw, module.__file__, 'exec'), module.__dict__)
    return module


def validate_standing_output(value, expected, units_source):
    """Same closed ABI for staged and live derivation; no native operations."""
    need(type(value) is dict and set(value) == {'schema', 'hub_profile', 'units_source', 'standing_config_sha256', 'standing_config_written', 'input_sha256', 'review_text_printed', 'private_files_read'}, 'CLOSED_G7_DERIVATION_OUTPUT')
    need(value['schema'] == DERIVATION_SCHEMA and value['hub_profile'] == 'r13' and units_source in ('staged', 'live') and value['units_source'] == units_source
         and value['standing_config_written'] is True and value['review_text_printed'] is False and value['private_files_read'] is False
         and digest(value['standing_config_sha256']), 'EXACT_G7_DERIVATION_RESULT')
    need(type(expected) is dict and set(expected) == {'source_sha256', 'unit_sha256', 'controller_prefix_sha256', 'ancestry_input_sha256'}, 'CLOSED_EXPECTED_DERIVATION')
    inputs = {'successor_guardian_source_sha256': expected['source_sha256'], 'head_generation': 'g7pair', 'head_core_digest': 'sha256:' + NEW_DIGEST,
              'head_controller_config_sha256': G7_CONFIG_SHA, 'historical_g6_controller_config_sha256': G6_CONFIG_SHA,
              'pair_predecessor_standing_config_sha256': PREFIX_STANDINGS, **ANCESTORS,
              'pair_chain_controller_config_sha256': {**expected['controller_prefix_sha256'], 'g7pair': G7_CONFIG_SHA},
              **expected['unit_sha256'], **expected['ancestry_input_sha256']}
    need(set(expected['unit_sha256']) == set(UNITS) and set(expected['controller_prefix_sha256']) == {'base', 'f5pair', 'g2pair', 'g3pair', 'g4pair', 'g5pair', 'g6pair'}
         and expected['controller_prefix_sha256']['g6pair'] == G6_CONFIG_SHA, 'EXACT_PREFIX_AND_FOUR_UNITS')
    need(set(expected['ancestry_input_sha256']) == {'predecessor_standing_config_sha256', 'r13_predecessor_standing_config_sha256', 'r42_controller_config_sha256', 'r13_base_controller_config_sha256', 'hub_source_sha256', 'hub_boot_config_sha256', 'hub_unit_sha256'}, 'CLOSED_ORIGINAL_ANCESTRY_INPUTS')
    need(expected['unit_sha256'][HUB] == expected['ancestry_input_sha256']['hub_unit_sha256']
         and expected['controller_prefix_sha256']['base'] == expected['ancestry_input_sha256']['r13_base_controller_config_sha256'], 'SAME_HUB_UNIT_AND_R13_BASE_ACROSS_OUTPUT_AXES')
    need(all(digest(x) for x in [expected['source_sha256'], *expected['unit_sha256'].values(), *expected['controller_prefix_sha256'].values(), *expected['ancestry_input_sha256'].values()]), 'NONZERO_DERIVATION_PINS')
    need(value['input_sha256'] == inputs, 'EXACT_G7_DUAL_ANCESTRY_STAGED_OR_LIVE_ABI')
    return value['standing_config_sha256']


def validate_manifest(m):
    keys = {'schema', 'source_commit', 'source_R', 'amd64_D', 'runtime_package_sha256', 'files', 'tools', 'controller_unit_sha256', 'root_controller_review_sha256', 'root_standing_review_sha256', 'expected_controller_identity', 'expected_guardian_identity', 'protected_refs', 'ci_attestation', 'continuity_peer_ipv4'}
    need(type(m) is dict and set(m) == keys and m['schema'] == PACKAGE_SCHEMA and m['source_R'] == SOURCE_R and m['amd64_D'] == NEW_DIGEST and re.fullmatch('[a-f0-9]{40}', str(m['source_commit'])), 'CLOSED_EXACT_G7_OPERATIONAL_PACKAGE')
    for key in ('runtime_package_sha256', 'controller_unit_sha256', 'root_controller_review_sha256', 'root_standing_review_sha256'):
        need(digest(m[key]), 'EXACT_PACKAGE_PIN')
    need(set(m['files']) == {'source/' + n for n in MODULES} | {'units/' + n for n in (COLD, GUARD)} and all(digest(x) for x in m['files'].values()), 'EXACT_SOURCE8_UNITS2_ROSTER')
    need(all(m['files']['source/' + n] == h for n, h in HELPERS.items()) and set(m['tools']) == set(TOOLS) and all(digest(x) for x in m['tools'].values()), 'UNCHANGED_SEVEN_HELPERS_AND_EXACT_FOUR_TOOLS')
    identity(m['expected_controller_identity']); identity(m['expected_guardian_identity'])
    need(m['expected_controller_identity']['boot_id'] == m['expected_guardian_identity']['boot_id'] and m['expected_controller_identity']['pid'] != m['expected_guardian_identity']['pid'], 'SAME_BOOT_DISTINCT_OWNED_LIFETIMES')
    need(type(m['continuity_peer_ipv4']) is str and str(ipaddress.IPv4Address(m['continuity_peer_ipv4'])) == m['continuity_peer_ipv4'] and ipaddress.IPv4Address(m['continuity_peer_ipv4']).is_private, 'ROOT_REVIEWED_ACTUAL_CONTINUITY_PEER_IPV4')
    refs = m['protected_refs']
    need(type(refs) is list and 3 <= len(refs) <= 128, 'EXPLICIT_ORIGINAL_PROTECTED_REFS')
    for v in refs:
        need(type(v) is dict and set(v) == {'path', 'sha256'} and Path(v['path']).parent == LEDGER and re.fullmatch('[A-Za-z0-9_.-]+(?:\.PUBLIC(?:\.json)?|\.JSONL)', Path(v['path']).name) and digest(v['sha256']), 'FIXED_PUBLIC_LEDGER_REF')
    need(len({v['path'] for v in refs}) == len(refs), 'UNIQUE_ORIGINAL_PROTECTED_REFS')
    ci = m['ci_attestation']
    need(type(ci) is dict and set(ci) == {'schema', 'commit', 'reviewed_by_root', 'runs'} and ci['schema'] == 'guardian_g7_exact_source_ci_v1'
         and ci['commit'] == m['source_commit'] and ci['reviewed_by_root'] is True and type(ci['runs']) is list and len(ci['runs']) == len(REQUIRED_CI), 'ROOT_REVIEWED_EXACT_G7_CI')
    need(all(type(r) is dict and set(r) == {'id', 'name', 'event', 'head_sha', 'status', 'conclusion', 'attempt'} and type(r['id']) is int and r['id'] > 0 and r['head_sha'] == m['source_commit']
             and r['status'] == 'completed' and r['conclusion'] == 'success' and type(r['attempt']) is int and r['attempt'] >= 1 for r in ci['runs']) and len({r['id'] for r in ci['runs']}) == len(ci['runs']), 'EVERY_REQUIRED_EXACT_G7_CI_RUN_SUCCESS')
    need({(r['name'], r['event']) for r in ci['runs']} == REQUIRED_CI, 'ALL_APPLICABLE_G7_CI_NAMES_AND_EVENTS_PRESENT')
    return m


def package(folder, expected_sha):
    folder = Path(folder); private_dir(folder)
    raw = read(folder / 'MANIFEST.json')
    need(digest(expected_sha) and sha(raw) == expected_sha, 'ROOT_REVIEWED_PACKAGE_MANIFEST_SHA')
    m = validate_manifest(loads(raw))
    runtime_raw = read(folder / 'PACKAGE.json')
    need(sha(runtime_raw) == m['runtime_package_sha256'] and loads(runtime_raw)['files'] == m['files'], 'EXACT_SEPARATE_RUNTIME_PACKAGE10')
    for name, pin in m['files'].items():
        need(sha(read(folder / name)) == pin, 'EXACT_RUNTIME_PACKAGE_FILE')
    for name, pin in m['tools'].items():
        need(sha(read(folder / 'tools' / name)) == pin, 'EXACT_OPERATIONAL_TOOL_FILE')
    need(sha(read(folder / 'controller.service', 32768)) == m['controller_unit_sha256'], 'EXACT_DERIVED_CONTROLLER_UNIT')
    need(sha(read(folder / 'ROOT-CONTROLLER-REVIEW.txt', 8192)) == m['root_controller_review_sha256'] and sha(read(folder / 'ROOT-STANDING-REVIEW.txt', 8192)) == m['root_standing_review_sha256'], 'EXACT_ROOT_REVIEW_FILES')
    return folder, m
