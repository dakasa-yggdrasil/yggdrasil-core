"""Closed native commands; original per-call custody with bounded durable errors.

No Kubernetes/AWS credential command is accepted here. Initialization retains
full original local IO. Hot success retains only the original transport/hash
facts in RAM; errors retain original IO before propagating. Each concurrent
reader owns a distinct capture dictionary. No retry or inherited context.
"""
import base64
import hashlib
import ipaddress
import json
import os
import re
from pathlib import Path
import stat
import subprocess
import threading
import time

import original_process as process

ROOT = Path('/opt/dakasa/capacity-network')
DIRECTORY = None  # Bound from actual Boot/PID/start ticks during configure().
MAX_RECORDS = 64
MAX_DURABLE_BYTES = 128 * 1024**2
ROLES = frozenset(('owned_json', 'owned_text', 'owned_bracket', 'ruleset_mark',
    'ruleset_structure', 'adopt_owned_text', 'ct_census', 'route_core', 'route_broker', 'route_rds',
    'route_redis', 'route_prometheus', 'refresh_template_check',
    'initial_static_check', 'initial_static_apply', 'hot_dynamic_apply'))
_lock = threading.Lock()
_local = threading.local()
_directory = None
_initialized = False
_initial = True
_index = 0
_reserved_records = 0
_reserved_bytes = 0
_used_records = 0
_used_bytes = 0


def require(ok, guard):
    process.require(ok, guard)


def configure():
    global _directory, _initialized, DIRECTORY
    require(not _initialized, 'ONE_ORIGINAL_NATIVE_CUSTODY_CONFIGURATION')
    process.private(ROOT, True)
    boot = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    require(re.fullmatch('[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}', boot) is not None, 'ACTUAL_NATIVE_CUSTODY_BOOT')
    proc = Path('/proc/self/stat').read_bytes()
    ticks = proc[proc.rfind(b')') + 1:].split()[19]
    require(ticks.isdigit(), 'ACTUAL_NATIVE_CUSTODY_START_TICKS')
    DIRECTORY = ROOT / ('r11-original-native-custody-' + boot + '-' + str(os.getpid()) + '-' + ticks.decode('ascii'))
    DIRECTORY.mkdir(mode=0o700)
    process.private(DIRECTORY, True)
    parent = os.open(ROOT, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try: os.fsync(parent)
    finally: os.close(parent)
    _directory, _initialized = DIRECTORY, True


def end_initialization():
    global _initial
    require(_initialized, 'ORIGINAL_NATIVE_CUSTODY_REQUIRED')
    _initial = False


def allowed(argv, role, data):
    require(role in ROLES and type(argv) is list and all(type(x) is str for x in argv), 'COMPILED_NATIVE_ROLE_AND_ARGV')
    if role.startswith('route_'):
        require(len(argv) == 6 and argv[:5] == ['/usr/sbin/ip', '-j', '-4', 'route', 'get']
                and str(ipaddress.IPv4Address(argv[5])) == argv[5] and data is None, 'ONLY_NATIVE_ROUTE_GET')
        return
    shape = {
        'owned_json': ['/usr/sbin/nft', '-j', 'list', 'table', 'inet', 'dakasa_capacity_network'],
        'owned_bracket': ['/usr/sbin/nft', '-j', 'list', 'table', 'inet', 'dakasa_capacity_network'],
        'owned_text': ['/usr/sbin/nft', 'list', 'table', 'inet', 'dakasa_capacity_network'],
        'adopt_owned_text': ['/usr/sbin/nft', '-a', 'list', 'table', 'inet', 'dakasa_capacity_network'],
        'ruleset_mark': ['/usr/sbin/nft', '-j', 'list', 'ruleset'],
        'ruleset_structure': ['/usr/sbin/nft', '-j', 'list', 'ruleset'],
        'refresh_template_check': ['/usr/sbin/nft', '-c', '-f', '-'],
        'initial_static_check': ['/usr/sbin/nft', '-c', '-f', '-'],
        'initial_static_apply': ['/usr/sbin/nft', '-a', '-e', '-f', '-'],
        'hot_dynamic_apply': ['/usr/sbin/nft', '-f', '-'],
        'ct_census': ['/var/tmp/dakasa-two-cluster-b5c117ab7f94221f3de4/brain-data/data/d76b59b2203578bb4cb3438338ccad2f0d3e194bef799a8957f21430b7d5f1e3/bin/conntrack', '-L', '-o', 'extended'],
    }
    require(argv == shape[role], 'ONLY_COMPILED_NATIVE_READ_CHECK_OR_OWNED_APPLY')
    require((type(data) is bytes and 0 < len(data) <= 65536) if role in ('refresh_template_check', 'initial_static_check', 'initial_static_apply', 'hot_dynamic_apply') else data is None, 'COMPILED_NATIVE_INPUT_SHAPE')


def command(argv, *, data=None, timeout=2, role):
    global _index, _reserved_records, _reserved_bytes, _used_records, _used_bytes
    allowed(argv, role, data)
    require(_initialized and type(timeout) in (int, float) and 0 < timeout <= 10, 'INITIALIZED_BOUNDED_ORIGINAL_NATIVE_OPERATION')
    # Reserve worst-case full error bytes BEFORE starting each child. Output
    # cap is 8MiB per pipe, as in the prior whole-ruleset reader. Bounded disk
    # custody refuses new children instead of pruning history or retrying.
    cap = 8 * 1024**2
    reserved = ((2 * cap + 65536) * 4 // 3) + 32768
    with _lock:
        require(_used_records + _reserved_records < MAX_RECORDS
                and _used_bytes + _reserved_bytes + reserved <= MAX_DURABLE_BYTES, 'BOUNDED_ORIGINAL_NATIVE_CUSTODY_HIGH_WATER_HOLD')
        _reserved_records += 1; _reserved_bytes += reserved; _index += 1; index = _index
    started, capture, facts, error = time.monotonic(), {}, {}, None
    deadline = started + timeout
    out = None
    try:
        out, _ = process.native(argv, deadline=deadline, stdin=b'' if data is None else data,
            env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C'}, cap=cap, custody=facts, capture=capture)
    except BaseException as caught:
        error = caught
    returned = time.monotonic()
    # Original finally has completed all joins before this record is made.
    original = capture.get('transport', facts)
    stdout, stderr = capture.get('stdout', b''), capture.get('stderr', b'')
    local = all(original.get(k) is True for k in ('native_started', 'stdout_EOF', 'stderr_EOF', 'all_local_FDs_closed', 'local_child_joined'))
    closed = local and original.get('captured_output_truncated') is False
    bounded_outputs = len(stdout) <= 8 * 1024**2 and len(stderr) <= 1024**2
    success = bounded_outputs and error is None and closed and original.get('exit_code') == 0 and original.get('wait_zero') is True and returned < deadline
    metadata = {'schema': 'root_R11_original_native_command_facts_v1', 'sequence': index,
        'role': role, 'argv': argv, 'stdin_sha256': process.digest(b'' if data is None else data),
        'stdout_sha256': process.digest(stdout), 'stdout_bytes': len(stdout),
        'stderr_sha256': process.digest(stderr), 'stderr_bytes': len(stderr),
        'started_monotonic': started, 'returned_monotonic': returned, 'original_deadline': deadline,
        'original_transport': dict(original), 'closed_before_original_deadline_zero': success,
        'error_class': None if error is None else type(error).__name__,
        'closed_failure_guard': str(error) if isinstance(error, process.Held) and re.fullmatch('[A-Z0-9_]{1,160}',str(error)) else None,
        'initialization_phase': _initial, 'original_output_caps_satisfied':bounded_outputs, 'unknown_effect_never_replayed': True}
    durable = _initial or not success
    _local.last_facts = metadata
    try:
        if durable:
            full = {**metadata, 'stdout_base64': None if role == 'ct_census' else base64.b64encode(stdout).decode(),
                    'stderr_base64': None if role == 'ct_census' else base64.b64encode(stderr).decode(), 'stdin_base64': base64.b64encode(b'' if data is None else data).decode(),
                    'conntrack_output_redacted': role == 'ct_census', 'success_authority': False}
            raw = process.canonical(full)
            require(len(raw) <= reserved, 'ORIGINAL_NATIVE_DIAGNOSTIC_RESERVATION')
            process.once(_directory / ('NATIVE-%06d-ORIGINAL-IO.json' % index), full)
            metadata['durable_original_IO_sha256'] = process.digest(raw)
        # One bounded thread-local record; no shared last_custody races.
        metadata['diagnostic_retention_returned_monotonic'] = time.monotonic()
        metadata['retention_inside_original_deadline'] = time.monotonic() < deadline
        _local.last_facts = metadata
    finally:
        with _lock:
            _reserved_records -= 1; _reserved_bytes -= reserved
            if durable:
                _used_records += 1; _used_bytes += len(raw) if 'raw' in locals() else reserved
    if error is not None:
        # The original exact closed guard is diagnostic, never replay authority.
        reason = str(error) if isinstance(error, process.Held) else 'ORIGINAL_NATIVE_TRANSPORT_EXCEPTION'
        raise process.Held(reason) from None
    require(bounded_outputs, 'NATIVE_OUTPUT_CAP')
    require(closed and original.get('exit_code') is not None, 'ORIGINAL_NATIVE_IO_AND_WAIT_FULLY_JOINED')
    require(time.monotonic() < deadline, 'ORIGINAL_NATIVE_CALL_RETURN_DEADLINE')
    # Nonzero status is retained above, then interpreted by owning callsite.
    return subprocess.CompletedProcess(argv, original['exit_code'], stdout, stderr)


def last_facts():
    value = getattr(_local, 'last_facts', None)
    return None if value is None else json.loads(json.dumps(value))
