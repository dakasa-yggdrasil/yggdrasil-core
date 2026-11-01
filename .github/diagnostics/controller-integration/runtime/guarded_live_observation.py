"""LAB candidate for Guardian-owned tuple/deadline evidence, never a grant.

Requires a private same-process verified generation, original Guardian Readers,
consistent live sender/map/rule re-read and a pinned probe. Current15 and the
cross-process effect lease are intentionally absent, so every caller must HOLD.
"""
import base64
import hashlib
import json
import os
import re
import select
import struct
import time
from pathlib import Path


def observe(verified, *, verifier, sources, nl, coverage, probe_path, probe_sha256):
    check = nl.check
    check(type(verified) is verifier._VerifiedGeneration
          and verified.capability is verifier._VERIFIED_CAPABILITY
          and verified.guardian_pid == os.getpid() and verified.sender_pidfd is not None,
          'ORIGINAL_SAME_GUARDIAN_VERIFIED_GENERATION_REQUIRED')
    result, anchor, cache = verified.result, verified.anchor, verified.reader_cache
    sender_pid = anchor['pid']
    poll = select.poll()
    poll.register(verified.sender_pidfd, select.POLLIN)
    check(not poll.poll(0) and nl.startticks(sender_pid) == anchor['start_ticks'],
          'ORIGINAL_SENDER_MUST_BE_LIVE')
    source = Path(probe_path).resolve(strict=True)
    check(hashlib.sha256(source.read_bytes()).hexdigest() == probe_sha256, 'EXACT_GUARDIAN_PROBE_SOURCE')
    prefix = ['/usr/bin/nsenter', '--net=/proc/' + str(sender_pid) + '/ns/net']
    def probe():
        import fenced_probe_CI
        return json.loads(fenced_probe_CI.call(nl,prefix,source))
    first = probe()
    check(first['genid'] == result['after'] and len(first['rules']) == 2, 'ORIGINAL_GUARDED_GENERATION_REQUIRED')
    actual = {}
    check(len(result['programs']) == 2, 'EXACT_TWO_PROGRAMS_REQUIRED')
    for name, rec in zip(('inbound', 'reverse'), result['programs']):
        info = nl.fdinfo(sender_pid, rec['program_fd'])
        m = nl.fdinfo(sender_pid, rec['map_fd'])
        check(int(info['prog_id']) == rec['program_id'] and int(m['map_id']) == rec['map_id']
              and m['frozen'].strip() == '1', 'LIVE_ORIGINAL_FROZEN_CUSTODY_REQUIRED')
        actual[name] = nl.map_rows(rec['map_id'])
        check(set(actual[name]) == set(verified.actual[name]) and len(actual[name]) == len(verified.actual[name]),
              'SAME_VERIFIED_ORIGINAL_MAP_CONTENTS')
    kernel_read_started_ns = time.monotonic_ns()
    import fenced_probe_CI
    text = fenced_probe_CI.read_nft(nl,prefix, '-a', 'list', 'table', 'inet', 'dakasa_capacity_network')
    kernel = coverage.kernel_text(text)
    joined = sources.verify(cache, kernel, actual)
    check(type(kernel['minimum_actual_expires_ms']) is int and kernel['minimum_actual_expires_ms'] > 0,
          'ALL_DYNAMIC_KERNEL_EXPIRIES_POSITIVE')
    collection_deadline_ns = kernel_read_started_ns + kernel['minimum_actual_expires_ms'] * 1_000_000
    last = probe()
    check(last == first and not poll.poll(0) and nl.startticks(sender_pid) == anchor['start_ticks'],
          'SAME_GENERATION_AND_SENDER_AFTER_INDEPENDENT_JOIN')
    for entry, handle, encoded in zip(result['programs'], result['handles'], last['rules']):
        body = base64.b64decode(encoded)
        fields = dict((k & 0x3fff, value) for k, value in nl.attrs(body[4:]))
        check(struct.unpack('>Q', fields[3])[0] == handle
              and struct.pack('<HHi', 2, 0, entry['program_fd']) in body,
              'SAME_ORIGINAL_FD_RULE_HANDLE')
    now = time.monotonic_ns()
    deadlines = [deadline for rows in actual.values() for _, deadline in rows]
    check(deadlines and min(min(deadlines), collection_deadline_ns) > now, 'ALL_ORIGINAL_KERNEL_DEADLINES_STILL_LIVE')
    canonical = {name: [[key.hex(), deadline] for key, deadline in sorted(actual[name])]
                 for name in ('inbound', 'reverse')}
    invocation = os.environ.get('INVOCATION_ID', '')
    check(re.fullmatch('[a-f0-9]{32}', invocation) is not None, 'OWN_GUARDIAN_INVOCATION_REQUIRED')
    receipt = {k: v for k, v in result.items() if k not in ('ok', 'counter')}
    observation = {'boot_id': Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
        'netns': anchor['netns'], 'genid': result['after'],
        'receipt_sha256': hashlib.sha256(nl.canon(receipt)).hexdigest(),
        'guardian_invocation_id': invocation, 'guardian_pid': os.getpid(),
        'guardian_start_ticks': nl.startticks(os.getpid()),
        'reader_generation': joined['source_generation'],
        'current15_start_ns': None, 'current15_observed_until_ns': None,
        'current15_guaranteed_until_ns': None,
        'kernel_min_deadline_ns': min(min(deadlines), collection_deadline_ns),
        'tuples_sha256': hashlib.sha256(nl.canon(canonical)).hexdigest(),
        'inbound_tuple_count': len(actual['inbound']), 'reverse_tuple_count': len(actual['reverse']),
        'peer_count': 16}
    return {'schema': 'lab_guardian_live_tuple_observation_v1', 'observation': observation,
            'invalidation_epoch': joined.get('invalidation_epoch'), 'observed_ns': now, 'current15_qualified': False,
            'cross_process_effect_lease': False, 'grant_authority': False}
