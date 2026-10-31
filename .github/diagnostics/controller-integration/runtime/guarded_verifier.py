"""LAB Guardian candidate: independently verify one emitted generation.

This does not start a service, authorize a cutover, attest preexisting pins,
or provide crash recovery. The long-lived Guardian must own the returned pidfd,
check caller credentials, monitor Readers, and prove its source/runtime seals.
"""
import base64
import ctypes
import hashlib
import json
import os
import select
import struct
from pathlib import Path


def verify_generation(*, result, anchor, plan, receipt_dir, reader_cache,
                      nl, sources, transition, coverage, probe_path, probe_sha256):
    check = nl.check
    sender_pid = anchor['pid']
    pin = transition.OriginalPin(base64.b64decode(anchor['initial']))
    sender_fd = os.pidfd_open(sender_pid, 0)
    sender_poll = select.poll()
    sender_poll.register(sender_fd, select.POLLIN)
    try:
        check(result['after'] == ((result['genid'] + 1) & 0xffffffff or 1)
              and result['stale_code'] == -85, 'GENERATION_NOT_EXPECTED')
        savedir = Path(receipt_dir)
        index = result['counter']
        intent_raw = nl.private_read(savedir / ('INTENT-%03d.json' % index))
        intent = json.loads(intent_raw)
        wire = nl.private_read(savedir / ('WIRE-%03d.bin' % index))
        stored = json.loads(nl.private_read(savedir / ('ACK-%03d.json' % index)))
        check(stored == {k: v for k, v in result.items() if k not in ('ok', 'counter')}
              and stored['intent_sha256'] == hashlib.sha256(intent_raw).hexdigest(),
              'DURABLE_ORIGINAL_RECEIPT')
        check(intent['pid'] == sender_pid
              and intent['start_ticks'] == anchor['start_ticks'] == nl.startticks(sender_pid)
              and intent['netns'] == anchor['netns']
              and intent['boot_id'] == Path('/proc/sys/kernel/random/boot_id').read_text().strip()
              and intent['genid'] == result['genid']
              and intent['ack_sequences'] == result['ack_sequences']
              and intent['programs'] == result['programs']
              and hashlib.sha256(wire).hexdigest() == result['wire_sha256'] == intent['wire_sha256'],
              'ORIGINAL_SEND_PID_AND_PAYLOAD')
        parsed = []
        for encoded in result['ack']:
            for typ, seq, data in nl.packets(base64.b64decode(encoded)):
                check(typ == 2 and len(data) >= 4, 'ORIGINAL_ACK_DUMP')
                parsed.append((seq, struct.unpack_from('<i', data)[0]))
        check(sorted(parsed) == [(x, 0) for x in result['ack_sequences']], 'EXACT_ORIGINAL_ACK')
        probe = Path(probe_path).resolve(strict=True)
        check(hashlib.sha256(probe.read_bytes()).hexdigest() == probe_sha256,
              'EXACT_LAB_PROBE_SOURCE')
        prefix = ['/usr/bin/nsenter', '--net=/proc/' + str(sender_pid) + '/ns/net']
        def crossprobe():
            return json.loads(nl.cmd(*prefix, '/usr/bin/python3', '-I', '-B', str(probe), 'probe'))
        first_probe = crossprobe()
        check(first_probe['genid'] == result['after'] and len(first_probe['rules']) == 2,
              'INDEPENDENT_PRE_READ_GENERATION')
        actual = {}
        check(len(result['programs']) == 2, 'EXACT_TWO_PROGRAMS_REQUIRED')
        for name, entry in zip(('inbound', 'reverse'), result['programs']):
            pi = nl.ProgInfo()
            ids = (ctypes.c_uint32 * 8)()
            pi.nr_map_ids = 8
            pi.map_ids = ctypes.addressof(ids)
            fd = nl.bpf(13, struct.pack('<I', entry['program_id']))
            try:
                nl.info(fd, pi)
                check(pi.id == entry['program_id'] and bytes(pi.tag).hex() == entry['program_tag']
                      and pi.nr_map_ids == 1 and ids[0] == entry['map_id'], 'KERNEL_PROGRAM_IDENTITY')
            finally:
                os.close(fd)
            check(int(nl.fdinfo(sender_pid, entry['program_fd'])['prog_id']) == entry['program_id'],
                  'SENDER_PROGRAM_FD_ID')
            mi = nl.fdinfo(sender_pid, entry['map_fd'])
            check(int(mi['map_id']) == entry['map_id'] and mi['frozen'].strip() == '1',
                  'SENDER_MAP_FROZEN')
            actual[name] = nl.map_rows(entry['map_id'])
        raw = nl.cmd(*prefix, '/usr/sbin/nft', '-a', '-j', 'list', 'ruleset')
        transition.verify_guarded(pin, raw, observed_chain_handle=result['chain'],
                                  observed_rule_handles=tuple(result['handles']))
        text = nl.cmd(*prefix, '/usr/sbin/nft', '-a', 'list', 'table', 'inet', 'dakasa_capacity_network')
        joined = sources.verify(reader_cache, coverage.kernel_text(text), actual)
        last_probe = crossprobe()
        check(last_probe == first_probe and not sender_poll.poll(0)
              and nl.startticks(sender_pid) == anchor['start_ticks'],
              'CONSISTENT_GENERATION_AND_LIVE_OWNER')
        check(hashlib.sha256(probe.read_bytes()).hexdigest() == probe_sha256,
              'UNCHANGED_LAB_PROBE_SOURCE')
        for entry, handle, encoded in zip(result['programs'], result['handles'], last_probe['rules']):
            body = base64.b64decode(encoded)
            fields = dict((k & 0x3fff, v) for k, v in nl.attrs(body[4:]))
            check(struct.unpack('>Q', fields[3])[0] == handle
                  and struct.pack('<HHi', 2, 0, entry['program_fd']) in body
                  and struct.pack('<HHi', 2, 0, entry['program_fd']) in wire,
                  'SAME_RULE_HANDLE_AND_EMITTING_FD')
        for name in ('inbound', 'reverse'):
            rows = plan['maps'][name]
            check(type(rows) is list and len(rows) == len(actual[name]),
                  'KERNEL_' + name.upper() + '_PLAN_ROW_COUNT')
            check(set(actual[name]) == set((bytes.fromhex(k), v) for k, v in rows),
                  'KERNEL_' + name.upper() + '_MAP_PLAN')
        return joined, os.dup(sender_fd), actual
    finally:
        os.close(sender_fd)

_VERIFIED_CAPABILITY = object()


class _VerifiedGeneration:
    """Same-Guardian-process result of the complete independent verification."""
    def __init__(self, *, result, anchor, reader_cache, joined, actual, sender_pidfd, capability):
        nl_check = capability is _VERIFIED_CAPABILITY
        if not nl_check:
            raise RuntimeError('PRIVATE_VERIFIED_GENERATION_CONSTRUCTOR')
        self.result = json.loads(json.dumps(result))
        self.anchor = json.loads(json.dumps(anchor))
        self.reader_cache = reader_cache
        self.joined = dict(joined)
        self.actual = {k: tuple((bytes(key), int(deadline)) for key, deadline in rows)
                       for k, rows in actual.items()}
        self.sender_pidfd = sender_pidfd
        self.guardian_pid = os.getpid()
        self.capability = capability

    def close(self):
        if self.sender_pidfd is not None:
            os.close(self.sender_pidfd)
            self.sender_pidfd = None


def verify_and_seal(*, result, anchor, plan, receipt_dir, reader_cache,
                    nl, sources, transition, coverage, probe_path, probe_sha256):
    joined, fd, actual = verify_generation(result=result, anchor=anchor, plan=plan,
        receipt_dir=receipt_dir, reader_cache=reader_cache, nl=nl, sources=sources,
        transition=transition, coverage=coverage, probe_path=probe_path, probe_sha256=probe_sha256)
    try:
        return _VerifiedGeneration(result=result, anchor=anchor, reader_cache=reader_cache,
            joined=joined, actual=actual, sender_pidfd=fd, capability=_VERIFIED_CAPABILITY)
    except BaseException:
        os.close(fd)
        raise
