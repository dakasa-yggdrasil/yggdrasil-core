"""LAB candidate emitter; not wired into a service or authorized for production.

The original sender holds FD custody and persists intent before a distinct
netlink batch. Ambiguous send/ACK moves to HOLD and cannot be retried. A
separate authenticated Guardian must verify the original receipt before the
previous FDs can be retired; the fixture-only confirmation below is not that
operational contract. Recovery, legacy termination and live lease remain external.
"""
import base64
import copy
import hashlib
import json
import os
import socket
import struct
import time
from pathlib import Path

import guarded_nl as n
import nft_owner as nft
import native_structure as structure
import guarded_sender_session_DRAFT as sender_protocol


class GenerationEmitter:
    def __init__(self, *, initial_raw, transition, receipt_dir, host_netns, recover_fixture=False):
        # Disposable CI clone only. The LAB source's fixed boot does not exist
        # on an ephemeral runner; require a distinct inherited network ns.
        n.check(os.environ.get('CI_GUARDED_FIXTURE') == '1' and os.geteuid() == 0,
                'EXACT_DISPOSABLE_CI_FIXTURE_REQUIRED')
        n.check(os.readlink('/proc/self/ns/net') != host_netns, 'PRIVATE_LAB_NETNS_REQUIRED')
        self.pid = os.getpid()
        self.pin = transition.OriginalPin(initial_raw)
        self.transition = transition
        self.receipt_dir = Path(receipt_dir)
        n.check(self.receipt_dir.is_dir() and not self.receipt_dir.is_symlink(),
                'PRIVATE_LAB_RECEIPT_DIRECTORY')
        self.nl = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, 12)
        self.nl.bind((0, 0))
        self.nl.settimeout(5)
        self.state = 'READY'
        self.counter = 100 if recover_fixture else 0
        self.has_gates = False
        try:
            if recover_fixture:
                first = n.genid(self.nl)
                current = n.rules(self.nl, 'admit_deadline')
                handles = [struct.unpack('>Q', dict((k & 0x3fff, v) for k, v in fields)[3])[0]
                           for fields, _ in current]
                raw = n.cmd('/usr/sbin/nft', '-a', '-j', 'list', 'ruleset')
                owned, _ = structure._objects(raw)
                chains = [r['chain']['handle'] for r in owned
                          if 'chain' in r and r['chain']['name'] == 'admit_deadline']
                n.check(len(handles) == 2 and len(chains) == 1, 'RECOVERY_COMPLETE_50_ONLY')
                transition.verify_guarded(self.pin, raw, observed_chain_handle=chains[0],
                                          observed_rule_handles=tuple(handles))
                n.check(n.genid(self.nl) == first, 'RECOVERY_SAME_GENERATION_SNAPSHOT')
                self.has_gates = True
        except BaseException:
            self.nl.close()
            raise
        self.old = []
        self.held = []
        self.pending = []
        self.receipt = None
        self.active_receipt = None

    @staticmethod
    def _close(records):
        for rec in records:
            os.close(rec['program_fd'])
            os.close(rec['map_fd'])
        records.clear()

    def submit(self, plan, records, *, original_lease=None, original_owner=None, transition_origin=None, guardian_session=None, guarded_lease=None, guarded_owner=None, guarded_pin=None, sender_session=None, sender_permit=None, drain_permit=None, emergency_permit=None):
        """Take ownership of two FD pairs; never replay after a possible send."""
        n.check(self.state == 'READY' and self.pid == os.getpid(), 'ONLY_READY_SAME_OWNER')
        import drain_marker_v3_DRAFT as drain_v3
        denied_plan=not plan['backends'] and not plan['cores'] and not plan['prom']
        if denied_plan:
            n.check(drain_permit is None,'NO_POSITIVE_PERMIT_FOR_EMERGENCY')
            drain_v3.authorize_emergency(emergency_permit,plan,self.nl,consume=False)
        else:
            n.check(emergency_permit is None,'NO_EMERGENCY_PERMIT_FOR_POSITIVE')
            drain_v3.authorize_positive(drain_permit,plan)
        lease_mode = original_lease is not None or original_owner is not None or transition_origin is not None
        guarded_mode = guarded_lease is not None or guarded_owner is not None or guarded_pin is not None
        n.check(not (lease_mode and guarded_mode), 'ONE_GUARDED_OR_ORIGINAL_LEASE_MODE')
        attempt_started = time.monotonic()
        if guarded_mode:
            n.check(self.has_gates and type(guarded_pin) is structure._GuardedStructure
                    and guarded_pin.capability is structure._CAPABILITY and guarded_pin.pid == self.pid
                    and guarded_pin.emitter is self and self.active_receipt == guarded_pin.receipt
                    and type(guarded_owner) is structure._OwnershipReader
                    and guarded_owner._pin is guarded_pin and type(guarded_lease) is structure._Lease
                    and guarded_lease.reader is guarded_owner,
                    'EXACT_ORIGINAL_GUARDED_LEASE_AND_PIN_REQUIRED')
            structure._lab_guardian_alive(guarded_pin.session)
        if lease_mode:
            n.check(not self.has_gates and type(transition_origin) is structure._GuardedTransitionOrigin
                    and transition_origin._capability is structure._CAPABILITY
                    and transition_origin._pid == self.pid and not transition_origin._consumed
                    and type(original_owner) is structure._OwnershipReader
                    and original_owner._pin is transition_origin._pin
                    and type(original_lease) is structure._Lease
                    and original_lease.reader is original_owner,
                    'EXACT_ORIGINAL_47_LEASE_AND_ORIGIN_REQUIRED')
            n.check(self.transition.OriginalPin(transition_origin._raw).digest == self.pin.digest,
                    'EMITTER_ORIGINAL_PIN_EQUALS_SAME_PROCESS_ORIGIN')
        n.check(type(records) is list and len(records) == 2, 'EXACT_TWO_PROGRAMS_REQUIRED')
        n.check(len({v['program_id'] for v in records}) == 2
                and len({v['map_id'] for v in records}) == 2
                and len({v[k] for v in records for k in ('program_fd', 'map_fd')}) == 4,
                'DISTINCT_OWNER_PROGRAMS_MAPS_AND_FDS')
        self.pending = records
        self.state = 'BUILDING'
        possible_send = False
        ack = {}
        try:
            n.check(type(plan) is dict and set(plan['maps']) == {'inbound', 'reverse'}, 'EXACT_MAP_GROUPS')
            now = time.monotonic_ns()
            denied = not plan['backends'] and not plan['cores'] and not plan['prom']
            requires_sender = self.has_gates and not denied
            if requires_sender:
                n.check(type(sender_session) is sender_protocol.SenderSession
                        and type(sender_permit) is sender_protocol._Permit,
                        'EXACT_GUARDIAN_SENDER_PERMIT_REQUIRED_BY_EMITTER')
            else:
                n.check(sender_session is None and sender_permit is None,
                        'NO_POSITIVE_PERMIT_FOR_BOOTSTRAP_OR_DENY')
            for name, rec in zip(('inbound', 'reverse'), self.pending):
                actual = n.map_rows(rec['map_id'])
                wanted = [(bytes.fromhex(k), v) for k, v in plan['maps'][name]]
                n.check(len(actual) == len(wanted) and set(actual) == set(wanted), 'MAP_EQUALS_PLAN')
                n.check(all(v == 1 if denied else v > now for _, v in wanted), 'MAP_DEADLINE_AT_SEND')
                fi = n.fdinfo(self.pid, rec['map_fd'])
                n.check(int(fi['map_id']) == rec['map_id'] and fi['frozen'].strip() == '1', 'FROZEN_OWNER_MAP')
                n.check(int(n.fdinfo(self.pid, rec['program_fd'])['prog_id']) == rec['program_id'], 'OWNER_PROGRAM_FD')
            g = n.genid(self.nl)
            if guarded_mode:
                n.check(g == guarded_pin.receipt['after'], 'GUARDED_LEASE_GENERATION_REQUIRED')
            if guardian_session is not None:
                n.check(lease_mode and type(guardian_session) is structure._GuardedGuardianSession
                        and guardian_session.capability is structure._CAPABILITY
                        and guardian_session.origin is transition_origin and not guardian_session.used
                        and guardian_session.genid == g, 'GUARDIAN_ORIGINAL_47_GENERATION_REQUIRED')
                structure._lab_guardian_alive(guardian_session)
            parts = []
            seq = 101
            def push(make):
                nonlocal seq
                parts.append(make(seq))
                seq += 1
            if not self.has_gates:
                prior = [row for row, raw in n.rules(self.nl, 'forward_guard') if b'admit_new\0' in raw]
                n.check(len(prior) == 3, 'THREE_ORIGINAL_JUMPS')
                push(lambda q: n.msg((10 << 8) | 3, 1 | 4 | 0x400 | 0x200, q,
                    struct.pack('>BBH', 1, 0, 0) + n.attr(1, b'dakasa_capacity_network\0')
                    + n.attr(3, b'admit_deadline\0')))
            else:
                current = n.rules(self.nl, 'admit_deadline')
                n.check(len(current) == 2, 'TWO_OLD_GATES')
                for fields, _ in current:
                    h = dict((k & 0x3fff, v) for k, v in fields)[3]
                    push(lambda q, h=h: n.msg((10 << 8) | 8, 1 | 4, q,
                        struct.pack('>BBH', 1, 0, 0) + n.attr(1, b'dakasa_capacity_network\0')
                        + n.attr(2, b'admit_deadline\0') + n.attr(3, h)))
            for rec in self.pending:
                push(lambda q, rec=rec: n.xtjump(rec['program_fd'], q))
            if not self.has_gates:
                for fields in prior:
                    push(lambda q, fields=fields: n.replace_jump(fields, q))
            for name in ('core_ready4', 'prometheus_ready4', 'backend_forward4', 'backend_dnat4'):
                push(lambda q, name=name: n.flush(name, q))
            now = time.monotonic_ns()
            ip = socket.inet_aton
            port = lambda value: struct.pack('>H', int(value)) + bytes(2)
            entries, forward = [], []
            for value in plan['backends']:
                ttl = (value['deadline'] - now) // 1_000_000 - 750
                n.check(ttl > 0, 'LIVE_BACKEND_TTL')
                vip, vport = nft.VIP_PORTS[value['kind']]
                key = ip(vip) + port(vport)
                dest = ip(value['address']) + port(value['port'])
                entries.append(n.element(key, ttl, dest))
                forward.append(n.element(key + dest, ttl))
            def source_entry(value):
                ttl = (value['deadline'] - now) // 1_000_000 - 750
                n.check(ttl > 0, 'LIVE_SOURCE_TTL')
                return n.element(ip(value['address']), ttl)
            cores = [source_entry(x) for x in plan['cores']]
            prom = [source_entry(x) for x in plan['prom']]
            for name, values in (('core_ready4', cores), ('prometheus_ready4', prom),
                                 ('backend_forward4', forward), ('backend_dnat4', entries)):
                if values:
                    push(lambda q, name=name, values=values: n.add(name, values, q))
            payload = n.begin(g, 100) + b''.join(parts) + n.end(seq)
            self.counter += 1
            intent = {'schema': 'lab_real_reader_rotation_intent_v1', 'pid': self.pid,
                'start_ticks': n.startticks(self.pid),
                'boot_id': Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
                'netns': os.readlink('/proc/self/ns/net'), 'genid': g, 'programs': self.pending,
                'ack_sequences': list(range(101, seq)), 'wire_sha256': hashlib.sha256(payload).hexdigest(),
                'no_retry': True}
            stem = '%03d' % self.counter
            n.durable(self.receipt_dir / ('WIRE-' + stem + '.bin'), payload)
            n.durable(self.receipt_dir / ('INTENT-' + stem + '.json'), n.canon(intent))
            inject = os.environ.get('LAB_INJECT_ROTATION_CRASH') if self.counter == 2 else None
            if inject is not None:
                n.check(os.environ.get('LAB_ENABLE_CRASH_TEST') == '1', 'LAB_CRASH_TEST_NOT_ENABLED')
            if inject == 'before_send':
                os._exit(71)
            if guarded_mode:
                structure.consume_lab_guarded_ownership(guarded_lease.token, guarded_pin, .750)
                n.check(0 <= time.monotonic() - attempt_started < .250,
                        'GUARDED_250MS_BEFORE_SEND_NOT_EXTENDED')
                guarded_owner.permit_original_send(guarded_lease, attempt_started)
            if lease_mode:
                if guardian_session is not None:
                    structure._lab_guardian_alive(guardian_session)
                nft._consume_ownership(original_lease.token, .750)
                n.check(0 <= time.monotonic() - attempt_started < .250,
                        'ORIGINAL_250MS_BEFORE_SEND_NOT_EXTENDED')
                original_owner.permit_original_send(original_lease, attempt_started)
                transition_origin._consumed = True
            if requires_sender:
                n.check(sender_session.consume(sender_permit, self.pending)['lab_sender_permit_consumed'],
                        'ORIGINAL_GUARDIAN_SENDER_PERMIT_CONSUMED_AT_DISPATCH')
                n.check(time.monotonic_ns() < sender_permit.deadline_ns,
                        'ORIGINAL_SENDER_PERMIT_DEADLINE_AT_DISPATCH')
            # Enforce the marker and exact generation immediately before
            # the only native send. No marker is removed by this operation.
            if denied_plan:
                drain_v3.authorize_emergency(emergency_permit,plan,self.nl,consume=True)
            else:
                n.check(n.genid(self.nl)==g,'GUARDED_DRAIN_SAME_GENERATION_AT_SEND')
                drain_v3.authorize_positive(drain_permit,plan,consume=True,emitter=self,genid=g)
            if guarded_mode or lease_mode:
                n.check(0 <= time.monotonic() - attempt_started < .250,
                        'GUARDED_DRAIN_250MS_BEFORE_SEND_NOT_EXTENDED')
            send_started = time.monotonic_ns()
            possible_send = True
            self.state = 'SEND_UNCERTAIN'
            n.check(self.nl.send(payload) == len(payload), 'WHOLE_NETLINK_DATAGRAM_SENT')
            send_returned = time.monotonic_ns()
            if guarded_mode:
                n.check(0 <= send_returned / 1e9 - attempt_started < .250,
                        'GUARDED_250MS_SEND_RETURN_NOT_EXTENDED')
            if lease_mode:
                n.check(0 <= send_returned / 1e9 - attempt_started < .250,
                        'ORIGINAL_250MS_SEND_RETURN_NOT_EXTENDED')
            if inject == 'after_send':
                os._exit(72)
            expected = set(range(101, seq))
            ack_raw = []
            while set(ack) != expected:
                raw = self.nl.recv(65536)
                ack_raw.append(base64.b64encode(raw).decode())
                for typ, number, data in n.packets(raw):
                    n.check(typ == 2 and number in expected and number not in ack and len(data) >= 4, 'ACK_SHAPE')
                    ack[number] = struct.unpack_from('<i', data)[0]
                    n.check(ack[number] == 0, 'ACK_FAILED_SEQUENCE_%s_ERRNO_%s' % (number,ack[number]))
            current = n.rules(self.nl, 'admit_deadline')
            handles = [struct.unpack('>Q', dict((k & 0x3fff, v) for k, v in fields)[3])[0]
                       for fields, _ in current]
            n.check(len(handles) == 2, 'TWO_NEW_GATES')
            raw = n.cmd('/usr/sbin/nft', '-a', '-j', 'list', 'ruleset')
            owned, _ = structure._objects(raw)
            chain = [r['chain']['handle'] for r in owned if 'chain' in r and r['chain']['name'] == 'admit_deadline']
            n.check(len(chain) == 1, 'ONE_GATE_CHAIN')
            self.transition.verify_guarded(self.pin, raw, observed_chain_handle=chain[0],
                                           observed_rule_handles=tuple(handles))
            stale = n.begin(g, 800) + n.flush('core_ready4', 801) + n.end(802)
            n.check(self.nl.send(stale) == len(stale), 'STALE_TEST_DATAGRAM_SENT')
            reply = n.packets(self.nl.recv(8192))
            n.check(len(reply) == 1 and reply[0][1] == 800
                    and struct.unpack_from('<i', reply[0][2])[0] == -85, 'STALE_GENID_NOT_REJECTED')
            receipt = {'schema': 'lab_real_reader_rotation_ack_v1', 'pid': self.pid,
                'start_ticks': n.startticks(self.pid), 'intent_sha256': hashlib.sha256(n.canon(intent)).hexdigest(),
                'genid': g, 'after': n.genid(self.nl), 'programs': self.pending, 'handles': handles,
                'chain': chain[0], 'wire_sha256': hashlib.sha256(payload).hexdigest(), 'ack': ack_raw,
                'ack_sequences': sorted(ack), 'stale_code': -85, 'send_started_ns': send_started,
                'send_returned_ns': send_returned}
            if lease_mode:
                receipt.update(original_47_lease_used=True,
                               original_47_origin_sha256=transition_origin._raw_sha256,
                               original_47_lease_returned_ns=int(original_lease.token.returned * 1e9))
            if guarded_mode:
                receipt.update(guarded_lease_used=True,
                               guarded_previous_receipt_sha256=hashlib.sha256(n.canon(guarded_pin.receipt)).hexdigest(),
                               guarded_lease_returned_ns=int(guarded_lease.token.returned * 1e9))
            n.durable(self.receipt_dir / ('ACK-' + stem + '.json'), n.canon(receipt))
            self.receipt = receipt
            self.has_gates = True
            self.state = 'AWAITING_FIXTURE_VERIFICATION'
            if inject == 'after_ack':
                os._exit(73)
            return {'ok': True, 'counter': self.counter, **receipt}
        except BaseException:
            if possible_send:
                self.state = 'HOLD_UNKNOWN_OR_UNVERIFIED'
            else:
                self._close(self.pending)
                self.state = 'READY'
            raise

    def activate_lab_guarded_pin(self, pin):
        """Fixture-only promotion after the authenticated Guardian attestation."""
        n.check(type(pin) is structure._GuardedStructure and pin.capability is structure._CAPABILITY
                and pin.emitter is self and self.state == 'AWAITING_FIXTURE_VERIFICATION'
                and self.receipt == pin.receipt and pin.session.used,
                'AUTHENTICATED_LAB_GUARDED_PIN_REQUIRED')
        structure._lab_guardian_alive(pin.session)
        self._close(self.old)
        self._close(self.held)
        self.old, self.pending = self.pending, []
        self.active_receipt = copy.deepcopy(self.receipt)
        self.receipt = None
        self.state = 'READY'

    def deny_after_unverified_fixture(self, plan, records):
        """LAB emergency replacement while the prior ACK lacks Guardian verification.

        Keep every prior FD until the distinct deny transaction is acknowledged.
        This is not an operational Guardian protocol or crash recovery.
        """
        n.check(self.state == 'AWAITING_FIXTURE_VERIFICATION', 'UNVERIFIED_ACK_REQUIRED')
        n.check(not plan['backends'] and not plan['cores'] and not plan['prom']
                and set(plan['maps']) == {'inbound', 'reverse'}
                and all(plan['maps'][role] and all(v == 1 for _, v in plan['maps'][role])
                        for role in ('inbound', 'reverse')), 'ONLY_EXPIRED_DENY_MAPS')
        self.held.extend(self.old)
        self.old = self.pending
        self.pending = []
        self.receipt = None
        self.state = 'READY'
        try:
            return self.submit(plan, records)
        except BaseException:
            self.state = 'HOLD_UNKNOWN_OR_UNVERIFIED'
            raise

    def confirm_fixture_only(self, receipt):
        """Not an operational Guardian acceptance mechanism."""
        n.check(self.state == 'AWAITING_FIXTURE_VERIFICATION' and receipt == self.receipt,
                'FIXTURE_ORIGINAL_RECEIPT_REQUIRED')
        self._close(self.old)
        self._close(self.held)
        self.old, self.pending = self.pending, []
        self.receipt = None
        self.state = 'READY'

    def close_private_fixture(self):
        """Discard only after fixture teardown; uncertain live state needs recovery."""
        self._close(self.pending)
        self._close(self.old)
        self._close(self.held)
        self.nl.close()
        self.state = 'CLOSED'
