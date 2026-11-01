"""LAB-only authenticated Guardian lease, never an external-effect grant.

The socket's actual root peer is the holder; no PID or map content is accepted
on assertion. Incompatible refresh is denied before send, and Reader/holder
failure or the original deadline must revoke the fixture lease before observation.
Remote effects still require an independently enforced point-of-effect fence.
"""
import ctypes
import hashlib
import os
import select
import secrets
import socket
import struct
import threading
import time
import weakref


class Held(Exception):
    pass

class BusyBeforeRenew(Exception):
    """No renewal or new sender effect was performed."""
    pass


def need(value, reason):
    if not value:
        raise Held(reason)


class _OwnedPidfd:
    """One generation owns one duplicate; a lease snapshot retains its owner."""
    def __init__(self, fd):
        self.fd = fd

    def close(self):
        if self.fd is not None:
            fd, self.fd = self.fd, None
            os.close(fd)

    def __del__(self):
        self.close()


class EffectLeaseAuthority:
    # CI-only hard stop until per-generation readers have explicit custody.
    MAX_OWNED_SENDER_PIDFDS = 64

    def _require_sender_fd_capacity_locked(self):
        need(len(self._owned_sender_pidfds) < self.MAX_OWNED_SENDER_PIDFDS,
             'HOLDER_SENDER_PIDFD_CAPACITY_EXHAUSTED')

    def __init__(self, channel, *, cache, sources, nl, verifier, current15, preparer_channel=None, program_reference=None):
        need(type(channel) is socket.socket, 'ORIGINAL_CONTROL_SOCKET_REQUIRED')
        peer, uid, _ = struct.unpack('3i', channel.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
        need(uid == 0 and peer > 1, 'ROOT_ORIGINAL_SUPERVISOR_PEER_REQUIRED')
        self.channel, self.peer, self.peer_ticks = channel, peer, nl.startticks(peer)
        self.peer_pidfd = os.pidfd_open(peer, 0)
        self.preparer_pidfd = None
        try:
            poll = select.poll();poll.register(self.peer_pidfd, select.POLLIN)
            need(not poll.poll(0) and nl.startticks(peer) == self.peer_ticks, 'SAME_ORIGINAL_SUPERVISOR_AFTER_PIDFD')
            self.preparer_channel = preparer_channel
            self.preparer_pidfd = None
            if preparer_channel is None:
                self.preparer, self.preparer_ticks = peer, self.peer_ticks
            else:
                need(type(preparer_channel) is socket.socket and preparer_channel is not channel,
                     'DISTINCT_ORIGINAL_PREPARER_CHANNEL_REQUIRED')
                preparer, prep_uid, _ = struct.unpack('3i', preparer_channel.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
                need(prep_uid == 0 and preparer > 1 and preparer != peer, 'DISTINCT_ROOT_PREPARER_REQUIRED')
                self.preparer, self.preparer_ticks = preparer, nl.startticks(preparer)
                self.preparer_pidfd = os.pidfd_open(preparer, 0)
                poll = select.poll();poll.register(self.preparer_pidfd, select.POLLIN)
                need(not poll.poll(0) and nl.startticks(preparer) == self.preparer_ticks,
                     'SAME_ORIGINAL_PREPARER_AFTER_PIDFD')
        except BaseException:
            if self.preparer_pidfd is not None:os.close(self.preparer_pidfd)
            os.close(self.peer_pidfd)
            raise
        self.cache, self.sources, self.nl, self.verifier, self.current15 = cache, sources, nl, verifier, current15
        self.program_reference = program_reference
        self.pid = os.getpid()
        self.lock = threading.Lock()
        self.lease = None
        self.pending = None
        # Weak references enforce a cap without retaining retired generations.
        # Every live lease snapshot holds its generation's owner strongly.
        self._owned_sender_pidfds = weakref.WeakSet()

    def _duplicate_sender_locked(self, fd):
        self._require_sender_fd_capacity_locked()
        owner = _OwnedPidfd(os.dup(fd))
        self._owned_sender_pidfds.add(owner)
        return owner

    def _peer_live(self):
        p = select.poll();p.register(self.peer_pidfd, select.POLLIN)
        need(not p.poll(0) and self.nl.startticks(self.peer) == self.peer_ticks, 'ORIGINAL_SUPERVISOR_MUST_BE_LIVE')
        if self.preparer_pidfd is not None:
            p = select.poll();p.register(self.preparer_pidfd, select.POLLIN)
            need(not p.poll(0) and self.nl.startticks(self.preparer) == self.preparer_ticks,
                 'ORIGINAL_PREPARER_MUST_BE_LIVE')
        need(self.pid == os.getpid(), 'SAME_GUARDIAN_PROCESS_REQUIRED')

    def _source_live(self, lease):
        now = time.monotonic_ns()
        need(now < lease['until'], 'FIXTURE_LEASE_EXPIRED')
        self._peer_live()
        poll = select.poll();poll.register(lease['sender_pidfd'].fd, select.POLLIN)
        need(not poll.poll(0), 'ORIGINAL_SENDER_MUST_REMAIN_LIVE')
        current = self.sources.build_expected(self.cache)
        need(current['invalidation_epoch'] == lease['invalidation_epoch'], 'READER_INVALIDATION_REVOKES_LEASE')
        for role in ('inbound', 'reverse'):
            need(set(current[role]) == set(lease['maps'][role]), 'SOURCE_TUPLE_CHANGE_REVOKES_LEASE')
            need(all(current[role][key] >= lease['until'] for key in lease['maps'][role]),
                 'SOURCE_DEADLINE_SHORTER_THAN_LEASE')
        return current

    def acquire(self, verified, chain, requested_until_ns):
        now = time.monotonic_ns()
        need(type(verified) is self.verifier._VerifiedGeneration
             and verified.capability is self.verifier._VERIFIED_CAPABILITY
             and verified.guardian_pid == self.pid and verified.reader_cache is self.cache
             and verified.sender_pidfd is not None, 'ORIGINAL_VERIFIED_GENERATION_REQUIRED')
        need(type(chain) is self.current15.CoverageChain and chain.cache is self.cache
             and chain.pid == self.pid and chain.verifier is self.verifier
             and chain.last_verified is verified and chain.last_observation is not None,
             'ORIGINAL_GUARDIAN_COVERAGE_CHAIN_REQUIRED')
        qualified, start, observed, deadline, epoch, genid, receipt_hash = chain.last_observation
        need(qualified is True and observed - start >= 15_000_000_000 and now < deadline
             and chain.genid == genid and chain.epoch == epoch and chain.deadline_ns == deadline,
             'ORIGINAL_CURRENT15_AND_KERNEL_MUST_BE_LIVE')
        need(type(requested_until_ns) is int and now < requested_until_ns <= now + 5_000_000_000,
             'BOUNDED_LAB_LEASE_REQUEST')
        receipt = {k: v for k, v in verified.result.items() if k not in ('ok', 'counter')}
        need(hashlib.sha256(self.nl.canon(receipt)).hexdigest() == receipt_hash
             and verified.result['after'] == genid, 'EXACT_VERIFIED_EPOCH_REQUIRED')
        poll = select.poll();poll.register(verified.sender_pidfd, select.POLLIN)
        need(not poll.poll(0), 'ORIGINAL_SENDER_MUST_BE_LIVE')
        maps = {role: dict(verified.actual[role]) for role in ('inbound', 'reverse')}
        until = min(requested_until_ns, deadline)
        need(now < until and all(deadline >= until for rows in maps.values() for deadline in rows.values()),
             'ALL_ORIGINAL_TUPLES_MUST_COVER_LEASE')
        with self.lock:owned_fd=self._duplicate_sender_locked(verified.sender_pidfd)
        lease = {'token': secrets.token_hex(32), 'until': until, 'epoch': genid,
                 'receipt_sha256': receipt_hash, 'invalidation_epoch': epoch,
                 'maps': maps, 'sender_pidfd': owned_fd, 'revoked': False}
        try:
            self._source_live(lease)
            with self.lock:
                need(self.lease is None, 'ONE_OUTSTANDING_EFFECT_LEASE')
                self.lease = lease
        except BaseException:
            owned_fd.close();raise
        return {'token': lease['token'], 'expires_monotonic_ns': until, 'genid': lease['epoch'],
                'receipt_sha256': lease['receipt_sha256'], 'lab_only': True,
                'external_effect_authorized': False, 'production_authority': False}

    def renew(self, token, verified, chain, requested_until_ns, live):
        """CI-only: extend only on the same live confirmed Guardian generation."""
        lease=self._require_lease(token);now=time.monotonic_ns()
        need(type(verified) is self.verifier._VerifiedGeneration
             and verified.capability is self.verifier._VERIFIED_CAPABILITY
             and verified.guardian_pid==self.pid and verified.reader_cache is self.cache
             and verified.sender_pidfd is not None, 'ORIGINAL_VERIFIED_GENERATION_REQUIRED')
        need(type(chain) is self.current15.CoverageChain and chain.cache is self.cache
             and chain.pid==self.pid and chain.verifier is self.verifier
             and chain.last_verified is verified and chain.last_observation is not None,
             'ORIGINAL_GUARDIAN_COVERAGE_CHAIN_REQUIRED')
        qualified,start,observed,deadline,epoch,genid,receipt_hash=chain.last_observation
        need(qualified is True and observed-start>=15_000_000_000 and now<deadline
             and chain.genid==genid==lease['epoch'] and chain.epoch==epoch==lease['invalidation_epoch']
             and chain.deadline_ns==deadline and receipt_hash==lease['receipt_sha256'],
             'SAME_CONTINUOUS_VERIFIED_LEASE_GENERATION_REQUIRED')
        need(type(requested_until_ns) is int and now<requested_until_ns<=now+5_000_000_000,
             'BOUNDED_LAB_LEASE_REQUEST')
        obs=live['observation']
        need(live.get('invalidation_epoch')==epoch and obs['genid']==genid
             and obs['receipt_sha256']==receipt_hash, 'LIVE_KERNEL_AND_SOURCE_REQUIRED_FOR_RENEW')
        until=min(requested_until_ns,deadline,obs['kernel_min_deadline_ns'])
        maps={role:dict(verified.actual[role]) for role in ('inbound','reverse')}
        need(until>lease['until'] and all(set(maps[role])==set(lease['maps'][role])
             and all(expiry>=until for expiry in maps[role].values()) for role in maps),
             'RENEWED_LEASE_MUST_BE_COVERED')
        current=self._source_live(lease)
        need(all(all(current[role][key]>=until for key in maps[role]) for role in maps),
             'RENEWAL_EXCEEDS_CURRENT_SOURCE_DEADLINE')
        with self.lock:
            need(self.lease is lease and not lease['revoked'] and time.monotonic_ns()<lease['until'],
                 'PREVIOUS_LEASE_MUST_STILL_BE_LIVE')
            renewed=dict(lease);renewed['until']=until;self.lease=renewed
        return {'token':renewed['token'],'expires_monotonic_ns':until,'genid':genid,
                'lab_only':True,'external_effect_authorized':False,'production_authority':False}

    def _require_lease(self, token):
        with self.lock:
            lease = self.lease
            need(lease is not None and not lease['revoked'] and secrets.compare_digest(token, lease['token']),
                 'LIVE_AUTHENTICATED_FIXTURE_LEASE_REQUIRED')
        self._source_live(lease)
        return lease

    def status(self, token):
        lease = self._require_lease(token)
        with self.lock:
            need(self.lease is lease and not lease['revoked'] and self.pending is None,
                 'LIVE_LEASE_AND_NO_UNVERIFIED_SUCCESSOR')
        return {'valid': True, 'genid': lease['epoch'], 'expires_monotonic_ns': lease['until'],
                'external_effect_authorized': False}

    def prepare_successor(self, token, records, before, *, current_genid):
        """Verify preparer's actual frozen FDs before any netlink send."""
        lease = self._require_lease(token)
        need(type(records) is list and len(records) == 2
             and type(before) is self.current15._BeforeSend and before.capability is self.current15._CAPABILITY
             and before.cache is self.cache
             and before.pid == self.pid and before.epoch == lease['invalidation_epoch']
             and not before.consumed and current_genid == lease['epoch'], 'SAME_LIVE_EPOCH_AND_SOURCE_SNAPSHOT')
        expected = self.sources.build_expected(self.cache)
        need(expected['invalidation_epoch'] == before.epoch, 'SOURCE_INVALIDATED_DURING_PREPARE')
        need(self.program_reference is not None, 'INDEPENDENT_GUARDIAN_PROGRAM_REFERENCE_REQUIRED')
        ids = []
        for role, rec in zip(('inbound', 'reverse'), records):
            pinfo = self.nl.fdinfo(self.preparer, rec['program_fd'])
            minfo = self.nl.fdinfo(self.preparer, rec['map_fd'])
            need(int(pinfo['prog_id']) == rec['program_id'] and int(minfo['map_id']) == rec['map_id']
                 and minfo['frozen'].strip() == '1', 'PREPARER_LIVE_FROZEN_FDS_REQUIRED')
            pi = self.nl.ProgInfo();mi_ids=(ctypes.c_uint32*8)();pi.nr_map_ids=8;pi.map_ids=ctypes.addressof(mi_ids)
            fd = self.nl.bpf(13, struct.pack('<I', rec['program_id']))
            try:
                self.nl.info(fd, pi)
                need(pi.id == rec['program_id'] and pi.nr_map_ids == 1 and mi_ids[0] == rec['map_id'],
                     'PREPARED_PROGRAM_MAP_BINDING')
            finally:
                os.close(fd)
            self.program_reference.verify(rec['program_id'],rec['map_id'])
            rows = self.nl.map_rows(rec['map_id']);maps = dict(rows)
            need(len(maps) == len(rows) and set(maps) == set(before.expected[role])
                 and set(maps) == set(expected[role]) and set(maps) == set(lease['maps'][role]),
                 'SAME_ALL_REQUIRED_TUPLES')
            need(all(lease['until'] <= expiry <= before.expected[role][key]
                     and expiry <= expected[role][key] for key, expiry in maps.items()),
                 'SUCCESSOR_MUST_PRESERVE_LEASE_WITHIN_ORIGINAL_WITNESSES')
            ids.append((rec['program_id'], rec['map_id']))
        need(len(set(ids)) == 2, 'DISTINCT_SUCCESSOR_PROGRAMS')
        self._source_live(lease)
        self._peer_live()
        with self.lock:
            need(self.lease is lease and not lease['revoked'] and self.pending is None, 'ONE_PENDING_SUCCESSOR')
            self.pending = {'ids': tuple(ids), 'genid': current_genid}
        return {'prepared': True, 'genid': current_genid, 'expires_monotonic_ns': lease['until'],
                'approved_ids': ids, 'external_effect_authorized': False}

    def prepare_from_preparer(self, channel, records, before, *, current_genid):
        need(self.preparer_channel is not None and channel is self.preparer_channel,
             'ONLY_ORIGINAL_AUTHENTICATED_PREPARER_CHANNEL')
        with self.lock:
            lease = self.lease
            need(lease is not None and not lease['revoked'], 'LIVE_HOLDER_LEASE_REQUIRED')
            token = lease['token']
        return self.prepare_successor(token, records, before, current_genid=current_genid)

    def confirm_from_preparer(self, channel, verified, chain):
        need(self.preparer_channel is not None and channel is self.preparer_channel,
             'ONLY_ORIGINAL_AUTHENTICATED_PREPARER_CHANNEL')
        with self.lock:
            lease = self.lease
            need(lease is not None and not lease['revoked'], 'LIVE_HOLDER_LEASE_REQUIRED')
            token = lease['token']
        return self.confirm_successor(token, verified, chain)

    def confirm_successor(self, token, verified, chain):
        lease = self._require_lease(token)
        need(type(verified) is self.verifier._VerifiedGeneration
             and verified.capability is self.verifier._VERIFIED_CAPABILITY and verified.sender_pidfd is not None
             and verified.guardian_pid == self.pid and verified.reader_cache is self.cache,
             'OWN_VERIFIED_SUCCESSOR_REQUIRED')
        need(type(chain) is self.current15.CoverageChain and chain.cache is self.cache
             and chain.verifier is self.verifier and chain.pid == self.pid and chain.last_verified is verified
             and chain.last_observation is not None, 'ORIGINAL_SUCCESSOR_CHAIN_REQUIRED')
        qualified, start, observed, deadline, epoch, genid, receipt_hash = chain.last_observation
        result = verified.result
        receipt = {k:v for k,v in result.items() if k not in ('ok', 'counter')}
        need(hashlib.sha256(self.nl.canon(receipt)).hexdigest() == receipt_hash, 'SUCCESSOR_RECEIPT_BINDING')
        with self.lock:
            pending = self.pending
        need(pending is not None and result['genid'] == pending['genid']
             and tuple((v['program_id'], v['map_id']) for v in result['programs']) == pending['ids']
             and genid == result['after'], 'SAME_PREPARED_SUCCESSOR_AND_ORIGINAL_ACK')
        need(epoch == lease['invalidation_epoch'] and chain.genid == genid
             and chain.deadline_ns == deadline and deadline >= lease['until'], 'SUCCESSOR_KERNEL_DEADLINE_MUST_COVER_LEASE')
        for role in ('inbound', 'reverse'):
            maps = dict(verified.actual[role])
            need(set(maps) == set(lease['maps'][role]) and all(v >= lease['until'] for v in maps.values()),
                 'VERIFIED_SUCCESSOR_PRESERVES_ALL_TUPLES')
        self._source_live(lease)
        with self.lock:
            need(self.lease is lease and self.pending is pending and not lease['revoked'], 'SAME_PENDING_LIVE_LEASE')
            owned_fd=self._duplicate_sender_locked(verified.sender_pidfd)
            successor=dict(lease)
            successor.update({'epoch':genid,'receipt_sha256':receipt_hash,'sender_pidfd':owned_fd,
                              'maps':{role:dict(verified.actual[role]) for role in ('inbound','reverse')}})
            self.lease=successor
            self.pending = None
        return {'successor_verified': True, 'genid': genid, 'external_effect_authorized': False}

    def revoke(self):
        with self.lock:
            if self.lease is not None:
                self.lease['revoked'] = True

    def release(self, token):
        lease = self._require_lease(token)
        with self.lock:
            need(self.lease is lease and self.pending is None, 'NO_PENDING_SUCCESSOR_ON_RELEASE')
            self.lease = None
        return {'released': True, 'external_effect_authorized': False}

    def close(self):
        self.revoke()
        os.close(self.peer_pidfd)
        if self.preparer_pidfd is not None:os.close(self.preparer_pidfd)
        # A reader holding a lease snapshot keeps its generation FD alive.
        with self.lock:self.lease=None
