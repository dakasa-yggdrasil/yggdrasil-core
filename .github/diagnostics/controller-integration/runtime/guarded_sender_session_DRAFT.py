"""LAB-only sender/Guardian permit draft; not wired to a live controller.

The Guardian endpoint must independently verify Reader witnesses, frozen maps,
previous nft genid and its same-process effect lease before answering. This
module checks the sender side only: its existence or a caller-supplied answer
never establishes those Guardian-side properties or production authority.
"""
import array
import ctypes
import hashlib
import json
import os
import secrets
import select
import socket
import struct
import time
import threading
from pathlib import Path

_CAPABILITY = object()

class Held(RuntimeError):
    pass

def need(value, reason):
    if not value:raise Held(reason)

def _bind_netlink(sock):
    sock.bind((0,0));sock.settimeout(5)

def _close_netlink(sock):
    sock.close()

class _Permit:
    def __init__(self, session, genid, ids, digest, deadline_ns, epoch, capability):
        need(capability is _CAPABILITY, 'ONLY_ORIGINAL_SENDER_SESSION_PERMIT')
        self.session, self.genid, self.ids, self.digest = session, genid, ids, digest
        self.deadline_ns, self.epoch, self.pid = deadline_ns, epoch, os.getpid()
        self.capability, self.consumed = capability, False

class _PositiveAttestation:
    def __init__(self, session, receipt_sha256, genid, ids, digest, deadline_ns, source_epoch, capability):
        need(capability is _CAPABILITY and type(session) is SenderSession, 'ONLY_ORIGINAL_GUARDIAN_POSITIVE_ATTESTATION')
        self.session, self.receipt_sha256, self.genid = session, receipt_sha256, genid
        self.ids, self.digest, self.deadline_ns, self.source_epoch = ids, digest, deadline_ns, source_epoch
        self.pid, self.capability = os.getpid(), capability

class SenderSession:
    def __init__(self, channel, *, identity, guardian, nl, coord):
        need(type(channel) is socket.socket and type(guardian) is dict
             and set(guardian)=={'unit','invocation_id','argv','source_sha256'},
             'EXACT_CONNECTED_GUARDIAN_IDENTITY_REQUIRED')
        need(os.geteuid()==0 and os.environ.get('CI_GUARDED_FIXTURE')=='1'
             and os.environ.get('CI_HOST_NETNS') and os.readlink('/proc/self/ns/net')!=os.environ['CI_HOST_NETNS'],
             'ONLY_DISPOSABLE_LAB_SENDER_NETNS')
        self.channel, self.nl, self.pid, self.thread = channel, nl, os.getpid(), threading.get_ident()
        self.netns = os.readlink('/proc/self/ns/net')
        self.ticks = nl.startticks(self.pid)
        self.peer = identity.authenticate(channel,unit=guardian['unit'],
            expected_invocation=guardian['invocation_id'],expected_argv=guardian['argv'],
            source_sha256=guardian['source_sha256'],expected_uid=0)
        self.pidfd=self.peer['pidfd'];self.pending=None;self.closed=False
        self.netlink=None;self.netlink_inode=None;self.writer_lease=None
        try:
            import drain_marker_v3_DRAFT as marker
            need(type(coord) is marker.CoordinatorV3,'EXACT_SENDER_WRITER_COORDINATOR_REQUIRED')
            # A potentially writable netfilter socket may never precede SH.
            self.writer_lease=coord.acquire_writer_lease()
            self.netlink=socket.socket(socket.AF_NETLINK,socket.SOCK_RAW,12)
            self.netlink_inode=os.fstat(self.netlink.fileno()).st_ino
            _bind_netlink(self.netlink)
            # The Guardian receives this FD over the authenticated sender channel
            # and acquires its own SH on a distinct open-file-description.
            sent=self.channel.sendmsg([b'W'],[(socket.SOL_SOCKET,socket.SCM_RIGHTS,array.array('i',[self.writer_lease.validate()]))])
            need(sent==1,'EXACT_WRITER_CUSTODY_TRANSFER_REQUIRED')
        except BaseException:
            # On close failure or another live alias, keep SH held.
            try:self._close_writer_socket()
            finally:
                os.close(self.pidfd);self.pidfd=None;self.channel.close()
            raise

    def _live(self, *, require_quiet):
        need(not self.closed and os.getpid()==self.pid and threading.get_ident()==self.thread
             and os.readlink('/proc/self/ns/net')==self.netns and self.nl.startticks(self.pid)==self.ticks,
             'SAME_LIVE_SENDER_PROCESS_REQUIRED')
        poll=select.poll();poll.register(self.pidfd,select.POLLIN);poll.register(self.channel,select.POLLERR|select.POLLHUP|select.POLLIN)
        events=poll.poll(0)
        need(not any(fd==self.pidfd for fd,_ in events), 'GUARDIAN_PROCESS_TERMINATED')
        need(not any(fd==self.channel.fileno() and mask & (select.POLLERR|select.POLLHUP) for fd,mask in events),
             'GUARDIAN_CHANNEL_TERMINATED')
        if require_quiet:need(not any(fd==self.channel.fileno() and mask & select.POLLIN for fd,mask in events),
                              'PENDING_GUARDIAN_EVENT_REQUIRES_HOLD')

    def _records(self, records):
        need(type(records) is list and len(records)==2,'EXACT_TWO_ORIGINAL_FD_PAIRS')
        rows={};ids=[]
        for role,rec in zip(('inbound','reverse'),records):
            need(type(rec) is dict and all(type(rec.get(k)) is int and rec[k]>0 for k in ('program_fd','program_id','map_fd','map_id')),
                 'EXACT_PROGRAM_AND_MAP_DESCRIPTOR_FIELDS')
            p=self.nl.fdinfo(self.pid,rec['program_fd']);m=self.nl.fdinfo(self.pid,rec['map_fd'])
            need(int(p['prog_id'])==rec['program_id'] and int(m['map_id'])==rec['map_id'] and m['frozen'].strip()=='1',
                 'LIVE_SENDER_FROZEN_FD_BINDING')
            pi=self.nl.ProgInfo();array=(ctypes.c_uint32*8)();pi.nr_map_ids=8;pi.map_ids=ctypes.addressof(array)
            fd=self.nl.bpf(13,struct.pack('<I',rec['program_id']))
            try:
                self.nl.info(fd,pi)
                need(pi.id==rec['program_id'] and pi.nr_map_ids==1 and array[0]==rec['map_id'],
                     'SENDER_PROGRAM_REFERENCES_EXACT_MAP')
            finally:os.close(fd)
            actual=self.nl.map_rows(rec['map_id']);need(actual and len(dict(actual))==len(actual),'NONEMPTY_UNIQUE_ORIGINAL_MAP')
            rows[role]=[[k.hex(),v] for k,v in sorted(actual)];ids.append((rec['program_id'],rec['map_id']))
        need(len({x[0] for x in ids})==2 and len({x[1] for x in ids})==2,'DISTINCT_PROGRAM_MAP_PAIRS')
        return tuple(ids),hashlib.sha256(self.nl.canon(rows)).hexdigest()

    def _read_reply(self, until_ns):
        data=bytearray()
        while len(data)<=4096:
            self._live(require_quiet=False);remaining=until_ns-time.monotonic_ns();need(remaining>0,'GUARDIAN_PERMIT_TIMEOUT')
            poll=select.poll();poll.register(self.channel,select.POLLIN|select.POLLERR|select.POLLHUP);poll.register(self.pidfd,select.POLLIN)
            ready=poll.poll(max(1,min(5000,(remaining+999999)//1000000)));need(bool(ready),'GUARDIAN_PERMIT_TIMEOUT')
            need(not any(fd==self.pidfd for fd,_ in ready),'GUARDIAN_PROCESS_TERMINATED')
            part=self.channel.recv(1);need(bool(part),'GUARDIAN_CHANNEL_EOF')
            if part==b'\n':break
            data.extend(part)
        else:raise Held('BOUNDED_GUARDIAN_REPLY_REQUIRED')
        def pairs(items):
            out={}
            for key,value in items:need(key not in out,'NO_DUPLICATE_GUARDIAN_REPLY_KEYS');out[key]=value
            return out
        reply=json.loads(data,object_pairs_hook=pairs,parse_constant=lambda _: (_ for _ in ()).throw(Held('FINITE_JSON_REQUIRED')))
        need(type(reply) is dict,'EXACT_GUARDIAN_REPLY_REQUIRED');return reply

    def prepare(self, records, *, until_ns):
        need(self.pending is None and type(until_ns) is int and time.monotonic_ns()<until_ns<=time.monotonic_ns()+5_000_000_000,
             'ONE_BOUNDED_PENDING_SENDER_PERMIT')
        self._live(require_quiet=True);ids,digest=self._records(records);genid=self.nl.genid(self.netlink)
        nonce=secrets.token_hex(32)
        request={'schema':'lab_sender_prepared_permit_request_v1','nonce':nonce,'sender_pid':self.pid,'sender_start_ticks':self.ticks,
                 'genid':genid,'programs':[dict(rec) for rec in records],'map_digest':digest,'until_ns':until_ns}
        self.channel.settimeout(max(.001,min(5,(until_ns-time.monotonic_ns())/1e9)))
        self.channel.sendall(self.nl.canon(request));reply=self._read_reply(until_ns)
        need(set(reply)=={'schema','nonce','sender_pid','sender_start_ticks','genid','ids','map_digest','deadline_ns','source_epoch','external_effect_authorized'}
             and reply['schema']=='lab_sender_prepared_permit_reply_v1' and reply['nonce']==nonce
             and reply['sender_pid']==self.pid and reply['sender_start_ticks']==self.ticks
             and reply['genid']==genid and reply['ids']==[list(x) for x in ids] and reply['map_digest']==digest
             and type(reply['deadline_ns']) is int and time.monotonic_ns()<reply['deadline_ns']<=until_ns
             and type(reply['source_epoch']) is int and reply['source_epoch']>=0
             and reply['external_effect_authorized'] is False,'ORIGINAL_GUARDIAN_PREPARED_REPLY_REQUIRED')
        self._live(require_quiet=True);need(self.nl.genid(self.netlink)==genid,'SAME_NETLINK_GENERATION_AFTER_GUARDIAN')
        permit=_Permit(self,genid,ids,digest,reply['deadline_ns'],reply['source_epoch'],_CAPABILITY);self.pending=permit
        return permit

    def consume(self, permit, records):
        need(type(permit) is _Permit and permit.capability is _CAPABILITY and permit.session is self
             and permit.pid==os.getpid() and self.pending is permit and not permit.consumed,
             'EXACT_SINGLE_USE_SENDER_PERMIT_REQUIRED')
        permit.consumed=True;self.pending=None
        need(time.monotonic_ns()<permit.deadline_ns,'ORIGINAL_PERMIT_DEADLINE_EXPIRED')
        self._live(require_quiet=True);ids,digest=self._records(records)
        need(ids==permit.ids and digest==permit.digest and self.nl.genid(self.netlink)==permit.genid,
             'SAME_FDS_MAPS_AND_NETLINK_GENERATION_AT_SEND')
        self._live(require_quiet=True)
        need(time.monotonic_ns()<permit.deadline_ns,'ORIGINAL_PERMIT_DEADLINE_EXPIRED_AFTER_REVALIDATION')
        return {'lab_sender_permit_consumed':True,'external_effect_authorized':False,'production_authority':False}

    def attest_current(self, receipt, *, until_ns):
        need(type(receipt) is dict and self.pending is None and type(until_ns) is int
             and time.monotonic_ns()<until_ns<=time.monotonic_ns()+30_000_000_000,
             'ORIGINAL_BOUNDED_POSITIVE_ATTESTATION_REQUEST')
        self._live(require_quiet=True)
        ids,digest=self._records(receipt['programs']);genid=self.nl.genid(self.netlink)
        need(genid==receipt['after'],'ATTEST_CURRENT_RECEIPT_GENID')
        receipt_sha=hashlib.sha256(self.nl.canon(receipt)).hexdigest();nonce=secrets.token_hex(32)
        req={'schema':'lab_positive_generation_attest_request_v1','nonce':nonce,'sender_pid':self.pid,
             'sender_start_ticks':self.ticks,'genid':genid,'receipt_sha256':receipt_sha,
             'ids':[list(x) for x in ids],'map_digest':digest,'until_ns':until_ns}
        self.channel.settimeout(max(.001,min(5,(until_ns-time.monotonic_ns())/1e9)))
        self.channel.sendall(self.nl.canon(req));reply=self._read_reply(until_ns)
        need(type(reply) is dict and set(reply)=={'schema','nonce','sender_pid','sender_start_ticks','genid','receipt_sha256','ids','map_digest','deadline_ns','source_epoch','external_effect_authorized'}
             and reply['schema']=='lab_positive_generation_attest_reply_v1' and reply['nonce']==nonce
             and reply['sender_pid']==self.pid and reply['sender_start_ticks']==self.ticks
             and reply['genid']==genid and reply['receipt_sha256']==receipt_sha and reply['ids']==req['ids']
             and reply['map_digest']==digest and type(reply['deadline_ns']) is int
             and time.monotonic_ns()<reply['deadline_ns']<=until_ns and type(reply['source_epoch']) is int
             and reply['source_epoch']>=0 and reply['external_effect_authorized'] is False,
             'EXACT_ORIGINAL_GUARDIAN_POSITIVE_ATTESTATION')
        self._live(require_quiet=True)
        need(self.nl.genid(self.netlink)==genid and time.monotonic_ns()<reply['deadline_ns'],
             'LIVE_UNCHANGED_POSITIVE_ATTESTATION')
        return _PositiveAttestation(self,receipt_sha,genid,ids,digest,reply['deadline_ns'],reply['source_epoch'],_CAPABILITY)

    def _close_writer_socket(self):
        if self.netlink is not None:
            _close_netlink(self.netlink)  # an exception deliberately retains SH
            self.netlink=None
        if self.netlink_inode is not None:
            expected='socket:['+str(self.netlink_inode)+']'
            for name in os.listdir('/proc/self/fd'):
                try:target=os.readlink('/proc/self/fd/'+name)
                except FileNotFoundError:continue
                need(target!=expected,'SESSION_NETLINK_SOCKET_STILL_REFERENCED')
            self.netlink_inode=None
        if self.writer_lease is not None:
            self.writer_lease.close();self.writer_lease=None
    def close(self):
        need(os.getpid()==self.pid and threading.get_ident()==self.thread,'SAME_SESSION_CLOSER_REQUIRED')
        self.closed=True;self.pending=None
        if self.pidfd is not None:os.close(self.pidfd);self.pidfd=None
        self.channel.close()
        self._close_writer_socket()
