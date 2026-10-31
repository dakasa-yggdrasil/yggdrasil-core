"""LAB-only Guardian registry for ordinary and holder-preserving refreshes.

No production authorization. The surrounding Guardian must route *all* holder
acquisitions and sender commits through this same registry. A crash or unknown
send requires distinct recovery; fixture initialization is not restart proof.
"""
import ctypes,hashlib,os,select,socket,struct,threading,time
from pathlib import Path

_CAPABILITY=object()
class Held(RuntimeError):pass

def need(value,reason):
    if not value:raise Held(reason)

class _Prepared:
    def __init__(self,registry,ids,digest,genid,epoch,until,mode,records,rows,holder,capability):
        need(capability is _CAPABILITY,'ONLY_SAME_GUARDIAN_PREPARED_REFRESH')
        self.registry,self.ids,self.digest,self.genid,self.epoch,self.until,self.mode=registry,ids,digest,genid,epoch,until,mode
        self.records=tuple(dict(x) for x in records);self.rows={role:tuple((bytes.fromhex(key),value) for key,value in values) for role,values in rows.items()}
        self.holder=holder
        self.pid,self.capability,self.sender_claimed,self.sent=os.getpid(),capability,False,False

class GuardianRefreshRegistry:
    def __init__(self,channel,prep_identity,*,cache,sources,nl,verifier,current15,program_module,reference,validate_kernel):
        need(os.geteuid()==0 and os.environ.get('CI_GUARDED_FIXTURE')=='1'
             and os.environ.get('CI_HOST_NETNS') and os.readlink('/proc/self/ns/net')!=os.environ['CI_HOST_NETNS'],
             'ONLY_EXACT_DISPOSABLE_LAB_BOOT')
        need(type(channel) is socket.socket and type(prep_identity) is dict and type(prep_identity.get('pidfd')) is int
             and type(reference) is program_module.GuardianProgramReference and not reference.closed
             and reference.pid==os.getpid() and callable(validate_kernel),'ORIGINAL_GUARDIAN_PREPARER_AND_REFERENCE_REQUIRED')
        peer,uid,_=struct.unpack('3i',channel.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
        need(uid==0 and peer==prep_identity['pid'] and nl.startticks(peer)==prep_identity['start_ticks'],
             'EXACT_INDEPENDENTLY_AUTHENTICATED_PREPARER')
        self.channel,self.prep,self.cache,self.sources,self.nl=channel,prep_identity,cache,sources,nl
        self.verifier,self.current15,self.reference,self.validate_kernel=verifier,current15,reference,validate_kernel
        self.pid=os.getpid();self.lock=threading.Lock();self.holder=None;self.state='FIXTURE_EMPTY';self.pending=None
        self._preparer_live()

    def _preparer_live(self):
        poll=select.poll();poll.register(self.prep['pidfd'],select.POLLIN)
        need(os.getpid()==self.pid and not poll.poll(0) and self.nl.startticks(self.prep['pid'])==self.prep['start_ticks'],
             'ORIGINAL_PREPARER_AND_GUARDIAN_LIVE')

    def acquire_holder(self,authority,authority_module,acquire):
        """Only path to add a holder: serialize acquire with all refreshes."""
        with self.lock:
            need(self.state=='FIXTURE_EMPTY' and self.pending is None and self.holder is None
                 and type(authority) is authority_module.EffectLeaseAuthority and authority.preparer_channel is self.channel
                 and authority.preparer==self.prep['pid'] and callable(acquire),'ONE_HOLDER_OUTSIDE_REFRESH_REQUIRED')
            value=acquire()
            need(authority.lease is not None and not authority.lease['revoked'] and value.get('external_effect_authorized') is False,
                 'ORIGINAL_HOLDER_LEASE_REQUIRED')
            self.holder=authority;self.state='HOLDER';return value

    def holder_lost(self):
        """Loss is ambiguous until explicit fenced recovery, never 'absent'."""
        with self.lock:
            if self.holder is not None:self.holder.revoke()
            self.state='UNKNOWN'

    def prepare(self,before,verified,records):
        with self.lock:
            need(self.state in ('FIXTURE_EMPTY','HOLDER') and self.pending is None,'NO_AMBIGUOUS_OR_PENDING_REFRESH')
            reservation=object();self.pending=reservation;holder=self.holder;mode=self.state
        try:
            self._preparer_live()
            need(type(before) is self.current15._BeforeSend and before.capability is self.current15._CAPABILITY
                 and before.cache is self.cache and before.pid==self.pid and not before.consumed,
                 'ORIGINAL_BEFORE_SEND_WITNESS_REQUIRED')
            need(type(verified) is self.verifier._VerifiedGeneration and verified.capability is self.verifier._VERIFIED_CAPABILITY
                 and verified.guardian_pid==self.pid and verified.reader_cache is self.cache and verified.sender_pidfd is not None,
                 'ORIGINAL_GUARDIAN_VERIFIED_ACTIVE_GENERATION')
            live=self.validate_kernel(verified);obs=live['observation'];current=self.sources.build_expected(self.cache)
            need(current['invalidation_epoch']==before.epoch==live['invalidation_epoch'] and obs['genid']==verified.result['after']
                 and time.monotonic_ns()<obs['kernel_min_deadline_ns'],'LIVE_ORIGINAL_SOURCE_AND_KERNEL_GENERATION')
            lease=None
            if holder is not None:
                with holder.lock:lease=holder.lease
                need(lease is not None and not lease['revoked'] and lease['epoch']==obs['genid']
                     and lease['invalidation_epoch']==before.epoch,'SAME_LIVE_HOLDER_GENERATION_REQUIRED')
                holder._source_live(lease)
            need(type(records) is list and len(records)==2,'EXACT_TWO_PREPARED_PROGRAM_MAP_PAIRS')
            ids=[];rows={};now=time.monotonic_ns()
            for role,rec in zip(('inbound','reverse'),records):
                need(type(rec) is dict and all(type(rec.get(k)) is int and rec[k]>0 for k in ('program_fd','program_id','map_fd','map_id')),
                     'EXACT_PREPARER_DESCRIPTOR_FIELDS')
                pi=self.nl.fdinfo(self.prep['pid'],rec['program_fd']);mi=self.nl.fdinfo(self.prep['pid'],rec['map_fd'])
                need(int(pi['prog_id'])==rec['program_id'] and int(mi['map_id'])==rec['map_id'] and mi['frozen'].strip()=='1',
                     'ORIGINAL_PREPARER_FROZEN_FDS')
                self.reference.verify(rec['program_id'],rec['map_id'])
                actual=self.nl.map_rows(rec['map_id']);values=dict(actual)
                need(len(actual)==len(values) and set(values)==set(before.expected[role])==set(current[role]),
                     'EXACT_BEFORE_AND_CURRENT_ORIGINAL_TUPLES')
                need(all(now<expiry<=before.expected[role][key] and expiry<=current[role][key] for key,expiry in values.items()),
                     'DEADLINES_BOUND_TO_ORIGINAL_WITNESSES')
                if lease is not None:
                    need(set(values)==set(lease['maps'][role]) and all(expiry>=lease['until'] for expiry in values.values()),
                         'ALL_TUPLES_MUST_PRESERVE_HOLDER_LEASE')
                rows[role]=[[key.hex(),value] for key,value in sorted(actual)];ids.append((rec['program_id'],rec['map_id']))
            need(len({x[0] for x in ids})==2 and len({x[1] for x in ids})==2,'DISTINCT_PREPARED_MAP_PROGRAM_IDS')
            until=min(obs['kernel_min_deadline_ns'],*(value for role in rows.values() for _,value in role))
            if lease is not None:need(until>=lease['until'],'NFT_AND_MAPS_MUST_COVER_HOLDER_LEASE')
            digest=hashlib.sha256(self.nl.canon(rows)).hexdigest();self._preparer_live()
            final=self.sources.build_expected(self.cache);now=time.monotonic_ns()
            need(final['invalidation_epoch']==before.epoch and now<until,'LIVE_ORIGINAL_SOURCE_AT_APPROVAL')
            for role in ('inbound','reverse'):
                actual={bytes.fromhex(key):value for key,value in rows[role]}
                need(set(actual)==set(final[role]) and all(now<expiry<=final[role][key] for key,expiry in actual.items()),
                     'UNCHANGED_ORIGINAL_TUPLES_AT_APPROVAL')
            if holder is not None:holder._source_live(lease)
            with self.lock:
                need(self.pending is reservation and self.state==mode and self.holder is holder,'SAME_REFRESH_RESERVATION')
                proof=_Prepared(self,tuple(ids),digest,obs['genid'],before.epoch,until,mode,records,rows,holder,_CAPABILITY);self.pending=proof
            return proof
        except BaseException:
            with self.lock:
                if self.pending is reservation:self.pending=None
            raise

    def mark_send_started(self,proof):
        # This is a pre-send check, not a kernel-atomic revocation fence.
        with self.lock:
            need(type(proof) is _Prepared and proof.capability is _CAPABILITY and proof.registry is self
                 and proof.pid==self.pid and self.pending is proof and not proof.sent
                 and self.state==proof.mode and self.holder is proof.holder,
                 'SAME_UNREVOKED_REFRESH_RESERVATION_REQUIRED')
            holder=self.holder
        self._preparer_live();current=self.sources.build_expected(self.cache);now=time.monotonic_ns()
        need(current['invalidation_epoch']==proof.epoch and now<proof.until,'LIVE_ORIGINAL_WITNESS_AT_DISPATCH')
        for role,rec,ids in zip(('inbound','reverse'),proof.records,proof.ids):
            pi=self.nl.fdinfo(self.prep['pid'],rec['program_fd']);mi=self.nl.fdinfo(self.prep['pid'],rec['map_fd'])
            need(int(pi['prog_id'])==ids[0] and int(mi['map_id'])==ids[1] and mi['frozen'].strip()=='1',
                 'SAME_PREPARER_FDS_AT_DISPATCH')
            self.reference.verify(ids[0],ids[1]);actual=dict(self.nl.map_rows(ids[1]))
            need(actual==dict(proof.rows[role]) and set(actual)==set(current[role])
                 and all(now<expiry<=current[role][key] for key,expiry in actual.items()),
                 'SAME_LIVE_ORIGINAL_MAPS_AT_DISPATCH')
        if holder is not None:
            with holder.lock:lease=holder.lease
            need(lease is not None and not lease['revoked'] and lease['epoch']==proof.genid
                 and lease['invalidation_epoch']==proof.epoch,'SAME_LIVE_HOLDER_AT_DISPATCH')
            holder._source_live(lease)
        self._preparer_live()
        with self.lock:
            need(self.pending is proof and not proof.sent and self.state==proof.mode and self.holder is holder
                 and time.monotonic_ns()<proof.until,'SAME_LIVE_RESERVATION_AT_DISPATCH')
            proof.sent=True

    def confirm(self,proof,verified):
        """Only same-Guardian independent ACK/FD/kernel reread clears a send."""
        with self.lock:
            need(type(proof) is _Prepared and proof.capability is _CAPABILITY and proof.registry is self
                 and self.pending is proof and proof.sent and self.state==proof.mode,
                 'ONE_DISPATCHED_PENDING_REFRESH_REQUIRED')
            holder=self.holder
        need(type(verified) is self.verifier._VerifiedGeneration and verified.capability is self.verifier._VERIFIED_CAPABILITY
             and verified.guardian_pid==self.pid and verified.reader_cache is self.cache and verified.sender_pidfd is not None,
             'ORIGINAL_GUARDIAN_SUCCESSOR_VERIFICATION_REQUIRED')
        result=verified.result;need(result['genid']==proof.genid and result['after']!=proof.genid
             and tuple((rec['program_id'],rec['map_id']) for rec in result['programs'])==proof.ids,
             'EXACT_PREPARED_SUCCESSOR_AND_ORIGINAL_ACK')
        actual={role:[[key.hex(),value] for key,value in sorted(verified.actual[role])] for role in ('inbound','reverse')}
        need(hashlib.sha256(self.nl.canon(actual)).hexdigest()==proof.digest,'SAME_APPROVED_SENDER_MAPS')
        live=self.validate_kernel(verified);obs=live['observation']
        need(obs['genid']==result['after'] and live['invalidation_epoch']==proof.epoch
             and time.monotonic_ns()<obs['kernel_min_deadline_ns'],'SAME_LIVE_SUCCESSOR_AND_SOURCE_EPOCH')
        if holder is not None:
            with holder.lock:lease=holder.lease
            need(lease is not None and not lease['revoked'] and obs['kernel_min_deadline_ns']>=lease['until'],
                 'CONFIRMED_SUCCESSOR_MUST_COVER_HOLDER')
            holder._source_live(lease)
        self._preparer_live()
        with self.lock:
            need(self.pending is proof and self.state==proof.mode and self.holder is holder,'SAME_PENDING_LIVE_REFRESH')
            self.pending=None
        return {'same_guardian_successor_verified':True,'mode':proof.mode,'external_effect_authorized':False,'production_authority':False}

    def fail_or_unknown(self,proof):
        with self.lock:
            need(self.pending is proof,'SAME_PENDING_REFRESH_REQUIRED')
            if proof.sent:self.state='UNKNOWN'
            else:self.pending=None
