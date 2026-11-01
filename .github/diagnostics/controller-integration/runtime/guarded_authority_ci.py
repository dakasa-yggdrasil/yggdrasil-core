"""LAB-only Guardian sender permit for ordinary and holder refresh modes.

The registry must be the sole path for refresh/holder state. Before replying,
it marks a single prepared generation as possibly dispatched; a reply failure
or process loss is UNKNOWN, never replayed. This does not make a userspace
check atomic with a later kernel send or grant any external effect.
"""
import array,fcntl,hashlib,os,re,select,socket,stat,struct,threading,time
from pathlib import Path

class Held(RuntimeError):pass

def need(value,reason):
    if not value:raise Held(reason)

class SenderRegistryAuthority:
    def __init__(self,channel,*,registry,registry_module,verified,verifier,identity,nl,
                 sender_argv,sender_sha256,validate_kernel):
        need(type(channel) is socket.socket and type(registry) is registry_module.GuardianRefreshRegistry
             and registry.pid==os.getpid() and type(verified) is verifier._VerifiedGeneration
             and verified.capability is verifier._VERIFIED_CAPABILITY and verified.guardian_pid==os.getpid()
             and verified.reader_cache is registry.cache and verified.sender_pidfd is not None
             and callable(validate_kernel),'ORIGINAL_GUARDIAN_REGISTRY_AND_VERIFICATION_REQUIRED')
        pid,uid,gid=struct.unpack('3i',channel.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12));anchor=verified.anchor
        source_index = (3 if type(sender_argv) is list and sender_argv[:3] == ['/usr/bin/python3','-I','-B']
                        else 2 if type(sender_argv) is list and sender_argv[:2] == ['/usr/bin/python3','-B'] else -1)
        need(uid==0 and pid==anchor['pid'] and nl.startticks(pid)==anchor['start_ticks']
             and os.readlink('/proc/%d/ns/net'%pid)==anchor['netns']
             and source_index > 0 and len(sender_argv) > source_index,
             'EXACT_ORIGINAL_SENDER_PEER_REQUIRED')
        self.channel,self.registry,self.registry_module,self.verified,self.nl=channel,registry,registry_module,verified,nl
        self.sender,self.ticks,self.netns,self.guardian=pid,anchor['start_ticks'],anchor['netns'],os.getpid()
        self.identity,self.uid,self.gid=identity,uid,gid;self.validate_kernel=validate_kernel
        self.lock=threading.Lock();self.closed=False;self.pidfd=os.pidfd_open(pid,0);self.writer_guard=None
        try:
            self._live();raw=Path('/proc/%d/cmdline'%pid).read_bytes()
            need(raw.endswith(b'\0') and raw[:-1].split(b'\0')==[x.encode() for x in sender_argv],'EXACT_SENDER_ARGV')
            exe=os.stat('/proc/%d/exe'%pid);expected=os.stat(sender_argv[0]);need((exe.st_dev,exe.st_ino)==(expected.st_dev,expected.st_ino),'EXACT_SENDER_INTERPRETER')
            identity._secure_source(Path(sender_argv[source_index]),sender_sha256)
            prep=registry.prep['pid'];need(Path('/proc/%d/cgroup'%pid).read_bytes()==Path('/proc/%d/cgroup'%prep).read_bytes(),'SENDER_PREPARER_CGROUP')
            if pid==prep:
                observed=identity.authenticate(channel,unit=registry.prep['unit'],expected_invocation=registry.prep['invocation_id'],expected_argv=sender_argv,source_sha256=sender_sha256,expected_uid=0)
                try:need(observed['pid']==prep and observed['start_ticks']==registry.prep['start_ticks'] and observed['control_group']==registry.prep['control_group'],'SAME_ORIGINAL_CONTROLLER_IDENTITY')
                finally:os.close(observed['pidfd'])
            else:
                need(len(sender_argv)>source_index+1 and sender_argv[source_index+1]=='sender','ONLY_EXACT_LAB_CHILD_SENDER_ENTRY')
                fields=Path('/proc/%d/stat'%pid).read_bytes().rsplit(b') ',1)[1].split();need(int(fields[1])==prep,'SENDER_DIRECT_PREPARER_CHILD')
            self._live();registry._preparer_live()
        except BaseException:os.close(self.pidfd);raise

    def _live(self):
        poll=select.poll();poll.register(self.pidfd,select.POLLIN)
        need(not self.closed and os.getpid()==self.guardian and not poll.poll(0)
             and self.nl.startticks(self.sender)==self.ticks and os.readlink('/proc/%d/ns/net'%self.sender)==self.netns,
             'SAME_LIVE_GUARDIAN_AND_SENDER')
        self.identity._current_ids(self.sender,self.uid,self.gid)

    def receive_writer_custody(self,coord):
        import drain_marker_v3_DRAFT as marker
        need(type(coord) is marker.CoordinatorV3 and self.writer_guard is None,
             'ONE_EXACT_WRITER_CUSTODY_REQUIRED')
        self._live();unclaimed=[];independent=None
        try:
            msg,anc,flags,_=self.channel.recvmsg(1,socket.CMSG_SPACE(array.array('i').itemsize))
            for level,kind,data in anc:
                if level==socket.SOL_SOCKET and kind==socket.SCM_RIGHTS:
                    a=array.array('i');a.frombytes(data[:len(data)-len(data)%a.itemsize]);unclaimed.extend(a)
            need(msg==b'W' and not flags&(socket.MSG_CTRUNC|socket.MSG_TRUNC)
                 and len(anc)==1 and anc[0][:2]==(socket.SOL_SOCKET,socket.SCM_RIGHTS)
                 and len(unclaimed)==1,'EXACT_SENDER_WRITER_FD_REQUIRED')
            received=unclaimed[0];coord.base._private_directory()
            sent=os.fstat(received);named=os.lstat(coord.writer_lock)
            expected=(named.st_dev,named.st_ino)
            need(stat.S_ISREG(named.st_mode) and named.st_uid==0 and named.st_nlink==1
                 and stat.S_IMODE(named.st_mode)==0o600 and (sent.st_dev,sent.st_ino)==expected,
                 'SAME_PRIVATE_WRITER_INODE_REQUIRED')
            independent=os.open(coord.writer_lock,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
            opened=os.fstat(independent)
            need((opened.st_dev,opened.st_ino)==expected,'SAME_INDEPENDENT_WRITER_INODE_REQUIRED')
            fcntl.flock(independent,fcntl.LOCK_SH|fcntl.LOCK_NB)
            self._live();self.writer_guard=(coord,independent,expected,self.sender,self.ticks)
            independent=None
        finally:
            for fd in unclaimed:os.close(fd)
            if independent is not None:os.close(independent)

    def require_writer_custody(self,coord,verified):
        guard=self.writer_guard
        need(not self.closed and guard is not None and guard[0] is coord
             and verified.anchor['pid']==self.sender==guard[3]
             and verified.anchor['start_ticks']==self.ticks==guard[4],
             'BOUND_ACTIVE_GUARDIAN_WRITER_CUSTODY_REQUIRED')
        self._live();opened=os.fstat(guard[1]);named=os.lstat(coord.writer_lock)
        need((opened.st_dev,opened.st_ino)==(named.st_dev,named.st_ino)==guard[2],
             'SAME_GUARDIAN_WRITER_CUSTODY_INODE_REQUIRED')
        return guard[2]

    def _send(self,value):
        with self.lock:self.channel.sendall(self.nl.canon(value))

    def revoke_and_notify(self):
        self.registry.holder_lost()
        try:self._send({'event':'REVOKED'})
        except (BrokenPipeError,ConnectionResetError,OSError):pass

    def _records(self,records,proof,lease):
        need(type(records) is list and len(records)==2,'EXACT_TWO_SENDER_FD_PAIRS')
        source=self.registry.sources.build_expected(self.registry.cache);now=time.monotonic_ns();rows={};ids=[]
        need(source['invalidation_epoch']==proof.epoch,'SAME_ORIGINAL_READER_EPOCH')
        for role,rec in zip(('inbound','reverse'),records):
            need(type(rec) is dict and all(type(rec.get(k)) is int and rec[k]>0 for k in ('program_fd','program_id','map_fd','map_id')),'EXACT_SENDER_FD_FIELDS')
            pi=self.nl.fdinfo(self.sender,rec['program_fd']);mi=self.nl.fdinfo(self.sender,rec['map_fd'])
            need(int(pi['prog_id'])==rec['program_id'] and int(mi['map_id'])==rec['map_id'] and mi['frozen'].strip()=='1','ORIGINAL_SENDER_FROZEN_FDS')
            self.registry.reference.verify(rec['program_id'],rec['map_id'])
            actual=self.nl.map_rows(rec['map_id']);values=dict(actual)
            need(len(values)==len(actual) and values==dict(proof.rows[role]) and set(values)==set(source[role])
                 and all(now<expiry<=source[role][key] for key,expiry in values.items()),'EXACT_ORIGINAL_SENDER_MAPS_AND_WITNESSES')
            if lease is not None:need(set(values)==set(lease['maps'][role]) and all(value>=lease['until'] for value in values.values()),'SENDER_MAPS_PRESERVE_HOLDER')
            rows[role]=[[key.hex(),value] for key,value in sorted(actual)];ids.append((rec['program_id'],rec['map_id']))
        need(len({x[0] for x in ids})==2 and len({x[1] for x in ids})==2,'DISTINCT_SENDER_MAP_PROGRAM_IDS')
        return tuple(ids),hashlib.sha256(self.nl.canon(rows)).hexdigest()

    def answer_once(self,request):
        fields={'schema','nonce','sender_pid','sender_start_ticks','genid','programs','map_digest','until_ns'}
        need(type(request) is dict and set(request)==fields and request['schema']=='lab_sender_prepared_permit_request_v1'
             and type(request['nonce']) is str and re.fullmatch('[a-f0-9]{64}',request['nonce']) is not None
             and request['sender_pid']==self.sender and request['sender_start_ticks']==self.ticks
             and type(request['genid']) is int and type(request['until_ns']) is int,'EXACT_SENDER_REQUEST')
        self._live()
        with self.registry.lock:
            proof=self.registry.pending;holder=self.registry.holder
            need(type(proof) is self.registry_module._Prepared and proof.capability is self.registry_module._CAPABILITY
                 and proof.registry is self.registry and self.registry.state==proof.mode and proof.holder is holder
                 and not proof.sender_claimed and not proof.sent,'ONE_LIVE_PREPARED_GENERATION')
        lease=None
        if holder is not None:
            with holder.lock:lease=holder.lease
            need(lease is not None and not lease['revoked'] and lease['epoch']==proof.genid,'LIVE_HOLDER_GENERATION')
            holder._source_live(lease)
        live=self.validate_kernel(self.verified);obs=live['observation']
        need(obs['genid']==proof.genid==request['genid'] and live['invalidation_epoch']==proof.epoch
             and obs['kernel_min_deadline_ns']>time.monotonic_ns(),'SAME_GUARDIAN_KERNEL_AND_SOURCE')
        ids,digest=self._records(request['programs'],proof,lease)
        need(ids==proof.ids and digest==proof.digest==request['map_digest'],'SAME_PREPARED_PROGRAMS_AND_MAPS')
        deadline=min(request['until_ns'],proof.until,obs['kernel_min_deadline_ns'])
        if lease is not None:deadline=min(deadline,lease['until'])
        need(time.monotonic_ns()<deadline,'UNEXPIRED_SENDER_PERMIT')
        with self.registry.lock:
            need(self.registry.pending is proof and self.registry.state==proof.mode and not proof.sender_claimed and not proof.sent,'ONE_GLOBAL_SENDER_CLAIM')
            proof.sender_claimed=True
        try:
            self.registry.mark_send_started(proof)
            self._send({'schema':'lab_sender_prepared_permit_reply_v1','nonce':request['nonce'],
                        'sender_pid':self.sender,'sender_start_ticks':self.ticks,'genid':proof.genid,
                        'ids':[list(x) for x in ids],'map_digest':digest,'deadline_ns':deadline,
                        'source_epoch':proof.epoch,'external_effect_authorized':False})
        except BaseException:
            self.registry.fail_or_unknown(proof)
            raise

    def attest_current(self,request):
        fields={'schema','nonce','sender_pid','sender_start_ticks','genid','receipt_sha256','ids','map_digest','until_ns'}
        need(type(request) is dict and set(request)==fields and request['schema']=='lab_positive_generation_attest_request_v1'
             and type(request['nonce']) is str and re.fullmatch('[a-f0-9]{64}',request['nonce']) is not None
             and request['sender_pid']==self.sender and request['sender_start_ticks']==self.ticks
             and type(request['until_ns']) is int and time.monotonic_ns()<request['until_ns']<=time.monotonic_ns()+30_000_000_000,
             'EXACT_POSITIVE_ATTESTATION_REQUEST')
        self._live();self.registry._preparer_live()
        live=self.validate_kernel(self.verified);obs=live['observation'];result=self.verified.result
        receipt={k:v for k,v in result.items() if k not in ('ok','counter')}
        receipt_sha=hashlib.sha256(self.nl.canon(receipt)).hexdigest()
        need(obs['genid']==request['genid']==receipt['after'] and obs['receipt_sha256']==receipt_sha==request['receipt_sha256']
             and live['invalidation_epoch'] is not None,'EXACT_VERIFIED_POSITIVE_RECEIPT')
        rows={};ids=[]
        for role,rec in zip(('inbound','reverse'),receipt['programs']):
            p=self.nl.fdinfo(self.sender,rec['program_fd']);mp=self.nl.fdinfo(self.sender,rec['map_fd'])
            need(int(p['prog_id'])==rec['program_id'] and int(mp['map_id'])==rec['map_id'] and mp['frozen'].strip()=='1',
                 'EXACT_CURRENT_POSITIVE_FDS')
            self.registry.reference.verify(rec['program_id'],rec['map_id'])
            actual=self.nl.map_rows(rec['map_id']);need(actual and set(actual)==set(self.verified.actual[role]),'EXACT_VERIFIED_CURRENT_MAP')
            rows[role]=[[key.hex(),value] for key,value in sorted(actual)];ids.append([rec['program_id'],rec['map_id']])
        digest=hashlib.sha256(self.nl.canon(rows)).hexdigest()
        need(ids==request['ids'] and digest==request['map_digest'],'EXACT_CURRENT_POSITIVE_MAP_DIGEST')
        if os.environ.get('LAB_TEST_ATTEST_DRIFT')=='1':
            need(Path('/proc/sys/kernel/random/boot_id').read_text().strip()=='9930f6b8-f1e4-4542-a81b-9000e0efa4ed'
                 and self.netns != os.environ.get('LAB_HOST_NETNS'),'ONLY_PRIVATE_LAB_DRIFT_INJECTION')
            self._live();self.nl.cmd('/usr/bin/nsenter','--net=/proc/%d/ns/net'%self.sender,'/usr/sbin/nft','add','table','ip','lab_attest_test_genid_drift')
        second=self.validate_kernel(self.verified);again=second['observation'];self._live();self.registry._preparer_live()
        need(again['genid']==obs['genid'] and again['receipt_sha256']==receipt_sha
             and second['invalidation_epoch']==live['invalidation_epoch'],'STABLE_POSITIVE_KERNEL_AND_SOURCE')
        until=min(request['until_ns'],obs['kernel_min_deadline_ns'],again['kernel_min_deadline_ns'])
        need(time.monotonic_ns()<until,'POSITIVE_ATTESTATION_DEADLINE_EXPIRED')
        self._send({'schema':'lab_positive_generation_attest_reply_v1','nonce':request['nonce'],
                    'sender_pid':self.sender,'sender_start_ticks':self.ticks,'genid':receipt['after'],
                    'receipt_sha256':receipt_sha,'ids':ids,'map_digest':digest,'deadline_ns':until,
                    'source_epoch':live['invalidation_epoch'],'external_effect_authorized':False})

    def close(self):
        if not self.closed:
            self.closed=True
            try:os.close(self.pidfd)
            finally:self.channel.close()
