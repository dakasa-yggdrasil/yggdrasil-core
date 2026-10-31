"""CI-only guarded sender intent marker; NO production authority.

A visible marker blocks participating admission/writers even before its bytes
are durable. It is created under the same flock and fsynced outside it; no
guarded prepare/send may begin before that fsync completes. Unknown outcomes
leave the marker. BPF-admission validation and emergency exception remain open.
"""
import contextlib
import hashlib
import json
import os
import re
from pathlib import Path
import secrets
import stat
import time
import threading
from drain_coordination_DRAFT import Coordinator, FenceError

_CAPABILITY=object()

def _original_systemd_identity():
    import guarded_unit_identity as identity
    unit=os.environ.get('CI_CONTROLLER_UNIT','')
    invocation=os.environ.get('INVOCATION_ID','')
    if not re.fullmatch(r'[a-zA-Z0-9_.@:-]+\.service',unit) or not re.fullmatch(r'[0-9a-f]{32}',invocation):
        raise FenceError('EXACT_SYSTEMD_UNIT_INVOCATION_REQUIRED')
    first=identity._properties(unit)
    pid=os.getpid();ticks=identity._startticks(pid)
    cgroup=Path('/proc/self/cgroup').read_text().splitlines()
    if (first['ActiveState']!='active' or int(first['MainPID'])!=pid
            or first['InvocationID']!=invocation
            or not first['ControlGroup'].startswith('/system.slice/')
            or cgroup!=['0::'+first['ControlGroup']]
            or identity._properties(unit)!=first or identity._startticks(pid)!=ticks):
        raise FenceError('SAME_LIVE_SYSTEMD_PROCESS_REQUIRED')
    return {'unit':unit,'invocation_id':invocation,'control_group':first['ControlGroup'],'start_ticks':ticks}

class Intent:
    def __init__(self, owner, nonce, inode, digest, core_uid, core_address, writer_lease, capability):
        if capability is not _CAPABILITY:raise FenceError('ONLY_LOCAL_INTENT')
        self.owner,self.nonce,self.inode,self.digest=owner,nonce,inode,digest
        self.core_uid,self.core_address=core_uid,core_address
        self.writer_lease=writer_lease
        self.pid=os.getpid();self.capability=capability
        self.sent=False;self.before_genid=None;self.emitter=None

class _AdmissionReservation:
    def __init__(self,owner,inode,nonce,capability):
        if capability is not _CAPABILITY:raise FenceError('PRIVATE_ADMISSION_RESERVATION')
        self.owner,self.inode,self.nonce,self.capability=owner,inode,nonce,capability
        self.pid=os.getpid();self.closed=False

class CoordinatorV3:
    def __init__(self,directory):
        self.base=Coordinator(directory);self.directory=Path(directory)
        self.marker=self.directory/'guarded-intent.json'
        self.admission_marker=self.directory/'admission-intent.json'
        self.writer_lock=self.directory/'writer.lock'
        self._writer_identity=None
        self._local=threading.local()
    def initialize_for_ci(self):
        self.base.initialize_for_test()
        fd=os.open(self.writer_lock,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        try:os.fsync(fd)
        finally:os.close(fd)
        directory_fd=os.open(self.directory,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        try:os.fsync(directory_fd)
        finally:os.close(directory_fd)
    def acquire_writer_lease(self):
        import writer_lease_v3_DRAFT as writer_lease
        return writer_lease.acquire(self)
    @contextlib.contextmanager
    def writer_lease(self):
        current=getattr(self._local,'writer_lease',None)
        if current is not None:
            current.validate();yield current;return
        lease=self.acquire_writer_lease()
        self._local.writer_lease=lease
        try:yield lease
        finally:
            self._local.writer_lease=None
            lease.close()
    def current_writer_lease(self):
        lease=getattr(self._local,'writer_lease',None)
        if lease is None:raise FenceError('TYPED_WRITER_LEASE_REQUIRED')
        lease.validate()
        return lease
    def marker_exists(self):
        try:os.lstat(self.marker);return True
        except FileNotFoundError:return False
    def admission_marker_exists(self):
        try:os.lstat(self.admission_marker);return True
        except FileNotFoundError:return False
    def reserve_admission(self, *, _ci_after_create=None):
        # Exclusive visible reservation blocks writers before slow fsync. It
        # grants no DELETE and has no path that commits a retirement yet.
        if os.environ.get('CI_GUARDED_FIXTURE')!='1':raise FenceError('ONLY_PRIVATE_CI_RESERVATION')
        if getattr(self._local,'state',None) is not None:raise FenceError('RESERVATION_REQUIRES_NO_HELD_LOCK')
        nonce=secrets.token_hex(32)
        raw=(json.dumps({'schema':'ci_admission_reservation_v1','pid':os.getpid(),
                        'nonce':nonce},sort_keys=True,separators=(',',':'))+'\n').encode()
        with self.base.locked(nonblocking=True):
            if self.marker_exists() or self.admission_marker_exists():raise FenceError('ADMISSION_OR_SENDER_PENDING')
            fd=os.open(self.admission_marker,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
            identity=os.fstat(fd);inode=(identity.st_dev,identity.st_ino)
        try:
            if _ci_after_create is not None:_ci_after_create()
            offset=0
            while offset<len(raw):
                n=os.write(fd,raw[offset:])
                if n<=0:raise OSError('admission reservation write failed')
                offset+=n
            os.fsync(fd)
        finally:os.close(fd)
        parent=os.open(self.directory,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        try:os.fsync(parent)
        finally:os.close(parent)
        with self.base.locked(nonblocking=True):
            named=os.lstat(self.admission_marker)
            if (named.st_dev,named.st_ino)!=inode:raise FenceError('ADMISSION_RESERVATION_CHANGED')
        return _AdmissionReservation(self,inode,nonce,_CAPABILITY)
    def cancel_admission(self,reservation):
        # Only unused reservations can be canceled; no retirement is exposed.
        if (type(reservation) is not _AdmissionReservation or reservation.capability is not _CAPABILITY
                or reservation.owner is not self or reservation.pid!=os.getpid() or reservation.closed):
            raise FenceError('ORIGINAL_UNUSED_ADMISSION_RESERVATION_REQUIRED')
        with self.base.locked(nonblocking=True):
            fd=os.open(self.admission_marker,os.O_RDONLY|os.O_NOFOLLOW)
            try:
                value=os.fstat(fd);raw=os.read(fd,4097)
                if ((value.st_dev,value.st_ino)!=reservation.inode or len(raw)>4096
                        or json.loads(raw).get('nonce')!=reservation.nonce):
                    raise FenceError('ADMISSION_RESERVATION_CHANGED')
            finally:os.close(fd)
            os.unlink(self.admission_marker)
            reservation.closed=True
        parent=os.open(self.directory,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        try:os.fsync(parent)
        finally:os.close(parent)
    @contextlib.contextmanager
    def admission_or_other_writer(self):
        # Reentrancy is per-thread and only for the identical coordinator,
        # so native_io can enforce the same held lock at the final send.
        if getattr(self._local,'state',None) is not None:
            self.base.revalidate_lock()
            yield self._local.state
            return
        with self.base.locked(nonblocking=True) as state:
            if self.marker_exists():raise FenceError('GUARDED_INTENT_PENDING')
            if self.admission_marker_exists():raise FenceError('ADMISSION_INTENT_PENDING')
            self._local.state=state
            try:yield state
            finally:self._local.state=None
    @contextlib.contextmanager
    def typed_native_send(self):
        if getattr(self._local,'state',None) is None:
            raise FenceError('NATIVE_SEND_REQUIRES_HELD_COORDINATION')
        prior=getattr(self._local,'native_send',False)
        self._local.native_send=True
        try:yield
        finally:self._local.native_send=prior
    def native_send_authorized(self):
        return getattr(self._local,'state',None) is not None and getattr(self._local,'native_send',False)
    def begin(self, core, sources, *, writer_lease, _ci_after_create=None):
        uid=core.native_identity.split('/',1)[0]
        if not uid or not core.address:raise FenceError('CORE_IDENTITY_REQUIRED')
        if not sources or not any(x.address==core.address and x.native_identity==core.native_identity for x in sources):
            raise FenceError('CORE_SOURCE_JOIN_REQUIRED')
        import writer_lease_v3_DRAFT as lease_module
        if type(writer_lease) is not lease_module.WriterLease or writer_lease.coord is not self:
            raise FenceError('ORIGINAL_WRITER_LEASE_REQUIRED_BEFORE_INTENT')
        writer_lease.validate()
        identity=_original_systemd_identity()
        nonce=secrets.token_hex(32)
        record={'schema':'ci_guarded_drain_intent_v3','nonce':nonce,'pid':os.getpid(),
                'core_uid':uid,'core_address':core.address,'core_identity':core.native_identity,
                **identity,'boot_id':Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
                'netns':os.readlink('/proc/self/ns/net'),
                'sources':sorted((x.native_identity,x.address) for x in sources)}
        # O_EXCL is intentionally the only filesystem mutation while locked.
        # Mere existence, including an empty/torn record, blocks all participants.
        with self.base.locked(nonblocking=True) as state:
            if self.marker_exists():raise FenceError('GUARDED_INTENT_PENDING')
            if self.admission_marker_exists():raise FenceError('ADMISSION_INTENT_PENDING')
            self.base.require_allowed(state,uid,core.address)
            self.base.require_anchor(state,(core,),sources)
            for source in sources:self.base.require_allowed(state,source.native_identity.split('/',1)[0],source.address)
            writer_lease.validate()
            record['lock_dev'],record['lock_ino']=self.base._lock_identity
            record['writer_lock_identity']=list(self._writer_identity)
            record['directory_identity']=list(self.base._directory_identity)
            record['mount_identity']=list(self.base._mount_identity)
            raw=(json.dumps(record,sort_keys=True,separators=(',',':'))+'\n').encode()
            fd=os.open(self.marker,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
            inode=os.fstat(fd).st_ino
        try:
            if _ci_after_create is not None:_ci_after_create()
            offset=0
            while offset<len(raw):
                written=os.write(fd,raw[offset:])
                if written<=0:raise OSError('intent write failed')
                offset+=written
            os.fsync(fd)
        finally:os.close(fd)
        directory_fd=os.open(self.directory,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        try:os.fsync(directory_fd)
        finally:os.close(directory_fd)
        if _original_systemd_identity()!=identity:
            raise FenceError('SYSTEMD_IDENTITY_CHANGED_DURING_INTENT')
        return Intent(self,nonce,inode,hashlib.sha256(raw).hexdigest(),uid,core.address,writer_lease,_CAPABILITY)
    def _verify(self,intent,core,sources,state):
        if (type(intent)is not Intent or intent.capability is not _CAPABILITY
                or intent.owner is not self or intent.pid!=os.getpid()):
            raise FenceError('ONLY_OWN_LIVE_INTENT')
        intent.writer_lease.validate()
        fd=os.open(self.marker,os.O_RDONLY|os.O_NOFOLLOW)
        try:
            st=os.fstat(fd)
            if (not stat.S_ISREG(st.st_mode) or st.st_ino!=intent.inode or st.st_nlink!=1
                    or stat.S_IMODE(st.st_mode)!=0o600 or st.st_uid!=self.directory.stat().st_uid):
                raise FenceError('INTENT_INODE_CHANGED')
            raw=os.read(fd,65537)
        finally:os.close(fd)
        if len(raw)>65536 or hashlib.sha256(raw).hexdigest()!=intent.digest:
            raise FenceError('INTENT_CONTENT_CHANGED')
        record=json.loads(raw)
        import guarded_unit_identity as identity
        if (record.get('unit')!=os.environ.get('CI_CONTROLLER_UNIT')
                or record.get('invocation_id')!=os.environ.get('INVOCATION_ID')
                or record.get('start_ticks')!=identity._startticks(os.getpid())
                or (record.get('lock_dev'),record.get('lock_ino'))!=self.base._lock_identity
                or record.get('directory_identity')!=list(self.base._directory_identity)
                or record.get('mount_identity')!=list(self.base._mount_identity)
                or record.get('writer_lock_identity')!=list(self._writer_identity)
                or Path('/proc/self/cgroup').read_text().splitlines()!=['0::'+record.get('control_group','')]):
            raise FenceError('SAME_PROCESS_LIFETIME_REQUIRED')
        current=sorted((x.native_identity,x.address) for x in sources)
        uid=core.native_identity.split('/',1)[0]
        if (record['nonce']!=intent.nonce or record['pid']!=os.getpid()
                or record['boot_id']!=Path('/proc/sys/kernel/random/boot_id').read_text().strip()
                or record['netns']!=os.readlink('/proc/self/ns/net')
                or uid!=intent.core_uid or core.address!=intent.core_address
                or core.native_identity!=record['core_identity']
                or current!=[tuple(x) for x in record['sources']]):
            raise FenceError('INTENT_OBSERVATION_CHANGED')
        now=time.monotonic()
        if core.expires<=now+.250 or any(x.expires<=now+.250 for x in sources):
            raise FenceError('INTENT_READY_EVIDENCE_EXPIRED')
        self.base.require_allowed(state,uid,core.address)
        self.base.require_anchor(state,(core,),sources)
        for source in sources:self.base.require_allowed(state,source.native_identity.split('/',1)[0],source.address)
    def barrier(self,intent,core,sources):
        # Recheck immediately before prepare/send. No send or long fsync under
        # this lock; the durable marker keeps later participants closed.
        with self.base.locked(nonblocking=True) as state:
            self._verify(intent,core,sources,state)
        return _PositivePermit(self,intent,core,tuple(sources),_CAPABILITY)
    def finish(self,intent,pin,emitted):
        import native_structure
        intent.writer_lease.validate()
        # Exact same-process Guardian pin; no generic caller boolean.
        if (type(pin) is not native_structure._GuardedStructure
                or pin.capability is not native_structure._CAPABILITY
                or pin.pid!=os.getpid() or not intent.sent
                or pin.emitter is not intent.emitter
                or pin.receipt.get('genid')!=intent.before_genid
                or type(emitted) is not dict
                or any(pin.receipt.get(k)!=emitted.get(k) for k in ('genid','after','wire_sha256','programs'))):
            raise FenceError('ORIGINAL_CONFIRMED_GUARDIAN_PIN_REQUIRED')
        with self.base.locked(nonblocking=True):
            st=os.lstat(self.marker)
            if st.st_ino!=intent.inode or intent.owner is not self or intent.pid!=os.getpid():
                raise FenceError('INTENT_IDENTITY_CHANGED')
            os.unlink(self.marker)
        directory_fd=os.open(self.directory,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        try:os.fsync(directory_fd)
        finally:os.close(directory_fd)


class _PositivePermit:
    def __init__(self,owner,intent,core,sources,capability):
        if capability is not _CAPABILITY:raise FenceError('ONLY_LOCAL_POSITIVE_PERMIT')
        self.owner,self.intent,self.core,self.sources=owner,intent,core,sources
        self.pid=os.getpid();self.capability=capability

def authorize_positive(permit,plan,*,consume=False,emitter=None,genid=None):
    if type(permit) is not _PositivePermit or permit.capability is not _CAPABILITY or permit.pid!=os.getpid():
        raise FenceError('ORIGINAL_DURABLE_INTENT_REQUIRED')
    if permit.intent.sent:raise FenceError('POSITIVE_INTENT_ALREADY_SENT_OR_UNKNOWN')
    permit.owner.barrier(permit.intent,permit.core,permit.sources)
    core=[x for x in plan['backends'] if x['kind']=='core']
    if len(core)!=1 or core[0]['address']!=permit.core.address:
        raise FenceError('POSITIVE_PLAN_CORE_DIFFERS_FROM_INTENT')
    sources=plan['cores']
    if (len(sources)!=len(permit.sources)
            or {x['address'] for x in sources}!={x.address for x in permit.sources}
            or any(x['deadline']>int(source.expires*1e9)
                   for x in sources for source in permit.sources if source.address==x['address'])):
        raise FenceError('POSITIVE_PLAN_REVERSE_DIFFERS_FROM_INTENT')
    if consume:
        if (emitter is None or type(genid) is not int
                or getattr(emitter,'writer_lease',None) is not permit.intent.writer_lease):
            raise FenceError('EXACT_EMITTER_GENERATION_REQUIRED')
        permit.intent.sent=True
        permit.intent.before_genid=genid
        permit.intent.emitter=emitter

class _EmergencyPermit:
    def __init__(self,coord,verified,registry,nl,genid,epoch,recovery_epoch,marker_identity,writer_lease,emitter,capability):
        if capability is not _CAPABILITY:raise FenceError('ONLY_GUARDIAN_EMERGENCY_PERMIT')
        self.coord,self.verified,self.registry,self.nl=coord,verified,registry,nl
        self.genid,self.epoch,self.recovery_epoch,self.marker_identity=genid,epoch,recovery_epoch,marker_identity
        self.writer_lease=writer_lease;self.emitter=emitter
        self.pid=os.getpid();self.netns=os.readlink('/proc/self/ns/net')
        self.until=time.monotonic()+5;self.used=False;self.capability=capability

def _marker_identity(coord):
    with coord.base.locked(nonblocking=True):
        fd=os.open(coord.marker,os.O_RDONLY|os.O_NOFOLLOW)
        try:
            st=os.fstat(fd);raw=os.read(fd,65537)
        finally:os.close(fd)
        if (not stat.S_ISREG(st.st_mode) or st.st_nlink!=1 or stat.S_IMODE(st.st_mode)!=0o600
                or st.st_uid!=coord.directory.stat().st_uid or not raw or len(raw)>65536):
            raise FenceError('EXACT_DURABLE_INTENT_REQUIRED_FOR_DENY')
        record=json.loads(raw)
        if record.get('schema')!='ci_guarded_drain_intent_v3':
            raise FenceError('EXACT_DURABLE_INTENT_SCHEMA_REQUIRED')
        return (st.st_dev,st.st_ino,hashlib.sha256(raw).hexdigest(),record)

def _durable_marker_identity(coord):
    # Visible bytes do not prove durability. Guardian fsyncs the exact opened
    # marker and parent outside flock, then compares it again under the lock.
    fd=os.open(coord.marker,os.O_RDONLY|os.O_NOFOLLOW)
    try:
        before=os.fstat(fd);raw=os.read(fd,65537)
        if (not stat.S_ISREG(before.st_mode) or before.st_nlink!=1
                or stat.S_IMODE(before.st_mode)!=0o600
                or before.st_uid!=coord.directory.stat().st_uid or not raw or len(raw)>65536):
            raise FenceError('EXACT_DURABLE_INTENT_REQUIRED_FOR_DENY')
        record=json.loads(raw)
        if record.get('schema')!='ci_guarded_drain_intent_v3':
            raise FenceError('EXACT_DURABLE_INTENT_SCHEMA_REQUIRED')
        os.fsync(fd)
        directory_fd=os.open(coord.directory,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        try:os.fsync(directory_fd)
        finally:os.close(directory_fd)
        after=os.fstat(fd)
        key=lambda st:(st.st_dev,st.st_ino,st.st_uid,st.st_mode,st.st_size,st.st_mtime_ns,st.st_ctime_ns)
        if key(before)!=key(after):raise FenceError('INTENT_CHANGED_DURING_DURABILITY')
        expected=(before.st_dev,before.st_ino,hashlib.sha256(raw).hexdigest())
    finally:os.close(fd)
    observed=_marker_identity(coord)
    if observed[:3]!=expected:raise FenceError('INTENT_CHANGED_AFTER_DURABILITY')
    return observed

def mint_emergency(coord,verified,registry,emitter):
    import guarded_verifier
    import guarded_refresh_registry_DRAFT as registry_module
    import guarded_generation
    import guarded_nl as nl
    if (type(verified) is not guarded_verifier._VerifiedGeneration
            or verified.capability is not guarded_verifier._VERIFIED_CAPABILITY
            or verified.guardian_pid!=os.getpid() or verified.sender_pidfd is None
            or type(registry) is not registry_module.GuardianRefreshRegistry
            or registry.pid!=os.getpid() or registry.cache is not verified.reader_cache):
        raise FenceError('AUTHENTICATED_GUARDIAN_IDENTITY_REQUIRED')
    import writer_lease_v3_DRAFT as lease_module
    if type(emitter) is not guarded_generation.GenerationEmitter or emitter.pid!=os.getpid():
        raise FenceError('ORIGINAL_GUARDIAN_EMITTER_REQUIRED')
    writer_lease=emitter.writer_lease
    if type(writer_lease) is not lease_module.WriterLease:
        raise FenceError('GUARDIAN_WRITER_LEASE_REQUIRED')
    writer_lease.validate()
    with registry.lock:
        if registry.state!='UNKNOWN':raise FenceError('INVALIDATED_GUARDIAN_REQUIRED')
    with registry.cache.lock:
        if not registry.cache.errors:raise FenceError('REAL_EXPLICIT_READER_INVALIDATION_REQUIRED')
        epoch=registry.cache.guard_invalidation_epoch
        recovery_epoch=registry.cache.guard_recovery_epoch
    marker=_durable_marker_identity(coord);record=marker[3]
    if (record['pid']!=verified.anchor['pid']
            or record['start_ticks']!=verified.anchor['start_ticks']
            or (record.get('lock_dev'),record.get('lock_ino'))!=coord.base._lock_identity
            or record.get('directory_identity')!=list(coord.base._directory_identity)
            or record.get('mount_identity')!=list(coord.base._mount_identity)
            or record.get('writer_lock_identity')!=list(writer_lease.coord._writer_identity)
            or any(record.get(k)!=registry.prep.get(k) for k in
                   ('pid','start_ticks','unit','invocation_id','control_group'))
            or record['boot_id']!=Path('/proc/sys/kernel/random/boot_id').read_text().strip()
            or record['netns']!=os.readlink('/proc/self/ns/net')):
        raise FenceError('SAME_MARKER_OWNER_BOOT_AND_NETNS_REQUIRED')
    return _EmergencyPermit(coord,verified,registry,nl,nl.genid(emitter.nl),epoch,recovery_epoch,marker,writer_lease,emitter,_CAPABILITY)

def authorize_emergency(permit,plan,netlink,*,consume):
    if (type(permit) is not _EmergencyPermit or permit.capability is not _CAPABILITY
            or permit.pid!=os.getpid() or permit.netns!=os.readlink('/proc/self/ns/net')
            or permit.used or time.monotonic()>=permit.until):
        raise FenceError('ORIGINAL_LIVE_EMERGENCY_PERMIT_REQUIRED')
    if permit.emitter.nl is not netlink or permit.emitter.writer_lease is not permit.writer_lease:
        raise FenceError('SAME_GUARDIAN_EMITTER_REQUIRED')
    permit.writer_lease.validate()
    if plan['backends'] or plan['cores'] or plan['prom'] or set(plan['maps'])!={'inbound','reverse'}:
        raise FenceError('EMERGENCY_DENY_MUST_HAVE_NO_POSITIVE_BACKENDS')
    if any(deadline!=1 for rows in plan['maps'].values() for _,deadline in rows):
        raise FenceError('EMERGENCY_MAPS_MUST_BE_EXPIRED')
    with permit.registry.lock:
        if permit.registry.state!='UNKNOWN':raise FenceError('GUARDIAN_NOT_IN_UNKNOWN')
    with permit.registry.cache.lock:
        current_epoch=permit.registry.cache.guard_invalidation_epoch
        if not permit.registry.cache.errors:
            raise FenceError('READER_NO_LONGER_INVALID')
        if permit.registry.cache.guard_recovery_epoch!=permit.recovery_epoch:
            raise FenceError('READER_RECOVERED_SINCE_PERMIT')
        if type(current_epoch) is not int or current_epoch<permit.epoch:
            raise FenceError('READER_INVALIDATION_EPOCH_ROLLED_BACK')
    current=_marker_identity(permit.coord)
    if current[:3]!=permit.marker_identity[:3] or permit.nl.genid(netlink)!=permit.genid:
        raise FenceError('EMERGENCY_MARKER_OR_GENID_CHANGED')
    if consume:permit.used=True
