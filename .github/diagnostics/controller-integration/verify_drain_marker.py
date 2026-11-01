"""Concurrent process and crash checks for CI-only v3 marker."""
import fcntl,os,subprocess,sys,tempfile,threading,time,types
from pathlib import Path
from unittest import mock
HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE/'runtime'))
import drain_marker_v3_DRAFT as v3
import guarded_admission_v3_DRAFT as admission

def backend(uid='old',ip='10.244.1.2'):
    now=time.monotonic()
    return types.SimpleNamespace(native_identity=uid+'/container',address=ip,expires=now+20)

def must_hold(fn,reason):
    try:fn()
    except v3.FenceError as error:
        assert str(error)==reason,(str(error),reason)
    else:raise AssertionError('expected hold '+reason)

with tempfile.TemporaryDirectory(prefix='ci-admission-reserve-') as tmp:
    coord=v3.CoordinatorV3(Path(tmp)/'coord');coord.initialize_for_ci()
    with mock.patch.dict(os.environ,{'CI_GUARDED_FIXTURE':'1'}):
        original_fsync=os.fsync;seen=[]
        def during_reservation(fd):
            with coord.base.locked(nonblocking=True):seen.append(True)
            must_hold(lambda:admission.evaluate({},coord),'ADMISSION_INTENT_PENDING')
            return original_fsync(fd)
        with mock.patch.object(v3.os,'fsync',side_effect=during_reservation):
            reservation=coord.reserve_admission()
        assert len(seen)==2 and coord.admission_marker_exists()
        with coord.writer_lease() as lease:
            core=backend()
            must_hold(lambda:coord.begin(core,[core],writer_lease=lease),'ADMISSION_INTENT_PENDING')
        coord.cancel_admission(reservation)
        assert not coord.admission_marker_exists()
        must_hold(lambda:coord.cancel_admission(reservation),'ORIGINAL_UNUSED_ADMISSION_RESERVATION_REQUIRED')
        child=os.fork()
        if child==0:
            coord.reserve_admission(_ci_after_create=lambda:os._exit(19))
            os._exit(20)
        _pid,status=os.waitpid(child,0)
        assert os.waitstatus_to_exitcode(status)==19 and coord.admission_marker_exists()
        must_hold(lambda:admission.evaluate({},coord),'ADMISSION_INTENT_PENDING')
        print('PASS admission reservation excludes writers during fsync, cancellation works, crash holds',flush=True)

with tempfile.TemporaryDirectory(prefix='ci-admission-effect-') as tmp:
    coord=v3.CoordinatorV3(Path(tmp)/'coord');coord.initialize_for_ci()
    with mock.patch.dict(os.environ,{'CI_GUARDED_FIXTURE':'1'}):
        r=coord.reserve_admission()
        result=coord.begin_admission_effect(r,'00000000-0000-0000-0000-000000000001','10.244.1.1',
                    anchor_uid='00000000-0000-0000-0000-000000000002',anchor_address='10.244.1.2')
        assert result['fence_persisted'] and not result['delete_allowed'] and not result['production_authority']
        must_hold(lambda:coord.cancel_admission(r),'ORIGINAL_UNUSED_ADMISSION_RESERVATION_REQUIRED')
        must_hold(lambda:admission.evaluate({},coord),'ADMISSION_INTENT_PENDING')
        with coord.base.locked(nonblocking=True) as state:
            assert state['retired']=={'00000000-0000-0000-0000-000000000001':'10.244.1.1'}
            assert state['anchor']=={'uid':'00000000-0000-0000-0000-000000000002','address':'10.244.1.2'}
        print('PASS effect and fence persist outside lock while reservation keeps DELETE held',flush=True)

with tempfile.TemporaryDirectory(prefix='ci-effect-failure-') as tmp:
    coord=v3.CoordinatorV3(Path(tmp)/'coord');coord.initialize_for_ci()
    with mock.patch.dict(os.environ,{'CI_GUARDED_FIXTURE':'1'}):
        r=coord.reserve_admission()
        with mock.patch.object(coord.base,'_write',side_effect=OSError('injected fsync uncertainty')):
            try:coord.begin_admission_effect(r,'00000000-0000-0000-0000-000000000001','10.244.1.1',
                        anchor_uid='00000000-0000-0000-0000-000000000002',anchor_address='10.244.1.2')
            except OSError:pass
            else:raise AssertionError('failed fence write accepted')
        assert coord.admission_marker_exists() and coord.admission_effect.exists()
        must_hold(lambda:coord.cancel_admission(r),'ORIGINAL_UNUSED_ADMISSION_RESERVATION_REQUIRED')
        must_hold(lambda:admission.evaluate({},coord),'ADMISSION_INTENT_PENDING')

with tempfile.TemporaryDirectory(prefix='ci-effect-tamper-') as tmp:
    coord=v3.CoordinatorV3(Path(tmp)/'coord');coord.initialize_for_ci()
    with mock.patch.dict(os.environ,{'CI_GUARDED_FIXTURE':'1'}):
        r=coord.reserve_admission();original_fsync=os.fsync;tampered=[]
        def corrupt_effect(fd):
            original_fsync(fd)
            if not tampered and coord.admission_effect.exists():
                with coord.admission_effect.open('wb') as f:f.write(b'{}\n')
                tampered.append(True)
        with mock.patch.object(v3.os,'fsync',side_effect=corrupt_effect):
            must_hold(lambda:coord.begin_admission_effect(r,'00000000-0000-0000-0000-000000000001','10.244.1.1',
                        anchor_uid='00000000-0000-0000-0000-000000000002',anchor_address='10.244.1.2'),
                      'ADMISSION_EFFECT_CHANGED')
        with coord.base.locked(nonblocking=True) as state:assert state['retired']=={}
        must_hold(lambda:admission.evaluate({},coord),'ADMISSION_INTENT_PENDING')
        must_hold(lambda:coord.cancel_admission(r),'ORIGINAL_UNUSED_ADMISSION_RESERVATION_REQUIRED')

with tempfile.TemporaryDirectory(prefix='ci-effect-delay-') as tmp:
    coord=v3.CoordinatorV3(Path(tmp)/'coord');coord.initialize_for_ci()
    with mock.patch.dict(os.environ,{'CI_GUARDED_FIXTURE':'1'}):
        r=coord.reserve_admission();entered=threading.Event();release=threading.Event();results=[]
        original_fsync=os.fsync
        def delayed_fsync(fd):
            if not entered.is_set():
                entered.set()
                if not release.wait(5):raise RuntimeError('fixture release timed out')
            return original_fsync(fd)
        def run_effect():
            try:results.append(coord.begin_admission_effect(r,'00000000-0000-0000-0000-000000000001','10.244.1.1',
                anchor_uid='00000000-0000-0000-0000-000000000002',anchor_address='10.244.1.2'))
            except BaseException as error:results.append(error)
        with mock.patch.object(v3.os,'fsync',side_effect=delayed_fsync):
            worker=threading.Thread(target=run_effect);worker.start()
            try:
                assert entered.wait(5)
                with coord.base.locked(nonblocking=True):pass
                must_hold(lambda:admission.evaluate({},coord),'ADMISSION_INTENT_PENDING')
                must_hold(lambda:coord.cancel_admission(r),'ORIGINAL_UNUSED_ADMISSION_RESERVATION_REQUIRED')
            finally:release.set();worker.join(5)
        assert not worker.is_alive() and len(results)==1 and isinstance(results[0],dict) and not results[0]['delete_allowed']
        print('PASS delayed effect fsync leaves locks available and admission held',flush=True)

with tempfile.TemporaryDirectory(prefix='ci-anchor-delete-') as tmp:
    coord=v3.CoordinatorV3(Path(tmp)/'coord');coord.initialize_for_ci()
    with coord.admission_or_other_writer() as state:
        coord.base.retire(state,'00000000-0000-0000-0000-000000000001','10.244.1.1',
                          anchor_uid='00000000-0000-0000-0000-000000000002',anchor_address='10.244.1.2')
    with mock.patch.dict(os.environ,{'CI_GUARDED_FIXTURE':'1'}):
        r=coord.reserve_admission()
        must_hold(lambda:coord.begin_admission_effect(r,'00000000-0000-0000-0000-000000000002','10.244.1.2',
                     anchor_uid='00000000-0000-0000-0000-000000000003',anchor_address='10.244.1.3'),
                  'ACTIVE_ANCHOR_DELETE_HELD')
        coord.cancel_admission(r)
    print('PASS failed effect remains held and DELETE of the active anchor is denied',flush=True)

with tempfile.TemporaryDirectory(prefix='ci-drain-marker-') as tmp:
    coord=v3.CoordinatorV3(Path(tmp)/'coord');coord.initialize_for_ci()
    core=backend()
    must_hold(lambda:coord.begin(core,[core],writer_lease=object()),
              'ORIGINAL_WRITER_LEASE_REQUIRED_BEFORE_INTENT')
    writer_lease=coord.acquire_writer_lease()
    exclusive_fd=os.open(coord.writer_lock,os.O_RDWR)
    try:
        try:fcntl.flock(exclusive_fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError:pass
        else:raise AssertionError('recovery EX acquired while writer lease lives')
    finally:os.close(exclusive_fd)
    must_hold(lambda:admission.evaluate({},coord),'GUARDED_BPF_ADMISSION_NOT_VALIDATED')
    # fsync runs with no flock: another participant can acquire it, sees the
    # visible pending marker and denies rather than waiting for durability.
    real_fsync=os.fsync;checks=[]
    def observed_fsync(fd):
        with coord.base.locked(nonblocking=True):checks.append(True)
        must_hold(lambda:admission.evaluate({},coord),'GUARDED_INTENT_PENDING')
        return real_fsync(fd)
    with mock.patch.object(v3.os,'fsync',side_effect=observed_fsync):
        intent=coord.begin(core,[core],writer_lease=writer_lease)
    assert len(checks)==2 and coord.marker_exists()
    permit=coord.barrier(intent,core,[core])
    plan={'backends':[{'kind':'core','address':core.address,'deadline':int(core.expires*1e9)}],
          'cores':[{'address':core.address,'deadline':int(core.expires*1e9)}],
          'prom':[],'maps':{'inbound':[],'reverse':[]}}
    must_hold(lambda:v3.authorize_positive(None,plan),'ORIGINAL_DURABLE_INTENT_REQUIRED')
    v3.authorize_positive(permit,plan)
    must_hold(lambda:v3.authorize_emergency(None,{'backends':[],'cores':[],'prom':[],
              'maps':{'inbound':[],'reverse':[]}},None,consume=False),'ORIGINAL_LIVE_EMERGENCY_PERMIT_REQUIRED')
    must_hold(lambda:v3.mint_emergency(coord,object(),object(),None),
              'AUTHENTICATED_GUARDIAN_IDENTITY_REQUIRED')
    must_hold(lambda:admission.evaluate({},coord),'GUARDED_INTENT_PENDING')
    # The common native-IO boundary must also reject direct cold and hot
    # writers, including callers that bypass controller wrappers.
    import native_io
    native_io.CI_DRAIN_COORDINATION=coord
    with mock.patch.dict(os.environ,{'CI_GUARDED_FIXTURE':'1'}):
        for role in ('initial_static_apply','hot_dynamic_apply'):
            must_hold(lambda:native_io.command([],role=role),'GUARDED_INTENT_PENDING')
    must_hold(lambda:coord.barrier(intent,backend(ip='10.244.1.3'),[core]),'INTENT_OBSERVATION_CHANGED')
    # Unknown outcome has no cleanup path; another begin is refused.
    must_hold(lambda:coord.begin(core,[core],writer_lease=writer_lease),'GUARDED_INTENT_PENDING')
    # Guardian does its own file+directory fsync without holding flock; merely
    # seeing a complete JSON marker is not accepted as a durability proof.
    checks=[]
    with mock.patch.object(v3.os,'fsync',side_effect=observed_fsync):
        marker=v3._durable_marker_identity(coord)
    assert len(checks)==2 and marker[1]==intent.inode
    # Policy-only fake token exercises monotone epochs, strict denial and genid
    # checks; mint_emergency above still rejects an unauthenticated caller.
    cache=types.SimpleNamespace(lock=threading.Lock(),guard_invalidation_epoch=3,
        guard_recovery_epoch=1,errors={'rds':'failure'})
    registry=types.SimpleNamespace(lock=threading.Lock(),state='UNKNOWN',cache=cache)
    nl=types.SimpleNamespace(genid=lambda _:99)
    fake_emitter=types.SimpleNamespace(nl=None,writer_lease=writer_lease)
    emergency=v3._EmergencyPermit(coord,object(),registry,nl,99,3,1,marker,writer_lease,fake_emitter,v3._CAPABILITY)
    denial={'backends':[],'cores':[],'prom':[],'maps':{'inbound':[('00'*12,1)],'reverse':[('01'*12,1)]}}
    cache.guard_invalidation_epoch=5
    v3.authorize_emergency(emergency,denial,None,consume=False)
    cache.guard_invalidation_epoch=2
    must_hold(lambda:v3.authorize_emergency(emergency,denial,None,consume=False),
              'READER_INVALIDATION_EPOCH_ROLLED_BACK')
    cache.guard_invalidation_epoch=5
    cache.errors={}
    must_hold(lambda:v3.authorize_emergency(emergency,denial,None,consume=False),
              'READER_NO_LONGER_INVALID')
    cache.errors={'rds':'failure'};cache.guard_recovery_epoch=2
    must_hold(lambda:v3.authorize_emergency(emergency,denial,None,consume=False),
              'READER_RECOVERED_SINCE_PERMIT')
    cache.guard_recovery_epoch=1
    positive=dict(denial,backends=[{'kind':'core'}])
    must_hold(lambda:v3.authorize_emergency(emergency,positive,None,consume=False),
              'EMERGENCY_DENY_MUST_HAVE_NO_POSITIVE_BACKENDS')
    nl.genid=lambda _:100
    must_hold(lambda:v3.authorize_emergency(emergency,denial,None,consume=False),
              'EMERGENCY_MARKER_OR_GENID_CHANGED')
    nl.genid=lambda _:99
    v3.authorize_emergency(emergency,denial,None,consume=True)
    must_hold(lambda:v3.authorize_emergency(emergency,denial,None,consume=False),
              'ORIGINAL_LIVE_EMERGENCY_PERMIT_REQUIRED')
    assert coord.marker_exists()
    v3.authorize_positive(permit,plan,consume=True,emitter=types.SimpleNamespace(writer_lease=writer_lease),genid=1)
    must_hold(lambda:v3.authorize_positive(permit,plan),'POSITIVE_INTENT_ALREADY_SENT_OR_UNKNOWN')
    assert coord.marker_exists()
    writer_lease.close()
    exclusive_fd=os.open(coord.writer_lock,os.O_RDWR)
    try:fcntl.flock(exclusive_fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
    finally:os.close(exclusive_fd)

# The actual Cache increments recovery epoch when a stored error clears,
# even if another failure appears before an observer samples it.
import observations
cache=observations.Cache()
with cache.lock:
    before=cache._state_key();cache.errors={'rds':'failure'};cache._changed(before)
    before=cache._state_key();cache.errors={};cache._changed(before)
    recovered=cache.guard_recovery_epoch
    before=cache._state_key();cache.errors={'rds':'failure-again'};cache._changed(before)
    assert recovered>0 and cache.guard_recovery_epoch==recovered

# A UID may change while IP, role and deadlines stay the same. This checks
# invalidation before a simulated retirement; it grants no DELETE authority.
import nft_owner
same_ip_cache=observations.Cache()
now=time.monotonic();deadline=now+20
uid1='00000000-0000-0000-0000-000000000001'
uid2='00000000-0000-0000-0000-000000000002'
def topology(identity):
    core=nft_owner.Backend('core','10.244.1.2',9443,now,deadline,identity+'/container')
    return ([core],[core],[],{},frozenset(),deadline)
same_ip_cache.publish_topology(topology(uid1))
with same_ip_cache.lock:witness_epoch=same_ip_cache.guard_invalidation_epoch
same_ip_cache.publish_topology(topology(uid1))
with same_ip_cache.lock:assert same_ip_cache.guard_invalidation_epoch==witness_epoch
same_ip_cache.publish_topology(topology(uid2))
with tempfile.TemporaryDirectory(prefix='ci-stale-uid-') as tmp:
    test_coord=v3.CoordinatorV3(Path(tmp)/'coord');test_coord.initialize_for_ci()
    def retire_if_current():
        with test_coord.admission_or_other_writer() as state:
            with same_ip_cache.lock:
                if same_ip_cache.guard_invalidation_epoch!=witness_epoch:
                    raise v3.FenceError('READER_CHANGED_BEFORE_RETIRE')
                test_coord.base.retire(state,uid1,'10.244.1.1',anchor_uid=uid2,anchor_address='10.244.1.2')
    must_hold(retire_if_current,'READER_CHANGED_BEFORE_RETIRE')
    with test_coord.admission_or_other_writer() as state:
        assert state['retired']=={} and state['anchor'] is None
print('PASS same-IP Core UID replacement blocks experimental retirement and leaves fence unchanged',flush=True)

with tempfile.TemporaryDirectory(prefix='ci-drain-retired-') as tmp:
    coord=v3.CoordinatorV3(Path(tmp)/'coord');coord.initialize_for_ci()
    old='00000000-0000-0000-0000-000000000001'
    new='00000000-0000-0000-0000-000000000002'
    with coord.admission_or_other_writer() as state:
        coord.base.retire(state,old,'10.244.1.1',anchor_uid=new,anchor_address='10.244.1.2')
    assert not coord.marker_exists()
    with coord.writer_lease() as lease:
        third=types.SimpleNamespace(kind='core',native_identity='00000000-0000-0000-0000-000000000003/container',
                                    address='10.244.1.3',expires=time.monotonic()+20)
        must_hold(lambda:coord.begin(third,[third],writer_lease=lease),'ACTIVE_ANCHOR_MUST_REMAIN_SELECTED')
    with coord.admission_or_other_writer() as state:
        must_hold(lambda:coord.base.retire(state,'00000000-0000-0000-0000-000000000003',
                    '10.244.1.3',anchor_uid='00000000-0000-0000-0000-000000000004',
                    anchor_address='10.244.1.4'),'ACTIVE_ANCHOR_CANNOT_BE_REPLACED')
    import nft_owner as nft
    nft.CI_DRAIN_COORDINATION=coord
    stale=types.SimpleNamespace(kind='core',native_identity=old+'/container',address='10.244.1.1')
    good=types.SimpleNamespace(kind='core',native_identity=new+'/container',address='10.244.1.2')
    reused=types.SimpleNamespace(kind='core',native_identity=new+'/container',address='10.244.1.1')
    native_io.CI_DRAIN_COORDINATION=coord
    def must_not_send(call,reason):
        try:call()
        except nft.NoSend as error:assert error.guard==reason,(error.guard,reason)
        else:raise AssertionError('expected pre-send hold '+reason)
    with mock.patch.dict(os.environ,{'CI_GUARDED_FIXTURE':'1'}):
        must_not_send(lambda:nft.native_batch([stale],apply=True),'DRAFT_RETIRED_CORE_SOURCE')
        must_not_send(lambda:nft.native_batch([good],core_sources=[good,stale],apply=True),
                      'DRAFT_RETIRED_CORE_SOURCE')
        must_not_send(lambda:nft.native_batch([reused],apply=True),'DRAFT_RETIRED_CORE_SOURCE')
        must_not_send(lambda:nft.native_batch([good],core_sources=[good,reused],apply=True),
                      'DRAFT_RETIRED_CORE_SOURCE')
        try:native_io.command([],role='hot_dynamic_apply')
        except native_io.process.Held as error:assert str(error)=='TYPED_NATIVE_WRITER_REQUIRED'
        else:raise AssertionError('untyped native write was accepted')
        import partial_refresh_DRAFT as partial
        captured=[]
        def fake_partial(backends,*,core_sources,**kwargs):
            captured.extend(core_sources)
            raise v3.FenceError('AFTER_POSSIBLE_PARTIAL_SEND')
        with mock.patch.object(partial,'native_partial',side_effect=fake_partial):
            try:nft.native_refresh([good],core_sources=[good,stale],prometheus_sources=[],
                                   apply=lambda:True,_ownership=None)
            except v3.FenceError as error:assert str(error)=='AFTER_POSSIBLE_PARTIAL_SEND'
            else:raise AssertionError('partial writer error was recast or swallowed')
        assert captured==[good]
        captured.clear()
        with mock.patch.object(partial,'native_partial',side_effect=fake_partial):
            try:nft.native_refresh([good],core_sources=[good,reused],prometheus_sources=[],
                                   apply=lambda:True,_ownership=None)
            except v3.FenceError as error:assert str(error)=='AFTER_POSSIBLE_PARTIAL_SEND'
            else:raise AssertionError('reused-IP source was not filtered')
        assert captured==[good]

with tempfile.TemporaryDirectory(prefix='ci-drain-lock-seal-') as tmp:
    coord=v3.CoordinatorV3(Path(tmp)/'coord');coord.initialize_for_ci()
    with coord.base.locked():pass
    original=coord.base.lock_path.with_name('original.lock')
    os.rename(coord.base.lock_path,original)
    coord.base.lock_path.touch(mode=0o600)
    must_hold(lambda:coord.base.locked().__enter__(),'COORDINATION_LOCK_REPLACED')
    coord.base.lock_path.unlink();os.rename(original,coord.base.lock_path)
    os.chmod(coord.base.lock_path,0o666)
    must_hold(lambda:coord.base.locked().__enter__(),'ROOT_PRIVATE_STABLE_LOCK_REQUIRED')
    os.chmod(coord.base.lock_path,0o600)
    with coord.base.locked():
        coord.base.revalidate_lock()
        os.chmod(coord.base.lock_path,0o666)
        must_hold(coord.base.revalidate_lock,'ROOT_PRIVATE_STABLE_LOCK_REQUIRED')
        os.chmod(coord.base.lock_path,0o600)
    os.chmod(coord.directory,0o777)
    must_hold(lambda:coord.base.locked().__enter__(),'ROOT_PRIVATE_COORDINATION_DIRECTORY_REQUIRED')
    os.chmod(coord.directory,0o700)
    parent=coord.directory.parent
    os.chmod(parent,0o777)
    must_hold(lambda:coord.base.locked().__enter__(),'ROOT_CONTROLLED_COORDINATION_ANCESTOR_REQUIRED')
    os.chmod(parent,0o700)

with tempfile.TemporaryDirectory(prefix='ci-emitter-bind-') as tmp:
    import guarded_generation as generation
    import writer_lease_v3_DRAFT as writer_module
    coord=v3.CoordinatorV3(Path(tmp)/'coord');coord.initialize_for_ci()
    generation.CI_DRAIN_COORDINATION=coord
    events=[]
    class FailedBindSocket:
        def bind(self,_):raise OSError('CI_BIND_FAILED')
        def close(self):events.append('socket_closed')
    close_original=writer_module.WriterLease.close
    def close_observed(lease):
        events.append('lease_closed');return close_original(lease)
    fake_transition=types.SimpleNamespace(OriginalPin=lambda _:object())
    with mock.patch.dict(os.environ,{'CI_GUARDED_FIXTURE':'1'}),          mock.patch.object(generation.socket,'socket',return_value=FailedBindSocket()),          mock.patch.object(writer_module.WriterLease,'close',close_observed):
        try:generation.GenerationEmitter(initial_raw=b'ci',transition=fake_transition,
                receipt_dir=Path(tmp),host_netns='not-current')
        except OSError as error:assert str(error)=='CI_BIND_FAILED'
        else:raise AssertionError('failed socket bind unexpectedly succeeded')
    assert events==['socket_closed','lease_closed'],events
    fd=os.open(coord.writer_lock,os.O_RDWR)
    try:fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
    finally:os.close(fd)
    # If socket close itself is uncertain, the lease must remain live.
    class UnknownCloseSocket(FailedBindSocket):
        def close(self):events.append('socket_close_unknown');raise OSError('CI_CLOSE_UNKNOWN')
    acquired=[];original_acquire=coord.acquire_writer_lease
    def capture_lease():
        lease=original_acquire();acquired.append(lease);return lease
    with mock.patch.dict(os.environ,{'CI_GUARDED_FIXTURE':'1'}),          mock.patch.object(coord,'acquire_writer_lease',side_effect=capture_lease),          mock.patch.object(generation.socket,'socket',return_value=UnknownCloseSocket()):
        try:generation.GenerationEmitter(initial_raw=b'ci',transition=fake_transition,
                receipt_dir=Path(tmp),host_netns='not-current')
        except OSError as error:assert str(error)=='CI_CLOSE_UNKNOWN'
        else:raise AssertionError('uncertain close unexpectedly succeeded')
    assert len(acquired)==1 and not acquired[0].closed
    fd=os.open(coord.writer_lock,os.O_RDWR)
    try:
        try:fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError:pass
        else:raise AssertionError('uncertain socket close released writer lease')
    finally:os.close(fd);acquired[0].close()

with tempfile.TemporaryDirectory(prefix='ci-drain-crash-') as tmp:
    coord=v3.CoordinatorV3(Path(tmp)/'coord');coord.initialize_for_ci()
    program="""
import os,sys,time,types
sys.path.insert(0,sys.argv[1])
import drain_marker_v3_DRAFT as v3
coord=v3.CoordinatorV3(sys.argv[2]); now=time.monotonic()
core=types.SimpleNamespace(native_identity='old/container',address='10.244.1.2',expires=now+20)
lease=coord.acquire_writer_lease()
coord.begin(core,[core],writer_lease=lease,_ci_after_create=lambda:os._exit(81))
"""
    unit='ci-drain-marker-crash-'+str(os.getpid())
    p=subprocess.run(['/usr/bin/systemd-run','--quiet','--wait','--pipe','--unit='+unit,
        '--setenv=CI_CONTROLLER_UNIT='+unit+'.service','/usr/bin/python3','-I','-B','-c',program,
        str(HERE/'runtime'),str(coord.directory)],stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=20)
    assert p.returncode==81 and coord.marker_exists() and coord.marker.stat().st_size==0, (p.returncode,p.stderr.decode())
    must_hold(lambda:admission.evaluate({},coord),'GUARDED_INTENT_PENDING')
print('PASS CI marker blocks admission/writers, no flock during fsync, crash leaves hold; BPF admission remains disabled',flush=True)
