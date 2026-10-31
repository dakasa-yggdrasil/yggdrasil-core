"""Concurrent process and crash checks for CI-only v3 marker."""
import os,subprocess,sys,tempfile,threading,time,types
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

with tempfile.TemporaryDirectory(prefix='ci-drain-marker-') as tmp:
    coord=v3.CoordinatorV3(Path(tmp)/'coord');coord.initialize_for_ci()
    core=backend()
    must_hold(lambda:admission.evaluate({},coord),'GUARDED_BPF_ADMISSION_NOT_VALIDATED')
    # fsync runs with no flock: another participant can acquire it, sees the
    # visible pending marker and denies rather than waiting for durability.
    real_fsync=os.fsync;checks=[]
    def observed_fsync(fd):
        with coord.base.locked(nonblocking=True):checks.append(True)
        must_hold(lambda:admission.evaluate({},coord),'GUARDED_INTENT_PENDING')
        return real_fsync(fd)
    with mock.patch.object(v3.os,'fsync',side_effect=observed_fsync):
        intent=coord.begin(core,[core])
    assert len(checks)==2 and coord.marker_exists()
    permit=coord.barrier(intent,core,[core])
    plan={'backends':[{'kind':'core','address':core.address,'deadline':int(core.expires*1e9)}],
          'cores':[{'address':core.address,'deadline':int(core.expires*1e9)}],
          'prom':[],'maps':{'inbound':[],'reverse':[]}}
    must_hold(lambda:v3.authorize_positive(None,plan),'ORIGINAL_DURABLE_INTENT_REQUIRED')
    v3.authorize_positive(permit,plan)
    must_hold(lambda:v3.authorize_emergency(None,{'backends':[],'cores':[],'prom':[],
              'maps':{'inbound':[],'reverse':[]}},None,consume=False),'ORIGINAL_LIVE_EMERGENCY_PERMIT_REQUIRED')
    must_hold(lambda:v3.mint_emergency(coord,object(),object(),None,None),
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
    must_hold(lambda:coord.begin(core,[core]),'GUARDED_INTENT_PENDING')
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
    emergency=v3._EmergencyPermit(coord,object(),registry,nl,99,3,1,marker,v3._CAPABILITY)
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
    v3.authorize_positive(permit,plan,consume=True,emitter=object(),genid=1)
    must_hold(lambda:v3.authorize_positive(permit,plan),'POSITIVE_INTENT_ALREADY_SENT_OR_UNKNOWN')
    assert coord.marker_exists()

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

with tempfile.TemporaryDirectory(prefix='ci-drain-retired-') as tmp:
    coord=v3.CoordinatorV3(Path(tmp)/'coord');coord.initialize_for_ci()
    old='00000000-0000-0000-0000-000000000001'
    new='00000000-0000-0000-0000-000000000002'
    with coord.admission_or_other_writer() as state:
        coord.base.retire(state,old,'10.244.1.1',anchor_uid=new,anchor_address='10.244.1.2')
    assert not coord.marker_exists()
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

with tempfile.TemporaryDirectory(prefix='ci-drain-crash-') as tmp:
    coord=v3.CoordinatorV3(Path(tmp)/'coord');coord.initialize_for_ci()
    program="""
import os,sys,time,types
sys.path.insert(0,sys.argv[1])
import drain_marker_v3_DRAFT as v3
coord=v3.CoordinatorV3(sys.argv[2]); now=time.monotonic()
core=types.SimpleNamespace(native_identity='old/container',address='10.244.1.2',expires=now+20)
coord.begin(core,[core],_ci_after_create=lambda:os._exit(81))
"""
    unit='ci-drain-marker-crash-'+str(os.getpid())
    p=subprocess.run(['/usr/bin/systemd-run','--quiet','--wait','--pipe','--unit='+unit,
        '--setenv=CI_CONTROLLER_UNIT='+unit+'.service','/usr/bin/python3','-I','-B','-c',program,
        str(HERE/'runtime'),str(coord.directory)],stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=20)
    assert p.returncode==81 and coord.marker_exists() and coord.marker.stat().st_size==0, (p.returncode,p.stderr.decode())
    must_hold(lambda:admission.evaluate({},coord),'GUARDED_INTENT_PENDING')
print('PASS CI marker blocks admission/writers, no flock during fsync, crash leaves hold; BPF admission remains disabled',flush=True)
