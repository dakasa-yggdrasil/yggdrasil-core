"""Actual legacy cached_cycle and Guardian kernel read, disposable nft netns.

The cache, owner and deployment-specific compiled AST pin are fixtures. This
exercises real controller/native process and Guardian methods, not BPF service
integration or production authority.
"""
import base64,hashlib,importlib.util,json,os,select,socket,struct,subprocess,sys,tempfile,threading,time,types,uuid
from pathlib import Path
HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE/'runtime'))
import controller,native_io,native_structure,nft_owner as nft
spec=importlib.util.spec_from_file_location('test_guardian',HERE/'network_guardian.py');guardian=importlib.util.module_from_spec(spec);spec.loader.exec_module(guardian)
spec=importlib.util.spec_from_file_location('test_coverage',HERE/'coverage.py');coverage=importlib.util.module_from_spec(spec);spec.loader.exec_module(coverage)
def cmd(*args,inp=None):return subprocess.run(args,input=inp,stdout=subprocess.PIPE,stderr=subprocess.PIPE,check=True,timeout=10).stdout

def endpoints(suffix):
    now=time.monotonic();ttl=29 if os.environ.get('CI_HOLDER_TEST')=='1' else 20
    entries=[nft.Backend(k,a,nft.PORTS[k],now,now+ttl,
             ('00000000-0000-0000-0000-%012x/synthetic'%suffix if k=='core' else 'synthetic')) for k,a in
       [('core','10.244.1.'+str(suffix)),('broker','172.18.1.2'),('rds','172.18.1.3'),('redis','172.18.1.4')]]
    prom=nft.PrometheusSource('10.244.1.9',now,now+ttl,'synthetic')
    return entries,[entries[0]],[prom]
class Cache:
    def __init__(self):self.rows=endpoints(1);self.key='initial'
    def commit_snapshot(self):return ((*self.rows,{},1),self.key,1)
class Ownership:
    def permit_original_send(self,lease,started):
        assert not lease.dispatched
        lease.dispatched=True

def cycle(cache,previous):
    original=nft.owned_table_snapshot();token=nft.revalidate_owned_ruleset(original)
    lease=types.SimpleNamespace(token=token,dispatched=False)
    result,key=controller.cached_cycle(types.SimpleNamespace(cache=cache),lease,Ownership(),apply=lambda:True,previous_key=previous)
    return result,key,lease

def main():
    assert os.geteuid()==0
    import guarded_unit_identity
    peer,peer2=socket.socketpair()
    try:
        argv=Path('/proc/self/cmdline').read_bytes().rstrip(b'\0').decode().split('\0')
        observed=guarded_unit_identity.authenticate(peer,unit=os.environ['CI_CONTROLLER_UNIT'],
                   expected_invocation=os.environ['INVOCATION_ID'],expected_argv=argv,
                   source_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest())
        assert observed['pid']==os.getpid();os.close(observed['pidfd'])
    finally:peer.close();peer2.close()
    print('PASS actual controller process systemd identity, source hash and cgroup',flush=True)
    import drain_marker_v3_DRAFT as drain_v3
    drain=drain_v3.CoordinatorV3(HERE/'drain-coordinator')
    drain.initialize_for_ci();controller.CI_DRAIN_COORDINATION=drain;native_io.CI_DRAIN_COORDINATION=drain;nft.CI_DRAIN_COORDINATION=drain
    native_io.ROOT=HERE/'custody';native_io.ROOT.mkdir(mode=0o700)
    native_io.configure();native_io.end_initialization()
    cmd('/usr/sbin/nft','-f','-',inp=nft.render((),now=time.monotonic(),table_exists=False).encode())
    raw=cmd('/usr/sbin/nft','-a','-j','list','ruleset');owned,_=native_structure._objects(raw)
    expected=hashlib.sha256(native_structure._structure(owned,keep_handles=False)).hexdigest()
    assert len(owned)==47
    guardian.RUNTIME=HERE/'runtime';guardian.RUNTIME_HASHES['nft_owner.py']=hashlib.sha256((guardian.RUNTIME/'nft_owner.py').read_bytes()).hexdigest()
    observer=guardian.Owner.__new__(guardian.Owner)
    observer.C=types.SimpleNamespace(_objects=native_structure._objects,_structure=native_structure._structure,AST47=expected)
    observer.coverage=coverage
    observer.call=lambda name,args:cmd(*args)
    cache=Cache();one,key,lease=cycle(cache,None)
    assert one['applied'] and lease.dispatched and key=='initial'
    snapshot,_=observer.kernel();assert snapshot['all_four_backends_and_reverse_sources_positive']
    same,key,silent=cycle(cache,key);assert same is None and not silent.dispatched
    # Model guard admission->durable retirement with no pending v3 marker.
    # A stale Core must not be reinstalled; a fresh Ready anchor may preserve
    # its own untouched TTL while the other backends refresh atomically.
    anchor_rows=endpoints(2);cache.rows=anchor_rows;cache.key='anchor'
    anchored,key,_=cycle(cache,key);assert anchored['applied'] and key=='anchor'
    old_uid='00000000-0000-0000-0000-000000000001'
    new_uid='00000000-0000-0000-0000-000000000002'
    with drain.admission_or_other_writer() as state:
        drain.base.retire(state,old_uid,'10.244.1.1',anchor_uid=new_uid,anchor_address='10.244.1.2')
    assert not drain.marker_exists()
    stale=endpoints(1);fresh=endpoints(2)
    cache.rows=(stale[0],fresh[1],fresh[2]);cache.key='retired-stale'
    partial,pending,partial_lease=cycle(cache,key)
    assert partial['applied'] and partial['core_pending'] and pending==key and partial_lease.dispatched
    after=cmd('/usr/sbin/nft','-a','list','table','inet','dakasa_capacity_network')
    assert b'10.244.1.2' in after and b'10.244.1.1' not in after
    print('PASS retired Core blocked after marker cleared; fresh anchor preserved, other maps refreshed',flush=True)
    old_native=native_io.process.native;calls=[]
    def ambiguous(*args,**kwargs):
        value=old_native(*args,**kwargs)
        if args[0]==['/usr/sbin/nft','-f','-']:
            calls.append(1)
            raise native_io.process.Held('CI_INJECT_AFTER_NATIVE_COMPLETED')
        return value
    native_io.process.native=ambiguous
    cache.rows=endpoints(2);cache.key='uncertain'
    try:
        try:cycle(cache,key);raise AssertionError('unknown effect reported success')
        except nft.Held as e:assert str(e)=='CI_INJECT_AFTER_NATIVE_COMPLETED'
    finally:native_io.process.native=old_native
    assert len(calls)==1
    uncertain=cmd('/usr/sbin/nft','-a','list','table','inet','dakasa_capacity_network');assert b'10.244.1.2' in uncertain
    # External genid advance and a NEW observation produce a distinct transaction.
    # CI owns this entire namespace and no other mutator. This does not establish
    # those prerequisites or any receipt/attachment truth in production.
    cmd('/usr/sbin/nft','add','table','ip','ci_unrelated')
    third=endpoints(3);anchor=endpoints(2)
    cache.rows=(third[0],anchor[1],anchor[2]);cache.key='third-unretired'
    new,newkey,newlease=cycle(cache,key)
    assert new['applied'] and new['core_pending'] and newlease.dispatched and newkey==key
    fresh=cmd('/usr/sbin/nft','-a','list','table','inet','dakasa_capacity_network')
    assert b'10.244.1.2' in fresh and b'10.244.1.3' not in fresh
    print('PASS third unretired Core cannot replace fenced anchor before DELETE',flush=True)
    snapshot,_=observer.kernel();assert snapshot['all_four_backends_and_reverse_sources_positive']
    print('PASS actual cached_cycle/native nft, Guardian.kernel, unknown effect no replay, fresh distinct reconciliation',flush=True)
    print('BOUNDARY: private CI namespace; cache, owner and compiled AST pin are fixtures; legacy relative TTL',flush=True)
    # The following independent BPF fixture uses a fresh, isolated fence.
    # Preserve the earlier fixture directory; this is not an anchor release.
    (HERE/'drain-coordinator').rename(HERE/'drain-coordinator-anchored-fixture')
    drain=drain_v3.CoordinatorV3(HERE/'drain-coordinator');drain.initialize_for_ci()
    controller.CI_DRAIN_COORDINATION=drain;native_io.CI_DRAIN_COORDINATION=drain;nft.CI_DRAIN_COORDINATION=drain
    # Experiment with the actual LAB 47->50 sender, fixed to this CI namespace.
    # The CI fixture supplies observation/lease authority and is not a service.
    import guarded_nl as nl, guarded_generation as generation, transition_structure_DRAFT as trans
    generation.CI_DRAIN_COORDINATION=drain
    native_structure.COMPILED_NATIVE_AST_SHA256=expected
    raw=cmd('/usr/sbin/nft','-a','-j','list','ruleset')
    original=trans.OriginalPin(raw)
    records=[];first=None;uncertain=None;recovery=None;positive=None;session=None;server=None;prepared=None;initial_prepared=None;watch=None;pre_guardian=None;rotation_session=None;rotation_prepared=None
    server_done=threading.Event();server_errors=[];worker=None;holder_unit=None;holder_pidfd=None;holder_state=None;holder_cgroup=None;holder_unit_file=None;continuous_readers=[]
    try:
        import ci_reader_fixture,guarded_sources,guarded_preparation
        real_cache=ci_reader_fixture.start(endpoints)
        guardian_cache=ci_reader_fixture.start(endpoints,setup=False)
        assert real_cache is not guardian_cache
        guard_expected=guarded_sources.build_expected(guardian_cache)
        initial_prepared=guarded_preparation.PreparedGeneration(real_cache,
                 deadline_ceilings={role:guard_expected[role] for role in ('inbound','reverse')})
        def encode(row):return {'kind':getattr(row,'kind','prom'),'address':row.address,'port':getattr(row,'port',0),'deadline':int(row.expires*1e9)}
        receipts=HERE/'receipts';receipts.mkdir(mode=0o700)
        first=generation.GenerationEmitter(initial_raw=raw,transition=trans,receipt_dir=receipts,host_netns=os.environ['CI_HOST_NETNS'])
        original_rows,_=native_structure._objects(raw)
        # Fixture pin is built from this disposable namespace; production
        # must instead use its own qualified echo/read-adoption pin.
        pin=native_structure._OriginalStructure(native_structure._handles(original_rows),None,native_structure._CAPABILITY,
                  proof_kind='original_owned_read_adoption',original_native_read_sha256=hashlib.sha256(raw).hexdigest())
        origin=native_structure.begin_guarded_transition(pin)
        initial_entries,initial_cores,_,_,_=real_cache.snapshot()
        initial_core=next(x for x in initial_entries if x.kind=='core')
        initial_drain_intent=drain.begin(initial_core,initial_cores,writer_lease=first.writer_lease)
        drain.barrier(initial_drain_intent,initial_core,initial_cores)
        try:
            with drain.admission_or_other_writer():pass
            raise AssertionError('pending guarded intent did not block admission')
        except drain_v3.FenceError as error:
            assert str(error)=='GUARDED_INTENT_PENDING'
        import ci_guardian47_unit
        pre_guardian=ci_guardian47_unit.Guardian47(root=HERE,origin=origin)
        stop=threading.Event();wake=threading.Event()
        owner=native_structure._OwnershipReader(pin,stop,wake);owner.start();lease=None
        try:
            deadline=time.monotonic()+5
            while lease is None and time.monotonic()<deadline:
                handed,error=owner.take()
                if handed is None:wake.wait(.05);wake.clear()
                else:lease=handed[0]
            assert lease is not None
            handoff,pending_key=controller.cached_guarded_cycle(types.SimpleNamespace(cache=real_cache),lease,owner,
                  emitter=first,prepared=initial_prepared,apply=lambda:True,previous_key=None,transition_origin=origin,
                  guardian_session=pre_guardian.session,drain_intent=initial_drain_intent)
            assert pending_key is not None and handoff['guardian_receipt_acceptance_pending'] is True
            emitted=handoff['native_result']
        finally:
            if lease is not None:owner.release(lease)
            stop.set();wake.set();owner.close_join(time.monotonic()+5)
        assert emitted['ok'] and first.state=='AWAITING_FIXTURE_VERIFICATION'
        import guarded_verifier,guarded_live_observation
        first_maps={role:[(item.hex(),deadline) for item,deadline in sorted(nl.map_rows(rec['map_id']))]
                    for role,rec in zip(('inbound','reverse'),emitted['programs'])}
        erows,ecores,eprom,eerrors,_=real_cache.snapshot();assert not eerrors
        first_plan={'maps':first_maps,'backends':[encode(x) for x in erows],
                    'cores':[encode(x) for x in ecores],'prom':[encode(x) for x in eprom]}
        anchor={'pid':os.getpid(),'start_ticks':nl.startticks(os.getpid()),'netns':os.readlink('/proc/self/ns/net'),
                'initial':base64.b64encode(raw).decode()}
        probe=HERE/'runtime'/'ci_nl_probe.py'
        verified=guarded_verifier.verify_and_seal(result=emitted,anchor=anchor,plan=first_plan,receipt_dir=receipts,
                    reader_cache=guardian_cache,nl=nl,sources=guarded_sources,transition=trans,coverage=coverage,
                    probe_path=probe,probe_sha256=hashlib.sha256(probe.read_bytes()).hexdigest())
        guarded_context={'verified':verified,'verifier':guarded_verifier,'sources':guarded_sources,'nl':nl,
                         'transition':trans,'live':guarded_live_observation,'probe':probe,
                         'probe_sha256':hashlib.sha256(probe.read_bytes()).hexdigest()}
        live,_=observer.kernel(guarded=guarded_context)
        assert live['scope']=='guarded50_non_authorizing_ci_lab' and live['kernel']['all_four_backends_and_reverse_sources_positive']
        assert live['live']['grant_authority'] is False
        print('PASS Owner.kernel guarded 50 with real source/tuple join and original receipt',flush=True)
        import ci_guardian_unit
        watch=ci_guardian_unit.Watch(root=HERE,anchor=anchor,result=emitted,plan=first_plan,existing=pre_guardian)
        assert watch.peer['pid']==pre_guardian.session.pid
        print('PASS cached_guarded_cycle with actual original 47 ownership reader and BPF emitter',flush=True)
        try:first.submit({},[]);raise AssertionError('unverified generation allowed another send')
        except RuntimeError as e:assert str(e)=='ONLY_READY_SAME_OWNER'
        # Pause observation explicitly during the in-flight handoff. This is
        # a measured sampling gap, not continuous monitoring or authority.
        import guarded_sender_session_DRAFT as direct_sender
        sender_channel=watch.sender_channel()
        guardian_spec={'unit':pre_guardian.unit,'invocation_id':pre_guardian.session.invocation,
                       'argv':pre_guardian.argv,'source_sha256':hashlib.sha256(Path(pre_guardian.argv[2]).read_bytes()).hexdigest()}
        rotation_session=direct_sender.SenderSession(sender_channel,identity=guarded_unit_identity,guardian=guardian_spec,nl=nl)
        positive_guardian=native_structure.begin_lab_positive_guardian_session(rotation_session,origin,pre_guardian.session)
        attestation=rotation_session.attest_current(first.receipt,until_ns=time.monotonic_ns()+8_000_000_000)
        active_pin=native_structure.accept_lab_positive_guarded(positive_guardian,first,attestation)
        first.activate_lab_guarded_pin(active_pin)
        drain.finish(initial_drain_intent,active_pin,emitted)
        assert not drain.marker_exists()
        uid=initial_core.native_identity.split('/',1)[0]
        witness=watch.admission_witness(uid,initial_core.address)
        assert witness['event']=='ADMISSION_WITNESS',witness
        assert witness['fifty_object_shape_verified'] and witness['bpf_rule_fd_map_join_verified']
        assert not witness['kubernetes_proven'] and not witness['production_authority']
        assert watch.admission_witness('wrong-uid',initial_core.address)['event']=='ADMISSION_HOLD'
        print('PASS Guardian-owned 50-object BPF/rules/Reader read-only witness and UID mismatch HOLD',flush=True)
        if os.environ.get('CI_TEST_EXPIRED_PERMIT')=='1':
            ceiling=guarded_sources.build_expected(guardian_cache)
            rotation_prepared=guarded_preparation.PreparedGeneration(real_cache,
                         deadline_ceilings={role:ceiling[role] for role in ('inbound','reverse')})
            descriptors=list(rotation_prepared.fixture_descriptors(real_cache))
            rows,cores,_,_,_=real_cache.snapshot()
            core=next(x for x in rows if x.kind=='core')
            expired_intent=drain.begin(core,cores,writer_lease=first.writer_lease);drain.barrier(expired_intent,core,cores)
            watch.prepare(descriptors)
            permit=rotation_session.prepare(descriptors,until_ns=time.monotonic_ns()+1_500_000_000)
            before=nl.genid(first.nl)
            while time.monotonic_ns()<=permit.deadline_ns:time.sleep(.01)
            try:rotation_session.consume(permit,descriptors);raise AssertionError('expired permit accepted')
            except direct_sender.Held as error:assert str(error)=='ORIGINAL_PERMIT_DEADLINE_EXPIRED'
            try:rotation_session.consume(permit,descriptors);raise AssertionError('expired permit reused')
            except direct_sender.Held as error:assert str(error)=='EXACT_SINGLE_USE_SENDER_PERMIT_REQUIRED'
            pending=watch.pending_state()
            assert pending['pending'] and pending['possible_send'] and nl.genid(first.nl)==before
            assert drain.marker_exists() and first.counter==1 and not (receipts/'INTENT-002.json').exists()
            print('PASS expired Guardian permit and v3 marker remain pending without nft send',flush=True)
            verified.close()
            return
        if os.environ.get('CI_CONTINUOUS_TEST')=='1':
            # Guardian owns the synthetic DNS socket. Separate controller-side
            # Readers use that actual socket and refresh route/topology while
            # the Guardian keeps its independent Reader and kernel validation.
            continuous_readers=[ci_reader_fixture.LiveReaders(endpoints,shared_dns=True),
                                ci_reader_fixture.LiveReaders(endpoints,shared_dns=True)]
            real_cache,guardian_cache=(r.cache for r in continuous_readers)
        import ci_guarded_driver
        external_stop=threading.Event() if os.environ.get('CI_CONTINUOUS_TEST')=='1' else None
        timeout_test=os.environ.get('CI_ADMISSION_TIMEOUT_TEST')=='1'
        source_timeout_test=os.environ.get('CI_SOURCE_TIMEOUT_TEST')=='1'
        if source_timeout_test:
            continuous_readers[1].close()
            guardian_cache.dns_failed('rds','CI_PERSISTENT_DNS_FAILURE')
        post_marker_test=os.environ.get('CI_POST_MARKER_TEST')=='1'
        timer=threading.Timer(42,external_stop.set) if external_stop is not None and not (timeout_test or post_marker_test or source_timeout_test) else None
        if timer is not None:timer.daemon=True;timer.start()
        admission_release=None;admission_errors=[]
        if external_stop is not None and not (post_marker_test or source_timeout_test):
            reservation=drain.reserve_admission()
            def release_admission():
                try:
                    time.sleep(3 if timeout_test else .6);drain.cancel_admission(reservation)
                except BaseException as error:admission_errors.append(error)
            admission_release=threading.Thread(target=release_admission,daemon=True);admission_release.start()
        driver=ci_guarded_driver.GuardedDriver(watch=watch,sender=rotation_session,emitter=first,
                  positive_session=positive_guardian,ceiling_cache=guardian_cache,endpoints=endpoints,
                  max_commits=(12 if external_stop is not None else (4 if os.environ.get('CI_HOLDER_TEST')=='1' else 2)),
                  stop_signal=external_stop)
        if external_stop is not None:
            changed=[False]
            def change_cache_once():
                if changed[0]:return
                changed[0]=True
                entries,cores,prom=endpoints(4)
                real_cache.publish_topology(([x for x in entries if x.kind in ('core','broker')],cores,prom,{},frozenset(),time.monotonic()+35))
            driver._ci_before_pre_intent=change_cache_once
        if post_marker_test:
            begin=driver.begin_handoff
            def inject_after_prepare():
                begin()
                original_snapshot=real_cache.commit_snapshot
                owner_thread=threading.get_ident();calls=[0]
                def changed_snapshot():
                    if threading.get_ident()==owner_thread:
                        calls[0]+=1
                        if calls[0]==2:
                            entries,cores,prom=endpoints(4)
                            real_cache.publish_topology(([x for x in entries if x.kind in ('core','broker')],cores,prom,{},frozenset(),time.monotonic()+35))
                            real_cache.commit_snapshot=original_snapshot
                    return original_snapshot()
                real_cache.commit_snapshot=changed_snapshot
            driver.begin_handoff=inject_after_prepare
        running_reader=types.SimpleNamespace(cache=real_cache,stop=threading.Event(),shutdown_deadline=lambda:time.monotonic()+5)
        try:
            loop_result=controller.serve_hot(running_reader,active_pin,apply=lambda:True,guarded_driver=driver)
        except drain_v3.AdmissionPendingBeforeIntent:
            if not timeout_test:raise
            assert driver.pre_intent_waits>0 and not drain.marker_exists() and first.counter==1
            assert not (receipts/'INTENT-002.json').exists()
            admission_release.join(5)
            assert not admission_release.is_alive() and not admission_errors
            print('PASS admission hold timed out before marker or prepare; no sender replay or new wire',flush=True)
            return
        except ci_guarded_driver.TransientSourcesBeforeIntent:
            if not source_timeout_test:raise
            assert driver.pre_source_waits>0 and not drain.marker_exists() and first.counter==1
            assert not (receipts/'INTENT-002.json').exists()
            print('PASS persistent missing original DNS source times out before marker or prepare, no wire',flush=True)
            return
        except nft.Held as error:
            if not post_marker_test or str(error)!='SAME_CACHE_SNAPSHOT_BEFORE_GUARDED_HANDOFF':raise
            pending=watch.pending_state()
            assert pending['pending'] and drain.marker_exists() and first.counter==1
            assert not (receipts/'INTENT-002.json').exists()
            print('PASS cache change after prepare remains HOLD with marker and Guardian reservation, no replay',flush=True)
            return
        if timeout_test or post_marker_test or source_timeout_test:raise AssertionError('EXPECTED_PRE_SEND_HOLD')
        if timer is not None:
            timer.cancel();timer.join();admission_release.join(2)
            assert not admission_release.is_alive() and not admission_errors and driver.pre_intent_waits>0 and driver.pre_intent_discards>0
            print('PASS concurrent cache change and admission reservation before sender intent; bounded typed retry and fresh observations',flush=True)
            assert external_stop.is_set() and len(driver.results)>=7
            span=driver.results[-1]['confirmed_ns']-driver.results[0]['confirmed_ns']
            assert span>=35_000_000_000,(span,len(driver.results))
            print('PASS independent stop signal, confirmed guarded rotations span %.2fs with no expired prior window'%(span/1e9),flush=True)
            # The following fault injection is a separate, bounded scenario.
            # Keep its last actual source evidence/deadlines but stop these
            # controller-side producers so they cannot replace the snapshot
            # in the middle of the deliberately suspended handoff. Guardian's
            # independent live Readers and all deadline guards remain active.
            for active_reader in continuous_readers:active_reader.close()
            continuous_readers=[]
        else:assert len(driver.results)==(4 if os.environ.get('CI_HOLDER_TEST')=='1' else 2)
        assert loop_result['sequence']==len(driver.results)+1 and loop_result['production_authority'] is False
        next_pin=loop_result['pin'];result=driver.results[-1]['native_result']
        while True:
            sample=watch.read()
            if sample['event']=='SAMPLE':
                assert sample['generation']==result['after'];break
            if sample['event']!='FINISHED':raise RuntimeError('UNEXPECTED_POST_ROTATION_EVENT:'+str(sample))
        print('PASS serve_hot and separate Guardian verified guarded rotations: '+json.dumps([
            {key:round(row[key],2) for key in ('lease_age_ms','dispatch_ms','watch_pause_ms')} for row in driver.results]),flush=True)
        if os.environ.get('CI_HOLDER_TEST')=='1':
            coverage_state=watch.control('COVERAGE','COVERAGE')
            assert coverage_state['qualified'] and coverage_state['coverage_ns']>=15_000_000_000,coverage_state
            holder_unit='ci-rotation-holder-'+uuid.uuid4().hex+'.service'
            go=HERE/'holder-go';acquired=HERE/'holder-acquired';revoked=HERE/'holder-revoked'
            holder_script=(HERE/'runtime'/'ci_holder_process.py').resolve()
            holder_argv=['/usr/bin/python3','-B',str(holder_script),str(watch.path),str(go),str(acquired),str(revoked)]
            holder_unit_file=Path('/run/systemd/system')/holder_unit
            holder_unit_file.write_text('[Service]\nType=simple\nRuntimeMaxSec=20s\nExecStart=/usr/bin/nsenter --net=/proc/'+str(os.getpid())+'/ns/net '+' '.join(holder_argv)+'\n')
            subprocess.run(['/usr/bin/systemctl','daemon-reload'],check=True,timeout=10)
            subprocess.run(['/usr/bin/systemctl','start',holder_unit],check=True,timeout=10)
            until=time.monotonic()+8
            while True:
                holder_props=guarded_unit_identity._properties(holder_unit)
                if holder_props['ActiveState']=='active' and int(holder_props['MainPID'])>1:break
                if time.monotonic()>until:raise RuntimeError('HOLDER_SYSTEMD_NOT_ACTIVE')
                time.sleep(.02)
            import recovery_terminality_DRAFT as terminal
            holder_pid=int(holder_props['MainPID']);holder_pidfd=os.pidfd_open(holder_pid)
            holder_cgroup=terminal._CgroupRoot(holder_props['ControlGroup'])
            watch.control('CONNECT_HOLDER','HOLDER_LISTENING',unit=holder_unit,invocation=holder_props['InvocationID'],
                          argv=holder_argv,source_sha256=hashlib.sha256(holder_script.read_bytes()).hexdigest())
            go.touch(mode=0o600)
            while True:
                connected=watch.read()
                if connected['event']=='HOLDER_CONNECTED':break
                if connected['event'] not in ('SAMPLE','FINISHED'):raise RuntimeError('UNEXPECTED_HOLDER_EVENT:'+str(connected))
            assert connected['pid']==holder_pid and holder_pid!=watch.peer['pid'] and holder_pid!=os.getpid()
            while not acquired.exists():
                if time.monotonic()>until:raise RuntimeError('HOLDER_ACQUISITION_TIMEOUT')
                time.sleep(.01)
            holder_state=json.loads(acquired.read_text())
            assert holder_state['until']>time.monotonic_ns()+500_000_000
            print('PASS separate systemd Guardian and holder; real continuous coverage >=15s and active bounded lease',flush=True)

        # Keep watch running while a second positive transaction is ready to
        # send. The Guardian invalidates its own Reader and wins a distinct
        # genid-fenced deny transaction before the old send is released.
        guard_expected=(ci_guarded_driver.bounded_guardian_ceilings(watch,guardian_cache)
                        if external_stop is not None else guarded_sources.build_expected(guardian_cache))
        failure_prepared=guarded_preparation.PreparedGeneration(real_cache,
                deadline_ceilings={role:guard_expected[role] for role in ('inbound','reverse')})
        failure_records=failure_prepared.fixture_descriptors(real_cache)
        failure_entries,failure_cores,_,_,_=real_cache.snapshot()
        failure_core=next(x for x in failure_entries if x.kind=='core')
        failure_drain_intent=drain.begin(failure_core,failure_cores,writer_lease=first.writer_lease)
        drain.barrier(failure_drain_intent,failure_core,failure_cores)
        watch.prepare(failure_records)
        failure_permit=rotation_session.prepare(list(failure_records),until_ns=time.monotonic_ns()+5_000_000_000)
        failure_stop=threading.Event();failure_wake=threading.Event()
        failure_owner=native_structure._OwnershipReader(next_pin,failure_stop,failure_wake);failure_owner.start();failure_lease=None
        entered=threading.Event();release=threading.Event();failure_result=[];failure_errors=[];positive_generation=[];positive_send_time=[]
        failure_order=os.environ.get('CI_FAILURE_ORDER','deny-first')
        assert failure_order in ('deny-first','positive-first')
        class DelayedPositiveSend:
            def __init__(self,inner):self.inner=inner;self.sent=0
            def send(self,payload):
                if self.sent==0 and len(payload)>=6 and struct.unpack_from('<H',payload,4)[0]==0x10:
                    if failure_order=='positive-first':
                        outcome=self.inner.send(payload);self.sent+=1;positive_send_time.append(time.monotonic_ns())
                        probe_sock=socket.socket(socket.AF_NETLINK,socket.SOCK_RAW,12);probe_sock.bind((0,0));probe_sock.settimeout(5)
                        try:positive_generation.append(nl.genid(probe_sock))
                        finally:probe_sock.close()
                    entered.set()
                    if not release.wait(8):raise RuntimeError('CI_RELEASE_TIMEOUT')
                    if failure_order=='positive-first':
                        if os.environ.get('CI_HOLDER_TEST')=='1':raise RuntimeError('CI_POSITIVE_ACK_UNKNOWN_AFTER_SEND')
                        return outcome
                    self.sent+=1
                return self.inner.send(payload)
            def __getattr__(self,name):return getattr(self.inner,name)
        def inject_failure():
            try:
                if not entered.wait(8):raise RuntimeError('POSITIVE_SEND_NOT_REACHED')
                failure_result.append(watch.stop_dns_and_wait_for_autonomous_deny())
            except BaseException as error:failure_errors.append(error)
            finally:release.set()
        injector=threading.Thread(target=inject_failure);injector.start()
        try:
            deadline=time.monotonic()+5
            while failure_lease is None and time.monotonic()<deadline:
                handed,error=failure_owner.take()
                if handed is None:failure_wake.wait(.05);failure_wake.clear()
                else:failure_lease=handed[0]
            assert failure_lease is not None
            first.nl=DelayedPositiveSend(first.nl)
            pending_handoff=None
            try:
                pending_handoff,_=controller.cached_guarded_cycle(types.SimpleNamespace(cache=real_cache),failure_lease,failure_owner,
                     emitter=first,prepared=failure_prepared,apply=lambda:True,previous_key=None,
                     guarded_pin=next_pin,sender_session=rotation_session,sender_permit=failure_permit,
                     drain_intent=failure_drain_intent)
            except Exception as error:
                assert first.state=='HOLD_UNKNOWN_OR_UNVERIFIED' and first.nl.sent==1
                if holder_state is not None:
                    assert str(error)=='CI_POSITIVE_ACK_UNKNOWN_AFTER_SEND'
                    assert not (receipts/('ACK-%03d.json'%first.counter)).exists()
                    print('PASS holder-active 50-to-50 sender ACK unobserved; intent retained and no replay',flush=True)
            injector.join(10);assert not injector.is_alive() and not failure_errors and len(failure_result)==1
            denied_by_guardian=failure_result[0];assert denied_by_guardian['reader_invalidated']
            if holder_state is not None:
                assert failure_order=='positive-first' and len(positive_send_time)==1
                assert positive_send_time[0]<holder_state['until'],'HOLDER_EXPIRED_BEFORE_SEND'
                until=time.monotonic()+5
                while not revoked.exists():
                    if time.monotonic()>until:raise RuntimeError('HOLDER_REVOCATION_NOT_OBSERVED')
                    time.sleep(.01)
                poll=select.poll();poll.register(holder_pidfd,select.POLLIN)
                assert poll.poll(5000),'HOLDER_PIDFD_NOT_TERMINAL'
                deadline=time.monotonic()+5
                while True:
                    holder_terminal=terminal._systemd(holder_unit)
                    if (holder_terminal['InvocationID']==holder_props['InvocationID']
                        and holder_terminal['MainPID']=='0' and holder_terminal['ActiveState']=='failed'
                        and holder_terminal['SubState']=='failed' and holder_terminal['Job']==''
                        and not holder_cgroup.populated()):break
                    if time.monotonic()>deadline:raise RuntimeError('HOLDER_CGROUP_OR_UNIT_NOT_TERMINAL:'+str(holder_terminal))
                    time.sleep(.02)
                assert terminal._systemd(holder_unit)==holder_terminal and not holder_cgroup.populated()
                print('PASS 50-to-50 send with active holder; Guardian revoked it and original systemd invocation/cgroup terminated',flush=True)
            assert drain.marker_exists(), 'uncertain prior intent must remain'
            try:
                with drain.admission_or_other_writer():pass
                raise AssertionError('uncertain intent allowed ordinary admission')
            except drain_v3.FenceError as error:assert str(error)=='GUARDED_INTENT_PENDING'
            prior_generation=next_pin.receipt['after']
            next_generation=lambda value:((value+1)&0xffffffff or 1)
            uncertain_deny=os.environ.get('CI_DENY_ACK_UNCERTAIN')=='1'
            assert denied_by_guardian['original_deny_ack_unknown']==uncertain_deny
            assert denied_by_guardian['distinct_deny_recovery']==uncertain_deny
            print('CI_GENERATION_ORDER',json.dumps({'order':failure_order,'prior':prior_generation,
                  'after_positive_send':positive_generation,'after_deny_ack':denied_by_guardian['genid'],
                  'deny_ack_unknown':uncertain_deny,'recovery_before':denied_by_guardian['recovery_before']}),flush=True)
            if failure_order=='positive-first':
                assert positive_generation==[next_generation(prior_generation)]
                before_deny=positive_generation[0]
            else:
                assert not positive_generation;before_deny=prior_generation
            if uncertain_deny:
                assert denied_by_guardian['recovery_before']==next_generation(before_deny)
                assert denied_by_guardian['genid']==next_generation(denied_by_guardian['recovery_before'])
                assert denied_by_guardian['unknown_wire_sha256']!=denied_by_guardian['wire_sha256']
            else:assert denied_by_guardian['genid']==next_generation(before_deny)
            old_intent=json.loads((receipts/('INTENT-%03d.json'%first.counter)).read_bytes())
            assert old_intent['wire_sha256']!=denied_by_guardian['wire_sha256']
            if pending_handoff is not None:
                assert failure_order=='positive-first' and first.state=='AWAITING_FIXTURE_VERIFICATION'
                # Local ACK alone cannot confirm the successor: the Guardian
                # must reject the old receipt after the newer deny generation.
                try:
                    guarded_verifier.verify_and_seal(result=pending_handoff['native_result'],anchor=anchor,
                         plan=pending_handoff['submitted_plan'],receipt_dir=receipts,reader_cache=guardian_cache,
                         nl=nl,sources=guarded_sources,transition=trans,coverage=coverage,
                         probe_path=probe,probe_sha256=hashlib.sha256(probe.read_bytes()).hexdigest())
                    raise AssertionError('stale success was incorrectly verified')
                except RuntimeError as error:assert str(error) in ('GENERATION_NOT_EXPECTED','INDEPENDENT_PRE_READ_GENERATION')
            current=socket.socket(socket.AF_NETLINK,socket.SOCK_RAW,12);current.bind((0,0));current.settimeout(5)
            try:assert nl.genid(current)==denied_by_guardian['genid']
            finally:current.close()
            kernel_after=coverage.kernel_text(cmd('/usr/sbin/nft','-a','list','table','inet','dakasa_capacity_network'))
            assert all(not rows for rows in kernel_after['dynamic_collections'].values())
            restored=watch.restore_dns()
            assert restored['registry_state']=='UNKNOWN' and restored['genid']==denied_by_guardian['genid']
            assert drain.marker_exists()
            print('PASS DNS recovered; Guardian UNKNOWN and v3 marker remain held',flush=True)
            deny_ms=(denied_by_guardian['deny_ack_ns']-denied_by_guardian['failure_ns'])/1e6
            print('PASS concurrent Reader failure order=%s deny_ack_unknown=%s: distinct Guardian deny and no accepted stale successor; deny_ack_ms=%.2f'%(failure_order,uncertain_deny,deny_ms),flush=True)
        finally:
            release.set();injector.join(10)
            if failure_lease is not None:failure_owner.release(failure_lease)
            failure_stop.set();failure_wake.set();failure_owner.close_join(time.monotonic()+5)
            failure_prepared.close()
        # Independently changed foreign nft object: never infer that the old
        # receipt proves the present generation. The diagnostic recovery sender
        # is distinct and submits a deny-only batch using fresh expired maps.
        cmd('/usr/sbin/nft','add','table','ip','ci_foreign_after_50')
        watch.expect_hold();watch.close();watch=None
        rotation_session.close();rotation_session=None
        pre_guardian.close();pre_guardian=None
        try:observer.kernel(guarded=guarded_context);raise AssertionError('foreign genid change was accepted')
        except RuntimeError as error:assert str(error)=='GUARDED_RECEIPT_GENERATION_CHANGED'
        verified.close()
        # The untouched legacy standalone cases execute separately in a new
        # network namespace and separate filesystem tree. They cannot consume
        # or clear this v3 unknown marker, which remains held here.
        assert drain.marker_exists(), 'unknown v3 intent must not be removed'
        print('PASS v3 unknown marker retained; standalone legacy corpus runs in separate netns',flush=True)
        print('BOUNDARY: independent legacy corpus does not prove v3 recovery',flush=True)
    finally:
        for reader in continuous_readers:reader.close()
        if holder_pidfd is not None:os.close(holder_pidfd)
        if holder_cgroup is not None:holder_cgroup.close()
        if holder_unit is not None:subprocess.run(['/usr/bin/systemctl','stop',holder_unit],check=False,timeout=10)
        if holder_unit_file is not None:
            holder_unit_file.unlink(missing_ok=True);subprocess.run(['/usr/bin/systemctl','daemon-reload'],check=False,timeout=10)
        if pre_guardian is not None:
            log=subprocess.run(['/usr/bin/journalctl','-u',pre_guardian.unit,'--no-pager','-n','100'],capture_output=True,text=True,timeout=10).stdout
            for line in log.splitlines()[-30:]:print('CI_GUARDIAN_LOG '+line,flush=True)
            pre_guardian.close()
        if watch is not None:watch.close()
        if rotation_session is not None:rotation_session.close()
        for rec in records:
            os.close(rec['program_fd']);os.close(rec['map_fd'])
        server_done.set()
        if worker is not None:worker.join(10)
        if session is not None:session.close()
        if server is not None:server.close()
        if server_errors:raise RuntimeError('fixture Guardian failed') from server_errors[0]
        if initial_prepared is not None:initial_prepared.close()
        if rotation_prepared is not None:rotation_prepared.close()
        if prepared is not None:prepared.close()
        if positive is not None:positive.close_private_fixture()
        if recovery is not None:recovery.close_private_fixture()
        if uncertain is not None:uncertain.close_private_fixture()
        if first is not None:first.close_private_fixture()
if __name__=='__main__':main()
