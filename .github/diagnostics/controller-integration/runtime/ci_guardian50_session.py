"""Bounded experimental Guardian watch and registry for a private CI netns.

No production authority. Guardian and controller are separate systemd peers;
synthetic DNS/topology and a fixture-derived 47 pin remain explicit.
"""
import base64,hashlib,importlib.util,json,os,re,socket,struct,threading,time,types
from pathlib import Path
import ci_reader_fixture,guarded_nl as nl,guarded_sources,guarded_unit_identity as identity
import guarded_verifier,guarded_live_observation,transition_structure_DRAFT as trans
import guarded_current15 as current15,guarded_refresh_registry_DRAFT as registry_module
import guarded_effect_lease_two_peers_DRAFT as effect_lease,guarded_lease_ipc_DRAFT as holder_ipc
import guarded_program_identity_DRAFT as program_module,guarded_authority_ci as authority
import native_io,native_structure,nft_owner as nft
import guarded_generation as generation
import drain_marker_v3_DRAFT as drain_v3
import guarded_admission_v3_DRAFT as admission
HERE=Path(__file__).resolve().parent;ROOT=HERE.parent
spec=importlib.util.spec_from_file_location('ci_guardian',ROOT/'network_guardian.py');guardian=importlib.util.module_from_spec(spec);spec.loader.exec_module(guardian)
spec=importlib.util.spec_from_file_location('ci_coverage',ROOT/'coverage.py');coverage=importlib.util.module_from_spec(spec);spec.loader.exec_module(coverage)

def endpoints(suffix):
    now=time.monotonic();ttl=29 if os.environ.get('CI_HOLDER_TEST')=='1' else 20
    entries=[nft.Backend(k,a,nft.PORTS[k],now,now+ttl,
             ('00000000-0000-0000-0000-%012x/synthetic'%suffix if k=='core' else 'synthetic')) for k,a in
       [('core','10.244.1.'+str(suffix)),('broker','172.18.1.2'),('rds','172.18.1.3'),('redis','172.18.1.4')]]
    return entries,[entries[0]],[nft.PrometheusSource('10.244.1.9',now,now+ttl,'synthetic')]

def read_line(channel):
    data=bytearray()
    while len(data)<=1024*1024:
        ch=channel.recv(1)
        if not ch:raise EOFError('fixture peer closed')
        if ch==b'\n':return json.loads(data)
        data.extend(ch)
    raise RuntimeError('bounded fixture message')

def serve(channel,listener):
    verified=None;controller=None;reference=None;holder_channel=None;holder_identity=None;holder_authority=None;holder_session=None;holder_worker=None;chain_before=None;sender_channel=None;auth=None;sender_worker=None;watcher=None;denier=None;deny_recovery=None;readers=None;monitor=None;cache=None
    watch_stop=threading.Event();closing=threading.Event();send_lock=threading.Lock();sender_errors=[]
    def publish(row):
        with send_lock:channel.sendall(nl.canon(row))
    def stop_watch():
        nonlocal watcher
        if watcher is not None:
            watch_stop.set();watcher.join(5)
            if watcher.is_alive():raise RuntimeError('GUARDED_WATCH_DID_NOT_STOP')
            watcher=None
    try:
        generation.CI_DRAIN_COORDINATION=drain_v3.CoordinatorV3(ROOT/'drain-coordinator')
        channel.settimeout(30 if os.environ.get('CI_HOLDER_TEST')=='1' else 15);request=read_line(channel)
        controller=identity.authenticate(channel,unit=request['unit'],expected_invocation=request['invocation'],
                      expected_argv=request['argv'],source_sha256=request['source_sha256'])
        assert controller['pid']==request['anchor']['pid'] and controller['start_ticks']==request['anchor']['start_ticks']
        native_io.ROOT=ROOT/'guardian-custody';native_io.ROOT.mkdir(mode=0o700);native_io.configure();native_io.end_initialization()
        readers=ci_reader_fixture.LiveReaders(endpoints);cache=readers.cache
        original=base64.b64decode(request['anchor']['initial'],validate=True)
        rows,_=native_structure._objects(original)
        native_structure.COMPILED_NATIVE_AST_SHA256=hashlib.sha256(native_structure._structure(rows,keep_handles=False)).hexdigest()
        probe=HERE/'ci_nl_probe.py';probe_sha=hashlib.sha256(probe.read_bytes()).hexdigest()
        def seal(result,plan):
            return guarded_verifier.verify_and_seal(result=result,anchor=request['anchor'],plan=plan,
                  receipt_dir=ROOT/'receipts',reader_cache=cache,nl=nl,sources=guarded_sources,transition=trans,
                  coverage=coverage,probe_path=probe,probe_sha256=probe_sha)
        verified=seal(request['result'],request['plan'])
        guardian.RUNTIME=HERE;guardian.RUNTIME_HASHES['nft_owner.py']=hashlib.sha256((HERE/'nft_owner.py').read_bytes()).hexdigest()
        observer=guardian.Owner.__new__(guardian.Owner)
        observer.C=types.SimpleNamespace(_objects=native_structure._objects,_structure=native_structure._structure,
                        AST47=native_structure.COMPILED_NATIVE_AST_SHA256)
        observer.coverage=coverage;observer.call=lambda name,args:nl.cmd(*args)
        ctx={'verified':verified,'verifier':guarded_verifier,'sources':guarded_sources,'nl':nl,'transition':trans,
             'live':guarded_live_observation,'probe':probe,'probe_sha256':probe_sha}
        def validate(v):
            local=dict(ctx);local['verified']=v
            return observer.kernel(guarded=local)[0]['live']
        reference=program_module.GuardianProgramReference()
        reg=registry_module.GuardianRefreshRegistry(channel,controller,cache=cache,sources=guarded_sources,nl=nl,
                verifier=guarded_verifier,current15=current15,program_module=program_module,reference=reference,validate_kernel=validate)
        chain=current15.CoverageChain(cache,guarded_sources,guarded_verifier);proof=None
        def launch_watch():
            nonlocal watcher,watch_stop
            if watcher is not None:raise RuntimeError('ONE_WATCH_ONLY')
            watch_stop=threading.Event()
            watcher=threading.Thread(target=lambda:observer.watch(guarded=ctx,stop=watch_stop,publish=publish,duration=10))
            watcher.start()
        def serve_sender():
            try:
                while not closing.is_set():
                    req=read_line(sender_channel);schema=req.get('schema')
                    if schema=='lab_positive_generation_attest_request_v1':auth.attest_current(req)
                    elif schema=='lab_sender_prepared_permit_request_v1':auth.answer_once(req)
                    else:raise RuntimeError('UNEXPECTED_GUARDIAN_SENDER_REQUEST')
            except (EOFError,OSError):
                if not closing.is_set():sender_errors.append('SENDER_CLOSED')
            except BaseException as error:
                sender_errors.append(type(error).__name__+':'+str(error))
                print('CI_GUARDIAN_SENDER_ERROR '+type(error).__name__+':'+str(error),flush=True)
        def deny_after_reader_failure():
            nonlocal denier,deny_recovery
            # CI-only: interrupt the independently owned Reader after a
            # positive permit, then fence pending old sends with a distinct
            # expired-map transaction. This is not a production recovery.
            if os.environ.get('CI_GUARDED_FIXTURE')!='1':raise RuntimeError('ONLY_PRIVATE_CI_FAILURE_INJECTION')
            failure_ns=time.monotonic_ns();auth.revoke_and_notify()
            if holder_session is not None:holder_session.revoke_and_notify()
            deny_dir=ROOT/'guardian-deny-receipts';deny_dir.mkdir(mode=0o700)
            denier=generation.GenerationEmitter(initial_raw=original,transition=trans,receipt_dir=deny_dir,
                         host_netns=os.environ['CI_HOST_NETNS'],recover_fixture=True)
            uncertain=os.environ.get('CI_DENY_ACK_UNCERTAIN')=='1'
            recovery_before=None;unknown_wire=None
            if uncertain:
                class UnknownAfterSend:
                    def __init__(self,inner):self.inner=inner;self.sent=0
                    def send(self,payload):
                        result=self.inner.send(payload)
                        if len(payload)>=6 and struct.unpack_from('<H',payload,4)[0]==0x10:
                            self.sent+=1;raise RuntimeError('CI_DENY_ACK_UNKNOWN_AFTER_SEND')
                        return result
                    def __getattr__(self,name):return getattr(self.inner,name)
                denier.nl=UnknownAfterSend(denier.nl)
            maps={'inbound':[('0b'*12,1)],'reverse':[('0c'*12,1)]};records=[]
            try:
                for role in ('inbound','reverse'):records.append(nl.make_program(maps[role]))
                transferred=records;records=[]
                emergency=drain_v3.mint_emergency(drain_v3.CoordinatorV3(ROOT/'drain-coordinator'),
                    verified,reg,denier)
                try:denied=denier.submit({'maps':maps,'backends':[],'cores':[],'prom':[]},transferred,
                                         emergency_permit=emergency)
                except RuntimeError as error:
                    if not uncertain or str(error)!='CI_DENY_ACK_UNKNOWN_AFTER_SEND':raise
                    assert denier.state=='HOLD_UNKNOWN_OR_UNVERIFIED' and denier.nl.sent==1
                    intent=json.loads((deny_dir/'INTENT-101.json').read_bytes())
                    unknown_wire=intent['wire_sha256']
                    assert not (deny_dir/'ACK-101.json').exists()
                    denier.nl.close()  # old socket terminal; FDs stay held
                    recovery_dir=ROOT/'guardian-deny-recovery';recovery_dir.mkdir(mode=0o700)
                    deny_recovery=generation.GenerationEmitter(initial_raw=original,transition=trans,
                         receipt_dir=recovery_dir,host_netns=os.environ['CI_HOST_NETNS'],recover_fixture=True)
                    recovery_before=nl.genid(deny_recovery.nl)
                    maps2={'inbound':[('0d'*12,1)],'reverse':[('0e'*12,1)]}
                    for role in ('inbound','reverse'):records.append(nl.make_program(maps2[role]))
                    transferred=records;records=[]
                    recovery_emergency=drain_v3.mint_emergency(drain_v3.CoordinatorV3(ROOT/'drain-coordinator'),
                        verified,reg,deny_recovery)
                    denied=deny_recovery.submit({'maps':maps2,'backends':[],'cores':[],'prom':[]},transferred,
                                                emergency_permit=recovery_emergency)
                    assert denied['wire_sha256']!=intent['wire_sha256']
            finally:
                for record in records:os.close(record['program_fd']);os.close(record['map_fd'])
            if uncertain:assert deny_recovery is not None
            publish({'event':'DENIED','genid':denied['after'],'wire_sha256':denied['wire_sha256'],
                     'reader_invalidated':True,'failure_ns':failure_ns,'deny_ack_ns':time.monotonic_ns(),
                     'original_deny_ack_unknown':uncertain,'distinct_deny_recovery':uncertain,
                     'recovery_before':recovery_before,'unknown_wire_sha256':unknown_wire,
                     'production_authority':False})
        def monitor_readers():
            while not closing.is_set():
                cache.wake.wait(.05);cache.wake.clear()
                if closing.is_set():return
                _rows,_cores,_prom,errors,_gen=cache.snapshot()
                if errors and auth is not None:
                    try:deny_after_reader_failure()
                    except BaseException as error:
                        publish({'event':'DENY_FAILED','error_class':type(error).__name__,'guard':str(error)[:160],'production_authority':False})
                    return
        monitor=threading.Thread(target=monitor_readers);monitor.start()
        publish({'event':'READY','pid':os.getpid(),'production_authority':False});launch_watch()
        while True:
            command=read_line(channel);kind=command['command']
            if kind=='ADMISSION_WITNESS':
                try:
                    result=admission.observe(verified,reg,generation.CI_DRAIN_COORDINATION,command['uid'],command['address'])
                    publish({'event':'ADMISSION_WITNESS',**result})
                except Exception as error:
                    publish({'event':'ADMISSION_HOLD','error_class':type(error).__name__,
                             'guard':str(error)[:160],'production_authority':False})
            elif kind=='PAUSE':
                stop_watch();publish({'event':'PAUSED','production_authority':False})
            elif kind=='CONNECT':
                if auth is not None:raise RuntimeError('ONE_SENDER_CHANNEL')
                publish({'event':'LISTENING','production_authority':False})
                sender_channel,_=listener.accept();sender_channel.settimeout(30 if os.environ.get('CI_HOLDER_TEST')=='1' else 15)
                auth=authority.SenderRegistryAuthority(sender_channel,registry=reg,registry_module=registry_module,
                     verified=verified,verifier=guarded_verifier,identity=identity,nl=nl,sender_argv=request['argv'],
                     sender_sha256=request['source_sha256'],validate_kernel=validate)
                sender_worker=threading.Thread(target=serve_sender);sender_worker.start()
                publish({'event':'CONNECTED','production_authority':False})
            elif kind=='SOURCE_CEILINGS':
                expected=guarded_sources.build_expected(cache)
                publish({'event':'SOURCE_CEILINGS',
                         'maps':{role:[[key.hex(),value] for key,value in sorted(expected[role].items())]
                                 for role in ('inbound','reverse')},'production_authority':False})
            elif kind=='COVERAGE':
                obs=chain.last_observation
                publish({'event':'COVERAGE','qualified':bool(obs is not None and obs[0]),
                         'coverage_ns':0 if obs is None else obs[2]-obs[1],'production_authority':False})
            elif kind=='CONNECT_HOLDER':
                if os.environ.get('CI_HOLDER_TEST')!='1' or holder_session is not None:raise RuntimeError('ONLY_ONE_HOLDER_TEST')
                holder_script=HERE/'ci_holder_process.py'
                admission._read_sealed(holder_script,admission.CI_SOURCE_SHA256['ci_holder_process.py'])
                expected_holder_argv=['/usr/bin/python3','-B',str(holder_script),str(ROOT/'guardian47.sock'),
                                      str(ROOT/'holder-go'),str(ROOT/'holder-acquired'),str(ROOT/'holder-revoked')]
                if (re.fullmatch(r'ci-rotation-holder-[0-9a-f]{32}\.service',command.get('unit','')) is None
                        or command.get('argv')!=expected_holder_argv
                        or command.get('source_sha256')!=admission.CI_SOURCE_SHA256['ci_holder_process.py']):
                    raise RuntimeError('EXACT_CI_HOLDER_UNIT_AND_SOURCE_REQUIRED')
                publish({'event':'HOLDER_LISTENING','production_authority':False})
                holder_channel,_=listener.accept();holder_channel.settimeout(10)
                holder_identity=identity.authenticate(holder_channel,unit=command['unit'],expected_invocation=command['invocation'],
                    expected_argv=command['argv'],source_sha256=command['source_sha256'])
                holder_authority=effect_lease.EffectLeaseAuthority(holder_channel,cache=cache,sources=guarded_sources,nl=nl,
                    verifier=guarded_verifier,current15=current15,preparer_channel=channel,program_reference=reference)
                assert holder_authority.peer==holder_identity['pid'] and holder_authority.preparer==controller['pid']
                def acquire_holder(until):
                    return reg.acquire_holder(holder_authority,effect_lease,lambda:holder_authority.acquire(verified,chain,until))
                def validate_holder():
                    value=validate(verified);lease=holder_authority.lease
                    assert lease is not None and value['observation']['genid']==lease['epoch']
                    assert value['invalidation_epoch']==lease['invalidation_epoch']
                holder_session=holder_ipc.HolderSession(holder_channel,holder_authority,acquire_holder,validate_holder)
                holder_worker=threading.Thread(target=holder_session.serve);holder_worker.start()
                publish({'event':'HOLDER_CONNECTED','pid':holder_identity['pid'],'production_authority':False})
            elif kind=='PREPARE':
                chain_before=chain.capture_before_send()
                proof=reg.prepare(chain_before,verified,command['records'])
                publish({'event':'PREPARED','genid':proof.genid,'production_authority':False})
            elif kind=='CONFIRM':
                next_verified=seal(command['result'],command['plan'])
                try:confirmation=reg.confirm(proof,next_verified)
                except BaseException:next_verified.close();raise
                if os.environ.get('CI_HOLDER_TEST')=='1':
                    envelope=validate(next_verified)
                    chain.record(chain_before,next_verified,envelope)
                    confirmation['current15_qualified']=envelope['current15_qualified']
                    confirmation['coverage_ns']=envelope['observed_ns']-chain.start_ns
                old=verified;verified=next_verified;ctx['verified']=verified;auth.verified=verified;old.close();proof=None
                publish({'event':'CONFIRMED','genid':verified.result['after'],**confirmation})
            elif kind=='RESUME':
                launch_watch();publish({'event':'RESUMED','production_authority':False})
            elif kind=='PROBE_PENDING':
                with reg.lock:
                    pending=reg.pending
                    publish({'event':'PENDING_STATE','pending':pending is not None,
                             'possible_send':bool(pending is not None and getattr(pending,'sent',False)),
                             'state':reg.state,'production_authority':False})
            elif kind=='STOP_DNS':
                readers.stop_dns();publish({'event':'DNS_STOPPED','dns_stop_ns':time.monotonic_ns(),'production_authority':False})
            elif kind=='RESTORE_DNS':
                # Fresh DNS/route observations must not clear UNKNOWN or turn
                # the old permit into authority for a new kernel effect.
                readers.restart_dns();deadline=time.monotonic()+8;fresh=None
                while time.monotonic()<deadline:
                    try:fresh=guarded_sources.build_expected(cache);break
                    except guarded_sources.Held:time.sleep(.025)
                if fresh is None:raise RuntimeError('FRESH_DNS_OBSERVATION_NOT_READY')
                with reg.lock:
                    assert reg.state=='UNKNOWN' and reg.pending is not None and reg.pending.sent
                net=socket.socket(socket.AF_NETLINK,socket.SOCK_RAW,12);net.bind((0,0));net.settimeout(5)
                try:
                    before=nl.genid(net)
                    snapshot=coverage.kernel_text(nl.cmd('/usr/sbin/nft','-a','list','table','inet','dakasa_capacity_network'))
                    assert all(not rows for rows in snapshot['dynamic_collections'].values()) and nl.genid(net)==before
                finally:net.close()
                publish({'event':'DNS_RESTORED','genid':before,'registry_state':reg.state,
                         'source_epoch':fresh['invalidation_epoch'],'production_authority':False})
            elif kind=='STOP':break
            else:raise RuntimeError('UNEXPECTED_GUARDIAN_CONTROL_COMMAND')
    except BaseException as error:
        print('CI_GUARDIAN_CONTROL_ERROR '+type(error).__name__+':'+str(error),flush=True)
        raise
    finally:
        closing.set()
        if cache is not None:cache.wake.set()
        stop_watch()
        if monitor is not None:monitor.join(5)
        if readers is not None:readers.close()
        if holder_session is not None:holder_session.stopped.set()
        if holder_channel is not None:
            try:holder_channel.shutdown(2)
            except OSError:pass
        if holder_worker is not None:holder_worker.join(5)
        if holder_authority is not None:holder_authority.close()
        if holder_identity is not None:os.close(holder_identity['pidfd'])
        if holder_channel is not None:holder_channel.close()
        if sender_channel is not None:
            try:sender_channel.shutdown(2)
            except OSError:pass
        if sender_worker is not None:sender_worker.join(5)
        if auth is not None:auth.close()
        elif sender_channel is not None:sender_channel.close()
        if reference is not None:reference.close()
        if denier is not None:denier.close_private_fixture()
        if deny_recovery is not None:deny_recovery.close_private_fixture()
        if verified is not None:verified.close()
        if controller is not None:os.close(controller['pidfd'])
        if sender_errors:raise RuntimeError('GUARDIAN_SENDER_ERROR:'+','.join(sender_errors))
