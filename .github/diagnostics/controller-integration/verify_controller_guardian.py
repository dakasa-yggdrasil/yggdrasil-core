"""Actual legacy cached_cycle and Guardian kernel read, disposable nft netns.

The cache, owner and deployment-specific compiled AST pin are fixtures. This
exercises real controller/native process and Guardian methods, not BPF service
integration or production authority.
"""
import base64,hashlib,importlib.util,json,os,socket,struct,subprocess,sys,tempfile,threading,time,types
from pathlib import Path
HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE/'runtime'))
import controller,native_io,native_structure,nft_owner as nft
spec=importlib.util.spec_from_file_location('test_guardian',HERE/'network_guardian.py');guardian=importlib.util.module_from_spec(spec);spec.loader.exec_module(guardian)
spec=importlib.util.spec_from_file_location('test_coverage',HERE/'coverage.py');coverage=importlib.util.module_from_spec(spec);spec.loader.exec_module(coverage)
def cmd(*args,inp=None):return subprocess.run(args,input=inp,stdout=subprocess.PIPE,stderr=subprocess.PIPE,check=True,timeout=10).stdout

def endpoints(suffix):
    now=time.monotonic()
    entries=[nft.Backend(k,a,nft.PORTS[k],now,now+20,'synthetic') for k,a in
       [('core','10.244.1.'+str(suffix)),('broker','172.18.1.2'),('rds','172.18.1.3'),('redis','172.18.1.4')]]
    prom=nft.PrometheusSource('10.244.1.9',now,now+20,'synthetic')
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
    cache.rows=endpoints(3);cache.key='new-observation'
    new,newkey,newlease=cycle(cache,key);assert new['applied'] and newlease.dispatched and newkey=='new-observation'
    fresh=cmd('/usr/sbin/nft','-a','list','table','inet','dakasa_capacity_network')
    assert b'10.244.1.3' in fresh and b'10.244.1.2' not in fresh
    snapshot,_=observer.kernel();assert snapshot['all_four_backends_and_reverse_sources_positive']
    print('PASS actual cached_cycle/native nft, Guardian.kernel, unknown effect no replay, fresh distinct reconciliation',flush=True)
    print('BOUNDARY: private CI namespace; cache, owner and compiled AST pin are fixtures; legacy relative TTL',flush=True)
    # Experiment with the actual LAB 47->50 sender, fixed to this CI namespace.
    # The CI fixture supplies observation/lease authority and is not a service.
    import guarded_nl as nl, guarded_generation as generation, transition_structure_DRAFT as trans
    native_structure.COMPILED_NATIVE_AST_SHA256=expected
    raw=cmd('/usr/sbin/nft','-a','-j','list','ruleset')
    original=trans.OriginalPin(raw)
    records=[];first=None;uncertain=None;recovery=None;positive=None;session=None;server=None;prepared=None;initial_prepared=None;watch=None
    server_done=threading.Event();server_errors=[];worker=None
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
                  emitter=first,prepared=initial_prepared,apply=lambda:True,previous_key=None,transition_origin=origin)
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
        watch=ci_guardian_unit.Watch(root=HERE,anchor=anchor,result=emitted,plan=first_plan)
        print('PASS cached_guarded_cycle with actual original 47 ownership reader and BPF emitter',flush=True)
        try:first.submit({},[]);raise AssertionError('unverified generation allowed another send')
        except RuntimeError as e:assert str(e)=='ONLY_READY_SAME_OWNER'
        # Independently changed foreign nft object: never infer that the old
        # receipt proves the present generation. The diagnostic recovery sender
        # is distinct and submits a deny-only batch using fresh expired maps.
        cmd('/usr/sbin/nft','add','table','ip','ci_foreign_after_50')
        watch.expect_hold();watch.close();watch=None
        try:observer.kernel(guarded=guarded_context);raise AssertionError('foreign genid change was accepted')
        except RuntimeError as error:assert str(error)=='GUARDED_RECEIPT_GENERATION_CHANGED'
        verified.close()
        # A complete netlink send is made, but its ACK is deliberately never
        # read. Hold its ownership/FD custody and never submit that wire again.
        unknown_dir=HERE/'unknown-receipts';unknown_dir.mkdir(mode=0o700)
        uncertain=generation.GenerationEmitter(initial_raw=raw,transition=trans,receipt_dir=unknown_dir,
                                               host_netns=os.environ['CI_HOST_NETNS'],recover_fixture=True)
        class InjectAfterSend:
            def __init__(self,inner):self.inner=inner;self.sent=0
            def send(self,payload):
                sent=self.inner.send(payload)
                if len(payload)>=6 and struct.unpack_from('<H',payload,4)[0]==0x10:
                    self.sent+=1
                    raise RuntimeError('CI_UNKNOWN_AFTER_ACTUAL_NETLINK_SEND')
                return sent
            def __getattr__(self,name):return getattr(self.inner,name)
        uncertain.nl=InjectAfterSend(uncertain.nl)
        unknown_maps={'inbound':[('09'*12,1)],'reverse':[('0a'*12,1)]}
        for role in ('inbound','reverse'):records.append(nl.make_program(unknown_maps[role]))
        transferred=records;records=[]
        try:
            uncertain.submit({'maps':unknown_maps,'backends':[],'cores':[],'prom':[]},transferred)
            raise AssertionError('uncertain send was reported successful')
        except RuntimeError as error:assert str(error)=='CI_UNKNOWN_AFTER_ACTUAL_NETLINK_SEND'
        assert uncertain.state=='HOLD_UNKNOWN_OR_UNVERIFIED' and uncertain.nl.sent==1
        try:uncertain.submit({},[]);raise AssertionError('uncertain sender allowed replay')
        except RuntimeError as error:assert str(error)=='ONLY_READY_SAME_OWNER'
        unknown_intent=json.loads((unknown_dir/'INTENT-101.json').read_bytes())
        assert not (unknown_dir/'ACK-101.json').exists()
        uncertain.nl.close()
        recovery=generation.GenerationEmitter(initial_raw=raw,transition=trans,receipt_dir=receipts,
                                               host_netns=os.environ['CI_HOST_NETNS'],recover_fixture=True)
        deny_maps={'inbound':[('03'*12,1)],'reverse':[('04'*12,1)]}
        for role in ('inbound','reverse'):records.append(nl.make_program(deny_maps[role]))
        transferred=records;records=[]
        denied=recovery.submit({'maps':deny_maps,'backends':[],'cores':[],'prom':[]},transferred)
        assert denied['ok'] and denied['genid']!=emitted['after'] and denied['wire_sha256']!=emitted['wire_sha256']
        assert denied['wire_sha256']!=unknown_intent['wire_sha256']
        text=cmd('/usr/sbin/nft','-a','list','table','inet','dakasa_capacity_network')
        observed=coverage.kernel_text(text)
        assert all(not values for values in observed['dynamic_collections'].values())
        print('PASS actual BPF-backed 47-to-50, unknown after real send, no replay and distinct deny-only fenced transaction',flush=True)
        print('BOUNDARY: fake authority and AST; deny-only recovery, not live Guardian or positive recovery',flush=True)
        # Continue only in the isolated fixture: an untrusted stand-in Guardian
        # provides a permit, while the real SenderSession checks the live FDs,
        # frozen maps, program->map linkage and same kernel generation twice.
        # No observation, systemd identity, ownership lease or service grant
        # is proved by this stand-in.
        import guarded_sender_session_DRAFT as sender_protocol
        receipts2=HERE/'receipts2';receipts2.mkdir(mode=0o700)
        positive=generation.GenerationEmitter(initial_raw=raw,transition=trans,receipt_dir=receipts2,
                                               host_netns=os.environ['CI_HOST_NETNS'],recover_fixture=True)
        a,b=socket.socketpair();server=b
        class FakeIdentity:
            def authenticate(self,*args,**kwargs):return {'pidfd':os.pidfd_open(os.getpid(),0)}
        guard={'unit':'fixture.service','invocation_id':'f'*32,'argv':['fixture'],'source_sha256':'a'*64}
        session=sender_protocol.SenderSession(a,identity=FakeIdentity(),guardian=guard,nl=nl)
        def mock_guardian():
            try:
                data=bytearray()
                while not data.endswith(b'\n'):
                    chunk=b.recv(1)
                    if not chunk:raise RuntimeError('fixture peer closed')
                    data.extend(chunk)
                request=json.loads(data)
                ids=[[x['program_id'],x['map_id']] for x in request['programs']]
                reply={'schema':'lab_sender_prepared_permit_reply_v1','nonce':request['nonce'],
                       'sender_pid':request['sender_pid'],'sender_start_ticks':request['sender_start_ticks'],
                       'genid':request['genid'],'ids':ids,'map_digest':request['map_digest'],
                       'deadline_ns':request['until_ns'],'source_epoch':1,'external_effect_authorized':False}
                b.sendall(nl.canon(reply));server_done.wait(10)
            except BaseException as error:server_errors.append(error)
        worker=threading.Thread(target=mock_guardian);worker.start()
        guard_expected=guarded_sources.build_expected(guardian_cache)
        prepared=guarded_preparation.PreparedGeneration(real_cache,
                 deadline_ceilings={role:guard_expected[role] for role in ('inbound','reverse')})
        descriptors=prepared.fixture_descriptors(real_cache)
        new_maps={role:[(key.hex(),deadline) for key,deadline in sorted(nl.map_rows(rec['map_id']))]
                  for role,rec in zip(('inbound','reverse'),descriptors)}
        assert len(new_maps['inbound'])==64 and len(new_maps['reverse'])==32
        rows,cores,prom,errors,_=real_cache.snapshot();assert not errors
        new_plan={'maps':new_maps,'backends':[encode(x) for x in rows],'cores':[encode(x) for x in cores],'prom':[encode(x) for x in prom]}
        permit=session.prepare(list(descriptors),until_ns=time.monotonic_ns()+3_000_000_000)
        transferred=prepared.take_same_process_for_emitter(real_cache)
        refreshed=positive.submit(new_plan,transferred,sender_session=session,sender_permit=permit)
        assert refreshed['ok'] and permit.consumed and refreshed['genid']==denied['after']
        assert refreshed['wire_sha256'] not in (emitted['wire_sha256'],denied['wire_sha256'])
        text=cmd('/usr/sbin/nft','-a','list','table','inet','dakasa_capacity_network')
        assert coverage.kernel_text(text)['all_four_backends_and_reverse_sources_positive']
        print('PASS fresh positive BPF sender with real one-use FD/genid permit after deny-only generation',flush=True)
        print('BOUNDARY: Guardian permit, source witnesses and ownership lease simulated; no production authority',flush=True)
        import ci_guardian_registry
        ci_guardian_registry.exercise(root=HERE,raw=raw,trans=trans,host_netns=os.environ['CI_HOST_NETNS'],
                 baseline=refreshed,baseline_plan=new_plan,reader_cache=guardian_cache,sender_cache=real_cache,encode=encode,coverage=coverage)
    finally:
        if watch is not None:watch.close()
        for rec in records:
            os.close(rec['program_fd']);os.close(rec['map_fd'])
        server_done.set()
        if worker is not None:worker.join(10)
        if session is not None:session.close()
        if server is not None:server.close()
        if server_errors:raise RuntimeError('fixture Guardian failed') from server_errors[0]
        if initial_prepared is not None:initial_prepared.close()
        if prepared is not None:prepared.close()
        if positive is not None:positive.close_private_fixture()
        if recovery is not None:recovery.close_private_fixture()
        if uncertain is not None:uncertain.close_private_fixture()
        if first is not None:first.close_private_fixture()
if __name__=='__main__':main()
