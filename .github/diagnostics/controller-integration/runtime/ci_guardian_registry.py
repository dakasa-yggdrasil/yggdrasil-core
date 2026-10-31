"""Private-CI integration of actual Guardian registry and actual BPF sender.

Source Reader evidence, systemd identity and pre-existing verified generation
are fixtures. Real nft/BPF and the original Guardian registry and authority
methods execute; none of this grants production authority.
"""
import base64,hashlib,json,os,socket,sys,threading,time
from pathlib import Path
import guarded_nl as nl
import guarded_generation as generation
import guarded_sender_session_DRAFT as sender_protocol
import guarded_refresh_registry_DRAFT as registry_module
import guarded_program_identity_DRAFT as program_module
import guarded_verifier as verifier
import guarded_current15 as current15
import guarded_authority_ci as authority
import guarded_sources


def exercise(*, root, raw, trans, host_netns, baseline, baseline_plan, reader_cache, sender_cache, encode, coverage):
    from subprocess import run,PIPE
    def text():return run(['/usr/sbin/nft','-a','list','table','inet','dakasa_capacity_network'],stdout=PIPE,check=True,timeout=5).stdout
    net=socket.socket(socket.AF_NETLINK,socket.SOCK_RAW,12);net.bind((0,0));net.settimeout(5)
    preparer,registry_side=socket.socketpair();sender_side,guardian_side=socket.socketpair()
    prep_fd=os.pidfd_open(os.getpid(),0);ctrl_group=Path('/proc/self/cgroup').read_text().strip().split(':',2)[2]
    prep={'pid':os.getpid(),'start_ticks':nl.startticks(os.getpid()),'pidfd':prep_fd,'unit':'fixture.service',
          'invocation_id':'f'*32,'control_group':ctrl_group}
    cache=reader_cache;reference=None;old_verified=None;new_verified=None;sender=None;session=None;auth=None
    stop=threading.Event();server_errors=[];worker=None;records=[]
    try:
        original_expected=guarded_sources.build_expected(sender_cache)
        maps={role:[(key.hex(),deadline) for key,deadline in sorted(original_expected[role].items())]
              for role in ('inbound','reverse')}
        assert len(maps['inbound'])==64 and len(maps['reverse'])==32
        for role in ('inbound','reverse'):records.append(nl.make_program(maps[role]))
        class Sources:
            invalid=False
            @classmethod
            def build_expected(cls,cache):
                value=guarded_sources.build_expected(cache)
                if cls.invalid:value['invalidation_epoch']+=1
                return value
            @staticmethod
            def verify(cache,kernel,actual):
                return guarded_sources.verify(cache,kernel,actual)
        sources=Sources()
        old_result={k:v for k,v in baseline.items() if k not in ('ok','counter')}
        anchor={'pid':os.getpid(),'start_ticks':prep['start_ticks'],'netns':os.readlink('/proc/self/ns/net'),
                'initial':base64.b64encode(raw).decode()}
        probe=Path(__file__).with_name('ci_nl_probe.py');probe_sha=hashlib.sha256(probe.read_bytes()).hexdigest()
        old_verified=verifier.verify_and_seal(result=baseline,anchor=anchor,plan=baseline_plan,receipt_dir=root/'receipts2',
                reader_cache=cache,nl=nl,sources=sources,transition=trans,coverage=coverage,
                probe_path=probe,probe_sha256=probe_sha)
        def validate(verified):
            generation_now=nl.genid(net);snapshot=coverage.kernel_text(text())
            if not snapshot['all_four_backends_and_reverse_sources_positive']:raise RuntimeError('CI_EXPECTED_POSITIVE_KERNEL')
            return {'observation':{'genid':generation_now,
                    'kernel_min_deadline_ns':time.monotonic_ns()+snapshot['minimum_actual_expires_ms']*1_000_000},
                    'invalidation_epoch':cache.guard_invalidation_epoch}
        reference=program_module.GuardianProgramReference()
        reg=registry_module.GuardianRefreshRegistry(registry_side,prep,cache=cache,sources=sources,nl=nl,
                    verifier=verifier,current15=current15,program_module=program_module,reference=reference,validate_kernel=validate)
        chain=current15.CoverageChain(cache,sources,verifier)
        invalid=chain.capture_before_send();Sources.invalid=True
        try:reg.prepare(invalid,old_verified,records);raise AssertionError('invalidated reader accepted')
        except registry_module.Held as exc:assert str(exc)=='LIVE_ORIGINAL_SOURCE_AND_KERNEL_GENERATION'
        assert reg.pending is None;Sources.invalid=False
        before=chain.capture_before_send();proof=reg.prepare(before,old_verified,records)
        assert not proof.sent and reg.pending is proof
        class Identity:
            @staticmethod
            def _current_ids(*_):pass
            @staticmethod
            def _secure_source(*_):pass
            @staticmethod
            def authenticate(*_,**__):return {'pid':os.getpid(),'start_ticks':prep['start_ticks'],
                    'control_group':ctrl_group,'pidfd':os.pidfd_open(os.getpid(),0)}
        ident=Identity();argv=Path('/proc/self/cmdline').read_bytes().rstrip(b'\0').decode().split('\0')
        auth=authority.SenderRegistryAuthority(guardian_side,registry=reg,registry_module=registry_module,
            verified=old_verified,verifier=verifier,identity=ident,nl=nl,sender_argv=argv,
            sender_sha256='a'*64,validate_kernel=validate)
        session=sender_protocol.SenderSession(sender_side,identity=ident,
            guardian={'unit':'fixture.service','invocation_id':'f'*32,'argv':['fixture'],'source_sha256':'a'*64},nl=nl)
        def serve():
            try:
                raw_request=bytearray()
                while not raw_request.endswith(b'\n'):
                    chunk=guardian_side.recv(1)
                    if not chunk:raise RuntimeError('sender channel closed')
                    raw_request.extend(chunk)
                auth.answer_once(json.loads(raw_request));stop.wait(10)
            except BaseException as exc:server_errors.append(exc)
        worker=threading.Thread(target=serve);worker.start()
        permit=session.prepare(records,until_ns=time.monotonic_ns()+3_000_000_000)
        assert proof.sent and proof.sender_claimed and reg.pending is proof
        receipts=root/'receipts3';receipts.mkdir(mode=0o700)
        sender=generation.GenerationEmitter(initial_raw=raw,transition=trans,receipt_dir=receipts,host_netns=host_netns,recover_fixture=True)
        entries,cores,prom,errors,_=sender_cache.snapshot();assert not errors
        plan={'maps':maps,'backends':[encode(x) for x in entries],'cores':[encode(x) for x in cores],'prom':[encode(x) for x in prom]}
        transfer=records;records=[]
        result=sender.submit(plan,transfer,sender_session=session,sender_permit=permit)
        assert result['ok'] and permit.consumed and result['genid']==old_result['after']
        new_verified=verifier.verify_and_seal(result=result,anchor=anchor,plan=plan,receipt_dir=receipts,
                reader_cache=cache,nl=nl,sources=sources,transition=trans,coverage=coverage,
                probe_path=probe,probe_sha256=probe_sha)
        confirmed=reg.confirm(proof,new_verified)
        assert confirmed['same_guardian_successor_verified'] and reg.pending is None
        print('PASS actual Guardian registry, reference-program comparison, one-use authority and BPF nft rotation',flush=True)
        print('BOUNDARY: synthetic DNS/topology, separate same-process Reader caches, systemd identity, ownership lease and deployed service integration',flush=True)
    finally:
        stop.set()
        if worker is not None:worker.join(10)
        if session is not None:session.close()
        else:sender_side.close()
        if auth is not None:auth.close()
        else:guardian_side.close()
        preparer.close();registry_side.close();net.close();os.close(prep_fd)
        if new_verified is not None:new_verified.close()
        if old_verified is not None:old_verified.close()
        if reference is not None:reference.close()
        if sender is not None:sender.close_private_fixture()
        for rec in records:os.close(rec['program_fd']);os.close(rec['map_fd'])
        if server_errors:raise RuntimeError('guardian protocol fixture failed') from server_errors[0]
