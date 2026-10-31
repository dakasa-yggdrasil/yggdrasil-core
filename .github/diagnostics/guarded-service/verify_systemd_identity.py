"""Exercise real candidate identity against a disposable transient systemd unit."""
import hashlib,os,socket,subprocess,sys,tempfile,time,uuid
from pathlib import Path
import guarded_unit_identity as identity

root=Path(__file__).resolve().parent
peer=(root/'systemd_peer.py').resolve()
sockpath=root/'peer.sock'
unit='ci-guarded-identity-'+uuid.uuid4().hex+'.service'
server=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
server.bind(str(sockpath));server.listen(1);server.settimeout(15)
argv=['/usr/bin/python3','-B',str(peer),str(sockpath)]
channel=None
try:
    subprocess.run(['/usr/bin/systemd-run','--quiet','--no-block','--collect','--unit='+unit,
                    '--property=RuntimeMaxSec=30s',*argv],check=True,timeout=10)
    channel,_=server.accept()
    props=identity._properties(unit)
    digest=hashlib.sha256(peer.read_bytes()).hexdigest()
    observed=identity.authenticate(channel,unit=unit,expected_invocation=props['InvocationID'],
                 expected_argv=argv,source_sha256=digest)
    try:
        assert observed['pid']==int(props['MainPID']) and observed['control_group']==props['ControlGroup']
    finally:os.close(observed['pidfd'])
    def rejected(**updates):
        args={'unit':unit,'expected_invocation':props['InvocationID'],'expected_argv':argv,'source_sha256':digest};args.update(updates)
        try:identity.authenticate(channel,**args)
        except RuntimeError:return
        raise AssertionError('incorrect identity was accepted')
    rejected(source_sha256='0'*64)
    rejected(expected_invocation='0'*32)
    rejected(expected_argv=['/usr/bin/python3','-B',str(peer),'different'])
    print('PASS real systemd PID, invocation, cgroup, argv, root source hash and three negative checks',flush=True)
finally:
    if channel is not None:channel.close()
    server.close()
    subprocess.run(['/usr/bin/systemctl','stop',unit],check=False,timeout=10)
    sockpath.unlink(missing_ok=True)

# Exercise precommit with the actual systemd authenticator and root-owned peer.
# AST/parser and source fixture pin are simulated; nft reads and identity are real.
import guardian47,guarded_nl,types,json
peer47=(root/'systemd_peer_47.py').resolve()
sockpath=root/'peer47.sock';unit='ci-guarded-47-'+uuid.uuid4().hex+'.service'
server=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);server.bind(str(sockpath));server.listen(1);server.settimeout(15)
argv=['/usr/bin/python3','-B',str(peer47),str(sockpath)]
channel=None;net=socket.socket(socket.AF_NETLINK,socket.SOCK_RAW,12);net.bind((0,0));net.settimeout(5)
try:
    subprocess.run(['/usr/bin/systemd-run','--quiet','--no-block','--collect','--unit='+unit,
                    '--property=RuntimeMaxSec=30s',*argv],check=True,timeout=10)
    channel,_=server.accept();props=identity._properties(unit);pid=int(props['MainPID'])
    prep={'pid':pid,'start_ticks':guarded_nl.startticks(pid),'unit':unit,
          'invocation_id':props['InvocationID'],'control_group':props['ControlGroup']}
    probe=root/'ci_probe.py';probe.write_text('fixture\n');probe.chmod(0o600)
    class Netlink:
        startticks=staticmethod(guarded_nl.startticks)
        canon=staticmethod(lambda x:(json.dumps(x,sort_keys=True,separators=(',',':'))+'\n').encode())
        @staticmethod
        def cmd(*args):
            if 'list' in args:return guarded_nl.cmd('/usr/sbin/nft','-j','list','ruleset')
            return json.dumps({'genid':guarded_nl.genid(net)}).encode()
    structure=types.SimpleNamespace(_objects=lambda raw,_with_origin:([],[],json.loads(raw)))
    transition=types.SimpleNamespace(OriginalPin=lambda raw:types.SimpleNamespace(digest='b'*64))
    nft=types.SimpleNamespace(ruleset_mark_preflight=lambda *args,**kwargs:None)
    os.environ['INVOCATION_ID']='d'*32
    guardian47.serve(channel,preparer_identity=prep,sender_argv=argv,
         source_sha256=hashlib.sha256(peer47.read_bytes()).hexdigest(),probe_path=str(probe),
         probe_sha256=hashlib.sha256(probe.read_bytes()).hexdigest(),identity=identity,nl=Netlink(),
         structure=structure,transition=transition,nft=nft,host_netns='not-current')
    print('PASS precommit Guardian with real systemd peer authentication and nft reads; AST simulated',flush=True)
finally:
    if channel is not None:channel.close()
    server.close();net.close()
    subprocess.run(['/usr/bin/systemctl','stop',unit],check=False,timeout=10)
    sockpath.unlink(missing_ok=True)
