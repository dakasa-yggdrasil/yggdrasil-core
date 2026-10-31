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
