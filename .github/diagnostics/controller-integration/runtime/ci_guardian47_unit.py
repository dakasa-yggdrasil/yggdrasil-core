"""Controller-side start, authentication and lifecycle of CI precommit Guardian."""
import hashlib,os,socket,subprocess,time,uuid
from pathlib import Path
import guarded_guardian47_ci as precommit,guarded_unit_identity as identity,guarded_nl as nl
import native_structure as structure,transition_structure_DRAFT as trans

class Guardian47:
    def __init__(self,*,root,origin):
        self.unit='ci-guarded-precommit-'+uuid.uuid4().hex+'.service';self.path=root/'guardian47.sock'
        self.channel=None;self.session=None
        script=Path(__file__).with_name('ci_guardian47_process.py').resolve()
        self.argv=['/usr/bin/python3','-B',str(script),str(self.path)]
        try:
            subprocess.run(['/usr/bin/systemd-run','--quiet','--no-block','--unit='+self.unit,
                '--property=RuntimeMaxSec=30s','--setenv=CI_GUARDED_FIXTURE=1',
                '--setenv=CI_HOST_NETNS='+os.environ['CI_HOST_NETNS'],
                '--setenv=CI_DENY_ACK_UNCERTAIN='+os.environ.get('CI_DENY_ACK_UNCERTAIN','0'),
                '--setenv=CI_CONTROLLER_UNIT='+os.environ['CI_CONTROLLER_UNIT'],
                '/usr/bin/nsenter','--net=/proc/%d/ns/net'%os.getpid(),*self.argv],check=True,timeout=10)
            until=time.monotonic()+12
            while not self.path.exists() and time.monotonic()<until:time.sleep(.03)
            if not self.path.exists():raise RuntimeError('GUARDIAN47_SOCKET_NOT_READY')
            self.channel=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);self.channel.settimeout(10);self.channel.connect(str(self.path))
            props=identity._properties(self.unit)
            self.session=precommit.connect(origin,self.channel,guardian_unit=self.unit,invocation=props['InvocationID'],
                 guardian_argv=self.argv,source_sha256=hashlib.sha256(script.read_bytes()).hexdigest(),
                 identity=identity,nl=nl,structure=structure,transition=trans)
            print('PASS separate systemd Guardian 47 precommit with mutual real process identity',flush=True)
        except BaseException:
            subprocess.run(['/usr/bin/journalctl','-u',self.unit,'--no-pager','-n','40'],check=False,timeout=10)
            self.close();raise
    def close(self):
        if self.session is not None:os.close(self.session.pidfd);self.session=None
        if self.channel is not None:self.channel.close();self.channel=None
        subprocess.run(['/usr/bin/systemctl','stop',self.unit],check=False,timeout=10)
        self.path.unlink(missing_ok=True)
