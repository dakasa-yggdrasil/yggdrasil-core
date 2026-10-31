"""Start and authenticate an isolated, time-bounded Guardian systemd process."""
import hashlib,json,os,socket,subprocess,time,uuid
from pathlib import Path
import guarded_nl,guarded_unit_identity as identity

class Watch:
    def __init__(self,*,root,anchor,result,plan,existing=None):
        self.owns_unit=existing is None
        self.unit=('ci-guarded-watch-'+uuid.uuid4().hex+'.service') if self.owns_unit else existing.unit
        self.path=(root/'guardian-watch.sock') if self.owns_unit else existing.path
        self.channel=None;self.peer=None;self.start=time.monotonic();self.last_hold=None
        script=Path(__file__).with_name('ci_guardian_process.py').resolve() if self.owns_unit else Path(existing.argv[2])
        self.argv=['/usr/bin/python3','-B',str(script),str(self.path)] if self.owns_unit else existing.argv
        try:
            if self.owns_unit:subprocess.run(['/usr/bin/systemd-run','--quiet','--no-block','--unit='+self.unit,
                 '--property=RuntimeMaxSec=30s','--setenv=CI_GUARDED_FIXTURE=1',
                 '--setenv=CI_HOST_NETNS='+os.environ['CI_HOST_NETNS'],
                 '/usr/bin/nsenter','--net=/proc/%d/ns/net'%os.getpid(),*self.argv],check=True,timeout=10)
            until=time.monotonic()+12
            while not self.path.exists() and time.monotonic()<until:time.sleep(.03)
            if not self.path.exists():raise RuntimeError('GUARDIAN_SOCKET_NOT_READY')
            self.channel=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);self.channel.settimeout(10);self.channel.connect(str(self.path))
            props=identity._properties(self.unit)
            self.peer=identity.authenticate(self.channel,unit=self.unit,expected_invocation=props['InvocationID'],
                         expected_argv=self.argv,source_sha256=hashlib.sha256(script.read_bytes()).hexdigest())
            argv=Path('/proc/self/cmdline').read_bytes().rstrip(b'\0').decode().split('\0')
            request={'unit':os.environ['CI_CONTROLLER_UNIT'],'invocation':os.environ['INVOCATION_ID'],
                     'argv':argv,'source_sha256':hashlib.sha256(Path(argv[2]).read_bytes()).hexdigest(),
                     'anchor':anchor,'result':result,'plan':plan}
            self.channel.sendall(guarded_nl.canon(request))
            ready=self.read();assert ready['event']=='READY' and ready['pid']==self.peer['pid'] and not ready['production_authority']
            samples=[self.read(),self.read()]
            assert all(x['event']=='SAMPLE' and x['generation']==result['after'] and not x['production_authority'] for x in samples)
            print('PASS separate systemd Guardian and controller mutual identity, independent DNS Reader and two guarded watch samples',flush=True)
        except BaseException:
            subprocess.run(['/usr/bin/journalctl','-u',self.unit,'--no-pager','-n','40'],check=False,timeout=10)
            self.close();raise
    def read(self):
        buf=bytearray()
        while len(buf)<=8192:
            b=self.channel.recv(1)
            if not b:raise RuntimeError('GUARDIAN_WATCH_EOF')
            if b==b'\n':return json.loads(buf)
            buf.extend(b)
        raise RuntimeError('GUARDIAN_WATCH_OUTPUT_TOO_LARGE')
    def control(self,command,expected,**fields):
        self.channel.sendall(guarded_nl.canon({'command':command,**fields}))
        while True:
            row=self.read()
            if row['event']==expected:return row
            if row['event']=='HOLD' and command=='INJECT_READER_FAILURE_AND_DENY':
                self.last_hold=row;continue
            if row['event'] not in ('SAMPLE','FINISHED'):raise RuntimeError('UNEXPECTED_GUARDIAN_CONTROL_EVENT:'+str(row))
    def pause(self):return self.control('PAUSE','PAUSED')
    def sender_channel(self):
        self.control('CONNECT','LISTENING')
        channel=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);channel.settimeout(10);channel.connect(str(self.path))
        while True:
            row=self.read()
            if row['event']=='CONNECTED':return channel
            if row['event'] not in ('SAMPLE','FINISHED'):raise RuntimeError('UNEXPECTED_GUARDIAN_CONNECT_EVENT:'+str(row))
    def prepare(self,records):return self.control('PREPARE','PREPARED',records=list(records))
    def confirm(self,result,plan):return self.control('CONFIRM','CONFIRMED',result=result,plan=plan)
    def resume(self):return self.control('RESUME','RESUMED')
    def inject_reader_failure_and_deny(self):return self.control('INJECT_READER_FAILURE_AND_DENY','DENIED')
    def expect_hold(self):
        deadline=time.monotonic()+8
        while time.monotonic()<deadline:
            row=self.last_hold if self.last_hold is not None else self.read()
            self.last_hold=None
            if row['event']=='HOLD':
                assert isinstance(row['guard'],str) and row['guard'] and not row['production_authority']
                print('PASS separate Guardian watch HOLD after source failure or genid change: '+row['guard'],flush=True);return
            assert row['event']=='SAMPLE'
        raise RuntimeError('GUARDIAN_HOLD_NOT_OBSERVED')
    def close(self):
        if self.peer is not None:os.close(self.peer['pidfd']);self.peer=None
        if self.channel is not None:
            try:self.channel.sendall(guarded_nl.canon({'command':'STOP'}))
            except OSError:pass
            self.channel.close();self.channel=None
        if self.owns_unit:
            subprocess.run(['/usr/bin/systemctl','stop',self.unit],check=False,timeout=10)
            self.path.unlink(missing_ok=True)
