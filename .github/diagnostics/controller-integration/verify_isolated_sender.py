"""Systemd sender/FD custody preflight, not cancellation or replay authority."""
import array,fcntl,hashlib,json,os,signal,socket,subprocess,sys,time,uuid
from pathlib import Path
root=Path(__file__).resolve().parent;sys.path.insert(0,str(root/'runtime'))
import drain_marker_v3_DRAFT as v3,guarded_nl as nl,guarded_unit_identity as identity
import native_structure,nft_owner as nft,recovery_terminality_DRAFT as terminal
import isolated_sender_custody_CI as custody

def run(*args,input=None):
    return subprocess.run(args,input=input,stdout=subprocess.PIPE,stderr=subprocess.PIPE,check=True,timeout=10).stdout
coord=v3.CoordinatorV3(root/'coord');coord.initialize_for_ci()
run('/usr/sbin/nft','-f','-',input=nft.render((),now=time.monotonic(),table_exists=False).encode())
raw=nl.cmd('/usr/sbin/nft','-a','-j','list','ruleset');objects,_=native_structure._objects(raw)
assert len(objects)==47
net=socket.socket(socket.AF_NETLINK,socket.SOCK_RAW,12);net.bind((0,0));net.settimeout(5)
before=nl.genid(net)
server=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);server.bind(str(root/'sender.sock'));server.listen(2);server.settimeout(10)
unit='ci-isolated-sender-'+uuid.uuid4().hex+'.service';unitfile=Path('/run/systemd/system')/unit
script=(root/'runtime'/'ci_isolated_sender.py').resolve();argv=['/usr/bin/python3','-B',str(script),str(root)]
channel=None;anchor=None;childfd=None;received=[];live=None
try:
    bad_fd=os.environ.get('CI_BAD_FD_TEST')=='1'
    unitfile.write_text('[Service]\nType=simple\nKillMode=process\nRuntimeMaxSec=30s\nEnvironment=CI_GUARDED_FIXTURE=1\nEnvironment=CI_SENDER_BAD_FD_ID='+('1' if bad_fd else '0')+'\nEnvironment=CI_HOST_NETNS='+os.readlink('/proc/1/ns/net')+'\nEnvironment=CI_CONTROLLER_UNIT='+unit+'\nExecStart=/usr/bin/nsenter --net=/proc/'+str(os.getpid())+'/ns/net '+' '.join(argv)+'\n')
    run('/usr/bin/systemctl','daemon-reload');run('/usr/bin/systemctl','start',unit)
    channel,_=server.accept();props=identity._properties(unit)
    try:
        live=custody.LiveSenderCustody(channel,unit=unit,invocation=props['InvocationID'],argv=argv,
            source_sha256=hashlib.sha256(script.read_bytes()).hexdigest(),coord=coord,netlink=net)
    except custody.Held as error:
        if not bad_fd or str(error)!='SENDER_AND_CUSTODIAN_FDS_MUST_MATCH':raise
        assert coord.marker_exists()
        print('PASS mismatched sender FD identity rejected and marker retained',flush=True)
        sys.exit(0)
    if bad_fd:raise AssertionError('mismatched sender FD identity accepted')
    anchor=live.anchor;marked=live.marker;records=live.records;received=live.fds
    assert live.genid==before
    childfd=os.pidfd_open(int((root/'sender-child.pid').read_text()))
    run('/usr/bin/systemctl','kill','--kill-whom=main','--signal=KILL',unit)
    deadline=time.monotonic()+5
    while not terminal._pidfd_terminal(anchor.verified['pidfd']):
        assert time.monotonic()<deadline;time.sleep(.02)
    try:terminal.prove_terminal_for_marker(marked);raise AssertionError('live descendant accepted')
    except terminal.Held as error:assert str(error)=='SENDER_CGROUP_OR_DESCENDANTS_STILL_POPULATED'
    with open(coord.writer_lock,'rb') as fence:
        try:fcntl.flock(fence,fcntl.LOCK_EX|fcntl.LOCK_NB);raise AssertionError('live descendant failed to fence')
        except BlockingIOError:pass
    print('PASS killed sender leader, inherited live socket and SH block terminality and EX',flush=True)
    signal.pidfd_send_signal(childfd,signal.SIGKILL)
    deadline=time.monotonic()+5
    while True:
        try:terminal.prove_terminal_for_marker(marked);break
        except terminal.Held:
            if time.monotonic()>deadline:raise
            time.sleep(.05)
    with custody.ExclusiveObservation(marked,net,before) as fence:
        observation=fence.verify();assert observation['cancel_authority'] is False
        assert nl.genid(net)==before and coord.marker_exists()
        probe=subprocess.run(['/usr/bin/flock','-s','-n',str(coord.writer_lock),'/usr/bin/true'],timeout=5)
        assert probe.returncode!=0  # new cooperating sender cannot acquire SH
        restart_unit='ci-sender-restart-'+uuid.uuid4().hex
        run('/usr/bin/systemd-run','--quiet','--wait','--pipe','--unit='+restart_unit,
            '--property=RuntimeMaxSec=10s','--setenv=CI_GUARDED_FIXTURE=1',
            '/usr/bin/nsenter','--net=/proc/'+str(os.getpid())+'/ns/net','/usr/bin/python3','-B',
            str(root/'runtime'/'ci_sender_restart_probe.py'),str(root))
        fence.verify()  # the actual typed lease could not create a writer
        fcntl.flock(fence.fd,fcntl.LOCK_UN)
        try:fence.verify();raise AssertionError('released EX accepted')
        except custody.Held as error:assert str(error)=='EXCLUSIVE_WRITER_FENCE_LOST'
        fcntl.flock(fence.fd,fcntl.LOCK_EX|fcntl.LOCK_NB);fence.verify()
        print('PASS lost EX is rejected before observation can be used',flush=True)
        assert not list((root/'sender-receipts').glob('WIRE-*')) and not list((root/'sender-receipts').glob('INTENT-*'))
        for rec,pf,mf in zip(records,received[::2],received[1::2]):
            assert int(nl.fdinfo(os.getpid(),pf)['prog_id'])==rec['program_id']
            assert int(nl.fdinfo(os.getpid(),mf)['map_id'])==rec['map_id']
        print('PASS terminal original systemd cgroup, writer EX and retained original SCM_RIGHTS under unchanged genid',flush=True)
        # Even EX is cooperative: an unparticipating writer changes genid and
        # must invalidate any observation, never justify marker deletion.
        run('/usr/sbin/nft','add','table','ip','ci_external_uncooperative_writer')
        assert nl.genid(net)!=before and coord.marker_exists()
        try:fence.verify();raise AssertionError('drift accepted')
        except custody.Held as error:assert str(error)=='EXCLUSIVE_OBSERVATION_GENID_CHANGED'
        print('PASS external genid drift invalidates exclusive observation and marker remains',flush=True)
    print('BOUNDARY: no Guardian prepare/permit, no marker removal or restart authority',flush=True)
finally:
    subprocess.run(['/usr/bin/journalctl','-u',unit,'--no-pager','-n','40'],check=False,timeout=10)
    if childfd is not None:
        try:signal.pidfd_send_signal(childfd,signal.SIGKILL)
        except ProcessLookupError:pass
        os.close(childfd)
    if live is not None:live.close()
    elif anchor is not None:anchor.close()
    if channel is not None:channel.close()
    server.close();net.close()
    subprocess.run(['/usr/bin/systemctl','kill','--kill-whom=all','--signal=KILL',unit],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=10)
    subprocess.run(['/usr/bin/systemctl','stop',unit],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=10)
    unitfile.unlink(missing_ok=True)
    subprocess.run(['/usr/bin/systemctl','daemon-reload'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=10)
